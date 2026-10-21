//! The ledger writer against a real encrypted spool in a temporary directory
//! (ADR-0009 decisions 5 and 6). Request-path behaviour (the 503, the
//! fail-open warning, the slot a refused request gives back) is tested where
//! requests are served, in `proxy-core`'s `listener_ledger_tests.rs`.

use crate::ledger::testing::{TempLedger, TempLedgerDir};
use crate::ledger::{Ledger, LedgerQueryError, LedgerTicket, OnUnavailable, Unavailable};
use crate::records::{tests::record, LedgerCharge, RequestRecord};
use std::sync::{mpsc, Arc};
use std::time::Duration;

/// Bounds a call that must not wait on the writer. Generous on purpose: it
/// catches a hang, not a slow box.
const NO_WAIT: Duration = Duration::from_secs(10);

fn numbered(i: usize) -> RequestRecord {
    let mut r = record();
    r.event_id = format!("event-{i}");
    r
}

/// Admission as the router sees it: a refusal is answered, so counted.
fn admit(ledger: &Arc<Ledger>) -> Result<LedgerTicket, Unavailable> {
    ledger.admit().map_err(crate::ledger::LedgerRefusal::refuse)
}

fn reserve(ledger: &Arc<Ledger>) -> crate::ledger::LedgerReservation {
    match admit(ledger) {
        Ok(LedgerTicket::Reserved(r)) => r,
        Ok(LedgerTicket::Unledgered(_)) => panic!("unledgered"),
        Err(reason) => panic!("refused: {reason:?}"),
    }
}

/// A counter's value in the scrape: the line `name{labels} value`.
fn counter(scrape: &str, series: &str) -> u64 {
    scrape
        .lines()
        .find(|l| l.split_whitespace().next() == Some(series))
        .and_then(|l| l.split_whitespace().last())
        .unwrap_or_else(|| panic!("no series {series} in:\n{scrape}"))
        .parse()
        .unwrap()
}

/// Many workers append at once with no lock between them; the writer numbers
/// what it receives, so every entry is committed once and `seq` runs 0..n
/// with no gap and no repeat.
#[test]
fn concurrent_appends_are_numbered_without_gaps_or_repeats() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 150;
    let mut ledger = TempLedger::open(THREADS * PER_THREAD, OnUnavailable::Reject);
    std::thread::scope(|scope| {
        for t in 0..THREADS {
            let ledger = &ledger.ledger;
            scope.spawn(move || {
                for i in 0..PER_THREAD {
                    reserve(ledger).append(numbered(t * PER_THREAD + i), LedgerCharge::default());
                }
            });
        }
    });
    let entries = ledger.entries();
    let seqs: Vec<u64> = entries.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, (0..(THREADS * PER_THREAD) as u64).collect::<Vec<_>>());
    let mut events: Vec<_> = entries.iter().map(|e| e.record.event_id.clone()).collect();
    events.sort();
    events.dedup();
    assert_eq!(events.len(), THREADS * PER_THREAD);
    assert!(entries.iter().all(|e| e.instance_id == "test-instance"));
    assert_eq!(
        ledger.ledger.reserved(),
        0,
        "committed entries give their slots back"
    );
}

/// A writer stuck before its next write does not slow admission or the
/// hand-off: both return while it is stalled. Its uncommitted entries keep
/// their slots, so once every slot is held the next admission is refused at
/// once, and the refusal is counted. Resuming commits everything in order.
#[test]
fn a_stalled_writer_never_delays_admission_and_fills_slots_instead() {
    const SLOTS: usize = 4;
    let hooks = crate::ledger::writer_test_hooks::install();
    hooks.stall();
    let mut ledger = TempLedger::open(SLOTS, OnUnavailable::Reject);
    let (done, finished) = mpsc::channel();
    std::thread::scope(|scope| {
        let ledger = &ledger.ledger;
        scope.spawn(move || {
            for i in 0..SLOTS {
                reserve(ledger).append(numbered(i), LedgerCharge::default());
            }
            done.send(admit(ledger).err()).unwrap();
        });
        let refusal = finished
            .recv_timeout(NO_WAIT)
            .expect("admission and append return while the writer is stalled");
        assert_eq!(refusal, Some(Unavailable::QueueFull));
    });
    assert_eq!(
        counter(
            &ledger.scrape(),
            "envoy_llmproxy_ledger_rejected_total{reason=\"queue_full\"}"
        ),
        1
    );
    hooks.resume();
    let entries = ledger.entries();
    assert_eq!(
        entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    assert_eq!(ledger.ledger.reserved(), 0);
}

/// A writer that fails on storage stops granting slots: admission follows
/// `on_unavailable` (reject here), and an entry handed over afterwards is
/// counted lost rather than vanishing.
#[test]
fn a_failed_writer_refuses_admission_and_counts_what_it_loses() {
    let hooks = crate::ledger::writer_test_hooks::install();
    hooks.fail_next_write();
    let ledger = TempLedger::open(16, OnUnavailable::Reject);
    let held = reserve(&ledger.ledger);
    reserve(&ledger.ledger).append(numbered(0), LedgerCharge::default());
    let refused = (0..1000)
        .find_map(|_| match admit(&ledger.ledger) {
            Err(reason) => Some(reason),
            Ok(_) => {
                std::thread::sleep(Duration::from_millis(10));
                None
            }
        })
        .expect("the writer's failure reaches admission");
    assert_eq!(refused, Unavailable::WriterFailed);
    held.append(numbered(1), LedgerCharge::default());
    let scrape = ledger.scrape();
    assert_eq!(
        counter(
            &scrape,
            "envoy_llmproxy_ledger_entries_lost_total{reason=\"writer_failed\"}"
        ),
        2,
        "the batch the write failed on, and the append after the writer exited"
    );
    assert!(
        counter(
            &scrape,
            "envoy_llmproxy_ledger_rejected_total{reason=\"writer_failed\"}"
        ) >= 1
    );
}

/// At the spool's disk cap admission is refused with `disk_full`, and every
/// entry the writer reported committed is still in the spool afterwards:
/// nothing committed and unacknowledged is evicted to make room. Entries
/// accepted after the cap are held, and counted lost only at shutdown.
#[test]
fn at_the_disk_cap_admission_is_refused_and_committed_entries_are_kept() {
    let dir = TempLedgerDir::new();
    let mut config = dir.config(64, OnUnavailable::Reject);
    config.max_disk_bytes = proxy_capture_spool::MIN_DISK_BYTES;
    config.group_commit_max_entries = 8;
    let mut ledger = TempLedger::open_with(dir, config);
    let padding = "x".repeat(16 * 1024);
    let mut appended = 0;
    let mut refusal = None;
    for _ in 0..20_000 {
        match admit(&ledger.ledger) {
            Ok(LedgerTicket::Reserved(r)) => {
                let mut rec = numbered(appended);
                rec.route = padding.clone();
                r.append(rec, LedgerCharge::default());
                appended += 1;
            }
            Ok(LedgerTicket::Unledgered(_)) => unreachable!("reject mode"),
            Err(Unavailable::QueueFull) => std::thread::sleep(Duration::from_millis(1)),
            Err(other) => {
                refusal = Some(other);
                break;
            }
        }
    }
    assert_eq!(refusal, Some(Unavailable::DiskFull));
    let committed_before_shutdown = counter(
        &ledger.scrape(),
        "envoy_llmproxy_ledger_entries_committed_total",
    );
    let entries = ledger.entries();
    let scrape = ledger.scrape();
    assert_eq!(entries.len() as u64, committed_before_shutdown);
    assert_eq!(
        entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
        (0..entries.len() as u64).collect::<Vec<_>>()
    );
    assert_eq!(
        entries.len() as u64
            + counter(
                &scrape,
                "envoy_llmproxy_ledger_entries_lost_total{reason=\"shutdown\"}"
            ),
        appended as u64,
        "every entry handed over is either committed or counted lost"
    );
    assert!(
        counter(
            &scrape,
            "envoy_llmproxy_ledger_rejected_total{reason=\"disk_full\"}"
        ) >= 1
    );

    // The batch that met the cap was never committed, so the stop lost
    // entries and the epoch did not close. This process's counters are gone
    // after a restart; the next start reports the epoch from the spool.
    assert!(
        counter(
            &scrape,
            "envoy_llmproxy_ledger_entries_lost_total{reason=\"shutdown\"}"
        ) > 0
    );
    ledger.restart();
    assert_eq!(
        counter(
            &ledger.scrape(),
            "envoy_llmproxy_ledger_unclean_epochs_total"
        ),
        1
    );
    let epochs = ledger.ledger.read_committed(0, 1, ASK).unwrap().epochs;
    assert_eq!(epochs.len(), 2);
    assert_eq!(epochs[0].epoch, entries[0].epoch);
    assert!(
        !epochs[0].closed,
        "an epoch that lost entries is not closed"
    );
}

/// A restart opens a new epoch, past the last one in the spool, and starts
/// `seq` again at 0; the previous epoch's committed entries are still there.
/// A clean stop closes its epoch, so the next start reports nothing unclean.
#[test]
fn a_restart_opens_a_later_epoch_and_keeps_committed_entries() {
    let mut ledger = TempLedger::open(4, OnUnavailable::Reject);
    for i in 0..2 {
        reserve(&ledger.ledger).append(numbered(i), LedgerCharge::default());
    }
    ledger.restart();
    assert_eq!(
        counter(
            &ledger.scrape(),
            "envoy_llmproxy_ledger_unclean_epochs_total"
        ),
        0
    );
    let epochs = ledger.ledger.read_committed(0, 1, ASK).unwrap().epochs;
    assert_eq!(epochs.len(), 2);
    assert!(epochs[0].closed, "a clean stop closes its epoch");
    assert!(!epochs[1].closed, "the running epoch is not closed yet");
    reserve(&ledger.ledger).append(numbered(2), LedgerCharge::default());
    let entries = ledger.entries();
    let shape: Vec<(u64, u64)> = entries.iter().map(|e| (e.epoch, e.seq)).collect();
    assert_eq!(shape.len(), 3);
    let (old, new) = (shape[0].0, shape[2].0);
    assert!(new > old, "epoch {new} follows {old}");
    assert_eq!(shape, [(old, 0), (old, 1), (new, 0)]);
    assert_eq!(
        epochs.iter().map(|e| e.epoch).collect::<Vec<_>>(),
        [old, new]
    );
}

/// The key file must be a private 32-byte file; the error names the config
/// field and the path, and never the key bytes.
#[test]
fn a_readable_key_file_is_refused_naming_the_field() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempLedgerDir::new();
    let config = dir.config(4, OnUnavailable::Reject);
    std::fs::set_permissions(
        &config.encryption_key.file,
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let error = match crate::ledger::open(&config, "i", &crate::stats::StatsControl::new(1)) {
        Ok(_) => panic!("a world-readable key opened"),
        Err(e) => e.to_string(),
    };
    assert!(error.starts_with("encryption_key_file: "), "{error}");
    assert!(error.contains("ledger.key"), "{error}");
}

// ------------------------------------------------- reads and acknowledgement --

/// Reads and acknowledgements are answered by the writer; this bounds the
/// wait like the admin API does.
const ASK: Duration = Duration::from_secs(10);

/// Poll until `n` entries are committed; returns the page.
fn committed(ledger: &Ledger, n: usize) -> crate::ledger::LedgerPage {
    for _ in 0..1000 {
        let page = ledger.read_committed(0, 1000, ASK).expect("read");
        if page.entries.len() >= n {
            return page;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("{n} entries were never committed");
}

fn spend_charge(micro_usd: u64) -> LedgerCharge {
    LedgerCharge {
        charged_micro_usd: micro_usd,
        charged_scopes: vec![crate::records::ChargedScope {
            scope: crate::records::ChargeScope::Tenant,
            id: "t1".into(),
            period: "2026-10".into(),
        }],
        rate_card_version: Some("v1".into()),
    }
}

/// A read returns only what is committed: an entry the writer holds in an
/// open group is not returned while the group is open. Pages run in cursor
/// order across a restart, where `seq` starts again at 0 but the cursor keeps
/// rising, which is why the cursor and not `seq` is what reads take.
#[test]
fn a_read_returns_committed_entries_only_in_cursor_order_across_epochs() {
    let dir = TempLedgerDir::new();
    let mut config = dir.config(8, OnUnavailable::Reject);
    config.group_commit_max_entries = 2;
    config.group_commit_interval = Duration::from_secs(60);
    let mut ledger = TempLedger::open_with(dir, config);

    reserve(&ledger.ledger).append(numbered(0), LedgerCharge::default());
    let open_group = ledger.ledger.read_committed(0, 1000, ASK).expect("read");
    assert!(
        open_group.entries.is_empty(),
        "an uncommitted entry was returned: {open_group:?}"
    );
    assert_eq!(open_group.committed_through, 0);

    reserve(&ledger.ledger).append(numbered(1), LedgerCharge::default());
    let first = committed(&ledger.ledger, 2);
    ledger.restart();
    for i in 2..4 {
        reserve(&ledger.ledger).append(numbered(i), LedgerCharge::default());
    }
    let page = committed(&ledger.ledger, 4);
    let shape: Vec<(u64, u64, u64)> = page
        .entries
        .iter()
        .map(|e| (e.cursor, e.entry.epoch, e.entry.seq))
        .collect();
    let (old, new) = (first.entries[0].entry.epoch, page.entries[2].entry.epoch);
    assert!(new > old);
    assert_eq!(shape, [(1, old, 0), (2, old, 1), (3, new, 0), (4, new, 1)]);
    assert_eq!(page.committed_through, 4);
    assert!(page
        .entries
        .iter()
        .all(|e| e.entry.instance_id == "test-instance"));

    let after = ledger.ledger.read_committed(2, 1, ASK).expect("read");
    assert_eq!(
        after.entries.iter().map(|e| e.cursor).collect::<Vec<_>>(),
        [3],
        "after is exclusive and limit bounds the page"
    );
}

/// An acknowledgement removes entries through its cursor from the spool, not
/// just from later reads: a reopened spool no longer holds them. A cursor
/// past the last committed entry is refused and changes nothing.
#[test]
fn an_acknowledgement_reclaims_entries_through_its_cursor() {
    let mut ledger = TempLedger::open(8, OnUnavailable::Reject);
    for i in 0..5 {
        reserve(&ledger.ledger).append(numbered(i), LedgerCharge::default());
    }
    let page = committed(&ledger.ledger, 5);
    let through = page.entries[2].cursor;

    assert_eq!(
        ledger.ledger.acknowledge(99, ASK),
        Err(LedgerQueryError::BeyondCommitted {
            through: 99,
            committed_through: 5
        })
    );
    let ack = ledger.ledger.acknowledge(through, ASK).expect("ack");
    assert_eq!(ack.acknowledged_through, through);
    assert!(ack.admitting);

    let rest = ledger.ledger.read_committed(0, 1000, ASK).expect("read");
    assert_eq!(
        rest.entries
            .iter()
            .map(|e| e.entry.record.event_id.as_str())
            .collect::<Vec<_>>(),
        ["event-3", "event-4"]
    );
    let kept: Vec<String> = ledger
        .entries()
        .into_iter()
        .map(|e| e.record.event_id)
        .collect();
    assert_eq!(kept, ["event-3", "event-4"], "acknowledged rows are gone");
}

/// The disk-cap hold is released by an acknowledgement, without a restart:
/// under `reject` admission is refused with `disk_full`, the entries handed
/// over at the cap are held, and once space is acknowledged they are written
/// in order, `seq` continues with no gap (numbers given back by a refused
/// write are reused), and the next request is admitted again.
#[test]
fn an_acknowledgement_at_the_disk_cap_resumes_admission_and_writes_held_entries() {
    let dir = TempLedgerDir::new();
    let mut config = dir.config(64, OnUnavailable::Reject);
    config.max_disk_bytes = proxy_capture_spool::MIN_DISK_BYTES;
    config.group_commit_max_entries = 8;
    let mut ledger = TempLedger::open_with(dir, config);
    let padding = "x".repeat(16 * 1024);
    let padded = |i: usize| {
        let mut rec = numbered(i);
        rec.route = padding.clone();
        rec
    };
    // Slots taken while there is room, used only after the cap is reached.
    let held: Vec<_> = (0..3).map(|_| reserve(&ledger.ledger)).collect();
    let mut appended = 0;
    let mut refusal = None;
    for _ in 0..20_000 {
        match admit(&ledger.ledger) {
            Ok(LedgerTicket::Reserved(r)) => {
                r.append(padded(appended), LedgerCharge::default());
                appended += 1;
            }
            Ok(LedgerTicket::Unledgered(_)) => unreachable!("reject mode"),
            Err(Unavailable::QueueFull) => std::thread::sleep(Duration::from_millis(1)),
            Err(other) => {
                refusal = Some(other);
                break;
            }
        }
    }
    assert_eq!(refusal, Some(Unavailable::DiskFull));
    for r in held {
        r.append(padded(appended), LedgerCharge::default());
        appended += 1;
    }
    assert_eq!(
        admit(&ledger.ledger).err(),
        Some(Unavailable::DiskFull),
        "still at the cap before the acknowledgement"
    );

    // A consumer pulls and acknowledges page by page. The slots held at the
    // cap can hold more entries than one acknowledgement frees room for, so
    // the writer re-enters the cap until the consumer has caught up; every
    // acknowledgement must still make progress.
    let mut pulled = Vec::new();
    let mut last_ack = 0;
    loop {
        let page = ledger
            .ledger
            .read_committed(last_ack, 1000, ASK)
            .expect("reads work at the cap");
        let Some(through) = page.entries.last().map(|e| e.cursor) else {
            panic!("at the cap with nothing committed to acknowledge");
        };
        pulled.extend(page.entries.into_iter().map(|e| e.entry));
        let ack = ledger.ledger.acknowledge(through, ASK).expect("ack");
        assert!(ack.acknowledged_through > last_ack, "an ack made progress");
        last_ack = ack.acknowledged_through;
        if ack.admitting {
            break;
        }
        assert_eq!(admit(&ledger.ledger).err(), Some(Unavailable::DiskFull));
    }
    reserve(&ledger.ledger).append(padded(appended), LedgerCharge::default());
    appended += 1;

    pulled.extend(ledger.entries());
    let scrape = ledger.scrape();
    assert_eq!(
        counter(
            &scrape,
            "envoy_llmproxy_ledger_entries_lost_total{reason=\"shutdown\"}"
        ),
        0,
        "nothing stayed held"
    );
    assert_eq!(
        counter(&scrape, "envoy_llmproxy_ledger_entries_committed_total"),
        appended as u64
    );
    let seqs: Vec<u64> = pulled.iter().map(|e| e.seq).collect();
    assert_eq!(
        seqs,
        (0..appended as u64).collect::<Vec<_>>(),
        "seq has no gap across the cap: numbers a refused write gave back are reused"
    );
    let events: Vec<String> = pulled.iter().map(|e| e.record.event_id.clone()).collect();
    let expected: Vec<String> = (0..appended).map(|i| format!("event-{i}")).collect();
    assert_eq!(
        events, expected,
        "held entries are written in arrival order"
    );
}

/// The ledger side of reconciliation (ADR-0009 decision 7) counts the spend
/// charges of committed entries; a list price on an unbudgeted route is in
/// the entry but is not a spend charge.
#[test]
fn the_spend_written_counter_sums_committed_spend_charges_only() {
    let mut ledger = TempLedger::open(8, OnUnavailable::Reject);
    for i in 0..3 {
        reserve(&ledger.ledger).append(numbered(i), spend_charge(7));
    }
    for i in 3..5 {
        let list_price = LedgerCharge {
            charged_micro_usd: 5,
            ..LedgerCharge::default()
        };
        reserve(&ledger.ledger).append(numbered(i), list_price);
    }
    assert_eq!(ledger.entries().len(), 5);
    assert_eq!(
        counter(
            &ledger.scrape(),
            "envoy_llmproxy_ledger_spend_written_micro_usd_total"
        ),
        21
    );
}

/// A batch the spool refuses at the cap was numbered but never written, so
/// its numbers are given back. The first acknowledgement's retry is refused
/// again part way through the held entries; the second writes them all, in
/// arrival order, and `seq` has no gap.
#[test]
fn a_batch_refused_at_the_cap_gives_its_seq_numbers_back() {
    const HELD: usize = 6;
    let hooks = crate::ledger::writer_test_hooks::install();
    // The batch that meets the cap, then the first batch the retry writes.
    hooks.refuse_appends(2);
    let dir = TempLedgerDir::new();
    let mut config = dir.config(HELD + 1, OnUnavailable::Reject);
    config.group_commit_max_entries = 2;
    let mut ledger = TempLedger::open_with(dir, config);
    let slots: Vec<_> = (0..HELD).map(|_| reserve(&ledger.ledger)).collect();
    for (i, slot) in slots.into_iter().enumerate() {
        slot.append(numbered(i), LedgerCharge::default());
    }
    let refused = (0..1000)
        .find_map(|_| match admit(&ledger.ledger) {
            Err(reason) => Some(reason),
            Ok(_) => {
                std::thread::sleep(Duration::from_millis(10));
                None
            }
        })
        .expect("the refused append reaches admission");
    assert_eq!(refused, Unavailable::DiskFull);
    // Nothing is committed, so there is nothing to acknowledge; each
    // acknowledgement still retries the held writes. The channel is FIFO, so
    // every entry above reaches the writer before the acknowledgement does.
    let first = ledger.ledger.acknowledge(0, ASK).expect("ack");
    assert!(!first.admitting, "the retry was refused again");
    let second = ledger.ledger.acknowledge(0, ASK).expect("ack");
    assert!(second.admitting);
    reserve(&ledger.ledger).append(numbered(HELD), LedgerCharge::default());
    let shape: Vec<(u64, String)> = ledger
        .entries()
        .into_iter()
        .map(|e| (e.seq, e.record.event_id))
        .collect();
    let expected: Vec<(u64, String)> = (0..=HELD)
        .map(|i| (i as u64, format!("event-{i}")))
        .collect();
    assert_eq!(shape, expected);
}

/// One group commit can hold more entries than the spool at its cap has room
/// for even with every committed entry acknowledged: a minimum-size spool
/// holds about 1 MiB. Committed whole, a refused batch stayed pending and was
/// refused again after every acknowledgement, so admissions never resumed.
/// The writer commits in chunks bounded by the disk cap instead, so what a
/// refusal leaves pending fits once the consumer has acknowledged; its
/// "acknowledge until admitting" loop drains everything, and nothing is lost.
#[test]
fn a_group_commit_larger_than_the_disk_cap_still_drains() {
    const BATCH: usize = 128;
    let dir = TempLedgerDir::new();
    let mut config = dir.config(BATCH, OnUnavailable::Reject);
    config.max_disk_bytes = proxy_capture_spool::MIN_DISK_BYTES;
    // The batch closes on its size, never on the timer, so all of it is one
    // group commit.
    config.group_commit_max_entries = BATCH;
    config.group_commit_interval = Duration::from_secs(600);
    let mut ledger = TempLedger::open_with(dir, config);
    let padding = "x".repeat(12 * 1024);
    let slots: Vec<_> = (0..BATCH).map(|_| reserve(&ledger.ledger)).collect();
    for (i, slot) in slots.into_iter().enumerate() {
        let mut rec = numbered(i);
        rec.route = padding.clone();
        slot.append(rec, LedgerCharge::default());
    }
    // The writer answers in arrival order, so this read follows the batch.
    ledger.ledger.read_committed(0, 1, ASK).unwrap();
    assert_eq!(
        admit(&ledger.ledger).err(),
        Some(Unavailable::DiskFull),
        "the batch did not reach the cap; make it larger"
    );

    let mut acked = 0;
    let mut pulled = Vec::new();
    let mut rounds = 0;
    loop {
        let page = ledger.ledger.read_committed(acked, 1000, ASK).unwrap();
        let through = page.entries.last().map_or(acked, |e| e.cursor);
        pulled.extend(page.entries.into_iter().map(|e| e.entry.seq));
        let ack = ledger.ledger.acknowledge(through, ASK).expect("ack");
        acked = through;
        if ack.admitting {
            break;
        }
        rounds += 1;
        assert!(
            rounds < 32,
            "never resumed admitting with everything acknowledged ({} of {BATCH} read)",
            pulled.len()
        );
    }
    pulled.extend(ledger.entries().into_iter().map(|e| e.seq));
    assert_eq!(pulled, (0..BATCH as u64).collect::<Vec<_>>());
    let scrape = ledger.scrape();
    assert_eq!(
        counter(&scrape, "envoy_llmproxy_ledger_entries_committed_total"),
        BATCH as u64
    );
    assert_eq!(
        counter(
            &scrape,
            "envoy_llmproxy_ledger_entries_lost_total{reason=\"shutdown\"}"
        ),
        0
    );
}
