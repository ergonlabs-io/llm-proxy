//! The ledger writer against a real encrypted spool in a temporary directory
//! (ADR-0009 decisions 5 and 6). Request-path behaviour (the 503, the
//! fail-open warning, the slot a refused request gives back) is tested where
//! requests are served, in `proxy-core`'s `listener_ledger_tests.rs`.

use crate::ledger::testing::{TempLedger, TempLedgerDir};
use crate::ledger::{Ledger, LedgerTicket, OnUnavailable, Unavailable};
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

fn reserve(ledger: &Arc<Ledger>) -> crate::ledger::LedgerReservation {
    match ledger.admit() {
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
    assert_eq!(ledger.ledger.reserved(), 0, "committed entries give their slots back");
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
            done.send(ledger.admit().err()).unwrap();
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
        .find_map(|_| match ledger.ledger.admit() {
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
        match ledger.ledger.admit() {
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
}

/// A restart opens a new epoch, past the last one in the spool, and starts
/// `seq` again at 0; the previous epoch's committed entries are still there.
#[test]
fn a_restart_opens_a_later_epoch_and_keeps_committed_entries() {
    let mut ledger = TempLedger::open(4, OnUnavailable::Reject);
    for i in 0..2 {
        reserve(&ledger.ledger).append(numbered(i), LedgerCharge::default());
    }
    ledger.restart();
    reserve(&ledger.ledger).append(numbered(2), LedgerCharge::default());
    let entries = ledger.entries();
    let shape: Vec<(u64, u64)> = entries.iter().map(|e| (e.epoch, e.seq)).collect();
    assert_eq!(shape.len(), 3);
    let (old, new) = (shape[0].0, shape[2].0);
    assert!(new > old, "epoch {new} follows {old}");
    assert_eq!(shape, [(old, 0), (old, 1), (new, 0)]);
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
