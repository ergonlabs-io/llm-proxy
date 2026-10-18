//! Versioned, per-replica spend checkpoints. Only startup and the flusher
//! access this file; request workers only update the parent's memory buckets.
use std::collections::HashMap;
use std::path::Path;

use redb::{Database, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};

use super::{Bucket, PeriodKey};
use crate::auth::TenantId;
use crate::control::{store_err, StoreError};

const CHECKPOINT: TableDefinition<&str, &[u8]> = TableDefinition::new("spend_recovery_v1");
type RecoveryBuckets = HashMap<(TenantId, PeriodKey), Bucket>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u32,
    stat_prefix: String,
    node_id: String,
    rows: Vec<Row>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    subject: String,
    period: String,
    bucket: Bucket,
}

/// Borrowed twin of [`Checkpoint`], used only to WRITE. A save serialises the
/// rows it was handed instead of cloning each bucket a second time, which
/// would make "the flush copies the map once" false in spirit: the copy under
/// the request-path mutex would be followed by another on the flusher thread.
///
/// Field names and order match `Checkpoint`, which is what `open` reads back;
/// every test below that saves and reopens pins that they stay in step.
#[derive(Serialize)]
struct CheckpointRef<'a> {
    version: u32,
    stat_prefix: &'a str,
    node_id: &'a str,
    rows: Vec<RowRef<'a>>,
}

#[derive(Serialize)]
struct RowRef<'a> {
    subject: &'a str,
    period: &'a str,
    bucket: &'a Bucket,
}

pub(super) struct Journal {
    db: Database,
    stat_prefix: String,
    node_id: String,
    /// Durable commits since open, so a test can pin "one per flush tick".
    #[cfg(test)]
    commits: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    fail_writes: std::sync::atomic::AtomicBool,
}

impl Journal {
    pub(super) fn open(
        path: &Path,
        stat_prefix: &str,
        node_id: &str,
    ) -> Result<(Self, RecoveryBuckets), StoreError> {
        let db = Database::create(path).map_err(store_err)?;
        let txn = db.begin_write().map_err(store_err)?;
        txn.open_table(CHECKPOINT).map_err(store_err)?;
        txn.commit().map_err(store_err)?;
        let journal = Self {
            db,
            stat_prefix: stat_prefix.into(),
            node_id: node_id.into(),
            #[cfg(test)]
            commits: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            fail_writes: std::sync::atomic::AtomicBool::new(false),
        };
        let txn = journal.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(CHECKPOINT).map_err(store_err)?;
        let mut buckets = HashMap::new();
        if let Some(raw) = table.get("checkpoint").map_err(store_err)? {
            let checkpoint: Checkpoint = serde_json::from_slice(raw.value()).map_err(store_err)?;
            if checkpoint.version != 1
                || checkpoint.stat_prefix != stat_prefix
                || checkpoint.node_id != node_id
            {
                return Err(StoreError::Unavailable(
                    "spend recovery journal version or replica/chain identity mismatch".into(),
                ));
            }
            for row in checkpoint.rows {
                if let Some(attempt) = row.bucket.attempt {
                    if attempt.seq == 0
                        || attempt.delta > row.bucket.pending_delta_micros
                        || row.bucket.next_seq != Some(attempt.seq)
                    {
                        return Err(StoreError::Unavailable(
                            "invalid spend recovery attempt".into(),
                        ));
                    }
                }
                if buckets
                    .insert(
                        (TenantId::new(row.subject), PeriodKey(row.period)),
                        row.bucket,
                    )
                    .is_some()
                {
                    return Err(StoreError::Unavailable(
                        "duplicate spend recovery row".into(),
                    ));
                }
            }
        }
        drop(table);
        drop(txn);
        Ok((journal, buckets))
    }

    pub(super) fn save(
        &self,
        buckets: &HashMap<(TenantId, PeriodKey), Bucket>,
    ) -> Result<(), StoreError> {
        #[cfg(test)]
        if self.fail_writes.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(StoreError::Unavailable(
                "test: journal commit failed".into(),
            ));
        }
        let checkpoint = CheckpointRef {
            version: 1,
            stat_prefix: &self.stat_prefix,
            node_id: &self.node_id,
            rows: buckets
                .iter()
                .map(|((subject, period), bucket)| RowRef {
                    subject: subject.as_str(),
                    period: period.as_str(),
                    bucket,
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&checkpoint).map_err(store_err)?;
        let txn = self.db.begin_write().map_err(store_err)?;
        // redb's default Immediate durability fsyncs the transaction at commit.
        txn.open_table(CHECKPOINT)
            .map_err(store_err)?
            .insert("checkpoint", bytes.as_slice())
            .map_err(store_err)?;
        txn.commit().map_err(store_err)?;
        #[cfg(test)]
        self.commits
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// What the last commit holds, read back through a fresh read
    /// transaction: the on-disk truth, not the in-memory map it was built
    /// from. Going through `Checkpoint` also proves what `save` wrote is
    /// something `open` can read.
    #[cfg(test)]
    pub(super) fn saved_rows(&self) -> Vec<(TenantId, PeriodKey, Bucket)> {
        let txn = self.db.begin_read().expect("journal read transaction");
        let table = txn.open_table(CHECKPOINT).expect("journal table");
        let Some(raw) = table.get("checkpoint").expect("journal read") else {
            return Vec::new();
        };
        let checkpoint: Checkpoint =
            serde_json::from_slice(raw.value()).expect("journal checkpoint decodes");
        checkpoint
            .rows
            .into_iter()
            .map(|row| {
                (
                    TenantId::new(row.subject),
                    PeriodKey(row.period),
                    row.bucket,
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{ControlPlaneStore, FlushToken, InMemoryControlPlaneStore};
    use crate::spend::{FlushAttempt, Period, SpendAccumulator};
    use std::sync::Arc;

    fn path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "spend-recovery-{}-{}.redb",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn journal_replays_ambiguous_payload_without_losing_new_charges() {
        let path = path();
        let subject = TenantId::new("\u{1f}key:a");
        let period = Period::Daily.key_for_now();
        let store = Arc::new(InMemoryControlPlaneStore::default());
        store
            .add_spend(
                "chain",
                &subject,
                &period,
                6,
                FlushToken {
                    node_id: "node",
                    seq: 1,
                },
            )
            .unwrap();
        let (journal, _) = Journal::open(&path, "chain", "node").unwrap();
        let buckets = HashMap::from([(
            (subject.clone(), period.clone()),
            Bucket {
                pending_delta_micros: 8,
                next_seq: Some(1),
                attempt: Some(FlushAttempt { seq: 1, delta: 6 }),
                ..Bucket::default()
            },
        )]);
        journal.save(&buckets).unwrap();
        drop(journal);
        {
            let recovered =
                SpendAccumulator::new("chain".into(), store.clone(), Period::Daily, "node".into())
                    .with_recovery_journal(&path)
                    .unwrap();
            assert_eq!(recovered.current_total(&subject, &period), 8);
            recovered.flush_now().unwrap();
            assert_eq!(store.load_spend("chain", &subject, &period).unwrap(), 8);
            assert_eq!(
                recovered
                    .report(&subject, &period)
                    .journal_pending_micro_usd,
                0
            );
        }
        {
            let clean =
                SpendAccumulator::new("chain".into(), store.clone(), Period::Daily, "node".into())
                    .with_recovery_journal(&path)
                    .unwrap();
            clean.flush_now().unwrap();
            assert_eq!(store.load_spend("chain", &subject, &period).unwrap(), 8);
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn journal_restores_pending_spend_without_a_seeded_sequence() {
        let path = path();
        let subject = TenantId::new("\u{1f}key:a");
        let period = Period::Daily.key_for_now();
        let (journal, _) = Journal::open(&path, "chain", "node").unwrap();
        journal
            .save(&HashMap::from([(
                (subject.clone(), period.clone()),
                Bucket {
                    pending_delta_micros: 9,
                    ..Bucket::default()
                },
            )]))
            .unwrap();
        drop(journal);
        let store = Arc::new(InMemoryControlPlaneStore::default());
        {
            let recovered =
                SpendAccumulator::new("chain".into(), store.clone(), Period::Daily, "node".into())
                    .with_recovery_journal(&path)
                    .unwrap();
            assert_eq!(recovered.current_total(&subject, &period), 9);
            assert_eq!(
                store
                    .last_flush_seq("chain", &subject, &period, "node")
                    .unwrap(),
                1
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn journal_rejects_identity_mismatch_and_exclusive_path_reuse() {
        let path = path();
        let (journal, _) = Journal::open(&path, "chain", "node").unwrap();
        journal.save(&HashMap::new()).unwrap();
        assert!(Journal::open(&path, "chain", "node").is_err());
        drop(journal);
        assert!(Journal::open(&path, "different", "node").is_err());
        assert!(Journal::open(&path, "chain", "different").is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn journal_rejects_unknown_version() {
        let path = path();
        let (journal, _) = Journal::open(&path, "chain", "node").unwrap();
        let write = |bytes: &[u8]| {
            let txn = journal.db.begin_write().unwrap();
            txn.open_table(CHECKPOINT)
                .unwrap()
                .insert("checkpoint", bytes)
                .unwrap();
            txn.commit().unwrap();
        };
        write(br#"{"version":99,"stat_prefix":"chain","node_id":"node","rows":[]}"#);
        drop(journal);
        assert!(Journal::open(&path, "chain", "node").is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn production_first_touch_does_not_query_the_store() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let known = crate::auth::KeyId::new("a");
        let unknown = crate::auth::KeyId::new("b");
        let period = Period::Daily.key_for_now();
        store
            .overwrite_spend(
                "chain",
                &crate::spend::key_spend_subject(&known),
                &period,
                2,
            )
            .unwrap();
        store
            .overwrite_spend(
                "chain",
                &crate::spend::key_spend_subject(&unknown),
                &period,
                9,
            )
            .unwrap();
        let accumulator =
            SpendAccumulator::new("chain".into(), store.clone(), Period::Daily, "node".into());
        accumulator
            .prepare_request_workers(std::slice::from_ref(&known))
            .unwrap();
        assert_eq!(accumulator.current_total_key(&known, &period), 2);
        assert_eq!(accumulator.current_total_key(&unknown, &period), 0);
        accumulator.flush_now().unwrap();
        assert_eq!(accumulator.current_total_key(&unknown, &period), 9);
    }

    #[test]
    fn failed_journal_checkpoint_prevents_remote_writes_and_preserves_local_accrual() {
        let path = path();
        let subject = TenantId::new("subject");
        let period = Period::Daily.key_for_now();
        let store = Arc::new(InMemoryControlPlaneStore::default());
        {
            let accumulator =
                SpendAccumulator::new("chain".into(), store.clone(), Period::Daily, "node".into())
                    .with_recovery_journal(&path)
                    .unwrap();
            accumulator
                .inner
                .journal
                .as_ref()
                .unwrap()
                .fail_writes
                .store(true, std::sync::atomic::Ordering::Relaxed);
            accumulator.record_now(
                &subject,
                Period::Daily,
                crate::spend::Charge::Priced(crate::spend::MicroUsd::from_micros(9)),
                None,
                None,
            );
            assert!(accumulator.flush_now().is_err());
            assert_eq!(
                store
                    .last_flush_seq("chain", &subject, &period, "node")
                    .unwrap(),
                0
            );
            assert_eq!(store.load_spend("chain", &subject, &period).unwrap(), 0);
            assert_eq!(accumulator.current_total(&subject, &period), 9);
            accumulator
                .inner
                .journal
                .as_ref()
                .unwrap()
                .fail_writes
                .store(false, std::sync::atomic::Ordering::Relaxed);
            accumulator.flush_now().unwrap();
            assert_eq!(store.load_spend("chain", &subject, &period).unwrap(), 9);
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn journal_rejects_invalid_attempts_and_duplicate_rows() {
        for (attempt, next_seq) in [
            (FlushAttempt { seq: 0, delta: 1 }, Some(0)),
            (FlushAttempt { seq: 1, delta: 3 }, Some(1)),
            (FlushAttempt { seq: 1, delta: 1 }, Some(2)),
        ] {
            let path = path();
            let (journal, _) = Journal::open(&path, "chain", "node").unwrap();
            journal
                .save(&HashMap::from([(
                    (TenantId::new("subject"), Period::Daily.key_for_now()),
                    Bucket {
                        pending_delta_micros: 2,
                        next_seq,
                        attempt: Some(attempt),
                        ..Bucket::default()
                    },
                )]))
                .unwrap();
            drop(journal);
            assert!(Journal::open(&path, "chain", "node").is_err());
            std::fs::remove_file(path).unwrap();
        }
        let path = path();
        let (journal, _) = Journal::open(&path, "chain", "node").unwrap();
        let bucket = Bucket::default();
        let bytes = serde_json::to_vec(&Checkpoint {
            version: 1,
            stat_prefix: "chain".into(),
            node_id: "node".into(),
            rows: vec![
                Row {
                    subject: "same".into(),
                    period: "same".into(),
                    bucket: bucket.clone(),
                },
                Row {
                    subject: "same".into(),
                    period: "same".into(),
                    bucket,
                },
            ],
        })
        .unwrap();
        let txn = journal.db.begin_write().unwrap();
        txn.open_table(CHECKPOINT)
            .unwrap()
            .insert("checkpoint", bytes.as_slice())
            .unwrap();
        txn.commit().unwrap();
        drop(journal);
        assert!(Journal::open(&path, "chain", "node").is_err());
        std::fs::remove_file(path).unwrap();
    }

    // --- the shape of a flush tick, journal side --------------------------

    use crate::spend::test_support::ProbeStore;
    use crate::spend::{Charge, MicroUsd};
    use std::sync::atomic::Ordering::{Relaxed, SeqCst};

    fn journaled_accumulator(store: &Arc<ProbeStore>, path: &Path) -> SpendAccumulator {
        SpendAccumulator::new(
            "chain".into(),
            Arc::clone(store) as Arc<dyn ControlPlaneStore>,
            Period::Daily,
            "node".into(),
        )
        .with_recovery_journal(path)
        .unwrap()
    }

    fn charge(accumulator: &SpendAccumulator, subject: &TenantId, micros: u64) {
        accumulator.record_now(
            subject,
            Period::Daily,
            Charge::Priced(MicroUsd::from_micros(micros)),
            None,
            None,
        );
    }

    /// A tick used to copy the whole map three times under the request-path
    /// mutex and commit the journal three times, each commit an fsync. It
    /// takes one copy and makes one commit, and the first tick (which seeds
    /// sequences for new buckets) costs the same as a steady one.
    ///
    /// Mutation: add a second `self.checkpoint(...)` after the deliveries in
    /// `Inner::flush_now`.
    #[test]
    fn a_flush_tick_copies_the_buckets_once_and_commits_the_journal_once() {
        let path = path();
        let store = ProbeStore::new();
        {
            let accumulator = journaled_accumulator(&store, &path);
            for name in ["a", "b", "c"] {
                charge(&accumulator, &TenantId::new(name), 5);
            }
            let journal = accumulator.inner.journal.as_ref().unwrap();
            // Opening replays through one tick already; count from here.
            let copies_before = accumulator.inner.snapshots_taken.load(Relaxed);
            let commits_before = journal.commits.load(Relaxed);

            accumulator.flush_now().unwrap();
            assert_eq!(
                accumulator.inner.snapshots_taken.load(Relaxed) - copies_before,
                1,
                "a tick copies the map once, under the mutex, for the journal"
            );
            assert_eq!(journal.commits.load(Relaxed) - commits_before, 1);

            accumulator.flush_now().unwrap();
            assert_eq!(
                accumulator.inner.snapshots_taken.load(Relaxed) - copies_before,
                2
            );
            assert_eq!(
                journal.commits.load(Relaxed) - commits_before,
                2,
                "one durable commit per tick, however many buckets it carries"
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    /// The checkpoint now predates the deliveries, so the pending gauges are
    /// reduced by what the store confirms; otherwise a healthy replica would
    /// read "pending" for a whole interval after it had already delivered.
    /// Walk one row through an outage and a recovery, including a delivery
    /// that confirms only part of what the journal holds.
    ///
    /// Mutation: drop the gauge subtraction at the end of `flush_now`.
    #[test]
    fn the_pending_gauges_count_journaled_spend_the_store_has_not_confirmed() {
        let path = path();
        let store = ProbeStore::new();
        let subject = TenantId::new("subject");
        let period = Period::Daily.key_for_now();
        {
            let accumulator = journaled_accumulator(&store, &path);
            let gauges = |accumulator: &SpendAccumulator| {
                let report = accumulator.report(&subject, &period);
                (
                    report.journal_pending_micro_usd,
                    report.journal_pending_rows,
                )
            };

            charge(&accumulator, &subject, 9);
            store.fail_add_spend.store(true, SeqCst);
            accumulator.flush_now().unwrap_err();
            assert_eq!(gauges(&accumulator), (9, 1), "journaled and undelivered");

            // More spend accrues while the store is down; the frozen
            // attempt still carries only the 9.
            charge(&accumulator, &subject, 4);
            accumulator.flush_now().unwrap_err();
            assert_eq!(gauges(&accumulator), (13, 1));

            // The store returns. The retry delivers the frozen 9 and the
            // 4 recorded since is still journaled and still unconfirmed.
            store.fail_add_spend.store(false, SeqCst);
            accumulator.flush_now().unwrap();
            assert_eq!(
                gauges(&accumulator),
                (4, 1),
                "a partial confirmation must leave the remainder counted, and its row"
            );

            accumulator.flush_now().unwrap();
            assert_eq!(gauges(&accumulator), (0, 0));
            assert_eq!(
                store.inner.load_spend("chain", &subject, &period).unwrap(),
                13
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    /// The commit moved from before the sequence seeding to after it, so the
    /// property the old first commit existed for is pinned on its own: spend
    /// accrued while the store cannot even answer a sequence read is still on
    /// disk when the tick gives up.
    ///
    /// Mutation: return early from `flush_now` when a sequence read fails,
    /// before the checkpoint.
    #[test]
    fn spend_accrued_while_the_store_cannot_seed_a_sequence_is_still_journaled() {
        let path = path();
        let store = ProbeStore::new();
        let subject = TenantId::new("subject");
        let period = Period::Daily.key_for_now();
        {
            let accumulator = journaled_accumulator(&store, &path);
            charge(&accumulator, &subject, 9);
            store.fail_last_flush_seq.store(true, SeqCst);

            accumulator.flush_now().unwrap_err();

            let rows = accumulator.inner.journal.as_ref().unwrap().saved_rows();
            assert_eq!(rows.len(), 1);
            let (_, _, bucket) = &rows[0];
            assert_eq!(bucket.pending_delta_micros, 9);
            assert!(bucket.attempt.is_none(), "no sequence, so nothing frozen");
            assert_eq!(store.add_spend_calls(), 0, "and nothing was sent");

            store.fail_last_flush_seq.store(false, SeqCst);
            accumulator.flush_now().unwrap();
            assert_eq!(
                store.inner.load_spend("chain", &subject, &period).unwrap(),
                9
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    /// The one placement of the commit that is load-bearing: the frozen
    /// `(seq, delta)` is on disk when the store is first called. If a delivery
    /// could land before its attempt was durable, a crash would let the
    /// restarted replica freeze a fresh attempt for charges the store already
    /// holds, and charge them twice.
    ///
    /// Mutation: move the checkpoint in `flush_now` to after the delivery
    /// loop.
    #[test]
    fn the_frozen_attempt_is_durable_before_the_first_remote_write() {
        let path = path();
        let store = ProbeStore::new();
        let subject = TenantId::new("subject");
        let accumulator = Arc::new(journaled_accumulator(&store, &path));
        charge(&accumulator, &subject, 9);
        let durable_at_send = Arc::new(std::sync::Mutex::new(Vec::new()));
        {
            // A `Weak`, not an `Arc`: the store would otherwise own the
            // accumulator that owns the store, and neither would ever drop.
            let accumulator = Arc::downgrade(&accumulator);
            let durable_at_send = Arc::clone(&durable_at_send);
            *store.before_add_spend.lock().unwrap() = Some(Box::new(move || {
                let accumulator = accumulator.upgrade().expect("flush runs inside the test");
                let rows = accumulator.inner.journal.as_ref().unwrap().saved_rows();
                durable_at_send.lock().unwrap().push(
                    rows.iter()
                        .map(|(_, _, bucket)| bucket.attempt.map(|a| (a.seq, a.delta)))
                        .collect::<Vec<_>>(),
                );
            }));
        }

        accumulator.flush_now().unwrap();

        assert_eq!(
            *durable_at_send.lock().unwrap(),
            vec![vec![Some((1, 9))]],
            "at the moment the store was called, the journal already held attempt 1 / 9"
        );
        // The hook borrows the accumulator weakly; remove it before `Drop`'s
        // final flush calls the store again with no accumulator to upgrade.
        *store.before_add_spend.lock().unwrap() = None;
        drop(accumulator);
        std::fs::remove_file(path).unwrap();
    }

    // --- eviction, journal side --------------------------------------------

    fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> chrono::DateTime<chrono::Utc> {
        use chrono::TimeZone;
        chrono::Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap()
    }

    /// Settled buckets are out of the set the flusher copies and journals, so
    /// neither the copy under the request-path mutex nor the checkpoint grows
    /// with them. Forty settled buckets sit in memory; the checkpoint holds
    /// the one live row.
    ///
    /// Mutation: have `journal_snapshot` clone `active` and `settled` alike.
    #[test]
    fn settled_buckets_are_not_copied_or_journaled() {
        let path = path();
        let store = ProbeStore::new();
        let live = TenantId::new("live");
        {
            let accumulator = journaled_accumulator(&store, &path);
            let old = at(2026, 9, 3, 12, 0);
            for i in 0..40 {
                accumulator.record(
                    &TenantId::new(format!("old-{i}")),
                    old,
                    Period::Daily,
                    Charge::Priced(MicroUsd::from_micros(5)),
                    None,
                    None,
                );
            }
            charge(&accumulator, &live, 1);
            // Reconciles the ended period and settles it inside the grace.
            accumulator.inner.flush_at(at(2026, 9, 4, 0, 30)).unwrap();
            assert_eq!(accumulator.inner.buckets.lock().unwrap().counts(), (1, 40));
            let journal = accumulator.inner.journal.as_ref().unwrap();
            assert_eq!(
                journal.saved_rows().len(),
                41,
                "that tick's commit predates the settling"
            );

            accumulator.inner.flush_at(at(2026, 9, 4, 0, 35)).unwrap();

            let rows = journal.saved_rows();
            assert_eq!(rows.len(), 1, "the next commit carries the live row only");
            assert_eq!(rows[0].0, live);
        }
        std::fs::remove_file(path).unwrap();
    }

    /// An evicted bucket is gone from the journal, and a restart restores
    /// only what was still live. The old period here is far in the past, so
    /// the first tick delivers, settles and evicts it; the second tick's
    /// commit is the one that no longer carries it.
    ///
    /// Mutation: skip the eviction step at the end of `flush_at` (the
    /// settled bucket then lingers, and so does the journal row's absence
    /// check on the in-memory side).
    #[test]
    fn restart_replay_restores_only_live_buckets() {
        let path = path();
        let store = ProbeStore::new();
        let live = TenantId::new("live");
        let old_tenant = TenantId::new("old");
        let old_key = Period::Daily.key_for(at(2020, 1, 5, 12, 0));
        {
            let accumulator = journaled_accumulator(&store, &path);
            accumulator.record(
                &old_tenant,
                at(2020, 1, 5, 12, 0),
                Period::Daily,
                Charge::Priced(MicroUsd::from_micros(10)),
                None,
                None,
            );
            charge(&accumulator, &live, 5);

            accumulator.flush_now().unwrap();
            assert_eq!(accumulator.inner.buckets.lock().unwrap().counts(), (1, 0));
            accumulator.flush_now().unwrap();
            let rows = accumulator.inner.journal.as_ref().unwrap().saved_rows();
            assert!(
                rows.iter().all(|(tenant, _, _)| *tenant != old_tenant),
                "the evicted bucket is no longer in the journal"
            );
        }
        let restarted = journaled_accumulator(&store, &path);
        let (active, settled) = restarted.inner.buckets.lock().unwrap().counts();
        assert_eq!(active + settled, 1, "only the live bucket was restored");
        assert_eq!(
            restarted.current_total(&live, &Period::Daily.key_for_now()),
            5
        );
        assert_eq!(
            store
                .inner
                .load_spend("chain", &old_tenant, &old_key)
                .unwrap(),
            10,
            "and the evicted period's spend is still in the store"
        );
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    /// A journal written before eviction existed holds every period the
    /// process ever saw. Replaying it must prune them: each historical row
    /// is reconciled once, settled, and evicted, and the live row survives
    /// with its pending spend delivered.
    ///
    /// Mutation: make `BucketMap::from_restored` leave `period_end` unset
    /// (the historical rows then never end and never leave).
    #[test]
    fn a_journal_from_before_eviction_is_pruned_on_replay() {
        let path = path();
        let store = ProbeStore::new();
        let live = TenantId::new("live");
        let (journal, _) = Journal::open(&path, "chain", "node").unwrap();
        let mut rows = HashMap::new();
        for day in 1..=3 {
            rows.insert(
                (
                    TenantId::new("old"),
                    Period::Daily.key_for(at(2020, 1, day, 12, 0)),
                ),
                Bucket::default(),
            );
        }
        rows.insert(
            (live.clone(), Period::Daily.key_for_now()),
            Bucket {
                pending_delta_micros: 9,
                ..Bucket::default()
            },
        );
        journal.save(&rows).unwrap();
        drop(journal);

        let recovered = journaled_accumulator(&store, &path);

        let (active, settled) = recovered.inner.buckets.lock().unwrap().counts();
        assert_eq!(active + settled, 1, "the three historical rows were pruned");
        assert_eq!(
            store
                .inner
                .load_spend("chain", &live, &Period::Daily.key_for_now())
                .unwrap(),
            9
        );
        recovered.flush_now().unwrap();
        assert_eq!(
            recovered.inner.journal.as_ref().unwrap().saved_rows().len(),
            1
        );
        drop(recovered);
        std::fs::remove_file(path).unwrap();
    }
}
