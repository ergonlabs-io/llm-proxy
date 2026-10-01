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

pub(super) struct Journal {
    db: Database,
    stat_prefix: String,
    node_id: String,
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
        let checkpoint = Checkpoint {
            version: 1,
            stat_prefix: self.stat_prefix.clone(),
            node_id: self.node_id.clone(),
            rows: buckets
                .iter()
                .map(|((subject, period), bucket)| Row {
                    subject: subject.as_str().into(),
                    period: period.as_str().into(),
                    bucket: bucket.clone(),
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
        txn.commit().map_err(store_err)
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
}
