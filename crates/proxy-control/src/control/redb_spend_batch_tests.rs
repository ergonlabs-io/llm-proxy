//! The redb store's spend batches against a storage backend that counts
//! syncs, which is what a durable commit costs on disk.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use redb::backends::InMemoryBackend;
use redb::StorageBackend;

use super::{ControlPlaneStore, FlushToken, RedbControlPlaneStore, SpendDelta};
use crate::auth::TenantId;
use crate::spend::PeriodKey;

/// redb's in-memory backend, counting `sync_data` calls.
#[derive(Debug)]
struct CountingBackend {
    inner: InMemoryBackend,
    syncs: Arc<AtomicUsize>,
}

impl StorageBackend for CountingBackend {
    fn len(&self) -> Result<u64, std::io::Error> {
        self.inner.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
        self.inner.read(offset, out)
    }

    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        self.inner.set_len(len)
    }

    fn sync_data(&self) -> Result<(), std::io::Error> {
        self.syncs.fetch_add(1, Ordering::SeqCst);
        self.inner.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        self.inner.write(offset, data)
    }
}

fn counted_store() -> (RedbControlPlaneStore, Arc<AtomicUsize>) {
    let syncs = Arc::new(AtomicUsize::new(0));
    let db = redb::Builder::new()
        .create_with_backend(CountingBackend {
            inner: InMemoryBackend::new(),
            syncs: Arc::clone(&syncs),
        })
        .expect("an in-memory backend opens");
    let store = RedbControlPlaneStore::from_database(db).expect("tables are created");
    (store, syncs)
}

/// The spend flusher delivers every dirty bucket as one batch per tick. On
/// redb that batch was one durable commit, so one fsync, per row: a thousand
/// active keys cost two thousand fsyncs every five seconds. It is now one
/// commit for the batch, and a batch of nothing but replays commits nothing.
///
/// Mutation: remove `RedbControlPlaneStore::add_spend_batch`, so the trait's
/// per-row default runs.
#[test]
fn a_redb_spend_batch_of_n_rows_commits_once() {
    let (store, syncs) = counted_store();
    let period = PeriodKey::for_test("2026-10");
    let synced = || syncs.load(Ordering::SeqCst);

    let before = synced();
    store
        .add_spend(
            "chain",
            &TenantId::new("warm-up"),
            &period,
            1,
            FlushToken {
                node_id: "node-a",
                seq: 1,
            },
        )
        .unwrap();
    let one_commit = synced() - before;
    assert!(one_commit > 0, "a durable commit syncs the backend");

    let tenants: Vec<TenantId> = (0..50)
        .map(|i| TenantId::new(format!("tenant-{i}")))
        .collect();
    let rows: Vec<SpendDelta<'_>> = tenants
        .iter()
        .enumerate()
        .map(|(i, tenant)| SpendDelta {
            tenant,
            period: &period,
            delta_micros: i as u64 + 1,
            seq: 1,
        })
        .collect();
    let before = synced();
    let totals = store.add_spend_batch("chain", "node-a", &rows);
    assert_eq!(synced() - before, one_commit, "50 rows, one commit");
    let expected: Vec<_> = (1..=50).map(Ok).collect();
    assert_eq!(totals, expected, "each row got its own delta");

    let before = synced();
    let replayed = store.add_spend_batch("chain", "node-a", &rows);
    assert_eq!(replayed, expected, "a replay answers the stored totals");
    assert_eq!(synced() - before, 0, "and commits nothing");

    let keys: Vec<(TenantId, PeriodKey)> = tenants
        .iter()
        .map(|tenant| (tenant.clone(), period.clone()))
        .collect();
    assert_eq!(store.load_spend_batch("chain", &keys), expected);
    assert_eq!(
        store.last_flush_seq_batch("chain", "node-a", &keys),
        vec![Ok(1); 50]
    );
}
