#[path = "support/redb_spool.rs"]
mod redb_spool;
use redb_spool::{Config, Error, Prototype, RECORDS, STATE};
fn config(dir: &std::path::Path) -> Config {
    Config {
        directory: dir.join("spool"),
        node_id: "test-node".into(),
        max_record_bytes: 4096,
        max_disk_bytes: 32 * 1024 * 1024,
        cache_bytes: 1024 * 1024,
    }
}
#[test]
fn invalid_resource_bounds_fail_before_creating_storage() {
    for change in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let mut c = config(dir.path());
        match change {
            0 => c.max_record_bytes = 524289,
            1 => c.cache_bytes = 0,
            2 => c.cache_bytes = 16 * 1024 * 1024 + 1,
            3 => c.node_id = "x".repeat(129),
            _ => c.max_disk_bytes = 0,
        }
        assert!(matches!(Prototype::open(c, [7; 32]), Err(Error::Invalid)));
        assert!(!dir.path().join("spool").exists());
    }
}
#[test]
fn reservation_survives_drop_without_committing_payload() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let mut spool = Prototype::open(c.clone(), [7; 32]).unwrap();
    assert_eq!(spool.append_batch(&[b"pending"]).unwrap(), [1]);
    assert_eq!(spool.stats().durable, 0);
    assert!(spool.replay(8, 4096).unwrap().is_empty());
    drop(spool);
    let mut spool = Prototype::open(c, [7; 32]).unwrap();
    assert_eq!(spool.stats().next_sequence, 2);
    assert_eq!(spool.append_batch(&[b"committed"]).unwrap(), [2]);
    assert_eq!(spool.commit().unwrap(), 2);
}
#[test]
fn groups_and_replay_bounds_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let mut spool = Prototype::open(c.clone(), [7; 32]).unwrap();
    spool.append_batch(&[b"one", b"two"]).unwrap();
    assert_eq!(spool.commit().unwrap(), 2);
    spool.append_batch(&[b"three"]).unwrap();
    assert_eq!(spool.commit().unwrap(), 3);
    drop(spool);
    let mut spool = Prototype::open(c, [7; 32]).unwrap();
    assert_eq!(spool.stats().count, 3);
    assert_eq!(spool.replay(1, 100).unwrap(), vec![(1, b"one".to_vec())]);
    assert_eq!(spool.replay(8, 5).unwrap().len(), 1);
    assert!(spool.replay(8, 2).unwrap().is_empty());
    assert_eq!(spool.replay(0, 100).unwrap().len(), 0);
}
#[test]
fn invalid_batches_do_not_reserve_or_poison() {
    let dir = tempfile::tempdir().unwrap();
    let mut spool = Prototype::open(config(dir.path()), [7; 32]).unwrap();
    assert!(matches!(spool.append_batch(&[]), Err(Error::Invalid)));
    assert!(spool.append_batch(&[&b"a"[..]; 9]).is_err());
    assert!(spool.append_batch(&[&vec![0; 4097]]).is_err());
    assert_eq!(spool.stats().next_sequence, 1);
    spool.append_batch(&[b"a"]).unwrap();
    assert!(spool.append_batch(&[b"b"]).is_err());
    assert!(!spool.stats().poisoned);
}
#[test]
fn lock_released_on_drop_and_identity_authenticated() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let spool = Prototype::open(c.clone(), [7; 32]).unwrap();
    assert!(Prototype::open(c.clone(), [7; 32]).is_err());
    drop(spool);
    assert!(matches!(
        Prototype::open(c.clone(), [8; 32]),
        Err(Error::Authentication)
    ));
    let mut wrong = c.clone();
    wrong.node_id = "other".into();
    assert!(Prototype::open(wrong, [7; 32]).is_err());
    assert!(Prototype::open(c, [7; 32]).is_ok());
}
#[test]
fn altered_or_missing_committed_data_fails_closed() {
    for mutation in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let c = config(dir.path());
        let mut spool = Prototype::open(c.clone(), [7; 32]).unwrap();
        spool.append_batch(&[b"secret"]).unwrap();
        spool.commit().unwrap();
        drop(spool);
        let db = redb::Database::create(c.directory.join("prototype.redb")).unwrap();
        let tx = db.begin_write().unwrap();
        if mutation == 0 {
            tx.open_table(RECORDS).unwrap().remove(1).unwrap();
        } else if mutation == 1 {
            tx.open_table(RECORDS)
                .unwrap()
                .insert(1, &[0u8; 34][..])
                .unwrap();
        } else if mutation == 2 {
            tx.open_table(STATE)
                .unwrap()
                .insert(0, &[0u8; 84][..])
                .unwrap();
        } else {
            tx.open_table(STATE)
                .unwrap()
                .insert(1, &[0u8; 84][..])
                .unwrap();
        }
        tx.commit().unwrap();
        drop(db);
        assert!(Prototype::open(c, [7; 32]).is_err());
    }
}
#[test]
fn sync_failure_never_returns_positive_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let mut spool = Prototype::open(c.clone(), [7; 32]).unwrap();
    spool.append_batch(&[b"older"]).unwrap();
    assert_eq!(spool.commit().unwrap(), 1);
    spool.append_batch(&[b"record"]).unwrap();
    spool.fail_next_sync();
    assert!(spool.commit().is_err());
    assert!(spool.stats().poisoned);
    assert_eq!(spool.stats().durable, 1);
    assert!(matches!(
        spool.append_batch(&[b"later"]),
        Err(Error::Poisoned)
    ));
    drop(spool);
    let mut reopened = Prototype::open(c, [7; 32]).unwrap();
    let replay = reopened.replay(8, 4096).unwrap();
    assert!(
        replay == vec![(1, b"older".to_vec())]
            || replay == vec![(1, b"older".to_vec()), (2, b"record".to_vec())]
    );
    assert_eq!(reopened.stats().next_sequence, 3);
}
#[test]
fn physical_quota_never_overruns_and_preserves_receipts() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(dir.path());
    c.max_disk_bytes = 2 * 1024 * 1024;
    let mut spool = Prototype::open(c.clone(), [7; 32]).unwrap();
    let payload = vec![1; 4096];
    let mut acked = 0;
    loop {
        match spool
            .append_batch(&[payload.as_slice(); 8])
            .and_then(|_| spool.commit())
        {
            Ok(seq) => acked = seq,
            Err(Error::Full) => break,
            Err(e) => panic!("{e}"),
        };
        assert!(acked < 10000);
    }
    assert!(spool.stats().poisoned);
    assert!(spool.stats().disk_bytes <= c.max_disk_bytes);
    assert!(acked > 0);
    drop(spool);
    let mut reopened = Prototype::open(c.clone(), [7; 32]).unwrap();
    let records = reopened.replay(10000, usize::MAX).unwrap();
    assert!(records.len() >= acked as usize);
    assert!(reopened.stats().disk_bytes <= c.max_disk_bytes);
}
#[test]
fn inventory_rejects_symlinks_and_unexpected_files() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    drop(Prototype::open(c.clone(), [7; 32]).unwrap());
    std::os::unix::fs::symlink("prototype.redb", c.directory.join("extra")).unwrap();
    assert!(Prototype::open(c, [7; 32]).is_err());
}
