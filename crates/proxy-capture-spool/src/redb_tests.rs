use super::*;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tempfile::TempDir;

const CHILD_ROOT: &str = "LLMPROXY_REDB_CRASH_ROOT";
const CHILD_STAGE: &str = "LLMPROXY_REDB_CRASH_STAGE";
const CHILD_READY: &str = "LLMPROXY_REDB_CRASH_READY";
const PAYLOAD: &[u8] = b"durable capture metadata";

fn test_config(temp: &TempDir) -> SpoolConfig {
    SpoolConfig {
        directory: temp.path().join("spool"),
        node_id: "node-1".into(),
        max_record_bytes: 256,
        max_disk_bytes: 8 * 1024 * 1024,
        cache_bytes: DEFAULT_CACHE_BYTES,
        max_pending_records: 8,
    }
}

fn key() -> EncryptionKey {
    EncryptionKey::new("key-1", [7; 32]).unwrap()
}

fn alternate_key() -> EncryptionKey {
    EncryptionKey::new("key-2", [9; 32]).unwrap()
}

fn open(config: SpoolConfig) -> MetadataSpool {
    MetadataSpool::open(config, key(), []).unwrap()
}

fn payloads(spool: &MetadataSpool) -> Vec<(u64, Vec<u8>)> {
    spool
        .replay(0, 100, 1024)
        .unwrap()
        .into_iter()
        .map(|record| (record.sequence, record.payload))
        .collect()
}

#[test]
fn committed_records_reopen_replay_and_acknowledge_monotonically() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let mut spool = open(config.clone());
    assert_eq!(spool.append(b"one").unwrap().sequence, 1);
    assert_eq!(spool.append(b"two").unwrap().sequence, 2);
    assert_eq!(spool.stats().unwrap().pending_records, 2);
    assert!(payloads(&spool).is_empty());
    assert_eq!(spool.commit().unwrap().through_sequence, 2);
    let stats = spool.stats().unwrap();
    assert_eq!(stats.pending_records, 0);
    assert_eq!(stats.retained_records, 2);
    assert_eq!(stats.durable_through_sequence, 2);
    assert_eq!(stats.acknowledged_through_sequence, 0);
    drop(spool);

    let mut spool = open(config.clone());
    assert_eq!(
        payloads(&spool),
        vec![(1, b"one".to_vec()), (2, b"two".to_vec())]
    );
    spool.acknowledge(1).unwrap();
    assert_eq!(payloads(&spool), vec![(2, b"two".to_vec())]);
    let stats = spool.stats().unwrap();
    assert_eq!(stats.acknowledged_through_sequence, 1);
    assert_eq!(stats.retained_records, 1);
    drop(spool);

    let mut spool = open(config);
    assert_eq!(payloads(&spool), vec![(2, b"two".to_vec())]);
    spool.acknowledge(2).unwrap();
    spool.acknowledge(1).unwrap();
    assert!(payloads(&spool).is_empty());
    assert_eq!(spool.append(b"three").unwrap().sequence, 3);
}

#[test]
fn pending_records_are_not_committed_on_drop_but_reservations_survive() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"lost pending").unwrap();
    assert!(matches!(
        spool.acknowledge(1),
        Err(Error::InvalidAcknowledgement)
    ));
    drop(spool);

    let mut spool = open(config);
    assert!(payloads(&spool).is_empty());
    assert_eq!(spool.stats().unwrap().next_sequence, 2);
    assert_eq!(spool.append(b"replacement").unwrap().sequence, 2);
    spool.seal().unwrap();
    assert_eq!(payloads(&spool), vec![(2, b"replacement".to_vec())]);
}

#[test]
fn append_bounds_and_batch_reservation_have_explicit_sequence_semantics() {
    let temp = TempDir::new().unwrap();
    let mut spool = open(test_config(&temp));
    assert!(matches!(
        spool.append(&[0; 257]),
        Err(Error::RecordTooLarge)
    ));
    assert_eq!(spool.stats().unwrap().next_sequence, 1);
    assert!(spool.append_batch(&[b"x".as_slice(); 9]).is_err());
    assert_eq!(spool.stats().unwrap().next_sequence, 1);

    let oversized = [0; 257];
    let batch = spool
        .append_batch(&[b"first", &oversized, b"third"])
        .unwrap();
    assert_eq!(batch[0].as_ref().unwrap().sequence, 1);
    assert!(matches!(batch[1], Err(Error::RecordTooLarge)));
    assert_eq!(batch[2].as_ref().unwrap().sequence, 3);
    assert_eq!(spool.stats().unwrap().next_sequence, 4);
    spool.commit().unwrap();
    assert_eq!(
        payloads(&spool),
        vec![(1, b"first".to_vec()), (3, b"third".to_vec())]
    );
}

#[test]
fn pending_limit_is_shared_across_calls_and_full_does_not_reserve() {
    let temp = TempDir::new().unwrap();
    let mut spool = open(test_config(&temp));
    for sequence in 1..=7 {
        assert_eq!(spool.append(b"pending").unwrap().sequence, sequence);
    }
    let batch = spool.append_batch(&[b"a", b"b"]).unwrap_err();
    assert!(matches!(batch, Error::Full));
    assert_eq!(spool.stats().unwrap().next_sequence, 8);
    assert_eq!(spool.stats().unwrap().pending_records, 7);
    assert_eq!(spool.append(b"eighth").unwrap().sequence, 8);
    assert!(matches!(spool.append(b"ninth"), Err(Error::Full)));
    assert_eq!(spool.stats().unwrap().next_sequence, 9);
    spool.commit().unwrap();
    assert_eq!(spool.stats().unwrap().retained_records, 8);
}

#[test]
fn replay_respects_cursor_record_and_byte_bounds() {
    let temp = TempDir::new().unwrap();
    let mut spool = open(test_config(&temp));
    for payload in [b"abc".as_slice(), b"defg", b"hij"] {
        spool.append(payload).unwrap();
    }
    spool.commit().unwrap();
    assert!(spool.replay(0, 0, 100).unwrap().is_empty());
    assert!(spool.replay(0, 10, 0).unwrap().is_empty());
    assert!(spool.replay(0, 10, 2).unwrap().is_empty());
    assert_eq!(spool.replay(0, 1, 100).unwrap().len(), 1);
    assert_eq!(spool.replay(0, 10, 7).unwrap().len(), 2);
    assert_eq!(
        spool
            .replay(1, 10, 16)
            .unwrap()
            .iter()
            .map(|record| record.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert!(spool.replay(3, usize::MAX, usize::MAX).unwrap().is_empty());
}

#[test]
fn duplicate_or_unavailable_keys_fail_without_discarding_the_database() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let mut spool = open(config.clone());
    spool.append(PAYLOAD).unwrap();
    spool.commit().unwrap();
    drop(spool);

    assert!(matches!(
        MetadataSpool::open(config.clone(), key(), [key()]),
        Err(Error::DuplicateKey)
    ));
    let new_key = || EncryptionKey::new("key-2", [9; 32]).unwrap();
    assert!(matches!(
        MetadataSpool::open(config.clone(), new_key(), []),
        Err(Error::MissingKey)
    ));
    assert!(config.directory.join(DATABASE).exists());
    assert!(!config.directory.join(QUARANTINE).exists());

    let spool = MetadataSpool::open(config, new_key(), [key()]).unwrap();
    assert_eq!(payloads(&spool), vec![(1, PAYLOAD.to_vec())]);
}

#[test]
fn authenticated_state_corruption_quarantines_the_whole_database() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let mut spool = open(config.clone());
    spool.append(PAYLOAD).unwrap();
    spool.commit().unwrap();
    drop(spool);

    let path = config.directory.join(DATABASE);
    let database = Database::open(&path).unwrap();
    let envelope = {
        let tx = database.begin_read().unwrap();
        let table = tx.open_table(STATE).unwrap();
        table.get(0).unwrap().unwrap().value().to_vec()
    };
    drop(database);
    let mut damaged = envelope;
    *damaged.last_mut().unwrap() ^= 1;
    let database = Database::open(&path).unwrap();
    let tx = database.begin_write().unwrap();
    tx.open_table(STATE)
        .unwrap()
        .insert(0, damaged.as_slice())
        .unwrap();
    tx.commit().unwrap();
    drop(database);

    assert!(matches!(
        MetadataSpool::open(config.clone(), key(), []),
        Err(Error::Corrupt)
    ));
    assert!(!path.exists());
    assert!(config.directory.join(QUARANTINE).exists());
    assert!(matches!(
        MetadataSpool::open(config, key(), []),
        Err(Error::Quarantined)
    ));
}

#[test]
fn empty_database_and_unrecognized_inventory_fail_closed() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    fs::create_dir(&config.directory).unwrap();
    fs::set_permissions(&config.directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(config.directory.join(DATABASE), []).unwrap();
    assert!(matches!(
        MetadataSpool::open(config.clone(), key(), []),
        Err(Error::Corrupt)
    ));

    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    drop(open(config.clone()));
    fs::write(config.directory.join("unrecognized"), b"data").unwrap();
    assert!(matches!(
        MetadataSpool::open(config.clone(), key(), []),
        Err(Error::Corrupt)
    ));
    assert!(config.directory.join(DATABASE).exists());
    assert!(!config.directory.join(QUARANTINE).exists());
}

#[test]
fn config_bounds_reject_small_disk_pending_limits_and_oversized_database_cache() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    config.max_disk_bytes = MIN_DISK_BYTES - 1;
    assert!(matches!(
        MetadataSpool::open(config.clone(), key(), []),
        Err(Error::InvalidConfig(_))
    ));
    config.max_disk_bytes = 8 * 1024 * 1024;
    for pending in [0, MAX_PENDING_RECORDS + 1] {
        let mut config = config.clone();
        config.max_pending_records = pending;
        assert!(matches!(
            MetadataSpool::open(config, key(), []),
            Err(Error::InvalidConfig(_))
        ));
    }
    config.cache_bytes = MAX_CACHE_BYTES + 1;
    assert!(matches!(
        MetadataSpool::open(config, key(), []),
        Err(Error::InvalidConfig(_))
    ));
}

#[test]
fn writer_lock_is_exclusive_and_released_on_drop() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let spool = open(config.clone());
    assert!(matches!(
        MetadataSpool::open(config.clone(), key(), []),
        Err(Error::Locked)
    ));
    drop(spool);
    let mut spool = open(config);
    assert_eq!(spool.append(b"after reopen").unwrap().sequence, 1);
}

/// Commits `payload` records one batch at a time until the disk ceiling refuses
/// a commit. Returns the sequences that committed and the batch left pending.
fn fill_to_cap(spool: &mut MetadataSpool, payload: &[u8], batch: usize) -> (Vec<u64>, usize) {
    let mut committed = Vec::new();
    for _ in 0..256 {
        let mut appended = Vec::new();
        for _ in 0..batch {
            match spool.append(payload) {
                Ok(receipt) => appended.push(receipt.sequence),
                Err(Error::Full) => return (committed, appended.len()),
                Err(error) => panic!("append failed with {error:?}, not Full"),
            }
        }
        match spool.commit() {
            Ok(_) => committed.extend(appended),
            Err(Error::Full) => return (committed, appended.len()),
            Err(error) => panic!("commit failed with {error:?}, not Full"),
        }
    }
    panic!("the disk ceiling never refused a commit");
}

#[test]
fn disk_cap_refuses_admissions_without_poisoning_until_an_ack_reclaims_space() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    config.max_record_bytes = 16 * 1024;
    config.max_disk_bytes = 4 * 1024 * 1024;
    let mut spool = open(config.clone());
    let payload = vec![0x5a; config.max_record_bytes];
    // Three fill-and-drain cycles: each refill needs the pages the previous
    // acknowledgement freed, so the file cannot simply keep growing.
    for cycle in 0..3 {
        let (committed, pending) = fill_to_cap(&mut spool, &payload, 4);
        assert!(committed.len() >= 8, "cycle {cycle} filled too little");
        let stats = spool.stats().unwrap();
        assert!(!stats.poisoned, "a full disk must not poison the handle");
        assert!(stats.disk_bytes <= config.max_disk_bytes);
        assert_eq!(stats.pending_records, pending as u64);
        // Admissions stay refused while at the ceiling; reads still work.
        assert!(matches!(spool.append(b"while full"), Err(Error::Full)));
        let replayed: Vec<u64> = spool
            .replay(0, 1024, usize::MAX)
            .unwrap()
            .iter()
            .map(|row| row.sequence)
            .collect();
        assert_eq!(replayed, committed, "cycle {cycle} lost a committed row");

        spool.acknowledge(*committed.last().unwrap()).unwrap();
        assert!(payloads(&spool).is_empty());
        // The records refused at the ceiling are still pending and now publish.
        let durable = spool.commit().unwrap().through_sequence;
        assert_eq!(spool.stats().unwrap().pending_records, 0);
        assert_eq!(
            spool.replay(0, 1024, usize::MAX).unwrap().len(),
            pending,
            "cycle {cycle}"
        );
        spool.acknowledge(durable).unwrap();
    }
    let last = spool.append(b"after three cycles").unwrap().sequence;
    spool.commit().unwrap();
    drop(spool);
    let reopened = open(config);
    assert_eq!(
        payloads(&reopened),
        vec![(last, b"after three cycles".to_vec())]
    );
}

#[test]
fn a_batch_larger_than_eight_commits_in_one_transaction() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    config.max_record_bytes = 16 * 1024;
    config.max_disk_bytes = 4 * 1024 * 1024;
    config.max_pending_records = 512;
    let mut spool = open(config.clone());
    let payload = vec![0x33; config.max_record_bytes];
    let batch = vec![payload.as_slice(); 40];
    assert!(spool
        .append_batch(&batch)
        .unwrap()
        .iter()
        .all(Result::is_ok));
    assert_eq!(spool.commit().unwrap().through_sequence, 40);
    assert_eq!(spool.replay(0, 1024, usize::MAX).unwrap().len(), 40);

    // 300 records outgrow the 4 MiB ceiling: committing them in smaller
    // transactions would publish a prefix before the refusal.
    let oversized = vec![payload.as_slice(); 300];
    assert!(spool
        .append_batch(&oversized)
        .unwrap()
        .iter()
        .all(Result::is_ok));
    assert!(matches!(spool.commit(), Err(Error::Full)));
    assert_eq!(spool.replay(0, 1024, usize::MAX).unwrap().len(), 40);
    drop(spool);
    assert_eq!(
        open(config).replay(0, 1024, usize::MAX).unwrap().len(),
        40,
        "a refused batch must publish none of its records"
    );
}

#[test]
fn fail_hooks_poison_ambiguous_mutations_and_reopen_to_atomic_state() {
    for (fault, operation, expected) in [
        (Fault::ReserveAfterCommit, "reserve", 1),
        (Fault::Encrypt, "encrypt", 1),
        (Fault::CommitBeforeCommit, "commit-before", 2),
        (Fault::CommitAfterCommit, "commit-after", 2),
        (Fault::AcknowledgeBeforeCommit, "ack-before", 1),
        (Fault::AcknowledgeAfterCommit, "ack-after", 1),
    ] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let hooks = Arc::new(Hooks::default());
        let mut spool =
            MetadataSpool::open_with_hooks(config.clone(), key(), [], hooks.clone()).unwrap();
        if operation.starts_with("commit") || operation.starts_with("ack") {
            spool.append(b"prefix").unwrap();
            spool.commit().unwrap();
        }
        if operation.starts_with("ack") {
            hooks.fail(fault);
            assert!(spool.acknowledge(1).is_err());
        } else {
            if operation == "commit-before" || operation == "commit-after" {
                spool.append(b"next").unwrap();
            }
            hooks.fail(fault);
            if operation == "commit-before" || operation == "commit-after" {
                assert!(spool.commit().is_err());
            } else {
                assert!(spool.append(b"next").is_err());
            }
        }
        assert!(spool.stats().unwrap().poisoned);
        drop(spool);
        let recovered = open(config);
        assert_eq!(recovered.stats().unwrap().next_sequence, expected + 1);
        match operation {
            "commit-after" => assert_eq!(payloads(&recovered).len(), 2),
            "commit-before" => assert_eq!(payloads(&recovered).len(), 1),
            "ack-after" => assert!(payloads(&recovered).is_empty()),
            "ack-before" => assert_eq!(payloads(&recovered).len(), 1),
            _ => assert!(payloads(&recovered).is_empty()),
        }
    }
}

#[test]
fn initialization_hooks_leave_either_no_database_or_a_recoverable_initial_state() {
    for fault in [
        Fault::InitializeBeforeCommit,
        Fault::InitializeAfterCommit,
        Fault::InitializeDirectorySync,
    ] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let hooks = Arc::new(Hooks::default());
        hooks.fail(fault);
        assert!(MetadataSpool::open_with_hooks(config.clone(), key(), [], hooks).is_err());

        match MetadataSpool::open(config.clone(), key(), []) {
            Ok(spool) => {
                assert_eq!(spool.stats().unwrap().next_sequence, 1);
                assert!(payloads(&spool).is_empty());
            }
            Err(Error::Corrupt) if fault == Fault::InitializeBeforeCommit => {
                assert!(config.directory.join(QUARANTINE).exists());
                assert!(matches!(
                    MetadataSpool::open(config, key(), []),
                    Err(Error::Quarantined)
                ));
            }
            Err(error) => panic!("unexpected initialization recovery: {error:?}"),
        }
    }
}

#[test]
fn rewrap_and_quarantine_fail_hooks_preserve_the_last_committed_transition() {
    for fault in [Fault::RewrapBeforeCommit, Fault::RewrapAfterCommit] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let mut spool = open(config.clone());
        spool.append(PAYLOAD).unwrap();
        spool.commit().unwrap();
        drop(spool);

        let hooks = Arc::new(Hooks::default());
        hooks.fail(fault);
        assert!(
            MetadataSpool::open_with_hooks(config.clone(), alternate_key(), [key()], hooks)
                .is_err()
        );
        let persisted_state_key = state_key_id(&config.directory.join(DATABASE));
        let with_recovery_key =
            MetadataSpool::open(config.clone(), alternate_key(), [key()]).unwrap();
        assert_eq!(payloads(&with_recovery_key), vec![(1, PAYLOAD.to_vec())]);
        drop(with_recovery_key);
        match fault {
            Fault::RewrapBeforeCommit => assert_eq!(persisted_state_key, "key-1"),
            Fault::RewrapAfterCommit => assert_eq!(persisted_state_key, "key-2"),
            _ => unreachable!(),
        }
    }

    for fault in [Fault::QuarantineRename, Fault::QuarantineDirectorySync] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let mut spool = open(config.clone());
        spool.append(PAYLOAD).unwrap();
        spool.commit().unwrap();
        drop(spool);
        corrupt_state_envelope(&config.directory.join(DATABASE));

        let hooks = Arc::new(Hooks::default());
        hooks.fail(fault);
        assert!(MetadataSpool::open_with_hooks(config.clone(), key(), [], hooks).is_err());
        match fault {
            Fault::QuarantineRename => {
                assert!(config.directory.join(DATABASE).exists());
                assert!(!config.directory.join(QUARANTINE).exists());
                assert!(matches!(
                    MetadataSpool::open(config.clone(), key(), []),
                    Err(Error::Corrupt)
                ));
            }
            Fault::QuarantineDirectorySync => {
                assert!(!config.directory.join(DATABASE).exists());
                assert!(config.directory.join(QUARANTINE).exists());
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            MetadataSpool::open(config, key(), []),
            Err(Error::Quarantined)
        ));
    }
}

#[test]
fn backend_failures_are_storage_errors_and_keep_the_durable_prefix() {
    for fault in [
        Fault::BackendWrite,
        Fault::BackendPartialWrite,
        Fault::BackendResize,
        Fault::BackendAfterResize,
        Fault::BackendSync,
        Fault::BackendAfterSync,
    ] {
        let temp = TempDir::new().unwrap();
        let mut config = test_config(&temp);
        config.max_record_bytes = 512 * 1024;
        let mut prefix = open(config.clone());
        prefix.append(b"durable prefix").unwrap();
        prefix.commit().unwrap();
        drop(prefix);

        let hooks = Arc::new(Hooks::default());
        let mut spool =
            MetadataSpool::open_with_hooks(config.clone(), key(), [], hooks.clone()).unwrap();
        hooks.fail(fault);
        // Four MiB of records cannot fit the file as opened, so publishing
        // them reaches every backend step, including growth.
        let large = vec![0x42; config.max_record_bytes];
        let result = spool
            .append_batch(&[large.as_slice(); 8])
            .and_then(|_| spool.commit());
        assert!(
            matches!(result, Err(Error::Io(_)) | Err(Error::Storage(_))),
            "{fault:?}: {result:?}"
        );
        assert!(spool.stats().unwrap().poisoned);
        drop(spool);

        let mut recovered = open(config);
        assert_eq!(payloads(&recovered), vec![(1, b"durable prefix".to_vec())]);
        assert!(recovered.append(b"next").unwrap().sequence >= 2);
    }
}

#[test]
fn key_count_and_cache_limits_are_bounded() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let recovery_keys = (0..MAX_ENCRYPTION_KEYS - 1)
        .map(|index| EncryptionKey::new(format!("recovery-{index}"), [index as u8; 32]).unwrap());
    drop(MetadataSpool::open(config.clone(), key(), recovery_keys).unwrap());

    let recovery_keys = (0..MAX_ENCRYPTION_KEYS)
        .map(|index| EncryptionKey::new(format!("excess-{index}"), [index as u8; 32]).unwrap());
    assert!(matches!(
        MetadataSpool::open(config, key(), recovery_keys),
        Err(Error::InvalidConfig(_))
    ));
}

#[test]
fn empty_payload_is_a_retained_record_and_replays_with_zero_payload_bytes() {
    let temp = TempDir::new().unwrap();
    let mut spool = open(test_config(&temp));
    spool.append(b"").unwrap();
    spool.append(b"x").unwrap();
    spool.commit().unwrap();
    let replay = spool.replay(0, 2, 1).unwrap();
    assert_eq!(replay.len(), 2);
    assert_eq!(replay[0].sequence, 1);
    assert!(replay[0].payload.is_empty());
    assert_eq!(replay[1].payload, b"x");
}

#[test]
fn authenticated_record_and_inventory_corruption_quarantines_the_database() {
    for damage in ["envelope", "missing-row"] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let mut spool = open(config.clone());
        spool.append(PAYLOAD).unwrap();
        spool.commit().unwrap();
        drop(spool);
        let path = config.directory.join(DATABASE);
        if damage == "envelope" {
            corrupt_record_envelope(&path, 1);
        } else {
            let database = Database::open(&path).unwrap();
            let tx = database.begin_write().unwrap();
            {
                tx.open_table(RECORDS).unwrap().remove(1).unwrap();
            }
            tx.commit().unwrap();
        }
        assert!(matches!(
            MetadataSpool::open(config.clone(), key(), []),
            Err(Error::Corrupt)
        ));
        assert!(!path.exists());
        assert!(config.directory.join(QUARANTINE).exists());
    }
}

#[test]
fn unsupported_format_and_identity_errors_fail_without_quarantining() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    drop(open(config.clone()));
    set_state_envelope(&config.directory.join(DATABASE), |mut envelope| {
        envelope[8..12].copy_from_slice(&2_u32.to_le_bytes());
        envelope
    });
    assert!(matches!(
        MetadataSpool::open(config.clone(), key(), []),
        Err(Error::UnknownVersion(2))
    ));
    assert!(config.directory.join(DATABASE).exists());
    assert!(!config.directory.join(QUARANTINE).exists());

    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    drop(open(config.clone()));
    let mut other_node = config.clone();
    other_node.node_id = "other-node".into();
    assert!(matches!(
        MetadataSpool::open(other_node, key(), []),
        Err(Error::Corrupt)
    ));
    assert!(config.directory.join(QUARANTINE).exists());

    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    drop(open(config.clone()));
    assert!(matches!(
        MetadataSpool::open(
            config.clone(),
            EncryptionKey::new("key-1", [8; 32]).unwrap(),
            []
        ),
        Err(Error::Corrupt)
    ));
    assert!(config.directory.join(QUARANTINE).exists());
}

#[test]
fn authenticated_but_inconsistent_inventory_digest_is_quarantined() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let mut spool = open(config.clone());
    spool.append(PAYLOAD).unwrap();
    spool.commit().unwrap();
    drop(spool);

    rewrite_state_plaintext(&config.directory.join(DATABASE), "node-1", |mut plain| {
        let digest_start = plain.len() - 32;
        plain[digest_start] ^= 1;
        plain
    });
    assert!(matches!(
        MetadataSpool::open(config.clone(), key(), []),
        Err(Error::Corrupt)
    ));
    assert!(config.directory.join(QUARANTINE).exists());
}

#[test]
fn replay_authentication_failure_poison_blocks_writes_until_reopen() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let mut spool = open(config.clone());
    spool.append(PAYLOAD).unwrap();
    spool.commit().unwrap();
    corrupt_record_envelope_in_database(spool.db().unwrap(), 1);
    assert!(matches!(spool.replay(0, 10, 1024), Err(Error::Corrupt)));
    assert!(spool.stats().unwrap().poisoned);
    assert!(matches!(spool.append(b"unsafe"), Err(Error::Poisoned)));
}

#[test]
fn full_acknowledgement_retires_old_record_keys() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let mut spool = open(config.clone());
    spool.append(PAYLOAD).unwrap();
    spool.commit().unwrap();
    drop(spool);

    let mut rotated = MetadataSpool::open(config.clone(), alternate_key(), [key()]).unwrap();
    rotated.acknowledge(1).unwrap();
    assert_eq!(rotated.stats().unwrap().retained_records, 0);
    drop(rotated);
    let recovered = MetadataSpool::open(config, alternate_key(), []).unwrap();
    assert!(payloads(&recovered).is_empty());
}

/// The application row is the caller's durable state outside the record
/// stream: it survives a reopen and acknowledging every record, and a key
/// rotation rewraps it, so it opens once the old key is retired.
#[test]
fn application_state_survives_acknowledgement_reopen_and_key_rotation() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let mut spool = open(config.clone());
    assert_eq!(spool.application_state(), None);
    spool.set_application_state(b"first").unwrap();
    spool.set_application_state(b"epoch 7 open").unwrap();
    spool.append(PAYLOAD).unwrap();
    spool.commit().unwrap();
    spool.acknowledge(1).unwrap();
    assert!(matches!(
        spool.set_application_state(&vec![0; config.max_record_bytes + 1]),
        Err(Error::RecordTooLarge)
    ));
    drop(spool);

    let rotated = MetadataSpool::open(config.clone(), alternate_key(), [key()]).unwrap();
    assert_eq!(rotated.application_state(), Some(&b"epoch 7 open"[..]));
    drop(rotated);
    let retired = MetadataSpool::open(config, alternate_key(), []).unwrap();
    assert_eq!(retired.application_state(), Some(&b"epoch 7 open"[..]));
}

#[cfg(unix)]
#[test]
fn symlink_entries_are_rejected_by_strict_inventory() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    drop(open(config.clone()));
    symlink(temp.path(), config.directory.join("unexpected-link")).unwrap();
    assert!(matches!(
        MetadataSpool::open(config, key(), []),
        Err(Error::Corrupt)
    ));
}

#[cfg(unix)]
struct KillOnDrop(Child);
#[cfg(unix)]
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
fn crash_at(root: &Path, stage: &str) {
    use std::os::unix::process::ExitStatusExt;
    let marker = root.join("ready");
    let mut child = KillOnDrop(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::redb_crash_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ROOT, root)
            .env(CHILD_STAGE, stage)
            .env(CHILD_READY, &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !marker.exists() {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("redb crash child exited before {stage}: {status}");
        }
        assert!(Instant::now() < deadline, "redb crash child missed {stage}");
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().unwrap();
    assert_eq!(child.0.wait().unwrap().signal(), Some(9));
}

#[cfg(unix)]
fn child_stage(stage: &str, root: &Path, marker: &Path) {
    let config = SpoolConfig {
        directory: root.join("spool"),
        node_id: "node-1".into(),
        max_record_bytes: 256,
        max_disk_bytes: 8 * 1024 * 1024,
        cache_bytes: DEFAULT_CACHE_BYTES,
        max_pending_records: 8,
    };
    let hooks = Arc::new(Hooks::default());
    let (fault, operation) = match stage {
        "initialize-before" => (Fault::InitializeBeforeCommit, "open-old"),
        "initialize-after" => (Fault::InitializeAfterCommit, "open-old"),
        "reserve-before" => (Fault::ReserveBeforeCommit, "append"),
        "reserve-after" => (Fault::ReserveAfterCommit, "append"),
        "encrypt" => (Fault::Encrypt, "append"),
        "commit-before" => (Fault::CommitBeforeCommit, "commit"),
        "commit-after" => (Fault::CommitAfterCommit, "commit"),
        "rewrap-before" => (Fault::RewrapBeforeCommit, "rewrap-old"),
        "rewrap-after" => (Fault::RewrapAfterCommit, "rewrap-old"),
        "ack-before" => (Fault::AcknowledgeBeforeCommit, "ack"),
        "ack-after" => (Fault::AcknowledgeAfterCommit, "ack"),
        "quarantine-rename" => (Fault::QuarantineRename, "quarantine"),
        "quarantine-sync" => (Fault::QuarantineDirectorySync, "quarantine"),
        "backend-reserve-sync-before" => (Fault::BackendSync, "append"),
        "backend-reserve-sync-after" => (Fault::BackendAfterSync, "append"),
        "backend-commit-sync-before" => (Fault::BackendSync, "commit-hooked"),
        "backend-commit-sync-after" => (Fault::BackendAfterSync, "commit-hooked"),
        "backend-ack-sync-before" => (Fault::BackendSync, "ack"),
        "backend-ack-sync-after" => (Fault::BackendAfterSync, "ack"),
        "backend-rewrap-sync-before" => (Fault::BackendSync, "rewrap-old"),
        "backend-rewrap-sync-after" => (Fault::BackendAfterSync, "rewrap-old"),
        "backend-initialize-sync-before" => (Fault::BackendSync, "open-old"),
        "backend-initialize-sync-after" => (Fault::BackendAfterSync, "open-old"),
        _ => panic!("unknown redb crash stage {stage}"),
    };
    if operation != "commit-hooked" {
        hooks.pause(fault, marker.to_path_buf());
    }
    match operation {
        "open-old" => {
            let _ = MetadataSpool::open_with_hooks(config, key(), [], hooks);
        }
        "append" => {
            let mut spool = MetadataSpool::open_with_hooks(config, key(), [], hooks).unwrap();
            let _ = spool.append(PAYLOAD);
        }
        "commit" => {
            let mut spool = MetadataSpool::open_with_hooks(config, key(), [], hooks).unwrap();
            spool.append(PAYLOAD).unwrap();
            let _ = spool.commit();
        }
        "commit-hooked" => {
            let mut spool =
                MetadataSpool::open_with_hooks(config, key(), [], hooks.clone()).unwrap();
            spool.append(PAYLOAD).unwrap();
            spool.hooks.pause(fault, marker.to_path_buf());
            let _ = spool.commit();
        }
        "rewrap-old" => {
            let _ = MetadataSpool::open_with_hooks(config, alternate_key(), [key()], hooks);
        }
        "ack" => {
            let mut spool = MetadataSpool::open_with_hooks(config, key(), [], hooks).unwrap();
            let _ = spool.acknowledge(1);
        }
        "quarantine" => {
            let _ = MetadataSpool::open_with_hooks(config, key(), [], hooks);
        }
        _ => unreachable!(),
    }
}

#[cfg(unix)]
#[test]
fn redb_crash_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let stage = std::env::var(CHILD_STAGE).unwrap();
    let marker = PathBuf::from(std::env::var_os(CHILD_READY).unwrap());
    child_stage(&stage, &root, &marker);
    panic!("crash hook returned without being killed");
}

#[cfg(unix)]
#[test]
fn sigkill_at_initialization_reservation_encrypt_and_commit_boundaries_recovers_prefix() {
    for stage in [
        "initialize-before",
        "initialize-after",
        "reserve-before",
        "reserve-after",
        "encrypt",
        "commit-before",
        "commit-after",
    ] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        if !stage.starts_with("initialize") {
            let mut spool = open(config.clone());
            spool.append(b"earlier durable prefix").unwrap();
            spool.commit().unwrap();
            drop(spool);
        }
        crash_at(temp.path(), stage);
        let recovered = match MetadataSpool::open(config.clone(), key(), []) {
            Ok(spool) => spool,
            Err(Error::Corrupt) if stage == "initialize-before" => {
                assert!(config.directory.join(QUARANTINE).exists());
                continue;
            }
            Err(error) => panic!("unexpected recovery result at {stage}: {error:?}"),
        };
        let records = payloads(&recovered);
        if stage.starts_with("initialize") {
            assert!(records.is_empty());
        } else {
            assert_eq!(
                records.first().unwrap(),
                &(1, b"earlier durable prefix".to_vec())
            );
        }
        match stage {
            "reserve-before" => assert_eq!(recovered.stats().unwrap().next_sequence, 2),
            "reserve-after" | "encrypt" => assert_eq!(recovered.stats().unwrap().next_sequence, 3),
            "commit-before" => assert_eq!(recovered.stats().unwrap().next_sequence, 3),
            "commit-after" => {
                assert_eq!(recovered.stats().unwrap().next_sequence, 3);
                assert_eq!(records.len(), 2);
            }
            _ => assert_eq!(recovered.stats().unwrap().next_sequence, 1),
        }
    }
}

#[cfg(unix)]
#[test]
fn sigkill_during_rewrap_and_acknowledgement_keeps_one_atomic_state() {
    for stage in ["rewrap-before", "rewrap-after", "ack-before", "ack-after"] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let mut spool = open(config.clone());
        spool.append(PAYLOAD).unwrap();
        spool.commit().unwrap();
        drop(spool);
        crash_at(temp.path(), stage);

        if stage.starts_with("rewrap") {
            assert_eq!(
                state_key_id(&config.directory.join(DATABASE)),
                if stage == "rewrap-before" {
                    "key-1"
                } else {
                    "key-2"
                }
            );
            let spool = MetadataSpool::open(config.clone(), alternate_key(), [key()]).unwrap();
            assert_eq!(payloads(&spool), vec![(1, PAYLOAD.to_vec())]);
        } else {
            let spool = open(config);
            if stage == "ack-before" {
                assert_eq!(payloads(&spool), vec![(1, PAYLOAD.to_vec())]);
                assert_eq!(spool.stats().unwrap().acknowledged_through_sequence, 0);
            } else {
                assert!(payloads(&spool).is_empty());
                assert_eq!(spool.stats().unwrap().acknowledged_through_sequence, 1);
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn sigkill_during_quarantine_never_exposes_corrupt_database_as_live() {
    for stage in ["quarantine-rename", "quarantine-sync"] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let mut spool = open(config.clone());
        spool.append(PAYLOAD).unwrap();
        spool.commit().unwrap();
        drop(spool);
        corrupt_state_envelope(&config.directory.join(DATABASE));
        crash_at(temp.path(), stage);
        if stage == "quarantine-rename" {
            assert!(config.directory.join(DATABASE).exists());
            assert!(!config.directory.join(QUARANTINE).exists());
            assert!(matches!(
                MetadataSpool::open(config.clone(), key(), []),
                Err(Error::Corrupt)
            ));
        } else {
            assert!(!config.directory.join(DATABASE).exists());
            assert!(config.directory.join(QUARANTINE).exists());
        }
        assert!(matches!(
            MetadataSpool::open(config, key(), []),
            Err(Error::Quarantined)
        ));
    }
}

#[cfg(unix)]
#[test]
fn sigkill_at_backend_sync_boundaries_keeps_transactions_atomic() {
    for stage in ["backend-reserve-sync-before", "backend-reserve-sync-after"] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let mut spool = open(config.clone());
        spool.append(b"earlier durable prefix").unwrap();
        spool.commit().unwrap();
        drop(spool);
        crash_at(temp.path(), stage);

        let recovered = open(config);
        assert_eq!(
            payloads(&recovered),
            vec![(1, b"earlier durable prefix".to_vec())]
        );
        assert!(matches!(recovered.stats().unwrap().next_sequence, 2 | 3));
    }

    for stage in ["backend-commit-sync-before", "backend-commit-sync-after"] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let mut spool = open(config.clone());
        spool.append(b"earlier durable prefix").unwrap();
        spool.commit().unwrap();
        drop(spool);
        crash_at(temp.path(), stage);

        let recovered = open(config);
        let records = payloads(&recovered);
        assert_eq!(records[0], (1, b"earlier durable prefix".to_vec()));
        assert!(
            records.len() == 1
                || records
                    == vec![
                        (1, b"earlier durable prefix".to_vec()),
                        (2, PAYLOAD.to_vec())
                    ]
        );
        assert_eq!(recovered.stats().unwrap().next_sequence, 3);
    }

    for stage in ["backend-ack-sync-before", "backend-ack-sync-after"] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let mut spool = open(config.clone());
        spool.append(PAYLOAD).unwrap();
        spool.commit().unwrap();
        drop(spool);
        crash_at(temp.path(), stage);

        let recovered = open(config);
        let stats = recovered.stats().unwrap();
        assert!(
            stats.acknowledged_through_sequence == 0 || stats.acknowledged_through_sequence == 1
        );
        assert_eq!(stats.next_sequence, 2);
        assert_eq!(
            payloads(&recovered).len(),
            (stats.acknowledged_through_sequence == 0) as usize
        );
    }

    for stage in ["backend-rewrap-sync-before", "backend-rewrap-sync-after"] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        let mut spool = open(config.clone());
        spool.append(PAYLOAD).unwrap();
        spool.commit().unwrap();
        drop(spool);
        crash_at(temp.path(), stage);

        let state_key_after_crash = state_key_id(&config.directory.join(DATABASE));
        assert!(state_key_after_crash == "key-1" || state_key_after_crash == "key-2");
        let recovered = MetadataSpool::open(config.clone(), alternate_key(), [key()]).unwrap();
        assert_eq!(payloads(&recovered), vec![(1, PAYLOAD.to_vec())]);
    }

    for stage in [
        "backend-initialize-sync-before",
        "backend-initialize-sync-after",
    ] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        crash_at(temp.path(), stage);
        match MetadataSpool::open(config.clone(), key(), []) {
            Ok(recovered) => {
                assert_eq!(recovered.stats().unwrap().next_sequence, 1);
                assert!(payloads(&recovered).is_empty());
            }
            Err(Error::Corrupt) | Err(Error::Quarantined) => {
                assert!(config.directory.join(QUARANTINE).exists());
            }
            Err(error) => panic!("unexpected initialization sync recovery: {error:?}"),
        }
    }
}

fn corrupt_state_envelope(path: &Path) {
    let database = Database::open(path).unwrap();
    let bytes = {
        let tx = database.begin_read().unwrap();
        tx.open_table(STATE)
            .unwrap()
            .get(0)
            .unwrap()
            .unwrap()
            .value()
            .to_vec()
    };
    drop(database);
    let mut damaged = bytes;
    *damaged.last_mut().unwrap() ^= 1;
    let database = Database::open(path).unwrap();
    let tx = database.begin_write().unwrap();
    tx.open_table(STATE)
        .unwrap()
        .insert(0, damaged.as_slice())
        .unwrap();
    tx.commit().unwrap();
}

fn state_key_id(path: &Path) -> String {
    let database = Database::open(path).unwrap();
    let tx = database.begin_read().unwrap();
    let table = tx.open_table(STATE).unwrap();
    let envelope = table.get(0).unwrap().unwrap();
    format::key_id(envelope.value(), format::MAX_STATE_BYTES)
        .unwrap()
        .to_owned()
}

fn set_state_envelope(path: &Path, update: impl FnOnce(Vec<u8>) -> Vec<u8>) {
    let database = Database::open(path).unwrap();
    let bytes = {
        let tx = database.begin_read().unwrap();
        tx.open_table(STATE)
            .unwrap()
            .get(0)
            .unwrap()
            .unwrap()
            .value()
            .to_vec()
    };
    drop(database);
    let updated = update(bytes);
    let database = Database::open(path).unwrap();
    let tx = database.begin_write().unwrap();
    tx.open_table(STATE)
        .unwrap()
        .insert(0, updated.as_slice())
        .unwrap();
    tx.commit().unwrap();
}

fn rewrite_state_plaintext(path: &Path, node_id: &str, update: impl FnOnce(Vec<u8>) -> Vec<u8>) {
    let database = Database::open(path).unwrap();
    let envelope = {
        let tx = database.begin_read().unwrap();
        tx.open_table(STATE)
            .unwrap()
            .get(0)
            .unwrap()
            .unwrap()
            .value()
            .to_vec()
    };
    drop(database);
    let mut keys = BTreeMap::new();
    keys.insert("key-1".to_owned(), key());
    let plain = format::decrypt(&keys, node_id, 0, 0, &envelope, format::MAX_STATE_BYTES).unwrap();
    let changed = update(plain);
    let updated = format::encrypt(&key(), node_id, 0, 0, &changed).unwrap();
    let database = Database::open(path).unwrap();
    let tx = database.begin_write().unwrap();
    tx.open_table(STATE)
        .unwrap()
        .insert(0, updated.as_slice())
        .unwrap();
    tx.commit().unwrap();
}

fn corrupt_record_envelope(path: &Path, sequence: u64) {
    let database = Database::open(path).unwrap();
    corrupt_record_envelope_in_database(&database, sequence);
}

fn corrupt_record_envelope_in_database(database: &Database, sequence: u64) {
    let bytes = {
        let tx = database.begin_read().unwrap();
        tx.open_table(RECORDS)
            .unwrap()
            .get(sequence)
            .unwrap()
            .unwrap()
            .value()
            .to_vec()
    };
    let mut damaged = bytes;
    *damaged.last_mut().unwrap() ^= 1;
    let tx = database.begin_write().unwrap();
    tx.open_table(RECORDS)
        .unwrap()
        .insert(sequence, damaged.as_slice())
        .unwrap();
    tx.commit().unwrap();
}

#[test]
fn envelope_lengths_and_authenticated_state_watermarks_are_bounded() {
    let mut keys = BTreeMap::new();
    keys.insert("key-1".into(), key());
    let envelope = format::encrypt(&key(), "node-1", 1, 1, b"payload").unwrap();
    assert!(matches!(format::key_id(&envelope, 6), Err(Error::Corrupt)));
    for bad_length in [0u16, 129, u16::MAX] {
        let mut bad = envelope.clone();
        bad[12..14].copy_from_slice(&bad_length.to_le_bytes());
        assert!(matches!(
            format::decrypt(&keys, "node-1", 1, 1, &bad, 256),
            Err(Error::Corrupt)
        ));
    }
    for length in 0..envelope.len() {
        assert!(format::decrypt(&keys, "node-1", 1, 1, &envelope[..length], 256).is_err());
    }
    for (next, durable, acknowledged, count) in [
        (0, 0, 0, 0),
        (1, 1, 0, 1),
        (2, 1, 2, 0),
        (2, 1, 0, 0),
        (2, 1, 0, 2),
    ] {
        let state = format::State {
            next,
            durable,
            acknowledged,
            count,
            ..format::State::empty()
        };
        assert!(matches!(
            format::State::decode(&state.encode("node-1"), "node-1"),
            Err(Error::Corrupt)
        ));
    }
}

#[test]
fn fresh_format_rejects_legacy_inventory_without_removing_it() {
    for filename in [
        "checkpoint",
        "segment-00000000000000000001.seg",
        "prototype.redb",
    ] {
        let temp = TempDir::new().unwrap();
        let config = test_config(&temp);
        fs::create_dir(&config.directory).unwrap();
        fs::set_permissions(&config.directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = config.directory.join(filename);
        fs::write(&path, b"preserved legacy evidence").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            MetadataSpool::open(config.clone(), key(), []),
            Err(Error::Corrupt)
        ));
        assert_eq!(fs::read(path).unwrap(), b"preserved legacy evidence");
        assert!(!config.directory.join(DATABASE).exists());
    }
}

#[test]
fn encrypted_envelopes_and_debug_do_not_disclose_payloads_or_keys() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let mut spool = open(config.clone());
    let payload = b"private-user-metadata-never-plaintext";
    spool.append_batch(&[payload, payload]).unwrap();
    assert_ne!(spool.pending[0].1, spool.pending[1].1);
    spool.commit().unwrap();
    drop(spool);
    let bytes = fs::read(config.directory.join(DATABASE)).unwrap();
    assert!(!bytes.windows(payload.len()).any(|window| window == payload));
    assert_eq!(format!("{:?}", key()), "EncryptionKey([REDACTED])");
    let record = ReplayRecord {
        sequence: 1,
        payload: payload.to_vec(),
    };
    assert!(!format!("{record:?}").contains("private-user"));
}

/// Commits `batch` records per transaction until the ceiling refuses one, or
/// until `limit` rows are durable. Returns the last durable sequence.
fn fill_with_batches(spool: &mut MetadataSpool, payload: &[u8], batch: usize, limit: u64) -> u64 {
    let payloads = vec![payload; batch];
    let mut durable = spool.stats().unwrap().durable_through_sequence;
    while durable < limit {
        match spool.append_batch(&payloads) {
            Ok(results) => assert!(results.iter().all(Result::is_ok)),
            Err(Error::Full) => return durable,
            Err(error) => panic!("append_batch failed with {error:?}, not Full"),
        }
        match spool.commit() {
            Ok(receipt) => durable = receipt.through_sequence,
            Err(Error::Full) => return durable,
            Err(error) => panic!("commit failed with {error:?}, not Full"),
        }
    }
    durable
}

/// A consumer must always be able to free space: acknowledging everything
/// committed succeeds at the ceiling in one call, and admissions resume.
/// Without the reserve, a full acknowledgement of many small rows needs pages
/// the file does not have, and redb grows a file only by doubling it, so it
/// was refused.
#[test]
fn a_full_acknowledgement_at_the_ceiling_succeeds_and_reopens_admissions() {
    {
        let temp = TempDir::new().unwrap();
        let mut config = test_config(&temp);
        config.max_record_bytes = 16 * 1024;
        config.max_disk_bytes = 16 * 1024 * 1024;
        config.max_pending_records = 512;
        let payload = [0x5a; 300];
        // Large batches stop with a batch's worth of free pages left in the
        // file. Find where they stop on a scratch spool, then fill in large
        // batches to just short of that and in one-row commits from there,
        // which packs the file as tightly as a busy ledger's short group
        // commits do.
        let reach = {
            let scratch = TempDir::new().unwrap();
            let mut scratch_config = config.clone();
            scratch_config.directory = scratch.path().join("spool");
            fill_with_batches(&mut open(scratch_config), &payload, 512, u64::MAX)
        };
        let mut spool = open(config.clone());
        assert!(spool.stats().unwrap().headroom_reserved);
        fill_with_batches(&mut spool, &payload, 512, reach - 256);
        let durable = fill_with_batches(&mut spool, &payload, 1, u64::MAX);
        assert!(matches!(spool.append(b"while full"), Err(Error::Full)));

        spool.acknowledge(durable).unwrap();
        let stats = spool.stats().unwrap();
        assert_eq!(stats.acknowledged_through_sequence, durable);
        assert_eq!(stats.retained_records, 0);
        assert!(stats.headroom_reserved, "reserve not restored");
        assert!(stats.disk_bytes <= config.max_disk_bytes);
        // The row refused at the ceiling is still pending and now publishes.
        let last = spool.append(b"after the ceiling").unwrap().sequence;
        spool.commit().unwrap();
        drop(spool);
        let reopened = open(config);
        assert!(reopened.stats().unwrap().headroom_reserved);
        assert_eq!(
            payloads(&reopened),
            vec![
                (durable + 1, payload.to_vec()),
                (last, b"after the ceiling".to_vec())
            ]
        );
    }
}

/// The fallback when even the reserve does not make the whole range fit: the
/// spool halves the prefix on each refusal and still acknowledges all of it.
/// If not even one row fits, it answers `Full` and keeps admissions closed.
#[test]
fn a_refused_acknowledgement_falls_back_to_shorter_prefixes() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let hooks = Arc::new(Hooks::default());
    let mut spool =
        MetadataSpool::open_with_hooks(config.clone(), key(), [], hooks.clone()).unwrap();
    for _ in 0..2 {
        assert!(spool
            .append_batch(&[PAYLOAD; 8])
            .unwrap()
            .iter()
            .all(Result::is_ok));
        spool.commit().unwrap();
    }

    // The whole range, then 8 and 4 rows are refused; 2 rows fit.
    hooks.refuse_acknowledgements(3);
    spool.acknowledge(16).unwrap();
    let stats = spool.stats().unwrap();
    assert_eq!(stats.acknowledged_through_sequence, 16);
    assert_eq!(stats.retained_records, 0);
    assert!(stats.headroom_reserved);
    spool.append(b"admitted").unwrap();
    spool.commit().unwrap();

    hooks.refuse_acknowledgements(usize::MAX);
    assert!(matches!(spool.acknowledge(17), Err(Error::Full)));
    let stats = spool.stats().unwrap();
    assert_eq!(stats.acknowledged_through_sequence, 16);
    assert!(!stats.poisoned);
    assert!(matches!(spool.append(b"refused"), Err(Error::Full)));
    hooks.refuse_acknowledgements(0);
    spool.acknowledge(17).unwrap();
    assert!(spool.stats().unwrap().headroom_reserved);
    spool.append(b"admitted again").unwrap();
}

/// Putting the reserve back after an acknowledgement at the ceiling can be
/// refused too, which leaves admissions closed with nothing left to
/// acknowledge. Repeating the last acknowledgement retries the reserve, so the
/// consumer's "acknowledge until admitting" loop reopens admissions.
#[test]
fn a_repeated_acknowledgement_retries_a_reserve_that_did_not_fit() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let hooks = Arc::new(Hooks::default());
    let mut spool =
        MetadataSpool::open_with_hooks(config.clone(), key(), [], hooks.clone()).unwrap();
    assert!(spool
        .append_batch(&[PAYLOAD; 8])
        .unwrap()
        .iter()
        .all(Result::is_ok));
    spool.commit().unwrap();

    // The whole-range acknowledgement is refused, so the reserve is spent;
    // the acknowledgement then succeeds but the reserve does not fit back.
    hooks.refuse_acknowledgements(1);
    hooks.refuse_restores(1);
    spool.acknowledge(8).unwrap();
    let stats = spool.stats().unwrap();
    assert_eq!(stats.acknowledged_through_sequence, 8);
    assert_eq!(stats.retained_records, 0);
    assert!(!stats.headroom_reserved);
    assert!(matches!(spool.append(b"refused"), Err(Error::Full)));

    spool.acknowledge(8).unwrap();
    assert!(spool.stats().unwrap().headroom_reserved);
    spool.append(b"admitted").unwrap();
    spool.commit().unwrap();
}

/// A commit refused at the ceiling closes admissions until an acknowledgement.
/// If the retry after a full acknowledgement is refused too, nothing new is
/// left to acknowledge; a repeated acknowledgement must still let the pending
/// commit try again, or the spool refuses it unseen forever.
#[test]
fn a_repeated_acknowledgement_lets_a_refused_commit_try_again() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let hooks = Arc::new(Hooks::default());
    let mut spool =
        MetadataSpool::open_with_hooks(config.clone(), key(), [], hooks.clone()).unwrap();
    assert!(spool
        .append_batch(&[PAYLOAD; 8])
        .unwrap()
        .iter()
        .all(Result::is_ok));
    spool.commit().unwrap();
    spool.append(b"held").unwrap();

    hooks.refuse_commits(2);
    assert!(matches!(spool.commit(), Err(Error::Full)));
    spool.acknowledge(8).unwrap();
    assert!(matches!(spool.commit(), Err(Error::Full)));
    let stats = spool.stats().unwrap();
    assert_eq!(stats.acknowledged_through_sequence, 8);
    assert_eq!(stats.durable_through_sequence, 8);
    assert!(stats.headroom_reserved);

    spool.acknowledge(8).unwrap();
    assert_eq!(spool.commit().unwrap().through_sequence, 9);
}
