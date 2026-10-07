use super::*;
use std::io::{Seek, SeekFrom};
use tempfile::TempDir;

fn config(temp: &TempDir) -> SpoolConfig {
    SpoolConfig {
        directory: temp.path().join("spool"),
        node_id: "node-1".into(),
        max_record_bytes: 256,
        max_segment_bytes: 1024,
        max_disk_bytes: 16 * 1024,
        max_segments: 8,
        max_segment_age: Duration::from_secs(60),
    }
}

fn key() -> EncryptionKey {
    EncryptionKey::new("key-1", [7; 32]).unwrap()
}

fn open(config: SpoolConfig) -> MetadataSpool {
    MetadataSpool::open(config, key(), []).unwrap()
}

#[test]
fn commit_reopen_replay() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    assert_eq!(spool.append(b"metadata-one").unwrap().sequence, 1);
    assert_eq!(spool.append(b"metadata-two").unwrap().sequence, 2);
    assert_eq!(spool.commit().unwrap().through_sequence, 2);
    assert_eq!(spool.stats().unwrap().pending_records, 0);
    drop(spool);
    let spool = open(config);
    let records = spool.replay(0, 10, 1000).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].sequence, 1);
    assert_eq!(records[0].payload, b"metadata-one");
    assert_eq!(records[1].sequence, 2);
    assert_eq!(records[1].payload, b"metadata-two");
}

fn overwrite(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn payloads(spool: &MetadataSpool) -> Vec<Vec<u8>> {
    spool
        .replay(0, 100, 4096)
        .unwrap()
        .into_iter()
        .map(|r| r.payload)
        .collect()
}

#[test]
fn pending_is_not_durable_and_drop_never_commits() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    let receipt = spool.append(b"pending").unwrap();
    assert_eq!(receipt.sequence, 1);
    assert_eq!(spool.stats().unwrap().durable_through_sequence, 0);
    assert!(payloads(&spool).is_empty());
    assert!(matches!(
        spool.acknowledge(1),
        Err(Error::InvalidAcknowledgement)
    ));
    drop(spool);
    let mut spool = open(config);
    assert!(payloads(&spool).is_empty());
    assert_eq!(spool.stats().unwrap().recovered_pending_records, 1);
    assert_eq!(spool.append(b"replacement").unwrap().sequence, 2);
    assert_eq!(spool.seal().unwrap().through_sequence, 2);
}

#[test]
fn replay_has_row_byte_and_cursor_bounds() {
    let temp = TempDir::new().unwrap();
    let mut spool = open(config(&temp));
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
            .replay(1, 10, 7)
            .unwrap()
            .iter()
            .map(|r| r.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert!(spool.replay(3, usize::MAX, usize::MAX).unwrap().is_empty());
}

#[test]
fn empty_records_still_obey_row_limit() {
    let temp = TempDir::new().unwrap();
    let mut spool = open(config(&temp));
    for _ in 0..5 {
        spool.append(b"").unwrap();
    }
    spool.commit().unwrap();
    assert_eq!(spool.replay(0, 2, 1).unwrap().len(), 2);
}

#[test]
fn torn_uncommitted_tail_preserves_durable_prefix_and_sequence() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"durable").unwrap();
    spool.commit().unwrap();
    spool.append(b"pending-one").unwrap();
    spool.append(b"pending-two").unwrap();
    let path = spool.path(2, "open");
    drop(spool);
    let file = OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(file.metadata().unwrap().len() - 6).unwrap();
    file.sync_all().unwrap();
    let mut spool = open(config);
    assert_eq!(payloads(&spool), vec![b"durable".to_vec()]);
    assert_eq!(spool.stats().unwrap().recovered_pending_records, 1);
    assert_eq!(spool.append(b"next").unwrap().sequence, 4);
}

#[test]
fn truncated_pending_header_is_discarded_after_sequence_reservation() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"pending").unwrap();
    let path = spool.path(1, "open");
    drop(spool);
    OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(10)
        .unwrap();
    let mut spool = open(config);
    assert_eq!(spool.append(b"next").unwrap().sequence, 2);
}

#[test]
fn committed_ciphertext_corruption_is_quarantined_and_fails_closed() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"abcdef").unwrap();
    spool.commit().unwrap();
    let path = spool.path(1, "seg");
    let quarantine = spool.path(1, "bad");
    let before = spool.stats().unwrap().disk_bytes;
    drop(spool);
    let flipped = fs::read(&path).unwrap()[HEADER_BYTES + 25] ^ 1;
    overwrite(&path, HEADER_BYTES as u64 + 25, &[flipped]);
    assert!(matches!(
        MetadataSpool::open(config.clone(), key(), []),
        Err(Error::Corrupt)
    ));
    assert!(quarantine.exists());
    assert!(!path.exists());
    assert_eq!(
        fs::read_dir(&config.directory)
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum::<u64>(),
        before
    );
    assert!(matches!(
        MetadataSpool::open(config, key(), []),
        Err(Error::Quarantined)
    ));
}

#[test]
fn corrupt_sealed_footer_is_not_treated_as_pending_tail() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"committed").unwrap();
    spool.commit().unwrap();
    let path = spool.path(1, "seg");
    let length = fs::metadata(&path).unwrap().len();
    drop(spool);
    let mut bytes = fs::read(&path).unwrap();
    bytes[length as usize - 1] ^= 1;
    overwrite(&path, length - 1, &bytes[length as usize - 1..]);
    assert!(matches!(
        MetadataSpool::open(config, key(), []),
        Err(Error::Corrupt)
    ));
}

#[test]
fn missing_committed_segment_fails_closed() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"committed").unwrap();
    spool.commit().unwrap();
    let path = spool.path(1, "seg");
    drop(spool);
    fs::remove_file(path).unwrap();
    assert!(matches!(
        MetadataSpool::open(config, key(), []),
        Err(Error::Corrupt)
    ));
}

#[test]
fn corrupt_checkpoint_never_resets_sequence_or_acknowledgement() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"committed").unwrap();
    spool.commit().unwrap();
    spool.acknowledge(1).unwrap();
    drop(spool);
    let path = config.directory.join("checkpoint");
    overwrite(&path, HEADER_BYTES as u64, &u32::MAX.to_le_bytes());
    assert!(matches!(
        MetadataSpool::open(config, key(), []),
        Err(Error::Corrupt)
    ));
}

#[test]
fn malformed_record_lengths_are_bounded_before_allocation() {
    for length in [0_u32, 1, 36, u32::MAX] {
        let temp = TempDir::new().unwrap();
        let config = config(&temp);
        let mut spool = open(config.clone());
        spool.append(b"committed").unwrap();
        spool.commit().unwrap();
        let path = spool.path(1, "seg");
        drop(spool);
        overwrite(&path, HEADER_BYTES as u64, &length.to_le_bytes());
        assert!(matches!(
            MetadataSpool::open(config, key(), []),
            Err(Error::Corrupt)
        ));
    }
}

#[test]
fn bounded_header_identifier_lengths_do_not_panic() {
    for offset in [20, 22] {
        let temp = TempDir::new().unwrap();
        let config = config(&temp);
        let mut spool = open(config.clone());
        spool.append(b"committed").unwrap();
        spool.commit().unwrap();
        let path = spool.path(1, "seg");
        drop(spool);
        overwrite(&path, offset, &u16::MAX.to_le_bytes());
        assert!(matches!(
            MetadataSpool::open(config, key(), []),
            Err(Error::Corrupt)
        ));
    }
}

#[test]
fn unknown_segment_and_checkpoint_versions_are_refused() {
    for checkpoint in [false, true] {
        let temp = TempDir::new().unwrap();
        let config = config(&temp);
        let mut spool = open(config.clone());
        spool.append(b"committed").unwrap();
        spool.commit().unwrap();
        let path = if checkpoint {
            config.directory.join("checkpoint")
        } else {
            spool.path(1, "seg")
        };
        drop(spool);
        overwrite(&path, 8, &2_u32.to_le_bytes());
        assert!(matches!(
            MetadataSpool::open(config, key(), []),
            Err(Error::UnknownVersion(2))
        ));
    }
}

#[test]
fn unknown_pending_segment_version_is_not_silently_discarded() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"pending").unwrap();
    let path = spool.path(1, "open");
    drop(spool);
    overwrite(&path, 8, &2_u32.to_le_bytes());
    assert!(matches!(
        MetadataSpool::open(config, key(), []),
        Err(Error::UnknownVersion(2))
    ));
    assert!(path.exists());
}

#[test]
fn unavailable_key_preserves_backlog_and_can_be_supplied_for_recovery() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"committed").unwrap();
    spool.commit().unwrap();
    drop(spool);
    let new_key = || EncryptionKey::new("key-2", [9; 32]).unwrap();
    assert!(matches!(
        MetadataSpool::open(config.clone(), new_key(), []),
        Err(Error::MissingKey)
    ));
    let mut spool = MetadataSpool::open(config.clone(), new_key(), [key()]).unwrap();
    assert_eq!(payloads(&spool), vec![b"committed".to_vec()]);
    spool.append(b"rotated").unwrap();
    spool.commit().unwrap();
    drop(spool);
    assert!(matches!(
        MetadataSpool::open(config.clone(), new_key(), []),
        Err(Error::MissingKey)
    ));
    let spool = MetadataSpool::open(config, new_key(), [key()]).unwrap();
    assert_eq!(
        payloads(&spool),
        vec![b"committed".to_vec(), b"rotated".to_vec()]
    );
}

#[test]
fn wrong_key_material_fails_authentication() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"committed").unwrap();
    spool.commit().unwrap();
    drop(spool);
    assert!(matches!(
        MetadataSpool::open(config, EncryptionKey::new("key-1", [8; 32]).unwrap(), []),
        Err(Error::Corrupt)
    ));
}

#[test]
fn append_bound_failure_does_not_poison_or_reserve_sequence() {
    let temp = TempDir::new().unwrap();
    let mut spool = open(config(&temp));
    assert!(matches!(
        spool.append(&[0; 257]),
        Err(Error::RecordTooLarge)
    ));
    assert_eq!(spool.append(&[0; 256]).unwrap().sequence, 1);
    spool.commit().unwrap();
}

#[test]
fn full_segment_count_preserves_backlog_until_backend_acknowledges() {
    let temp = TempDir::new().unwrap();
    let mut config = config(&temp);
    config.max_segments = 1;
    let mut spool = open(config.clone());
    spool.append(b"first").unwrap();
    spool.commit().unwrap();
    assert!(matches!(spool.append(b"second"), Err(Error::Full)));
    assert_eq!(payloads(&spool), vec![b"first".to_vec()]);
    assert!(matches!(spool.append(b"over-limit"), Err(Error::Full)));
    assert!(!spool.stats().unwrap().poisoned);
    spool.acknowledge(1).unwrap();
    assert_eq!(spool.append(b"second").unwrap().sequence, 2);
    spool.commit().unwrap();
    drop(spool);
    assert_eq!(payloads(&open(config)), vec![b"second".to_vec()]);
}

#[test]
fn disk_budget_reserves_footer_and_two_checkpoints() {
    let temp = TempDir::new().unwrap();
    let mut config = config(&temp);
    config.max_segment_bytes = (HEADER_BYTES + FRAME_OVERHEAD + 256 + FOOTER_BYTES) as u64;
    config.max_disk_bytes = config.control_reserve().unwrap() + config.max_segment_bytes;
    let mut spool = open(config.clone());
    spool.append(&[0; 256]).unwrap();
    spool.commit().unwrap();
    assert!(spool.stats().unwrap().disk_bytes <= config.max_disk_bytes);
    assert!(matches!(spool.append(b"next"), Err(Error::Full)));
    spool.acknowledge(1).unwrap();
    spool.append(&[1; 256]).unwrap();
    spool.commit().unwrap();
    assert!(spool.stats().unwrap().disk_bytes <= config.max_disk_bytes);
}

#[test]
fn acknowledgement_replays_only_remaining_records_and_reclaims_whole_segments() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"one").unwrap();
    spool.append(b"two").unwrap();
    spool.commit().unwrap();
    let path = spool.path(1, "seg");
    spool.acknowledge(1).unwrap();
    assert!(path.exists());
    assert_eq!(payloads(&spool), vec![b"two".to_vec()]);
    drop(spool);
    let mut spool = open(config.clone());
    assert_eq!(payloads(&spool), vec![b"two".to_vec()]);
    spool.acknowledge(2).unwrap();
    assert!(!path.exists());
    assert_eq!(spool.stats().unwrap().committed_segments, 0);
    spool.acknowledge(1).unwrap(); // Idempotent older backend confirmation.
    drop(spool);
    let mut spool = open(config);
    assert!(payloads(&spool).is_empty());
    assert_eq!(spool.append(b"three").unwrap().sequence, 3);
    spool.commit().unwrap();
}

#[test]
fn gap_from_lost_pending_batch_remains_monotonic_after_all_reclaimed() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"lost").unwrap();
    drop(spool);
    let mut spool = open(config.clone());
    spool.append(b"kept").unwrap();
    spool.commit().unwrap();
    spool.acknowledge(2).unwrap();
    drop(spool);
    let mut spool = open(config);
    assert_eq!(spool.append(b"next").unwrap().sequence, 3);
}

#[test]
fn os_writer_lock_releases_on_drop_but_lock_file_can_remain() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let spool = open(config.clone());
    assert!(matches!(
        MetadataSpool::open(config.clone(), key(), []),
        Err(Error::Locked)
    ));
    drop(spool);
    assert!(config.directory.join("writer.lock").exists());
    let mut spool = open(config);
    spool.append(b"next-writer").unwrap();
    spool.commit().unwrap();
}

#[test]
fn segment_size_rotates_without_expiring_committed_data() {
    let temp = TempDir::new().unwrap();
    let mut config = config(&temp);
    config.max_segment_bytes = (HEADER_BYTES + FRAME_OVERHEAD + 256 + FOOTER_BYTES) as u64;
    let mut spool = open(config.clone());
    spool.append(&[1; 256]).unwrap();
    spool.append(&[2; 256]).unwrap(); // Rotates and commits previous batch.
    assert_eq!(spool.stats().unwrap().durable_through_sequence, 1);
    assert_eq!(spool.stats().unwrap().pending_records, 1);
    spool.seal().unwrap();
    assert_eq!(spool.stats().unwrap().committed_segments, 2);
    assert_eq!(payloads(&spool).len(), 2);
}

#[test]
fn age_rotates_on_append_and_never_expires_backlog() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config);
    spool.append(b"old").unwrap();
    spool.pending.as_mut().unwrap().started = Instant::now() - Duration::from_secs(120);
    spool.append(b"new").unwrap();
    assert_eq!(spool.stats().unwrap().durable_through_sequence, 1);
    assert_eq!(payloads(&spool), vec![b"old".to_vec()]);
    spool.seal().unwrap();
    assert_eq!(payloads(&spool), vec![b"old".to_vec(), b"new".to_vec()]);
}

#[test]
fn encryption_and_debug_never_expose_payload_or_key_bytes() {
    let temp = TempDir::new().unwrap();
    let mut spool = open(config(&temp));
    let plaintext = b"secret-unique-metadata-payload";
    spool.append(plaintext).unwrap();
    spool.commit().unwrap();
    for entry in fs::read_dir(&spool.config.directory).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(!bytes.windows(plaintext.len()).any(|w| w == plaintext));
        assert!(!bytes.windows(32).any(|w| w == [7; 32]));
    }
    assert_eq!(format!("{:?}", key()), "EncryptionKey([REDACTED])");
    assert!(!format!("{:?}", spool.replay(0, 10, 100).unwrap()).contains("secret"));
    assert!(spool
        .path(1, "seg")
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .contains("00000000000000000001"));
}

#[test]
fn duplicate_keys_and_invalid_limits_are_rejected() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    assert!(matches!(
        MetadataSpool::open(config.clone(), key(), [key()]),
        Err(Error::DuplicateKey)
    ));
    for index in 0..7 {
        let mut config = config.clone();
        match index {
            0 => config.max_record_bytes = 0,
            1 => config.max_record_bytes = usize::MAX,
            2 => config.max_segment_bytes = 1,
            3 => config.max_segments = 0,
            4 => config.max_segments = usize::MAX,
            5 => config.max_segment_age = Duration::ZERO,
            _ => config.max_disk_bytes = 1,
        }
        assert!(matches!(
            MetadataSpool::open(config, key(), []),
            Err(Error::InvalidConfig(_))
        ));
    }
    assert!(matches!(
        EncryptionKey::new("", [0; 32]),
        Err(Error::InvalidConfig(_))
    ));
}

#[test]
fn node_identity_mismatch_is_refused() {
    let temp = TempDir::new().unwrap();
    let mut config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"owned").unwrap();
    spool.commit().unwrap();
    drop(spool);
    config.node_id = "different-node".into();
    assert!(matches!(
        MetadataSpool::open(config, key(), []),
        Err(Error::Corrupt)
    ));
}

#[test]
fn symlinks_and_unrecognized_files_are_refused() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    drop(open(config.clone()));
    std::os::unix::fs::symlink(
        temp.path(),
        config.directory.join("segment-00000000000000000001.open"),
    )
    .unwrap();
    assert!(matches!(
        MetadataSpool::open(config.clone(), key(), []),
        Err(Error::Corrupt)
    ));
    fs::remove_file(config.directory.join("segment-00000000000000000001.open")).unwrap();
    create_file(&config.directory.join("sensitive-unrecognized-name")).unwrap();
    assert!(matches!(
        MetadataSpool::open(config, key(), []),
        Err(Error::Corrupt)
    ));
}

#[test]
fn failed_append_barrier_poisoning_preserves_existing_backlog() {
    for fault in [
        Fault::CheckpointSync,
        Fault::CheckpointDirectorySync,
        Fault::AppendWrite,
    ] {
        let temp = TempDir::new().unwrap();
        let config = config(&temp);
        let mut spool = open(config.clone());
        spool.append(b"committed").unwrap();
        spool.commit().unwrap();
        spool.fault = Some(fault);
        assert!(matches!(spool.append(b"ambiguous"), Err(Error::Io(_))));
        assert!(spool.stats().unwrap().poisoned);
        assert!(matches!(spool.append(b"unsafe"), Err(Error::Poisoned)));
        assert!(matches!(spool.commit(), Err(Error::Poisoned)));
        assert!(matches!(spool.acknowledge(1), Err(Error::Poisoned)));
        drop(spool);
        let mut spool = open(config);
        assert_eq!(payloads(&spool), vec![b"committed".to_vec()]);
        assert!(spool.append(b"recovered").unwrap().sequence >= 2);
    }
}

#[test]
fn ambiguous_commit_cannot_return_false_receipt_or_continue_writing() {
    for fault in [
        Fault::SegmentSync,
        Fault::PublishDirectorySync,
        Fault::CheckpointSync,
        Fault::CheckpointDirectorySync,
    ] {
        let temp = TempDir::new().unwrap();
        let config = config(&temp);
        let mut spool = open(config.clone());
        spool.append(b"existing").unwrap();
        spool.commit().unwrap();
        spool.append(b"ambiguous").unwrap();
        spool.fault = Some(fault);
        assert!(matches!(spool.commit(), Err(Error::Io(_))));
        assert!(matches!(spool.commit(), Err(Error::Poisoned)));
        assert!(matches!(spool.append(b"unsafe"), Err(Error::Poisoned)));
        assert!(matches!(spool.acknowledge(2), Err(Error::Poisoned)));
        drop(spool);
        let mut spool = open(config);
        let records = payloads(&spool);
        assert_eq!(records[0], b"existing");
        assert_eq!(
            records.len(),
            if fault == Fault::CheckpointDirectorySync {
                2
            } else {
                1
            }
        );
        assert_eq!(spool.append(b"recovered").unwrap().sequence, 3);
    }
}

#[test]
fn checkpoint_failure_never_reclaims_unconfirmed_segments() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"confirmed-later").unwrap();
    spool.commit().unwrap();
    let path = spool.path(1, "seg");
    spool.fault = Some(Fault::CheckpointSync);
    assert!(matches!(spool.acknowledge(1), Err(Error::Io(_))));
    assert!(path.exists());
    drop(spool);
    let spool = open(config);
    assert_eq!(payloads(&spool), vec![b"confirmed-later".to_vec()]);
}

#[test]
fn acknowledgement_checkpoint_survives_crash_before_reclamation() {
    for fault in [Fault::CheckpointDirectorySync, Fault::Reclaim] {
        let temp = TempDir::new().unwrap();
        let config = config(&temp);
        let mut spool = open(config.clone());
        spool.append(b"backend-confirmed").unwrap();
        spool.commit().unwrap();
        let path = spool.path(1, "seg");
        spool.fault = Some(fault);
        assert!(matches!(spool.acknowledge(1), Err(Error::Io(_))));
        assert!(path.exists());
        drop(spool);
        let mut spool = open(config);
        assert!(payloads(&spool).is_empty());
        assert!(!path.exists());
        assert_eq!(spool.append(b"next").unwrap().sequence, 2);
    }
}

#[test]
fn checkpoint_structural_bounds_are_checked_after_authentication() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut bytes = State::empty().encode();
    bytes[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(
        State::decode(&bytes, &config),
        Err(Error::Corrupt)
    ));
    bytes = State::empty().encode();
    bytes[..8].copy_from_slice(&0_u64.to_le_bytes());
    assert!(matches!(
        State::decode(&bytes, &config),
        Err(Error::Corrupt)
    ));
}

#[test]
fn replay_corruption_poisoning_blocks_mutation_until_recovery() {
    let temp = TempDir::new().unwrap();
    let mut spool = open(config(&temp));
    spool.append(b"committed").unwrap();
    spool.commit().unwrap();
    let path = spool.path(1, "seg");
    let flipped = fs::read(&path).unwrap()[HEADER_BYTES + 25] ^ 1;
    overwrite(&path, HEADER_BYTES as u64 + 25, &[flipped]);
    assert!(matches!(spool.replay(0, 10, 100), Err(Error::Corrupt)));
    assert!(spool.stats().unwrap().poisoned);
    assert!(matches!(spool.append(b"unsafe"), Err(Error::Poisoned)));
    assert!(matches!(spool.commit(), Err(Error::Poisoned)));
    assert!(matches!(spool.acknowledge(1), Err(Error::Poisoned)));
}

#[test]
fn acknowledged_reclaim_does_not_need_retired_payload_key() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let mut spool = open(config.clone());
    spool.append(b"backend-confirmed").unwrap();
    spool.commit().unwrap();
    drop(spool);
    let new_key = || EncryptionKey::new("key-2", [9; 32]).unwrap();
    let mut spool = MetadataSpool::open(config.clone(), new_key(), [key()]).unwrap();
    let path = spool.path(1, "seg");
    spool.fault = Some(Fault::Reclaim);
    assert!(spool.acknowledge(1).is_err());
    assert!(path.exists());
    drop(spool);
    let spool = MetadataSpool::open(config, new_key(), []).unwrap();
    assert!(!path.exists());
    assert!(spool.replay(0, 10, 100).unwrap().is_empty());
    assert_eq!(spool.stats().unwrap().recovered_pending_records, 0);
}

#[test]
fn recovery_key_count_and_directory_permissions_are_bounded() {
    let temp = TempDir::new().unwrap();
    let config = config(&temp);
    let keys = (0..MAX_ENCRYPTION_KEYS)
        .map(|i| EncryptionKey::new(format!("recovery-key-{i}"), [9; 32]).unwrap());
    assert!(matches!(
        MetadataSpool::open(config.clone(), key(), keys),
        Err(Error::InvalidConfig(_))
    ));
    fs::set_permissions(&config.directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        MetadataSpool::open(config, key(), []),
        Err(Error::InvalidConfig(_))
    ));
}
