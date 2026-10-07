//! Process-crash tests independent of the spool implementation's unit tests.
#![cfg(unix)]

use proxy_capture_spool::{EncryptionKey, MetadataSpool, SpoolConfig};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PAYLOAD: &[u8] = br#"{"schema_version":1,"event_id":"crash-test:terminal"}"#;
const CHILD_ROOT: &str = "LLMPROXY_SPOOL_CRASH_ROOT";
const CHILD_STAGE: &str = "LLMPROXY_SPOOL_CRASH_STAGE";

fn open(root: &Path) -> MetadataSpool {
    let config = SpoolConfig {
        directory: root.join("spool"),
        node_id: "crash-test".into(),
        max_record_bytes: 1024,
        max_segment_bytes: 16 * 1024,
        max_disk_bytes: 128 * 1024,
        max_segments: 8,
        max_segment_age: Duration::from_secs(60),
    };
    let key = EncryptionKey::new("crash-test-key", [37; 32]).unwrap();
    MetadataSpool::open(config, key, Vec::new()).unwrap()
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn crash_at(root: &Path, stage: &str) {
    let mut child = KillOnDrop(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_child", "--nocapture", "--test-threads=1"])
            .env(CHILD_ROOT, root)
            .env(CHILD_STAGE, stage)
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !root.join("ready").exists() {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("crash child exited before {stage}: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "crash child did not reach {stage}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // On Unix Child::kill sends SIGKILL: neither Drop nor sealing can run.
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9));
}

#[test]
fn crash_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return; // Only the parent-selected subprocess exercises this helper.
    };
    let root = std::path::PathBuf::from(root);
    let stage = std::env::var(CHILD_STAGE).unwrap();
    let mut spool = open(&root);
    let appended = spool.append(PAYLOAD).unwrap();
    if stage != "append" {
        let committed = spool.commit().unwrap();
        assert_eq!(committed.through_sequence, appended.sequence);
        if stage == "seal" {
            spool.seal().unwrap();
        } else if stage == "acknowledge" {
            spool.acknowledge(committed.through_sequence).unwrap();
        }
    }
    std::fs::write(root.join("ready"), b"ready").unwrap();
    loop {
        std::thread::park_timeout(Duration::from_secs(1));
    }
}

#[test]
fn sigkill_before_commit_does_not_create_a_durable_record() {
    let root = tempfile::tempdir().unwrap();
    crash_at(root.path(), "append");
    let mut recovered = open(root.path());
    assert!(recovered.replay(0, 8, 8192).unwrap().is_empty());
    recovered.append(PAYLOAD).unwrap();
    recovered.commit().unwrap();
    assert_eq!(recovered.replay(0, 8, 8192).unwrap().len(), 1);
}

#[test]
fn sigkill_after_commit_replays_the_durability_acknowledged_record() {
    let root = tempfile::tempdir().unwrap();
    crash_at(root.path(), "commit");
    let recovered = open(root.path());
    let records = recovered.replay(0, 8, 8192).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].payload, PAYLOAD);
}

#[test]
fn sigkill_after_seal_preserves_committed_payloads() {
    let root = tempfile::tempdir().unwrap();
    crash_at(root.path(), "seal");
    let recovered = open(root.path());
    let records = recovered.replay(0, 8, 8192).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].payload, PAYLOAD);
}

#[test]
fn sigkill_after_backend_ack_preserves_checkpoint_and_sequence_identity() {
    let root = tempfile::tempdir().unwrap();
    crash_at(root.path(), "acknowledge");
    let mut recovered = open(root.path());
    assert!(recovered.replay(0, 8, 8192).unwrap().is_empty());
    let next = recovered.append(PAYLOAD).unwrap();
    assert!(
        next.sequence > 1,
        "reclaimed sequence identity must not be reused"
    );
    recovered.commit().unwrap();
    assert_eq!(recovered.replay(0, 8, 8192).unwrap().len(), 1);
}
