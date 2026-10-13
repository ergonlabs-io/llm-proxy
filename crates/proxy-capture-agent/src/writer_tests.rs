//! Batching rule of the spool writer. These drive the real `writer` (the
//! function `Agent::start` runs on its own OS thread) against a real redb
//! spool. The connection side is a test that sends `Job`s the way `serve` does:
//! one record per producer, then nothing until its receipt arrives.
use super::*;
use proxy_capture_spool::{EncryptionKey, SpoolConfig};
use std::{path::Path, thread::JoinHandle};
use tokio::time::timeout;

/// Reached only when the writer hangs; never a timing window a test must meet.
const WAIT: Duration = Duration::from_secs(5);
/// Far longer than any test runs, so a writer that holds a batch open for more
/// jobs shows up as a receipt that never arrives, not as a slow one.
const HOUR: Duration = Duration::from_secs(3600);

fn payload(event_id: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version":1,"event_id":event_id,"request_id":"request","instance_id":"instance",
        "started_at":"2026-10-01T00:00:00Z","finished_at":"2026-10-01T00:00:01Z",
        "tenant_id":"default","user_id":null,"key_id":null,"trace_id":null,
        "routing_revision":null,"policy_generation":null,"capture_policy_version":null,
        "method":"POST","route":"/v1/chat/completions","requested_model":null,
        "selected_cluster":null,"selected_provider":null,"selected_model":null,
        "status":200,"termination":"complete","error_category":null,"response_flags":[],
        "duration_ms":1,"time_to_first_byte_ms":null,"bytes_request":0,"bytes_response":0,
        "usage":null,"cost":null,"attempt_count":0,"physical_attempt_count":0,
        "attempts":[],"attempts_truncated":false
    }))
    .unwrap()
}

fn new_job(payload: Vec<u8>) -> (Job, oneshot::Receiver<Receipt>) {
    let (reply, receipt) = oneshot::channel();
    let producer = Producer {
        producer_id: "producer".into(),
        uid: 0,
        tenants: vec!["default".into()],
    };
    let job = Job {
        payload,
        producer,
        reply,
    };
    (job, receipt)
}

fn open_spool(directory: &Path) -> MetadataSpool {
    let config = SpoolConfig {
        directory: directory.join("spool"),
        node_id: "node".into(),
        max_record_bytes: 4096,
        max_disk_bytes: 4 * 1_048_576,
        cache_bytes: 4 * 1024 * 1024,
    };
    let key = EncryptionKey::new("key", [37; 32]).unwrap();
    MetadataSpool::open(config, key, Vec::new()).unwrap()
}

/// Starts the real writer on its own OS thread, as `Agent::start` does.
fn spawn_writer(
    directory: &Path,
    queue: mpsc::Receiver<Job>,
    max_hold: Duration,
) -> JoinHandle<()> {
    let spool = open_spool(directory);
    std::thread::spawn(move || writer(spool, queue, "node", &Health::default(), max_hold))
}

/// Event IDs in the spool in sequence order, read after the writer has stopped
/// and released the spool's single-writer lock.
fn stored_event_ids(directory: &Path) -> Vec<String> {
    open_spool(directory)
        .replay(0, 64, 262_144)
        .unwrap()
        .iter()
        .map(|row| {
            serde_json::from_slice::<RequestRecord>(&row.payload)
                .unwrap()
                .event_id
        })
        .collect()
}

/// Runs blocking `work` on its own thread and fails the test, rather than
/// hanging it, if `work` has not finished within `WAIT`.
fn bounded<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    // Rust note: `impl FnOnce() -> T + Send + 'static` accepts a closure that
    // runs once, can move to another thread, and borrows nothing from this frame.
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(work());
    });
    finished
        .recv_timeout(WAIT)
        .expect("bounded work blocked past the deadline or panicked")
}

#[tokio::test]
async fn lone_producer_is_committed_without_waiting_for_a_full_batch() {
    let directory = tempfile::tempdir().unwrap();
    let (jobs, queue) = mpsc::channel(MAX_CLIENTS);
    let thread = spawn_writer(directory.path(), queue, HOUR);
    for n in 1..=3 {
        let (job, receipt) = new_job(payload(&format!("lone-{n}")));
        jobs.try_send(job).unwrap();
        // Like a connection, send nothing more until this receipt arrives. No
        // other producer exists, so the batch can never reach `MAX_CLIENTS`.
        let receipt = timeout(WAIT, receipt)
            .await
            .expect("no receipt: the writer is holding a partial batch for more jobs")
            .unwrap();
        assert_eq!(receipt.outcome, Outcome::Durable);
        assert_eq!(receipt.sequence, Some(n));
    }
    drop(jobs);
    thread.join().unwrap();
    assert_eq!(
        stored_event_ids(directory.path()),
        ["lone-1", "lone-2", "lone-3"]
    );
}

#[tokio::test]
async fn queued_jobs_beyond_the_cap_commit_in_further_batches() {
    let directory = tempfile::tempdir().unwrap();
    let total = 2 * MAX_CLIENTS + 4;
    // Production's queue holds `MAX_CLIENTS` jobs. This one is wider so that a
    // writer ignoring the cap would find more than the spool accepts at once.
    let (jobs, queue) = mpsc::channel(total);
    let mut receipts = Vec::new();
    for n in 0..total {
        let (job, receipt) = new_job(payload(&format!("queued-{n}")));
        jobs.try_send(job).unwrap();
        receipts.push(receipt);
    }
    // Start the writer only now, so its first collection finds every job queued.
    let thread = spawn_writer(directory.path(), queue, HOUR);
    let mut sequences = Vec::new();
    for receipt in receipts {
        let receipt = timeout(WAIT, receipt)
            .await
            .expect("no receipt: the writer is holding a partial batch for more jobs")
            .unwrap();
        // A batch above the spool's cap would be refused and come back as
        // Unavailable.
        assert_eq!(receipt.outcome, Outcome::Durable);
        sequences.push(receipt.sequence.unwrap());
    }
    drop(jobs);
    thread.join().unwrap();
    sequences.sort_unstable();
    assert_eq!(sequences, (1..=total as u64).collect::<Vec<_>>());
    let expected: Vec<String> = (0..total).map(|n| format!("queued-{n}")).collect();
    assert_eq!(stored_event_ids(directory.path()), expected);
}

#[test]
fn collection_takes_only_what_is_already_queued_up_to_the_cap() {
    let total = 2 * MAX_CLIENTS + 4;
    let (jobs, mut queue) = mpsc::channel(total);
    for n in 0..total {
        jobs.try_send(new_job(format!("queued-{n}").into_bytes()).0)
            .unwrap();
    }
    // `jobs` stays alive, so the last batch ends on an empty but still-open
    // queue: the situation of a producer waiting for its receipt.
    let (sizes, order) = bounded(move || {
        let mut sizes = Vec::new();
        let mut order = Vec::new();
        for _ in 0..3 {
            let batch = next_batch(&mut queue, HOUR).expect("jobs are queued");
            sizes.push(batch.len());
            order.extend(batch.into_iter().map(|job| job.payload));
        }
        (sizes, order)
    });
    assert_eq!(sizes, [MAX_CLIENTS, MAX_CLIENTS, 4]);
    let expected: Vec<Vec<u8>> = (0..total)
        .map(|n| format!("queued-{n}").into_bytes())
        .collect();
    assert_eq!(order, expected);
    drop(jobs);
}

#[test]
fn max_hold_caps_collection_even_when_more_jobs_are_queued() {
    let (jobs, mut queue) = mpsc::channel(MAX_CLIENTS);
    for n in 0..3u8 {
        jobs.try_send(new_job(vec![n]).0).unwrap();
    }
    // Jobs are queued, so this call cannot block; a zero hold leaves no time to
    // collect the two behind the first.
    let batch = next_batch(&mut queue, Duration::ZERO).expect("jobs are queued");
    assert_eq!(batch.len(), 1);
}
