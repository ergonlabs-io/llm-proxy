//! Batching rule of the spool writer. Most of these drive the real `writer`
//! (the function `Agent::start` runs on its own OS thread) against a real redb
//! spool. The connection side is a test that sends `Job`s the way `serve` does:
//! one record per connection, then nothing until its receipt arrives.
//! `lockstep_producers_converge_to_full_batches` drives `Batcher` directly,
//! because only the batch sizes it observes can show the cohorts merging.
use super::*;
use proxy_capture_spool::{EncryptionKey, SpoolConfig};
use std::{path::Path, thread::JoinHandle};
use tokio::time::timeout;

/// Reached only when the writer hangs; never a timing window a test must meet.
const WAIT: Duration = Duration::from_secs(5);
/// Far longer than any test runs, so a writer that holds a batch open for a
/// producer that is not coming shows up as a receipt that never arrives, not as
/// a slow one.
const HOUR: Duration = Duration::from_secs(3600);
/// Records each lockstep producer sends, and so batches the writer forms.
const ROUNDS: usize = 4;

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

fn new_job(connection: u64, payload: Vec<u8>) -> (Job, oneshot::Receiver<Receipt>) {
    let (reply, receipt) = oneshot::channel();
    let producer = Producer {
        producer_id: "producer".into(),
        uid: 0,
        tenants: vec!["default".into()],
    };
    let job = Job {
        payload,
        producer,
        connection,
        reply,
    };
    (job, receipt)
}

/// The answer a stand-in writer gives; the real writer builds its own.
fn durable() -> Receipt {
    Receipt {
        version: VERSION,
        node_id: "node".into(),
        event_id: String::new(),
        sequence: None,
        outcome: Outcome::Durable,
    }
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
    settle: Duration,
) -> JoinHandle<()> {
    let spool = open_spool(directory);
    std::thread::spawn(move || writer(spool, queue, "node", &Health::default(), max_hold, settle))
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

/// A producer that behaves like a connection: it sends a record, waits for the
/// receipt, pauses for `pause` (what a real client needs to turn a receipt into
/// its next record), and repeats for `ROUNDS` records. `queued` is the receipt
/// of a first record the test has already put on the queue.
fn lockstep_producer(
    connection: u64,
    jobs: mpsc::SyncSender<Job>,
    queued: Option<oneshot::Receiver<Receipt>>,
    pause: Duration,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut queued = queued;
        for round in 0..ROUNDS {
            let receipt = match queued.take() {
                Some(receipt) => receipt,
                None => {
                    std::thread::sleep(pause);
                    let event = format!("producer-{connection}-{round}");
                    let (job, receipt) = new_job(connection, payload(&event));
                    jobs.send(job).unwrap();
                    receipt
                }
            };
            receipt
                .blocking_recv()
                .expect("the writer answers every job");
        }
    })
}

#[tokio::test]
async fn lone_producer_is_committed_without_waiting_for_a_full_batch() {
    let directory = tempfile::tempdir().unwrap();
    let (jobs, queue) = mpsc::sync_channel(MAX_CLIENTS);
    // Both bounds are far beyond the test deadline, so any wait on a producer
    // that is not coming shows up as a receipt that never arrives. Other
    // connections may be open and idle; the writer only ever waits for ones it
    // answered, and a lone connection is its own previous batch.
    let thread = spawn_writer(directory.path(), queue, HOUR, HOUR);
    for n in 1..=3 {
        let (job, receipt) = new_job(0, payload(&format!("lone-{n}")));
        jobs.try_send(job).unwrap();
        // Like a connection, send nothing more until this receipt arrives.
        let receipt = timeout(WAIT, receipt)
            .await
            .expect("no receipt: the writer is waiting for a producer that is not coming")
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
    let (jobs, queue) = mpsc::sync_channel(total);
    let mut receipts = Vec::new();
    for n in 0..total {
        let (job, receipt) = new_job(n as u64, payload(&format!("queued-{n}")));
        jobs.try_send(job).unwrap();
        receipts.push(receipt);
    }
    // Start the writer only now, so its first collection finds every job queued.
    // No settle wait: these connections never send again, so waiting for them
    // would only hold the later batches.
    let thread = spawn_writer(directory.path(), queue, HOUR, Duration::ZERO);
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

#[tokio::test]
async fn a_producer_that_goes_silent_delays_the_next_batch_by_at_most_the_settle_bound() {
    let directory = tempfile::tempdir().unwrap();
    let (jobs, queue) = mpsc::sync_channel(MAX_CLIENTS);
    // Two connections share the first batch, because both are queued before the
    // writer starts.
    let (a_first, a_first_receipt) = new_job(0, payload("a-1"));
    let (b_first, b_first_receipt) = new_job(1, payload("b-1"));
    jobs.try_send(a_first).unwrap();
    jobs.try_send(b_first).unwrap();
    // A modest bound: the wait below is real, but only a hang can reach WAIT.
    let thread = spawn_writer(directory.path(), queue, HOUR, Duration::from_millis(100));
    for receipt in [a_first_receipt, b_first_receipt] {
        let receipt = timeout(WAIT, receipt).await.expect("no receipt").unwrap();
        assert_eq!(receipt.outcome, Outcome::Durable);
    }
    // Both were answered. `a` sends again; `b` never does. The next batch holds
    // for `b`, but only for the settle bound.
    let (a_second, a_second_receipt) = new_job(0, payload("a-2"));
    jobs.try_send(a_second).unwrap();
    let receipt = timeout(WAIT, a_second_receipt)
        .await
        .expect("no receipt: the writer waited on a silent producer past its settle bound")
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Durable);
    drop(jobs);
    thread.join().unwrap();
    assert_eq!(stored_event_ids(directory.path()), ["a-1", "b-1", "a-2"]);
}

#[test]
fn collection_takes_only_what_is_already_queued_up_to_the_cap() {
    let total = 2 * MAX_CLIENTS + 4;
    let (jobs, queue) = mpsc::sync_channel(total);
    for n in 0..total {
        jobs.try_send(new_job(n as u64, format!("queued-{n}").into_bytes()).0)
            .unwrap();
    }
    // No settle wait: each batch's connections never send again here.
    let mut batcher = Batcher::new(queue, HOUR, Duration::ZERO);
    // `jobs` stays alive, so the last batch ends on an empty but still-open
    // queue: the situation of a producer waiting for its receipt.
    let (sizes, order) = bounded(move || {
        let mut sizes = Vec::new();
        let mut order = Vec::new();
        for _ in 0..3 {
            let batch = batcher.next_batch().expect("jobs are queued");
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
    let (jobs, queue) = mpsc::sync_channel(MAX_CLIENTS);
    for n in 0..3u8 {
        jobs.try_send(new_job(u64::from(n), vec![n]).0).unwrap();
    }
    let mut batcher = Batcher::new(queue, Duration::ZERO, HOUR);
    // Jobs are queued, so this call cannot block; a zero hold leaves no time to
    // collect the two behind the first.
    let batch = batcher.next_batch().expect("jobs are queued");
    assert_eq!(batch.len(), 1);
}

#[test]
fn max_hold_also_caps_the_settle_wait() {
    let (jobs, queue) = mpsc::sync_channel(MAX_CLIENTS);
    // The settle bound alone would hold the batch for an hour.
    let mut batcher = Batcher::new(queue, Duration::from_millis(100), HOUR);
    // Connection 1 was answered by the previous commit and never sends again.
    batcher.answered = vec![1];
    jobs.try_send(new_job(0, vec![0]).0).unwrap();
    let batch = bounded(move || batcher.next_batch().expect("a job is queued").len());
    assert_eq!(batch, 1);
    drop(jobs);
}

#[test]
fn lockstep_producers_converge_to_full_batches() {
    let (jobs, queue) = mpsc::sync_channel(MAX_CLIENTS);
    let mut batcher = Batcher::new(queue, HOUR, HOUR);
    // Start from the split the cohort effect produces: the previous commit
    // answered connections 0-3, which have not sent again yet, while 4-7 sent
    // during that commit and are already queued. Without a settle wait the next
    // batch would be the four queued jobs alone, and the two cohorts would
    // alternate from then on.
    batcher.answered = vec![0, 1, 2, 3];
    let mut producers = Vec::new();
    for connection in 0..8u64 {
        let queued = (connection >= 4).then(|| {
            let (job, receipt) = new_job(connection, payload(&format!("first-{connection}")));
            jobs.try_send(job).unwrap();
            receipt
        });
        // Staggered pauses: each client needs a different time to answer. They
        // decide who arrives last, never what the batch contains.
        let pause = Duration::from_millis(10 * (connection + 1));
        producers.push(lockstep_producer(connection, jobs.clone(), queued, pause));
    }
    drop(jobs);
    // The stand-in writer answers every job at once, as the real one does after
    // its commit, and ends when every producer has finished and hung up.
    let sizes = bounded(move || {
        let mut sizes = Vec::new();
        while let Some(batch) = batcher.next_batch() {
            sizes.push(batch.len());
            for job in batch {
                let _ = job.reply.send(durable());
            }
        }
        sizes
    });
    assert_eq!(sizes, [MAX_CLIENTS; ROUNDS]);
    for producer in producers {
        producer.join().unwrap();
    }
}
