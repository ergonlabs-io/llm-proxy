//! Independently resourced Unix metadata collector. Local durability only.
pub mod config;

use config::{Config, Producer};
use proxy_capture_protocol::{
    decode, encode, read_frame, write_frame, Hello, Kind, Outcome, Receipt, Welcome, VERSION,
};
use proxy_capture_spool::{Error, MetadataSpool};
use proxy_observability::records::RequestRecord;
use std::{
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{oneshot, Semaphore},
};

const MAX_CLIENTS: usize = 8;
const DEADLINE: Duration = Duration::from_secs(2);
/// Ceiling on how long the writer spends collecting one batch, counted from its
/// first job and including the settle wait below. With that wait at a few
/// milliseconds this only binds if the writer thread is descheduled mid-batch.
const MAX_BATCH_HOLD: Duration = Duration::from_millis(50);
/// How long a partial batch waits for the producers the previous commit just
/// answered. Those producers send again only after its receipt returns, by
/// which time the writer has already drained the queue for the next commit, so
/// they always miss it and run one commit behind the producers that sent while
/// it was in fsync. Left alone, lockstep producers settle into alternating
/// half-size cohorts. Waiting about one send round trip lets the cohorts merge.
const COHORT_SETTLE: Duration = Duration::from_millis(2);

#[derive(Default)]
pub struct Health {
    pub durable: AtomicU64,
    pub rejected: AtomicU64,
    pub failures: AtomicU64,
}

struct Job {
    payload: Vec<u8>,
    producer: Producer,
    /// The accepted connection that sent this job. A connection has one job in
    /// flight, so the writer can tell which producers a commit answered. The
    /// grant in `producer` cannot: several connections may share one.
    connection: u64,
    reply: oneshot::Sender<Receipt>,
}

pub struct Agent {
    listener: UnixListener,
    config: Arc<Config>,
    jobs: mpsc::SyncSender<Job>,
    done: oneshot::Receiver<()>,
    pub health: Arc<Health>,
}

impl Agent {
    pub fn start(config: Config) -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        config.validate()?;
        let parent = config
            .socket_path
            .parent()
            .ok_or_else(|| io::Error::other("socket requires a parent"))?;
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "socket parent must be a private directory",
            ));
        }
        let (active, recovery) = config.load_keys()?;
        let spool = MetadataSpool::open(config.spool_config(), active, recovery)
            .map_err(io::Error::other)?;
        // Never unlink an existing endpoint: it may belong to a live collector.
        let listener = UnixListener::bind(&config.socket_path)?;
        if let Err(error) =
            std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))
        {
            drop(listener);
            let _ = std::fs::remove_file(&config.socket_path);
            return Err(error);
        }
        let config = Arc::new(config);
        // Rust note: a std `sync_channel` is bounded like tokio's `channel`, and
        // its `Receiver` has the blocking `recv_timeout` the writer's settle wait
        // needs, which tokio's receiver lacks outside an async task.
        let (jobs, receiver) = mpsc::sync_channel(MAX_CLIENTS);
        let (done_tx, done) = oneshot::channel();
        let health = Arc::new(Health::default());
        let writer_health = health.clone();
        let node_id = config.node_id.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("metadata-spool".into())
            .spawn(move || {
                writer(
                    spool,
                    receiver,
                    &node_id,
                    &writer_health,
                    MAX_BATCH_HOLD,
                    COHORT_SETTLE,
                );
                let _ = done_tx.send(());
            })
        {
            drop(listener);
            let _ = std::fs::remove_file(&config.socket_path);
            return Err(error);
        }
        Ok(Self {
            listener,
            config,
            jobs,
            done,
            health,
        })
    }

    /// Stops connections and bounds waiting for a potentially blocked fsync.
    /// A timeout cannot cancel the OS writer; restart establishes durability.
    pub async fn run(self, shutdown: impl std::future::Future<Output = ()>) -> io::Result<()> {
        tokio::pin!(shutdown);
        let clients = Arc::new(Semaphore::new(MAX_CLIENTS));
        let mut tasks = tokio::task::JoinSet::new();
        let mut next_connection = 0u64;
        let outcome = loop {
            tokio::select! {
                _ = &mut shutdown => break Ok(()),
                accepted = self.listener.accept() => {
                    let (stream, _) = match accepted { Ok(value) => value, Err(error) => break Err(error) };
                    let Ok(permit) = clients.clone().try_acquire_owned() else {
                        self.health.rejected.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let config = self.config.clone();
                    let jobs = self.jobs.clone();
                    let health = self.health.clone();
                    let connection = next_connection;
                    next_connection += 1;
                    tasks.spawn(async move {
                        let _permit = permit;
                        if serve(stream, &config, jobs, connection).await.is_err() {
                            health.failures.fetch_add(1, Ordering::Relaxed);
                        }
                    });
                },
                _ = tasks.join_next(), if !tasks.is_empty() => {},
            }
        };
        drop(self.listener);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        drop(self.jobs);
        let drained = tokio::time::timeout(Duration::from_secs(5), self.done).await;
        // The private directory is trusted; remove only this bound socket on graceful exit.
        let _ = std::fs::remove_file(&self.config.socket_path);
        if !matches!(drained, Ok(Ok(()))) {
            return Err(io::Error::other(
                "agent writer drain deadline exceeded; durability unknown",
            ));
        }
        outcome
    }
}

async fn serve(
    mut stream: UnixStream,
    config: &Config,
    jobs: mpsc::SyncSender<Job>,
    connection: u64,
) -> io::Result<()> {
    let uid = stream.peer_cred()?.uid();
    let first = tokio::time::timeout(DEADLINE, read_frame(&mut stream))
        .await
        .map_err(|_| io::Error::other("handshake deadline"))??;
    if first.kind != Kind::Hello {
        return Err(io::Error::other("expected handshake"));
    }
    let hello: Hello = decode(&first.payload)?;
    if hello.version != VERSION {
        return Err(io::Error::other("unsupported protocol version"));
    }
    let producer = config
        .producers
        .iter()
        .find(|grant| grant.uid == uid && grant.producer_id == hello.producer_id)
        .ok_or_else(|| io::Error::other("unauthorized producer"))?
        .clone();
    tokio::time::timeout(
        DEADLINE,
        write_frame(
            &mut stream,
            Kind::Welcome,
            &encode(&Welcome {
                version: VERSION,
                node_id: config.node_id.clone(),
            })?,
        ),
    )
    .await
    .map_err(|_| io::Error::other("handshake deadline"))??;
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(30), read_frame(&mut stream))
            .await
            .map_err(|_| io::Error::other("idle deadline"))??;
        if frame.kind != Kind::Record {
            return Err(io::Error::other("expected metadata record"));
        }
        let (reply, received) = oneshot::channel();
        // One bounded event per connection, with no unbounded waiter/task backlog.
        jobs.try_send(Job {
            payload: frame.payload,
            producer: producer.clone(),
            connection,
            reply,
        })
        .map_err(|_| io::Error::other("writer unavailable"))?;
        let receipt = tokio::time::timeout(DEADLINE, received)
            .await
            .map_err(|_| io::Error::other("commit deadline; durability unknown"))?
            .map_err(|_| io::Error::other("writer unavailable"))?;
        tokio::time::timeout(
            DEADLINE,
            write_frame(&mut stream, Kind::Receipt, &encode(&receipt)?),
        )
        .await
        .map_err(|_| io::Error::other("receipt deadline"))??;
    }
}

/// Forms the writer's commit batches from its queue.
struct Batcher {
    jobs: mpsc::Receiver<Job>,
    max_hold: Duration,
    settle: Duration,
    /// Connections whose jobs were in the previous batch. The writer answers
    /// every job in a batch before it asks for the next one, so these are the
    /// producers the previous commit just answered, and the only ones a batch
    /// ever waits for.
    answered: Vec<u64>,
}

impl Batcher {
    fn new(jobs: mpsc::Receiver<Job>, max_hold: Duration, settle: Duration) -> Self {
        Self {
            jobs,
            max_hold,
            settle,
            answered: Vec::new(),
        }
    }

    /// Blocks for the next job and returns it with the rest of its batch:
    /// whatever else is already queued, at most `MAX_CLIENTS` in all. `None`
    /// means every sender is gone and the queue is drained.
    ///
    /// The batch is committed as soon as nothing is queued, with one exception.
    /// A connection sends nothing more until its receipt returns, so a lone
    /// producer can never fill a batch, and waiting for one would charge every
    /// record the whole window. But producers answered by the previous commit
    /// send again only after it returned, so they miss the next batch and run
    /// a commit behind the rest. So a batch missing any of them waits up to
    /// `settle` (and never past `max_hold`) for those connections, and for no
    /// one else. A lone producer is its own previous batch, so it never waits,
    /// and connections that are open but idle are never waited for.
    fn next_batch(&mut self) -> Option<Vec<Job>> {
        // Rust note: `?` on an `Option` returns `None` early, the way it returns
        // `Err` early from a function that returns `Result`.
        let first = self.jobs.recv().ok()?;
        let started = Instant::now();
        let mut batch = Vec::with_capacity(MAX_CLIENTS);
        batch.push(first);
        let patience = self.settle.min(self.max_hold);
        // The cap must stay within the spool's eight pending records: the spool
        // refuses a larger append batch, and that refusal stops this writer.
        while batch.len() < MAX_CLIENTS && started.elapsed() < self.max_hold {
            match self.jobs.try_recv() {
                Ok(job) => {
                    batch.push(job);
                    continue;
                }
                // Every sender is gone, so nothing more can arrive. The caller's
                // next `next_batch` reports the closed channel.
                Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            // Nothing is queued. Commit now unless a connection the previous
            // batch answered has not sent again.
            let outstanding = self
                .answered
                .iter()
                .any(|id| batch.iter().all(|job| job.connection != *id));
            if !outstanding {
                break;
            }
            // Rust note: `let ... else` binds on success and otherwise runs a
            // block that must diverge, here `break` once patience is spent.
            let Some(remaining) = patience.checked_sub(started.elapsed()) else {
                break;
            };
            match self.jobs.recv_timeout(remaining) {
                Ok(job) => batch.push(job),
                // Out of patience, or every sender is gone.
                Err(_) => break,
            }
        }
        self.answered.clear();
        self.answered.extend(batch.iter().map(|job| job.connection));
        Some(batch)
    }
}

fn writer(
    mut spool: MetadataSpool,
    jobs: mpsc::Receiver<Job>,
    node_id: &str,
    health: &Health,
    max_hold: Duration,
    settle: Duration,
) {
    let mut batcher = Batcher::new(jobs, max_hold, settle);
    while let Some(batch) = batcher.next_batch() {
        let mut prepared = Vec::with_capacity(MAX_CLIENTS);
        let mut fatal = false;
        for job in batch {
            let mut receipt = Receipt {
                version: VERSION,
                node_id: node_id.to_owned(),
                event_id: String::new(),
                sequence: None,
                outcome: Outcome::Invalid,
            };
            let record: RequestRecord = match serde_json::from_slice(&job.payload) {
                Ok(record) => record,
                Err(_) => {
                    health.rejected.fetch_add(1, Ordering::Relaxed);
                    let _ = job.reply.send(receipt);
                    continue;
                }
            };
            if record.event_id.len() <= 128 {
                receipt.event_id.clone_from(&record.event_id);
            }
            if record.validate(64).is_err()
                || record.event_id.len() > 128
                || record.event_id.chars().any(char::is_control)
                || record.request_id.len() > 128
                || record.tenant_id.len() > 512
                || record.user_id.as_ref().is_some_and(|id| id.len() > 512)
                || record.response_flags.len() > 32
                || record.attempts.iter().any(|attempt| {
                    attempt.schema_version != proxy_observability::records::SCHEMA_VERSION
                        || attempt.request_id != record.request_id
                        || attempt.event_id.is_empty()
                        || attempt.event_id.len() > 128
                        || attempt.attempt_id.is_empty()
                        || attempt.attempt_id.len() > 128
                })
            {
                health.rejected.fetch_add(1, Ordering::Relaxed);
                let _ = job.reply.send(receipt);
                continue;
            }
            if !job.producer.tenants.contains(&record.tenant_id) {
                receipt.outcome = Outcome::Unauthorized;
                health.rejected.fetch_add(1, Ordering::Relaxed);
                let _ = job.reply.send(receipt);
                continue;
            }
            let canonical = match serde_json::to_value(&record) {
                Ok(value) => value,
                Err(_) => {
                    let _ = job.reply.send(receipt);
                    continue;
                }
            };
            let source: serde_json::Value = match serde_json::from_slice(&job.payload) {
                Ok(value) => value,
                Err(_) => {
                    let _ = job.reply.send(receipt);
                    continue;
                }
            };
            // Reject unsupported fields, including body/header additions, rather
            // than acknowledging a silently discarded part of an envelope.
            if !supported_shape(&source, &canonical) {
                health.rejected.fetch_add(1, Ordering::Relaxed);
                let _ = job.reply.send(receipt);
                continue;
            }
            let payload = match serde_json::to_vec(&record) {
                Ok(payload) => payload,
                Err(_) => {
                    let _ = job.reply.send(receipt);
                    continue;
                }
            };
            prepared.push((job.reply, receipt, payload));
        }
        let payloads: Vec<&[u8]> = prepared
            .iter()
            .map(|(_, _, payload)| payload.as_slice())
            .collect();
        let appended = spool.append_batch(&payloads);
        drop(payloads);
        let appended = match appended {
            Ok(results) => results,
            Err(_) => {
                for (reply, mut receipt, _) in prepared {
                    receipt.outcome = Outcome::Unavailable;
                    health.failures.fetch_add(1, Ordering::Relaxed);
                    let _ = reply.send(receipt);
                }
                break;
            }
        };
        let mut pending = Vec::with_capacity(MAX_CLIENTS);
        for ((reply, mut receipt, _), appended) in prepared.into_iter().zip(appended) {
            match appended {
                Ok(appended) => {
                    receipt.sequence = Some(appended.sequence);
                    pending.push((reply, receipt));
                }
                Err(Error::Full) => {
                    receipt.outcome = Outcome::Full;
                    health.rejected.fetch_add(1, Ordering::Relaxed);
                    let _ = reply.send(receipt);
                }
                Err(Error::RecordTooLarge) => {
                    health.rejected.fetch_add(1, Ordering::Relaxed);
                    let _ = reply.send(receipt);
                }
                Err(_) => {
                    receipt.outcome = Outcome::Unavailable;
                    health.failures.fetch_add(1, Ordering::Relaxed);
                    let _ = reply.send(receipt);
                    fatal = true;
                }
            }
        }
        if !pending.is_empty() {
            let committed = !fatal && spool.commit().is_ok();
            for (reply, mut receipt) in pending {
                receipt.outcome = if committed {
                    Outcome::Durable
                } else {
                    Outcome::Unavailable
                };
                if committed {
                    health.durable.fetch_add(1, Ordering::Relaxed);
                } else {
                    health.failures.fetch_add(1, Ordering::Relaxed);
                }
                let _ = reply.send(receipt);
            }
            fatal |= !committed;
        }
        if fatal {
            break;
        }
    }
}

fn supported_shape(source: &serde_json::Value, canonical: &serde_json::Value) -> bool {
    match (source, canonical) {
        (serde_json::Value::Object(source), serde_json::Value::Object(canonical)) => {
            source.iter().all(|(key, value)| {
                canonical
                    .get(key)
                    .is_some_and(|expected| supported_shape(value, expected))
            })
        }
        (serde_json::Value::Array(source), serde_json::Value::Array(canonical)) => {
            source.len() == canonical.len()
                && source
                    .iter()
                    .zip(canonical)
                    .all(|(value, expected)| supported_shape(value, expected))
        }
        (serde_json::Value::String(value), _) => value.len() <= 512,
        _ => true,
    }
}

#[cfg(test)]
mod writer_tests;
