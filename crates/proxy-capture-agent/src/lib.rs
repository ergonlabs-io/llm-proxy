//! Independently resourced Unix metadata collector. Local durability only.
pub mod config;

use config::{Config, Producer};
use proxy_capture_protocol::{
    decode, encode, read_frame, write_frame, Frame, Hello, InspectOutcome, Kind, Outcome, Receipt,
    RecordsQuery, RecordsReply, SpoolSnapshot, SpooledRecord, StatsQuery, StatsReply, Welcome,
    MAX_INSPECT_RECORDS, MAX_INSPECT_RECORD_BYTES, VERSION,
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

/// What the bounded queue to the writer thread carries. Inspection shares the
/// queue so a flood of queries cannot grow an unbounded backlog either, and so
/// the spool is only ever touched from the writer thread.
// Rust note: an enum holds one of several shapes in one type, so a single
// channel can carry both kinds of work and `match` must handle each.
enum Work {
    Record(Job),
    Inspect(InspectJob),
}

/// A read-only question about the spool. Answering it never changes the spool.
struct InspectJob {
    query: Query,
    /// Tenants of the asking grant; records of any other tenant are not returned.
    tenants: Vec<String>,
    reply: oneshot::Sender<InspectReply>,
}

enum Query {
    Stats,
    Records {
        after_sequence: u64,
        max_records: u16,
    },
}

enum InspectReply {
    Stats(StatsReply),
    Records(RecordsReply),
}

impl InspectReply {
    /// The reply for a query that was not answered from the spool.
    fn rejected(stats: bool, outcome: InspectOutcome, after_sequence: u64) -> Self {
        if stats {
            Self::Stats(StatsReply {
                version: VERSION,
                outcome,
                stats: None,
            })
        } else {
            Self::Records(RecordsReply {
                version: VERSION,
                outcome,
                records: Vec::new(),
                next_after_sequence: after_sequence,
                durable_through_sequence: 0,
            })
        }
    }
}

pub struct Agent {
    listener: UnixListener,
    config: Arc<Config>,
    jobs: mpsc::SyncSender<Work>,
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
        let max_disk_bytes = config.spool.max_disk_bytes;
        if let Err(error) = std::thread::Builder::new()
            .name("metadata-spool".into())
            .spawn(move || {
                writer(
                    spool,
                    receiver,
                    &node_id,
                    max_disk_bytes,
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
    jobs: mpsc::SyncSender<Work>,
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
        if matches!(frame.kind, Kind::StatsQuery | Kind::RecordsQuery) {
            if !serve_query(&mut stream, &jobs, &producer, frame).await? {
                return Ok(());
            }
            continue;
        }
        if frame.kind != Kind::Record {
            return Err(io::Error::other("expected metadata record"));
        }
        let (reply, received) = oneshot::channel();
        // One bounded event per connection, with no unbounded waiter/task backlog.
        jobs.try_send(Work::Record(Job {
            payload: frame.payload,
            producer: producer.clone(),
            connection,
            reply,
        }))
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

/// Answers one inspection frame. Returns whether the connection stays open:
/// a grant without `inspect` is told so and then dropped, while a malformed or
/// out-of-range query is answered `Invalid` and the connection kept.
async fn serve_query(
    stream: &mut UnixStream,
    jobs: &mpsc::SyncSender<Work>,
    producer: &Producer,
    frame: Frame,
) -> io::Result<bool> {
    let stats = frame.kind == Kind::StatsQuery;
    // Authorize before decoding: an ungranted producer learns nothing from the
    // validity of its query.
    if !producer.inspect {
        let denied = InspectReply::rejected(stats, InspectOutcome::Unauthorized, 0);
        write_inspect_reply(stream, &denied).await?;
        return Ok(false);
    }
    let (query, after_sequence) = if stats {
        let query: StatsQuery = decode(&frame.payload)?;
        ((query.version == VERSION).then_some(Query::Stats), 0)
    } else {
        let query: RecordsQuery = decode(&frame.payload)?;
        let valid =
            query.version == VERSION && (1..=MAX_INSPECT_RECORDS).contains(&query.max_records);
        (
            valid.then_some(Query::Records {
                after_sequence: query.after_sequence,
                max_records: query.max_records,
            }),
            query.after_sequence,
        )
    };
    let Some(query) = query else {
        let invalid = InspectReply::rejected(stats, InspectOutcome::Invalid, after_sequence);
        write_inspect_reply(stream, &invalid).await?;
        return Ok(true);
    };
    let (reply, received) = oneshot::channel();
    let queued = jobs.try_send(Work::Inspect(InspectJob {
        query,
        tenants: producer.tenants.clone(),
        reply,
    }));
    let answer = if queued.is_err() {
        InspectReply::rejected(stats, InspectOutcome::Unavailable, after_sequence)
    } else {
        match tokio::time::timeout(DEADLINE, received).await {
            Err(_) => return Err(io::Error::other("inspect deadline")),
            Ok(Ok(answer)) => answer,
            // The writer stopped and dropped the job.
            Ok(Err(_)) => {
                InspectReply::rejected(stats, InspectOutcome::Unavailable, after_sequence)
            }
        }
    };
    write_inspect_reply(stream, &answer).await?;
    Ok(true)
}

async fn write_inspect_reply(stream: &mut UnixStream, reply: &InspectReply) -> io::Result<()> {
    let (kind, payload) = match reply {
        InspectReply::Stats(reply) => (Kind::StatsReply, encode(reply)?),
        InspectReply::Records(reply) => (Kind::RecordsReply, encode(reply)?),
    };
    tokio::time::timeout(DEADLINE, write_frame(stream, kind, &payload))
        .await
        .map_err(|_| io::Error::other("inspect reply deadline"))?
}

/// One round of writer work: records to commit, and inspections to answer once
/// they have been.
struct Batch {
    records: Vec<Job>,
    inspects: Vec<InspectJob>,
}

/// Forms the writer's commit batches from its queue.
struct Batcher {
    jobs: mpsc::Receiver<Work>,
    max_hold: Duration,
    settle: Duration,
    /// Connections whose jobs were in the previous batch. The writer answers
    /// every job in a batch before it asks for the next one, so these are the
    /// producers the previous commit just answered, and the only ones a batch
    /// ever waits for.
    answered: Vec<u64>,
}

impl Batcher {
    fn new(jobs: mpsc::Receiver<Work>, max_hold: Duration, settle: Duration) -> Self {
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
    /// An inspection ends collection: it is returned with the records gathered
    /// so far, which the writer commits first, so a query sees every record
    /// acknowledged before it was sent and never waits on a settle window. An
    /// inspection alone is returned at once and leaves the settle cohort alone.
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
    fn next_batch(&mut self) -> Option<Batch> {
        // Rust note: `?` on an `Option` returns `None` early, the way it returns
        // `Err` early from a function that returns `Result`.
        let first = match self.jobs.recv().ok()? {
            Work::Record(job) => job,
            Work::Inspect(inspect) => {
                return Some(Batch {
                    records: Vec::new(),
                    inspects: vec![inspect],
                })
            }
        };
        let started = Instant::now();
        let mut batch = Vec::with_capacity(MAX_CLIENTS);
        let mut inspects = Vec::new();
        batch.push(first);
        let patience = self.settle.min(self.max_hold);
        // The cap must stay within the spool's eight pending records: the spool
        // refuses a larger append batch, and that refusal stops this writer.
        while batch.len() < MAX_CLIENTS && started.elapsed() < self.max_hold {
            match self.jobs.try_recv() {
                Ok(Work::Record(job)) => {
                    batch.push(job);
                    continue;
                }
                Ok(Work::Inspect(inspect)) => {
                    inspects.push(inspect);
                    break;
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
                Ok(Work::Record(job)) => batch.push(job),
                Ok(Work::Inspect(inspect)) => {
                    inspects.push(inspect);
                    break;
                }
                // Out of patience, or every sender is gone.
                Err(_) => break,
            }
        }
        self.answered.clear();
        self.answered.extend(batch.iter().map(|job| job.connection));
        Some(Batch {
            records: batch,
            inspects,
        })
    }
}

fn writer(
    mut spool: MetadataSpool,
    jobs: mpsc::Receiver<Work>,
    node_id: &str,
    max_disk_bytes: u64,
    health: &Health,
    max_hold: Duration,
    settle: Duration,
) {
    let mut batcher = Batcher::new(jobs, max_hold, settle);
    while let Some(Batch { records, inspects }) = batcher.next_batch() {
        if records.is_empty() {
            for job in inspects {
                answer_inspect(&spool, node_id, max_disk_bytes, health, job);
            }
            continue;
        }
        let mut prepared = Vec::with_capacity(MAX_CLIENTS);
        let mut fatal = false;
        for job in records {
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
        // After the commit, so a query sees the records it was queued behind. On
        // a fatal round the spool is no longer trusted and the jobs are dropped,
        // which the connection reports as `Unavailable`.
        if !fatal {
            for job in inspects {
                answer_inspect(&spool, node_id, max_disk_bytes, health, job);
            }
        }
        if fatal {
            break;
        }
    }
}

/// Answers an inspection on the writer thread. Reads only: nothing here
/// appends, commits or acknowledges, and record contents are never logged.
fn answer_inspect(
    spool: &MetadataSpool,
    node_id: &str,
    max_disk_bytes: u64,
    health: &Health,
    job: InspectJob,
) {
    let reply = match &job.query {
        Query::Stats => InspectReply::Stats(match spool.stats() {
            Ok(stats) => StatsReply {
                version: VERSION,
                outcome: InspectOutcome::Ok,
                stats: Some(SpoolSnapshot {
                    node_id: node_id.to_owned(),
                    next_sequence: stats.next_sequence,
                    durable_through_sequence: stats.durable_through_sequence,
                    acknowledged_through_sequence: stats.acknowledged_through_sequence,
                    pending_records: stats.pending_records,
                    retained_records: stats.retained_records,
                    database_bytes: stats.database_bytes,
                    disk_bytes: stats.disk_bytes,
                    max_disk_bytes,
                    quarantine_bytes: stats.quarantine_bytes,
                    poisoned: stats.poisoned,
                    durable_total: health.durable.load(Ordering::Relaxed),
                    rejected_total: health.rejected.load(Ordering::Relaxed),
                    failures_total: health.failures.load(Ordering::Relaxed),
                }),
            },
            Err(_) => StatsReply {
                version: VERSION,
                outcome: InspectOutcome::Unavailable,
                stats: None,
            },
        }),
        Query::Records {
            after_sequence,
            max_records,
        } => records_page(spool, &job.tenants, *after_sequence, *max_records),
    };
    let _ = job.reply.send(reply);
}

fn records_page(
    spool: &MetadataSpool,
    tenants: &[String],
    after_sequence: u64,
    max_records: u16,
) -> InspectReply {
    let unavailable = || InspectReply::rejected(false, InspectOutcome::Unavailable, after_sequence);
    let Ok(stats) = spool.stats() else {
        return unavailable();
    };
    let Ok(replayed) = spool.replay(
        after_sequence,
        usize::from(max_records),
        MAX_INSPECT_RECORD_BYTES,
    ) else {
        return unavailable();
    };
    // The cursor passes records of other tenants too, so a page that holds
    // none of this grant's records still makes progress.
    let next_after_sequence = replayed.last().map_or(after_sequence, |row| row.sequence);
    let mut records = Vec::new();
    for row in replayed {
        let Ok(record) = serde_json::from_slice::<serde_json::Value>(&row.payload) else {
            return unavailable();
        };
        let allowed = record
            .get("tenant_id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|tenant| tenants.iter().any(|granted| granted == tenant));
        if allowed {
            records.push(SpooledRecord {
                sequence: row.sequence,
                record,
            });
        }
    }
    InspectReply::Records(RecordsReply {
        version: VERSION,
        outcome: InspectOutcome::Ok,
        records,
        next_after_sequence,
        durable_through_sequence: stats.durable_through_sequence,
    })
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

#[cfg(test)]
mod inspect_tests;
