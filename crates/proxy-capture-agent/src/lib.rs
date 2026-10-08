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
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{mpsc, oneshot, Semaphore},
};

const MAX_CLIENTS: usize = 8;
const DEADLINE: Duration = Duration::from_secs(2);
const COMMIT_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Default)]
pub struct Health {
    pub durable: AtomicU64,
    pub rejected: AtomicU64,
    pub failures: AtomicU64,
}

struct Job {
    payload: Vec<u8>,
    producer: Producer,
    reply: oneshot::Sender<Receipt>,
}

pub struct Agent {
    listener: UnixListener,
    config: Arc<Config>,
    jobs: mpsc::Sender<Job>,
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
        // Never unlink an existing endpoint: it may belong to a live collector.
        let (active, recovery) = config.load_keys()?;
        let spool = MetadataSpool::open(config.spool_config(), active, recovery)
            .map_err(io::Error::other)?;
        let listener = UnixListener::bind(&config.socket_path)?;
        if let Err(error) =
            std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))
        {
            drop(listener);
            let _ = std::fs::remove_file(&config.socket_path);
            return Err(error);
        }
        let config = Arc::new(config);
        let (jobs, receiver) = mpsc::channel(MAX_CLIENTS);
        let (done_tx, done) = oneshot::channel();
        let health = Arc::new(Health::default());
        let writer_health = health.clone();
        let node_id = config.node_id.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("metadata-spool".into())
            .spawn(move || {
                writer(spool, receiver, &node_id, &writer_health);
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
                    tasks.spawn(async move {
                        let _permit = permit;
                        if serve(stream, &config, jobs).await.is_err() {
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

async fn serve(mut stream: UnixStream, config: &Config, jobs: mpsc::Sender<Job>) -> io::Result<()> {
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

fn writer(mut spool: MetadataSpool, mut jobs: mpsc::Receiver<Job>, node_id: &str, health: &Health) {
    while let Some(first) = jobs.blocking_recv() {
        let deadline = Instant::now() + COMMIT_INTERVAL;
        let mut batch = vec![first];
        // At most one frame per admitted connection. Polling is isolated in the agent writer.
        while batch.len() < MAX_CLIENTS && Instant::now() < deadline {
            match jobs.try_recv() {
                Ok(job) => batch.push(job),
                Err(mpsc::error::TryRecvError::Disconnected) => break,
                Err(mpsc::error::TryRecvError::Empty) => {
                    std::thread::park_timeout(Duration::from_millis(2))
                }
            }
        }
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
