//! Local metadata transport, invoked only by the dedicated collector thread.
use proxy_capture_protocol::{
    decode, encode, read_frame, write_frame, Hello, Kind, Outcome, Receipt, Welcome, VERSION,
};
use std::{
    io::{self, Write},
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::net::UnixStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureTransportLimits {
    pub connect_deadline: Duration,
    pub write_deadline: Duration,
    pub ack_deadline: Duration,
    pub event_deadline: Duration,
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    pub max_attempts: u16,
    pub drain_deadline: Duration,
}

impl Default for CaptureTransportLimits {
    fn default() -> Self {
        Self {
            connect_deadline: Duration::from_millis(250),
            write_deadline: Duration::from_secs(1),
            ack_deadline: Duration::from_secs(2),
            event_deadline: Duration::from_secs(10),
            backoff_initial: Duration::from_millis(50),
            backoff_max: Duration::from_secs(5),
            max_attempts: 4,
            drain_deadline: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTransportConfig {
    pub socket_path: PathBuf,
    pub expected_agent_uid: u32,
    pub expected_node_id: String,
    pub producer_id: String,
}

impl AgentTransportConfig {
    pub fn validate(&self) -> io::Result<()> {
        if !self.socket_path.is_absolute()
            || self.expected_node_id.is_empty()
            || self.expected_node_id.len() > 128
            || self.expected_node_id.chars().any(char::is_control)
            || self.producer_id.is_empty()
            || self.producer_id.len() > 128
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid metadata agent endpoint or identity",
            ));
        }
        Ok(())
    }
}

pub(crate) struct TransportWriter {
    config: AgentTransportConfig,
    runtime: Option<tokio::runtime::Runtime>,
    connection: Option<UnixStream>,
    limits: CaptureTransportLimits,
    max_encoded_record_bytes: usize,
    event_deadline: Option<Instant>,
}

impl TransportWriter {
    pub(crate) fn new(config: AgentTransportConfig) -> io::Result<Self> {
        Self::with_limits(
            config,
            CaptureTransportLimits {
                max_attempts: 3,
                ..Default::default()
            },
            proxy_capture_protocol::MAX_RECORD_BYTES,
        )
    }

    pub(crate) fn with_limits(
        config: AgentTransportConfig,
        limits: CaptureTransportLimits,
        max_encoded_record_bytes: usize,
    ) -> io::Result<Self> {
        config.validate()?;
        if limits.max_attempts == 0
            || limits.backoff_initial > limits.backoff_max
            || max_encoded_record_bytes == 0
            || max_encoded_record_bytes > proxy_capture_protocol::MAX_RECORD_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid capture transport limits",
            ));
        }
        Ok(Self {
            config,
            runtime: None,
            connection: None,
            limits,
            max_encoded_record_bytes,
            event_deadline: None,
        })
    }

    pub(crate) fn set_event_deadline(&mut self, deadline: Instant) {
        self.event_deadline = Some(deadline);
    }
}

async fn bounded<T>(
    deadline: Instant,
    phase: Duration,
    work: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "metadata event deadline expired",
        ));
    }
    tokio::time::timeout(remaining.min(phase), work)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "metadata transport deadline expired",
            )
        })?
}

fn retry_cap(limits: &CaptureTransportLimits, attempt: u16) -> Duration {
    let mut cap = limits.backoff_initial.min(limits.backoff_max);
    for _ in 0..attempt {
        cap = cap.saturating_mul(2).min(limits.backoff_max);
        if cap == limits.backoff_max {
            break;
        }
    }
    cap
}

async fn connect(config: &AgentTransportConfig) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(&config.socket_path).await?;
    if stream.peer_cred()?.uid() != config.expected_agent_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unauthorized metadata agent",
        ));
    }
    write_frame(
        &mut stream,
        Kind::Hello,
        &encode(&Hello {
            version: VERSION,
            producer_id: config.producer_id.clone(),
        })?,
    )
    .await?;
    let frame = read_frame(&mut stream).await?;
    if frame.kind != Kind::Welcome {
        return Err(io::Error::other("invalid agent handshake"));
    }
    let welcome: Welcome = decode(&frame.payload)?;
    if welcome.version != VERSION || welcome.node_id != config.expected_node_id {
        return Err(io::Error::other("agent identity or protocol mismatch"));
    }
    Ok(stream)
}

impl Write for TransportWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let started = Instant::now();
        let deadline = self
            .event_deadline
            .take()
            .or_else(|| started.checked_add(self.limits.event_deadline))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "metadata event deadline overflow",
                )
            })?;
        let payload = data.strip_suffix(b"\n").unwrap_or(data);
        if payload.len() > self.max_encoded_record_bytes {
            return Err(io::Error::other("encoded metadata exceeds frame limit"));
        }
        // Already bounded and serialized by the collector, never the request worker.
        let record: crate::records::RequestRecord = serde_json::from_slice(payload)
            .map_err(|_| io::Error::other("invalid metadata envelope"))?;
        let config = &self.config;
        let connection = &mut self.connection;
        let limits = &self.limits;
        if self.runtime.is_none() {
            self.runtime = Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?,
            );
        }
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| io::Error::other("metadata runtime unavailable"))?;
        runtime.block_on(async {
            for attempt in 0..limits.max_attempts {
                if Instant::now() >= deadline {
                    break;
                }
                let exchange = async {
                    if connection.is_none() {
                        *connection = Some(
                            bounded(deadline, limits.connect_deadline, connect(config)).await?,
                        );
                    }
                    let stream = connection
                        .as_mut()
                        .ok_or_else(|| io::Error::other("metadata connection unavailable"))?;
                    bounded(
                        deadline,
                        limits.write_deadline,
                        write_frame(stream, Kind::Record, payload),
                    )
                    .await?;
                    let frame = bounded(deadline, limits.ack_deadline, read_frame(stream)).await?;
                    if frame.kind != Kind::Receipt {
                        return Err(io::Error::other("invalid metadata receipt"));
                    }
                    let receipt: Receipt = decode(&frame.payload)?;
                    if receipt.version != VERSION
                        || receipt.node_id != config.expected_node_id
                        || receipt.event_id != record.event_id
                    {
                        return Err(io::Error::other("metadata receipt identity mismatch"));
                    }
                    Ok(receipt)
                };
                match exchange.await {
                    Ok(receipt)
                        if receipt.outcome == Outcome::Durable
                            && receipt.sequence.is_some_and(|s| s > 0) =>
                    {
                        return Ok(data.len())
                    }
                    Ok(_) => return Err(io::Error::other("metadata agent declined capture")),
                    _ => {
                        *connection = None;
                        if attempt + 1 < limits.max_attempts {
                            // Finite reconnect jitter, on this single off-path writer only.
                            use rand::Rng;
                            let nanos = rand::thread_rng()
                                .gen_range(0..=retry_cap(limits, attempt).as_nanos());
                            let jitter = Duration::new(
                                (nanos / 1_000_000_000) as u64,
                                (nanos % 1_000_000_000) as u32,
                            );
                            tokio::time::sleep(
                                jitter.min(deadline.saturating_duration_since(Instant::now())),
                            )
                            .await;
                        }
                    }
                }
            }
            Err(io::Error::other(
                "metadata delivery failed or durability unknown",
            ))
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::MetadataDelivery,
        records::{tests::record, RequestRecordSink, SubmitResult},
        stats::{prometheus_render, MetadataDeliveryStats, StatsControl},
    };
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn configured_handshake_and_ack_deadlines_exhaust_attempts() {
        for handshake in [true, false] {
            let temp = tempfile::tempdir().unwrap();
            let socket = temp.path().join("socket");
            let uid = UnixStream::pair().unwrap().0.peer_cred().unwrap().uid();
            let listener = UnixListener::bind(&socket).unwrap();
            let server = tokio::spawn(async move {
                let mut streams = Vec::new();
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    read_frame(&mut stream).await.unwrap();
                    if !handshake {
                        write_frame(
                            &mut stream,
                            Kind::Welcome,
                            &encode(&Welcome {
                                version: VERSION,
                                node_id: "node".into(),
                            })
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                        assert_eq!(read_frame(&mut stream).await.unwrap().kind, Kind::Record);
                    }
                    streams.push(stream);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            });
            let writer = tokio::task::spawn_blocking(move || {
                let mut writer = TransportWriter::with_limits(
                    AgentTransportConfig {
                        socket_path: socket,
                        expected_agent_uid: uid,
                        expected_node_id: "node".into(),
                        producer_id: "proxy".into(),
                    },
                    CaptureTransportLimits {
                        connect_deadline: Duration::from_millis(20),
                        ack_deadline: Duration::from_millis(20),
                        backoff_initial: Duration::ZERO,
                        backoff_max: Duration::ZERO,
                        max_attempts: 2,
                        ..Default::default()
                    },
                    proxy_capture_protocol::MAX_RECORD_BYTES,
                )
                .unwrap();
                writer.write(&serde_json::to_vec(&record()).unwrap())
            });
            assert!(tokio::time::timeout(Duration::from_secs(2), writer)
                .await
                .unwrap()
                .unwrap()
                .is_err());
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn expired_queue_age_and_encoded_bound_prevent_connect() {
        let config = AgentTransportConfig {
            socket_path: PathBuf::from("/nonexistent/capture/socket"),
            expected_agent_uid: 0,
            expected_node_id: "node".into(),
            producer_id: "proxy".into(),
        };
        let payload = serde_json::to_vec(&record()).unwrap();
        let mut writer =
            TransportWriter::with_limits(config.clone(), Default::default(), payload.len() - 1)
                .unwrap();
        assert!(writer.write(&payload).is_err());
        assert!(writer.runtime.is_none());
        let mut writer =
            TransportWriter::with_limits(config, Default::default(), payload.len()).unwrap();
        writer.set_event_deadline(Instant::now());
        let started = Instant::now();
        assert!(writer.write(&payload).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(writer.event_deadline.is_none());
    }

    #[test]
    fn exponential_backoff_saturates() {
        let limits = CaptureTransportLimits::default();
        assert_eq!(limits.max_attempts, 4);
        assert_eq!(retry_cap(&limits, 0), Duration::from_millis(50));
        assert_eq!(retry_cap(&limits, 1), Duration::from_millis(100));
        assert_eq!(retry_cap(&limits, u16::MAX), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn event_age_caps_blocked_write() {
        let (mut sender, _receiver) = tokio::io::duplex(1);
        let started = Instant::now();
        let error = bounded(
            started + Duration::from_millis(20),
            Duration::from_secs(1),
            write_frame(&mut sender, Kind::Record, b"record"),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn forged_event_receipts_never_increment_durable_delivery() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("socket");
        let uid = UnixStream::pair().unwrap().0.peer_cred().unwrap().uid();
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert_eq!(read_frame(&mut stream).await.unwrap().kind, Kind::Hello);
                write_frame(
                    &mut stream,
                    Kind::Welcome,
                    &encode(&Welcome {
                        version: VERSION,
                        node_id: "node".into(),
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
                assert_eq!(read_frame(&mut stream).await.unwrap().kind, Kind::Record);
                write_frame(
                    &mut stream,
                    Kind::Receipt,
                    &encode(&Receipt {
                        version: VERSION,
                        event_id: "wrong-event".into(),
                        node_id: "node".into(),
                        sequence: Some(1),
                        outcome: Outcome::Durable,
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
            }
        });
        let control = StatsControl::new(1);
        let (sink, delivery) = MetadataDelivery::start_agent(
            AgentTransportConfig {
                socket_path: socket,
                expected_agent_uid: uid,
                expected_node_id: "node".into(),
                producer_id: "proxy".into(),
            },
            1,
            MetadataDeliveryStats::resolve(&control),
        )
        .unwrap();
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        drop(sink);
        let summary = delivery.shutdown(Duration::from_secs(8)).await;
        assert!(!summary.timed_out);
        assert_eq!((summary.written, summary.failed), (0, 1));
        let scrape = prometheus_render::render(&control.registry());
        assert!(scrape.contains("envoy_llmproxy_metadata_durable 0"));
        assert!(scrape.contains("envoy_llmproxy_metadata_written 0"));
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn stalled_agent_cannot_extend_proxy_shutdown_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("socket");
        let uid = UnixStream::pair().unwrap().0.peer_cred().unwrap().uid();
        let listener = UnixListener::bind(&socket).unwrap();
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, held) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_frame(&mut stream).await.unwrap();
            let _ = entered.send(());
            let _ = held.await;
        });
        let control = StatsControl::new(1);
        let stats = MetadataDeliveryStats::resolve(&control);
        let failures = control.resolve(&crate::stats::instruments::METADATA_WRITE_FAILURES, &[]);
        let (sink, delivery) = MetadataDelivery::start_agent(
            AgentTransportConfig {
                socket_path: socket,
                expected_agent_uid: uid,
                expected_node_id: "node".into(),
                producer_id: "proxy".into(),
            },
            1,
            stats,
        )
        .unwrap();
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        drop(sink);
        tokio::time::timeout(Duration::from_secs(2), observed)
            .await
            .unwrap()
            .unwrap();
        let summary = tokio::time::timeout(
            Duration::from_secs(1),
            delivery.shutdown(Duration::from_millis(20)),
        )
        .await
        .unwrap();
        assert!(summary.timed_out);
        assert_eq!(summary.written, 0);
        assert_eq!(summary.unwritten, 1);
        let _ = release.send(());
        server.await.unwrap();
        tokio::time::timeout(Duration::from_secs(8), async {
            while control.registry().value(failures) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}
