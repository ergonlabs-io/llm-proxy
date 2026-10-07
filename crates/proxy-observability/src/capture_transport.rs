//! Local metadata transport, invoked only by the dedicated collector thread.
use proxy_capture_protocol::{
    decode, encode, read_frame, write_frame, Hello, Kind, Outcome, Receipt, Welcome, VERSION,
};
use std::{
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};
use tokio::net::UnixStream;

#[derive(Debug, Clone)]
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
}

impl TransportWriter {
    pub(crate) fn new(config: AgentTransportConfig) -> io::Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            runtime: None,
            connection: None,
        })
    }
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
        let payload = data.strip_suffix(b"\n").unwrap_or(data);
        if payload.len() > proxy_capture_protocol::MAX_RECORD_BYTES {
            return Err(io::Error::other("encoded metadata exceeds frame limit"));
        }
        // Already bounded and serialized by the collector, never the request worker.
        let record: crate::records::RequestRecord = serde_json::from_slice(payload)
            .map_err(|_| io::Error::other("invalid metadata envelope"))?;
        let config = &self.config;
        let connection = &mut self.connection;
        if self.runtime.is_none() {
            self.runtime = Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?,
            );
        }
        self.runtime.as_ref().unwrap().block_on(async {
            for attempt in 0..3 {
                let exchange = async {
                    if connection.is_none() {
                        *connection = Some(connect(config).await?);
                    }
                    let stream = connection.as_mut().unwrap();
                    write_frame(stream, Kind::Record, payload).await?;
                    let frame = read_frame(stream).await?;
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
                match tokio::time::timeout(Duration::from_secs(2), exchange).await {
                    Ok(Ok(receipt))
                        if receipt.outcome == Outcome::Durable
                            && receipt.sequence.is_some_and(|s| s > 0) =>
                    {
                        return Ok(data.len())
                    }
                    Ok(Ok(_)) => return Err(io::Error::other("metadata agent declined capture")),
                    _ => {
                        *connection = None;
                        if attempt < 2 {
                            // Finite reconnect jitter, on this single off-path writer only.
                            use rand::Rng;
                            let jitter = rand::thread_rng().gen_range(0..=25);
                            tokio::time::sleep(Duration::from_millis((25 << attempt) + jitter))
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
