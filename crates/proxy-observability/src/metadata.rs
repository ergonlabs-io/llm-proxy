//! Metadata delivery runs on a dedicated OS thread. Blocking file collectors
//! cannot block forwarding, the control runtime, or the shutdown deadline.
//! This append-only JSONL collector is best effort; write success is not a
//! durability acknowledgement and this file is not a billing ledger.

use crate::records::{BoundedRecordSink, DropCounters};
use crate::stats::MetadataDeliveryStats;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::oneshot;

pub struct MetadataDelivery {
    done: oneshot::Receiver<()>,
    counters: Arc<DropCounters>,
    written: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Copy)]
pub struct DeliverySummary {
    pub written: u64,
    pub failed: u64,
    /// Accepted records not written or failed at the shutdown snapshot.
    /// On timeout, the detached writer can still complete them afterward.
    pub unwritten: u64,
    pub admission: crate::records::DropCounterSnapshot,
    pub timed_out: bool,
}

impl MetadataDelivery {
    /// Opt-in authenticated Unix agent delivery. Success means a verified durable
    /// local receipt, not remote indexing. Agent outages never close forwarding.
    #[cfg(unix)]
    pub fn start_agent(
        config: crate::capture_transport::AgentTransportConfig,
        capacity: usize,
        stats: MetadataDeliveryStats,
    ) -> io::Result<(BoundedRecordSink, Self)> {
        let writer = crate::capture_transport::TransportWriter::new(config)?;
        let instance_id = crate::trace::TraceContext::new_root(false)
            .trace_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Self::start_writer_policy(writer, capacity, instance_id, Some(stats), false)
    }
    pub fn start(
        path: &Path,
        capacity: usize,
        stats: MetadataDeliveryStats,
    ) -> io::Result<(BoundedRecordSink, Self)> {
        if capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "metadata queue capacity must be positive",
            ));
        }
        if let Ok(metadata) = path.metadata() {
            if !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "metadata destination must be a regular file",
                ));
            }
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        let instance_id: String = crate::trace::TraceContext::new_root(false)
            .trace_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Self::start_writer(file, capacity, instance_id, Some(stats))
    }

    fn start_writer(
        file: impl Write + Send + 'static,
        capacity: usize,
        instance_id: String,
        stats: Option<MetadataDeliveryStats>,
    ) -> io::Result<(BoundedRecordSink, Self)> {
        Self::start_writer_policy(file, capacity, instance_id, stats, true)
    }

    fn start_writer_policy(
        mut file: impl Write + Send + 'static,
        capacity: usize,
        instance_id: String,
        stats: Option<MetadataDeliveryStats>,
        close_on_failure: bool,
    ) -> io::Result<(BoundedRecordSink, Self)> {
        if capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "metadata queue capacity must be positive",
            ));
        }
        let (sink, mut receiver) = BoundedRecordSink::new(capacity);
        let sink = match stats.as_ref() {
            Some(stats) => {
                stats.configure_queue(capacity);
                sink.with_delivery_stats(stats.clone())
            }
            None => sink,
        };
        let counters = sink.counters();
        let written = Arc::new(AtomicU64::new(0));
        let failed = Arc::new(AtomicU64::new(0));
        let thread_written = written.clone();
        let thread_failed = failed.clone();
        let (done_tx, done) = oneshot::channel();
        std::thread::Builder::new()
            .name("llmproxy-metadata".into())
            .spawn(move || {
                let mut write_failed = false;
                while let Some(mut record) = receiver.blocking_recv() {
                    if let Some(stats) = &stats {
                        stats.record_dequeued();
                    }
                    record.instance_id.clone_from(&instance_id);
                    let result = serde_json::to_vec(&record)
                        .map_err(io::Error::other)
                        .and_then(|mut data| {
                            data.push(b'\n');
                            file.write_all(&data)
                        });
                    if result.is_ok() {
                        thread_written.fetch_add(1, Ordering::Relaxed);
                        if let Some(stats) = &stats {
                            stats.record_written();
                            if !close_on_failure {
                                stats.record_durable();
                            }
                        }
                    } else {
                        thread_failed.fetch_add(1, Ordering::Relaxed);
                        if let Some(stats) = &stats {
                            stats.record_write_failure();
                        }
                        if !close_on_failure {
                            continue;
                        }
                        write_failed = true;
                        // Stop admission before discarding anything left in
                        // the channel. Capture failure is isolated from
                        // forwarding; this only frees the bounded queue.
                        receiver.close();
                        break;
                    }
                }
                if write_failed {
                    while receiver.blocking_recv().is_some() {
                        if let Some(stats) = &stats {
                            stats.record_dequeued();
                            stats.record_drained_after_close();
                        }
                    }
                }
                let _ = done_tx.send(());
            })?;
        Ok((
            sink,
            Self {
                done,
                counters,
                written,
                failed,
            },
        ))
    }

    /// Call after forwarding has drained and ALL producer handles are dropped.
    /// A stalled filesystem can leave a thread pending until process exit;
    /// it cannot extend this control-side deadline.
    pub async fn shutdown(self, deadline: Duration) -> DeliverySummary {
        let timed_out = !matches!(tokio::time::timeout(deadline, self.done).await, Ok(Ok(())));
        let written = self.written.load(Ordering::Relaxed);
        let failed = self.failed.load(Ordering::Relaxed);
        DeliverySummary {
            written,
            failed,
            admission: self.counters.snapshot(),
            unwritten: self
                .counters
                .snapshot()
                .accepted
                .saturating_sub(written)
                .saturating_sub(failed),
            timed_out,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{tests::record, RequestRecordSink, SubmitResult};
    use crate::stats::{prometheus_render, MetadataDeliveryStats, StatsControl};

    #[tokio::test]
    async fn queued_records_are_written_before_shutdown_returns() {
        #[derive(Clone)]
        struct Writer(Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Writer {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (sink, delivery) =
            MetadataDelivery::start_writer(Writer(bytes.clone()), 2, "instance".into(), None)
                .unwrap();
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        drop(sink);
        let summary = delivery.shutdown(Duration::from_secs(2)).await;
        assert!(!summary.timed_out);
        assert_eq!(summary.written, 1);
        assert_eq!(summary.unwritten, 0);
        let value: serde_json::Value = serde_json::from_slice(&bytes.lock().unwrap()).unwrap();
        assert_eq!(value["instance_id"], "instance");
    }

    #[tokio::test]
    async fn collector_failure_closes_admission_and_reports_loss() {
        struct Failed;
        impl Write for Failed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("full"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (sink, delivery) =
            MetadataDelivery::start_writer(Failed, 2, "instance".into(), None).unwrap();
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        let summary = delivery.shutdown(Duration::from_secs(2)).await;
        assert_eq!(summary.failed, 1);
        assert_eq!(sink.submit(record()), SubmitResult::Closed);
    }

    #[tokio::test]
    async fn records_drained_after_the_lane_closes_are_counted_as_dropped() {
        // The first write blocks until three more records are queued, then
        // fails; the writer closes the lane and drains those three unwritten.
        struct FailAfterRelease {
            entered: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }
        impl Write for FailAfterRelease {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                let _ = self.entered.send(());
                let _ = self.release.recv();
                Err(io::Error::other("full"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let control = StatsControl::new(1);
        let registry = control.registry();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (sink, delivery) = MetadataDelivery::start_writer(
            FailAfterRelease {
                entered: entered_tx,
                release: release_rx,
            },
            3,
            "instance".into(),
            Some(MetadataDeliveryStats::resolve(&control)),
        )
        .unwrap();
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        entered_rx.recv().unwrap();
        for _ in 0..3 {
            assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        }
        release_tx.send(()).unwrap();
        let summary = delivery.shutdown(Duration::from_secs(2)).await;
        assert!(!summary.timed_out);
        assert_eq!(summary.failed, 1);
        let rendered = prometheus_render::render(&registry);
        assert!(
            rendered.contains("envoy_llmproxy_metadata_dropped{reason=\"drained_after_close\"} 3"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn metadata_health_renders_admission_queue_and_writer_signals() {
        struct Blocked {
            entered: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }
        impl Write for Blocked {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                let _ = self.entered.send(());
                let _ = self.release.recv();
                Ok(data.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let control = StatsControl::new(1);
        let registry = control.registry();
        let stats = MetadataDeliveryStats::resolve(&control);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (sink, delivery) = MetadataDelivery::start_writer(
            Blocked {
                entered: entered_tx,
                release: release_rx,
            },
            1,
            "instance".into(),
            Some(stats),
        )
        .unwrap();

        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        entered_rx.recv().unwrap(); // first record left the queue for I/O
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        assert_eq!(sink.submit(record()), SubmitResult::CapacityExceeded);
        let before_write = prometheus_render::render(&registry);
        assert!(before_write.contains("envoy_llmproxy_metadata_admission{outcome=\"accepted\"} 2"));
        assert!(before_write
            .contains("envoy_llmproxy_metadata_admission{outcome=\"capacity_exceeded\"} 1"));
        assert!(before_write.contains("envoy_llmproxy_metadata_queue_depth 1"));
        assert!(before_write.contains("envoy_llmproxy_metadata_queue_capacity 1"));
        let otlp = crate::otlp::map_metrics(
            &registry,
            &proxy_api::opentelemetry::proto::resource::v1::Resource::default(),
        );
        let names: Vec<&str> = otlp.resource_metrics[0].scope_metrics[0]
            .metrics
            .iter()
            .map(|metric| metric.name.as_str())
            .collect();
        assert!(names.contains(&"llmproxy_metadata_admission"));
        assert!(names.contains(&"llmproxy_metadata_queue_depth"));

        let _ = release_tx.send(());
        // The second write intentionally blocks too.
        entered_rx.recv().unwrap();
        let _ = release_tx.send(());
        drop(sink);
        let summary = delivery.shutdown(Duration::from_secs(2)).await;
        assert_eq!(summary.written, 2);
        let rendered = prometheus_render::render(&registry);
        assert!(rendered.contains("envoy_llmproxy_metadata_queue_depth 0"));
        assert!(rendered.contains("envoy_llmproxy_metadata_written 2"));
        assert!(rendered.contains("envoy_llmproxy_metadata_write_failures 0"));
    }

    #[tokio::test]
    async fn collector_failure_is_visible_without_a_forwarding_side_effect() {
        struct Failed;
        impl Write for Failed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("full"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let control = StatsControl::new(1);
        let registry = control.registry();
        let stats = MetadataDeliveryStats::resolve(&control);
        let (sink, delivery) =
            MetadataDelivery::start_writer(Failed, 1, "instance".into(), Some(stats)).unwrap();
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        let summary = delivery.shutdown(Duration::from_secs(2)).await;
        assert_eq!(summary.failed, 1);
        // `submit` reports only metadata admission; callers ignore it, so a
        // failed file collector cannot turn a completed forwarding path into
        // a request error.
        assert_eq!(sink.submit(record()), SubmitResult::Closed);
        let rendered = prometheus_render::render(&registry);
        assert!(rendered.contains("envoy_llmproxy_metadata_write_failures 1"));
        assert!(rendered.contains("envoy_llmproxy_metadata_admission{outcome=\"closed\"} 1"));
    }

    #[tokio::test]
    async fn blocking_collector_cannot_block_shutdown_deadline() {
        struct Blocked(std::sync::mpsc::Receiver<()>);
        impl Write for Blocked {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                let _ = self.0.recv();
                Ok(data.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (release, wait) = std::sync::mpsc::channel();
        let (sink, delivery) =
            MetadataDelivery::start_writer(Blocked(wait), 1, "instance".into(), None).unwrap();
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        drop(sink);
        let summary = tokio::time::timeout(
            Duration::from_secs(1),
            delivery.shutdown(Duration::from_millis(20)),
        )
        .await
        .unwrap();
        assert!(summary.timed_out);
        assert_eq!(summary.unwritten, 1);
        let _ = release.send(());
    }
}
