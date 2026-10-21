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
    instance_id: String,
    last_seq: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
pub struct DeliverySummary {
    /// The `instance_id` every record from this process carries.
    pub instance_id: String,
    pub written: u64,
    pub failed: u64,
    /// Accepted records not written or failed at the shutdown snapshot.
    /// On timeout, the detached writer can still complete them afterward.
    pub unwritten: u64,
    pub admission: crate::records::DropCounterSnapshot,
    pub timed_out: bool,
    /// The highest `record_seq` the writer stamped; 0 when it wrote nothing.
    pub last_record_seq: u64,
}

impl DeliverySummary {
    /// Whether any record was refused, failed, or left unwritten, or the flush
    /// ran out of time.
    pub fn lost_records(&self) -> bool {
        let a = &self.admission;
        self.timed_out
            || self.failed > 0
            || self.unwritten > 0
            || a.capacity_exceeded > 0
            || a.oversize > 0
            || a.invalid > 0
            || a.closed > 0
    }

    /// The one line per process a metering consumer reconciles against
    /// (ADR-0011 decision 2): records `1..=last_record_seq` of `instance_id`
    /// should all have arrived. WARN when anything was lost, INFO otherwise
    /// (AGENTS.md "Fail-open controls"). `context` says why delivery stopped.
    pub fn log(&self, context: &str) {
        macro_rules! emit {
            ($level:ident, $message:literal) => {
                tracing::$level!(
                    event = "metadata_delivery_summary",
                    context,
                    instance_id = %self.instance_id,
                    last_record_seq = self.last_record_seq,
                    accepted = self.admission.accepted,
                    written = self.written,
                    failed = self.failed,
                    unwritten = self.unwritten,
                    dropped_capacity = self.admission.capacity_exceeded,
                    dropped_oversize = self.admission.oversize,
                    dropped_invalid = self.admission.invalid,
                    dropped_closed = self.admission.closed,
                    timed_out = self.timed_out,
                    $message
                )
            };
        }
        if self.lost_records() {
            emit!(warn, "metadata delivery stopped with request records lost");
        } else {
            emit!(
                info,
                "metadata delivery stopped; file writes do not imply durability"
            );
        }
    }
}

impl MetadataDelivery {
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
        mut file: impl Write + Send + 'static,
        capacity: usize,
        instance_id: String,
        stats: Option<MetadataDeliveryStats>,
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
        let last_seq = Arc::new(AtomicU64::new(0));
        let thread_last_seq = last_seq.clone();
        let summary_instance_id = instance_id.clone();
        let (done_tx, done) = oneshot::channel();
        std::thread::Builder::new()
            .name("llmproxy-metadata".into())
            .spawn(move || {
                let mut write_failed = false;
                let mut seq = 0u64;
                while let Some(mut record) = receiver.blocking_recv() {
                    if let Some(stats) = &stats {
                        stats.record_dequeued();
                    }
                    record.instance_id.clone_from(&instance_id);
                    // Numbered here, on the one writer thread, so records
                    // arrive in order and a gap means a write was lost
                    // (ADR-0011 decision 2).
                    seq += 1;
                    record.record_seq = Some(seq);
                    thread_last_seq.store(seq, Ordering::Relaxed);
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
                        }
                    } else {
                        thread_failed.fetch_add(1, Ordering::Relaxed);
                        if let Some(stats) = &stats {
                            stats.record_write_failure();
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
                instance_id: summary_instance_id,
                last_seq,
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
            instance_id: self.instance_id,
            last_record_seq: self.last_seq.load(Ordering::Relaxed),
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
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        drop(sink);
        let summary = delivery.shutdown(Duration::from_secs(2)).await;
        assert!(!summary.timed_out);
        assert_eq!(summary.written, 2);
        assert_eq!(summary.unwritten, 0);
        assert!(!summary.lost_records());
        // The summary names the instance and the last number, so a consumer
        // can check that records 1..=last all arrived (ADR-0011 decision 2).
        assert_eq!(summary.instance_id, "instance");
        assert_eq!(summary.last_record_seq, 2);
        let written = bytes.lock().unwrap().clone();
        let values: Vec<serde_json::Value> = written
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(values.len(), 2);
        for (value, seq) in values.iter().zip(1..) {
            assert_eq!(value["instance_id"], "instance");
            assert_eq!(value["record_seq"], seq);
        }
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
        assert!(summary.lost_records(), "a failed write is a loss to report");
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
