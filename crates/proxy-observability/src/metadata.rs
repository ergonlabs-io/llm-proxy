//! Metadata delivery runs on a dedicated OS thread. Blocking file collectors
//! cannot block forwarding, the control runtime, or the shutdown deadline.
//! This append-only JSONL collector is best effort; write success is not a
//! durability acknowledgement and this file is not a billing ledger.

use crate::records::{BoundedRecordSink, DropCounters};
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
    pub fn start(path: &Path, capacity: usize) -> io::Result<(BoundedRecordSink, Self)> {
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
        Self::start_writer(file, capacity, instance_id)
    }

    fn start_writer(
        mut file: impl Write + Send + 'static,
        capacity: usize,
        instance_id: String,
    ) -> io::Result<(BoundedRecordSink, Self)> {
        let (sink, mut receiver) = BoundedRecordSink::new(capacity);
        let counters = sink.counters();
        let written = Arc::new(AtomicU64::new(0));
        let failed = Arc::new(AtomicU64::new(0));
        let thread_written = written.clone();
        let thread_failed = failed.clone();
        let (done_tx, done) = oneshot::channel();
        std::thread::Builder::new()
            .name("llmproxy-metadata".into())
            .spawn(move || {
                while let Some(mut record) = receiver.blocking_recv() {
                    record.instance_id.clone_from(&instance_id);
                    let result = serde_json::to_vec(&record)
                        .map_err(io::Error::other)
                        .and_then(|mut data| {
                            data.push(b'\n');
                            file.write_all(&data)
                        });
                    if result.is_ok() {
                        thread_written.fetch_add(1, Ordering::Relaxed);
                    } else {
                        thread_failed.fetch_add(1, Ordering::Relaxed);
                        break; // Disable admission after a partial/error write.
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
            MetadataDelivery::start_writer(Writer(bytes.clone()), 2, "instance".into()).unwrap();
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
            MetadataDelivery::start_writer(Failed, 2, "instance".into()).unwrap();
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        let summary = delivery.shutdown(Duration::from_secs(2)).await;
        assert_eq!(summary.failed, 1);
        assert_eq!(sink.submit(record()), SubmitResult::Closed);
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
            MetadataDelivery::start_writer(Blocked(wait), 1, "instance".into()).unwrap();
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
