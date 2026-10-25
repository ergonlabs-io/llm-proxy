//! Metadata delivery runs on a dedicated OS thread. Blocking file collectors
//! cannot block forwarding, the control runtime, or the shutdown deadline.
//! This append-only JSONL collector is best effort; write success is not a
//! durability acknowledgement and this file is not a billing ledger.
//!
//! A failed write loses that one record (its `record_seq` leaves a gap), logs
//! once per outage, and the writer backs off, reopens the file, and carries on
//! with the next record. The lane never closes on a write error.

use crate::records::{BoundedRecordSink, DropCounters};
use crate::stats::MetadataDeliveryStats;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
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
    reopen: ReopenHandle,
}

/// A run of consecutive failed writes, for the line logged when writes
/// succeed again.
struct Outage {
    first_seq: u64,
    failed: u64,
}

/// Appends one JSONL line. After a write that stopped part-way through a line,
/// a newline goes first, so the fragment cannot swallow the next record.
fn write_line(
    out: &mut (impl Write + ?Sized),
    line: &[u8],
    partial_line: &mut bool,
) -> io::Result<()> {
    if *partial_line {
        write_tracked(out, b"\n", partial_line)?;
    }
    write_tracked(out, line, partial_line)
}

/// `write_all` that records whether bytes of an unfinished line reached the
/// file. Every `buf` here ends in a newline, so finishing it ends the line.
fn write_tracked(
    out: &mut (impl Write + ?Sized),
    mut buf: &[u8],
    partial_line: &mut bool,
) -> io::Result<()> {
    while !buf.is_empty() {
        match out.write(buf) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                *partial_line = true;
                buf = &buf[n..];
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    *partial_line = false;
    Ok(())
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

/// Opens the records destination. Called at start, after a failed write, and
/// after a [`ReopenHandle::request`].
type Opener = Box<dyn FnMut() -> io::Result<Box<dyn Write + Send>> + Send>;

/// First pause after a failed write. Doubles per consecutive failure.
const RETRY_BACKOFF_INITIAL: Duration = Duration::from_millis(10);
/// Longest pause between attempts while the destination keeps failing. Well
/// under the 5 s shutdown budget, so one pause cannot use most of it.
const RETRY_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Asks the writer thread to close and reopen the records file before its
/// next write: SIGUSR1 after logrotate renamed the file. Cheap to clone.
#[derive(Clone)]
pub struct ReopenHandle(Arc<AtomicBool>);

impl ReopenHandle {
    /// The writer reopens before the next record it writes, so records queued
    /// before this call can still land in the old file.
    pub fn request(&self) {
        self.0.store(true, Ordering::Release);
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
        let owned = path.to_path_buf();
        let opener: Opener = Box::new(move || {
            let mut options = OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            Ok(Box::new(options.open(&owned)?) as Box<dyn Write + Send>)
        });
        let instance_id: String = crate::trace::TraceContext::new_root(false)
            .trace_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Self::start_writer(
            opener,
            path.display().to_string(),
            capacity,
            instance_id,
            Some(stats),
        )
    }

    /// The handle SIGUSR1 uses to make the writer reopen its file.
    pub fn reopen_handle(&self) -> ReopenHandle {
        self.reopen.clone()
    }

    /// `open` is called once here, so a destination that cannot be opened is
    /// a startup error, and again after every failed write.
    fn start_writer(
        mut open: Opener,
        destination: String,
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
        let first = open()?;
        let (sink, mut receiver) = BoundedRecordSink::new(capacity);
        let sink = match stats.as_ref() {
            Some(stats) => {
                stats.configure_queue(capacity);
                stats.publish_instance(&instance_id);
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
        let reopen = ReopenHandle(Arc::new(AtomicBool::new(false)));
        let thread_reopen = reopen.0.clone();
        let summary_instance_id = instance_id.clone();
        let (done_tx, done) = oneshot::channel();
        // The thread logs through the caller's subscriber, not only the global
        // one, so a scoped subscriber sees the failure line too.
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        std::thread::Builder::new()
            .name("llmproxy-metadata".into())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    let mut file = Some(first);
                    let mut partial_line = false;
                    let mut outage: Option<Outage> = None;
                    let mut backoff = RETRY_BACKOFF_INITIAL;
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
                        if let Some(stats) = &stats {
                            stats.record_stamped();
                        }
                        if thread_reopen.swap(false, Ordering::AcqRel) {
                            file = None;
                        }
                        let result = serde_json::to_vec(&record)
                            .map_err(io::Error::other)
                            .and_then(|mut data| {
                                data.push(b'\n');
                                let out = match file.as_mut() {
                                    Some(out) => out,
                                    None => file.insert(open()?),
                                };
                                write_line(out, &data, &mut partial_line)
                            });
                        match result {
                            Ok(()) => {
                                thread_written.fetch_add(1, Ordering::Relaxed);
                                if let Some(stats) = &stats {
                                    stats.record_written();
                                }
                                backoff = RETRY_BACKOFF_INITIAL;
                                if let Some(outage) = outage.take() {
                                    tracing::warn!(
                                        event = "request_records_resumed",
                                        destination = %destination,
                                        records_lost = outage.failed,
                                        first_lost_seq = outage.first_seq,
                                        record_seq = seq,
                                        "request records are being written again"
                                    );
                                }
                            }
                            Err(err) => {
                                thread_failed.fetch_add(1, Ordering::Relaxed);
                                if let Some(stats) = &stats {
                                    stats.record_write_failure();
                                }
                                // Reopen before the next attempt: the old
                                // handle may point at a removed file or a
                                // dead mount.
                                file = None;
                                match &mut outage {
                                    Some(outage) => outage.failed += 1,
                                    None => {
                                        // Once per outage; the resume line
                                        // carries the count, and
                                        // `llmproxy_metadata_write_failures`
                                        // the running total.
                                        tracing::error!(
                                            event = "request_records_write_failed",
                                            destination = %destination,
                                            error = %err,
                                            record_seq = seq,
                                            "cannot write request records; retrying with backoff \
                                             and reopening the file, and records are lost until \
                                             a write succeeds (forwarding continues)"
                                        );
                                        outage = Some(Outage {
                                            first_seq: seq,
                                            failed: 1,
                                        });
                                    }
                                }
                                // The bounded queue absorbs records during
                                // the pause. Once every producer is gone
                                // (shutdown) the pause only spends the
                                // shutdown budget, so each record gets one
                                // prompt attempt instead.
                                if !receiver.is_closed() {
                                    std::thread::sleep(backoff);
                                    backoff = (backoff * 2).min(RETRY_BACKOFF_MAX);
                                }
                            }
                        }
                    }
                    if let Some(outage) = outage {
                        tracing::error!(
                            event = "request_records_write_failed",
                            destination = %destination,
                            records_lost = outage.failed,
                            first_lost_seq = outage.first_seq,
                            "request records were still failing to write when delivery stopped"
                        );
                    }
                });
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
                reopen,
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

    /// Opens `writer` once. A reopen fails, like a destination that is gone.
    fn open_once(writer: impl Write + Send + 'static) -> Opener {
        let mut writer = Some(writer);
        Box::new(move || {
            writer
                .take()
                .map(|w| Box::new(w) as Box<dyn Write + Send>)
                .ok_or_else(|| io::Error::other("reopen refused"))
        })
    }

    fn start_writer(
        writer: impl Write + Send + 'static,
        capacity: usize,
        stats: Option<MetadataDeliveryStats>,
    ) -> (BoundedRecordSink, MetadataDelivery) {
        MetadataDelivery::start_writer(
            open_once(writer),
            "test".into(),
            capacity,
            "instance".into(),
            stats,
        )
        .unwrap()
    }

    /// A shared in-memory file whose next `fail` writes fail. A partial
    /// failure writes `partial` bytes of the line before the error.
    #[derive(Clone, Default)]
    struct Flaky {
        bytes: Arc<std::sync::Mutex<Vec<u8>>>,
        fail: Arc<AtomicU64>,
        partial: usize,
        opens: Arc<AtomicU64>,
    }
    impl Write for Flaky {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if self
                .fail
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                let partial = self.partial.min(data.len());
                if partial > 0 {
                    self.bytes
                        .lock()
                        .unwrap()
                        .extend_from_slice(&data[..partial]);
                    // Report the bytes; the error comes on the next call,
                    // as from a short write followed by ENOSPC.
                    self.partial = 0;
                    self.fail.fetch_add(1, Ordering::SeqCst);
                    return Ok(partial);
                }
                return Err(io::Error::other("no space left on device"));
            }
            self.bytes.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Flaky {
        fn opener(&self) -> Opener {
            let file = self.clone();
            Box::new(move || {
                file.opens.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(file.clone()) as Box<dyn Write + Send>)
            })
        }
        fn lines(&self) -> Vec<String> {
            String::from_utf8(self.bytes.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    /// A `tracing` writer that appends to a shared buffer.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Captured {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
        /// Polls, bounded, for the writer thread's log line.
        fn wait_for(&self, needle: &str) -> String {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                let text = self.text();
                if text.contains(needle) {
                    return text;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "no log line containing {needle:?}; captured:\n{text}"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

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
        let (sink, delivery) = start_writer(Writer(bytes.clone()), 2, None);
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

    /// A transient write error (ENOSPC, EIO) loses that one record, is
    /// logged when it happens rather than only in the shutdown summary, and
    /// later records are written again through a reopened file.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_writer_that_fails_once_logs_at_the_failure_and_records_resume() {
        // `cargo test` runs tests as threads of one process. With exactly one
        // live dispatcher, tracing-core decides a callsite's interest from
        // the default of whichever thread reaches it first, so another test's
        // writer thread would cache the failure line as disabled. A second
        // live dispatcher makes it ask every live dispatcher instead.
        let _second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let captured = Captured::default();
        let log_writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || log_writer.clone())
            .with_ansi(false)
            .finish();
        let file = Flaky::default();
        file.fail.store(1, Ordering::SeqCst);
        let control = StatsControl::new(1);
        let registry = control.registry();
        let (sink, delivery) = tracing::subscriber::with_default(subscriber, || {
            MetadataDelivery::start_writer(
                file.opener(),
                "/var/log/records.jsonl".into(),
                4,
                "instance".into(),
                Some(MetadataDeliveryStats::resolve(&control)),
            )
            .unwrap()
        });

        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        // Logged while the process runs, before any shutdown summary.
        let at_failure = captured.wait_for("request_records_write_failed");
        assert!(
            at_failure.contains("ERROR")
                && at_failure.contains("/var/log/records.jsonl")
                && at_failure.contains("no space left on device")
                && at_failure.contains("record_seq=1"),
            "the failure line names the file, the error and the lost record:\n{at_failure}"
        );

        // Admission stays open, and the next records reach the file.
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        let resumed = captured.wait_for("request_records_resumed");
        assert!(
            resumed.contains("records_lost=1") && resumed.contains("first_lost_seq=1"),
            "the resume line counts what the outage lost:\n{resumed}"
        );
        drop(sink);
        let summary = delivery.shutdown(Duration::from_secs(2)).await;
        assert!(!summary.timed_out);
        assert_eq!((summary.written, summary.failed), (2, 1));
        assert_eq!(summary.unwritten, 0);
        assert!(summary.lost_records(), "the failed record is still a loss");
        assert_eq!(
            file.opens.load(Ordering::SeqCst),
            2,
            "the writer reopens the file after a failed write"
        );
        let seqs: Vec<u64> = file
            .lines()
            .iter()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["record_seq"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        assert_eq!(seqs, [2, 3], "record 1 is the gap a consumer detects");
        assert_eq!(
            captured
                .text()
                .matches("request_records_write_failed")
                .count(),
            1,
            "one failure line per outage"
        );
        let rendered = prometheus_render::render(&registry);
        assert!(
            rendered.contains("envoy_llmproxy_metadata_write_failures 1"),
            "{rendered}"
        );
        assert!(
            rendered.contains("envoy_llmproxy_metadata_written 2"),
            "{rendered}"
        );
        // The scrape names the instance its counters belong to, and the last
        // stamped number counts the failed record too, as the summary does.
        assert!(
            rendered.contains(&format!(
                "envoy_llmproxy_metadata_instance_info{{instance_id=\"{}\"}} 1",
                summary.instance_id
            )),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "envoy_llmproxy_metadata_last_record_seq {}",
                summary.last_record_seq
            )) && summary.last_record_seq == 3,
            "last_record_seq {} must render:\n{rendered}",
            summary.last_record_seq
        );
    }

    /// A write that stopped part-way leaves a fragment in the file. The next
    /// record starts on its own line, so a line-by-line reader loses only the
    /// fragment.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_partial_write_cannot_swallow_the_next_record() {
        let file = Flaky {
            partial: 7,
            ..Flaky::default()
        };
        file.fail.store(1, Ordering::SeqCst);
        let (sink, delivery) = MetadataDelivery::start_writer(
            file.opener(),
            "test".into(),
            4,
            "instance".into(),
            None,
        )
        .unwrap();
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        drop(sink);
        let summary = delivery.shutdown(Duration::from_secs(2)).await;
        assert_eq!((summary.written, summary.failed), (1, 1));
        let lines = file.lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines[0].len(), 7, "the fragment of record 1: {lines:?}");
        let second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(second["record_seq"], 2);
    }

    /// A destination that stays broken costs records, never forwarding:
    /// `submit` keeps answering `Accepted`, and every lost record is counted.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_destination_that_stays_broken_keeps_admitting_and_counts_every_loss() {
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
        let (sink, delivery) =
            start_writer(Failed, 4, Some(MetadataDeliveryStats::resolve(&control)));
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        drop(sink);
        let summary = delivery.shutdown(Duration::from_secs(5)).await;
        assert!(!summary.timed_out);
        assert_eq!((summary.written, summary.failed), (0, 2));
        assert!(summary.lost_records());
        let rendered = prometheus_render::render(&registry);
        assert!(
            rendered.contains("envoy_llmproxy_metadata_write_failures 2"),
            "{rendered}"
        );
        assert!(rendered.contains("envoy_llmproxy_metadata_admission{outcome=\"closed\"} 0"));
    }

    /// logrotate renames the file, then SIGUSR1 asks for a reopen: records
    /// after the request land in a new file at the configured path.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reopen_request_moves_later_records_to_a_new_file_at_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("records.jsonl");
        let rotated = dir.path().join("records.jsonl.1");
        let control = StatsControl::new(1);
        let (sink, delivery) =
            MetadataDelivery::start(&path, 4, MetadataDeliveryStats::resolve(&control)).unwrap();
        let wait_lines = |path: &Path, count: usize| {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                let text = std::fs::read_to_string(path).unwrap_or_default();
                if text.lines().count() >= count {
                    return text;
                }
                assert!(std::time::Instant::now() < deadline, "{text}");
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        wait_lines(&path, 1);
        std::fs::rename(&path, &rotated).unwrap();
        // Without the reopen the writer keeps appending to the renamed inode.
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        wait_lines(&rotated, 2);
        delivery.reopen_handle().request();
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        drop(sink);
        let summary = delivery.shutdown(Duration::from_secs(2)).await;
        assert_eq!((summary.written, summary.failed), (3, 0));
        let fresh = std::fs::read_to_string(&path).unwrap();
        let fresh: Vec<serde_json::Value> = fresh
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0]["record_seq"], 3);
        assert_eq!(
            std::fs::read_to_string(&rotated).unwrap().lines().count(),
            2
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
        let (sink, delivery) = start_writer(
            Blocked {
                entered: entered_tx,
                release: release_rx,
            },
            1,
            Some(stats),
        );

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
        let (sink, delivery) = start_writer(Blocked(wait), 1, None);
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
