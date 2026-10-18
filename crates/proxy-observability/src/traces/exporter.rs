//! The trace exporter thread (ADR-0008 decisions 5-7; design note sections
//! 5-7). It owns everything the worker must not do: decompressing,
//! reassembling streams, serialising lines, compressing segments, writing
//! and syncing files, and retention. One thread, one trace at a time, so its
//! memory is bounded by one trace plus the open segments' encoders.

use crate::records::RequestRecord;
use crate::stats::{instruments, Handle, Registry, StatsControl, WorkerId};
use crate::traces::capture::{CapturedTrace, DropReason, PartialReason, TraceAdmission, TraceMeta};
use crate::traces::config::TraceExportConfig;
use crate::traces::reassemble::{self, Body};
use crate::traces::segment::{OpenError, SealReason, Sealed, SegmentStore, WriteOutcome};
use crate::traces::uploader::{UploadQueue, Uploader};
use serde::Serialize;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// The line format's own version, separate from the record's.
pub const LINE_SCHEMA_VERSION: u16 = 1;

/// How often an idle exporter seals by age and applies retention.
const TICK: Duration = Duration::from_secs(1);

/// Seconds between repeats of one warning class.
const WARN_INTERVAL: Duration = Duration::from_secs(5);

/// An LRU seal of a segment younger than this means `max_open_segments` is
/// below the number of active tenants, which makes objects small.
const YOUNG_LRU_SEAL: Duration = Duration::from_secs(60);

/// Exporter-side counters, resolved at start so they scrape as zeroes.
struct ExporterStats {
    registry: Arc<Registry>,
    written: [Handle; 2],
    partial: [Handle; PartialReason::ALL.len()],
    sealed: [Handle; SealReason::ALL.len()],
    lost: [Handle; 3],
    expired: [Handle; 2],
    disk: Handle,
    up: Handle,
}

/// Indexes into `ExporterStats::lost`, in its label order.
const LOST_UPLOAD_BACKLOG: usize = 0;
const LOST_UNSEALED_AT_START: usize = 1;
const LOST_WRITE_ERROR: usize = 2;

impl ExporterStats {
    fn resolve(control: &StatsControl) -> Self {
        ExporterStats {
            registry: control.registry(),
            written: ["complete", "partial"]
                .map(|c| control.resolve(&instruments::TRACE_WRITTEN, &[("capture", c)])),
            partial: PartialReason::ALL
                .map(|r| control.resolve(&instruments::TRACE_PARTIAL, &[("reason", r.as_str())])),
            sealed: SealReason::ALL.map(|r| {
                control.resolve(
                    &instruments::TRACE_SEGMENTS_SEALED,
                    &[("reason", r.as_str())],
                )
            }),
            lost: ["upload_backlog", "unsealed_at_start", "write_error"]
                .map(|r| control.resolve(&instruments::TRACE_SEGMENTS_LOST, &[("reason", r)])),
            expired: ["age", "size"]
                .map(|r| control.resolve(&instruments::TRACE_SEGMENTS_EXPIRED, &[("reason", r)])),
            disk: control.resolve(&instruments::TRACE_DISK_BYTES, &[]),
            up: control.resolve(&instruments::TRACE_EXPORTER_UP, &[]),
        }
    }

    fn incr(&self, handle: Handle, n: u64) {
        if n > 0 {
            self.registry.incr(WorkerId(0), handle, n);
        }
    }

    fn set(&self, handle: Handle, last: &mut i64, value: i64) {
        self.registry.add(WorkerId(0), handle, value - *last);
        *last = value;
    }
}

/// One warning per class per window; the counters count every event.
struct Warn {
    last: Option<Instant>,
}

impl Warn {
    fn due(&mut self) -> bool {
        if self.last.is_some_and(|t| t.elapsed() < WARN_INTERVAL) {
            return false;
        }
        self.last = Some(Instant::now());
        true
    }
}

/// The running exporter. Dropping it without [`Self::shutdown`] stops the
/// thread at its next tick without draining.
pub struct TraceExporter {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    uploader: Option<Uploader>,
}

/// The exporter's side of the S3 destination.
struct Upload {
    queue: Arc<UploadQueue>,
    uploaded: mpsc::Receiver<PathBuf>,
}

impl TraceExporter {
    /// Open the directory (lock, epoch mark, leftovers) and start the
    /// thread. Errors name the field or path they concern.
    pub fn spawn(
        config: &TraceExportConfig,
        node_id: &str,
        admission: Arc<TraceAdmission>,
        traces: mpsc::Receiver<Box<CapturedTrace>>,
        control: &StatsControl,
    ) -> Result<Self, OpenError> {
        let store = SegmentStore::open(
            &config.directory,
            node_id,
            config.codec,
            config.segment_max_bytes,
            config.max_open_segments,
        )?;
        let stats = ExporterStats::resolve(control);
        stats.incr(stats.lost[LOST_UNSEALED_AT_START], store.leftovers_removed);
        if store.leftovers_removed > 0 {
            tracing::warn!(
                segments = store.leftovers_removed,
                "removed trace segments left open by a crash; their lines are lost \
                 (llmproxy_trace_segments_lost_total{{reason=\"unsealed_at_start\"}})"
            );
        }
        let (upload, uploader) = match &config.s3 {
            None => (None, None),
            Some(destination) => {
                let queue = Arc::new(UploadQueue::default());
                // Segments sealed before a restart are uploaded first.
                for segment in store.sealed() {
                    queue.push(segment.clone());
                }
                let (uploaded_tx, uploaded) = mpsc::channel();
                let uploader =
                    Uploader::spawn(destination, Arc::clone(&queue), uploaded_tx, control)
                        .map_err(|e| OpenError::Io {
                            path: "trace-uploader thread".into(),
                            reason: e.to_string(),
                        })?;
                (Some(Upload { queue, uploaded }), Some(uploader))
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let mut state = Exporter {
            upload,
            config: config.clone(),
            node_id: node_id.to_string(),
            store,
            admission,
            stats,
            disk_last: 0,
            write_warn: Warn { last: None },
            lru_warn: Warn { last: None },
            retry_open_after: None,
        };
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("trace-exporter".into())
            .spawn(move || state.run(traces, thread_stop))
            .map_err(|e| OpenError::Io {
                path: "trace-exporter thread".into(),
                reason: e.to_string(),
            })?;
        Ok(TraceExporter {
            stop,
            thread: Some(thread),
            uploader,
        })
    }

    /// Drain what is queued within `deadline`, seal every open segment, and
    /// stop. Anything still queued counts as `shutdown`. `true` when the
    /// thread finished in time.
    /// With an S3 destination, the uploader then gets what is left of
    /// `deadline` for the upload in flight; unsent segments stay on disk.
    pub fn shutdown(mut self, deadline: Duration) -> bool {
        self.stop.store(true, Ordering::Release);
        let started = Instant::now();
        let mut finished = true;
        if let Some(thread) = self.thread.take() {
            while !thread.is_finished() {
                if started.elapsed() > deadline + TICK {
                    finished = false;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            finished = finished && thread.join().is_ok();
        }
        if let Some(uploader) = self.uploader.take() {
            finished &= uploader.shutdown(deadline.saturating_sub(started.elapsed()));
        }
        finished
    }
}

impl Drop for TraceExporter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

struct Exporter {
    upload: Option<Upload>,
    config: TraceExportConfig,
    node_id: String,
    store: SegmentStore,
    admission: Arc<TraceAdmission>,
    stats: ExporterStats,
    disk_last: i64,
    write_warn: Warn,
    lru_warn: Warn,
    /// After a failed segment, new segments open at most once a second.
    retry_open_after: Option<Instant>,
}

impl Exporter {
    fn run(&mut self, traces: mpsc::Receiver<Box<CapturedTrace>>, stop: Arc<AtomicBool>) {
        let mut up = 0;
        self.stats.set(self.stats.up, &mut up, 1);
        let mut next_tick = Instant::now() + TICK;
        loop {
            if stop.load(Ordering::Acquire) {
                break;
            }
            match traces.recv_timeout(next_tick.saturating_duration_since(Instant::now())) {
                Ok(trace) => self.handle(trace),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if Instant::now() >= next_tick {
                self.tick();
                next_tick = Instant::now() + TICK;
            }
        }
        // Shutdown: what is already queued gets one pass, bounded by the
        // queue's own depth (the slots), then everything is sealed.
        while let Ok(trace) = traces.try_recv() {
            self.handle(trace);
        }
        let mut sealed = Vec::new();
        let failed = self.store.seal_all(&mut sealed);
        self.after_seals(sealed);
        if failed > 0 {
            self.admission.stats.dropped(DropReason::WriteError, failed);
        }
        self.publish_disk();
        self.stats.set(self.stats.up, &mut up, 0);
    }

    fn tick(&mut self) {
        let mut sealed = Vec::new();
        let mut failed = 0;
        self.store.seal_due(
            self.config.segment_max_age,
            &utc_date_now(),
            &mut sealed,
            &mut failed,
        );
        if failed > 0 {
            self.lost_segment_lines(failed);
        }
        self.after_seals(sealed);
        self.retain();
    }

    fn handle(&mut self, mut trace: Box<CapturedTrace>) {
        if trace.gate_moved() {
            trace.drop_for(DropReason::EmergencyDisabled);
            return;
        }
        if self.retry_open_after.is_some_and(|t| Instant::now() < t) {
            trace.drop_for(DropReason::WriteError);
            return;
        }
        let (line, partial) = build_line(&trace, &self.node_id, &self.config);
        let tenant = trace.record.tenant_id.clone();
        let date = trace
            .record
            .finished_at
            .get(..10)
            .unwrap_or("unknown")
            .to_string();
        // Make room before opening anything new, so a full disk does not
        // turn every line into a failed segment.
        self.retain();
        let mut sealed = Vec::new();
        match self.store.write_line(&tenant, &date, &line, &mut sealed) {
            Ok(WriteOutcome::Written) => {
                let complete = partial.is_empty();
                self.stats
                    .incr(self.stats.written[usize::from(!complete)], 1);
                for reason in &partial {
                    let i = PartialReason::ALL.iter().position(|r| r == reason).unwrap();
                    self.stats.incr(self.stats.partial[i], 1);
                }
                trace.mark_accounted();
            }
            Ok(WriteOutcome::Failed { lines_lost }) => {
                trace.mark_accounted();
                self.lost_segment_lines(lines_lost);
            }
            Err(e) => {
                trace.mark_accounted();
                self.lost_segment_lines(1);
                if self.write_warn.due() {
                    tracing::error!(error = %e, "trace segment could not be opened or sealed");
                }
            }
        }
        drop(trace);
        self.after_seals(sealed);
        self.publish_disk();
    }

    /// A failed segment loses every line in it.
    fn lost_segment_lines(&mut self, lines: u64) {
        self.admission.stats.dropped(DropReason::WriteError, lines);
        self.stats.incr(self.stats.lost[LOST_WRITE_ERROR], 1);
        self.retry_open_after = Some(Instant::now() + Duration::from_secs(1));
        if self.write_warn.due() {
            tracing::error!(
                lines,
                "a trace segment failed and was removed; its lines are lost \
                 (llmproxy_trace_dropped_total{{reason=\"write_error\"}})"
            );
        }
    }

    fn after_seals(&mut self, sealed: Vec<(Sealed, SealReason)>) {
        for (segment, reason) in sealed {
            if let Some(upload) = &self.upload {
                upload.queue.push(segment.clone());
            }
            let i = SealReason::ALL.iter().position(|r| *r == reason).unwrap();
            self.stats.incr(self.stats.sealed[i], 1);
            if reason == SealReason::Lru
                && segment.open_for.is_some_and(|age| age < YOUNG_LRU_SEAL)
                && self.lru_warn.due()
            {
                tracing::warn!(
                    max_open_segments = self.config.max_open_segments,
                    "a trace segment was sealed early because more tenants are active than \
                     max_open_segments; raise it to keep objects large"
                );
            }
        }
        self.retain();
    }

    /// With S3: forget what was uploaded, then, while over the disk cap,
    /// drop the oldest segment not yet sent (never the one in flight) and
    /// count it lost. Otherwise directory retention: age, then total size,
    /// oldest first, counted as expiry, not loss: that is the retention the
    /// operator configured.
    fn retain(&mut self) {
        if let Some(upload) = &self.upload {
            while let Ok(path) = upload.uploaded.try_recv() {
                self.store.forget(&path);
            }
            while self.store.disk_bytes() > self.config.max_disk_bytes {
                let mut queue = upload.queue.lock();
                let in_flight = queue.in_flight.clone();
                let Some(evicted) = self
                    .store
                    .remove_oldest(|s| in_flight.as_deref() == Some(s.path.as_path()))
                else {
                    break;
                };
                queue.pending.retain(|s| s.path != evicted.path);
                drop(queue);
                self.stats.incr(self.stats.lost[LOST_UPLOAD_BACKLOG], 1);
                if let Some(lines) = evicted.lines {
                    self.admission
                        .stats
                        .dropped(DropReason::UploadBacklog, lines);
                }
                if self.write_warn.due() {
                    tracing::warn!(
                        "trace upload backlog reached max_disk_bytes; the oldest unsent segment \
                         was dropped (llmproxy_trace_segments_lost_total{{reason=\"upload_backlog\"}})"
                    );
                }
            }
            self.publish_disk();
            return;
        }
        if let Some(max_age) = self.config.max_age {
            let old = self.store.remove_older_than(max_age);
            self.stats.incr(self.stats.expired[0], old.len() as u64);
        }
        while self.store.disk_bytes() > self.config.max_disk_bytes {
            match self.store.remove_oldest(|_| false) {
                Some(_) => self.stats.incr(self.stats.expired[1], 1),
                None => break,
            }
        }
        self.publish_disk();
    }

    fn publish_disk(&mut self) {
        let bytes = self.store.disk_bytes() as i64;
        let mut last = self.disk_last;
        self.stats.set(self.stats.disk, &mut last, bytes);
        self.disk_last = last;
    }
}

fn utc_date_now() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

#[derive(Serialize)]
struct Line<'a> {
    schema_version: u16,
    event_id: &'a str,
    instance_id: &'a str,
    record: &'a RequestRecord,
    capture: Capture<'a>,
    request: Direction<'a>,
    response: ResponseDirection<'a>,
}

#[derive(Serialize)]
struct Capture<'a> {
    state: &'static str,
    reasons: &'a [PartialReason],
}

#[derive(Serialize)]
struct Direction<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_encoding: Option<&'a str>,
    representation: &'static str,
    #[serde(flatten)]
    body: BodyField<'a>,
}

#[derive(Serialize)]
struct ResponseDirection<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    streamed: bool,
    #[serde(flatten)]
    direction: Direction<'a>,
}

#[derive(Serialize)]
enum BodyField<'a> {
    #[serde(rename = "body")]
    Json(&'a serde_json::value::RawValue),
    #[serde(rename = "body_text")]
    Text(&'a str),
    #[serde(rename = "body_base64")]
    Base64(&'a str),
}

impl<'a> From<&'a Body> for BodyField<'a> {
    fn from(body: &'a Body) -> Self {
        match body {
            Body::Json(raw) => BodyField::Json(raw),
            Body::Text(text) => BodyField::Text(text),
            Body::Base64(b64) => BodyField::Base64(b64),
        }
    }
}

/// Inflate `gzip` or `deflate` bodies up to `cap` decoded bytes. `None`
/// for any other encoding (exported as wire bytes, partial).
fn decode(encoding: Option<&str>, bytes: &[u8], cap: usize) -> Option<(Vec<u8>, bool)> {
    let encoding = encoding.map(|e| e.trim().to_ascii_lowercase());
    let mut reader: Box<dyn Read> = match encoding.as_deref() {
        None | Some("") | Some("identity") => return Some((bytes.to_vec(), false)),
        Some("gzip") | Some("x-gzip") => Box::new(flate2::read::MultiGzDecoder::new(bytes)),
        Some("deflate") => Box::new(flate2::read::ZlibDecoder::new(bytes)),
        Some(_) => return None,
    };
    let mut out = Vec::new();
    match (&mut reader).take(cap as u64 + 1).read_to_end(&mut out) {
        Ok(_) => {
            let over = out.len() > cap;
            out.truncate(cap);
            Some((out, over))
        }
        // A body cut by the capture cap is not a whole stream; whatever
        // inflated before the cut is kept.
        Err(_) if !out.is_empty() => Some((out, true)),
        Err(_) => None,
    }
}

fn push_reason(reasons: &mut Vec<PartialReason>, reason: PartialReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

/// Build one line. Returns it with a trailing newline and the partial
/// reasons it carries.
fn build_line(
    trace: &CapturedTrace,
    node_id: &str,
    config: &TraceExportConfig,
) -> (Vec<u8>, Vec<PartialReason>) {
    let meta: &TraceMeta = &trace.meta;
    let mut reasons = trace.partial.clone();
    let request_cut = reasons.contains(&PartialReason::RequestOverCap);
    let response_cut = reasons.contains(&PartialReason::ResponseOverCap)
        || reasons.contains(&PartialReason::MemoryBudget);

    let encoded_request = meta.request_content_encoding.as_deref();
    let (request_bytes, request_repr) = match decode(
        encoded_request,
        &trace.request,
        config.max_request_body_bytes,
    ) {
        Some((bytes, over)) => {
            if over {
                push_reason(&mut reasons, PartialReason::RequestOverCap);
            }
            let repr = if is_identity(encoded_request) {
                "wire"
            } else {
                "decoded"
            };
            (Some(bytes), repr)
        }
        None => {
            push_reason(&mut reasons, PartialReason::ContentEncoding);
            (None, "wire")
        }
    };
    let (request_body, request_reasons) = match &request_bytes {
        Some(bytes) => reassemble::request_body(
            bytes,
            request_cut || reasons.contains(&PartialReason::RequestOverCap),
        ),
        None => reassemble::request_body(&trace.request, true),
    };
    for r in request_reasons {
        push_reason(&mut reasons, r);
    }

    let response_raw = trace.response_bytes();
    let encoded_response = meta.response_content_encoding.as_deref();
    let (response, response_repr) = match decode(
        encoded_response,
        &response_raw,
        config.max_response_body_bytes,
    ) {
        Some((bytes, over)) => {
            if over {
                push_reason(&mut reasons, PartialReason::ResponseOverCap);
            }
            let repr = if is_identity(encoded_response) {
                "wire"
            } else {
                "decoded"
            };
            (
                reassemble::reassemble_response(
                    meta.dialect,
                    &meta.path,
                    meta.response_content_type.as_deref(),
                    &bytes,
                    response_cut || over,
                ),
                repr,
            )
        }
        None => {
            push_reason(&mut reasons, PartialReason::ContentEncoding);
            (
                reassemble::reassemble_response(None, &meta.path, None, &response_raw, true),
                "wire",
            )
        }
    };
    for r in &response.partial {
        // An unknown dialect on an undecodable body says the same thing twice.
        if !(reasons.contains(&PartialReason::ContentEncoding)
            && *r == PartialReason::UnsupportedDialect)
        {
            push_reason(&mut reasons, *r);
        }
    }

    let line = Line {
        schema_version: LINE_SCHEMA_VERSION,
        event_id: &trace.record.event_id,
        instance_id: node_id,
        record: &trace.record,
        capture: Capture {
            state: if reasons.is_empty() {
                "complete"
            } else {
                "partial"
            },
            reasons: &reasons,
        },
        request: Direction {
            content_type: meta.request_content_type.as_deref(),
            content_encoding: encoded_request.filter(|e| !is_identity(Some(e))),
            representation: request_repr,
            body: (&request_body).into(),
        },
        response: ResponseDirection {
            status: meta.status,
            streamed: response.streamed,
            direction: Direction {
                content_type: meta.response_content_type.as_deref(),
                content_encoding: encoded_response.filter(|e| !is_identity(Some(e))),
                representation: response_repr,
                body: (&response.body).into(),
            },
        },
    };
    let mut out = serde_json::to_vec(&line).expect("a line of owned JSON values serializes");
    out.push(b'\n');
    (out, reasons)
}

fn is_identity(encoding: Option<&str>) -> bool {
    encoding.is_none_or(|e| {
        let e = e.trim();
        e.is_empty() || e.eq_ignore_ascii_case("identity")
    })
}
