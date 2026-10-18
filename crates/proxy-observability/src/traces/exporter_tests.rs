//! The exporter and its segment store, driven through the real admission
//! and channel the workers use, against a temporary directory. What reaches
//! disk is read back by decompressing the sealed files, as a consumer would.

use super::capture::{CapturedTrace, TraceAdmission, TraceDialect, TraceMeta, TraceStats};
use super::config::{TraceCodec, TraceExportConfig};
use super::exporter::TraceExporter;
use super::gate::TraceGate;
use super::segment::{OpenError, SealReason, SegmentStore};
use crate::ledger::testing::record;
use crate::stats::StatsControl;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::Duration;

fn config(dir: &Path) -> TraceExportConfig {
    TraceExportConfig {
        directory: dir.to_path_buf(),
        max_disk_bytes: 1 << 40,
        max_age: None,
        codec: TraceCodec::Gzip,
        max_request_body_bytes: 1 << 16,
        max_response_body_bytes: 1 << 16,
        max_memory_bytes: 1 << 24,
        max_queued_traces: 64,
        segment_max_bytes: 1 << 20,
        segment_max_age: Duration::from_secs(300),
        max_open_segments: 8,
        s3: None,
    }
}

struct Running {
    admission: Arc<TraceAdmission>,
    gate: Arc<TraceGate>,
    exporter: TraceExporter,
    stats: StatsControl,
}

fn start(config: &TraceExportConfig) -> Running {
    let stats = StatsControl::new(1);
    let gate = Arc::new(TraceGate::open(&config.directory));
    let (admission, traces) =
        TraceAdmission::new(config, Arc::clone(&gate), TraceStats::resolve(&stats));
    let exporter =
        TraceExporter::spawn(config, "node-a", Arc::clone(&admission), traces, &stats).unwrap();
    Running {
        admission,
        gate,
        exporter,
        stats,
    }
}

impl Running {
    /// One opted-in request through admission and the hand-off.
    fn submit(&self, tenant: &str, event: &str, request: &[u8], response: &[u8], meta: TraceMeta) {
        let mut capture = self.admission.admit(request).expect("admitted");
        assert!(capture.push_response(response));
        let mut record = record(event);
        record.tenant_id = tenant.into();
        capture.finish(record, meta);
    }

    fn stop(self) -> StatsControl {
        assert!(self.exporter.shutdown(Duration::from_secs(5)));
        self.stats
    }
}

fn sse_meta() -> TraceMeta {
    TraceMeta {
        path: "/v1/chat/completions".into(),
        status: Some(200),
        request_content_type: Some("application/json".into()),
        request_content_encoding: None,
        response_content_type: Some("text/event-stream".into()),
        response_content_encoding: None,
        dialect: Some(TraceDialect::OpenAi),
    }
}

const REQUEST: &[u8] =
    br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
const STREAM: &[u8] = b"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n\
data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n\
data: [DONE]\n\n";

/// Every sealed segment under `dir`, as (path relative to dir, lines).
fn sealed_lines(dir: &Path) -> Vec<(String, Vec<serde_json::Value>)> {
    let mut out = Vec::new();
    for entry in walk(dir) {
        let rel = entry
            .strip_prefix(dir)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let name = entry.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with('.') || !rel.starts_with("tenant=") {
            continue;
        }
        let mut text = String::new();
        let file = std::fs::File::open(&entry).unwrap();
        if name.ends_with(".gz") {
            flate2::read::MultiGzDecoder::new(file)
                .read_to_string(&mut text)
                .unwrap();
        } else {
            let mut decoder = zstd::stream::read::Decoder::new(file).unwrap();
            decoder.window_log_max(31).unwrap();
            decoder.read_to_string(&mut text).unwrap();
        }
        let lines = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        out.push((rel, lines));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// The whole path: a stream and its request become one line under
/// `tenant=<t>/date=<d>/`, with the record, the node id, a complete capture,
/// the request as JSON and the reassembled response; files are 0600,
/// directories 0700, and only sealed names are visible after shutdown.
#[test]
fn a_captured_stream_becomes_one_line_in_a_sealed_private_segment() {
    let dir = tempfile::tempdir().unwrap();
    let running = start(&config(dir.path()));
    running.submit("acme", "e1:terminal", REQUEST, STREAM, sse_meta());
    let stats = running.stop();

    let segments = sealed_lines(dir.path());
    assert_eq!(segments.len(), 1, "{segments:?}");
    let (rel, lines) = &segments[0];
    assert!(
        rel.starts_with("tenant=acme/date=2026-10-01/node-a-"),
        "{rel}"
    );
    assert!(rel.ends_with(".jsonl.gz"));
    let line = &lines[0];
    assert_eq!(line["schema_version"], 1);
    assert_eq!(line["event_id"], "e1:terminal");
    assert_eq!(line["instance_id"], "node-a");
    assert_eq!(line["record"]["event_id"], "e1:terminal");
    assert_eq!(line["capture"]["state"], "complete");
    assert_eq!(line["request"]["body"]["model"], "m");
    assert_eq!(line["response"]["streamed"], true);
    assert_eq!(
        line["response"]["body"]["choices"][0]["message"]["content"],
        "Hello"
    );
    assert_eq!(
        line["response"]["body"]["choices"][0]["finish_reason"],
        "stop"
    );

    let file = dir.path().join(rel);
    assert_eq!(mode(&file), 0o600);
    assert_eq!(mode(file.parent().unwrap()), 0o700);
    assert_eq!(mode(file.parent().unwrap().parent().unwrap()), 0o700);
    let text = crate::stats::prometheus_render::render(&stats.registry());
    assert!(text.contains("envoy_llmproxy_trace_written_total{capture=\"complete\"} 1"));
    assert!(text.contains("envoy_llmproxy_trace_segments_sealed_total{reason=\"shutdown\"} 1"));
}

/// A stream cut before its terminal event, and a gzip-encoded JSON
/// response, are both written; the first is partial with its reason, the
/// second is inflated and says so.
#[test]
fn partial_and_encoded_responses_are_written_with_their_state() {
    let dir = tempfile::tempdir().unwrap();
    let running = start(&config(dir.path()));
    let cut = &STREAM[..STREAM.len() - b"data: [DONE]\n\n".len()];
    running.submit("acme", "cut", REQUEST, cut, sse_meta());

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, br#"{"id":"x","object":"chat.completion"}"#).unwrap();
    let meta = TraceMeta {
        response_content_type: Some("application/json".into()),
        response_content_encoding: Some("gzip".into()),
        ..sse_meta()
    };
    running.submit(
        "acme",
        "gz",
        br#"{"model":"m"}"#,
        &gz.finish().unwrap(),
        meta,
    );
    let stats = running.stop();

    let lines = &sealed_lines(dir.path())[0].1;
    let by_event = |e: &str| lines.iter().find(|l| l["event_id"] == e).unwrap().clone();
    let cut = by_event("cut");
    assert_eq!(cut["capture"]["state"], "partial");
    assert_eq!(
        cut["capture"]["reasons"],
        serde_json::json!(["stream_unterminated"])
    );
    assert_eq!(
        cut["response"]["body"]["choices"][0]["message"]["content"],
        "Hello"
    );
    let gz = by_event("gz");
    assert_eq!(gz["capture"]["state"], "complete");
    assert_eq!(gz["response"]["representation"], "decoded");
    assert_eq!(gz["response"]["content_encoding"], "gzip");
    assert_eq!(gz["response"]["body"]["id"], "x");
    let text = crate::stats::prometheus_render::render(&stats.registry());
    assert!(text.contains("envoy_llmproxy_trace_partial_total{reason=\"stream_unterminated\"} 1"));
}

/// A trace admitted before an emergency disable is not written, even if it
/// reached the exporter's queue, and the loss is counted.
#[test]
fn a_trace_admitted_before_a_disable_is_not_written() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    cfg.max_queued_traces = 4;
    let stats = StatsControl::new(1);
    let gate = Arc::new(TraceGate::open(dir.path()));
    let (admission, traces) =
        TraceAdmission::new(&cfg, Arc::clone(&gate), TraceStats::resolve(&stats));
    // Queue first, then disable, then start the exporter: the trace is in
    // the channel when the gate moves.
    let mut capture = admission.admit(REQUEST).unwrap();
    capture.push_response(STREAM);
    let (relay_tx, relay_rx) = mpsc::channel::<Box<CapturedTrace>>();
    capture.finish(record("late"), sse_meta());
    let queued = traces.recv().unwrap();
    gate.set_disabled(true, 0).unwrap();
    relay_tx.send(queued).unwrap();
    let exporter =
        TraceExporter::spawn(&cfg, "node-a", Arc::clone(&admission), relay_rx, &stats).unwrap();
    drop(relay_tx);
    assert!(exporter.shutdown(Duration::from_secs(5)));
    assert!(sealed_lines(dir.path()).is_empty());
    let text = crate::stats::prometheus_render::render(&stats.registry());
    assert!(
        text.contains("envoy_llmproxy_trace_dropped_total{reason=\"emergency_disabled\"} 1"),
        "{text}"
    );
    assert_eq!(admission.held_slots(), 0);
    drop(traces);
}

/// Sealing before a write keeps segments at their size bound; more tenants
/// than open segments seal the least recently written one; a date other
/// than today seals; and every seal is counted by its reason.
#[test]
fn segments_seal_by_size_by_lru_and_by_date() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = SegmentStore::open(dir.path(), "node-a", TraceCodec::Gzip, 1 << 20, 2).unwrap();
    let mut sealed = Vec::new();
    // Incompressible lines, so compressed size tracks what was written.
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let line: Vec<u8> = (0..400_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    for _ in 0..3 {
        store
            .write_line("a", "2026-10-01", &line, &mut sealed)
            .unwrap();
    }
    assert_eq!(
        sealed.iter().map(|(_, r)| *r).collect::<Vec<_>>(),
        vec![SealReason::Size],
        "the third line would cross 1 MiB, so the first two are sealed before it"
    );
    assert!(sealed[0].0.bytes <= 1 << 20);
    assert_eq!(sealed[0].0.lines, Some(2));

    store
        .write_line("b", "2026-10-01", b"{}\n", &mut sealed)
        .unwrap();
    store
        .write_line("c", "2026-10-01", b"{}\n", &mut sealed)
        .unwrap();
    assert_eq!(sealed.last().unwrap().1, SealReason::Lru);
    assert!(sealed.last().unwrap().0.relative.starts_with("tenant=a/"));

    let mut failed = 0;
    store.seal_due(
        Duration::from_secs(3600),
        "2026-10-02",
        &mut sealed,
        &mut failed,
    );
    assert_eq!(failed, 0);
    assert_eq!(
        sealed
            .iter()
            .filter(|(_, r)| *r == SealReason::Date)
            .count(),
        2,
        "b and c were open for yesterday's date"
    );
}

/// One process per directory; leftovers of any node id are removed at
/// start; and the epoch is raised past the persisted mark even when no
/// segment remains on disk (an S3 destination deletes uploaded ones), so a
/// name, and its object key, never repeats.
#[test]
fn the_directory_is_exclusive_and_names_never_repeat() {
    let dir = tempfile::tempdir().unwrap();
    let first = SegmentStore::open(dir.path(), "node-a", TraceCodec::Gzip, 1 << 20, 2).unwrap();
    assert!(matches!(
        SegmentStore::open(dir.path(), "node-a", TraceCodec::Gzip, 1 << 20, 2),
        Err(OpenError::Locked(_))
    ));
    let epoch = first.epoch();
    drop(first);

    let leftover_dir = dir.path().join("tenant=x/date=2026-10-01");
    std::fs::create_dir_all(&leftover_dir).unwrap();
    std::fs::write(leftover_dir.join(".old-node-1-0.jsonl.gz.open"), b"cut").unwrap();
    // Wind the mark forward, as if the clock had been ahead last time.
    std::fs::write(
        dir.path().join(".epoch-node-a"),
        (epoch + 1_000_000).to_string(),
    )
    .unwrap();
    let second = SegmentStore::open(dir.path(), "node-a", TraceCodec::Gzip, 1 << 20, 2).unwrap();
    assert_eq!(second.leftovers_removed, 1);
    assert!(second.epoch() > epoch + 1_000_000);
    assert!(!leftover_dir.join(".old-node-1-0.jsonl.gz.open").exists());

    assert!(matches!(
        SegmentStore::open(
            tempfile::tempdir().unwrap().path(),
            "-",
            TraceCodec::Gzip,
            1,
            1
        ),
        Err(OpenError::NodeId)
    ));
}

/// Directory retention removes the oldest sealed segments first, by size
/// and by age, and counts them as expiry, not loss. Each run below writes one
/// segment and seals it at shutdown; retention runs before every write.
#[test]
fn retention_removes_the_oldest_segments_first() {
    let dir = tempfile::tempdir().unwrap();
    for (i, tenant) in ["t1", "t2", "t3"].iter().enumerate() {
        let running = start(&config(dir.path()));
        running.submit(tenant, &format!("e{i}"), REQUEST, STREAM, sse_meta());
        let _ = running.stop();
    }
    let all = sealed_lines(dir.path());
    assert_eq!(all.len(), 3);
    let size = |rel: &str| std::fs::metadata(dir.path().join(rel)).unwrap().len();
    let (t2, t3) = (size(&all[1].0), size(&all[2].0));

    // Less than the two newest: the two oldest go before the next write,
    // and the small new segment fits beside the newest old one.
    let mut cfg = config(dir.path());
    cfg.max_disk_bytes = t2 + t3 - 1;
    let running = start(&cfg);
    running.submit("t4", "e4", br#"{}"#, b"{}", TraceMeta::default());
    let stats = running.stop();
    let text = crate::stats::prometheus_render::render(&stats.registry());
    assert!(
        text.contains("envoy_llmproxy_trace_segments_expired_total{reason=\"size\"} 2"),
        "{text}"
    );
    let left: Vec<String> = sealed_lines(dir.path())
        .into_iter()
        .map(|(r, _)| r)
        .collect();
    assert!(
        left.iter().any(|r| r.starts_with("tenant=t3/")) && left.len() == 2,
        "the newest old segment and the new one remain: {left:?}"
    );

    // Past max_age, every sealed segment goes before the next write.
    let mut cfg = config(dir.path());
    cfg.max_age = Some(Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(5));
    let running = start(&cfg);
    running.submit("t5", "e5", br#"{}"#, b"{}", TraceMeta::default());
    let stats = running.stop();
    let text = crate::stats::prometheus_render::render(&stats.registry());
    assert!(text.contains("envoy_llmproxy_trace_segments_expired_total{reason=\"age\"} 2"));
    let left: Vec<String> = sealed_lines(dir.path())
        .into_iter()
        .map(|(r, _)| r)
        .collect();
    assert_eq!(left.len(), 1);
    assert!(left[0].starts_with("tenant=t5/"));
}

/// The zstd codec writes a stream any zstd reader decodes with a large
/// enough window.
#[test]
fn the_zstd_codec_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    cfg.codec = TraceCodec::Zstd { window_log: 24 };
    let running = start(&cfg);
    running.submit("acme", "z", REQUEST, STREAM, sse_meta());
    let _ = running.stop();
    let segments = sealed_lines(dir.path());
    assert!(segments[0].0.ends_with(".jsonl.zst"));
    assert_eq!(segments[0].1[0]["event_id"], "z");
}

/// Persisted disable: an exporter started over a directory whose gate was
/// closed starts closed.
#[test]
fn a_persisted_disable_closes_the_gate_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let running = start(&config(dir.path()));
    running.gate.set_disabled(true, 0).unwrap();
    let _ = running.stop();
    let running = start(&config(dir.path()));
    assert!(!running.admission.gate_open());
    assert!(running.admission.admit(REQUEST).is_none());
    let stats = running.stop();
    let text = crate::stats::prometheus_render::render(&stats.registry());
    assert!(
        text.contains("envoy_llmproxy_trace_capture_disabled 1"),
        "the closed gate is visible: {text}"
    );
}
