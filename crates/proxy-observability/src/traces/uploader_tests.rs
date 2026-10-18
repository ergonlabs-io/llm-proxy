//! The S3 destination against a hermetic store: a loopback HTTP server that
//! checks each request's SigV4 signature from the request-target and
//! headers it actually received, keeps objects by path, and can be switched
//! to answer 503. No real cloud credentials or endpoints are involved.

use super::capture::{TraceAdmission, TraceDialect, TraceMeta, TraceStats};
use super::config::{S3Credentials, S3Destination, TraceCodec, TraceExportConfig};
use super::exporter::TraceExporter;
use super::gate::TraceGate;
use super::sigv4;
use crate::ledger::testing::record;
use crate::stats::StatsControl;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const KEY_ID: &str = "AKIDTRACETEST";
const SECRET: &str = "trace-test-secret-do-not-log";

#[derive(Default)]
struct Store {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    failing: AtomicBool,
    /// Holds each response until cleared, so an upload stays in flight.
    holding: AtomicBool,
    bad_signatures: AtomicUsize,
    requests: AtomicUsize,
}

fn spawn_store() -> (SocketAddr, Arc<Store>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let store = Arc::new(Store::default());
    let shared = Arc::clone(&store);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let store = Arc::clone(&shared);
            std::thread::spawn(move || serve(stream, &store));
        }
    });
    (addr, store)
}

fn serve(stream: std::net::TcpStream, store: &Store) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let (method, target) = (
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("").to_string(),
    );
    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    store.requests.fetch_add(1, Ordering::SeqCst);
    while store.holding.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(10));
    }
    let respond = |status: &str| {
        let mut stream = stream.try_clone().unwrap();
        let _ = stream.write_all(
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        );
    };
    if !signature_matches(&method, &target, &headers, &body) {
        store.bad_signatures.fetch_add(1, Ordering::SeqCst);
        respond("403 Forbidden");
        return;
    }
    if store.failing.load(Ordering::SeqCst) {
        respond("503 Slow Down");
        return;
    }
    store.objects.lock().unwrap().insert(target, body);
    respond("200 OK");
}

/// What a store does: recompute the signature over the request-target as
/// received and the headers the client said it signed, with the payload
/// hash taken from the body itself.
fn signature_matches(
    method: &str,
    target: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> bool {
    let Some(auth) = headers.get("authorization") else {
        return false;
    };
    let Some(signed) = auth
        .split("SignedHeaders=")
        .nth(1)
        .and_then(|s| s.split(',').next())
    else {
        return false;
    };
    let payload = sigv4::sha256_hex(body);
    if headers.get("x-amz-content-sha256") != Some(&payload) {
        return false;
    }
    let signed_pairs: Vec<(&str, &str)> = signed
        .split(';')
        .map(|name| (name, headers.get(name).map(String::as_str).unwrap_or("")))
        .collect();
    let amz_date = headers.get("x-amz-date").cloned().unwrap_or_default();
    let expected = sigv4::authorization(
        &sigv4::Request {
            method,
            canonical_uri: target,
            query: &[],
            headers: &signed_pairs,
            payload_sha256: &payload,
        },
        &sigv4::Scope {
            access_key_id: KEY_ID,
            secret_access_key: SECRET,
            region: "test-region-1",
            service: "s3",
            amz_date: &amz_date,
        },
    );
    &expected == auth && signed.split(';').any(|h| h == "host")
}

fn config(dir: &Path, store: SocketAddr) -> TraceExportConfig {
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
        segment_max_age: Duration::from_millis(1),
        max_open_segments: 1,
        s3: Some(S3Destination {
            bucket: "traces".into(),
            region: "test-region-1".into(),
            endpoint: Some(format!("http://{store}")),
            path_style: true,
            prefix: "pre/fix".into(),
            credentials: S3Credentials {
                access_key_id: KEY_ID.into(),
                secret_access_key: SECRET.into(),
                session_token: None,
            },
            upload_timeout: Duration::from_secs(10),
        }),
    }
}

fn meta() -> TraceMeta {
    TraceMeta {
        path: "/v1/chat/completions".into(),
        status: Some(200),
        request_content_type: Some("application/json".into()),
        response_content_type: Some("application/json".into()),
        dialect: Some(TraceDialect::OpenAi),
        ..TraceMeta::default()
    }
}

struct Running {
    admission: Arc<TraceAdmission>,
    exporter: TraceExporter,
    stats: StatsControl,
}

fn start(config: &TraceExportConfig) -> Running {
    let stats = StatsControl::new(1);
    let gate = Arc::new(TraceGate::open(&config.directory));
    let (admission, traces) = TraceAdmission::new(config, gate, TraceStats::resolve(&stats));
    let exporter =
        TraceExporter::spawn(config, "node-a", Arc::clone(&admission), traces, &stats).unwrap();
    Running {
        admission,
        exporter,
        stats,
    }
}

impl Running {
    fn submit(&self, tenant: &str, event: &str) {
        let mut capture = self.admission.admit(br#"{"model":"m"}"#).unwrap();
        capture.push_response(br#"{"id":"r"}"#);
        let mut record = record(event);
        record.tenant_id = tenant.into();
        capture.finish(record, meta());
    }

    fn metrics(&self) -> String {
        crate::stats::prometheus_render::render(&self.stats.registry())
    }

    fn counter(&self, series: &str) -> u64 {
        self.metrics()
            .lines()
            .find_map(|l| l.strip_prefix(&format!("envoy_{series} ")))
            .map(|v| v.parse().unwrap())
            .unwrap_or_else(|| panic!("no {series}"))
    }
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Sealed segment files still on disk.
fn local_segments(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                stack.push(path);
            } else if name.ends_with(".jsonl.gz") && !name.starts_with('.') {
                out.push(path);
            }
        }
    }
    out
}

/// A sealed segment is PUT under `<prefix>/tenant=<t>/date=<d>/<name>`, each
/// segment of the key encoded once (`=` as `%3D`, an encoded tenant's `%` as
/// `%25`), signed so the store accepts it, and removed locally afterwards.
#[test]
fn a_sealed_segment_is_uploaded_under_its_key_and_removed_locally() {
    let (addr, store) = spawn_store();
    let dir = tempfile::tempdir().unwrap();
    let running = start(&config(dir.path(), addr));
    running.submit("t=1/x", "e1");
    wait_until("the upload", || !store.objects.lock().unwrap().is_empty());
    wait_until("the local delete", || local_segments(dir.path()).is_empty());

    let objects = store.objects.lock().unwrap().clone();
    let (key, body) = objects.iter().next().unwrap();
    assert!(
        key.starts_with("/traces/pre/fix/tenant%3Dt%253D1%252Fx/date%3D2026-10-01/node-a-"),
        "{key}"
    );
    assert!(key.ends_with("-0.jsonl.gz"));
    let mut text = String::new();
    flate2::read::MultiGzDecoder::new(&body[..])
        .read_to_string(&mut text)
        .unwrap();
    let line: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(line["event_id"], "e1");
    assert_eq!(store.bad_signatures.load(Ordering::SeqCst), 0);
    assert_eq!(running.counter("llmproxy_trace_segments_uploaded_total"), 1);
    assert!(running.exporter.shutdown(Duration::from_secs(5)));
}

/// With the store down, the disk stays under its cap by dropping the oldest
/// unsent segment, which is counted with its lines; the segment in flight is
/// never the one dropped. When the store recovers, what remains is uploaded.
/// No credential reaches the metrics.
#[test]
fn an_outage_drops_the_oldest_unsent_segment_and_recovery_uploads_the_rest() {
    let (addr, store) = spawn_store();
    store.failing.store(true, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();

    // Measure one segment, then allow about two and a half on disk.
    let probe_dir = tempfile::tempdir().unwrap();
    let probe = start(&config(probe_dir.path(), addr));
    probe.submit("t0", "probe");
    wait_until("the probe's first attempt", || {
        store.requests.load(Ordering::SeqCst) >= 1
    });
    let one = std::fs::metadata(&local_segments(probe_dir.path())[0])
        .unwrap()
        .len();
    drop(probe);

    let mut cfg = config(dir.path(), addr);
    cfg.max_disk_bytes = one * 5 / 2;
    let running = start(&cfg);
    // One open segment, so each new tenant seals the previous one.
    for i in 0..6 {
        running.submit(&format!("t{i}"), &format!("e{i}"));
    }
    // The cap is enforced after each write: measure once all six are in.
    wait_until("all six lines written", || {
        running.counter("llmproxy_trace_written_total{capture=\"complete\"}") == 6
    });
    wait_until("the disk to settle under the cap", || {
        let on_disk: u64 = local_segments(dir.path())
            .iter()
            .map(|p| std::fs::metadata(p).map_or(0, |m| m.len()))
            .sum();
        on_disk <= cfg.max_disk_bytes
    });
    assert!(running.counter("llmproxy_trace_segments_lost_total{reason=\"upload_backlog\"}") >= 2);
    let lost = running.counter("llmproxy_trace_segments_lost_total{reason=\"upload_backlog\"}");
    assert_eq!(
        running.counter("llmproxy_trace_dropped_total{reason=\"upload_backlog\"}"),
        lost,
        "one line per segment here"
    );
    wait_until("a failed attempt", || {
        running.counter("llmproxy_trace_upload_failures_total{reason=\"status_5xx\"}") >= 1
    });

    store.failing.store(false, Ordering::SeqCst);
    // Six segments in all: five sealed by LRU while the store was down, the
    // last by age once a tick passes. Each is either uploaded or counted
    // lost, and the newest survive, since eviction takes the oldest unsent.
    let lost_now =
        || running.counter("llmproxy_trace_segments_lost_total{reason=\"upload_backlog\"}");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let local = local_segments(dir.path()).len();
        let objects = store.objects.lock().unwrap().len() as u64;
        if local == 0 && objects + lost_now() == 6 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "local {local}, uploaded {objects}, lost {}:\n{}",
            lost_now(),
            running.metrics()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let uploaded: Vec<String> = store.objects.lock().unwrap().keys().cloned().collect();
    for newest in ["tenant%3Dt4/", "tenant%3Dt5/"] {
        assert!(uploaded.iter().any(|k| k.contains(newest)), "{uploaded:?}");
    }
    assert_eq!(store.bad_signatures.load(Ordering::SeqCst), 0);
    assert!(!running.metrics().contains(SECRET));
    assert!(!running.metrics().contains(KEY_ID));
    assert!(running.exporter.shutdown(Duration::from_secs(5)));
}

/// The segment being uploaded is never the one the disk cap drops, however
/// far over the cap the backlog goes while it is in flight.
#[test]
fn the_segment_in_flight_is_never_the_one_dropped() {
    let (addr, store) = spawn_store();
    store.holding.store(true, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path(), addr);
    // Measured in the outage test's way would race the held upload; one
    // segment of this shape is well under 2 KiB.
    cfg.max_disk_bytes = 2048;
    let running = start(&cfg);
    running.submit("t0", "e0");
    wait_until("t0 in flight", || {
        store.requests.load(Ordering::SeqCst) >= 1
    });
    for i in 1..6 {
        running.submit(&format!("t{i}"), &format!("e{i}"));
    }
    wait_until("evictions while t0 is in flight", || {
        running.counter("llmproxy_trace_segments_lost_total{reason=\"upload_backlog\"}") >= 2
    });
    store.holding.store(false, Ordering::SeqCst);
    // Every segment is uploaded or counted lost, exactly once: an evicted
    // in-flight segment would still finish uploading from its open file and
    // be counted both ways.
    wait_until("exact accounting", || {
        local_segments(dir.path()).is_empty()
            && store.objects.lock().unwrap().len() as u64
                + running.counter("llmproxy_trace_segments_lost_total{reason=\"upload_backlog\"}")
                == 6
    });
    assert!(store
        .objects
        .lock()
        .unwrap()
        .keys()
        .any(|k| k.contains("tenant%3Dt0/")));
    assert!(running.exporter.shutdown(Duration::from_secs(5)));
}
