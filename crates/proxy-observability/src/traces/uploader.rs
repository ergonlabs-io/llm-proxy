//! The S3-compatible uploader (ADR-0008 decision 7; design note section 7.2).
//!
//! One `trace-uploader` thread with its own current-thread runtime PUTs
//! sealed segments, oldest first, one at a time, and deletes each file once
//! the store answers 2xx. A failure is retried with full-jitter exponential
//! backoff; the local disk cap, which the exporter enforces, is what bounds
//! a long outage. The segment being uploaded is protected from that
//! eviction: the queue and the in-flight path share one lock.
//!
//! Credentials come from the exporter config only (AGENTS.md invariant 6)
//! and are never logged: errors name a status, a reason class or the
//! bucket, nothing else.

use crate::stats::{instruments, Handle, Registry, StatsControl, WorkerId};
use crate::traces::config::S3Destination;
use crate::traces::segment::Sealed;
use crate::traces::sigv4;
use bytes::Bytes;
use http_body_util::BodyExt;
use std::collections::VecDeque;
use std::io::Read;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

const BACKOFF_BASE: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(300);
const WARN_INTERVAL: Duration = Duration::from_secs(5);
const CHUNK: usize = 64 * 1024;

/// Why an upload failed. A closed set: it is a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadFailure {
    Connect,
    Timeout,
    Status4xx,
    Status5xx,
    Io,
}

impl UploadFailure {
    pub const ALL: [Self; 5] = [
        Self::Connect,
        Self::Timeout,
        Self::Status4xx,
        Self::Status5xx,
        Self::Io,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::Status4xx => "status_4xx",
            Self::Status5xx => "status_5xx",
            Self::Io => "io",
        }
    }
}

#[derive(Default)]
pub struct QueueState {
    pub pending: VecDeque<Sealed>,
    pub in_flight: Option<PathBuf>,
    stopping: bool,
}

/// Sealed segments waiting for upload, shared by the exporter (which adds
/// and evicts) and the uploader (which takes).
#[derive(Default)]
pub struct UploadQueue {
    state: Mutex<QueueState>,
    ready: Condvar,
}

impl UploadQueue {
    pub fn push(&self, segment: Sealed) {
        self.state.lock().unwrap().pending.push_back(segment);
        self.ready.notify_one();
    }

    /// Hold the queue while evicting, so the uploader cannot take the
    /// segment being evicted, nor the evictor delete the one in flight.
    pub fn lock(&self) -> std::sync::MutexGuard<'_, QueueState> {
        self.state.lock().unwrap()
    }

    fn stop(&self) {
        self.state.lock().unwrap().stopping = true;
        self.ready.notify_all();
    }
}

struct UploaderStats {
    registry: Arc<Registry>,
    uploaded: Handle,
    failures: [Handle; UploadFailure::ALL.len()],
}

impl UploaderStats {
    fn resolve(control: &StatsControl) -> Self {
        UploaderStats {
            registry: control.registry(),
            uploaded: control.resolve(&instruments::TRACE_SEGMENTS_UPLOADED, &[]),
            failures: UploadFailure::ALL.map(|f| {
                control.resolve(
                    &instruments::TRACE_UPLOAD_FAILURES,
                    &[("reason", f.as_str())],
                )
            }),
        }
    }

    fn failed(&self, failure: UploadFailure) {
        let i = UploadFailure::ALL
            .iter()
            .position(|f| *f == failure)
            .unwrap();
        self.registry.incr(WorkerId(0), self.failures[i], 1);
    }
}

/// Where and how to PUT, resolved once from the config.
struct Target {
    scheme_https: bool,
    /// The address to connect to.
    connect_host: String,
    port: u16,
    /// The `host` header, which SigV4 signs.
    host_header: String,
    /// Path before the key: `/<bucket>` for path style, empty otherwise.
    bucket_path: Option<String>,
    prefix: Vec<String>,
    destination: S3Destination,
}

impl Target {
    fn new(destination: &S3Destination) -> Self {
        let endpoint = destination
            .endpoint
            .clone()
            .unwrap_or_else(|| format!("https://s3.{}.amazonaws.com", destination.region));
        let uri: http::Uri = endpoint.parse().expect("validated at config load");
        let scheme_https = uri.scheme_str() == Some("https");
        let host = uri.host().expect("validated at config load").to_string();
        let port = uri
            .port_u16()
            .unwrap_or(if scheme_https { 443 } else { 80 });
        let default_port = (scheme_https && port == 443) || (!scheme_https && port == 80);
        let authority = |h: &str| {
            if default_port {
                h.to_string()
            } else {
                format!("{h}:{port}")
            }
        };
        let (connect_host, host_header, bucket_path) = if destination.path_style {
            (
                host.clone(),
                authority(&host),
                Some(destination.bucket.clone()),
            )
        } else {
            let virtual_host = format!("{}.{host}", destination.bucket);
            (virtual_host.clone(), authority(&virtual_host), None)
        };
        Target {
            scheme_https,
            connect_host,
            port,
            host_header,
            bucket_path,
            prefix: destination
                .prefix
                .split('/')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            destination: destination.clone(),
        }
    }

    /// The request-target, also the SigV4 canonical URI: every segment
    /// encoded once.
    fn path_for(&self, relative: &str) -> String {
        let mut segments: Vec<&str> = Vec::new();
        if let Some(bucket) = &self.bucket_path {
            segments.push(bucket);
        }
        segments.extend(self.prefix.iter().map(String::as_str));
        segments.extend(relative.split('/'));
        sigv4::encode_path(&segments)
    }
}

/// The running uploader.
pub struct Uploader {
    queue: Arc<UploadQueue>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Uploader {
    /// Start the thread. `uploaded` receives the path of every segment the
    /// store confirmed and that was then deleted locally.
    pub fn spawn(
        destination: &S3Destination,
        queue: Arc<UploadQueue>,
        uploaded: mpsc::Sender<PathBuf>,
        control: &StatsControl,
    ) -> std::io::Result<Self> {
        let target = Target::new(destination);
        if !target.scheme_https {
            let loopback = target.connect_host == "localhost"
                || target
                    .connect_host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback());
            if !loopback {
                tracing::warn!(
                    bucket = %destination.bucket,
                    "trace upload endpoint is plain http: request and response bodies travel \
                     unencrypted (the credential itself is not sent; SigV4 signs with it)"
                );
            }
        }
        let stats = UploaderStats::resolve(control);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_queue = Arc::clone(&queue);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let thread = std::thread::Builder::new()
            .name("trace-uploader".into())
            .spawn(move || {
                runtime.block_on(run(target, thread_queue, uploaded, stats, thread_stop));
            })?;
        Ok(Uploader {
            queue,
            stop,
            thread: Some(thread),
        })
    }

    /// Stop after the upload in flight, waiting at most `deadline`. What is
    /// left stays on disk and is uploaded at the next start.
    pub fn shutdown(mut self, deadline: Duration) -> bool {
        self.stop.store(true, Ordering::Release);
        self.queue.stop();
        let Some(thread) = self.thread.take() else {
            return true;
        };
        let started = Instant::now();
        while !thread.is_finished() {
            if started.elapsed() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        thread.join().is_ok()
    }
}

impl Drop for Uploader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.queue.stop();
    }
}

async fn run(
    target: Target,
    queue: Arc<UploadQueue>,
    uploaded: mpsc::Sender<PathBuf>,
    stats: UploaderStats,
    stop: Arc<AtomicBool>,
) {
    let tls = match tls_connector() {
        Ok(tls) => Some(tls),
        Err(e) if target.scheme_https => {
            tracing::error!(error = %e, "trace uploader cannot build its TLS client; uploads stop");
            return;
        }
        Err(_) => None,
    };
    let mut attempt: u32 = 0;
    let mut last_warn: Option<Instant> = None;
    loop {
        // Wait for work without holding a runtime thread's attention: the
        // condvar wait is short and this runtime runs nothing else.
        let segment = {
            let mut state = queue.state.lock().unwrap();
            loop {
                if state.stopping || stop.load(Ordering::Acquire) {
                    return;
                }
                if let Some(segment) = state.pending.pop_front() {
                    state.in_flight = Some(segment.path.clone());
                    break segment;
                }
                state = queue
                    .ready
                    .wait_timeout(state, Duration::from_millis(200))
                    .unwrap()
                    .0;
            }
        };
        let outcome = tokio::time::timeout(
            target.destination.upload_timeout,
            put(&target, tls.as_ref(), &segment),
        )
        .await
        .unwrap_or(Err(UploadFailure::Timeout));
        match outcome {
            Ok(()) => {
                let _ = std::fs::remove_file(&segment.path);
                queue.state.lock().unwrap().in_flight = None;
                let _ = uploaded.send(segment.path);
                stats.registry.incr(WorkerId(0), stats.uploaded, 1);
                attempt = 0;
            }
            Err(failure) => {
                {
                    let mut state = queue.state.lock().unwrap();
                    state.in_flight = None;
                    // The exporter may have evicted it meanwhile only if it
                    // was not in flight, which it was; retry it first.
                    state.pending.push_front(segment);
                }
                stats.failed(failure);
                if last_warn.is_none_or(|t| t.elapsed() >= WARN_INTERVAL) {
                    last_warn = Some(Instant::now());
                    tracing::warn!(
                        bucket = %target.destination.bucket,
                        reason = failure.as_str(),
                        "trace segment upload failed; retrying with backoff \
                         (llmproxy_trace_upload_failures_total)"
                    );
                }
                attempt = attempt.saturating_add(1);
                let ceiling = BACKOFF_BASE
                    .saturating_mul(1u32 << attempt.min(16))
                    .min(BACKOFF_CAP);
                let wait = ceiling.mul_f64(rand::random::<f64>());
                let until = Instant::now() + wait;
                while Instant::now() < until {
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(50).min(wait)).await;
                }
            }
        }
    }
}

fn tls_connector() -> Result<tokio_rustls::TlsConnector, String> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    if native.certs.is_empty() {
        return Err(format!("no system root certificates: {:?}", native.errors));
    }
    roots.add_parsable_certificates(native.certs);
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("{e:?}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// A request body read from the segment file in fixed chunks. The uploader
/// runs on its own thread, so a blocking read here stalls nothing else, and
/// a segment is never held in memory whole.
struct FileBody {
    file: std::fs::File,
    remaining: u64,
}

impl hyper::body::Body for FileBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.remaining == 0 {
            return Poll::Ready(None);
        }
        let mut buf = vec![0u8; CHUNK.min(this.remaining as usize)];
        match this.file.read(&mut buf) {
            Ok(0) => Poll::Ready(Some(Err(std::io::ErrorKind::UnexpectedEof.into()))),
            Ok(n) => {
                buf.truncate(n);
                this.remaining -= n as u64;
                Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from(buf)))))
            }
            Err(e) => Poll::Ready(Some(Err(e))),
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.remaining)
    }
}

fn file_sha256(path: &std::path::Path) -> std::io::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; CHUNK];
    let mut len = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        context.update(&buf[..n]);
        len += n as u64;
    }
    let digest: String = context
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((digest, len))
}

async fn put(
    target: &Target,
    tls: Option<&tokio_rustls::TlsConnector>,
    segment: &Sealed,
) -> Result<(), UploadFailure> {
    let (payload_sha256, len) = file_sha256(&segment.path).map_err(|_| UploadFailure::Io)?;
    let path = target.path_for(&segment.relative);
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let credentials = &target.destination.credentials;
    let len_text = len.to_string();
    let mut signed: Vec<(&str, &str)> = vec![
        ("content-length", &len_text),
        ("content-type", "application/x-ndjson"),
        ("host", &target.host_header),
        ("x-amz-content-sha256", &payload_sha256),
        ("x-amz-date", &amz_date),
    ];
    if let Some(token) = &credentials.session_token {
        signed.push(("x-amz-security-token", token));
    }
    let authorization = sigv4::authorization(
        &sigv4::Request {
            method: "PUT",
            canonical_uri: &path,
            query: &[],
            headers: &signed,
            payload_sha256: &payload_sha256,
        },
        &sigv4::Scope {
            access_key_id: &credentials.access_key_id,
            secret_access_key: &credentials.secret_access_key,
            region: &target.destination.region,
            service: "s3",
            amz_date: &amz_date,
        },
    );
    let mut request = http::Request::builder().method("PUT").uri(&path);
    for (name, value) in &signed {
        request = request.header(*name, *value);
    }
    let file = std::fs::File::open(&segment.path).map_err(|_| UploadFailure::Io)?;
    let request = request
        .header("authorization", authorization)
        .body(FileBody {
            file,
            remaining: len,
        })
        .map_err(|_| UploadFailure::Io)?;

    let tcp = tokio::net::TcpStream::connect((target.connect_host.as_str(), target.port))
        .await
        .map_err(|_| UploadFailure::Connect)?;
    let status = if target.scheme_https {
        let tls = tls.ok_or(UploadFailure::Connect)?;
        let name = rustls::pki_types::ServerName::try_from(target.connect_host.clone())
            .map_err(|_| UploadFailure::Connect)?;
        let stream = tls
            .connect(name, tcp)
            .await
            .map_err(|_| UploadFailure::Connect)?;
        send(hyper_util::rt::TokioIo::new(stream), request).await?
    } else {
        send(hyper_util::rt::TokioIo::new(tcp), request).await?
    };
    match status {
        s if s.is_success() => Ok(()),
        s if s.is_client_error() => Err(UploadFailure::Status4xx),
        _ => Err(UploadFailure::Status5xx),
    }
}

async fn send<I>(io: I, request: http::Request<FileBody>) -> Result<http::StatusCode, UploadFailure>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|_| UploadFailure::Connect)?;
    let driver = tokio::spawn(connection);
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| UploadFailure::Io)?;
    let status = response.status();
    // Bounded: an error body from a store is small; a huge one is cut.
    let mut body = response.into_body();
    let mut read = 0usize;
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                read += frame.data_ref().map_or(0, |d| d.len());
                if read > 64 * 1024 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    driver.abort();
    Ok(status)
}
