//! The two load modes (closed-loop / open-loop) and the single-stream
//! request/response cycle they both drive.
//!
//! The default remains connect-per-stream. Opt-in transports provide bounded
//! HTTP/1.1 keep-alive reuse and TLS/ALPN HTTP/2 multiplexing.

use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::Serialize;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;

use crate::dialect::{Endpoint, FrameKind};
use crate::metrics::{Aggregator, Outcome, RunSummary, StreamResult, TransportSummary};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DownstreamMode {
    Short,
    H1Pool,
    H2,
}

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub mode: DownstreamMode,
    pub h1_pool_size: usize,
    pub ca_file: Option<PathBuf>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            mode: DownstreamMode::Short,
            h1_pool_size: 32,
            ca_file: None,
        }
    }
}
use crate::sse::SseParser;

/// One upstream to send requests to. Connect-per-stream means every stream
/// picks a target (round-robin across however many were given) and dials it
/// fresh.
#[derive(Debug, Clone)]
pub struct Target {
    pub tls: bool,
    pub host: String,
    pub port: u16,
}

/// Parse `--target` values: each element may itself be a comma-separated
/// list, so `--target a,b --target c` and `--target a --target b --target c`
/// are equivalent -- both give the driver more loopback aliases to
/// round-robin across (see the crate doc's port-exhaustion mitigation).
pub fn parse_targets(raw: &[String]) -> anyhow::Result<Vec<Target>> {
    let mut targets = Vec::new();
    for entry in raw {
        for piece in entry.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            targets.push(parse_target(piece)?);
        }
    }
    if targets.is_empty() {
        anyhow::bail!("at least one --target is required");
    }
    Ok(targets)
}

fn parse_target(raw: &str) -> anyhow::Result<Target> {
    let uri: http::Uri = raw
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid target {raw:?}: {e}"))?;
    let scheme = uri.scheme_str().unwrap_or("http");
    if scheme != "http" && scheme != "https" {
        anyhow::bail!("target {raw:?}: scheme must be http or https");
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("target {raw:?} has no host"))?;
    Ok(Target {
        tls: scheme == "https",
        host: authority.host().to_string(),
        port: authority
            .port_u16()
            .unwrap_or(if scheme == "https" { 443 } else { 80 }),
    })
}

/// Everything one stream needs that doesn't change between streams.
pub struct RunConfig {
    pub targets: Vec<Target>,
    pub endpoint: Endpoint,
    pub model: String,
    pub prompt: String,
    pub max_tokens: u32,
    pub api_key: Option<String>,
    pub stream: bool,
    pub timeout: Duration,
    pub transport: TransportConfig,
}

#[derive(Default)]
struct TransportCounters {
    opened: AtomicU64,
    reused: AtomicU64,
    streams: AtomicU64,
}

impl TransportCounters {
    fn snapshot(&self) -> TransportSummary {
        let connections_opened = self.opened.load(Ordering::Relaxed);
        let logical_streams = self.streams.load(Ordering::Relaxed);
        TransportSummary {
            connections_opened,
            connections_reused: self.reused.load(Ordering::Relaxed),
            logical_streams,
            streams_per_connection: if connections_opened == 0 {
                0.0
            } else {
                logical_streams as f64 / connections_opened as f64
            },
        }
    }
}

type H1Sender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;
type H2Sender = hyper::client::conn::http2::SendRequest<Full<Bytes>>;

struct ClientState {
    cfg: TransportConfig,
    counters: Arc<TransportCounters>,
    h1: Vec<Mutex<Option<H1Sender>>>,
    h1_next: AtomicUsize,
    h2: Vec<Mutex<Option<H2Sender>>>,
}

impl ClientState {
    fn new(cfg: TransportConfig, targets: usize) -> Self {
        let size = cfg.h1_pool_size.max(1);
        Self {
            cfg,
            counters: Arc::new(TransportCounters::default()),
            h1: (0..targets * size).map(|_| Mutex::new(None)).collect(),
            h1_next: AtomicUsize::new(0),
            h2: (0..targets).map(|_| Mutex::new(None)).collect(),
        }
    }
}

fn pick_target<'a>(cfg: &'a RunConfig, idx: &AtomicUsize) -> (usize, &'a Target) {
    // Rust note: `Relaxed` is enough here -- this counter only needs to hand
    // out distinct-ish indices for round-robin, not to synchronize any other
    // memory access, so the stronger orderings would just cost more for no
    // benefit.
    let i = idx.fetch_add(1, Ordering::Relaxed);
    let index = i % cfg.targets.len();
    (index, &cfg.targets[index])
}

enum ExecError {
    Http(u16),
    Transport,
    Timeout,
    /// The body ended (cleanly, no transport error) without ever producing a
    /// `FrameKind::Terminal` frame -- the proxy (or upstream) cut the stream
    /// short. Kept distinct from `Transport`: "the connection broke" and
    /// "the connection was fine but the stream never finished" are different
    /// bugs, and folding them together would send someone chasing the wrong
    /// one from a capacity report.
    Truncated,
}

/// What one successful (2xx, fully read) stream measured.
struct Measured {
    first_content_at: Option<Instant>,
    inter_token_gaps: Vec<Duration>,
    tokens_received: u64,
    bytes_received: u64,
    end: Instant,
}

/// Run one request/response cycle against `target`, streaming and
/// classifying SSE frames as they arrive (or, in `--no-stream` mode, just
/// reading the whole body).
fn request(cfg: &RunConfig, target: &Target) -> Request<Full<Bytes>> {
    let body_value = cfg
        .endpoint
        .build_body(&cfg.model, &cfg.prompt, cfg.max_tokens, cfg.stream);
    let body_bytes = serde_json::to_vec(&body_value).expect("request body is always serializable");
    let mut builder = Request::builder()
        .method("POST")
        .uri(cfg.endpoint.path())
        .header("host", format!("{}:{}", target.host, target.port))
        .header("content-type", "application/json")
        .header("content-length", body_bytes.len());
    if cfg.stream {
        builder = builder.header("accept", "text/event-stream");
    }
    for (name, value) in cfg.endpoint.auth_headers(cfg.api_key.as_deref()) {
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(Bytes::from(body_bytes)))
        .expect("valid request")
}

fn tls_config(ca_file: Option<&PathBuf>, alpn: &[u8]) -> Result<rustls::ClientConfig, ExecError> {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(path) = ca_file {
        let file = std::fs::File::open(path).map_err(|_| ExecError::Transport)?;
        for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(file)) {
            roots
                .add(cert.map_err(|_| ExecError::Transport)?)
                .map_err(|_| ExecError::Transport)?;
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = roots.add(cert);
        }
        if !native.errors.is_empty() && roots.is_empty() {
            return Err(ExecError::Transport);
        }
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

/// An HTTP/1.1 connection, over TLS (ALPN `http/1.1`) for an https target,
/// so a TLS listener can be measured with the same pooled and short modes.
async fn new_h1(
    target: &Target,
    cfg: &TransportConfig,
    counters: &TransportCounters,
) -> Result<H1Sender, ExecError> {
    let stream = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|_| ExecError::Transport)?;
    if !target.tls {
        counters.opened.fetch_add(1, Ordering::Relaxed);
        return h1_handshake(stream).await;
    }
    let server_name =
        ServerName::try_from(target.host.clone()).map_err(|_| ExecError::Transport)?;
    let tls = TlsConnector::from(Arc::new(tls_config(cfg.ca_file.as_ref(), b"http/1.1")?))
        .connect(server_name, stream)
        .await
        .map_err(|_| ExecError::Transport)?;
    counters.opened.fetch_add(1, Ordering::Relaxed);
    h1_handshake(tls).await
}

async fn h1_handshake<T>(io: T) -> Result<H1Sender, ExecError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake::<_, Full<Bytes>>(TokioIo::new(io))
        .await
        .map_err(|_| ExecError::Transport)?;
    tokio::spawn(conn);
    Ok(sender)
}

async fn new_h2(
    target: &Target,
    cfg: &TransportConfig,
    counters: &TransportCounters,
) -> Result<H2Sender, ExecError> {
    if !target.tls {
        return Err(ExecError::Transport);
    }
    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|_| ExecError::Transport)?;
    let server_name =
        ServerName::try_from(target.host.clone()).map_err(|_| ExecError::Transport)?;
    let tls = TlsConnector::from(Arc::new(tls_config(cfg.ca_file.as_ref(), b"h2")?))
        .connect(server_name, tcp)
        .await
        .map_err(|_| ExecError::Transport)?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(ExecError::Transport);
    }
    counters.opened.fetch_add(1, Ordering::Relaxed);
    let (sender, conn) =
        hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
            .await
            .map_err(|_| ExecError::Transport)?;
    tokio::spawn(conn);
    Ok(sender)
}

async fn consume_response(
    cfg: &RunConfig,
    response: Response<hyper::body::Incoming>,
) -> Result<Measured, ExecError> {
    let status = response.status();
    if !status.is_success() {
        return Err(ExecError::Http(status.as_u16()));
    }

    if !cfg.stream {
        let collected = response
            .into_body()
            .collect()
            .await
            .map_err(|_| ExecError::Transport)?;
        let bytes = collected.to_bytes();
        return Ok(Measured {
            first_content_at: None,
            inter_token_gaps: Vec::new(),
            tokens_received: 0,
            bytes_received: bytes.len() as u64,
            end: Instant::now(),
        });
    }

    let mut body = response.into_body();
    let mut parser = SseParser::new();
    let mut first_content_at = None;
    let mut last_token_at: Option<Instant> = None;
    let mut gaps = Vec::new();
    let mut tokens_received = 0u64;
    let mut bytes_received = 0u64;
    // Rust note: this is the whole fix -- `FrameKind::Terminal` used to be
    // matched and discarded (`FrameKind::Terminal | FrameKind::Other => {}`).
    // Recording whether we ever saw one lets the `None => break` arm below
    // tell "the stream finished" apart from "the body just stopped".
    let mut terminal_seen = false;

    loop {
        let frame = match body.frame().await {
            Some(Ok(frame)) => frame,
            Some(Err(_)) => return Err(ExecError::Transport),
            None => break,
        };
        let Some(data) = frame.data_ref() else {
            continue;
        };
        bytes_received += data.len() as u64;
        for sse_frame in parser.push(data) {
            match cfg.endpoint.classify(&sse_frame) {
                FrameKind::ContentDelta(_text) => {
                    let now = Instant::now();
                    if first_content_at.is_none() {
                        first_content_at = Some(now);
                    }
                    if let Some(last) = last_token_at {
                        gaps.push(now.duration_since(last));
                    }
                    last_token_at = Some(now);
                    tokens_received += 1;
                }
                FrameKind::Terminal => terminal_seen = true,
                FrameKind::Other => {}
            }
        }
    }

    if !terminal_seen {
        // The body closed cleanly (no transport error) but never delivered
        // the dialect's terminal frame -- a truncated stream, not a
        // successful one. `cfg.endpoint.classify` already knows the
        // dialect's terminal shape ([DONE], `response.completed`,
        // `message_stop`, ...), so this check stays generic across dialects.
        return Err(ExecError::Truncated);
    }

    Ok(Measured {
        first_content_at,
        inter_token_gaps: gaps,
        tokens_received,
        bytes_received,
        end: Instant::now(),
    })
}

async fn execute(
    cfg: &RunConfig,
    state: &ClientState,
    target_index: usize,
    target: &Target,
) -> Result<Measured, ExecError> {
    state.counters.streams.fetch_add(1, Ordering::Relaxed);
    match state.cfg.mode {
        DownstreamMode::Short => {
            let mut sender = new_h1(target, &state.cfg, &state.counters).await?;
            consume_response(
                cfg,
                sender
                    .send_request(request(cfg, target))
                    .await
                    .map_err(|_| ExecError::Transport)?,
            )
            .await
        }
        DownstreamMode::H1Pool => {
            let size = state.cfg.h1_pool_size.max(1);
            let slot_index =
                target_index * size + state.h1_next.fetch_add(1, Ordering::Relaxed) % size;
            let started = Instant::now();
            let mut slot =
                match tokio::time::timeout(cfg.timeout, state.h1[slot_index].lock()).await {
                    Ok(slot) => slot,
                    Err(_) => return Err(ExecError::Timeout),
                };
            let remaining = cfg.timeout.saturating_sub(started.elapsed());
            let operation = async {
                if slot.is_some() {
                    state.counters.reused.fetch_add(1, Ordering::Relaxed);
                }
                if slot.is_none() {
                    *slot = Some(new_h1(target, &state.cfg, &state.counters).await?);
                }
                let result = slot
                    .as_mut()
                    .expect("initialized")
                    .send_request(request(cfg, target))
                    .await;
                let response = match result {
                    Ok(r) => r,
                    Err(_) => {
                        *slot = None;
                        return Err(ExecError::Transport);
                    }
                };
                consume_response(cfg, response).await
            };
            match tokio::time::timeout(remaining, operation).await {
                Ok(result) => result,
                Err(_) => {
                    // A cancelled HTTP/1 response cannot safely return its
                    // connection to the pool: unread response bytes would
                    // corrupt the next request. Evict the slot while keeping
                    // the outcome classified as the timeout that caused it.
                    *slot = None;
                    Err(ExecError::Timeout)
                }
            }
        }
        DownstreamMode::H2 => {
            let mut slot = state.h2[target_index].lock().await;
            if slot.is_some() {
                state.counters.reused.fetch_add(1, Ordering::Relaxed);
            }
            if slot.is_none() {
                *slot = Some(new_h2(target, &state.cfg, &state.counters).await?);
            }
            let sender = slot.as_mut().expect("initialized").clone();
            drop(slot);
            let mut sender = sender;
            consume_response(
                cfg,
                sender
                    .send_request(request(cfg, target))
                    .await
                    .map_err(|_| ExecError::Transport)?,
            )
            .await
        }
    }
}

fn success_result(
    scheduled_start: Instant,
    send_start: Instant,
    measured: Measured,
) -> StreamResult {
    StreamResult {
        scheduled_start,
        send_start,
        outcome: Outcome::Success,
        ttft_from_scheduled: measured
            .first_content_at
            .map(|t| t.duration_since(scheduled_start)),
        ttft_from_send: measured
            .first_content_at
            .map(|t| t.duration_since(send_start)),
        total_from_scheduled: measured.end.duration_since(scheduled_start),
        total_from_send: measured.end.duration_since(send_start),
        inter_token_gaps: measured.inter_token_gaps,
        tokens_received: measured.tokens_received,
        bytes_received: measured.bytes_received,
    }
}

fn failed_result(scheduled_start: Instant, send_start: Instant, outcome: Outcome) -> StreamResult {
    let end = Instant::now();
    StreamResult {
        scheduled_start,
        send_start,
        outcome,
        ttft_from_scheduled: None,
        ttft_from_send: None,
        total_from_scheduled: end.duration_since(scheduled_start),
        total_from_send: end.duration_since(send_start),
        inter_token_gaps: Vec::new(),
        tokens_received: 0,
        bytes_received: 0,
    }
}

/// Run one stream end to end (connect through last byte, or error/timeout)
/// and turn the outcome into a [`StreamResult`]. `scheduled_start` is the
/// coordinated-omission baseline (see `metrics.rs`); `send_start` is
/// recorded here, right as the connection attempt begins.
async fn run_one_stream(
    cfg: &RunConfig,
    state: &ClientState,
    target_index: usize,
    target: &Target,
    scheduled_start: Instant,
) -> StreamResult {
    let send_start = Instant::now();
    let execution = execute(cfg, state, target_index, target);
    let outcome = if state.cfg.mode == DownstreamMode::H1Pool {
        Ok(execution.await)
    } else {
        tokio::time::timeout(cfg.timeout, execution).await
    };
    match outcome {
        Ok(Ok(measured)) => success_result(scheduled_start, send_start, measured),
        Ok(Err(ExecError::Http(status))) => {
            failed_result(scheduled_start, send_start, Outcome::HttpError(status))
        }
        Ok(Err(ExecError::Transport)) => {
            failed_result(scheduled_start, send_start, Outcome::TransportError)
        }
        Ok(Err(ExecError::Timeout)) => failed_result(scheduled_start, send_start, Outcome::Timeout),
        Ok(Err(ExecError::Truncated)) => {
            failed_result(scheduled_start, send_start, Outcome::Truncated)
        }
        Err(_elapsed) => failed_result(scheduled_start, send_start, Outcome::Timeout),
    }
}

/// Closed-loop (`--concurrency N`) result: just the aggregated stats, since
/// there is no schedule to fall behind on -- workers replace a finished
/// stream immediately, by construction.
pub async fn run_closed_loop(
    cfg: Arc<RunConfig>,
    concurrency: usize,
    duration: Duration,
    warmup: Duration,
) -> RunSummary {
    let run_start = Instant::now();
    let deadline = run_start + duration;
    let warmup_end = run_start + warmup;
    let target_idx = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(ClientState::new(cfg.transport.clone(), cfg.targets.len()));
    let (tx, rx) = mpsc::unbounded_channel::<StreamResult>();

    let mut workers = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let cfg = cfg.clone();
        let target_idx = target_idx.clone();
        let tx = tx.clone();
        let state = state.clone();
        workers.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let (target_index, target) = pick_target(&cfg, &target_idx);
                let scheduled_start = Instant::now();
                let result =
                    run_one_stream(&cfg, &state, target_index, target, scheduled_start).await;
                if tx.send(result).is_err() {
                    break;
                }
            }
        }));
    }
    // Rust note: dropping our own `tx` (the workers hold their own clones)
    // is what lets the collector's `rx.recv()` loop end -- an mpsc channel
    // closes once every `Sender` clone is gone.
    drop(tx);

    let collector = spawn_collector(rx, warmup_end, state.counters.clone());
    for worker in workers {
        let _ = worker.await;
    }
    collector.await.expect("collector task panicked")
}

/// Open-loop (`--rate R`) run stats, including the honesty guards required
/// by the design: requested vs. achieved rate, and how far the driver fell
/// behind its own schedule.
#[derive(Debug, Serialize)]
pub struct OpenLoopStats {
    pub requested_rate: f64,
    pub achieved_rate: f64,
    pub requested_count: u64,
    /// 99th-percentile delay between a request's schedule slot and its
    /// actual dispatch. Unlike the maximum, this distinguishes sustained
    /// scheduler pressure from one OS wake-up outlier.
    pub p99_backlog_ms: f64,
    /// Longest observed gap between a stream's scheduled slot and when it
    /// actually got sent. This stays visible for diagnosis but a single
    /// outlier does not by itself declare the entire run saturated.
    pub max_backlog_ms: f64,
    /// `true` when the driver misses at least 1% of requested dispatch
    /// throughput or its p99 backlog exceeds the larger of five schedule
    /// intervals and 50ms. The fixed floor accommodates normal VM scheduler
    /// jitter while the loadgen, mock upstreams, and target share a host.
    pub driver_saturated: bool,
}

pub async fn run_open_loop(
    cfg: Arc<RunConfig>,
    rate: f64,
    duration: Duration,
    warmup: Duration,
) -> (RunSummary, OpenLoopStats) {
    let run_start = Instant::now();
    let warmup_end = run_start + warmup;
    let interval = Duration::from_secs_f64(1.0 / rate);
    let total_requests = (rate * duration.as_secs_f64()).round().max(0.0) as u64;
    let target_idx = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(ClientState::new(cfg.transport.clone(), cfg.targets.len()));
    let (tx, rx) = mpsc::unbounded_channel::<StreamResult>();

    // Pace from one scheduler instead of registering one sleeping Tokio task
    // per request up front. At 5k RPS the old shape created 15,000 timers
    // before the three-second run had settled, and timer registration itself
    // delayed the tasks whose deadlines had already arrived.
    let mut requests = JoinSet::new();
    for i in 0..total_requests {
        let scheduled_start = run_start + Duration::from_secs_f64(i as f64 / rate);
        tokio::time::sleep_until(tokio::time::Instant::from_std(scheduled_start)).await;
        let cfg = cfg.clone();
        let target_idx = target_idx.clone();
        let tx = tx.clone();
        let state = state.clone();
        requests.spawn(async move {
            let (target_index, target) = pick_target(&cfg, &target_idx);
            let result = run_one_stream(&cfg, &state, target_index, target, scheduled_start).await;
            let _ = tx.send(result);
        });

        // Reap completed requests while scheduling so the join set contains
        // roughly the in-flight population, not every request in the run.
        while requests.try_join_next().is_some() {}
    }
    drop(tx);

    let collector = spawn_collector_with_backlog(rx, warmup_end, state.counters.clone());
    while requests.join_next().await.is_some() {}
    let (summary, p99_backlog, max_backlog, last_send_start) =
        collector.await.expect("collector task panicked");

    // Request completion tails are target latency, not load-driver
    // throughput. Measure through the final actual dispatch and add one
    // nominal interval so a perfectly paced N-request run reports its
    // configured rate rather than N/(duration - one interval).
    let elapsed = last_send_start
        .map(|last| last.saturating_duration_since(run_start) + interval)
        .unwrap_or_default()
        .as_secs_f64();
    let achieved_rate = if elapsed > 0.0 {
        summary.streams_started as f64 / elapsed
    } else {
        0.0
    };
    let driver_saturated = is_driver_saturated(rate, achieved_rate, interval, p99_backlog);
    let stats = OpenLoopStats {
        requested_rate: rate,
        achieved_rate,
        requested_count: total_requests,
        p99_backlog_ms: p99_backlog.as_secs_f64() * 1000.0,
        max_backlog_ms: max_backlog.as_secs_f64() * 1000.0,
        driver_saturated,
    };
    (summary, stats)
}

fn is_driver_saturated(
    requested_rate: f64,
    achieved_rate: f64,
    interval: Duration,
    p99_backlog: Duration,
) -> bool {
    let backlog_budget = (interval * 5).max(Duration::from_millis(50));
    achieved_rate < requested_rate * 0.99 || p99_backlog > backlog_budget
}

fn spawn_collector(
    mut rx: mpsc::UnboundedReceiver<StreamResult>,
    warmup_end: Instant,
    counters: Arc<TransportCounters>,
) -> tokio::task::JoinHandle<RunSummary> {
    tokio::spawn(async move {
        let mut aggregator = Aggregator::new(warmup_end);
        while let Some(result) = rx.recv().await {
            aggregator.record(result);
        }
        aggregator.set_transport(counters.snapshot());
        aggregator.finish()
    })
}

fn spawn_collector_with_backlog(
    mut rx: mpsc::UnboundedReceiver<StreamResult>,
    warmup_end: Instant,
    counters: Arc<TransportCounters>,
) -> tokio::task::JoinHandle<(RunSummary, Duration, Duration, Option<Instant>)> {
    tokio::spawn(async move {
        let mut aggregator = Aggregator::new(warmup_end);
        let mut backlogs = Vec::new();
        let mut max_backlog = Duration::ZERO;
        let mut last_send_start = None;
        while let Some(result) = rx.recv().await {
            let backlog = result
                .send_start
                .saturating_duration_since(result.scheduled_start);
            backlogs.push(backlog);
            max_backlog = max_backlog.max(backlog);
            last_send_start = Some(last_send_start.map_or(result.send_start, |last: Instant| {
                last.max(result.send_start)
            }));
            aggregator.record(result);
        }
        backlogs.sort_unstable();
        let p99_backlog = if backlogs.is_empty() {
            Duration::ZERO
        } else {
            let index = backlogs
                .len()
                .saturating_mul(99)
                .div_ceil(100)
                .saturating_sub(1);
            backlogs[index]
        };
        aggregator.set_transport(counters.snapshot());
        (
            aggregator.finish(),
            p99_backlog,
            max_backlog,
            last_send_start,
        )
    })
}

/// Small helper so `main.rs` can time an arbitrary future (used for the
/// direct-vs-proxy A/B, which runs sequentially -- see crate doc).
pub async fn timed<F, T>(fut: F) -> (T, Duration)
where
    F: Future<Output = T>,
{
    let start = Instant::now();
    let out = fut.await;
    (out, start.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_loop_saturation_requires_sustained_dispatch_pressure() {
        let interval = Duration::from_micros(200);

        assert!(!is_driver_saturated(
            5_000.0,
            4_999.0,
            interval,
            Duration::from_millis(19),
        ));
        assert!(is_driver_saturated(
            5_000.0,
            4_900.0,
            interval,
            Duration::from_millis(19),
        ));
        assert!(is_driver_saturated(
            5_000.0,
            5_000.0,
            interval,
            Duration::from_millis(51),
        ));
    }
}
