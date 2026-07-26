//! The two load modes (closed-loop / open-loop) and the single-stream
//! request/response cycle they both drive.
//!
//! Every stream opens its own fresh TCP connection (connect-per-stream, no
//! pooling/keep-alive reuse) -- see the environment note in the crate's
//! design doc: this is deliberate so the rig's ephemeral-port ceiling is
//! exercised the same way a from-scratch client hitting the proxy would be,
//! and so one stream's connection lifecycle can never affect another's
//! latency measurement.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::dialect::{Endpoint, FrameKind};
use crate::metrics::{Aggregator, Outcome, RunSummary, StreamResult};
use crate::sse::SseParser;

/// One upstream to send requests to. Connect-per-stream means every stream
/// picks a target (round-robin across however many were given) and dials it
/// fresh.
#[derive(Debug, Clone)]
pub struct Target {
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
    if scheme != "http" {
        anyhow::bail!(
            "target {raw:?}: only plain http:// targets are supported \
             (upstream TLS origination in the driver is a later milestone)"
        );
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("target {raw:?} has no host"))?;
    Ok(Target {
        host: authority.host().to_string(),
        port: authority.port_u16().unwrap_or(80),
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
}

fn pick_target<'a>(cfg: &'a RunConfig, idx: &AtomicUsize) -> &'a Target {
    // Rust note: `Relaxed` is enough here -- this counter only needs to hand
    // out distinct-ish indices for round-robin, not to synchronize any other
    // memory access, so the stronger orderings would just cost more for no
    // benefit.
    let i = idx.fetch_add(1, Ordering::Relaxed);
    &cfg.targets[i % cfg.targets.len()]
}

enum ExecError {
    Http(u16),
    Transport,
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
async fn execute(cfg: &RunConfig, target: &Target) -> Result<Measured, ExecError> {
    let stream = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|_| ExecError::Transport)?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake::<_, Full<Bytes>>(io)
        .await
        .map_err(|_| ExecError::Transport)?;
    // Rust note: unlike the proxy's own upstream codec (`proxy-http`'s
    // `send_upstream_http1`), our request body is `Full<Bytes>` (`Send`),
    // so the connection-driving future is `Send` too and can go on the
    // normal multi-threaded `tokio::spawn` -- no `spawn_local`/`LocalSet`
    // needed. Detached (dropped `JoinHandle`): the connection tears down
    // when `sender`/the response body are dropped either way.
    tokio::spawn(conn);

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
    let request = builder
        .body(Full::new(Bytes::from(body_bytes)))
        .expect("method/uri/headers are all valid; building can't fail here");

    let response = sender
        .send_request(request)
        .await
        .map_err(|_| ExecError::Transport)?;
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
                FrameKind::Terminal | FrameKind::Other => {}
            }
        }
    }

    Ok(Measured {
        first_content_at,
        inter_token_gaps: gaps,
        tokens_received,
        bytes_received,
        end: Instant::now(),
    })
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
    target: &Target,
    scheduled_start: Instant,
) -> StreamResult {
    let send_start = Instant::now();
    match tokio::time::timeout(cfg.timeout, execute(cfg, target)).await {
        Ok(Ok(measured)) => success_result(scheduled_start, send_start, measured),
        Ok(Err(ExecError::Http(status))) => {
            failed_result(scheduled_start, send_start, Outcome::HttpError(status))
        }
        Ok(Err(ExecError::Transport)) => {
            failed_result(scheduled_start, send_start, Outcome::TransportError)
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
    let (tx, rx) = mpsc::unbounded_channel::<StreamResult>();

    let mut workers = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let cfg = cfg.clone();
        let target_idx = target_idx.clone();
        let tx = tx.clone();
        workers.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let target = pick_target(&cfg, &target_idx);
                let scheduled_start = Instant::now();
                let result = run_one_stream(&cfg, target, scheduled_start).await;
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

    let collector = spawn_collector(rx, warmup_end);
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
    /// Longest observed gap between a stream's scheduled slot and when it
    /// actually got sent. Large values mean the *loadgen* fell behind its
    /// own schedule -- see `driver_saturated` for the derived verdict.
    pub max_backlog_ms: f64,
    /// `true` once `max_backlog_ms` exceeds a few schedule intervals --
    /// i.e. the driver, not the target, is the bottleneck, and the run's
    /// latency numbers describe the loadgen, not the proxy.
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
    let (tx, rx) = mpsc::unbounded_channel::<StreamResult>();

    let mut handles = Vec::with_capacity(total_requests as usize);
    for i in 0..total_requests {
        let scheduled_start = run_start + Duration::from_secs_f64(i as f64 / rate);
        let cfg = cfg.clone();
        let target_idx = target_idx.clone();
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(scheduled_start)).await;
            let target = pick_target(&cfg, &target_idx);
            let result = run_one_stream(&cfg, target, scheduled_start).await;
            let _ = tx.send(result);
        }));
    }
    drop(tx);

    let collector = spawn_collector_with_backlog(rx, warmup_end);
    for handle in handles {
        let _ = handle.await;
    }
    let (summary, max_backlog) = collector.await.expect("collector task panicked");

    let elapsed = run_start.elapsed().as_secs_f64();
    let achieved_rate = if elapsed > 0.0 {
        summary.streams_started as f64 / elapsed
    } else {
        0.0
    };
    // A backlog of several full schedule intervals means requests are
    // piling up faster than they can even be dispatched -- the driver
    // itself, not the target under test, has become the bottleneck.
    let driver_saturated = max_backlog > interval * 5;
    let stats = OpenLoopStats {
        requested_rate: rate,
        achieved_rate,
        requested_count: total_requests,
        max_backlog_ms: max_backlog.as_secs_f64() * 1000.0,
        driver_saturated,
    };
    (summary, stats)
}

fn spawn_collector(
    mut rx: mpsc::UnboundedReceiver<StreamResult>,
    warmup_end: Instant,
) -> tokio::task::JoinHandle<RunSummary> {
    tokio::spawn(async move {
        let mut aggregator = Aggregator::new(warmup_end);
        while let Some(result) = rx.recv().await {
            aggregator.record(result);
        }
        aggregator.finish()
    })
}

fn spawn_collector_with_backlog(
    mut rx: mpsc::UnboundedReceiver<StreamResult>,
    warmup_end: Instant,
) -> tokio::task::JoinHandle<(RunSummary, Duration)> {
    tokio::spawn(async move {
        let mut aggregator = Aggregator::new(warmup_end);
        let mut max_backlog = Duration::ZERO;
        while let Some(result) = rx.recv().await {
            let backlog = result
                .send_start
                .saturating_duration_since(result.scheduled_start);
            max_backlog = max_backlog.max(backlog);
            aggregator.record(result);
        }
        (aggregator.finish(), max_backlog)
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
