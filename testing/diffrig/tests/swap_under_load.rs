//! The v0.2.0 ship-gate clause this closes: "a config swap under live
//! traffic with zero dropped streams." `internal-docs/MILESTONES.md` names WP-26's
//! traffic-replay topology as a prerequisite -- it is not one. Three pieces
//! that already exist compose into exactly this scenario:
//!
//! - `diffrig::upstreams::OpenAiUpstream` -- a mock upstream with real SSE
//!   pacing (`ttft` + `inter_token_delay`), reused directly here for both the
//!   pre-swap and post-swap providers.
//! - `diffrig::harness::{resolve_llm_proxy_bin, free_port, ScratchDir}` --
//!   binary resolution and scratch-file plumbing, reused directly.
//! - `loadgen::driver::run_open_loop` -- the open-loop, coordinated-omission
//!   -aware driver, reused for the *non-streaming* half of the traffic mix
//!   (see "what is NOT reused, and why" below for the streaming half).
//! - `crates/proxy/tests/reload.rs`'s pattern (spawn with piped stderr, poll
//!   for a log line, `kill -HUP`) -- not literally shared code (it lives in
//!   a different crate, and `diffrig::harness::ProxyProcess` redirects
//!   stdout/stderr to a *file*, not something pollable line-by-line, and has
//!   no signal-sending API), but reproduced here at the same small scope
//!   `harness.rs`'s own module doc says every `tests/*.rs` file already pays
//!   ("each file under `testing/diffrig/tests/` is its own separate
//!   compilation unit"). Adding a `sighup()`/pid-exposing method to the
//!   shared `ProxyProcess` for one test file felt like scope creep, so this
//!   is a third, independent instance of that small amount of glue rather
//!   than a change to shared harness code.
//!
//! ## What is NOT reused, and why
//!
//! The long-lived SSE streams are driven by hand-rolled code in this file,
//! not `loadgen::driver::run_open_loop`, despite the brief calling that
//! driver out as reusable. `loadgen::driver::execute` classifies a stream as
//! `Outcome::Success` once its HTTP body ends without a transport-level
//! error -- it never inspects the *content* of the last SSE frame, so a
//! stream truncated by a clean-looking connection close (the proxy or an
//! upstream ending the response early but still terminating the chunked
//! encoding properly) would read as a success. That is exactly the failure
//! mode this task's brief calls "the assertion that actually matters," so it
//! cannot be answered by layering onto a driver that cannot see it. The
//! non-streaming background traffic has no such gap -- a non-streaming
//! request either comes back 2xx with a full body or it doesn't, which is
//! precisely what `RunSummary` already reports -- so that half *is* driven
//! through `run_open_loop` unmodified.
//!
//! ## The scenario
//!
//! Config A points a single `STATIC` cluster ("backend") at mock upstream 1.
//! While a pool of long-lived SSE streams and a stream of short
//! non-streaming requests are continuously in flight, config B (same
//! listener address, same cluster name, different endpoint -- pointed at
//! mock upstream 2) is written and delivered via `SIGHUP`. Traffic keeps
//! running for a while after the reload succeeds, then everything is
//! drained and every outcome is checked.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::net::TcpStream;

use diffrig::harness::{free_port, resolve_llm_proxy_bin, ScratchDir};
use diffrig::upstreams::{OpenAiConfig, OpenAiUpstream};
use loadgen::dialect::Endpoint;
use loadgen::driver::{run_open_loop, RunConfig, Target};

// --------------------------------------------------------------- tuning ----
//
// Every timing constant below is a liveness backstop or a "definitely still
// running" margin, never a tight race -- see the module doc on the honesty
// requirement against timing flakiness.

/// Per-stream SSE pacing: `TTFT + INTER_TOKEN_DELAY * (tokens - 1)` is the
/// wall-clock length of one stream. With 16 tokens this is ~30ms + 15*90ms =
/// ~1.38s -- long enough that `PRE_SWAP_WARMUP` (well under one stream's
/// length) reliably still finds every streaming worker mid-stream.
const TTFT: Duration = Duration::from_millis(30);
const INTER_TOKEN_DELAY: Duration = Duration::from_millis(90);
const RESPONSE_TEXT: &str = "one two three four five six seven eight nine ten eleven twelve \
                              thirteen fourteen fifteen sixteen";

/// How many long-lived SSE streams run concurrently. Each worker holds
/// exactly one stream in flight at a time (it starts the next only after the
/// previous finishes), so at any instant before `POST_SWAP_HOLD` starts,
/// up to this many streams are open.
const STREAM_CONCURRENCY: usize = 6;

/// How long to let traffic run before triggering the swap -- well under one
/// stream's ~1.38s length, so every streaming worker's first iteration is
/// still in flight when it's sampled.
const PRE_SWAP_WARMUP: Duration = Duration::from_millis(700);
/// How long to keep traffic running after the reload succeeds, so both
/// "already in flight when the swap happened" and "started fresh after it"
/// streams get exercised.
const POST_SWAP_HOLD: Duration = Duration::from_millis(1800);
/// Total span the background non-streaming (`loadgen`) traffic runs for --
/// comfortably longer than `PRE_SWAP_WARMUP` + a generous reload allowance +
/// `POST_SWAP_HOLD`, so it is still running (or has just finished) by the
/// time the streaming half is torn down.
const NONSTREAM_RUN: Duration = Duration::from_secs(5);
const NONSTREAM_RATE_HZ: f64 = 10.0;

const RELOAD_TIMEOUT: Duration = Duration::from_secs(10);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);

// ------------------------------------------------------------------ mocks --

fn upstream_config(label: &str) -> OpenAiConfig {
    OpenAiConfig {
        model: "swap-test-model".to_string(),
        response_text: format!("{label} {RESPONSE_TEXT}"),
        ttft: TTFT,
        inter_token_delay: INTER_TOKEN_DELAY,
        require_api_key: None,
        forced_error: None,
        cached_tokens: 0,
    }
}

// ----------------------------------------------------------------- config --

/// One `STATIC` cluster ("backend") behind an `http_connection_manager` +
/// router, matching prefix "/" -- so no dialect-specific routing header is
/// needed and `loadgen`'s plain client headers are enough. Same shape as
/// `crates/proxy/tests/stats_e2e.rs`'s config, generalized to take the
/// upstream address as a parameter so config A/B differ only in that.
fn envoy_config(listener_port: u16, upstream: SocketAddr) -> String {
    format!(
        r#"
static_resources:
  listeners:
    - name: ingress_http
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend_vhost
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: backend
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: backend
      type: STATIC
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {upstream_ip}, port_value: {upstream_port} }}
"#,
        upstream_ip = upstream.ip(),
        upstream_port = upstream.port(),
    )
}

// ------------------------------------------------- process + SIGHUP glue ---
//
// A third, small instance of `crates/proxy/tests/reload.rs`'s pattern -- see
// the module doc for why this isn't a change to `diffrig::harness`.

fn wait_for_connectable(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if std::net::TcpStream::connect(addr).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn spawn_line_reader(
    mut reader: BufReader<impl std::io::Read + Send + 'static>,
) -> Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line.clone()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

/// Strips `ESC '[' ... 'm'` ANSI SGR sequences -- see
/// `crates/proxy/tests/reload.rs`'s identical helper for why this is needed
/// (`tracing_subscriber`'s default formatter colorizes even a piped stderr).
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            let mut consumed = false;
            let rest: String = chars.clone().collect();
            if let Some(stripped) = rest.strip_prefix('[') {
                if let Some(end) = stripped.find('m') {
                    for _ in 0..=end + 1 {
                        chars.next();
                    }
                    consumed = true;
                }
            }
            if !consumed {
                out.push(c);
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn drain_into(rx: &Receiver<String>, into: &mut Vec<String>) {
    while let Ok(line) = rx.try_recv() {
        into.push(line);
    }
}

fn wait_for_log_line(
    rx: &Receiver<String>,
    log: &mut Vec<String>,
    needle: &str,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        drain_into(rx, log);
        if log.iter().any(|line| strip_ansi(line).contains(needle)) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn send_sighup(child: &Child) {
    let pid = child.id().to_string();
    let status = Command::new("kill")
        .args(["-HUP", &pid])
        .status()
        .expect("failed to send SIGHUP");
    assert!(status.success(), "kill -HUP failed");
}

fn terminate_and_wait(child: &mut Child) {
    let pid = child.id().to_string();
    let _ = Command::new("kill").args(["-TERM", &pid]).status();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

struct ProxyHandle {
    child: Child,
    log: Vec<String>,
    rx: Receiver<String>,
    config_path: PathBuf,
}

impl ProxyHandle {
    fn spawn(bin: &std::path::Path, config_path: PathBuf, ready_addr: SocketAddr) -> Self {
        let mut child = Command::new(bin)
            .args(["-c", config_path.to_str().unwrap()])
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn llm-proxy");
        let stderr = child.stderr.take().expect("child stderr not piped");
        let rx = spawn_line_reader(BufReader::new(stderr));
        let mut log = Vec::new();
        let ready = wait_for_connectable(ready_addr, STARTUP_TIMEOUT);
        drain_into(&rx, &mut log);
        assert!(
            ready,
            "llm-proxy's listener at {ready_addr} never came up; stderr so far: {log:?}"
        );
        ProxyHandle {
            child,
            log,
            rx,
            config_path,
        }
    }

    fn rewrite_config(&self, contents: &str) {
        std::fs::write(&self.config_path, contents).expect("failed to rewrite config");
    }

    fn sighup(&self) {
        send_sighup(&self.child);
    }

    fn wait_for_log(&mut self, needle: &str, timeout: Duration) -> bool {
        wait_for_log_line(&self.rx, &mut self.log, needle, timeout)
    }

    fn finish(mut self) {
        terminate_and_wait(&mut self.child);
    }
}

// --------------------------------------------------- streaming SSE client --
//
// Hand-rolled (see module doc for why this isn't `loadgen::driver`):
// fallible (a transport error becomes an `Err`, not a panic, so one bad
// stream doesn't take down every other concurrently running task) and
// content-aware (it looks at the *last* SSE frame, not just whether the
// body ended cleanly).

#[derive(Debug)]
enum StreamOutcome {
    /// The body ended with no transport error. `clean` is whether the very
    /// last frame was the OpenAI chat-completions terminator
    /// (`data: [DONE]`) -- a truncated stream (proxy or upstream cutting the
    /// response short but still closing the connection "properly") shows up
    /// here as `clean: false`, not as an error.
    Completed {
        clean: bool,
        event_count: u64,
        last_event: Option<String>,
    },
    /// A non-2xx status. Read to completion anyway so `last_event` (if any)
    /// is still useful for diagnosis.
    HttpError { status: u16 },
}

async fn try_send_streaming_chat(
    addr: SocketAddr,
    body: &serde_json::Value,
) -> Result<StreamOutcome, String> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake(io)
        .await
        .map_err(|e| format!("http1 handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .body(Full::new(Bytes::from(body.to_string())))
        .map_err(|e| format!("build request: {e}"))?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("send_request: {e}"))?;
    let status = response.status().as_u16();
    let mut body_stream = response.into_body();

    let mut pending = String::new();
    let mut last_event: Option<String> = None;
    let mut event_count = 0u64;
    loop {
        let frame = match body_stream.frame().await {
            Some(Ok(frame)) => frame,
            Some(Err(e)) => {
                return Err(format!(
                    "frame read error mid-stream (status {status}, {event_count} events \
                     already seen): {e}"
                ))
            }
            None => break,
        };
        if let Some(data) = frame.data_ref() {
            pending.push_str(&String::from_utf8_lossy(data));
            while let Some(pos) = pending.find("\n\n") {
                let event = pending[..pos].to_string();
                pending = pending.split_off(pos + 2);
                event_count += 1;
                last_event = Some(event);
            }
        }
    }

    if status != 200 {
        return Ok(StreamOutcome::HttpError { status });
    }
    let clean = last_event.as_deref().map(str::trim) == Some("data: [DONE]");
    Ok(StreamOutcome::Completed {
        clean,
        event_count,
        last_event,
    })
}

/// One streaming worker: loops issuing fresh streams (fresh TCP connection
/// each time, matching this proxy's connect-per-stream upstream behavior)
/// until `stop` is set. `stop` is only checked *between* streams, so a
/// stream already in flight when `stop` flips always runs to completion --
/// which is exactly the property under test.
async fn stream_worker(
    addr: SocketAddr,
    body: serde_json::Value,
    stop: Arc<AtomicBool>,
    in_flight: Arc<AtomicUsize>,
    tx: tokio::sync::mpsc::UnboundedSender<Result<StreamOutcome, String>>,
) {
    while !stop.load(Ordering::Relaxed) {
        in_flight.fetch_add(1, Ordering::SeqCst);
        let outcome = try_send_streaming_chat(addr, &body).await;
        in_flight.fetch_sub(1, Ordering::SeqCst);
        if tx.send(outcome).is_err() {
            break;
        }
    }
}

// -------------------------------------------------------------------- test --

/// The v0.2.0 ship-gate acceptance test: see the module doc for the full
/// scenario. Not `#[ignore]`d -- total wall time is ~6-8s (dominated by
/// `NONSTREAM_RUN`'s fixed 5s span), in the same range as this crate's other
/// e2e suites, and it needs no network beyond loopback.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_swap_under_live_traffic_drops_no_streams() {
    let upstream_1 = OpenAiUpstream::spawn(upstream_config("upstream-1"))
        .await
        .expect("spawn mock upstream 1");
    let upstream_2 = OpenAiUpstream::spawn(upstream_config("upstream-2"))
        .await
        .expect("spawn mock upstream 2");

    let scratch = ScratchDir::new("swap-under-load");
    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_path = scratch.write(
        "bootstrap.yaml",
        &envoy_config(listener_port, upstream_1.addr()),
    );

    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyHandle::spawn(&bin, config_path, listener_addr);

    // ---- start sustained concurrent traffic --------------------------------

    let stop = Arc::new(AtomicBool::new(false));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Result<StreamOutcome, String>>();

    let stream_body = json!({
        "model": "swap-test-model",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });
    let mut stream_workers = Vec::with_capacity(STREAM_CONCURRENCY);
    for _ in 0..STREAM_CONCURRENCY {
        stream_workers.push(tokio::spawn(stream_worker(
            listener_addr,
            stream_body.clone(),
            stop.clone(),
            in_flight.clone(),
            tx.clone(),
        )));
    }
    // Rust note: dropping this file's own `tx` (each worker holds its own
    // clone) is what lets the collector below see the channel close once
    // every worker has exited -- same pattern as `loadgen::driver`'s
    // collector.
    drop(tx);
    let stream_results_handle = tokio::spawn(async move {
        let mut results = Vec::new();
        let mut rx = rx;
        while let Some(result) = rx.recv().await {
            results.push(result);
        }
        results
    });

    let nonstream_cfg = Arc::new(RunConfig {
        targets: vec![Target {
            host: "127.0.0.1".to_string(),
            port: listener_port,
        }],
        endpoint: Endpoint::Chat,
        model: "swap-test-model".to_string(),
        prompt: "hi".to_string(),
        max_tokens: 16,
        api_key: None,
        stream: false,
        timeout: Duration::from_secs(5),
    });
    let nonstream_handle = tokio::spawn(run_open_loop(
        nonstream_cfg,
        NONSTREAM_RATE_HZ,
        NONSTREAM_RUN,
        Duration::ZERO,
    ));

    // ---- warm up, then sample "in flight" right before the swap ------------

    tokio::time::sleep(PRE_SWAP_WARMUP).await;
    let in_flight_at_swap = in_flight.load(Ordering::SeqCst);
    eprintln!("swap_under_load: streams in flight at the moment of the swap = {in_flight_at_swap}");
    assert!(
        in_flight_at_swap > 0,
        "no streams were in flight when the swap happened -- this test proved nothing; \
         widen PRE_SWAP_WARMUP relative to the per-stream duration"
    );

    // ---- config B: same listener address, cluster repointed at upstream 2 --

    proxy.rewrite_config(&envoy_config(listener_port, upstream_2.addr()));
    proxy.sighup();
    let reloaded = proxy.wait_for_log("SIGHUP: config reload succeeded", RELOAD_TIMEOUT);
    assert!(
        reloaded,
        "expected a successful-reload log line within {RELOAD_TIMEOUT:?}; stderr so far: {:?}",
        proxy.log
    );

    // ---- keep traffic running a while after the swap, then drain -----------

    tokio::time::sleep(POST_SWAP_HOLD).await;
    stop.store(true, Ordering::Relaxed);
    for worker in stream_workers {
        worker.await.expect("stream worker task panicked");
    }
    let stream_results = stream_results_handle
        .await
        .expect("stream result collector panicked");
    let (nonstream_summary, nonstream_stats) =
        nonstream_handle.await.expect("nonstream driver panicked");

    proxy.finish();

    // ---- assertions ----------------------------------------------------

    // 1. No connection errors, no non-2xx, for the non-streaming half.
    assert_eq!(
        nonstream_summary.transport_errors, 0,
        "non-streaming traffic saw transport errors: {:?}",
        nonstream_summary
    );
    assert_eq!(
        nonstream_summary.timeouts, 0,
        "non-streaming traffic saw timeouts: {:?}",
        nonstream_summary
    );
    assert!(
        nonstream_summary.http_errors.is_empty(),
        "non-streaming traffic saw non-2xx responses: {:?}",
        nonstream_summary.http_errors
    );
    assert!(
        nonstream_summary.streams_counted > 0,
        "the non-streaming background traffic never actually ran -- \
         requested_count={}, achieved_rate={}",
        nonstream_stats.requested_count,
        nonstream_stats.achieved_rate
    );

    // 2. Every SSE stream: no transport error, and terminated cleanly (the
    // terminal `[DONE]` frame, not merely an unclean-but-error-free EOF).
    let mut stream_total = 0u64;
    let mut stream_transport_errors = Vec::new();
    let mut stream_http_errors = Vec::new();
    let mut stream_truncated = Vec::new();
    for result in &stream_results {
        stream_total += 1;
        match result {
            Ok(StreamOutcome::Completed { clean: true, .. }) => {}
            Ok(StreamOutcome::Completed {
                clean: false,
                event_count,
                last_event,
            }) => {
                stream_truncated.push(format!("{event_count} events, last event: {last_event:?}"))
            }
            Ok(StreamOutcome::HttpError { status }) => stream_http_errors.push(*status),
            Err(message) => stream_transport_errors.push(message.clone()),
        }
    }
    assert!(
        stream_total > 0,
        "no streams ran at all -- this test proved nothing"
    );
    assert!(
        stream_transport_errors.is_empty(),
        "{} of {stream_total} streams hit a transport-level error (a dropped stream): {:#?}",
        stream_transport_errors.len(),
        stream_transport_errors
    );
    assert!(
        stream_http_errors.is_empty(),
        "{} of {stream_total} streams got a non-2xx status: {:?}",
        stream_http_errors.len(),
        stream_http_errors
    );
    assert!(
        stream_truncated.is_empty(),
        "{} of {stream_total} streams ended without the terminal `[DONE]` frame (a silent \
         truncation -- the exact failure mode this test exists to catch): {:#?}",
        stream_truncated.len(),
        stream_truncated
    );

    // 3. The swap actually took effect: upstream 2 must have served real
    // traffic, and (sanity) upstream 1 must have served some too, or the
    // "in flight at swap" number above would be meaningless.
    let upstream_1_requests = upstream_1.log.requests().len();
    let upstream_2_requests = upstream_2.log.requests().len();
    eprintln!(
        "swap_under_load: upstream_1 served {upstream_1_requests} requests, \
         upstream_2 served {upstream_2_requests} requests, \
         {stream_total} streams total, \
         {} non-streaming requests total",
        nonstream_summary.streams_counted
    );
    assert!(
        upstream_1_requests > 0,
        "upstream 1 (pre-swap) served no requests at all -- the pre-swap phase never ran traffic"
    );
    assert!(
        upstream_2_requests > 0,
        "upstream 2 (post-swap) served no requests -- the reload did not actually take effect \
         (a reload that silently did nothing would otherwise pass every assertion above)"
    );

    upstream_1.shutdown().await;
    upstream_2.shutdown().await;
    drop(scratch);
}
