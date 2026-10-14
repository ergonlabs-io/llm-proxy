//! Fast end-to-end smoke test: drive a real closed-loop run against a
//! trivial local hyper server that speaks the OpenAI `/v1/chat/completions`
//! SSE shape, and check the whole pipeline (connect -> request -> SSE parse
//! -> classify -> aggregate) produces sane, error-free results. Kept short
//! (concurrency 2, ~500ms) so it's cheap enough for `make ci`.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use loadgen::dialect::Endpoint;
use loadgen::driver::{self, RunConfig};
use tokio::net::TcpListener;

/// A fixed three-token chat-completion SSE response, all in one write --
/// enough to exercise TTFT/inter-token/terminal-frame handling without
/// needing artificial chunking (the SSE parser's split-frame behavior is
/// already covered by `sse.rs`'s unit tests).
const SSE_BODY: &str = concat!(
    "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n",
    "data: {\"choices\":[{\"delta\":{\"content\":\"lo \"}}]}\n\n",
    "data: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\n",
    "data: [DONE]\n\n",
);

async fn handle(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Full::new(Bytes::from_static(SSE_BODY.as_bytes())))
        .expect("static response is always valid"))
}

/// How long [`handle_held`] holds every response. It is far longer than the
/// open-loop dispatch interval, so counting response time as dispatch time
/// moves the reported elapsed time by much more than any rounding margin.
const RESPONSE_HOLD: Duration = Duration::from_millis(250);

async fn handle_held(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    tokio::time::sleep(RESPONSE_HOLD).await;
    handle(req).await
}

async fn spawn_server() -> std::net::SocketAddr {
    spawn_server_with(false).await
}

async fn spawn_server_with(hold_responses: bool) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req| async move {
                    if hold_responses {
                        handle_held(req).await
                    } else {
                        handle(req).await
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn closed_loop_end_to_end_smoke() {
    let addr = spawn_server().await;
    let targets = driver::parse_targets(&[format!("http://{addr}")]).expect("parse target");
    let cfg = Arc::new(RunConfig {
        targets,
        endpoint: Endpoint::Chat,
        model: "test-model".to_string(),
        prompt: "hi".to_string(),
        max_tokens: 16,
        api_key: None,
        stream: true,
        timeout: Duration::from_secs(5),
        transport: Default::default(),
    });

    let summary = driver::run_closed_loop(cfg, 2, Duration::from_millis(500), Duration::ZERO).await;

    assert!(
        summary.streams_counted > 0,
        "expected at least one completed stream"
    );
    assert_eq!(summary.error_rate, 0.0, "expected no errors: {summary:?}");
    assert_eq!(summary.success, summary.streams_counted);
    assert!(summary.tokens_received >= summary.streams_counted * 3);
    assert!(summary.ttft_from_scheduled_us.is_some());
    assert!(summary.total_from_scheduled_us.is_some());
}

// The run cannot return before its last request, dispatched at
// `last_send`, has been held for `RESPONSE_HOLD`. So with correct pacing the
// reported dispatch window, `last_send - run_start + interval`, is at most
// `run_wall - RESPONSE_HOLD + interval`. Counting the response drain makes it
// roughly `run_wall` instead. Machine load only lengthens `run_wall` and the
// hold, never shortens them, so the bound holds on a loaded box; it asserts
// no wall-clock window (AGENTS.md "Build And Test").
#[tokio::test]
async fn open_loop_paces_without_counting_response_drain_as_dispatch_time() {
    let addr = spawn_server_with(true).await;
    let targets = driver::parse_targets(&[format!("http://{addr}")]).expect("parse target");
    let cfg = Arc::new(RunConfig {
        targets,
        endpoint: Endpoint::Chat,
        model: "test-model".to_string(),
        prompt: "hi".to_string(),
        max_tokens: 16,
        api_key: None,
        stream: true,
        timeout: Duration::from_secs(30),
        transport: Default::default(),
    });
    let rate = 100.0;
    let interval = Duration::from_secs_f64(1.0 / rate);

    let wall_start = std::time::Instant::now();
    let (summary, stats) =
        driver::run_open_loop(cfg, rate, Duration::from_millis(500), Duration::ZERO).await;
    let run_wall = wall_start.elapsed();

    assert_eq!(stats.requested_count, 50);
    assert_eq!(summary.streams_started, stats.requested_count);
    assert_eq!(summary.error_rate, 0.0, "expected no errors: {summary:?}");
    assert!(stats.achieved_rate > 0.0, "no dispatch recorded: {stats:?}");

    let reported_window =
        Duration::from_secs_f64(summary.streams_started as f64 / stats.achieved_rate);
    // 1ms absorbs float rounding in the rate -> window round trip only.
    let bound = (run_wall + interval + Duration::from_millis(1)).saturating_sub(RESPONSE_HOLD);
    assert!(
        reported_window <= bound,
        "response drain was counted as dispatch time: reported window \
         {reported_window:?} exceeds {bound:?} (run took {run_wall:?}, \
         each response held {RESPONSE_HOLD:?}): {stats:?}"
    );
}
