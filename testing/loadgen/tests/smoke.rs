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

async fn spawn_server() -> std::net::SocketAddr {
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
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(handle))
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

#[tokio::test]
async fn open_loop_paces_without_counting_response_drain_as_dispatch_time() {
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
    });

    let (summary, stats) =
        driver::run_open_loop(cfg, 100.0, Duration::from_millis(500), Duration::ZERO).await;

    assert_eq!(stats.requested_count, 50);
    assert_eq!(summary.streams_started, stats.requested_count);
    assert_eq!(summary.error_rate, 0.0, "expected no errors: {summary:?}");
    assert!(!stats.driver_saturated, "driver saturated: {stats:?}");
    assert!(
        stats.achieved_rate >= 90.0,
        "response drain was counted as dispatch time: {stats:?}"
    );
}
