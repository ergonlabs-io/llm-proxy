//! A truncated SSE stream must count as a failure. A local Hyper server tests
//! terminal-frame handling for OpenAI and Anthropic without external services.

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
use loadgen::metrics::RunSummary;
use tokio::net::TcpListener;

/// Three OpenAI-chat-completions content chunks, no `[DONE]` -- the body
/// closes right after the last content chunk, exactly what a mid-stream
/// truncation by the proxy looks like on the wire.
const OPENAI_TRUNCATED: &str = concat!(
    "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n",
    "data: {\"choices\":[{\"delta\":{\"content\":\"lo \"}}]}\n\n",
    "data: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\n",
);

/// The same three chunks, this time properly terminated.
const OPENAI_COMPLETE: &str = concat!(
    "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n",
    "data: {\"choices\":[{\"delta\":{\"content\":\"lo \"}}]}\n\n",
    "data: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\n",
    "data: [DONE]\n\n",
);

/// Anthropic content deltas without the required `message_stop` terminal frame.
const ANTHROPIC_TRUNCATED: &str = concat!(
    "event: message_start\ndata: {}\n\n",
    "event: content_block_start\ndata: {}\n\n",
    "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
    "event: content_block_stop\ndata: {}\n\n",
);

const ANTHROPIC_COMPLETE: &str = concat!(
    "event: message_start\ndata: {}\n\n",
    "event: content_block_start\ndata: {}\n\n",
    "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
    "event: content_block_stop\ndata: {}\n\n",
    "event: message_delta\ndata: {}\n\n",
    "event: message_stop\ndata: {}\n\n",
);

/// A non-streaming JSON body -- used to prove `--no-stream` runs never touch
/// any of this at all.
const NON_STREAM_BODY: &str = r#"{"choices":[{"message":{"content":"hi"}}]}"#;

async fn spawn_sse_server(body: &'static str) -> std::net::SocketAddr {
    spawn_server(body, "text/event-stream").await
}

async fn spawn_server(body: &'static str, content_type: &'static str) -> std::net::SocketAddr {
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
                let handler = move |_req: Request<Incoming>| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .header("content-type", content_type)
                            .body(Full::new(Bytes::from_static(body.as_bytes())))
                            .expect("static response is always valid"),
                    )
                };
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(handler))
                    .await;
            });
        }
    });
    addr
}

fn base_cfg(addr: std::net::SocketAddr, endpoint: Endpoint, stream: bool) -> Arc<RunConfig> {
    let targets = driver::parse_targets(&[format!("http://{addr}")]).expect("parse target");
    Arc::new(RunConfig {
        targets,
        endpoint,
        model: "test-model".to_string(),
        prompt: "hi".to_string(),
        max_tokens: 16,
        api_key: None,
        stream,
        timeout: Duration::from_secs(5),
        transport: Default::default(),
    })
}

async fn run_one(cfg: Arc<RunConfig>) -> RunSummary {
    driver::run_closed_loop(cfg, 1, Duration::from_millis(200), Duration::ZERO).await
}

#[tokio::test]
async fn truncated_openai_stream_is_counted_as_truncated_not_success() {
    let addr = spawn_sse_server(OPENAI_TRUNCATED).await;
    let cfg = base_cfg(addr, Endpoint::Chat, true);
    let summary = run_one(cfg).await;

    assert!(summary.streams_counted > 0, "expected at least one stream");
    assert_eq!(
        summary.success, 0,
        "a stream missing its terminal frame must not count as a success"
    );
    assert_eq!(summary.truncated, summary.streams_counted);
    assert_eq!(
        summary.transport_errors, 0,
        "a clean-EOF truncation is not a transport error"
    );
    assert_eq!(summary.error_rate, 1.0);
    // The dropped stream must not leak into the success-only latency
    // histograms.
    assert!(summary.ttft_from_scheduled_us.is_none());
    assert!(summary.total_from_scheduled_us.is_none());
}

#[tokio::test]
async fn complete_openai_stream_reports_zero_truncations() {
    let addr = spawn_sse_server(OPENAI_COMPLETE).await;
    let cfg = base_cfg(addr, Endpoint::Chat, true);
    let summary = run_one(cfg).await;

    assert!(summary.streams_counted > 0, "expected at least one stream");
    assert_eq!(summary.truncated, 0);
    assert_eq!(summary.success, summary.streams_counted);
    assert_eq!(summary.error_rate, 0.0);
    assert!(summary.ttft_from_scheduled_us.is_some());
}

#[tokio::test]
async fn truncated_anthropic_stream_is_also_caught_generically() {
    // The Anthropic dialect's terminal frame is `message_stop`, not
    // `[DONE]` -- this proves `driver.rs`'s check is generic over
    // `FrameKind::Terminal`, not hardcoded to the OpenAI shape.
    let addr = spawn_sse_server(ANTHROPIC_TRUNCATED).await;
    let cfg = base_cfg(addr, Endpoint::Messages, true);
    let summary = run_one(cfg).await;

    assert!(summary.streams_counted > 0, "expected at least one stream");
    assert_eq!(summary.success, 0);
    assert_eq!(summary.truncated, summary.streams_counted);
    assert_eq!(summary.error_rate, 1.0);
}

#[tokio::test]
async fn complete_anthropic_stream_reports_zero_truncations() {
    let addr = spawn_sse_server(ANTHROPIC_COMPLETE).await;
    let cfg = base_cfg(addr, Endpoint::Messages, true);
    let summary = run_one(cfg).await;

    assert!(summary.streams_counted > 0, "expected at least one stream");
    assert_eq!(summary.truncated, 0);
    assert_eq!(summary.success, summary.streams_counted);
    assert_eq!(summary.error_rate, 0.0);
}

#[tokio::test]
async fn non_streaming_runs_are_unaffected_by_the_terminal_frame_check() {
    // `--no-stream` never enters the SSE loop at all -- the fixed body here
    // isn't even valid SSE, so if the terminal-frame check somehow fired for
    // a non-streaming run, this would be counted as truncated instead of a
    // success.
    let addr = spawn_server(NON_STREAM_BODY, "application/json").await;
    let cfg = base_cfg(addr, Endpoint::Chat, false);
    let summary = run_one(cfg).await;

    assert!(summary.streams_counted > 0, "expected at least one stream");
    assert_eq!(summary.truncated, 0);
    assert_eq!(summary.success, summary.streams_counted);
    assert_eq!(summary.error_rate, 0.0);
    assert!(summary.bytes_received > 0);
}
