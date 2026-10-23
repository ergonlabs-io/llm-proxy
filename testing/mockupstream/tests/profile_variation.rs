//! Exercises profile selection, terminal frames, and usage counts through a
//! real HTTP round trip over an in-memory pipe (AGENTS.md "Running The Product").

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::sync::Arc;

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use mockupstream::frames::StreamConfig;
use mockupstream::handler::{self, AppState};
use mockupstream::profiles::{Dist, Profile, ProfileSet, DEFAULT_PROFILE};
use serde_json::{json, Value};
use tokio::io::duplex;

/// Runs an HTTP/1.1 server and Hyper client over an in-memory duplex pipe.
async fn spawn_server(state: Arc<AppState>) -> SendRequest<Full<Bytes>> {
    let (client_io, server_io) = duplex(4 * 1024 * 1024);

    tokio::spawn(async move {
        let service = hyper::service::service_fn(move |req| {
            let state = Arc::clone(&state);
            async move { Ok::<_, std::convert::Infallible>(handler::handle(req, state).await) }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(server_io), service)
            .await
            .expect("mock server connection");
    });

    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
        .await
        .expect("client handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

/// Uses built-in profile names with smaller timings so integration coverage stays
/// fast while preserving profile selection and relative stream lengths.
fn test_profiles() -> ProfileSet {
    let mut set = ProfileSet::with_builtins(Profile {
        name: DEFAULT_PROFILE.to_string(),
        ttft_ms: Dist::fixed(0),
        inter_token_ms: Dist::fixed(0),
        length: Dist::fixed(16),
    });
    set.merge_file(
        serde_json::from_value(json!({
            "profiles": {
                "mock-fast-short": {"ttft_ms": {"min": 0, "max": 1}, "inter_token_ms": {"min": 0, "max": 1}, "length": {"min": 3, "max": 5}},
                "mock-medium": {"ttft_ms": {"min": 0, "max": 1}, "inter_token_ms": {"min": 0, "max": 1}, "length": {"min": 8, "max": 12}},
                "mock-slow-long": {"ttft_ms": {"min": 0, "max": 1}, "inter_token_ms": {"min": 0, "max": 1}, "length": {"min": 20, "max": 30}}
            }
        }))
        .unwrap(),
    );
    set
}

fn test_state() -> Arc<AppState> {
    Arc::new(AppState::new(
        StreamConfig { prompt_tokens: 10 },
        test_profiles(),
    ))
}

async fn post(
    sender: &mut SendRequest<Full<Bytes>>,
    path: &str,
    body: Value,
) -> (StatusCode, Bytes) {
    sender.ready().await.expect("connection ready");
    let req = Request::post(path)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
        .unwrap();
    let resp = sender.send_request(req).await.expect("send request");
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    (status, body)
}

/// Split a raw SSE body into its individual `data:`/`event:` frames the
/// same way a real client would -- frames are separated by a blank line.
fn sse_frames(body: &[u8]) -> Vec<String> {
    let text = String::from_utf8(body.to_vec()).expect("utf8 SSE body");
    text.split("\n\n")
        .filter(|f| !f.is_empty())
        .map(|f| f.to_string())
        .collect()
}

// --------------------------------------------------- profile selection ---

/// Acceptance: a request selecting `mock-fast-short` yields a shorter
/// stream than `mock-slow-long`. Deterministic despite the randomness --
/// `test_profiles`' length ranges for the two never overlap (3-5 vs.
/// 20-30), so *any* draw from each is correctly ordered. The real built-in
/// ranges (50-150 vs. 1000-2000, see `profiles.rs`) preserve the same
/// non-overlapping property; only the test-scale magnitude differs, for the
/// reason `test_profiles`' doc gives.
#[tokio::test]
async fn fast_short_profile_yields_shorter_stream_than_slow_long() {
    let state = test_state();
    let mut sender = spawn_server(state).await;

    let (status_a, body_a) = post(
        &mut sender,
        "/v1/chat/completions",
        json!({"model": "mock-fast-short", "stream": true}),
    )
    .await;
    assert_eq!(status_a, StatusCode::OK);
    let (status_b, body_b) = post(
        &mut sender,
        "/v1/chat/completions",
        json!({"model": "mock-slow-long", "stream": true}),
    )
    .await;
    assert_eq!(status_b, StatusCode::OK);

    let frames_a = sse_frames(&body_a);
    let frames_b = sse_frames(&body_b);
    assert!(
        frames_a.len() < frames_b.len(),
        "fast-short ({}) should yield fewer frames than slow-long ({})",
        frames_a.len(),
        frames_b.len()
    );
}

/// Acceptance: an unknown model falls back to the default profile rather
/// than erroring, and gets that profile's (here, fixed) shape.
#[tokio::test]
async fn unknown_model_falls_back_to_default_profile() {
    let state = test_state();
    let mut sender = spawn_server(state).await;

    let (status, body) = post(
        &mut sender,
        "/v1/chat/completions",
        json!({"model": "some-model-nobody-configured", "stream": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let frames = sse_frames(&body);
    // role-delta + 16 (test_profiles' fixed default length) content-delta
    // + usage + [DONE]
    assert_eq!(frames.len(), 19);
    assert!(frames.last().unwrap().contains("[DONE]"));
}

// ------------------------------------------------ terminal frame + usage --

/// Acceptance: every streamed OpenAI response ends with `[DONE]` and a
/// usage chunk whose `completion_tokens` equals the number of content
/// chunks actually sent -- across several different drawn lengths (not
/// just whatever the default profile happens to draw).
#[tokio::test]
async fn openai_stream_always_ends_correctly_with_matching_usage() {
    let state = test_state();
    let mut sender = spawn_server(state).await;

    for model in ["mock-fast-short", "mock-medium", "mock-slow-long"] {
        let (status, body) = post(
            &mut sender,
            "/v1/chat/completions",
            json!({"model": model, "stream": true}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "model={model}");
        let frames = sse_frames(&body);
        assert!(frames.last().unwrap().contains("[DONE]"), "model={model}");

        let usage_frame = &frames[frames.len() - 2];
        let usage_json: Value =
            serde_json::from_str(usage_frame.trim_start_matches("data: ")).unwrap();
        let reported_k = usage_json["usage"]["completion_tokens"].as_u64().unwrap();

        // role-delta (1) + k content-delta + usage (1) + [DONE] (1)
        let actual_k = frames.len() as u64 - 3;
        assert_eq!(reported_k, actual_k, "model={model} frames={frames:?}");
    }
}

/// Same property for Anthropic: `message_stop` terminal frame, and
/// `message_delta`'s `output_tokens` matching the actual chunk count.
#[tokio::test]
async fn anthropic_stream_always_ends_correctly_with_matching_usage() {
    let state = test_state();
    let mut sender = spawn_server(state).await;

    for model in ["mock-fast-short", "mock-medium", "mock-slow-long"] {
        let (status, body) = post(
            &mut sender,
            "/v1/messages",
            json!({"model": model, "stream": true}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "model={model}");
        let frames = sse_frames(&body);
        assert!(
            frames.last().unwrap().starts_with("event: message_stop"),
            "model={model}"
        );

        let message_delta = &frames[frames.len() - 2];
        assert!(
            message_delta.starts_with("event: message_delta"),
            "model={model}"
        );
        let json_part = message_delta.lines().nth(1).unwrap();
        let value: Value = serde_json::from_str(json_part.trim_start_matches("data: ")).unwrap();
        let reported_k = value["usage"]["output_tokens"].as_u64().unwrap();

        // message_start (1) + content_block_start (1) + k content_block_delta
        // + content_block_stop (1) + message_delta (1) + message_stop (1)
        let actual_k = frames.len() as u64 - 5;
        assert_eq!(reported_k, actual_k, "model={model} frames={frames:?}");
    }
}

// --------------------------------------------------------- non-streaming --

/// Acceptance: non-streaming still returns a well-formed body with
/// `usage` matching the drawn `k`, for both dialects.
#[tokio::test]
async fn non_streaming_usage_matches_a_valid_draw() {
    let state = test_state();
    let mut sender = spawn_server(state).await;

    let (status, body) = post(
        &mut sender,
        "/v1/chat/completions",
        json!({"model": "mock-medium", "stream": false}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let value: Value = serde_json::from_slice(&body).unwrap();
    let k = value["usage"]["completion_tokens"].as_u64().unwrap();
    assert!((8..=12).contains(&k), "k={k} out of mock-medium range");
    assert_eq!(
        value["usage"]["total_tokens"].as_u64().unwrap(),
        10 + k // prompt_tokens (10, from test_state) + k
    );

    let (status, body) = post(
        &mut sender,
        "/v1/messages",
        json!({"model": "mock-medium", "stream": false}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let value: Value = serde_json::from_slice(&body).unwrap();
    let k = value["usage"]["output_tokens"].as_u64().unwrap();
    assert!((8..=12).contains(&k), "k={k} out of mock-medium range");
}

/// A non-streaming reply is framed by `content-length`, not chunked, on both
/// dialects. The proxy forwards upstream framing as it is, so a mock that
/// chunks fixed-length JSON makes the proxy look like it drops
/// `content-length`, and adds a closing-chunk write to every measured request.
#[tokio::test]
async fn non_streaming_reply_is_framed_by_content_length() {
    let mut sender = spawn_server(test_state()).await;
    for path in ["/v1/chat/completions", "/v1/messages"] {
        sender.ready().await.expect("connection ready");
        let req = Request::post(path)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_static(
                br#"{"model":"mock-medium","stream":false}"#,
            )))
            .unwrap();
        let resp = sender.send_request(req).await.expect("send request");
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            headers
                .get("content-length")
                .map(|v| v.to_str().unwrap().to_owned()),
            Some(body.len().to_string()),
            "{path}: content-length must equal the body length; headers: {headers:?}"
        );
        assert!(
            headers.get("transfer-encoding").is_none(),
            "{path}: a fixed-length reply must not be chunked; headers: {headers:?}"
        );
    }
}
