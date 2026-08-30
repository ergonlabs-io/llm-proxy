//! End-to-end coverage for the scale-test profile extension: real HTTP
//! requests against a real `AppState`-backed server, over an in-memory pipe
//! (never a bound port -- see CLAUDE.md rule 15, "a worktree does not
//! isolate ports"). Exercises what `frames.rs`'/`handler.rs`'s unit tests
//! can't: that profile selection, the terminal frame, and the usage count
//! all survive a real hyper request/response round trip, for both dialects.

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

/// Spin up one `AppState` behind a real http/1.1 server connection on one
/// end of an in-memory `tokio::io::duplex` pipe, and hand back a low-level
/// hyper client to drive it from the other end -- the same "server + client
/// over an in-process pipe" technique
/// `crates/proxy-http/tests/http1_codec.rs` uses, minus the `!Send`
/// `LocalSet` machinery that file needs and this crate's handler doesn't
/// (see the crate doc: this crate's bodies are all `Send`).
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

/// A `ProfileSet` using the built-in profile *names* with test-scale
/// timing/length instead of the real ones.
///
/// The real built-ins are production values for an actual scale run
/// (`mock-slow-long` alone streams up to 2000 chunks at up to 60ms apart --
/// minutes of real wall-clock sleeping per request, by design). Running
/// this crate's own integration tests against those would make the suite
/// itself the next `terminate-after` casualty (CLAUDE.md rule 14). What's
/// under test here is the *selection and accounting* logic -- "the model
/// picks the right profile", "the reported count matches what was actually
/// sent" -- which holds at any scale, so the override keeps the same names
/// (a real loadgen run selects profiles this same way) and the same
/// *relative* ordering (fast-short < medium < slow-long) while shrinking
/// every number enough to keep the whole suite well under a second.
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
