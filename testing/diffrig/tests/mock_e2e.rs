//! Hermetic mock-provider end-to-end suite: the real `llm-proxy` binary,
//! booted from a dialect (`llmproxy.yaml`) config, proxies real HTTP/1.1
//! requests to the in-process OpenAI/Anthropic mocks in
//! `diffrig::upstreams` over plain loopback TCP (no TLS needed here --
//! `tls_e2e.rs` already covers the TLS-handshake-specific behavior; this
//! file's job is the request/response contract and streaming pacing).
//!
//! **Not `#[ignore]`d** -- no network beyond loopback, no API keys, so this
//! suite runs in `make ci`. See `diffrig::harness` for the shared
//! spawn/poll/HTTP-client machinery this file builds on.

use std::net::SocketAddr;
use std::time::Duration;

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, send_json_collect_sse, ProxyProcess, ScratchDir,
    READY_TIMEOUT,
};
use diffrig::upstreams::{AnthropicConfig, AnthropicUpstream, OpenAiConfig, OpenAiUpstream};
use serde_json::json;

// ------------------------------------------------------------------ config --

/// Render the dialect (`llmproxy-v0`) config for this suite: one listener, a
/// plaintext (`http://`) `openai` provider and `anthropic` provider (named
/// exactly that so the dialect infers their type without an explicit
/// `type:` field), each pointed at an in-process mock on loopback. Routing
/// matches the `x-llmproxy-model` request header against a `gpt-*`/`claude-*`
/// glob, same as `tls_e2e.rs`.
fn dialect_config(listener_port: u16, openai_port: u16, anthropic_port: u16) -> String {
    format!(
        r#"
version: 0
listen: "127.0.0.1:{listener_port}"
providers:
  openai:
    base_url: "http://127.0.0.1:{openai_port}"
    api_key: "test-openai-key"
  anthropic:
    base_url: "http://127.0.0.1:{anthropic_port}"
    api_key: "test-anthropic-key"
routes:
  - model: "gpt-*"
    provider: openai
  - model: "claude-*"
    provider: anthropic
"#
    )
}

// ----------------------------------------------------------------- helpers --

fn base_openai_config() -> OpenAiConfig {
    OpenAiConfig {
        model: "gpt-mock".to_string(),
        response_text: "alpha beta gamma".to_string(),
        ttft: Duration::from_millis(1),
        inter_token_delay: Duration::from_millis(1),
        require_api_key: Some("test-openai-key".to_string()),
        forced_error: None,
        cached_tokens: 0,
    }
}

fn base_anthropic_config() -> AnthropicConfig {
    AnthropicConfig {
        model: "claude-mock".to_string(),
        response_text: "delta epsilon zeta".to_string(),
        ttft: Duration::from_millis(1),
        inter_token_delay: Duration::from_millis(1),
        require_api_key: Some("test-anthropic-key".to_string()),
        forced_error: None,
        cache_read_tokens: 0,
        cache_creation_tokens: 0,
    }
}

/// Spawn both mocks plus the real proxy wired to them via the dialect,
/// returning everything the caller needs to drive requests and inspect what
/// the mocks actually received. Guards are returned so the caller controls
/// drop order (proxy first, then the mocks) at the end of the test body.
async fn spawn_suite(
    label: &str,
    openai_config: OpenAiConfig,
    anthropic_config: AnthropicConfig,
) -> (
    SocketAddr,
    OpenAiUpstream,
    AnthropicUpstream,
    ScratchDir,
    ProxyProcess,
) {
    let openai_upstream = OpenAiUpstream::spawn(openai_config)
        .await
        .expect("spawn openai mock");
    let anthropic_upstream = AnthropicUpstream::spawn(anthropic_config)
        .await
        .expect("spawn anthropic mock");

    let scratch = ScratchDir::new(label);
    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_yaml = dialect_config(
        listener_port,
        openai_upstream.addr().port(),
        anthropic_upstream.addr().port(),
    );
    let config_path = scratch.write("llmproxy.yaml", &config_yaml);

    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyProcess::spawn(&bin, &config_path, &scratch.path().join("proxy.log"));
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);

    (
        listener_addr,
        openai_upstream,
        anthropic_upstream,
        scratch,
        proxy,
    )
}

// -------------------------------------------------------------------- tests --

/// A non-streaming OpenAI chat-completions request through the proxy comes
/// back with the upstream's status, a JSON content-type, and the exact
/// completion body intact -- and the client's request (model, messages,
/// `stream` flag) reaches the mock unmangled, and the dialect's injected
/// `authorization: Bearer <key>` actually arrives there too. This is
/// regression cover for the P0 where `request_headers_to_add` was lowered
/// by the front-end but read by nothing, so every request reached its
/// provider with no credentials.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_non_streaming_round_trip_preserves_status_headers_body_and_forwards_credentials() {
    let (listener_addr, openai_upstream, anthropic_upstream, scratch, proxy) = spawn_suite(
        "openai-non-streaming",
        base_openai_config(),
        base_anthropic_config(),
    )
    .await;

    let body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi there"}],
    });
    let res = send_json(
        listener_addr,
        "POST",
        "/v1/chat/completions",
        &[("x-llmproxy-model", "gpt-4o-mini")],
        &body,
    )
    .await;

    assert_eq!(res.status, 200, "openai non-streaming body: {}", res.body);
    assert!(
        res.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.contains("application/json")),
        "expected a JSON content-type forwarded from the upstream, got: {:?}",
        res.headers
    );
    let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json");
    assert_eq!(parsed["object"], "chat.completion");
    assert_eq!(
        parsed["choices"][0]["message"]["content"],
        "alpha beta gamma"
    );

    // Credentials actually arrived at the upstream.
    let requests = openai_upstream.log.requests();
    let last = requests.last().expect("openai mock received a request");
    assert!(
        last.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("authorization") && v == "Bearer test-openai-key"),
        "expected `authorization: Bearer test-openai-key` at the upstream, got: {:?}",
        last.headers
    );

    // The client's request body reached the upstream unmangled.
    let received_bodies = openai_upstream.bodies.bodies();
    let received = received_bodies.last().expect("openai mock recorded a body");
    assert_eq!(received["model"], "gpt-4o-mini");
    assert_eq!(received["messages"][0]["role"], "user");
    assert_eq!(received["messages"][0]["content"], "hi there");

    drop(proxy);
    openai_upstream.shutdown().await;
    anthropic_upstream.shutdown().await;
    drop(scratch);
}

/// The Anthropic-dialect twin of the OpenAI round-trip test above: `/v1/messages`
/// shape, `x-api-key` + the dialect's default `anthropic-version` actually
/// arriving at the upstream, and the client's request body forwarded intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anthropic_non_streaming_round_trip_preserves_status_headers_body_and_forwards_credentials()
{
    let (listener_addr, openai_upstream, anthropic_upstream, scratch, proxy) = spawn_suite(
        "anthropic-non-streaming",
        base_openai_config(),
        base_anthropic_config(),
    )
    .await;

    let body = json!({
        "model": "claude-3-mock",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi there"}],
    });
    let res = send_json(
        listener_addr,
        "POST",
        "/v1/messages",
        &[("x-llmproxy-model", "claude-3-mock")],
        &body,
    )
    .await;

    assert_eq!(
        res.status, 200,
        "anthropic non-streaming body: {}",
        res.body
    );
    let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json");
    assert_eq!(parsed["type"], "message");
    assert_eq!(parsed["content"][0]["text"], "delta epsilon zeta");

    let requests = anthropic_upstream.log.requests();
    let last = requests.last().expect("anthropic mock received a request");
    assert!(
        last.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("x-api-key") && v == "test-anthropic-key"),
        "expected `x-api-key: test-anthropic-key` at the upstream, got: {:?}",
        last.headers
    );
    // The dialect injects a default `anthropic-version` when the user
    // doesn't set one (`DEFAULT_ANTHROPIC_VERSION` in `lower.rs`).
    assert!(
        last.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("anthropic-version") && v == "2023-06-01"),
        "expected a default `anthropic-version: 2023-06-01` at the upstream, got: {:?}",
        last.headers
    );

    let received_bodies = anthropic_upstream.bodies.bodies();
    let received = received_bodies
        .last()
        .expect("anthropic mock recorded a body");
    assert_eq!(received["model"], "claude-3-mock");
    assert_eq!(received["messages"][0]["content"], "hi there");

    drop(proxy);
    openai_upstream.shutdown().await;
    anthropic_upstream.shutdown().await;
    drop(scratch);
}

/// Proves streaming is genuinely streamed, by construction: with a large
/// `ttft` (time-to-first-chunk) and a small `inter_token_delay` over several
/// chunks, the client's first frame must not arrive before roughly `ttft`,
/// AND the last frame must arrive well after the first -- consistent with
/// per-chunk pacing actually having elapsed between forwarded frames. A
/// proxy that buffered the whole response and flushed it at the end would
/// deliver every frame at essentially the same (late) instant and fail the
/// second assertion, which is the one that matters.
///
/// Tolerances: `tokio::time::sleep` never fires *early*, so the lower bound
/// on `ttft` is solid; the spread assertion uses a generous ~60% margin
/// below the theoretical minimum gap to absorb CI scheduling jitter without
/// going so loose it would pass under buffering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_streaming_delivers_frames_as_they_are_produced_not_buffered() {
    let ttft = Duration::from_millis(400);
    let inter_token_delay = Duration::from_millis(30);
    // 6 tokens -> 5 gaps of `inter_token_delay` between the first and last
    // content-delta chunk.
    let mut openai_config = base_openai_config();
    openai_config.response_text = "one two three four five six".to_string();
    openai_config.ttft = ttft;
    openai_config.inter_token_delay = inter_token_delay;

    let (listener_addr, openai_upstream, anthropic_upstream, scratch, proxy) = spawn_suite(
        "openai-streaming-timing",
        openai_config,
        base_anthropic_config(),
    )
    .await;

    let stream_body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });
    let (status, _headers, events) = send_json_collect_sse(
        listener_addr,
        "POST",
        "/v1/chat/completions",
        &[("x-llmproxy-model", "gpt-4o-mini")],
        &stream_body,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        events.len() >= 3,
        "expected multiple SSE frames, got {}",
        events.len()
    );

    let first = &events[0];
    let last_event = events.last().expect("at least one event");

    // First frame (the role-delta chunk) must not arrive before ttft --
    // `sleep` cannot fire early, so allow only a small clock-skew slop.
    assert!(
        first.at >= ttft.saturating_sub(Duration::from_millis(50)),
        "first SSE frame arrived at {:?}, before the configured ttft ({ttft:?})",
        first.at
    );

    // The last frame must arrive well after the first, consistent with real
    // per-chunk pacing (5 gaps of `inter_token_delay`) having elapsed --
    // this is the assertion that rules out whole-response buffering.
    let theoretical_min_gap = inter_token_delay * 5;
    let tolerant_min_gap = theoretical_min_gap.mul_f64(0.6);
    let observed_gap = last_event.at.saturating_sub(first.at);
    assert!(
        observed_gap >= tolerant_min_gap,
        "first and last SSE frames arrived too close together ({:?} vs {:?}, gap {:?} < {:?}); \
         proxy may be buffering the whole response instead of streaming it",
        first.at,
        last_event.at,
        observed_gap,
        tolerant_min_gap
    );

    drop(proxy);
    openai_upstream.shutdown().await;
    anthropic_upstream.shutdown().await;
    drop(scratch);
}

/// The Anthropic twin of the streaming-timing proof above, using
/// `content_block_delta` events instead of OpenAI's data-only chunks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anthropic_streaming_delivers_frames_as_they_are_produced_not_buffered() {
    let ttft = Duration::from_millis(400);
    let inter_token_delay = Duration::from_millis(30);
    let mut anthropic_config = base_anthropic_config();
    anthropic_config.response_text = "one two three four five six".to_string();
    anthropic_config.ttft = ttft;
    anthropic_config.inter_token_delay = inter_token_delay;

    let (listener_addr, openai_upstream, anthropic_upstream, scratch, proxy) = spawn_suite(
        "anthropic-streaming-timing",
        base_openai_config(),
        anthropic_config,
    )
    .await;

    let stream_body = json!({
        "model": "claude-3-mock",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });
    let (status, _headers, events) = send_json_collect_sse(
        listener_addr,
        "POST",
        "/v1/messages",
        &[("x-llmproxy-model", "claude-3-mock")],
        &stream_body,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        events.len() >= 3,
        "expected multiple SSE frames, got {}",
        events.len()
    );

    let first = &events[0];
    let last_event = events.last().expect("at least one event");

    assert!(
        first.at >= ttft.saturating_sub(Duration::from_millis(50)),
        "first SSE frame (message_start) arrived at {:?}, before the configured ttft ({ttft:?})",
        first.at
    );

    let theoretical_min_gap = inter_token_delay * 5;
    let tolerant_min_gap = theoretical_min_gap.mul_f64(0.6);
    let observed_gap = last_event.at.saturating_sub(first.at);
    assert!(
        observed_gap >= tolerant_min_gap,
        "Anthropic SSE frames arrived too close together ({:?} vs {:?}, gap {:?} < {:?}); \
         proxy may be buffering the whole response instead of streaming it",
        first.at,
        last_event.at,
        observed_gap,
        tolerant_min_gap
    );

    drop(proxy);
    openai_upstream.shutdown().await;
    anthropic_upstream.shutdown().await;
    drop(scratch);
}

/// A `stream: true` request's flag reaches the upstream exactly as sent --
/// separate from the timing proofs above, this is a plain content check on
/// what the mock recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_stream_flag_reaches_upstream_unmangled() {
    let (listener_addr, openai_upstream, anthropic_upstream, scratch, proxy) =
        spawn_suite("stream-flag", base_openai_config(), base_anthropic_config()).await;

    let stream_body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });
    let (status, _headers, _events) = send_json_collect_sse(
        listener_addr,
        "POST",
        "/v1/chat/completions",
        &[("x-llmproxy-model", "gpt-4o-mini")],
        &stream_body,
    )
    .await;
    assert_eq!(status, 200);

    let received_bodies = openai_upstream.bodies.bodies();
    let received = received_bodies.last().expect("openai mock recorded a body");
    assert_eq!(received["model"], "gpt-4o-mini");
    assert_eq!(received["stream"], true);

    drop(proxy);
    openai_upstream.shutdown().await;
    anthropic_upstream.shutdown().await;
    drop(scratch);
}

/// An upstream 5xx must be surfaced to the client as-is, never swallowed or
/// turned into a 200 -- exercised for both providers since each has its own
/// error envelope shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_5xx_is_surfaced_to_the_client_not_swallowed_or_turned_into_200() {
    let mut openai_config = base_openai_config();
    openai_config.forced_error = Some((503, "mock upstream overloaded".to_string()));
    let (listener_addr, openai_upstream, anthropic_upstream, scratch, proxy) =
        spawn_suite("openai-5xx", openai_config, base_anthropic_config()).await;

    let body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi there"}],
    });
    let res = send_json(
        listener_addr,
        "POST",
        "/v1/chat/completions",
        &[("x-llmproxy-model", "gpt-4o-mini")],
        &body,
    )
    .await;

    assert_eq!(
        res.status, 503,
        "expected the upstream's 503 to be surfaced to the client, got {}: {}",
        res.status, res.body
    );
    assert_ne!(
        res.status, 200,
        "an upstream error must never be turned into a 200"
    );

    drop(proxy);
    openai_upstream.shutdown().await;
    anthropic_upstream.shutdown().await;
    drop(scratch);
}
