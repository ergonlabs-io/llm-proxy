//! **v0.0.1 ship-gate**: a live, network-hitting end-to-end proof that a
//! client can call the real `llm-proxy` binary, have it forward to a real
//! provider gateway (OpenAI and Anthropic, over the public internet, with
//! real API keys), and get the provider's response back intact --
//! non-streaming and streamed (SSE) -- for both providers.
//!
//! This is the single test that defines the v0.0.1 release milestone. It is
//! deliberately **not** part of `make ci`: it costs real money (small,
//! `max_tokens`-limited requests, but non-zero) and needs live credentials.
//! Every test in this file is `#[ignore]`d for that reason.
//!
//! ## How to run
//!
//! ```sh
//! OPENAI_API_KEY=sk-... ANTHROPIC_API_KEY=sk-ant-... \
//!   cargo test -p diffrig --test live_smoke -- --ignored
//! ```
//!
//! Both env vars must be set (each test that needs a given provider's key
//! fails loudly, naming the missing variable, rather than silently passing
//! or skipping -- a green "skip" here would be exactly the kind of false
//! confidence this gate exists to rule out).
//!
//! **This bills your account.** Each request uses a tiny `max_tokens` and a
//! one-line prompt, but running the whole file still makes four real calls
//! against two providers' production endpoints.
//!
//! ## Harness
//!
//! Uses `diffrig::harness` (spawn the real `llm-proxy` binary against a temp
//! dialect config, poll the listener socket for readiness, plain-file
//! captured stdout/stderr, `Drop`-based teardown) but points the dialect's
//! providers at the real `https://api.openai.com` / `https://api.anthropic.com`
//! base URLs instead of an in-process mock -- there is no `ca_file` override
//! needed since these present certificates chaining to a public root the
//! proxy's default trust store already trusts.
//!
//! `${VAR}` env interpolation **is** implemented in the dialect (see
//! `crates/proxy-simple-config/src/parse.rs`'s `interpolate_env`), so the API
//! keys are referenced as `${OPENAI_API_KEY}` / `${ANTHROPIC_API_KEY}` in the
//! rendered config text and never written to disk in plaintext by this test
//! -- the child process re-reads its own environment (inherited from this
//! test process) to resolve them at load time.

use std::net::SocketAddr;

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, send_json_collect_sse, ProxyProcess, ScratchDir,
    READY_TIMEOUT,
};
use serde_json::json;

// ------------------------------------------------------------------ config --

/// Render the dialect (`llmproxy-v0`) config for this test: one listener, an
/// `openai` and an `anthropic` provider (named exactly that so the dialect
/// infers their type and default `base_url` -- `https://api.openai.com` /
/// `https://api.anthropic.com` -- from the name; see
/// `crates/proxy-simple-config/src/model.rs`'s `effective_base_url`), each
/// with `api_key: ${VAR}` so the real secret is interpolated from this
/// process's environment at load time and never appears in the file on
/// disk. Deliberately omits `limits:`/`fallbacks:` -- the dialect does not
/// yet accept either (WP-34/WP-35).
fn dialect_config(listener_port: u16) -> String {
    format!(
        r#"
version: 0
listen: "127.0.0.1:{listener_port}"
providers:
  openai:
    api_key: ${{OPENAI_API_KEY}}
  anthropic:
    api_key: ${{ANTHROPIC_API_KEY}}
routes:
  - model: "gpt-*"
    provider: openai
  - model: "claude-*"
    provider: anthropic
"#
    )
}

/// Spawn the proxy against a config pointed at the real provider endpoints,
/// returning the listener address plus the guards that must outlive the
/// test body (dropped in reverse declaration order at the caller's scope
/// end).
fn spawn_live_proxy(label: &str) -> (SocketAddr, ScratchDir, ProxyProcess) {
    let scratch = ScratchDir::new(label);
    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_path = scratch.write("llmproxy.yaml", &dialect_config(listener_port));

    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyProcess::spawn(&bin, &config_path, &scratch.path().join("proxy.log"));
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);
    (listener_addr, scratch, proxy)
}

/// Fail loudly, naming the variable, rather than silently skipping -- a
/// missing key inside an explicitly `--ignored`-requested run is a real
/// test failure, not a reason to report success.
fn require_env(var: &str) {
    if std::env::var(var).is_err() {
        panic!(
            "{var} is not set; this ship-gate test needs a real API key -- \
             run as `{var}=... cargo test -p diffrig --test live_smoke -- --ignored`"
        );
    }
}

// -------------------------------------------------------------------- tests --

/// Proves: a non-streaming `chat/completions` request through the proxy
/// reaches the real OpenAI API and comes back with an intact 200 JSON body
/// -- a choice with non-empty assistant content, and the requested model
/// echoed.
#[tokio::test]
#[ignore = "hits the real OpenAI API and bills tokens; run with --ignored"]
async fn openai_non_streaming_chat_completion_round_trips_through_the_proxy() {
    require_env("OPENAI_API_KEY");

    let (listener_addr, scratch, proxy) = spawn_live_proxy("openai-non-streaming");

    let body = json!({
        "model": "gpt-4o-mini",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with exactly one short word."}],
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
        res.status, 200,
        "expected 200 from the real OpenAI API through the proxy, got {}: {}",
        res.status, res.body
    );
    assert!(
        res.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.contains("application/json")),
        "expected a JSON content-type forwarded from OpenAI, got: {:?}",
        res.headers
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&res.body).expect("OpenAI response body must be well-formed JSON");
    assert_eq!(
        parsed["model"]
            .as_str()
            .map(|m| m.starts_with("gpt-4o-mini")),
        Some(true),
        "expected the model field to echo the requested model, got: {}",
        parsed["model"]
    );
    let content = parsed["choices"][0]["message"]["content"]
        .as_str()
        .expect("choices[0].message.content must be a string");
    assert!(
        !content.trim().is_empty(),
        "expected non-empty assistant message content, got: {parsed}"
    );

    drop(proxy);
    drop(scratch);
}

/// Proves: a streamed (`"stream": true`) request through the proxy delivers
/// real incremental SSE frames from OpenAI as they arrive rather than
/// buffering the whole response -- more than one frame, `[DONE]` last, and
/// (the load-bearing assertion) the first frame shows up well before the
/// stream as a whole finishes.
#[tokio::test]
#[ignore = "hits the real OpenAI API and bills tokens; run with --ignored"]
async fn openai_streaming_chat_completion_delivers_incremental_sse_frames() {
    require_env("OPENAI_API_KEY");

    let (listener_addr, scratch, proxy) = spawn_live_proxy("openai-streaming");

    let body = json!({
        "model": "gpt-4o-mini",
        "max_tokens": 24,
        "messages": [{"role": "user", "content": "Count from one to five, one number per word."}],
        "stream": true,
    });
    let (status, headers, events) = send_json_collect_sse(
        listener_addr,
        "POST",
        "/v1/chat/completions",
        &[("x-llmproxy-model", "gpt-4o-mini")],
        &body,
    )
    .await;

    assert_eq!(status, 200, "expected 200 from the real OpenAI API");
    assert!(
        headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.contains("text/event-stream")),
        "expected `content-type: text/event-stream`, got: {headers:?}"
    );
    assert!(
        events.len() > 1,
        "expected more than one SSE frame from a real streamed completion, got {}",
        events.len()
    );
    let last_event = events.last().expect("at least one event");
    assert_eq!(
        last_event.data, "data: [DONE]",
        "expected the stream to terminate with `data: [DONE]`, got: {}",
        last_event.data
    );

    // At least one non-terminal frame must carry an incremental content
    // delta -- proves the proxy forwarded token-by-token deltas, not just a
    // role-announcement chunk followed immediately by [DONE].
    let has_content_delta = events[..events.len() - 1].iter().any(|e| {
        e.data.trim_start_matches("data: ").contains("\"delta\"") && e.data.contains("\"content\"")
    });
    assert!(
        has_content_delta,
        "expected at least one SSE frame with an incremental content delta"
    );

    // Time-to-first-frame must be meaningfully less than the total
    // duration -- this is what distinguishes real streaming from a proxy
    // that buffers the whole response and replays it as fake SSE frames all
    // at once at the end. Require the first frame to land at or before 80%
    // of the total elapsed time, i.e. at least 20% of the stream's
    // real-world duration must still be ahead of it.
    let first_at = events[0].at;
    let total = last_event.at;
    assert!(
        (first_at.as_secs_f64()) <= total.as_secs_f64() * 0.8,
        "first SSE frame arrived at {first_at:?} out of a total {total:?} -- this looks like \
         the whole response was buffered and replayed as SSE rather than genuinely streamed"
    );

    drop(proxy);
    drop(scratch);
}

/// Proves: a non-streaming `/v1/messages` request through the proxy reaches
/// the real Anthropic API and comes back with an intact 200 JSON body -- a
/// text content block and a `usage` object.
#[tokio::test]
#[ignore = "hits the real Anthropic API and bills tokens; run with --ignored"]
async fn anthropic_non_streaming_message_round_trips_through_the_proxy() {
    require_env("ANTHROPIC_API_KEY");

    let (listener_addr, scratch, proxy) = spawn_live_proxy("anthropic-non-streaming");

    let body = json!({
        "model": "claude-3-5-haiku-latest",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with exactly one short word."}],
    });
    let res = send_json(
        listener_addr,
        "POST",
        "/v1/messages",
        &[("x-llmproxy-model", "claude-3-5-haiku-latest")],
        &body,
    )
    .await;

    assert_eq!(
        res.status, 200,
        "expected 200 from the real Anthropic API through the proxy, got {}: {}",
        res.status, res.body
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&res.body).expect("Anthropic response body must be well-formed JSON");
    assert_eq!(parsed["type"], "message");
    let content = parsed["content"][0]["text"]
        .as_str()
        .expect("content[0].text must be a string");
    assert!(
        !content.trim().is_empty(),
        "expected non-empty assistant content, got: {parsed}"
    );
    assert!(
        parsed["usage"]["input_tokens"].is_u64() && parsed["usage"]["output_tokens"].is_u64(),
        "expected a numeric usage.input_tokens/output_tokens, got: {}",
        parsed["usage"]
    );

    drop(proxy);
    drop(scratch);
}

/// Proves: a streamed `/v1/messages` request through the proxy delivers
/// real incremental SSE frames from Anthropic as they arrive -- opening
/// with `message_start`, ending with `message_stop`, with at least one
/// `content_block_delta` in between, and (the load-bearing assertion) the
/// first frame shows up well before the stream as a whole finishes.
#[tokio::test]
#[ignore = "hits the real Anthropic API and bills tokens; run with --ignored"]
async fn anthropic_streaming_message_delivers_incremental_sse_frames() {
    require_env("ANTHROPIC_API_KEY");

    let (listener_addr, scratch, proxy) = spawn_live_proxy("anthropic-streaming");

    let body = json!({
        "model": "claude-3-5-haiku-latest",
        "max_tokens": 24,
        "messages": [{"role": "user", "content": "Count from one to five, one number per word."}],
        "stream": true,
    });
    let (status, headers, events) = send_json_collect_sse(
        listener_addr,
        "POST",
        "/v1/messages",
        &[("x-llmproxy-model", "claude-3-5-haiku-latest")],
        &body,
    )
    .await;

    assert_eq!(status, 200, "expected 200 from the real Anthropic API");
    assert!(
        headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.contains("text/event-stream")),
        "expected `content-type: text/event-stream`, got: {headers:?}"
    );
    assert!(
        events.len() > 1,
        "expected more than one SSE frame from a real streamed message, got {}",
        events.len()
    );
    let first = &events[0];
    let last_event = events.last().expect("at least one event");
    assert!(
        first.data.contains("event: message_start"),
        "expected `message_start` first, got: {}",
        first.data
    );
    assert!(
        last_event.data.contains("event: message_stop"),
        "expected `message_stop` last, got: {}",
        last_event.data
    );
    assert!(
        events
            .iter()
            .any(|e| e.data.contains("event: content_block_delta")),
        "expected at least one `content_block_delta` frame in between"
    );

    let first_at = first.at;
    let total = last_event.at;
    assert!(
        (first_at.as_secs_f64()) <= total.as_secs_f64() * 0.8,
        "first SSE frame arrived at {first_at:?} out of a total {total:?} -- this looks like \
         the whole response was buffered and replayed as SSE rather than genuinely streamed"
    );

    drop(proxy);
    drop(scratch);
}
