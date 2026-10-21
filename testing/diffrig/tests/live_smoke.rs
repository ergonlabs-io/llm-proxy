//! Live provider smoke tests: the real `llm-proxy` binary, loaded with a
//! `--config` dialect file, forwards to real providers over the public
//! internet, and the responses and usage records come back intact. Every
//! other test in this repository runs against mocks, so this file is the only
//! place a provider-side wire or auth change shows up before a customer hits
//! it.
//!
//! Every test is `#[ignore]`d, so `make tq` and `make ci` never run it. It
//! needs live credentials and some providers bill per token.
//!
//! ## How to run
//!
//! ```sh
//! make smoke-live
//! ```
//!
//! Set the variables for the providers you want to exercise; see
//! `testing/diffrig/README.md` "Live provider smoke tests" for the full list.
//! `.github/workflows/live-smoke.yml` runs the same target weekly and on
//! demand, with credentials from repository secrets.
//!
//! ## Skipping
//!
//! A test whose credentials are absent prints
//! `LIVE-SKIP live_smoke::<test>: <VAR> is not set` and returns. nextest still
//! reports it as passed, so read the `LIVE-SKIP` lines (the make target runs
//! with `--no-capture` for that reason) before treating a run as coverage.
//! Set `LIVE_SMOKE_STRICT=1` to turn every skip into a failure, for a run that
//! is meant to prove a given set of providers.
//!
//! ## Cost
//!
//! OpenRouter uses a free model (`:free` suffix), so its tests cost nothing;
//! they allow 256 tokens because free models often reason before answering.
//! The OpenAI, Anthropic, Vertex and Bedrock tests bill the account behind
//! their credentials, and each uses a one-line prompt and a `max_tokens` of
//! 24 or less.
//!
//! ## Harness
//!
//! Uses `diffrig::harness`: spawn the binary against a temp dialect config,
//! poll the listener for readiness, capture stdout and stderr in a scratch
//! file, tear down on `Drop`. Credentials appear in the rendered config only as
//! `${VAR}` references, which the dialect interpolates from the child's
//! inherited environment at load time, so no key is ever written to disk.
//! Assertion messages print response bodies and access-log lines, never the
//! config or the environment.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, send_json_collect_sse, ProxyProcess, RawResponse,
    ScratchDir, TimedEvent, READY_TIMEOUT,
};
use serde_json::{json, Value};

// ----------------------------------------------------------------- helpers --

/// Real endpoints are far slower than the loopback mocks the rest of the rig
/// uses, and free OpenRouter models queue. Bounds each request so a hung
/// provider fails the test by name instead of reaching nextest's
/// `terminate-after`.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(90);

/// The access-log writer batches lines on its own thread, so the line lands
/// shortly after the response, not before it.
const ACCESS_LOG_TIMEOUT: Duration = Duration::from_secs(10);

/// Free models come and go on OpenRouter; override with
/// `OPENROUTER_SMOKE_MODEL` when this one is retired or rate-limited. Passed
/// live on 2026-10-21; the Gemma free models were rate-limited upstream
/// (429 from a shared pool) that day.
const OPENROUTER_DEFAULT_MODEL: &str = "liquid/lfm-2.5-2.6b:free";

/// Returns whether every variable in `vars` is set. When one is not, prints a
/// `LIVE-SKIP` line naming the test and the variable and returns `false`, so
/// the caller returns early. `LIVE_SMOKE_STRICT=1` makes that a failure.
fn live_env(test: &str, vars: &[&str]) -> bool {
    let Some(missing) = vars.iter().find(|var| std::env::var(var).is_err()) else {
        return true;
    };
    let reason = format!("{missing} is not set");
    if std::env::var("LIVE_SMOKE_STRICT").as_deref() == Ok("1") {
        panic!("live_smoke::{test}: {reason} and LIVE_SMOKE_STRICT=1");
    }
    // Both streams: stdout is what `--no-capture` interleaves with nextest's
    // own lines, stderr is what a captured run keeps.
    println!("LIVE-SKIP live_smoke::{test}: {reason}");
    eprintln!("LIVE-SKIP live_smoke::{test}: {reason}");
    false
}

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

/// The listener port is rendered into the config, so the caller supplies a
/// closure from port to config text.
struct LiveProxy {
    addr: SocketAddr,
    // Field order is drop order: stop the process before removing its files.
    _proxy: ProxyProcess,
    scratch: ScratchDir,
}

impl LiveProxy {
    fn spawn(label: &str, config: impl FnOnce(u16) -> String) -> Self {
        let scratch = ScratchDir::new(label);
        let port = free_port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let config_path = scratch.write("llmproxy.yaml", &config(port));
        let bin = resolve_llm_proxy_bin();
        let mut proxy = ProxyProcess::spawn(&bin, &config_path, &scratch.path().join("proxy.log"));
        proxy.wait_until_ready(addr, READY_TIMEOUT);
        Self {
            addr,
            _proxy: proxy,
            scratch,
        }
    }

    async fn send(&self, path: &str, body: &Value) -> RawResponse {
        tokio::time::timeout(
            CLIENT_TIMEOUT,
            send_json(self.addr, "POST", path, &[], body),
        )
        .await
        .unwrap_or_else(|_| panic!("no response from the proxy within {CLIENT_TIMEOUT:?}"))
    }

    async fn send_sse(
        &self,
        path: &str,
        body: &Value,
    ) -> (u16, Vec<(String, String)>, Vec<TimedEvent>) {
        tokio::time::timeout(
            CLIENT_TIMEOUT,
            send_json_collect_sse(self.addr, "POST", path, &[], body),
        )
        .await
        .unwrap_or_else(|_| panic!("no complete stream from the proxy within {CLIENT_TIMEOUT:?}"))
    }

    /// The first JSON access-log line the proxy wrote. Each test sends one
    /// request per proxy, so the first line is that request's record.
    async fn access_log_entry(&self) -> Value {
        let path = self.scratch.path().join("proxy.log");
        let deadline = Instant::now() + ACCESS_LOG_TIMEOUT;
        loop {
            let logs = std::fs::read_to_string(&path).unwrap_or_default();
            if let Some(entry) = logs
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .find(|entry| entry.get("response_code").is_some())
            {
                return entry;
            }
            assert!(
                Instant::now() < deadline,
                "no JSON access-log line within {ACCESS_LOG_TIMEOUT:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// The JSON access-log block every config here carries, so each request
/// leaves a record naming the provider it dialled and the usage it extracted.
const ACCESS_LOG_JSON: &str = r#"
observability:
  access_logs:
    output: stdout
    format: json
"#;

/// Access-log fields render as strings; accept a number too.
fn count(entry: &Value, field: &str) -> Option<u64> {
    match &entry[field] {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

/// The request record names the provider cluster, shows an upstream was
/// dialled, and carries token usage the proxy extracted from the provider's
/// response (not from the client's view of the body).
fn assert_record_names_provider_with_usage(entry: &Value, cluster: &str) {
    assert_eq!(
        entry["selected_provider"], cluster,
        "access-log line must name the provider cluster: {entry}"
    );
    assert!(
        entry["upstream_host"]
            .as_str()
            .is_some_and(|h| !h.is_empty()),
        "access-log line must show an upstream was dialled: {entry}"
    );
    for field in ["llm_input_tokens", "llm_output_tokens"] {
        assert!(
            count(entry, field).is_some_and(|n| n > 0),
            "access-log line must carry extracted usage `{field}` > 0: {entry}"
        );
    }
}

/// Concatenate the `choices[0].delta.content` of every OpenAI-shaped SSE
/// frame, skipping `[DONE]` and frames that are not JSON.
fn openai_stream_text(events: &[TimedEvent]) -> String {
    events
        .iter()
        .filter_map(|e| e.data.strip_prefix("data: "))
        .filter_map(|data| serde_json::from_str::<Value>(data).ok())
        .filter_map(|frame| {
            frame["choices"][0]["delta"]["content"]
                .as_str()
                .map(str::to_owned)
        })
        .collect()
}

fn header_contains(headers: &[(String, String)], name: &str, needle: &str) -> bool {
    headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case(name) && v.contains(needle))
}

/// Proves streaming is incremental rather than buffered and replayed: the
/// first frame lands at or before 80% of the stream's total duration.
fn assert_first_frame_early(events: &[TimedEvent]) {
    let first_at = events[0].at;
    let total = events.last().expect("at least one event").at;
    assert!(
        first_at.as_secs_f64() <= total.as_secs_f64() * 0.8,
        "first SSE frame arrived at {first_at:?} out of a total {total:?} -- this looks like \
         the whole response was buffered and replayed as SSE rather than genuinely streamed"
    );
}

// --------------------------------------------------------------- OpenRouter --

/// `openrouter` is inferred from the provider name, with base URL
/// `https://openrouter.ai` and the `/v1` -> `/api/v1` rewrite. The model is
/// quoted because free model IDs contain `:`.
fn openrouter_config(port: u16, api_key: &str, model: &str) -> String {
    format!(
        r#"
version: 0
listen: "127.0.0.1:{port}"
providers:
  openrouter:
    api_key: {api_key}
routes: []
models:
  "{model}": {{ providers: [openrouter] }}
{ACCESS_LOG_JSON}"#
    )
}

/// Many free models reason before they answer, and reasoning tokens count
/// against `max_tokens`, so a small cap ends the reply before any content.
/// Reasoning cannot always be switched off (some endpoints answer 400), so
/// the cap leaves room for it instead. Free models cost nothing.
fn openrouter_body(model: &str, stream: bool) -> Value {
    json!({
        "model": model,
        "max_tokens": 256,
        "messages": [{"role": "user", "content": "Reply with exactly one short word."}],
        "stream": stream,
    })
}

/// Proves: a non-streaming chat request through the proxy reaches OpenRouter
/// with the configured key and returns 200 with non-empty content, and the
/// request record names `provider:openrouter` with extracted usage.
#[tokio::test]
#[ignore = "hits the real OpenRouter API (free model); run with make smoke-live"]
async fn openrouter_non_streaming_chat_returns_content_and_usage() {
    let test = "openrouter_non_streaming_chat_returns_content_and_usage";
    if !live_env(test, &["OPENROUTER_API_KEY"]) {
        return;
    }
    let model = env_or("OPENROUTER_SMOKE_MODEL", OPENROUTER_DEFAULT_MODEL);
    let proxy = LiveProxy::spawn("openrouter-non-streaming", |port| {
        openrouter_config(port, "${OPENROUTER_API_KEY}", &model)
    });

    let res = proxy
        .send("/v1/chat/completions", &openrouter_body(&model, false))
        .await;

    assert_eq!(
        res.status, 200,
        "expected 200 from OpenRouter ({model}) through the proxy, got {}: {} \
         (a 404 or 429 may mean the free model is gone or saturated; \
         set OPENROUTER_SMOKE_MODEL)",
        res.status, res.body
    );
    let parsed: Value =
        serde_json::from_str(&res.body).expect("OpenRouter response body must be JSON");
    let content = parsed["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_default();
    assert!(
        !content.trim().is_empty(),
        "expected non-empty assistant content, got: {parsed}"
    );
    assert!(
        parsed["usage"]["prompt_tokens"]
            .as_u64()
            .is_some_and(|n| n > 0),
        "expected usage.prompt_tokens > 0 in the provider body, got: {}",
        parsed["usage"]
    );
    assert_record_names_provider_with_usage(&proxy.access_log_entry().await, "provider:openrouter");
}

/// Proves: a streamed chat request through the proxy returns 200 SSE from
/// OpenRouter, incrementally, with non-empty delta content ending in
/// `[DONE]`, and the proxy extracts usage from the stream (it forces
/// `stream_options.include_usage` for OpenAI-shaped streams).
#[tokio::test]
#[ignore = "hits the real OpenRouter API (free model); run with make smoke-live"]
async fn openrouter_streaming_chat_returns_content_and_usage() {
    let test = "openrouter_streaming_chat_returns_content_and_usage";
    if !live_env(test, &["OPENROUTER_API_KEY"]) {
        return;
    }
    let model = env_or("OPENROUTER_SMOKE_MODEL", OPENROUTER_DEFAULT_MODEL);
    let proxy = LiveProxy::spawn("openrouter-streaming", |port| {
        openrouter_config(port, "${OPENROUTER_API_KEY}", &model)
    });

    let (status, headers, events) = proxy
        .send_sse("/v1/chat/completions", &openrouter_body(&model, true))
        .await;

    let raw: Vec<&str> = events.iter().map(|e| e.data.as_str()).collect();
    assert_eq!(
        status, 200,
        "expected 200 from OpenRouter ({model}) through the proxy, got {status}: {raw:?}"
    );
    assert!(
        header_contains(&headers, "content-type", "text/event-stream"),
        "expected `content-type: text/event-stream`, got: {headers:?}"
    );
    assert_eq!(
        events.last().map(|e| e.data.as_str()),
        Some("data: [DONE]"),
        "expected the stream to end with `data: [DONE]`, got: {raw:?}"
    );
    let text = openai_stream_text(&events);
    assert!(
        !text.trim().is_empty(),
        "expected non-empty streamed delta content, got: {raw:?}"
    );
    assert_first_frame_early(&events);

    let entry = proxy.access_log_entry().await;
    assert_record_names_provider_with_usage(&entry, "provider:openrouter");
    assert_eq!(
        entry["llm_usage_completeness"], "complete",
        "streamed usage must be complete: {entry}"
    );
}

/// Proves: with a bad key, the client gets OpenRouter's own 401 through the
/// proxy, not a local 5xx. The record shows the upstream was dialled, which a
/// locally generated error never does. Needs no secret, so it runs whenever
/// the live suite runs.
#[tokio::test]
#[ignore = "hits the real OpenRouter API (no key needed); run with make smoke-live"]
async fn openrouter_bad_key_returns_provider_401() {
    let model = env_or("OPENROUTER_SMOKE_MODEL", OPENROUTER_DEFAULT_MODEL);
    let proxy = LiveProxy::spawn("openrouter-bad-key", |port| {
        openrouter_config(port, "sk-or-v1-llm-proxy-live-smoke-invalid-key", &model)
    });

    let res = proxy
        .send("/v1/chat/completions", &openrouter_body(&model, false))
        .await;

    assert_eq!(
        res.status, 401,
        "expected OpenRouter's 401 through the proxy, got {}: {}",
        res.status, res.body
    );
    let parsed: Value =
        serde_json::from_str(&res.body).expect("the 401 body must be the provider's JSON error");
    assert!(
        parsed["error"].is_object(),
        "expected the provider's `error` object, got: {parsed}"
    );
    let entry = proxy.access_log_entry().await;
    assert_eq!(entry["selected_provider"], "provider:openrouter", "{entry}");
    assert_eq!(count(&entry, "response_code"), Some(401), "{entry}");
    assert!(
        entry["upstream_host"]
            .as_str()
            .is_some_and(|h| !h.is_empty()),
        "the 401 must come from a dialled upstream, not the proxy: {entry}"
    );
}

// ------------------------------------------------------------ Vertex, Bedrock --
//
// Both use the `anthropic` dialect on a `models:` entry, because routes carry
// no dialect and these provider types serve several wire formats. Neither has
// run against the real provider yet: no credentials were available when they
// were written. Treat a first failure as a finding about the proxy or the
// test, not as flakiness.

/// Vertex with a static access token, for example from
/// `gcloud auth print-access-token`. The proxy also supports minted tokens
/// (`oauth2_jwt_bearer`); this test keeps to the smaller credential surface.
fn vertex_config(port: u16, location: &str, model: &str) -> String {
    format!(
        r#"
version: 0
listen: "127.0.0.1:{port}"
providers:
  vertex:
    type: vertex
    base_url: https://{location}-aiplatform.googleapis.com
    project: ${{VERTEX_PROJECT}}
    location: {location}
    publisher: anthropic
    access_token: ${{VERTEX_ACCESS_TOKEN}}
routes: []
models:
  smoke-vertex:
    providers:
      - {{ provider: vertex, model: "{model}", dialect: anthropic }}
{ACCESS_LOG_JSON}"#
    )
}

/// Proves: an Anthropic-shaped message routed to Claude on Vertex returns 200
/// with non-empty content, and the record names `provider:vertex` with usage.
#[tokio::test]
#[ignore = "hits the real Vertex AI API and bills tokens; run with make smoke-live"]
async fn vertex_anthropic_message_returns_content_and_usage() {
    let test = "vertex_anthropic_message_returns_content_and_usage";
    if !live_env(test, &["VERTEX_PROJECT", "VERTEX_ACCESS_TOKEN"]) {
        return;
    }
    let location = env_or("VERTEX_LOCATION", "us-east5");
    let model = env_or("VERTEX_SMOKE_MODEL", "claude-haiku-4-5@20251001");
    let proxy = LiveProxy::spawn("vertex", |port| vertex_config(port, &location, &model));

    let body = json!({
        "model": "smoke-vertex",
        "anthropic_version": "vertex-2023-10-16",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with exactly one short word."}],
    });
    let res = proxy.send("/v1/messages", &body).await;

    assert_anthropic_message(&res, "Vertex");
    assert_record_names_provider_with_usage(&proxy.access_log_entry().await, "provider:vertex");
}

fn bedrock_config(port: u16, region: &str, model: &str, session_token: bool) -> String {
    let session = if session_token {
        "\n    session_token: ${AWS_SESSION_TOKEN}"
    } else {
        ""
    };
    format!(
        r#"
version: 0
listen: "127.0.0.1:{port}"
providers:
  bedrock:
    type: bedrock
    base_url: https://bedrock-runtime.{region}.amazonaws.com
    region: {region}
    access_key_id: ${{AWS_ACCESS_KEY_ID}}
    secret_access_key: ${{AWS_SECRET_ACCESS_KEY}}{session}
routes: []
models:
  smoke-bedrock:
    providers:
      - {{ provider: bedrock, model: "{model}", dialect: anthropic }}
{ACCESS_LOG_JSON}"#
    )
}

/// Proves: an Anthropic-shaped message routed to Claude on Bedrock, signed
/// with SigV4, returns 200 with non-empty content, and the record names
/// `provider:bedrock` with usage.
#[tokio::test]
#[ignore = "hits the real Amazon Bedrock API and bills tokens; run with make smoke-live"]
async fn bedrock_anthropic_message_returns_content_and_usage() {
    let test = "bedrock_anthropic_message_returns_content_and_usage";
    if !live_env(
        test,
        &["AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
    ) {
        return;
    }
    let region = env_or("AWS_REGION", "us-east-1");
    let model = env_or(
        "BEDROCK_SMOKE_MODEL",
        "anthropic.claude-3-haiku-20240307-v1:0",
    );
    let session_token = std::env::var("AWS_SESSION_TOKEN").is_ok();
    let proxy = LiveProxy::spawn("bedrock", |port| {
        bedrock_config(port, &region, &model, session_token)
    });

    let body = json!({
        "model": "smoke-bedrock",
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with exactly one short word."}],
    });
    let res = proxy.send("/v1/messages", &body).await;

    assert_anthropic_message(&res, "Bedrock");
    assert_record_names_provider_with_usage(&proxy.access_log_entry().await, "provider:bedrock");
}

fn assert_anthropic_message(res: &RawResponse, provider: &str) {
    assert_eq!(
        res.status, 200,
        "expected 200 from {provider} through the proxy, got {}: {}",
        res.status, res.body
    );
    let parsed: Value = serde_json::from_str(&res.body)
        .unwrap_or_else(|e| panic!("{provider} response body must be JSON ({e}): {}", res.body));
    let content = parsed["content"][0]["text"].as_str().unwrap_or_default();
    assert!(
        !content.trim().is_empty(),
        "expected non-empty assistant content, got: {parsed}"
    );
}

// ------------------------------------------------------- OpenAI, Anthropic --

/// `openai` and `anthropic` are inferred from the provider name, with their
/// default base URLs.
fn named_provider_config(port: u16, provider: &str, key_var: &str, pattern: &str) -> String {
    format!(
        r#"
version: 0
listen: "127.0.0.1:{port}"
providers:
  {provider}:
    api_key: ${{{key_var}}}
routes:
  - model: "{pattern}"
    provider: {provider}
"#
    )
}

fn openai_proxy(label: &str) -> LiveProxy {
    LiveProxy::spawn(label, |port| {
        named_provider_config(port, "openai", "OPENAI_API_KEY", "gpt-*")
    })
}

fn anthropic_proxy(label: &str) -> LiveProxy {
    LiveProxy::spawn(label, |port| {
        named_provider_config(port, "anthropic", "ANTHROPIC_API_KEY", "claude-*")
    })
}

/// Proves: a non-streaming `chat/completions` request through the proxy
/// reaches the real OpenAI API and comes back with an intact 200 JSON body
/// -- a choice with non-empty assistant content, and the requested model
/// echoed.
#[tokio::test]
#[ignore = "hits the real OpenAI API and bills tokens; run with make smoke-live"]
async fn openai_non_streaming_chat_completion_round_trips_through_the_proxy() {
    let test = "openai_non_streaming_chat_completion_round_trips_through_the_proxy";
    if !live_env(test, &["OPENAI_API_KEY"]) {
        return;
    }
    let proxy = openai_proxy("openai-non-streaming");

    let body = json!({
        "model": "gpt-4o-mini",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with exactly one short word."}],
    });
    let res = proxy.send("/v1/chat/completions", &body).await;

    assert_eq!(
        res.status, 200,
        "expected 200 from the real OpenAI API through the proxy, got {}: {}",
        res.status, res.body
    );
    assert!(
        header_contains(&res.headers, "content-type", "application/json"),
        "expected a JSON content-type forwarded from OpenAI, got: {:?}",
        res.headers
    );
    let parsed: Value =
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
}

/// Proves: a streamed (`"stream": true`) request through the proxy delivers
/// real incremental SSE frames from OpenAI as they arrive rather than
/// buffering the whole response -- more than one frame, `[DONE]` last, and
/// (the load-bearing assertion) the first frame shows up well before the
/// stream as a whole finishes.
#[tokio::test]
#[ignore = "hits the real OpenAI API and bills tokens; run with make smoke-live"]
async fn openai_streaming_chat_completion_delivers_incremental_sse_frames() {
    let test = "openai_streaming_chat_completion_delivers_incremental_sse_frames";
    if !live_env(test, &["OPENAI_API_KEY"]) {
        return;
    }
    let proxy = openai_proxy("openai-streaming");

    let body = json!({
        "model": "gpt-4o-mini",
        "max_tokens": 24,
        "messages": [{"role": "user", "content": "Count from one to five, one number per word."}],
        "stream": true,
    });
    let (status, headers, events) = proxy.send_sse("/v1/chat/completions", &body).await;

    assert_eq!(status, 200, "expected 200 from the real OpenAI API");
    assert!(
        header_contains(&headers, "content-type", "text/event-stream"),
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
    // At least one frame must carry an incremental content delta -- proves
    // the proxy forwarded token-by-token deltas, not just a role
    // announcement followed immediately by [DONE].
    assert!(
        !openai_stream_text(&events).is_empty(),
        "expected at least one SSE frame with an incremental content delta"
    );
    assert_first_frame_early(&events);
}

/// Proves: a non-streaming `/v1/messages` request through the proxy reaches
/// the real Anthropic API and comes back with an intact 200 JSON body -- a
/// text content block and a `usage` object.
#[tokio::test]
#[ignore = "hits the real Anthropic API and bills tokens; run with make smoke-live"]
async fn anthropic_non_streaming_message_round_trips_through_the_proxy() {
    let test = "anthropic_non_streaming_message_round_trips_through_the_proxy";
    if !live_env(test, &["ANTHROPIC_API_KEY"]) {
        return;
    }
    let proxy = anthropic_proxy("anthropic-non-streaming");

    let body = json!({
        "model": "claude-3-5-haiku-latest",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with exactly one short word."}],
    });
    let res = proxy.send("/v1/messages", &body).await;

    assert_anthropic_message(&res, "Anthropic");
    let parsed: Value = serde_json::from_str(&res.body).unwrap();
    assert_eq!(parsed["type"], "message");
    assert!(
        parsed["usage"]["input_tokens"].is_u64() && parsed["usage"]["output_tokens"].is_u64(),
        "expected a numeric usage.input_tokens/output_tokens, got: {}",
        parsed["usage"]
    );
}

/// Proves: a streamed `/v1/messages` request through the proxy delivers
/// real incremental SSE frames from Anthropic as they arrive -- opening
/// with `message_start`, ending with `message_stop`, with at least one
/// `content_block_delta` in between, and (the load-bearing assertion) the
/// first frame shows up well before the stream as a whole finishes.
#[tokio::test]
#[ignore = "hits the real Anthropic API and bills tokens; run with make smoke-live"]
async fn anthropic_streaming_message_delivers_incremental_sse_frames() {
    let test = "anthropic_streaming_message_delivers_incremental_sse_frames";
    if !live_env(test, &["ANTHROPIC_API_KEY"]) {
        return;
    }
    let proxy = anthropic_proxy("anthropic-streaming");

    let body = json!({
        "model": "claude-3-5-haiku-latest",
        "max_tokens": 24,
        "messages": [{"role": "user", "content": "Count from one to five, one number per word."}],
        "stream": true,
    });
    let (status, headers, events) = proxy.send_sse("/v1/messages", &body).await;

    assert_eq!(status, 200, "expected 200 from the real Anthropic API");
    assert!(
        header_contains(&headers, "content-type", "text/event-stream"),
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
    assert_first_frame_early(&events);
}
