//! `anthropic`: an Anthropic-Messages-compatible mock upstream (`POST
//! /v1/messages`), the Anthropic-dialect sibling of `openai`'s chat
//! completions mock. It exists for the same LLM feature lanes (streaming
//! metrics, token metering, model routing) and mirrors
//! `openai.rs`'s structure closely, but gets several wire details
//! deliberately different to match the real API:
//!
//! - Auth is `x-api-key: <key>` (not `authorization: Bearer <key>`).
//! - The non-streaming response envelope is `{"type":"message", ...}`, not
//!   `{"object":"chat.completion", ...}`.
//! - Errors are `{"type":"error","error":{"type":..,"message":..}}`.
//! - Streaming is a sequence of *named* SSE events (`event:` + `data:` per
//!   frame), not the data-only frames OpenAI chat completions uses, and usage
//!   is split across two event types (`message_start` for input tokens,
//!   `message_delta` for a *cumulative* output token count) — see
//!   `crates/proxy-filters/src/usage.rs`'s `Dialect::Anthropic` handling,
//!   which this mock is built to match exactly.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use serde::Deserialize;
use serde_json::json;

use super::tls_support::{serve_tls, MockTls, TlsServerHandle};
use super::{record_request_with_body, serve, RequestLog, ResponseBody, ServerHandle};

/// How the mock upstream should behave for every request it serves.
#[derive(Debug, Clone)]
pub struct AnthropicConfig {
    /// Model name echoed back on `/v1/messages` responses (real Anthropic
    /// responses report back whatever `model` the request asked for).
    pub model: String,
    /// The canned assistant reply. Split on whitespace to produce the
    /// per-chunk `content_block_delta` tokens when streaming.
    pub response_text: String,
    /// Delay before the first streamed event (time-to-first-token), applied
    /// to `message_start` — nothing is emitted before it, mirroring a real
    /// provider that stays silent until generation starts.
    pub ttft: Duration,
    /// Delay between subsequent `content_block_delta` events.
    pub inter_token_delay: Duration,
    /// When set, requests must send `x-api-key: <key>` or get a 401
    /// Anthropic-style error envelope.
    pub require_api_key: Option<String>,
    /// When set, every request gets this `(status, message)` back instead of
    /// being handled normally — for retry/fallback drills.
    pub forced_error: Option<(u16, String)>,
    /// Cache-read input tokens to report in `usage.cache_read_input_tokens`
    /// (a discounted subset served from Anthropic's prompt cache — unlike
    /// OpenAI, Anthropic's `input_tokens` already excludes this, so it is
    /// *not* folded into the input count). Defaults to 0 in scenario files;
    /// set nonzero to drive that cost bucket in metering tests (see
    /// `crates/proxy-filters/src/usage.rs`).
    pub cache_read_tokens: u64,
    /// Cache-write input tokens to report in
    /// `usage.cache_creation_input_tokens` (Anthropic-only cost bucket;
    /// OpenAI has no equivalent).
    pub cache_creation_tokens: u64,
}

/// Thread-safe, append-only log of parsed `/v1/messages` request bodies —
/// the Anthropic-dialect twin of `openai::ChatRequestLog`.
#[derive(Debug, Clone, Default)]
pub struct MessagesRequestLog(Arc<Mutex<Vec<serde_json::Value>>>);

impl MessagesRequestLog {
    pub fn new() -> Self {
        Self::default()
    }

    fn record(&self, body: serde_json::Value) {
        self.0
            .lock()
            .expect("messages request log mutex poisoned")
            .push(body);
    }

    /// Snapshot of every parsed `/v1/messages` request body received so far,
    /// in arrival order.
    pub fn bodies(&self) -> Vec<serde_json::Value> {
        self.0
            .lock()
            .expect("messages request log mutex poisoned")
            .clone()
    }
}

/// Either a plaintext accept loop (`spawn`) or a TLS-terminating one
/// (`spawn_tls`) — see `openai::Handle` for the same shape and rationale.
enum Handle {
    Plain(ServerHandle),
    Tls(TlsServerHandle),
}

pub struct AnthropicUpstream {
    pub log: RequestLog,
    pub bodies: MessagesRequestLog,
    handle: Handle,
}

impl AnthropicUpstream {
    /// Only valid for a plaintext (`spawn`) upstream — see
    /// `openai::OpenAiUpstream::addr`.
    pub fn addr(&self) -> SocketAddr {
        match &self.handle {
            Handle::Plain(h) => h.addr,
            Handle::Tls(_) => {
                panic!("AnthropicUpstream::addr() is not meaningful for a TLS upstream; use port()")
            }
        }
    }

    pub fn port(&self) -> u16 {
        match &self.handle {
            Handle::Plain(h) => h.addr.port(),
            Handle::Tls(h) => h.port,
        }
    }

    pub async fn spawn(config: AnthropicConfig) -> anyhow::Result<Self> {
        let log = RequestLog::new();
        let bodies = MessagesRequestLog::new();
        let log_for_handler = log.clone();
        let bodies_for_handler = bodies.clone();
        let config = Arc::new(config);
        // Rust note: shared, monotonically increasing message ids across
        // every connection this upstream serves; `Ordering::Relaxed` is fine
        // since we only need uniqueness, not synchronization with anything
        // else — same reasoning as `openai::OpenAiUpstream::spawn`.
        let next_id = Arc::new(AtomicU64::new(1));
        let handle = Handle::Plain(
            serve(move |req: Request<Incoming>| {
                let log = log_for_handler.clone();
                let bodies = bodies_for_handler.clone();
                let config = Arc::clone(&config);
                let next_id = Arc::clone(&next_id);
                async move { Ok(handle_anthropic(req, &log, &bodies, &config, &next_id).await) }
            })
            .await?,
        );
        Ok(Self {
            log,
            bodies,
            handle,
        })
    }

    /// The TLS-capable twin of `spawn` — see
    /// `openai::OpenAiUpstream::spawn_tls`.
    pub async fn spawn_tls(config: AnthropicConfig, tls: &MockTls) -> anyhow::Result<Self> {
        let log = RequestLog::new();
        let bodies = MessagesRequestLog::new();
        let log_for_handler = log.clone();
        let bodies_for_handler = bodies.clone();
        let config = Arc::new(config);
        let next_id = Arc::new(AtomicU64::new(1));
        let handle = Handle::Tls(
            serve_tls(
                move |req: Request<Incoming>| {
                    let log = log_for_handler.clone();
                    let bodies = bodies_for_handler.clone();
                    let config = Arc::clone(&config);
                    let next_id = Arc::clone(&next_id);
                    async move { Ok(handle_anthropic(req, &log, &bodies, &config, &next_id).await) }
                },
                tls,
            )
            .await?,
        );
        Ok(Self {
            log,
            bodies,
            handle,
        })
    }

    pub async fn shutdown(self) {
        match self.handle {
            Handle::Plain(h) => h.shutdown().await,
            Handle::Tls(h) => h.shutdown().await,
        }
    }
}

/// Request shape we care about; anything else in the body is ignored here —
/// this is a test double, not a config surface (see `openai::ChatCompletionRequest`
/// for the same reasoning).
#[derive(Debug, Deserialize)]
struct MessagesRequest {
    model: String,
    #[serde(default)]
    messages: Vec<AnthropicMessage>,
    #[serde(default)]
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct AnthropicMessage {
    #[serde(default)]
    #[allow(dead_code)]
    role: String,
    #[serde(default)]
    content: MessageContent,
}

/// Anthropic message content may be a bare string or a list of typed content
/// blocks (`{"type":"text","text":"..."}`, among others we don't need to
/// understand here).
///
/// Rust note: `#[serde(untagged)]` tries `Text` (a JSON string) before
/// `Blocks` (a JSON array); see `openai::ResponsesInput` for the same shape.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum MessageContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

impl Default for MessageContent {
    fn default() -> Self {
        MessageContent::Text(String::new())
    }
}

impl MessageContent {
    fn whitespace_tokens(&self) -> usize {
        match self {
            MessageContent::Text(text) => whitespace_tokens(text),
            MessageContent::Blocks(blocks) => {
                blocks.iter().map(|b| whitespace_tokens(&b.text)).sum()
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    #[serde(default)]
    #[allow(dead_code)]
    r#type: String,
    #[serde(default)]
    text: String,
}

async fn handle_anthropic(
    req: Request<Incoming>,
    log: &RequestLog,
    bodies: &MessagesRequestLog,
    config: &AnthropicConfig,
    next_id: &Arc<AtomicU64>,
) -> Response<ResponseBody> {
    let (recorded, body_bytes) = record_request_with_body(req, log).await;

    if let Some((status, message)) = &config.forced_error {
        return error_response(*status, message, "api_error");
    }

    if let Some(expected_key) = &config.require_api_key {
        let authorized = recorded
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-api-key") && value == expected_key);
        if !authorized {
            return error_response(401, "invalid x-api-key", "authentication_error");
        }
    }

    // Rust note: strip a query string before matching, same as
    // `openai::handle_openai` does.
    let path = recorded
        .path
        .split('?')
        .next()
        .unwrap_or(&recorded.path)
        .to_string();

    match (recorded.method.as_str(), path.as_str()) {
        ("POST", "/v1/messages") => handle_messages(body_bytes, bodies, config, next_id),
        _ => error_response(
            404,
            &format!("Unknown endpoint: {} {}", recorded.method, recorded.path),
            "not_found_error",
        ),
    }
}

fn handle_messages(
    body_bytes: Bytes,
    bodies: &MessagesRequestLog,
    config: &AnthropicConfig,
    next_id: &Arc<AtomicU64>,
) -> Response<ResponseBody> {
    let value: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(e) => {
            return error_response(
                400,
                &format!("Invalid JSON in request body: {e}"),
                "invalid_request_error",
            )
        }
    };
    let parsed: MessagesRequest = match serde_json::from_value(value.clone()) {
        Ok(parsed) => parsed,
        Err(e) => {
            return error_response(
                400,
                &format!("Invalid messages request: {e}"),
                "invalid_request_error",
            )
        }
    };
    bodies.record(value);

    let id = format!("msg_{}", next_id.fetch_add(1, Ordering::Relaxed));
    // Anthropic's `input_tokens` already excludes cache reads/writes — unlike
    // OpenAI's `prompt_tokens`, no cache amount gets folded in here.
    let input_tokens: usize = parsed
        .messages
        .iter()
        .map(|m| m.content.whitespace_tokens())
        .sum();
    let output_tokens = whitespace_tokens(&config.response_text);

    if parsed.stream {
        streaming_response(&id, &parsed.model, config, input_tokens, output_tokens)
    } else {
        let body = json!({
            "id": id,
            "type": "message",
            "role": "assistant",
            "model": parsed.model,
            "content": [{ "type": "text", "text": config.response_text }],
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {
                "input_tokens": input_tokens,
                "cache_creation_input_tokens": config.cache_creation_tokens,
                "cache_read_input_tokens": config.cache_read_tokens,
                "output_tokens": output_tokens,
            },
        });
        json_response(200, &body)
    }
}

/// Paced SSE for `/v1/messages`, matching the real event sequence:
/// `message_start` (carries input/cache usage) → `content_block_start` →
/// repeated `content_block_delta` → `content_block_stop` → `message_delta`
/// (carries the *cumulative* output token count) → `message_stop`.
fn streaming_response(
    id: &str,
    model: &str,
    config: &AnthropicConfig,
    input_tokens: usize,
    output_tokens: usize,
) -> Response<ResponseBody> {
    let tokens: Vec<&str> = config.response_text.split_whitespace().collect();
    let mut frames: Vec<(Duration, String)> = Vec::new();

    // TTFT gates the very first event, same reasoning as
    // `openai::streaming_response`'s role-delta frame.
    frames.push((
        config.ttft,
        super::sse_named_frame(
            "message_start",
            &json!({
                "type": "message_start",
                "message": {
                    "id": id,
                    "type": "message",
                    "role": "assistant",
                    "model": model,
                    "content": [],
                    "stop_reason": null,
                    "stop_sequence": null,
                    "usage": {
                        "input_tokens": input_tokens,
                        "cache_creation_input_tokens": config.cache_creation_tokens,
                        "cache_read_input_tokens": config.cache_read_tokens,
                        "output_tokens": 0,
                    },
                },
            })
            .to_string(),
        ),
    ));

    frames.push((
        Duration::ZERO,
        super::sse_named_frame(
            "content_block_start",
            &json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": { "type": "text", "text": "" },
            })
            .to_string(),
        ),
    ));

    for (i, token) in tokens.iter().enumerate() {
        let delay = if i == 0 {
            Duration::ZERO
        } else {
            config.inter_token_delay
        };
        let text = if i == 0 {
            (*token).to_string()
        } else {
            format!(" {token}")
        };
        frames.push((
            delay,
            super::sse_named_frame(
                "content_block_delta",
                &json!({
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": { "type": "text_delta", "text": text },
                })
                .to_string(),
            ),
        ));
    }

    frames.push((
        Duration::ZERO,
        super::sse_named_frame(
            "content_block_stop",
            &json!({ "type": "content_block_stop", "index": 0 }).to_string(),
        ),
    ));

    frames.push((
        Duration::ZERO,
        super::sse_named_frame(
            "message_delta",
            &json!({
                "type": "message_delta",
                "delta": { "stop_reason": "end_turn", "stop_sequence": null },
                // Cumulative, not incremental — the real API sends the total
                // output-token count so far, not a per-chunk delta. `usage.rs`
                // relies on exactly this ("last message_delta wins").
                "usage": { "output_tokens": output_tokens },
            })
            .to_string(),
        ),
    ));

    frames.push((
        Duration::ZERO,
        super::sse_named_frame(
            "message_stop",
            &json!({ "type": "message_stop" }).to_string(),
        ),
    ));

    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(super::paced_sse_body(frames))
        .expect("response built from known-valid parts")
}

fn error_response(status: u16, message: &str, error_type: &str) -> Response<ResponseBody> {
    let body = json!({
        "type": "error",
        "error": {
            "type": error_type,
            "message": message,
        },
    });
    json_response(status, &body)
}

fn json_response(status: u16, body: &serde_json::Value) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())).boxed())
        .expect("response built from known-valid parts")
}

fn whitespace_tokens(text: &str) -> usize {
    text.split_whitespace().count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Test-only HTTP client helpers, identical in shape to
    /// `openai::tests::test_support` (see that module for the rationale):
    /// send a JSON body, optionally collect a paced SSE stream with
    /// per-event timestamps.
    mod test_support {
        use bytes::Bytes;
        use http_body_util::{BodyExt, Full};
        use hyper::client::conn::http1;
        use hyper::Request;
        use hyper_util::rt::TokioIo;
        use std::net::SocketAddr;
        use std::time::{Duration, Instant};
        use tokio::net::TcpStream;

        pub struct RawResponse {
            pub status: u16,
            pub body: String,
        }

        pub async fn send_json(
            addr: SocketAddr,
            method: &str,
            path: &str,
            headers: &[(&str, &str)],
            json_body: &serde_json::Value,
        ) -> anyhow::Result<RawResponse> {
            let stream = TcpStream::connect(addr).await?;
            let io = TokioIo::new(stream);
            let (mut sender, conn) = http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });

            let mut builder = Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json");
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            let req = builder.body(Full::new(Bytes::from(json_body.to_string())))?;

            let res = sender.send_request(req).await?;
            let status = res.status().as_u16();
            let body_bytes = res.into_body().collect().await?.to_bytes();
            let body = String::from_utf8_lossy(&body_bytes).to_string();

            Ok(RawResponse { status, body })
        }

        /// One SSE event (the `event:`/`data:` pair with the trailing blank
        /// line stripped), timestamped relative to when the request was sent.
        pub struct TimedEvent {
            pub at: Duration,
            pub data: String,
        }

        pub async fn send_json_collect_sse(
            addr: SocketAddr,
            method: &str,
            path: &str,
            headers: &[(&str, &str)],
            json_body: &serde_json::Value,
        ) -> anyhow::Result<(u16, Vec<TimedEvent>)> {
            let stream = TcpStream::connect(addr).await?;
            let io = TokioIo::new(stream);
            let (mut sender, conn) = http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });

            let mut builder = Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json");
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            let req = builder.body(Full::new(Bytes::from(json_body.to_string())))?;

            let started = Instant::now();
            let res = sender.send_request(req).await?;
            let status = res.status().as_u16();
            let mut body = res.into_body();

            let mut events = Vec::new();
            let mut pending = String::new();
            while let Some(frame) = body.frame().await {
                let frame = frame?;
                if let Some(data) = frame.data_ref() {
                    pending.push_str(&String::from_utf8_lossy(data));
                    while let Some(pos) = pending.find("\n\n") {
                        let event = pending[..pos].to_string();
                        pending = pending.split_off(pos + 2);
                        events.push(TimedEvent {
                            at: started.elapsed(),
                            data: event,
                        });
                    }
                }
            }
            Ok((status, events))
        }
    }

    fn base_config() -> AnthropicConfig {
        AnthropicConfig {
            model: "mock-claude".to_string(),
            response_text: "hello there friend".to_string(),
            ttft: Duration::from_millis(10),
            inter_token_delay: Duration::from_millis(5),
            require_api_key: None,
            forced_error: None,
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
        }
    }

    #[tokio::test]
    async fn non_streaming_returns_message_with_usage_and_records_body() {
        let upstream = AnthropicUpstream::spawn(base_config())
            .await
            .expect("spawn anthropic");

        let body = json!({
            "model": "mock-claude",
            "messages": [{"role": "user", "content": "hi there"}],
            "max_tokens": 100,
        });
        let res = test_support::send_json(upstream.addr(), "POST", "/v1/messages", &[], &body)
            .await
            .expect("request should succeed");

        assert_eq!(res.status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json body");
        assert_eq!(parsed["type"], "message");
        assert_eq!(parsed["role"], "assistant");
        assert_eq!(parsed["model"], "mock-claude");
        assert_eq!(parsed["content"][0]["type"], "text");
        assert_eq!(parsed["content"][0]["text"], "hello there friend");
        assert_eq!(parsed["stop_reason"], "end_turn");
        assert_eq!(parsed["usage"]["input_tokens"], 2);
        assert_eq!(parsed["usage"]["output_tokens"], 3);
        assert_eq!(parsed["usage"]["cache_read_input_tokens"], 0);
        assert_eq!(parsed["usage"]["cache_creation_input_tokens"], 0);

        let captured = upstream.bodies.bodies();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0]["model"], "mock-claude");

        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn non_streaming_reports_configured_cache_token_buckets() {
        let mut config = base_config();
        config.cache_read_tokens = 40;
        config.cache_creation_tokens = 15;
        let upstream = AnthropicUpstream::spawn(config)
            .await
            .expect("spawn anthropic");

        let body = json!({
            "model": "mock-claude",
            "messages": [{"role": "user", "content": "hi there"}],
        });
        let res = test_support::send_json(upstream.addr(), "POST", "/v1/messages", &[], &body)
            .await
            .expect("request should succeed");

        let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json body");
        assert_eq!(
            parsed["usage"]["input_tokens"], 2,
            "excludes cache, unlike OpenAI"
        );
        assert_eq!(parsed["usage"]["cache_read_input_tokens"], 40);
        assert_eq!(parsed["usage"]["cache_creation_input_tokens"], 15);

        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn streaming_emits_the_full_anthropic_event_sequence_in_order() {
        let ttft = Duration::from_millis(40);
        let inter_token_delay = Duration::from_millis(20);
        let mut config = base_config();
        config.response_text = "a b c".to_string();
        config.ttft = ttft;
        config.inter_token_delay = inter_token_delay;
        let upstream = AnthropicUpstream::spawn(config)
            .await
            .expect("spawn anthropic");

        let body = json!({
            "model": "mock-claude",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true,
        });

        let (status, events) = test_support::send_json_collect_sse(
            upstream.addr(),
            "POST",
            "/v1/messages",
            &[],
            &body,
        )
        .await
        .expect("request should succeed");
        assert_eq!(status, 200);

        // message_start, content_block_start, 3x content_block_delta,
        // content_block_stop, message_delta, message_stop.
        assert_eq!(
            events.len(),
            8,
            "unexpected event count: {:?}",
            events.iter().map(|e| &e.data).collect::<Vec<_>>()
        );
        assert!(events[0].data.contains("event: message_start"));
        assert!(events[0].data.contains("\"input_tokens\":1"));
        assert!(events[1].data.contains("event: content_block_start"));
        for event in &events[2..=4] {
            assert!(event.data.contains("event: content_block_delta"));
            assert!(event.data.contains("\"text_delta\""));
        }
        assert!(events[5].data.contains("event: content_block_stop"));
        assert!(events[6].data.contains("event: message_delta"));
        assert!(events[6].data.contains("\"output_tokens\":3"));
        assert!(events[7].data.contains("event: message_stop"));

        assert!(
            events[0].at >= ttft,
            "message_start must not arrive before ttft ({ttft:?}), got {:?}",
            events[0].at
        );
        assert!(
            events[2].at >= ttft,
            "first content delta gated by ttft too"
        );

        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn require_api_key_rejects_missing_or_wrong_key() {
        let mut config = base_config();
        config.require_api_key = Some("secret-key".to_string());
        let upstream = AnthropicUpstream::spawn(config)
            .await
            .expect("spawn anthropic");
        let body = json!({"model": "mock-claude", "messages": [{"role": "user", "content": "hi"}]});

        let unauthorized =
            test_support::send_json(upstream.addr(), "POST", "/v1/messages", &[], &body)
                .await
                .expect("request should succeed");
        assert_eq!(unauthorized.status, 401);
        let err: serde_json::Value =
            serde_json::from_str(&unauthorized.body).expect("valid json body");
        assert_eq!(err["type"], "error");
        assert_eq!(err["error"]["type"], "authentication_error");

        // Wrong auth-header shape (OpenAI's `authorization: Bearer`) must
        // also be rejected — Anthropic wants `x-api-key` specifically.
        let wrong_header_shape = test_support::send_json(
            upstream.addr(),
            "POST",
            "/v1/messages",
            &[("authorization", "Bearer secret-key")],
            &body,
        )
        .await
        .expect("request should succeed");
        assert_eq!(wrong_header_shape.status, 401);

        let authorized = test_support::send_json(
            upstream.addr(),
            "POST",
            "/v1/messages",
            &[("x-api-key", "secret-key")],
            &body,
        )
        .await
        .expect("request should succeed");
        assert_eq!(authorized.status, 200);

        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn forced_error_overrides_every_request() {
        let mut config = base_config();
        config.forced_error = Some((503, "upstream overloaded".to_string()));
        let upstream = AnthropicUpstream::spawn(config)
            .await
            .expect("spawn anthropic");
        let body = json!({"model": "mock-claude", "messages": []});

        let res = test_support::send_json(upstream.addr(), "POST", "/v1/messages", &[], &body)
            .await
            .expect("request should succeed");
        assert_eq!(res.status, 503);
        let err: serde_json::Value = serde_json::from_str(&res.body).expect("valid json body");
        assert_eq!(err["type"], "error");
        assert_eq!(err["error"]["message"], "upstream overloaded");

        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn malformed_json_body_returns_400() {
        let upstream = AnthropicUpstream::spawn(base_config())
            .await
            .expect("spawn anthropic");

        let stream = tokio::net::TcpStream::connect(upstream.addr())
            .await
            .expect("connect");
        use http_body_util::BodyExt;
        use hyper::client::conn::http1;
        use hyper_util::rt::TokioIo;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io).await.expect("handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header("content-type", "application/json")
            .body(http_body_util::Full::new(Bytes::from_static(b"{ not json")))
            .expect("request built");
        let response = sender.send_request(req).await.expect("send request");
        assert_eq!(response.status().as_u16(), 400);
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect")
            .to_bytes();
        let err: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("error body is json");
        assert_eq!(err["error"]["type"], "invalid_request_error");

        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let upstream = AnthropicUpstream::spawn(base_config())
            .await
            .expect("spawn anthropic");

        let res = test_support::send_json(upstream.addr(), "GET", "/v1/nope", &[], &json!({}))
            .await
            .expect("request should succeed");
        assert_eq!(res.status, 404);
        let err: serde_json::Value = serde_json::from_str(&res.body).expect("valid json body");
        assert_eq!(err["type"], "error");
        assert_eq!(err["error"]["type"], "not_found_error");

        upstream.shutdown().await;
    }
}
