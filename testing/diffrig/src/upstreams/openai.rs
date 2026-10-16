//! OpenAI-compatible mock upstream for `/v1/chat/completions`. It returns JSON
//! or paced SSE and records parsed request bodies for forwarding assertions.

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
pub struct OpenAiConfig {
    /// Model name reported by `GET /v1/models`. Chat completion responses
    /// instead echo back whatever `model` the request asked for, matching
    /// real providers.
    pub model: String,
    /// The canned assistant reply. Split on whitespace to produce the
    /// per-chunk `delta.content` tokens when streaming.
    pub response_text: String,
    /// Delay before the first streamed chunk (time-to-first-token). Applied
    /// to the leading role-delta chunk: real providers emit nothing at all
    /// until generation starts, so a proxy measuring TTFT at first-event
    /// arrival must observe this delay.
    pub ttft: Duration,
    /// Delay between subsequent streamed content chunks.
    pub inter_token_delay: Duration,
    /// When set, requests must send `authorization: Bearer <key>` or get a
    /// 401 OpenAI-style error.
    pub require_api_key: Option<String>,
    /// When set, every request gets this `(status, message)` back instead of
    /// being handled normally — for retry/fallback drills.
    pub forced_error: Option<(u16, String)>,
    /// Cache-read tokens to report as a subset of `prompt_tokens`, under
    /// `usage.prompt_tokens_details.cached_tokens`. Defaults to 0 in scenario
    /// files; set nonzero to drive the cached-token cost bucket in metering
    /// tests (see `crates/proxy-filters/src/usage.rs`, which reads
    /// `input_tokens` as `prompt_tokens - cached_tokens`). `prompt_tokens`
    /// itself is inflated by this amount, matching real OpenAI responses
    /// where `prompt_tokens` is inclusive of the cached portion.
    pub cached_tokens: u64,
}

/// Thread-safe, append-only log of parsed `/v1/chat/completions` request
/// bodies, so tests can assert on what a proxy forwarded (model, messages,
/// stream flags) without re-parsing raw bytes themselves.
///
/// Rust note: same `Arc<Mutex<Vec<_>>>` shape as `RequestLog` in `mod.rs`,
/// just holding `serde_json::Value` instead of `RecordedRequest` — kept
/// local to this module since only the `openai` upstream understands request
/// bodies as JSON.
#[derive(Debug, Clone, Default)]
pub struct ChatRequestLog(Arc<Mutex<Vec<serde_json::Value>>>);

impl ChatRequestLog {
    pub fn new() -> Self {
        Self::default()
    }

    fn record(&self, body: serde_json::Value) {
        self.0
            .lock()
            .expect("chat request log mutex poisoned")
            .push(body);
    }

    /// Snapshot of every parsed chat-completion request body received so
    /// far, in arrival order.
    pub fn bodies(&self) -> Vec<serde_json::Value> {
        self.0
            .lock()
            .expect("chat request log mutex poisoned")
            .clone()
    }
}

/// Either a plaintext accept loop (`spawn`) or a TLS-terminating one
/// (`spawn_tls`) -- see `spawn_tls`'s doc comment for why the TLS variant
/// carries a bare port rather than a single `SocketAddr` (it listens on both
/// loopback address families).
enum Handle {
    Plain(ServerHandle),
    Tls(TlsServerHandle),
}

pub struct OpenAiUpstream {
    pub log: RequestLog,
    pub bodies: ChatRequestLog,
    handle: Handle,
}

impl OpenAiUpstream {
    /// Only valid for a plaintext (`spawn`) upstream -- a TLS upstream
    /// listens on two address families at the same port, so callers should
    /// use [`Self::port`] and dial it by hostname instead.
    pub fn addr(&self) -> SocketAddr {
        match &self.handle {
            Handle::Plain(h) => h.addr,
            Handle::Tls(_) => {
                panic!("OpenAiUpstream::addr() is not meaningful for a TLS upstream; use port()")
            }
        }
    }

    pub fn port(&self) -> u16 {
        match &self.handle {
            Handle::Plain(h) => h.addr.port(),
            Handle::Tls(h) => h.port,
        }
    }

    pub async fn spawn(config: OpenAiConfig) -> anyhow::Result<Self> {
        let log = RequestLog::new();
        let bodies = ChatRequestLog::new();
        let log_for_handler = log.clone();
        let bodies_for_handler = bodies.clone();
        let config = Arc::new(config);
        // Rust note: shared, monotonically increasing completion ids across
        // every connection this upstream serves; `Ordering::Relaxed` is fine
        // since we only need uniqueness, not synchronization with anything
        // else.
        let next_id = Arc::new(AtomicU64::new(1));
        let handle = Handle::Plain(
            serve(move |req: Request<Incoming>| {
                let log = log_for_handler.clone();
                let bodies = bodies_for_handler.clone();
                let config = Arc::clone(&config);
                let next_id = Arc::clone(&next_id);
                async move { Ok(handle_openai(req, &log, &bodies, &config, &next_id).await) }
            })
            .await?,
        );
        Ok(Self {
            log,
            bodies,
            handle,
        })
    }

    /// The TLS-capable twin of `spawn`: serves the same
    /// chat-completions/responses handler behind `tls`'s minted certificate,
    /// for the hermetic upstream-TLS end-to-end test. Bound on both
    /// loopback address families at one port -- see [`TlsServerHandle`]'s
    /// doc comment for why.
    pub async fn spawn_tls(config: OpenAiConfig, tls: &MockTls) -> anyhow::Result<Self> {
        let log = RequestLog::new();
        let bodies = ChatRequestLog::new();
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
                    async move { Ok(handle_openai(req, &log, &bodies, &config, &next_id).await) }
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

/// Request shape we care about; anything else in the body is ignored here
/// (this is a test double, not a config surface — the strict "every field
/// maps or errors" rule applies to *our* config, not to mimicking a
/// third-party API schema).
#[derive(Debug, Deserialize)]
struct ChatCompletionRequest {
    model: String,
    #[serde(default)]
    messages: Vec<ChatMessage>,
    #[serde(default)]
    stream: bool,
    #[serde(default)]
    stream_options: Option<StreamOptions>,
}

#[derive(Debug, Deserialize)]
struct ChatMessage {
    #[serde(default)]
    #[allow(dead_code)]
    role: String,
    #[serde(default)]
    content: String,
}

#[derive(Debug, Deserialize)]
struct StreamOptions {
    #[serde(default)]
    include_usage: bool,
}

async fn handle_openai(
    req: Request<Incoming>,
    log: &RequestLog,
    bodies: &ChatRequestLog,
    config: &OpenAiConfig,
    next_id: &Arc<AtomicU64>,
) -> Response<ResponseBody> {
    let (recorded, body_bytes) = record_request_with_body(req, log).await;

    if let Some((status, message)) = &config.forced_error {
        return error_response(*status, message, "mock_forced_error", None);
    }

    if let Some(expected_key) = &config.require_api_key {
        let expected_header = format!("Bearer {expected_key}");
        let authorized = recorded.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("authorization") && value == &expected_header
        });
        if !authorized {
            return error_response(
                401,
                "Incorrect API key provided",
                "invalid_request_error",
                Some("invalid_api_key"),
            );
        }
    }

    // Rust note: strip a query string before matching, same as the path the
    // client sent could include one (`RecordedRequest::path` keeps it).
    let path = recorded
        .path
        .split('?')
        .next()
        .unwrap_or(&recorded.path)
        .to_string();

    match (recorded.method.as_str(), path.as_str()) {
        ("POST", "/v1/chat/completions") => {
            handle_chat_completions(body_bytes, bodies, config, next_id)
        }
        ("POST", "/v1/responses") => handle_responses(body_bytes, bodies, config, next_id),
        ("GET", "/v1/models") => models_response(config),
        _ => error_response(
            404,
            &format!("Unknown endpoint: {} {}", recorded.method, recorded.path),
            "invalid_request_error",
            Some("not_found"),
        ),
    }
}

fn handle_chat_completions(
    body_bytes: Bytes,
    bodies: &ChatRequestLog,
    config: &OpenAiConfig,
    next_id: &Arc<AtomicU64>,
) -> Response<ResponseBody> {
    let value: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(e) => {
            return error_response(
                400,
                &format!("Invalid JSON in request body: {e}"),
                "invalid_request_error",
                Some("invalid_json"),
            )
        }
    };
    let parsed: ChatCompletionRequest = match serde_json::from_value(value.clone()) {
        Ok(parsed) => parsed,
        Err(e) => {
            return error_response(
                400,
                &format!("Invalid chat completion request: {e}"),
                "invalid_request_error",
                Some("invalid_body"),
            )
        }
    };
    bodies.record(value);

    let id = format!("chatcmpl-{}", next_id.fetch_add(1, Ordering::Relaxed));
    let created = now_unix();
    let completion_tokens = whitespace_tokens(&config.response_text);
    // Rust note: `prompt_tokens` mirrors real OpenAI responses, whose
    // `prompt_tokens` is inclusive of the cached portion (`cached_tokens` is
    // reported separately as a *subset*, not on top) — so the configured
    // cache count is added in here rather than kept apart.
    let base_prompt_tokens: usize = parsed
        .messages
        .iter()
        .map(|m| whitespace_tokens(&m.content))
        .sum();
    let prompt_tokens = base_prompt_tokens + config.cached_tokens as usize;

    if parsed.stream {
        let include_usage = parsed
            .stream_options
            .as_ref()
            .map(|o| o.include_usage)
            .unwrap_or(false);
        streaming_response(
            &id,
            created,
            &parsed.model,
            config,
            prompt_tokens,
            completion_tokens,
            include_usage,
        )
    } else {
        let body = json!({
            "id": id,
            "object": "chat.completion",
            "created": created,
            "model": parsed.model,
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": config.response_text },
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
                "prompt_tokens_details": { "cached_tokens": config.cached_tokens },
            },
        });
        json_response(200, &body)
    }
}

#[allow(clippy::too_many_arguments)]
fn streaming_response(
    id: &str,
    created: u64,
    model: &str,
    config: &OpenAiConfig,
    prompt_tokens: usize,
    completion_tokens: usize,
    include_usage: bool,
) -> Response<ResponseBody> {
    let tokens: Vec<&str> = config.response_text.split_whitespace().collect();

    // Rust note: build the whole paced event schedule up front as
    // `(delay_before_this_frame, already-rendered SSE frame text)` pairs, then
    // hand it to `super::paced_sse_body` — see that function's doc comment for
    // why the pacing state machine lives there instead of here.
    let mut frames: Vec<(Duration, String)> = Vec::new();
    // TTFT gates the *first* frame: nothing (not even the role delta) is
    // emitted before it, mirroring a real provider that stays silent until
    // generation starts.
    frames.push((
        config.ttft,
        super::sse_data_frame(&chunk_json(
            id,
            created,
            model,
            json!({ "role": "assistant" }),
            None,
        )),
    ));
    for (i, token) in tokens.iter().enumerate() {
        let delay = if i == 0 {
            Duration::ZERO
        } else {
            config.inter_token_delay
        };
        let content = if i == 0 {
            (*token).to_string()
        } else {
            format!(" {token}")
        };
        frames.push((
            delay,
            super::sse_data_frame(&chunk_json(
                id,
                created,
                model,
                json!({ "content": content }),
                None,
            )),
        ));
    }
    frames.push((
        Duration::ZERO,
        super::sse_data_frame(&chunk_json(id, created, model, json!({}), Some("stop"))),
    ));
    if include_usage {
        let usage = json!({
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "prompt_tokens_details": { "cached_tokens": config.cached_tokens },
        });
        frames.push((
            Duration::ZERO,
            super::sse_data_frame(
                &json!({
                    "id": id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [],
                    "usage": usage,
                })
                .to_string(),
            ),
        ));
    }
    frames.push((Duration::ZERO, super::sse_data_frame("[DONE]")));

    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(super::paced_sse_body(frames))
        .expect("response built from known-valid parts")
}

// --- Responses API (`POST /v1/responses`) ----------------------------------
//
// Same server, same `OpenAiConfig` knobs as chat completions — just a
// different request/response envelope, matching real OpenAI's newer
// "Responses" surface. Note the different usage field names
// (`input_tokens`/`output_tokens`, not `prompt_tokens`/`completion_tokens`);
// see the module-level `handle_responses` doc for why that matters for token
// metering.

/// `input` may be a bare string (the common case for a single-turn prompt) or
/// a list of role/content items, matching the real Responses API's request
/// shape.
///
/// Rust note: `#[serde(untagged)]` tries each variant in turn against the
/// incoming JSON; `Text` matches a JSON string, `Items` matches a JSON array.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ResponsesInput {
    Text(String),
    Items(Vec<ResponsesInputItem>),
}

impl Default for ResponsesInput {
    fn default() -> Self {
        ResponsesInput::Text(String::new())
    }
}

impl ResponsesInput {
    fn whitespace_tokens(&self) -> usize {
        match self {
            ResponsesInput::Text(text) => whitespace_tokens(text),
            ResponsesInput::Items(items) => items
                .iter()
                .map(|item| whitespace_tokens(&item.content))
                .sum(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ResponsesInputItem {
    #[serde(default)]
    #[allow(dead_code)]
    role: String,
    #[serde(default)]
    content: String,
}

#[derive(Debug, Deserialize)]
struct ResponsesRequest {
    model: String,
    #[serde(default)]
    input: ResponsesInput,
    #[serde(default)]
    stream: bool,
}

/// Handle `POST /v1/responses`.
///
/// **The one place this mock deliberately does NOT feed
/// `crates/proxy-filters/src/usage.rs`'s `Dialect::OpenAi` parser:** the real
/// Responses API reports usage as `usage.input_tokens`/`usage.output_tokens`
/// (with `usage.input_tokens_details.cached_tokens`), not the chat-completions
/// `prompt_tokens`/`completion_tokens` shape that `usage.rs` currently parses.
/// This mock renders the real wire shape rather than bending it to match
/// `usage.rs`, since the mock mirrors the provider — the gap
/// (no `Dialect` for the Responses API today) is a real one, reported to the
/// orchestrator rather than silently patched over here.
fn handle_responses(
    body_bytes: Bytes,
    bodies: &ChatRequestLog,
    config: &OpenAiConfig,
    next_id: &Arc<AtomicU64>,
) -> Response<ResponseBody> {
    let value: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(e) => {
            return error_response(
                400,
                &format!("Invalid JSON in request body: {e}"),
                "invalid_request_error",
                Some("invalid_json"),
            )
        }
    };
    let parsed: ResponsesRequest = match serde_json::from_value(value.clone()) {
        Ok(parsed) => parsed,
        Err(e) => {
            return error_response(
                400,
                &format!("Invalid responses request: {e}"),
                "invalid_request_error",
                Some("invalid_body"),
            )
        }
    };
    bodies.record(value);

    let id = format!("resp_{}", next_id.fetch_add(1, Ordering::Relaxed));
    let completion_tokens = whitespace_tokens(&config.response_text);
    let base_input_tokens = parsed.input.whitespace_tokens();
    let input_tokens = base_input_tokens + config.cached_tokens as usize;

    if parsed.stream {
        responses_streaming_response(&id, &parsed.model, config, input_tokens, completion_tokens)
    } else {
        let body = json!({
            "id": id,
            "object": "response",
            "created_at": now_unix(),
            "model": parsed.model,
            "status": "completed",
            "output": [{
                "type": "message",
                "id": format!("msg_{id}"),
                "role": "assistant",
                "content": [{ "type": "output_text", "text": config.response_text, "annotations": [] }],
            }],
            "usage": {
                "input_tokens": input_tokens,
                "input_tokens_details": { "cached_tokens": config.cached_tokens },
                "output_tokens": completion_tokens,
                "output_tokens_details": { "reasoning_tokens": 0 },
                "total_tokens": input_tokens + completion_tokens,
            },
        });
        json_response(200, &body)
    }
}

/// Paced SSE for the Responses API: `response.created` (gated by `ttft`, like
/// chat completions gates its role-delta frame), then one
/// `response.output_text.delta` per token (paced by `inter_token_delay`),
/// then a `response.completed` frame carrying the final output and usage.
fn responses_streaming_response(
    id: &str,
    model: &str,
    config: &OpenAiConfig,
    input_tokens: usize,
    completion_tokens: usize,
) -> Response<ResponseBody> {
    let tokens: Vec<&str> = config.response_text.split_whitespace().collect();
    let mut frames: Vec<(Duration, String)> = Vec::new();

    frames.push((
        config.ttft,
        super::sse_named_frame(
            "response.created",
            &json!({
                "type": "response.created",
                "response": { "id": id, "object": "response", "status": "in_progress", "model": model },
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
        let delta = if i == 0 {
            (*token).to_string()
        } else {
            format!(" {token}")
        };
        frames.push((
            delay,
            super::sse_named_frame(
                "response.output_text.delta",
                &json!({
                    "type": "response.output_text.delta",
                    "item_id": format!("msg_{id}"),
                    "output_index": 0,
                    "content_index": 0,
                    "delta": delta,
                })
                .to_string(),
            ),
        ));
    }

    frames.push((
        Duration::ZERO,
        super::sse_named_frame(
            "response.completed",
            &json!({
                "type": "response.completed",
                "response": {
                    "id": id,
                    "object": "response",
                    "status": "completed",
                    "model": model,
                    "output": [{
                        "type": "message",
                        "id": format!("msg_{id}"),
                        "role": "assistant",
                        "content": [{ "type": "output_text", "text": config.response_text, "annotations": [] }],
                    }],
                    "usage": {
                        "input_tokens": input_tokens,
                        "input_tokens_details": { "cached_tokens": config.cached_tokens },
                        "output_tokens": completion_tokens,
                        "output_tokens_details": { "reasoning_tokens": 0 },
                        "total_tokens": input_tokens + completion_tokens,
                    },
                },
            })
            .to_string(),
        ),
    ));

    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(super::paced_sse_body(frames))
        .expect("response built from known-valid parts")
}

fn models_response(config: &OpenAiConfig) -> Response<ResponseBody> {
    let body = json!({
        "object": "list",
        "data": [{
            "id": config.model,
            "object": "model",
            "created": now_unix(),
            "owned_by": "mock-openai",
        }],
    });
    json_response(200, &body)
}

fn chunk_json(
    id: &str,
    created: u64,
    model: &str,
    delta: serde_json::Value,
    finish_reason: Option<&str>,
) -> String {
    json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "delta": delta,
            "finish_reason": finish_reason,
        }],
    })
    .to_string()
}

fn error_response(
    status: u16,
    message: &str,
    error_type: &str,
    code: Option<&str>,
) -> Response<ResponseBody> {
    let body = json!({
        "error": {
            "message": message,
            "type": error_type,
            "code": code,
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

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Test-only HTTP client helpers for `openai`: unlike `test_client` in
    /// `mod.rs` (bodyless requests, collect-the-whole-response), these send a
    /// JSON body and can incrementally collect an SSE stream with per-event
    /// timestamps, since the pacing behavior is the whole point of the
    /// streaming tests below.
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

        /// One SSE event as observed by the test client (the `data: ...`
        /// payload with the trailing blank line stripped), timestamped
        /// relative to when the request was sent.
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

            // Rust note: hyper's chunked-transfer-encoding frames don't
            // necessarily line up with our SSE "events" (each `data: ...\n\n`
            // record), so buffer decoded text and only emit a `TimedEvent`
            // once we see the blank-line terminator.
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

    #[tokio::test]
    async fn non_streaming_returns_completion_with_usage_and_records_body() {
        let config = OpenAiConfig {
            model: "mock-gpt".to_string(),
            response_text: "hello there friend".to_string(),
            ttft: Duration::from_millis(10),
            inter_token_delay: Duration::from_millis(5),
            require_api_key: None,
            forced_error: None,
            cached_tokens: 0,
        };
        let upstream = OpenAiUpstream::spawn(config).await.expect("spawn openai");

        let body = json!({
            "model": "mock-gpt",
            "messages": [{"role": "user", "content": "hi there"}],
        });
        let res =
            test_support::send_json(upstream.addr(), "POST", "/v1/chat/completions", &[], &body)
                .await
                .expect("request should succeed");

        assert_eq!(res.status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json body");
        assert_eq!(parsed["object"], "chat.completion");
        assert_eq!(parsed["model"], "mock-gpt");
        assert_eq!(
            parsed["choices"][0]["message"]["content"],
            "hello there friend"
        );
        assert_eq!(parsed["choices"][0]["finish_reason"], "stop");
        assert_eq!(parsed["usage"]["prompt_tokens"], 2);
        assert_eq!(parsed["usage"]["completion_tokens"], 3);
        assert_eq!(parsed["usage"]["total_tokens"], 5);

        let captured = upstream.bodies.bodies();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0]["model"], "mock-gpt");
        assert_eq!(captured[0]["messages"][0]["content"], "hi there");

        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn streaming_paces_chunks_in_order_and_terminates_with_done() {
        let ttft = Duration::from_millis(40);
        let inter_token_delay = Duration::from_millis(20);
        let config = OpenAiConfig {
            model: "mock-gpt".to_string(),
            response_text: "a b c".to_string(),
            ttft,
            inter_token_delay,
            require_api_key: None,
            forced_error: None,
            cached_tokens: 0,
        };
        let upstream = OpenAiUpstream::spawn(config).await.expect("spawn openai");

        let body = json!({
            "model": "mock-gpt",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true,
            "stream_options": {"include_usage": true},
        });

        let (status, events) = test_support::send_json_collect_sse(
            upstream.addr(),
            "POST",
            "/v1/chat/completions",
            &[],
            &body,
        )
        .await
        .expect("request should succeed");
        assert_eq!(status, 200);

        // role delta, 3 content chunks, finish, usage, [DONE]
        assert_eq!(
            events.len(),
            7,
            "unexpected event count: {:?}",
            events.iter().map(|e| &e.data).collect::<Vec<_>>()
        );
        assert!(events[0].data.contains("\"role\":\"assistant\""));
        for event in &events[1..=3] {
            assert!(event.data.contains("chat.completion.chunk"));
            assert!(event.data.contains("\"content\""));
        }
        assert!(events[4].data.contains("\"finish_reason\":\"stop\""));
        assert!(events[5].data.contains("\"usage\""));
        assert_eq!(events[6].data, "data: [DONE]");

        assert!(
            events[0].at >= ttft,
            "no event (even the role delta) should arrive before ttft ({ttft:?}), got {:?}",
            events[0].at
        );
        assert!(
            events[1].at >= ttft,
            "first content chunk should arrive at/after ttft ({ttft:?}), got {:?}",
            events[1].at
        );
        // A usage chunk (index 5) must precede [DONE] (index 6) — already
        // implied by event order, asserted explicitly for clarity.
        assert!(events[5].at <= events[6].at);

        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn require_api_key_rejects_missing_or_wrong_bearer_token() {
        let config = OpenAiConfig {
            model: "mock-gpt".to_string(),
            response_text: "ok".to_string(),
            ttft: Duration::from_millis(1),
            inter_token_delay: Duration::from_millis(1),
            require_api_key: Some("secret-key".to_string()),
            forced_error: None,
            cached_tokens: 0,
        };
        let upstream = OpenAiUpstream::spawn(config).await.expect("spawn openai");
        let body = json!({"model": "mock-gpt", "messages": [{"role": "user", "content": "hi"}]});

        let unauthorized =
            test_support::send_json(upstream.addr(), "POST", "/v1/chat/completions", &[], &body)
                .await
                .expect("request should succeed");
        assert_eq!(unauthorized.status, 401);
        let err: serde_json::Value =
            serde_json::from_str(&unauthorized.body).expect("valid json body");
        assert!(err["error"]["message"].is_string());

        let authorized = test_support::send_json(
            upstream.addr(),
            "POST",
            "/v1/chat/completions",
            &[("authorization", "Bearer secret-key")],
            &body,
        )
        .await
        .expect("request should succeed");
        assert_eq!(authorized.status, 200);

        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn forced_error_overrides_every_request() {
        let config = OpenAiConfig {
            model: "mock-gpt".to_string(),
            response_text: "ok".to_string(),
            ttft: Duration::from_millis(1),
            inter_token_delay: Duration::from_millis(1),
            require_api_key: None,
            forced_error: Some((503, "upstream overloaded".to_string())),
            cached_tokens: 0,
        };
        let upstream = OpenAiUpstream::spawn(config).await.expect("spawn openai");
        let body = json!({"model": "mock-gpt", "messages": []});

        let res =
            test_support::send_json(upstream.addr(), "POST", "/v1/chat/completions", &[], &body)
                .await
                .expect("request should succeed");
        assert_eq!(res.status, 503);
        let err: serde_json::Value = serde_json::from_str(&res.body).expect("valid json body");
        assert_eq!(err["error"]["message"], "upstream overloaded");

        // The GET /v1/models endpoint is subject to forced_error too.
        let models = test_support::send_json(upstream.addr(), "GET", "/v1/models", &[], &json!({}))
            .await
            .expect("request should succeed");
        assert_eq!(models.status, 503);

        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn malformed_json_body_returns_400() {
        let config = OpenAiConfig {
            model: "mock-gpt".to_string(),
            response_text: "ok".to_string(),
            ttft: Duration::from_millis(1),
            inter_token_delay: Duration::from_millis(1),
            require_api_key: None,
            forced_error: None,
            cached_tokens: 0,
        };
        let upstream = OpenAiUpstream::spawn(config).await.expect("spawn openai");

        // Drive the connection by hand: `send_json` always serializes valid
        // JSON, so malformed input needs a raw request body.
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
            .uri("/v1/chat/completions")
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
    async fn models_endpoint_lists_the_configured_model() {
        let config = OpenAiConfig {
            model: "mock-gpt-4".to_string(),
            response_text: "ok".to_string(),
            ttft: Duration::from_millis(1),
            inter_token_delay: Duration::from_millis(1),
            require_api_key: None,
            forced_error: None,
            cached_tokens: 0,
        };
        let upstream = OpenAiUpstream::spawn(config).await.expect("spawn openai");

        let res = test_support::send_json(upstream.addr(), "GET", "/v1/models", &[], &json!({}))
            .await
            .expect("request should succeed");
        assert_eq!(res.status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json body");
        assert_eq!(parsed["object"], "list");
        assert_eq!(parsed["data"][0]["id"], "mock-gpt-4");

        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let config = OpenAiConfig {
            model: "mock-gpt".to_string(),
            response_text: "ok".to_string(),
            ttft: Duration::from_millis(1),
            inter_token_delay: Duration::from_millis(1),
            require_api_key: None,
            forced_error: None,
            cached_tokens: 0,
        };
        let upstream = OpenAiUpstream::spawn(config).await.expect("spawn openai");

        let res = test_support::send_json(upstream.addr(), "GET", "/v1/nope", &[], &json!({}))
            .await
            .expect("request should succeed");
        assert_eq!(res.status, 404);
        let err: serde_json::Value = serde_json::from_str(&res.body).expect("valid json body");
        assert_eq!(err["error"]["type"], "invalid_request_error");

        upstream.shutdown().await;
    }

    // ---- /v1/responses (Responses API) ------------------------------------

    #[tokio::test]
    async fn responses_non_streaming_returns_output_text_with_usage_and_records_body() {
        let config = OpenAiConfig {
            model: "mock-gpt".to_string(),
            response_text: "hello there friend".to_string(),
            ttft: Duration::from_millis(10),
            inter_token_delay: Duration::from_millis(5),
            require_api_key: None,
            forced_error: None,
            cached_tokens: 0,
        };
        let upstream = OpenAiUpstream::spawn(config).await.expect("spawn openai");

        let body = json!({
            "model": "mock-gpt",
            "input": "hi there",
        });
        let res = test_support::send_json(upstream.addr(), "POST", "/v1/responses", &[], &body)
            .await
            .expect("request should succeed");

        assert_eq!(res.status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json body");
        assert_eq!(parsed["object"], "response");
        assert_eq!(parsed["model"], "mock-gpt");
        assert_eq!(parsed["status"], "completed");
        assert_eq!(parsed["output"][0]["type"], "message");
        assert_eq!(parsed["output"][0]["content"][0]["type"], "output_text");
        assert_eq!(
            parsed["output"][0]["content"][0]["text"],
            "hello there friend"
        );
        // Responses API usage field names differ from chat completions:
        // `input_tokens`/`output_tokens`, not `prompt_tokens`/`completion_tokens`.
        assert_eq!(parsed["usage"]["input_tokens"], 2);
        assert_eq!(parsed["usage"]["output_tokens"], 3);
        assert_eq!(parsed["usage"]["input_tokens_details"]["cached_tokens"], 0);

        let captured = upstream.bodies.bodies();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0]["model"], "mock-gpt");
        assert_eq!(captured[0]["input"], "hi there");

        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn responses_non_streaming_accepts_item_list_input_and_reports_cached_tokens() {
        let config = OpenAiConfig {
            model: "mock-gpt".to_string(),
            response_text: "ok".to_string(),
            ttft: Duration::from_millis(1),
            inter_token_delay: Duration::from_millis(1),
            require_api_key: None,
            forced_error: None,
            cached_tokens: 80,
        };
        let upstream = OpenAiUpstream::spawn(config).await.expect("spawn openai");

        let body = json!({
            "model": "mock-gpt",
            "input": [{"role": "user", "content": "hi there friend"}],
        });
        let res = test_support::send_json(upstream.addr(), "POST", "/v1/responses", &[], &body)
            .await
            .expect("request should succeed");
        assert_eq!(res.status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json body");
        // base (3) + configured cached (80), matching real OpenAI where the
        // headline input count is inclusive of the cached portion.
        assert_eq!(parsed["usage"]["input_tokens"], 83);
        assert_eq!(parsed["usage"]["input_tokens_details"]["cached_tokens"], 80);

        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn responses_streaming_emits_created_deltas_then_completed_with_usage() {
        let ttft = Duration::from_millis(40);
        let inter_token_delay = Duration::from_millis(20);
        let config = OpenAiConfig {
            model: "mock-gpt".to_string(),
            response_text: "a b c".to_string(),
            ttft,
            inter_token_delay,
            require_api_key: None,
            forced_error: None,
            cached_tokens: 0,
        };
        let upstream = OpenAiUpstream::spawn(config).await.expect("spawn openai");

        let body = json!({
            "model": "mock-gpt",
            "input": "hi",
            "stream": true,
        });

        let (status, events) = test_support::send_json_collect_sse(
            upstream.addr(),
            "POST",
            "/v1/responses",
            &[],
            &body,
        )
        .await
        .expect("request should succeed");
        assert_eq!(status, 200);

        // response.created, 3x response.output_text.delta, response.completed
        assert_eq!(
            events.len(),
            5,
            "unexpected event count: {:?}",
            events.iter().map(|e| &e.data).collect::<Vec<_>>()
        );
        assert!(events[0].data.contains("event: response.created"));
        for event in &events[1..=3] {
            assert!(event.data.contains("event: response.output_text.delta"));
            assert!(event.data.contains("\"delta\""));
        }
        assert!(events[4].data.contains("event: response.completed"));
        assert!(events[4].data.contains("\"output_tokens\":3"));

        assert!(
            events[0].at >= ttft,
            "response.created should not arrive before ttft ({ttft:?}), got {:?}",
            events[0].at
        );
        assert!(events[1].at >= ttft, "first delta gated by ttft too");

        upstream.shutdown().await;
    }
}
