//! `openai`: an OpenAI-chat-completions-compatible mock upstream for the LLM
//! feature lanes (streaming metrics WP-33, token metering WP-34, model
//! routing WP-35). Unlike `echo`/`slow` it understands the request body
//! (`/v1/chat/completions`) well enough to fabricate a plausible completion —
//! non-streaming JSON or a paced SSE stream — and it records the parsed
//! request bodies (not just method/path/headers) so scenarios can assert on
//! what the proxy forwarded upstream.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response};
use serde::Deserialize;
use serde_json::json;

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
    /// Delay before the first streamed content chunk (time-to-first-token).
    pub ttft: Duration,
    /// Delay between subsequent streamed content chunks.
    pub inter_token_delay: Duration,
    /// When set, requests must send `authorization: Bearer <key>` or get a
    /// 401 OpenAI-style error.
    pub require_api_key: Option<String>,
    /// When set, every request gets this `(status, message)` back instead of
    /// being handled normally — for retry/fallback drills (WP-35).
    pub forced_error: Option<(u16, String)>,
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
        self.0.lock().expect("chat request log mutex poisoned").clone()
    }
}

pub struct OpenAiUpstream {
    pub log: RequestLog,
    pub bodies: ChatRequestLog,
    handle: ServerHandle,
}

impl OpenAiUpstream {
    pub fn addr(&self) -> SocketAddr {
        self.handle.addr
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
        let handle = serve(move |req: Request<Incoming>| {
            let log = log_for_handler.clone();
            let bodies = bodies_for_handler.clone();
            let config = Arc::clone(&config);
            let next_id = Arc::clone(&next_id);
            async move { Ok(handle_openai(req, &log, &bodies, &config, &next_id).await) }
        })
        .await?;
        Ok(Self {
            log,
            bodies,
            handle,
        })
    }

    pub async fn shutdown(self) {
        self.handle.shutdown().await;
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
        let authorized = recorded
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("authorization") && value == &expected_header);
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
    let prompt_tokens: usize = parsed.messages.iter().map(|m| whitespace_tokens(&m.content)).sum();

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
    // `(delay_before_this_frame, already-rendered SSE payload)` pairs, then
    // hand it to `futures::stream::unfold` below — the seed for `unfold` is
    // just "how far through this Vec are we", which keeps the async step
    // closure trivial instead of hand-rolling a state machine per event kind.
    let mut frames: Vec<(Duration, String)> = Vec::new();
    frames.push((
        Duration::ZERO,
        chunk_json(id, created, model, json!({ "role": "assistant" }), None),
    ));
    for (i, token) in tokens.iter().enumerate() {
        let delay = if i == 0 {
            config.ttft
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
            chunk_json(id, created, model, json!({ "content": content }), None),
        ));
    }
    frames.push((
        Duration::ZERO,
        chunk_json(id, created, model, json!({}), Some("stop")),
    ));
    if include_usage {
        let usage = json!({
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        });
        frames.push((
            Duration::ZERO,
            json!({
                "id": id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [],
                "usage": usage,
            })
            .to_string(),
        ));
    }
    frames.push((Duration::ZERO, "[DONE]".to_string()));

    let stream = futures::stream::unfold((0usize, frames), |(i, frames)| async move {
        let (delay, payload) = frames.get(i)?.clone();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let event = Bytes::from(format!("data: {payload}\n\n"));
        Some((
            Ok::<_, std::convert::Infallible>(Frame::data(event)),
            (i + 1, frames),
        ))
    });

    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        // Rust note: `StreamBody` turns any `Stream` of `Result<Frame<Bytes>,
        // E>` into a `Body`; hyper polls it frame by frame and writes each
        // one out as an HTTP/1.1 chunked-encoding chunk as soon as it's
        // ready, which is what gives us real (not buffered) pacing.
        .body(StreamBody::new(stream).boxed())
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
        };
        let upstream = OpenAiUpstream::spawn(config).await.expect("spawn openai");

        let body = json!({
            "model": "mock-gpt",
            "messages": [{"role": "user", "content": "hi there"}],
        });
        let res = test_support::send_json(
            upstream.addr(),
            "POST",
            "/v1/chat/completions",
            &[],
            &body,
        )
        .await
        .expect("request should succeed");

        assert_eq!(res.status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json body");
        assert_eq!(parsed["object"], "chat.completion");
        assert_eq!(parsed["model"], "mock-gpt");
        assert_eq!(parsed["choices"][0]["message"]["content"], "hello there friend");
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
        assert_eq!(events.len(), 7, "unexpected event count: {:?}", events.iter().map(|e| &e.data).collect::<Vec<_>>());
        assert!(events[0].data.contains("\"role\":\"assistant\""));
        for event in &events[1..=3] {
            assert!(event.data.contains("chat.completion.chunk"));
            assert!(event.data.contains("\"content\""));
        }
        assert!(events[4].data.contains("\"finish_reason\":\"stop\""));
        assert!(events[5].data.contains("\"usage\""));
        assert_eq!(events[6].data, "data: [DONE]");

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
        };
        let upstream = OpenAiUpstream::spawn(config).await.expect("spawn openai");
        let body = json!({"model": "mock-gpt", "messages": [{"role": "user", "content": "hi"}]});

        let unauthorized = test_support::send_json(
            upstream.addr(),
            "POST",
            "/v1/chat/completions",
            &[],
            &body,
        )
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
        };
        let upstream = OpenAiUpstream::spawn(config).await.expect("spawn openai");
        let body = json!({"model": "mock-gpt", "messages": []});

        let res = test_support::send_json(
            upstream.addr(),
            "POST",
            "/v1/chat/completions",
            &[],
            &body,
        )
        .await
        .expect("request should succeed");
        assert_eq!(res.status, 503);
        let err: serde_json::Value = serde_json::from_str(&res.body).expect("valid json body");
        assert_eq!(err["error"]["message"], "upstream overloaded");

        // The GET /v1/models endpoint is subject to forced_error too.
        let models = test_support::send_json(
            upstream.addr(),
            "GET",
            "/v1/models",
            &[],
            &json!({}),
        )
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
        let body_bytes = response.into_body().collect().await.expect("collect").to_bytes();
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
}
