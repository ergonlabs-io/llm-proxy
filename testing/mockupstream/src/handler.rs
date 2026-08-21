//! Routes the four endpoints this mock upstream speaks, reads (and caps)
//! the request body, and dispatches to the pre-rendered response builders in
//! [`crate::frames`].

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use serde_json::json;

use crate::frames::{self, AnthropicFrames, OpenAiFrames, ResponseBody, StreamConfig};
use crate::request::{self, MAX_BODY_BYTES};
use crate::stats::Stats;

/// Everything one accepted connection's request handlers share: the
/// pre-rendered frame sets (one build per process, at startup) and the
/// request counters. Cheap to clone (an `Arc` bump) per connection/request.
pub struct AppState {
    openai: OpenAiFrames,
    anthropic: AnthropicFrames,
    openai_cfg: StreamConfig,
    anthropic_cfg: StreamConfig,
    pub stats: Arc<Stats>,
}

impl AppState {
    pub fn new(cfg: StreamConfig) -> Self {
        Self {
            openai: OpenAiFrames::new(&cfg),
            anthropic: AnthropicFrames::new(&cfg),
            openai_cfg: cfg,
            anthropic_cfg: cfg,
            stats: Arc::new(Stats::default()),
        }
    }
}

/// Handle one request. Infallible at the HTTP level -- every outcome this
/// mock can produce (including "body too large" and "unknown route") is
/// rendered as a normal `Response`, never a connection-level error.
pub async fn handle(req: Request<Incoming>, state: Arc<AppState>) -> Response<ResponseBody> {
    match (req.method().clone(), req.uri().path()) {
        (Method::POST, "/v1/chat/completions") => {
            handle_dialect(req, &state, Dialect::OpenAi).await
        }
        (Method::POST, "/v1/messages") => handle_dialect(req, &state, Dialect::Anthropic).await,
        (Method::GET, "/health") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(frames::full_body(Bytes::from_static(b"ok")))
            .expect("static health response is always valid"),
        _ => {
            state.stats.record_rejected();
            json_error(
                StatusCode::NOT_FOUND,
                &format!("no such route: {} {}", req.method(), req.uri().path()),
            )
        }
    }
}

enum Dialect {
    OpenAi,
    Anthropic,
}

async fn handle_dialect(
    req: Request<Incoming>,
    state: &AppState,
    dialect: Dialect,
) -> Response<ResponseBody> {
    let body = match read_capped_body(req).await {
        Ok(bytes) => bytes,
        Err(resp) => {
            state.stats.record_rejected();
            return resp;
        }
    };
    let meta = request::parse_request_meta(&body);
    // The crate doc's "do not retain the body" rule: `body` goes out of
    // scope at the end of this function and is never stored anywhere past
    // `parse_request_meta`.
    state.stats.record_request(meta.stream);

    match dialect {
        Dialect::OpenAi => {
            if meta.stream {
                sse_response(state.openai.stream_body(&meta.model))
            } else {
                json_response(frames::openai_completion_body(
                    &state.openai_cfg,
                    &meta.model,
                ))
            }
        }
        Dialect::Anthropic => {
            if meta.stream {
                sse_response(state.anthropic.stream_body(&meta.model))
            } else {
                json_response(frames::anthropic_message_body(
                    &state.anthropic_cfg,
                    &meta.model,
                ))
            }
        }
    }
}

/// Read the whole request body, capped at [`MAX_BODY_BYTES`]. Returns the
/// bytes on success, or an already-rendered 413 response on overflow.
async fn read_capped_body(req: Request<Incoming>) -> Result<Bytes, Response<ResponseBody>> {
    let limited = Limited::new(req.into_body(), MAX_BODY_BYTES);
    match limited.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(_) => {
            // `Limited`'s only error is a length-limit overflow (any
            // transport-level read error would also land here, but this is
            // a mock upstream serving loopback load-test traffic, so folding
            // both into one 413 is an acceptable simplification -- a real
            // provider's exact error taxonomy isn't the thing under test).
            Err(json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                &format!("request body exceeds {MAX_BODY_BYTES} bytes"),
            ))
        }
    }
}

fn json_response(bytes: Bytes) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(frames::full_body(bytes))
        .expect("status/headers are always valid")
}

fn sse_response(body: ResponseBody) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .body(body)
        .expect("status/headers are always valid")
}

fn json_error(status: StatusCode, message: &str) -> Response<ResponseBody> {
    let body = serde_json::to_vec(&json!({"error": {"message": message}}))
        .expect("error value is always serializable");
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(frames::full_body(Bytes::from(body)))
        .expect("status/headers are always valid")
}
