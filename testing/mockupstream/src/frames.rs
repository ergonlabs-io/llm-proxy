//! Pre-rendered response fragments for both dialects, streaming and
//! non-streaming.
//!
//! # Why frames are rendered once at startup, not per request
//!
//! Every constant piece of a streamed response -- the `--tokens`
//! content-delta chunks, the terminal usage/`[DONE]` frames -- is fully
//! determined by the CLI flags, which never change after startup. This
//! module builds every one of those pieces exactly once, as `Bytes`, in
//! [`OpenAiFrames::new`]/[`AnthropicFrames::new`], and shares them across
//! every request (and every one of the `--tokens` chunks *within* a
//! request) behind an `Arc` -- cloning a `Step` is a refcount bump, not a
//! JSON serialization.
//!
//! The one thing that genuinely varies per request is the client-supplied
//! `model` string (see `crate::request::parse_request_meta`). Splicing it
//! into every repeated content-delta chunk would mean paying a JSON
//! serialization `--tokens` times per request -- precisely the per-request
//! formatting cost this crate exists to keep off the hot path. The decision
//! made here: `model` is echoed exactly once per stream, in the leading
//! role-delta / `message_start` frame (and in the non-streaming body,
//! which is only ever built once per request regardless). Every repeated
//! per-token chunk stays 100% pre-rendered and model-free -- real providers
//! do repeat `model` on every chunk, but nothing that reads these frames
//! (`crates/proxy-filters/src/usage.rs`, `testing/loadgen`'s SSE classifier)
//! looks at it there, so the fidelity gap costs nothing while the
//! performance win is real.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::stream::{self, Stream};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use serde_json::json;

/// The response-body type every handler returns, streaming or not. `Full`
/// and `StreamBody` are both `Body<Data = Bytes, Error = Infallible>`, so
/// `.boxed()` unifies them into one concrete type without an error
/// conversion.
pub type ResponseBody = BoxBody<Bytes, Infallible>;

/// The CLI knobs that shape every rendered frame, converted once from raw
/// `u64` milliseconds into `Duration`s so nothing downstream repeats that
/// conversion.
#[derive(Debug, Clone, Copy)]
pub struct StreamConfig {
    /// Delay before the very first frame of a stream (the role-delta /
    /// `message_start` frame). Zero means "no delay", handled by skipping
    /// the sleep entirely -- see [`maybe_sleep`].
    pub ttft: Duration,
    /// Delay before each content-bearing chunk.
    pub inter_token: Duration,
    /// Number of content-delta chunks to stream, and the reported
    /// `output_tokens`/`completion_tokens`.
    pub tokens: u32,
    /// Reported input token count.
    pub prompt_tokens: u32,
}

/// One step of a rendered SSE stream: wait `.0` (skipped entirely when
/// zero), then emit `.1` as one already-framed SSE chunk (`data: ...\n\n` or
/// `event: ...\ndata: ...\n\n`).
pub type Step = (Duration, Bytes);

const CONTENT_CHUNK_TEXT: &str = "token ";
const NON_STREAMING_CONTENT: &str = "This is a mock response from mock-upstream.";

fn sse_data_frame(value: &serde_json::Value) -> Bytes {
    Bytes::from(format!("data: {value}\n\n"))
}

fn sse_event_frame(event: &str, value: &serde_json::Value) -> Bytes {
    Bytes::from(format!("event: {event}\ndata: {value}\n\n"))
}

// --------------------------------------------------------------- OpenAI ---

/// Pre-rendered OpenAI `chat.completion.chunk` fragments.
pub struct OpenAiFrames {
    ttft: Duration,
    created: i64,
    /// The model-independent tail of every stream this process serves:
    /// `tokens` content-delta chunks (each preceded by `inter_token`), the
    /// final usage chunk, then `data: [DONE]`. Built once; shared by every
    /// request via `Arc`.
    tail: Arc<Vec<Step>>,
}

impl OpenAiFrames {
    pub fn new(cfg: &StreamConfig) -> Self {
        let created = unix_time_secs();
        let content_delta = sse_data_frame(&json!({
            "id": "chatcmpl-mock",
            "object": "chat.completion.chunk",
            "created": created,
            "choices": [{
                "index": 0,
                "delta": {"content": CONTENT_CHUNK_TEXT},
                "finish_reason": null,
            }],
        }));
        let final_usage = sse_data_frame(&json!({
            "id": "chatcmpl-mock",
            "object": "chat.completion.chunk",
            "created": created,
            "choices": [],
            "usage": {
                "prompt_tokens": cfg.prompt_tokens,
                "completion_tokens": cfg.tokens,
                "total_tokens": cfg.prompt_tokens + cfg.tokens,
            },
        }));
        let done = Bytes::from_static(b"data: [DONE]\n\n");

        let mut tail = Vec::with_capacity(cfg.tokens as usize + 2);
        for _ in 0..cfg.tokens {
            tail.push((cfg.inter_token, content_delta.clone()));
        }
        tail.push((Duration::ZERO, final_usage));
        tail.push((Duration::ZERO, done));

        Self {
            ttft: cfg.ttft,
            created,
            tail: Arc::new(tail),
        }
    }

    fn role_delta(&self, model: &str) -> Bytes {
        sse_data_frame(&json!({
            "id": "chatcmpl-mock",
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": model,
            "choices": [{
                "index": 0,
                "delta": {"role": "assistant"},
                "finish_reason": null,
            }],
        }))
    }

    /// Build this request's streaming response body: the `ttft`-delayed,
    /// model-bearing leading chunk, followed by the shared static tail.
    pub fn stream_body(&self, model: &str) -> ResponseBody {
        steps_body((self.ttft, self.role_delta(model)), self.tail.clone())
    }
}

/// Non-streaming `chat.completion` body. Built fresh per request (one
/// `serde_json` allocation, not looped over `--tokens`) since it is only
/// ever rendered once -- unlike the streaming tail above, there is no
/// repeated-per-chunk cost to avoid here.
pub fn openai_completion_body(cfg: &StreamConfig, model: &str) -> Bytes {
    let value = json!({
        "id": "chatcmpl-mock",
        "object": "chat.completion",
        "created": unix_time_secs(),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": NON_STREAMING_CONTENT},
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": cfg.prompt_tokens,
            "completion_tokens": cfg.tokens,
            "total_tokens": cfg.prompt_tokens + cfg.tokens,
        },
    });
    Bytes::from(serde_json::to_vec(&value).expect("value is always serializable"))
}

// ------------------------------------------------------------ Anthropic ---

/// Pre-rendered Anthropic Messages fragments.
pub struct AnthropicFrames {
    ttft: Duration,
    prompt_tokens: u32,
    /// The model-independent tail: `content_block_start`, `tokens` ×
    /// `content_block_delta` (each preceded by `inter_token`),
    /// `content_block_stop`, `message_delta` (carrying the final
    /// `output_tokens`), then `message_stop`. Built once; shared via `Arc`.
    tail: Arc<Vec<Step>>,
}

impl AnthropicFrames {
    pub fn new(cfg: &StreamConfig) -> Self {
        let content_block_start = sse_event_frame(
            "content_block_start",
            &json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            }),
        );
        let content_block_delta = sse_event_frame(
            "content_block_delta",
            &json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": CONTENT_CHUNK_TEXT},
            }),
        );
        let content_block_stop = sse_event_frame(
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": 0}),
        );
        let message_delta = sse_event_frame(
            "message_delta",
            &json!({
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                "usage": {"output_tokens": cfg.tokens},
            }),
        );
        let message_stop = sse_event_frame("message_stop", &json!({"type": "message_stop"}));

        let mut tail = Vec::with_capacity(cfg.tokens as usize + 4);
        tail.push((Duration::ZERO, content_block_start));
        for _ in 0..cfg.tokens {
            tail.push((cfg.inter_token, content_block_delta.clone()));
        }
        tail.push((Duration::ZERO, content_block_stop));
        tail.push((Duration::ZERO, message_delta));
        tail.push((Duration::ZERO, message_stop));

        Self {
            ttft: cfg.ttft,
            prompt_tokens: cfg.prompt_tokens,
            tail: Arc::new(tail),
        }
    }

    fn message_start(&self, model: &str) -> Bytes {
        sse_event_frame(
            "message_start",
            &json!({
                "type": "message_start",
                "message": {
                    "id": "msg_mock",
                    "type": "message",
                    "role": "assistant",
                    "model": model,
                    "content": [],
                    "usage": {"input_tokens": self.prompt_tokens, "output_tokens": 0},
                },
            }),
        )
    }

    /// Build this request's streaming response body: the `ttft`-delayed,
    /// model-bearing `message_start` frame, followed by the shared static
    /// tail.
    pub fn stream_body(&self, model: &str) -> ResponseBody {
        steps_body((self.ttft, self.message_start(model)), self.tail.clone())
    }
}

/// Non-streaming Anthropic `message` body. Same reasoning as
/// `openai_completion_body`: built fresh per request since it is rendered
/// exactly once, not looped.
pub fn anthropic_message_body(cfg: &StreamConfig, model: &str) -> Bytes {
    let value = json!({
        "id": "msg_mock",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": NON_STREAMING_CONTENT}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": cfg.prompt_tokens,
            "output_tokens": cfg.tokens,
        },
    });
    Bytes::from(serde_json::to_vec(&value).expect("value is always serializable"))
}

// -------------------------------------------------------- shared plumbing --

/// A cursor over one request's frame sequence: the request-specific leading
/// step (carrying the echoed model), then the shared, `Arc`-held tail.
///
/// Rust note: this is the state type for the [`futures::stream::unfold`]
/// below -- `unfold` builds a `Stream` out of a plain "given the current
/// state, produce the next item and the next state" async function, which
/// reads a lot like a hand-written state machine without needing one of our
/// own `Future`/`Stream` impls (both of which would need unsafe-free but
/// fiddly manual `Pin` handling to write by hand).
enum StepCursor {
    Leading(Step, Arc<Vec<Step>>),
    Tail(Arc<Vec<Step>>, usize),
}

async fn maybe_sleep(delay: Duration) {
    // The crate doc's hot-path requirement: `--ttft-ms 0` / `--inter-token-ms
    // 0` must skip the sleep entirely rather than awaiting a zero-duration
    // timer, which would still register with (and get polled by) the tokio
    // timer wheel for no benefit.
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
}

fn step_stream(
    leading: Step,
    tail: Arc<Vec<Step>>,
) -> impl Stream<Item = Result<Frame<Bytes>, Infallible>> + Send + 'static {
    stream::unfold(StepCursor::Leading(leading, tail), |cursor| async move {
        match cursor {
            StepCursor::Leading((delay, bytes), tail) => {
                maybe_sleep(delay).await;
                Some((Ok(Frame::data(bytes)), StepCursor::Tail(tail, 0)))
            }
            StepCursor::Tail(tail, idx) => {
                let (delay, bytes) = tail.get(idx)?.clone();
                maybe_sleep(delay).await;
                Some((Ok(Frame::data(bytes)), StepCursor::Tail(tail, idx + 1)))
            }
        }
    })
}

/// Turn a leading step plus a shared tail into a boxed streaming response
/// body. Shared by both dialects above since the cursor shape is identical.
fn steps_body(leading: Step, tail: Arc<Vec<Step>>) -> ResponseBody {
    StreamBody::new(step_stream(leading, tail)).boxed()
}

/// Wrap a single already-complete body (a non-streaming JSON response, a
/// health check, an error body) as a [`ResponseBody`].
pub fn full_body(bytes: Bytes) -> ResponseBody {
    Full::new(bytes).boxed()
}

fn unix_time_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // A mock's `created` timestamp doesn't need per-request accuracy --
    // computed once per `*Frames::new` call (process startup, and once more
    // per non-streaming request), never per streamed chunk.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> StreamConfig {
        StreamConfig {
            ttft: Duration::ZERO,
            inter_token: Duration::ZERO,
            tokens: 3,
            prompt_tokens: 10,
        }
    }

    async fn collect_frames(body: ResponseBody) -> Vec<Bytes> {
        let mut body = body;
        let mut out = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.expect("mock frames never error");
            if let Ok(data) = frame.into_data() {
                out.push(data);
            }
        }
        out
    }

    #[tokio::test]
    async fn openai_stream_shape_and_counts() {
        let frames = OpenAiFrames::new(&cfg());
        let chunks = collect_frames(frames.stream_body("gpt-4o-mini")).await;
        // role-delta + 3 content-delta + usage + [DONE]
        assert_eq!(chunks.len(), 6);
        let role = String::from_utf8(chunks[0].to_vec()).unwrap();
        assert!(role.contains("\"role\":\"assistant\""));
        assert!(role.contains("\"model\":\"gpt-4o-mini\""));
        for chunk in &chunks[1..4] {
            let text = String::from_utf8(chunk.to_vec()).unwrap();
            assert!(text.contains("\"content\":\"token \""));
        }
        let usage = String::from_utf8(chunks[4].to_vec()).unwrap();
        assert!(usage.contains("\"prompt_tokens\":10"));
        assert!(usage.contains("\"completion_tokens\":3"));
        assert_eq!(&chunks[5][..], b"data: [DONE]\n\n");
    }

    #[tokio::test]
    async fn openai_non_streaming_echoes_model_and_usage() {
        let body = openai_completion_body(&cfg(), "gpt-4o-mini");
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["model"], "gpt-4o-mini");
        assert_eq!(value["usage"]["prompt_tokens"], 10);
        assert_eq!(value["usage"]["completion_tokens"], 3);
        assert!(value["choices"][0]["message"]["content"].is_string());
    }

    #[tokio::test]
    async fn anthropic_stream_shape_and_counts() {
        let frames = AnthropicFrames::new(&cfg());
        let chunks = collect_frames(frames.stream_body("claude-3-haiku")).await;
        // message_start + content_block_start + 3 delta + content_block_stop
        // + message_delta + message_stop
        assert_eq!(chunks.len(), 8);
        let start = String::from_utf8(chunks[0].to_vec()).unwrap();
        assert!(start.starts_with("event: message_start\n"));
        assert!(start.contains("\"model\":\"claude-3-haiku\""));
        assert!(start.contains("\"input_tokens\":10"));
        let last = String::from_utf8(chunks[7].to_vec()).unwrap();
        assert!(last.starts_with("event: message_stop\n"));
        let message_delta = String::from_utf8(chunks[6].to_vec()).unwrap();
        assert!(message_delta.starts_with("event: message_delta\n"));
        assert!(message_delta.contains("\"output_tokens\":3"));
    }

    #[tokio::test]
    async fn anthropic_non_streaming_echoes_model_and_usage() {
        let body = anthropic_message_body(&cfg(), "claude-3-haiku");
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["model"], "claude-3-haiku");
        assert_eq!(value["usage"]["input_tokens"], 10);
        assert_eq!(value["usage"]["output_tokens"], 3);
        assert!(value["content"][0]["text"].is_string());
    }

    #[tokio::test]
    async fn zero_tokens_still_yields_terminal_frames() {
        let mut c = cfg();
        c.tokens = 0;
        let frames = OpenAiFrames::new(&c);
        let chunks = collect_frames(frames.stream_body("m")).await;
        // role-delta + usage + [DONE], no content chunks.
        assert_eq!(chunks.len(), 3);
        assert_eq!(&chunks[2][..], b"data: [DONE]\n\n");
    }

    /// The whole point of the shared `tail`: two requests against the same
    /// `OpenAiFrames` must not affect each other's echoed model.
    #[tokio::test]
    async fn two_requests_get_independent_models() {
        let frames = OpenAiFrames::new(&cfg());
        let a = collect_frames(frames.stream_body("model-a")).await;
        let b = collect_frames(frames.stream_body("model-b")).await;
        assert!(String::from_utf8(a[0].to_vec())
            .unwrap()
            .contains("model-a"));
        assert!(String::from_utf8(b[0].to_vec())
            .unwrap()
            .contains("model-b"));
    }
}
