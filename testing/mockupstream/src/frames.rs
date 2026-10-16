//! Pre-rendered response fragments for both dialects, streaming and
//! non-streaming.
//!
//! Content chunks are rendered once as `Bytes` and cloned for each streamed
//! token. The terminal usage frame is rebuilt per request so its token count
//! matches the sampled length. The requested model appears in the leading
//! frame; consumers do not inspect it on later chunks.

use std::convert::Infallible;
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

/// The process-wide knobs that never vary per request: only the reported
/// input token count. Everything that *does* vary per request -- TTFT,
/// inter-token delay, output length -- comes from the resolved
/// [`crate::profiles::Profile`] instead; see `handler.rs`.
#[derive(Debug, Clone, Copy)]
pub struct StreamConfig {
    /// Reported input token count.
    pub prompt_tokens: u32,
}

/// One step of a rendered SSE stream: wait `.0` (skipped entirely when
/// zero), then emit `.1` as one already-framed SSE chunk (`data: ...\n\n` or
/// `event: ...\ndata: ...\n\n`).
pub type Step = (Duration, Bytes);

/// This request's draw from a [`crate::profiles::Profile`]: how long to
/// wait before the first frame, and one freshly-drawn inter-token delay per
/// content chunk (its length is `k`, the number of chunks to stream).
pub struct Draw {
    pub ttft: Duration,
    pub inter_token_delays: Vec<Duration>,
}

impl Draw {
    /// Number of content-delta chunks this draw calls for -- also the
    /// reported `output_tokens`/`completion_tokens`.
    pub fn k(&self) -> u32 {
        self.inter_token_delays.len() as u32
    }
}

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
    created: i64,
    /// The single content-delta fragment shared by every stream this
    /// process serves, at every position -- see the module doc. Cloning it
    /// `k` times per request is a refcount bump each, not a re-render.
    content_delta: Bytes,
    done: Bytes,
}

impl OpenAiFrames {
    pub fn new() -> Self {
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
        let done = Bytes::from_static(b"data: [DONE]\n\n");

        Self {
            created,
            content_delta,
            done,
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

    fn final_usage(&self, prompt_tokens: u32, k: u32) -> Bytes {
        sse_data_frame(&json!({
            "id": "chatcmpl-mock",
            "object": "chat.completion.chunk",
            "created": self.created,
            "choices": [],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": k,
                "total_tokens": prompt_tokens + k,
            },
        }))
    }

    /// Build this request's streaming response body: the `ttft`-delayed,
    /// model-bearing leading chunk; `draw.k()` content-delta chunks, each
    /// preceded by its own freshly-drawn inter-token delay; a usage chunk
    /// reporting `draw.k()` completion tokens; then `data: [DONE]`. Every
    /// content-delta chunk is a clone of the one fragment rendered in
    /// [`Self::new`] -- see the module doc.
    pub fn stream_body(&self, model: &str, prompt_tokens: u32, draw: Draw) -> ResponseBody {
        let k = draw.k();
        let mut tail = Vec::with_capacity(draw.inter_token_delays.len() + 2);
        for delay in draw.inter_token_delays {
            tail.push((delay, self.content_delta.clone()));
        }
        tail.push((Duration::ZERO, self.final_usage(prompt_tokens, k)));
        tail.push((Duration::ZERO, self.done.clone()));
        steps_body((draw.ttft, self.role_delta(model)), tail)
    }
}

impl Default for OpenAiFrames {
    fn default() -> Self {
        Self::new()
    }
}

/// Non-streaming `chat.completion` body. Built fresh per request (one
/// `serde_json` allocation, not looped over `k`) since it is only ever
/// rendered once regardless -- unlike the streaming tail above, there is no
/// repeated-per-chunk cost to avoid here.
pub fn openai_completion_body(prompt_tokens: u32, k: u32, model: &str) -> Bytes {
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
            "prompt_tokens": prompt_tokens,
            "completion_tokens": k,
            "total_tokens": prompt_tokens + k,
        },
    });
    Bytes::from(serde_json::to_vec(&value).expect("value is always serializable"))
}

// ------------------------------------------------------------ Anthropic ---

/// Pre-rendered Anthropic Messages fragments.
pub struct AnthropicFrames {
    prompt_tokens: u32,
    content_block_start: Bytes,
    /// The single content-delta fragment shared by every stream this
    /// process serves, at every position -- see the module doc.
    content_block_delta: Bytes,
    content_block_stop: Bytes,
    message_stop: Bytes,
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
        let message_stop = sse_event_frame("message_stop", &json!({"type": "message_stop"}));

        Self {
            prompt_tokens: cfg.prompt_tokens,
            content_block_start,
            content_block_delta,
            content_block_stop,
            message_stop,
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

    fn message_delta(&self, k: u32) -> Bytes {
        sse_event_frame(
            "message_delta",
            &json!({
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                "usage": {"output_tokens": k},
            }),
        )
    }

    /// Build this request's streaming response body: the `ttft`-delayed,
    /// model-bearing `message_start` frame; `content_block_start`;
    /// `draw.k()` content-delta chunks, each preceded by its own
    /// freshly-drawn inter-token delay; `content_block_stop`;
    /// `message_delta` (carrying `draw.k()` as `output_tokens`); then
    /// `message_stop`.
    pub fn stream_body(&self, model: &str, draw: Draw) -> ResponseBody {
        let k = draw.k();
        let mut tail = Vec::with_capacity(draw.inter_token_delays.len() + 4);
        tail.push((Duration::ZERO, self.content_block_start.clone()));
        for delay in draw.inter_token_delays {
            tail.push((delay, self.content_block_delta.clone()));
        }
        tail.push((Duration::ZERO, self.content_block_stop.clone()));
        tail.push((Duration::ZERO, self.message_delta(k)));
        tail.push((Duration::ZERO, self.message_stop.clone()));
        steps_body((draw.ttft, self.message_start(model)), tail)
    }
}

/// Non-streaming Anthropic `message` body. Same reasoning as
/// `openai_completion_body`: built fresh per request since it is rendered
/// exactly once, not looped.
pub fn anthropic_message_body(prompt_tokens: u32, k: u32, model: &str) -> Bytes {
    let value = json!({
        "id": "msg_mock",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": NON_STREAMING_CONTENT}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": prompt_tokens,
            "output_tokens": k,
        },
    });
    Bytes::from(serde_json::to_vec(&value).expect("value is always serializable"))
}

// -------------------------------------------------------- shared plumbing --

/// A cursor over one request's frame sequence: the request-specific leading
/// step (carrying the echoed model), then the request-specific tail built in
/// `stream_body` above (owned outright now -- it embeds this request's own
/// drawn delays and token count, so unlike the pre-scale-test version there
/// is nothing left to share across requests via `Arc`).
///
/// Rust note: this is the state type for the [`futures::stream::unfold`]
/// below -- `unfold` builds a `Stream` out of a plain "given the current
/// state, produce the next item and the next state" async function, which
/// reads a lot like a hand-written state machine without needing one of our
/// own `Future`/`Stream` impls (both of which would need unsafe-free but
/// fiddly manual `Pin` handling to write by hand).
enum StepCursor {
    Leading(Step, Vec<Step>),
    Tail(Vec<Step>, usize),
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
    tail: Vec<Step>,
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

/// Turn a leading step plus this request's tail into a boxed streaming
/// response body. Shared by both dialects above since the cursor shape is
/// identical.
fn steps_body(leading: Step, tail: Vec<Step>) -> ResponseBody {
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
        StreamConfig { prompt_tokens: 10 }
    }

    /// A fixed, no-jitter draw of exactly `k` content chunks -- most tests
    /// here care about frame *shape* and token *counts*, not timing, so this
    /// keeps them fast and deterministic. Timing/length variation itself is
    /// covered in `handler.rs`'s tests, which exercise the RNG draw path.
    fn fixed_draw(k: u32) -> Draw {
        Draw {
            ttft: Duration::ZERO,
            inter_token_delays: vec![Duration::ZERO; k as usize],
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
        let frames = OpenAiFrames::new();
        let chunks = collect_frames(frames.stream_body("gpt-4o-mini", 10, fixed_draw(3))).await;
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
        let body = openai_completion_body(10, 3, "gpt-4o-mini");
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["model"], "gpt-4o-mini");
        assert_eq!(value["usage"]["prompt_tokens"], 10);
        assert_eq!(value["usage"]["completion_tokens"], 3);
        assert!(value["choices"][0]["message"]["content"].is_string());
    }

    #[tokio::test]
    async fn anthropic_stream_shape_and_counts() {
        let frames = AnthropicFrames::new(&cfg());
        let chunks = collect_frames(frames.stream_body("claude-3-haiku", fixed_draw(3))).await;
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
        let body = anthropic_message_body(10, 3, "claude-3-haiku");
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["model"], "claude-3-haiku");
        assert_eq!(value["usage"]["input_tokens"], 10);
        assert_eq!(value["usage"]["output_tokens"], 3);
        assert!(value["content"][0]["text"].is_string());
    }

    #[tokio::test]
    async fn zero_tokens_still_yields_terminal_frames() {
        let frames = OpenAiFrames::new();
        let chunks = collect_frames(frames.stream_body("m", 10, fixed_draw(0))).await;
        // role-delta + usage + [DONE], no content chunks.
        assert_eq!(chunks.len(), 3);
        assert_eq!(&chunks[2][..], b"data: [DONE]\n\n");
    }

    /// The whole point of building the tail per request: two requests
    /// against the same `OpenAiFrames` must not affect each other's echoed
    /// model or drawn length.
    #[tokio::test]
    async fn two_requests_get_independent_models() {
        let frames = OpenAiFrames::new();
        let a = collect_frames(frames.stream_body("model-a", 10, fixed_draw(3))).await;
        let b = collect_frames(frames.stream_body("model-b", 10, fixed_draw(3))).await;
        assert!(String::from_utf8(a[0].to_vec())
            .unwrap()
            .contains("model-a"));
        assert!(String::from_utf8(b[0].to_vec())
            .unwrap()
            .contains("model-b"));
    }

    /// A streamed response with a different `k` per request must end with
    /// the correct terminal frame and a `usage`/`output_tokens` matching the
    /// number of content chunks actually sent -- for both dialects. This is
    /// the acceptance check that varying length never desyncs the reported
    /// count from the real one.
    #[tokio::test]
    async fn openai_usage_always_matches_actual_chunk_count() {
        let frames = OpenAiFrames::new();
        for k in [0u32, 1, 7, 50] {
            let chunks = collect_frames(frames.stream_body("m", 10, fixed_draw(k))).await;
            assert_eq!(chunks.len() as u32, k + 3, "k={k}"); // role + k + usage + [DONE]
            assert_eq!(&chunks[chunks.len() - 1][..], b"data: [DONE]\n\n", "k={k}");
            let usage = String::from_utf8(chunks[chunks.len() - 2].to_vec()).unwrap();
            assert!(
                usage.contains(&format!("\"completion_tokens\":{k}")),
                "k={k} usage={usage}"
            );
        }
    }

    #[tokio::test]
    async fn anthropic_usage_always_matches_actual_chunk_count() {
        let frames = AnthropicFrames::new(&cfg());
        for k in [0u32, 1, 7, 50] {
            let chunks = collect_frames(frames.stream_body("m", fixed_draw(k))).await;
            // message_start + content_block_start + k content_block_delta +
            // content_block_stop + message_delta + message_stop
            assert_eq!(chunks.len() as u32, k + 5, "k={k}");
            let last = String::from_utf8(chunks[chunks.len() - 1].to_vec()).unwrap();
            assert!(last.starts_with("event: message_stop\n"), "k={k}");
            let message_delta = String::from_utf8(chunks[chunks.len() - 2].to_vec()).unwrap();
            assert!(
                message_delta.contains(&format!("\"output_tokens\":{k}")),
                "k={k} message_delta={message_delta}"
            );
        }
    }
}
