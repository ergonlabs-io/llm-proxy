//! Per-endpoint wire shapes: request bodies and SSE frame classification for
//! the three dialects the driver speaks. Kept deliberately independent of
//! `testing/diffrig`'s mock types (see module doc in `lib.rs`) -- this code
//! only assumes the wire shapes those mocks (and real providers) emit.

use serde_json::{json, Value};

use crate::sse::SseFrame;

/// Which provider/endpoint shape a run targets. Selects the request body,
/// the URL path, and how SSE frames are classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Endpoint {
    /// OpenAI `POST /v1/chat/completions`.
    Chat,
    /// OpenAI `POST /v1/responses`.
    Responses,
    /// Anthropic `POST /v1/messages`.
    Messages,
}

impl Endpoint {
    /// The request path this endpoint is served at.
    pub fn path(self) -> &'static str {
        match self {
            Endpoint::Chat => "/v1/chat/completions",
            Endpoint::Responses => "/v1/responses",
            Endpoint::Messages => "/v1/messages",
        }
    }

    /// Build the JSON request body for one stream.
    pub fn build_body(self, model: &str, prompt: &str, max_tokens: u32, stream: bool) -> Value {
        match self {
            Endpoint::Chat => json!({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "stream": stream,
            }),
            Endpoint::Responses => json!({
                "model": model,
                "input": prompt,
                "max_output_tokens": max_tokens,
                "stream": stream,
            }),
            Endpoint::Messages => json!({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "stream": stream,
            }),
        }
    }

    /// Extra headers this dialect's provider expects beyond
    /// `content-type`/`host`/`content-length` (which the driver sets itself).
    /// Anthropic wants `x-api-key` + `anthropic-version` instead of the
    /// bearer-token `authorization` header OpenAI-shaped endpoints use.
    pub fn auth_headers(self, api_key: Option<&str>) -> Vec<(&'static str, String)> {
        let Some(key) = api_key else {
            return Vec::new();
        };
        match self {
            Endpoint::Chat | Endpoint::Responses => {
                vec![("authorization", format!("Bearer {key}"))]
            }
            Endpoint::Messages => vec![
                ("x-api-key", key.to_string()),
                ("anthropic-version", "2023-06-01".to_string()),
            ],
        }
    }

    /// Classify one already-parsed SSE frame for this dialect.
    ///
    /// Rust note: this hands back a borrow-free `FrameKind` (an owned
    /// `String` for token text) rather than a reference into `frame`, since
    /// the caller needs to record it into metrics that outlive the frame.
    pub fn classify(self, frame: &SseFrame) -> FrameKind {
        match self {
            Endpoint::Chat => classify_chat(frame),
            Endpoint::Responses => classify_responses(frame),
            Endpoint::Messages => classify_messages(frame),
        }
    }
}

/// What one SSE frame means to the driver: does it carry a piece of the
/// generated text (a "token" for our purposes -- one delta chunk, not a
/// tokenizer token), does it end the stream, or is it bookkeeping we don't
/// care about (role deltas, `content_block_start`, etc.)?
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameKind {
    ContentDelta(String),
    Terminal,
    Other,
}

/// OpenAI `/v1/chat/completions`: data-only frames, each a
/// `chat.completion.chunk` JSON object; terminated by a literal
/// `data: [DONE]` frame (not JSON).
fn classify_chat(frame: &SseFrame) -> FrameKind {
    if frame.data.trim() == "[DONE]" {
        return FrameKind::Terminal;
    }
    let Ok(value) = serde_json::from_str::<Value>(&frame.data) else {
        return FrameKind::Other;
    };
    let text = value
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("delta"))
        .and_then(|d| d.get("content"))
        .and_then(Value::as_str);
    match text {
        Some(text) if !text.is_empty() => FrameKind::ContentDelta(text.to_string()),
        _ => FrameKind::Other,
    }
}

/// OpenAI `/v1/responses`: named events. The content-bearing event is
/// `response.output_text.delta` (`data.delta` is the text chunk);
/// `response.completed` ends the stream. Some deployments also send a
/// trailing `data: [DONE]` frame, so that is treated as terminal too.
fn classify_responses(frame: &SseFrame) -> FrameKind {
    if frame.data.trim() == "[DONE]" {
        return FrameKind::Terminal;
    }
    match frame.event.as_deref() {
        Some("response.completed") => FrameKind::Terminal,
        Some("response.output_text.delta") => {
            let text = serde_json::from_str::<Value>(&frame.data)
                .ok()
                .and_then(|v| v.get("delta").and_then(Value::as_str).map(str::to_string));
            match text {
                Some(text) if !text.is_empty() => FrameKind::ContentDelta(text),
                _ => FrameKind::Other,
            }
        }
        _ => FrameKind::Other,
    }
}

/// Anthropic `/v1/messages`: every frame carries both an `event:` and
/// `data:` line. Sequence is `message_start` -> `content_block_start` ->
/// `content_block_delta`* -> `content_block_stop` -> `message_delta` ->
/// `message_stop`. Content deltas are `content_block_delta` frames whose
/// `delta.type` is `text_delta`; `message_stop` ends the stream.
fn classify_messages(frame: &SseFrame) -> FrameKind {
    match frame.event.as_deref() {
        Some("message_stop") => FrameKind::Terminal,
        Some("content_block_delta") => {
            let value = match serde_json::from_str::<Value>(&frame.data) {
                Ok(v) => v,
                Err(_) => return FrameKind::Other,
            };
            let delta = value.get("delta");
            let is_text =
                delta.and_then(|d| d.get("type")).and_then(Value::as_str) == Some("text_delta");
            let text = delta.and_then(|d| d.get("text")).and_then(Value::as_str);
            match (is_text, text) {
                (true, Some(text)) if !text.is_empty() => FrameKind::ContentDelta(text.to_string()),
                _ => FrameKind::Other,
            }
        }
        _ => FrameKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_delta_and_done() {
        let delta = SseFrame {
            event: None,
            data: r#"{"choices":[{"delta":{"content":"hi"}}]}"#.to_string(),
        };
        assert_eq!(
            Endpoint::Chat.classify(&delta),
            FrameKind::ContentDelta("hi".to_string())
        );
        let done = SseFrame {
            event: None,
            data: "[DONE]".to_string(),
        };
        assert_eq!(Endpoint::Chat.classify(&done), FrameKind::Terminal);
    }

    #[test]
    fn chat_role_only_delta_is_other() {
        let frame = SseFrame {
            event: None,
            data: r#"{"choices":[{"delta":{"role":"assistant"}}]}"#.to_string(),
        };
        assert_eq!(Endpoint::Chat.classify(&frame), FrameKind::Other);
    }

    #[test]
    fn responses_delta_and_completed() {
        let delta = SseFrame {
            event: Some("response.output_text.delta".to_string()),
            data: r#"{"delta":"hi"}"#.to_string(),
        };
        assert_eq!(
            Endpoint::Responses.classify(&delta),
            FrameKind::ContentDelta("hi".to_string())
        );
        let completed = SseFrame {
            event: Some("response.completed".to_string()),
            data: "{}".to_string(),
        };
        assert_eq!(
            Endpoint::Responses.classify(&completed),
            FrameKind::Terminal
        );
    }

    #[test]
    fn messages_text_delta_and_stop() {
        let delta = SseFrame {
            event: Some("content_block_delta".to_string()),
            data: r#"{"delta":{"type":"text_delta","text":"hi"}}"#.to_string(),
        };
        assert_eq!(
            Endpoint::Messages.classify(&delta),
            FrameKind::ContentDelta("hi".to_string())
        );
        let stop = SseFrame {
            event: Some("message_stop".to_string()),
            data: "{}".to_string(),
        };
        assert_eq!(Endpoint::Messages.classify(&stop), FrameKind::Terminal);
    }

    #[test]
    fn messages_content_block_start_is_other() {
        let frame = SseFrame {
            event: Some("content_block_start".to_string()),
            data: r#"{"content_block":{"type":"text","text":""}}"#.to_string(),
        };
        assert_eq!(Endpoint::Messages.classify(&frame), FrameKind::Other);
    }
}
