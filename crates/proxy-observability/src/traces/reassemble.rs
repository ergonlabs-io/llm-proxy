//! Turns a delivered response (or request) into the body a trace line carries
//! (`internal-docs/trace-export-design.md` section 5). Runs on the exporter
//! thread, never a worker, so it may parse and allocate; its memory stays
//! proportional to its input, which the capture caps bound.
//!
//! The proxy does not guess: a stream it cannot attribute to a supported
//! dialect and shape is exported as the delivered bytes with a partial reason.

use std::collections::BTreeMap;

use base64::Engine as _;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{json, Map, Value};

use super::capture::{PartialReason, TraceDialect};

/// A body as a trace line embeds it.
#[derive(Debug)]
pub enum Body {
    /// Valid JSON, embedded verbatim (not re-serialised).
    Json(Box<RawValue>),
    /// Valid UTF-8 that is not (complete) JSON.
    Text(String),
    /// Anything else, base64 (standard alphabet, padded).
    Base64(String),
}

#[derive(Debug)]
pub struct Reassembled {
    pub body: Body,
    /// The response was `text/event-stream`.
    pub streamed: bool,
    /// Each reason at most once, in first-seen order.
    pub partial: Vec<PartialReason>,
}

fn add_reason(reasons: &mut Vec<PartialReason>, reason: PartialReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

/// Valid UTF-8 as `Text`, anything else as `Base64`.
fn raw_body(bytes: &[u8]) -> Body {
    match std::str::from_utf8(bytes) {
        Ok(s) => Body::Text(s.to_owned()),
        Err(_) => Body::Base64(base64::engine::general_purpose::STANDARD.encode(bytes)),
    }
}

/// `Json` when `bytes` is one complete UTF-8 JSON value.
fn json_body(bytes: &[u8]) -> Option<Body> {
    let text = std::str::from_utf8(bytes).ok()?;
    RawValue::from_string(text.to_owned()).ok().map(Body::Json)
}

/// The request body. `Json` when complete valid JSON; otherwise `Text` or
/// `Base64`. `RequestNotJson` only when the capture is complete (a truncated
/// capture already carries `RequestOverCap`); an empty request has no body to
/// be wrong about.
pub fn request_body(bytes: &[u8], truncated: bool) -> (Body, Vec<PartialReason>) {
    if !truncated {
        if let Some(body) = json_body(bytes) {
            return (body, Vec::new());
        }
    }
    let reasons = if truncated || bytes.is_empty() {
        Vec::new()
    } else {
        vec![PartialReason::RequestNotJson]
    };
    (raw_body(bytes), reasons)
}

fn is_event_stream(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|ct| ct.split(';').next())
        .is_some_and(|mt| mt.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// `content_type` is the response media type header (parameters allowed),
/// `path` the request path, `bytes` the delivered (already decoded) response
/// and `truncated` whether the capture hit a cap (then never `Json`).
pub fn reassemble_response(
    dialect: Option<TraceDialect>,
    path: &str,
    content_type: Option<&str>,
    bytes: &[u8],
    truncated: bool,
) -> Reassembled {
    let mut partial = Vec::new();
    if !is_event_stream(content_type) {
        let body = match (truncated, json_body(bytes)) {
            (false, Some(body)) => body,
            (_, _) => {
                // An empty body without a content type has nothing to be
                // "not JSON" about.
                let empty_untyped = bytes.is_empty() && content_type.is_none();
                if !truncated && !empty_untyped {
                    partial.push(PartialReason::ResponseNotJson);
                }
                raw_body(bytes)
            }
        };
        return Reassembled {
            body,
            streamed: false,
            partial,
        };
    }

    let body = match dialect {
        None => {
            partial.push(PartialReason::UnsupportedDialect);
            raw_body(bytes)
        }
        Some(dialect) => {
            let items = decode_events(&String::from_utf8_lossy(bytes), &mut partial);
            let out = match dialect {
                TraceDialect::Anthropic => anthropic_messages(&items, &mut partial),
                TraceDialect::OpenAi if path_is_responses(path) => openai_responses(&items),
                TraceDialect::OpenAi => match first_object(&items) {
                    Some("chat.completion.chunk") => openai_chat(&items),
                    Some("text_completion") => openai_legacy(&items),
                    _ => Out::Unrecognised,
                },
            };
            match out {
                Out::Unrecognised => {
                    partial.push(PartialReason::UnsupportedShape);
                    raw_body(bytes)
                }
                Out::Body { json, terminal } => {
                    if !terminal {
                        add_reason(&mut partial, PartialReason::StreamUnterminated);
                    }
                    json.and_then(|j| RawValue::from_string(j).ok())
                        .map(Body::Json)
                        .unwrap_or_else(|| raw_body(bytes))
                }
            }
        }
    };
    Reassembled {
        body,
        streamed: true,
        partial,
    }
}

fn path_is_responses(path: &str) -> bool {
    path.split('?')
        .next()
        .is_some_and(|p| p.ends_with("/responses"))
}

// ---------------------------------------------------------------- SSE

struct SseEvent {
    name: Option<String>,
    data: String,
}

/// Splits a stream into events: `event:`/`data:` fields (one optional space
/// after the colon), `\n` or `\r\n` line ends, blank-line dispatch, `:`
/// comments ignored. An event with no `data:` line is not dispatched. A final
/// event without its blank line is still dispatched; it may have been cut.
fn parse_sse(text: &str) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let mut name: Option<String> = None;
    let mut data: Option<String> = None;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            match data.take() {
                Some(data) => events.push(SseEvent {
                    name: name.take(),
                    data,
                }),
                None => name = None,
            }
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        match field {
            "event" => name = Some(value.to_owned()),
            "data" => match &mut data {
                Some(data) => {
                    data.push('\n');
                    data.push_str(value);
                }
                None => data = Some(value.to_owned()),
            },
            _ => {}
        }
    }
    if let Some(data) = data {
        events.push(SseEvent { name, data });
    }
    events
}

enum Item {
    /// `data: [DONE]`.
    Done,
    Json {
        name: Option<String>,
        /// The event's data text, kept so a nested object can be embedded
        /// without re-serialising it.
        data: String,
        value: Value,
    },
}

/// Parses each event's data as JSON. A non-JSON event is skipped and recorded
/// once as `MalformedStream`; reassembly continues.
fn decode_events(text: &str, reasons: &mut Vec<PartialReason>) -> Vec<Item> {
    let mut items = Vec::new();
    for event in parse_sse(text) {
        if event.data.trim() == "[DONE]" {
            items.push(Item::Done);
            continue;
        }
        match serde_json::from_str::<Value>(&event.data) {
            Ok(value) => items.push(Item::Json {
                name: event.name,
                data: event.data,
                value,
            }),
            Err(_) => add_reason(reasons, PartialReason::MalformedStream),
        }
    }
    items
}

fn json_chunks(items: &[Item]) -> impl Iterator<Item = &Value> {
    // Rust note: `filter_map` with a pattern keeps only the `Json` variants.
    items.iter().filter_map(|i| match i {
        Item::Json { value, .. } => Some(value),
        Item::Done => None,
    })
}

fn first_object(items: &[Item]) -> Option<&str> {
    json_chunks(items).find_map(|v| v.get("object")?.as_str())
}

fn saw_done(items: &[Item]) -> bool {
    items.iter().any(|i| matches!(i, Item::Done))
}

/// What one dialect's reassembler produced.
enum Out {
    /// No event of a shape this dialect knows.
    Unrecognised,
    /// `json: None` means "nothing better than the delivered bytes".
    Body {
        json: Option<String>,
        terminal: bool,
    },
}

/// A JSON object with its keys in the given order. Built by hand because
/// `serde_json::Map` sorts keys unless the `preserve_order` feature is on, and
/// the line format documents a stable top-level order.
fn ordered_object(fields: Vec<(&str, Value)>) -> String {
    let parts: Vec<String> = fields
        .into_iter()
        .map(|(k, v)| format!("{}:{}", Value::from(k), v))
        .collect();
    format!("{{{}}}", parts.join(","))
}

fn push_str_field(slot: &mut Option<String>, delta: &Value) {
    if let Some(s) = delta.as_str() {
        slot.get_or_insert_with(String::new).push_str(s);
    }
}

// ------------------------------------------------------- OpenAI chat

#[derive(Default)]
struct ToolAcc {
    id: Option<String>,
    kind: Option<String>,
    name: String,
    arguments: String,
}

#[derive(Default)]
struct ChatChoice {
    role: Option<String>,
    content: Option<String>,
    refusal: Option<String>,
    tool_calls: BTreeMap<u64, ToolAcc>,
    logprobs: Option<Vec<Value>>,
    finish_reason: Option<String>,
}

fn openai_chat(items: &[Item]) -> Out {
    let mut choices: BTreeMap<u64, ChatChoice> = BTreeMap::new();
    let (mut id, mut created, mut model, mut fingerprint, mut usage) =
        (None, None, None, None, None);
    let mut seen_chunk = false;
    for chunk in json_chunks(items) {
        if chunk.get("object").and_then(Value::as_str) != Some("chat.completion.chunk") {
            continue;
        }
        seen_chunk = true;
        // Top level from the first chunk that carries each field.
        for (slot, key) in [
            (&mut id, "id"),
            (&mut created, "created"),
            (&mut model, "model"),
            (&mut fingerprint, "system_fingerprint"),
        ] {
            if slot.is_none() {
                *slot = chunk.get(key).filter(|v| !v.is_null()).cloned();
            }
        }
        if let Some(u) = chunk.get("usage").filter(|u| !u.is_null()) {
            usage = Some(u.clone());
        }
        for c in chunk["choices"].as_array().into_iter().flatten() {
            let choice = choices.entry(c["index"].as_u64().unwrap_or(0)).or_default();
            if let Some(f) = c["finish_reason"].as_str() {
                choice.finish_reason = Some(f.to_owned());
            }
            if let Some(lp) = c["logprobs"]["content"].as_array() {
                choice
                    .logprobs
                    .get_or_insert_with(Vec::new)
                    .extend(lp.iter().cloned());
            }
            let delta = &c["delta"];
            if choice.role.is_none() {
                choice.role = delta["role"].as_str().map(str::to_owned);
            }
            push_str_field(&mut choice.content, &delta["content"]);
            push_str_field(&mut choice.refusal, &delta["refusal"]);
            for tc in delta["tool_calls"].as_array().into_iter().flatten() {
                let acc = choice
                    .tool_calls
                    .entry(tc["index"].as_u64().unwrap_or(0))
                    .or_default();
                if let Some(v) = tc["id"].as_str() {
                    acc.id = Some(v.to_owned());
                }
                if let Some(v) = tc["type"].as_str() {
                    acc.kind = Some(v.to_owned());
                }
                if let Some(v) = tc["function"]["name"].as_str() {
                    acc.name = v.to_owned();
                }
                if let Some(v) = tc["function"]["arguments"].as_str() {
                    acc.arguments.push_str(v);
                }
            }
        }
    }
    if !seen_chunk {
        return Out::Unrecognised;
    }

    let choices: Vec<Value> = choices
        .into_iter()
        .map(|(index, ch)| {
            let mut message = Map::new();
            message.insert(
                "role".into(),
                ch.role.unwrap_or_else(|| "assistant".into()).into(),
            );
            message.insert(
                "content".into(),
                ch.content.map_or(Value::Null, Value::from),
            );
            if let Some(refusal) = ch.refusal {
                message.insert("refusal".into(), refusal.into());
            }
            if !ch.tool_calls.is_empty() {
                let calls: Vec<Value> = ch
                    .tool_calls
                    .into_values()
                    .map(|t| {
                        json!({
                            "id": t.id,
                            "type": t.kind.unwrap_or_else(|| "function".into()),
                            "function": {"name": t.name, "arguments": t.arguments},
                        })
                    })
                    .collect();
                message.insert("tool_calls".into(), calls.into());
            }
            json!({
                "index": index,
                "message": message,
                "logprobs": ch.logprobs.map_or(Value::Null, |c| json!({"content": c})),
                "finish_reason": ch.finish_reason,
            })
        })
        .collect();

    let mut fields = vec![
        ("id", id.unwrap_or(Value::Null)),
        ("object", "chat.completion".into()),
        ("created", created.unwrap_or(Value::Null)),
        ("model", model.unwrap_or(Value::Null)),
        ("choices", choices.into()),
    ];
    if let Some(u) = usage {
        fields.push(("usage", u));
    }
    if let Some(f) = fingerprint {
        fields.push(("system_fingerprint", f));
    }
    Out::Body {
        json: Some(ordered_object(fields)),
        terminal: saw_done(items),
    }
}

// ------------------------------------------------- OpenAI legacy completions

#[derive(Default)]
struct LegacyChoice {
    text: String,
    logprobs: Value,
    finish_reason: Option<String>,
}

fn openai_legacy(items: &[Item]) -> Out {
    let mut choices: BTreeMap<u64, LegacyChoice> = BTreeMap::new();
    let (mut id, mut created, mut model, mut fingerprint, mut usage) =
        (None, None, None, None, None);
    let mut seen_chunk = false;
    for chunk in json_chunks(items) {
        if chunk.get("object").and_then(Value::as_str) != Some("text_completion") {
            continue;
        }
        seen_chunk = true;
        for (slot, key) in [
            (&mut id, "id"),
            (&mut created, "created"),
            (&mut model, "model"),
            (&mut fingerprint, "system_fingerprint"),
        ] {
            if slot.is_none() {
                *slot = chunk.get(key).filter(|v| !v.is_null()).cloned();
            }
        }
        if let Some(u) = chunk.get("usage").filter(|u| !u.is_null()) {
            usage = Some(u.clone());
        }
        for c in chunk["choices"].as_array().into_iter().flatten() {
            let choice = choices.entry(c["index"].as_u64().unwrap_or(0)).or_default();
            if let Some(t) = c["text"].as_str() {
                choice.text.push_str(t);
            }
            if let Some(f) = c["finish_reason"].as_str() {
                choice.finish_reason = Some(f.to_owned());
            }
            if !c["logprobs"].is_null() {
                choice.logprobs = c["logprobs"].clone();
            }
        }
    }
    if !seen_chunk {
        return Out::Unrecognised;
    }
    let choices: Vec<Value> = choices
        .into_iter()
        .map(|(index, c)| {
            json!({
                "text": c.text,
                "index": index,
                "logprobs": c.logprobs,
                "finish_reason": c.finish_reason,
            })
        })
        .collect();
    let mut fields = vec![
        ("id", id.unwrap_or(Value::Null)),
        ("object", "text_completion".into()),
        ("created", created.unwrap_or(Value::Null)),
        ("model", model.unwrap_or(Value::Null)),
        ("choices", choices.into()),
    ];
    if let Some(u) = usage {
        fields.push(("usage", u));
    }
    if let Some(f) = fingerprint {
        fields.push(("system_fingerprint", f));
    }
    Out::Body {
        json: Some(ordered_object(fields)),
        terminal: saw_done(items),
    }
}

// ------------------------------------------------------ OpenAI Responses

#[derive(Deserialize)]
struct ResponsesEvent {
    #[serde(rename = "type")]
    kind: Option<String>,
    response: Option<Box<RawValue>>,
}

fn openai_responses(items: &[Item]) -> Out {
    let mut recognised = false;
    let mut latest_progress: Option<String> = None;
    for item in items {
        let Item::Json { data, .. } = item else {
            continue;
        };
        let Ok(ev) = serde_json::from_str::<ResponsesEvent>(data) else {
            continue;
        };
        let Some(kind) = ev.kind.as_deref().filter(|k| k.starts_with("response.")) else {
            continue;
        };
        recognised = true;
        match kind {
            "response.completed" | "response.incomplete" | "response.failed" => {
                return Out::Body {
                    json: ev.response.map(|r| r.get().to_owned()),
                    terminal: true,
                };
            }
            "response.created" | "response.in_progress" => {
                if let Some(r) = ev.response {
                    latest_progress = Some(r.get().to_owned());
                }
            }
            _ => {}
        }
    }
    if recognised {
        Out::Body {
            json: latest_progress,
            terminal: false,
        }
    } else {
        Out::Unrecognised
    }
}

// ------------------------------------------------------ Anthropic messages

fn append_str(block: &mut Value, key: &str, s: &str) {
    let Some(obj) = block.as_object_mut() else {
        return;
    };
    if let Some(Value::String(cur)) = obj.get_mut(key) {
        cur.push_str(s);
    } else {
        obj.insert(key.to_owned(), s.into());
    }
}

fn anthropic_messages(items: &[Item], reasons: &mut Vec<PartialReason>) -> Out {
    let mut base: Option<Value> = None;
    let mut blocks: BTreeMap<u64, Value> = BTreeMap::new();
    let mut json_bufs: BTreeMap<u64, String> = BTreeMap::new();
    let mut delta_fields = Map::new();
    let mut usage_updates = Map::new();
    let mut error: Option<String> = None;
    let (mut recognised, mut terminal) = (false, false);

    for item in items {
        let Item::Json { name, data, value } = item else {
            continue;
        };
        let kind = value["type"].as_str().or(name.as_deref());
        let index = value["index"].as_u64().unwrap_or(0);
        match kind {
            Some("message_start") => {
                recognised = true;
                base = Some(value["message"].clone());
            }
            Some("content_block_start") => {
                recognised = true;
                blocks.insert(index, value["content_block"].clone());
            }
            Some("content_block_delta") => {
                recognised = true;
                let delta = &value["delta"];
                let block = blocks.entry(index).or_insert_with(|| json!({}));
                match delta["type"].as_str() {
                    Some("text_delta") => {
                        append_str(block, "text", delta["text"].as_str().unwrap_or(""))
                    }
                    Some("thinking_delta") => {
                        append_str(block, "thinking", delta["thinking"].as_str().unwrap_or(""))
                    }
                    Some("signature_delta") => append_str(
                        block,
                        "signature",
                        delta["signature"].as_str().unwrap_or(""),
                    ),
                    Some("input_json_delta") => json_bufs
                        .entry(index)
                        .or_default()
                        .push_str(delta["partial_json"].as_str().unwrap_or("")),
                    _ => {}
                }
            }
            Some("content_block_stop") => {
                recognised = true;
                // An empty buffer keeps the start block's `input` (usually {}).
                if let Some(buf) = json_bufs.remove(&index).filter(|b| !b.is_empty()) {
                    let input = serde_json::from_str::<Value>(&buf).unwrap_or_else(|_| {
                        add_reason(reasons, PartialReason::MalformedStream);
                        Value::String(buf)
                    });
                    if let Some(obj) = blocks
                        .entry(index)
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                    {
                        obj.insert("input".into(), input);
                    }
                }
            }
            Some("message_delta") => {
                recognised = true;
                for key in ["stop_reason", "stop_sequence"] {
                    if let Some(v) = value["delta"].get(key) {
                        delta_fields.insert(key.to_owned(), v.clone());
                    }
                }
                if let Some(u) = value["usage"].as_object() {
                    usage_updates.extend(u.iter().map(|(k, v)| (k.clone(), v.clone())));
                }
            }
            Some("message_stop") => {
                recognised = true;
                terminal = true;
            }
            Some("error") => {
                recognised = true;
                error = Some(data.trim().to_owned());
            }
            // `ping` and event types added later carry nothing we merge.
            _ => {}
        }
    }
    if !recognised {
        return Out::Unrecognised;
    }
    if let Some(error) = error {
        return Out::Body {
            json: Some(error),
            terminal,
        };
    }

    let mut message = base.unwrap_or_else(|| json!({"type": "message", "role": "assistant"}));
    if let Some(obj) = message.as_object_mut() {
        obj.insert(
            "content".into(),
            blocks.into_values().collect::<Vec<_>>().into(),
        );
        obj.extend(delta_fields);
        if !usage_updates.is_empty() {
            let usage = obj.entry("usage").or_insert_with(|| json!({}));
            if let Some(usage) = usage.as_object_mut() {
                usage.extend(usage_updates);
            }
        }
    }
    Out::Body {
        json: Some(message.to_string()),
        terminal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use PartialReason::*;
    use TraceDialect::{Anthropic, OpenAi};

    fn json_of(body: &Body) -> Value {
        match body {
            Body::Json(raw) => serde_json::from_str(raw.get()).unwrap(),
            other => panic!("expected Json, got {other:?}"),
        }
    }

    fn sse(dialect: Option<TraceDialect>, path: &str, bytes: &[u8]) -> Reassembled {
        reassemble_response(dialect, path, Some("text/event-stream"), bytes, false)
    }

    /// Removes the value at a JSON pointer such as `/choices/0/message/refusal`.
    fn remove_pointer(v: &mut Value, pointer: &str) {
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        v.pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .and_then(|o| o.remove(key))
            .unwrap_or_else(|| panic!("fixture lacks {pointer}"));
    }

    /// Each fixture pair is the same completion streamed and non-streamed. The
    /// fields in `absent_from_stream` are the only ones the non-streaming
    /// response has that the stream never carries.
    ///
    /// - OpenAI chat: the non-streaming message has `refusal: null` and
    ///   `annotations: []`; stream chunks only send `refusal` when set and have
    ///   no annotations. The streams include the `include_usage` chunk.
    /// - OpenAI Responses and Anthropic: the stream carries everything
    ///   (`response.completed` holds the full object; Anthropic deltas rebuild
    ///   every field), so nothing is removed.
    #[test]
    fn reassembled_stream_equals_the_non_streaming_response() {
        let chat_gaps: &[&str] = &[
            "/choices/0/message/refusal",
            "/choices/0/message/annotations",
        ];
        let cases = [
            (
                "openai chat text",
                include_str!("../../tests/fixtures/traces/openai_chat_text.sse"),
                include_str!("../../tests/fixtures/traces/openai_chat_text.json"),
                Some(OpenAi),
                "/v1/chat/completions",
                chat_gaps,
            ),
            (
                "openai chat parallel tool calls",
                include_str!("../../tests/fixtures/traces/openai_chat_tools.sse"),
                include_str!("../../tests/fixtures/traces/openai_chat_tools.json"),
                Some(OpenAi),
                "/v1/chat/completions",
                chat_gaps,
            ),
            (
                "openai responses text",
                include_str!("../../tests/fixtures/traces/openai_responses_text.sse"),
                include_str!("../../tests/fixtures/traces/openai_responses_text.json"),
                Some(OpenAi),
                "/v1/responses?foo=bar",
                &[],
            ),
            (
                "anthropic text",
                include_str!("../../tests/fixtures/traces/anthropic_text.sse"),
                include_str!("../../tests/fixtures/traces/anthropic_text.json"),
                Some(Anthropic),
                "/v1/messages",
                &[],
            ),
            (
                "anthropic tool_use",
                include_str!("../../tests/fixtures/traces/anthropic_tool_use.sse"),
                include_str!("../../tests/fixtures/traces/anthropic_tool_use.json"),
                Some(Anthropic),
                "/v1/messages",
                &[],
            ),
            (
                "anthropic thinking",
                include_str!("../../tests/fixtures/traces/anthropic_thinking.sse"),
                include_str!("../../tests/fixtures/traces/anthropic_thinking.json"),
                Some(Anthropic),
                "/v1/messages",
                &[],
            ),
        ];
        for (name, stream, full, dialect, path, absent_from_stream) in cases {
            let got = sse(dialect, path, stream.as_bytes());
            assert!(got.streamed, "{name}");
            assert!(got.partial.is_empty(), "{name}: {:?}", got.partial);
            let mut expected: Value = serde_json::from_str(full).unwrap();
            for pointer in absent_from_stream {
                remove_pointer(&mut expected, pointer);
            }
            assert_eq!(json_of(&got.body), expected, "{name}");
        }
    }

    /// Top-level key order is part of the line format, and CRLF streams parse
    /// the same as LF ones.
    #[test]
    fn chat_output_key_order_is_stable_and_crlf_is_equivalent() {
        let lf = include_str!("../../tests/fixtures/traces/openai_chat_text.sse");
        let crlf = lf.replace('\n', "\r\n");
        let a = sse(Some(OpenAi), "/v1/chat/completions", lf.as_bytes());
        let b = sse(Some(OpenAi), "/v1/chat/completions", crlf.as_bytes());
        let (Body::Json(a), Body::Json(b)) = (a.body, b.body) else {
            panic!("expected Json");
        };
        assert_eq!(a.get(), b.get());
        let keys = [
            "id",
            "object",
            "created",
            "model",
            "choices",
            "usage",
            "system_fingerprint",
        ];
        let positions: Vec<usize> = keys
            .iter()
            .map(|k| a.get().find(&format!("\"{k}\":")).unwrap())
            .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{}", a.get());
    }

    /// Comments, a JSON value split over two `data:` lines, and a final event
    /// without its blank line; legacy completions merge per index.
    #[test]
    fn legacy_completions_with_sse_edge_syntax() {
        let stream = concat!(
            ": keep-alive\n",
            "data: {\"id\":\"cmpl-1\",\"object\":\"text_completion\",\n",
            "data: \"created\":5,\"model\":\"m\",\"choices\":[{\"text\":\"foo\",\"index\":0,\"finish_reason\":null}]}\n\n",
            "data:{\"id\":\"cmpl-1\",\"object\":\"text_completion\",\"choices\":[{\"text\":\"bar\",\"index\":0,\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]",
        );
        let got = sse(Some(OpenAi), "/v1/completions", stream.as_bytes());
        assert!(got.partial.is_empty(), "{:?}", got.partial);
        assert_eq!(
            json_of(&got.body),
            json!({"id":"cmpl-1","object":"text_completion","created":5,"model":"m",
                   "choices":[{"text":"foobar","index":0,"logprobs":null,"finish_reason":"stop"}]})
        );
    }

    /// Dropping the terminal event keeps what was merged and says so, whether
    /// or not the capture cap caused the cut; an Anthropic `error` event is the
    /// body.
    #[test]
    fn unterminated_streams_keep_what_was_reassembled() {
        let chat = include_str!("../../tests/fixtures/traces/openai_chat_text.sse");
        let cut = chat.split("data: [DONE]").next().unwrap();
        for truncated in [false, true] {
            let got = reassemble_response(
                Some(OpenAi),
                "/v1/chat/completions",
                Some("text/event-stream; charset=utf-8"),
                cut.as_bytes(),
                truncated,
            );
            assert_eq!(got.partial, vec![StreamUnterminated]);
            assert_eq!(
                json_of(&got.body)["choices"][0]["message"]["content"],
                "Hello, world!"
            );
        }

        let anthropic = include_str!("../../tests/fixtures/traces/anthropic_text.sse");
        let head = anthropic
            .split("event: content_block_start")
            .next()
            .unwrap();
        let errored = format!(
            "{head}event: error\ndata: {{\"type\":\"error\",\"error\":{{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}}}\n\n"
        );
        let got = sse(Some(Anthropic), "/v1/messages", errored.as_bytes());
        assert_eq!(got.partial, vec![StreamUnterminated]);
        assert_eq!(json_of(&got.body)["error"]["type"], "overloaded_error");

        // Responses: no terminal event falls back to the latest progress object.
        let responses = include_str!("../../tests/fixtures/traces/openai_responses_text.sse");
        let cut = responses.split("event: response.completed").next().unwrap();
        let got = sse(Some(OpenAi), "/v1/responses", cut.as_bytes());
        assert_eq!(got.partial, vec![StreamUnterminated]);
        assert_eq!(json_of(&got.body)["status"], "in_progress");
    }

    /// Non-JSON data lines are skipped, flagged once, and do not disturb the rest.
    #[test]
    fn malformed_data_lines_are_skipped_and_flagged_once() {
        let chat = include_str!("../../tests/fixtures/traces/openai_chat_text.sse");
        let dirty = chat.replace(
            "data: [DONE]",
            "data: {not json\n\ndata: also bad\n\ndata: [DONE]",
        );
        let got = sse(Some(OpenAi), "/v1/chat/completions", dirty.as_bytes());
        assert_eq!(got.partial, vec![MalformedStream]);
        assert_eq!(
            json_of(&got.body)["choices"][0]["message"]["content"],
            "Hello, world!"
        );

        // Anthropic: unparseable tool input keeps the raw string.
        let bad_tool = include_str!("../../tests/fixtures/traces/anthropic_tool_use.sse")
            .replace("\\\"Paris\\\"}", "\\\"Par");
        let got = sse(Some(Anthropic), "/v1/messages", bad_tool.as_bytes());
        assert_eq!(got.partial, vec![MalformedStream]);
        assert_eq!(
            json_of(&got.body)["content"][1]["input"],
            "{\"city\": \"Par"
        );
    }

    /// The proxy does not guess: anything it cannot attribute is the delivered
    /// bytes, as text or base64.
    #[test]
    fn unattributable_streams_export_the_delivered_bytes() {
        let chat = include_str!("../../tests/fixtures/traces/openai_chat_text.sse");
        let got = sse(None, "/v1/chat/completions", chat.as_bytes());
        assert!(matches!(&got.body, Body::Text(t) if t == chat));
        assert_eq!(got.partial, vec![UnsupportedDialect]);

        let other = "data: {\"object\":\"something.else\"}\n\ndata: [DONE]\n\n";
        let got = sse(Some(OpenAi), "/v1/chat/completions", other.as_bytes());
        assert!(matches!(&got.body, Body::Text(t) if t == other));
        assert_eq!(got.partial, vec![UnsupportedShape]);

        // Anthropic parser on an OpenAI stream (cross-dialect): no event matches.
        let got = sse(Some(Anthropic), "/v1/messages", chat.as_bytes());
        assert!(matches!(&got.body, Body::Text(t) if t == chat));
        assert_eq!(got.partial, vec![UnsupportedShape]);

        let got = sse(None, "/v1/x", &[0xff, 0xfe, b'a']);
        assert!(matches!(&got.body, Body::Base64(b) if b == "//5h"));
    }

    /// Non-SSE responses: complete JSON is embedded verbatim; everything else is
    /// text/base64, and a truncated JSON prefix is never `Json`.
    #[test]
    fn non_streamed_bodies() {
        let text = "{\"b\": 1,\n \"a\":[1.0,  2]}";
        let got = reassemble_response(
            Some(OpenAi),
            "/v1/x",
            Some("application/json"),
            text.as_bytes(),
            false,
        );
        assert!(!got.streamed && got.partial.is_empty());
        assert!(matches!(&got.body, Body::Json(r) if r.get() == text));

        // (content type, bytes, truncated, expected reasons)
        let cases = [
            (Some("application/json"), &b"{\"a\":"[..], true, vec![]),
            (
                Some("application/json"),
                &b"<html>"[..],
                false,
                vec![ResponseNotJson],
            ),
            (
                Some("application/json"),
                &b""[..],
                false,
                vec![ResponseNotJson],
            ),
            (None, &b""[..], false, vec![]),
            (
                Some("application/json"),
                &[0xff, 0x00][..],
                false,
                vec![ResponseNotJson],
            ),
        ];
        for (ct, bytes, truncated, reasons) in cases {
            let got = reassemble_response(None, "/v1/x", ct, bytes, truncated);
            assert!(!matches!(got.body, Body::Json(_)), "{bytes:?}");
            assert_eq!(got.partial, reasons, "{bytes:?}");
        }
        let got = reassemble_response(None, "/v1/x", Some("text/plain"), &[0xff, 0x00], false);
        assert!(matches!(got.body, Body::Base64(_)));
    }

    #[test]
    fn request_body_cases() {
        let (body, reasons) = request_body(b"{\"model\":\"m\"}", false);
        assert!(
            matches!(&body, Body::Json(r) if r.get() == "{\"model\":\"m\"}") && reasons.is_empty()
        );

        // Truncated: never Json, and no extra reason (the caller has RequestOverCap).
        let (body, reasons) = request_body(b"{\"model\":\"m\"}", true);
        assert!(matches!(body, Body::Text(_)) && reasons.is_empty());

        let (body, reasons) = request_body(b"a=b&c=d", false);
        assert!(matches!(&body, Body::Text(t) if t == "a=b&c=d"));
        assert_eq!(reasons, vec![RequestNotJson]);

        let (body, reasons) = request_body(&[0xff, 0xad], false);
        assert!(matches!(&body, Body::Base64(b) if b == "/60="));
        assert_eq!(reasons, vec![RequestNotJson]);

        let (body, reasons) = request_body(b"", false);
        assert!(matches!(&body, Body::Text(t) if t.is_empty()) && reasons.is_empty());
    }
}
