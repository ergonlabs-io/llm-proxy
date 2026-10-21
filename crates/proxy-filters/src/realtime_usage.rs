//! Usage of a realtime WebSocket session, read from its server event frames
//! (ADR-0015).
//!
//! The session's upstream bytes reach the usage filter as an ordinary
//! response body (envoy-semantics.md S10.2). This scanner decodes their
//! RFC 6455 frames as they pass, reassembles each text message, and reads
//! the `usage` of every `response.done` event, summing them across the
//! session. Nothing is buffered beyond the message being read, which is
//! capped, and the bytes are never changed.
//!
//! A `response.done` without readable usage, and a response still in flight
//! when the session ends, is a response the session did not pay for. Each is
//! counted (`llmproxy_realtime_usage_missing_total{reason}`) and warned
//! about, rate-limited, so a missing meter is loud, never silently free
//! (AGENTS.md "Fail-open controls").

use proxy_http::websocket::{opcode, FrameDecoder};

use crate::usage::{realtime_usage_parts, Modality, TokenUsage};

/// The longest text message read in full. Event frames are small; the large
/// ones are audio deltas, which carry no usage. A longer message is skipped,
/// and counted when its start shows it is a `response.done`.
pub(crate) const MAX_EVENT_BYTES: usize = 1 << 20;

/// How much of an over-long message is kept to tell what event it was.
const EVENT_HEAD_BYTES: usize = 256;

/// Why a response's usage was not metered. The label set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Missing {
    /// A `response.done` with no `usage`, or one that reports no tokens.
    NoUsage,
    /// A `response.done` that is not valid JSON, or over [`MAX_EVENT_BYTES`].
    Unreadable,
    /// A text message compressed with `permessage-deflate`. The usage filter
    /// strips the extension offer, so a compliant server never sends one.
    Compressed,
    /// A response created but not done when the session ended.
    Cut,
}

impl Missing {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Missing::NoUsage => "no_usage",
            Missing::Unreadable => "unreadable",
            Missing::Compressed => "compressed",
            Missing::Cut => "cut",
        }
    }
}

#[derive(Default)]
pub(crate) struct RealtimeScanner {
    frames: FrameDecoder,
    /// The frame now being read is the first piece of a new frame.
    frame_open: bool,
    message: Option<Message>,
    usage: Option<(TokenUsage, Modality)>,
    created: u64,
    done: u64,
    missing: Vec<Missing>,
    /// The raw `usage` object of the last metered `response.done`, as
    /// evidence for the request record.
    last_usage_json: Option<String>,
}

struct Message {
    text: bool,
    compressed: bool,
    bytes: Vec<u8>,
    oversized: bool,
}

impl RealtimeScanner {
    pub(crate) fn push(&mut self, data: &[u8]) {
        // Rust note: the decoder borrows `self.frames` mutably while the
        // closure needs the rest of `self`, so the frames are taken out for
        // the call and put back.
        let mut frames = std::mem::take(&mut self.frames);
        frames.feed(data, &mut |piece| {
            let first = !self.frame_open;
            self.frame_open = !piece.last;
            let header = piece.header;
            if header.opcode >= opcode::CLOSE {
                // Control frames may sit between a message's fragments.
                return;
            }
            if first && header.opcode != opcode::CONTINUATION {
                self.message = Some(Message {
                    text: header.opcode == opcode::TEXT,
                    compressed: header.rsv1,
                    bytes: Vec::new(),
                    oversized: false,
                });
            }
            let Some(message) = self.message.as_mut() else {
                return;
            };
            if message.text && !message.compressed {
                let room = if message.oversized {
                    EVENT_HEAD_BYTES.saturating_sub(message.bytes.len())
                } else {
                    MAX_EVENT_BYTES + 1 - message.bytes.len()
                };
                let take = piece.payload.len().min(room);
                message.bytes.extend_from_slice(&piece.payload[..take]);
                if !message.oversized && message.bytes.len() > MAX_EVENT_BYTES {
                    message.oversized = true;
                    message.bytes.truncate(EVENT_HEAD_BYTES);
                }
            }
            if piece.last && header.fin {
                if let Some(message) = self.message.take() {
                    self.finish(message);
                }
            }
        });
        self.frames = frames;
    }

    fn finish(&mut self, message: Message) {
        if !message.text {
            return;
        }
        if message.compressed {
            self.missing.push(Missing::Compressed);
            return;
        }
        if message.oversized {
            if contains(&message.bytes, b"\"response.done\"") {
                self.done += 1;
                self.missing.push(Missing::Unreadable);
            }
            return;
        }
        let names_done = contains(&message.bytes, b"\"response.done\"");
        if !names_done && !contains(&message.bytes, b"\"response.created\"") {
            return;
        }
        let event: serde_json::Value = match serde_json::from_slice(&message.bytes) {
            Ok(event) => event,
            Err(_) => {
                if names_done {
                    self.done += 1;
                    self.missing.push(Missing::Unreadable);
                }
                return;
            }
        };
        match event.get("type").and_then(serde_json::Value::as_str) {
            Some("response.created") => self.created += 1,
            Some("response.done") => {
                self.done += 1;
                let usage = event.get("response").and_then(|r| r.get("usage"));
                match usage.and_then(realtime_usage_parts) {
                    Some((tokens, modality)) => {
                        self.add(tokens, modality);
                        self.last_usage_json = usage.map(|u| u.to_string());
                    }
                    None => self.missing.push(Missing::NoUsage),
                }
            }
            _ => {}
        }
    }

    fn add(&mut self, tokens: TokenUsage, modality: Modality) {
        let (sum, sum_modality) = self.usage.get_or_insert_with(Default::default);
        sum.input_tokens += tokens.input_tokens;
        sum.cached_tokens += tokens.cached_tokens;
        sum.cache_creation_tokens += tokens.cache_creation_tokens;
        sum.output_tokens += tokens.output_tokens;
        sum_modality.input_audio_tokens += modality.input_audio_tokens;
        sum_modality.output_audio_tokens += modality.output_audio_tokens;
        sum_modality.input_image_tokens += modality.input_image_tokens;
        sum_modality.output_image_tokens += modality.output_image_tokens;
    }

    /// The session's summed usage so far. `None` until a `response.done`
    /// reported some.
    pub(crate) fn usage(&self) -> Option<(TokenUsage, Modality)> {
        self.usage
    }

    pub(crate) fn last_usage_json(&self) -> Option<&str> {
        self.last_usage_json.as_deref()
    }

    /// Every unmetered response so far, oldest first, and with `ended` the
    /// responses still in flight as [`Missing::Cut`]. Drains the list, so each
    /// is reported once.
    pub(crate) fn take_missing(&mut self, ended: bool) -> Vec<Missing> {
        let mut missing = std::mem::take(&mut self.missing);
        if ended {
            let in_flight = self.created.saturating_sub(self.done);
            missing.extend((0..in_flight).map(|_| Missing::Cut));
            self.created = self.done;
        }
        missing
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One unmasked server frame.
    fn frame(fin: bool, op: u8, rsv1: bool, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![(if fin { 0x80 } else { 0 }) | (if rsv1 { 0x40 } else { 0 }) | op];
        match payload.len() {
            n if n < 126 => out.push(n as u8),
            n if n <= 0xffff => {
                out.push(126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        out.extend_from_slice(payload);
        out
    }

    fn text(event: &str) -> Vec<u8> {
        frame(true, opcode::TEXT, false, event.as_bytes())
    }

    const DONE_1: &str = r#"{"type":"response.done","event_id":"e1","response":{"id":"r1","status":"completed","usage":{"total_tokens":180,"input_tokens":100,"output_tokens":80,"input_token_details":{"cached_tokens":20,"text_tokens":30,"audio_tokens":70,"cached_tokens_details":{"text_tokens":10,"audio_tokens":10}},"output_token_details":{"text_tokens":20,"audio_tokens":60}}}}"#;
    const DONE_2: &str = r#"{"type":"response.done","response":{"usage":{"input_tokens":10,"output_tokens":5,"input_token_details":{"text_tokens":10},"output_token_details":{"text_tokens":5}}}}"#;

    /// Usage is summed across every `response.done`, in the session's
    /// buckets: non-cached input, cached input, output, and the audio
    /// subsets the rate card's modality rates price.
    #[test]
    fn sums_response_done_usage_across_a_session_split_anywhere() {
        let mut wire = text(r#"{"type":"session.created","session":{}}"#);
        wire.extend(text(
            r#"{"type":"response.created","response":{"id":"r1"}}"#,
        ));
        wire.extend(frame(true, opcode::BINARY, false, b"\x00\x01"));
        wire.extend(text(DONE_1));
        wire.extend(text(r#"{"type":"response.created"}"#));
        wire.extend(text(DONE_2));
        for chunk in [1, 7, wire.len()] {
            let mut scanner = RealtimeScanner::default();
            for piece in wire.chunks(chunk) {
                scanner.push(piece);
            }
            let (tokens, modality) = scanner.usage().expect("usage");
            assert_eq!(
                tokens,
                TokenUsage {
                    input_tokens: 80 + 10,
                    cached_tokens: 20,
                    cache_creation_tokens: 0,
                    output_tokens: 85,
                }
            );
            assert_eq!(
                modality.input_audio_tokens, 60,
                "70 audio, 10 of them cached"
            );
            assert_eq!(modality.output_audio_tokens, 60);
            assert!(scanner.take_missing(true).is_empty(), "chunk {chunk}");
        }
    }

    /// A `response.done` split across a text frame and continuations, with a
    /// ping between the fragments, is still read.
    #[test]
    fn reads_a_fragmented_event_around_a_control_frame() {
        let (a, b) = DONE_2.as_bytes().split_at(20);
        let mut wire = frame(false, opcode::TEXT, false, a);
        wire.extend(frame(true, 0x9, false, b"ping"));
        wire.extend(frame(true, opcode::CONTINUATION, false, b));
        let mut scanner = RealtimeScanner::default();
        scanner.push(&wire);
        assert_eq!(scanner.usage().map(|(t, _)| t.output_tokens), Some(5));
    }

    /// Every response the session did not pay for is reported, with why.
    #[test]
    fn counts_each_response_without_usage_by_reason() {
        // One `response.created` for each `response.done` below that names
        // itself, and one more still in flight at the end.
        let mut wire = Vec::new();
        for _ in 0..4 {
            wire.extend(text(r#"{"type":"response.created"}"#));
        }
        wire.extend(text(
            r#"{"type":"response.done","response":{"status":"failed"}}"#,
        ));
        wire.extend(text(r#"{"type":"response.done", not json"#));
        wire.extend(frame(true, opcode::TEXT, true, b"\x01\x02compressed"));
        let mut big = br#"{"type":"response.done","response":{"output":""#.to_vec();
        big.extend(vec![b'x'; MAX_EVENT_BYTES]);
        big.extend_from_slice(br#""}}"#);
        wire.extend(text(std::str::from_utf8(&big).unwrap()));
        // A big audio delta is skipped without a report.
        let mut delta = br#"{"type":"response.audio.delta","delta":""#.to_vec();
        delta.extend(vec![b'A'; MAX_EVENT_BYTES]);
        delta.extend_from_slice(br#""}"#);
        wire.extend(text(std::str::from_utf8(&delta).unwrap()));
        let mut scanner = RealtimeScanner::default();
        scanner.push(&wire);
        assert_eq!(scanner.usage(), None);
        assert_eq!(
            scanner.take_missing(false),
            vec![
                Missing::NoUsage,
                Missing::Unreadable,
                Missing::Compressed,
                Missing::Unreadable
            ]
        );
        assert_eq!(
            scanner.take_missing(true),
            vec![Missing::Cut],
            "reported once"
        );
        assert!(scanner.take_missing(true).is_empty());
    }
}
