//! WP-34 (Lane H) — provider usage/token extraction.
//!
//! This module answers one question: **how many tokens did this response
//! cost?** It is the input to token-based rate limiting (the budget store and
//! the 429 enforcement path, both later chunks) and to the GenAI token
//! counters in WP-33.
//!
//! # Why this is a pure-function module
//!
//! Everything here operates on plain byte slices and owns no I/O, no async,
//! and no filter-chain state. That is deliberate: it makes the tricky part
//! (parsing) exhaustively unit-testable against scripted provider responses,
//! and it keeps the streaming filter that eventually calls it trivial.
//!
//! # The hard requirement: streaming-safe, never buffer the stream
//!
//! WP-33 guarantees flush-through on the encode path — tokens reach the client
//! as they arrive. So usage extraction may **not** accumulate the response
//! body to parse it at the end. [`SseUsageScanner`] is fed whatever byte chunks
//! happen to arrive and must retain only a bounded amount of state (at most one
//! partial line).
//!
//! Chunk boundaries fall in arbitrary places — mid-line, mid-JSON, even mid
//! UTF-8 character. A scanner that assumes each `push` is a whole line or a
//! whole event is the single most likely bug in this module, which is why the
//! tests hammer that case specifically.
//!
//! # Status
//!
//! Function bodies are `todo!()` placeholders. The tests below encode the
//! required behavior and are `#[ignore]`d so the CI gate stays green; remove
//! the `#[ignore]` from a test as you make it pass.

use serde::Deserialize;

/// Tokens consumed by one request/response exchange.
///
/// Rust note: `Copy` is derived because this is two `u64`s — small enough that
/// copying is cheaper than referencing, so callers needn't think about borrows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenUsage {
    /// Prompt/input tokens (OpenAI `prompt_tokens`, Anthropic `input_tokens`).
    pub input_tokens: u64,
    /// Completion/output tokens (OpenAI `completion_tokens`, Anthropic
    /// `output_tokens`).
    pub output_tokens: u64,
}

impl TokenUsage {
    pub fn total(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }
}

/// Which provider's response schema to parse.
///
/// Kept as an enum rather than a trait because the set of dialects is small,
/// closed, and known at config time; adding a variant should force every
/// `match` in this module to be updated (ground rule #1's spirit: no silent
/// fallthrough).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// OpenAI chat-completions schema (also used by most OpenAI-compatible
    /// providers).
    OpenAi,
    /// Anthropic messages schema.
    Anthropic,
}

/// Upper bound on a single retained SSE line. A provider that never emits a
/// newline must not be able to grow our buffer without limit — that would be a
/// memory-exhaustion vector driven by an upstream we don't control.
///
/// A line longer than this is discarded (usage is best-effort telemetry; losing
/// it is strictly better than an OOM).
pub const MAX_SSE_LINE_BYTES: usize = 1 << 20; // 1 MiB

// --- non-streaming (whole-body) extraction ---------------------------------

/// Extract usage from a complete, non-streaming JSON response body.
///
/// This is the easy path: the caller already has the whole body (a plain
/// `application/json` chat completion, not an SSE stream).
///
/// **Required behavior**
/// - `Dialect::OpenAi`: read the top-level `usage` object's `prompt_tokens`
///   and `completion_tokens`.
///   `{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`
///   → `TokenUsage { input_tokens: 10, output_tokens: 5 }`.
///   Ignore `total_tokens` — derive it via [`TokenUsage::total`] so a provider
///   that reports an inconsistent total can't corrupt billing.
/// - `Dialect::Anthropic`: read the top-level `usage` object's `input_tokens`
///   and `output_tokens`.
/// - Body with no `usage` key → `None`.
/// - Malformed/invalid JSON → `None`. **Never panic** — this parses bytes from
///   an upstream we do not control.
/// - A `usage` object missing *one* of the two fields → treat the missing one
///   as `0` (providers omit `completion_tokens` on some error responses).
/// - A `usage` object containing **neither** of this dialect's two field names
///   → `None`, not `Some(0, 0)`. This is what stops an OpenAI parser from
///   "successfully" reading an Anthropic `usage` object (whose keys it doesn't
///   recognize) and silently reporting zero tokens — a wrong answer is worse
///   than no answer when the output feeds billing. The
///   `openai_scanner_does_not_misread_anthropic_events` test covers this.
/// - `usage` present but not a JSON object (e.g. a string) → `None`.
pub fn extract_json_usage(dialect: Dialect, body: &[u8]) -> Option<TokenUsage> {
    let _ = (dialect, body);
    todo!("WP-34: parse the whole-body JSON usage object")
}

// --- streaming (SSE) extraction --------------------------------------------

/// Incrementally scans an SSE response for usage, without buffering the stream.
///
/// Feed it every response-body chunk in order via [`Self::push`]; ask for the
/// result with [`Self::usage`] (typically once the stream ends, though it is
/// valid to ask at any point — it returns the best answer known so far).
///
/// # SSE shape you need to handle
///
/// An SSE stream is lines separated by `\n` (possibly `\r\n`). The lines that
/// matter here start with `data:` (one optional space after the colon is
/// conventional and must be tolerated). Other lines (`event:`, `id:`, `:`
/// comments, blank separators) are not needed for either dialect below, though
/// you may find `event:` useful.
///
/// **OpenAI** (`stream_options.include_usage = true`): every streamed chunk is
/// a `data:` line holding a JSON object. Almost all carry token deltas and no
/// usage. The *final* data frame before `data: [DONE]` carries an empty
/// `choices` array and the `usage` object:
/// ```text
/// data: {"choices":[{"delta":{"content":"Hi"}}]}
/// data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5}}
/// data: [DONE]
/// ```
/// `data: [DONE]` is a sentinel, not JSON — parsing it must not error.
/// If `include_usage` was not set, no frame carries usage → `None`.
///
/// **Anthropic**: usage arrives across two different event types.
/// `message_start` carries the input token count (and an initial output count);
/// each `message_delta` carries a **cumulative** output count, so the last one
/// wins — do not sum them.
/// ```text
/// event: message_start
/// data: {"type":"message_start","message":{"usage":{"input_tokens":10,"output_tokens":1}}}
/// event: message_delta
/// data: {"type":"message_delta","usage":{"output_tokens":15}}
/// ```
/// → `TokenUsage { input_tokens: 10, output_tokens: 15 }`.
///
/// # Implementation guidance
///
/// Keep a small `Vec<u8>` of the bytes after the last newline seen. On `push`,
/// append the chunk, then repeatedly split off complete lines and process them,
/// leaving any trailing partial line in the buffer for the next call. Enforce
/// [`MAX_SSE_LINE_BYTES`] on that buffer.
pub struct SseUsageScanner {
    dialect: Dialect,
    /// Bytes received since the last newline — the only unbounded-ish state,
    /// capped by [`MAX_SSE_LINE_BYTES`].
    ///
    /// Rust note: the `allow(dead_code)` is here **only** because `push` is
    /// still a `todo!()` placeholder, so nothing reads this field yet and
    /// clippy's `-D warnings` gate would fail the build. Delete the attribute
    /// as soon as you implement `push`.
    #[allow(dead_code)]
    partial: Vec<u8>,
    /// Best usage known so far.
    usage: Option<TokenUsage>,
}

impl SseUsageScanner {
    pub fn new(dialect: Dialect) -> Self {
        Self {
            dialect,
            partial: Vec::new(),
            usage: None,
        }
    }

    /// Feed the next chunk of response body. Chunks may split anywhere.
    ///
    /// **Required behavior**
    /// - Handle a line split across any number of `push` calls (even one byte
    ///   at a time).
    /// - Tolerate `\r\n` as well as `\n`.
    /// - Tolerate `data:{...}` and `data: {...}` (optional single space).
    /// - Ignore `data: [DONE]` and any line whose payload isn't valid JSON.
    /// - Never panic on arbitrary bytes, including invalid UTF-8.
    /// - Never let `self.partial` exceed [`MAX_SSE_LINE_BYTES`]; discard the
    ///   oversized line instead (and resync at the next newline).
    pub fn push(&mut self, chunk: &[u8]) {
        let _ = chunk;
        todo!("WP-34: buffer partial lines, extract complete ones, update self.usage")
    }

    /// The usage discovered so far, if any.
    pub fn usage(&self) -> Option<TokenUsage> {
        self.usage
    }

    /// The dialect this scanner was built for.
    pub fn dialect(&self) -> Dialect {
        self.dialect
    }
}

// --- helper types you may find useful --------------------------------------
//
// Rust note: `#[derive(Deserialize)]` lets serde_json build these structs
// straight from JSON. `Option<..>` fields make a key optional (absent -> None)
// and `#[serde(default)]` makes a missing numeric field default to 0 instead of
// erroring. You are free to ignore these and parse via `serde_json::Value` if
// you prefer -- they're a starting point, not a requirement.

/// OpenAI's `usage` object.
#[derive(Debug, Deserialize)]
pub struct OpenAiUsage {
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
}

/// Anthropic's `usage` object. Both fields are optional because
/// `message_delta` carries only `output_tokens`.
#[derive(Debug, Deserialize)]
pub struct AnthropicUsage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

#[cfg(test)]
mod tests {
    //! The WP-34 acceptance suite. Every test is `#[ignore]`d so the CI gate
    //! stays green while the implementation is still `todo!()`.
    //!
    //! **Workflow:** pick a test, delete its `#[ignore]` line, run
    //! `cargo test -p proxy-filters` (it will fail), implement until it
    //! passes. Work top to bottom — they're ordered easiest to hardest.

    use super::*;

    // ---- extract_json_usage: OpenAI ---------------------------------------

    #[test]
    #[ignore = "WP-34: implement extract_json_usage"]
    fn openai_json_basic_usage() {
        let body =
            br#"{"id":"x","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#;
        let usage = extract_json_usage(Dialect::OpenAi, body).expect("usage should be found");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(usage.total(), 15);
    }

    #[test]
    #[ignore = "WP-34: implement extract_json_usage"]
    fn openai_json_without_usage_is_none() {
        let body = br#"{"id":"x","choices":[]}"#;
        assert_eq!(extract_json_usage(Dialect::OpenAi, body), None);
    }

    /// Upstream bytes are untrusted: malformed JSON must return `None`, not
    /// panic and take down the worker.
    #[test]
    #[ignore = "WP-34: implement extract_json_usage"]
    fn malformed_json_is_none_not_a_panic() {
        for body in [
            &b"not json at all"[..],
            &b"{"[..],
            &b""[..],
            &b"{\"usage\": \"not-an-object\"}"[..],
            &[0xff, 0xfe, 0x00][..], // invalid UTF-8
        ] {
            assert_eq!(
                extract_json_usage(Dialect::OpenAi, body),
                None,
                "body: {body:?}"
            );
            assert_eq!(
                extract_json_usage(Dialect::Anthropic, body),
                None,
                "body: {body:?}"
            );
        }
    }

    /// Providers omit `completion_tokens` on some responses; treat as 0.
    #[test]
    #[ignore = "WP-34: implement extract_json_usage"]
    fn openai_json_missing_field_defaults_to_zero() {
        let body = br#"{"usage":{"prompt_tokens":7}}"#;
        let usage = extract_json_usage(Dialect::OpenAi, body).expect("usage should be found");
        assert_eq!(usage.input_tokens, 7);
        assert_eq!(usage.output_tokens, 0);
    }

    /// `total_tokens` is derived, never trusted — a provider reporting a bogus
    /// total must not corrupt our accounting.
    #[test]
    #[ignore = "WP-34: implement extract_json_usage"]
    fn openai_json_ignores_provider_reported_total() {
        let body = br#"{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":9999}}"#;
        let usage = extract_json_usage(Dialect::OpenAi, body).expect("usage should be found");
        assert_eq!(
            usage.total(),
            15,
            "total must be derived from the two counts"
        );
    }

    // ---- extract_json_usage: Anthropic ------------------------------------

    #[test]
    #[ignore = "WP-34: implement extract_json_usage"]
    fn anthropic_json_basic_usage() {
        let body = br#"{"type":"message","usage":{"input_tokens":12,"output_tokens":34}}"#;
        let usage = extract_json_usage(Dialect::Anthropic, body).expect("usage should be found");
        assert_eq!(usage.input_tokens, 12);
        assert_eq!(usage.output_tokens, 34);
    }

    // ---- SseUsageScanner: OpenAI ------------------------------------------

    /// Helper: feed a whole stream as one chunk.
    fn scan_all(dialect: Dialect, stream: &[u8]) -> Option<TokenUsage> {
        let mut s = SseUsageScanner::new(dialect);
        s.push(stream);
        s.usage()
    }

    #[test]
    #[ignore = "WP-34: implement SseUsageScanner::push"]
    fn openai_sse_final_frame_carries_usage() {
        let stream = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\
                       data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n\
                       data: [DONE]\n";
        let usage = scan_all(Dialect::OpenAi, stream).expect("usage should be found");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
    }

    /// Without `stream_options.include_usage`, no frame carries usage.
    #[test]
    #[ignore = "WP-34: implement SseUsageScanner::push"]
    fn openai_sse_without_usage_is_none() {
        let stream = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\
                       data: [DONE]\n";
        assert_eq!(scan_all(Dialect::OpenAi, stream), None);
    }

    /// `data: [DONE]` is a sentinel, not JSON. It must not panic or error.
    #[test]
    #[ignore = "WP-34: implement SseUsageScanner::push"]
    fn done_sentinel_is_tolerated() {
        let stream = b"data: [DONE]\n";
        assert_eq!(scan_all(Dialect::OpenAi, stream), None);
    }

    /// Both `data:{...}` and `data: {...}` are valid in the wild.
    #[test]
    #[ignore = "WP-34: implement SseUsageScanner::push"]
    fn optional_space_after_data_colon() {
        let with_space = b"data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2}}\n";
        let without = b"data:{\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2}}\n";
        assert_eq!(
            scan_all(Dialect::OpenAi, with_space),
            scan_all(Dialect::OpenAi, without),
        );
        assert!(scan_all(Dialect::OpenAi, without).is_some());
    }

    #[test]
    #[ignore = "WP-34: implement SseUsageScanner::push"]
    fn crlf_line_endings_are_handled() {
        let stream = b"data: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\r\n\
                       data: [DONE]\r\n";
        let usage = scan_all(Dialect::OpenAi, stream).expect("usage should be found");
        assert_eq!(usage.input_tokens, 3);
        assert_eq!(usage.output_tokens, 4);
    }

    // ---- SseUsageScanner: the streaming-safety tests ----------------------
    //
    // These are the ones that catch the real bug. Everything above can pass
    // with an implementation that wrongly assumes each push is a whole line.

    /// The critical case: chunk boundaries fall in arbitrary places. Feeding
    /// the same stream one byte at a time must produce the same answer.
    #[test]
    #[ignore = "WP-34: implement SseUsageScanner::push"]
    fn usage_is_found_when_pushed_one_byte_at_a_time() {
        let stream =
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n\
                       data: [DONE]\n";
        let mut s = SseUsageScanner::new(Dialect::OpenAi);
        for byte in stream.iter() {
            s.push(&[*byte]);
        }
        let usage = s
            .usage()
            .expect("usage should survive byte-at-a-time chunking");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
    }

    /// Splitting at every possible offset must never change the result.
    #[test]
    #[ignore = "WP-34: implement SseUsageScanner::push"]
    fn every_split_point_yields_the_same_usage() {
        let stream: &[u8] =
            b"data: {\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\ndata: [DONE]\n";
        let expected = TokenUsage {
            input_tokens: 10,
            output_tokens: 5,
        };
        for split in 0..=stream.len() {
            let mut s = SseUsageScanner::new(Dialect::OpenAi);
            s.push(&stream[..split]);
            s.push(&stream[split..]);
            assert_eq!(
                s.usage(),
                Some(expected),
                "failed when split at offset {split}"
            );
        }
    }

    /// A stream that ends without a trailing newline still has a final line.
    /// Decide and document your behavior: the simplest correct choice is to
    /// treat end-of-stream as terminating the last line. (If you choose to
    /// require a trailing newline, change this test to match — but say why.)
    #[test]
    #[ignore = "WP-34: implement SseUsageScanner::push"]
    fn final_line_without_trailing_newline() {
        let stream = b"data: {\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":3}}";
        let usage = scan_all(Dialect::OpenAi, stream);
        assert_eq!(
            usage,
            Some(TokenUsage {
                input_tokens: 2,
                output_tokens: 3
            })
        );
    }

    #[test]
    #[ignore = "WP-34: implement SseUsageScanner::push"]
    fn empty_pushes_are_harmless() {
        let mut s = SseUsageScanner::new(Dialect::OpenAi);
        s.push(b"");
        s.push(b"data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n");
        s.push(b"");
        assert!(s.usage().is_some());
    }

    /// Arbitrary bytes, including invalid UTF-8, must not panic.
    #[test]
    #[ignore = "WP-34: implement SseUsageScanner::push"]
    fn binary_garbage_does_not_panic() {
        let mut s = SseUsageScanner::new(Dialect::OpenAi);
        s.push(&[0xff, 0xfe, 0x00, b'\n']);
        s.push(b"data: \xff\xfe not json\n");
        assert_eq!(s.usage(), None);
    }

    /// An upstream that never sends a newline must not grow our buffer without
    /// bound. Push well past the cap and assert we stayed bounded — then that
    /// we resync and still find usage on the next well-formed line.
    #[test]
    #[ignore = "WP-34: implement the MAX_SSE_LINE_BYTES guard"]
    fn oversized_line_is_bounded_and_resyncs() {
        let mut s = SseUsageScanner::new(Dialect::OpenAi);
        let blob = vec![b'x'; 64 * 1024];
        for _ in 0..40 {
            // 2.5 MiB total, no newline anywhere.
            s.push(&blob);
            assert!(
                s.partial.len() <= MAX_SSE_LINE_BYTES,
                "partial buffer grew past the cap: {}",
                s.partial.len()
            );
        }
        // Terminate the oversized line, then send a good one.
        s.push(b"\ndata: {\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":9}}\n");
        let usage = s
            .usage()
            .expect("scanner should resync after an oversized line");
        assert_eq!(usage.input_tokens, 8);
        assert_eq!(usage.output_tokens, 9);
    }

    // ---- SseUsageScanner: Anthropic --------------------------------------

    #[test]
    #[ignore = "WP-34: implement Anthropic SSE handling"]
    fn anthropic_sse_combines_message_start_and_message_delta() {
        let stream = b"event: message_start\n\
                       data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\
                       \n\
                       event: message_delta\n\
                       data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n";
        let usage = scan_all(Dialect::Anthropic, stream).expect("usage should be found");
        assert_eq!(usage.input_tokens, 10, "input comes from message_start");
        assert_eq!(
            usage.output_tokens, 15,
            "output comes from the last message_delta"
        );
    }

    /// `message_delta` output counts are CUMULATIVE — the last one wins.
    /// Summing them (10 + 15 + 20 = 45) is the bug this test exists to catch.
    #[test]
    #[ignore = "WP-34: implement Anthropic SSE handling"]
    fn anthropic_message_delta_is_cumulative_not_additive() {
        let stream = b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":1}}}\n\
                       data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":10}}\n\
                       data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n\
                       data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":20}}\n";
        let usage = scan_all(Dialect::Anthropic, stream).expect("usage should be found");
        assert_eq!(usage.input_tokens, 5);
        assert_eq!(
            usage.output_tokens, 20,
            "last cumulative value wins, not the sum"
        );
    }

    #[test]
    #[ignore = "WP-34: implement Anthropic SSE handling"]
    fn anthropic_sse_survives_byte_at_a_time_chunking() {
        let stream = b"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\
                       data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n";
        let mut s = SseUsageScanner::new(Dialect::Anthropic);
        for byte in stream.iter() {
            s.push(&[*byte]);
        }
        assert_eq!(
            s.usage(),
            Some(TokenUsage {
                input_tokens: 10,
                output_tokens: 15
            })
        );
    }

    /// A dialect mismatch should simply find nothing, not misparse.
    #[test]
    #[ignore = "WP-34: implement both dialects"]
    fn openai_scanner_does_not_misread_anthropic_events() {
        let anthropic = b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n";
        assert_eq!(scan_all(Dialect::OpenAi, anthropic), None);
    }
}
