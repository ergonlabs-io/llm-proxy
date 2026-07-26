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
//! Extraction is complete for all three dialects (OpenAI chat completions,
//! OpenAI Responses, and Anthropic Messages), streaming and non-streaming, and
//! the full acceptance suite below runs in the CI gate.
//!
//! Not yet done: this module is a pure extractor with no `HttpFilter` wrapper,
//! so nothing calls it on real traffic. Wiring it into the encode chain is
//! WP-33.

/// Tokens consumed by one request/response exchange, split into the buckets
/// that are **priced differently** so downstream cost accounting can apply a
/// per-bucket rate.
///
/// The buckets are deliberately **non-overlapping** — each token is counted in
/// exactly one field — so [`total`](Self::total) is a true sum and each field
/// can be multiplied by its own rate without double-counting. This means
/// `input_tokens` is the *non-cached* input only: for OpenAI, whose
/// `prompt_tokens` is inclusive of cached tokens, we subtract the cached
/// portion out; for Anthropic, whose `input_tokens` already excludes cache, we
/// take it as-is. (So `input_tokens` here will not always equal the provider's
/// headline `prompt_tokens`.)
///
/// Rust note: `Copy` is derived because this is four `u64`s — small enough that
/// copying is cheaper than referencing, so callers needn't think about borrows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenUsage {
    /// Standard (non-cached) input tokens, priced at the base input rate.
    /// OpenAI `prompt_tokens` minus its cached portion; Anthropic `input_tokens`.
    pub input_tokens: u64,
    /// Cache-**read** input tokens, served from a prompt cache at a steep
    /// discount. OpenAI `prompt_tokens_details.cached_tokens` (a subset of
    /// `prompt_tokens`); Anthropic `cache_read_input_tokens`.
    pub cached_tokens: u64,
    /// Cache-**write** input tokens, priced at a premium over base input.
    /// Anthropic `cache_creation_input_tokens`; OpenAI has no such billed
    /// bucket, so this stays 0 there.
    pub cache_creation_tokens: u64,
    /// Output/completion tokens (OpenAI `completion_tokens`, Anthropic
    /// `output_tokens`).
    pub output_tokens: u64,
}

impl TokenUsage {
    /// Total token count across all buckets. Sound to sum because the buckets
    /// don't overlap.
    pub fn total(&self) -> u64 {
        self.input_tokens + self.cached_tokens + self.cache_creation_tokens + self.output_tokens
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
    /// OpenAI's newer Responses API (`POST /v1/responses`) schema:
    /// `usage.input_tokens` / `usage.output_tokens` /
    /// `usage.input_tokens_details.cached_tokens`.
    ///
    /// **Why this is its own variant and not folded into `OpenAi` or
    /// `Anthropic`:** the field *names* (`input_tokens`/`output_tokens`)
    /// coincide with Anthropic's, but the *semantics* do not, and getting
    /// this wrong is a billing-accuracy bug, not a cosmetic one. OpenAI's
    /// `input_tokens` here is **inclusive** of cached tokens (same as
    /// chat-completions' `prompt_tokens`), so the cached portion must be
    /// subtracted out; Anthropic's `input_tokens` **already excludes**
    /// cached tokens. Reusing `Dialect::Anthropic` for Responses traffic
    /// would silently fold cached tokens into the full-price input bucket
    /// and report `cached_tokens: 0` — wrong on both counts. Reusing
    /// `Dialect::OpenAi` doesn't work either, since it reads
    /// `prompt_tokens`/`completion_tokens`, which the Responses API doesn't
    /// send.
    OpenAiResponses,
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
/// - `Dialect::OpenAiResponses`: read the top-level `usage` object's
///   `input_tokens` (inclusive of cache, so the cached portion is subtracted
///   out — see [`Dialect::OpenAiResponses`]'s doc comment) and
///   `output_tokens`.
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
    let json_body: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = json_body.get("usage")?;
    usage_from_object(dialect, usage)
}

// --- shared usage-object reading -------------------------------------------
//
// Both the whole-body path and the SSE path pull the same two token counts out
// of the same shaped `usage` object; this is that one primitive, so the
// dialect-specific key names live in exactly one place.

/// The token counts a single `usage` object carries, already normalized to the
/// non-overlapping buckets of [`TokenUsage`] but kept as `Option`s so callers
/// can tell which fields the object actually contained.
///
/// The presence information matters for two reasons: the streaming merge must
/// know which fields a given frame carried (an Anthropic `message_delta`
/// carries only `output_tokens`), and "no recognized field present at all" is
/// what distinguishes this dialect's object from another dialect's — the guard
/// that stops an OpenAI scanner from "successfully" reading an Anthropic frame.
#[derive(Default)]
struct RawTokens {
    input: Option<u64>,
    cached: Option<u64>,
    cache_creation: Option<u64>,
    output: Option<u64>,
}

impl RawTokens {
    /// True when the object carried none of this dialect's recognized keys.
    fn is_empty(&self) -> bool {
        self.input.is_none()
            && self.cached.is_none()
            && self.cache_creation.is_none()
            && self.output.is_none()
    }
}

/// Read the per-bucket token counts for `dialect` out of a `usage` object,
/// applying the normalization documented on [`TokenUsage`] (all `None` when
/// `usage` is not a JSON object).
fn read_tokens(dialect: Dialect, usage: &serde_json::Value) -> RawTokens {
    if !usage.is_object() {
        return RawTokens::default();
    }
    let u64_at = |key: &str| usage.get(key).and_then(|v| v.as_u64());
    match dialect {
        Dialect::OpenAi => {
            // `cached_tokens` is nested under `prompt_tokens_details` and is a
            // *subset* of `prompt_tokens`; subtract it out so `input` is the
            // non-cached remainder (saturating, in case a provider ever reports
            // cached > prompt). OpenAI bills no cache-write bucket.
            let cached = usage
                .get("prompt_tokens_details")
                .and_then(|d| d.get("cached_tokens"))
                .and_then(|v| v.as_u64());
            let input =
                u64_at("prompt_tokens").map(|prompt| prompt.saturating_sub(cached.unwrap_or(0)));
            RawTokens {
                input,
                cached,
                cache_creation: None,
                output: u64_at("completion_tokens"),
            }
        }
        Dialect::Anthropic => RawTokens {
            // Anthropic's `input_tokens` already excludes cached tokens, which
            // it reports in their own sibling fields — no subtraction needed.
            input: u64_at("input_tokens"),
            cached: u64_at("cache_read_input_tokens"),
            cache_creation: u64_at("cache_creation_input_tokens"),
            output: u64_at("output_tokens"),
        },
        Dialect::OpenAiResponses => {
            // Same inclusive-of-cache semantics as chat-completions'
            // `prompt_tokens` (see the `Dialect::OpenAi` arm above), just
            // under different field names and a nested `_details` object.
            // Subtract the cached portion out so `input` is the non-cached
            // remainder. OpenAI bills no cache-write bucket here either.
            let cached = usage
                .get("input_tokens_details")
                .and_then(|d| d.get("cached_tokens"))
                .and_then(|v| v.as_u64());
            let input =
                u64_at("input_tokens").map(|total| total.saturating_sub(cached.unwrap_or(0)));
            RawTokens {
                input,
                cached,
                cache_creation: None,
                output: u64_at("output_tokens"),
            }
        }
    }
}

/// Read a complete `usage` object into a [`TokenUsage`], defaulting missing
/// (but recognized) buckets to `0`.
///
/// Returns `None` when the object carries **none** of this dialect's token
/// keys — that is what stops one dialect's parser from "successfully" reading
/// another dialect's `usage` object and reporting zero tokens (a wrong answer
/// is worse than no answer when this feeds billing).
fn usage_from_object(dialect: Dialect, usage: &serde_json::Value) -> Option<TokenUsage> {
    let raw = read_tokens(dialect, usage);
    if raw.is_empty() {
        return None;
    }
    Some(TokenUsage {
        input_tokens: raw.input.unwrap_or(0),
        cached_tokens: raw.cached.unwrap_or(0),
        cache_creation_tokens: raw.cache_creation.unwrap_or(0),
        output_tokens: raw.output.unwrap_or(0),
    })
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
/// **OpenAI Responses API** (`/v1/responses`): usage arrives once, in the
/// terminal `response.completed` named event, nested one level down under
/// `response` (not at the top level like chat-completions). There is no
/// `data: [DONE]` sentinel on this API — `response.completed` is itself the
/// terminal frame.
/// ```text
/// event: response.completed
/// data: {"type":"response.completed","response":{"usage":{"input_tokens":10,"output_tokens":5,"input_tokens_details":{"cached_tokens":4}}}}
/// ```
/// → `TokenUsage { input_tokens: 6, cached_tokens: 4, output_tokens: 5 }`
/// (`input_tokens` is inclusive of cache, same subtraction as the
/// non-streaming path).
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
        if chunk.is_empty() {
            return;
        }
        self.partial.extend_from_slice(chunk);
        // Peel off every complete (newline-terminated) line, leaving any
        // trailing partial line in the buffer for the next call.
        while let Some(newline_pos) = self.partial.iter().position(|&b| b == b'\n') {
            // Rust note: `drain(..=newline_pos)` removes the line *and* its `\n`
            // from `partial` and yields them; we collect into an owned `Vec` so
            // the borrow on `partial` ends before we touch `self.usage`.
            let line: Vec<u8> = self.partial.drain(..=newline_pos).collect();
            merge_line(&mut self.usage, self.dialect, &line[..line.len() - 1]);
        }
        // What remains has no newline. If it has grown past the cap, this is an
        // upstream that never emits a newline; discard it (usage is best-effort
        // telemetry — losing a line beats an OOM) and resync at the next one.
        if self.partial.len() > MAX_SSE_LINE_BYTES {
            self.partial.clear();
        }
    }

    /// The usage discovered so far, if any.
    ///
    /// Folds in any trailing partial line: end-of-stream implicitly terminates
    /// the final line even without a trailing newline. Done read-only here (on
    /// a copy) rather than by mutating in `push`, so `usage()` stays a pure
    /// accessor that is valid to call at any point in the stream.
    pub fn usage(&self) -> Option<TokenUsage> {
        let mut result = self.usage;
        if !self.partial.is_empty() {
            merge_line(&mut result, self.dialect, &self.partial);
        }
        result
    }

    /// The dialect this scanner was built for.
    pub fn dialect(&self) -> Dialect {
        self.dialect
    }
}

// --- SSE frame merging ------------------------------------------------------

/// Locate the `usage` object inside one parsed SSE data frame, per dialect.
///
/// OpenAI (chat-completions) carries it at the top level. Anthropic splits it
/// across two event shapes: `message_start` nests it under `message` (with
/// the input count), while `message_delta` puts it at the top level (with a
/// cumulative output count) — so we look under `message` first and fall back
/// to the top level. The Responses API only ever sends usage once, in the
/// terminal `response.completed` frame, nested under `response` — unlike
/// Anthropic, it has no other event type to fall back to, and adding one
/// would let this dialect wrongly "successfully" read an Anthropic
/// `message_delta` frame (which happens to share the `output_tokens` name at
/// its top level).
fn frame_usage_object(dialect: Dialect, value: &serde_json::Value) -> Option<&serde_json::Value> {
    match dialect {
        Dialect::OpenAi => value.get("usage"),
        Dialect::Anthropic => value
            .get("message")
            .and_then(|m| m.get("usage"))
            .or_else(|| value.get("usage")),
        Dialect::OpenAiResponses => value.get("response").and_then(|r| r.get("usage")),
    }
}

/// Merge the token counts a single frame carries into `target`.
///
/// A field is updated only when the frame actually carries it, so an Anthropic
/// `message_delta` (output only) does not clobber the input count set earlier
/// by `message_start`. Output counts are *set*, not added — Anthropic's
/// `message_delta` output is cumulative, so the last frame wins (summing would
/// over-count). A frame carrying neither recognized key contributes nothing,
/// which is what keeps one dialect's scanner from misreading another's frames.
fn merge_usage(target: &mut Option<TokenUsage>, dialect: Dialect, usage: &serde_json::Value) {
    let raw = read_tokens(dialect, usage);
    if raw.is_empty() {
        return;
    }
    let entry = target.get_or_insert_with(TokenUsage::default);
    if let Some(input) = raw.input {
        entry.input_tokens = input;
    }
    if let Some(cached) = raw.cached {
        entry.cached_tokens = cached;
    }
    if let Some(cache_creation) = raw.cache_creation {
        entry.cache_creation_tokens = cache_creation;
    }
    if let Some(output) = raw.output {
        entry.output_tokens = output;
    }
}

/// Parse one SSE line (its trailing `\n` already stripped by the caller) and
/// merge any usage it carries into `target`. Shared by [`SseUsageScanner::push`]
/// (per newline-terminated line) and [`SseUsageScanner::usage`] (the final
/// unterminated line at end-of-stream).
fn merge_line(target: &mut Option<TokenUsage>, dialect: Dialect, line: &[u8]) {
    // Tolerate CRLF endings: strip a trailing `\r` left after the `\n`.
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    // Only `data:` lines carry payloads; ignore `event:`, `id:`, comments, blanks.
    let Some(rest) = line.strip_prefix(b"data:") else {
        return;
    };
    // One optional space after the colon is conventional; tolerate its absence.
    let payload = rest.strip_prefix(b" ").unwrap_or(rest);
    // `[DONE]` is a sentinel, not JSON — must not be treated as a parse error.
    if payload == b"[DONE]" {
        return;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return;
    };
    if let Some(usage) = frame_usage_object(dialect, &value) {
        merge_usage(target, dialect, usage);
    }
}

#[cfg(test)]
mod tests {
    //! The WP-34 acceptance suite. Every test runs in the CI gate; they are
    //! ordered easiest to hardest, which is also the order they were made to
    //! pass. Add a failing test here first when extending a dialect.

    use super::*;

    // ---- extract_json_usage: OpenAI ---------------------------------------

    #[test]
    fn openai_json_basic_usage() {
        let body =
            br#"{"id":"x","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#;
        let usage = extract_json_usage(Dialect::OpenAi, body).expect("usage should be found");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(usage.total(), 15);
    }

    #[test]
    fn openai_json_without_usage_is_none() {
        let body = br#"{"id":"x","choices":[]}"#;
        assert_eq!(extract_json_usage(Dialect::OpenAi, body), None);
    }

    /// Upstream bytes are untrusted: malformed JSON must return `None`, not
    /// panic and take down the worker.
    #[test]
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
    fn openai_json_missing_field_defaults_to_zero() {
        let body = br#"{"usage":{"prompt_tokens":7}}"#;
        let usage = extract_json_usage(Dialect::OpenAi, body).expect("usage should be found");
        assert_eq!(usage.input_tokens, 7);
        assert_eq!(usage.output_tokens, 0);
    }

    /// `total_tokens` is derived, never trusted — a provider reporting a bogus
    /// total must not corrupt our accounting.
    #[test]
    fn openai_json_ignores_provider_reported_total() {
        let body = br#"{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":9999}}"#;
        let usage = extract_json_usage(Dialect::OpenAi, body).expect("usage should be found");
        assert_eq!(
            usage.total(),
            15,
            "total must be derived from the two counts"
        );
    }

    /// Cached tokens are a discounted *subset* of OpenAI's `prompt_tokens` and
    /// live under `prompt_tokens_details`. They must be broken into their own
    /// bucket (different price) and NOT double-counted: `input_tokens` is the
    /// non-cached remainder, and `total()` still equals `prompt + completion`.
    #[test]
    fn openai_json_breaks_out_cached_tokens() {
        let body = br#"{"usage":{"prompt_tokens":100,"completion_tokens":20,"prompt_tokens_details":{"cached_tokens":80}}}"#;
        let usage = extract_json_usage(Dialect::OpenAi, body).expect("usage should be found");
        assert_eq!(usage.input_tokens, 20, "non-cached input = prompt - cached");
        assert_eq!(usage.cached_tokens, 80);
        assert_eq!(
            usage.cache_creation_tokens, 0,
            "OpenAI has no cache-write bucket"
        );
        assert_eq!(usage.output_tokens, 20);
        assert_eq!(
            usage.total(),
            120,
            "prompt(100) + completion(20), no double-count"
        );
    }

    // ---- extract_json_usage: Anthropic ------------------------------------

    #[test]
    fn anthropic_json_basic_usage() {
        let body = br#"{"type":"message","usage":{"input_tokens":12,"output_tokens":34}}"#;
        let usage = extract_json_usage(Dialect::Anthropic, body).expect("usage should be found");
        assert_eq!(usage.input_tokens, 12);
        assert_eq!(usage.output_tokens, 34);
    }

    /// Anthropic reports cache read and cache write as sibling fields, each
    /// priced differently, and its `input_tokens` already excludes them (no
    /// subtraction). All four buckets must be tracked separately.
    #[test]
    fn anthropic_json_breaks_out_cache_read_and_creation() {
        let body = br#"{"usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":40,"cache_creation_input_tokens":15}}"#;
        let usage = extract_json_usage(Dialect::Anthropic, body).expect("usage should be found");
        assert_eq!(
            usage.input_tokens, 10,
            "Anthropic input already excludes cache"
        );
        assert_eq!(usage.cached_tokens, 40);
        assert_eq!(usage.cache_creation_tokens, 15);
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(usage.total(), 70);
    }

    // ---- extract_json_usage: OpenAI Responses API -------------------------

    /// Wire shape lifted from `testing/diffrig/src/upstreams/openai.rs`'s
    /// `handle_responses`: `input_tokens` is inclusive of cache, so `input`
    /// must come out net of the cached portion — 14 - 4 = 10, not 14.
    #[test]
    fn openai_responses_json_breaks_out_cached_tokens() {
        let body = br#"{"id":"resp_1","usage":{"input_tokens":14,"output_tokens":5,"input_tokens_details":{"cached_tokens":4},"total_tokens":19}}"#;
        let usage =
            extract_json_usage(Dialect::OpenAiResponses, body).expect("usage should be found");
        assert_eq!(
            usage.input_tokens, 10,
            "input_tokens is inclusive of cache; must be reported net of it"
        );
        assert_eq!(usage.cached_tokens, 4);
        assert_eq!(
            usage.cache_creation_tokens, 0,
            "OpenAI has no cache-write bucket"
        );
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(usage.total(), 19);
    }

    /// Absent `input_tokens_details` (no caching used) → `cached_tokens: 0`
    /// and `input_tokens` NOT reduced.
    #[test]
    fn openai_responses_json_missing_details_defaults_cached_to_zero() {
        let body = br#"{"usage":{"input_tokens":10,"output_tokens":5}}"#;
        let usage =
            extract_json_usage(Dialect::OpenAiResponses, body).expect("usage should be found");
        assert_eq!(
            usage.input_tokens, 10,
            "no cache present, nothing to subtract"
        );
        assert_eq!(usage.cached_tokens, 0);
        assert_eq!(usage.output_tokens, 5);
    }

    /// The crux of this whole task, made executable: the same JSON body,
    /// shaped like an Anthropic `usage` object with `input_tokens`/
    /// `output_tokens` at the top level, MUST be interpreted differently by
    /// `Dialect::Anthropic` and `Dialect::OpenAiResponses` — because
    /// Anthropic's `input_tokens` excludes cache while OpenAI Responses'
    /// includes it. If these two branches ever agree here, cached tokens are
    /// silently being folded into full-price input for one of the two
    /// providers — a billing-accuracy bug.
    #[test]
    fn anthropic_and_openai_responses_disagree_on_the_same_body() {
        let body = br#"{"usage":{"input_tokens":14,"output_tokens":5,"input_tokens_details":{"cached_tokens":4}}}"#;

        let anthropic =
            extract_json_usage(Dialect::Anthropic, body).expect("usage should be found");
        assert_eq!(
            anthropic.input_tokens, 14,
            "Anthropic treats input_tokens as already excluding cache"
        );
        assert_eq!(
            anthropic.cached_tokens, 0,
            "Anthropic doesn't recognize input_tokens_details; it wants cache_read_input_tokens"
        );

        let responses =
            extract_json_usage(Dialect::OpenAiResponses, body).expect("usage should be found");
        assert_eq!(
            responses.input_tokens, 10,
            "OpenAI Responses subtracts the cached portion out of input_tokens"
        );
        assert_eq!(responses.cached_tokens, 4);

        assert_ne!(
            anthropic, responses,
            "the two dialects must not agree on this body"
        );
    }

    // ---- SseUsageScanner: OpenAI ------------------------------------------

    /// Helper: feed a whole stream as one chunk.
    fn scan_all(dialect: Dialect, stream: &[u8]) -> Option<TokenUsage> {
        let mut s = SseUsageScanner::new(dialect);
        s.push(stream);
        s.usage()
    }

    #[test]
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
    fn openai_sse_without_usage_is_none() {
        let stream = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\
                       data: [DONE]\n";
        assert_eq!(scan_all(Dialect::OpenAi, stream), None);
    }

    /// `data: [DONE]` is a sentinel, not JSON. It must not panic or error.
    #[test]
    fn done_sentinel_is_tolerated() {
        let stream = b"data: [DONE]\n";
        assert_eq!(scan_all(Dialect::OpenAi, stream), None);
    }

    /// Both `data:{...}` and `data: {...}` are valid in the wild.
    #[test]
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
    fn every_split_point_yields_the_same_usage() {
        let stream: &[u8] =
            b"data: {\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\ndata: [DONE]\n";
        let expected = TokenUsage {
            input_tokens: 10,
            output_tokens: 5,
            ..Default::default()
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
    fn final_line_without_trailing_newline() {
        let stream = b"data: {\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":3}}";
        let usage = scan_all(Dialect::OpenAi, stream);
        assert_eq!(
            usage,
            Some(TokenUsage {
                input_tokens: 2,
                output_tokens: 3,
                ..Default::default()
            })
        );
    }

    #[test]
    fn empty_pushes_are_harmless() {
        let mut s = SseUsageScanner::new(Dialect::OpenAi);
        s.push(b"");
        s.push(b"data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n");
        s.push(b"");
        assert!(s.usage().is_some());
    }

    /// Arbitrary bytes, including invalid UTF-8, must not panic.
    #[test]
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
                output_tokens: 15,
                ..Default::default()
            })
        );
    }

    /// A dialect mismatch should simply find nothing, not misparse.
    #[test]
    fn openai_scanner_does_not_misread_anthropic_events() {
        let anthropic = b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n";
        assert_eq!(scan_all(Dialect::OpenAi, anthropic), None);
    }

    // ---- SseUsageScanner: OpenAI Responses API -----------------------------

    /// Wire shape from `testing/diffrig/src/upstreams/openai.rs`'s
    /// `responses_streaming_response`: usage arrives once, in the terminal
    /// `response.completed` named event, nested under `response`. There is
    /// no `data: [DONE]` sentinel on this API.
    #[test]
    fn openai_responses_sse_completed_frame_carries_usage() {
        let stream = b"event: response.created\n\
                       data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"status\":\"in_progress\"}}\n\
                       \n\
                       event: response.output_text.delta\n\
                       data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hi\"}\n\
                       \n\
                       event: response.completed\n\
                       data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":5,\"input_tokens_details\":{\"cached_tokens\":4}}}}\n";
        let usage = scan_all(Dialect::OpenAiResponses, stream).expect("usage should be found");
        assert_eq!(usage.input_tokens, 6, "input_tokens net of cache: 10 - 4");
        assert_eq!(usage.cached_tokens, 4);
        assert_eq!(usage.output_tokens, 5);
    }

    /// Absent `input_tokens_details` in the streamed frame → `cached_tokens: 0`
    /// and `input_tokens` not reduced.
    #[test]
    fn openai_responses_sse_missing_details_defaults_cached_to_zero() {
        let stream = b"event: response.completed\n\
                       data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n";
        let usage = scan_all(Dialect::OpenAiResponses, stream).expect("usage should be found");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.cached_tokens, 0);
        assert_eq!(usage.output_tokens, 5);
    }

    /// The classic bug: the `response.completed` frame split across chunk
    /// boundaries, mid-JSON, must still be found.
    #[test]
    fn openai_responses_sse_frame_split_across_chunk_boundary() {
        let stream: &[u8] = b"event: response.completed\n\
                       data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":5,\"input_tokens_details\":{\"cached_tokens\":4}}}}\n";
        // Split mid-JSON, inside the `usage` object.
        let split = stream
            .windows(b"cached_tokens".len())
            .position(|w| w == b"cached_tokens")
            .expect("fixture should contain cached_tokens")
            + 3;
        let mut s = SseUsageScanner::new(Dialect::OpenAiResponses);
        s.push(&stream[..split]);
        s.push(&stream[split..]);
        let usage = s
            .usage()
            .expect("usage should survive a mid-JSON chunk split");
        assert_eq!(usage.input_tokens, 6);
        assert_eq!(usage.cached_tokens, 4);
        assert_eq!(usage.output_tokens, 5);
    }

    /// A dialect mismatch should simply find nothing, not misparse.
    #[test]
    fn openai_responses_scanner_does_not_misread_anthropic_events() {
        let anthropic = b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n";
        assert_eq!(scan_all(Dialect::OpenAiResponses, anthropic), None);
    }
}
