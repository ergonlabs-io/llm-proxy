//! Provider usage/token extraction.
//!
//! This module answers one question: **how many tokens did this response
//! cost?** It is the input to token-based rate limiting (the budget store and
//! the 429 enforcement path) and to the GenAI token counters.
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
//! The encode path guarantees flush-through — tokens reach the client
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
//! This module is a pure extractor; [`crate::usage_filter`] wires it into the
//! encode chain.

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
        // Saturating, not `+`: every one of these four numbers comes straight
        // from a provider's JSON via `as_u64()` with no clamping, so the sum is
        // attacker-/bug-reachable input, not a value we computed. A plain `+`
        // panics on overflow in debug (killing the worker) and wraps in release
        // (logging a billing number nobody computed). `parse_usage_object`
        // already uses `saturating_sub` against these same numbers two lines
        // away; this is the one place that was missed.
        self.input_tokens
            .saturating_add(self.cached_tokens)
            .saturating_add(self.cache_creation_tokens)
            .saturating_add(self.output_tokens)
    }
}

/// Which provider's response schema to parse.
///
/// Kept as an enum rather than a trait because the set of dialects is small,
/// closed, and known at config time; adding a variant should force every
/// `match` in this module to be updated (AGENTS.md invariant 1's spirit: no silent
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

/// Extract usage from the last bytes of a response body too large to hold
/// whole. Providers emit `usage` as the final top-level member, so it normally
/// survives in a bounded tail.
///
/// The truncated document cannot be fully parsed, so "top-level" is checked
/// structurally. Candidates are `"usage"` keys followed by `:` and `{`, tried
/// last to first. A candidate is accepted only if, after its balanced object,
/// the rest of the tail closes exactly one object, at the last non-whitespace
/// byte. A `usage` nested in `choices[..]` or `message` closes more than one
/// level (or a `]`) and is rejected. The residual risk is a nested `usage`
/// that is the final member of a document whose top-level `usage` is absent;
/// that requires a non-standard response and the object must still parse as
/// this dialect's token counts, otherwise the answer is `None`, never a guess.
pub fn extract_json_usage_from_tail(dialect: Dialect, tail: &[u8]) -> Option<TokenUsage> {
    let span = tail_usage_span(tail)?;
    let usage: serde_json::Value = serde_json::from_slice(span).ok()?;
    usage_from_object(dialect, &usage)
}

/// The byte span of the top-level `usage` object inside a body tail, found by
/// the structural rules documented on [`extract_json_usage_from_tail`].
fn tail_usage_span(tail: &[u8]) -> Option<&[u8]> {
    const KEY: &[u8] = b"\"usage\"";
    // Bound the work an adversarial body full of `"usage"` keys can cause.
    const MAX_CANDIDATES: usize = 8;
    let mut end = tail.len();
    let mut tried = 0;
    while let Some(pos) = tail[..end].windows(KEY.len()).rposition(|w| w == KEY) {
        end = pos;
        // An escaped quote means the key text sits inside a string value.
        let backslashes = tail[..pos]
            .iter()
            .rev()
            .take_while(|&&b| b == b'\\')
            .count();
        if backslashes % 2 == 1 {
            continue;
        }
        tried += 1;
        if tried > MAX_CANDIDATES {
            return None;
        }
        let mut i = pos + KEY.len();
        i = skip_ws(tail, i);
        if tail.get(i) != Some(&b':') {
            continue;
        }
        i = skip_ws(tail, i + 1);
        if tail.get(i) != Some(&b'{') {
            continue;
        }
        let Some(object_end) = balanced_object_end(tail, i) else {
            continue;
        };
        if !closes_exactly_one_object(&tail[object_end..]) {
            continue;
        }
        return Some(&tail[i..object_end]);
    }
    None
}

/// Longest model name accepted from a response. Real model identifiers are
/// short; a longer value is a malformed or hostile response, and it feeds a
/// price lookup and an audit record, so it is dropped rather than truncated
/// (a truncated name could collide with a different model's card).
pub const MAX_SERVED_MODEL_BYTES: usize = 128;

/// Accept a provider-reported model name only if it is non-empty, within
/// [`MAX_SERVED_MODEL_BYTES`], and free of control characters (it reaches
/// access logs and records).
fn bounded_served_model(model: &str) -> Option<String> {
    if model.is_empty()
        || model.len() > MAX_SERVED_MODEL_BYTES
        || model.chars().any(char::is_control)
    {
        return None;
    }
    Some(model.to_owned())
}

/// The model the provider says it served, from a complete JSON response body.
/// All three dialects carry it as the top-level `model` string. The oversized
/// tail path has no counterpart: providers emit `model` near the start of the
/// document, which the tail window has already dropped.
pub fn extract_json_served_model(body: &[u8]) -> Option<String> {
    let json_body: serde_json::Value = serde_json::from_slice(body).ok()?;
    bounded_served_model(json_body.get("model")?.as_str()?)
}

// --- the provider's own identifiers and usage object ------------------------
//
// Audit evidence only. Nothing here is read for billing: the rate card is the
// only source of cost, and the provider's `usage` object is kept as the exact
// text it sent so a disagreement can be investigated later.

/// Longest upstream response id kept. Real ids are well under this; a longer
/// one is dropped, not truncated (a truncated id would name a different
/// response).
pub const MAX_UPSTREAM_ID_BYTES: usize = 256;

/// Largest provider `usage` object kept verbatim. Over this nothing is stored
/// and the miss is counted, so a hostile or odd provider cannot make every
/// record carry an arbitrarily large blob.
pub const MAX_UPSTREAM_USAGE_BYTES: usize = 4096;

/// What the provider said about itself in one response: its response id and
/// the `usage` object exactly as sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamEvidence {
    /// The upstream response id (`chatcmpl-...`, `msg_...`, `resp_...`).
    pub response_id: Option<String>,
    /// The `usage` JSON text as sent (the last one, for a stream that carries
    /// several). Only insignificant whitespace is ever altered; see
    /// [`single_line_json`].
    pub usage_json: Option<String>,
    /// An id was present but longer than [`MAX_UPSTREAM_ID_BYTES`].
    pub id_oversized: bool,
    /// The latest `usage` object was longer than [`MAX_UPSTREAM_USAGE_BYTES`].
    pub usage_oversized: bool,
}

impl UpstreamEvidence {
    /// Record an id from its raw JSON text. Returns whether the member was a
    /// string and so settles the id (a number or `null` leaves it open for a
    /// later frame).
    fn set_id(&mut self, raw: &str) -> bool {
        // Escapes only shorten a string, so a span this long cannot hold an
        // in-bounds id; skip decoding it.
        if raw.len() > 4 * MAX_UPSTREAM_ID_BYTES {
            self.id_oversized = true;
            return true;
        }
        let Ok(id) = serde_json::from_str::<String>(raw) else {
            return false;
        };
        if id.len() > MAX_UPSTREAM_ID_BYTES {
            self.id_oversized = true;
        } else if !id.is_empty() && !id.chars().any(char::is_control) {
            self.response_id = Some(id);
        }
        true
    }

    fn set_usage(&mut self, raw: &str) {
        let raw = raw.trim();
        // Only an object is a usage record; `null` (OpenAI sends it on every
        // content chunk when usage is requested) must not replace a real one.
        if !raw.starts_with('{') {
            return;
        }
        if raw.len() > MAX_UPSTREAM_USAGE_BYTES {
            self.usage_json = None;
            self.usage_oversized = true;
        } else {
            self.usage_json = Some(single_line_json(raw));
            self.usage_oversized = false;
        }
    }
}

/// Remove line breaks from JSON text. Inside a JSON string a line break must
/// be escaped, so a raw one can only be insignificant whitespace between
/// tokens; dropping it keeps the value identical while letting it sit on one
/// access-log line.
fn single_line_json(raw: &str) -> String {
    if raw.contains(['\n', '\r']) {
        raw.chars().filter(|c| !matches!(c, '\n' | '\r')).collect()
    } else {
        raw.to_owned()
    }
}

/// Members of a JSON object kept as raw text, so no value is re-encoded.
///
/// Rust note: `&RawValue` borrows the exact input span; with `#[serde(borrow)]`
/// the derive hands it out without copying. Members not named here are skipped.
#[derive(serde::Deserialize)]
struct RawMembers<'a> {
    #[serde(borrow)]
    id: Option<&'a serde_json::value::RawValue>,
    #[serde(borrow)]
    usage: Option<&'a serde_json::value::RawValue>,
    #[serde(borrow)]
    message: Option<&'a serde_json::value::RawValue>,
    #[serde(borrow)]
    response: Option<&'a serde_json::value::RawValue>,
}

fn raw_members(json: &str) -> Option<RawMembers<'_>> {
    serde_json::from_str(json).ok()
}

/// Id and `usage` of a complete (non-streaming) JSON response body.
pub fn extract_json_upstream(body: &[u8]) -> UpstreamEvidence {
    let mut evidence = UpstreamEvidence::default();
    let Ok(text) = std::str::from_utf8(body) else {
        return evidence;
    };
    let Some(members) = raw_members(text) else {
        return evidence;
    };
    if let Some(id) = members.id {
        evidence.set_id(id.get());
    }
    if let Some(usage) = members.usage {
        evidence.set_usage(usage.get());
    }
    evidence
}

/// `usage` of an oversized body, from the tail window. The id sits at the
/// start of the document, which the window has already dropped.
pub fn extract_json_upstream_from_tail(tail: &[u8]) -> UpstreamEvidence {
    let mut evidence = UpstreamEvidence::default();
    let valid = tail_usage_span(tail)
        .and_then(|span| std::str::from_utf8(span).ok())
        .filter(|span| serde_json::from_str::<&serde_json::value::RawValue>(span).is_ok());
    if let Some(span) = valid {
        evidence.set_usage(span);
    }
    evidence
}

/// Where the frame's id and usage live, per dialect, mirroring
/// [`frame_usage_object`] and [`frame_served_model`]. Returns the raw `id` and
/// raw `usage` texts of one SSE data payload.
fn frame_upstream(dialect: Dialect, payload: &str) -> (Option<String>, Option<String>) {
    let Some(top) = raw_members(payload) else {
        return (None, None);
    };
    // Rust note: a named `fn` can say the result borrows from the argument;
    // closure signatures cannot express that relationship.
    fn nested(holder: Option<&serde_json::value::RawValue>) -> Option<RawMembers<'_>> {
        holder.and_then(|h| raw_members(h.get()))
    }
    let owned = |raw: Option<&serde_json::value::RawValue>| raw.map(|r| r.get().to_owned());
    match dialect {
        Dialect::OpenAi => (owned(top.id), owned(top.usage)),
        Dialect::Anthropic => {
            let message = nested(top.message);
            let id = message
                .as_ref()
                .and_then(|m| m.id)
                .map(|i| i.get().to_owned());
            let usage = message
                .as_ref()
                .and_then(|m| m.usage)
                .or(top.usage)
                .map(|u| u.get().to_owned());
            (id, usage)
        }
        Dialect::OpenAiResponses => {
            let response = nested(top.response);
            (
                owned(response.as_ref().and_then(|r| r.id)),
                response
                    .as_ref()
                    .and_then(|r| r.usage)
                    .map(|u| u.get().to_owned()),
            )
        }
    }
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    i
}

/// Index one past the `}` matching the `{` at `start`, honoring strings.
fn balanced_object_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, &b) in bytes[start..].iter().enumerate() {
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(start + offset + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// True when `rest` (what follows a candidate `usage` object) never closes a
/// container before its final non-whitespace byte, and that byte is the `}`
/// closing the one object that held the key.
fn closes_exactly_one_object(rest: &[u8]) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut closed = false;
    for &b in rest {
        if closed {
            if b.is_ascii_whitespace() {
                continue;
            }
            return false;
        }
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' if depth == 0 => closed = true,
            b']' if depth == 0 => return false,
            b'}' | b']' => depth -= 1,
            _ => {}
        }
    }
    closed
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

/// Interpret one JSON value from a provider's `usage` object as a token
/// count, tolerating the shapes real providers send while refusing to
/// silently turn "unparseable" into `0`.
///
/// **Why `None`, not `0`, for anything we can't make sense of:** downstream,
/// `None` means "this provider reported no usage for this field" and renders
/// as absent, while `0` means "this provider reported zero tokens" and is a
/// number someone will bill against. `serde_json`'s own `as_u64()` returns
/// `None` for *any* JSON number that isn't a non-negative integer — including
/// a perfectly ordinary `150.0`, which real providers do emit — and every
/// caller here used to feed that straight into `.unwrap_or(0)` two calls
/// downstream in [`usage_from_object`]. That silently turned "provider sent a
/// float" into "provider sent zero", which is a confident wrong billing
/// number with nothing logged and nothing erroring. This function is the
/// single place that distinction gets made, so it only has to be gotten
/// right once:
/// - a non-negative JSON integer passes through unchanged;
/// - a non-negative finite float is truncated toward zero (`150.0` means
///   150; a provider using a float for a count is a formatting difference,
///   not missing data);
/// - a negative number, NaN, or infinity is `None` — not data we can bill
///   from;
/// - anything that isn't a number (string, bool, object, null), or an absent
///   field, is `None`.
fn token_count(value: Option<&serde_json::Value>) -> Option<u64> {
    let value = value?;
    // The common path: already a non-negative JSON integer.
    if let Some(int) = value.as_u64() {
        return Some(int);
    }
    // Anything else that still parses as a JSON number is a float (or a
    // negative/out-of-range integer, which `as_f64` also accepts) — reject
    // negative and non-finite values, then truncate the rest toward zero.
    let float = value.as_f64()?;
    // `is_finite` here is unreachable and deliberately kept. `serde_json`
    // cannot hold a non-finite number at all -- `Number::from_f64` rejects
    // NaN and infinity, and JSON itself has no syntax for them -- so nothing
    // from the wire, and nothing constructible as a `Value`, arrives here
    // non-finite. It stays because `as u64` on a NaN yields 0, which is
    // precisely the confident-wrong-billing-number this function exists to
    // prevent, and because the guard costs one comparison on a path that runs
    // once per response. Do not "simplify" it away on the grounds that no test
    // covers it: no test CAN.
    if !float.is_finite() || float.is_sign_negative() {
        return None;
    }
    // Rust note: `as u64` on an `f64` saturates rather than wrapping or
    // producing UB (this has been guaranteed since Rust 1.45's "unified
    // float-to-int casts") — a float bigger than `u64::MAX` becomes
    // `u64::MAX` here, not a wrapped-around small number.
    Some(float as u64)
}

/// Read the per-bucket token counts for `dialect` out of a `usage` object,
/// applying the normalization documented on [`TokenUsage`] (all `None` when
/// `usage` is not a JSON object).
fn read_tokens(dialect: Dialect, usage: &serde_json::Value) -> RawTokens {
    if !usage.is_object() {
        return RawTokens::default();
    }
    let u64_at = |key: &str| token_count(usage.get(key));
    match dialect {
        Dialect::OpenAi => {
            // `cached_tokens` is nested under `prompt_tokens_details` and is a
            // *subset* of `prompt_tokens`; subtract it out so `input` is the
            // non-cached remainder (saturating, in case a provider ever reports
            // cached > prompt). OpenAI itself bills no cache-write bucket, but
            // OpenAI-compatible gateways fronting Anthropic or Gemini (for
            // example OpenRouter) report cache writes as
            // `prompt_tokens_details.cache_write_tokens`, also a subset of
            // `prompt_tokens`. Read it when present so the write is billed at
            // the cache-write rate instead of folded into full-price input.
            // The SSE path reaches this same arm through `merge_usage`.
            let details = usage.get("prompt_tokens_details");
            let cached = token_count(details.and_then(|d| d.get("cached_tokens")));
            let cache_write = token_count(details.and_then(|d| d.get("cache_write_tokens")));
            let input = u64_at("prompt_tokens").map(|prompt| {
                prompt
                    .saturating_sub(cached.unwrap_or(0))
                    .saturating_sub(cache_write.unwrap_or(0))
            });
            RawTokens {
                input,
                cached,
                cache_creation: cache_write,
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
            let cached = token_count(
                usage
                    .get("input_tokens_details")
                    .and_then(|d| d.get("cached_tokens")),
            );
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
    /// The first model name any frame reported; later frames never replace it.
    served_model: Option<String>,
    /// The provider's response id (first frame that names one) and last
    /// `usage` object, kept as sent.
    upstream: UpstreamEvidence,
    /// An id has been decided (kept or found oversized); later frames never
    /// replace it.
    id_decided: bool,
}

impl SseUsageScanner {
    pub fn new(dialect: Dialect) -> Self {
        Self {
            dialect,
            partial: Vec::new(),
            usage: None,
            served_model: None,
            upstream: UpstreamEvidence::default(),
            id_decided: false,
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
            merge_line(
                &mut self.usage,
                &mut self.served_model,
                &mut self.upstream,
                &mut self.id_decided,
                self.dialect,
                &line[..line.len() - 1],
            );
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
            merge_line(
                &mut result,
                &mut None,
                &mut UpstreamEvidence::default(),
                &mut true,
                self.dialect,
                &self.partial,
            );
        }
        result
    }

    /// The model the provider reported serving: the first frame that names one
    /// wins (OpenAI chunks repeat it on every frame; Anthropic names it once in
    /// `message_start`; Responses in `response.created`). Like [`Self::usage`],
    /// folds in an unterminated final line without mutating state.
    pub fn served_model(&self) -> Option<String> {
        if self.served_model.is_some() || self.partial.is_empty() {
            return self.served_model.clone();
        }
        let mut result = None;
        merge_line(
            &mut None,
            &mut result,
            &mut UpstreamEvidence::default(),
            &mut true,
            self.dialect,
            &self.partial,
        );
        result
    }

    /// The provider's response id and last `usage` object seen so far. Like
    /// [`Self::usage`], folds in an unterminated final line without mutating
    /// state.
    pub fn upstream(&self) -> UpstreamEvidence {
        if self.partial.is_empty() {
            return self.upstream.clone();
        }
        let mut evidence = self.upstream.clone();
        merge_line(
            &mut None,
            &mut None,
            &mut evidence,
            &mut self.id_decided.clone(),
            self.dialect,
            &self.partial,
        );
        evidence
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

/// Locate the served-model string inside one parsed SSE data frame, per
/// dialect: top level for chat-completions, under `message` for Anthropic's
/// `message_start`, under `response` for the Responses API.
fn frame_served_model(dialect: Dialect, value: &serde_json::Value) -> Option<&str> {
    match dialect {
        Dialect::OpenAi => value.get("model"),
        Dialect::Anthropic => value.get("message").and_then(|m| m.get("model")),
        Dialect::OpenAiResponses => value.get("response").and_then(|r| r.get("model")),
    }?
    .as_str()
}

/// Whether a parsed frame carries a string id where `dialect` puts one.
fn frame_has_id(dialect: Dialect, value: &serde_json::Value) -> bool {
    match dialect {
        Dialect::OpenAi => value.get("id"),
        Dialect::Anthropic => value.get("message").and_then(|m| m.get("id")),
        Dialect::OpenAiResponses => value.get("response").and_then(|r| r.get("id")),
    }
    .is_some_and(serde_json::Value::is_string)
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
fn merge_line(
    target: &mut Option<TokenUsage>,
    served_model: &mut Option<String>,
    upstream: &mut UpstreamEvidence,
    id_decided: &mut bool,
    dialect: Dialect,
    line: &[u8],
) {
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
    // Second pass for the raw text. The typed parse above cannot give back the
    // bytes as sent, so only frames that can carry an id we still want, or a
    // `usage` object, pay for it.
    let wants_id = !*id_decided && frame_has_id(dialect, &value);
    let has_usage = frame_usage_object(dialect, &value).is_some_and(serde_json::Value::is_object);
    if wants_id || has_usage {
        if let Ok(text) = std::str::from_utf8(payload) {
            let (id, usage) = frame_upstream(dialect, text);
            if wants_id {
                if let Some(id) = id {
                    *id_decided = upstream.set_id(&id);
                }
            }
            if has_usage {
                if let Some(usage) = usage {
                    upstream.set_usage(&usage);
                }
            }
        }
    }
    if served_model.is_none() {
        *served_model = frame_served_model(dialect, &value).and_then(bounded_served_model);
    }
}

#[cfg(test)]
mod tests {
    //! The acceptance suite. Every test runs in the CI gate; they are
    //! ordered easiest to hardest, which is also the order they were made to
    //! pass. Add a failing test here first when extending a dialect.

    use super::*;

    // ---- OpenAI-compatible gateways: cache writes ---------------------------

    #[test]
    fn openai_cache_write_tokens_are_split_out_of_input_json_and_sse() {
        let usage = r#"{"prompt_tokens":100,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":10,"cache_write_tokens":30}}"#;
        let expected = TokenUsage {
            input_tokens: 60,
            cached_tokens: 10,
            cache_creation_tokens: 30,
            output_tokens: 5,
        };
        let body = format!(r#"{{"usage":{usage}}}"#);
        assert_eq!(
            extract_json_usage(Dialect::OpenAi, body.as_bytes()),
            Some(expected)
        );
        let mut scanner = SseUsageScanner::new(Dialect::OpenAi);
        scanner.push(format!("data: {body}\n\n").as_bytes());
        assert_eq!(scanner.usage(), Some(expected));
    }

    #[test]
    fn openai_without_cache_write_tokens_is_unchanged() {
        let body = br#"{"usage":{"prompt_tokens":100,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":10}}}"#;
        let usage = extract_json_usage(Dialect::OpenAi, body).expect("usage");
        assert_eq!(usage.input_tokens, 90);
        assert_eq!(usage.cache_creation_tokens, 0);
    }

    // ---- tail extraction for bodies past the accumulation cap ---------------

    #[test]
    fn tail_extraction_accepts_only_the_top_level_usage_object() {
        let ok = br#"ssage":"x"}}],"usage":{"prompt_tokens":7,"completion_tokens":9},"id":"a"}"#;
        let got = extract_json_usage_from_tail(Dialect::OpenAi, ok).expect("top-level usage");
        assert_eq!((got.input_tokens, got.output_tokens), (7, 9));

        // A usage object nested inside another container closes more than one
        // level afterwards, so it is not mistaken for the top-level one.
        let nested = br#"..."choices":[{"usage":{"prompt_tokens":7,"completion_tokens":9}}]}"#;
        assert_eq!(extract_json_usage_from_tail(Dialect::OpenAi, nested), None);
        let nested_obj = br#"{"message":{"usage":{"prompt_tokens":7,"completion_tokens":9}}}"#;
        assert_eq!(
            extract_json_usage_from_tail(Dialect::OpenAi, nested_obj),
            None
        );
        // Escaped key text inside a string value is not a key.
        let in_string = br#"{"t":"\"usage\":{\"prompt_tokens\":1}"}"#;
        assert_eq!(
            extract_json_usage_from_tail(Dialect::OpenAi, in_string),
            None
        );
        // Another dialect's object is not read as zero tokens.
        let wrong = br#"{"usage":{"input_tokens":1,"output_tokens":2}}"#;
        assert_eq!(extract_json_usage_from_tail(Dialect::OpenAi, wrong), None);
        // Truncated usage object (opening brace beyond the window) is None.
        let cut = br#""prompt_tokens":1,"completion_tokens":2},"id":"a"}"#;
        assert_eq!(extract_json_usage_from_tail(Dialect::OpenAi, cut), None);
    }

    // ---- token_count: a present-but-unparseable count must never read as 0 --
    //
    // `serde_json::Value::as_u64()` returns `None` for any
    // JSON number that isn't a non-negative integer -- including an ordinary
    // `150.0`, which real providers emit -- and that `None` used to become a
    // silent `0` two calls downstream. These are table-driven per the case
    // table in the task spec.

    #[test]
    fn token_count_cases() {
        use serde_json::json;

        let cases: &[(&str, serde_json::Value, Option<u64>)] = &[
            ("non-negative integer passes through", json!(150), Some(150)),
            (
                "non-negative whole float truncates to the same value",
                json!(150.0),
                Some(150),
            ),
            (
                "non-negative fractional float truncates toward zero",
                json!(150.9),
                Some(150),
            ),
            ("negative integer is None, not 0", json!(-5), None),
            ("negative float is None, not 0", json!(-5.5), None),
            ("a numeric string is not a number", json!("150"), None),
            ("null is None", json!(null), None),
            ("a bool is not a number", json!(true), None),
            ("an object is not a number", json!({"n": 150}), None),
            (
                "a float above u64::MAX saturates instead of wrapping",
                json!(1e30),
                Some(u64::MAX),
            ),
        ];

        for (why, value, expected) in cases {
            assert_eq!(token_count(Some(value)), *expected, "{why}");
        }

        // NaN and infinity: these two assert the right ANSWER for the wrong
        // REASON, and it is worth being precise about which.
        //
        // Rust note: `serde_json::Number::from_f64` returns `None` for any
        // non-finite float, and `impl From<f64> for Value` maps that to
        // `Value::Null`. So BOTH of these values are `Value::Null` by the time
        // `token_count` sees them, and both take its "not a number" arm --
        // neither one ever reaches the `!float.is_finite()` guard. A JSON
        // document cannot express NaN or infinity either, so no provider
        // response can reach that guard from the wire.
        //
        // They stay because they pin the observable contract (a caller writing
        // `Value::from(f64::NAN)` gets `None`, never `0`), but do not read them
        // as coverage of the `is_finite` branch -- see its own comment.
        let nan = serde_json::Value::from(f64::NAN);
        assert_eq!(token_count(Some(&nan)), None, "NaN is None, not 0");
        let infinity = serde_json::Value::from(f64::INFINITY);
        assert_eq!(
            token_count(Some(&infinity)),
            None,
            "infinity is None, not 0"
        );

        // Absent field.
        assert_eq!(token_count(None), None, "absent field is None");
    }

    // ---- extract_json_usage: OpenAI ---------------------------------------

    /// `total()` sums four numbers that came from a provider's JSON, so it
    /// must never panic or wrap. Before this was saturating, a response
    /// reporting huge token counts panicked the worker in debug builds
    /// ("attempt to add with overflow") and silently wrapped in release --
    /// on the live path, since `access_log.rs` calls `total()` for every
    /// logged request.
    #[test]
    fn total_saturates_instead_of_overflowing_on_provider_numbers() {
        let u = TokenUsage {
            input_tokens: u64::MAX,
            cached_tokens: 1,
            cache_creation_tokens: 1,
            output_tokens: 1,
        };
        assert_eq!(u.total(), u64::MAX, "must clamp, not wrap");
    }

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

    // ---- a present-but-unparseable count must never read as 0 ------
    //
    // End-to-end (through `extract_json_usage`, not just `token_count`
    // directly): a full OpenAI-shaped `usage` object with float counts must
    // produce the right `TokenUsage`, cached-token subtraction included.
    // Before this fix, every one of these three floats (`prompt_tokens`,
    // `completion_tokens`, `cached_tokens`) would have parsed as `None` via
    // `as_u64()` and silently rendered as 0.

    #[test]
    fn openai_json_usage_with_float_counts() {
        let body = br#"{"usage":{"prompt_tokens":100.0,"completion_tokens":20.0,"prompt_tokens_details":{"cached_tokens":80.0}}}"#;
        let usage = extract_json_usage(Dialect::OpenAi, body).expect("usage should be found");
        assert_eq!(
            usage.input_tokens, 20,
            "100.0 prompt - 80.0 cached, both floats"
        );
        assert_eq!(usage.cached_tokens, 80);
        assert_eq!(usage.output_tokens, 20);
        assert_eq!(usage.total(), 120);
    }

    /// The `saturating_sub` interaction, one direction: `cached_tokens`
    /// parses but `prompt_tokens` does not (a string here). `input` must come
    /// out defaulted to 0 via the normal "field absent" path -- not a
    /// negative-then-wrapped garbage number -- and `cached_tokens`, which did
    /// parse, must be unaffected by its sibling's failure.
    #[test]
    fn openai_json_usage_unparseable_prompt_with_valid_cached() {
        let body = br#"{"usage":{"prompt_tokens":"bad","completion_tokens":5,"prompt_tokens_details":{"cached_tokens":80}}}"#;
        let usage = extract_json_usage(Dialect::OpenAi, body).expect("usage should be found");
        assert_eq!(
            usage.input_tokens, 0,
            "unparseable prompt_tokens defaults input to 0, doesn't underflow against cached"
        );
        assert_eq!(usage.cached_tokens, 80, "cached_tokens itself still parses");
        assert_eq!(usage.output_tokens, 5);
    }

    /// The other direction: `prompt_tokens` parses (as a float) but the
    /// nested `cached_tokens` does not (negative, here) -- the subtraction
    /// must treat cached as 0 rather than corrupting `input`, and the
    /// negative count itself must not leak through as a token count.
    #[test]
    fn openai_json_usage_valid_prompt_with_unparseable_cached() {
        let body = br#"{"usage":{"prompt_tokens":100.0,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":-1}}}"#;
        let usage = extract_json_usage(Dialect::OpenAi, body).expect("usage should be found");
        assert_eq!(
            usage.input_tokens, 100,
            "negative cached_tokens is None, so nothing is subtracted"
        );
        assert_eq!(
            usage.cached_tokens, 0,
            "a negative cache count is not data we bill from"
        );
        assert_eq!(usage.output_tokens, 5);
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

    /// End-to-end: an Anthropic `usage` object with float counts must
    /// still produce the right `TokenUsage`, all four buckets included.
    #[test]
    fn anthropic_json_usage_with_float_counts() {
        let body = br#"{"usage":{"input_tokens":10.0,"output_tokens":5.0,"cache_read_input_tokens":40.0,"cache_creation_input_tokens":15.0}}"#;
        let usage = extract_json_usage(Dialect::Anthropic, body).expect("usage should be found");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.cached_tokens, 40);
        assert_eq!(usage.cache_creation_tokens, 15);
        assert_eq!(usage.output_tokens, 5);
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

    /// End-to-end: an OpenAI Responses `usage` object with float
    /// counts, cached-token subtraction included -- 14.0 - 4.0 = 10, not 0.
    #[test]
    fn openai_responses_json_usage_with_float_counts() {
        let body = br#"{"usage":{"input_tokens":14.0,"output_tokens":5.0,"input_tokens_details":{"cached_tokens":4.0}}}"#;
        let usage =
            extract_json_usage(Dialect::OpenAiResponses, body).expect("usage should be found");
        assert_eq!(
            usage.input_tokens, 10,
            "14.0 - 4.0 cached, both floats, is 10, not 0"
        );
        assert_eq!(usage.cached_tokens, 4);
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

    // ---- upstream id and raw usage ----------------------------------------

    fn sse_upstream(dialect: Dialect, stream: &str) -> UpstreamEvidence {
        let mut s = SseUsageScanner::new(dialect);
        s.push(stream.as_bytes());
        s.upstream()
    }

    #[test]
    fn json_body_id_and_usage_are_kept_verbatim_for_every_dialect() {
        let usage = r#"{"prompt_tokens": 7,"cost":0.000012340,  "x":{"b":1,"a":2}}"#;
        let body = format!(r#"{{"id":"chatcmpl-1","usage":{usage}}}"#);
        let e = extract_json_upstream(body.as_bytes());
        assert_eq!(e.response_id.as_deref(), Some("chatcmpl-1"));
        assert_eq!(e.usage_json.as_deref(), Some(usage));
        // Anthropic and Responses JSON bodies carry both at the top level too.
        let e = extract_json_upstream(br#"{"id":"msg_1","usage":{"input_tokens":3}}"#);
        assert_eq!(e.response_id.as_deref(), Some("msg_1"));
        assert_eq!(e.usage_json.as_deref(), Some(r#"{"input_tokens":3}"#));
    }

    #[test]
    fn json_body_without_id_or_with_null_usage_records_nothing() {
        let e = extract_json_upstream(br#"{"id":5,"usage":null}"#);
        assert_eq!(e, UpstreamEvidence::default());
        assert_eq!(
            extract_json_upstream(b"not json"),
            UpstreamEvidence::default()
        );
    }

    #[test]
    fn pretty_printed_usage_is_collapsed_to_one_line_without_changing_its_value() {
        let body = "{\"usage\": {\n  \"a\": 1,\r\n  \"b\": \"x y\"\n}}";
        let e = extract_json_upstream(body.as_bytes());
        let text = e.usage_json.unwrap();
        assert!(!text.contains(['\n', '\r']), "{text:?}");
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["b"], "x y");
    }

    #[test]
    fn oversized_id_and_usage_are_dropped_and_flagged() {
        let id = "i".repeat(MAX_UPSTREAM_ID_BYTES + 1);
        let pad = "p".repeat(MAX_UPSTREAM_USAGE_BYTES);
        let body = format!(r#"{{"id":"{id}","usage":{{"k":"{pad}"}}}}"#);
        let e = extract_json_upstream(body.as_bytes());
        assert_eq!(e.response_id, None);
        assert_eq!(e.usage_json, None);
        assert!(e.id_oversized && e.usage_oversized);
        // At the bound exactly, both are kept.
        let id = "i".repeat(MAX_UPSTREAM_ID_BYTES);
        let body = format!(r#"{{"id":"{id}","usage":{{"k":1}}}}"#);
        let e = extract_json_upstream(body.as_bytes());
        assert_eq!(e.response_id.as_deref(), Some(id.as_str()));
        assert!(!e.id_oversized);
    }

    #[test]
    fn tail_window_yields_raw_usage_but_no_id() {
        let tail = br#"...,"id":"x","usage":{"prompt_tokens":1,"completion_tokens":2}}"#;
        let e = extract_json_upstream_from_tail(tail);
        assert_eq!(
            e.usage_json.as_deref(),
            Some(r#"{"prompt_tokens":1,"completion_tokens":2}"#)
        );
        assert_eq!(e.response_id, None);
    }

    #[test]
    fn openai_sse_first_id_wins_and_last_object_usage_is_kept() {
        let stream = "data: {\"id\":\"chatcmpl-1\",\"usage\":null}\n\n\
                      data: {\"id\":\"chatcmpl-2\",\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2}}\n\n\
                      data: {\"id\":\"chatcmpl-3\",\"usage\":null}\n\n";
        let e = sse_upstream(Dialect::OpenAi, stream);
        assert_eq!(e.response_id.as_deref(), Some("chatcmpl-1"));
        assert_eq!(
            e.usage_json.as_deref(),
            Some(r#"{"prompt_tokens":1,"completion_tokens":2}"#),
            "a later `usage: null` must not erase a real object"
        );
    }

    #[test]
    fn anthropic_sse_id_is_message_start_and_usage_is_the_last_object() {
        let stream = "event: message_start\n\
            data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\n\
            event: message_delta\n\
            data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n\n";
        let e = sse_upstream(Dialect::Anthropic, stream);
        assert_eq!(e.response_id.as_deref(), Some("msg_1"));
        assert_eq!(e.usage_json.as_deref(), Some(r#"{"output_tokens":15}"#));
    }

    #[test]
    fn responses_sse_reads_response_id_and_response_usage() {
        let stream = "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}\n\n\
            data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"usage\":{\"input_tokens\":4,\"output_tokens\":2}}}\n\n";
        let e = sse_upstream(Dialect::OpenAiResponses, stream);
        assert_eq!(e.response_id.as_deref(), Some("resp_1"));
        assert_eq!(
            e.usage_json.as_deref(),
            Some(r#"{"input_tokens":4,"output_tokens":2}"#)
        );
    }

    #[test]
    fn sse_upstream_is_independent_of_chunking_and_sees_an_unterminated_last_line() {
        let stream = "data: {\"id\":\"c1\",\"usage\":{\"prompt_tokens\":1}}";
        let mut s = SseUsageScanner::new(Dialect::OpenAi);
        for b in stream.as_bytes() {
            s.push(std::slice::from_ref(b));
        }
        let e = s.upstream();
        assert_eq!(e.response_id.as_deref(), Some("c1"));
        assert_eq!(e.usage_json.as_deref(), Some(r#"{"prompt_tokens":1}"#));
    }

    #[test]
    fn sse_oversized_usage_is_dropped_flagged_and_a_later_small_one_recovers() {
        let pad = "p".repeat(MAX_UPSTREAM_USAGE_BYTES);
        let big = format!("data: {{\"usage\":{{\"prompt_tokens\":1,\"k\":\"{pad}\"}}}}\n\n");
        let e = sse_upstream(Dialect::OpenAi, &big);
        assert!(e.usage_oversized && e.usage_json.is_none());
        let small = format!("{big}data: {{\"usage\":{{\"prompt_tokens\":2}}}}\n\n");
        let e = sse_upstream(Dialect::OpenAi, &small);
        assert!(!e.usage_oversized);
        assert_eq!(e.usage_json.as_deref(), Some(r#"{"prompt_tokens":2}"#));
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

    // ---- served model --------------------------------------------------------

    fn sse_served_model(dialect: Dialect, stream: &str) -> Option<String> {
        let mut scanner = SseUsageScanner::new(dialect);
        scanner.push(stream.as_bytes());
        scanner.served_model()
    }

    #[test]
    fn json_served_model_is_the_top_level_model_for_every_dialect() {
        // Nested `model` keys (here under `choices[0]`) must not be mistaken
        // for the top-level one.
        let body = br#"{"choices":[{"model":"nested"}],"model":"gpt-4o-mini-2024-07-18","usage":{"prompt_tokens":1,"completion_tokens":1}}"#;
        assert_eq!(
            extract_json_served_model(body).as_deref(),
            Some("gpt-4o-mini-2024-07-18")
        );
        assert_eq!(extract_json_served_model(br#"{"usage":{}}"#), None);
        assert_eq!(extract_json_served_model(br#"{"model":7}"#), None);
        assert_eq!(extract_json_served_model(b"not json"), None);
    }

    #[test]
    fn sse_served_model_openai_chat_first_chunk_wins() {
        let stream = "data: {\"model\":\"gpt-4o-mini-2024-07-18\",\"choices\":[]}\n\n\
                      data: {\"model\":\"other\",\"choices\":[]}\n\n";
        assert_eq!(
            sse_served_model(Dialect::OpenAi, stream).as_deref(),
            Some("gpt-4o-mini-2024-07-18")
        );
    }

    #[test]
    fn sse_served_model_anthropic_reads_message_start_only() {
        let stream = "event: message_start\n\
            data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-haiku\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n\
            event: message_delta\n\
            data: {\"type\":\"message_delta\",\"model\":\"top-level-ignored\",\"usage\":{\"output_tokens\":2}}\n\n";
        assert_eq!(
            sse_served_model(Dialect::Anthropic, stream).as_deref(),
            Some("claude-haiku")
        );
    }

    #[test]
    fn sse_served_model_responses_reads_response_object() {
        let stream = "event: response.created\n\
            data: {\"type\":\"response.created\",\"response\":{\"model\":\"gpt-5-2025-08-07\"}}\n\n\
            event: response.completed\n\
            data: {\"type\":\"response.completed\",\"response\":{\"model\":\"later\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n";
        assert_eq!(
            sse_served_model(Dialect::OpenAiResponses, stream).as_deref(),
            Some("gpt-5-2025-08-07")
        );
    }

    #[test]
    fn sse_served_model_survives_split_chunks_and_an_unterminated_last_line() {
        let line = "data: {\"model\":\"m-1\"}";
        let mut scanner = SseUsageScanner::new(Dialect::OpenAi);
        scanner.push(&line.as_bytes()[..9]);
        assert_eq!(scanner.served_model(), None);
        scanner.push(&line.as_bytes()[9..]);
        assert_eq!(scanner.served_model().as_deref(), Some("m-1"));
    }

    #[test]
    fn over_long_or_control_character_served_model_is_dropped_not_stored() {
        let at_limit = "m".repeat(MAX_SERVED_MODEL_BYTES);
        let over = "m".repeat(MAX_SERVED_MODEL_BYTES + 1);
        let json = |m: &str| format!(r#"{{"model":"{m}"}}"#);
        assert_eq!(
            extract_json_served_model(json(&at_limit).as_bytes()).as_deref(),
            Some(at_limit.as_str())
        );
        assert_eq!(extract_json_served_model(json(&over).as_bytes()), None);
        assert_eq!(extract_json_served_model(br#"{"model":"a\nb"}"#), None);
        assert_eq!(
            sse_served_model(Dialect::OpenAi, &format!("data: {}\n", json(&over))),
            None
        );
    }
}
