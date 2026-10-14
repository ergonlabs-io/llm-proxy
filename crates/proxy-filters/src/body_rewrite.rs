//! Bounded request-body prefix scanner and splice engine.
//!
//! This module answers two questions without ever buffering a request body:
//! **what does the top-level JSON object say** (`model`, `stream`, whether
//! `stream_options` is already present), and **what bytes, if any, should be
//! spliced in, and where.**
//!
//! # Why a bounded prefix scan, not "buffer the body and parse it"
//!
//! A multimodal chat-completion request carries megabytes of inline base64
//! image data inside `messages`. Any cap large enough to admit that body is
//! large enough that `cap × concurrent_streams` can exhaust the worker; any
//! cap small enough to be safe silently drops exactly the requests a customer
//! most wants metered. So this scanner never buffers the body: it holds at
//! most `cap` bytes, no matter how large the body turns out to be.
//!
//! What makes that workable is that every field we care about — `model`,
//! `stream`, `stream_options` — is a **top-level scalar/object, a sibling of
//! `messages`, not a child of it**, and SDKs emit them early. So
//! [`BodyPrefixScanner`] is a depth-tracking incremental tokenizer (the same
//! shape as [`SseUsageScanner`](crate::usage::SseUsageScanner): fed arbitrary
//! byte chunks, retains only bounded state) that walks the top-level object
//! key by key, **skips over nested structures without materializing them**,
//! and keeps only the handful of top-level facts this module needs.
//!
//! # Splice, don't re-serialize
//!
//! The injection point is immediately after the top-level opening `{`, which
//! lives in the very first byte(s) of the held prefix. Mutation is therefore
//! a **prefix splice**: emit the bytes up to `splice_at`, the injected bytes,
//! then the rest of the body untouched. The body is never reassembled, so it
//! never round-trips through a JSON serializer that could reorder keys or
//! renormalize numbers.
//!
//! Splicing at the *front* is deliberate, not incidental: under
//! last-key-wins JSON parsing (which every mainstream JSON decoder,
//! including `serde_json` and every SDK's client library, implements), a
//! client's own later `stream_options` key still wins over one spliced in
//! near the start of the object. That is exactly why `ScanOutcome::CapExceeded`
//! (we hit the cap before proving `stream_options` is absent) is still safe
//! to inject into: if the client's real `stream_options` shows up later in
//! the body (outside our window), it silently overrides ours instead of
//! colliding with it.
//!
//! # Failure is "pass through untouched", never an error
//!
//! Non-JSON bodies, truncated bodies, and bodies whose interesting keys never
//! appear inside the window all produce [`ScanOutcome::NotJson`] or
//! "not found" facts — never a parse error. A proxy that rejects a request it
//! merely failed to *understand* is worse than one that forwards it
//! unmetered/unrouted.

/// Default bound on how many prefix bytes a [`BodyPrefixScanner`] will ever
/// hold. This bounds *how far in we look* for top-level keys, not how large a
/// body we accept — bodies of any size pass through; only the amount we
/// retain and scan is capped.
pub const DEFAULT_PREFIX_CAP: usize = 64 * 1024;

/// Facts the scanner recovered from the top-level JSON object.
#[derive(Debug, Clone, PartialEq)]
pub struct BodyFacts {
    /// The `model` field's string value, if a `model` key with a string
    /// value was seen inside the window.
    pub model: Option<String>,
    /// The `stream` field's boolean value, if a `stream` key with a literal
    /// `true`/`false` value was seen inside the window.
    pub stream: Option<bool>,
    /// Whether a top-level `stream_options` key was seen at all (its value
    /// is never inspected — presence is all that matters to the injection
    /// policy).
    pub saw_stream_options: bool,
    /// Byte offset, into the held prefix, of the position immediately after
    /// the top-level opening `{` — where a splice goes. `None` if the body
    /// never got that far (e.g. it isn't a JSON object at all).
    pub splice_at: Option<usize>,
    /// How the scan ended.
    pub outcome: ScanOutcome,
}

/// How a [`BodyPrefixScanner`] scan concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOutcome {
    /// The top-level object closed inside the window: every fact above is
    /// authoritative, including the *absence* of a key (e.g.
    /// `saw_stream_options == false` really does mean the client never sent
    /// it).
    Complete,
    /// The cap was hit before the top-level object closed. Facts found *so
    /// far* are valid (a key we did see, we saw correctly) but absence is
    /// not proven — a key we didn't see might simply be further in.
    CapExceeded,
    /// The body is not valid JSON, not a JSON object at the top level, or
    /// ended (truncated) before we could tell either way.
    NotJson,
}

/// Whether a [`BodyPrefixScanner::push`] call reached a final decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanState {
    /// The scanner needs more bytes before it can decide anything.
    NeedMore,
    /// A decision (`Complete`, `CapExceeded`, or `NotJson`) has been made;
    /// further bytes are ignored. Call [`BodyPrefixScanner::finish`].
    Decided,
}

/// Which top-level key, if any, is currently being parsed. Only the keys
/// this module cares about get special handling; everything else is parsed
/// (to keep depth tracking correct) but not retained.
///
/// Rust note: this is a small closed enum rather than comparing raw byte
/// slices at every use site — `PartialEq` derive lets `current_key ==
/// KeyKind::Model` read naturally at each call site below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Model,
    Stream,
    StreamOptions,
    Other,
}

fn classify_key(key: &[u8]) -> KeyKind {
    match key {
        b"model" => KeyKind::Model,
        b"stream" => KeyKind::Stream,
        b"stream_options" => KeyKind::StreamOptions,
        _ => KeyKind::Other,
    }
}

fn is_json_ws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// A byte that legally ends a bare literal (`true`/`false`/`null`/a number)
/// at the top level: whitespace, the next key's comma, or the object's
/// closing brace. JSON literals never contain any of these internally, so
/// this alone is enough to find the end without a full number/keyword
/// grammar.
fn is_literal_terminator(byte: u8) -> bool {
    is_json_ws(byte) || matches!(byte, b',' | b'}' | b']')
}

/// Tokenizer state. Rust note: this machine only ever needs to remember "one
/// level" of context beyond the top level, because everything below the top
/// level is handled by [`State::InNestedSkip`]'s own depth counter — we don't
/// need a full recursive-descent stack because we never interpret anything
/// nested, only skip past it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Before the top-level `{` has been seen.
    BeforeTopOpen,
    /// Inside the top-level object, expecting a key's opening `"` or the
    /// object's closing `}`.
    ExpectKeyOrClose,
    /// Inside a top-level key's string content.
    InKey,
    /// Just closed a key's string; expecting `:`.
    AfterKey,
    /// Just consumed `:`; expecting the value's first byte.
    BeforeValue,
    /// Inside the `model` key's string value (content is retained via a
    /// byte-range into the held prefix, not a separate buffer).
    InModelString,
    /// Inside some other key's string value (not retained).
    InSkipString,
    /// Inside a bare literal value (`true`/`false`/`null`/a number).
    InLiteralValue,
    /// Inside a nested object/array value, tracking only enough to know when
    /// it closes.
    InNestedSkip,
    /// Just closed a value; expecting `,` (another key) or the top-level `}`.
    AfterValue,
}

/// Bounded incremental scanner over a JSON request body's top-level object.
///
/// Feed it chunks via [`Self::push`] in order; memory is `O(cap)` regardless
/// of how large the body turns out to be, because the scanner stops holding
/// (and stops looking at) bytes the instant it has held `cap` of them. See
/// the module docs for why that is the right tradeoff.
pub struct BodyPrefixScanner {
    cap: usize,
    /// Rust note: this is the *only* buffer the scanner owns. `model` and
    /// `stream`'s values are recovered later, in [`Self::finish`], by
    /// slicing back into this same buffer via byte ranges recorded during
    /// the scan — that avoids a second, redundant copy of bytes we already
    /// hold.
    held: Vec<u8>,
    decided: bool,
    outcome: Option<ScanOutcome>,
    state: State,

    // Key parsing.
    key_start: usize,
    current_key: KeyKind,
    /// Shared "are we mid-escape-sequence" flag for whichever single-level
    /// string is currently open (`InKey`, `InModelString`, or
    /// `InSkipString`) — only one of those is ever active at a time, so one
    /// field suffices.
    str_escaped: bool,

    // `model` value.
    model_start: usize,
    model_range: Option<(usize, usize)>,

    // `stream` value.
    literal_start: usize,
    literal_capturing: bool,
    stream_literal_range: Option<(usize, usize)>,

    // `stream_options` presence.
    saw_stream_options: bool,

    // Nested value skip state.
    nest_depth: u32,
    nest_in_string: bool,
    nest_escaped: bool,

    splice_at: Option<usize>,
}

impl BodyPrefixScanner {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            held: Vec::new(),
            decided: false,
            outcome: None,
            state: State::BeforeTopOpen,
            key_start: 0,
            current_key: KeyKind::Other,
            str_escaped: false,
            model_start: 0,
            model_range: None,
            literal_start: 0,
            literal_capturing: false,
            stream_literal_range: None,
            saw_stream_options: false,
            nest_depth: 0,
            nest_in_string: false,
            nest_escaped: false,
            splice_at: None,
        }
    }

    /// Feed the next chunk of the request body. Chunks may split anywhere,
    /// including mid-string, mid-escape, and mid-number.
    ///
    /// Once a decision has been reached, this is a no-op — the scanner
    /// never holds or looks at another byte, which is what keeps memory at
    /// `O(cap)` even when many more chunks arrive afterward.
    pub fn push(&mut self, chunk: &[u8]) -> ScanState {
        if !self.decided {
            for &byte in chunk {
                if self.held.len() >= self.cap {
                    self.decide(ScanOutcome::CapExceeded);
                    break;
                }
                self.held.push(byte);
                let idx = self.held.len() - 1;
                if let Some(outcome) = self.feed_byte(idx) {
                    self.decide(outcome);
                    break;
                }
            }
        }
        if self.decided {
            ScanState::Decided
        } else {
            ScanState::NeedMore
        }
    }

    /// End of stream reached (or the caller has decided to stop feeding
    /// bytes, e.g. because [`ScanState::Decided`] was already returned).
    ///
    /// If no decision was reached — the body ran out before the top-level
    /// object closed and before the cap was hit — that is treated as
    /// [`ScanOutcome::NotJson`]: we never got proof either way, and a
    /// truncated/malformed body is exactly the "don't guess, pass through"
    /// case this module exists to handle safely.
    pub fn finish(mut self) -> BodyFacts {
        if !self.decided {
            self.decide(ScanOutcome::NotJson);
        }
        let outcome = self.outcome.expect("decide() always sets outcome");
        let model = self
            .model_range
            .and_then(|(start, end)| decode_json_string(&self.held[start..end]));
        let stream =
            self.stream_literal_range
                .and_then(|(start, end)| match &self.held[start..end] {
                    b"true" => Some(true),
                    b"false" => Some(false),
                    _ => None,
                });
        BodyFacts {
            model,
            stream,
            saw_stream_options: self.saw_stream_options,
            splice_at: self.splice_at,
            outcome,
        }
    }

    /// Bytes currently held. Never more than `cap`, regardless of how much
    /// of the body has been pushed.
    pub fn held(&self) -> &[u8] {
        &self.held
    }

    fn decide(&mut self, outcome: ScanOutcome) {
        self.outcome = Some(outcome);
        self.decided = true;
    }

    /// Advance the tokenizer by exactly one already-held byte at `idx`.
    /// Returns `Some(outcome)` the instant a decision is reached.
    ///
    /// Rust note: most states consume the byte and `return None` (move on to
    /// the next byte from the caller). A couple of states (a literal value
    /// ending, a nested value closing) instead change `self.state` and
    /// `continue` the loop *without* advancing `idx` — the same byte gets
    /// re-interpreted under the new state. That's what lets, say, a `stream`
    /// value's terminating `,` be recognized as "the literal ended" and
    /// "the next key starts" in the same call, without a second `push`.
    fn feed_byte(&mut self, idx: usize) -> Option<ScanOutcome> {
        loop {
            let byte = self.held[idx];
            match self.state {
                State::BeforeTopOpen => {
                    if is_json_ws(byte) {
                        return None;
                    }
                    if byte == b'{' {
                        self.splice_at = Some(idx + 1);
                        self.state = State::ExpectKeyOrClose;
                        return None;
                    }
                    return Some(ScanOutcome::NotJson);
                }
                State::ExpectKeyOrClose => {
                    if is_json_ws(byte) {
                        return None;
                    }
                    if byte == b'"' {
                        self.key_start = idx + 1;
                        self.str_escaped = false;
                        self.state = State::InKey;
                        return None;
                    }
                    if byte == b'}' {
                        return Some(ScanOutcome::Complete);
                    }
                    return Some(ScanOutcome::NotJson);
                }
                State::InKey => {
                    if self.str_escaped {
                        self.str_escaped = false;
                        return None;
                    }
                    if byte == b'\\' {
                        self.str_escaped = true;
                        return None;
                    }
                    if byte == b'"' {
                        let raw_key = &self.held[self.key_start..idx];
                        // A key spelled with a JSON escape (`"\u0073tream"`)
                        // names the same member to the provider's decoder, so
                        // decode before classifying.
                        self.current_key = if raw_key.contains(&b'\\') {
                            decode_json_string(raw_key)
                                .map_or(KeyKind::Other, |k| classify_key(k.as_bytes()))
                        } else {
                            classify_key(raw_key)
                        };
                        if self.current_key == KeyKind::StreamOptions {
                            // Presence is all that matters; the value is
                            // still parsed normally below so depth tracking
                            // stays correct.
                            self.saw_stream_options = true;
                        }
                        self.state = State::AfterKey;
                        return None;
                    }
                    return None;
                }
                State::AfterKey => {
                    if is_json_ws(byte) {
                        return None;
                    }
                    if byte == b':' {
                        self.state = State::BeforeValue;
                        return None;
                    }
                    return Some(ScanOutcome::NotJson);
                }
                State::BeforeValue => {
                    if is_json_ws(byte) {
                        return None;
                    }
                    if self.current_key == KeyKind::Model && byte != b'"' {
                        // A non-string `model` replaces an earlier string one
                        // under last-key-wins, so no model is known.
                        self.model_range = None;
                    }
                    match byte {
                        b'"' => {
                            self.str_escaped = false;
                            if self.current_key == KeyKind::Model {
                                self.model_start = idx + 1;
                                self.state = State::InModelString;
                            } else {
                                self.state = State::InSkipString;
                            }
                            return None;
                        }
                        b't' | b'f' | b'n' | b'-' | b'0'..=b'9' => {
                            self.literal_start = idx;
                            self.literal_capturing = self.current_key == KeyKind::Stream;
                            self.state = State::InLiteralValue;
                            return None;
                        }
                        b'{' | b'[' => {
                            self.nest_depth = 1;
                            self.nest_in_string = false;
                            self.nest_escaped = false;
                            self.state = State::InNestedSkip;
                            return None;
                        }
                        _ => return Some(ScanOutcome::NotJson),
                    }
                }
                State::InModelString => {
                    if self.str_escaped {
                        self.str_escaped = false;
                        return None;
                    }
                    if byte == b'\\' {
                        self.str_escaped = true;
                        return None;
                    }
                    if byte == b'"' {
                        self.model_range = Some((self.model_start, idx));
                        self.state = State::AfterValue;
                        return None;
                    }
                    return None;
                }
                State::InSkipString => {
                    if self.str_escaped {
                        self.str_escaped = false;
                        return None;
                    }
                    if byte == b'\\' {
                        self.str_escaped = true;
                        return None;
                    }
                    if byte == b'"' {
                        self.state = State::AfterValue;
                        return None;
                    }
                    return None;
                }
                State::InLiteralValue => {
                    if is_literal_terminator(byte) {
                        if self.literal_capturing {
                            self.stream_literal_range = Some((self.literal_start, idx));
                        }
                        self.state = State::AfterValue;
                        continue; // Re-interpret this same byte as AfterValue.
                    }
                    return None;
                }
                State::InNestedSkip => {
                    if self.nest_in_string {
                        if self.nest_escaped {
                            self.nest_escaped = false;
                        } else if byte == b'\\' {
                            self.nest_escaped = true;
                        } else if byte == b'"' {
                            self.nest_in_string = false;
                        }
                        return None;
                    }
                    match byte {
                        b'"' => self.nest_in_string = true,
                        b'{' | b'[' => self.nest_depth += 1,
                        b'}' | b']' => {
                            self.nest_depth -= 1;
                            if self.nest_depth == 0 {
                                self.state = State::AfterValue;
                            }
                        }
                        _ => {}
                    }
                    return None;
                }
                State::AfterValue => {
                    if is_json_ws(byte) {
                        return None;
                    }
                    if byte == b',' {
                        self.state = State::ExpectKeyOrClose;
                        return None;
                    }
                    if byte == b'}' {
                        return Some(ScanOutcome::Complete);
                    }
                    return Some(ScanOutcome::NotJson);
                }
            }
        }
    }
}

/// Decode a JSON string's raw content bytes (the bytes strictly between the
/// quotes, exactly as they appeared in the body, escapes and all) into an
/// owned `String`.
///
/// Rust note: rather than hand-roll `\uXXXX`/`\n`/etc. unescaping, this
/// re-wraps the bytes in quotes and hands them to `serde_json` — the
/// tokenizer above already proved these bytes form one complete, well-formed
/// JSON string, so this call cannot fail in practice; `.ok()` degrades to
/// `None` rather than panicking if it somehow did.
fn decode_json_string(raw: &[u8]) -> Option<String> {
    let mut quoted = Vec::with_capacity(raw.len() + 2);
    quoted.push(b'"');
    quoted.extend_from_slice(raw);
    quoted.push(b'"');
    serde_json::from_slice(&quoted).ok()
}

/// The exact bytes to splice at `facts.splice_at`, or `None` to pass the
/// body through untouched.
///
/// Only injects when the client asked for a stream (`stream == Some(true)`)
/// and did not already send `stream_options`. `CapExceeded` is still
/// eligible — see the module docs for why splicing at the front makes that
/// safe even though we can't prove `stream_options` is truly absent.
pub fn include_usage_injection(facts: &BodyFacts) -> Option<&'static str> {
    if facts.saw_stream_options {
        return None;
    }
    if facts.stream != Some(true) {
        return None;
    }
    match facts.outcome {
        ScanOutcome::Complete | ScanOutcome::CapExceeded => {
            Some(r#""stream_options":{"include_usage":true},"#)
        }
        ScanOutcome::NotJson => None,
    }
}

#[cfg(test)]
mod tests {
    //! The acceptance suite: the tokenizer and the
    //! splice-policy function, in isolation from any filter wiring.

    use super::*;

    /// Feed the whole body in one `push`, then `finish`.
    fn scan(body: &[u8], cap: usize) -> BodyFacts {
        let mut scanner = BodyPrefixScanner::new(cap);
        scanner.push(body);
        scanner.finish()
    }

    // ---- basic extraction ---------------------------------------------

    #[test]
    fn escaped_stream_key_is_recognized_and_injected() {
        let facts = scan(br#"{"model":"m","\u0073tream":true}"#, DEFAULT_PREFIX_CAP);
        assert_eq!(facts.stream, Some(true));
        assert!(include_usage_injection(&facts).is_some());
    }

    #[test]
    fn escaped_model_key_is_recognized() {
        let facts = scan(br#"{"mo\u0064el":"expensive"}"#, DEFAULT_PREFIX_CAP);
        assert_eq!(facts.model.as_deref(), Some("expensive"));
    }

    #[test]
    fn later_non_string_model_clears_earlier_model() {
        let facts = scan(br#"{"model":"a","model":1}"#, DEFAULT_PREFIX_CAP);
        assert_eq!(facts.model, None);
    }

    #[test]
    fn typical_openai_body_extracts_model_and_stream() {
        let body =
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
        let facts = scan(body, DEFAULT_PREFIX_CAP);
        assert_eq!(facts.model.as_deref(), Some("gpt-4o"));
        assert_eq!(facts.stream, Some(true));
        assert!(!facts.saw_stream_options);
        assert_eq!(facts.outcome, ScanOutcome::Complete);
        assert_eq!(
            facts.splice_at,
            Some(1),
            "splice goes right after the opening brace"
        );
    }

    #[test]
    fn stream_false_produces_no_injection() {
        let body = br#"{"model":"gpt-4o","stream":false}"#;
        let facts = scan(body, DEFAULT_PREFIX_CAP);
        assert_eq!(facts.stream, Some(false));
        assert_eq!(include_usage_injection(&facts), None);
    }

    #[test]
    fn stream_absent_produces_no_injection() {
        let body = br#"{"model":"gpt-4o"}"#;
        let facts = scan(body, DEFAULT_PREFIX_CAP);
        assert_eq!(facts.stream, None);
        assert_eq!(facts.outcome, ScanOutcome::Complete);
        assert_eq!(include_usage_injection(&facts), None);
    }

    #[test]
    fn client_supplied_stream_options_suppresses_injection() {
        let body = br#"{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":false}}"#;
        let facts = scan(body, DEFAULT_PREFIX_CAP);
        assert!(facts.saw_stream_options);
        assert_eq!(facts.stream, Some(true));
        assert_eq!(
            include_usage_injection(&facts),
            None,
            "must not duplicate a key the client already set"
        );
    }

    /// Pins the degenerate empty-object case: `{}` has no `stream` at all,
    /// so the policy already returns `None` well before any "trailing
    /// comma into thin air" concern would matter.
    #[test]
    fn empty_object_produces_no_injection() {
        let facts = scan(b"{}", DEFAULT_PREFIX_CAP);
        assert_eq!(facts.stream, None);
        assert_eq!(facts.model, None);
        assert!(!facts.saw_stream_options);
        assert_eq!(facts.outcome, ScanOutcome::Complete);
        assert_eq!(
            include_usage_injection(&facts),
            None,
            "an empty object has no stream:true, so nothing should be spliced into it"
        );
    }

    // ---- cap behavior ----------------------------------------------------

    #[test]
    fn keys_after_a_large_messages_array_fall_outside_the_window() {
        let filler = "x".repeat(4096);
        let body = format!(
            r#"{{"messages":[{{"role":"user","content":"{filler}"}}],"model":"gpt-4o","stream":true}}"#
        );
        let cap = 256; // Much smaller than the filler, well before model/stream.
        let facts = scan(body.as_bytes(), cap);
        assert_eq!(facts.outcome, ScanOutcome::CapExceeded);
        assert_eq!(facts.model, None, "model appears after the cap");
        assert_eq!(facts.stream, None, "stream appears after the cap");

        // Also prove the scanner itself never held more than the cap.
        let mut scanner = BodyPrefixScanner::new(cap);
        scanner.push(body.as_bytes());
        assert!(scanner.held().len() <= cap);
    }

    // ---- non-JSON / malformed --------------------------------------------

    #[test]
    fn non_json_bodies_pass_through_untouched() {
        let cases: [&[u8]; 4] = [
            b"not json at all",
            b"{\"model\": \"gpt-4o\"", // truncated: never closes
            b"[1,2,3]",                // top-level array, not object
            b"",
        ];
        for body in cases {
            let facts = scan(body, DEFAULT_PREFIX_CAP);
            assert_eq!(facts.outcome, ScanOutcome::NotJson, "body: {body:?}");
            assert_eq!(include_usage_injection(&facts), None, "body: {body:?}");
        }
    }

    // ---- string escaping / depth tracking ---------------------------------

    #[test]
    fn escaped_quotes_and_backslashes_do_not_desync_depth() {
        let body = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"say \"hi\" and a \\ backslash"}],"stream":true}"#;
        let facts = scan(body, DEFAULT_PREFIX_CAP);
        assert_eq!(facts.model.as_deref(), Some("gpt-4o"));
        assert_eq!(facts.stream, Some(true));
        assert_eq!(
            facts.outcome,
            ScanOutcome::Complete,
            "escaped quotes inside `messages` content must not be mistaken for the string's end, \
             or for the object's close"
        );
    }

    /// The escape tests above are necessary but NOT sufficient, and the reason
    /// is worth stating: they use an EVEN number of escaped quotes. A scanner
    /// that ignores escaping entirely reads each `\"` as a real quote, so an
    /// even count toggles the "in string" flag back to where it started and
    /// depth lands correctly by accident. The broken scanner passes.
    ///
    /// Only ODD parity actually catches it, so these two tests pin it. This
    /// was found by mutation testing (deleting the `nest_escaped` handling
    /// left the even-parity test green), which is exactly the class of hole
    /// mutation testing exists to find.
    #[test]
    fn an_odd_escaped_quote_in_a_nested_string_does_not_desync_depth() {
        // One `\"` inside `messages` content. Ignore escaping and that quote
        // closes the string early; `}],` is then swallowed as string content,
        // the `messages` array never closes, and `stream` is never seen as a
        // top-level key -- so `stream` comes back None and nothing is injected.
        let body = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"an odd \" quote"}],"stream":true}"#;
        let facts = scan(body, DEFAULT_PREFIX_CAP);
        assert_eq!(facts.model.as_deref(), Some("gpt-4o"));
        assert_eq!(
            facts.stream,
            Some(true),
            "a single escaped quote inside nested content must not end the string, \
             or `stream` falls outside the top level and is never seen"
        );
        assert_eq!(facts.outcome, ScanOutcome::Complete);
        assert!(
            include_usage_injection(&facts).is_some(),
            "the practical consequence of desyncing here is a silently un-metered request"
        );
    }

    /// The same parity argument for a TOP-LEVEL string value, which runs
    /// through `str_escaped` rather than `nest_escaped` -- a separate code
    /// path, and so a separate way to get this wrong.
    #[test]
    fn an_odd_escaped_quote_in_a_top_level_string_does_not_desync_depth() {
        let body = br#"{"model":"od\"d","stream":true}"#;
        let facts = scan(body, DEFAULT_PREFIX_CAP);
        // The extracted value is UNescaped: raw `od\"d` in the body -> `od"d`.
        assert_eq!(facts.model.as_deref(), Some("od\"d"));
        assert_eq!(facts.stream, Some(true));
        assert_eq!(facts.outcome, ScanOutcome::Complete);
    }

    #[test]
    fn escaped_backslash_before_quote_does_not_end_string_early() {
        // `\\\"` is an escaped backslash followed by a real closing quote —
        // the classic tokenizer bug is treating `\\"` as "the backslash
        // escapes this quote" when it's actually "the backslash escapes
        // itself, then the quote closes the string".
        let body = br#"{"model":"a\\","stream":true}"#;
        let facts = scan(body, DEFAULT_PREFIX_CAP);
        assert_eq!(facts.model.as_deref(), Some("a\\"));
        assert_eq!(facts.stream, Some(true));
        assert_eq!(facts.outcome, ScanOutcome::Complete);
    }

    // ---- chunk-boundary robustness ----------------------------------------

    #[test]
    fn every_split_point_yields_identical_facts() {
        let body: &[u8] = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"say \"hi\""}],"stream":true,"temperature":0.7}"#;
        let expected = scan(body, DEFAULT_PREFIX_CAP);
        for split in 1..body.len() {
            let mut scanner = BodyPrefixScanner::new(DEFAULT_PREFIX_CAP);
            scanner.push(&body[..split]);
            scanner.push(&body[split..]);
            let facts = scanner.finish();
            assert_eq!(facts, expected, "mismatch when split at offset {split}");
        }
    }

    // ---- O(cap) memory, not O(body) ---------------------------------------

    /// The test that fails if someone "simplifies" this back into a
    /// full-body buffer: several MB of body, `model`/`stream` in their
    /// normal leading position, and a marker planted deep inside the
    /// (never-retained) `messages` blob.
    #[test]
    fn large_multimodal_body_stays_bounded_by_cap() {
        let cap = 4096;
        let marker = "UNIQUE_MARKER_DEEP_IN_MESSAGES";
        // Several MB of base64-looking filler, comfortably past `cap`, with
        // the marker planted after the first `cap` bytes of it.
        let blob_len = 6 * 1024 * 1024;
        let mut content = "A".repeat(cap * 4);
        content.push_str(marker);
        content.push_str(&"B".repeat(blob_len - content.len()));

        let body = format!(
            r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"{content}"}}]}}"#
        );

        let mut scanner = BodyPrefixScanner::new(cap);
        // Feed it in realistic streaming-sized chunks, checking the bound
        // holds after every single push, not just at the end.
        for window in body.as_bytes().chunks(8192) {
            scanner.push(window);
            assert!(
                scanner.held().len() <= cap,
                "held {} bytes, cap is {cap}",
                scanner.held().len()
            );
        }

        // The marker sits well past `cap` bytes into the body; it must never
        // have entered the held prefix at all.
        assert!(
            !scanner
                .held()
                .windows(marker.len())
                .any(|w| w == marker.as_bytes()),
            "the scanner retained bytes from deep inside `messages` — it is buffering the body"
        );
        assert!(scanner.held().len() <= cap);

        let facts = scanner.finish();
        assert_eq!(facts.model.as_deref(), Some("gpt-4o"));
        assert_eq!(facts.stream, Some(true));
        assert_eq!(facts.splice_at, Some(1));
        assert_eq!(
            facts.outcome,
            ScanOutcome::CapExceeded,
            "the body is far larger than the cap, so the top-level object never closes \
             inside the window"
        );
        assert_eq!(
            include_usage_injection(&facts),
            Some(r#""stream_options":{"include_usage":true},"#),
            "facts found before the cap are still valid, so CapExceeded must still allow injection"
        );
    }

    // ---- include_usage_injection policy table ------------------------------

    #[test]
    fn injection_policy_covers_every_combination() {
        let outcomes = [
            ScanOutcome::Complete,
            ScanOutcome::CapExceeded,
            ScanOutcome::NotJson,
        ];
        let streams = [Some(true), Some(false), None];
        let saw_stream_options_values = [true, false];

        for &outcome in &outcomes {
            for &stream in &streams {
                for &saw_stream_options in &saw_stream_options_values {
                    let facts = BodyFacts {
                        model: None,
                        stream,
                        saw_stream_options,
                        splice_at: Some(1),
                        outcome,
                    };
                    let expected = if saw_stream_options || stream != Some(true) {
                        None
                    } else {
                        match outcome {
                            ScanOutcome::Complete | ScanOutcome::CapExceeded => {
                                Some(r#""stream_options":{"include_usage":true},"#)
                            }
                            ScanOutcome::NotJson => None,
                        }
                    };
                    assert_eq!(
                        include_usage_injection(&facts),
                        expected,
                        "outcome={outcome:?} stream={stream:?} saw_stream_options={saw_stream_options}"
                    );
                }
            }
        }
    }
}
