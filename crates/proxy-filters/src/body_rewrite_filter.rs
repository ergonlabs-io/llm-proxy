//! WP-45 increment 2b — wires the [`crate::body_rewrite`] scanner/splice
//! engine into a real decode-path `HttpFilter`.
//!
//! Scope, deliberately narrow: **consumer A only** — force
//! `stream_options.include_usage = true` onto OpenAI-dialect streaming
//! requests that didn't already opt in, so WP-33's usage filter has
//! something to find. Consumer B (body-based model routing, via
//! `clear_route_cache()`) is a separate future increment; this module never
//! reads `model` for routing purposes. The `llmproxy` dialect / JSON schema
//! surface that will eventually configure this filter from `--config` is
//! increment 2c, also not built here — this filter is Envoy-typed-config only.
//!
//! # State machine
//!
//! Per stream: `Scanning { .. } -> PassThrough`. `decode_headers` decides
//! up front whether this request is even a candidate (OpenAI dialect, has a
//! body, JSON content type); everything else goes straight to `PassThrough`.
//! Once in `PassThrough` (either from the start, or once a splice decision
//! has been made), every subsequent `decode_data` call is a straight-through
//! no-op: `Continue`, `data` untouched, no buffer touched. See
//! [`BodyRewriteFilterInstance::decode_data`] for the `Scanning` side.
//!
//! # Memory bound: `O(prefix cap + one chunk)`, not strictly `O(cap)`
//!
//! [`crate::body_rewrite::BodyPrefixScanner`] itself stops *holding* bytes
//! the instant it has `cap` of them. But this filter must still forward
//! whatever's left of the chunk that crossed that boundary — it can't hand
//! the downstream router half a chunk — so this filter's own `pending`
//! buffer is bounded by `cap` plus the size of one inbound chunk, not
//! strictly `cap`. Chunks themselves are bounded by the codec's read buffer,
//! so this is still nowhere near `O(body)`: a 40MB multimodal request never
//! costs more than `cap + one chunk`, and the moment a decision is made
//! (`Decided`, or `end_stream`), `pending` is handed off and the state drops
//! back to `PassThrough`, discarding it. IMPLEMENTATION_PLAN.md's WP-45
//! acceptance 4b describes the bound as `O(cap)`; this doc is the precise
//! version, written down so nobody "fixes" the extra chunk of slack later
//! under a misunderstanding of the acceptance criterion.
//!
//! # Never fails a request
//!
//! Non-JSON bodies, truncated JSON, and bodies whose interesting keys never
//! show up inside the window all fall out of [`crate::body_rewrite`] as
//! "no injection" facts, never an error — this filter forwards them
//! untouched, exactly per that module's "pass through, never fail" rule.
//!
//! # Config identity: reusing `RuntimeFeatureFlag`
//!
//! Same rationale as `usage_filter`'s module doc (reusing `DataSource`) and
//! `header_mutation_filter`'s (reusing `HeaderValueOption`): an Any's type
//! URL is just an opaque `prefix/full.type.name` string, and only the suffix
//! has to resolve against the descriptor pool, so pointing our
//! `type.llmproxy.dev` prefix at an existing compiled message is legal, if a
//! little unusual. This filter needs exactly two config facts — an on/off
//! switch and the dialect — and `envoy.config.core.v3.RuntimeFeatureFlag`
//! happens to have exactly that shape: `default_value` (a `BoolValue`) maps
//! onto the on/off switch (WP-45's `observability.force_usage_reporting`,
//! default `true`), and `runtime_key` (a plain string) carries the dialect
//! name. `DataSource` (already used by `usage_filter`) was ruled out only
//! because `FilterRegistry::register` asserts on a duplicate `type_url`, and
//! this filter is a distinct extension from the usage filter even though
//! both currently borrow a stand-in proto. A vendored Lane-H proto is the
//! real answer once this filter grows a third config knob (e.g. the prefix
//! cap) — see `tests::runtime_feature_flag_resolves_in_the_descriptor_pool`
//! for the check that pins this message actually being compiled in.

use bytes::{Bytes, BytesMut};
use http::header::CONTENT_LENGTH;
use http::{HeaderMap, HeaderValue};
use prost_reflect::DynamicMessage;
use std::sync::Arc;

use proxy_config::ConfigError;
use proxy_http::filter::{
    DecoderCallbacks, FactoryContext, FilterDataStatus, FilterHeadersStatus, FilterInstanceFactory,
    HttpFilter, HttpFilterFactory, PerRouteConfig, RequestHeaders,
};

use crate::body_rewrite::{
    include_usage_injection, BodyPrefixScanner, ScanState, DEFAULT_PREFIX_CAP,
};
use crate::usage::Dialect;

/// Type URL this filter is registered under (see the module doc for the
/// `RuntimeFeatureFlag`-reuse rationale).
pub const TYPE_URL: &str = "type.llmproxy.dev/envoy.config.core.v3.RuntimeFeatureFlag";

/// Parsed, validated config: whether this filter does anything at all, and
/// which dialect it should treat as OpenAI-shaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BodyRewriteConfig {
    /// `typed_config.default_value` — an operator kill switch
    /// (`observability.force_usage_reporting`, default `true` per the WP-45
    /// dialect surface once 2c wires it up).
    enabled: bool,
    dialect: Dialect,
}

/// Read a `RuntimeFeatureFlag`-shaped `typed_config`: `default_value.value`
/// (a `BoolValue`, required) is `enabled`; `runtime_key` is the dialect name.
fn parse_config(config: &DynamicMessage) -> Result<BodyRewriteConfig, ConfigError> {
    let invalid = |field_path: &str, reason: String| ConfigError::InvalidValue {
        field_path: field_path.to_string(),
        reason,
    };

    // Rust note: `get_field_by_name` returns the *default* value for an
    // unset message field, not `None` (that's `has_field_by_name`'s job) --
    // so presence has to be checked explicitly, or a caller that omits
    // `default_value` entirely would silently parse as `enabled: false`
    // instead of the required-field error the PGV `validate.rules` on this
    // proto field calls for.
    if !config.has_field_by_name("default_value") {
        return Err(invalid(
            "typed_config.default_value",
            "the `default_value` field is required".to_string(),
        ));
    }
    let enabled = config
        .get_field_by_name("default_value")
        .and_then(|v| v.as_message().cloned())
        .and_then(|m| m.get_field_by_name("value").and_then(|v| v.as_bool()))
        .unwrap_or(false);

    let runtime_key = config
        .get_field_by_name("runtime_key")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();

    let dialect = match runtime_key.to_ascii_lowercase().as_str() {
        "openai" => Dialect::OpenAi,
        "anthropic" => Dialect::Anthropic,
        _ => {
            return Err(invalid(
                "typed_config.runtime_key",
                format!("expected `openai` or `anthropic`, got `{runtime_key}`"),
            ))
        }
    };

    Ok(BodyRewriteConfig { enabled, dialect })
}

/// [`HttpFilterFactory`] for [`TYPE_URL`].
#[derive(Default)]
pub struct BodyRewriteFilterFactory;

impl HttpFilterFactory for BodyRewriteFilterFactory {
    fn type_url(&self) -> &'static str {
        TYPE_URL
    }

    fn create(
        &self,
        config: &DynamicMessage,
        _ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        let config = parse_config(config)?;
        Ok(Box::new(BodyRewriteInstanceFactory { config }))
    }

    fn parse_per_route(
        &self,
        config: &DynamicMessage,
    ) -> Result<Arc<dyn PerRouteConfig>, ConfigError> {
        let config = parse_config(config)?;
        Ok(Arc::new(BodyRewritePerRouteConfig(config)))
    }
}

/// Created once per (filter config, listener); stateless beyond the parsed
/// config, so building a fresh per-stream instance is cheap.
struct BodyRewritePerRouteConfig(BodyRewriteConfig);

impl PerRouteConfig for BodyRewritePerRouteConfig {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct BodyRewriteInstanceFactory {
    config: BodyRewriteConfig,
}

impl FilterInstanceFactory for BodyRewriteInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(BodyRewriteFilterInstance {
            config: self.config,
            state: State::PassThrough,
        })
    }
}

/// Rust note: the whole per-stream state machine described in the module
/// doc, in one enum. `Scanning` owns everything the scan needs; the instant
/// a decision is made it's discarded and replaced with the zero-size
/// `PassThrough` variant, which is what keeps a long-lived stream (many
/// chunks after the decision) from holding on to anything.
enum State {
    Scanning {
        scanner: BodyPrefixScanner,
        /// Every byte fed to `scanner` so far, kept so the eventual splice
        /// has something to splice into and so the tail past `cap` (see the
        /// module doc's memory-bound note) can still be forwarded.
        pending: BytesMut,
        /// The request's declared `content-length`, if the header was
        /// present and parsed as a valid, non-negative integer. `None`
        /// covers both "absent" (e.g. a chunked request) and "present but
        /// unparsable" — either way there is nothing sound to fix up.
        content_length: Option<u64>,
    },
    PassThrough,
}

/// Per-stream instance. One per request, per the frozen `HttpFilter`
/// contract (`filter.rs`'s module doc) — plain fields, no `Rc`/`RefCell`
/// needed, since it never leaves the worker thread that owns this stream.
struct BodyRewriteFilterInstance {
    config: BodyRewriteConfig,
    state: State,
}

/// Whether `headers` names a JSON media type (ignoring `;` parameters,
/// ASCII-case-insensitively), the same convention `usage_filter::classify_body`
/// uses for responses. A missing `content-type` is treated as "not JSON" —
/// we don't guess.
fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Some(value) = headers.get(http::header::CONTENT_TYPE) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let media_type = value.split(';').next().unwrap_or("").trim();
    media_type.eq_ignore_ascii_case("application/json")
}

impl HttpFilter for BodyRewriteFilterInstance {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        end_stream: bool,
    ) -> FilterHeadersStatus {
        let cfg = cb
            .per_route_config()
            .and_then(|c| {
                c.as_any()
                    .downcast_ref::<BodyRewritePerRouteConfig>()
                    .map(|c| c.0)
            })
            .unwrap_or(self.config);

        // Acceptance 3: an Anthropic body must be byte-identical in and out
        // -- there is no `stream_options` field there, and adding one risks
        // a 400 from a strict provider. Same short-circuit for a disabled
        // filter, a bodyless request, and a non-JSON content type: none of
        // these are candidates for the scan at all.
        if !cfg.enabled
            || cfg.dialect != Dialect::OpenAi
            || end_stream
            || !is_json_content_type(&headers.headers)
        {
            self.state = State::PassThrough;
            return FilterHeadersStatus::Continue;
        }

        let content_length = headers
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        // `content-length` is not fixed up here -- we don't yet know whether
        // we'll inject anything, and won't until body bytes have been
        // scanned. This callback is a no-op from `decode_headers` anyway
        // (see `DecoderCallbacks::modify_decoded_headers`'s doc); the real
        // fix-up happens in `decode_data`, once a decision is made.
        self.state = State::Scanning {
            scanner: BodyPrefixScanner::new(DEFAULT_PREFIX_CAP),
            pending: BytesMut::new(),
            content_length,
        };
        FilterHeadersStatus::Continue
    }

    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        // Rust note: swap the state out to get owned access to `scanner` and
        // `pending` (both moved out of `self`, not merely borrowed), since
        // `scanner.finish()` below consumes it. If we're not scanning at
        // all, this is a one-line no-op: `data` is left exactly as the
        // caller gave it, and we return before touching anything else --
        // this is the "PassThrough costs nothing" half of the module doc.
        let State::Scanning {
            mut scanner,
            mut pending,
            content_length,
        } = std::mem::replace(&mut self.state, State::PassThrough)
        else {
            return FilterDataStatus::Continue;
        };

        pending.extend_from_slice(data);
        let scan_state = scanner.push(data);

        if scan_state == ScanState::NeedMore && !end_stream {
            // Still undecided and more bytes are coming: hold everything
            // scanned so far and emit nothing this call. Rust note: setting
            // `*data = Bytes::new()` (an empty chunk) rather than returning
            // some `StopIteration*` status is the mechanism that lets us
            // hold bytes without the filter-manager's stop/resume dance --
            // an empty chunk is a legal, cheap "nothing to send yet" that
            // flows straight through like any other `Continue`.
            self.state = State::Scanning {
                scanner,
                pending,
                content_length,
            };
            *data = Bytes::new();
            return FilterDataStatus::Continue;
        }

        // Either the scanner reached a decision, or the body just ended
        // without one (truncated/malformed JSON) -- either way, finish now.
        let facts = scanner.finish();
        if let Some(inject) = include_usage_injection(&facts) {
            let splice_at = facts
                .splice_at
                .expect("include_usage_injection only returns Some when a splice point exists");
            let tail = pending.split_off(splice_at);
            pending.extend_from_slice(inject.as_bytes());
            pending.unsplit(tail);

            if let Some(len) = content_length {
                // Saturating, not `+`: `len` was parsed out of a CLIENT-supplied
                // `content-length` header, so it is untrusted input rather than a
                // number we computed. A client sending a near-`u64::MAX`
                // content-length would otherwise panic the worker in debug builds
                // and wrap in release. Same defect class as `TokenUsage::total()`,
                // and reachable from the downstream side rather than the upstream
                // one, which makes it strictly worse.
                let new_len = len.saturating_add(inject.len() as u64);
                cb.modify_decoded_headers(&mut |headers: &mut RequestHeaders| {
                    headers.headers.insert(
                        CONTENT_LENGTH,
                        HeaderValue::from_str(&new_len.to_string())
                            .expect("a decimal integer is always a valid header value"),
                    );
                });
            }
            // A chunked request (`content_length == None`) needs no header
            // fix-up at all -- there is nothing to recompute.
        }

        *data = pending.freeze();
        // `self.state` is already `PassThrough` from the `mem::replace`
        // above; every later `decode_data` call on this stream now takes
        // the early-return path.
        FilterDataStatus::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{RefCell, RefMut};

    use http::{HeaderMap, Method, StatusCode, Uri};
    use proxy_config::ir::RouteEntry;
    use proxy_http::filter::{BufferedBody, PerRouteConfig};
    use proxy_http::stream_info::StreamInfo;

    // --- test scaffolding ---------------------------------------------------

    /// A minimal `DecoderCallbacks` double. Only `modify_decoded_headers`,
    /// `per_route_config`, and `stream_info` are ever exercised by this
    /// filter; every other method panics loudly so a change that starts
    /// calling one of them (e.g. buffering via `add_decoded_data`, or
    /// resolving the route for consumer-B-style routing) fails a test
    /// instead of silently passing.
    struct TestCallbacks {
        /// The manager's canonical request head -- `decode_headers` gets a
        /// separate, ephemeral `&mut RequestHeaders` parameter (mirroring
        /// production, where `modify_decoded_headers` is a no-op from that
        /// callback); this is what `modify_decoded_headers` actually writes
        /// through, and what tests inspect afterward.
        head: RequestHeaders,
        per_route_config: Option<Arc<dyn PerRouteConfig>>,
        stream_info: RefCell<StreamInfo>,
    }

    impl TestCallbacks {
        fn new(head: RequestHeaders) -> Self {
            TestCallbacks {
                head,
                per_route_config: None,
                stream_info: RefCell::new(StreamInfo::default()),
            }
        }

        fn with_per_route_config(mut self, config: Arc<dyn PerRouteConfig>) -> Self {
            self.per_route_config = Some(config);
            self
        }
    }

    impl DecoderCallbacks for TestCallbacks {
        fn send_local_reply(
            &mut self,
            _code: StatusCode,
            _body: &str,
            _modify_headers: Option<proxy_http::filter::HeaderMutationFn>,
            _details: &str,
        ) {
            unimplemented!("body_rewrite_filter must never send a local reply")
        }
        fn continue_decoding(&mut self) {
            unimplemented!("body_rewrite_filter must never stop iteration")
        }
        fn add_decoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!("body_rewrite_filter must never buffer via add_decoded_data")
        }
        fn inject_decoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!("body_rewrite_filter must not inject data out of band")
        }
        fn decoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!("body_rewrite_filter must not consult the decoding buffer")
        }
        fn modify_decoding_buffer(&mut self, _f: &mut dyn FnMut(&mut BytesMut)) {
            unimplemented!(
                "body_rewrite_filter splices its own held bytes; \
                 it must not touch the filter-manager's decoding buffer"
            )
        }
        fn modify_decoded_headers(&mut self, f: &mut dyn FnMut(&mut RequestHeaders)) -> bool {
            f(&mut self.head);
            true
        }
        fn route(&mut self) -> Option<Arc<RouteEntry>> {
            unimplemented!("consumer B (body-based routing) is out of scope for increment 2b")
        }
        fn clear_route_cache(&mut self) {
            unimplemented!("consumer B (body-based routing) is out of scope for increment 2b")
        }
        fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
            self.per_route_config.clone()
        }
        fn stream_info(&mut self) -> RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    fn request_headers(content_type: Option<&str>, content_length: Option<u64>) -> RequestHeaders {
        let mut headers = HeaderMap::new();
        if let Some(ct) = content_type {
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_str(ct).unwrap(),
            );
        }
        if let Some(len) = content_length {
            headers.insert(
                CONTENT_LENGTH,
                HeaderValue::from_str(&len.to_string()).unwrap(),
            );
        }
        RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
            headers,
        }
    }

    fn filter_for(dialect: Dialect) -> BodyRewriteFilterInstance {
        BodyRewriteFilterInstance {
            config: BodyRewriteConfig {
                enabled: true,
                dialect,
            },
            state: State::PassThrough,
        }
    }

    /// `content-length` is CLIENT-supplied, so the fix-up arithmetic is done
    /// on untrusted input. A client sending a near-`u64::MAX` content-length
    /// must not be able to panic the worker (debug) or wrap the header
    /// (release) -- same defect class as `TokenUsage::total()`, but reachable
    /// from downstream rather than upstream, which makes it worse.
    ///
    /// The request is nonsense, of course; the point is that nonsense from a
    /// client is answered with a clamped header rather than a dead worker.
    #[test]
    fn an_absurd_client_content_length_saturates_instead_of_panicking() {
        let body = br#"{"model":"gpt-4o","stream":true,"messages":[]}"#;
        let headers = request_headers(Some("application/json"), Some(u64::MAX));
        let (out, cb) = run(Dialect::OpenAi, headers, &[body]);

        assert!(
            std::str::from_utf8(&out).unwrap().contains("include_usage"),
            "the body should still be spliced"
        );
        assert_eq!(
            cb.head
                .headers
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some(u64::MAX.to_string().as_str()),
            "content-length must clamp at u64::MAX, not wrap around to a small number"
        );
    }

    fn runtime_feature_flag(default_value: bool, runtime_key: &str) -> DynamicMessage {
        let bool_value_desc = proxy_api::descriptor_pool()
            .get_message_by_name("google.protobuf.BoolValue")
            .expect("BoolValue is a well-known type compiled into proxy-api");
        let mut bv = DynamicMessage::new(bool_value_desc);
        bv.set_field_by_name("value", prost_reflect::Value::Bool(default_value));

        let desc = proxy_api::descriptor_pool()
            .get_message_by_name("envoy.config.core.v3.RuntimeFeatureFlag")
            .expect("RuntimeFeatureFlag is compiled into proxy-api");
        let mut msg = DynamicMessage::new(desc);
        msg.set_field_by_name("default_value", prost_reflect::Value::Message(bv));
        msg.set_field_by_name(
            "runtime_key",
            prost_reflect::Value::String(runtime_key.to_string()),
        );
        msg
    }

    /// Drive `decode_headers` then `decode_data` (one chunk per entry of
    /// `chunks`) through a fresh filter instance, returning the assembled
    /// output bytes and the callbacks double for header inspection.
    fn run(
        dialect: Dialect,
        headers: RequestHeaders,
        chunks: &[&[u8]],
    ) -> (Vec<u8>, TestCallbacks) {
        let mut filter = filter_for(dialect);
        let mut cb = TestCallbacks::new(headers.clone());
        let mut headers = headers;
        filter.decode_headers(&mut cb, &mut headers, chunks.is_empty());

        let mut out = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let end_stream = i + 1 == chunks.len();
            let mut data = Bytes::copy_from_slice(chunk);
            let status = filter.decode_data(&mut cb, &mut data, end_stream);
            assert_eq!(status, FilterDataStatus::Continue);
            out.extend_from_slice(&data);
        }
        (out, cb)
    }

    // --- config parsing -------------------------------------------------------

    #[test]
    fn runtime_feature_flag_resolves_in_the_descriptor_pool() {
        // Pins the type-URL choice: if this message ever stopped resolving
        // (e.g. a vendored-proto pruning pass dropped it), every bootstrap
        // using this filter would fail at load time with an opaque
        // `UnknownTypeUrl`, not here where the reason is obvious.
        let resolved = proxy_api::descriptor_pool()
            .get_message_by_name("envoy.config.core.v3.RuntimeFeatureFlag");
        assert!(resolved.is_some(), "{TYPE_URL} must resolve");
    }

    #[test]
    fn config_parses_enabled_and_dialect() {
        let cfg = parse_config(&runtime_feature_flag(true, "openai")).expect("valid config");
        assert!(cfg.enabled);
        assert_eq!(cfg.dialect, Dialect::OpenAi);

        let cfg = parse_config(&runtime_feature_flag(false, "anthropic")).expect("valid config");
        assert!(!cfg.enabled);
        assert_eq!(cfg.dialect, Dialect::Anthropic);
    }

    #[test]
    fn config_rejects_unknown_dialect() {
        let err =
            parse_config(&runtime_feature_flag(true, "gemini")).expect_err("must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.runtime_key");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn config_rejects_missing_default_value() {
        let desc = proxy_api::descriptor_pool()
            .get_message_by_name("envoy.config.core.v3.RuntimeFeatureFlag")
            .unwrap();
        let mut msg = DynamicMessage::new(desc);
        msg.set_field_by_name("runtime_key", prost_reflect::Value::String("openai".into()));
        let err = parse_config(&msg).expect_err("missing default_value must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.default_value");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // --- acceptance 1: injection into a streaming OpenAI body ----------------

    #[test]
    fn streaming_openai_body_without_stream_options_gets_injected() {
        let body =
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let (out, cb) = run(Dialect::OpenAi, headers, &[body]);

        let parsed: serde_json::Value =
            serde_json::from_slice(&out).expect("output must still be valid JSON");
        assert_eq!(
            parsed["stream_options"]["include_usage"],
            serde_json::Value::Bool(true)
        );

        let expected_len = body.len() + r#""stream_options":{"include_usage":true},"#.len();
        let got_len: u64 = cb
            .head
            .headers
            .get(CONTENT_LENGTH)
            .expect("content-length must be present")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            got_len, expected_len as u64,
            "content-length must grow by exactly the injected length"
        );
        assert_eq!(out.len(), expected_len);
    }

    // --- acceptance 2: client already opted in --------------------------------

    #[test]
    fn client_supplied_stream_options_is_forwarded_byte_identical() {
        let body = br#"{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":false}}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let (out, cb) = run(Dialect::OpenAi, headers, &[body]);

        assert_eq!(out, body);
        let got_len: u64 = cb
            .head
            .headers
            .get(CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(got_len, body.len() as u64, "content-length must not change");
    }

    // --- acceptance 3: Anthropic dialect is untouched -------------------------

    #[test]
    fn anthropic_dialect_route_is_byte_identical_in_and_out() {
        let body = br#"{"model":"claude-3-5-sonnet","stream":true,"messages":[]}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let (out, cb) = run(Dialect::Anthropic, headers, &[body]);

        assert_eq!(out, body);
        let got_len: u64 = cb
            .head
            .headers
            .get(CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(got_len, body.len() as u64);
    }

    // --- stream: false / absent ------------------------------------------------

    #[test]
    fn stream_false_and_stream_absent_are_byte_identical() {
        for body in [
            br#"{"model":"gpt-4o","stream":false,"messages":[]}"#.as_slice(),
            br#"{"model":"gpt-4o","messages":[]}"#.as_slice(),
        ] {
            let headers = request_headers(Some("application/json"), Some(body.len() as u64));
            let (out, _cb) = run(Dialect::OpenAi, headers, &[body]);
            assert_eq!(out, body, "body: {body:?}");
        }
    }

    // --- acceptance 4: non-JSON and out-of-window bodies ----------------------

    #[test]
    fn non_json_body_reaches_upstream_untouched() {
        let body = b"not json at all";
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let (out, _cb) = run(Dialect::OpenAi, headers, &[body]);
        assert_eq!(out, body);
    }

    #[test]
    fn body_whose_keys_fall_outside_the_window_is_untouched() {
        let filler = "x".repeat(DEFAULT_PREFIX_CAP + 4096);
        let body = format!(
            r#"{{"messages":[{{"role":"user","content":"{filler}"}}],"model":"gpt-4o","stream":true}}"#
        );
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let (out, _cb) = run(Dialect::OpenAi, headers, &[body.as_bytes()]);
        assert_eq!(out, body.as_bytes());
    }

    #[test]
    fn non_openai_content_type_is_untouched() {
        let body = br#"{"model":"gpt-4o","stream":true}"#;
        let headers = request_headers(Some("text/plain"), Some(body.len() as u64));
        let (out, _cb) = run(Dialect::OpenAi, headers, &[body]);
        assert_eq!(out, body);
    }

    /// The route's per-route config wins over the listener-level dialect --
    /// a listener configured as OpenAI, with a route pinned to Anthropic,
    /// must not inject into that route's bodies.
    #[test]
    fn per_route_config_overrides_the_listener_dialect() {
        let body = br#"{"model":"claude-3-5-sonnet","stream":true,"messages":[]}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));

        let mut filter = filter_for(Dialect::OpenAi);
        let override_cfg = Arc::new(BodyRewritePerRouteConfig(BodyRewriteConfig {
            enabled: true,
            dialect: Dialect::Anthropic,
        }));
        let mut cb = TestCallbacks::new(headers.clone()).with_per_route_config(override_cfg);
        let mut req_headers = headers;
        filter.decode_headers(&mut cb, &mut req_headers, false);

        let mut data = Bytes::copy_from_slice(body);
        let status = filter.decode_data(&mut cb, &mut data, true);
        assert_eq!(status, FilterDataStatus::Continue);
        assert_eq!(
            &data[..],
            body,
            "per-route Anthropic override must suppress injection"
        );
    }

    #[test]
    fn disabled_filter_is_untouched() {
        let body = br#"{"model":"gpt-4o","stream":true}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let mut filter = BodyRewriteFilterInstance {
            config: BodyRewriteConfig {
                enabled: false,
                dialect: Dialect::OpenAi,
            },
            state: State::PassThrough,
        };
        let mut cb = TestCallbacks::new(headers.clone());
        let mut headers = headers;
        filter.decode_headers(&mut cb, &mut headers, false);
        let mut data = Bytes::copy_from_slice(body);
        let status = filter.decode_data(&mut cb, &mut data, true);
        assert_eq!(status, FilterDataStatus::Continue);
        assert_eq!(&data[..], body);
    }

    // --- chunked request: no content-length invented --------------------------

    #[test]
    fn chunked_request_is_injected_without_inventing_content_length() {
        let body = br#"{"model":"gpt-4o","messages":[],"stream":true}"#;
        let headers = request_headers(Some("application/json"), None);
        let (out, cb) = run(Dialect::OpenAi, headers, &[body]);

        let parsed: serde_json::Value =
            serde_json::from_slice(&out).expect("output must still be valid JSON");
        assert_eq!(
            parsed["stream_options"]["include_usage"],
            serde_json::Value::Bool(true)
        );
        assert!(
            cb.head.headers.get(CONTENT_LENGTH).is_none(),
            "a chunked request must not gain a content-length header"
        );
    }

    // --- chunk-boundary robustness ---------------------------------------------

    #[test]
    fn every_split_point_yields_identical_output_bytes() {
        let body: &[u8] =
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true,"temperature":0.7}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let (expected, _) = run(Dialect::OpenAi, headers.clone(), &[body]);

        for split in 1..body.len() {
            let (out, _cb) = run(
                Dialect::OpenAi,
                headers.clone(),
                &[&body[..split], &body[split..]],
            );
            assert_eq!(out, expected, "mismatch when split at offset {split}");
        }
    }

    // --- acceptance 4b: multimodal body, bounded memory -----------------------

    /// A body of several MB with `model`/`stream` leading, several MB of
    /// filler inside `messages`, and a marker planted well past the prefix
    /// cap. Asserts: (1) the output is injected correctly and everything
    /// after the splice point matches byte-for-byte; (2) at no point while
    /// still `Scanning` does the filter's own held buffer exceed
    /// `cap + one chunk` -- the structural proof (not RSS) that this filter
    /// does not buffer the body.
    #[test]
    fn large_multimodal_body_is_metered_without_buffering_the_body() {
        let chunk_size = 8192;
        let marker = "UNIQUE_MARKER_DEEP_IN_MESSAGES";
        let mut content = "A".repeat(DEFAULT_PREFIX_CAP * 4);
        content.push_str(marker);
        let blob_len = 3 * 1024 * 1024;
        content.push_str(&"B".repeat(blob_len - content.len()));

        let body = format!(
            r#"{{"model":"gpt-4o","stream":true,"messages":[{{"role":"user","content":"{content}"}}]}}"#
        );
        let body = body.into_bytes();

        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new(headers.clone());
        let mut req_headers = headers;
        filter.decode_headers(&mut cb, &mut req_headers, false);

        let mut out = Vec::new();
        let mut decided = false;
        for window in body.chunks(chunk_size) {
            let end_stream = false; // never reached in this test; cap forces an early decision.
            let mut data = Bytes::copy_from_slice(window);
            let status = filter.decode_data(&mut cb, &mut data, end_stream);
            assert_eq!(status, FilterDataStatus::Continue);

            match &filter.state {
                State::Scanning { pending, .. } => {
                    assert!(
                        pending.len() <= DEFAULT_PREFIX_CAP + chunk_size,
                        "held {} bytes while still scanning, cap+chunk is {}",
                        pending.len(),
                        DEFAULT_PREFIX_CAP + chunk_size
                    );
                    assert!(
                        !pending.windows(marker.len()).any(|w| w == marker.as_bytes()),
                        "the filter retained bytes deep inside `messages` -- it is buffering the body"
                    );
                }
                State::PassThrough => {
                    decided = true;
                }
            }
            out.extend_from_slice(&data);
        }
        assert!(
            decided,
            "the cap should force a decision well before the body ends"
        );

        let inject = r#""stream_options":{"include_usage":true},"#;
        let mut expected = Vec::with_capacity(body.len() + inject.len());
        expected.extend_from_slice(&body[..1]);
        expected.extend_from_slice(inject.as_bytes());
        expected.extend_from_slice(&body[1..]);
        assert_eq!(
            out, expected,
            "output must equal the original body with the injection spliced in right after `{{`"
        );
    }
}
