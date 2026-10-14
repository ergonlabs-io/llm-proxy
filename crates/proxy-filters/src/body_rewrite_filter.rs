//! Wires the [`crate::body_rewrite`]
//! scanner/splice engine into a real decode-path `HttpFilter`, for BOTH
//! consumers of the one scan (one scan, one held prefix, two consumers —
//! never a second scanner):
//!
//! - **Consumer A** — force `stream_options.include_usage = true` onto
//!   OpenAI-dialect streaming requests that didn't already opt in, so
//!   the usage filter has something to find. Gated on `cfg.enabled &&
//!   cfg.dialect == OpenAi`, exactly as before.
//! - **Consumer B** — publish the scanned `model` onto the
//!   [`MODEL_HEADER_NAME`] request header (overwriting any client-supplied
//!   value; removing it outright when no model was found — a security
//!   property, not a tidiness one; see "Header trust" below) and call
//!   `clear_route_cache()` so S2.8 re-resolves the route against it.
//!   Dialect-agnostic and unconditional: it runs for every dialect and
//!   regardless of `cfg.enabled` (model extraction has
//!   nothing to do with the usage-reporting kill switch).
//!
//! The `llmproxy` dialect / JSON schema surface that configures this filter
//! from `--config` lives in `proxy-simple-config`'s `lower.rs`.
//!
//! # State machine
//!
//! Per stream: `Scanning { .. } -> PassThrough`. `decode_headers` decides up
//! front whether this request even has a body worth scanning (has a body,
//! JSON content type) — dialect and `enabled` no longer gate entry, since
//! consumer B needs every dialect. A request with no scannable body still
//! gets its model header cleared right there (see
//! [`BodyRewriteFilterInstance::decode_headers`]) since absence there means
//! the same thing "Header trust" means everywhere else: no proven model, no
//! trusted header. Once in `PassThrough` (either from the start, or once a
//! decision has been made), every subsequent `decode_data` call is a
//! straight-through no-op: `Continue`, `data` untouched, no buffer touched.
//! See [`BodyRewriteFilterInstance::decode_data`] for the `Scanning` side.
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
//! back to `PassThrough`, discarding it. The bound is often loosely described as `O(cap)`; this doc is
//! the precise version, written down so nobody "fixes" the extra chunk of
//! slack later under a misunderstanding.
//!
//! This bound is the central requirement of the filter. A multimodal request
//! (several MB of inline base64 image data, with `model`/`stream` in their
//! normal leading position) must be spliced into correctly, forwarded
//! byte-identical after the splice point, and metered with real token counts,
//! while peak memory stays independent of body size. The acceptance test for
//! that case is what fails if someone "simplifies" the scanner back into a
//! full-body buffer, which is the most likely way this filter gets built
//! wrong.
//!
//! # Header trust
//!
//! [`MODEL_HEADER_NAME`] is derived from the body, never trusted from the
//! client. A client-supplied value is overwritten when the body has a model
//! and removed when it does not (including a non-JSON or bodyless request).
//! A body whose `model` falls past the prefix cap (`CapExceeded`) is treated
//! exactly like "no model found": absence is not proven, so the header is
//! cleared and routing falls through to the `*` backstop.
//!
//! # Never fails a request
//!
//! Non-JSON bodies, truncated JSON, and bodies whose interesting keys never
//! show up inside the window all fall out of [`crate::body_rewrite`] as
//! "no injection" facts, never an error — this filter forwards them
//! untouched, exactly per that module's "pass through, never fail" rule.
//!
//! # Config identity: owned `llmproxy.filters.v0.BodyRewrite`
//!
//! The filter owns its enable switch and dialect. The old
//! `RuntimeFeatureFlag` carrier remains accepted for one release through
//! [`LegacyBodyRewriteFilterFactory`], so existing bootstraps keep loading
//! while new configs use the versioned message.

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

/// Canonical type URL for the owned body-rewrite configuration.
pub const TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.BodyRewrite";

/// Borrowed type URL accepted for one release after the move to an owned, versioned message.
pub const LEGACY_TYPE_URL: &str = "type.llmproxy.dev/envoy.config.core.v3.RuntimeFeatureFlag";

/// The request header consumer B publishes the scanned `model` onto. Must
/// equal `proxy_simple_config::lower::MODEL_HEADER`, which the dialect's
/// route table matches against — duplicated as a literal rather than
/// imported, for the same cross-crate reason `lower.rs` gives for its own
/// `USAGE_FILTER_TYPE_URL`/`BODY_REWRITE_FILTER_TYPE_URL` (`proxy-filters`
/// cannot depend on `proxy-simple-config`: that would drag the whole data
/// plane into a crate that only ever emits JSON, and `proxy-simple-config`
/// already depends on `proxy-filters` as a dev-dependency to pin the type
/// URLs the other direction). This is
/// the exact shape that produced the `io.llmproxy.provider_auth` seam gap
/// found 2026-08-03: two crates agreeing on a string by convention, each
/// crate's tests pinning its own literal, nothing testing the join. The pin
/// here is `proxy-simple-config/tests/dialect.rs`'s
/// `body_based_model_routing_reaches_the_right_provider`, which drives a
/// real request through a dialect-lowered config and asserts on which
/// CLUSTER was reached — not on this string, since a string-equality
/// assertion is exactly the check that would have passed right through the
/// 2026-08-03 gap.
pub const MODEL_HEADER_NAME: &str = "x-llmproxy-model";

/// Write `model` onto [`MODEL_HEADER_NAME`], or remove the header outright
/// when `model` is `None` — the header is derived from the
/// body, never trusted from the client (see the module doc's "Header trust"), so "no proven model" must clear
/// whatever the client sent rather than leave it standing. A `model` value
/// that doesn't survive `HeaderValue::from_str` (e.g. it contains a raw
/// newline) is treated the same as "no model": removed, never a failed
/// request — the module's "never fails a request" rule applies here too.
pub(crate) fn apply_model_header(headers: &mut HeaderMap, model: Option<&str>) {
    let name = http::header::HeaderName::from_static(MODEL_HEADER_NAME);
    match model.and_then(|m| HeaderValue::from_str(m).ok()) {
        Some(value) => {
            headers.insert(name, value);
        }
        None => {
            headers.remove(name);
        }
    }
}

/// Parsed, validated config: whether this filter does anything at all, and
/// which dialect it should treat as OpenAI-shaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BodyRewriteConfig {
    /// `typed_config.default_value` — an operator kill switch
    /// (`observability.force_usage_reporting`, default `true` in the dialect
    /// surface).
    enabled: bool,
    dialect: Dialect,
    /// `typed_config.max_output_tokens`: the output-token cap this config
    /// asks the router to enforce. Independent of `enabled`, which only
    /// governs the usage-option splice.
    max_output_tokens: Option<u32>,
}

fn parse_dialect(raw: String, field_path: &str) -> Result<Dialect, ConfigError> {
    match raw.to_ascii_lowercase().as_str() {
        "openai" => Ok(Dialect::OpenAi),
        "anthropic" => Ok(Dialect::Anthropic),
        _ => Err(ConfigError::InvalidValue {
            field_path: field_path.to_string(),
            reason: format!("expected `openai` or `anthropic`, got `{raw}`"),
        }),
    }
}

/// Read an owned `BodyRewrite` typed config.
fn parse_owned_config(config: &DynamicMessage) -> Result<BodyRewriteConfig, ConfigError> {
    let invalid = |field_path: &str, reason: String| ConfigError::InvalidValue {
        field_path: field_path.to_string(),
        reason,
    };

    if !config.has_field_by_name("enabled") {
        return Err(invalid(
            "typed_config.enabled",
            "the `enabled` field is required".to_string(),
        ));
    }
    let enabled = config
        .get_field_by_name("enabled")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| {
            invalid(
                "typed_config.enabled",
                "the `enabled` field is invalid".into(),
            )
        })?;

    if !config.has_field_by_name("dialect") {
        return Err(invalid(
            "typed_config.dialect",
            "the `dialect` field is required".to_string(),
        ));
    }
    let dialect = config
        .get_field_by_name("dialect")
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| {
            invalid(
                "typed_config.dialect",
                "the `dialect` field is invalid".into(),
            )
        })?;
    let dialect = parse_dialect(dialect, "typed_config.dialect")?;

    // Rust note: `has_field_by_name` distinguishes "unset" from "set to the
    // proto3 default (0)" for `optional` fields, which is what lets an explicit
    // `0` be rejected instead of read as "no cap".
    let max_output_tokens = if config.has_field_by_name("max_output_tokens") {
        let value = config
            .get_field_by_name("max_output_tokens")
            .and_then(|v| v.as_u32())
            .filter(|n| *n > 0)
            .ok_or_else(|| {
                invalid(
                    "typed_config.max_output_tokens",
                    "must be a positive integer that fits in u32".into(),
                )
            })?;
        Some(value)
    } else {
        None
    };

    Ok(BodyRewriteConfig {
        enabled,
        dialect,
        max_output_tokens,
    })
}

/// Read the borrowed `RuntimeFeatureFlag` compatibility config.
fn parse_legacy_config(config: &DynamicMessage) -> Result<BodyRewriteConfig, ConfigError> {
    if !config.has_field_by_name("default_value") {
        return Err(ConfigError::InvalidValue {
            field_path: "typed_config.default_value".to_string(),
            reason: "the `default_value` field is required".to_string(),
        });
    }
    let enabled = config
        .get_field_by_name("default_value")
        .and_then(|v| v.as_message().cloned())
        .and_then(|m| m.get_field_by_name("value").and_then(|v| v.as_bool()))
        .ok_or_else(|| ConfigError::InvalidValue {
            field_path: "typed_config.default_value".to_string(),
            reason: "the `default_value` field is invalid".to_string(),
        })?;
    let runtime_key = config
        .get_field_by_name("runtime_key")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let dialect = parse_dialect(runtime_key, "typed_config.runtime_key")?;
    Ok(BodyRewriteConfig {
        enabled,
        dialect,
        max_output_tokens: None,
    })
}

fn warn_legacy_config() {
    tracing::warn!(
        legacy_type_url = LEGACY_TYPE_URL,
        replacement_type_url = TYPE_URL,
        "llmproxy.body_rewrite uses a deprecated borrowed typed_config; migrate to llmproxy.filters.v0.BodyRewrite before the next release"
    );
}

/// [`HttpFilterFactory`] for [`TYPE_URL`].
#[derive(Default)]
pub struct BodyRewriteFilterFactory;

impl HttpFilterFactory for BodyRewriteFilterFactory {
    fn type_url(&self) -> &'static str {
        TYPE_URL
    }

    fn may_buffer_response(&self) -> bool {
        false
    }

    fn create(
        &self,
        config: &DynamicMessage,
        _ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        let config = parse_owned_config(config)?;
        Ok(Box::new(BodyRewriteInstanceFactory { config }))
    }

    fn parse_per_route(
        &self,
        config: &DynamicMessage,
    ) -> Result<Arc<dyn PerRouteConfig>, ConfigError> {
        let config = parse_owned_config(config)?;
        Ok(Arc::new(BodyRewritePerRouteConfig(config)))
    }
}

/// Decoder for [`LEGACY_TYPE_URL`].
#[derive(Default)]
pub struct LegacyBodyRewriteFilterFactory;

impl HttpFilterFactory for LegacyBodyRewriteFilterFactory {
    fn type_url(&self) -> &'static str {
        LEGACY_TYPE_URL
    }

    fn may_buffer_response(&self) -> bool {
        false
    }

    fn create(
        &self,
        config: &DynamicMessage,
        _ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        warn_legacy_config();
        Ok(Box::new(BodyRewriteInstanceFactory {
            config: parse_legacy_config(config)?,
        }))
    }

    fn parse_per_route(
        &self,
        config: &DynamicMessage,
    ) -> Result<Arc<dyn PerRouteConfig>, ConfigError> {
        warn_legacy_config();
        Ok(Arc::new(BodyRewritePerRouteConfig(parse_legacy_config(
            config,
        )?)))
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
            takes_usage_option: false,
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
    /// Whether the request path takes `stream_options.include_usage`. The
    /// Responses and Messages APIs report usage on every stream unasked, and
    /// OpenAI's Responses API rejects the field outright, so those two are
    /// excluded. Every other path keeps the option, so an unrecognized path
    /// errs toward metering.
    takes_usage_option: bool,
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

impl BodyRewriteFilterInstance {
    /// Resolve this stream's effective config: the route's
    /// `typed_per_filter_config` override if one applies, else the
    /// listener-level config this instance was created with. Called from
    /// both `decode_headers` and `decode_data` (consumer A's splice
    /// decision is only made once body bytes are in, in `decode_data`) so
    /// the two must resolve it identically -- factored out rather than
    /// duplicated inline.
    fn resolve_config(&self, cb: &mut dyn DecoderCallbacks) -> BodyRewriteConfig {
        cb.per_route_config()
            .and_then(|c| {
                c.as_any()
                    .downcast_ref::<BodyRewritePerRouteConfig>()
                    .map(|c| c.0)
            })
            .unwrap_or(self.config)
    }

    /// Publish the effective output-token cap for the router to enforce
    /// (by refusal) against the whole buffered body. Every dialect and path, unlike the
    /// usage splice: a cap is a spend control, not a protocol feature. Must
    /// run after `clear_route_cache()` so `per_route_config` sees the route the
    /// model header selects.
    fn publish_max_output_tokens(&self, cb: &mut dyn DecoderCallbacks) {
        if let Some(cap) = self.resolve_config(cb).max_output_tokens {
            cb.stream_info().max_output_tokens = Some(cap);
        }
    }
}

impl HttpFilter for BodyRewriteFilterInstance {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        end_stream: bool,
    ) -> FilterHeadersStatus {
        // A bodyless request, or a non-JSON content type, has no `model` to
        // find -- the header-trust rule still applies: any client-supplied
        // `x-llmproxy-model` must be removed here, not left standing, since
        // there is no proof of what the real model is. Mutate `headers`
        // directly rather than through `modify_decoded_headers` -- that
        // callback is a no-op called from inside `decode_headers` itself
        // (see its doc); this parameter IS the live request head.
        let path = headers.uri.path();
        self.takes_usage_option = !(path.ends_with("/responses") || path.ends_with("/messages"));
        if end_stream || !is_json_content_type(&headers.headers) {
            apply_model_header(&mut headers.headers, None);
            cb.clear_route_cache();
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
            // Not scanning: a body not declared as JSON (the provider may still
            // parse it as JSON, so the cap still applies; the router decides from
            // the bytes). The manager refreshed its route snapshot from the head
            // `decode_headers` just edited, so the route resolved here is the one
            // the router will use.
            self.publish_max_output_tokens(cb);
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

        // Consumer A: OpenAI-only, and only when the operator hasn't turned
        // it off (`cfg.enabled`). Unlike the old gate, `cfg` is resolved
        // fresh here rather than in `decode_headers` -- scanning itself no
        // longer depends on it (consumer B needs every dialect), so only
        // the splice decision reads it.
        let cfg = self.resolve_config(cb);
        if cfg.enabled && cfg.dialect == Dialect::OpenAi && self.takes_usage_option {
            if facts.splice_at.is_some() {
                // The router reconciles the whole buffered body against this,
                // so a client opt-out or a key beyond the scan window cannot
                // switch metering off.
                cb.stream_info().force_include_usage = true;
            }
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
        }

        // Consumer B: unconditional -- publish the scanned
        // `model`, or remove any client-supplied value when none was found
        // (`CapExceeded` with no `model` seen yet means
        // absence is NOT proven, so this deliberately still clears the
        // header and lets routing fall through to the `*` backstop, rather
        // than trusting a client-supplied value). `clear_route_cache()`
        // (S2.8) always follows, so a route match against the OLD header
        // value is never reused.
        let model = facts.model.clone();
        // Publish the same extracted `model` onto
        // `StreamInfo::requested_model` for `model_authz_filter` to read --
        // reuses this scan rather than adding a second body buffer. Rust note: scoped so
        // the `RefMut` guard drops before `modify_decoded_headers` below --
        // `stream_info()` must not be held across another call on `cb` (see
        // its doc), same pattern `auth_filter`/`token_limit_filter` use.
        {
            cb.stream_info().requested_model = model.clone();
        }
        cb.modify_decoded_headers(&mut |headers: &mut RequestHeaders| {
            apply_model_header(&mut headers.headers, model.as_deref());
        });
        cb.clear_route_cache();
        // Resolved only now: the per-route override must come from the route
        // the model header just published selects, not the one matched before
        // the body was read.
        self.publish_max_output_tokens(cb);

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
    /// `per_route_config`, `clear_route_cache`, and `stream_info` are ever
    /// exercised by this filter; every other method panics loudly so a
    /// change that starts calling one of them (e.g. buffering via
    /// `add_decoded_data`, or resolving the route via `route()`, which this
    /// filter has no reason to call -- it clears the cache, it doesn't read
    /// it) fails a test instead of silently passing.
    struct TestCallbacks {
        /// The manager's canonical request head -- `decode_headers` gets a
        /// separate, ephemeral `&mut RequestHeaders` parameter (mirroring
        /// production, where `modify_decoded_headers` is a no-op from that
        /// callback); this is what `modify_decoded_headers` actually writes
        /// through, and what tests inspect afterward.
        head: RequestHeaders,
        per_route_config: Option<Arc<dyn PerRouteConfig>>,
        stream_info: RefCell<StreamInfo>,
        /// How many times `clear_route_cache()` was called -- consumer B
        /// calls it unconditionally once a decision is reached, so
        /// tests that want to pin that can inspect this instead of only
        /// inferring it from the header outcome.
        route_cache_cleared: std::cell::Cell<u32>,
    }

    impl TestCallbacks {
        fn new(head: RequestHeaders) -> Self {
            TestCallbacks {
                head,
                per_route_config: None,
                stream_info: RefCell::new(StreamInfo::default()),
                route_cache_cleared: std::cell::Cell::new(0),
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
            unimplemented!(
                "body_rewrite_filter clears the route cache, it never reads it via route()"
            )
        }
        fn clear_route_cache(&mut self) {
            self.route_cache_cleared
                .set(self.route_cache_cleared.get() + 1);
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
                max_output_tokens: None,
            },
            state: State::PassThrough,
            takes_usage_option: false,
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

    fn body_rewrite(enabled: bool, dialect: &str) -> DynamicMessage {
        let desc = proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.BodyRewrite")
            .expect("BodyRewrite is compiled into proxy-api");
        let mut msg = DynamicMessage::new(desc);
        msg.set_field_by_name("enabled", prost_reflect::Value::Bool(enabled));
        msg.set_field_by_name("dialect", prost_reflect::Value::String(dialect.to_string()));
        msg
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
    fn body_rewrite_resolves_in_the_descriptor_pool() {
        let resolved =
            proxy_api::descriptor_pool().get_message_by_name("llmproxy.filters.v0.BodyRewrite");
        assert!(resolved.is_some(), "{TYPE_URL} must resolve");
    }

    #[test]
    fn config_parses_enabled_and_dialect() {
        let cfg = parse_owned_config(&body_rewrite(true, "openai")).expect("valid config");
        assert!(cfg.enabled);
        assert_eq!(cfg.dialect, Dialect::OpenAi);

        let cfg = parse_owned_config(&body_rewrite(false, "anthropic")).expect("valid config");
        assert!(!cfg.enabled);
        assert_eq!(cfg.dialect, Dialect::Anthropic);
    }

    #[test]
    fn config_rejects_unknown_dialect() {
        let err = parse_owned_config(&body_rewrite(true, "gemini")).expect_err("must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.dialect");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn config_rejects_missing_enabled_with_exact_field_path() {
        let desc = proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.BodyRewrite")
            .unwrap();
        let mut msg = DynamicMessage::new(desc);
        msg.set_field_by_name("dialect", prost_reflect::Value::String("openai".into()));
        let err = parse_owned_config(&msg).expect_err("missing enabled must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.enabled");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn legacy_runtime_feature_flag_still_parses_through_compatibility_decoder() {
        let cfg = parse_legacy_config(&runtime_feature_flag(false, "anthropic"))
            .expect("legacy RuntimeFeatureFlag remains accepted for one release");
        assert!(!cfg.enabled);
        assert_eq!(cfg.dialect, Dialect::Anthropic);
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
            max_output_tokens: None,
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
                max_output_tokens: None,
            },
            state: State::PassThrough,
            takes_usage_option: false,
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

    // ======================================================================
    // Consumer B: body-based model routing
    // ======================================================================

    /// Like [`request_headers`], but with an extra client-supplied header --
    /// used to seed a spoofed `x-llmproxy-model` before driving a request,
    /// so tests can prove the filter overwrites/removes it rather than
    /// trusting it.
    fn request_headers_with(
        content_type: Option<&str>,
        content_length: Option<u64>,
        extra: &[(&str, &str)],
    ) -> RequestHeaders {
        let mut req = request_headers(content_type, content_length);
        for (k, v) in extra {
            req.headers.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        req
    }

    fn model_header(cb: &TestCallbacks) -> Option<&str> {
        cb.head
            .headers
            .get(MODEL_HEADER_NAME)
            .and_then(|v| v.to_str().ok())
    }

    /// A body naming `model` publishes it onto `x-llmproxy-model` -- the
    /// basic positive case, OpenAI dialect.
    #[test]
    fn body_model_publishes_the_routing_header() {
        let body = br#"{"model":"gpt-4o","messages":[],"stream":false}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let (_out, cb) = run(Dialect::OpenAi, headers, &[body]);
        assert_eq!(model_header(&cb), Some("gpt-4o"));
        assert_eq!(
            cb.route_cache_cleared.get(),
            1,
            "a decision was reached, so the route cache must be invalidated exactly once"
        );
    }

    /// The same scanned `model` is published onto
    /// `StreamInfo::requested_model`, not only the routing header --
    /// `model_authz_filter` reads the `StreamInfo` field, never the header.
    #[test]
    fn body_model_publishes_stream_info_requested_model() {
        let body = br#"{"model":"gpt-4o","messages":[],"stream":false}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let (_out, cb) = run(Dialect::OpenAi, headers, &[body]);
        assert_eq!(
            cb.stream_info.borrow().requested_model.as_deref(),
            Some("gpt-4o")
        );
    }

    /// The router overrides a client's usage opt-out only when this filter
    /// asked it to, so the flag must follow the OpenAI forcing gate: set for
    /// an OpenAI JSON body even when the client opted out, never for the
    /// Anthropic dialect.
    #[test]
    fn forcing_gate_is_published_for_the_router() {
        let body = br#"{"model":"m","stream":true,"stream_options":{"include_usage":false}}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let (_out, cb) = run(Dialect::OpenAi, headers.clone(), &[body]);
        assert!(cb.stream_info.borrow().force_include_usage);
        let (_out, cb) = run(Dialect::Anthropic, headers, &[body]);
        assert!(!cb.stream_info.borrow().force_include_usage);
    }

    /// The Responses API rejects `stream_options.include_usage` and reports
    /// usage unasked, so a streaming request to it is neither spliced nor
    /// forced.
    #[test]
    fn responses_path_gets_no_usage_option() {
        let body = br#"{"model":"m","stream":true}"#;
        let mut headers = request_headers(Some("application/json"), Some(body.len() as u64));
        headers.uri = Uri::from_static("/v1/responses");
        let (out, cb) = run(Dialect::OpenAi, headers, &[body]);
        assert_eq!(out, body.to_vec());
        assert!(!cb.stream_info.borrow().force_include_usage);
    }

    // --- output-token cap -----------------------------------------------------

    fn filter_with_cap(dialect: Dialect, cap: Option<u32>) -> BodyRewriteFilterInstance {
        let mut filter = filter_for(dialect);
        filter.config.max_output_tokens = cap;
        filter
    }

    /// Drive one JSON request through `filter` and return the callbacks double.
    fn drive(
        mut filter: BodyRewriteFilterInstance,
        mut cb: TestCallbacks,
        headers: RequestHeaders,
        body: &[u8],
    ) -> TestCallbacks {
        let mut req_headers = headers;
        filter.decode_headers(&mut cb, &mut req_headers, false);
        let mut data = Bytes::copy_from_slice(body);
        filter.decode_data(&mut cb, &mut data, true);
        cb
    }

    #[test]
    fn config_parses_max_output_tokens() {
        let cfg = parse_owned_config(&body_rewrite(true, "openai")).unwrap();
        assert_eq!(cfg.max_output_tokens, None);

        let mut msg = body_rewrite(true, "openai");
        msg.set_field_by_name("max_output_tokens", prost_reflect::Value::U32(4096));
        let cfg = parse_owned_config(&msg).unwrap();
        assert_eq!(cfg.max_output_tokens, Some(4096));
    }

    #[test]
    fn explicit_zero_max_output_tokens_is_a_config_error_with_its_path() {
        let mut msg = body_rewrite(true, "openai");
        msg.set_field_by_name("max_output_tokens", prost_reflect::Value::U32(0));
        let err = parse_owned_config(&msg).expect_err("zero cap must be rejected");
        assert!(
            err.to_string().contains("typed_config.max_output_tokens"),
            "got: {err}"
        );
    }

    #[test]
    fn listener_level_cap_is_published_for_both_dialects() {
        let body = br#"{"model":"m","stream":false}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        for dialect in [Dialect::OpenAi, Dialect::Anthropic] {
            let cb = drive(
                filter_with_cap(dialect, Some(512)),
                TestCallbacks::new(headers.clone()),
                headers.clone(),
                body,
            );
            assert_eq!(cb.stream_info.borrow().max_output_tokens, Some(512));
        }
    }

    #[test]
    fn no_cap_publishes_nothing() {
        let body = br#"{"model":"m","stream":false}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let cb = drive(
            filter_with_cap(Dialect::OpenAi, None),
            TestCallbacks::new(headers.clone()),
            headers,
            body,
        );
        assert_eq!(cb.stream_info.borrow().max_output_tokens, None);
    }

    /// The per-route override replaces the listener config wholesale, so a
    /// route's cap wins over the listener's, and a route override without a
    /// cap removes the listener's.
    #[test]
    fn per_route_cap_overrides_the_listener_cap() {
        let body = br#"{"model":"m","stream":false}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        for (route_cap, expected) in [(Some(64), Some(64)), (None, None)] {
            let override_cfg = Arc::new(BodyRewritePerRouteConfig(BodyRewriteConfig {
                enabled: true,
                dialect: Dialect::OpenAi,
                max_output_tokens: route_cap,
            }));
            let cb = drive(
                filter_with_cap(Dialect::OpenAi, Some(512)),
                TestCallbacks::new(headers.clone()).with_per_route_config(override_cfg),
                headers.clone(),
                body,
            );
            assert_eq!(cb.stream_info.borrow().max_output_tokens, expected);
        }
    }

    /// A body declared as something other than JSON is still published a cap
    /// (the provider may parse it as JSON anyway); the router decides from
    /// the bytes.
    #[test]
    fn cap_is_published_for_a_non_json_content_type() {
        let body = br#"{"model":"m"}"#;
        let headers = request_headers(Some("text/plain"), Some(body.len() as u64));
        let cb = drive(
            filter_with_cap(Dialect::OpenAi, Some(7)),
            TestCallbacks::new(headers.clone()),
            headers,
            body,
        );
        assert_eq!(cb.stream_info.borrow().max_output_tokens, Some(7));
    }

    /// A body with no extractable model must leave `StreamInfo::requested_model`
    /// at `None` -- the same "no proof, don't trust" rule the routing header
    /// already follows, now checked for the `model_authz_filter` seam too.
    #[test]
    fn body_with_no_model_leaves_stream_info_requested_model_none() {
        let body = br#"{"messages":[],"stream":false}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let (_out, cb) = run(Dialect::OpenAi, headers, &[body]);
        assert_eq!(cb.stream_info.borrow().requested_model, None);
    }

    /// The Anthropic dialect gets no `include_usage` splice, but model
    /// extraction is dialect-agnostic -- proves the old
    /// `cfg.dialect != OpenAi` short-circuit no longer suppresses scanning.
    #[test]
    fn anthropic_dialect_body_also_publishes_the_routing_header() {
        let body = br#"{"model":"claude-3-5-sonnet","messages":[],"stream":true}"#;
        let headers = request_headers(Some("application/json"), Some(body.len() as u64));
        let (out, cb) = run(Dialect::Anthropic, headers, &[body]);
        assert_eq!(model_header(&cb), Some("claude-3-5-sonnet"));
        // Still byte-identical -- consumer A never touches an Anthropic body.
        assert_eq!(out, body);
    }

    /// SECURITY: a client-supplied `x-llmproxy-model`
    /// must be OVERWRITTEN by the body's real value, never left standing or
    /// merely supplemented -- otherwise a client can steer its own request
    /// to a different provider by lying in the header while the body says
    /// something else.
    #[test]
    fn client_supplied_model_header_is_overwritten_by_the_body() {
        let body = br#"{"model":"gpt-4o","messages":[],"stream":false}"#;
        let headers = request_headers_with(
            Some("application/json"),
            Some(body.len() as u64),
            &[(MODEL_HEADER_NAME, "claude-3-5-sonnet")],
        );
        let (_out, cb) = run(Dialect::OpenAi, headers, &[body]);
        assert_eq!(
            model_header(&cb),
            Some("gpt-4o"),
            "the body's model must win over whatever the client claimed in the header"
        );
    }

    /// SECURITY: when the body has no extractable model,
    /// a client-supplied `x-llmproxy-model` must be REMOVED, not left
    /// standing -- absence must not be silently trusted as "use the header".
    #[test]
    fn client_supplied_model_header_is_removed_when_the_body_has_no_model() {
        let body = br#"{"messages":[],"stream":false}"#;
        let headers = request_headers_with(
            Some("application/json"),
            Some(body.len() as u64),
            &[(MODEL_HEADER_NAME, "claude-3-5-sonnet")],
        );
        let (_out, cb) = run(Dialect::OpenAi, headers, &[body]);
        assert!(
            cb.head.headers.get(MODEL_HEADER_NAME).is_none(),
            "a spoofed header must not survive a body with no model"
        );
    }

    /// SECURITY: same removal, but for the short-circuit path -- a
    /// non-JSON-content-type request never even enters `Scanning`, and must
    /// still clear a spoofed header rather than skip straight past it.
    #[test]
    fn client_supplied_model_header_is_removed_for_a_non_json_request() {
        let headers =
            request_headers_with(Some("text/plain"), None, &[(MODEL_HEADER_NAME, "claude")]);
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new(headers.clone());
        let mut req_headers = headers;
        filter.decode_headers(&mut cb, &mut req_headers, false);
        assert!(
            req_headers.headers.get(MODEL_HEADER_NAME).is_none(),
            "decode_headers mutates its own `headers` parameter directly for this path"
        );
        assert_eq!(cb.route_cache_cleared.get(), 1);
    }

    /// `ScanOutcome::CapExceeded` before `model` was ever
    /// seen means absence is NOT proven -- but the policy here is still to
    /// treat it exactly like "no model found": clear the header and let
    /// routing fall through to the `*` backstop deliberately, rather than
    /// trusting a client-supplied value just because we ran out of window.
    #[test]
    fn model_past_the_prefix_cap_yields_no_header() {
        let filler = "x".repeat(DEFAULT_PREFIX_CAP + 4096);
        let body = format!(
            r#"{{"messages":[{{"role":"user","content":"{filler}"}}],"model":"gpt-4o","stream":true}}"#
        );
        let headers = request_headers_with(
            Some("application/json"),
            Some(body.len() as u64),
            &[(MODEL_HEADER_NAME, "claude-3-5-sonnet")],
        );
        let (_out, cb) = run(Dialect::OpenAi, headers, &[body.as_bytes()]);
        assert!(
            cb.head.headers.get(MODEL_HEADER_NAME).is_none(),
            "a model past the cap must not be trusted from the client header either"
        );
    }

    /// A non-JSON body (JSON content type, but not actually JSON) reaches
    /// upstream untouched and does not fail the request -- same "never
    /// fails a request" rule the splice side already has, now checked for
    /// the routing side too.
    #[test]
    fn non_json_body_publishes_no_header_and_passes_through() {
        let body = b"not json at all";
        let headers = request_headers_with(
            Some("application/json"),
            Some(body.len() as u64),
            &[(MODEL_HEADER_NAME, "claude-3-5-sonnet")],
        );
        let (out, cb) = run(Dialect::OpenAi, headers, &[body]);
        assert_eq!(
            out, body,
            "an unparseable body must reach upstream untouched"
        );
        assert!(cb.head.headers.get(MODEL_HEADER_NAME).is_none());
    }
}
