//! WP-34 increment 2 — wires the [`crate::token_limit`] budget limiter into
//! the real HTTP path as an enforcing `HttpFilter`.
//!
//! # Retrospective enforcement (recap; see `token_limit`'s module doc)
//!
//! Token cost is unknown until a response completes, so this filter checks
//! on the **decode** path (before a request is sent upstream) and records on
//! the **encode** path, at response end. An over-limit key gets the *next*
//! request denied; a stream already in flight is NEVER truncated — there is
//! no code path here that touches response bytes at all.
//!
//! # Filter position: BEFORE `llmproxy.usage` in config order
//!
//! S2.1: encoder callbacks run in **reverse** config order. This filter's
//! encode-side job is to read the [`proxy_http::LlmTokenUsage`] the WP-33
//! usage filter (`crate::usage_filter`) wrote into `StreamInfo` at response
//! end — but that only exists if the usage filter's own encode callback has
//! *already run* by the time this filter's does. Reverse order means "already
//! run" = "later in config order". So this filter MUST be configured BEFORE
//! `llmproxy.usage` in `http_filters`. Get this backwards and nothing errors:
//! `StreamInfo::llm.usage` simply reads `None` forever (see
//! [`TokenLimitFilterInstance::record_if_present`]'s "absent usage" case),
//! silently recording zero cost for every request. There is no code assertion
//! for this — the module doc is the only guard.
//!
//! # Fail open on a store error
//!
//! [`crate::token_limit::BudgetStore::check`] can return
//! `Err(BudgetUnavailable)` (never from [`crate::token_limit::InProcessBudgetStore`]
//! today, but the trait is shaped for a future remote store — see its module
//! doc). This filter treats `Err` the same as `Allow`: the request proceeds.
//! A limiter that hard-denies (or 500s) every request the instant its budget
//! backend blips is a worse failure mode than briefly over-admitting a few
//! requests — this is Envoy's own `failure_mode_deny: false` default for its
//! rate-limit filter. The store call is isolated to exactly one function,
//! [`TokenLimitFilterInstance::check_budget`], so a future async/remote store
//! (which will need to hold the stream with `StopIteration` and resume via
//! `continue_decoding()`, per `token_limit`'s "Making this distributed"
//! section) only has one call site to change.
//!
//! # Config: a thin slice, `envoy.config.core.v3.RateLimitSettings`
//!
//! `envoy.type.v3.TokenBucket` (`max_tokens` + `fill_interval`) would have
//! been the obvious proto to reuse here, and was tried first — but it is
//! vendored without ever being compiled into `proxy-api`'s descriptor pool
//! (`proxy-api/build.rs`'s `roots` only pull in what bootstrap/HCM/router/
//! tcp_proxy/tls/access-log config transitively imports, and none of those
//! reach `envoy/type/v3/token_bucket.proto`); see
//! `tests::rate_limit_settings_resolves_in_the_descriptor_pool` for the check
//! that would have caught reusing an unresolvable message. `DataSource`,
//! `RuntimeFeatureFlag`, and `HeaderValueOption` were already taken by other
//! filters under `type.llmproxy.dev/` (`FilterRegistry::register` asserts on
//! a duplicate `type_url`), so the fallback is `envoy.config.core.v3.RateLimitSettings`
//! (from `config_source.proto`, reachable via the ADS/xDS roots) — itself a
//! genuine token-bucket-shaped rate-limit config, just for a different
//! Envoy feature (adaptive concurrency of xDS discovery requests) than the
//! one this filter implements: `max_tokens` (`google.protobuf.UInt32Value`,
//! required here) maps onto [`crate::token_limit::LimitRule::max_tokens`]
//! directly, and `fill_rate` (`google.protobuf.DoubleValue`, tokens per
//! second, required here) is converted into
//! [`crate::token_limit::LimitRule::window`] as `max_tokens / fill_rate`
//! seconds — "how long, at the configured refill rate, it takes to earn back
//! the whole bucket" is exactly this limiter's fixed-window length. This is
//! a genuine unit conversion, not a coincidence of field names, and it is
//! the one place in this filter where the config-reuse convention other
//! filters established (matching *shape*, not necessarily *meaning*) is worth
//! calling out explicitly as slightly stretched.
//!
//! This increment does not expose per-descriptor configurability:
//! [`crate::token_limit::LimitOn::Total`] is hardcoded, and the bucket key is
//! fixed as **(route name, the `authorization` header's value)** — no
//! configured list of descriptors, no per-route override. This is a
//! deliberate thin slice, not an oversight; the dialect `limits` config
//! surface (increment 3) and any richer per-descriptor budget config want a
//! vendored Lane-H proto, exactly like `body_rewrite_filter`'s and
//! `usage_filter`'s module docs already predict for their own next config
//! knob.
//!
//! # The credential never reaches the key in cleartext
//!
//! The `authorization` header's value identifies a caller, so it must never
//! land somewhere it could reach a log — this repo already takes credential
//! care seriously elsewhere (the access-log request-header snapshot is taken
//! before route-injected auth is applied, in `filter_manager::drive_decode`).
//! [`hash_credential`] hashes it before it ever touches a [`LimitKey`]; see
//! that function's doc for why a plain (non-cryptographic) hash is
//! sufficient here.

use std::sync::Arc;
use std::time::{Duration, Instant};

use http::header::AUTHORIZATION;
use http::StatusCode;
use prost_reflect::DynamicMessage;

use proxy_config::ConfigError;
use proxy_http::filter::{
    DecoderCallbacks, EncoderCallbacks, FactoryContext, FilterDataStatus, FilterHeadersStatus,
    FilterInstanceFactory, FilterTrailersStatus, HttpFilter, HttpFilterFactory, RequestHeaders,
    ResponseHeaders, ResponseTrailers,
};
use proxy_http::LlmTokenUsage;

use crate::token_limit::{
    BudgetStore, BudgetUnavailable, InProcessBudgetStore, LimitDecision, LimitKey, LimitOn,
    LimitRule,
};
use crate::usage::TokenUsage;

/// Type URL this filter is registered under (see the module doc for why
/// `RateLimitSettings`, not `TokenBucket`).
pub const TYPE_URL: &str = "type.llmproxy.dev/envoy.config.core.v3.RateLimitSettings";

/// Read `max_tokens`/`fill_rate` out of a `RateLimitSettings`-shaped
/// `typed_config` and convert them into a [`LimitRule`] (see the module
/// doc's "Config" section for the `fill_rate` -> `window` conversion). Both
/// fields are required here even though neither is `required` on the proto
/// itself (Envoy defaults them for its own discovery-throttling use; this
/// filter has no analogous default to fall back to). `on` is always
/// [`LimitOn::Total`] in this increment.
fn parse_config(config: &DynamicMessage) -> Result<LimitRule, ConfigError> {
    let invalid = |field_path: &str, reason: String| ConfigError::InvalidValue {
        field_path: field_path.to_string(),
        reason,
    };

    if !config.has_field_by_name("max_tokens") {
        return Err(invalid(
            "typed_config.max_tokens",
            "the `max_tokens` field is required".to_string(),
        ));
    }
    let max_tokens = config
        .get_field_by_name("max_tokens")
        .and_then(|v| v.as_message().cloned())
        .and_then(|m| m.get_field_by_name("value").and_then(|v| v.as_u32()))
        .unwrap_or(0);
    if max_tokens == 0 {
        return Err(invalid(
            "typed_config.max_tokens.value",
            "must be greater than 0".to_string(),
        ));
    }

    if !config.has_field_by_name("fill_rate") {
        return Err(invalid(
            "typed_config.fill_rate",
            "the `fill_rate` field is required".to_string(),
        ));
    }
    let fill_rate = config
        .get_field_by_name("fill_rate")
        .and_then(|v| v.as_message().cloned())
        .and_then(|m| m.get_field_by_name("value").and_then(|v| v.as_f64()));
    let Some(fill_rate) = fill_rate else {
        return Err(invalid(
            "typed_config.fill_rate.value",
            "must be a valid double".to_string(),
        ));
    };
    if !(fill_rate.is_finite() && fill_rate > 0.0) {
        return Err(invalid(
            "typed_config.fill_rate.value",
            format!("must be a finite number greater than 0, got `{fill_rate}`"),
        ));
    }

    // "How long, at this refill rate, it takes to earn back the whole
    // bucket" -- see the module doc. `f64 as u64` saturates rather than
    // panicking/wrapping (same convention as `token_limit::record`'s own
    // weighted-token arithmetic), so a pathological `fill_rate` clamps to a
    // very long window instead of misbehaving.
    let window_secs = (max_tokens as f64 / fill_rate).round();
    let window = if window_secs.is_sign_negative() {
        Duration::ZERO
    } else {
        Duration::from_secs(window_secs as u64)
    };
    if window.is_zero() {
        return Err(invalid(
            "typed_config.fill_rate.value",
            "implies a fill window of zero seconds (max_tokens / fill_rate rounds to 0); \
             lower `fill_rate` or raise `max_tokens`"
                .to_string(),
        ));
    }

    Ok(LimitRule {
        on: LimitOn::Total,
        max_tokens: max_tokens as u64,
        window,
    })
}

/// [`HttpFilterFactory`] for [`TYPE_URL`]. No `parse_per_route` override —
/// this increment has no per-route config (see the module doc's thin-slice
/// note); the trait default (`ConfigError::Unimplemented`) is correct.
#[derive(Default)]
pub struct TokenLimitFilterFactory;

impl HttpFilterFactory for TokenLimitFilterFactory {
    fn type_url(&self) -> &'static str {
        TYPE_URL
    }

    fn create(
        &self,
        config: &DynamicMessage,
        _ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        let rule = parse_config(config)?;
        // One store per (filter config, listener) -- exactly the lifetime
        // the budget needs: it must outlive any single stream (that's the
        // whole point of a *budget*), but a fresh listener config gets a
        // fresh one. Every per-stream filter instance below shares this same
        // `Arc`, which is what makes the limit apply across requests/workers
        // rather than per-stream (see `InProcessBudgetStore`'s doc for why
        // that requires `Send + Sync` + `Mutex`, not worker-local state).
        let store: Arc<dyn BudgetStore> = Arc::new(InProcessBudgetStore::new(rule));
        Ok(Box::new(TokenLimitInstanceFactory { store }))
    }
}

struct TokenLimitInstanceFactory {
    store: Arc<dyn BudgetStore>,
}

impl FilterInstanceFactory for TokenLimitInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(TokenLimitFilterInstance {
            store: Arc::clone(&self.store),
            key: None,
            recorded: false,
        })
    }
}

/// A stable, non-cryptographic hash of the `authorization` header's value,
/// rendered as hex.
///
/// This is not a security control against an attacker who already has the
/// header value — that isn't the threat model, and the value becomes neither
/// more nor less usable for auth by being hashed. It exists so the credential
/// never appears in cleartext anywhere a [`LimitKey`] could end up: a debug
/// log, a metrics label, a future `%DYNAMIC_METADATA%`-style access-log field.
///
/// # Why FNV-1a rather than `std`'s `DefaultHasher`
///
/// `DefaultHasher` would be the obvious zero-dependency choice, and it is what
/// this function used first. It is wrong here for one reason: `std` explicitly
/// does **not** guarantee its algorithm is stable across Rust releases. That is
/// harmless while every key is computed and compared inside one process — but
/// this store sits behind [`BudgetStore`](crate::token_limit::BudgetStore),
/// whose entire purpose is to let a distributed (Redis/RLS) backend land later.
/// The moment a budget is shared, two proxies built against different
/// toolchains would hash the same credential to different keys and each be
/// handed a full budget — a quota silently multiplied by the fleet size, which
/// is the exact failure the shared store was chosen to avoid in the first
/// place.
///
/// FNV-1a 64 is a frozen, published specification: same input, same output,
/// forever, on any machine and any compiler. It costs about eight lines and no
/// new crate — relevant because this workspace's dependency tree is already
/// slated for review. Collision resistance is irrelevant here; stability is the
/// requirement, and it is the one `DefaultHasher` does not offer.
fn hash_credential(value: &str) -> String {
    // FNV-1a, 64-bit. Rust note: `wrapping_mul` is the defined behavior of the
    // algorithm (it is specified modulo 2^64), not a guard against a bug --
    // a plain `*` would panic on overflow in debug builds on the first byte.
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

/// Per-stream instance. Plain fields, no `Rc`/`RefCell` (this never leaves
/// the worker thread that owns the stream) -- only `store` is the
/// cross-thread-shared piece, and it's an `Arc` clone, not shared interior
/// state of this struct itself.
struct TokenLimitFilterInstance {
    store: Arc<dyn BudgetStore>,
    /// Set in `decode_headers`, from the route + hashed credential. `None`
    /// only if `decode_headers` never ran (can't happen in practice for an
    /// HTTP filter, but this makes `record_if_present` total rather than
    /// assuming).
    key: Option<LimitKey>,
    /// Guards against double-recording from more than one encode callback
    /// observing `end_stream` (mirrors `usage_filter::UsageFilterInstance`'s
    /// `finalized` flag).
    recorded: bool,
}

impl TokenLimitFilterInstance {
    /// The single call site for [`BudgetStore::check`] -- see the module
    /// doc's "Fail open on a store error" section for why this isolation
    /// matters for the eventual remote-store swap.
    fn check_budget(&self, key: &LimitKey) -> Result<LimitDecision, BudgetUnavailable> {
        self.store.check(key, Instant::now())
    }

    /// Read `StreamInfo::llm.usage` and, if present, record it against
    /// `self.key`. Never fails the request: a missing key (shouldn't
    /// happen), a missing usage (no usage was ever reported for this
    /// stream), and a successful record are all handled without
    /// propagating anything back to the caller.
    fn record_if_present(&mut self, cb: &mut dyn EncoderCallbacks) {
        if self.recorded {
            return;
        }
        self.recorded = true;

        let Some(key) = &self.key else {
            return;
        };

        // Rust note: read the field out of the `RefMut` guard and drop it
        // before calling `self.store.record` below -- `stream_info()` must
        // not be held across another call (see its doc), and `record` isn't
        // a call on `cb` but the borrow checker doesn't know that; scoping it
        // like this keeps the rule visibly satisfied either way.
        let usage: Option<LlmTokenUsage> = cb.stream_info().llm.usage;

        // `None` must stay unrecorded -- inventing a zero-cost record would
        // be wrong (nothing happened) and a nonzero guess would be worse
        // (this feeds a real budget). See `token_limit`'s central semantic.
        let Some(usage) = usage else {
            return;
        };

        let usage = TokenUsage {
            input_tokens: usage.input_tokens,
            cached_tokens: usage.cached_tokens,
            cache_creation_tokens: usage.cache_creation_tokens,
            output_tokens: usage.output_tokens,
        };
        // Thin slice: weight is always 1.0 -- see the module doc. `record`
        // is infallible from here regardless of backend (best-effort for a
        // remote store; see `token_limit`'s module doc), so there is nothing
        // to check on the return value.
        self.store.record(key, &usage, 1.0, Instant::now());
    }
}

impl HttpFilter for TokenLimitFilterInstance {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        let route_name = cb
            .route()
            .and_then(|route| route.name.clone())
            .unwrap_or_default();
        let credential = headers
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let credential_hash = hash_credential(credential);

        let key = LimitKey::from_descriptors(&[
            ("route", route_name.as_str()),
            ("cred", credential_hash.as_str()),
        ]);

        match self.check_budget(&key) {
            // Fail open: a store error is treated exactly like `Allow` (see
            // the module doc).
            Ok(LimitDecision::Allow { .. }) | Err(BudgetUnavailable) => {}
            Ok(LimitDecision::Deny {
                limit,
                remaining,
                reset_after,
                retry_after,
            }) => {
                self.key = Some(key);
                let reset_secs = reset_after.as_secs();
                let retry_secs = retry_after.as_secs();
                cb.send_local_reply(
                    StatusCode::TOO_MANY_REQUESTS,
                    "token budget exceeded",
                    Some(Box::new(move |headers: &mut http::HeaderMap| {
                        // Rust note: `HeaderValue::from` on formatted decimal
                        // strings never fails (ASCII digits are always a
                        // valid header value), so these unwraps are total.
                        headers.insert(
                            "x-ratelimit-limit",
                            http::HeaderValue::from_str(&limit.to_string()).unwrap(),
                        );
                        headers.insert(
                            "x-ratelimit-remaining",
                            http::HeaderValue::from_str(&remaining.to_string()).unwrap(),
                        );
                        headers.insert(
                            "x-ratelimit-reset",
                            http::HeaderValue::from_str(&reset_secs.to_string()).unwrap(),
                        );
                        headers.insert(
                            "retry-after",
                            http::HeaderValue::from_str(&retry_secs.to_string()).unwrap(),
                        );
                    })),
                    "token_limit_exceeded",
                );
                // Rust note: the returned status is irrelevant here --
                // `drive_decode` checks `ctx.local_reply.is_some()` right
                // after this callback returns and stops the chain
                // unconditionally when it's set, regardless of what status
                // this function returns (see `filter_manager.rs`). `Continue`
                // is returned only because the trait requires *a* value.
                return FilterHeadersStatus::Continue;
            }
        }

        self.key = Some(key);
        FilterHeadersStatus::Continue
    }

    fn encode_headers(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        _headers: &mut ResponseHeaders,
        end_stream: bool,
    ) -> FilterHeadersStatus {
        if end_stream {
            self.record_if_present(cb);
        }
        FilterHeadersStatus::Continue
    }

    fn encode_data(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        _data: &mut bytes::Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        if end_stream {
            self.record_if_present(cb);
        }
        // Never buffers, never inspects response bytes -- see the module
        // doc's "never truncates" guarantee.
        FilterDataStatus::Continue
    }

    fn encode_trailers(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        _trailers: &mut ResponseTrailers,
    ) -> FilterTrailersStatus {
        // A response can end via trailers instead of an end_stream data
        // frame; `record_if_present`'s `recorded` guard makes this safe to
        // call unconditionally alongside the two call sites above.
        self.record_if_present(cb);
        FilterTrailersStatus::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{RefCell, RefMut};

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Method, Uri};
    use proxy_config::ir::RouteEntry;
    use proxy_http::filter::{BufferedBody, HeaderMutationFn, PerRouteConfig};
    use proxy_http::stream_info::StreamInfo;

    use crate::token_limit::LimitOn as TlLimitOn;

    // --- config parsing -------------------------------------------------------

    fn wrapped_u32(value: u32) -> prost_reflect::Value {
        let desc = proxy_api::descriptor_pool()
            .get_message_by_name("google.protobuf.UInt32Value")
            .expect("UInt32Value is a well-known type compiled into proxy-api");
        let mut m = DynamicMessage::new(desc);
        m.set_field_by_name("value", prost_reflect::Value::U32(value));
        prost_reflect::Value::Message(m)
    }

    fn wrapped_f64(value: f64) -> prost_reflect::Value {
        let desc = proxy_api::descriptor_pool()
            .get_message_by_name("google.protobuf.DoubleValue")
            .expect("DoubleValue is a well-known type compiled into proxy-api");
        let mut m = DynamicMessage::new(desc);
        m.set_field_by_name("value", prost_reflect::Value::F64(value));
        prost_reflect::Value::Message(m)
    }

    fn rate_limit_settings_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("envoy.config.core.v3.RateLimitSettings")
            .expect("RateLimitSettings is compiled into proxy-api")
    }

    fn rate_limit_settings(max_tokens: u32, fill_rate: f64) -> DynamicMessage {
        let mut msg = DynamicMessage::new(rate_limit_settings_desc());
        msg.set_field_by_name("max_tokens", wrapped_u32(max_tokens));
        msg.set_field_by_name("fill_rate", wrapped_f64(fill_rate));
        msg
    }

    #[test]
    fn rate_limit_settings_resolves_in_the_descriptor_pool() {
        // Pins the type-URL choice: see `body_rewrite_filter`'s equivalent
        // test for why this matters (an unresolvable message fails every
        // bootstrap using this filter with an opaque `UnknownTypeUrl`, not
        // here where the reason is obvious). Also see the module doc: this
        // is the message the *first-choice* `envoy.type.v3.TokenBucket`
        // failed this exact check for.
        let resolved = proxy_api::descriptor_pool()
            .get_message_by_name("envoy.config.core.v3.RateLimitSettings");
        assert!(resolved.is_some(), "{TYPE_URL} must resolve");
    }

    #[test]
    fn config_parses_max_tokens_and_derives_window_from_fill_rate() {
        // max_tokens=60, fill_rate=1.0 token/sec -> a 60s window.
        let rule = parse_config(&rate_limit_settings(60, 1.0)).expect("valid config");
        assert_eq!(rule.on, TlLimitOn::Total);
        assert_eq!(rule.max_tokens, 60);
        assert_eq!(rule.window, Duration::from_secs(60));
    }

    #[test]
    fn config_rejects_missing_max_tokens() {
        let mut msg = DynamicMessage::new(rate_limit_settings_desc());
        msg.set_field_by_name("fill_rate", wrapped_f64(1.0));

        let err = parse_config(&msg).expect_err("missing max_tokens must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.max_tokens");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn config_rejects_missing_fill_rate() {
        let mut msg = DynamicMessage::new(rate_limit_settings_desc());
        msg.set_field_by_name("max_tokens", wrapped_u32(10));

        let err = parse_config(&msg).expect_err("missing fill_rate must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.fill_rate");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn config_rejects_zero_max_tokens() {
        let err = parse_config(&rate_limit_settings(0, 1.0))
            .expect_err("zero max_tokens must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.max_tokens.value");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn config_rejects_non_positive_fill_rate() {
        for bad in [0.0, -1.0, f64::NAN, f64::NEG_INFINITY] {
            let err = parse_config(&rate_limit_settings(10, bad))
                .expect_err(&format!("fill_rate {bad} must be rejected"));
            match err {
                ConfigError::InvalidValue { field_path, .. } => {
                    assert_eq!(field_path, "typed_config.fill_rate.value");
                }
                other => panic!("expected InvalidValue for fill_rate {bad}, got {other:?}"),
            }
        }
    }

    // --- test scaffolding ---------------------------------------------------

    /// A route table entry good enough to give `cb.route()` a name to
    /// return; `route_index` and the matcher/action are never consulted by
    /// this filter, so they're the cheapest legal values.
    fn route_named(name: &str) -> Arc<RouteEntry> {
        Arc::new(RouteEntry {
            name: Some(name.to_string()),
            matcher: proxy_config::ir::RouteMatcher {
                path: proxy_config::ir::PathMatch::Prefix("/".to_string()),
                case_sensitive: true,
                headers: vec![],
            },
            action: proxy_config::ir::RouteActionIR::DirectResponse {
                status: 200,
                body: None,
            },
            request_headers_to_add: vec![],
            typed_per_filter_config: Default::default(),
            route_index: 0,
        })
    }

    /// A `DecoderCallbacks` + `EncoderCallbacks` double sharing one
    /// `StreamInfo`, mirroring `usage_filter`/`body_rewrite_filter`'s test
    /// doubles. Every method this filter doesn't use panics loudly.
    struct TestCallbacks {
        route: Option<Arc<RouteEntry>>,
        stream_info: RefCell<StreamInfo>,
        local_reply: Option<(StatusCode, HeaderMap)>,
    }

    impl TestCallbacks {
        fn new(route: Option<Arc<RouteEntry>>) -> Self {
            TestCallbacks {
                route,
                stream_info: RefCell::new(StreamInfo::default()),
                local_reply: None,
            }
        }

        fn set_usage(&self, usage: LlmTokenUsage) {
            self.stream_info.borrow_mut().llm.usage = Some(usage);
        }
    }

    impl DecoderCallbacks for TestCallbacks {
        fn send_local_reply(
            &mut self,
            code: StatusCode,
            _body: &str,
            modify_headers: Option<HeaderMutationFn>,
            _details: &str,
        ) {
            let mut headers = HeaderMap::new();
            if let Some(f) = modify_headers {
                f(&mut headers);
            }
            self.local_reply = Some((code, headers));
        }
        fn continue_decoding(&mut self) {
            unimplemented!("token_limit_filter never stops iteration")
        }
        fn add_decoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!("token_limit_filter never buffers request data")
        }
        fn inject_decoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!("token_limit_filter never injects data")
        }
        fn decoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!("token_limit_filter never consults the decoding buffer")
        }
        fn modify_decoding_buffer(&mut self, _f: &mut dyn FnMut(&mut bytes::BytesMut)) {
            unimplemented!("token_limit_filter never touches request bytes")
        }
        fn modify_decoded_headers(&mut self, _f: &mut dyn FnMut(&mut RequestHeaders)) -> bool {
            unimplemented!("token_limit_filter never rewrites request headers")
        }
        fn route(&mut self) -> Option<Arc<RouteEntry>> {
            self.route.clone()
        }
        fn clear_route_cache(&mut self) {
            unimplemented!("token_limit_filter never rewrites routing headers")
        }
        fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
            None
        }
        fn stream_info(&mut self) -> RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    impl EncoderCallbacks for TestCallbacks {
        fn continue_encoding(&mut self) {
            unimplemented!("token_limit_filter never stops iteration")
        }
        fn add_encoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!("token_limit_filter never buffers response data")
        }
        fn inject_encoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!("token_limit_filter never injects data")
        }
        fn encoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!("token_limit_filter never consults the encoding buffer")
        }
        fn modify_encoding_buffer(&mut self, _f: &mut dyn FnMut(&mut bytes::BytesMut)) {
            unimplemented!("token_limit_filter never touches response bytes")
        }
        fn stream_info(&mut self) -> RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    fn request_headers(authorization: Option<&str>) -> RequestHeaders {
        let mut headers = HeaderMap::new();
        if let Some(a) = authorization {
            headers.insert(AUTHORIZATION, HeaderValue::from_str(a).unwrap());
        }
        RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
            headers,
        }
    }

    fn response_headers() -> ResponseHeaders {
        ResponseHeaders {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        }
    }

    fn usage(total: u64) -> LlmTokenUsage {
        LlmTokenUsage {
            input_tokens: total,
            ..Default::default()
        }
    }

    fn store_with(max_tokens: u64, window: Duration) -> Arc<dyn BudgetStore> {
        Arc::new(InProcessBudgetStore::new(LimitRule {
            on: LimitOn::Total,
            max_tokens,
            window,
        }))
    }

    fn filter_with(store: Arc<dyn BudgetStore>) -> TokenLimitFilterInstance {
        TokenLimitFilterInstance {
            store,
            key: None,
            recorded: false,
        }
    }

    /// Drive one full request/response cycle: a FRESH `TokenLimitFilterInstance`
    /// (production creates one per stream, via `FilterInstanceFactory::create_filter`
    /// -- see `TokenLimitInstanceFactory`; reusing one instance across
    /// requests here would leak the `recorded` guard across streams and mask
    /// bugs no production traffic pattern could hit), sharing `store`, runs
    /// `decode_headers` then (if not denied) `encode_headers` +
    /// `encode_data(end_stream: true)` with `usage` written into
    /// `StreamInfo` beforehand exactly like the real usage filter would
    /// have. Returns whatever `send_local_reply` recorded, if any.
    fn run_request(
        store: &Arc<dyn BudgetStore>,
        route: &str,
        credential: Option<&str>,
        usage: Option<LlmTokenUsage>,
    ) -> Option<(StatusCode, HeaderMap)> {
        let mut filter = filter_with(Arc::clone(store));
        let mut cb = TestCallbacks::new(Some(route_named(route)));
        let mut head = request_headers(credential);
        filter.decode_headers(&mut cb, &mut head, true);

        if cb.local_reply.is_none() {
            if let Some(usage) = usage {
                cb.set_usage(usage);
            }
            let mut headers = response_headers();
            filter.encode_headers(&mut cb, &mut headers, false);
            let mut data = Bytes::new();
            filter.encode_data(&mut cb, &mut data, true);
        }

        cb.local_reply
    }

    // --- exact onset ------------------------------------------------------

    /// A scripted sequence of ten-token responses against a 25-token budget,
    /// driven through the real `HttpFilter` callbacks (not `BudgetStore`
    /// directly): admits requests 1-3, denies exactly request 4.
    #[test]
    fn exact_429_onset_across_a_scripted_sequence_of_requests() {
        let store = store_with(25, Duration::from_secs(60));

        for i in 1..=3 {
            let reply = run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(10)));
            assert!(
                reply.is_none(),
                "request {i} must be admitted, got a local reply"
            );
        }

        let reply = run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(10)));
        assert!(
            reply.is_some(),
            "request 4 is the exact index at which a 429 must first appear"
        );
    }

    // --- 429 headers --------------------------------------------------------

    #[test]
    fn a_429_carries_all_four_rate_limit_headers() {
        let store = store_with(10, Duration::from_secs(60));

        // Exhaust the budget.
        run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(10)));
        let (status, headers) = run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(0)))
            .expect("second request must be denied");

        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        for name in [
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
            "retry-after",
        ] {
            assert!(
                headers.get(name).is_some(),
                "expected header `{name}` on a 429, got: {headers:?}"
            );
        }
        assert_eq!(headers.get("x-ratelimit-limit").unwrap(), "10");
        assert_eq!(headers.get("x-ratelimit-remaining").unwrap(), "0");
    }

    // --- central semantic: in-flight requests are never truncated -----------

    /// A request already "in flight" when another request's `record` pushes
    /// the budget over the top must still complete with a normal response --
    /// this filter has no mechanism to cut off bytes mid-stream, and must
    /// never grow one.
    #[test]
    fn a_request_already_in_flight_when_the_budget_is_exhausted_completes_normally() {
        let store = store_with(10, Duration::from_secs(60));
        let mut filter = filter_with(store);

        // Simulate "in flight": decode_headers has already admitted this
        // request (budget was empty at admission time) before another
        // request's usage pushes the total over budget.
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer sk-1"));
        filter.decode_headers(&mut cb, &mut head, true);
        assert!(
            cb.local_reply.is_none(),
            "must be admitted while budget is empty"
        );

        // The response now completes with enough usage to blow well past
        // the 10-token budget.
        cb.set_usage(usage(1_000));
        let mut headers = response_headers();
        let status = filter.encode_headers(&mut cb, &mut headers, false);
        assert_eq!(status, FilterHeadersStatus::Continue);
        let mut data = Bytes::from_static(b"the response body, streamed through untouched");
        let data_status = filter.encode_data(&mut cb, &mut data, true);
        assert_eq!(data_status, FilterDataStatus::Continue);
        assert_eq!(
            &data[..],
            b"the response body, streamed through untouched",
            "response bytes must be forwarded completely untouched"
        );
        assert!(
            cb.local_reply.is_none(),
            "an in-flight request must never be turned into an error after the fact"
        );
    }

    // --- usage absent ---------------------------------------------------------

    #[test]
    fn absent_usage_records_nothing_and_never_fails_the_request() {
        let store = store_with(10, Duration::from_secs(60));

        let reply = run_request(&store, "r1", Some("Bearer sk-1"), None);
        assert!(
            reply.is_none(),
            "a request with no usage must not be denied"
        );

        // Nothing was recorded: the budget must still show fully available.
        assert_eq!(
            store.check(
                &LimitKey::from_descriptors(&[
                    ("route", "r1"),
                    ("cred", &hash_credential("Bearer sk-1")),
                ]),
                Instant::now()
            ),
            Ok(LimitDecision::Allow {
                limit: 10,
                remaining: 10,
                reset_after: Duration::from_secs(60),
            }),
            "recording nothing must leave the budget untouched"
        );
    }

    // --- independent budgets -------------------------------------------------

    #[test]
    fn distinct_credentials_get_independent_budgets() {
        let store = store_with(10, Duration::from_secs(60));

        run_request(&store, "r1", Some("Bearer sk-a"), Some(usage(10)));
        let denied = run_request(&store, "r1", Some("Bearer sk-a"), Some(usage(0)));
        assert!(denied.is_some(), "sk-a's budget must now be exhausted");

        let other = run_request(&store, "r1", Some("Bearer sk-b"), Some(usage(0)));
        assert!(
            other.is_none(),
            "a distinct credential on the same route must have an independent budget"
        );
    }

    #[test]
    fn distinct_routes_get_independent_budgets() {
        let store = store_with(10, Duration::from_secs(60));

        run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(10)));
        let denied = run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(0)));
        assert!(denied.is_some(), "r1's budget must now be exhausted");

        let other = run_request(&store, "r2", Some("Bearer sk-1"), Some(usage(0)));
        assert!(
            other.is_none(),
            "the same credential on a distinct route must have an independent budget"
        );
    }

    // --- credential care ------------------------------------------------------

    /// Pins `hash_credential` to the published FNV-1a 64 test vectors.
    ///
    /// This test is the stability guarantee, not the doc comment above it. The
    /// whole reason this function is not `std`'s `DefaultHasher` is that a
    /// distributed budget store requires two different processes -- possibly
    /// built with different Rust toolchains -- to derive the SAME key from the
    /// same credential. A hash that silently changed would not break any other
    /// test in this file (every one of them hashes and compares within a single
    /// process), it would just quietly hand every proxy in a fleet its own full
    /// budget once the remote store landed. These fixed vectors are what turns
    /// that from a comment into something CI enforces.
    #[test]
    fn hash_credential_matches_the_published_fnv1a_vectors() {
        for (input, want) in [
            ("", "cbf29ce484222325"),
            ("a", "af63dc4c8601ec8c"),
            ("foobar", "85944171f73967e8"),
        ] {
            assert_eq!(
                hash_credential(input),
                want,
                "FNV-1a 64 of {input:?} is a frozen published value; if this \
                 changed, the hash is no longer portable across processes and \
                 a distributed budget store would break"
            );
        }
    }

    #[test]
    fn the_credential_never_appears_in_cleartext_in_the_limit_key() {
        let credential = "Bearer sk-super-secret-value";
        let key = LimitKey::from_descriptors(&[
            ("route", "r1"),
            ("cred", hash_credential(credential).as_str()),
        ]);
        assert!(
            !format!("{key:?}").contains(credential),
            "the raw credential must never appear in a LimitKey's Debug output"
        );
        assert!(
            !format!("{key:?}").contains("sk-super-secret-value"),
            "nor any substring of the raw secret"
        );
    }

    // --- window rollover --------------------------------------------------

    #[test]
    fn window_rollover_restores_budget_through_the_filter() {
        let store = store_with(10, Duration::from_millis(10));

        run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(10)));
        let denied = run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(0)));
        assert!(
            denied.is_some(),
            "budget must be exhausted immediately after"
        );

        std::thread::sleep(Duration::from_millis(15));

        let allowed = run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(0)));
        assert!(allowed.is_none(), "the window must have rolled over by now");
    }

    // --- fail open ----------------------------------------------------------

    /// A `BudgetStore` double whose `check` always errors -- proves the
    /// filter admits the request rather than denying or erroring it. See the
    /// module doc's "Fail open on a store error" section.
    struct AlwaysErrorsStore;

    impl BudgetStore for AlwaysErrorsStore {
        fn check(
            &self,
            _key: &LimitKey,
            _now: Instant,
        ) -> Result<LimitDecision, BudgetUnavailable> {
            Err(BudgetUnavailable)
        }
        fn record(&self, _key: &LimitKey, _usage: &TokenUsage, _weight: f64, _now: Instant) {
            panic!("record must not be called by this test -- it never gets past decode_headers if fail-open is broken in the deny direction, and this test only exercises decode_headers")
        }
    }

    #[test]
    fn a_store_error_fails_open_and_admits_the_request() {
        let store: Arc<dyn BudgetStore> = Arc::new(AlwaysErrorsStore);
        let mut filter = filter_with(store);

        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer sk-1"));
        let status = filter.decode_headers(&mut cb, &mut head, true);

        assert_eq!(status, FilterHeadersStatus::Continue);
        assert!(
            cb.local_reply.is_none(),
            "a budget-store error must admit the request (fail open), not deny it"
        );
    }
}
