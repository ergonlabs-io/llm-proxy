//! Wires the [`crate::token_limit`] budget limiter into
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
//! encode-side job is to read the [`proxy_http::LlmTokenUsage`] the
//! usage filter (`crate::usage_filter`) wrote into `StreamInfo` at response
//! end — but that only exists if the usage filter's own encode callback has
//! *already run* by the time this filter's does. Reverse order means "already
//! run" = "later in config order". So this filter MUST be configured BEFORE
//! `llmproxy.usage` in `http_filters`. Get this backwards and
//! `StreamInfo::llm.usage` simply reads `None` forever (see
//! [`TokenLimitFilterInstance::record_if_present`]'s "absent usage" case),
//! recording zero cost for every request that should have been charged. This
//! used to be silent; it no longer is — see "Loud on unreadable usage" below.
//! There is still no code assertion for the ordering itself — the module doc
//! remains the only guard for *that* — but the symptom is no longer invisible.
//!
//! # Loud on unreadable usage, but never fail-closed
//!
//! A budget that applies to a request (`self.key` is `Some`, i.e. this
//! request was actually bucketed) but whose usage reads `None` is exactly
//! the "confirmed live" defect this section exists to close: a metering gap
//! that silently charged nothing and never showed up anywhere an operator
//! would look. [`TokenLimitFilterInstance::record_if_present`] now calls
//! [`UsageMissingWarner::warn_if_due`] on that path — `warn!`, never an
//! error and never a denial, because the request itself succeeded and the
//! proxy behaved exactly as designed (see the module doc's "Fail open on a
//! store error" section for the same philosophy applied to the store side).
//! A route with no configured limit (`self.key` is `None`) never reaches
//! this call at all, so an unlimited route stays silent — warning there
//! would just be a second, noisier outage.
//!
//! Suppression is once-per-key-per-minute, not once-per-process: see
//! [`UsageMissingWarner`]'s doc for why a periodic repeat was chosen over
//! "warn once, ever" (an operator who starts reading logs after the first
//! occurrence must still be able to see it), and why that repeat is cheap
//! enough to keep on the same rare path rather than needing a background
//! task. The warner tracks at most `UsageMissingWarner::MAX_TRACKED_KEYS`
//! keys; past that, warnings fold into one line that names no key.
//!
//! # Local admission, reconciled counters
//!
//! Every limit is checked against local counters
//! ([`crate::window_counter`]): admission never calls the store (ADR-0006
//! addendum §1). The counters reconcile with the configured `auth.store`
//! backend on a control-side thread about once a second, and early when a
//! subject nears its limit. If reconciling fails, the filter keeps enforcing
//! against the last known fleet totals plus local counts and, once past the
//! reconciliation bound, counts and warns about each admission it makes
//! (fail open, loudly; AGENTS.md "Fail-open controls").
//!
//! Windows are aligned to the Unix epoch, so a caller's first window can be
//! shorter than the configured length.
//!
//! # Config: `llmproxy.filters.v0.TokenLimit`
//!
//! The limiter has an owned, versioned config message.  Its
//! `max_tokens` and `fill_rate` fields map directly onto this filter's fixed
//! window semantics; `fill_rate` is tokens per second and the window is
//! `max_tokens / fill_rate` seconds.  Unlike the retired
//! `envoy.config.core.v3.RateLimitSettings` stand-in, the type URL tells an
//! operator what it configures instead of describing xDS discovery throttling.
//!
//! The borrowed Envoy type remains accepted for one release as
//! [`LEGACY_TYPE_URL`]. It uses a separate factory so the registry can decode
//! its wrapped fields exactly, emits a deprecation warning, and cannot become
//! the default accidentally. New configuration must use [`TYPE_URL`].
//!
//! This filter does not expose per-descriptor configurability:
//! [`crate::token_limit::LimitOn::Total`] is hardcoded, and the bucket key is
//! fixed as **(route name, the `authorization` header's value)** — no
//! configured list of descriptors, no per-route override. This is a
//! deliberate thin slice, not an oversight; any richer per-descriptor budget config
//! (such as a dialect `limits` surface) wants a
//! vendored proto, exactly like `body_rewrite_filter`'s and
//! `usage_filter`'s module docs already predict for their own next config
//! knob.
//!
//! The two fields are set together or not at all. With neither, there is no
//! static rule and the filter enforces only the tenant and key limits below;
//! that needs `llmproxy.auth` earlier in the chain, or the config is refused,
//! since the filter would enforce nothing.
//!
//! # Tenant and key limits from the control plane
//!
//! When `llmproxy.auth` precedes this filter, it also enforces the limits set
//! through `PUT /tenants/{id}/limits` and `PUT /keys/{id}/limits`: tokens per
//! minute, requests per minute and concurrent streams. A tenant sets the
//! ceiling and each key can only narrow it, so a request must pass both its
//! tenant's bucket and its key's; a key with no limits row is bounded by its
//! tenant alone. These buckets are per tenant and per key across every route,
//! in their own key spaces ([`crate::token_limit::LimitSubject::TenantPolicy`]
//! and `KeyPolicy`), apart from the static rule's per-route buckets, which are
//! still the only ones `GET /v1/usage` reports. A write applies on the next
//! request. Counters are per process, so N replicas admit up to N times a
//! limit until a shared counter backend exists.
//!
//! # The bucket key: an authenticated tenant if there is one, else the credential
//!
//! This filter originally bucketed on
//! `(route, hash_credential(<the client's `authorization` header>))`. Nothing
//! verified that header, so a caller who wanted more quota changed it and got a
//! fresh bucket — the limit was advisory by construction, and v0.1.0's "a
//! token-based rate limit is enforced" clause could not be honestly verified.
//!
//! It now prefers an identity the *proxy* assigned:
//!
//! | `StreamInfo::auth.tenant` | bucket key |
//! |---|---|
//! | `Some(t)` | `(route, tenant=t)` — an identity the caller cannot choose |
//! | `None` | `(route, cred=<hashed header>)` — the legacy, spoofable key |
//!
//! Three things about that table are load-bearing.
//!
//! **The two key spaces never overlap.** The descriptor *name* differs
//! (`tenant` vs `cred`), not just its value, so no hashed credential can ever
//! collide with a tenant id and no caller can hop out of their tenant's bucket
//! by manipulating the header. See
//! `tests::a_tenant_bucket_and_a_credential_bucket_never_collide`.
//!
//! **The fallback is not a bypass, but only because of what stands in front of
//! it.** `auth.tenant` is `None` exactly when no auth filter authenticated
//! this stream. With an auth filter configured, that cannot happen on an
//! admitted request: it fails closed and refuses the stream with a 401 before
//! this filter's `decode_headers` ever runs, so every request reaching here
//! carries a tenant. Without one, there is no assigned identity in the system
//! at all and the hashed header is the only key available — the same
//! best-effort behavior as before, and no worse. Because the caller picks
//! that header, the store caps how many credential buckets exist at once
//! ([`crate::token_limit::MAX_CREDENTIAL_WINDOWS`]); past the cap, new
//! credentials share one overflow budget per route, and expired windows are
//! evicted (review M8).
//!
//! **Which means the ordering requirement is a security property, not a
//! preference.** Decoder callbacks run in **config order** (S2.1), so
//! `llmproxy.auth` MUST be configured BEFORE `llmproxy.token_limit` in
//! `http_filters`. Get it backwards and nothing errors and nothing logs: this
//! filter reads an `auth.tenant` that the auth filter has not written yet,
//! sees `None`, and silently falls back to the spoofable credential hash —
//! quietly undoing the whole point of authenticating. This is the second
//! ordering trap in this file (the first, `llmproxy.usage` on the *encode*
//! side, runs in the opposite direction — see above), and they are opposites
//! because encode order is reversed, which is exactly why neither is obvious.
//! `proxy_core::listener` rejects the wrong order at config-load time; that
//! check, not this comment, is the actual guard.
//!
//! # The credential never reaches the key in cleartext
//!
//! On the fallback path the `authorization` header's value identifies a
//! caller, so it must never land somewhere it could reach a log — this repo
//! already takes credential care seriously elsewhere (the access-log
//! request-header snapshot is taken before route-injected auth is applied, in
//! `filter_manager::drive_decode`). [`LimitKey::for_credential`] hashes it,
//! via [`CredentialDigest::hash`], before it ever touches a [`LimitKey`] --
//! see that function's doc for why a plain (non-cryptographic) hash is
//! sufficient here, and see [`CredentialDigest`]'s own doc for why that
//! hashing is now enforced by the type, not by every call site remembering
//! to do it. A tenant id needs no such treatment — it is an identifier the
//! operator chose, not a secret.
//!
//! # `GET /v1/usage` — a read-only tenant self-service endpoint
//!
//! This filter also intercepts `GET /v1/usage` in `decode_headers`, before
//! any budget check, and answers it directly rather than proxying it
//! upstream — see [`TokenLimitFilterInstance::handle_usage_request`] for the
//! implementation and its status-code policy. It reports the static rule's
//! per-route tenant buckets from this replica's counters, which is exact
//! with one replica.
//!
//! **The security property is the design, not a detail: the key
//! authenticates AND scopes.** The tenant comes ONLY from
//! `StreamInfo::auth.tenant` — there is no code path here that accepts a
//! caller-supplied tenant from a query parameter, a header, or the path. An
//! unauthenticated request (`auth.tenant` is `None`) is refused with `401`,
//! never falls back to the credential-keyed bucket, and never returns an
//! empty-but-successful body — either would let an unauthenticated caller
//! probe. This is also why the endpoint structurally cannot appear on a
//! listener with no `auth` block configured: with no auth filter in the
//! chain, `auth.tenant` is never written, so `401` is the only reachable
//! outcome.
//!
//! Nothing an authenticated tenant's own request returns is a
//! [`LimitKey`], a [`LimitSubject::Credential`], or a [`CredentialDigest`] --
//! [`crate::token_limit::TenantUsage`] carries only a route name and plain
//! numbers, by construction.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http::header::AUTHORIZATION;
use http::StatusCode;
use prost_reflect::DynamicMessage;

use proxy_config::ConfigError;
use proxy_http::filter::{
    DecoderCallbacks, EncoderCallbacks, FactoryContext, FilterDataStatus, FilterHeadersStatus,
    FilterInstanceFactory, FilterTrailersStatus, HttpFilter, HttpFilterFactory, RequestHeaders,
    RequestTrailers, ResponseHeaders, ResponseTrailers,
};
use proxy_http::LlmTokenUsage;
use proxy_observability::ResponseFlag;

use arc_swap::ArcSwap;

use crate::auth::{KeyId, TenantId};
use crate::auth_filter;
use crate::control::{
    ControlPlane, ControlPlaneSnapshot, ControlPlaneStore, InMemoryControlPlaneStore, LimitPolicy,
    WindowDimension, WindowKey,
};
use crate::model_authz::ModelPattern;
use crate::token_limit::{
    CredentialDigest, LimitDecision, LimitKey, LimitOn, LimitRule, StreamLease, TenantUsage,
};
use crate::usage::TokenUsage;
use crate::window_counter::{
    unconfigured_node_id, Admission, InMemoryLeaseStore, LeaseGauge, WindowAccumulator,
    DEFAULT_LEASE_PUBLISH_INTERVAL, DEFAULT_WINDOW_FLUSH_INTERVAL,
};
use crate::window_usage::{
    ChainRouteNames, RouteTotals, UsageAnswer, UsageReader, ROUTE_NAMES_KEY, USAGE_READ_TIMEOUT,
};

/// Canonical owned type URL for this filter.
pub const TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.TokenLimit";

/// Borrowed type URL accepted for one release after the move to an owned, versioned message.
pub const LEGACY_TYPE_URL: &str = "type.llmproxy.dev/envoy.config.core.v3.RateLimitSettings";

/// Convert validated scalar budget values into the one-rule thin slice.
///
/// The legacy Envoy stand-in nests values in wrappers while `TokenLimit`
/// owns scalars directly, so callers provide the exact paths their operators
/// wrote. Compatibility must not make a useful legacy error point at a field
/// that did not exist in that config shape.
fn parse_rule(
    max_tokens: u64,
    fill_rate: f64,
    max_tokens_path: &str,
    fill_rate_path: &str,
) -> Result<LimitRule, ConfigError> {
    let invalid = |field_path: &str, reason: String| ConfigError::InvalidValue {
        field_path: field_path.to_string(),
        reason,
    };
    if max_tokens == 0 {
        return Err(invalid(
            max_tokens_path,
            "must be greater than 0".to_string(),
        ));
    }
    if !(fill_rate.is_finite() && fill_rate > 0.0) {
        return Err(invalid(
            fill_rate_path,
            format!("must be a finite number greater than 0, got `{fill_rate}`"),
        ));
    }

    let window_secs = (max_tokens as f64 / fill_rate).round();
    let window = if window_secs.is_sign_negative() {
        Duration::ZERO
    } else {
        Duration::from_secs(window_secs as u64)
    };
    if window.is_zero() {
        return Err(invalid(
            fill_rate_path,
            "implies a fill window of zero seconds (max_tokens / fill_rate rounds to 0); \
             lower `fill_rate` or raise `max_tokens`"
                .to_string(),
        ));
    }

    Ok(LimitRule {
        on: LimitOn::Total,
        max_tokens,
        window,
    })
}

/// Read the owned `TokenLimit` message. `optional` fields preserve presence,
/// so omitted and explicitly-invalid values report distinct, exact paths.
///
/// A message with neither `max_tokens` nor `fill_rate` configures no static
/// rule: the filter then enforces only tenant and key limits from the control
/// plane (`Ok(None)`). Exactly one of the two is still an error.
fn parse_config(config: &DynamicMessage) -> Result<Option<LimitRule>, ConfigError> {
    let invalid = |field_path: &str, reason: String| ConfigError::InvalidValue {
        field_path: field_path.to_string(),
        reason,
    };
    if !config.has_field_by_name("max_tokens") && !config.has_field_by_name("fill_rate") {
        return Ok(None);
    }

    if !config.has_field_by_name("max_tokens") {
        return Err(invalid(
            "typed_config.max_tokens",
            "the `max_tokens` field is required".to_string(),
        ));
    }
    let max_tokens = config
        .get_field_by_name("max_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    if !config.has_field_by_name("fill_rate") {
        return Err(invalid(
            "typed_config.fill_rate",
            "the `fill_rate` field is required".to_string(),
        ));
    }
    let fill_rate = config
        .get_field_by_name("fill_rate")
        .and_then(|v| v.as_f64());
    let Some(fill_rate) = fill_rate else {
        return Err(invalid(
            "typed_config.fill_rate",
            "must be a valid double".to_string(),
        ));
    };
    parse_rule(
        max_tokens,
        fill_rate,
        "typed_config.max_tokens",
        "typed_config.fill_rate",
    )
    .map(Some)
}

/// Who a keyed rule counts against; mirrors `LimitRule.Key`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RuleKey {
    Global,
    ClientIp,
    Tenant,
    Header(http::HeaderName),
}

/// One `TokenLimit.rules` entry, validated.
#[derive(Debug, Clone)]
struct KeyedRule {
    key: RuleKey,
    limits: LimitPolicy,
    models: Vec<ModelPattern>,
    /// `|models=...` with the patterns sorted, or empty when unscoped. Part
    /// of the bucket subject, so a scoped rule counts only matching requests.
    scope: String,
}

/// `LimitRule.Key` enum numbers.
const RULE_KEY_GLOBAL: i32 = 1;
const RULE_KEY_CLIENT_IP: i32 = 2;
const RULE_KEY_TENANT: i32 = 3;
const RULE_KEY_HEADER: i32 = 4;

/// Read and validate `TokenLimit.rules`. Every error names the rule's
/// dotted path (AGENTS.md invariant 1).
fn parse_rules(config: &DynamicMessage) -> Result<Vec<KeyedRule>, ConfigError> {
    let invalid = |field_path: String, reason: &str| ConfigError::InvalidValue {
        field_path,
        reason: reason.to_string(),
    };
    let Some(list) = config.get_field_by_name("rules") else {
        return Ok(Vec::new());
    };
    let Some(list) = list.as_list() else {
        return Ok(Vec::new());
    };
    let mut rules = Vec::with_capacity(list.len());
    for (i, entry) in list.iter().enumerate() {
        let path = format!("typed_config.rules[{i}]");
        let Some(msg) = entry.as_message() else {
            return Err(invalid(path, "must be a LimitRule message"));
        };
        let header = msg
            .get_field_by_name("header")
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let key_number = msg
            .get_field_by_name("key")
            .and_then(|v| v.as_enum_number())
            .unwrap_or(0);
        let key = match key_number {
            RULE_KEY_GLOBAL => RuleKey::Global,
            RULE_KEY_CLIENT_IP => RuleKey::ClientIp,
            RULE_KEY_TENANT => RuleKey::Tenant,
            RULE_KEY_HEADER => {
                if header.is_empty() {
                    return Err(invalid(
                        format!("{path}.header"),
                        "is required when `key` is HEADER",
                    ));
                }
                let name = http::HeaderName::from_bytes(header.to_ascii_lowercase().as_bytes())
                    .map_err(|_| invalid(format!("{path}.header"), "is not a valid header name"))?;
                RuleKey::Header(name)
            }
            _ => {
                return Err(invalid(
                    format!("{path}.key"),
                    "must be GLOBAL, CLIENT_IP, TENANT or HEADER",
                ))
            }
        };
        if key_number != RULE_KEY_HEADER && !header.is_empty() {
            return Err(invalid(
                format!("{path}.header"),
                "is only meaningful when `key` is HEADER",
            ));
        }
        let optional_u64 = |name: &str| {
            msg.has_field_by_name(name)
                .then(|| msg.get_field_by_name(name).and_then(|v| v.as_u64()))
                .flatten()
        };
        let limits = LimitPolicy {
            tokens_per_minute: optional_u64("tokens_per_minute"),
            requests_per_minute: optional_u64("requests_per_minute"),
            concurrent_streams: msg
                .has_field_by_name("concurrent_streams")
                .then(|| {
                    msg.get_field_by_name("concurrent_streams")
                        .and_then(|v| v.as_u32())
                })
                .flatten(),
        };
        if limits == LimitPolicy::default() {
            return Err(invalid(
                path,
                "sets no limit; set tokens_per_minute, requests_per_minute or concurrent_streams",
            ));
        }
        let mut models = Vec::new();
        if let Some(patterns) = msg.get_field_by_name("models") {
            for (j, pattern) in patterns.as_list().unwrap_or(&[]).iter().enumerate() {
                let pattern = pattern.as_str().unwrap_or_default();
                if !ModelPattern::is_valid(pattern) {
                    return Err(invalid(
                        format!("{path}.models[{j}]"),
                        "must be an exact model name or a single trailing `*` glob",
                    ));
                }
                models.push(ModelPattern::new(pattern));
            }
        }
        let scope = if models.is_empty() {
            String::new()
        } else {
            let mut names: Vec<&str> = models.iter().map(ModelPattern::as_str).collect();
            names.sort_unstable();
            format!("|models={}", names.join(","))
        };
        rules.push(KeyedRule {
            key,
            limits,
            models,
            scope,
        });
    }
    Ok(rules)
}

/// Fold buckets that share a key into one, keeping the lowest limit of each
/// kind: two rules counting the same requests in the same bucket must not
/// count them twice.
fn merge_buckets(buckets: Vec<PolicyBucket>) -> Vec<PolicyBucket> {
    fn min_opt<T: Ord + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
        match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    let mut merged: Vec<PolicyBucket> = Vec::with_capacity(buckets.len());
    for (key, limits) in buckets {
        match merged.iter_mut().find(|(k, _)| *k == key) {
            Some((_, existing)) => {
                existing.tokens_per_minute =
                    min_opt(existing.tokens_per_minute, limits.tokens_per_minute);
                existing.requests_per_minute =
                    min_opt(existing.requests_per_minute, limits.requests_per_minute);
                existing.concurrent_streams =
                    min_opt(existing.concurrent_streams, limits.concurrent_streams);
            }
            None => merged.push((key, limits)),
        }
    }
    merged
}

/// Decode the borrowed one-release compatibility message.
fn parse_legacy_config(config: &DynamicMessage) -> Result<LimitRule, ConfigError> {
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
    if !config.has_field_by_name("fill_rate") {
        return Err(invalid(
            "typed_config.fill_rate",
            "the `fill_rate` field is required".to_string(),
        ));
    }
    let fill_rate = config
        .get_field_by_name("fill_rate")
        .and_then(|v| v.as_message().cloned())
        .and_then(|m| m.get_field_by_name("value").and_then(|v| v.as_f64()))
        .ok_or_else(|| {
            invalid(
                "typed_config.fill_rate.value",
                "must be a valid double".to_string(),
            )
        })?;
    parse_rule(
        u64::from(max_tokens),
        fill_rate,
        "typed_config.max_tokens.value",
        "typed_config.fill_rate.value",
    )
}

/// [`HttpFilterFactory`] for [`TYPE_URL`]. No `parse_per_route` override —
/// this filter has no per-route config (see the module doc's thin-slice
/// note); the trait default (`ConfigError::Unimplemented`) is correct.
#[derive(Default)]
pub struct TokenLimitFilterFactory;

impl HttpFilterFactory for TokenLimitFilterFactory {
    fn type_url(&self) -> &'static str {
        TYPE_URL
    }

    fn may_buffer_response(&self) -> bool {
        false
    }

    fn create(
        &self,
        config: &DynamicMessage,
        ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        create_filter_factory(parse_config(config)?, parse_rules(config)?, TYPE_URL, ctx)
    }
}

/// Decoder for [`LEGACY_TYPE_URL`].  It deliberately has its own registry
/// identity: a `TokenLimit` factory cannot decode the different field wire
/// types in Envoy's old `RateLimitSettings` message.
#[derive(Default)]
pub struct LegacyTokenLimitFilterFactory;

impl HttpFilterFactory for LegacyTokenLimitFilterFactory {
    fn type_url(&self) -> &'static str {
        LEGACY_TYPE_URL
    }

    fn may_buffer_response(&self) -> bool {
        false
    }

    fn create(
        &self,
        config: &DynamicMessage,
        ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        tracing::warn!(
            legacy_type_url = LEGACY_TYPE_URL,
            replacement_type_url = TYPE_URL,
            "llmproxy.token_limit uses a deprecated borrowed typed_config; migrate to llmproxy.filters.v0.TokenLimit before the next release"
        );
        create_filter_factory(
            Some(parse_legacy_config(config)?),
            Vec::new(),
            LEGACY_TYPE_URL,
            ctx,
        )
    }
}

/// Build the shared budget state from either supported wire representation.
/// Both decoders converge before this point so the compatibility path cannot
/// acquire different runtime semantics by accident.
fn create_filter_factory(
    rule: Option<LimitRule>,
    rules: Vec<KeyedRule>,
    config_type_url: &'static str,
    ctx: &FactoryContext,
) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
    create_filter_factory_with_clock(rule, rules, config_type_url, ctx, SystemTime::now)
}

/// [`create_filter_factory`] with the wall-clock source the filter reads,
/// so tests can pin windows.
fn create_filter_factory_with_clock(
    rule: Option<LimitRule>,
    rules: Vec<KeyedRule>,
    config_type_url: &'static str,
    ctx: &FactoryContext,
    clock: fn() -> SystemTime,
) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
    // Tenant and key limits live in the `ControlPlane` that `llmproxy.auth`
    // registers in this chain (the same `ctx.get` resolution
    // `model_authz_filter` uses). Without it only a static rule can apply,
    // and a filter with neither would enforce nothing, which must be a load
    // error rather than a silent no-op (AGENTS.md invariant 1).
    let control_plane = ctx.get(auth_filter::TYPE_URL).map(|cp| {
        cp.downcast::<ControlPlane>().expect(
            "the control-plane singleton registered under auth_filter::TYPE_URL \
             is always a ControlPlane",
        )
    });
    let policy = control_plane.as_ref().map(|cp| cp.handle());
    if rule.is_none() && rules.is_empty() && policy.is_none() {
        return Err(ConfigError::InvalidValue {
            field_path: "typed_config".to_string(),
            reason: "llmproxy.token_limit has no `max_tokens`/`fill_rate` rule, no `rules` and \
                     no llmproxy.auth earlier in the same filter chain, so it would enforce \
                     nothing; configure a rule or add llmproxy.auth"
                .to_string(),
        });
    }
    // A TENANT rule with no authenticator would never see a tenant and so
    // never count anything.
    if policy.is_none() {
        if let Some(i) = rules.iter().position(|r| r.key == RuleKey::Tenant) {
            return Err(ConfigError::InvalidValue {
                field_path: format!("typed_config.rules[{i}].key"),
                reason: "TENANT needs llmproxy.auth earlier in the same filter chain".to_string(),
            });
        }
    }
    let rules: Arc<[KeyedRule]> = rules.into();

    // One set of counters (and one `UsageMissingWarner`) per chain. The
    // HTTP filter chain is rebuilt once PER WORKER (ADR-0003;
    // `build_hcm_handler` in `proxy-core`), and `create` runs once per worker
    // for the same chain, so the counters live in a `SharedFactoryState`
    // slot: every worker building this chain resolves the same `Arc`, and a
    // limit is not multiplied by the worker count.
    //
    // The slot is keyed by the chain and the decoded type URL, not by the
    // rule: counters are keyed by subject, dimension and window, never by
    // the limit (ADR-0006 amendment C), so changing a rule keeps the counts.
    // Two `llmproxy.token_limit` filters in one chain therefore share
    // counters wherever their route, subject, dimension and window length
    // coincide.
    let scope = format!("{}::token_limit(type_url={config_type_url})", ctx.scope);

    // Window rows go to the store `auth.store` selects when `llmproxy.auth`
    // precedes this filter, so the counters are shared exactly when spend
    // is. Without it there is nothing to share with, and the rows live in a
    // private in-memory store: one code path either way (ADR-0006 §6).
    let store: Arc<dyn ControlPlaneStore> = match &control_plane {
        Some(cp) => cp.store(),
        None => Arc::new(InMemoryControlPlaneStore::default()),
    };
    let node_id = if ctx.node_id().is_empty() {
        unconfigured_node_id()
    } else {
        ctx.node_id().to_string()
    };
    let stat_prefix = ctx.stat_prefix.clone();
    // Published by the connection manager before it builds the chain's
    // filters; absent only where no connection manager built this chain.
    let route_names = ctx
        .get(ROUTE_NAMES_KEY)
        .and_then(|names| names.downcast::<ChainRouteNames>().ok());
    // Looked up before `get_or_try_init`: its closure runs under the
    // singleton map's lock, which `get` also takes.
    let stats_registry = ctx
        .shared
        .get("", crate::usage_filter::STATS_REGISTRY_KEY)
        .and_then(|any| any.downcast::<proxy_observability::stats::Registry>().ok());

    let shared = ctx
        .shared
        .get_or_try_init(&scope, &ctx.stat_prefix, config_type_url, || {
            let counters = Arc::new(WindowAccumulator::new(
                stat_prefix.clone(),
                Arc::clone(&store),
                node_id.clone(),
            ));
            counters.start_flusher(DEFAULT_WINDOW_FLUSH_INTERVAL);
            let streams = Arc::new(LeaseGauge::new(
                stat_prefix.clone(),
                Arc::new(InMemoryLeaseStore::default()),
                node_id.clone(),
                DEFAULT_LEASE_PUBLISH_INTERVAL * 3,
            ));
            streams.start_publisher(DEFAULT_LEASE_PUBLISH_INTERVAL);
            // ADR-0006 amendment F: each seam publishes how long it has gone
            // without reconciling, so a fail-open outage shows on
            // `/stats/prometheus` before the warning bound trips.
            if let Some(registry) = &stats_registry {
                counters.export_reconciliation_age(Arc::clone(registry));
                streams.export_reconciliation_age(Arc::clone(registry));
            }
            let usage_missing_warner = Arc::new(UsageMissingWarner::new());
            // Only a shared store holds counts this replica's counters lack
            // (ADR-0006 addendum §4); otherwise the local answer is exact
            // and no reader thread is started.
            let usage_reader = store
                .is_shared()
                .then(|| Arc::new(UsageReader::new(stat_prefix.clone(), Arc::clone(&store))));
            Ok(Arc::new(SharedTokenLimitState {
                counters,
                streams,
                usage_missing_warner,
                usage_reader,
            }) as Arc<dyn std::any::Any + Send + Sync>)
        })?
        .downcast::<SharedTokenLimitState>()
        .expect("token_limit singleton is always a SharedTokenLimitState");

    Ok(Box::new(TokenLimitInstanceFactory {
        clock,
        counters: Arc::clone(&shared.counters),
        streams: Arc::clone(&shared.streams),
        rule,
        rules,
        policy,
        usage_missing_warner: Arc::clone(&shared.usage_missing_warner),
        usage_reader: shared.usage_reader.clone(),
        route_names,
    }))
}

/// The pair of pieces that must be shared across every worker building the
/// SAME chain with the SAME rule -- see `TokenLimitFilterFactory::create`'s
/// doc for why both live behind ONE `SharedFactoryState` slot (keyed
/// together, so a worker that resolves the store always resolves the
/// matching warner, never a stale or mismatched pairing left over from a
/// different rule).
struct SharedTokenLimitState {
    counters: Arc<WindowAccumulator>,
    streams: Arc<LeaseGauge>,
    usage_missing_warner: Arc<UsageMissingWarner>,
    /// `Some` exactly when the store is shared.
    usage_reader: Option<Arc<UsageReader>>,
}

struct TokenLimitInstanceFactory {
    clock: fn() -> SystemTime,
    counters: Arc<WindowAccumulator>,
    streams: Arc<LeaseGauge>,
    rule: Option<LimitRule>,
    rules: Arc<[KeyedRule]>,
    policy: Option<Arc<ArcSwap<ControlPlaneSnapshot>>>,
    usage_missing_warner: Arc<UsageMissingWarner>,
    usage_reader: Option<Arc<UsageReader>>,
    route_names: Option<Arc<ChainRouteNames>>,
}

impl FilterInstanceFactory for TokenLimitInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(TokenLimitFilterInstance {
            counters: Arc::clone(&self.counters),
            streams: Arc::clone(&self.streams),
            clock: self.clock,
            rule: self.rule,
            rules: Arc::clone(&self.rules),
            scoped_pending: Vec::new(),
            scoped_decided: false,
            policy: self.policy.clone(),
            usage_missing_warner: Arc::clone(&self.usage_missing_warner),
            usage_reader: self.usage_reader.clone(),
            route_names: self.route_names.clone(),
            usage_read: UsageRead::Idle,
            key: None,
            policy_charges: Vec::new(),
            leases: Vec::new(),
            recorded: false,
        })
    }
}

/// Control-plane limits are per minute, matching the dialect's
/// `tokens_per_minute` and `requests_per_minute`.
const POLICY_WINDOW: Duration = Duration::from_secs(60);

/// A control-plane limits row and the counter key it is enforced under.
type PolicyBucket = (LimitKey, LimitPolicy);

fn policy_window(now_secs: u64) -> WindowKey {
    WindowKey::containing(now_secs, POLICY_WINDOW.as_secs())
}

fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Which control-plane limit refused a request; selects the 429's body and
/// local-reply details so an operator can tell the three apart in logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Tokens,
    Requests,
    Streams,
}

impl Refusal {
    fn body(self) -> &'static str {
        match self {
            Refusal::Tokens => "token budget exceeded",
            Refusal::Requests => "request rate exceeded",
            Refusal::Streams => "too many concurrent streams",
        }
    }

    fn details(self) -> &'static str {
        match self {
            Refusal::Tokens => "token_limit_exceeded",
            Refusal::Requests => "request_limit_exceeded",
            Refusal::Streams => "concurrency_limit_exceeded",
        }
    }
}

/// Warns, at most once per [`LimitKey`] per [`Self::REPEAT_INTERVAL`], when a
/// budget applied to a request but its usage could not be read — see the
/// module doc's "Loud on unreadable usage" section for what this is
/// answering and [`TokenLimitFilterInstance::record_if_present`] for the one
/// call site.
///
/// # Why a `Mutex<HashMap<..>>`
///
/// A `Mutex`-guarded dedup structure touched only on the rare path (here,
/// "usage came back `None`"), never on a request that had usage to record.
/// One instance is shared, via `Arc`, across every per-stream
/// `TokenLimitFilterInstance` `TokenLimitInstanceFactory::create_filter`
/// hands out — same lifetime as `store`, and for the same reason: the
/// dedup state has to outlive any single stream to mean anything.
///
/// # Once per key, but not once ever
///
/// Usage can come back `None` for the whole life of a long-running process
/// (a provider that never changed its response shape, or a usage-filter
/// dialect misconfigured at boot and never fixed), and an operator who
/// starts reading logs an hour in must still be able to see it. So this
/// repeats — capped at once per key per [`Self::REPEAT_INTERVAL`] — rather
/// than going silent after the first occurrence.
///
/// The repeat costs one extra `Instant` read and comparison, on the same
/// rare, already-locked path the dedup check itself is on — not a
/// background task or a timer, both of which would add machinery the
/// warner is meant to avoid.
///
/// # Bounded by expiry, then by a cap
///
/// Keys come from tenants and credentials, so they keep arriving for the
/// life of the process. An entry older than [`Self::REPEAT_INTERVAL`]
/// behaves exactly like no entry (the key is due either way), so when the
/// map is full the warner first drops expired entries, which changes no
/// warning. If [`Self::MAX_TRACKED_KEYS`] keys all warned within the last
/// interval, a new key is not tracked: its warning folds into one overflow
/// line, itself repeated at most once per interval, that names no key. The
/// fail-open stays loud (AGENTS.md "Fail-open controls") without the dedup
/// state, or the log, growing with the number of callers. The sweep runs
/// only when the map is full and the oldest entry could have expired, so a
/// burst past the cap does not rescan the map on every request.
struct UsageMissingWarner {
    state: Mutex<WarnerState>,
}

#[derive(Default)]
struct WarnerState {
    last_warned: HashMap<LimitKey, Instant>,
    /// No entry can expire before this instant, so a sweep before it would
    /// free nothing. `None` until the first sweep.
    next_sweep: Option<Instant>,
    /// When the overflow line last fired.
    overflow_warned_at: Option<Instant>,
}

impl WarnerState {
    /// Drops entries older than [`UsageMissingWarner::REPEAT_INTERVAL`], if
    /// any could have expired by `now`.
    fn sweep_expired(&mut self, now: Instant) {
        if self.next_sweep.is_some_and(|at| now < at) {
            return;
        }
        let interval = UsageMissingWarner::REPEAT_INTERVAL;
        self.last_warned
            .retain(|_, last| now.saturating_duration_since(*last) < interval);
        self.next_sweep = self
            .last_warned
            .values()
            .min()
            .map(|oldest| *oldest + interval);
    }
}

fn is_due(last: Option<Instant>, now: Instant) -> bool {
    match last {
        Some(last) => now.saturating_duration_since(last) >= UsageMissingWarner::REPEAT_INTERVAL,
        None => true,
    }
}

impl UsageMissingWarner {
    /// How long a key's warning is suppressed before it may fire again. Not
    /// configurable — this is an operability aid, not a tunable knob, and a
    /// fixed value keeps this doc's "at most once per key per minute" claim
    /// actually true.
    const REPEAT_INTERVAL: Duration = Duration::from_secs(60);

    /// How many keys the warner remembers at once, per filter config. See
    /// "Bounded by expiry, then by a cap" above.
    const MAX_TRACKED_KEYS: usize = 1024;

    fn new() -> Self {
        UsageMissingWarner {
            state: Mutex::new(WarnerState::default()),
        }
    }

    /// Warns for `key` if this is the first time it has been seen on this
    /// path, or if [`Self::REPEAT_INTERVAL`] has elapsed since the last time
    /// it warned. Never called from a request that had usage to record (see
    /// the call site in `record_if_present`), so this `Mutex` is never
    /// contended by the healthy path.
    fn warn_if_due(&self, key: &LimitKey, now: Instant) {
        // Rust note: `unwrap_or_else(PoisonError::into_inner)` recovers the
        // guard from a poisoned `Mutex` rather than panicking -- same
        // convention as `RouterStats::warn_unknown_cluster_once`. A panic
        // while holding this lock elsewhere would otherwise turn "we
        // couldn't warn about a metering gap" into "the whole filter now
        // panics on every request", which is a worse outage than the one
        // this section exists to make visible.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let last = state.last_warned.get(key).copied();
        if !is_due(last, now) {
            return;
        }
        if last.is_none() && state.last_warned.len() >= Self::MAX_TRACKED_KEYS {
            state.sweep_expired(now);
        }
        if last.is_none() && state.last_warned.len() >= Self::MAX_TRACKED_KEYS {
            if !is_due(state.overflow_warned_at, now) {
                return;
            }
            state.overflow_warned_at = Some(now);
            drop(state);
            tracing::warn!(
                tracked_keys = Self::MAX_TRACKED_KEYS,
                "token_limit: the token budget for a request was NOT enforced and the \
                 request was allowed uncharged -- usage could not be extracted from the \
                 response. More budget keys hit this within the last minute than are \
                 tracked individually, so this line stands for all of the untracked ones \
                 and repeats at most once a minute. The most likely cause is that the \
                 llmproxy.usage filter's configured `dialect` does not match this \
                 provider's actual response shape; check that first."
            );
            return;
        }
        state.last_warned.insert(key.clone(), now);
        // Rust note: drop the guard before logging -- nothing below needs
        // it, and holding a lock across a macro call some future edit might
        // extend (e.g. to format something expensive) is worth avoiding on
        // principle even though `tracing::warn!` itself doesn't block.
        drop(state);

        tracing::warn!(
            budget_key = %key,
            "token_limit: the token budget for this request was NOT enforced and the \
             request was allowed uncharged -- usage could not be extracted from the \
             response (StreamInfo::llm.usage was None), so there was nothing to charge \
             against this budget. The most likely cause is that the llmproxy.usage \
             filter's configured `dialect` does not match this provider's actual response \
             shape for this route; check that first."
        );
    }
}

/// Per-stream instance. Plain fields, no `Rc`/`RefCell` (this never leaves
/// the worker thread that owns the stream) -- only `store` is the
/// cross-thread-shared piece, and it's an `Arc` clone, not shared interior
/// state of this struct itself.
struct TokenLimitFilterInstance {
    counters: Arc<WindowAccumulator>,
    streams: Arc<LeaseGauge>,
    /// Wall-clock source for epoch-aligned windows; a field so tests can pin
    /// time.
    clock: fn() -> SystemTime,
    /// The configured static rule, keyed per route; `None` in policy-only
    /// mode.
    rule: Option<LimitRule>,
    /// Keyed rules from `TokenLimit.rules`.
    rules: Arc<[KeyedRule]>,
    /// Model-scoped rules that apply to this request by key, with their
    /// bucket, waiting for the body to name the model.
    scoped_pending: Vec<(usize, LimitKey)>,
    /// Set once the model-scoped rules have been decided.
    scoped_decided: bool,
    /// The published control-plane snapshot holding tenant and key limits;
    /// `None` when no `llmproxy.auth` precedes this filter.
    policy: Option<Arc<ArcSwap<ControlPlaneSnapshot>>>,
    /// Shared across every stream this listener serves -- see
    /// [`UsageMissingWarner`]'s doc for why it needs to outlive one stream.
    usage_missing_warner: Arc<UsageMissingWarner>,
    /// Reads `GET /v1/usage` totals from the store; `Some` exactly when the
    /// store is shared.
    usage_reader: Option<Arc<UsageReader>>,
    /// The chain's route names, the rows a store read asks for.
    route_names: Option<Arc<ChainRouteNames>>,
    /// Where a held `GET /v1/usage` stands.
    usage_read: UsageRead,
    /// Set in `decode_headers`, from the route + hashed credential. `None`
    /// only if `decode_headers` never ran (can't happen in practice for an
    /// HTTP filter, but this makes `record_if_present` total rather than
    /// assuming).
    key: Option<LimitKey>,
    /// Tenant and key token buckets this admitted request is charged to at
    /// stream end, with the tokens-per-minute limit each was checked against.
    policy_charges: Vec<(LimitKey, u64)>,
    /// Concurrent-stream slots held for the life of this stream. Dropping a
    /// lease frees its slot, so they are cleared when the stream completes.
    leases: Vec<StreamLease>,
    /// Guards against double-recording from more than one encode callback
    /// observing `end_stream` (mirrors `usage_filter::UsageFilterInstance`'s
    /// `finalized` flag).
    recorded: bool,
}

impl TokenLimitFilterInstance {
    /// Admit a request against its tenant's and key's control-plane limits.
    /// Returns the refusal when one applies; on admission, keeps the leases
    /// and the token buckets to charge at stream end.
    ///
    /// Both levels are enforced, so a key only narrows its tenant (a key
    /// with no row adds no bucket and is bounded by the tenant alone). Token
    /// budgets are checked first because the check counts nothing; stream
    /// permits and request counts are taken only after. Stream permits are
    /// taken tenant first, then key, and a refused key drops the tenant
    /// permit with it (ADR-0006 amendment E). Request counts are taken key
    /// first, so a key refusal leaves the count its sibling keys share
    /// untouched; a tenant refusal after the key was admitted still counts
    /// that one request against the key, which errs toward the narrower
    /// bucket.
    ///
    /// Admission reads only local counters (ADR-0006 addendum §1).
    fn admit_policy(
        &mut self,
        tenant: Option<&str>,
        key_id: Option<&str>,
        now_secs: u64,
    ) -> Option<(LimitDecision, Refusal)> {
        let tenant = tenant?;
        let (tenant_bucket, key_bucket): (Option<PolicyBucket>, Option<PolicyBucket>) = {
            let snapshot = self.policy.as_ref()?.load();
            let key_bucket = key_id.and_then(|id| {
                snapshot
                    .key_limits
                    .get(&KeyId::new(id))
                    .map(|limits| (LimitKey::for_key_policy(id), *limits))
            });
            let tenant_bucket = snapshot
                .tenant_limits
                .get(&TenantId::new(tenant))
                .map(|limits| (LimitKey::for_tenant_policy(tenant), *limits));
            (tenant_bucket, key_bucket)
        };
        if tenant_bucket.is_none() && key_bucket.is_none() {
            return None;
        }
        let tenant_first: Vec<&PolicyBucket> =
            tenant_bucket.iter().chain(key_bucket.iter()).collect();
        let key_first: Vec<&PolicyBucket> = key_bucket.iter().chain(tenant_bucket.iter()).collect();
        self.admit_buckets(&tenant_first, &key_first, now_secs)
    }

    /// Admit against `buckets`: token budgets first (the check counts
    /// nothing), then stream permits in `streams_order`, then request counts
    /// in `requests_order`. On admission keeps the permits and the token
    /// buckets to charge at stream end, alongside any already held.
    fn admit_buckets(
        &mut self,
        streams_order: &[&PolicyBucket],
        requests_order: &[&PolicyBucket],
        now_secs: u64,
    ) -> Option<(LimitDecision, Refusal)> {
        let window = policy_window(now_secs);
        let tenant_first = streams_order;
        let key_first = requests_order;

        for (key, limits) in tenant_first {
            if let Some(tokens) = limits.tokens_per_minute {
                let used = self
                    .counters
                    .used(key, WindowDimension::TotalTokens, window);
                let decision = LimitDecision::for_window(used, tokens, window, now_secs);
                if matches!(decision, LimitDecision::Deny { .. }) {
                    return Some((decision, Refusal::Tokens));
                }
            }
        }

        let mut leases = Vec::new();
        for (key, limits) in tenant_first {
            if let Some(max_streams) = limits.concurrent_streams {
                match self.streams.try_acquire(key, max_streams) {
                    Ok(lease) => leases.push(lease),
                    // Permits taken so far drop with `leases` here.
                    Err(deny) => return Some((deny, Refusal::Streams)),
                }
            }
        }

        for (key, limits) in key_first {
            if let Some(max_requests) = limits.requests_per_minute {
                if let Admission::Refused { used } =
                    self.counters
                        .admit(key, WindowDimension::Requests, window, max_requests)
                {
                    let decision = LimitDecision::for_window(used, max_requests, window, now_secs);
                    return Some((decision, Refusal::Requests));
                }
            }
        }

        self.leases.extend(leases);
        self.policy_charges
            .extend(tenant_first.iter().filter_map(|(key, limits)| {
                limits.tokens_per_minute.map(|tokens| (key.clone(), tokens))
            }));
        None
    }

    /// The bucket a keyed rule counts this request in, or `None` when the
    /// rule does not apply: no tenant, no client address, or no such header.
    fn rule_key(
        rule: &KeyedRule,
        tenant: Option<&str>,
        client: Option<std::net::IpAddr>,
        headers: &RequestHeaders,
    ) -> Option<LimitKey> {
        let subject = match &rule.key {
            RuleKey::Global => "global".to_string(),
            RuleKey::ClientIp => format!("ip={}", client?),
            RuleKey::Tenant => format!("tenant={}", tenant?),
            // Hashed like an unauthenticated credential: the header may carry
            // a secret, and the bucket key reaches logs and the shared store.
            RuleKey::Header(name) => {
                let value = headers.headers.get(name)?;
                let digest = CredentialDigest::hash(&String::from_utf8_lossy(value.as_bytes()));
                format!("header={name}:{digest}")
            }
        };
        Some(LimitKey::for_rule(format!("{subject}{}", rule.scope)))
    }

    /// Admit the model-scoped rules once the model is known (the request
    /// body has been read, as for `llmproxy.model_authz`). A request whose
    /// model is unknown matches no scoped rule.
    fn admit_scoped(&mut self, cb: &mut dyn DecoderCallbacks) {
        if self.scoped_decided || self.scoped_pending.is_empty() {
            return;
        }
        self.scoped_decided = true;
        let model: Option<String> = cb.stream_info().routing_model().map(str::to_owned);
        let Some(model) = model else {
            return;
        };
        let buckets = merge_buckets(
            self.scoped_pending
                .iter()
                .filter(|(i, _)| self.rules[*i].models.iter().any(|p| p.matches(&model)))
                .map(|(i, key)| (key.clone(), self.rules[*i].limits))
                .collect(),
        );
        if buckets.is_empty() {
            return;
        }
        let order: Vec<&PolicyBucket> = buckets.iter().collect();
        let now = (self.clock)();
        match self.admit_buckets(&order, &order, unix_secs(now)) {
            Some((deny, refusal)) => self.refuse(cb, deny, refusal),
            None => {
                self.counters.note_admission(now);
            }
        }
    }

    /// Read `StreamInfo::llm.usage` and, if present, record it against the
    /// static rule's bucket and every control-plane token bucket this
    /// request was admitted against. Never fails the request: a missing key,
    /// a missing usage and a successful record are all handled without
    /// propagating anything back to the caller.
    ///
    /// A missing usage on a request a budget actually applies to is not
    /// silent: see the module doc's "Loud on unreadable usage" section and
    /// [`UsageMissingWarner`].
    fn record_if_present(&mut self, cb: &mut dyn EncoderCallbacks) {
        if self.recorded {
            return;
        }
        self.recorded = true;

        // The bucket named in a missing-usage warning: the static rule's key
        // when there is one, else the first control-plane bucket.
        let Some(warn_key) = self
            .key
            .as_ref()
            .or(self.policy_charges.first().map(|(key, _)| key))
        else {
            return;
        };

        // Rust note: read the field out of the `RefMut` guard and drop it
        // before recording -- `stream_info()` must not be held across another
        // call (see its doc).
        let usage: Option<LlmTokenUsage> = cb.stream_info().llm.usage;

        // `None` must stay unrecorded -- inventing a zero-cost record would
        // be wrong (nothing happened) and a nonzero guess would be worse
        // (this feeds a real budget). See `token_limit`'s central semantic.
        let Some(usage) = usage else {
            self.usage_missing_warner
                .warn_if_due(warn_key, Instant::now());
            return;
        };

        let usage = TokenUsage {
            input_tokens: usage.input_tokens,
            cached_tokens: usage.cached_tokens,
            cache_creation_tokens: usage.cache_creation_tokens,
            output_tokens: usage.output_tokens,
        };
        // Usage lands in the window containing the moment it is recorded
        // (ADR-0006 amendment B), which can be later than the admission's.
        let now_secs = unix_secs((self.clock)());
        if let (Some(key), Some(rule)) = (&self.key, &self.rule) {
            self.counters.add(
                key,
                rule.on.dimension(),
                rule.window_at(now_secs),
                rule.on.amount(&usage),
                rule.max_tokens,
            );
        }
        let window = policy_window(now_secs);
        for (key, tokens_per_minute) in &self.policy_charges {
            self.counters.add(
                key,
                WindowDimension::TotalTokens,
                window,
                usage.total(),
                *tokens_per_minute,
            );
        }
    }

    /// Refuse with 429 and the decision's rate-limit headers. The one place
    /// this filter refuses a request, so the one place `RL` is set.
    fn refuse(&self, cb: &mut dyn DecoderCallbacks, decision: LimitDecision, refusal: Refusal) {
        let LimitDecision::Deny {
            limit,
            remaining,
            reset_after,
            retry_after,
        } = decision
        else {
            return;
        };
        // Set *before* `send_local_reply` so a `%RESPONSE_FLAGS%` logger
        // reading `StreamInfo` after this callback returns already sees it,
        // the same ordering `auth_filter`/`router.rs` use for their own flags.
        // Never set on a fail-open path: that request was admitted.
        cb.stream_info()
            .set_response_flag(ResponseFlag::RateLimited);
        let reset_secs = reset_after.as_secs();
        let retry_secs = retry_after.as_secs();
        cb.send_local_reply(
            StatusCode::TOO_MANY_REQUESTS,
            refusal.body(),
            Some(Box::new(move |headers: &mut http::HeaderMap| {
                // Rust note: `HeaderValue::from` on formatted decimal
                // strings never fails (ASCII digits are always a valid
                // header value), so these unwraps are total.
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
            refusal.details(),
        );
    }

    /// Terminates a `GET /v1/usage` request with the
    /// authenticated caller's own current-window budgets, never proxying it
    /// upstream. See the module doc's usage-endpoint section for the
    /// security property this holds: the tenant comes ONLY from
    /// `StreamInfo::auth.tenant`, which an upstream `llmproxy.auth` filter
    /// wrote after authenticating -- there is no code path here that reads a
    /// tenant from a query parameter, a header, or the path.
    ///
    /// # Status codes
    ///
    /// - `401` if there is no authenticated tenant. This is what makes the
    ///   plan's gating acceptance ("the endpoint never appears on a listener
    ///   with no `auth` block") true by construction rather than by a
    ///   separate check: with no auth filter in the chain (or one that ran
    ///   and did not authenticate), `auth.tenant` is `None`, and this is the
    ///   ONLY branch reachable. It must never fall back to a credential-keyed
    ///   lookup -- that would let an unauthenticated caller probe by
    ///   presenting an arbitrary `authorization` header.
    /// - `200` otherwise, with a JSON body -- including a tenant with no
    ///   configured budgets at all, which gets `200` and an empty `routes`
    ///   array (a true answer), never an error.
    /// - `503` with a shared store when the store read fails or does not
    ///   answer within [`USAGE_READ_TIMEOUT`]. It never falls back to this
    ///   replica's counters, which would report a route only another replica
    ///   served as unused (ADR-0006 addendum §4).
    ///
    /// # Where the numbers come from
    ///
    /// With an in-memory or persistent store there is one replica, and its
    /// counters are exact. With a shared store the request is held (S2
    /// `StopIteration`) while [`UsageReader`] reads the fleet totals on its
    /// own thread; [`HttpFilter::poll_pending`] waits for the answer and the
    /// filter manager then calls `decode_headers` again (ADR-0004), which
    /// replies from it. The worker never touches the store.
    fn handle_usage_request(&mut self, cb: &mut dyn DecoderCallbacks) -> FilterHeadersStatus {
        if let UsageRead::Answered { held, answer } =
            std::mem::replace(&mut self.usage_read, UsageRead::Idle)
        {
            match answer {
                Ok(totals) => self.reply_usage(cb, &held, &totals),
                Err(failure) => reply_usage_unavailable(cb, failure),
            }
            return FilterHeadersStatus::Continue;
        }

        // Rust note: same "clone out of the RefMut guard, let it drop"
        // pattern as `decode_headers`'s own tenant read above -- `stream_info()`
        // must not be held across the `send_local_reply` call below.
        let tenant: Option<String> = cb.stream_info().auth.tenant.clone();

        let Some(tenant) = tenant else {
            cb.send_local_reply(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                None,
                "usage_endpoint_no_authenticated_tenant",
            );
            return FilterHeadersStatus::Continue;
        };

        let now_secs = unix_secs((self.clock)());
        let Some(rule) = self.rule else {
            send_usage_body(cb, &render_usage_response(&tenant, &[]));
            return FilterHeadersStatus::Continue;
        };
        let window = rule.window_at(now_secs);
        let local = self
            .counters
            .tenant_totals(&tenant, rule.on.dimension(), window);

        let Some(reader) = &self.usage_reader else {
            let routes = usage_rows(rule, window, now_secs, &local);
            send_usage_body(cb, &render_usage_response(&tenant, &routes));
            return FilterHeadersStatus::Continue;
        };

        // Every route of the chain, plus any this replica holds a bucket for
        // that the published names lack (an unnamed route, or a test chain
        // with no connection manager).
        let mut routes: Vec<String> = self
            .route_names
            .as_ref()
            .map(|names| names.load().as_ref().clone())
            .unwrap_or_default();
        routes.extend(local.into_iter().map(|(route, _)| route));
        let answer = reader.read(&tenant, rule.on.dimension(), window, routes, Instant::now());
        self.usage_read = UsageRead::Waiting {
            tenant,
            window,
            answer,
        };
        FilterHeadersStatus::StopIteration
    }

    /// Reply 200 with `totals`, read for `held`.
    fn reply_usage(&self, cb: &mut dyn DecoderCallbacks, held: &Held, totals: &RouteTotals) {
        let now_secs = unix_secs((self.clock)());
        let routes = match self.rule {
            Some(rule) => usage_rows(rule, held.window, now_secs, totals),
            None => Vec::new(),
        };
        send_usage_body(cb, &render_usage_response(&held.tenant, &routes));
    }
}

/// A `GET /v1/usage` waiting on, or answered by, a shared-store read.
enum UsageRead {
    Idle,
    Waiting {
        tenant: String,
        window: WindowKey,
        answer: tokio::sync::oneshot::Receiver<UsageAnswer>,
    },
    Answered {
        held: Held,
        answer: Result<RouteTotals, UsageFailure>,
    },
}

/// The tenant and window a held usage read was made for.
struct Held {
    tenant: String,
    window: WindowKey,
}

/// Why a shared-store usage read produced no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UsageFailure {
    Store,
    Timeout,
}

fn usage_rows(
    rule: LimitRule,
    window: WindowKey,
    now_secs: u64,
    totals: &[(String, u64)],
) -> Vec<TenantUsage> {
    let reset_after = Duration::from_secs(window.end_secs().saturating_sub(now_secs));
    totals
        .iter()
        .map(|(route, used)| TenantUsage {
            route: route.clone(),
            used: *used as f64,
            limit: rule.max_tokens as f64,
            remaining: rule.max_tokens.saturating_sub(*used) as f64,
            reset_after,
        })
        .collect()
}

fn send_usage_body(cb: &mut dyn DecoderCallbacks, body: &str) {
    cb.send_local_reply(
        StatusCode::OK,
        body,
        Some(Box::new(|response_headers: &mut http::HeaderMap| {
            response_headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
        })),
        "usage_endpoint",
    );
}

fn reply_usage_unavailable(cb: &mut dyn DecoderCallbacks, failure: UsageFailure) {
    let details = match failure {
        UsageFailure::Store => "usage_endpoint_store_unavailable",
        UsageFailure::Timeout => "usage_endpoint_store_timeout",
    };
    cb.send_local_reply(
        StatusCode::SERVICE_UNAVAILABLE,
        "usage unavailable",
        Some(Box::new(|headers: &mut http::HeaderMap| {
            headers.insert("retry-after", http::HeaderValue::from_static("1"));
        })),
        details,
    );
}

/// The exact path `GET /v1/usage` is matched against -- see
/// [`TokenLimitFilterInstance::handle_usage_request`]'s call site in
/// `decode_headers`. Compared against [`http::Uri::path`], which excludes
/// the query string, so this can never be influenced by one.
const USAGE_PATH: &str = "/v1/usage";

/// Render [`TokenLimitFilterInstance::handle_usage_request`]'s response body.
///
/// Built with `serde_json` (already a `proxy-filters` dependency -- see
/// `Cargo.toml`'s `serde` comment; it rides in for `ControlPlaneStore`'s
/// row encoding) rather than hand-rendered, specifically so `tenant` and
/// every `route` name are escaped correctly by a library that has already
/// solved that problem -- see
/// `tests::a_route_name_containing_a_quote_and_backslash_is_escaped_correctly`
/// for the case that would catch a hand-rolled escaper getting this wrong.
///
/// **Never pass a [`LimitKey`] or anything built from one to this
/// function.** It only ever receives `tenant` (a `&str` the caller already
/// authenticated) and [`TenantUsage`] (which, by its own doc, holds no
/// credential-shaped data) -- see the module doc's "never echo" rule.
fn render_usage_response(tenant: &str, routes: &[TenantUsage]) -> String {
    // Rust note: `serde_json::json!` builds a `serde_json::Value` tree
    // in-place (like a struct literal, but for untyped JSON) -- there is no
    // `#[derive(Serialize)]` response type here because this shape exists
    // only at this one call site and doesn't need one.
    let routes: Vec<serde_json::Value> = routes
        .iter()
        .map(|r| {
            serde_json::json!({
                "route": r.route,
                "used": r.used,
                "limit": r.limit,
                "remaining": r.remaining,
                "reset_after_seconds": r.reset_after.as_secs(),
            })
        })
        .collect();
    // This limiter only ever implements a fixed window (see `token_limit`'s
    // module doc) -- `window` is a constant describing that, not a per-route
    // value, so it renders once at the top level rather than per route.
    serde_json::json!({
        "tenant": tenant,
        "window": "fixed",
        "routes": routes,
    })
    .to_string()
}

impl HttpFilter for TokenLimitFilterInstance {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        // `GET /v1/usage` is intercepted here, before any
        // budget check or bucket-key derivation, and never proxied upstream
        // -- see the module doc's usage-endpoint section. `Uri::path()`
        // deliberately excludes the query string, so `?tenant=B` (or
        // anything else appended after `?`) changes nothing about whether
        // this branch fires, and [`Self::handle_usage_request`] never reads
        // the query string at all -- there is no code path from a query
        // parameter, a header, or a path segment to a tenant identity here.
        if headers.method == http::Method::GET && headers.uri.path() == USAGE_PATH {
            return self.handle_usage_request(cb);
        }

        let now = (self.clock)();
        let now_secs = unix_secs(now);
        let route_name = cb
            .route()
            .and_then(|route| route.name.clone())
            .unwrap_or_default();

        // Rust note: `stream_info()` hands back a `RefMut` guard that must not
        // be held across another call on `cb` (see its doc). Cloning the
        // fields out and letting the guard drop at the end of this block
        // keeps that rule visibly satisfied.
        let (tenant, key_id): (Option<String>, Option<String>) = {
            let info = cb.stream_info();
            (info.auth.tenant.clone(), info.auth.key_id.clone())
        };

        if let Some(rule) = self.rule {
            let key = match &tenant {
                // An identity the proxy assigned. The client's `authorization`
                // header is deliberately not consulted at all on this path --
                // it has no influence on which bucket the request lands in.
                Some(tenant) => LimitKey::for_tenant(route_name.as_str(), tenant),
                // No auth filter authenticated this stream. See the module
                // doc's bucket-key section: the descriptor NAME differs from
                // the authenticated case, so these two key spaces can never
                // collide. `for_credential` hashes the raw value internally --
                // see its doc -- so there is no separate hashing step to
                // forget here.
                None => {
                    let credential = headers
                        .headers
                        .get(AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default();
                    LimitKey::for_credential(route_name.as_str(), credential)
                }
            };
            // A local read only: admission never waits on the store
            // (ADR-0006 addendum §1).
            let window = rule.window_at(now_secs);
            let used = self.counters.used(&key, rule.on.dimension(), window);
            let decision = LimitDecision::for_window(used, rule.max_tokens, window, now_secs);
            self.key = Some(key);
            if let deny @ LimitDecision::Deny { .. } = decision {
                self.refuse(cb, deny, Refusal::Tokens);
                // Rust note: the returned status is irrelevant here --
                // `drive_decode` checks `ctx.local_reply.is_some()` right
                // after this callback returns and stops the chain
                // unconditionally when it's set (see `filter_manager.rs`).
                // `Continue` is returned only because the trait requires *a*
                // value.
                return FilterHeadersStatus::Continue;
            }
        }

        if let Some((deny, refusal)) =
            self.admit_policy(tenant.as_deref(), key_id.as_deref(), now_secs)
        {
            self.refuse(cb, deny, refusal);
            return FilterHeadersStatus::Continue;
        }

        if !self.rules.is_empty() {
            let client: Option<std::net::IpAddr> = cb.stream_info().client_address;
            let mut unscoped = Vec::new();
            for (i, rule) in self.rules.iter().enumerate() {
                let Some(key) = Self::rule_key(rule, tenant.as_deref(), client, headers) else {
                    continue;
                };
                if rule.models.is_empty() {
                    unscoped.push((key, rule.limits));
                } else {
                    self.scoped_pending.push((i, key));
                }
            }
            let buckets = merge_buckets(unscoped);
            let order: Vec<&PolicyBucket> = buckets.iter().collect();
            if let Some((deny, refusal)) = self.admit_buckets(&order, &order, now_secs) {
                self.refuse(cb, deny, refusal);
                return FilterHeadersStatus::Continue;
            }
        }
        // Counted (and warned about) only while the counters are past their
        // reconciliation bound; see `window_counter`'s "Store outage".
        if self.key.is_some() || !self.policy_charges.is_empty() || !self.leases.is_empty() {
            self.counters.note_admission(now);
        }
        FilterHeadersStatus::Continue
    }

    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _data: &mut bytes::Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        if end_stream {
            self.admit_scoped(cb);
        }
        FilterDataStatus::Continue
    }

    /// A request that ends in trailers never sends `end_stream` on data, so
    /// the scoped rules are decided here too.
    fn decode_trailers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _trailers: &mut RequestTrailers,
    ) -> FilterTrailersStatus {
        self.admit_scoped(cb);
        FilterTrailersStatus::Continue
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

    /// A stream cut off before its terminal frame never reaches the
    /// end-of-stream callbacks above. The usage filter, which completes before
    /// this filter (completion runs in reverse chain order), has by now written
    /// a partial estimate; charge it, so a client that keeps aborting still
    /// consumes its budget. A clean end already set `recorded`, so this cannot
    /// charge twice, and a stream with no partial usage (a denial, a local
    /// reply) is left alone, not reported as missing usage.
    fn on_stream_complete(&mut self, cb: &mut dyn EncoderCallbacks) {
        if !self.recorded {
            let partial_usage = {
                let info = cb.stream_info();
                info.llm.completeness
                    == Some(proxy_observability::records::UsageCompleteness::Partial)
                    && info.llm.usage.is_some()
            };
            if partial_usage {
                self.record_if_present(cb);
            }
        }
        // The stream is over: free its concurrent-stream slots now rather
        // than whenever the filter instance is dropped.
        self.leases.clear();
    }

    /// Waits for a held `GET /v1/usage` read, at most [`USAGE_READ_TIMEOUT`].
    /// The answer is applied when the filter manager calls `decode_headers`
    /// again.
    fn poll_pending<'a>(
        &'a mut self,
    ) -> Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>>> {
        if !matches!(self.usage_read, UsageRead::Waiting { .. }) {
            return None;
        }
        let UsageRead::Waiting {
            tenant,
            window,
            answer,
        } = std::mem::replace(&mut self.usage_read, UsageRead::Idle)
        else {
            unreachable!("checked just above");
        };
        Some(Box::pin(async move {
            let answer = match tokio::time::timeout(USAGE_READ_TIMEOUT, answer).await {
                Ok(Ok(Ok(totals))) => Ok(totals),
                Ok(Ok(Err(_))) | Ok(Err(_)) => Err(UsageFailure::Store),
                Err(_) => Err(UsageFailure::Timeout),
            };
            self.usage_read = UsageRead::Answered {
                held: Held { tenant, window },
                answer,
            };
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{RefCell, RefMut};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Method, Uri};
    use proxy_config::ir::RouteEntry;
    use proxy_http::filter::{BufferedBody, HeaderMutationFn, PerRouteConfig, SharedFactoryState};
    use proxy_http::stream_info::StreamInfo;

    use crate::token_limit::{CredentialDigest, LimitOn as TlLimitOn};

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

    fn token_limit_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.TokenLimit")
            .expect("TokenLimit is compiled into proxy-api")
    }

    fn token_limit(max_tokens: u64, fill_rate: f64) -> DynamicMessage {
        let mut msg = DynamicMessage::new(token_limit_desc());
        msg.set_field_by_name("max_tokens", prost_reflect::Value::U64(max_tokens));
        msg.set_field_by_name("fill_rate", prost_reflect::Value::F64(fill_rate));
        msg
    }

    #[test]
    fn token_limit_resolves_in_the_descriptor_pool() {
        let resolved =
            proxy_api::descriptor_pool().get_message_by_name("llmproxy.filters.v0.TokenLimit");
        assert!(resolved.is_some(), "{TYPE_URL} must resolve");
    }

    #[test]
    fn config_parses_max_tokens_and_derives_window_from_fill_rate() {
        // max_tokens=60, fill_rate=1.0 token/sec -> a 60s window.
        let rule = parse_config(&token_limit(60, 1.0))
            .expect("valid config")
            .expect("both fields configure a static rule");
        assert_eq!(rule.on, TlLimitOn::Total);
        assert_eq!(rule.max_tokens, 60);
        assert_eq!(rule.window, Duration::from_secs(60));
    }

    #[test]
    fn owned_config_is_not_artificially_capped_at_the_legacy_uint32_limit() {
        let max_tokens = u64::from(u32::MAX) + 1;
        let rule = parse_config(&token_limit(max_tokens, 1.0))
            .expect("the owned uint64 budget must decode")
            .expect("both fields configure a static rule");
        assert_eq!(rule.max_tokens, max_tokens);
    }

    #[test]
    fn config_rejects_missing_max_tokens() {
        let mut msg = DynamicMessage::new(token_limit_desc());
        msg.set_field_by_name("fill_rate", prost_reflect::Value::F64(1.0));

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
        let mut msg = DynamicMessage::new(token_limit_desc());
        msg.set_field_by_name("max_tokens", prost_reflect::Value::U64(10));

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
        let err = parse_config(&token_limit(0, 1.0)).expect_err("zero max_tokens must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.max_tokens");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn config_rejects_non_positive_fill_rate() {
        for bad in [0.0, -1.0, f64::NAN, f64::NEG_INFINITY] {
            let err = parse_config(&token_limit(10, bad))
                .expect_err(&format!("fill_rate {bad} must be rejected"));
            match err {
                ConfigError::InvalidValue { field_path, .. } => {
                    assert_eq!(field_path, "typed_config.fill_rate");
                }
                other => panic!("expected InvalidValue for fill_rate {bad}, got {other:?}"),
            }
        }
    }

    #[test]
    fn legacy_config_still_decodes_with_the_same_rule() {
        let rule = parse_legacy_config(&rate_limit_settings(60, 1.0))
            .expect("one-release legacy config remains valid");
        assert_eq!(rule.on, TlLimitOn::Total);
        assert_eq!(rule.max_tokens, 60);
        assert_eq!(rule.window, Duration::from_secs(60));
    }

    #[test]
    fn legacy_config_preserves_its_wrapped_error_path() {
        let err = parse_legacy_config(&rate_limit_settings(0, 1.0))
            .expect_err("a zero legacy max_tokens must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.max_tokens.value");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
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
            streaming_strict: false,
            typed_per_filter_config: Default::default(),
            route_index: 0,
            include_request_attempt_count: false,
            include_attempt_count_in_response: false,
        })
    }

    /// A `DecoderCallbacks` + `EncoderCallbacks` double sharing one
    /// `StreamInfo`, mirroring `usage_filter`/`body_rewrite_filter`'s test
    /// doubles. Every method this filter doesn't use panics loudly.
    struct TestCallbacks {
        route: Option<Arc<RouteEntry>>,
        stream_info: RefCell<StreamInfo>,
        local_reply: Option<(StatusCode, HeaderMap, String)>,
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

        /// Stand in for the auth filter, which runs earlier in config
        /// order on the decode path and writes exactly this.
        fn set_authenticated_tenant(&self, tenant: &str) {
            self.stream_info.borrow_mut().auth.tenant = Some(tenant.to_string());
        }
    }

    impl DecoderCallbacks for TestCallbacks {
        fn send_local_reply(
            &mut self,
            code: StatusCode,
            body: &str,
            modify_headers: Option<HeaderMutationFn>,
            _details: &str,
        ) {
            let mut headers = HeaderMap::new();
            if let Some(f) = modify_headers {
                f(&mut headers);
            }
            self.local_reply = Some((code, headers, body.to_string()));
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

    /// 20 seconds into a minute, so a test's requests never straddle a
    /// window boundary.
    fn fixed_clock() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000 + 20)
    }

    /// One minute after [`fixed_clock`]: the next window.
    fn next_minute_clock() -> SystemTime {
        fixed_clock() + Duration::from_secs(60)
    }

    /// A chain's counters over a private in-memory store, never flushed:
    /// with one replica everything lives in `pending`, which is exact.
    struct TestStore {
        counters: Arc<WindowAccumulator>,
        streams: Arc<LeaseGauge>,
        rule: LimitRule,
    }

    impl TestStore {
        /// The current window's total for `key` under the test rule.
        fn used(&self, key: &LimitKey) -> u64 {
            let window = self.rule.window_at(unix_secs(fixed_clock()));
            self.counters.used(key, self.rule.on.dimension(), window)
        }

        /// Record `amount` against `key` as a completed request would.
        fn seed(&self, key: &LimitKey, amount: u64) {
            let window = self.rule.window_at(unix_secs(fixed_clock()));
            self.counters.add(
                key,
                self.rule.on.dimension(),
                window,
                amount,
                self.rule.max_tokens,
            );
        }
    }

    /// Never stale: these counters are never reconciled, and tests that
    /// count warnings must not see the stale-counter one.
    fn test_counters() -> Arc<WindowAccumulator> {
        Arc::new(WindowAccumulator::with_reconciliation_bound(
            "test".to_string(),
            Arc::new(InMemoryControlPlaneStore::default()),
            "test-node".to_string(),
            Duration::MAX,
        ))
    }

    fn test_streams() -> Arc<LeaseGauge> {
        Arc::new(LeaseGauge::new(
            "test".to_string(),
            Arc::new(InMemoryLeaseStore::default()),
            "test-node".to_string(),
            Duration::from_secs(3),
        ))
    }

    fn store_with(max_tokens: u64, window: Duration) -> Arc<TestStore> {
        Arc::new(TestStore {
            counters: test_counters(),
            streams: test_streams(),
            rule: LimitRule {
                on: LimitOn::Total,
                max_tokens,
                window,
            },
        })
    }

    fn filter_with(store: Arc<TestStore>) -> TokenLimitFilterInstance {
        filter_at(store, fixed_clock)
    }

    fn filter_at(store: Arc<TestStore>, clock: fn() -> SystemTime) -> TokenLimitFilterInstance {
        TokenLimitFilterInstance {
            rule: Some(store.rule),
            rules: Arc::from(Vec::new()),
            scoped_pending: Vec::new(),
            scoped_decided: false,
            counters: Arc::clone(&store.counters),
            streams: Arc::clone(&store.streams),
            clock,
            policy: None,
            usage_missing_warner: Arc::new(UsageMissingWarner::new()),
            usage_reader: None,
            route_names: None,
            usage_read: UsageRead::Idle,
            key: None,
            policy_charges: Vec::new(),
            leases: Vec::new(),
            recorded: false,
        }
    }

    /// A factory over `ctx` with the clock pinned to [`fixed_clock`].
    fn pinned_factory(
        config: &DynamicMessage,
        ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        create_filter_factory_with_clock(
            parse_config(config)?,
            parse_rules(config)?,
            TYPE_URL,
            ctx,
            fixed_clock,
        )
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
        store: &Arc<TestStore>,
        route: &str,
        credential: Option<&str>,
        usage: Option<LlmTokenUsage>,
    ) -> Option<(StatusCode, HeaderMap, String)> {
        run_request_inner(store, route, None, credential, usage)
    }

    /// As [`run_request`], but with an authenticated tenant already written
    /// into `StreamInfo` — i.e. an auth filter ran ahead of this one, which is
    /// the ordering the module doc requires. `credential` is still passed
    /// through so a test can prove the header does NOT influence the bucket.
    fn run_request_as_tenant(
        store: &Arc<TestStore>,
        route: &str,
        tenant: &str,
        credential: Option<&str>,
        usage: Option<LlmTokenUsage>,
    ) -> Option<(StatusCode, HeaderMap, String)> {
        run_request_inner(store, route, Some(tenant), credential, usage)
    }

    fn run_request_inner(
        store: &Arc<TestStore>,
        route: &str,
        tenant: Option<&str>,
        credential: Option<&str>,
        usage: Option<LlmTokenUsage>,
    ) -> Option<(StatusCode, HeaderMap, String)> {
        let mut filter = filter_with(Arc::clone(store));
        let mut cb = TestCallbacks::new(Some(route_named(route)));
        if let Some(tenant) = tenant {
            cb.set_authenticated_tenant(tenant);
        }
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

    // --- cut-off streams ----------------------------------------------------

    /// One request whose stream ends part-way (`abort`) or cleanly, carrying
    /// usage the way the usage filter leaves it, then completed the way the
    /// filter manager completes every stream.
    fn run_stream(store: &Arc<TestStore>, abort: bool) -> Option<(StatusCode, HeaderMap, String)> {
        let mut filter = filter_with(Arc::clone(store));
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer sk-1"));
        filter.decode_headers(&mut cb, &mut head, true);
        if cb.local_reply.is_some() {
            return cb.local_reply;
        }
        cb.set_usage(usage(10));
        cb.stream_info.borrow_mut().llm.completeness = Some(if abort {
            proxy_observability::records::UsageCompleteness::Partial
        } else {
            proxy_observability::records::UsageCompleteness::Complete
        });
        filter.encode_headers(&mut cb, &mut response_headers(), false);
        if !abort {
            filter.encode_data(&mut cb, &mut Bytes::new(), true);
        }
        filter.on_stream_complete(&mut cb);
        None
    }

    /// A client that keeps aborting still consumes its budget: three partial
    /// streams of 10 tokens exhaust a 25-token budget.
    #[test]
    fn aborted_streams_are_charged_their_partial_usage() {
        let store = store_with(25, Duration::from_secs(60));
        for i in 1..=3 {
            assert!(run_stream(&store, true).is_none(), "stream {i} admitted");
        }
        assert!(run_stream(&store, true).is_some(), "30 tokens exhausted 25");
    }

    /// A clean stream is charged once even though completion runs after it:
    /// two of them are 20 tokens, so a third is still admitted.
    #[test]
    fn a_clean_stream_is_not_charged_again_at_completion() {
        let store = store_with(25, Duration::from_secs(60));
        assert!(run_stream(&store, false).is_none());
        assert!(run_stream(&store, false).is_none());
        assert!(
            run_stream(&store, false).is_none(),
            "double charge would deny"
        );
        assert!(run_stream(&store, false).is_some());
    }

    // --- 429 headers --------------------------------------------------------

    #[test]
    fn a_429_carries_all_four_rate_limit_headers() {
        let store = store_with(10, Duration::from_secs(60));

        // Exhaust the budget.
        run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(10)));
        let (status, headers, _body) =
            run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(0)))
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

    /// A real 429 (driven through `decode_headers`, not a hand-built
    /// `StreamInfo`) must render `%RESPONSE_FLAGS%` as `RL` -- the defect
    /// this test exists to catch left this filter's own refusal
    /// indistinguishable in the access log from any other 429. Asserts
    /// through [`proxy_observability::render_flags`], the exact function
    /// `%RESPONSE_FLAGS%` formatting uses (`access_log.rs`'s
    /// `FormatOp::ResponseFlags` arm), not just the enum -- the rendering is
    /// the contract, per the module doc's rule for these tests.
    #[test]
    fn a_denied_request_renders_the_rl_response_flag() {
        let store = store_with(10, Duration::from_secs(60));

        // First request spends the whole 10-token budget, through the real
        // decode+encode cycle (`run_request` drives both, exactly like a
        // real stream).
        let first = run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(10)));
        assert!(first.is_none(), "the first request must be admitted");

        // Second request, now over budget: built directly (not through
        // `run_request`, which discards `cb`) so `StreamInfo` can be
        // inspected after the denial.
        let mut filter = filter_with(Arc::clone(&store));
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer sk-1"));
        filter.decode_headers(&mut cb, &mut head, true);

        assert!(
            cb.local_reply.is_some(),
            "the second request over a 10-token budget must be denied"
        );
        let flags = cb.stream_info.borrow().response_flags().to_vec();
        assert_eq!(
            proxy_observability::flags::render_flags(&flags),
            "RL",
            "a request this filter refuses must render exactly `RL`, matching Envoy's \
             local-rate-limit code -- an admitted request must never carry it (see the \
             fail-open tests above, none of which touch response_flags)"
        );
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
            store.used(&LimitKey::for_credential("r1", "Bearer sk-1")),
            0,
            "recording nothing must leave the budget untouched"
        );
    }

    // --- loud on unreadable usage (was silent; see the module doc) ----------

    /// A minimal `tracing::Subscriber` that counts WARN-level events and
    /// captures each one's rendered `message` field -- enough to assert both
    /// the noise (how many fired) and the content (does the text say what it
    /// should). Mirrors `proxy_http::access_logging`'s test-only
    /// `WarnCounter`, extended with message capture since these tests need
    /// to check what the warning says, not just that one fired.
    struct WarnCapture {
        count: AtomicUsize,
        messages: Mutex<Vec<String>>,
    }

    impl WarnCapture {
        fn new() -> Self {
            WarnCapture {
                count: AtomicUsize::new(0),
                messages: Mutex::new(Vec::new()),
            }
        }
    }

    /// Rust note: `tracing::Subscriber` is the trait that receives every
    /// emitted event; a real process installs one (`tracing_subscriber`)
    /// that renders to a writer, but a test can install a small one that
    /// just records what it saw, via `tracing::subscriber::set_default`
    /// (dropped -- see the `guard` pattern below -- to un-install it before
    /// the next test runs).
    impl tracing::Subscriber for WarnCapture {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() != tracing::Level::WARN {
                return;
            }
            self.count.fetch_add(1, Ordering::SeqCst);

            // Rust note: a `Visit` implementor is how `tracing` hands field
            // values back out -- `event.record` calls it once per field.
            // Every field type here (the formatted message, and the
            // `%key`-displayed `budget_key`) routes through `record_debug`
            // (only the handful of primitive types tracing special-cases,
            // e.g. `record_str`/`record_u64`, get their own callback).
            struct MessageVisitor(String);
            impl tracing::field::Visit for MessageVisitor {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = format!("{value:?}");
                    }
                }
            }
            let mut visitor = MessageVisitor(String::new());
            event.record(&mut visitor);
            self.messages
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(visitor.0);
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// As [`run_request`], but the caller supplies (and can reuse across
    /// calls) the [`UsageMissingWarner`] -- production shares one via
    /// `TokenLimitInstanceFactory` across every stream on a listener (see
    /// its doc); `run_request` builds a fresh one per call, which is right
    /// for every test except the ones in this section that need to observe
    /// suppression *across* requests.
    fn run_request_with_shared_warner(
        store: &Arc<TestStore>,
        warner: &Arc<UsageMissingWarner>,
        route: &str,
        credential: Option<&str>,
        usage: Option<LlmTokenUsage>,
    ) -> Option<(StatusCode, HeaderMap, String)> {
        let mut filter = filter_with(Arc::clone(store));
        filter.usage_missing_warner = Arc::clone(warner);
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

    #[test]
    fn a_budget_that_applies_with_unreadable_usage_warns_and_still_admits_the_request() {
        let store = store_with(10, Duration::from_secs(60));
        let capture = Arc::new(WarnCapture::new());
        let guard = tracing::subscriber::set_default(capture.clone());

        let reply = run_request(&store, "r1", Some("Bearer sk-1"), None);

        drop(guard);
        assert!(
            reply.is_none(),
            "usage being unreadable must fail OPEN -- the request must still succeed"
        );
        assert_eq!(
            capture.count.load(Ordering::SeqCst),
            1,
            "exactly one warning must fire for the one request"
        );
        let messages = capture
            .messages
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert!(
            messages[0].contains("NOT enforced"),
            "the message must say plainly that the budget was not enforced, got: {:?}",
            messages[0]
        );
        assert!(
            messages[0].contains("dialect"),
            "the message must point at the likely cause (a usage-filter dialect mismatch), \
             got: {:?}",
            messages[0]
        );
    }

    #[test]
    fn a_route_with_no_budget_applied_never_warns_even_with_unreadable_usage() {
        // Mirrors `record_if_present`'s "missing key (shouldn't happen)"
        // case: a filter instance whose `decode_headers` never ran, so no
        // budget was ever bucketed for this stream -- the precise condition
        // the module doc requires to stay silent (an unlimited route must
        // never warn on every request).
        let store = store_with(10, Duration::from_secs(60));
        let capture = Arc::new(WarnCapture::new());
        let guard = tracing::subscriber::set_default(capture.clone());

        let mut filter = filter_with(store);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut headers = response_headers();
        filter.encode_headers(&mut cb, &mut headers, false);
        let mut data = Bytes::new();
        filter.encode_data(&mut cb, &mut data, true);

        drop(guard);
        assert_eq!(
            capture.count.load(Ordering::SeqCst),
            0,
            "no budget applied to this stream -- it must stay completely silent"
        );
    }

    #[test]
    fn readable_usage_never_warns_and_still_charges_the_budget_normally() {
        let store = store_with(10, Duration::from_secs(60));
        let capture = Arc::new(WarnCapture::new());
        let guard = tracing::subscriber::set_default(capture.clone());

        run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(10)));

        drop(guard);
        assert_eq!(
            capture.count.load(Ordering::SeqCst),
            0,
            "usage was readable -- this is the healthy path and must stay silent"
        );

        // The budget from the first (warning-free) request must actually
        // have been charged, exactly as before this change.
        let denied = run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(0)));
        assert!(
            denied.is_some(),
            "the successfully-recorded usage above must have exhausted the budget"
        );
    }

    #[test]
    fn repeated_unreadable_usage_on_one_key_warns_once_not_per_request() {
        let store = store_with(10, Duration::from_secs(60));
        let warner = Arc::new(UsageMissingWarner::new());
        let capture = Arc::new(WarnCapture::new());
        let guard = tracing::subscriber::set_default(capture.clone());

        for i in 1..=5 {
            let reply =
                run_request_with_shared_warner(&store, &warner, "r1", Some("Bearer sk-1"), None);
            assert!(
                reply.is_none(),
                "request {i} with unreadable usage must not be denied"
            );
        }

        drop(guard);
        assert_eq!(
            capture.count.load(Ordering::SeqCst),
            1,
            "5 requests with unreadable usage on the SAME key must warn exactly once, not 5 \
             times -- repeats within the suppression window must be swallowed"
        );
    }

    const OVERFLOW_LINE: &str = "stands for all of the untracked ones";

    #[test]
    fn unreadable_usage_on_more_keys_than_tracked_folds_into_one_overflow_line() {
        let store = store_with(10, Duration::from_secs(60));
        let warner = Arc::new(UsageMissingWarner::new());
        let capture = Arc::new(WarnCapture::new());
        let guard = tracing::subscriber::set_default(capture.clone());

        let keys = UsageMissingWarner::MAX_TRACKED_KEYS + 5;
        for i in 0..keys {
            let credential = format!("Bearer sk-{i}");
            for _ in 0..2 {
                let reply =
                    run_request_with_shared_warner(&store, &warner, "r1", Some(&credential), None);
                assert!(reply.is_none(), "key {i}: unreadable usage must fail open");
            }
        }

        drop(guard);
        let messages = capture
            .messages
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let overflow: Vec<&String> = messages
            .iter()
            .filter(|m| m.contains(OVERFLOW_LINE))
            .collect();
        assert_eq!(
            messages.len(),
            UsageMissingWarner::MAX_TRACKED_KEYS + 1,
            "one warning per tracked key plus one overflow line, none per repeat"
        );
        assert_eq!(overflow.len(), 1, "{overflow:?}");
        assert!(
            overflow[0].contains("NOT enforced"),
            "the overflow line must still say the budget was not enforced: {:?}",
            overflow[0]
        );
        let state = warner.state.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(
            state.last_warned.len(),
            UsageMissingWarner::MAX_TRACKED_KEYS
        );
    }

    #[test]
    fn a_full_warner_drops_expired_keys_before_folding_a_new_one() {
        // `now` is the warner's own parameter, so time moves without sleeping.
        let warner = UsageMissingWarner::new();
        let key = |i: usize| LimitKey::for_credential("r1", &format!("Bearer sk-{i}"));
        let start = Instant::now();
        let capture = Arc::new(WarnCapture::new());
        let guard = tracing::subscriber::set_default(capture.clone());

        for i in 0..UsageMissingWarner::MAX_TRACKED_KEYS {
            warner.warn_if_due(&key(i), start);
        }
        // Full and nothing expired: a new key folds into the overflow line,
        // which repeats only once per interval.
        warner.warn_if_due(&key(100_000), start + Duration::from_secs(1));
        warner.warn_if_due(&key(100_001), start + Duration::from_secs(2));
        // Every tracked key has expired: a new key gets its own warning.
        let later = start + UsageMissingWarner::REPEAT_INTERVAL;
        warner.warn_if_due(&key(100_002), later);

        drop(guard);
        let messages = capture
            .messages
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let tail: Vec<bool> = messages[UsageMissingWarner::MAX_TRACKED_KEYS..]
            .iter()
            .map(|m| m.contains(OVERFLOW_LINE))
            .collect();
        assert_eq!(tail, [true, false], "overflow once, then a per-key warning");
        let state = warner.state.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(state.last_warned.len(), 1, "expired keys were dropped");
        assert!(state.last_warned.contains_key(&key(100_002)));
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

    // --- cross-worker budget sharing (SharedFactoryState) --------------------

    /// As [`run_request`], but driven through a `Box<dyn HttpFilter>` handed
    /// back by [`FilterInstanceFactory::create_filter`] instead of a
    /// hand-built [`TokenLimitFilterInstance`] -- these tests care about the
    /// WIRING from `TokenLimitFilterFactory::create` down to the shared
    /// store, not just the instance's own decode/encode behavior, so they
    /// must go through the real factory path.
    fn run_request_through(
        filter: &mut dyn HttpFilter,
        route: &str,
        credential: Option<&str>,
        usage: Option<LlmTokenUsage>,
    ) -> Option<(StatusCode, HeaderMap, String)> {
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

    /// **The acceptance test for the shared-singleton fix.** Two `create()`
    /// calls over ONE `FactoryContext` is exactly what two workers do: the
    /// HTTP filter chain (and therefore this factory) is rebuilt once per
    /// worker (ADR-0003), and every worker for one serve is handed the same
    /// `SharedFactoryState`. Before this fix, each `create()` call built its
    /// own fresh `InProcessBudgetStore`, so a second worker always started
    /// with a brand-new, unshared budget -- a configured N-tokens/window
    /// limit admitted roughly `N * worker_count`. This test drives real
    /// requests through the real `HttpFilter` callbacks on TWO
    /// factory-produced filters (not `BudgetStore` directly), because the
    /// defect is in the wiring between `create` and the store, not in
    /// `InProcessBudgetStore`'s own accounting.
    #[test]
    fn two_workers_building_the_same_chain_share_one_budget() {
        let ctx = FactoryContext {
            shared: Arc::new(SharedFactoryState::default()),
            scope: "listener 'l' filter_chains[0]".to_string(),
            stat_prefix: "l".to_string(),
        };
        let config = token_limit(10, 1.0); // max_tokens=10, window=10s

        let mut filter_worker_1 = pinned_factory(&config, &ctx)
            .expect("worker 1's create must succeed")
            .create_filter();
        let mut filter_worker_2 = pinned_factory(&config, &ctx)
            .expect("worker 2's create must succeed")
            .create_filter();

        let reply = run_request_through(
            &mut *filter_worker_1,
            "r1",
            Some("Bearer sk-1"),
            Some(usage(10)),
        );
        assert!(
            reply.is_none(),
            "worker 1's first request, exactly at the budget, must be admitted"
        );

        let denied = run_request_through(
            &mut *filter_worker_2,
            "r1",
            Some("Bearer sk-1"),
            Some(usage(0)),
        );
        assert!(
            denied.is_some(),
            "worker 2 must see the budget worker 1 already exhausted -- an admission here \
             means each `create()` call built its own unshared InProcessBudgetStore, which \
             is the exact quota-multiplied-by-worker-count bug this test exists to catch"
        );
    }

    /// Two `llmproxy.token_limit` filters in ONE chain with DIFFERENT rules
    /// must never share a budget -- keying the shared slot on `ctx.scope`
    /// alone (rather than `ctx.scope` plus the parsed rule) would let the
    /// second filter's `create()` silently find the first filter's slot
    /// already filled and inherit its rule and its budget.
    #[test]
    fn two_different_rules_in_one_chain_get_independent_budgets() {
        let ctx = FactoryContext {
            shared: Arc::new(SharedFactoryState::default()),
            scope: "listener 'l' filter_chains[0]".to_string(),
            stat_prefix: "l".to_string(),
        };
        let config_a = token_limit(10, 1.0); // max_tokens=10, window=10s
        let config_b = token_limit(500, 1.0); // a different rule, same chain

        let mut filter_a = pinned_factory(&config_a, &ctx)
            .expect("filter A's create must succeed")
            .create_filter();
        let mut filter_b = pinned_factory(&config_b, &ctx)
            .expect("filter B's create must succeed")
            .create_filter();

        let reply = run_request_through(&mut *filter_a, "r1", Some("Bearer sk-1"), Some(usage(10)));
        assert!(reply.is_none(), "filter A's first request must be admitted");
        let denied = run_request_through(&mut *filter_a, "r1", Some("Bearer sk-1"), Some(usage(0)));
        assert!(
            denied.is_some(),
            "filter A's own budget must now be exhausted"
        );

        let allowed =
            run_request_through(&mut *filter_b, "r1", Some("Bearer sk-1"), Some(usage(0)));
        assert!(
            allowed.is_none(),
            "filter B, configured with a different rule in the same chain, must have an \
             independent budget from filter A -- a denial here means both filters shared \
             one store keyed on chain identity alone, dropping the rule from the scope"
        );
    }

    // --- the bucket key is an assigned identity, not a client header ---

    /// **This is the test that turns the rate limit from advisory into
    /// enforceable, and it is the whole point of keying on the assigned identity.**
    ///
    /// Before the re-key, a caller who exhausted their budget changed their
    /// `authorization` header and got a fresh one — the bucket was derived
    /// from a value they controlled. Now that an auth filter has resolved the
    /// stream to a tenant, the header is not consulted at all: the same tenant
    /// presenting a completely different credential must land in the SAME
    /// exhausted bucket.
    #[test]
    fn an_authenticated_tenant_cannot_get_a_fresh_budget_by_changing_the_header() {
        let store = store_with(10, Duration::from_secs(60));

        run_request_as_tenant(
            &store,
            "r1",
            "tenant-a",
            Some("Bearer llmp_first"),
            Some(usage(10)),
        );
        let denied = run_request_as_tenant(
            &store,
            "r1",
            "tenant-a",
            Some("Bearer llmp_first"),
            Some(usage(0)),
        );
        assert!(denied.is_some(), "tenant-a's budget must now be exhausted");

        let evasion_attempt = run_request_as_tenant(
            &store,
            "r1",
            "tenant-a",
            Some("Bearer llmp_a-completely-different-credential"),
            Some(usage(0)),
        );
        assert!(
            evasion_attempt.is_some(),
            "changing the `authorization` header must NOT buy a fresh budget once the \
             stream is authenticated -- the bucket keys on the tenant the proxy assigned, \
             not on anything the caller can choose. This is the enforcement property \
             keying on the assigned identity exists to deliver."
        );
    }

    #[test]
    fn distinct_tenants_get_independent_budgets() {
        let store = store_with(10, Duration::from_secs(60));

        run_request_as_tenant(&store, "r1", "tenant-a", None, Some(usage(10)));
        let denied = run_request_as_tenant(&store, "r1", "tenant-a", None, Some(usage(0)));
        assert!(denied.is_some(), "tenant-a's budget must now be exhausted");

        let other = run_request_as_tenant(&store, "r1", "tenant-b", None, Some(usage(0)));
        assert!(
            other.is_none(),
            "a distinct tenant on the same route must have an independent budget"
        );
    }

    /// Two keys shared by one tenant are one budget — the case that makes a
    /// per-account quota mean anything. (Handing each key its own full budget
    /// would let an account multiply its quota by issuing more keys.)
    #[test]
    fn two_keys_belonging_to_one_tenant_share_that_tenants_budget() {
        let store = store_with(10, Duration::from_secs(60));

        run_request_as_tenant(
            &store,
            "r1",
            "tenant-a",
            Some("Bearer llmp_key-one"),
            Some(usage(10)),
        );
        let denied = run_request_as_tenant(
            &store,
            "r1",
            "tenant-a",
            Some("Bearer llmp_key-two"),
            Some(usage(0)),
        );
        assert!(
            denied.is_some(),
            "a second key on the same tenant must draw on the same exhausted budget"
        );
    }

    /// The two key spaces are distinguished by descriptor NAME, not just
    /// value, so an unauthenticated caller can never be handed a bucket that
    /// an authenticated tenant is also using (in either direction).
    #[test]
    fn a_tenant_bucket_and_a_credential_bucket_never_collide() {
        let store = store_with(10, Duration::from_secs(60));

        // Exhaust the budget of the tenant literally named after the hash the
        // fallback path would produce for this credential -- the most
        // adversarial value available, and the collision a value-only
        // distinction would allow.
        let credential = "Bearer sk-collide";
        let colliding_name = CredentialDigest::hash(credential).to_string();
        run_request_as_tenant(&store, "r1", &colliding_name, None, Some(usage(10)));
        let denied = run_request_as_tenant(&store, "r1", &colliding_name, None, Some(usage(0)));
        assert!(denied.is_some(), "that tenant's budget must be exhausted");

        // An unauthenticated request whose credential hashes to that same
        // string must still get its own budget.
        let unauthenticated = run_request(&store, "r1", Some(credential), Some(usage(0)));
        assert!(
            unauthenticated.is_none(),
            "a hashed credential and a tenant id must never share a bucket, even when \
             the two strings are identical -- the descriptor NAME (`cred` vs `tenant`) \
             is what keeps the key spaces disjoint"
        );
    }

    /// With no auth filter in the chain there is no assigned identity to key
    /// on, and the filter must keep working exactly as it did before keying on the
    /// assigned identity
    /// rather than failing or bucketing everyone together.
    #[test]
    fn with_no_authenticated_tenant_the_filter_falls_back_to_the_hashed_credential() {
        let store = store_with(10, Duration::from_secs(60));

        run_request(&store, "r1", Some("Bearer sk-a"), Some(usage(10)));
        let denied = run_request(&store, "r1", Some("Bearer sk-a"), Some(usage(0)));
        assert!(denied.is_some(), "sk-a's budget must now be exhausted");

        // Name the bucket it landed in, exactly: the legacy `cred` one. This
        // is the half that a re-key which quietly changed the fallback's
        // descriptor name would fail -- the `denied.is_some()` above would
        // still pass, because SOME bucket got exhausted.
        assert_eq!(
            store.used(&LimitKey::for_credential("r1", "Bearer sk-a")),
            10,
            "an unauthenticated stream must still bucket on the hashed credential, so THIS \
             key must be the exhausted one"
        );
    }

    // --- credential care ------------------------------------------------------

    /// Pins `CredentialDigest::hash` to the published FNV-1a 64 test vectors.
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
                CredentialDigest::hash(input).to_string(),
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
        let key = LimitKey::for_credential("r1", credential);
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
        let store = store_with(10, Duration::from_secs(60));

        run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(10)));
        let denied = run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(0)));
        assert!(
            denied.is_some(),
            "budget must be exhausted immediately after"
        );

        // The next epoch-aligned window starts with nothing counted.
        let mut filter = filter_at(Arc::clone(&store), next_minute_clock);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        filter.decode_headers(&mut cb, &mut request_headers(Some("Bearer sk-1")), true);
        assert!(cb.local_reply.is_none(), "the window must have rolled over");
    }

    // --- fail open ----------------------------------------------------------

    /// Counters that have never reconciled with the store, past their
    /// bound: the filter still admits against what it knows locally (fail
    /// open), and the accumulator counts the admission so the bypass is
    /// visible (AGENTS.md "Fail-open controls").
    #[test]
    fn unreconciled_counters_admit_and_count_the_admission() {
        let counters = Arc::new(WindowAccumulator::with_reconciliation_bound(
            "test".to_string(),
            Arc::new(InMemoryControlPlaneStore::default()),
            "test-node".to_string(),
            Duration::ZERO,
        ));
        let store = Arc::new(TestStore {
            counters: Arc::clone(&counters),
            streams: test_streams(),
            rule: LimitRule {
                on: LimitOn::Total,
                max_tokens: 10,
                window: Duration::from_secs(60),
            },
        });
        // A real clock: the bound is measured against construction time.
        let mut filter = filter_at(store, SystemTime::now);
        std::thread::sleep(Duration::from_millis(5));

        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let status =
            filter.decode_headers(&mut cb, &mut request_headers(Some("Bearer sk-1")), true);

        assert_eq!(status, FilterHeadersStatus::Continue);
        assert!(
            cb.local_reply.is_none(),
            "an unreconciled counter must admit (fail open)"
        );
        assert_eq!(counters.unreconciled_admissions(), 1);
    }

    // --- GET /v1/usage ------------------------------------

    /// Drives ONLY `decode_headers` (the usage endpoint never reaches
    /// `encode_*` -- it terminates the request before any budget check),
    /// against a request whose `uri` and headers a test can shape freely.
    /// `tenant` stands in for whatever an upstream `llmproxy.auth` filter
    /// would have written; `None` mirrors no auth filter having run.
    fn run_usage_request(
        store: &Arc<TestStore>,
        tenant: Option<&str>,
        uri: &str,
        extra_header: Option<(&str, &str)>,
    ) -> Option<(StatusCode, HeaderMap, String)> {
        let mut filter = filter_with(Arc::clone(store));
        // `route: None` -- the usage endpoint never calls `cb.route()`, so a
        // route double would be dead weight here.
        let mut cb = TestCallbacks::new(None);
        if let Some(tenant) = tenant {
            cb.set_authenticated_tenant(tenant);
        }
        let mut headers = HeaderMap::new();
        if let Some((name, value)) = extra_header {
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        let mut head = RequestHeaders {
            method: Method::GET,
            uri: uri.parse().expect("valid test URI"),
            headers,
        };
        filter.decode_headers(&mut cb, &mut head, true);
        cb.local_reply
    }

    /// Records `used` (weighted) tokens for `(route, tenant)` directly on the
    /// store -- the fastest way to give a test a specific "current window"
    /// number to assert on, without driving a whole request/response cycle
    /// through the filter for each one.
    fn seed_tenant_usage(store: &Arc<TestStore>, route: &str, tenant: &str, used: u64) {
        store.seed(&LimitKey::for_tenant(route, tenant), used);
    }

    /// **Acceptance case 1**: an authenticated tenant with budgets on more
    /// than one route gets its own numbers back for every one of them, in
    /// deterministic (route-sorted) order — the multi-route case is the
    /// whole reason `LimitKey` became a struct ; a
    /// single-route test would not prove this.
    #[test]
    fn an_authenticated_tenant_reads_its_own_usage_across_multiple_routes() {
        let store = store_with(10_000, Duration::from_secs(60));
        seed_tenant_usage(&store, "chat", "acme", 1_200);
        seed_tenant_usage(&store, "images", "acme", 500);

        let (status, headers, body) = run_usage_request(&store, Some("acme"), "/v1/usage", None)
            .expect("an authenticated tenant must get a reply, not a proxied request");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get("content-type").unwrap(), "application/json");

        let mut parsed: serde_json::Value =
            serde_json::from_str(&body).expect("body must be valid JSON");
        // Rust note: `reset_after_seconds` counts down from the moment
        // `seed_tenant_usage` recorded, so a real (if tiny) amount of wall
        // time has elapsed by the time this assertion runs -- asserting its
        // exact value would be a flaky test asserting something about the
        // clock, not this endpoint. Every OTHER field has no such
        // dependency, so this blanks `reset_after_seconds` out of both
        // routes before the exact-equality check below, and checks its
        // bound (`<= 60`, the configured window) separately.
        for route in parsed["routes"].as_array_mut().unwrap() {
            let reset = route["reset_after_seconds"].as_u64().unwrap();
            assert!(
                reset <= 60,
                "reset_after_seconds must never exceed the configured 60s window, got {reset}"
            );
            route["reset_after_seconds"] = serde_json::Value::Null;
        }
        assert_eq!(
            parsed,
            serde_json::json!({
                "tenant": "acme",
                "window": "fixed",
                "routes": [
                    {
                        "route": "chat",
                        "used": 1200.0,
                        "limit": 10000.0,
                        "remaining": 8800.0,
                        "reset_after_seconds": null,
                    },
                    {
                        "route": "images",
                        "used": 500.0,
                        "limit": 10000.0,
                        "remaining": 9500.0,
                        "reset_after_seconds": null,
                    },
                ],
            }),
            "must report both routes with their own numbers, sorted by route name \
             (`chat` before `images`, not insertion order) -- got body: {body}"
        );
    }

    /// **Acceptance case 2, the cross-tenant negative -- the acceptance
    /// criterion itself.** Tenant A is authenticated; tenant B has its own,
    /// very different, usage recorded. No combination of a query parameter,
    /// a header, or a path segment naming tenant B may yield any of B's
    /// numbers -- the tenant comes ONLY from `StreamInfo::auth.tenant`. This
    /// test actually tries all three smuggling vectors rather than asserting
    /// the property in the abstract.
    #[test]
    fn no_query_parameter_header_or_path_segment_can_read_a_different_tenants_usage() {
        let store = store_with(10_000, Duration::from_secs(60));
        seed_tenant_usage(&store, "chat", "tenant-a", 42);
        seed_tenant_usage(&store, "chat", "tenant-b", 999_999);

        // Vector 1: a query parameter naming tenant B. `Uri::path()` excludes
        // the query string, so this must still be intercepted as the usage
        // endpoint and must still answer for tenant A (the authenticated
        // identity), never tenant B.
        let (status, _headers, body) =
            run_usage_request(&store, Some("tenant-a"), "/v1/usage?tenant=tenant-b", None)
                .expect("a query string must not stop this from being the usage endpoint");
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("\"tenant\":\"tenant-a\""),
            "must answer for the AUTHENTICATED tenant regardless of the query string, got: {body}"
        );
        assert!(
            !body.contains("tenant-b") && !body.contains("999999"),
            "a `?tenant=` query parameter must never select a different tenant's usage, got: {body}"
        );

        // Vector 2: a header naming tenant B. The handler never reads any
        // header at all, so this must behave identically to no header.
        let (status, _headers, body) = run_usage_request(
            &store,
            Some("tenant-a"),
            "/v1/usage",
            Some(("x-tenant", "tenant-b")),
        )
        .expect("a header must not stop this from being the usage endpoint");
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("\"tenant\":\"tenant-a\""),
            "must answer for the AUTHENTICATED tenant regardless of any header, got: {body}"
        );
        assert!(
            !body.contains("tenant-b") && !body.contains("999999"),
            "a header must never select a different tenant's usage, got: {body}"
        );

        // Vector 3: a path segment naming tenant B. This does NOT equal the
        // exact usage path, so it must not be intercepted as the usage
        // endpoint AT ALL -- it falls through to the ordinary budget-checked
        // request path (which, for a route named "" with no configured
        // budget on it, is simply admitted), never returning anyone's usage.
        let reply = run_usage_request(&store, Some("tenant-a"), "/v1/usage/tenant-b", None);
        if let Some((_status, _headers, body)) = reply {
            assert!(
                !body.contains("tenant-b") && !body.contains("999999"),
                "a path segment must never select a different tenant's usage, got: {body}"
            );
        }
    }

    /// **Acceptance case 3**: no authenticated tenant means no code path can
    /// have produced one, so this must refuse with `401` and leak nothing --
    /// not an empty-but-successful body, which would let an unauthenticated
    /// caller probe the endpoint's mere existence for free.
    #[test]
    fn a_request_with_no_authenticated_tenant_is_refused_with_401_and_no_body_leakage() {
        let store = store_with(10_000, Duration::from_secs(60));
        seed_tenant_usage(&store, "chat", "someone", 1_000);

        let (status, _headers, body) = run_usage_request(&store, None, "/v1/usage", None)
            .expect("an unauthenticated request must still get a reply -- a refusal, not a proxy");

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            !body.contains("someone") && !body.contains("1000") && !body.contains("route"),
            "a 401 must carry no usage data at all, got: {body}"
        );
    }

    /// This is also the acceptance test for the gating requirement
    /// ("the endpoint never appears on a listener that has no `auth` block
    /// configured"): with no auth filter in the chain, `StreamInfo::auth.tenant`
    /// is structurally `None` (nothing ever writes it), so this filter's ONLY
    /// reachable branch is the 401 above -- there is no separate check to
    /// forget, because there is no other code path that could produce `200`.
    #[test]
    fn with_no_auth_filter_in_the_chain_the_usage_endpoint_never_returns_200() {
        let store = store_with(10_000, Duration::from_secs(60));
        seed_tenant_usage(&store, "chat", "someone", 1_000);

        // No `set_authenticated_tenant` call at all -- exactly what a chain
        // with no `llmproxy.auth` filter leaves `StreamInfo::auth.tenant` as.
        let (status, ..) =
            run_usage_request(&store, None, "/v1/usage", None).expect("must still get a reply");
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "with no auth filter configured, this must never be 200"
        );
    }

    /// **Acceptance case 5**: a tenant that is authenticated but has no
    /// configured budget anywhere gets a true, empty answer -- `200`, not an
    /// error, and not a nonexistent-tenant error either (there is no such
    /// concept here; the store simply has nothing for this key).
    #[test]
    fn a_tenant_with_no_budgets_gets_200_and_an_empty_routes_array() {
        let store = store_with(10_000, Duration::from_secs(60));
        // Some OTHER tenant has usage; the queried tenant has none at all.
        seed_tenant_usage(&store, "chat", "someone-else", 500);

        let (status, _headers, body) =
            run_usage_request(&store, Some("brand-new-tenant"), "/v1/usage", None)
                .expect("must get a reply");

        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("body must be valid JSON");
        assert_eq!(
            parsed,
            serde_json::json!({"tenant": "brand-new-tenant", "window": "fixed", "routes": []}),
            "a tenant with no budgets must get an empty `routes` array, not an error"
        );
    }

    /// **Acceptance case 6**: drives a request through the credential-keyed
    /// fallback path first (so a `CredentialDigest` genuinely exists in the
    /// store), then asserts the usage endpoint's response -- for a
    /// completely different, authenticated tenant -- contains neither the
    /// digest nor anything that looks like a rendered `LimitKey`. See the
    /// module doc's "never echo" rule: it is safe to log a `LimitKey` only
    /// because of a property of the logging site, and this is a new site
    /// with no such guarantee, so it must never receive one at all.
    #[test]
    fn the_response_body_never_contains_a_credential_digest_or_a_rendered_limit_key() {
        let store = store_with(10_000, Duration::from_secs(60));

        // Populate a real credential-keyed bucket via the normal, unauthenticated
        // fallback path (see `with_no_authenticated_tenant_the_filter_falls_back_to_the_hashed_credential`).
        let credential = "Bearer sk-super-secret-value";
        run_request(&store, "chat", Some(credential), Some(usage(10)));
        let digest = CredentialDigest::hash(credential).to_string();

        seed_tenant_usage(&store, "chat", "acme", 1_200);
        let (status, _headers, body) =
            run_usage_request(&store, Some("acme"), "/v1/usage", None).expect("must get a reply");
        assert_eq!(status, StatusCode::OK);

        assert!(
            !body.contains(&digest),
            "the response must never contain a CredentialDigest, got: {body}"
        );
        assert!(
            !body.contains(credential) && !body.contains("sk-super-secret-value"),
            "the response must never contain the raw credential either, got: {body}"
        );
        assert!(
            !body.contains("cred=") && !body.contains("route=chat|"),
            "the response must never contain a rendered `LimitKey` (its `Display` format), \
             got: {body}"
        );
    }

    /// **Acceptance case 7**: a request that is not `GET /v1/usage` must be
    /// completely unaffected by this change -- proxied through the ordinary
    /// budget-checked path exactly as every other test in this file already
    /// exercises. Pins the two ways a request could *almost* match (right
    /// path, wrong method; wrong path) so a future edit can't accidentally
    /// widen the match.
    #[test]
    fn requests_other_than_get_v1_usage_are_unaffected_by_the_usage_endpoint() {
        let store = store_with(10, Duration::from_secs(60));

        // Wrong method, exact path: a POST to `/v1/usage` must be treated
        // as an ordinary request (budget-checked, not intercepted).
        let mut filter = filter_with(Arc::clone(&store));
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_authenticated_tenant("acme");
        let mut head = RequestHeaders {
            method: Method::POST,
            uri: "/v1/usage".parse().unwrap(),
            headers: HeaderMap::new(),
        };
        filter.decode_headers(&mut cb, &mut head, true);
        assert!(
            cb.local_reply.is_none(),
            "POST /v1/usage must be admitted like any other ordinary request, not intercepted"
        );

        // Right method, wrong path: unaffected, exactly as before this change.
        let reply = run_request(&store, "r1", Some("Bearer sk-1"), Some(usage(10)));
        assert!(
            reply.is_none(),
            "an ordinary chat-completions request must be admitted exactly as before"
        );
    }

    // --- tenant and key limits from the control plane -------------------------

    use crate::auth::{HmacSecret, KeySet};
    use crate::control::InMemoryControlPlaneStore;

    fn control_plane() -> Arc<ControlPlane> {
        Arc::new(
            ControlPlane::new(
                Box::new(InMemoryControlPlaneStore::default()),
                HmacSecret::new(b"operator-secret"),
                KeySet::new(),
            )
            .unwrap(),
        )
    }

    /// A policy-only `TokenLimit` (no static rule) built through the real
    /// factory over `cp`, registered the way `llmproxy.auth` registers it.
    fn policy_factory(cp: &Arc<ControlPlane>) -> Box<dyn FilterInstanceFactory> {
        let ctx = FactoryContext::default();
        ctx.get_or_try_init(auth_filter::TYPE_URL, || {
            Ok(Arc::clone(cp) as Arc<dyn std::any::Any + Send + Sync>)
        })
        .unwrap();
        match pinned_factory(&DynamicMessage::new(token_limit_desc()), &ctx) {
            Ok(factory) => factory,
            Err(e) => panic!("a policy-only config with auth must build: {e:?}"),
        }
    }

    fn mint(cp: &ControlPlane, tenant: &str, key: &str) {
        cp.mint_key(&TenantId::new(tenant), &KeyId::new(key))
            .unwrap();
    }

    fn limits(
        tokens_per_minute: Option<u64>,
        requests_per_minute: Option<u64>,
        concurrent_streams: Option<u32>,
    ) -> LimitPolicy {
        LimitPolicy {
            tokens_per_minute,
            requests_per_minute,
            concurrent_streams,
        }
    }

    /// Run `decode_headers` for an authenticated `tenant`/`key`. Returns the
    /// live filter (holding any stream slots) and its callbacks.
    fn admit(
        factory: &dyn FilterInstanceFactory,
        tenant: &str,
        key: &str,
    ) -> (Box<dyn HttpFilter>, TestCallbacks) {
        let mut filter = factory.create_filter();
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        cb.set_authenticated_tenant(tenant);
        cb.stream_info.borrow_mut().auth.key_id = Some(key.to_string());
        let mut head = request_headers(Some("Bearer llmp_test"));
        filter.decode_headers(&mut cb, &mut head, true);
        (filter, cb)
    }

    /// The 429 body when refused, `None` when admitted.
    fn refusal(factory: &dyn FilterInstanceFactory, tenant: &str, key: &str) -> Option<String> {
        let (_filter, cb) = admit(factory, tenant, key);
        cb.local_reply.map(|(status, _, body)| {
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            body
        })
    }

    /// Admit, then end the stream having used `tokens`.
    fn complete_with_usage(
        factory: &dyn FilterInstanceFactory,
        tenant: &str,
        key: &str,
        tokens: u64,
    ) {
        let (mut filter, mut cb) = admit(factory, tenant, key);
        assert!(cb.local_reply.is_none(), "setup request must be admitted");
        cb.set_usage(usage(tokens));
        filter.encode_headers(&mut cb, &mut response_headers(), true);
        filter.on_stream_complete(&mut cb);
    }

    #[test]
    fn a_policy_only_config_without_auth_is_a_load_error() {
        let ctx = FactoryContext::default();
        let err =
            match TokenLimitFilterFactory.create(&DynamicMessage::new(token_limit_desc()), &ctx) {
                Ok(_) => panic!("a filter that would enforce nothing must not load"),
                Err(e) => e,
            };
        match err {
            ConfigError::InvalidValue { field_path, .. } => assert_eq!(field_path, "typed_config"),
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn a_tenant_with_no_limits_row_is_admitted() {
        let cp = control_plane();
        mint(&cp, "tenant-a", "key-a");
        let factory = policy_factory(&cp);
        for _ in 0..5 {
            assert_eq!(refusal(&*factory, "tenant-a", "key-a"), None);
        }
    }

    #[test]
    fn a_key_request_limit_narrows_its_tenant_and_a_sibling_keeps_the_tenant_limit() {
        let cp = control_plane();
        mint(&cp, "tenant-a", "key-a");
        mint(&cp, "tenant-a", "key-b");
        cp.set_tenant_limits(
            &TenantId::new("tenant-a"),
            Some(&limits(None, Some(3), None)),
        )
        .unwrap();
        cp.set_key_limits(&KeyId::new("key-a"), Some(&limits(None, Some(1), None)))
            .unwrap();
        let factory = policy_factory(&cp);

        assert_eq!(refusal(&*factory, "tenant-a", "key-a"), None);
        // The tenant still has room; key-a's own limit refuses it.
        assert_eq!(
            refusal(&*factory, "tenant-a", "key-a").as_deref(),
            Some("request rate exceeded")
        );
        // key-b has no row, so only the tenant bounds it: 3 - 1 = 2 more.
        assert_eq!(refusal(&*factory, "tenant-a", "key-b"), None);
        assert_eq!(refusal(&*factory, "tenant-a", "key-b"), None);
        assert_eq!(
            refusal(&*factory, "tenant-a", "key-b").as_deref(),
            Some("request rate exceeded")
        );
    }

    #[test]
    fn a_key_limit_never_widens_its_tenant() {
        let cp = control_plane();
        mint(&cp, "tenant-a", "key-a");
        cp.set_tenant_limits(
            &TenantId::new("tenant-a"),
            Some(&limits(Some(10), None, None)),
        )
        .unwrap();
        cp.set_key_limits(&KeyId::new("key-a"), Some(&limits(Some(100), None, None)))
            .unwrap();
        let factory = policy_factory(&cp);

        complete_with_usage(&*factory, "tenant-a", "key-a", 10);
        // The key has 90 tokens left; the tenant has none.
        assert_eq!(
            refusal(&*factory, "tenant-a", "key-a").as_deref(),
            Some("token budget exceeded")
        );
    }

    #[test]
    fn a_key_token_limit_refuses_while_the_tenant_has_room() {
        let cp = control_plane();
        mint(&cp, "tenant-a", "key-a");
        mint(&cp, "tenant-a", "key-b");
        cp.set_tenant_limits(
            &TenantId::new("tenant-a"),
            Some(&limits(Some(100), None, None)),
        )
        .unwrap();
        cp.set_key_limits(&KeyId::new("key-a"), Some(&limits(Some(5), None, None)))
            .unwrap();
        let factory = policy_factory(&cp);

        complete_with_usage(&*factory, "tenant-a", "key-a", 5);
        assert_eq!(
            refusal(&*factory, "tenant-a", "key-a").as_deref(),
            Some("token budget exceeded")
        );
        assert_eq!(refusal(&*factory, "tenant-a", "key-b"), None);
    }

    #[test]
    fn concurrent_streams_are_held_until_the_stream_completes() {
        let cp = control_plane();
        mint(&cp, "tenant-a", "key-a");
        mint(&cp, "tenant-a", "key-b");
        cp.set_tenant_limits(
            &TenantId::new("tenant-a"),
            Some(&limits(None, None, Some(2))),
        )
        .unwrap();
        cp.set_key_limits(&KeyId::new("key-a"), Some(&limits(None, None, Some(1))))
            .unwrap();
        let factory = policy_factory(&cp);

        let (mut first, mut first_cb) = admit(&*factory, "tenant-a", "key-a");
        assert!(first_cb.local_reply.is_none());
        assert_eq!(
            refusal(&*factory, "tenant-a", "key-a").as_deref(),
            Some("too many concurrent streams")
        );
        // key-b takes the tenant's second slot; a third stream is over the tenant.
        let (_second, second_cb) = admit(&*factory, "tenant-a", "key-b");
        assert!(second_cb.local_reply.is_none());
        assert_eq!(
            refusal(&*factory, "tenant-a", "key-b").as_deref(),
            Some("too many concurrent streams")
        );

        first.on_stream_complete(&mut first_cb);
        assert_eq!(refusal(&*factory, "tenant-a", "key-a"), None);
    }

    #[test]
    fn a_key_refusal_does_not_count_against_its_tenant() {
        let cp = control_plane();
        mint(&cp, "tenant-a", "key-a");
        mint(&cp, "tenant-a", "key-b");
        cp.set_tenant_limits(
            &TenantId::new("tenant-a"),
            Some(&limits(None, Some(2), None)),
        )
        .unwrap();
        cp.set_key_limits(&KeyId::new("key-a"), Some(&limits(None, Some(0), None)))
            .unwrap();
        let factory = policy_factory(&cp);

        for _ in 0..3 {
            assert!(refusal(&*factory, "tenant-a", "key-a").is_some());
        }
        assert_eq!(refusal(&*factory, "tenant-a", "key-b"), None);
        assert_eq!(refusal(&*factory, "tenant-a", "key-b"), None);
    }

    #[test]
    fn a_limits_write_applies_on_the_next_request() {
        let cp = control_plane();
        mint(&cp, "tenant-a", "key-a");
        let factory = policy_factory(&cp);
        assert_eq!(refusal(&*factory, "tenant-a", "key-a"), None);

        cp.set_key_limits(&KeyId::new("key-a"), Some(&limits(None, Some(0), None)))
            .unwrap();
        assert!(refusal(&*factory, "tenant-a", "key-a").is_some());

        cp.set_key_limits(&KeyId::new("key-a"), None).unwrap();
        assert_eq!(refusal(&*factory, "tenant-a", "key-a"), None);
    }

    #[test]
    fn a_static_rule_and_tenant_limits_are_both_enforced() {
        let cp = control_plane();
        mint(&cp, "tenant-a", "key-a");
        cp.set_tenant_limits(
            &TenantId::new("tenant-a"),
            Some(&limits(None, Some(1), None)),
        )
        .unwrap();
        let ctx = FactoryContext::default();
        ctx.get_or_try_init(auth_filter::TYPE_URL, || {
            Ok(Arc::clone(&cp) as Arc<dyn std::any::Any + Send + Sync>)
        })
        .unwrap();
        let factory = match pinned_factory(&token_limit(1_000, 1_000.0 / 60.0), &ctx) {
            Ok(factory) => factory,
            Err(e) => panic!("valid config must build: {e:?}"),
        };

        assert_eq!(refusal(&*factory, "tenant-a", "key-a"), None);
        assert_eq!(
            refusal(&*factory, "tenant-a", "key-a").as_deref(),
            Some("request rate exceeded")
        );
    }

    // --- GET /v1/usage with a shared store -------------------------------------

    use crate::control::SharedMemoryStore;
    use crate::window_usage::test_store::ProbeStore;

    /// One replica of a fleet: its own factory state (its own process), a
    /// control plane over `store`, the chain's published route names, and a
    /// 10 000-token, 60-second static rule.
    struct Replica {
        ctx: FactoryContext,
        factory: Box<dyn FilterInstanceFactory>,
    }

    impl Replica {
        fn over(store: Box<dyn ControlPlaneStore>, routes: &[&str]) -> Self {
            let ctx = FactoryContext {
                stat_prefix: "ingress".to_string(),
                ..FactoryContext::default()
            };
            let cp = Arc::new(
                ControlPlane::new(store, HmacSecret::new(b"operator-secret"), KeySet::new())
                    .unwrap(),
            );
            ctx.get_or_try_init(auth_filter::TYPE_URL, || {
                Ok(cp as Arc<dyn std::any::Any + Send + Sync>)
            })
            .unwrap();
            let names = Arc::new(ChainRouteNames::default());
            names.publish(routes.iter().map(|route| route.to_string()));
            ctx.get_or_try_init(ROUTE_NAMES_KEY, || {
                Ok(names as Arc<dyn std::any::Any + Send + Sync>)
            })
            .unwrap();
            let factory = match pinned_factory(&token_limit(10_000, 10_000.0 / 60.0), &ctx) {
                Ok(factory) => factory,
                Err(e) => panic!("valid config must build: {e:?}"),
            };
            Replica { ctx, factory }
        }

        fn counters(&self) -> Arc<WindowAccumulator> {
            let scope = format!("{}::token_limit(type_url={TYPE_URL})", self.ctx.scope);
            let state = self
                .ctx
                .shared
                .get(&scope, TYPE_URL)
                .expect("the factory registered its counters")
                .downcast::<SharedTokenLimitState>()
                .unwrap();
            Arc::clone(&state.counters)
        }

        /// This replica's own counters for `tenant` in the test window.
        fn local_totals(&self, tenant: &str) -> Vec<(String, u64)> {
            let window = WindowKey::containing(unix_secs(fixed_clock()), 60);
            self.counters()
                .tenant_totals(tenant, LimitOn::Total.dimension(), window)
        }

        /// Serve one request for `tenant` on `route` that used `tokens`.
        fn serve(&self, tenant: &str, route: &str, tokens: u64) {
            let mut filter = self.factory.create_filter();
            let mut cb = TestCallbacks::new(Some(route_named(route)));
            cb.set_authenticated_tenant(tenant);
            filter.decode_headers(&mut cb, &mut request_headers(Some("Bearer llmp_x")), true);
            assert!(cb.local_reply.is_none(), "setup request must be admitted");
            cb.set_usage(usage(tokens));
            filter.encode_headers(&mut cb, &mut response_headers(), true);
        }

        /// `GET /v1/usage` for `tenant`, driven the way the filter manager
        /// drives a held request: `decode_headers`, await `poll_pending` on a
        /// runtime with a timer, then `decode_headers` again. Returns whether
        /// the request was held, and the reply.
        fn usage_reply(&self, tenant: &str) -> (bool, (StatusCode, HeaderMap, String)) {
            let mut filter = self.factory.create_filter();
            let mut cb = TestCallbacks::new(None);
            cb.set_authenticated_tenant(tenant);
            let mut head = RequestHeaders {
                method: Method::GET,
                uri: "/v1/usage".parse().unwrap(),
                headers: HeaderMap::new(),
            };
            let held = filter.decode_headers(&mut cb, &mut head, true)
                == FilterHeadersStatus::StopIteration;
            if held {
                assert!(cb.local_reply.is_none(), "a held request has no reply yet");
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                    .unwrap();
                let pending = filter
                    .poll_pending()
                    .expect("a held usage request has a read pending");
                runtime.block_on(pending);
                assert!(filter.poll_pending().is_none(), "one read per hold");
                filter.decode_headers(&mut cb, &mut head, true);
            }
            (
                held,
                cb.local_reply.expect("the usage endpoint always replies"),
            )
        }
    }

    fn reported_routes(body: &str) -> Vec<(String, u64)> {
        let parsed: serde_json::Value = serde_json::from_str(body).expect("valid JSON");
        parsed["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|route| {
                (
                    route["route"].as_str().unwrap().to_string(),
                    route["used"].as_f64().unwrap() as u64,
                )
            })
            .collect()
    }

    /// Two replicas on one shared store. Replica A serves the tenant; B never
    /// does, so B's own counters know nothing, which is what the endpoint
    /// used to report. B must read the fleet total from the store instead.
    #[test]
    fn a_replica_that_never_served_a_route_reports_the_fleet_total_from_a_shared_store() {
        let (store, _) = SharedMemoryStore::new();
        let a = Replica::over(Box::new(store.handle()), &["chat", "images"]);
        let b = Replica::over(Box::new(store.handle()), &["chat", "images"]);
        a.serve("acme", "chat", 700);
        a.serve("acme", "images", 50);
        a.serve("other", "chat", 9);
        a.counters().flush_now().unwrap();

        assert!(b.local_totals("acme").is_empty(), "B never served acme");
        let (held, (status, headers, body)) = b.usage_reply("acme");

        assert!(held, "a shared store is read off the worker");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get("content-type").unwrap(), "application/json");
        assert_eq!(
            reported_routes(&body),
            [("chat".to_string(), 700), ("images".to_string(), 50)]
        );
    }

    /// With an in-memory store there is one replica: the local counters are
    /// exact, so the request is answered at once, without a store read.
    #[test]
    fn a_single_replica_store_answers_from_local_counters_without_holding() {
        let a = Replica::over(Box::new(InMemoryControlPlaneStore::default()), &["chat"]);
        a.serve("acme", "chat", 700);

        let (held, (status, _, body)) = a.usage_reply("acme");

        assert!(!held);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reported_routes(&body), [("chat".to_string(), 700)]);
    }

    /// A failed store read answers 503, never the local view: here the local
    /// counters hold a number, so a fallback would have answered 200.
    #[test]
    fn a_store_error_answers_503_and_never_the_local_view() {
        let store = ProbeStore::default();
        let a = Replica::over(Box::new(store.clone()), &["chat"]);
        a.serve("acme", "chat", 700);
        assert!(!a.local_totals("acme").is_empty());
        store.fail.store(true, Ordering::SeqCst);

        let (held, (status, headers, body)) = a.usage_reply("acme");

        assert!(held);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, "usage unavailable");
        assert_eq!(headers.get("retry-after").unwrap(), "1");
    }

    /// A store that does not answer within the read timeout also answers
    /// 503, and the worker is not blocked while it waits.
    #[test]
    fn a_store_that_does_not_answer_in_time_answers_503() {
        let store = ProbeStore::default();
        let a = Replica::over(Box::new(store.clone()), &["chat"]);
        a.serve("acme", "chat", 700);
        store.hold();
        // Released however the test ends: the counters' final flush on drop
        // reads the store too, and would wait on the hold forever.
        struct Release(ProbeStore);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0.release();
            }
        }
        let _release = Release(store.clone());

        let (held, (status, _, _)) = a.usage_reply("acme");

        assert!(held);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// The tenant still comes only from authentication on the held path.
    #[test]
    fn an_unauthenticated_usage_request_on_a_shared_store_is_refused_without_a_read() {
        let store = ProbeStore::default();
        let a = Replica::over(Box::new(store.clone()), &["chat"]);
        let mut filter = a.factory.create_filter();
        let mut cb = TestCallbacks::new(None);
        let mut head = RequestHeaders {
            method: Method::GET,
            uri: "/v1/usage?tenant=acme".parse().unwrap(),
            headers: HeaderMap::new(),
        };

        let status = filter.decode_headers(&mut cb, &mut head, true);

        assert_eq!(status, FilterHeadersStatus::Continue);
        assert_eq!(cb.local_reply.unwrap().0, StatusCode::UNAUTHORIZED);
        assert_eq!(store.reads.load(Ordering::SeqCst), 0);
    }

    /// Through the real factory: each counter seam's reconciliation age is
    /// exported under the chain's `stat_prefix`, with no tenant or key label.
    #[test]
    fn the_factory_exports_the_rate_window_and_stream_lease_reconciliation_ages() {
        use crate::reconciliation_age::test_support::rendered_age;
        use crate::reconciliation_age::Seam;

        let ctx = FactoryContext {
            stat_prefix: "ingress".to_string(),
            ..FactoryContext::default()
        };
        let registry = proxy_observability::stats::StatsControl::new(1).registry();
        ctx.shared
            .get_or_try_init("", "", crate::usage_filter::STATS_REGISTRY_KEY, || {
                Ok(Arc::clone(&registry) as Arc<dyn std::any::Any + Send + Sync>)
            })
            .unwrap();
        let cp = control_plane();
        ctx.get_or_try_init(auth_filter::TYPE_URL, || {
            Ok(cp as Arc<dyn std::any::Any + Send + Sync>)
        })
        .unwrap();
        if let Err(e) = pinned_factory(&token_limit(1_000, 1_000.0 / 60.0), &ctx) {
            panic!("valid config must build: {e:?}");
        }

        assert!(rendered_age(&registry, "ingress", Seam::RateWindow).is_some());
        assert!(rendered_age(&registry, "ingress", Seam::StreamLease).is_some());
        let rendered = proxy_observability::stats::prometheus_render::render(&registry);
        for line in rendered
            .lines()
            .filter(|line| line.contains("counter_reconciliation_age"))
            .filter(|line| !line.starts_with('#'))
        {
            assert!(
                !line.contains("tenant") && !line.contains("key"),
                "only scope and seam label the series: {line}"
            );
        }
    }

    // --- keyed rules (TokenLimit.rules) ---------------------------------------

    fn limit_rule_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.LimitRule")
            .expect("LimitRule is compiled into proxy-api")
    }

    /// A `LimitRule` message. `key` is the enum number; limits are set only
    /// when `Some`.
    fn limit_rule(
        key: i32,
        header: &str,
        tokens: Option<u64>,
        requests: Option<u64>,
        streams: Option<u32>,
        models: &[&str],
    ) -> prost_reflect::Value {
        let mut msg = DynamicMessage::new(limit_rule_desc());
        msg.set_field_by_name("key", prost_reflect::Value::EnumNumber(key));
        if !header.is_empty() {
            msg.set_field_by_name("header", prost_reflect::Value::String(header.to_string()));
        }
        if let Some(n) = tokens {
            msg.set_field_by_name("tokens_per_minute", prost_reflect::Value::U64(n));
        }
        if let Some(n) = requests {
            msg.set_field_by_name("requests_per_minute", prost_reflect::Value::U64(n));
        }
        if let Some(n) = streams {
            msg.set_field_by_name("concurrent_streams", prost_reflect::Value::U32(n));
        }
        if !models.is_empty() {
            msg.set_field_by_name(
                "models",
                prost_reflect::Value::List(
                    models
                        .iter()
                        .map(|m| prost_reflect::Value::String(m.to_string()))
                        .collect(),
                ),
            );
        }
        prost_reflect::Value::Message(msg)
    }

    fn rules_config(rules: Vec<prost_reflect::Value>) -> DynamicMessage {
        let mut msg = DynamicMessage::new(token_limit_desc());
        msg.set_field_by_name("rules", prost_reflect::Value::List(rules));
        msg
    }

    /// A pinned-clock factory over `config`, with `cp` registered as
    /// `llmproxy.auth`'s control plane when given.
    fn rules_factory(
        config: &DynamicMessage,
        cp: Option<&Arc<ControlPlane>>,
    ) -> Box<dyn FilterInstanceFactory> {
        let ctx = FactoryContext::default();
        if let Some(cp) = cp {
            ctx.get_or_try_init(auth_filter::TYPE_URL, || {
                Ok(Arc::clone(cp) as Arc<dyn std::any::Any + Send + Sync>)
            })
            .unwrap();
        }
        match pinned_factory(config, &ctx) {
            Ok(factory) => factory,
            Err(e) => panic!("valid rules config must build: {e:?}"),
        }
    }

    fn rules_error(config: &DynamicMessage) -> String {
        match pinned_factory(config, &FactoryContext::default()) {
            Ok(_) => panic!("config must be refused"),
            Err(ConfigError::InvalidValue { field_path, .. }) => field_path,
            Err(other) => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    /// One request through `decode_headers` and, when admitted, an empty
    /// final body (which is when model-scoped rules decide). Returns the 429
    /// body, or `None` when admitted. `filter` stays alive in the result so a
    /// test can hold its stream slots.
    struct RuleRequest<'a> {
        tenant: Option<&'a str>,
        client: Option<&'a str>,
        header: Option<(&'a str, &'a str)>,
        model: Option<&'a str>,
    }

    impl Default for RuleRequest<'_> {
        fn default() -> Self {
            RuleRequest {
                tenant: None,
                client: Some("10.0.0.1"),
                header: None,
                model: None,
            }
        }
    }

    fn send(
        factory: &dyn FilterInstanceFactory,
        req: RuleRequest<'_>,
    ) -> (Box<dyn HttpFilter>, TestCallbacks, Option<String>) {
        let mut filter = factory.create_filter();
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        if let Some(tenant) = req.tenant {
            cb.set_authenticated_tenant(tenant);
        }
        cb.stream_info.borrow_mut().client_address = req.client.map(|ip| ip.parse().unwrap());
        let mut head = request_headers(None);
        if let Some((name, value)) = req.header {
            head.headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        filter.decode_headers(&mut cb, &mut head, false);
        if cb.local_reply.is_none() {
            if let Some(model) = req.model {
                cb.stream_info.borrow_mut().requested_model = Some(model.to_string());
            }
            filter.decode_data(&mut cb, &mut Bytes::new(), true);
        }
        let refused = cb.local_reply.as_ref().map(|(status, _, body)| {
            assert_eq!(*status, StatusCode::TOO_MANY_REQUESTS);
            body.clone()
        });
        (filter, cb, refused)
    }

    fn refused(factory: &dyn FilterInstanceFactory, req: RuleRequest<'_>) -> Option<String> {
        send(factory, req).2
    }

    const GLOBAL: i32 = RULE_KEY_GLOBAL;
    const CLIENT_IP: i32 = RULE_KEY_CLIENT_IP;
    const TENANT_KEY: i32 = RULE_KEY_TENANT;
    const HEADER: i32 = RULE_KEY_HEADER;

    #[test]
    fn invalid_rules_are_refused_with_their_dotted_path() {
        let cases = [
            (
                limit_rule(0, "", None, Some(1), None, &[]),
                "typed_config.rules[0].key",
            ),
            (
                limit_rule(HEADER, "", None, Some(1), None, &[]),
                "typed_config.rules[0].header",
            ),
            (
                limit_rule(GLOBAL, "x-a", None, Some(1), None, &[]),
                "typed_config.rules[0].header",
            ),
            (
                limit_rule(GLOBAL, "", None, None, None, &[]),
                "typed_config.rules[0]",
            ),
            (
                limit_rule(GLOBAL, "", None, Some(1), None, &["gpt-*-mini"]),
                "typed_config.rules[0].models[0]",
            ),
            // No authenticator in the chain: a tenant rule could never count.
            (
                limit_rule(TENANT_KEY, "", None, Some(1), None, &[]),
                "typed_config.rules[0].key",
            ),
        ];
        for (rule, path) in cases {
            assert_eq!(rules_error(&rules_config(vec![rule])), path);
        }
    }

    #[test]
    fn a_global_request_limit_counts_every_caller_together() {
        let factory = rules_factory(
            &rules_config(vec![limit_rule(GLOBAL, "", None, Some(2), None, &[])]),
            None,
        );
        let a = || RuleRequest {
            client: Some("10.0.0.1"),
            ..Default::default()
        };
        let b = || RuleRequest {
            client: Some("10.0.0.2"),
            ..Default::default()
        };
        assert_eq!(refused(&*factory, a()), None);
        assert_eq!(refused(&*factory, b()), None);
        assert_eq!(
            refused(&*factory, a()).as_deref(),
            Some("request rate exceeded")
        );
    }

    #[test]
    fn a_client_ip_limit_counts_each_address_alone() {
        let factory = rules_factory(
            &rules_config(vec![limit_rule(CLIENT_IP, "", None, Some(1), None, &[])]),
            None,
        );
        let from = |ip| RuleRequest {
            client: Some(ip),
            ..Default::default()
        };
        assert_eq!(refused(&*factory, from("10.0.0.1")), None);
        assert!(refused(&*factory, from("10.0.0.1")).is_some());
        assert_eq!(refused(&*factory, from("10.0.0.2")), None);
    }

    #[test]
    fn a_header_limit_buckets_on_the_hashed_value_and_skips_a_missing_header() {
        let factory = rules_factory(
            &rules_config(vec![limit_rule(
                HEADER,
                "X-Api-Key",
                None,
                Some(1),
                None,
                &[],
            )]),
            None,
        );
        let with = |value| RuleRequest {
            header: Some(("x-api-key", value)),
            ..Default::default()
        };
        assert_eq!(refused(&*factory, with("k-1")), None);
        assert!(refused(&*factory, with("k-1")).is_some());
        assert_eq!(refused(&*factory, with("k-2")), None);
        // Without the header the rule does not apply.
        assert_eq!(refused(&*factory, RuleRequest::default()), None);
        assert_eq!(refused(&*factory, RuleRequest::default()), None);
        let key = TokenLimitFilterInstance::rule_key(
            &parse_rules(&rules_config(vec![limit_rule(
                HEADER,
                "x-api-key",
                None,
                Some(1),
                None,
                &[],
            )]))
            .unwrap()[0],
            None,
            None,
            &{
                let mut head = request_headers(None);
                head.headers
                    .insert("x-api-key", HeaderValue::from_static("secret-value"));
                head
            },
        )
        .unwrap();
        assert!(!key.to_string().contains("secret-value"));
    }

    #[test]
    fn a_tenant_token_limit_counts_each_tenant_and_charges_usage() {
        let cp = control_plane();
        let factory = rules_factory(
            &rules_config(vec![limit_rule(TENANT_KEY, "", Some(10), None, None, &[])]),
            Some(&cp),
        );
        let as_tenant = |t| RuleRequest {
            tenant: Some(t),
            ..Default::default()
        };
        let (mut filter, mut cb, refusal) = send(&*factory, as_tenant("t1"));
        assert_eq!(refusal, None);
        cb.set_usage(usage(10));
        filter.encode_headers(&mut cb, &mut response_headers(), true);
        assert_eq!(
            refused(&*factory, as_tenant("t1")).as_deref(),
            Some("token budget exceeded")
        );
        assert_eq!(refused(&*factory, as_tenant("t2")), None);
    }

    #[test]
    fn a_concurrent_stream_limit_holds_a_slot_until_the_stream_completes() {
        let factory = rules_factory(
            &rules_config(vec![limit_rule(GLOBAL, "", None, None, Some(1), &[])]),
            None,
        );
        let (mut first, mut first_cb, refusal) = send(&*factory, RuleRequest::default());
        assert_eq!(refusal, None);
        assert_eq!(
            refused(&*factory, RuleRequest::default()).as_deref(),
            Some("too many concurrent streams")
        );
        first.on_stream_complete(&mut first_cb);
        assert_eq!(refused(&*factory, RuleRequest::default()), None);
    }

    #[test]
    fn a_models_scoped_rule_counts_only_matching_models_once_the_body_names_one() {
        let factory = rules_factory(
            &rules_config(vec![limit_rule(
                GLOBAL,
                "",
                None,
                Some(1),
                None,
                &["gpt-4*"],
            )]),
            None,
        );
        let model = |m| RuleRequest {
            model: m,
            ..Default::default()
        };
        assert_eq!(refused(&*factory, model(Some("gpt-4o"))), None);
        assert_eq!(
            refused(&*factory, model(Some("gpt-4o-mini"))).as_deref(),
            Some("request rate exceeded")
        );
        // Another model, or none named, is not counted by this rule.
        assert_eq!(refused(&*factory, model(Some("claude-3"))), None);
        assert_eq!(refused(&*factory, model(None)), None);
    }

    #[test]
    fn two_rules_on_one_bucket_count_once_against_the_lower_limit() {
        let factory = rules_factory(
            &rules_config(vec![
                limit_rule(GLOBAL, "", None, Some(3), None, &[]),
                limit_rule(GLOBAL, "", None, Some(2), None, &[]),
            ]),
            None,
        );
        assert_eq!(refused(&*factory, RuleRequest::default()), None);
        // Counted once per request: two admissions, not one.
        assert_eq!(refused(&*factory, RuleRequest::default()), None);
        assert!(refused(&*factory, RuleRequest::default()).is_some());
    }

    #[test]
    fn every_rule_that_applies_must_pass() {
        let factory = rules_factory(
            &rules_config(vec![
                limit_rule(GLOBAL, "", None, Some(10), None, &[]),
                limit_rule(CLIENT_IP, "", None, Some(1), None, &[]),
            ]),
            None,
        );
        assert_eq!(refused(&*factory, RuleRequest::default()), None);
        // The global rule has room; the client's own rule does not.
        assert!(refused(&*factory, RuleRequest::default()).is_some());
    }
}
