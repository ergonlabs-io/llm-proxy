//! Envoy v1.38 HTTP local rate limiting.
//!
//! The limiter is deliberately request-side only: a token is consumed before
//! the router sees a request.  A refusal is a local reply, so no upstream
//! request can escape after a bucket says no.
//!
//! This module owns the runtime mechanics and the HTTP-filter factory.  The
//! config/IR lane registers [`LocalRateLimitFilterFactory`] and supplies the
//! Envoy `LocalRateLimit` dynamic messages; it must not duplicate bucket
//! semantics here.

use std::any::Any;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use prost_reflect::{DynamicMessage, Value};

use proxy_config::ConfigError;
use proxy_http::filter::{
    DecoderCallbacks, EncoderCallbacks, FactoryContext, FilterDataStatus, FilterHeadersStatus,
    FilterInstanceFactory, HttpFilter, HttpFilterFactory, PerRouteConfig, RequestHeaders,
    ResponseHeaders,
};
use proxy_observability::ResponseFlag;

/// Envoy's registered HTTP filter type URL.
pub const TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit";

/// A token bucket starts full, refills in whole fill intervals, and never
/// exceeds `max_tokens`, matching Envoy's `TokenBucket` contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenBucketConfig {
    pub max_tokens: u32,
    pub tokens_per_fill: u32,
    pub fill_interval: Duration,
}

impl TokenBucketConfig {
    pub fn validate(&self, path: &str) -> Result<(), ConfigError> {
        if self.max_tokens == 0 {
            return Err(invalid(path, "max_tokens must be greater than zero"));
        }
        if self.tokens_per_fill == 0 {
            return Err(invalid(path, "tokens_per_fill must be greater than zero"));
        }
        // Envoy v1.38 requires this lower bound for HTTP local rate limit.
        if self.fill_interval < Duration::from_millis(50) {
            return Err(invalid(path, "fill_interval must be at least 50ms"));
        }
        Ok(())
    }
}

/// One key/value pair in an Envoy rate-limit descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DescriptorEntry {
    pub key: String,
    pub value: String,
}

/// A local descriptor overrides the default bucket only after a complete,
/// verbatim match. Envoy wildcard descriptor values need an LRU of dynamic
/// buckets; this module rejects them at config load until that state exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDescriptor {
    pub entries: Vec<DescriptorEntry>,
    pub token_bucket: TokenBucketConfig,
    pub shadow_mode: bool,
}

impl LocalDescriptor {
    fn matches(&self, request: &[DescriptorEntry]) -> bool {
        self.entries.len() == request.len()
            && self
                .entries
                .iter()
                .zip(request)
                .all(|(configured, actual)| {
                    configured.key == actual.key && configured.value == actual.value
                })
    }
}

/// The subset of Envoy rate-limit actions this module can turn into request
/// descriptors without reaching into protobufs on the hot path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorAction {
    GenericKey {
        key: String,
        value: String,
    },
    RequestHeader {
        header_name: HeaderName,
        descriptor_key: String,
        skip_if_absent: bool,
    },
}

impl DescriptorAction {
    fn append(&self, headers: &HeaderMap, target: &mut Vec<DescriptorEntry>) -> bool {
        match self {
            Self::GenericKey { key, value } => {
                target.push(DescriptorEntry {
                    key: key.clone(),
                    value: value.clone(),
                });
                true
            }
            Self::RequestHeader {
                header_name,
                descriptor_key,
                skip_if_absent,
            } => match headers
                .get(header_name)
                .and_then(|value| value.to_str().ok())
            {
                Some(value) => {
                    target.push(DescriptorEntry {
                        key: descriptor_key.clone(),
                        value: value.to_string(),
                    });
                    true
                }
                None => *skip_if_absent,
            },
        }
    }
}

/// Header mutation used on a locally rate-limited reply. The config parser
/// accepts Envoy's overwrite-or-add and append actions only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderMutation {
    pub name: HeaderName,
    pub value: HeaderValue,
    pub append: bool,
}

/// Parsed filter or per-route configuration. `enabled` and `enforced` are
/// booleans because this proxy has no Envoy runtime key-value subsystem: the
/// factory accepts only 0% or 100% static fractions and rejects all others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRateLimitConfig {
    pub stat_prefix: String,
    pub token_bucket: Option<TokenBucketConfig>,
    pub descriptors: Vec<LocalDescriptor>,
    pub descriptor_actions: Vec<Vec<DescriptorAction>>,
    pub always_consume_default_token_bucket: bool,
    pub enabled: bool,
    pub enforced: bool,
    pub status: StatusCode,
    pub response_headers_to_add: Vec<HeaderMutation>,
    pub enable_x_ratelimit_headers: bool,
}

impl LocalRateLimitConfig {
    /// A concise programmatic constructor for tests and config lowering.
    pub fn enabled(bucket: TokenBucketConfig) -> Self {
        Self {
            stat_prefix: "local_rate_limit".to_string(),
            token_bucket: Some(bucket),
            descriptors: Vec::new(),
            descriptor_actions: Vec::new(),
            always_consume_default_token_bucket: true,
            enabled: true,
            enforced: true,
            status: StatusCode::TOO_MANY_REQUESTS,
            response_headers_to_add: Vec::new(),
            enable_x_ratelimit_headers: false,
        }
    }

    fn validate(&self, per_route: bool) -> Result<(), ConfigError> {
        if self.stat_prefix.is_empty() {
            return Err(invalid("typed_config.stat_prefix", "must not be empty"));
        }
        if per_route && self.token_bucket.is_none() {
            return Err(invalid(
                "typed_per_filter_config.token_bucket",
                "token_bucket is required for per-route local rate limit configuration",
            ));
        }
        if let Some(bucket) = &self.token_bucket {
            bucket.validate("typed_config.token_bucket")?;
        }
        for (index, descriptor) in self.descriptors.iter().enumerate() {
            if descriptor.entries.is_empty() {
                return Err(invalid(
                    &format!("typed_config.descriptors[{index}].entries"),
                    "must contain at least one entry",
                ));
            }
            if descriptor
                .entries
                .iter()
                .any(|entry| entry.value.is_empty())
            {
                return Err(invalid(
                    &format!("typed_config.descriptors[{index}].entries"),
                    "wildcard descriptor values are not implemented",
                ));
            }
            descriptor
                .token_bucket
                .validate(&format!("typed_config.descriptors[{index}].token_bucket"))?;
            if let Some(default) = &self.token_bucket {
                if descriptor.token_bucket.fill_interval.as_nanos()
                    % default.fill_interval.as_nanos()
                    != 0
                {
                    return Err(invalid(
                        &format!("typed_config.descriptors[{index}].token_bucket.fill_interval"),
                        "must be a multiple of the default token bucket fill_interval",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: u32,
    last_fill: Instant,
}

impl Bucket {
    fn full(config: &TokenBucketConfig, now: Instant) -> Self {
        Self {
            tokens: config.max_tokens,
            last_fill: now,
        }
    }

    fn take(&mut self, config: &TokenBucketConfig, now: Instant) -> BucketResult {
        let intervals = now.saturating_duration_since(self.last_fill).as_nanos()
            / config.fill_interval.as_nanos();
        if intervals > 0 {
            let added = intervals.saturating_mul(u128::from(config.tokens_per_fill));
            self.tokens =
                (u128::from(self.tokens) + added).min(u128::from(config.max_tokens)) as u32;
            // Rust note: advance by complete intervals instead of setting
            // `last_fill = now`; a request just before a refill must not move
            // the periodic refill schedule.
            self.last_fill += config.fill_interval.saturating_mul(intervals as u32);
        }
        let reset_after = config
            .fill_interval
            .saturating_sub(now.saturating_duration_since(self.last_fill));
        if self.tokens == 0 {
            return BucketResult {
                allowed: false,
                remaining: 0,
                reset_after,
            };
        }
        self.tokens -= 1;
        BucketResult {
            allowed: true,
            remaining: self.tokens,
            reset_after,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct BucketResult {
    allowed: bool,
    remaining: u32,
    reset_after: Duration,
}

/// Result retained by the filter until encode headers, where Envoy emits the
/// optional `X-RateLimit-*` response fields for both allowed and refused
/// requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub shadow: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_after: Duration,
}

#[derive(Debug)]
struct LimiterState {
    default: Option<Bucket>,
    descriptors: Vec<Bucket>,
}

/// Thread-safe process-local bucket state. Factory-created filters share one
/// instance across workers; one HTTP filter instance remains per stream.
#[derive(Debug)]
pub struct LocalRateLimiter {
    config: Arc<LocalRateLimitConfig>,
    state: Mutex<LimiterState>,
}

impl LocalRateLimiter {
    pub fn new(config: Arc<LocalRateLimitConfig>, now: Instant) -> Result<Self, ConfigError> {
        config.validate(false)?;
        let default = config
            .token_bucket
            .as_ref()
            .map(|bucket| Bucket::full(bucket, now));
        let descriptors = config
            .descriptors
            .iter()
            .map(|descriptor| Bucket::full(&descriptor.token_bucket, now))
            .collect();
        Ok(Self {
            config,
            state: Mutex::new(LimiterState {
                default,
                descriptors,
            }),
        })
    }

    pub fn config(&self) -> &Arc<LocalRateLimitConfig> {
        &self.config
    }

    pub fn check(&self, headers: &HeaderMap, now: Instant) -> Option<RateLimitDecision> {
        if !self.config.enabled || self.config.token_bucket.is_none() {
            return None;
        }
        let descriptors = self.request_descriptors(headers);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);

        let mut selected: Option<(usize, bool)> = None;
        for descriptor in &descriptors {
            if let Some(index) = self
                .config
                .descriptors
                .iter()
                .position(|configured| configured.matches(descriptor))
            {
                selected = Some((index, self.config.descriptors[index].shadow_mode));
                break;
            }
        }

        let descriptor_result = selected.map(|(index, shadow)| {
            let result =
                state.descriptors[index].take(&self.config.descriptors[index].token_bucket, now);
            (
                result,
                shadow,
                self.config.descriptors[index].token_bucket.max_tokens,
            )
        });
        let consume_default = self.config.always_consume_default_token_bucket || selected.is_none();
        let default_result = if consume_default {
            let bucket = self.config.token_bucket.as_ref().expect("checked above");
            Some((
                state
                    .default
                    .as_mut()
                    .expect("default bucket exists")
                    .take(bucket, now),
                bucket.max_tokens,
            ))
        } else {
            None
        };

        // Envoy consults matching descriptor buckets before its default bucket.
        // The decision/header context is whichever bucket is closest to its
        // limit; this implementation selects a denied bucket first, then the
        // lower remaining-token bucket for an allowed request.
        let mut winner = default_result.map(|(result, limit)| (result, false, limit));
        if let Some((result, shadow, limit)) = descriptor_result {
            let replace = winner.is_none_or(|(current, _, _)| {
                (!result.allowed && current.allowed)
                    || (result.allowed == current.allowed && result.remaining < current.remaining)
            });
            if replace {
                winner = Some((result, shadow, limit));
            }
        }
        let (result, shadow, limit) = winner.expect("global bucket creates a decision");
        Some(RateLimitDecision {
            allowed: result.allowed,
            shadow: !result.allowed && shadow,
            limit,
            remaining: result.remaining,
            reset_after: result.reset_after,
        })
    }

    fn request_descriptors(&self, headers: &HeaderMap) -> Vec<Vec<DescriptorEntry>> {
        self.config
            .descriptor_actions
            .iter()
            .filter_map(|actions| {
                let mut descriptor = Vec::with_capacity(actions.len());
                actions
                    .iter()
                    .all(|action| action.append(headers, &mut descriptor))
                    .then_some(descriptor)
            })
            .collect()
    }
}

/// Route override held behind `PerRouteConfig`. Its limiter lives with the
/// parsed route config, so requests to different routes never share a bucket.
pub struct LocalRateLimitPerRouteConfig {
    limiter: Arc<LocalRateLimiter>,
}

impl LocalRateLimitPerRouteConfig {
    pub fn new(config: LocalRateLimitConfig, now: Instant) -> Result<Self, ConfigError> {
        config.validate(true)?;
        Ok(Self {
            limiter: Arc::new(LocalRateLimiter::new(Arc::new(config), now)?),
        })
    }
}

impl PerRouteConfig for LocalRateLimitPerRouteConfig {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Factory registered by the config/runtime wiring lane.
#[derive(Default)]
pub struct LocalRateLimitFilterFactory;

impl HttpFilterFactory for LocalRateLimitFilterFactory {
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
        let config = parse_config(config, false)?;
        // Config-time factories run once per worker. SharedFactoryState makes
        // the default process-local, matching Envoy's default scope instead
        // of accidentally multiplying a configured limit by worker count.
        let scope = format!("{}::local_ratelimit({config:?})", ctx.scope);
        let limiter = ctx
            .shared
            .get_or_try_init(&scope, &ctx.stat_prefix, TYPE_URL, || {
                Ok(
                    Arc::new(LocalRateLimiter::new(Arc::new(config), Instant::now())?)
                        as Arc<dyn Any + Send + Sync>,
                )
            })?
            .downcast::<LocalRateLimiter>()
            .expect("local rate limit singleton has its own type URL");
        Ok(Box::new(LocalRateLimitInstanceFactory { limiter }))
    }

    fn parse_per_route(
        &self,
        config: &DynamicMessage,
    ) -> Result<Arc<dyn PerRouteConfig>, ConfigError> {
        Ok(Arc::new(LocalRateLimitPerRouteConfig::new(
            parse_config(config, true)?,
            Instant::now(),
        )?))
    }
}

struct LocalRateLimitInstanceFactory {
    limiter: Arc<LocalRateLimiter>,
}

impl FilterInstanceFactory for LocalRateLimitInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(LocalRateLimitFilter {
            default: Arc::clone(&self.limiter),
            decision: None,
            emit_x_ratelimit_headers: false,
        })
    }
}

struct LocalRateLimitFilter {
    default: Arc<LocalRateLimiter>,
    decision: Option<RateLimitDecision>,
    emit_x_ratelimit_headers: bool,
}

impl LocalRateLimitFilter {
    fn effective_limiter(&self, cb: &mut dyn DecoderCallbacks) -> Arc<LocalRateLimiter> {
        cb.per_route_config()
            .and_then(|config| {
                config
                    .as_any()
                    .downcast_ref::<LocalRateLimitPerRouteConfig>()
                    .map(|config| Arc::clone(&config.limiter))
            })
            .unwrap_or_else(|| Arc::clone(&self.default))
    }

    fn add_standard_headers(headers: &mut HeaderMap, decision: RateLimitDecision) {
        // `HeaderValue::from_str` is total for decimal ASCII rendered here.
        headers.insert(
            "x-ratelimit-limit",
            HeaderValue::from_str(&decision.limit.to_string()).unwrap(),
        );
        headers.insert(
            "x-ratelimit-remaining",
            HeaderValue::from_str(&decision.remaining.to_string()).unwrap(),
        );
        headers.insert(
            "x-ratelimit-reset",
            HeaderValue::from_str(&decision.reset_after.as_secs().to_string()).unwrap(),
        );
    }
}

impl HttpFilter for LocalRateLimitFilter {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        let limiter = self.effective_limiter(cb);
        let Some(decision) = limiter.check(&headers.headers, Instant::now()) else {
            return FilterHeadersStatus::Continue;
        };
        self.decision = Some(decision);
        self.emit_x_ratelimit_headers = limiter.config().enable_x_ratelimit_headers;
        if decision.allowed || decision.shadow || !limiter.config().enforced {
            return FilterHeadersStatus::Continue;
        }

        let status = limiter.config().status;
        let mutations = limiter.config().response_headers_to_add.clone();
        let include_x_rate_limit = limiter.config().enable_x_ratelimit_headers;
        cb.stream_info()
            .set_response_flag(ResponseFlag::RateLimited);
        cb.send_local_reply(
            status,
            "local_rate_limited",
            Some(Box::new(move |headers| {
                headers.insert("x-envoy-ratelimited", HeaderValue::from_static("true"));
                for mutation in mutations {
                    if mutation.append {
                        headers.append(mutation.name, mutation.value);
                    } else {
                        headers.insert(mutation.name, mutation.value);
                    }
                }
                if include_x_rate_limit {
                    Self::add_standard_headers(headers, decision);
                }
            })),
            "local_rate_limited",
        );
        FilterHeadersStatus::StopIteration
    }

    fn encode_headers(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        headers: &mut ResponseHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        if let Some(decision) = self.decision {
            // Per Envoy, these optional headers describe the selected bucket
            // even when the request was admitted or shadow-limited.
            // `encode_headers` is not guaranteed to follow `decode_headers`,
            // hence the `Option` instead of assuming a decision exists.
            if self.emit_x_ratelimit_headers {
                Self::add_standard_headers(&mut headers.headers, decision);
            }
        }
        FilterHeadersStatus::Continue
    }

    fn encode_data(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        _data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        FilterDataStatus::Continue
    }
}

fn invalid(path: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: path.to_string(),
        reason: reason.into(),
    }
}

fn child_message(message: &DynamicMessage, field: &str) -> Option<DynamicMessage> {
    message
        .get_field_by_name(field)
        .and_then(|value| value.as_message().cloned())
}

fn parse_config(
    message: &DynamicMessage,
    per_route: bool,
) -> Result<LocalRateLimitConfig, ConfigError> {
    for field in [
        "request_headers_to_add_when_not_enforced",
        "local_rate_limit_per_downstream_connection",
        "local_cluster_rate_limit",
        "vh_rate_limits",
        "rate_limited_as_resource_exhausted",
        "max_dynamic_descriptors",
    ] {
        if message.has_field_by_name(field) {
            return Err(invalid(
                &format!("typed_config.{field}"),
                "field is not implemented",
            ));
        }
    }
    let stage = message
        .get_field_by_name("stage")
        .and_then(|value| value.as_u32())
        .unwrap_or(0);
    if stage != 0 {
        return Err(invalid("typed_config.stage", "only stage 0 is implemented"));
    }
    let stat_prefix = message
        .get_field_by_name("stat_prefix")
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default();
    let token_bucket = child_message(message, "token_bucket")
        .map(|bucket| parse_bucket(&bucket, "typed_config.token_bucket"))
        .transpose()?;
    let status = child_message(message, "status")
        .and_then(|status| {
            status
                .get_field_by_name("code")
                .and_then(|value| value.as_i32())
        })
        .and_then(|code| u16::try_from(code).ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .filter(|status| status.as_u16() >= 400)
        .unwrap_or(StatusCode::TOO_MANY_REQUESTS);
    let enabled = parse_fraction(message, "filter_enabled", false)?;
    let enforced = parse_fraction(message, "filter_enforced", false)?;
    let descriptors = list(message, "descriptors")
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let descriptor = value
                .as_message()
                .ok_or_else(|| invalid("typed_config.descriptors", "must contain messages"))?;
            parse_descriptor(descriptor, index)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let descriptor_actions = list(message, "rate_limits")
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let limit = value
                .as_message()
                .ok_or_else(|| invalid("typed_config.rate_limits", "must contain messages"))?;
            parse_actions(limit, index)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !descriptors.is_empty() && descriptor_actions.is_empty() {
        return Err(invalid(
            "typed_config.descriptors",
            "descriptors require typed_config.rate_limits because route rate-limit policies are not represented in the current IR",
        ));
    }
    let always_consume_default_token_bucket =
        child_message(message, "always_consume_default_token_bucket")
            .and_then(|value| {
                value
                    .get_field_by_name("value")
                    .and_then(|value| value.as_bool())
            })
            .unwrap_or(true);
    let response_headers_to_add = list(message, "response_headers_to_add")
        .iter()
        .enumerate()
        .map(|(index, value)| parse_header_mutation(value, index))
        .collect::<Result<Vec<_>, _>>()?;
    let enable_x_ratelimit_headers = message
        .get_field_by_name("enable_x_ratelimit_headers")
        .and_then(|value| value.as_i32())
        .unwrap_or(0)
        == 2;
    let config = LocalRateLimitConfig {
        stat_prefix,
        token_bucket,
        descriptors,
        descriptor_actions,
        always_consume_default_token_bucket,
        enabled,
        enforced,
        status,
        response_headers_to_add,
        enable_x_ratelimit_headers,
    };
    config.validate(per_route)?;
    Ok(config)
}

fn list(message: &DynamicMessage, field: &str) -> Vec<Value> {
    message
        .get_field_by_name(field)
        .and_then(|value| value.as_list().map(<[_]>::to_vec))
        .unwrap_or_default()
}

fn parse_bucket(message: &DynamicMessage, path: &str) -> Result<TokenBucketConfig, ConfigError> {
    let max_tokens = message
        .get_field_by_name("max_tokens")
        .and_then(|value| value.as_u32())
        .unwrap_or(0);
    let tokens_per_fill = child_message(message, "tokens_per_fill")
        .and_then(|value| {
            value
                .get_field_by_name("value")
                .and_then(|value| value.as_u32())
        })
        .unwrap_or(1);
    let fill_interval = child_message(message, "fill_interval")
        .ok_or_else(|| invalid(&format!("{path}.fill_interval"), "field is required"))?;
    let seconds = fill_interval
        .get_field_by_name("seconds")
        .and_then(|value| value.as_i64())
        .unwrap_or(0);
    let nanos = fill_interval
        .get_field_by_name("nanos")
        .and_then(|value| value.as_i32())
        .unwrap_or(0);
    if seconds < 0 || nanos < 0 {
        return Err(invalid(
            &format!("{path}.fill_interval"),
            "must be positive",
        ));
    }
    let config = TokenBucketConfig {
        max_tokens,
        tokens_per_fill,
        fill_interval: Duration::new(seconds as u64, nanos as u32),
    };
    config.validate(path)?;
    Ok(config)
}

fn parse_fraction(
    message: &DynamicMessage,
    field: &str,
    default: bool,
) -> Result<bool, ConfigError> {
    let Some(fraction) = child_message(message, field) else {
        return Ok(default);
    };
    if fraction
        .get_field_by_name("runtime_key")
        .and_then(|value| value.as_str().map(str::to_string))
        .is_some_and(|key| !key.is_empty())
    {
        return Err(invalid(
            &format!("typed_config.{field}.runtime_key"),
            "Envoy runtime keys are not implemented",
        ));
    }
    let default_value = child_message(&fraction, "default_value").ok_or_else(|| {
        invalid(
            &format!("typed_config.{field}.default_value"),
            "is required when the fraction is configured",
        )
    })?;
    let numerator = default_value
        .get_field_by_name("numerator")
        .and_then(|value| value.as_u32())
        .unwrap_or(0);
    let denominator = default_value
        .get_field_by_name("denominator")
        .and_then(|value| value.as_i32())
        .unwrap_or(0);
    match (numerator, denominator) {
        (0, _) => Ok(false),
        (100, 0) | (100, 1) => Ok(true),
        _ => Err(invalid(
            &format!("typed_config.{field}"),
            "only static 0% and 100% fractions are implemented",
        )),
    }
}

fn parse_descriptor(
    message: &DynamicMessage,
    index: usize,
) -> Result<LocalDescriptor, ConfigError> {
    let entries = list(message, "entries")
        .iter()
        .enumerate()
        .map(|(entry_index, value)| {
            let entry = value.as_message().ok_or_else(|| {
                invalid(
                    &format!("typed_config.descriptors[{index}].entries[{entry_index}]"),
                    "must be a message",
                )
            })?;
            let key = entry
                .get_field_by_name("key")
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_default();
            if key.is_empty() {
                return Err(invalid(
                    &format!("typed_config.descriptors[{index}].entries[{entry_index}].key"),
                    "must not be empty",
                ));
            }
            let value = entry
                .get_field_by_name("value")
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_default();
            if value.is_empty() {
                return Err(invalid(
                    &format!("typed_config.descriptors[{index}].entries[{entry_index}].value"),
                    "wildcard descriptor values are not implemented",
                ));
            }
            Ok(DescriptorEntry { key, value })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let bucket = child_message(message, "token_bucket").ok_or_else(|| {
        invalid(
            &format!("typed_config.descriptors[{index}].token_bucket"),
            "field is required",
        )
    })?;
    Ok(LocalDescriptor {
        entries,
        token_bucket: parse_bucket(
            &bucket,
            &format!("typed_config.descriptors[{index}].token_bucket"),
        )?,
        shadow_mode: message
            .get_field_by_name("shadow_mode")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
    })
}

fn parse_actions(
    message: &DynamicMessage,
    limit_index: usize,
) -> Result<Vec<DescriptorAction>, ConfigError> {
    list(message, "actions")
        .iter()
        .enumerate()
        .map(|(action_index, value)| {
            let action = value
                .as_message()
                .ok_or_else(|| invalid("typed_config.rate_limits", "must contain messages"))?;
            let path = format!("typed_config.rate_limits[{limit_index}].actions[{action_index}]");
            if let Some(generic) = child_message(action, "generic_key") {
                let key = generic
                    .get_field_by_name("descriptor_key")
                    .and_then(|value| value.as_str().map(str::to_string))
                    .unwrap_or_default();
                let value = generic
                    .get_field_by_name("descriptor_value")
                    .and_then(|value| value.as_str().map(str::to_string))
                    .unwrap_or_default();
                if key.is_empty() || value.is_empty() {
                    return Err(invalid(
                        &path,
                        "generic_key requires descriptor_key and descriptor_value",
                    ));
                }
                return Ok(DescriptorAction::GenericKey { key, value });
            }
            if let Some(request) = child_message(action, "request_headers") {
                let header_name = request
                    .get_field_by_name("header_name")
                    .and_then(|value| value.as_str().map(str::to_string))
                    .and_then(|name| HeaderName::from_bytes(name.as_bytes()).ok())
                    .ok_or_else(|| {
                        invalid(
                            &format!("{path}.request_headers.header_name"),
                            "must be a valid header name",
                        )
                    })?;
                let descriptor_key = request
                    .get_field_by_name("descriptor_key")
                    .and_then(|value| value.as_str().map(str::to_string))
                    .unwrap_or_default();
                if descriptor_key.is_empty() {
                    return Err(invalid(
                        &format!("{path}.request_headers.descriptor_key"),
                        "must not be empty",
                    ));
                }
                return Ok(DescriptorAction::RequestHeader {
                    header_name,
                    descriptor_key,
                    skip_if_absent: request
                        .get_field_by_name("skip_if_absent")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(false),
                });
            }
            Err(invalid(
                &path,
                "only generic_key and request_headers actions are implemented",
            ))
        })
        .collect()
}

fn parse_header_mutation(value: &Value, index: usize) -> Result<HeaderMutation, ConfigError> {
    let option = value.as_message().ok_or_else(|| {
        invalid(
            "typed_config.response_headers_to_add",
            "must contain messages",
        )
    })?;
    let header = child_message(option, "header").ok_or_else(|| {
        invalid(
            &format!("typed_config.response_headers_to_add[{index}].header"),
            "field is required",
        )
    })?;
    let name = header
        .get_field_by_name("key")
        .and_then(|value| value.as_str().map(str::to_string))
        .and_then(|name| HeaderName::from_bytes(name.as_bytes()).ok())
        .ok_or_else(|| {
            invalid(
                &format!("typed_config.response_headers_to_add[{index}].header.key"),
                "must be a valid header name",
            )
        })?;
    let value = header
        .get_field_by_name("value")
        .and_then(|value| value.as_str().map(str::to_string))
        .and_then(|value| HeaderValue::from_str(&value).ok())
        .ok_or_else(|| {
            invalid(
                &format!("typed_config.response_headers_to_add[{index}].header.value"),
                "must be a valid header value",
            )
        })?;
    let action = option
        .get_field_by_name("append_action")
        .and_then(|value| value.as_i32())
        .unwrap_or(0);
    match action {
        2 => Ok(HeaderMutation {
            name,
            value,
            append: false,
        }),
        0 => Ok(HeaderMutation {
            name,
            value,
            append: true,
        }),
        _ => Err(invalid(
            &format!("typed_config.response_headers_to_add[{index}].append_action"),
            "only APPEND_IF_EXISTS_OR_ADD and OVERWRITE_IF_EXISTS_OR_ADD are implemented",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{RefCell, RefMut};

    use proxy_http::filter::{BufferedBody, HeaderMutationFn};
    use proxy_http::stream_info::StreamInfo;

    struct TestCallbacks {
        stream_info: RefCell<StreamInfo>,
        reply: Option<(StatusCode, HeaderMap, String)>,
    }

    impl Default for TestCallbacks {
        fn default() -> Self {
            Self {
                stream_info: RefCell::new(StreamInfo::default()),
                reply: None,
            }
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
            if let Some(mutate) = modify_headers {
                mutate(&mut headers);
            }
            self.reply = Some((code, headers, body.to_string()));
        }

        fn continue_decoding(&mut self) {
            unreachable!("local rate limit never stops without a local reply")
        }

        fn add_decoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unreachable!("local rate limit never buffers request data")
        }

        fn inject_decoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unreachable!("local rate limit never injects request data")
        }

        fn decoding_buffer(&self) -> Option<&BufferedBody> {
            unreachable!("local rate limit never buffers request data")
        }

        fn modify_decoding_buffer(&mut self, _f: &mut dyn FnMut(&mut bytes::BytesMut)) {
            unreachable!("local rate limit never buffers request data")
        }

        fn route(&mut self) -> Option<Arc<proxy_config::ir::RouteEntry>> {
            None
        }

        fn clear_route_cache(&mut self) {
            unreachable!("local rate limit does not rewrite route inputs")
        }

        fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
            None
        }

        fn stream_info(&mut self) -> RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    fn bucket(max_tokens: u32) -> TokenBucketConfig {
        TokenBucketConfig {
            max_tokens,
            tokens_per_fill: 1,
            fill_interval: Duration::from_secs(1),
        }
    }

    #[test]
    fn full_bucket_allows_then_refills_on_its_original_schedule() {
        let now = Instant::now();
        let limiter =
            LocalRateLimiter::new(Arc::new(LocalRateLimitConfig::enabled(bucket(2))), now).unwrap();
        let headers = HeaderMap::new();
        assert!(limiter.check(&headers, now).unwrap().allowed);
        assert!(limiter.check(&headers, now).unwrap().allowed);
        assert!(!limiter.check(&headers, now).unwrap().allowed);
        assert!(
            limiter
                .check(&headers, now + Duration::from_secs(1))
                .unwrap()
                .allowed
        );
    }

    #[test]
    fn matching_descriptor_overrides_default() {
        let now = Instant::now();
        let mut config = LocalRateLimitConfig::enabled(bucket(10));
        config.always_consume_default_token_bucket = false;
        config.descriptors = vec![LocalDescriptor {
            entries: vec![DescriptorEntry {
                key: "tenant".to_string(),
                value: "a".to_string(),
            }],
            token_bucket: bucket(1),
            shadow_mode: false,
        }];
        config.descriptor_actions = vec![vec![DescriptorAction::RequestHeader {
            header_name: HeaderName::from_static("x-tenant"),
            descriptor_key: "tenant".to_string(),
            skip_if_absent: false,
        }]];
        let limiter = LocalRateLimiter::new(Arc::new(config), now).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant", HeaderValue::from_static("a"));
        assert!(limiter.check(&headers, now).unwrap().allowed);
        assert!(!limiter.check(&headers, now).unwrap().allowed);
    }

    #[test]
    fn descriptor_shadow_mode_never_refuses() {
        let now = Instant::now();
        let mut config = LocalRateLimitConfig::enabled(bucket(10));
        config.always_consume_default_token_bucket = false;
        config.descriptors = vec![LocalDescriptor {
            entries: vec![DescriptorEntry {
                key: "kind".to_string(),
                value: "free".to_string(),
            }],
            token_bucket: bucket(1),
            shadow_mode: true,
        }];
        config.descriptor_actions = vec![vec![DescriptorAction::GenericKey {
            key: "kind".to_string(),
            value: "free".to_string(),
        }]];
        let limiter = LocalRateLimiter::new(Arc::new(config), now).unwrap();
        let headers = HeaderMap::new();
        assert!(limiter.check(&headers, now).unwrap().allowed);
        let denied = limiter.check(&headers, now).unwrap();
        assert!(!denied.allowed);
        assert!(denied.shadow);
    }

    #[test]
    fn descriptor_interval_must_be_a_default_interval_multiple() {
        let mut config = LocalRateLimitConfig::enabled(bucket(10));
        config.descriptors.push(LocalDescriptor {
            entries: vec![DescriptorEntry {
                key: "kind".to_string(),
                value: "free".to_string(),
            }],
            token_bucket: TokenBucketConfig {
                fill_interval: Duration::from_millis(150),
                ..bucket(1)
            },
            shadow_mode: false,
        });
        let error = LocalRateLimiter::new(Arc::new(config), Instant::now()).unwrap_err();
        assert!(format!("{error}").contains("multiple"));
    }

    #[test]
    fn enforced_limit_returns_429_with_envoy_and_opt_in_standard_headers() {
        let now = Instant::now();
        let mut config = LocalRateLimitConfig::enabled(bucket(1));
        config.enable_x_ratelimit_headers = true;
        config.response_headers_to_add.push(HeaderMutation {
            name: HeaderName::from_static("x-local-limit"),
            value: HeaderValue::from_static("yes"),
            append: false,
        });
        let limiter = Arc::new(LocalRateLimiter::new(Arc::new(config), now).unwrap());
        let mut first = LocalRateLimitFilter {
            default: Arc::clone(&limiter),
            decision: None,
            emit_x_ratelimit_headers: false,
        };
        let mut second = LocalRateLimitFilter {
            default: limiter,
            decision: None,
            emit_x_ratelimit_headers: false,
        };
        let mut first_cb = TestCallbacks::default();
        let mut second_cb = TestCallbacks::default();
        let mut request = RequestHeaders {
            method: http::Method::GET,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
        };
        assert_eq!(
            first.decode_headers(&mut first_cb, &mut request, true),
            FilterHeadersStatus::Continue
        );
        assert_eq!(
            second.decode_headers(&mut second_cb, &mut request, true),
            FilterHeadersStatus::StopIteration
        );
        let (status, headers, body) = second_cb.reply.expect("second request must be refused");
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, "local_rate_limited");
        assert_eq!(headers.get("x-envoy-ratelimited").unwrap(), "true");
        assert_eq!(headers.get("x-ratelimit-limit").unwrap(), "1");
        assert_eq!(headers.get("x-ratelimit-remaining").unwrap(), "0");
        assert_eq!(headers.get("x-local-limit").unwrap(), "yes");
        assert_eq!(
            proxy_observability::flags::render_flags(
                &second_cb.stream_info.borrow().response_flags().to_vec()
            ),
            "RL"
        );
    }
}
