//! WP-33a — wires the WP-34 [`crate::usage`] extractor into the real HTTP
//! encode path.
//!
//! This is the filter that actually watches response bytes go by: it picks a
//! parsing strategy off `content-type`, feeds bytes to the right extractor as
//! they arrive, and writes the result (plus TTFT/inter-chunk timing) into
//! [`StreamInfo::llm`] once the response ends.
//!
//! # The one rule that matters more than any other
//!
//! This filter must **never** buffer the response. WP-33's whole product bet
//! is that a client streaming tokens from an LLM sees them as they're
//! generated, not after the proxy has assembled the full response. See the
//! `// Rust note:` on [`UsageFilterInstance::encode_data`] for the mechanical
//! guarantee.
//!
//! # Config: owned `llmproxy.filters.v0.Usage`
//!
//! The filter owns its dialect field and its opaque pricing JSON carrier.
//! Pricing remains JSON because its strict schema is shared with the dialect
//! price-list surface and is validated by this filter at listener creation.
//! The old `DataSource` shape remains accepted for one release through
//! [`LegacyUsageFilterFactory`].

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use prost_reflect::DynamicMessage;

use proxy_config::ConfigError;

use proxy_http::filter::{
    EncoderCallbacks, FactoryContext, FilterDataStatus, FilterHeadersStatus, FilterInstanceFactory,
    FilterTrailersStatus, HttpFilter, HttpFilterFactory, PerRouteConfig, ResponseHeaders,
    ResponseTrailers,
};
use proxy_http::stream_info::GenAiSystem;
use proxy_http::{LlmListCost, LlmTokenUsage};
use serde::Deserialize;

use crate::pricing::{PriceEntry, PriceList, Tier, TierBasis, TierMode};
use crate::usage::{extract_json_usage, Dialect, SseUsageScanner, TokenUsage};

/// Canonical type URL for the owned usage configuration.
pub const TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.Usage";

/// Shared live rate-card state. A request clones the current pricing context
/// when its filter instance is created, so an admin update can never re-price
/// a response already in flight.
pub struct PricingRegistry {
    current: RwLock<Option<PricingContext>>,
}

impl PricingRegistry {
    fn new(initial: Option<PricingContext>) -> Self {
        Self {
            current: RwLock::new(initial),
        }
    }

    pub(crate) fn new_for_spend() -> Self {
        Self::new(None)
    }

    fn snapshot(&self) -> Option<PricingContext> {
        self.current
            .read()
            .expect("pricing registry lock poisoned")
            .clone()
    }

    /// Seed a registry created by a preceding spend filter. Filter factories
    /// are built in chain order, while spend enforcement must precede usage
    /// extraction on the encode path.
    pub(crate) fn install_if_empty(&self, initial: Option<PricingContext>) {
        let mut current = self
            .current
            .write()
            .expect("pricing registry lock poisoned");
        if current.is_none() {
            *current = initial;
        }
    }

    /// Compute a dollar-enforcement charge from the current list card. Round
    /// nanodollars up to microdollars so enforcement never undercharges a
    /// request because of unit conversion.
    pub fn cost_micro_usd(
        &self,
        cluster: Option<&str>,
        model: Option<&str>,
        usage: &TokenUsage,
    ) -> Option<u64> {
        let pricing = self.snapshot()?;
        let cluster = cluster?;
        let model = model?;
        let provider = pricing.providers.get(cluster)?;
        pricing
            .list
            .list_cost_nanodollars(provider, model, usage)
            .map(|nano| nano.saturating_add(999) / 1000)
    }

    /// Replace the card after validating the same wire shape used at startup.
    pub fn replace_json(&self, json: &str) -> Result<String, ConfigError> {
        let wire: PricingWire = serde_json::from_str(json)
            .map_err(|e| invalid_config(format!("pricing update is invalid JSON: {e}")))?;
        let parsed = parse_pricing(wire)?;
        let version = parsed.list.version().as_str().to_string();
        *self
            .current
            .write()
            .expect("pricing registry lock poisoned") = Some(parsed);
        Ok(version)
    }
}

/// Borrowed type URL accepted for one release after the WP-47 migration.
pub const LEGACY_TYPE_URL: &str = "type.llmproxy.dev/envoy.config.core.v3.DataSource";

/// Upper bound on the response body this filter will accumulate to parse as a
/// single non-streaming JSON document. A response over this size still
/// streams through to the client untouched (see [`UsageFilterInstance::encode_data`]) —
/// this cap only decides whether *we* keep trying to compute usage for it.
pub const MAX_JSON_BODY_BYTES: usize = 1 << 20; // 1 MiB

/// Convert a [`TokenUsage`] into the [`LlmTokenUsage`] that `StreamInfo`
/// carries. All four cost buckets cross the boundary intact — dropping the
/// cache buckets would leave anything downstream (billing, the WP-34 token
/// limiter) unable to compute a correct cost, since the buckets are priced
/// differently.
///
/// Rust note: `From` is the idiomatic "one type converts unambiguously into
/// another" trait; implementing it here (rather than a free function) lets
/// callers write `usage.into()` and is what `stream_info.rs`'s doc comment on
/// `LlmTokenUsage` means by "the usage filter converts at its boundary".
impl From<TokenUsage> for LlmTokenUsage {
    fn from(usage: TokenUsage) -> Self {
        LlmTokenUsage {
            input_tokens: usage.input_tokens,
            cached_tokens: usage.cached_tokens,
            cache_creation_tokens: usage.cache_creation_tokens,
            output_tokens: usage.output_tokens,
        }
    }
}

/// [`HttpFilterFactory`] for [`TYPE_URL`].
#[derive(Default)]
pub struct UsageFilterFactory;

impl HttpFilterFactory for UsageFilterFactory {
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
        let parsed = parse_owned_factory_config(config)?;
        let initial = parsed.pricing.clone();
        let registry =
            ctx.shared
                .get_or_try_init(&ctx.scope, &ctx.stat_prefix, TYPE_URL, || {
                    Ok(Arc::new(PricingRegistry::new(initial.clone()))
                        as Arc<dyn std::any::Any + Send + Sync>)
                })?;
        let registry = registry
            .downcast::<PricingRegistry>()
            .map_err(|_| invalid_config("pricing registry type collision"))?;
        registry.install_if_empty(initial);
        Ok(Box::new(UsageFilterInstanceFactory {
            dialect: parsed.dialect,
            registry,
        }))
    }

    fn parse_per_route(
        &self,
        config: &DynamicMessage,
    ) -> Result<Arc<dyn PerRouteConfig>, ConfigError> {
        let dialect = parse_owned_config(config)?;
        Ok(Arc::new(UsagePerRouteConfig(dialect)))
    }
}

/// Parse one dialect value with a caller-supplied wire field path.
fn parse_dialect(raw: String, field_path: &str) -> Result<Dialect, ConfigError> {
    let raw = raw.to_ascii_lowercase();
    match raw.as_str() {
        "openai" => Ok(Dialect::OpenAi),
        "anthropic" => Ok(Dialect::Anthropic),
        _ => Err(ConfigError::InvalidValue {
            field_path: field_path.to_string(),
            reason: format!("expected `openai` or `anthropic`, got `{raw}`"),
        }),
    }
}

/// Read the dialect out of an owned `Usage` typed config.
fn parse_owned_config(config: &DynamicMessage) -> Result<Dialect, ConfigError> {
    let raw = config
        .get_field_by_name("dialect")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    parse_dialect(raw, "typed_config.dialect")
}

/// Read the dialect out of the borrowed `DataSource` compatibility config.
fn parse_legacy_config(config: &DynamicMessage) -> Result<Dialect, ConfigError> {
    let raw = config
        .get_field_by_name("inline_string")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    parse_dialect(raw, "typed_config.inline_string")
}

/// The old DataSource carrier accepted a bare dialect or a strict JSON object.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FactoryWire {
    dialect: String,
    price_list: PriceListWire,
    providers: HashMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PriceListWire {
    #[serde(default)]
    version: Option<String>,
    effective_from: String,
    entries: Vec<PriceEntryWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PriceEntryWire {
    provider_type: String,
    model: String,
    tier_mode: String,
    tiers: Vec<TierWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TierWire {
    #[serde(default)]
    up_to: Option<u64>,
    input_nanodollars_per_token: u64,
    cached_input_nanodollars_per_token: u64,
    cache_write_nanodollars_per_token: u64,
    output_nanodollars_per_token: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PricingWire {
    price_list: PriceListWire,
    providers: HashMap<String, String>,
}

#[derive(Clone)]
pub(crate) struct PricingContext {
    list: PriceList,
    /// Actual dialled cluster -> configured provider type.  A route can point
    /// at an aggregate/fallback, so this must not be inferred from dialect.
    providers: HashMap<String, String>,
}

struct ParsedFactoryConfig {
    dialect: Dialect,
    pricing: Option<PricingContext>,
}

fn invalid_config(reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: "typed_config.inline_string".to_string(),
        reason: reason.into(),
    }
}

fn parse_pricing(wire: PricingWire) -> Result<PricingContext, ConfigError> {
    let effective_from = chrono::DateTime::parse_from_rfc3339(&wire.price_list.effective_from)
        .map_err(|e| invalid_config(format!("price_list.effective_from must be RFC3339: {e}")))?
        .with_timezone(&chrono::Utc)
        .into();
    let mut entries = Vec::with_capacity(wire.price_list.entries.len());
    for (entry_index, entry) in wire.price_list.entries.into_iter().enumerate() {
        if entry.provider_type.is_empty() || entry.model.is_empty() || entry.tiers.is_empty() {
            return Err(invalid_config(format!(
                "price_list.entries[{entry_index}] requires provider_type, model, and tiers"
            )));
        }
        let tier_mode = match entry.tier_mode.as_str() {
            "whole_request" => TierMode::WholeRequest,
            "graduated" => TierMode::Graduated,
            other => return Err(invalid_config(format!("price_list.entries[{entry_index}].tier_mode must be whole_request or graduated, got `{other}`"))),
        };
        let mut previous = None;
        for (tier_index, tier) in entry.tiers.iter().enumerate() {
            if tier.up_to.is_none() && tier_index + 1 != entry.tiers.len() {
                return Err(invalid_config(format!("price_list.entries[{entry_index}].tiers[{tier_index}] open-ended tier must be last")));
            }
            if tier
                .up_to
                .is_some_and(|up_to| previous.is_some_and(|p| up_to <= p))
            {
                return Err(invalid_config(format!("price_list.entries[{entry_index}].tiers[{tier_index}].up_to must strictly increase")));
            }
            if tier.up_to.is_some() {
                previous = tier.up_to;
            }
        }
        if entry.tiers.last().is_some_and(|tier| tier.up_to.is_some()) {
            return Err(invalid_config(format!(
                "price_list.entries[{entry_index}].tiers requires a final open-ended tier"
            )));
        }
        entries.push(PriceEntry {
            provider_type: entry.provider_type,
            model: entry.model,
            tier_basis: TierBasis::InputTokens,
            tier_mode,
            tiers: entry
                .tiers
                .into_iter()
                .map(|tier| Tier {
                    up_to: tier.up_to,
                    input_nanodollars_per_token: tier.input_nanodollars_per_token,
                    cached_input_nanodollars_per_token: tier.cached_input_nanodollars_per_token,
                    cache_write_nanodollars_per_token: tier.cache_write_nanodollars_per_token,
                    output_nanodollars_per_token: tier.output_nanodollars_per_token,
                })
                .collect(),
        });
    }
    Ok(PricingContext {
        list: PriceList::new(wire.price_list.version.as_deref(), effective_from, entries),
        providers: wire.providers,
    })
}

fn parse_owned_factory_config(config: &DynamicMessage) -> Result<ParsedFactoryConfig, ConfigError> {
    let dialect = parse_owned_config(config)?;
    let pricing_json = config
        .get_field_by_name("pricing_json")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let pricing = if pricing_json.trim().is_empty() {
        None
    } else {
        let wire: PricingWire =
            serde_json::from_str(&pricing_json).map_err(|e| ConfigError::InvalidValue {
                field_path: "typed_config.pricing_json".to_string(),
                reason: format!("invalid pricing configuration: {e}"),
            })?;
        Some(parse_pricing(wire).map_err(|error| match error {
            ConfigError::InvalidValue { reason, .. } => ConfigError::InvalidValue {
                field_path: "typed_config.pricing_json".to_string(),
                reason,
            },
            other => other,
        })?)
    };
    Ok(ParsedFactoryConfig { dialect, pricing })
}

fn parse_legacy_factory_config(
    config: &DynamicMessage,
) -> Result<ParsedFactoryConfig, ConfigError> {
    let raw = config
        .get_field_by_name("inline_string")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    if !raw.trim_start().starts_with('{') {
        return Ok(ParsedFactoryConfig {
            dialect: parse_legacy_config(config)?,
            pricing: None,
        });
    }
    let wire: FactoryWire = serde_json::from_str(&raw)
        .map_err(|e| invalid_config(format!("invalid pricing configuration: {e}")))?;
    let dialect = parse_dialect(wire.dialect, "typed_config.inline_string")?;
    let pricing = parse_pricing(PricingWire {
        price_list: wire.price_list,
        providers: wire.providers,
    })?;
    Ok(ParsedFactoryConfig {
        dialect,
        pricing: Some(pricing),
    })
}

/// Decoder for [`LEGACY_TYPE_URL`]. It retains old `DataSource` field paths
/// while making the compatibility path visible during migration.
#[derive(Default)]
pub struct LegacyUsageFilterFactory;

fn warn_legacy_config() {
    tracing::warn!(
        legacy_type_url = LEGACY_TYPE_URL,
        replacement_type_url = TYPE_URL,
        "llmproxy.usage uses a deprecated borrowed typed_config; migrate to llmproxy.filters.v0.Usage before the next release"
    );
}

impl HttpFilterFactory for LegacyUsageFilterFactory {
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
        let parsed = parse_legacy_factory_config(config)?;
        Ok(Box::new(UsageFilterInstanceFactory {
            dialect: parsed.dialect,
            registry: Arc::new(PricingRegistry::new(parsed.pricing)),
        }))
    }

    fn parse_per_route(
        &self,
        config: &DynamicMessage,
    ) -> Result<Arc<dyn PerRouteConfig>, ConfigError> {
        warn_legacy_config();
        Ok(Arc::new(UsagePerRouteConfig(parse_legacy_config(config)?)))
    }
}

/// Created once per (filter config, listener); stateless beyond the parsed
/// dialect, so building a fresh per-stream instance is cheap.
struct UsagePerRouteConfig(Dialect);

impl PerRouteConfig for UsagePerRouteConfig {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct UsageFilterInstanceFactory {
    dialect: Dialect,
    registry: Arc<PricingRegistry>,
}

impl FilterInstanceFactory for UsageFilterInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(UsageFilterInstance {
            dialect: self.dialect,
            pricing: self.registry.snapshot(),
            mode: BodyMode::Inert,
            headers_at: None,
            last_chunk_at: None,
            time_to_first_byte: None,
            time_to_first_body_byte: None,
            max_inter_chunk: None,
            response_chunks: 0,
            finalized: false,
        })
    }
}

/// Rust note: an enum used as a small state machine — which strategy (if any)
/// this stream's body is being read with. Matching on it is exhaustive, so
/// adding a fourth mode later forces every call site here to decide what it
/// does in that case (ground rule #1's spirit, applied to our own code).
enum BodyMode {
    /// `text/event-stream`: feed chunks to the incremental SSE scanner.
    Sse(SseUsageScanner),
    /// `application/json`: accumulate the body, up to [`MAX_JSON_BODY_BYTES`].
    Json(BytesMut),
    /// Anything else (including "haven't seen headers yet"): do nothing.
    Inert,
}

/// Per-stream instance. One of these is created per response, per the frozen
/// `HttpFilter` contract (see `filter.rs`'s module doc) — so `!Send` interior
/// state (plain fields here, no `Rc`/`RefCell` needed) is safe: it never
/// leaves the worker thread that owns this stream.
struct UsageFilterInstance {
    dialect: Dialect,
    pricing: Option<PricingContext>,
    mode: BodyMode,
    /// When response headers were flushed — the TTFT baseline. `Instant`
    /// (not `SystemTime`) because we only ever compare it to another `Instant`
    /// on the same clock to get a duration; we never need it as a wall-clock
    /// timestamp.
    headers_at: Option<Instant>,
    /// When the previous response body chunk arrived. `None` means "no chunk
    /// yet" — the same `Option<Instant>` pattern as `headers_at`, distinct
    /// from `Some(Instant)` meaning "seen one, here's when".
    last_chunk_at: Option<Instant>,
    time_to_first_byte: Option<Duration>,
    /// Request-entered-HCM → first response-body byte. Kept separately from
    /// `time_to_first_byte`, whose response-header baseline is an
    /// access-log compatibility contract.
    time_to_first_body_byte: Option<Duration>,
    max_inter_chunk: Option<Duration>,
    response_chunks: u64,
    /// Guards against writing `StreamInfo` twice — `encode_data` with
    /// `end_stream=true` and a later `encode_trailers` (or vice versa) must
    /// not both finalize.
    finalized: bool,
}

/// Pick a [`BodyMode`] from the response's `content-type`, matching only the
/// media type (before any `;` parameters), ASCII-case-insensitively. Absent
/// or unrecognized content types get [`BodyMode::Inert`] — we do not guess.
fn classify_body(headers: &HeaderMap, dialect: Dialect) -> BodyMode {
    let Some(value) = headers.get(http::header::CONTENT_TYPE) else {
        return BodyMode::Inert;
    };
    let Ok(value) = value.to_str() else {
        return BodyMode::Inert;
    };
    let media_type = value.split(';').next().unwrap_or("").trim();

    if media_type.eq_ignore_ascii_case("text/event-stream") {
        BodyMode::Sse(SseUsageScanner::new(dialect))
    } else if media_type.eq_ignore_ascii_case("application/json") {
        BodyMode::Json(BytesMut::new())
    } else {
        BodyMode::Inert
    }
}

impl UsageFilterInstance {
    /// Update chunk-timing bookkeeping for one arriving body chunk. Called
    /// once per `encode_data`, before the chunk is handed to the body-mode
    /// scanner, so timing is tracked even in [`BodyMode::Inert`].
    fn record_chunk_timing(&mut self, cb: &mut dyn EncoderCallbacks) {
        let now = Instant::now();
        // The gap is measured from the previous chunk, or — for the very
        // first chunk — from when headers flushed (the TTFT definition).
        let previous = self.last_chunk_at.or(self.headers_at).unwrap_or(now); // encode_headers always runs first in practice;
                                                                              // this fallback just avoids a negative/undefined gap if it somehow didn't.
        let gap = now.duration_since(previous);

        if self.response_chunks == 0 {
            self.time_to_first_byte = Some(gap);
            self.time_to_first_body_byte =
                Some(cb.stream_info().elapsed_since_request_started(now));
        } else {
            self.max_inter_chunk = Some(match self.max_inter_chunk {
                Some(running_max) => running_max.max(gap),
                None => gap,
            });
        }

        self.response_chunks += 1;
        self.last_chunk_at = Some(now);
    }

    /// Convert the IR's cluster-level usage dialect to the filter's parsed
    /// dialect enum, preserving the one-source-of-truth mapping for the selected
    /// upstream member.
    fn resolve_cluster_dialect(cluster_dialect: proxy_config::ir::UsageDialect) -> Dialect {
        match cluster_dialect {
            proxy_config::ir::UsageDialect::OpenAi => Dialect::OpenAi,
            proxy_config::ir::UsageDialect::Anthropic => Dialect::Anthropic,
        }
    }

    /// Compute the final usage (if any) for the current body mode, without
    /// consuming `self.mode` — cheap enough (an `Option<TokenUsage>` and a
    /// JSON parse of an already-bounded buffer) that borrowing is simplest.
    fn compute_usage(&self) -> Option<TokenUsage> {
        match &self.mode {
            BodyMode::Sse(scanner) => scanner.usage(),
            BodyMode::Json(buf) => extract_json_usage(self.dialect, buf),
            BodyMode::Inert => None,
        }
    }

    /// Write the observed usage + timing into `StreamInfo::llm`, exactly
    /// once. Safe to call from more than one callback (`encode_data` at
    /// `end_stream`, `encode_trailers`) — the second call is a no-op.
    fn finalize(&mut self, cb: &mut dyn EncoderCallbacks) {
        if self.finalized {
            return;
        }
        self.finalized = true;

        let usage = self.compute_usage();
        // Rust note: `stream_info()` hands back a `RefMut` guard, not a plain
        // `&mut` — the stream's single `StreamInfo` is shared (`Rc<RefCell<_>>`)
        // between the filter chain and the router. `RefMut` derefs to
        // `&mut StreamInfo`, so the field writes below are unchanged; the guard
        // just must not be held across another `cb` call, or the `RefCell`
        // panics. It's dropped at the end of this function.
        let mut stream_info = cb.stream_info();
        // `None` must stay `None` here — never write `Some(0, 0)` for a
        // response that reported no usage at all (WP-34's rule; this number
        // feeds billing, and a wrong zero is worse than an honest "unknown").
        stream_info.llm.usage = usage.map(LlmTokenUsage::from);
        // The card is evaluated only after the terminal usage extractor has
        // seen the complete response. In particular, an SSE stream's partial
        // chunks cannot create a provisional price that later changes.
        stream_info.llm.list_cost = usage.and_then(|usage| {
            let pricing = self.pricing.as_ref()?;
            let cluster = stream_info.upstream_cluster.as_deref()?;
            let provider_type = pricing.providers.get(cluster)?;
            let model = stream_info.requested_model.as_deref()?;
            pricing
                .list
                .list_cost_nanodollars(provider_type, model, &usage)
                .map(|nanodollars| LlmListCost {
                    nanodollars,
                    rate_card_version: pricing.list.version().as_str().to_string(),
                })
        });
        stream_info.llm.system = Some(match self.dialect {
            Dialect::OpenAi | Dialect::OpenAiResponses => GenAiSystem::OpenAi,
            Dialect::Anthropic => GenAiSystem::Anthropic,
        });
        stream_info.llm.time_to_first_byte = self.time_to_first_byte;
        stream_info.llm.time_to_first_body_byte = self.time_to_first_body_byte;
        stream_info.llm.max_inter_chunk = self.max_inter_chunk;
        stream_info.llm.response_chunks = self.response_chunks;
    }
}

impl HttpFilter for UsageFilterInstance {
    fn encode_headers(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        headers: &mut ResponseHeaders,
        end_stream: bool,
    ) -> FilterHeadersStatus {
        self.headers_at = Some(Instant::now());
        let route_dialect = cb.per_route_config().and_then(|cfg| {
            cfg.as_any()
                .downcast_ref::<UsagePerRouteConfig>()
                .map(|c| c.0)
        });
        let cluster_dialect = cb
            .stream_info()
            .upstream_usage_dialect
            .map(Self::resolve_cluster_dialect);
        let dialect = cluster_dialect.or(route_dialect).unwrap_or(self.dialect);
        self.dialect = dialect;
        self.mode = classify_body(&headers.headers, dialect);

        // A response with no body at all (e.g. a 204, or a HEAD reply) — there's
        // nothing more to observe, so finalize right here.
        if end_stream {
            self.finalize(cb);
        }
        FilterHeadersStatus::Continue
    }

    fn encode_data(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        // A zero-length frame is not a response chunk, and must not be timed
        // as one. `proxy_http::filter_manager` delivers a synthetic empty
        // `end_stream=true` frame after the upstream body ends, so that a
        // filter which gated on end-of-stream can release its buffer. Timing
        // it unconditionally made `%LLM_RESPONSE_CHUNKS%` over-report by
        // exactly one on every response with a body, and fed the gap between
        // the last real chunk and that synthetic one into
        // `%LLM_MAX_STALL%` -- a stall that no client ever waited through.
        // (`%LLM_TTFT%` and `%LLM_TPOT%` were unaffected: TTFT is the first
        // gap and TPOT divides by `output_tokens`, not by this count.)
        if !data.is_empty() {
            self.record_chunk_timing(cb);
        }

        match &mut self.mode {
            BodyMode::Sse(scanner) => scanner.push(data),
            BodyMode::Json(buf) => {
                if buf.len() + data.len() > MAX_JSON_BODY_BYTES {
                    // Drop into inert mode rather than keep a truncated
                    // prefix: a partial JSON parse could silently produce a
                    // wrong (not just missing) token count, and this number
                    // feeds billing.
                    self.mode = BodyMode::Inert;
                } else {
                    buf.extend_from_slice(data);
                }
            }
            BodyMode::Inert => {}
        }

        if end_stream {
            self.finalize(cb);
        }

        // Rust note: this is the single most important line in the filter.
        // `Continue` (never any `StopIteration*` variant, and we never call
        // `cb.add_encoded_data`) means the filter manager passes every chunk
        // straight through to the next filter/downstream as it arrives. A
        // buffering encode filter here — even one that "just peeks and then
        // continues" via `StopIterationAndBuffer` — would hold the whole
        // response until the buffer's flushed, which destroys the one thing
        // that makes an LLM proxy usable: token-by-token streaming to the
        // client as the model generates them.
        FilterDataStatus::Continue
    }

    fn encode_trailers(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        _trailers: &mut ResponseTrailers,
    ) -> FilterTrailersStatus {
        // A response can end with trailers instead of an end_stream data
        // frame (chunked-with-trailers, gRPC-style status trailers, etc.);
        // finalize here if `encode_data` never saw `end_stream=true`.
        self.finalize(cb);
        FilterTrailersStatus::Continue
    }

    // `on_destroy` deliberately has no override here. Its contract (see
    // `filter.rs`) is `fn on_destroy(&mut self)` — no callbacks parameter —
    // so a reset-mid-stream path has no `StreamInfo` to write into even
    // though `self` still holds the timing/chunk counters observed so far.
    // There's no mechanism in the current `HttpFilter` trait to plumb a
    // reset notification through to something that *can* write `StreamInfo`
    // (the filter manager would need to call `finalize`-like logic itself,
    // or `on_destroy` would need a callbacks parameter) — that's a trait
    // change, which is out of scope here. Today, a reset mid-response simply
    // never gets a `StreamInfo::llm` write; the "finalize on end_stream /
    // trailers" path above is the only one that fires.
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use http::{HeaderValue, StatusCode};
    use std::sync::Arc;

    use proxy_http::filter::{BufferedBody, PerRouteConfig};
    use proxy_http::stream_info::StreamInfo;

    // --- test scaffolding ---------------------------------------------------

    /// A minimal `EncoderCallbacks` double: only `stream_info()` is ever
    /// exercised by this filter, so every other method is `unimplemented!()`
    /// — if the filter ever starts calling one of them (e.g. buffering via
    /// `add_encoded_data`), the test panics loudly instead of passing by
    /// accident.
    ///
    /// Rust note: the `StreamInfo` sits behind a `RefCell` because the real
    /// chain shares one instance between the filters and the router
    /// (`Rc<RefCell<StreamInfo>>`), so `stream_info()` returns a `RefMut`
    /// guard rather than a plain `&mut`. The double mirrors that shape; no
    /// `Rc` is needed here since nothing else holds a handle.
    struct TestCallbacks {
        stream_info: std::cell::RefCell<StreamInfo>,
        per_route_config: Option<Arc<dyn PerRouteConfig>>,
    }

    impl TestCallbacks {
        fn new() -> Self {
            TestCallbacks {
                stream_info: std::cell::RefCell::new(StreamInfo::default()),
                per_route_config: None,
            }
        }

        fn with_per_route_config(mut self, config: Arc<dyn PerRouteConfig>) -> Self {
            self.per_route_config = Some(config);
            self
        }

        /// Snapshot the LLM stats for assertions, so tests don't hold a
        /// `Ref` guard across a later filter call.
        fn llm(&self) -> proxy_http::LlmStats {
            self.stream_info.borrow().llm.clone()
        }
    }

    impl EncoderCallbacks for TestCallbacks {
        fn continue_encoding(&mut self) {
            unimplemented!("usage filter must not call continue_encoding")
        }
        fn add_encoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!("usage filter must never buffer via add_encoded_data")
        }
        fn inject_encoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!("usage filter must not inject data")
        }
        fn encoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!("usage filter must not consult the encoding buffer")
        }
        fn modify_encoding_buffer(&mut self, _f: &mut dyn FnMut(&mut BytesMut)) {
            unimplemented!("usage filter must not touch the encoding buffer")
        }
        /// Must be overridden, not inherited. `EncoderCallbacks` defaults this
        /// to `None`, so a double that merely *stores* a per-route config
        /// without returning it here sends every test down the no-override
        /// path — the per-route logic looks exercised while never running.
        fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
            self.per_route_config.clone()
        }
        fn stream_info(&mut self) -> std::cell::RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    fn response_headers(content_type: &str) -> ResponseHeaders {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(content_type).unwrap(),
        );
        ResponseHeaders {
            status: StatusCode::OK,
            headers,
        }
    }

    fn filter_for(dialect: Dialect) -> UsageFilterInstance {
        UsageFilterInstance {
            dialect,
            pricing: None,
            mode: BodyMode::Inert,
            headers_at: None,
            last_chunk_at: None,
            time_to_first_byte: None,
            time_to_first_body_byte: None,
            max_inter_chunk: None,
            response_chunks: 0,
            finalized: false,
        }
    }

    fn priced_filter() -> UsageFilterInstance {
        let list = PriceList::new(
            Some("2026-09"),
            std::time::SystemTime::UNIX_EPOCH,
            vec![PriceEntry {
                provider_type: "openai".into(),
                model: "gpt-5".into(),
                tier_basis: TierBasis::InputTokens,
                tier_mode: TierMode::WholeRequest,
                tiers: vec![Tier {
                    up_to: None,
                    input_nanodollars_per_token: 10,
                    cached_input_nanodollars_per_token: 1,
                    cache_write_nanodollars_per_token: 20,
                    output_nanodollars_per_token: 100,
                }],
            }],
        );
        UsageFilterInstance {
            pricing: Some(PricingContext {
                list,
                providers: HashMap::from([("provider:openai".into(), "openai".into())]),
            }),
            ..filter_for(Dialect::OpenAi)
        }
    }

    fn data_source(inline_string: &str) -> DynamicMessage {
        let desc = proxy_api::descriptor_pool()
            .get_message_by_name("envoy.config.core.v3.DataSource")
            .expect("DataSource is compiled into proxy-api");
        let mut msg = DynamicMessage::new(desc);
        msg.set_field_by_name(
            "inline_string",
            prost_reflect::Value::String(inline_string.to_string()),
        );
        msg
    }

    fn usage_config(dialect: &str) -> DynamicMessage {
        let desc = proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.Usage")
            .expect("Usage is compiled into proxy-api");
        let mut msg = DynamicMessage::new(desc);
        msg.set_field_by_name("dialect", prost_reflect::Value::String(dialect.to_string()));
        msg
    }

    // --- behavior tests -------------------------------------------------------

    #[test]
    fn openai_json_body_split_across_several_chunks() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json");
        assert_eq!(
            filter.encode_headers(&mut cb, &mut headers, false),
            FilterHeadersStatus::Continue
        );

        let body = br#"{"id":"x","usage":{"prompt_tokens":10,"completion_tokens":5}}"#;
        for (i, chunk) in body.chunks(7).enumerate() {
            let last = (i + 1) * 7 >= body.len();
            let mut data = Bytes::copy_from_slice(chunk);
            let status = filter.encode_data(&mut cb, &mut data, last);
            assert_eq!(status, FilterDataStatus::Continue);
        }

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
    }

    #[test]
    fn openai_sse_stream_fed_byte_at_a_time() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("text/event-stream");
        filter.encode_headers(&mut cb, &mut headers, false);

        let stream = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\
              data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n\
              data: [DONE]\n";

        for (i, byte) in stream.iter().enumerate() {
            let last = i + 1 == stream.len();
            let mut data = Bytes::copy_from_slice(std::slice::from_ref(byte));
            let status = filter.encode_data(&mut cb, &mut data, last);
            assert_eq!(status, FilterDataStatus::Continue);
        }

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(cb.llm().response_chunks, stream.len() as u64);
    }

    #[test]
    fn anthropic_sse_message_start_and_delta() {
        let mut filter = filter_for(Dialect::Anthropic);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("text/event-stream");
        filter.encode_headers(&mut cb, &mut headers, false);

        let start = b"event: message_start\n\
                      data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n";
        let delta =
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n";

        let mut data1 = Bytes::copy_from_slice(start);
        filter.encode_data(&mut cb, &mut data1, false);
        let mut data2 = Bytes::copy_from_slice(delta);
        filter.encode_data(&mut cb, &mut data2, true);

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 15);
    }

    #[test]
    fn unknown_content_type_is_inert_and_always_continues() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("text/plain");
        assert_eq!(
            filter.encode_headers(&mut cb, &mut headers, false),
            FilterHeadersStatus::Continue
        );

        let mut data = Bytes::from_static(b"hello, this is not usage data");
        assert_eq!(
            filter.encode_data(&mut cb, &mut data, false),
            FilterDataStatus::Continue
        );

        let mut trailers = ResponseTrailers::default();
        assert_eq!(
            filter.encode_trailers(&mut cb, &mut trailers),
            FilterTrailersStatus::Continue
        );

        assert_eq!(cb.llm().usage, None);
    }

    #[test]
    fn json_content_type_with_parameters_still_parses_as_json() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json; charset=utf-8");
        filter.encode_headers(&mut cb, &mut headers, false);

        let mut data =
            Bytes::from_static(br#"{"usage":{"prompt_tokens":1,"completion_tokens":2}}"#);
        filter.encode_data(&mut cb, &mut data, true);

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 1);
        assert_eq!(usage.output_tokens, 2);
    }

    #[test]
    fn oversized_json_body_yields_no_usage_not_a_partial_count() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json");
        filter.encode_headers(&mut cb, &mut headers, false);

        // One chunk bigger than the cap, followed by the well-formed tail
        // that (if this were parsed at all) would carry real usage. If the
        // filter mistakenly kept a truncated prefix, this would produce a
        // parse error but *could* in principle still be Some via a lenient
        // parser — assert None explicitly, not just "not the real answer".
        let mut oversized = Bytes::from(vec![b' '; MAX_JSON_BODY_BYTES + 1]);
        filter.encode_data(&mut cb, &mut oversized, false);

        let mut tail =
            Bytes::from_static(br#"{"usage":{"prompt_tokens":1,"completion_tokens":1}}"#);
        filter.encode_data(&mut cb, &mut tail, true);

        assert_eq!(cb.llm().usage, None);
    }

    #[test]
    fn no_usage_in_response_is_none_not_zero() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json");
        filter.encode_headers(&mut cb, &mut headers, false);

        let mut data = Bytes::from_static(br#"{"id":"x","choices":[]}"#);
        filter.encode_data(&mut cb, &mut data, true);

        assert_eq!(cb.llm().usage, None);
    }

    #[test]
    fn list_cost_is_recorded_once_at_terminal_usage_with_its_card_version() {
        let mut filter = priced_filter();
        let mut cb = TestCallbacks::new();
        {
            let mut info = cb.stream_info.borrow_mut();
            info.upstream_cluster = Some("provider:openai".into());
            info.requested_model = Some("gpt-5".into());
        }
        let mut headers = response_headers("text/event-stream");
        filter.encode_headers(&mut cb, &mut headers, false);
        let mut first = Bytes::from_static(
            b"data: {\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":3}}\n\n",
        );
        filter.encode_data(&mut cb, &mut first, false);
        assert_eq!(cb.llm().list_cost, None, "partial stream must not price");
        let mut end = Bytes::new();
        filter.encode_data(&mut cb, &mut end, true);
        let cost = cb.llm().list_cost.expect("terminal usage is priced");
        assert_eq!(cost.nanodollars, 320);
        assert!(cost.rate_card_version.starts_with("2026-09+"));
    }

    #[test]
    fn unpriced_model_stays_none_not_zero() {
        let mut filter = priced_filter();
        let mut cb = TestCallbacks::new();
        {
            let mut info = cb.stream_info.borrow_mut();
            info.upstream_cluster = Some("provider:openai".into());
            info.requested_model = Some("unpriced".into());
        }
        let mut headers = response_headers("application/json");
        filter.encode_headers(&mut cb, &mut headers, false);
        let mut data =
            Bytes::from_static(br#"{"usage":{"prompt_tokens":2,"completion_tokens":3}}"#);
        filter.encode_data(&mut cb, &mut data, true);
        assert_eq!(cb.llm().list_cost, None);
    }

    /// The four cost buckets are priced differently, so all four must survive
    /// the `TokenUsage` -> `LlmTokenUsage` conversion. A version of this
    /// filter that carried only input/output would still pass every other
    /// test in this file while making correct billing impossible.
    #[test]
    fn all_four_cost_buckets_cross_the_boundary() {
        let mut filter = filter_for(Dialect::Anthropic);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json");
        filter.encode_headers(&mut cb, &mut headers, false);

        let mut data = Bytes::from_static(
            br#"{"usage":{"input_tokens":10,"output_tokens":5,
                 "cache_read_input_tokens":80,"cache_creation_input_tokens":7}}"#,
        );
        filter.encode_data(&mut cb, &mut data, true);

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.cached_tokens, 80);
        assert_eq!(usage.cache_creation_tokens, 7);
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(usage.total(), 102);
    }

    /// OpenAI reports cached tokens nested under `prompt_tokens_details` as a
    /// *subset* of `prompt_tokens`; the extractor breaks them out, and the
    /// filter must not re-merge them.
    #[test]
    fn openai_cached_tokens_arrive_broken_out() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json");
        filter.encode_headers(&mut cb, &mut headers, false);

        let mut data = Bytes::from_static(
            br#"{"usage":{"prompt_tokens":100,"completion_tokens":20,
                 "prompt_tokens_details":{"cached_tokens":80}}}"#,
        );
        filter.encode_data(&mut cb, &mut data, true);

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(
            usage.input_tokens, 20,
            "prompt_tokens net of the cached part"
        );
        assert_eq!(usage.cached_tokens, 80);
        assert_eq!(usage.output_tokens, 20);
        assert_eq!(
            usage.total(),
            120,
            "must equal prompt_tokens + completion_tokens"
        );
    }

    #[test]
    fn encode_data_never_buffers() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("text/event-stream");
        filter.encode_headers(&mut cb, &mut headers, false);

        for i in 0..50 {
            let mut data = Bytes::from(format!("data: {{\"n\":{i}}}\n"));
            let status = filter.encode_data(&mut cb, &mut data, i == 49);
            assert_eq!(
                status,
                FilterDataStatus::Continue,
                "encode_data must always return Continue -- it must never buffer"
            );
        }
    }

    #[test]
    fn ttfb_and_max_inter_chunk_populate_as_chunks_arrive() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("text/event-stream");
        filter.encode_headers(&mut cb, &mut headers, false);
        assert_eq!(cb.llm().time_to_first_byte, None);
        assert_eq!(cb.llm().max_inter_chunk, None);

        let mut first = Bytes::from_static(b"data: {\"a\":1}\n");
        filter.encode_data(&mut cb, &mut first, false);
        // time_to_first_byte/max_inter_chunk are only written at finalize;
        // finalize the stream now to observe them.
        let mut second = Bytes::from_static(b"data: {\"b\":2}\n");
        filter.encode_data(&mut cb, &mut second, true);

        assert!(cb.llm().time_to_first_byte.is_some());
        assert!(cb.llm().max_inter_chunk.is_some());
    }

    // --- config parsing ---------------------------------------------------

    #[test]
    fn owned_config_resolves_and_parses_dialect() {
        let config = usage_config("OpenAI");
        assert_eq!(
            parse_owned_config(&config).expect("valid dialect"),
            Dialect::OpenAi
        );
        assert!(proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.Usage")
            .is_some());
    }

    #[test]
    fn owned_config_parses_the_current_pricing_json_payload() {
        let mut config = usage_config("anthropic");
        config.set_field_by_name(
            "pricing_json",
            prost_reflect::Value::String(
                r#"{"price_list":{"effective_from":"2026-09-01T00:00:00Z","entries":[{"provider_type":"anthropic","model":"claude-sonnet","tier_mode":"whole_request","tiers":[{"input_nanodollars_per_token":1,"cached_input_nanodollars_per_token":1,"cache_write_nanodollars_per_token":1,"output_nanodollars_per_token":1}]}]},"providers":{"provider:anthropic":"anthropic"}}"#.to_string(),
            ),
        );
        let parsed = parse_owned_factory_config(&config).expect("owned pricing config");
        assert_eq!(parsed.dialect, Dialect::Anthropic);
        assert!(parsed.pricing.is_some());
    }

    #[test]
    fn config_accepts_openai_case_insensitively() {
        for value in ["openai", "OpenAI", "OPENAI"] {
            let dialect = parse_owned_config(&usage_config(value)).expect("valid dialect");
            assert_eq!(dialect, Dialect::OpenAi);
        }
    }

    #[test]
    fn config_accepts_anthropic_case_insensitively() {
        for value in ["anthropic", "Anthropic", "ANTHROPIC"] {
            let dialect = parse_owned_config(&usage_config(value)).expect("valid dialect");
            assert_eq!(dialect, Dialect::Anthropic);
        }
    }

    #[test]
    fn config_rejects_unknown_dialect() {
        let err =
            parse_owned_config(&usage_config("gemini")).expect_err("unknown dialect must fail");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.dialect");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn config_rejects_empty_dialect() {
        let err = parse_owned_config(&usage_config("")).expect_err("empty dialect must fail");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.dialect");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn factory_creates_a_working_filter() {
        let factory = UsageFilterFactory;
        let instance_factory = factory
            .create(&usage_config("openai"), &FactoryContext::default())
            .expect("valid config builds a factory");
        let mut filter = instance_factory.create_filter();
        let mut cb = TestCallbacks::new();

        let mut headers = response_headers("application/json");
        assert_eq!(
            filter.encode_headers(&mut cb, &mut headers, false),
            FilterHeadersStatus::Continue
        );
        let mut data =
            Bytes::from_static(br#"{"usage":{"prompt_tokens":3,"completion_tokens":4}}"#);
        filter.encode_data(&mut cb, &mut data, true);

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 3);
        assert_eq!(usage.output_tokens, 4);
    }

    #[test]
    fn selected_cluster_dialect_is_used_when_no_route_override_exists() {
        let mut filter = filter_for(Dialect::Anthropic);
        let mut cb = TestCallbacks::new();
        {
            let mut info = cb.stream_info.borrow_mut();
            info.upstream_cluster = Some("provider:openai".into());
            info.upstream_usage_dialect = Some(proxy_config::ir::UsageDialect::OpenAi);
        }

        let mut headers = response_headers("application/json");
        assert_eq!(
            filter.encode_headers(&mut cb, &mut headers, false),
            FilterHeadersStatus::Continue
        );

        let mut data =
            Bytes::from_static(br#"{"usage":{"prompt_tokens":7,"completion_tokens":9}}"#);
        filter.encode_data(&mut cb, &mut data, true);

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 7);
        assert_eq!(usage.output_tokens, 9);
    }

    #[test]
    fn per_route_config_override_changes_the_dialect_used() {
        let mut filter = filter_for(Dialect::OpenAi);
        let override_cfg = Arc::new(UsagePerRouteConfig(Dialect::Anthropic));
        let mut cb = TestCallbacks::new().with_per_route_config(override_cfg);

        let mut headers = response_headers("application/json");
        assert_eq!(
            filter.encode_headers(&mut cb, &mut headers, false),
            FilterHeadersStatus::Continue
        );

        let mut data = Bytes::from_static(br#"{"usage":{"input_tokens":7,"output_tokens":9}}"#);
        filter.encode_data(&mut cb, &mut data, true);

        let usage = cb.llm().usage.expect("usage should be found");
        assert_eq!(usage.input_tokens, 7);
        assert_eq!(usage.output_tokens, 9);
    }

    /// The load-bearing property behind WP-33 acceptance criterion 3: an
    /// invalid per-route dialect must come back as `ConfigError::InvalidValue`,
    /// never `ConfigError::Unimplemented`.
    /// `filter_manager::resolve_per_filter_row` swallows exactly
    /// `Unimplemented` under `is_optional: true` (its default meaning "this
    /// filter has no per-route config at all"). If `parse_per_route`'s error
    /// variant here ever regressed to `Unimplemented`, a typo'd per-route
    /// dialect on an `is_optional: true` entry would be silently dropped
    /// instead of failing the build, and the route would go on to meter with
    /// the wrong (fallback) dialect -- exactly the silent-field-drop ground
    /// rule #1 forbids.
    #[test]
    fn parse_per_route_rejects_an_invalid_dialect_as_invalid_value() {
        let factory = UsageFilterFactory;
        for invalid in ["gemini", ""] {
            let err = match factory.parse_per_route(&usage_config(invalid)) {
                Ok(_) => panic!("invalid dialect must fail to parse"),
                Err(err) => err,
            };
            match err {
                ConfigError::InvalidValue { field_path, .. } => {
                    assert_eq!(field_path, "typed_config.dialect");
                }
                ConfigError::Unimplemented { .. } => panic!(
                    "must not be Unimplemented -- that variant is swallowed by \
                     filter_manager::resolve_per_filter_row when is_optional is \
                     true, which would silently drop an invalid dialect instead \
                     of failing the build"
                ),
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_per_route_accepts_route_level_dialect() {
        let factory = UsageFilterFactory;
        let per_route = factory
            .parse_per_route(&usage_config("anthropic"))
            .expect("valid per-route config");
        let dialect = per_route
            .as_any()
            .downcast_ref::<UsagePerRouteConfig>()
            .expect("UsagePerRouteConfig")
            .0;
        assert_eq!(dialect, Dialect::Anthropic);
    }

    #[test]
    fn legacy_config_still_parses_through_compatibility_factory() {
        let factory = LegacyUsageFilterFactory;
        let instance_factory = factory
            .create(&data_source("anthropic"), &FactoryContext::default())
            .expect("legacy DataSource config remains accepted for one release");
        let mut filter = instance_factory.create_filter();
        let mut cb = TestCallbacks::new();
        let mut headers = response_headers("application/json");
        filter.encode_headers(&mut cb, &mut headers, false);
        let mut data = Bytes::from_static(br#"{"usage":{"input_tokens":2,"output_tokens":3}}"#);
        filter.encode_data(&mut cb, &mut data, true);
        assert_eq!(cb.llm().usage.expect("legacy filter runs").input_tokens, 2);
    }

    #[test]
    fn live_rate_card_update_does_not_reprice_an_existing_request_snapshot() {
        let registry = PricingRegistry::new(None);
        let first = registry
            .replace_json(
                r#"{
                  "price_list": {"version":"v1","effective_from":"2026-09-25T00:00:00Z",
                    "entries":[{"provider_type":"openai","model":"gpt-5","tier_mode":"whole_request",
                      "tiers":[{"up_to":null,"input_nanodollars_per_token":10,"cached_input_nanodollars_per_token":0,
                        "cache_write_nanodollars_per_token":0,"output_nanodollars_per_token":20}]}]},
                  "providers":{"provider:p1":"openai"}
                }"#,
            )
            .expect("first card validates");
        let in_flight = registry.snapshot().expect("first card snapshot");
        let second = registry
            .replace_json(
                r#"{
                  "price_list": {"version":"v2","effective_from":"2026-09-25T01:00:00Z",
                    "entries":[{"provider_type":"openai","model":"gpt-5","tier_mode":"whole_request",
                      "tiers":[{"up_to":null,"input_nanodollars_per_token":99,"cached_input_nanodollars_per_token":0,
                        "cache_write_nanodollars_per_token":0,"output_nanodollars_per_token":99}]}]},
                  "providers":{"provider:p1":"openai"}
                }"#,
            )
            .expect("second card validates");
        assert_ne!(first, second);
        assert_eq!(in_flight.list.version().as_str(), first);
        assert_eq!(registry.snapshot().unwrap().list.version().as_str(), second);
    }
}
