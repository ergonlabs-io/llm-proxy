//! WP-50 increment 3c-iii-b — wires [`crate::spend`]'s price table, per-tenant
//! spend accumulator, and per-tenant budget into a real decode/encode
//! `HttpFilter`: `llmproxy.spend_limit`. See
//! `internal-docs/wp-50-3c-spend-budgets.md`'s "3c-iii" section, normative
//! here.
//!
//! # The check/record split is inherent, not a shortcut -- restated from
//! `token_limit_filter`, for money
//!
//! A request's cost is unknown until its response finishes (usage arrives at
//! the END of the stream, never before), so this filter -- exactly like
//! [`crate::token_limit_filter`] -- checks on the **decode** path (before a
//! request is sent upstream, against whatever the tenant's live spend
//! already is) and records on the **encode** path, at response end. The
//! consequence is the same shape as `token_limit`'s: the ONE request whose
//! cost pushes a tenant over its ceiling is necessarily ADMITTED (its own
//! cost cannot be known yet at the moment it is checked), and it is the
//! **next** request that gets refused. Overspend past a configured ceiling
//! is therefore bounded by at most one request's cost, never unbounded --
//! this is an accepted, documented property of "check before you know the
//! price", not a bug to fix by delaying the response.
//!
//! # Filter position: mirrors `token_limit_filter`'s two ordering rules
//! exactly, restated for tenant + usage instead of tenant + usage
//!
//! - **`llmproxy.auth` BEFORE `llmproxy.spend_limit`** (decode-side): this
//!   filter's decode check reads `StreamInfo::auth.tenant`, which the auth
//!   filter writes. Decoder callbacks run in config order (S2.1), so this
//!   is the same direction as `token_limit`'s own auth-ordering rule.
//! - **`llmproxy.spend_limit` BEFORE `llmproxy.usage`** (encode-side): this
//!   filter's encode-side `record` reads the [`proxy_http::LlmTokenUsage`]
//!   the usage filter writes at response end. Encoder callbacks run in
//!   REVERSE config order, so "the usage filter has already run" means "the
//!   usage filter is LATER in config order" -- exactly `token_limit`'s own
//!   usage-ordering rule, for the identical reason. Get it backwards and
//!   `StreamInfo::llm.usage` reads `None` forever; see "Loud on unreadable
//!   usage" below for why that is no longer silent.
//!
//! `proxy_config::lower::check_lane_h_filter_order` enforces both at config
//! load; this comment states the reasoning, not the guard.
//!
//! # No tenant -> admit; no budget -> admit (unlimited)
//!
//! Two DIFFERENT "nothing to enforce" cases, both admitting, for different
//! reasons:
//!
//! - **`StreamInfo::auth.tenant` is `None`.** This filter is not an
//!   authenticator, and duplicating `llmproxy.auth`'s own fail-closed 401
//!   here would only produce a second, confusingly different refusal reason
//!   for the same underlying fact ("this request was never authenticated").
//!   Nothing is recorded either -- there is no tenant to attribute spend to.
//! - **The authenticated tenant has no configured [`crate::spend::TenantBudget`]**
//!   (absent from the snapshot's `policies` entirely, or present with
//!   `budget: None`). Mirrors [`crate::model_authz_filter`]'s and
//!   [`crate::spend::TenantBudget`]'s own "`None` means unlimited, and that
//!   is the deliberate default" reasoning: a budget is an opt-in ceiling, not
//!   a default-deny, so enabling this filter must not silently deny every
//!   tenant's very first request the moment an operator adds it to a chain.
//!   Spend IS still recorded for this tenant (under
//!   [`crate::spend::SpendAccumulator::default_period`]) so its history
//!   accrues somewhere reportable even with no ceiling to check it against.
//!
//! # A configured ceiling of exactly zero denies immediately
//!
//! `Some(TenantBudget { max_micros: MicroUsd::from_micros(0), .. })` is a
//! real, deliberate policy -- deny every priced request this period -- not a
//! degenerate case to special-case away. The comparison below is
//! `current_micros >= limit_micros`, which is `0 >= 0` on a fresh period:
//! true, so the very first request a zero-budget tenant makes is refused.
//! See [`crate::spend::TenantBudget`]'s doc for why `None` and `Some(0)` are
//! kept distinguishable end to end rather than collapsed.
//!
//! # Enforcement reads the LIVE accumulator, never the last flush
//!
//! Exactly [`crate::spend::SpendAccumulator::current_total`]'s documented
//! property: a slow or dead flusher thread can only make the STORED total
//! staler, never loosen what this filter's decode check sees. This filter
//! never reads anything the flusher wrote; it reads live memory, every time.
//!
//! # Spend flushes into the OPERATOR'S store, not a private one
//!
//! [`crate::spend::SpendAccumulator`] needs a
//! [`crate::control::ControlPlaneStore`] to flush to and resume from, and it
//! gets the SAME one the `llmproxy.auth`-resolved
//! [`crate::control::ControlPlane`] persists budgets and policies into, via
//! [`crate::control::ControlPlane::store`]. That matters concretely: with
//! `store: persistent` configured on `llmproxy.auth`, a tenant's accrued
//! spend survives a restart along with its budget, and only the unflushed
//! window (bounded by the flush interval) is lost -- the crash-refund the
//! design brief documents.
//!
//! A private store here would have been the quiet failure. Budgets would
//! persist while SPEND reset to zero on every restart, so a monthly ceiling
//! would be escapable by bouncing the proxy, and 3c-ii-b's entire
//! persistence path (`add_spend`/`load_spend` on redb, additive writes,
//! restart-resume) would be wired to nothing while still passing its own
//! tests.
//! # Loud on unreadable usage, but never fail-closed -- restated from
//! `token_limit_filter`, per CLAUDE.md rule 17
//!
//! A request a budget actually applies to (this stream had a tenant AND that
//! tenant had a configured budget) whose usage reads `None` at encode time is
//! metered as zero spend and never shown anywhere an operator would look --
//! unless something says so. [`UsageMissingWarner::warn_if_due`] closes
//! exactly that gap, `warn!`, never a denial (the request itself succeeded
//! and behaved as designed): see [`crate::token_limit_filter`]'s identical
//! section for the full reasoning, including why this must warn ONLY when a
//! budget actually applies (an unbudgeted tenant's missing usage is not a
//! bypass of anything) and why the suppression is once-per-tenant-per-minute
//! rather than once-per-process. Tenant ids need no hashing before they
//! reach this warning -- unlike `token_limit`'s credential-derived key, a
//! tenant id is an identifier the OPERATOR chose, not a secret (see
//! `crate::auth::TenantPolicy`'s `Debug` impl, which reasons identically).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use chrono::Utc;
use http::StatusCode;
use prost_reflect::DynamicMessage;

use proxy_config::ConfigError;
use proxy_http::filter::{
    DecoderCallbacks, EncoderCallbacks, FactoryContext, FilterDataStatus, FilterHeadersStatus,
    FilterInstanceFactory, FilterTrailersStatus, HttpFilter, HttpFilterFactory, RequestHeaders,
    ResponseHeaders, ResponseTrailers,
};
use proxy_observability::ResponseFlag;

use crate::auth::TenantId;
use crate::auth_filter;
use crate::control::{ControlPlane, ControlPlaneSnapshot};
use crate::spend::{
    self, parse_micro_usd, ModelPrices, OnReconciliationExpired, Period, PriceTable,
    ReconciliationPolicy, SpendAccumulator,
};
use crate::usage::TokenUsage;

/// Type URL this filter is registered under.
pub const TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.SpendLimit";

/// The `%RESPONSE_CODE_DETAILS%`/body value for this filter's one refusal
/// reason -- unlike `model_authz_filter`'s deliberately generic denial, this
/// one names spend specifically: nothing about a spend ceiling is sensitive
/// the way a tenant's model allow-list contents might be, so there is no
/// analogous reason to keep it vague.
const DENY_DETAILS: &str = "spend_budget_exceeded";

fn invalid(field_path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: field_path.into(),
        reason: reason.into(),
    }
}

/// Reads `typed_config.pricing` (a repeated `ClusterPricing`) into a
/// [`PriceTable`]. An absent or empty `pricing` list parses successfully
/// into an EMPTY table -- every `(cluster, model)` pair costs zero, which is
/// legal (see [`PriceTable::cost_of`]'s "unpriced" semantic), not an error.
/// A malformed ENTRY (empty `cluster`, empty `model`, or a price string
/// [`parse_micro_usd`] rejects) is a hard `Err` naming its own dotted path,
/// per ground rule #1.
fn parse_pricing(config: &DynamicMessage) -> Result<PriceTable, ConfigError> {
    let mut table = PriceTable::new();

    let pricing: Vec<prost_reflect::Value> = config
        .get_field_by_name("pricing")
        .and_then(|v| v.as_list().map(<[_]>::to_vec))
        .unwrap_or_default();

    for (i, entry) in pricing.iter().enumerate() {
        let cluster_msg = entry
            .as_message()
            .ok_or_else(|| invalid(format!("typed_config.pricing[{i}]"), "must be a message"))?;

        let cluster = cluster_msg
            .get_field_by_name("cluster")
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        if cluster.is_empty() {
            return Err(invalid(
                format!("typed_config.pricing[{i}].cluster"),
                "must not be empty",
            ));
        }

        let models: Vec<prost_reflect::Value> = cluster_msg
            .get_field_by_name("models")
            .and_then(|v| v.as_list().map(<[_]>::to_vec))
            .unwrap_or_default();

        for (j, model_entry) in models.iter().enumerate() {
            let model_msg = model_entry.as_message().ok_or_else(|| {
                invalid(
                    format!("typed_config.pricing[{i}].models[{j}]"),
                    "must be a message",
                )
            })?;

            let model = model_msg
                .get_field_by_name("model")
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            if model.is_empty() {
                return Err(invalid(
                    format!("typed_config.pricing[{i}].models[{j}].model"),
                    "must not be empty",
                ));
            }

            let parse_rate = |field: &str| -> Result<crate::spend::MicroUsd, ConfigError> {
                let raw = model_msg
                    .get_field_by_name(field)
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                parse_micro_usd(&raw).map_err(|e| {
                    invalid(
                        format!("typed_config.pricing[{i}].models[{j}].{field}"),
                        e.to_string(),
                    )
                })
            };

            let prices = ModelPrices {
                input_per_million: parse_rate("input_per_million")?,
                output_per_million: parse_rate("output_per_million")?,
                cached_per_million: parse_rate("cached_per_million")?,
                cache_creation_per_million: parse_rate("cache_creation_per_million")?,
            };
            table.insert(cluster.clone(), model, prices);
        }
    }

    Ok(table)
}

/// Reads `typed_config.default_period` (a `Period` enum) -- `PERIOD_UNSPECIFIED`
/// (proto3's implicit zero, and an absent field reads the same way) means
/// `MONTHLY`, per the proto's own doc; any other value this build's
/// descriptor pool does not recognize is a hard `Err`, per ground rule #1 --
/// silently treating an unrecognized enum number as a default would be
/// exactly the kind of "config means one thing, does another" ground rule #1
/// exists to catch.
fn parse_default_period(config: &DynamicMessage) -> Result<Period, ConfigError> {
    let raw = config
        .get_field_by_name("default_period")
        .and_then(|v| v.as_enum_number())
        .unwrap_or(0);
    match raw {
        0 | 2 => Ok(Period::Monthly),
        1 => Ok(Period::Daily),
        other => Err(invalid(
            "typed_config.default_period",
            format!("unrecognized Period enum value `{other}`"),
        )),
    }
}

/// Reads `typed_config.flush_interval_seconds` -- `0` (proto3's implicit
/// default for an unset `uint32`) means "use the built-in 5-second default",
/// per the proto's own doc. This is a durability knob (see the module doc's
/// "Enforcement reads the LIVE accumulator" section), so treating unset as
/// "pick a sane default" rather than an error is safe in a way an unset
/// price or ceiling would not be.
fn parse_flush_interval(config: &DynamicMessage) -> Duration {
    let secs = config
        .get_field_by_name("flush_interval_seconds")
        .and_then(|v| v.as_u32())
        .unwrap_or(0);
    if secs == 0 {
        Duration::from_secs(5)
    } else {
        Duration::from_secs(u64::from(secs))
    }
}

/// Reads `typed_config.reconciliation_bound_seconds` and
/// `typed_config.on_reconciliation_expired` into a [`ReconciliationPolicy`]
/// (WP-62, ADR-0006 §5).
///
/// `0` seconds means [`spend::DEFAULT_RECONCILIATION_BOUND`], per the proto's
/// own doc -- same "a visibility knob may default" reasoning as
/// [`parse_flush_interval`].
///
/// The BEHAVIOUR field is the opposite case and is why this returns a
/// `Result`. `DENY` (2) and `DEGRADE` (3) are named in the proto so that
/// tightening the policy later is a config change rather than a redesign,
/// but neither is implemented -- so selecting one is a load error naming the
/// field's full dotted path. Accepting it and behaving as `ALLOW` would be
/// silently ignoring a config field, which ground rule 1 calls a P0 bug, and
/// it would fail in the worst direction: an operator who deliberately asked
/// for the strict behaviour would get the permissive one and no indication.
fn parse_reconciliation(config: &DynamicMessage) -> Result<ReconciliationPolicy, ConfigError> {
    let secs = config
        .get_field_by_name("reconciliation_bound_seconds")
        .and_then(|v| v.as_u32())
        .unwrap_or(0);
    let bound = if secs == 0 {
        spend::DEFAULT_RECONCILIATION_BOUND
    } else {
        Duration::from_secs(u64::from(secs))
    };

    let raw = config
        .get_field_by_name("on_reconciliation_expired")
        .and_then(|v| v.as_enum_number())
        .unwrap_or(0);
    let on_expired = match raw {
        0 | 1 => OnReconciliationExpired::Allow,
        2 => {
            return Err(invalid(
                "typed_config.on_reconciliation_expired",
                "DENY is declared in the config surface but not implemented in this build -- \
                 only ALLOW is. Refusing rather than quietly serving ALLOW, because an \
                 operator who asked for the strict behaviour would otherwise get the \
                 permissive one silently",
            ));
        }
        3 => {
            return Err(invalid(
                "typed_config.on_reconciliation_expired",
                "DEGRADE is declared in the config surface but not implemented in this build \
                 -- only ALLOW is. Refusing rather than quietly serving ALLOW, because an \
                 operator who asked for the strict behaviour would otherwise get the \
                 permissive one silently",
            ));
        }
        other => {
            return Err(invalid(
                "typed_config.on_reconciliation_expired",
                format!("unrecognized OnReconciliationExpired enum value `{other}`"),
            ));
        }
    };

    Ok(ReconciliationPolicy { bound, on_expired })
}

/// [`HttpFilterFactory`] for [`TYPE_URL`]. No `parse_per_route` override --
/// this increment has no per-route config; the trait default
/// (`ConfigError::Unimplemented`) is correct.
#[derive(Default)]
pub struct SpendLimitFilterFactory;

impl HttpFilterFactory for SpendLimitFilterFactory {
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
        let price_table = Arc::new(parse_pricing(config)?);
        let default_period = parse_default_period(config)?;
        let flush_interval = parse_flush_interval(config);
        let reconciliation = parse_reconciliation(config)?;

        // WP-50 3c-iii-b: resolve the SAME `ControlPlane` singleton
        // `llmproxy.auth`'s factory registers -- see `model_authz_filter`'s
        // identical resolution and its module doc for why this is `ctx.get`
        // (never `get_or_try_init`: this filter has none of a fresh
        // `ControlPlane`'s required inputs and must not invent them) and why
        // `None` is always a config error, given `proxy_config`'s
        // lowering-enforced filter order (`llmproxy.auth` before
        // `llmproxy.spend_limit`).
        let control_plane = ctx
            .get(auth_filter::TYPE_URL)
            .ok_or_else(|| {
                invalid(
                    "typed_config",
                    "llmproxy.spend_limit requires llmproxy.auth earlier in the same filter \
                     chain -- its ControlPlane singleton is where this filter's tenant and \
                     budgets live",
                )
            })?
            .downcast::<ControlPlane>()
            .expect(
                "the control-plane singleton registered under auth_filter::TYPE_URL is \
                 always a ControlPlane",
            );

        // One `SpendAccumulator` (+ its usage-missing warner) per (filter
        // config, listener) -- same singleton lifetime/reasoning as
        // `token_limit_filter`'s `SharedTokenLimitState`: it must outlive any
        // single stream (a budget is meaningless otherwise), but survive
        // exactly once across every worker BUILDING THIS SAME CHAIN, never
        // rebuilt per worker (ADR-0003) -- a fresh, unshared accumulator per
        // worker would let `worker_count` independent ceilings each admit up
        // to the full budget, the exact multiply-by-worker-count bug `A2`
        // (`0dc91d1`) already fixed for `token_limit`, one filter over.
        //
        // The accumulator flushes into the SAME store the operator configured
        // on `llmproxy.auth` (`typed_config.store`), reached through
        // `ControlPlane::store()`. A private store here would leave 3c-ii-b's
        // whole persistence path wired to nothing and reset every tenant's
        // accrued spend on restart -- a ceiling an operator could escape by
        // bouncing the proxy.
        let store = control_plane.store();
        let shared = ctx
            .get_or_try_init(TYPE_URL, || {
                let accumulator = Arc::new(SpendAccumulator::with_reconciliation(
                    ctx.stat_prefix.clone(),
                    store,
                    default_period,
                    resolve_node_id(ctx.node_id(), &ctx.stat_prefix),
                    reconciliation,
                ));
                accumulator.start_flusher(flush_interval);
                Ok(Arc::new(SharedSpendLimitState {
                    accumulator,
                    usage_missing_warner: Arc::new(UsageMissingWarner::new()),
                }) as Arc<dyn std::any::Any + Send + Sync>)
            })?
            .downcast::<SharedSpendLimitState>()
            .expect("spend_limit singleton is always a SharedSpendLimitState");

        Ok(Box::new(SpendLimitInstanceFactory {
            price_table,
            accumulator: Arc::clone(&shared.accumulator),
            usage_missing_warner: Arc::clone(&shared.usage_missing_warner),
            snapshot: control_plane.handle(),
        }))
    }
}

/// The pieces every worker building the SAME chain must share -- see
/// `create`'s doc for why both live behind ONE `SharedFactoryState` slot.
///
/// `pub` (crossing the crate boundary) because WP-50 increment 3c-iv's admin
/// spend read (`proxy-admin`) downcasts to this exact type: what is
/// registered under [`TYPE_URL`] in [`proxy_http::filter::SharedFactoryState`]
/// is THIS wrapper, never a bare `Arc<SpendAccumulator>` -- an admin-side
/// downcast straight to `SpendAccumulator` would silently fail every time.
/// `usage_missing_warner` stays private; only [`Self::accumulator`] is ever
/// read from outside this module.
pub struct SharedSpendLimitState {
    accumulator: Arc<SpendAccumulator>,
    usage_missing_warner: Arc<UsageMissingWarner>,
}

impl SharedSpendLimitState {
    /// The shared spend accumulator this chain's `llmproxy.spend_limit`
    /// filter accrues into -- what the admin spend read reports from.
    pub fn accumulator(&self) -> &Arc<SpendAccumulator> {
        &self.accumulator
    }

    /// Test-support constructor, `pub` so `proxy-admin`'s server tests (a
    /// different crate) can register a singleton of the EXACT type
    /// production registers under [`TYPE_URL`] without driving the whole
    /// `SpendLimitFilterFactory::create`/HCM-build machinery just to get one
    /// -- see this type's own doc for why registering a bare
    /// `Arc<SpendAccumulator>` instead would make the admin server's
    /// downcast silently miss.
    #[doc(hidden)]
    pub fn for_test(accumulator: Arc<SpendAccumulator>) -> Self {
        SharedSpendLimitState {
            accumulator,
            usage_missing_warner: Arc::new(UsageMissingWarner::new()),
        }
    }
}

struct SpendLimitInstanceFactory {
    price_table: Arc<PriceTable>,
    accumulator: Arc<SpendAccumulator>,
    usage_missing_warner: Arc<UsageMissingWarner>,
    /// One handle per (filter config, listener), shared by every per-stream
    /// instance -- same pattern as `model_authz_filter`'s
    /// `ModelAuthzInstanceFactory::snapshot`.
    snapshot: Arc<ArcSwap<ControlPlaneSnapshot>>,
}

impl FilterInstanceFactory for SpendLimitInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(SpendLimitFilterInstance {
            price_table: Arc::clone(&self.price_table),
            accumulator: Arc::clone(&self.accumulator),
            usage_missing_warner: Arc::clone(&self.usage_missing_warner),
            snapshot: Arc::clone(&self.snapshot),
            tenant: None,
            period: None,
            budget_applies: false,
            recorded: false,
        })
    }
}

/// Warns, at most once per tenant per [`Self::REPEAT_INTERVAL`], when a
/// budget actually applied to a request but its usage could not be read at
/// encode time -- see the module doc's "Loud on unreadable usage" section.
/// Mirrors `token_limit_filter::UsageMissingWarner` structurally; kept as a
/// separate type because it dedups on [`TenantId`], not `token_limit`'s
/// `LimitKey`, and needs no credential hashing (see the module doc for why).
struct UsageMissingWarner {
    last_warned: Mutex<HashMap<TenantId, Instant>>,
}

impl UsageMissingWarner {
    /// See `token_limit_filter::UsageMissingWarner::REPEAT_INTERVAL`'s doc
    /// for why this repeats rather than warning once ever.
    const REPEAT_INTERVAL: Duration = Duration::from_secs(60);

    fn new() -> Self {
        UsageMissingWarner {
            last_warned: Mutex::new(HashMap::new()),
        }
    }

    fn warn_if_due(&self, tenant: &TenantId, now: Instant) {
        // Rust note: `unwrap_or_else(PoisonError::into_inner)` recovers from
        // a poisoned lock rather than panicking -- same convention as
        // `token_limit_filter::UsageMissingWarner::warn_if_due`.
        let mut last_warned = self
            .last_warned
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let due = match last_warned.get(tenant) {
            Some(&last) => now.saturating_duration_since(last) >= Self::REPEAT_INTERVAL,
            None => true,
        };
        if !due {
            return;
        }
        last_warned.insert(tenant.clone(), now);
        drop(last_warned);

        tracing::warn!(
            tenant = tenant.as_str(),
            "spend_limit: this tenant's spend budget was NOT enforced for this request and \
             nothing was charged against it -- usage could not be extracted from the response \
             (StreamInfo::llm.usage was None). The most likely cause is that the llmproxy.usage \
             filter's configured `dialect` does not match this provider's actual response shape \
             for this route; check that first."
        );
    }
}

/// Per-stream instance. Plain fields, no `Rc`/`RefCell` (never leaves the
/// worker thread that owns the stream) -- `price_table`/`accumulator`/
/// `usage_missing_warner`/`snapshot` are the cross-thread-shared pieces, each
/// an `Arc` clone, not shared interior state of this struct itself.
struct SpendLimitFilterInstance {
    price_table: Arc<PriceTable>,
    accumulator: Arc<SpendAccumulator>,
    usage_missing_warner: Arc<UsageMissingWarner>,
    snapshot: Arc<ArcSwap<ControlPlaneSnapshot>>,
    /// Set in `decode_headers` whenever this stream has an authenticated
    /// tenant, regardless of whether that tenant has a budget -- `None`
    /// means "nothing to record" (see the module doc's "no tenant -> admit"
    /// case).
    tenant: Option<TenantId>,
    /// The period this tenant's spend accrues into for THIS request -- the
    /// tenant's own `TenantBudget::period` if one is configured, else
    /// `self.accumulator.default_period()`. Set alongside `tenant`; `None`
    /// exactly when `tenant` is `None`.
    period: Option<Period>,
    /// Whether a budget actually applied to this request -- distinguishes
    /// "no usage at encode time on a budgeted tenant" (warn: see the module
    /// doc) from "no usage on an unbudgeted tenant" (silent: nothing was
    /// ever being enforced for this request in the first place).
    budget_applies: bool,
    /// Guards against double-recording from more than one encode callback
    /// observing `end_stream` -- mirrors `token_limit_filter`'s identical
    /// flag.
    recorded: bool,
}

impl SpendLimitFilterInstance {
    /// Read `StreamInfo::llm.usage`/`upstream_cluster`/`requested_model` and,
    /// if a tenant is known, price and record the charge. Never fails the
    /// request. Follows `token_limit_filter::record_if_present`'s exact
    /// pattern for WHERE usage becomes available (the usage filter's own
    /// encode callback, which must run before this one -- see the module
    /// doc's ordering section) rather than inventing a second way to read it.
    fn record_if_present(&mut self, cb: &mut dyn EncoderCallbacks) {
        if self.recorded {
            return;
        }
        self.recorded = true;

        let Some(tenant) = self.tenant.clone() else {
            return;
        };
        let period = self
            .period
            .expect("period is always set alongside tenant in decode_headers");

        // Rust note: read every field out of the `RefMut` guard and drop it
        // before calling `self.accumulator.record` below -- `stream_info()`
        // must not be held across another call (see its doc), same pattern
        // as `token_limit_filter::record_if_present`.
        let (usage, cluster, model) = {
            let info = cb.stream_info();
            (
                info.llm.usage,
                info.upstream_cluster.clone(),
                info.requested_model.clone(),
            )
        };

        let Some(usage) = usage else {
            if self.budget_applies {
                self.usage_missing_warner
                    .warn_if_due(&tenant, Instant::now());
            }
            return;
        };

        let usage = TokenUsage {
            input_tokens: usage.input_tokens,
            cached_tokens: usage.cached_tokens,
            cache_creation_tokens: usage.cache_creation_tokens,
            output_tokens: usage.output_tokens,
        };
        let charge = self
            .price_table
            .cost_of(cluster.as_deref(), model.as_deref(), &usage);

        self.accumulator.record(
            &tenant,
            Utc::now(),
            period,
            charge,
            cluster.as_deref(),
            model.as_deref(),
        );
    }
}

impl HttpFilter for SpendLimitFilterInstance {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        // Rust note: `stream_info()` hands back a `RefMut` guard that must
        // not be held across another call on `cb` -- cloning the
        // `Option<String>` out and letting the guard drop at the end of this
        // block keeps that rule visibly satisfied, same pattern as
        // `token_limit_filter`/`model_authz_filter`.
        let tenant_name = cb.stream_info().auth.tenant.clone();

        // Case: no authenticated tenant -- see the module doc's "no tenant ->
        // admit" section. This filter is not an authenticator.
        let Some(tenant_name) = tenant_name else {
            self.tenant = None;
            self.period = None;
            self.budget_applies = false;
            return FilterHeadersStatus::Continue;
        };

        let tenant = TenantId::new(tenant_name.clone());
        let budget = self
            .snapshot
            .load()
            .policies
            .get(&tenant_name)
            .and_then(|policy| policy.budget);

        self.tenant = Some(tenant.clone());
        self.budget_applies = budget.is_some();
        let period = budget
            .map(|b| b.period)
            .unwrap_or_else(|| self.accumulator.default_period());
        self.period = Some(period);

        // Case: no configured budget -- unlimited. Spend is still tracked
        // (via `record_if_present`, at encode time) under
        // `self.accumulator.default_period()`; nothing to check here.
        let Some(budget) = budget else {
            return FilterHeadersStatus::Continue;
        };

        let now = Utc::now();
        let period_key = period.key_for(now);
        let current_micros = self.accumulator.current_total(&tenant, &period_key);
        let limit_micros = budget.max_micros.as_micros();

        // At or over the ceiling denies -- see the module doc's "A
        // configured ceiling of exactly zero denies immediately" section for
        // why this is `>=`, not `>`.
        if current_micros >= limit_micros {
            cb.stream_info()
                .set_response_flag(ResponseFlag::RateLimited);

            let remaining_micros = limit_micros.saturating_sub(current_micros);
            let reset_secs = period.seconds_until_reset(now);
            // Mirrors `token_limit_filter`'s convention: `retry-after` equals
            // `x-ratelimit-reset` here (there is only one reset event -- the
            // period boundary -- for this filter to name).
            let retry_secs = reset_secs;

            cb.send_local_reply(
                StatusCode::TOO_MANY_REQUESTS,
                "spend budget exceeded",
                Some(Box::new(move |headers: &mut http::HeaderMap| {
                    // Rust note: `HeaderValue::from_str` on formatted decimal
                    // strings never fails (ASCII digits are always a valid
                    // header value), so these unwraps are total -- same as
                    // `token_limit_filter`'s identical headers.
                    //
                    // VALUES ARE IN MICRO-DOLLARS (1e-6 USD), NOT REQUEST
                    // COUNTS -- unlike `token_limit_filter`'s identically
                    // named headers, which count tokens. These header names
                    // are a convention borrowed from request-count rate
                    // limiting; nothing about the name says "money", so an
                    // integrator reading a raw `x-ratelimit-remaining` value
                    // here without reading this filter's docs would
                    // reasonably misinterpret it as a request or token count.
                    headers.insert(
                        "x-ratelimit-limit",
                        http::HeaderValue::from_str(&limit_micros.to_string()).unwrap(),
                    );
                    headers.insert(
                        "x-ratelimit-remaining",
                        http::HeaderValue::from_str(&remaining_micros.to_string()).unwrap(),
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
                DENY_DETAILS,
            );
            // Rust note: the returned status is irrelevant here --
            // `drive_decode` checks `ctx.local_reply.is_some()` right after
            // this callback returns and stops the chain unconditionally when
            // it's set, regardless of what status this function returns (see
            // `filter_manager.rs`), same as `token_limit_filter`/
            // `model_authz_filter`.
            return FilterHeadersStatus::Continue;
        }

        // Admitted, under a CONFIGURED budget. If this replica has not
        // reconciled with the store within its bound, `current_micros` above
        // may be missing what other replicas spent, so this admission is one
        // the shared ceiling might not actually have had room for.
        //
        // Counted, not refused: ADR-0006 §5's `on_reconciliation_expired`,
        // of which only `Allow` is implemented -- a metering hiccup must not
        // start refusing traffic (rule 17). The counter and the flusher's
        // warning are what make the over-admission VISIBLE rather than
        // silent, which is the whole difference between this and the
        // fail-open bug rule 17 was written for.
        //
        // Deliberately after the deny check, so a replica that has already
        // burned the budget on its OWN traffic still returns 429 while
        // stale -- that is the enforcement that survives a store outage, and
        // counting it as an admission would misreport it.
        //
        // Deliberately inside the `Some(budget)` path: a tenant with no
        // ceiling cannot be over-admitted, so counting it would bury the
        // real signal (rule 17: only where the control was meant to apply).
        match self.accumulator.reconciliation_policy().on_expired {
            OnReconciliationExpired::Allow => {
                self.accumulator.note_admission(now);
            }
        }

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
        // Never buffers, never inspects response bytes -- same guarantee as
        // `token_limit_filter`.
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

/// This replica's spend-writer identity: `service_node` if the operator
/// configured one, otherwise a synthesised id that is unique to this process.
///
/// # Why an unset `service_node` warns instead of failing either way
///
/// The id is half of every [`crate::control::FlushToken`], and two replicas
/// sharing one id silently drop each other's flushes -- lost spend, which is
/// a budget escape. So an empty id must not be passed through.
///
/// The two obvious responses are both wrong here:
///
/// - Refusing the config fails CLOSED, and metering must not start refusing
///   traffic -- the same call `token_limit` already made for unreadable usage
///   (CLAUDE.md rule 17). It would also reject nearly every deployment that
///   works today: a fully static bootstrap does not carry a node id into the
///   IR at all.
/// - Passing the empty string through fails OPEN and SILENTLY, which is the
///   one outcome this whole work package exists to prevent.
///
/// Synthesising loses nothing. A unique id cannot collide, so no flush is
/// ever dropped as another replica's replay; the only property given up is
/// that a RESTARTED process no longer recognises its own pre-restart
/// sequence, which costs at most the one un-acknowledged flush already
/// bounded by the crash-refund window. The `warn!` is what makes the
/// unconfigured state visible rather than merely survivable.
fn resolve_node_id(configured: &str, stat_prefix: &str) -> String {
    if !configured.is_empty() {
        return configured.to_string();
    }
    // Rust note: process id plus process start time. The pid alone recycles
    // across restarts on the same host, and the timestamp alone collides
    // between two replicas started in the same nanosecond; together they are
    // unique in the only way that matters, which is "not equal to another
    // live replica's".
    let unique = format!(
        "unconfigured-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    tracing::warn!(
        stat_prefix = %stat_prefix,
        node_id = %unique,
        "llmproxy.spend_limit: no service_node is configured, so this replica has no stable \
         identity to write spend under; using a synthesised one. Spend is still counted \
         correctly, but set service_node in the bootstrap to keep a restarted replica's \
         identity stable"
    );
    unique
}

#[cfg(test)]
mod tests {
    use super::*;

    // Rust note: test-only now -- `create` reaches its store through
    // `ControlPlane::store()`, so the lib half never names a concrete store
    // type. Only the tests, which stand one up by hand, still do.
    use crate::control::{ControlPlaneStore, InMemoryControlPlaneStore};

    use std::cell::{RefCell, RefMut};

    use bytes::Bytes;
    use http::{HeaderMap, Method, Uri};
    use proxy_config::ir::RouteEntry;
    use proxy_http::filter::{BufferedBody, HeaderMutationFn, PerRouteConfig};
    use proxy_http::stream_info::StreamInfo;
    use proxy_http::LlmTokenUsage;

    use crate::auth::{HmacSecret, KeySet};
    use crate::control::ControlPlane;
    use crate::spend::{Charge, MicroUsd, TenantBudget};

    // --- config parsing ------------------------------------------------

    fn spend_limit_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.SpendLimit")
            .expect("SpendLimit is compiled into proxy-api")
    }

    fn cluster_pricing_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.ClusterPricing")
            .expect("ClusterPricing is compiled into proxy-api")
    }

    fn model_price_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.ModelPrice")
            .expect("ModelPrice is compiled into proxy-api")
    }

    fn model_price(model: &str, rate: &str) -> DynamicMessage {
        let mut m = DynamicMessage::new(model_price_desc());
        m.set_field_by_name("model", prost_reflect::Value::String(model.to_string()));
        for field in [
            "input_per_million",
            "output_per_million",
            "cached_per_million",
            "cache_creation_per_million",
        ] {
            m.set_field_by_name(field, prost_reflect::Value::String(rate.to_string()));
        }
        m
    }

    fn cluster_pricing(cluster: &str, models: Vec<DynamicMessage>) -> DynamicMessage {
        let mut m = DynamicMessage::new(cluster_pricing_desc());
        m.set_field_by_name("cluster", prost_reflect::Value::String(cluster.to_string()));
        m.set_field_by_name(
            "models",
            prost_reflect::Value::List(
                models
                    .into_iter()
                    .map(prost_reflect::Value::Message)
                    .collect(),
            ),
        );
        m
    }

    fn spend_limit_config(pricing: Vec<DynamicMessage>) -> DynamicMessage {
        let mut m = DynamicMessage::new(spend_limit_desc());
        m.set_field_by_name(
            "pricing",
            prost_reflect::Value::List(
                pricing
                    .into_iter()
                    .map(prost_reflect::Value::Message)
                    .collect(),
            ),
        );
        m
    }

    #[test]
    fn spend_limit_resolves_in_the_descriptor_pool() {
        assert!(
            proxy_api::descriptor_pool()
                .get_message_by_name("llmproxy.filters.v0.SpendLimit")
                .is_some(),
            "{TYPE_URL} must resolve"
        );
    }

    #[test]
    fn empty_pricing_parses_to_an_all_unpriced_table() {
        let table = parse_pricing(&spend_limit_config(vec![])).expect("valid config");
        let usage = TokenUsage {
            input_tokens: 1_000_000,
            ..Default::default()
        };
        assert_eq!(
            table.cost_of(Some("any-cluster"), Some("any-model"), &usage),
            Charge::Unpriced
        );
    }

    #[test]
    fn pricing_parses_into_a_working_price_table() {
        let table = parse_pricing(&spend_limit_config(vec![cluster_pricing(
            "cluster-a",
            vec![model_price("m", "2.00")],
        )]))
        .expect("valid config");
        let usage = TokenUsage {
            input_tokens: 1_000_000,
            ..Default::default()
        };
        assert_eq!(
            table.cost_of(Some("cluster-a"), Some("m"), &usage),
            Charge::Priced(MicroUsd::from_micros(2_000_000))
        );
    }

    #[test]
    fn empty_cluster_name_is_rejected() {
        let mut msg = DynamicMessage::new(cluster_pricing_desc());
        msg.set_field_by_name("cluster", prost_reflect::Value::String(String::new()));
        let err = parse_pricing(&spend_limit_config(vec![msg])).expect_err("must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.pricing[0].cluster");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn empty_model_name_is_rejected() {
        let mut price = DynamicMessage::new(model_price_desc());
        price.set_field_by_name("model", prost_reflect::Value::String(String::new()));
        let err = parse_pricing(&spend_limit_config(vec![cluster_pricing(
            "cluster-a",
            vec![price],
        )]))
        .expect_err("must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.pricing[0].models[0].model");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn an_invalid_rate_string_is_rejected_with_its_dotted_path() {
        let err = parse_pricing(&spend_limit_config(vec![cluster_pricing(
            "cluster-a",
            vec![model_price("m", "not-a-number")],
        )]))
        .expect_err("must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(
                    field_path,
                    "typed_config.pricing[0].models[0].input_per_million"
                );
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn unspecified_default_period_means_monthly() {
        let period = parse_default_period(&spend_limit_config(vec![])).expect("valid");
        assert_eq!(period, Period::Monthly);
    }

    #[test]
    fn explicit_daily_default_period_parses() {
        let mut msg = spend_limit_config(vec![]);
        msg.set_field_by_name("default_period", prost_reflect::Value::EnumNumber(1));
        assert_eq!(parse_default_period(&msg).expect("valid"), Period::Daily);
    }

    #[test]
    fn zero_flush_interval_means_the_five_second_default() {
        assert_eq!(
            parse_flush_interval(&spend_limit_config(vec![])),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn a_configured_flush_interval_is_honored() {
        let mut msg = spend_limit_config(vec![]);
        msg.set_field_by_name("flush_interval_seconds", prost_reflect::Value::U32(30));
        assert_eq!(parse_flush_interval(&msg), Duration::from_secs(30));
    }

    // --- WP-62: the reconciliation policy (ADR-0006 §5) --------------------

    #[test]
    fn zero_reconciliation_bound_means_the_stated_default() {
        let policy = parse_reconciliation(&spend_limit_config(vec![])).expect("valid config");
        assert_eq!(policy.bound, spend::DEFAULT_RECONCILIATION_BOUND);
        assert_eq!(policy.on_expired, OnReconciliationExpired::Allow);
    }

    #[test]
    fn a_configured_reconciliation_bound_is_honored() {
        let mut msg = spend_limit_config(vec![]);
        msg.set_field_by_name(
            "reconciliation_bound_seconds",
            prost_reflect::Value::U32(120),
        );
        let policy = parse_reconciliation(&msg).expect("valid config");
        assert_eq!(policy.bound, Duration::from_secs(120));
    }

    /// The unset enum and an explicit `ALLOW` are the same policy -- an
    /// operator who never touches this field gets the behaviour that is
    /// implemented, not a load error.
    #[test]
    fn explicit_allow_and_unset_are_the_same_policy() {
        let mut msg = spend_limit_config(vec![]);
        msg.set_field_by_name(
            "on_reconciliation_expired",
            prost_reflect::Value::EnumNumber(1),
        );
        assert_eq!(
            parse_reconciliation(&msg).expect("ALLOW is implemented"),
            parse_reconciliation(&spend_limit_config(vec![])).expect("unset means ALLOW"),
        );
    }

    /// Ground rule 1: a declared-but-unimplemented behaviour is a LOAD
    /// ERROR naming its full dotted path, never a silent downgrade to the
    /// permissive policy. This is the one direction the failure must not
    /// take -- an operator who asked for DENY and silently got ALLOW would
    /// believe a control is enforcing when it is not.
    ///
    /// Mutation: return `Ok(ReconciliationPolicy { bound, on_expired:
    /// Allow })` from the `2` and `3` arms of `parse_reconciliation`.
    #[test]
    fn declared_but_unimplemented_expiry_behaviours_are_rejected_at_load() {
        for value in [2, 3] {
            let mut msg = spend_limit_config(vec![]);
            msg.set_field_by_name(
                "on_reconciliation_expired",
                prost_reflect::Value::EnumNumber(value),
            );
            match parse_reconciliation(&msg).expect_err("must be rejected, not downgraded") {
                ConfigError::InvalidValue { field_path, .. } => {
                    assert_eq!(field_path, "typed_config.on_reconciliation_expired");
                }
                other => panic!("expected InvalidValue, got {other:?}"),
            }
        }
    }

    // --- test scaffolding ------------------------------------------------

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

    struct TestCallbacks {
        route: Option<Arc<RouteEntry>>,
        stream_info: RefCell<StreamInfo>,
        local_reply: Option<(StatusCode, HeaderMap)>,
    }

    impl TestCallbacks {
        fn new() -> Self {
            TestCallbacks {
                route: Some(route_named("r1")),
                stream_info: RefCell::new(StreamInfo::default()),
                local_reply: None,
            }
        }

        fn set_tenant(&self, tenant: &str) {
            self.stream_info.borrow_mut().auth.tenant = Some(tenant.to_string());
        }

        fn set_usage(&self, usage: LlmTokenUsage) {
            self.stream_info.borrow_mut().llm.usage = Some(usage);
        }

        fn set_upstream(&self, cluster: &str, model: &str) {
            let mut info = self.stream_info.borrow_mut();
            info.upstream_cluster = Some(cluster.to_string());
            info.requested_model = Some(model.to_string());
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
            unimplemented!("spend_limit_filter never stops iteration")
        }
        fn add_decoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!("spend_limit_filter never buffers request data")
        }
        fn inject_decoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!("spend_limit_filter never injects data")
        }
        fn decoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!("spend_limit_filter never consults the decoding buffer")
        }
        fn modify_decoding_buffer(&mut self, _f: &mut dyn FnMut(&mut bytes::BytesMut)) {
            unimplemented!("spend_limit_filter never touches request bytes")
        }
        fn modify_decoded_headers(&mut self, _f: &mut dyn FnMut(&mut RequestHeaders)) -> bool {
            unimplemented!("spend_limit_filter never rewrites request headers")
        }
        fn route(&mut self) -> Option<Arc<RouteEntry>> {
            self.route.clone()
        }
        fn clear_route_cache(&mut self) {
            unimplemented!("spend_limit_filter never rewrites routing headers")
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
            unimplemented!("spend_limit_filter never stops iteration")
        }
        fn add_encoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!("spend_limit_filter never buffers response data")
        }
        fn inject_encoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!("spend_limit_filter never injects data")
        }
        fn encoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!("spend_limit_filter never consults the encoding buffer")
        }
        fn modify_encoding_buffer(&mut self, _f: &mut dyn FnMut(&mut bytes::BytesMut)) {
            unimplemented!("spend_limit_filter never touches response bytes")
        }
        fn stream_info(&mut self) -> RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    fn request_headers() -> RequestHeaders {
        RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
            headers: HeaderMap::new(),
        }
    }

    fn response_headers() -> ResponseHeaders {
        ResponseHeaders {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        }
    }

    fn usage(input: u64) -> LlmTokenUsage {
        LlmTokenUsage {
            input_tokens: input,
            ..Default::default()
        }
    }

    /// A `ControlPlane` with `budgets` set for each named tenant via
    /// `ControlPlane::set_budget` -- the SAME write path (and republish) an
    /// admin `PUT /tenants/{id}/budget` call uses in production, deliberately
    /// NOT `seed_bootstrap_policies` (which only ever writes `ModelAccess`,
    /// never a `TenantBudget` -- see its own doc's "a bootstrap policy seed
    /// can never observe, let alone clobber, a budget an admin set").
    fn control_plane_with(budgets: &[(&str, TenantBudget)]) -> Arc<ControlPlane> {
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(b"test-secret-value-long-enough"),
            KeySet::default(),
        )
        .expect("control plane must build");
        for (tenant, budget) in budgets {
            cp.set_budget(&TenantId::new(*tenant), Some(budget))
                .expect("set_budget must succeed");
        }
        Arc::new(cp)
    }

    /// The shared pieces one test's chain would build once and reuse across
    /// every stream -- exactly `SpendLimitInstanceFactory`'s production
    /// shape. [`Self::new_instance`] is this harness's
    /// `FilterInstanceFactory::create_filter` stand-in: a FRESH
    /// `SpendLimitFilterInstance` per call, sharing the same accumulator/
    /// price table/snapshot. This split matters because
    /// `SpendLimitFilterInstance::recorded` is a per-STREAM guard (see its
    /// doc) -- reusing one instance across what a test means as several
    /// separate "requests" would leak that guard across them and silently
    /// stop the second and later requests from ever recording anything,
    /// exactly the trap `token_limit_filter::tests::run_request_inner`'s own
    /// doc warns about.
    struct FilterHarness {
        price_table: Arc<PriceTable>,
        accumulator: Arc<SpendAccumulator>,
        usage_missing_warner: Arc<UsageMissingWarner>,
        snapshot: Arc<ArcSwap<ControlPlaneSnapshot>>,
    }

    impl FilterHarness {
        fn new_instance(&self) -> SpendLimitFilterInstance {
            SpendLimitFilterInstance {
                price_table: Arc::clone(&self.price_table),
                accumulator: Arc::clone(&self.accumulator),
                usage_missing_warner: Arc::clone(&self.usage_missing_warner),
                snapshot: Arc::clone(&self.snapshot),
                tenant: None,
                period: None,
                budget_applies: false,
                recorded: false,
            }
        }
    }

    /// A harness wired to `control_plane`'s snapshot, a fresh `PriceTable`,
    /// and a fresh accumulator with the given `default_period` -- everything
    /// a decode+encode cycle needs, with no background flusher thread (tests
    /// drive `flush_now`/`current_total` directly where they need to, exactly
    /// like `spend.rs`'s own accumulator tests).
    fn filter_with(
        control_plane: &Arc<ControlPlane>,
        price_table: PriceTable,
        default_period: Period,
    ) -> FilterHarness {
        let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::default());
        let accumulator = Arc::new(SpendAccumulator::new(
            "test-chain".to_string(),
            store,
            default_period,
            "test-node".to_string(),
        ));
        FilterHarness {
            price_table: Arc::new(price_table),
            accumulator,
            usage_missing_warner: Arc::new(UsageMissingWarner::new()),
            snapshot: control_plane.handle(),
        }
    }

    /// `filter_with`, but with a reconciliation bound of ZERO, so the
    /// accumulator is already past its bound by the time a request runs --
    /// the state an operator sees when the shared store is unreachable.
    /// The spin (sub-millisecond, never a sleep) is what makes "past the
    /// bound" true rather than merely likely: `is_reconciled` compares with
    /// `<=`, so a zero bound is still reconciled at age exactly zero.
    fn stale_filter_with(
        control_plane: &Arc<ControlPlane>,
        price_table: PriceTable,
        default_period: Period,
    ) -> FilterHarness {
        let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::default());
        let accumulator = Arc::new(SpendAccumulator::with_reconciliation(
            "test-chain".to_string(),
            store,
            default_period,
            "test-node".to_string(),
            ReconciliationPolicy {
                bound: Duration::ZERO,
                on_expired: OnReconciliationExpired::Allow,
            },
        ));
        while accumulator.reconciliation_age(chrono::Utc::now()) == Duration::ZERO {
            std::hint::spin_loop();
        }
        FilterHarness {
            price_table: Arc::new(price_table),
            accumulator,
            usage_missing_warner: Arc::new(UsageMissingWarner::new()),
            snapshot: control_plane.handle(),
        }
    }

    /// Drives one full request/response cycle against a FRESH
    /// `SpendLimitFilterInstance` from `harness` -- one stream, exactly like
    /// production's `create_filter` per connection. Mirrors
    /// `token_limit_filter::tests::run_request_inner`'s shape.
    fn run_request(
        harness: &FilterHarness,
        tenant: &str,
        cluster_and_model: Option<(&str, &str)>,
        usage_tokens: Option<u64>,
    ) -> (Option<(StatusCode, HeaderMap)>, TestCallbacks) {
        let mut filter = harness.new_instance();
        let mut cb = TestCallbacks::new();
        cb.set_tenant(tenant);
        let mut head = request_headers();
        filter.decode_headers(&mut cb, &mut head, true);

        if cb.local_reply.is_none() {
            if let Some((cluster, model)) = cluster_and_model {
                cb.set_upstream(cluster, model);
            }
            if let Some(tokens) = usage_tokens {
                cb.set_usage(usage(tokens));
            }
            let mut headers = response_headers();
            filter.encode_headers(&mut cb, &mut headers, false);
            let mut data = Bytes::new();
            filter.encode_data(&mut cb, &mut data, true);
        }

        let reply = cb.local_reply.clone();
        (reply, cb)
    }

    // TestCallbacks needs Clone for `local_reply` above -- HeaderMap and
    // StatusCode are both Clone, so a manual small clone is simplest here
    // rather than deriving Clone on the whole struct (which holds a RefCell
    // this test never needs to duplicate).
    impl Clone for TestCallbacks {
        fn clone(&self) -> Self {
            unreachable!("only `local_reply` is ever cloned out of a TestCallbacks")
        }
    }

    // --- WP-62: over-admission while stale ---------------------------------

    /// A stale replica keeps serving (only `Allow` is implemented), and
    /// every admission it makes under a CONFIGURED budget is counted, so
    /// the bypass is visible instead of silent (rule 17).
    ///
    /// Mutation: delete the `note_admission` call in `decode_headers`.
    #[test]
    fn a_budgeted_request_admitted_while_stale_is_counted() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(1_000_000),
                period: Period::Daily,
            },
        )]);
        let harness = stale_filter_with(&cp, PriceTable::new(), Period::Monthly);

        let (reply, _cb) = run_request(&harness, "tenant-a", None, Some(10));

        assert!(
            reply.is_none(),
            "a metering hiccup must not start refusing traffic"
        );
        assert_eq!(
            harness.accumulator.unreconciled_admissions(),
            1,
            "the admission was made against a total that may be missing other replicas' spend"
        );
    }

    /// A tenant with NO ceiling cannot be over-admitted, so its requests
    /// must not be counted -- rule 17's "only warn where the control was
    /// actually meant to apply". Counting them would bury the real signal
    /// under whatever share of traffic happens to be unbudgeted.
    ///
    /// Mutation: move the `note_admission` call above the `Some(budget)`
    /// check in `decode_headers`.
    #[test]
    fn an_unbudgeted_request_admitted_while_stale_is_not_counted() {
        let cp = control_plane_with(&[]);
        let harness = stale_filter_with(&cp, PriceTable::new(), Period::Monthly);

        let (reply, _cb) = run_request(&harness, "tenant-no-budget", None, Some(10));

        assert!(reply.is_none(), "no budget means unlimited");
        assert_eq!(
            harness.accumulator.unreconciled_admissions(),
            0,
            "an unlimited tenant has no ceiling to over-admit against"
        );
    }

    /// Enforcement SURVIVES a store outage: a replica that has already
    /// burned the ceiling on its own traffic still returns 429 while stale,
    /// and a denial is not an admission. This is ADR-0006 §5's claim that
    /// degrading here beats a filter that holds no counter state at all.
    ///
    /// Mutation: move the `note_admission` call above the deny check.
    #[test]
    fn a_stale_replica_still_denies_and_a_denial_is_not_counted() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(0),
                period: Period::Daily,
            },
        )]);
        let harness = stale_filter_with(&cp, PriceTable::new(), Period::Monthly);

        let (reply, _cb) = run_request(&harness, "tenant-a", None, Some(10));

        let (status, _headers) = reply.expect("a zero ceiling denies the first request");
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            harness.accumulator.unreconciled_admissions(),
            0,
            "a refused request was not admitted, stale or not"
        );
    }

    // --- no tenant / no budget: admitted -----------------------------------

    #[test]
    fn no_authenticated_tenant_is_admitted_and_nothing_is_recorded() {
        let cp = control_plane_with(&[]);
        let harness = filter_with(&cp, PriceTable::new(), Period::Monthly);
        let mut filter = harness.new_instance();

        let mut cb = TestCallbacks::new();
        // No `set_tenant` call -- StreamInfo::auth.tenant stays `None`.
        let mut head = request_headers();
        let status = filter.decode_headers(&mut cb, &mut head, true);

        assert_eq!(status, FilterHeadersStatus::Continue);
        assert!(cb.local_reply.is_none(), "no tenant must never be denied");
    }

    /// The accumulator must flush into the SAME store the `ControlPlane`
    /// uses, not a private one of its own.
    ///
    /// This is the difference between spend surviving a restart and a
    /// monthly ceiling an operator could escape by bouncing the proxy. It
    /// goes through the real `SpendLimitFilterFactory::create` (not the test
    /// harness, which is handed an accumulator directly) precisely because
    /// the defect it guards would live in `create`'s wiring, not in the
    /// accumulator.
    #[test]
    fn the_accumulator_flushes_into_the_control_planes_own_store() {
        let cp = Arc::new(
            ControlPlane::new(
                Box::new(InMemoryControlPlaneStore::default()),
                HmacSecret::new(b"test-secret-value-long-enough"),
                KeySet::default(),
            )
            .expect("control plane must build"),
        );

        let ctx = FactoryContext::default();
        ctx.shared
            .get_or_try_init(&ctx.scope, &ctx.stat_prefix, auth_filter::TYPE_URL, || {
                Ok(Arc::clone(&cp) as Arc<dyn std::any::Any + Send + Sync>)
            })
            .expect("registering the control plane must succeed");

        let config = spend_limit_config(vec![]);
        SpendLimitFilterFactory
            .create(&config, &ctx)
            .expect("create must succeed with a ControlPlane registered");

        let accumulator = ctx
            .shared
            .get(&ctx.scope, TYPE_URL)
            .expect("create must register a spend accumulator")
            .downcast::<SharedSpendLimitState>()
            .expect("the spend singleton is always a SharedSpendLimitState");

        let tenant = TenantId::new("tenant-a");
        let now = chrono::Utc::now();
        let period = Period::Monthly;
        accumulator.accumulator.record(
            &tenant,
            now,
            period,
            Charge::Priced(MicroUsd::from_micros(4_242)),
            Some("cluster-a"),
            Some("m"),
        );
        accumulator
            .accumulator
            .flush_now()
            .expect("flush must succeed");

        // Read back through the CONTROL PLANE's own store handle -- if the
        // filter had built a private store, this one would still be empty.
        let stored = cp
            .store()
            .load_spend(&ctx.stat_prefix, &tenant, &period.key_for(now))
            .expect("load_spend must succeed");
        assert_eq!(
            stored, 4_242,
            "spend must be flushed into the ControlPlane's OWN store -- a private \
             store here would reset every tenant's accrued spend on restart while \
             budgets persisted, making a ceiling escapable by bouncing the proxy"
        );
    }

    #[test]
    fn a_tenant_with_no_configured_budget_is_admitted_unlimited() {
        let cp = control_plane_with(&[]);
        let mut table = PriceTable::new();
        table.insert(
            "cluster-a",
            "m",
            ModelPrices {
                input_per_million: MicroUsd::from_micros(1_000_000),
                ..Default::default()
            },
        );
        let filter = filter_with(&cp, table, Period::Monthly);

        // A huge usage that would exhaust virtually any real budget -- an
        // unbudgeted tenant must be admitted regardless.
        let (reply, _cb) = run_request(
            &filter,
            "tenant-unbudgeted",
            Some(("cluster-a", "m")),
            Some(1_000_000_000),
        );
        assert!(reply.is_none(), "an unbudgeted tenant must be unlimited");
    }

    // --- under / over budget -------------------------------------------

    #[test]
    fn under_budget_is_admitted_over_budget_is_denied_with_all_four_headers() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(10_000_000),
                period: Period::Daily,
            },
        )]);

        let mut table = PriceTable::new();
        table.insert(
            "cluster-a",
            "m",
            ModelPrices {
                input_per_million: MicroUsd::from_micros(1_000_000),
                ..Default::default()
            },
        );
        let filter = filter_with(&cp, table, Period::Monthly);

        // 9,000,000 input tokens at $1/million = $9 = 9,000,000 micros --
        // under the $10 budget.
        let (reply, _cb) = run_request(
            &filter,
            "tenant-a",
            Some(("cluster-a", "m")),
            Some(9_000_000),
        );
        assert!(reply.is_none(), "a request under budget must be admitted");

        // Per the module doc's "check/record split is inherent" section: the
        // request whose OWN cost crosses the ceiling is necessarily admitted
        // (its cost isn't known until encode) -- checked against a total of
        // 9,000,000 < 10,000,000. Recording it pushes the total to
        // 11,000,000, past the ceiling.
        let (reply, _cb) = run_request(
            &filter,
            "tenant-a",
            Some(("cluster-a", "m")),
            Some(2_000_000),
        );
        assert!(
            reply.is_none(),
            "the request that CROSSES the ceiling is admitted -- its own cost is unknown \
             at check time"
        );

        // Now the tenant's recorded total (11,000,000) is already at or over
        // the 10,000,000 ceiling -- THIS request is checked against that
        // total before anything about its own cost is known, and must deny.
        let (reply, _cb) = run_request(&filter, "tenant-a", Some(("cluster-a", "m")), Some(1));
        let (status, headers) =
            reply.expect("must be denied once the recorded total is over budget");
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
        assert_eq!(headers.get("x-ratelimit-limit").unwrap(), "10000000");
        assert_eq!(headers.get("x-ratelimit-remaining").unwrap(), "0");
    }

    #[test]
    fn a_denied_request_renders_the_rl_response_flag() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(0),
                period: Period::Daily,
            },
        )]);
        let harness = filter_with(&cp, PriceTable::new(), Period::Monthly);
        let mut filter = harness.new_instance();

        let mut cb = TestCallbacks::new();
        cb.set_tenant("tenant-a");
        let mut head = request_headers();
        filter.decode_headers(&mut cb, &mut head, true);

        assert!(
            cb.local_reply.is_some(),
            "a zero budget must deny immediately"
        );
        let flags = cb.stream_info.borrow().response_flags().to_vec();
        assert_eq!(
            proxy_observability::flags::render_flags(&flags),
            "RL",
            "a request this filter refuses must render exactly `RL`, matching \
             `token_limit_filter`'s own convention"
        );
    }

    // --- zero budget denies immediately ---------------------------------

    #[test]
    fn a_budget_of_exactly_zero_denies_the_very_first_request() {
        let cp = control_plane_with(&[(
            "tenant-zero",
            TenantBudget {
                max_micros: MicroUsd::from_micros(0),
                period: Period::Daily,
            },
        )]);
        let harness = filter_with(&cp, PriceTable::new(), Period::Monthly);
        let mut filter = harness.new_instance();

        let mut cb = TestCallbacks::new();
        cb.set_tenant("tenant-zero");
        let mut head = request_headers();
        filter.decode_headers(&mut cb, &mut head, true);

        assert!(
            cb.local_reply.is_some(),
            "a zero-micro-dollar budget must deny the very first request, per the deliberate \
             zero-ceiling policy"
        );
    }

    // --- unpriced requests never exhaust a budget -----------------------

    #[test]
    fn an_unpriced_cluster_model_costs_zero_and_never_exhausts_the_budget() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(1),
                period: Period::Daily,
            },
        )]);
        // An EMPTY price table -- every (cluster, model) is unpriced.
        let filter = filter_with(&cp, PriceTable::new(), Period::Monthly);

        for _ in 0..5 {
            let (reply, _cb) = run_request(
                &filter,
                "tenant-a",
                Some(("unpriced-cluster", "unpriced-model")),
                Some(1_000_000_000),
            );
            assert!(
                reply.is_none(),
                "an unpriced request must never exhaust a budget, no matter how much usage \
                 it reports"
            );
        }

        let tenant = TenantId::new("tenant-a");
        let now = Utc::now();
        assert_eq!(
            filter
                .accumulator
                .current_total(&tenant, &Period::Daily.key_for(now)),
            0,
            "an unpriced request must add nothing to the spend total"
        );
    }

    // --- admin set_budget changes enforcement with no reload -----------

    #[test]
    fn set_budget_changes_enforcement_on_the_very_next_request_with_no_reload() {
        let cp = control_plane_with(&[]);
        let mut table = PriceTable::new();
        table.insert(
            "cluster-a",
            "m",
            ModelPrices {
                input_per_million: MicroUsd::from_micros(1_000_000),
                ..Default::default()
            },
        );
        let filter = filter_with(&cp, table, Period::Monthly);

        // Before any budget is set: unlimited.
        let (reply, _cb) = run_request(
            &filter,
            "tenant-a",
            Some(("cluster-a", "m")),
            Some(5_000_000),
        );
        assert!(reply.is_none(), "unbudgeted must be admitted");

        // Admin sets a ZERO ceiling -- same shape as 3b-iv's acceptance test
        // (which toggles `ModelAccess`, not a counter): the point is that the
        // SAME `ControlPlane`, the SAME filter instance, and the SAME
        // accumulator are used before and after, with nothing rebuilt or
        // reloaded in between. A zero ceiling denies on `current >= 0`
        // regardless of this tenant's PRIOR (differently-keyed, since it
        // accrued under the accumulator's `default_period` before any budget
        // existed) spend history, so it isolates "did the write take effect"
        // from the unrelated question of period-key carryover.
        cp.set_budget(
            &TenantId::new("tenant-a"),
            Some(&TenantBudget {
                max_micros: MicroUsd::from_micros(0),
                period: Period::Daily,
            }),
        )
        .expect("set_budget must succeed");

        let (reply, _cb) = run_request(&filter, "tenant-a", Some(("cluster-a", "m")), Some(1));
        assert!(
            reply.is_some(),
            "the newly configured budget must be enforced on the very next request, with \
             no reload"
        );
    }

    // --- period rollover restores budget ---------------------------------

    #[test]
    fn period_rollover_restores_budget() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(1_000_000),
                period: Period::Daily,
            },
        )]);
        let mut table = PriceTable::new();
        table.insert(
            "cluster-a",
            "m",
            ModelPrices {
                input_per_million: MicroUsd::from_micros(1_000_000),
                ..Default::default()
            },
        );
        let filter = filter_with(&cp, table, Period::Monthly);

        // Exhaust today's budget.
        let (reply, _cb) = run_request(
            &filter,
            "tenant-a",
            Some(("cluster-a", "m")),
            Some(1_000_000),
        );
        assert!(
            reply.is_none(),
            "the exhausting request must itself be admitted"
        );

        let (reply, _cb) = run_request(&filter, "tenant-a", Some(("cluster-a", "m")), Some(1));
        assert!(reply.is_some(), "the next request today must be denied");

        // Simulate a period rollover directly against the accumulator (the
        // same technique `token_limit_filter`'s own rollover test uses):
        // record a charge under TOMORROW's period key so `current_total` for
        // tomorrow starts fresh, then check tomorrow's key directly rather
        // than waiting on the real wall clock.
        let tenant = TenantId::new("tenant-a");
        let tomorrow = Utc::now() + chrono::Duration::days(1);
        let tomorrow_key = Period::Daily.key_for(tomorrow);
        assert_eq!(
            filter.accumulator.current_total(&tenant, &tomorrow_key),
            0,
            "a new day's period key must start at zero even though today's is exhausted -- \
             this is what lets tomorrow's request be admitted with no operator action"
        );
    }

    // --- loud on unreadable usage (rule 17) -----------------------------

    struct WarnCapture {
        count: std::sync::atomic::AtomicUsize,
        messages: Mutex<Vec<String>>,
    }

    impl WarnCapture {
        fn new() -> Self {
            WarnCapture {
                count: std::sync::atomic::AtomicUsize::new(0),
                messages: Mutex::new(Vec::new()),
            }
        }
    }

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
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            struct MessageVisitor<'a>(&'a mut String);
            impl tracing::field::Visit for MessageVisitor<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        *self.0 = format!("{value:?}");
                    }
                }
            }
            let mut message = String::new();
            event.record(&mut MessageVisitor(&mut message));
            self.messages.lock().unwrap().push(message);
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    #[test]
    fn missing_usage_on_a_budgeted_tenant_warns_and_charges_nothing() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(10_000_000),
                period: Period::Daily,
            },
        )]);
        let filter = filter_with(&cp, PriceTable::new(), Period::Monthly);

        let capture = Arc::new(WarnCapture::new());
        let guard = tracing::subscriber::set_default(capture.clone());

        let (reply, _cb) = run_request(&filter, "tenant-a", Some(("cluster-a", "m")), None);
        assert!(reply.is_none(), "must not be denied");

        drop(guard);
        assert_eq!(
            capture.count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a budgeted tenant's missing usage must warn exactly once"
        );
        assert!(
            capture.messages.lock().unwrap()[0].contains("spend_limit"),
            "the warning must identify itself as coming from spend_limit"
        );
    }

    #[test]
    fn missing_usage_on_an_unbudgeted_tenant_stays_silent() {
        let cp = control_plane_with(&[]);
        let filter = filter_with(&cp, PriceTable::new(), Period::Monthly);

        let capture = Arc::new(WarnCapture::new());
        let guard = tracing::subscriber::set_default(capture.clone());

        let (reply, _cb) = run_request(&filter, "tenant-a", Some(("cluster-a", "m")), None);
        assert!(reply.is_none());

        drop(guard);
        assert_eq!(
            capture.count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "an unbudgeted tenant's missing usage must stay silent -- nothing was being \
             enforced for this request in the first place"
        );
    }
}
