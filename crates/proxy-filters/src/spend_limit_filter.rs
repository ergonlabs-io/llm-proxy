//! Enforces spend budgets through decode admission and records completed
//! request costs on encode. Costs arrive only at response end, so admitted
//! in-flight requests can exceed a ceiling; there are no reservations.
//!
//! Configure auth before this filter (decode order) and usage after it
//! (reverse encode order, S2.1). Budgets apply only to matching credential
//! sources (ADR-0007 decision 8). Missing identity is denied only when a
//! budget is configured; absent budgets mean unlimited while spend remains
//! reportable. A configured zero ceiling denies immediately.
//!
//! Admission reads the live accumulator, never the last flush. It shares the
//! auth control-plane store so persisted budgets and spend survive restarts;
//! unreadable applicable usage warns and records zero rather than denying a
//! completed request (AGENTS.md "Fail-open controls").
//!
//! A budget that binds a request refuses it with 403 `endpoint_not_metered`
//! when its endpoint cannot be counted (batches, files and every unknown
//! path; ADR-0010 decision 1, [`crate::unmetered`]), and, at the end of the
//! body, when a speech, transcription, translation or image edit request has
//! a shape that cannot be counted (decision 5). Free
//! endpoints (`GET .../models`, `GET .../usage`,
//! `POST .../messages/count_tokens`) pass without a missing-usage warning.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use chrono::Utc;
use http::StatusCode;
use prost_reflect::DynamicMessage;

use proxy_config::ConfigError;
use proxy_credentials::CredentialSource;
use proxy_http::endpoint::Endpoint;
use proxy_http::filter::{
    DecoderCallbacks, EncoderCallbacks, FactoryContext, FilterDataStatus, FilterHeadersStatus,
    FilterInstanceFactory, FilterTrailersStatus, HttpFilter, HttpFilterFactory, RequestHeaders,
    RequestTrailers, ResponseHeaders, ResponseTrailers,
};
use proxy_http::stream_info::LlmSpendCharge;
use proxy_observability::records::{ChargeScope, ChargedScope};
use proxy_observability::ResponseFlag;

use crate::auth::{KeyId, TenantId};
use crate::auth_filter;
use crate::control::{ControlPlane, ControlPlaneSnapshot};
use crate::spend::{
    self, Charge, MicroUsd, OnReconciliationExpired, Period, ReconciliationPolicy, SpendAccumulator,
};
use crate::unmetered::{self, RefusalCounter};
use crate::usage_filter::PricingRegistry;

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

/// Reads `typed_config.default_period` (a `Period` enum) -- `PERIOD_UNSPECIFIED`
/// (proto3's implicit zero, and an absent field reads the same way) means
/// `MONTHLY`, per the proto's own doc; any other value this build's
/// descriptor pool does not recognize is a hard `Err`, per AGENTS.md invariant 1 --
/// silently treating an unrecognized enum number as a default would be
/// exactly the kind of "config means one thing, does another" AGENTS.md invariant 1
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
/// (ADR-0006 §5).
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
/// silently ignoring a config field, which AGENTS.md invariant 1 calls a P0 bug, and
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
/// this filter has no per-route config; the trait default
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
        let default_period = parse_default_period(config)?;
        let flush_interval = parse_flush_interval(config);
        let reconciliation = parse_reconciliation(config)?;
        let journal_path = config
            .get_field_by_name("recovery_journal_path")
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let cutover = config
            .get_field_by_name("legacy_tenant_budget_cutover")
            .and_then(|v| v.as_enum_number())
            .unwrap_or(0);
        if !matches!(cutover, 0 | 1) {
            return Err(invalid(
                "typed_config.legacy_tenant_budget_cutover",
                "unsupported cutover policy",
            ));
        }
        if !journal_path.is_empty() && (ctx.node_id().is_empty() || ctx.node_id() == "-") {
            return Err(invalid(
                "typed_config.recovery_journal_path",
                "recovery requires an explicit stable service_node or bootstrap node.id",
            ));
        }

        // Resolve the SAME `ControlPlane` singleton
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

        if cutover == 0
            && control_plane
                .handle()
                .load()
                .policies
                .values()
                .any(|policy| policy.budget.is_some())
        {
            return Err(invalid(
                "typed_config.legacy_tenant_budget_cutover",
                "legacy tenant budgets require an explicit START_KEYS_FRESH cutover; retain history and configure key budgets before serving",
            ));
        }

        // Seed or join the usage filter's live rate-card registry. The usage
        // factory may be built later because spend must precede usage in the
        // encode chain, so this creates an empty slot that usage fills once it
        // parses the listener pricing config.
        let pricing_registry = crate::usage_filter::registry_for_chain(ctx)?;

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
        // `ControlPlane::store()`. A private store here would leave the
        // whole spend persistence path wired to nothing and reset every tenant's
        // accrued spend on restart -- a ceiling an operator could escape by
        // bouncing the proxy.
        let store = control_plane.store();
        // Looked up before `get_or_try_init`: its closure runs under the
        // singleton map's lock, which `get` also takes.
        let stats_registry = ctx
            .shared
            .get("", crate::usage_filter::STATS_REGISTRY_KEY)
            .and_then(|any| any.downcast::<proxy_observability::stats::Registry>().ok());
        let stats_registry_for_refusals = stats_registry.clone();
        let shared = ctx
            .get_or_try_init(TYPE_URL, || {
                let mut accumulator = SpendAccumulator::with_reconciliation(
                    ctx.stat_prefix.clone(),
                    store,
                    default_period,
                    resolve_node_id(ctx.node_id(), &ctx.stat_prefix),
                    reconciliation,
                );
                if !journal_path.is_empty() {
                    accumulator = accumulator
                        .with_recovery_journal(std::path::Path::new(&journal_path))
                        .map_err(|err| {
                            invalid("typed_config.recovery_journal_path", err.to_string())
                        })?;
                }
                let keys: Vec<_> = control_plane
                    .list_keys()
                    .into_iter()
                    .map(|key| key.key_id)
                    .collect();
                let snapshot = control_plane.handle().load_full();
                let tenants: Vec<_> = snapshot.key_tenants.values().cloned().collect();
                // A failed prefetch fails open, loudly: see
                // `SpendAccumulator::prepare_request_workers`.
                if let Err(err) = accumulator
                    .prepare_tenant_request_workers(&tenants)
                    .and(accumulator.prepare_request_workers(&keys))
                {
                    warn_prefetch_failed(&ctx.stat_prefix, &err);
                }
                let accumulator = Arc::new(accumulator);
                if let Some(registry) = &stats_registry {
                    accumulator.export_reconciliation_age(Arc::clone(registry));
                }
                accumulator.start_flusher(flush_interval);
                Ok(Arc::new(SharedSpendLimitState {
                    accumulator,
                    charged: stats_registry.map(|r| Arc::new(SpendChargedCounter::new(r))),
                    usage_missing_warner: Arc::new(UsageMissingWarner::new()),
                    unpriced_warner: Arc::new(UnpricedWarner::new(ctx.stat_prefix.clone())),
                    legacy_tenant_budget_cutover: AtomicBool::new(cutover == 1),
                }) as Arc<dyn std::any::Any + Send + Sync>)
            })?
            .downcast::<SharedSpendLimitState>()
            .expect("spend_limit singleton is always a SharedSpendLimitState");
        // The singleton outlives a reload, so record what THIS build's
        // configuration says: the admin API answers from it.
        shared
            .legacy_tenant_budget_cutover
            .store(cutover == 1, Ordering::Relaxed);

        Ok(Box::new(SpendLimitInstanceFactory {
            pricing_registry,
            accumulator: Arc::clone(&shared.accumulator),
            charged: shared.charged.clone(),
            unmetered: stats_registry_for_refusals.map(|r| Arc::new(RefusalCounter::new(r))),
            usage_missing_warner: Arc::clone(&shared.usage_missing_warner),
            unpriced_warner: Arc::clone(&shared.unpriced_warner),
            snapshot: control_plane.handle(),
        }))
    }
}

/// `llmproxy_spend_charged_micro_usd_total`: one series per process, which
/// every chain's spend filter adds to.
struct SpendChargedCounter {
    registry: Arc<proxy_observability::stats::Registry>,
    handle: proxy_observability::stats::Handle,
}

impl SpendChargedCounter {
    fn new(registry: Arc<proxy_observability::stats::Registry>) -> Self {
        // No attributes, so the cap is never reached; `resolve_capped` is
        // how a filter without the control-side `StatsControl` resolves.
        let handle = registry.resolve_capped(
            &proxy_observability::stats::instruments::SPEND_CHARGED,
            &[],
            1,
            &[],
        );
        Self { registry, handle }
    }

    fn add(&self, micro_usd: u64) {
        self.registry.incr(
            proxy_observability::stats::WorkerId(0),
            self.handle,
            micro_usd,
        );
    }
}

/// The pieces every worker building the SAME chain must share -- see
/// `create`'s doc for why both live behind ONE `SharedFactoryState` slot.
///
/// `pub` (crossing the crate boundary) because the admin
/// spend read (`proxy-admin`) downcasts to this exact type: what is
/// registered under [`TYPE_URL`] in [`proxy_http::filter::SharedFactoryState`]
/// is THIS wrapper, never a bare `Arc<SpendAccumulator>` -- an admin-side
/// downcast straight to `SpendAccumulator` would silently fail every time.
/// `usage_missing_warner` stays private; only [`Self::accumulator`] is ever
/// read from outside this module.
pub struct SharedSpendLimitState {
    accumulator: Arc<SpendAccumulator>,
    charged: Option<Arc<SpendChargedCounter>>,
    usage_missing_warner: Arc<UsageMissingWarner>,
    unpriced_warner: Arc<UnpricedWarner>,
    /// Whether `typed_config.legacy_tenant_budget_cutover` is set. Without it,
    /// the next start refuses to load a tenant budget from the store (see
    /// `create`), so the admin API must not write one. An atomic because a
    /// reload can change it while the admin server reads it.
    legacy_tenant_budget_cutover: AtomicBool,
}

impl SharedSpendLimitState {
    /// Whether this chain's spend filter was configured with
    /// `legacy_tenant_budget_cutover`. `PUT /tenants/{id}/budget` refuses to
    /// store a budget when it was not: the budget would stop the next start.
    pub fn legacy_tenant_budget_cutover(&self) -> bool {
        self.legacy_tenant_budget_cutover.load(Ordering::Relaxed)
    }

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
            charged: None,
            usage_missing_warner: Arc::new(UsageMissingWarner::new()),
            unpriced_warner: Arc::new(UnpricedWarner::new(String::new())),
            legacy_tenant_budget_cutover: AtomicBool::new(true),
        }
    }

    /// As [`Self::for_test`], for a filter configured WITHOUT the cutover,
    /// which is what production builds unless the operator sets it.
    #[doc(hidden)]
    pub fn for_test_without_cutover(accumulator: Arc<SpendAccumulator>) -> Self {
        let state = Self::for_test(accumulator);
        state
            .legacy_tenant_budget_cutover
            .store(false, Ordering::Relaxed);
        state
    }
}

struct SpendLimitInstanceFactory {
    pricing_registry: Arc<PricingRegistry>,
    accumulator: Arc<SpendAccumulator>,
    charged: Option<Arc<SpendChargedCounter>>,
    unmetered: Option<Arc<RefusalCounter>>,
    usage_missing_warner: Arc<UsageMissingWarner>,
    unpriced_warner: Arc<UnpricedWarner>,
    /// One handle per (filter config, listener), shared by every per-stream
    /// instance -- same pattern as `model_authz_filter`'s
    /// `ModelAuthzInstanceFactory::snapshot`.
    snapshot: Arc<ArcSwap<ControlPlaneSnapshot>>,
}

impl FilterInstanceFactory for SpendLimitInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(SpendLimitFilterInstance {
            pricing_snapshot: self.pricing_registry.snapshot_context(),
            accumulator: Arc::clone(&self.accumulator),
            charged: self.charged.clone(),
            unmetered: self.unmetered.clone(),
            usage_missing_warner: Arc::clone(&self.usage_missing_warner),
            unpriced_warner: Arc::clone(&self.unpriced_warner),
            snapshot: Arc::clone(&self.snapshot),
            endpoint: Endpoint::Unmetered,
            key_id: None,
            tenant: None,
            period: None,
            key_budget_scope: None,
            tenant_budget_scope: None,
            budget_applies: false,
            recorded: false,
            body_checked: false,
        })
    }
}

/// Warns, at most once per key per [`Self::REPEAT_INTERVAL`], when a
/// budget actually applied to a request but its usage could not be read at
/// encode time -- see the module doc's "Loud on unreadable usage" section.
/// Mirrors `token_limit_filter::UsageMissingWarner` structurally; kept as a
/// separate type because it dedups on [`KeyId`], not `token_limit`'s
/// `LimitKey`, and needs no credential hashing (see the module doc for why).
struct UsageMissingWarner {
    last_warned: Mutex<HashMap<KeyId, Instant>>,
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

    fn warn_if_due(&self, key_id: &KeyId, now: Instant) {
        // Rust note: `unwrap_or_else(PoisonError::into_inner)` recovers from
        // a poisoned lock rather than panicking -- same convention as
        // `token_limit_filter::UsageMissingWarner::warn_if_due`.
        let mut last_warned = self
            .last_warned
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let due = match last_warned.get(key_id) {
            Some(&last) => now.saturating_duration_since(last) >= Self::REPEAT_INTERVAL,
            None => true,
        };
        if !due {
            return;
        }
        last_warned.insert(key_id.clone(), now);
        drop(last_warned);

        tracing::warn!(
            key_id = key_id.as_str(),
            "spend_limit: this key's spend budget was NOT enforced for this request and \
             nothing was charged against it -- usage could not be extracted from the response \
             (StreamInfo::llm.usage was None). The most likely cause is that the llmproxy.usage \
             filter's configured `dialect` does not match this provider's actual response shape \
             for this route; check that first."
        );
    }
}

/// Most distinct unpriced model names one chain remembers. Model names are
/// chosen by the client, so an unbounded set would let a caller grow this
/// process's memory by sending made-up models.
const MAX_UNPRICED_MODELS_REMEMBERED: usize = 256;

/// Longest model name copied into the set or a log line.
const MAX_UNPRICED_MODEL_CHARS: usize = 128;

/// Warns, once per model per chain, when a dollar budget counted a request as
/// $0 because nothing prices its model. Repeats are suppressed, or the log
/// becomes the incident; the set of remembered names is capped, and hitting the
/// cap logs one summary line instead of one line per further name.
struct UnpricedWarner {
    chain: String,
    seen: Mutex<UnpricedSeen>,
    /// Models already warned about for modality tokens charged at the text
    /// rate (ADR-0010 decision 3). Separate from `seen`: a model can be both.
    underpriced: Mutex<UnpricedSeen>,
}

#[derive(Default)]
struct UnpricedSeen {
    models: std::collections::HashSet<String>,
    cap_reported: bool,
}

impl UnpricedWarner {
    fn new(chain: String) -> Self {
        UnpricedWarner {
            chain,
            seen: Mutex::new(UnpricedSeen::default()),
            underpriced: Mutex::new(UnpricedSeen::default()),
        }
    }

    /// The bounded model name, when this is the first time `seen` meets it.
    /// Past the cap, says so once and remembers nothing more.
    fn first_time(
        &self,
        seen: &Mutex<UnpricedSeen>,
        model: Option<&str>,
        cap_message: &'static str,
    ) -> Option<String> {
        let name: String = model
            .unwrap_or("(no model)")
            .chars()
            .take(MAX_UNPRICED_MODEL_CHARS)
            .collect();
        let mut seen = seen.lock().unwrap_or_else(PoisonError::into_inner);
        if seen.models.contains(&name) {
            return None;
        }
        if seen.models.len() >= MAX_UNPRICED_MODELS_REMEMBERED {
            let first_time = !seen.cap_reported;
            seen.cap_reported = true;
            drop(seen);
            if first_time {
                tracing::warn!(
                    chain = %self.chain,
                    remembered = MAX_UNPRICED_MODELS_REMEMBERED,
                    "{cap_message}"
                );
            }
            return None;
        }
        seen.models.insert(name.clone());
        Some(name)
    }

    /// A request under a dollar budget reported image or audio tokens its
    /// entry has no modality rate for. It was charged at the text rate, so the
    /// budget counted less than the provider bills: loud, once per model.
    fn note_underpriced(&self, model: Option<&str>, cluster: Option<&str>) {
        let Some(name) = self.first_time(
            &self.underpriced,
            model,
            "spend_limit: more distinct underpriced model names than this chain remembers; \
             further ones are still counted in llmproxy_usage_underpriced_modality_requests_total, \
             but are no longer named here",
        ) else {
            return;
        };
        // Debug formatting for the client-chosen name, as in `note`.
        tracing::warn!(
            chain = %self.chain,
            model = ?name,
            cluster = ?cluster,
            "spend_limit: a request under a dollar budget reported image or audio tokens that \
             its rate-card entry has no modality rate for, so they were charged at the text \
             rate, below the provider's price. Add the image_* or audio_* rates to the entry \
             (PUT /pricing). Counted in llmproxy_usage_underpriced_modality_requests_total; \
             logged once per model."
        );
    }

    /// `reason` runs only when a line is actually written.
    fn note(&self, model: Option<&str>, cluster: Option<&str>, reason: impl FnOnce() -> String) {
        let Some(name) = self.first_time(
            &self.seen,
            model,
            "spend_limit: more distinct unpriced model names than this chain remembers; \
             further ones are still charged $0 against dollar budgets and counted in \
             unpriced_requests, but are no longer named here",
        ) else {
            return;
        };
        // Debug formatting for the client-chosen name, so control characters
        // in it cannot forge a log line. Nothing credential-shaped is in this
        // line: the chain, cluster and model names and the reason.
        tracing::warn!(
            chain = %self.chain,
            model = ?name,
            cluster = ?cluster,
            reason = %reason(),
            "spend_limit: a request under a dollar budget was charged $0 because no price \
             applies to it, so the budget did not count it. Add the model to the rate card \
             (PUT /pricing). Logged once per model."
        );
    }
}

/// Per-stream instance. Plain fields, no `Rc`/`RefCell` (never leaves the
/// worker thread that owns the stream) -- `accumulator`/
/// `usage_missing_warner`/`snapshot` are the cross-thread-shared pieces, each
/// an `Arc` clone, not shared interior state of this struct itself.
struct SpendLimitFilterInstance {
    pricing_snapshot: Option<crate::usage_filter::PricingContext>,
    accumulator: Arc<SpendAccumulator>,
    /// `None` only where no stats registry exists (unit tests).
    charged: Option<Arc<SpendChargedCounter>>,
    /// `None` only where no stats registry exists (unit tests).
    unmetered: Option<Arc<RefusalCounter>>,
    usage_missing_warner: Arc<UsageMissingWarner>,
    unpriced_warner: Arc<UnpricedWarner>,
    snapshot: Arc<ArcSwap<ControlPlaneSnapshot>>,
    /// The request's endpoint class, set at admission.
    endpoint: Endpoint,
    /// Authenticated key and its reporting period, captured at admission.
    key_id: Option<KeyId>,
    period: Option<Period>,
    /// Tenant aggregation uses its own budget period independently of the key.
    tenant: Option<(TenantId, Period)>,
    /// The configured KEY budget's scope, captured at admission even when it
    /// did not match this request's mode: a non-matching budget is absent for
    /// admission (ADR-0007 decision 8) but still decides at encode whether
    /// this subject may be charged at all. `None` means no key budget was
    /// configured, and such a subject always records (reporting).
    key_budget_scope: Option<CredentialSource>,
    /// The tenant-budget twin of [`Self::key_budget_scope`].
    tenant_budget_scope: Option<CredentialSource>,
    /// Whether a budget actually applied to this request -- distinguishes
    /// "no usage at encode time on a budgeted tenant" (warn: see the module
    /// doc) from "no usage on an unbudgeted tenant" (silent: nothing was
    /// ever being enforced for this request in the first place).
    budget_applies: bool,
    /// Guards against double-recording from more than one encode callback
    /// observing `end_stream` -- mirrors `token_limit_filter`'s identical
    /// flag.
    recorded: bool,
    /// The body-time shape check ran (ADR-0010 decision 1, "Two admission
    /// points"); `decode_data` and `decode_trailers` can both end a body.
    body_checked: bool,
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

        let Some(key_id) = self.key_id.clone() else {
            return;
        };
        let period = self
            .period
            .expect("period is always set alongside key in decode_headers");

        // Rust note: read every field out of the `RefMut` guard and drop it
        // before calling `self.accumulator.record` below -- `stream_info()`
        // must not be held across another call (see its doc), same pattern
        // as `token_limit_filter::record_if_present`.
        let (usage, cluster, model, selected_model, served_model, credential_source) = {
            let info = cb.stream_info();
            (
                info.llm.usage.clone(),
                info.upstream_cluster.clone(),
                info.routing_model().map(str::to_owned),
                info.selected_model.clone(),
                info.llm.served_model.clone(),
                info.credential_source,
            )
        };

        let Some(usage) = usage else {
            // Silence is not a metering gap when nothing could be billed: a
            // free endpoint costs nothing, and a request that reached no
            // provider (a synthetic 404, a local reply) spent nothing.
            if self.budget_applies && self.endpoint != Endpoint::Free && cluster.is_some() {
                self.usage_missing_warner
                    .warn_if_due(&key_id, Instant::now());
            }
            return;
        };

        // Price at the same model the usage filter priced the logged cost at,
        // so the spend charge and the record agree when a provider served a
        // different model than the one sent.
        let sent_model = selected_model.as_deref().or(model.as_deref());
        let priced = PricingRegistry::price_served(
            self.pricing_snapshot.as_ref(),
            cluster.as_deref(),
            sent_model,
            served_model.as_deref(),
            &usage,
        );
        if self.budget_applies && priced.is_some_and(|priced| priced.underpriced_modality) {
            self.unpriced_warner
                .note_underpriced(sent_model, cluster.as_deref());
        }
        let charge = priced.map_or(Charge::Unpriced, |priced| {
            Charge::Priced(MicroUsd::from_micros(PricingRegistry::charge_micro_usd(
                priced.nanodollars,
            )))
        });

        // A configured dollar budget just counted this request as $0 because
        // nothing prices it. That is fail-open by design (a metering gap must
        // not refuse traffic), so it has to be loud (AGENTS.md "Fail-open
        // controls"). Only where a budget actually applies: an unbudgeted
        // subject's unpriced request bypasses nothing. The warner's state is
        // touched here and nowhere on the priced path.
        if self.budget_applies && matches!(charge, Charge::Unpriced) {
            let priced_model = selected_model.as_deref().or(model.as_deref());
            self.unpriced_warner
                .note(priced_model, cluster.as_deref(), || {
                    PricingRegistry::explain_unpriced(
                        self.pricing_snapshot.as_ref(),
                        cluster.as_deref(),
                        priced_model,
                        &usage,
                    )
                });
        }

        let now = Utc::now();
        let mut scopes = Vec::new();
        // ADR-0007 decision 8: spend is added to a budget only when the
        // attempt's source matches the budget's scope. A subject with NO
        // configured budget records unconditionally -- those counters also
        // serve spend reporting. A budgeted subject records only when the
        // router actually attempted the request under that budget's source:
        // `credential_source` is `None` when no attempt reached the
        // credential step (ADR-0007 decision 7), which matches no scope.
        if self
            .key_budget_scope
            .is_none_or(|scope| credential_source == Some(scope))
        {
            self.accumulator.record_key(
                &key_id,
                now,
                period,
                charge,
                cluster.as_deref(),
                selected_model.as_deref().or(model.as_deref()),
            );
            scopes.push(ChargedScope {
                scope: ChargeScope::Key,
                id: key_id.as_str().to_owned(),
                period: period.key_for(now).as_str().to_owned(),
            });
        }
        if let Some((tenant, tenant_period)) = &self.tenant {
            if self
                .tenant_budget_scope
                .is_none_or(|scope| credential_source == Some(scope))
            {
                self.accumulator.record(
                    tenant,
                    now,
                    *tenant_period,
                    charge,
                    cluster.as_deref(),
                    selected_model.as_deref().or(model.as_deref()),
                );
                scopes.push(ChargedScope {
                    scope: ChargeScope::Tenant,
                    id: tenant.as_str().to_owned(),
                    period: tenant_period.key_for(now).as_str().to_owned(),
                });
            }
        }
        // The ledger copies this rather than pricing the request again: the
        // usage filter's card snapshot can differ from this one across a
        // card swap (ADR-0009 decision 4).
        let (micro_usd, rate_card_version) = match charge {
            Charge::Priced(amount) => (
                amount.as_micros(),
                self.pricing_snapshot
                    .as_ref()
                    .map(|pricing| pricing.version().to_owned()),
            ),
            Charge::Unpriced => (0, None),
        };
        // ADR-0009 decision 7: the spend side of ledger reconciliation,
        // counted where the charge was made, not where the entry is built,
        // so a charge whose entry never reaches the ledger still shows.
        if !scopes.is_empty() {
            if let Some(charged) = &self.charged {
                charged.add(micro_usd);
            }
        }
        cb.stream_info().llm.spend_charge = Some(LlmSpendCharge {
            micro_usd,
            rate_card_version,
            scopes,
        });
    }
}

impl SpendLimitFilterInstance {
    /// Refuse a budgeted request whose body shape cannot be counted
    /// (ADR-0010 decision 5), with the same 403 as an unmetered endpoint.
    /// Only the endpoints whose countability depends on the body are
    /// checked, and only where a budget binds the request.
    fn admit_body(&mut self, cb: &mut dyn DecoderCallbacks) {
        if self.body_checked || !self.budget_applies || !unmetered::needs_body_facts(self.endpoint)
        {
            return;
        }
        self.body_checked = true;
        let countable = {
            let info = cb.stream_info();
            unmetered::countable_under_spend(
                self.endpoint,
                info.requested_model.is_some(),
                &info.request_facts,
            )
        };
        if !countable {
            // Nothing was dialled, so there is nothing to record.
            self.recorded = true;
            unmetered::refuse(
                cb,
                self.endpoint,
                unmetered::Control::Spend,
                self.unmetered.as_deref(),
            );
        }
    }
}

impl HttpFilter for SpendLimitFilterInstance {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        end_stream: bool,
    ) -> FilterHeadersStatus {
        self.endpoint = cb.stream_info().llm.endpoint;
        // Rust note: `stream_info()` hands back a `RefMut` guard that must
        // not be held across another call on `cb` -- cloning the
        // `Option<String>` out and letting the guard drop at the end of this
        // block keeps that rule visibly satisfied, same pattern as
        // `token_limit_filter`/`model_authz_filter`.
        let (key_id, tenant, mode) = {
            let info = cb.stream_info();
            // ADR-0007 decision 5: a tenant holding any credential is in
            // tenant mode; the auth filter is what puts the set on
            // `StreamInfo` (decision 4). An absent or empty set means this
            // request runs on the operator's credential -- platform mode.
            let mode = match info.tenant_credentials.as_ref() {
                Some(set) if !set.is_empty() => CredentialSource::Tenant,
                _ => CredentialSource::Platform,
            };
            (info.auth.key_id.clone(), info.auth.tenant.clone(), mode)
        };
        let snapshot = self.snapshot.load();
        let tenant_budgets_configured = (key_id.is_none() || tenant.is_none())
            && snapshot.policies.values().any(|p| p.budget.is_some());
        let Some(key_id) = key_id else {
            self.key_id = None;
            self.period = None;
            self.tenant = None;
            self.budget_applies = false;
            self.key_budget_scope = None;
            self.tenant_budget_scope = None;
            if !snapshot.key_budgets.is_empty() || tenant_budgets_configured {
                cb.send_local_reply(
                    StatusCode::FORBIDDEN,
                    "authenticated key identity required for spend policy",
                    None,
                    "spend_identity_missing",
                );
                return FilterHeadersStatus::StopIteration;
            }
            return FilterHeadersStatus::Continue;
        };
        if tenant.is_none() && tenant_budgets_configured {
            cb.send_local_reply(
                StatusCode::FORBIDDEN,
                "authenticated tenant identity required for spend policy",
                None,
                "spend_identity_missing",
            );
            return FilterHeadersStatus::StopIteration;
        }

        let key_id = KeyId::new(key_id);
        let tenant = tenant.map(TenantId::new);
        // The CONFIGURED budgets, whatever their scope: a budget's scope
        // decides at encode whether its subject may be charged (ADR-0007
        // decision 8), so it is captured even for a budget this request does
        // not enforce below.
        let key_budget_configured = snapshot.key_budgets.get(&key_id).copied();
        let tenant_budget_configured = tenant
            .as_ref()
            .and_then(|id| snapshot.policies.get(id.as_str()))
            .and_then(|p| p.budget);
        // Admission enforces only the budgets whose scope matches this
        // request's mode. A non-matching budget is treated as absent for
        // this request (ADR-0007 decision 8): no ceiling to compare, no
        // budget period, `budget_applies` stays false -- exactly the
        // behaviour of a subject with no budget at all.
        let key_budget = key_budget_configured.filter(|b| b.credential_source == mode);
        let tenant_budget = tenant_budget_configured.filter(|b| b.credential_source == mode);
        let default_period = self.accumulator.default_period();
        self.key_id = Some(key_id.clone());
        self.period = Some(key_budget.map(|b| b.period).unwrap_or(default_period));
        self.tenant = tenant.clone().map(|id| {
            (
                id,
                tenant_budget.map(|b| b.period).unwrap_or(default_period),
            )
        });
        self.budget_applies = key_budget.is_some() || tenant_budget.is_some();
        self.key_budget_scope = key_budget_configured.map(|b| b.credential_source);
        self.tenant_budget_scope = tenant_budget_configured.map(|b| b.credential_source);
        // A budget that binds this request must be able to count it, or the
        // request would be charged $0 (ADR-0010 decision 1). Refused before
        // the ceiling check: the request is uncountable whatever the spend.
        if self.budget_applies
            && self.endpoint != Endpoint::Free
            && !unmetered::metered_under_spend(self.endpoint)
        {
            // Nothing was dialled, so there is nothing to record.
            self.recorded = true;
            unmetered::refuse(
                cb,
                self.endpoint,
                unmetered::Control::Spend,
                self.unmetered.as_deref(),
            );
            return FilterHeadersStatus::Continue;
        }
        // A body that never comes proves nothing the shape check needs.
        if end_stream && self.budget_applies && unmetered::needs_body_facts(self.endpoint) {
            self.admit_body(cb);
            return FilterHeadersStatus::Continue;
        }
        let now = Utc::now();
        let ceilings = [
            key_budget.map(|budget| {
                (
                    budget,
                    self.accumulator
                        .current_total_key(&key_id, &budget.period.key_for(now)),
                )
            }),
            tenant_budget.map(|budget| {
                (
                    budget,
                    self.accumulator.current_total(
                        tenant
                            .as_ref()
                            .expect("tenant budget requires tenant identity"),
                        &budget.period.key_for(now),
                    ),
                )
            }),
        ];
        for (budget, current_micros) in ceilings.into_iter().flatten() {
            let period = budget.period;
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
        }
        if !self.budget_applies {
            return FilterHeadersStatus::Continue;
        }

        // Admitted, under a CONFIGURED budget. If this replica has not
        // reconciled with the store within its bound, `current_micros` above
        // may be missing what other replicas spent, so this admission is one
        // the shared ceiling might not actually have had room for.
        //
        // Counted, not refused: ADR-0006 §5's `on_reconciliation_expired`,
        // of which only `Allow` is implemented -- a metering hiccup must not
        // start refusing traffic (AGENTS.md "Fail-open controls"). The counter and the flusher's
        // warning are what make the over-admission VISIBLE rather than
        // silent, which is the whole difference between this and the
        // fail-open bug AGENTS.md "Fail-open controls" was written for.
        //
        // Deliberately after the deny check, so a replica that has already
        // burned the budget on its OWN traffic still returns 429 while
        // stale -- that is the enforcement that survives a store outage, and
        // counting it as an admission would misreport it.
        //
        // Deliberately inside the `Some(budget)` path: a tenant with no
        // ceiling cannot be over-admitted, so counting it would bury the
        // real signal (AGENTS.md "Fail-open controls": only where the control was meant to apply).
        match self.accumulator.reconciliation_policy().on_expired {
            OnReconciliationExpired::Allow => {
                self.accumulator.note_admission(now);
            }
        }

        FilterHeadersStatus::Continue
    }

    /// The shape check runs once the body_rewrite filter has published the
    /// body's facts, at the end of the body.
    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _data: &mut bytes::Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        if end_stream {
            self.admit_body(cb);
        }
        FilterDataStatus::Continue
    }

    /// A request that ends in trailers never sends `end_stream` on data.
    fn decode_trailers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _trailers: &mut RequestTrailers,
    ) -> FilterTrailersStatus {
        self.admit_body(cb);
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

    /// A stream cut off before its terminal frame never reaches the
    /// end-of-stream callbacks above. The usage filter, which completes before
    /// this filter (completion runs in reverse chain order), has by now written
    /// a partial estimate; charge it, so a client that keeps aborting still
    /// consumes its budget. A clean end already set `recorded`, so this cannot
    /// charge twice, and a stream with no partial usage (a denial, a local
    /// reply) is left alone, not reported as missing usage.
    fn on_stream_complete(&mut self, cb: &mut dyn EncoderCallbacks) {
        if self.recorded {
            return;
        }
        let partial_usage = {
            let info = cb.stream_info();
            info.llm.completeness == Some(proxy_observability::records::UsageCompleteness::Partial)
                && info.llm.usage.is_some()
        };
        if partial_usage {
            self.record_if_present(cb);
        }
    }
}

/// The one warning for a startup spend prefetch that could not read every
/// row. The filter still builds (AGENTS.md "Fail-open controls": metering
/// must not take the listener down with a store blip), and this line is what
/// makes the open window visible. It is logged once per accumulator, and
/// renders the store's error and the chain, never a key or tenant.
fn warn_prefetch_failed(stat_prefix: &str, err: &crate::control::StoreError) {
    tracing::warn!(
        stat_prefix = %stat_prefix,
        error = %err,
        "llmproxy.spend_limit: startup spend prefetch failed; serving anyway. Spend rows \
         that could not be read start from zero on this replica and are corrected from \
         the store on the first successful flush. Until then budgets may be over-admitted"
    );
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
///   (AGENTS.md "Fail-open controls"). It would also reject nearly every deployment that
///   works today: a fully static bootstrap does not carry a node id into the
///   IR at all.
/// - Passing the empty string through fails OPEN and SILENTLY, which is the
///   one outcome this whole filter exists to prevent.
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
         correctly, but pass --service-node (or set the bootstrap node.id) to a name \
         unique to this replica and stable across its restarts"
    );
    unique
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TenantId;

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

    use proxy_credentials::{TenantCredential, TenantCredentialSet, TenantSecret};

    use crate::auth::{HmacSecret, KeySet};
    use crate::control::ControlPlane;
    use crate::spend::{Charge, MicroUsd, TenantBudget};

    // --- config parsing ------------------------------------------------

    fn spend_limit_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.SpendLimit")
            .expect("SpendLimit is compiled into proxy-api")
    }

    fn spend_limit_config() -> DynamicMessage {
        DynamicMessage::new(spend_limit_desc())
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
    fn unspecified_default_period_means_monthly() {
        let period = parse_default_period(&spend_limit_config()).expect("valid");
        assert_eq!(period, Period::Monthly);
    }

    #[test]
    fn explicit_daily_default_period_parses() {
        let mut msg = spend_limit_config();
        msg.set_field_by_name("default_period", prost_reflect::Value::EnumNumber(1));
        assert_eq!(parse_default_period(&msg).expect("valid"), Period::Daily);
    }

    #[test]
    fn zero_flush_interval_means_the_five_second_default() {
        assert_eq!(
            parse_flush_interval(&spend_limit_config()),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn a_configured_flush_interval_is_honored() {
        let mut msg = spend_limit_config();
        msg.set_field_by_name("flush_interval_seconds", prost_reflect::Value::U32(30));
        assert_eq!(parse_flush_interval(&msg), Duration::from_secs(30));
    }

    // --- the reconciliation policy (ADR-0006 §5) --------------------

    #[test]
    fn zero_reconciliation_bound_means_the_stated_default() {
        let policy = parse_reconciliation(&spend_limit_config()).expect("valid config");
        assert_eq!(policy.bound, spend::DEFAULT_RECONCILIATION_BOUND);
        assert_eq!(policy.on_expired, OnReconciliationExpired::Allow);
    }

    #[test]
    fn a_configured_reconciliation_bound_is_honored() {
        let mut msg = spend_limit_config();
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
        let mut msg = spend_limit_config();
        msg.set_field_by_name(
            "on_reconciliation_expired",
            prost_reflect::Value::EnumNumber(1),
        );
        assert_eq!(
            parse_reconciliation(&msg).expect("ALLOW is implemented"),
            parse_reconciliation(&spend_limit_config()).expect("unset means ALLOW"),
        );
    }

    /// AGENTS.md invariant 1: a declared-but-unimplemented behaviour is a LOAD
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
            let mut msg = spend_limit_config();
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

    /// What `FilterChainHandler::handle` does before any filter runs:
    /// classify the request once into stream info (ADR-0010 decision 1).
    fn decode(
        filter: &mut dyn HttpFilter,
        cb: &mut TestCallbacks,
        headers: &mut RequestHeaders,
        end_stream: bool,
    ) -> FilterHeadersStatus {
        cb.stream_info.borrow_mut().llm.endpoint =
            proxy_http::endpoint::Endpoint::classify(&headers.method, headers.uri.path());
        filter.decode_headers(cb, headers, end_stream)
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
            let mut info = self.stream_info.borrow_mut();
            info.auth.tenant = Some(tenant.to_string());
            info.auth.key_id = Some(test_key_id(tenant).as_str().to_string());
            // The router sets the source at the credential step for every
            // attempt (ADR-0007 decision 7); this harness's default request
            // runs on the platform credential, matching the
            // platform-scoped budgets every pre-existing test configures.
            // Tenant-mode tests override this after `set_tenant`.
            info.credential_source = Some(CredentialSource::Platform);
        }

        /// The auth filter's hand-off (ADR-0007 decision 4): a tenant that
        /// holds at least one provider credential is in tenant mode
        /// (decision 5). One provider is enough -- this filter reads only
        /// `is_empty`.
        fn set_tenant_mode(&self) {
            let mut info = self.stream_info.borrow_mut();
            let mut by_provider = HashMap::new();
            by_provider.insert(
                "provider-x".to_owned(),
                TenantCredential::Usable(TenantSecret::new("test-secret".to_owned())),
            );
            info.tenant_credentials = Some(Arc::new(TenantCredentialSet::new(by_provider)));
        }

        /// The router's credential step (ADR-0007 decision 7): `None` means
        /// no attempt ever reached it.
        fn set_credential_source(&self, source: Option<CredentialSource>) {
            self.stream_info.borrow_mut().credential_source = source;
        }

        fn set_usage(&self, usage: LlmTokenUsage) {
            self.stream_info.borrow_mut().llm.usage =
                Some(proxy_http::LlmUsage::from_tokens(usage));
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

    fn test_key_id(tenant: &str) -> KeyId {
        KeyId::new(format!("key-{tenant}"))
    }

    /// A `ControlPlane` with a stable key and budget for every test tenant.
    fn control_plane_with(budgets: &[(&str, TenantBudget)]) -> Arc<ControlPlane> {
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(b"test-secret-value-long-enough"),
            KeySet::default(),
        )
        .expect("control plane must build");
        for (tenant, budget) in budgets {
            let tenant_id = TenantId::new(*tenant);
            cp.create_tenant(&tenant_id)
                .expect("tenant creation must succeed");
            let key_id = test_key_id(tenant);
            cp.mint_key(&tenant_id, &key_id)
                .expect("key mint must succeed");
            cp.set_key_budget(&key_id, Some(budget))
                .expect("set key budget must succeed");
        }
        Arc::new(cp)
    }

    /// The shared pieces one test's chain would build once and reuse across
    /// every stream -- exactly `SpendLimitInstanceFactory`'s production
    /// shape. [`Self::new_instance`] is this harness's
    /// `FilterInstanceFactory::create_filter` stand-in: a FRESH
    /// `SpendLimitFilterInstance` per call, sharing the same accumulator/
    /// rate card/snapshot. This split matters because
    /// `SpendLimitFilterInstance::recorded` is a per-STREAM guard (see its
    /// doc) -- reusing one instance across what a test means as several
    /// separate "requests" would leak that guard across them and silently
    /// stop the second and later requests from ever recording anything,
    /// exactly the trap `token_limit_filter::tests::run_request_inner`'s own
    /// doc warns about.
    struct FilterHarness {
        accumulator: Arc<SpendAccumulator>,
        usage_missing_warner: Arc<UsageMissingWarner>,
        unpriced_warner: Arc<UnpricedWarner>,
        pricing_registry: Arc<PricingRegistry>,
        snapshot: Arc<ArcSwap<ControlPlaneSnapshot>>,
    }

    impl FilterHarness {
        fn new_instance(&self) -> SpendLimitFilterInstance {
            SpendLimitFilterInstance {
                accumulator: Arc::clone(&self.accumulator),
                charged: None,
                unmetered: None,
                usage_missing_warner: Arc::clone(&self.usage_missing_warner),
                unpriced_warner: Arc::clone(&self.unpriced_warner),
                pricing_snapshot: self.pricing_registry.snapshot_context(),
                snapshot: Arc::clone(&self.snapshot),
                endpoint: Endpoint::Unmetered,
                key_id: None,
                tenant: None,
                period: None,
                key_budget_scope: None,
                tenant_budget_scope: None,
                budget_applies: false,
                recorded: false,
                body_checked: false,
            }
        }
    }

    /// Prices per `(cluster, model)`, in micro-dollars per million input
    /// tokens, published as the chain's rate card. Each cluster is its own
    /// provider type, so one model can cost differently per cluster, which
    /// is what keeps a fallback from being billed at the primary's rate
    /// (AGENTS.md invariant 6).
    #[derive(Clone, Default)]
    struct Card {
        entries: Vec<(String, String, u64)>,
    }

    impl Card {
        fn insert(&mut self, cluster: &str, model: &str, input_per_million_micros: u64) {
            self.entries.push((
                cluster.to_owned(),
                model.to_owned(),
                input_per_million_micros,
            ));
        }

        /// The wire document, or `None` for an empty card: the chain then has
        /// no rate card and every request is unpriced.
        fn json(&self) -> Option<String> {
            if self.entries.is_empty() {
                return None;
            }
            let entries: Vec<serde_json::Value> = self
                .entries
                .iter()
                .map(|(cluster, model, per_million)| {
                    serde_json::json!({
                        "provider_type": cluster,
                        "model": model,
                        "tier_mode": "whole_request",
                        "tiers": [{
                            "input_nanodollars_per_token": per_million / 1000,
                            "cached_input_nanodollars_per_token": 0,
                            "cache_write_nanodollars_per_token": 0,
                            "output_nanodollars_per_token": 0
                        }]
                    })
                })
                .collect();
            let providers: serde_json::Map<String, serde_json::Value> = self
                .entries
                .iter()
                .map(|(cluster, _, _)| (cluster.clone(), cluster.clone().into()))
                .collect();
            Some(
                serde_json::json!({
                    "price_list": {
                        "effective_from": "2026-01-01T00:00:00Z",
                        "entries": entries
                    },
                    "providers": providers
                })
                .to_string(),
            )
        }
    }

    fn harness(
        control_plane: &Arc<ControlPlane>,
        card: Card,
        accumulator: Arc<SpendAccumulator>,
    ) -> FilterHarness {
        let pricing_registry = Arc::new(PricingRegistry::new("test-chain"));
        if let Some(json) = card.json() {
            pricing_registry
                .publish_json(&json)
                .expect("the test card is valid");
        }
        FilterHarness {
            accumulator,
            usage_missing_warner: Arc::new(UsageMissingWarner::new()),
            unpriced_warner: Arc::new(UnpricedWarner::new("test-chain".to_string())),
            pricing_registry,
            snapshot: control_plane.handle(),
        }
    }

    /// A harness wired to `control_plane`'s snapshot, `card` as the chain's
    /// rate card, and a fresh accumulator with the given `default_period` -- everything
    /// a decode+encode cycle needs, with no background flusher thread (tests
    /// drive `flush_now`/`current_total` directly where they need to, exactly
    /// like `spend.rs`'s own accumulator tests).
    fn filter_with(
        control_plane: &Arc<ControlPlane>,
        card: Card,
        default_period: Period,
    ) -> FilterHarness {
        let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::default());
        let accumulator = Arc::new(SpendAccumulator::new(
            "test-chain".to_string(),
            store,
            default_period,
            "test-node".to_string(),
        ));
        harness(control_plane, card, accumulator)
    }

    /// `filter_with`, but with a reconciliation bound of ZERO, so the
    /// accumulator is already past its bound by the time a request runs --
    /// the state an operator sees when the shared store is unreachable.
    /// The spin (sub-millisecond, never a sleep) is what makes "past the
    /// bound" true rather than merely likely: `is_reconciled` compares with
    /// `<=`, so a zero bound is still reconciled at age exactly zero.
    fn stale_filter_with(
        control_plane: &Arc<ControlPlane>,
        card: Card,
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
        harness(control_plane, card, accumulator)
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
        decode(&mut filter, &mut cb, &mut head, true);

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

    // --- cut-off streams ----------------------------------------------------

    /// One request for tenant-a on `first` (1 micro-dollar per input token)
    /// with `tokens` of usage, ended `abort`ed or cleanly, then completed the
    /// way the filter manager completes every stream. `completeness` is what
    /// the usage filter would have written.
    fn run_stream(
        harness: &FilterHarness,
        tokens: u64,
        completeness: Option<proxy_observability::records::UsageCompleteness>,
        abort: bool,
    ) -> Option<StatusCode> {
        let mut filter = harness.new_instance();
        let mut cb = TestCallbacks::new();
        cb.set_tenant("tenant-a");
        decode(&mut filter, &mut cb, &mut request_headers(), true);
        if let Some((status, _)) = cb.local_reply.clone() {
            return Some(status);
        }
        cb.set_upstream("cluster-a", "first");
        if tokens > 0 {
            cb.set_usage(usage(tokens));
        }
        cb.stream_info.borrow_mut().llm.completeness = completeness;
        filter.encode_headers(&mut cb, &mut response_headers(), false);
        if !abort {
            filter.encode_data(&mut cb, &mut Bytes::new(), true);
        }
        filter.on_stream_complete(&mut cb);
        None
    }

    fn one_micro_per_token_harness(limit_micros: u64) -> FilterHarness {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(limit_micros),
                period: Period::Daily,
                credential_source: CredentialSource::Platform,
            },
        )]);
        let mut table = Card::default();
        table.insert("cluster-a", "first", 1_000_000);
        filter_with(&cp, table, Period::Monthly)
    }

    fn spent(harness: &FilterHarness) -> u64 {
        harness
            .accumulator
            .current_total_key(&test_key_id("tenant-a"), &Period::Daily.key_for_now())
    }

    #[test]
    fn an_aborted_stream_is_charged_its_partial_estimate_exactly_once() {
        use proxy_observability::records::UsageCompleteness::Partial;
        let harness = one_micro_per_token_harness(1_000);
        assert_eq!(run_stream(&harness, 7, Some(Partial), true), None);
        assert_eq!(spent(&harness), 7);
    }

    #[test]
    fn a_clean_stream_is_charged_once_and_completion_does_not_charge_again() {
        use proxy_observability::records::UsageCompleteness::Complete;
        let harness = one_micro_per_token_harness(1_000);
        assert_eq!(run_stream(&harness, 7, Some(Complete), false), None);
        assert_eq!(spent(&harness), 7);
    }

    /// With no partial usage written (a denial, a local reply, an unreadable
    /// body) completion records nothing and does not call the usage missing.
    #[test]
    fn completion_without_partial_usage_records_nothing() {
        let harness = one_micro_per_token_harness(1_000);
        assert_eq!(run_stream(&harness, 0, None, true), None);
        assert_eq!(spent(&harness), 0);
    }

    // --- over-admission while stale ---------------------------------

    /// A stale replica keeps serving (only `Allow` is implemented), and
    /// every admission it makes under a CONFIGURED budget is counted, so
    /// the bypass is visible instead of silent (AGENTS.md "Fail-open controls").
    ///
    /// Mutation: delete the `note_admission` call in `decode_headers`.
    #[test]
    fn a_budgeted_request_admitted_while_stale_is_counted() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(1_000_000),
                period: Period::Daily,
                credential_source: CredentialSource::Platform,
            },
        )]);
        let harness = stale_filter_with(&cp, Card::default(), Period::Monthly);

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
    /// must not be counted -- AGENTS.md "Fail-open controls" rule: "only warn where the control was
    /// actually meant to apply". Counting them would bury the real signal
    /// under whatever share of traffic happens to be unbudgeted.
    ///
    /// Mutation: move the `note_admission` call above the `Some(budget)`
    /// check in `decode_headers`.
    #[test]
    fn an_unbudgeted_request_admitted_while_stale_is_not_counted() {
        let cp = control_plane_with(&[]);
        let harness = stale_filter_with(&cp, Card::default(), Period::Monthly);

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
                credential_source: CredentialSource::Platform,
            },
        )]);
        let harness = stale_filter_with(&cp, Card::default(), Period::Monthly);

        let (reply, _cb) = run_request(&harness, "tenant-a", None, Some(10));

        let (status, _headers) = reply.expect("a zero ceiling denies the first request");
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            harness.accumulator.unreconciled_admissions(),
            0,
            "a refused request was not admitted, stale or not"
        );
    }

    // --- unpriced requests under a dollar budget are loud ---------------------

    fn dollar_budget() -> TenantBudget {
        TenantBudget {
            max_micros: MicroUsd::from_micros(1_000_000),
            period: Period::Daily,
            credential_source: CredentialSource::Platform,
        }
    }

    /// Warnings about a request charged $0, as the one line an operator reads.
    fn unpriced_warnings(capture: &crate::control::log_capture::Capture) -> Vec<String> {
        capture
            .rendered_at_or_above(tracing::Level::WARN)
            .into_iter()
            .filter(|line| line.contains("charged $0"))
            .collect()
    }

    #[test]
    fn an_unpriced_model_under_a_budget_warns_once_per_model() {
        let cp = control_plane_with(&[("tenant-a", dollar_budget())]);
        let harness = filter_with(&cp, Card::default(), Period::Monthly);

        let (capture, guard) = crate::control::log_capture::Capture::start();
        for _ in 0..3 {
            run_request(
                &harness,
                "tenant-a",
                Some(("cluster-a", "mystery")),
                Some(10),
            );
        }
        run_request(
            &harness,
            "tenant-a",
            Some(("cluster-a", "second")),
            Some(10),
        );
        drop(guard);

        let lines = unpriced_warnings(&capture);
        assert_eq!(
            lines.len(),
            2,
            "one per model, repeats suppressed: {lines:?}"
        );
        assert!(lines[0].contains("mystery") && lines[0].contains("cluster-a"));
        assert!(
            lines[0].contains("test-chain"),
            "names the chain: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("no rate card is installed"),
            "says why: {}",
            lines[0]
        );
        assert!(lines[1].contains("second"));
    }

    /// ADR-0010 decision 3: audio tokens under an entry with no audio rate
    /// are charged at the text rate, today's amount, and that under-pricing
    /// is loud once per model where a budget applies.
    #[test]
    fn modality_tokens_without_a_modality_rate_charge_todays_amount_and_warn_once() {
        let cp = control_plane_with(&[("tenant-a", dollar_budget())]);
        let mut card = Card::default();
        card.insert("cluster-a", "voice", 1_000_000);
        let harness = filter_with(&cp, card, Period::Monthly);

        let (capture, guard) = crate::control::log_capture::Capture::start();
        let mut charges = Vec::new();
        for _ in 0..3 {
            let mut filter = harness.new_instance();
            let mut cb = TestCallbacks::new();
            cb.set_tenant("tenant-a");
            decode(&mut filter, &mut cb, &mut request_headers(), true);
            cb.set_upstream("cluster-a", "voice");
            cb.set_usage(LlmTokenUsage {
                input_tokens: 10,
                input_audio_tokens: 6,
                ..Default::default()
            });
            filter.encode_headers(&mut cb, &mut response_headers(), false);
            filter.encode_data(&mut cb, &mut Bytes::new(), true);
            let charge = cb.stream_info.borrow().llm.spend_charge.clone();
            charges.push(charge.expect("charged").micro_usd);
        }
        drop(guard);

        // One micro-dollar per input token; the audio tokens are inside the
        // ten, at the text rate.
        assert_eq!(charges, [10, 10, 10]);
        let lines: Vec<String> = capture
            .rendered_at_or_above(tracing::Level::WARN)
            .into_iter()
            .filter(|line| line.contains("no modality rate"))
            .collect();
        assert_eq!(lines.len(), 1, "once per model: {lines:?}");
        assert!(lines[0].contains("voice") && lines[0].contains("cluster-a"));
    }

    /// AGENTS.md "Fail-open controls": warn only where the control was meant
    /// to apply. No budget means the $0 charge bypassed nothing.
    #[test]
    fn an_unpriced_model_without_a_budget_stays_silent() {
        let cp = control_plane_with(&[]);
        let harness = filter_with(&cp, Card::default(), Period::Monthly);

        let (capture, guard) = crate::control::log_capture::Capture::start();
        run_request(
            &harness,
            "tenant-none",
            Some(("cluster-a", "mystery")),
            Some(10),
        );
        drop(guard);

        assert!(unpriced_warnings(&capture).is_empty());
        assert!(harness
            .unpriced_warner
            .seen
            .lock()
            .unwrap()
            .models
            .is_empty());
    }

    /// The healthy path never touches the warner's state.
    #[test]
    fn a_priced_request_neither_warns_nor_touches_the_suppression_state() {
        let cp = control_plane_with(&[("tenant-a", dollar_budget())]);
        let mut table = Card::default();
        table.insert("cluster-a", "priced", 1_000_000);
        let harness = filter_with(&cp, table, Period::Monthly);

        let (capture, guard) = crate::control::log_capture::Capture::start();
        run_request(
            &harness,
            "tenant-a",
            Some(("cluster-a", "priced")),
            Some(10),
        );
        drop(guard);

        assert!(unpriced_warnings(&capture).is_empty());
        let seen = harness.unpriced_warner.seen.lock().unwrap();
        assert!(seen.models.is_empty() && !seen.cap_reported);
    }

    #[test]
    fn the_remembered_model_names_are_bounded_and_the_cap_logs_one_summary() {
        let cp = control_plane_with(&[("tenant-a", dollar_budget())]);
        let harness = filter_with(&cp, Card::default(), Period::Monthly);
        let extra = 20;

        let (capture, guard) = crate::control::log_capture::Capture::start();
        for n in 0..MAX_UNPRICED_MODELS_REMEMBERED + extra {
            run_request(
                &harness,
                "tenant-a",
                Some(("cluster-a", &format!("model-{n}"))),
                Some(1),
            );
        }
        drop(guard);

        assert_eq!(
            harness.unpriced_warner.seen.lock().unwrap().models.len(),
            MAX_UNPRICED_MODELS_REMEMBERED,
            "client-chosen names must not grow the set without bound"
        );
        let lines: Vec<_> = unpriced_warnings(&capture)
            .into_iter()
            .filter(|line| !line.contains("more distinct unpriced model names"))
            .collect();
        assert_eq!(
            lines.len(),
            MAX_UNPRICED_MODELS_REMEMBERED,
            "one per remembered model"
        );
        let summaries: Vec<_> = capture
            .rendered_at_or_above(tracing::Level::WARN)
            .into_iter()
            .filter(|line| line.contains("more distinct unpriced model names"))
            .collect();
        assert_eq!(summaries.len(), 1, "one summary, however many more arrive");
    }

    /// Check what the line renders: a forged newline in a client-chosen model
    /// name stays on one line, and no credential or key identity is in it.
    #[test]
    fn the_unpriced_warning_renders_no_credentials_and_cannot_be_forged() {
        // A tenant-scoped budget, so the request below (tenant mode, holding a
        // tenant credential) is one the budget actually applies to.
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                credential_source: CredentialSource::Tenant,
                ..dollar_budget()
            },
        )]);
        let harness = filter_with(&cp, Card::default(), Period::Monthly);
        let mut filter = harness.new_instance();
        let mut cb = TestCallbacks::new();
        cb.set_tenant("tenant-a");
        cb.set_tenant_mode();
        cb.set_credential_source(Some(CredentialSource::Tenant));
        decode(&mut filter, &mut cb, &mut request_headers(), true);
        cb.set_upstream("cluster-a", "evil\nWARN forged line");
        cb.set_usage(usage(5));

        let (capture, guard) = crate::control::log_capture::Capture::start();
        filter.encode_data(&mut cb, &mut Bytes::new(), true);
        drop(guard);

        let lines = unpriced_warnings(&capture);
        assert_eq!(lines.len(), 1, "{lines:?}");
        let line = &lines[0];
        assert!(
            !line.contains('\n'),
            "the name cannot start a second line: {line:?}"
        );
        assert!(line.contains("forged"), "the name is still shown");
        for secret in ["test-secret", "key-tenant-a", "tenant-a"] {
            assert!(
                !line.contains(secret),
                "{secret} must not be in the line: {line}"
            );
        }
    }

    /// Once the card prices the model, the same request stops warning.
    #[test]
    fn a_published_card_ends_the_warning_for_the_models_it_prices() {
        let cp = control_plane_with(&[("tenant-a", dollar_budget())]);
        let harness = filter_with(&cp, Card::default(), Period::Monthly);
        harness
            .pricing_registry
            .publish_json(
                r#"{"price_list":{"effective_from":"2026-01-01T00:00:00Z","entries":[{"provider_type":"openai","model":"gpt-5","tier_mode":"whole_request","tiers":[{"input_nanodollars_per_token":1000,"cached_input_nanodollars_per_token":0,"cache_write_nanodollars_per_token":0,"output_nanodollars_per_token":1000}]}]},"providers":{"cluster-a":"openai"}}"#,
            )
            .unwrap();

        let (capture, guard) = crate::control::log_capture::Capture::start();
        run_request(&harness, "tenant-a", Some(("cluster-a", "gpt-5")), Some(10));
        run_request(&harness, "tenant-a", Some(("cluster-a", "gpt-6")), Some(10));
        drop(guard);

        let lines = unpriced_warnings(&capture);
        assert_eq!(lines.len(), 1, "only the unpriced model warns: {lines:?}");
        assert!(lines[0].contains("gpt-6"));
        assert!(
            lines[0].contains("no entry for provider type `openai`"),
            "the reason names what is missing: {}",
            lines[0]
        );
    }

    /// The charge follows the model the provider served when the card lists
    /// it, and stays on the requested model's price when it does not.
    ///
    /// Mutation: pass `sent_model` instead of the repriced model in
    /// `cost_micro_usd_served`.
    #[test]
    fn spend_is_charged_at_the_served_models_card_entry() {
        let card = r#"{"price_list":{"effective_from":"2026-01-01T00:00:00Z","entries":[
            {"provider_type":"openai","model":"gpt-5","tier_mode":"whole_request","tiers":[{"input_nanodollars_per_token":1000,"cached_input_nanodollars_per_token":0,"cache_write_nanodollars_per_token":0,"output_nanodollars_per_token":1000}]},
            {"provider_type":"openai","model":"gpt-5-mini","tier_mode":"whole_request","tiers":[{"input_nanodollars_per_token":100,"cached_input_nanodollars_per_token":0,"cache_write_nanodollars_per_token":0,"output_nanodollars_per_token":100}]}
            ]},"providers":{"cluster-a":"openai"}}"#;
        let charged_for = |served: Option<&str>| {
            let cp = control_plane_with(&[("tenant-a", dollar_budget())]);
            let harness = filter_with(&cp, Card::default(), Period::Monthly);
            harness.pricing_registry.publish_json(card).unwrap();
            let mut filter = harness.new_instance();
            let mut cb = TestCallbacks::new();
            cb.set_tenant("tenant-a");
            decode(&mut filter, &mut cb, &mut request_headers(), true);
            cb.set_upstream("cluster-a", "gpt-5");
            cb.stream_info.borrow_mut().llm.served_model = served.map(str::to_owned);
            cb.set_usage(usage(5000));
            filter.encode_data(&mut cb, &mut Bytes::new(), true);
            harness
                .accumulator
                .current_total_key(&test_key_id("tenant-a"), &Period::Daily.key_for_now())
        };
        assert_eq!(charged_for(None), 5000, "no served model: requested price");
        assert_eq!(
            charged_for(Some("gpt-5-mini")),
            500,
            "served model has a card"
        );
        assert_eq!(
            charged_for(Some("gpt-5-2025-08-07")),
            5000,
            "served model without a card keeps the requested price"
        );
    }

    /// One model priced differently on two clusters charges each request at
    /// the rate of the cluster actually dialled, never the model's alone, so
    /// a fallback is not billed at the primary's rate (AGENTS.md invariant 6).
    #[test]
    fn the_same_model_on_two_clusters_charges_the_dialled_clusters_rate() {
        let cp = control_plane_with(&[("tenant-a", dollar_budget())]);
        let mut table = Card::default();
        table.insert("cluster-a", "m", 1_000_000);
        table.insert("cluster-b", "m", 2_000_000);
        let harness = filter_with(&cp, table, Period::Monthly);
        run_request(&harness, "tenant-a", Some(("cluster-b", "m")), Some(10));
        assert_eq!(spent(&harness), 20, "cluster-b's 2 micro-dollars per token");
        run_request(&harness, "tenant-a", Some(("cluster-a", "m")), Some(10));
        assert_eq!(spent(&harness), 30, "then cluster-a's 1");
    }

    // --- no tenant / no budget: admitted -----------------------------------

    #[test]
    fn no_authenticated_tenant_is_admitted_and_nothing_is_recorded() {
        let cp = control_plane_with(&[]);
        let harness = filter_with(&cp, Card::default(), Period::Monthly);
        let mut filter = harness.new_instance();

        let mut cb = TestCallbacks::new();
        // No `set_tenant` call -- StreamInfo::auth.tenant stays `None`.
        let mut head = request_headers();
        let status = decode(&mut filter, &mut cb, &mut head, true);

        assert_eq!(status, FilterHeadersStatus::Continue);
        assert!(cb.local_reply.is_none(), "no tenant must never be denied");
    }

    #[test]
    fn configured_key_policy_rejects_missing_authenticated_key_identity() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(10),
                period: Period::Daily,
                credential_source: CredentialSource::Platform,
            },
        )]);
        let harness = filter_with(&cp, Card::default(), Period::Monthly);
        let mut filter = harness.new_instance();
        let mut cb = TestCallbacks::new();
        cb.stream_info.borrow_mut().auth.tenant = Some("tenant-a".into());
        let status = decode(&mut filter, &mut cb, &mut request_headers(), true);
        assert_eq!(status, FilterHeadersStatus::StopIteration);
        assert_eq!(cb.local_reply.as_ref().unwrap().0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn concurrent_admissions_can_exceed_the_ceiling_until_completion() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(1),
                period: Period::Daily,
                credential_source: CredentialSource::Platform,
            },
        )]);
        let mut table = Card::default();
        table.insert("cluster-a", "m", 1_000_000);
        let harness = filter_with(&cp, table, Period::Monthly);
        let mut first = harness.new_instance();
        let mut second = harness.new_instance();
        let mut first_cb = TestCallbacks::new();
        first_cb.set_tenant("tenant-a");
        let mut second_cb = TestCallbacks::new();
        second_cb.set_tenant("tenant-a");
        assert_eq!(
            decode(&mut first, &mut first_cb, &mut request_headers(), true),
            FilterHeadersStatus::Continue
        );
        assert_eq!(
            decode(&mut second, &mut second_cb, &mut request_headers(), true),
            FilterHeadersStatus::Continue
        );
        for (filter, cb) in [(&mut first, &mut first_cb), (&mut second, &mut second_cb)] {
            cb.set_upstream("cluster-a", "m");
            cb.set_usage(usage(3));
            filter.encode_data(cb, &mut Bytes::new(), true);
        }
        assert_eq!(
            harness
                .accumulator
                .current_total_key(&test_key_id("tenant-a"), &Period::Daily.key_for_now()),
            6
        );
        assert_eq!(
            run_request(&harness, "tenant-a", None, None).0.unwrap().0,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn one_key_accumulates_across_models_and_selected_providers() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(5),
                period: Period::Daily,
                credential_source: CredentialSource::Platform,
            },
        )]);
        let mut table = Card::default();
        table.insert("cluster-a", "first", 1_000_000);
        table.insert("cluster-b", "second", 2_000_000);
        let harness = filter_with(&cp, table, Period::Monthly);
        assert!(
            run_request(&harness, "tenant-a", Some(("cluster-a", "first")), Some(1))
                .0
                .is_none()
        );
        assert!(
            run_request(&harness, "tenant-a", Some(("cluster-b", "second")), Some(2))
                .0
                .is_none()
        );
        assert_eq!(
            harness
                .accumulator
                .current_total_key(&test_key_id("tenant-a"), &Period::Daily.key_for_now()),
            5
        );
        assert_eq!(
            run_request(&harness, "tenant-a", Some(("cluster-a", "first")), Some(1))
                .0
                .unwrap()
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn tenant_budget_aggregates_keys_with_independent_periods() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(10),
                period: Period::Monthly,
                credential_source: CredentialSource::Platform,
            },
        )]);
        let tenant = TenantId::new("tenant-a");
        cp.set_budget(
            &tenant,
            Some(&TenantBudget {
                max_micros: MicroUsd::from_micros(3),
                period: Period::Daily,
                credential_source: CredentialSource::Platform,
            }),
        )
        .unwrap();
        let second = KeyId::new("second-key");
        cp.mint_key(&tenant, &second).unwrap();
        let mut table = Card::default();
        table.insert("cluster-a", "m", 1_000_000);
        let harness = filter_with(&cp, table, Period::Monthly);
        assert!(
            run_request(&harness, "tenant-a", Some(("cluster-a", "m")), Some(2))
                .0
                .is_none()
        );
        let mut filter = harness.new_instance();
        let mut cb = TestCallbacks::new();
        cb.set_tenant("tenant-a");
        cb.stream_info.borrow_mut().auth.key_id = Some(second.as_str().to_string());
        decode(&mut filter, &mut cb, &mut request_headers(), true);
        assert!(cb.local_reply.is_none());
        cb.set_upstream("cluster-a", "m");
        cb.set_usage(usage(2));
        filter.encode_data(&mut cb, &mut Bytes::new(), true);
        filter.encode_trailers(&mut cb, &mut ResponseTrailers(HeaderMap::new()));
        let now = Utc::now();
        assert_eq!(
            harness
                .accumulator
                .current_total(&tenant, &Period::Daily.key_for(now)),
            4
        );
        assert_eq!(
            harness
                .accumulator
                .current_total_key(&second, &Period::Monthly.key_for(now)),
            2
        );
        assert_eq!(
            harness
                .accumulator
                .current_total(&tenant, &Period::Monthly.key_for(now)),
            0
        );
        let (reply, _) = run_request(&harness, "tenant-a", None, None);
        let (status, headers) = reply.unwrap();
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(headers["x-ratelimit-limit"], "3");
        // Clearing the tenant ceiling must leave the independent key ledger intact.
        cp.set_budget(&tenant, None).unwrap();
        cp.set_key_budget(
            &test_key_id("tenant-a"),
            Some(&TenantBudget {
                max_micros: MicroUsd::from_micros(2),
                period: Period::Monthly,
                credential_source: CredentialSource::Platform,
            }),
        )
        .unwrap();
        let (reply, _) = run_request(&harness, "tenant-a", None, None);
        assert_eq!(reply.unwrap().1["x-ratelimit-limit"], "2");
    }

    #[test]
    fn tenant_reports_track_priced_and_unpriced_requests_without_a_budget() {
        let cp = control_plane_with(&[]);
        let mut table = Card::default();
        table.insert("cluster-a", "m", 1_000_000);
        let harness = filter_with(&cp, table, Period::Monthly);
        run_request(&harness, "tenant-a", Some(("cluster-a", "m")), Some(2));
        run_request(&harness, "tenant-a", Some(("unknown", "m")), Some(3));
        let period = Period::Monthly.key_for_now();
        let tenant = harness
            .accumulator
            .report(&TenantId::new("tenant-a"), &period);
        let key = harness
            .accumulator
            .report_key(&test_key_id("tenant-a"), &period);
        assert_eq!(tenant.total_micros, key.total_micros);
        assert_eq!(tenant.total_micros, 2);
        assert_eq!(tenant.unpriced_requests, 1);
        assert_eq!(tenant.unpriced_pairs, key.unpriced_pairs);
    }

    #[test]
    fn tenant_zero_budget_applies_without_any_key_budget() {
        let cp = control_plane_with(&[]);
        cp.set_budget(
            &TenantId::new("tenant-a"),
            Some(&TenantBudget {
                max_micros: MicroUsd::from_micros(0),
                period: Period::Daily,
                credential_source: CredentialSource::Platform,
            }),
        )
        .unwrap();
        let harness = filter_with(&cp, Card::default(), Period::Monthly);
        let (reply, _) = run_request(&harness, "tenant-a", None, None);
        assert_eq!(reply.unwrap().0, StatusCode::TOO_MANY_REQUESTS);
        assert!(run_request(&harness, "other-tenant", None, None)
            .0
            .is_none());
    }

    #[test]
    fn missing_identity_cannot_bypass_a_tenant_budget() {
        let cp = control_plane_with(&[]);
        cp.set_budget(
            &TenantId::new("tenant-a"),
            Some(&TenantBudget {
                max_micros: MicroUsd::from_micros(3),
                period: Period::Daily,
                credential_source: CredentialSource::Platform,
            }),
        )
        .unwrap();
        let harness = filter_with(&cp, Card::default(), Period::Monthly);
        for missing_key in [false, true] {
            let mut filter = harness.new_instance();
            let mut cb = TestCallbacks::new();
            cb.set_tenant("tenant-a");
            if missing_key {
                cb.stream_info.borrow_mut().auth.key_id = None;
            } else {
                cb.stream_info.borrow_mut().auth.tenant = None;
            }
            decode(&mut filter, &mut cb, &mut request_headers(), true);
            assert_eq!(cb.local_reply.unwrap().0, StatusCode::FORBIDDEN);
        }
    }

    #[test]
    fn legacy_tenant_budgets_require_explicit_cutover_even_when_zero() {
        for limit in [0, 10] {
            let cp = control_plane_with(&[]);
            cp.set_budget(
                &TenantId::new("tenant-a"),
                Some(&TenantBudget {
                    max_micros: MicroUsd::from_micros(limit),
                    period: Period::Daily,
                    credential_source: CredentialSource::Platform,
                }),
            )
            .unwrap();
            let ctx = FactoryContext::default();
            ctx.shared
                .get_or_try_init(&ctx.scope, &ctx.stat_prefix, auth_filter::TYPE_URL, || {
                    Ok(cp.clone() as Arc<dyn std::any::Any + Send + Sync>)
                })
                .unwrap();
            let mut config = spend_limit_config();
            let error = SpendLimitFilterFactory
                .create(&config, &ctx)
                .err()
                .expect("legacy budget must require cutover");
            assert!(error.to_string().contains("legacy_tenant_budget_cutover"));
            config.set_field_by_name(
                "legacy_tenant_budget_cutover",
                prost_reflect::Value::EnumNumber(1),
            );
            assert!(SpendLimitFilterFactory.create(&config, &ctx).is_ok());
            assert!(cp.handle().load().key_budgets.is_empty());
            assert_eq!(
                cp.handle().load().policies["tenant-a"]
                    .budget
                    .unwrap()
                    .max_micros
                    .as_micros(),
                limit
            );
        }
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

        let config = spend_limit_config();
        SpendLimitFilterFactory
            .create(&config, &ctx)
            .expect("create must succeed with a ControlPlane registered");

        let accumulator = ctx
            .shared
            .get(&ctx.scope, TYPE_URL)
            .expect("create must register a spend accumulator")
            .downcast::<SharedSpendLimitState>()
            .expect("the spend singleton is always a SharedSpendLimitState");

        let key_id = KeyId::new("key-tenant-a");
        let now = chrono::Utc::now();
        let period = Period::Monthly;
        accumulator.accumulator.record_key(
            &key_id,
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
            .load_spend(
                &ctx.stat_prefix,
                &crate::spend::test_support::key_spend_subject(&key_id),
                &period.key_for(now),
            )
            .expect("load_spend must succeed");
        assert_eq!(
            stored, 4_242,
            "spend must be flushed into the ControlPlane's OWN store -- a private \
             store here would reset every tenant's accrued spend on restart while \
             budgets persisted, making a ceiling escapable by bouncing the proxy"
        );
    }

    /// A store that cannot answer the startup spend prefetch must not take
    /// the listener down (review H5: a Redis blip during a rollout left the
    /// replica with no listener). The filter builds, and says once, loudly,
    /// that budgets are open until the first flush; the line names no key.
    /// What happens to the rows afterwards is
    /// `spend::tests::a_failed_startup_prefetch_still_serves_and_the_next_flush_corrects_the_base`.
    #[test]
    fn a_failed_startup_prefetch_builds_the_filter_and_warns_once() {
        use crate::spend::test_support::ProbeStore;
        let probe = Arc::try_unwrap(ProbeStore::new())
            .ok()
            .expect("nothing else holds the new store");
        probe
            .fail_load_spend
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let cp = ControlPlane::new(
            Box::new(probe),
            HmacSecret::new(b"test-secret-value-long-enough"),
            KeySet::default(),
        )
        .expect("the policy load does not read spend");
        let tenant = TenantId::new("tenant-a");
        cp.create_tenant(&tenant).unwrap();
        cp.mint_key(&tenant, &KeyId::new("key-secret-looking-id"))
            .unwrap();
        let ctx = FactoryContext::default();
        ctx.shared
            .get_or_try_init(&ctx.scope, &ctx.stat_prefix, auth_filter::TYPE_URL, || {
                Ok(Arc::new(cp) as Arc<dyn std::any::Any + Send + Sync>)
            })
            .unwrap();

        let (capture, guard) = crate::control::log_capture::Capture::start();
        let built = SpendLimitFilterFactory.create(&spend_limit_config(), &ctx);
        drop(guard);

        assert!(built.is_ok(), "a prefetch failure is not a config error");
        let warnings: Vec<String> = capture
            .rendered_at_or_above(tracing::Level::WARN)
            .into_iter()
            .filter(|line| line.contains("startup spend prefetch failed"))
            .collect();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            !warnings[0].contains("key-secret-looking-id") && !warnings[0].contains("tenant-a"),
            "{}",
            warnings[0]
        );
    }

    #[test]
    fn a_tenant_with_no_configured_budget_is_admitted_unlimited() {
        let cp = control_plane_with(&[]);
        let mut table = Card::default();
        table.insert("cluster-a", "m", 1_000_000);
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
                credential_source: CredentialSource::Platform,
            },
        )]);

        let mut table = Card::default();
        table.insert("cluster-a", "m", 1_000_000);
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
                credential_source: CredentialSource::Platform,
            },
        )]);
        let harness = filter_with(&cp, Card::default(), Period::Monthly);
        let mut filter = harness.new_instance();

        let mut cb = TestCallbacks::new();
        cb.set_tenant("tenant-a");
        let mut head = request_headers();
        decode(&mut filter, &mut cb, &mut head, true);

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
                credential_source: CredentialSource::Platform,
            },
        )]);
        let harness = filter_with(&cp, Card::default(), Period::Monthly);
        let mut filter = harness.new_instance();

        let mut cb = TestCallbacks::new();
        cb.set_tenant("tenant-zero");
        let mut head = request_headers();
        decode(&mut filter, &mut cb, &mut head, true);

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
                credential_source: CredentialSource::Platform,
            },
        )]);
        // An EMPTY price table -- every (cluster, model) is unpriced.
        let filter = filter_with(&cp, Card::default(), Period::Monthly);

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

        let key_id = test_key_id("tenant-a");
        let now = Utc::now();
        assert_eq!(
            filter
                .accumulator
                .current_total_key(&key_id, &Period::Daily.key_for(now)),
            0,
            "an unpriced request must add nothing to the spend total"
        );
    }

    // --- admin set_budget changes enforcement with no reload -----------

    #[test]
    fn set_budget_changes_enforcement_on_the_very_next_request_with_no_reload() {
        let cp = control_plane_with(&[]);
        let tenant = TenantId::new("tenant-a");
        let key_id = test_key_id("tenant-a");
        cp.create_tenant(&tenant)
            .expect("tenant creation must succeed");
        cp.mint_key(&tenant, &key_id)
            .expect("key mint must succeed");
        let mut table = Card::default();
        table.insert("cluster-a", "m", 1_000_000);
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
        cp.set_key_budget(
            &key_id,
            Some(&TenantBudget {
                max_micros: MicroUsd::from_micros(0),
                period: Period::Daily,
                credential_source: CredentialSource::Platform,
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
                credential_source: CredentialSource::Platform,
            },
        )]);
        let mut table = Card::default();
        table.insert("cluster-a", "m", 1_000_000);
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
        let key_id = test_key_id("tenant-a");
        let tomorrow = Utc::now() + chrono::Duration::days(1);
        let tomorrow_key = Period::Daily.key_for(tomorrow);
        assert_eq!(
            filter.accumulator.current_total_key(&key_id, &tomorrow_key),
            0,
            "a new day's period key must start at zero even though today's is exhausted -- \
             this is what lets tomorrow's request be admitted with no operator action"
        );
    }

    // --- loud on unreadable usage (AGENTS.md "Fail-open controls") -----------------------------

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
                credential_source: CredentialSource::Platform,
            },
        )]);
        let filter = filter_with(&cp, Card::default(), Period::Monthly);

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
        let filter = filter_with(&cp, Card::default(), Period::Monthly);

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

    // --- budgets scoped to one credential source (ADR-0007 decision 8) ----

    /// ADR-0007 decision 8: admission enforces only the budgets whose scope
    /// matches the request's mode. A platform-scoped TENANT budget at its
    /// limit refuses platform-mode traffic and is absent for tenant-mode
    /// traffic.
    ///
    /// Mutation: drop the `credential_source == mode` filter on the tenant
    /// budget in `decode_headers` -- the tenant-mode half must go red.
    #[test]
    fn a_platform_scoped_tenant_budget_denies_only_platform_mode() {
        let cp = control_plane_with(&[]);
        cp.set_budget(
            &TenantId::new("tenant-a"),
            Some(&TenantBudget {
                max_micros: MicroUsd::from_micros(0),
                period: Period::Daily,
                credential_source: CredentialSource::Platform,
            }),
        )
        .unwrap();
        let harness = filter_with(&cp, Card::default(), Period::Monthly);

        // Platform mode: no tenant credentials on StreamInfo.
        let mut filter = harness.new_instance();
        let mut cb = TestCallbacks::new();
        cb.set_tenant("tenant-a");
        decode(&mut filter, &mut cb, &mut request_headers(), true);
        assert_eq!(
            cb.local_reply.as_ref().map(|(status, _)| *status),
            Some(StatusCode::TOO_MANY_REQUESTS),
            "a platform-scoped budget at its limit must deny a platform-mode request"
        );

        // Tenant mode: the same budget must be treated as absent.
        let mut filter = harness.new_instance();
        let mut cb = TestCallbacks::new();
        cb.set_tenant("tenant-a");
        cb.set_tenant_mode();
        cb.set_credential_source(Some(CredentialSource::Tenant));
        decode(&mut filter, &mut cb, &mut request_headers(), true);
        assert!(
            cb.local_reply.is_none(),
            "a tenant-mode request must not be checked against a platform-scoped budget"
        );
    }

    /// The mirror of the test above: a TENANT-scoped tenant budget refuses
    /// tenant-mode traffic and is absent for platform-mode traffic.
    ///
    /// Mutation: make the mode filter in `decode_headers` always pass.
    #[test]
    fn a_tenant_scoped_tenant_budget_denies_only_tenant_mode() {
        let cp = control_plane_with(&[]);
        cp.set_budget(
            &TenantId::new("tenant-a"),
            Some(&TenantBudget {
                max_micros: MicroUsd::from_micros(0),
                period: Period::Daily,
                credential_source: CredentialSource::Tenant,
            }),
        )
        .unwrap();
        let harness = filter_with(&cp, Card::default(), Period::Monthly);

        let mut filter = harness.new_instance();
        let mut cb = TestCallbacks::new();
        cb.set_tenant("tenant-a");
        cb.set_tenant_mode();
        cb.set_credential_source(Some(CredentialSource::Tenant));
        decode(&mut filter, &mut cb, &mut request_headers(), true);
        assert_eq!(
            cb.local_reply.as_ref().map(|(status, _)| *status),
            Some(StatusCode::TOO_MANY_REQUESTS),
            "a tenant-scoped budget at its limit must deny a tenant-mode request"
        );

        let mut filter = harness.new_instance();
        let mut cb = TestCallbacks::new();
        cb.set_tenant("tenant-a");
        decode(&mut filter, &mut cb, &mut request_headers(), true);
        assert!(
            cb.local_reply.is_none(),
            "a platform-mode request must not be checked against a tenant-scoped budget"
        );
    }

    /// ADR-0007 decision 8: spend is added to a budget only when the
    /// attempt's source matches the budget's scope. The two budgets sit on
    /// DIFFERENT subjects (tenant vs. key), so each assertion reads the
    /// other budget's counter: a regression that charges either budget from
    /// the wrong mode moves a counter this test pins at zero.
    ///
    /// Mutation: drop the scope gate in `record_if_present` -- the
    /// zero-assertions must go red.
    #[test]
    fn charges_only_the_budget_whose_scope_matches_the_attempts_source() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(1_000_000),
                period: Period::Daily,
                credential_source: CredentialSource::Platform,
            },
        )]);
        cp.set_budget(
            &TenantId::new("tenant-a"),
            Some(&TenantBudget {
                max_micros: MicroUsd::from_micros(1_000_000),
                period: Period::Daily,
                credential_source: CredentialSource::Tenant,
            }),
        )
        .unwrap();
        let mut table = Card::default();
        table.insert("cluster-a", "m", 1_000_000);

        let run = |harness: &FilterHarness, mode: CredentialSource| {
            let mut filter = harness.new_instance();
            let mut cb = TestCallbacks::new();
            cb.set_tenant("tenant-a");
            if mode == CredentialSource::Tenant {
                cb.set_tenant_mode();
                cb.set_credential_source(Some(CredentialSource::Tenant));
            }
            decode(&mut filter, &mut cb, &mut request_headers(), true);
            assert!(cb.local_reply.is_none(), "both ceilings dwarf this cost");
            cb.set_upstream("cluster-a", "m");
            cb.set_usage(usage(2));
            filter.encode_data(&mut cb, &mut Bytes::new(), true);
        };

        let tenant = TenantId::new("tenant-a");
        let key = test_key_id("tenant-a");
        let daily = Period::Daily.key_for_now();
        // A regression that charges a non-matching budget would record it
        // under the DEFAULT period (the budget's own period is only applied
        // to a budget that matched at admission), so both period keys are
        // read for the subject pinned at zero.
        let monthly = Period::Monthly.key_for_now();

        // Tenant mode, source Tenant: the tenant-scoped budget is charged,
        // the platform-scoped key budget is not.
        let harness = filter_with(&cp, table.clone(), Period::Monthly);
        run(&harness, CredentialSource::Tenant);
        assert_eq!(harness.accumulator.current_total(&tenant, &daily), 2);
        for key_total in [
            harness.accumulator.current_total_key(&key, &daily),
            harness.accumulator.current_total_key(&key, &monthly),
        ] {
            assert_eq!(
                key_total, 0,
                "tenant-mode spend must never be charged to the platform-scoped key budget"
            );
        }

        // Platform mode, source Platform: the converse -- only the
        // platform-scoped key budget is charged.
        let harness = filter_with(&cp, table, Period::Monthly);
        run(&harness, CredentialSource::Platform);
        assert_eq!(harness.accumulator.current_total_key(&key, &daily), 2);
        for tenant_total in [
            harness.accumulator.current_total(&tenant, &daily),
            harness.accumulator.current_total(&tenant, &monthly),
        ] {
            assert_eq!(
                tenant_total, 0,
                "platform-mode spend must never be charged to the tenant-scoped tenant budget"
            );
        }
    }

    /// A request whose attempt never reached the credential step has NO
    /// source (`None`, ADR-0007 decision 7), which matches no budget's
    /// scope: the budgeted key subject is not charged. The tenant has no
    /// budget, so its counter keeps recording -- reporting for unbudgeted
    /// subjects must survive the scope gate unchanged.
    ///
    /// Mutation: drop the scope gate in `record_if_present` -- the key
    /// counter must go red.
    #[test]
    fn a_budgeted_subject_is_not_charged_when_credential_source_is_none() {
        let cp = control_plane_with(&[(
            "tenant-a",
            TenantBudget {
                max_micros: MicroUsd::from_micros(1_000_000),
                period: Period::Daily,
                credential_source: CredentialSource::Platform,
            },
        )]);
        let mut table = Card::default();
        table.insert("cluster-a", "m", 1_000_000);
        let harness = filter_with(&cp, table, Period::Monthly);

        let mut filter = harness.new_instance();
        let mut cb = TestCallbacks::new();
        cb.set_tenant("tenant-a");
        cb.set_credential_source(None);
        decode(&mut filter, &mut cb, &mut request_headers(), true);
        assert!(cb.local_reply.is_none());
        cb.set_upstream("cluster-a", "m");
        cb.set_usage(usage(2));
        filter.encode_data(&mut cb, &mut Bytes::new(), true);

        let now = Utc::now();
        assert_eq!(
            harness
                .accumulator
                .current_total_key(&test_key_id("tenant-a"), &Period::Daily.key_for(now)),
            0,
            "a request with no credential source must not be charged to its budget"
        );
        assert_eq!(
            harness
                .accumulator
                .current_total(&TenantId::new("tenant-a"), &Period::Monthly.key_for(now)),
            2,
            "the unbudgeted tenant still records for reporting, source or no source"
        );
    }

    /// ADR-0007 decision 8: when BOTH budgets are tenant-scoped, tenant mode
    /// enforces both -- each alone at its limit refuses the request. The
    /// platform-mode half of each case proves the refusals come from scope
    /// matching, not merely from a budget existing somewhere.
    ///
    /// Mutation: enforce every configured budget regardless of scope --
    /// the platform-mode halves must go red.
    #[test]
    fn tenant_mode_enforces_a_tenant_scoped_key_budget_and_tenant_budget_alike() {
        for (key_micros, tenant_micros) in [(0, 1_000_000), (1_000_000, 0)] {
            let cp = control_plane_with(&[(
                "tenant-a",
                TenantBudget {
                    max_micros: MicroUsd::from_micros(key_micros),
                    period: Period::Daily,
                    credential_source: CredentialSource::Tenant,
                },
            )]);
            cp.set_budget(
                &TenantId::new("tenant-a"),
                Some(&TenantBudget {
                    max_micros: MicroUsd::from_micros(tenant_micros),
                    period: Period::Daily,
                    credential_source: CredentialSource::Tenant,
                }),
            )
            .unwrap();
            let harness = filter_with(&cp, Card::default(), Period::Monthly);

            let mut filter = harness.new_instance();
            let mut cb = TestCallbacks::new();
            cb.set_tenant("tenant-a");
            cb.set_tenant_mode();
            cb.set_credential_source(Some(CredentialSource::Tenant));
            decode(&mut filter, &mut cb, &mut request_headers(), true);
            assert_eq!(
                cb.local_reply.as_ref().map(|(status, _)| *status),
                Some(StatusCode::TOO_MANY_REQUESTS),
                "key={key_micros} tenant={tenant_micros}: each tenant-scoped budget at its \
                 limit must deny on its own in tenant mode"
            );

            let mut filter = harness.new_instance();
            let mut cb = TestCallbacks::new();
            cb.set_tenant("tenant-a");
            decode(&mut filter, &mut cb, &mut request_headers(), true);
            assert!(
                cb.local_reply.is_none(),
                "key={key_micros} tenant={tenant_micros}: neither tenant-scoped budget may \
                 deny a platform-mode request"
            );
        }
    }

    /// Through the real factory: the spend seam's reconciliation age is
    /// exported under the chain's `stat_prefix` (ADR-0006 §5).
    #[test]
    fn the_factory_exports_the_spend_reconciliation_age() {
        use crate::reconciliation_age::test_support::rendered_age;
        use crate::reconciliation_age::Seam;

        let cp = control_plane_with(&[]);
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
        ctx.shared
            .get_or_try_init(&ctx.scope, &ctx.stat_prefix, auth_filter::TYPE_URL, || {
                Ok(cp as Arc<dyn std::any::Any + Send + Sync>)
            })
            .unwrap();

        assert!(SpendLimitFilterFactory
            .create(&spend_limit_config(), &ctx)
            .is_ok());

        assert_eq!(rendered_age(&registry, "ingress", Seam::Spend), Some(0));
    }
}
