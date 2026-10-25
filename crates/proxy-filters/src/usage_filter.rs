//! Streams response bytes through the usage extractor and publishes token
//! usage and timing when the response ends. It never buffers the response so
//! generated tokens reach the client immediately. Pricing JSON shares the
//! dialect's strict schema; legacy `DataSource` config remains accepted for
//! one release.

use std::cell::OnceCell;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime};

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use prost_reflect::DynamicMessage;

use proxy_config::ConfigError;

use proxy_config::ir::UnansweredUsage;
use proxy_http::endpoint::Endpoint;
use proxy_http::filter::{
    DecoderCallbacks, EncoderCallbacks, FactoryContext, FilterDataStatus, FilterHeadersStatus,
    FilterInstanceFactory, FilterTrailersStatus, HttpFilter, HttpFilterFactory, PerRouteConfig,
    RequestHeaders, ResponseHeaders, ResponseTrailers,
};
use proxy_http::stream_info::GenAiSystem;
use proxy_http::stream_info::{AttemptCharge, StreamInfo};
use proxy_http::{LlmListCost, LlmTokenUsage, LlmUsage, PriceBasis};
use proxy_observability::records::UsageCompleteness;
use proxy_observability::stats::{instruments, Handle, Instrument, Registry, WorkerId};
use serde::{Deserialize, Serialize};

use crate::auth_filter;
use crate::control::{
    ControlPlane, RateCardDelivery, StoredRateCard, RATE_CARD_SCHEMA_V1, RATE_CARD_SCHEMA_V2,
};
use crate::media_scan::{seconds_to_millis, MediaJsonScanner, MediaSseScanner};
use crate::pricing::{
    image_prices_conflict, ImagePrice, PriceEntry, PriceList, Priced, Tier, TierBasis, TierMode,
};
use crate::realtime_usage::{Missing, RealtimeScanner};
use crate::usage::{
    extract_json_facts, extract_json_upstream_from_tail, extract_json_usage_parts_from_tail,
    usage_object_parts, Dialect, JsonResponseFacts, Modality, SseUsageScanner, TokenUsage,
    UpstreamEvidence,
};
use proxy_http::LlmMeters;

/// Canonical type URL for the owned usage configuration.
pub const TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.Usage";

/// How far ahead of this process's clock a card read back from the store may
/// be dated before it is refused. The writer already checked the date against
/// its own clock, so without this a replica whose clock runs a few seconds
/// behind the writer's would refuse a card dated "now" and stay on the old one
/// until the next unrelated change. NTP-level skew is the case ADR-0006
/// section 6 accepts; five minutes covers it with room to spare.
const STORED_CARD_CLOCK_SKEW: Duration = Duration::from_secs(300);

/// Shared live rate-card state for one filter chain. A request clones the
/// current pricing context when its filter instance is created, so an admin
/// update can never re-price a response already in flight.
///
/// # Where the card comes from
///
/// With a control-plane store on the chain (`llmproxy.auth`), the stored card
/// is the source of truth (ADR-0006 section 1 puts price in tier 2). The
/// configured card only seeds an empty store, a `PUT /pricing` writes the
/// store, and the control plane's poll delivers other replicas' writes here.
/// Without one, the configuration is the only durable source: a reload that
/// changes the configured card installs it, and a `PUT` lasts until restart.
pub struct PricingRegistry {
    /// The chain's `stat_prefix`: the key its card is stored under.
    chain: String,
    /// The card requests are priced with. Read per request, so it stays a
    /// plain lock around a clone; everything below is touched only when
    /// configuration is applied or a card is published.
    current: RwLock<Option<PricingContext>>,
    config: Mutex<ConfigState>,
    /// Exports the active card's version; see [`RateCardGauge`].
    gauge: Mutex<RateCardGauge>,
    /// The stored card last deferred for being dated ahead of this replica's
    /// clock. The store offers it again on every policy poll, and this keeps
    /// those retries from logging the refusal each time.
    deferred: Mutex<Option<StoredRateCard>>,
}

/// Ceiling on `llmproxy_usage_rate_card_active` series. Each published card
/// version adds one, and retired versions stay at 0, so a process that
/// publishes more than this folds the rest into one overflow series.
const RATE_CARD_SERIES_CEILING: usize = 64;

/// The `llmproxy_usage_rate_card_active` series of one chain: which version
/// holds the 1. Updated from [`PricingRegistry::sync_gauge`], never on the
/// request path.
#[derive(Default)]
struct RateCardGauge {
    registry: Option<Arc<Registry>>,
    /// The version currently exported as 1, with its series.
    exported: Option<(String, Handle)>,
}

#[derive(Default)]
struct ConfigState {
    /// What the last `apply_config` was given. `None` until a usage filter has
    /// applied its configuration; `Some(None)` is "configured, with no card".
    /// Remembering it is how a reload tells "the configuration changed" from
    /// "the same configuration, built again by the next worker".
    configured: Option<Option<PricingContext>>,
    /// The chain's store, once linked.
    control_plane: Option<Arc<ControlPlane>>,
}

/// What a `PUT /pricing` did, for the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub rate_card_version: String,
    /// Whether the card survives a restart of this process.
    pub persisted: bool,
    /// One sentence for the operator on where the card now lives.
    pub note: &'static str,
}

/// Why a `PUT /pricing` did not publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// The document is not a usable rate card (the caller's fault).
    Invalid(String),
    /// The store refused or could not take the card. The card was not
    /// installed anywhere, so this replica and the store still agree.
    Store(String),
}

impl PricingRegistry {
    pub(crate) fn new(chain: impl Into<String>) -> Self {
        Self {
            chain: chain.into(),
            current: RwLock::new(None),
            config: Mutex::new(ConfigState::default()),
            gauge: Mutex::new(RateCardGauge::default()),
            deferred: Mutex::new(None),
        }
    }

    /// Exports the active card's version to `registry` from now on.
    pub(crate) fn export_to(&self, registry: Arc<Registry>) {
        self.gauge
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .registry = Some(registry);
        self.sync_gauge();
    }

    /// Brings the exported version in line with the installed card. Reads the
    /// card under the gauge lock, so concurrent installs cannot leave two
    /// series at 1 whatever order they reach here.
    fn sync_gauge(&self) {
        let mut gauge = self.gauge.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(registry) = gauge.registry.clone() else {
            return;
        };
        let version = self.snapshot().map(|card| card.list.version().to_string());
        if gauge.exported.as_ref().map(|(v, _)| v) == version.as_ref() {
            return;
        }
        if let Some((_, handle)) = gauge.exported.take() {
            registry.add(WorkerId(0), handle, -1);
        }
        if let Some(version) = version {
            let handle = registry.resolve_capped(
                &instruments::USAGE_RATE_CARD_ACTIVE,
                &[("scope", &self.chain), ("version", &version)],
                RATE_CARD_SERIES_CEILING,
                &[("scope", "overflow"), ("version", "overflow")],
            );
            registry.add(WorkerId(0), handle, 1);
            gauge.exported = Some((version, handle));
        }
    }

    fn snapshot(&self) -> Option<PricingContext> {
        self.current
            .read()
            .expect("pricing registry lock poisoned")
            .clone()
    }

    pub(crate) fn snapshot_context(&self) -> Option<PricingContext> {
        self.snapshot()
    }

    /// The chain's `stat_prefix`, which is also its key in the store.
    pub fn chain(&self) -> &str {
        &self.chain
    }

    /// Capture one immutable, public JSON view of the active pricing state.
    /// Cloning the context while holding one read lock keeps the rate card,
    /// provider mapping, and source catalog on the same registry revision.
    pub fn json_view(&self) -> Option<PricingJsonView> {
        let pricing = self.snapshot()?;
        Some(PricingJsonView::from(pricing))
    }

    /// Compute a dollar-enforcement charge from the current list card. Round
    /// nanodollars up to microdollars so enforcement never undercharges a
    /// request because of unit conversion.
    pub fn cost_micro_usd(
        &self,
        cluster: Option<&str>,
        model: Option<&str>,
        usage: &LlmUsage,
    ) -> Option<u64> {
        let pricing = self.snapshot()?;
        Self::cost_micro_usd_for(Some(&pricing), cluster, model, usage)
    }

    pub(crate) fn cost_micro_usd_for(
        pricing: Option<&PricingContext>,
        cluster: Option<&str>,
        model: Option<&str>,
        usage: &LlmUsage,
    ) -> Option<u64> {
        pricing?
            .list
            .list_cost_for_cluster(cluster?, model?, usage)
            .map(Self::charge_micro_usd)
    }

    /// A list price in nanodollars as the micro-USD amount a request is
    /// charged: rounded up, so a charge is never smaller than the price. The
    /// one conversion both the spend filter and the ledger use.
    pub(crate) fn charge_micro_usd(nanodollars: u64) -> u64 {
        nanodollars.saturating_add(999) / 1000
    }

    /// Price `usage` at the provider-reported model when the card lists it
    /// (see `PriceList::model_to_price`). The spend filter charges through
    /// this so its charge matches the usage filter's logged cost.
    pub(crate) fn price_served(
        pricing: Option<&PricingContext>,
        cluster: Option<&str>,
        sent_model: Option<&str>,
        served_model: Option<&str>,
        usage: &LlmUsage,
    ) -> Option<Priced> {
        let (pricing, cluster, sent) = (pricing?, cluster?, sent_model?);
        let model = pricing
            .list
            .model_to_price(cluster, sent, served_model, usage)
            .0;
        pricing.list.price_for_cluster(cluster, model, usage)
    }

    /// Why a request the rate card could not price was left unpriced, in words
    /// an operator can act on. Runs only on the unpriced path.
    pub(crate) fn explain_unpriced(
        pricing: Option<&PricingContext>,
        cluster: Option<&str>,
        model: Option<&str>,
        usage: &LlmUsage,
    ) -> String {
        let Some(pricing) = pricing else {
            return "no rate card is installed on this chain".to_string();
        };
        let Some(cluster) = cluster else {
            return "the request reached no upstream cluster".to_string();
        };
        let Some(model) = model else {
            return "the request names no model".to_string();
        };
        let Some(provider) = pricing.list.provider_for(cluster) else {
            return format!("the rate card's providers map does not name cluster `{cluster}`");
        };
        let Some(entry) = pricing.list.lookup(provider, model) else {
            return format!(
                "the rate card has no entry for provider type `{provider}` and this model"
            );
        };
        match entry.basis {
            PriceBasis::Tokens if usage.tokens.is_none() => {
                "the rate card prices this model by token, and the response reported no token \
                 usage"
                    .to_string()
            }
            PriceBasis::Tokens => {
                "the rate card cannot price the cache tokens this request reported".to_string()
            }
            PriceBasis::Images if usage.meters.images.is_none() => {
                "the rate card prices this model by image, and the response returned no images"
                    .to_string()
            }
            // The attribute values come from the provider or the client, so
            // they are not logged; the operator can read them in the record.
            _ => "the rate card has no image_prices row matching this request's size and quality"
                .to_string(),
        }
    }

    fn install(&self, card: PricingContext) {
        *self
            .current
            .write()
            .expect("pricing registry lock poisoned") = Some(card);
        self.sync_gauge();
    }

    /// Applies one usage filter's configuration. Called by every worker's
    /// `create`, so the first call is boot and the rest are either the same
    /// configuration built again (no-ops) or a reload that changed it.
    ///
    /// `store` is the chain's control plane when the chain has `llmproxy.auth`.
    /// `field_path` names the configuration field an error is reported at.
    pub(crate) fn apply_config(
        self: &Arc<Self>,
        card: Option<PricingContext>,
        store: Option<Arc<ControlPlane>>,
        field_path: &str,
    ) -> Result<(), ConfigError> {
        let mut state = self.config.lock().expect("pricing config lock poisoned");
        let first = state.configured.is_none();
        let changed = first || state.configured.as_ref() != Some(&card);
        if changed {
            if let Some(card) = &card {
                check_effective_from(card, SystemTime::now(), Duration::ZERO).map_err(
                    |reason| ConfigError::InvalidValue {
                        field_path: field_path.to_string(),
                        reason,
                    },
                )?;
            }
        }
        state.configured = Some(card);
        let newly_linked = self.link(&mut state, store);
        if changed || newly_linked {
            self.reconcile(&state, first, changed && !first, field_path)?;
        }
        Ok(())
    }

    /// Links the chain's store after the fact. `llmproxy.auth` calls this when
    /// the usage filter happened to be built first, so persistence does not
    /// depend on the order filters are listed in.
    pub(crate) fn attach_control_plane(
        self: &Arc<Self>,
        store: &Arc<ControlPlane>,
        field_path: &str,
    ) -> Result<(), ConfigError> {
        let mut state = self.config.lock().expect("pricing config lock poisoned");
        let newly_linked = self.link(&mut state, Some(Arc::clone(store)));
        if newly_linked && state.configured.is_some() {
            self.reconcile(&state, false, false, field_path)?;
        }
        Ok(())
    }

    /// Starts listening to the store for this chain. True if this call linked
    /// it. The first delivery happens inside the call and installs the stored
    /// card, if the store has one.
    fn link(self: &Arc<Self>, state: &mut ConfigState, store: Option<Arc<ControlPlane>>) -> bool {
        let Some(store) = store else {
            return false;
        };
        if state.control_plane.is_some() {
            return false;
        }
        // Rust note: the store's watch list holds this closure for as long as
        // the store lives, so it captures a `Weak`. A strong `Arc` here would
        // make the store keep the registry alive and the registry keep the
        // store alive, and neither would ever be freed.
        let weak = Arc::downgrade(self);
        store.watch_rate_card(&self.chain, move |stored| match weak.upgrade() {
            Some(registry) => registry.install_stored(stored, SystemTime::now()),
            None => RateCardDelivery::Settled,
        });
        state.control_plane = Some(store);
        true
    }

    /// Settles which card is in force after configuration was applied.
    /// `reloaded` is true when a reload changed the configured card, so an
    /// operator expected a new price.
    fn reconcile(
        &self,
        state: &ConfigState,
        first: bool,
        reloaded: bool,
        field_path: &str,
    ) -> Result<(), ConfigError> {
        let configured = state.configured.as_ref().and_then(Option::as_ref);
        let Some(store) = &state.control_plane else {
            // No store: the configuration is the only durable source, so a
            // changed configuration replaces whatever is active.
            self.install_from_config(configured, first);
            return Ok(());
        };
        match store.rate_card(&self.chain) {
            Some(stored) => {
                // The store wins, at boot and on every reload: otherwise each
                // restart would quietly undo a card an operator published.
                let active = self.snapshot();
                match (&active, configured) {
                    // A reload that changed `pricing` had no effect, which the
                    // operator did not expect, so it warns. At boot the
                    // difference is normal after any PUT and stays at info,
                    // or every restart of every replica would warn.
                    (Some(active), Some(configured)) if active != configured && reloaded => {
                        tracing::warn!(
                            chain = %self.chain,
                            stored_version = %stored.version,
                            configured_version = %configured.list.version(),
                            "the reloaded pricing was not applied: the rate card in the \
                             control-plane store stays in force; publish with PUT /pricing to \
                             replace it"
                        )
                    }
                    (Some(active), Some(configured)) if active != configured => tracing::info!(
                        chain = %self.chain,
                        stored_version = %stored.version,
                        configured_version = %configured.list.version(),
                        "the configured pricing differs from the rate card in the control-plane \
                         store; the stored card stays in force (publish with PUT /pricing to \
                         replace it)"
                    ),
                    (None, Some(configured)) => {
                        // The watcher refused the stored card and already said
                        // why. Pricing nothing would turn every budgeted request
                        // into a free one, so this process falls back to the
                        // configured card and leaves the store alone. A card
                        // refused only for its date replaces this one once
                        // this replica's clock reaches it.
                        tracing::warn!(
                            chain = %self.chain,
                            "the stored rate card could not be installed; pricing with the \
                             configured card in this process only"
                        );
                        self.install(configured.clone());
                    }
                    _ => {}
                }
            }
            None => {
                let Some(configured) = configured else {
                    return Ok(());
                };
                let row = configured.stored_row(&self.chain);
                store
                    .seed_rate_card(&row)
                    .map_err(|error| ConfigError::InvalidValue {
                        field_path: field_path.to_string(),
                        reason: format!(
                            "the configured rate card could not be seeded into the \
                             control-plane store: {error}"
                        ),
                    })?;
                // The store's watcher installed the seeded card, or the card a
                // racing replica seeded first. Only a row this build cannot
                // read leaves nothing installed.
                if self.snapshot().is_none() {
                    tracing::warn!(
                        chain = %self.chain,
                        "the control-plane store holds a rate card this build cannot read; \
                         pricing with the configured card in this process only"
                    );
                    self.install(configured.clone());
                }
            }
        }
        Ok(())
    }

    fn install_from_config(&self, configured: Option<&PricingContext>, first: bool) {
        match configured {
            Some(card) => {
                let previous = self.snapshot();
                if previous.as_ref() != Some(card) {
                    if !first {
                        tracing::info!(
                            chain = %self.chain,
                            version = %card.list.version(),
                            replaced_version = previous.as_ref().map(|p| p.list.version().to_string()),
                            "the configured pricing changed; installing it as the rate card"
                        );
                    }
                    self.install(card.clone());
                }
            }
            None if !first => {
                let mut current = self
                    .current
                    .write()
                    .expect("pricing registry lock poisoned");
                let cleared = current.take().is_some();
                drop(current);
                if cleared {
                    self.sync_gauge();
                    tracing::warn!(
                        chain = %self.chain,
                        "pricing was removed from the configuration; the rate card is cleared \
                         and requests are unpriced until one is published"
                    );
                }
            }
            None => {}
        }
    }

    /// Installs a card read from the store as of `now`. A card that cannot
    /// be parsed is refused loudly for good and the previous card stays; the
    /// store's watch hands that card over once, so this logs once per bad
    /// card. A card dated ahead of `now` (beyond the skew allowance) is
    /// deferred instead: another replica with a faster clock published it,
    /// and it becomes usable here once this clock catches up. The store
    /// offers it again on each policy poll; only the first refusal logs.
    fn install_stored(&self, stored: &StoredRateCard, now: SystemTime) -> RateCardDelivery {
        let card = match parse_card_json(&stored.card_json) {
            Ok(card) => card,
            Err(error) => {
                tracing::warn!(
                    chain = %self.chain,
                    stored_version = %stored.version,
                    %error,
                    "the rate card in the control-plane store is not usable; keeping the \
                     current rate card"
                );
                return RateCardDelivery::Settled;
            }
        };
        {
            let mut deferred = self
                .deferred
                .lock()
                .expect("pricing deferred lock poisoned");
            if let Err(reason) = check_effective_from(&card, now, STORED_CARD_CLOCK_SKEW) {
                if deferred.as_ref() != Some(stored) {
                    tracing::warn!(
                        chain = %self.chain,
                        stored_version = %stored.version,
                        %reason,
                        "the rate card in the control-plane store is dated ahead of this \
                         replica's clock; keeping the current rate card and retrying on each \
                         policy poll"
                    );
                    *deferred = Some(stored.clone());
                }
                return RateCardDelivery::Deferred;
            }
            *deferred = None;
        }
        let mut current = self
            .current
            .write()
            .expect("pricing registry lock poisoned");
        if current.as_ref() == Some(&card) {
            return RateCardDelivery::Settled;
        }
        let previous = current.as_ref().map(|p| p.list.version().to_string());
        let version = card.list.version().to_string();
        *current = Some(card);
        drop(current);
        self.sync_gauge();
        tracing::info!(
            chain = %self.chain,
            version = %version,
            previous_version = previous,
            "installed the rate card from the control-plane store"
        );
        RateCardDelivery::Settled
    }

    /// `PUT /pricing`: validates `json`, then publishes it. With a store the
    /// card is written first, and a refused write installs nothing, so this
    /// replica never prices with a card the store lacks. Without a store the
    /// card is installed in this process only.
    ///
    /// With a store this does not install `card` itself. `link` registered
    /// this registry as a watcher whenever `control_plane` is set, and
    /// `ControlPlane::put_rate_card` delivers the written card and then the
    /// store's current card to that watcher. A second replica can write
    /// between this put and that read-back; installing the local card
    /// afterwards would overwrite the store's card here, and later polls would
    /// not notice because the watcher already delivered it. The watcher's
    /// delivery is therefore authoritative, and `note` says so when it shows
    /// a different card than the one written.
    pub fn publish_json(&self, json: &str) -> Result<Published, PublishError> {
        let card = parse_card_json(json).map_err(|e| PublishError::Invalid(e.to_string()))?;
        check_effective_from(&card, SystemTime::now(), Duration::ZERO)
            .map_err(PublishError::Invalid)?;
        let version = card.list.version().to_string();
        // Clone the handle out: the store call below must not run under this
        // lock, because it calls back into this registry's watcher.
        let store = self
            .config
            .lock()
            .expect("pricing config lock poisoned")
            .control_plane
            .clone();
        let has_store = store.is_some();
        let (persisted, note) = match store {
            Some(store) => {
                let row = card.stored_row(&self.chain);
                store
                    .put_rate_card(&row)
                    .map_err(|e| PublishError::Store(e.to_string()))?;
                if self
                    .snapshot()
                    .is_some_and(|c| c.list.version().to_string() != version)
                {
                    // Another replica's write landed between our put and the
                    // read-back, so the store's card is what is active here.
                    (
                        store.store_is_durable(),
                        "written, but a concurrent publish to the same store superseded it; \
                         this replica now serves the store's card",
                    )
                } else if store.store_is_shared() {
                    (
                        true,
                        "stored in the control-plane store; replicas that share it install it on \
                         their next policy poll",
                    )
                } else if store.store_is_durable() {
                    // A `persistent` store is one replica's file: durable,
                    // but no other replica reads it.
                    (
                        true,
                        "stored in this replica's persistent store; it survives a restart, but \
                         other replicas do not read it",
                    )
                } else {
                    (
                        false,
                        "held in this process's in-memory control-plane store; a restart loses it",
                    )
                }
            }
            None => (
                false,
                "applied to this process only; a restart loads the configured rate card",
            ),
        };
        if !has_store {
            self.install(card);
        }
        Ok(Published {
            rate_card_version: version,
            persisted,
            note,
        })
    }
}

/// Refuses a card dated after `now + tolerance`. `effective_from` is
/// informational: a card applies from the moment it is installed, and nothing
/// selects a card by time. Accepting a future date would therefore price
/// requests early while the document says otherwise, so it is an error.
fn check_effective_from(
    card: &PricingContext,
    now: SystemTime,
    tolerance: Duration,
) -> Result<(), String> {
    let effective = card.list.effective_from();
    match effective.duration_since(now + tolerance) {
        Ok(ahead) if !ahead.is_zero() => {
            let when: chrono::DateTime<chrono::Utc> = effective.into();
            Err(format!(
                "price_list.effective_from {} is in the future; a rate card applies from the \
                 moment it is installed and is not scheduled, so date it now or earlier",
                when.to_rfc3339()
            ))
        }
        _ => Ok(()),
    }
}

/// The chain's registry, created empty on first use. `llmproxy.spend_limit`
/// is built before this filter and reads the same registry, so both go through
/// here and agree on the key.
pub(crate) fn registry_for_chain(
    ctx: &FactoryContext,
) -> Result<Arc<PricingRegistry>, ConfigError> {
    // Looked up before `get_or_try_init`, whose closure runs under the lock
    // `get` takes (see `stats_of`).
    let stats = ctx
        .shared
        .get("", STATS_REGISTRY_KEY)
        .and_then(|any| any.downcast::<Registry>().ok());
    ctx.shared
        .get_or_try_init(&ctx.scope, &ctx.stat_prefix, TYPE_URL, || {
            let registry = PricingRegistry::new(ctx.stat_prefix.clone());
            if let Some(stats) = stats.clone() {
                registry.export_to(stats);
            }
            Ok(Arc::new(registry) as Arc<dyn std::any::Any + Send + Sync>)
        })?
        .downcast::<PricingRegistry>()
        .map_err(|_| invalid_config("pricing registry type collision"))
}

/// This chain's usage stats, shared by every factory built for the chain.
fn stats_of(ctx: &FactoryContext) -> Result<Arc<UsageStats>, ConfigError> {
    // Looked up before `get_or_try_init`: its init closure runs under the
    // singleton map's lock, and `get` takes the same lock.
    let registry = ctx
        .shared
        .get("", STATS_REGISTRY_KEY)
        .and_then(|any| any.downcast::<Registry>().ok());
    ctx.get_or_try_init(STATS_SINGLETON_KEY, || {
        Ok(Arc::new(UsageStats::new(registry, &ctx.stat_prefix))
            as Arc<dyn std::any::Any + Send + Sync>)
    })?
    .downcast::<UsageStats>()
    .map_err(|_| invalid_config("usage stats type collision"))
}

/// This chain's control plane, if `llmproxy.auth` has been built for it yet.
fn control_plane_of(ctx: &FactoryContext) -> Option<Arc<ControlPlane>> {
    ctx.get(auth_filter::TYPE_URL)?
        .downcast::<ControlPlane>()
        .ok()
}

/// Borrowed type URL accepted for one release after the move to an owned, versioned message.
pub const LEGACY_TYPE_URL: &str = "type.llmproxy.dev/envoy.config.core.v3.DataSource";

/// Upper bound on the response body this filter will accumulate to parse as a
/// single non-streaming JSON document. A response over this size still
/// streams through to the client untouched (see [`UsageFilterInstance::encode_data`]) —
/// this cap only decides whether *we* keep trying to compute usage for it.
pub const MAX_JSON_BODY_BYTES: usize = 1 << 20; // 1 MiB

/// Bytes kept from the end of a JSON body once it passes
/// [`MAX_JSON_BODY_BYTES`]. Providers emit `usage` as the last top-level
/// member, so it normally lies inside this window. Whatever is found there is
/// accepted only if it is structurally the top-level `usage` object (see
/// [`extract_json_usage_from_tail`]), so the "never a partial count" rule
/// still holds: a usage object is read whole or not at all.
pub const JSON_TAIL_WINDOW_BYTES: usize = 64 << 10;

/// Minimum gap between repeats of the oversized-body warning. Repeats are
/// suppressed, or the log becomes the incident (AGENTS.md "Fail-open controls").
const OVERSIZED_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Bytes per token assumed when estimating the usage of a stream that ended
/// before the provider reported any: a coarse, tokenizer-free figure applied
/// to the request size (input) and the streamed text (output), rounded up.
/// It over-charges short English text slightly and under-charges dense text
/// such as code or CJK; the aim is that aborting does not make a request free,
/// not an exact count.
const BYTES_PER_TOKEN_ESTIMATE: u64 = 4;

/// Which token counts of a usage record are estimates.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Estimated {
    input: bool,
    output: bool,
}

/// Counters shared by every stream of one usage filter instance factory.
///
/// Failing to meter is a fail-open for spend and token limits, which read the
/// usage this filter records, so each miss is counted and warned about
/// (rate-limited). The healthy path never touches this struct.
#[derive(Default)]
pub struct UsageStats {
    /// Oversized JSON responses whose `usage` could not be recovered from the
    /// tail window. These requests were not metered.
    oversized_unrecoverable: AtomicU64,
    last_oversized_warning: Mutex<Option<Instant>>,
    /// Realtime responses with no readable usage (ADR-0015).
    realtime_missing: AtomicU64,
    last_realtime_warning: Mutex<Option<Instant>>,
    /// This chain's stat scope, for series resolved on a miss.
    scope: String,
    /// Requests priced at the provider-reported model instead of the sent one.
    served_model_repriced: AtomicU64,
    /// This chain's `llmproxy_usage_served_model_repriced_total` series.
    repriced_handle: Option<Handle>,
    /// The process stats registry and this chain's series, when the listener
    /// seeded [`STATS_REGISTRY_KEY`]. `None` only where no registry exists
    /// (unit tests that build the filter directly).
    exported: Option<(Arc<Registry>, Handle)>,
    /// Responses whose raw `usage` object was over the verbatim-capture bound.
    upstream_usage_oversized: ExportedCounter,
    /// Responses whose provider response id was over its bound.
    upstream_id_oversized: ExportedCounter,
    /// Streams that ended before the provider's final usage and were recorded
    /// as partial. Each one is metered from an estimate.
    partial: ExportedCounter,
    /// Partial records whose token counts include an estimate.
    estimated: ExportedCounter,
    /// Priced requests whose image or audio tokens had no modality rate on
    /// their entry, so they were charged at the text rate (ADR-0010
    /// decision 3).
    underpriced_modality: ExportedCounter,
    /// Attempts with no response charged an estimate.
    unanswered: ExportedCounter,
    /// Attempts with no response charged nothing (`unanswered_usage: none`).
    unanswered_uncharged: ExportedCounter,
    last_uncharged_warning: Mutex<Option<Instant>>,
}

/// One Prometheus-exported counter that also keeps an in-process total, so
/// unit tests can read it without rendering the export. `series` is `None`
/// only where no registry exists (filters built directly in tests).
#[derive(Default)]
struct ExportedCounter {
    total: AtomicU64,
    series: Option<(Arc<Registry>, Handle)>,
}

impl ExportedCounter {
    fn new(registry: Option<&Arc<Registry>>, instrument: &'static Instrument, scope: &str) -> Self {
        Self {
            total: AtomicU64::new(0),
            series: registry.map(|registry| {
                let handle = registry.resolve_capped(
                    instrument,
                    &[("scope", scope)],
                    256,
                    &[("scope", "overflow")],
                );
                (Arc::clone(registry), handle)
            }),
        }
    }

    fn incr(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if let Some((registry, handle)) = &self.series {
            registry.incr(WorkerId(0), *handle, 1);
        }
    }

    fn get(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

/// `SharedFactoryState` key under which the listener seeds the process
/// `Arc<Registry>` (scope `""`) for filters that export counters.
pub const STATS_REGISTRY_KEY: &str = "llmproxy.internal.stats_registry";

/// Type URL key of the per-chain [`UsageStats`] singleton. One per chain, so
/// the warning's suppression state survives per-worker and per-rebuild
/// `create` calls instead of repeating for each.
const STATS_SINGLETON_KEY: &str = "llmproxy.internal.usage_stats";

impl UsageStats {
    fn new(registry: Option<Arc<Registry>>, scope: &str) -> Self {
        let exported = registry.map(|registry| {
            let handle = registry.resolve_capped(
                &instruments::USAGE_OVERSIZED_BODY_UNMETERED,
                &[("scope", scope)],
                256,
                &[("scope", "overflow")],
            );
            (registry, handle)
        });
        let repriced_handle = exported.as_ref().map(|(registry, _)| {
            registry.resolve_capped(
                &instruments::USAGE_SERVED_MODEL_REPRICED,
                &[("scope", scope)],
                256,
                &[("scope", "overflow")],
            )
        });
        UsageStats {
            upstream_usage_oversized: ExportedCounter::new(
                exported.as_ref().map(|(registry, _)| registry),
                &instruments::USAGE_UPSTREAM_USAGE_OVERSIZED,
                scope,
            ),
            upstream_id_oversized: ExportedCounter::new(
                exported.as_ref().map(|(registry, _)| registry),
                &instruments::USAGE_UPSTREAM_ID_OVERSIZED,
                scope,
            ),
            partial: ExportedCounter::new(
                exported.as_ref().map(|(registry, _)| registry),
                &instruments::USAGE_PARTIAL,
                scope,
            ),
            estimated: ExportedCounter::new(
                exported.as_ref().map(|(registry, _)| registry),
                &instruments::USAGE_ESTIMATED,
                scope,
            ),
            underpriced_modality: ExportedCounter::new(
                exported.as_ref().map(|(registry, _)| registry),
                &instruments::USAGE_UNDERPRICED_MODALITY,
                scope,
            ),
            unanswered: ExportedCounter::new(
                exported.as_ref().map(|(registry, _)| registry),
                &instruments::USAGE_UNANSWERED,
                scope,
            ),
            unanswered_uncharged: ExportedCounter::new(
                exported.as_ref().map(|(registry, _)| registry),
                &instruments::USAGE_UNANSWERED_UNCHARGED,
                scope,
            ),
            exported,
            repriced_handle,
            scope: scope.to_string(),
            ..Default::default()
        }
    }

    pub fn realtime_missing(&self) -> u64 {
        self.realtime_missing.load(Ordering::Relaxed)
    }

    pub fn oversized_unrecoverable(&self) -> u64 {
        self.oversized_unrecoverable.load(Ordering::Relaxed)
    }

    pub fn upstream_usage_oversized(&self) -> u64 {
        self.upstream_usage_oversized.get()
    }

    pub fn partial(&self) -> u64 {
        self.partial.get()
    }

    pub fn estimated(&self) -> u64 {
        self.estimated.get()
    }

    pub fn underpriced_modality(&self) -> u64 {
        self.underpriced_modality.get()
    }

    pub fn upstream_id_oversized(&self) -> u64 {
        self.upstream_id_oversized.get()
    }

    pub fn served_model_repriced(&self) -> u64 {
        self.served_model_repriced.load(Ordering::Relaxed)
    }

    /// Count a request priced at the served model. Deliberately silent in the
    /// log: a served model with no card is common and keeps the requested
    /// price, and this path fires only when a card does exist, so the counter
    /// is the whole signal.
    fn note_served_model_repriced(&self) {
        self.served_model_repriced.fetch_add(1, Ordering::Relaxed);
        if let (Some((registry, _)), Some(handle)) = (&self.exported, self.repriced_handle) {
            registry.incr(WorkerId(0), handle, 1);
        }
    }

    fn note_realtime_missing(&self, missing: &[Missing], cluster: Option<&str>) {
        for reason in missing {
            self.realtime_missing.fetch_add(1, Ordering::Relaxed);
            if let Some((registry, _)) = &self.exported {
                let handle = registry.resolve_capped(
                    &instruments::REALTIME_USAGE_MISSING,
                    &[("scope", self.scope.as_str()), ("reason", reason.label())],
                    256,
                    &[("scope", "overflow"), ("reason", reason.label())],
                );
                registry.incr(WorkerId(0), handle, 1);
            }
        }
        let now = Instant::now();
        let mut last = self
            .last_realtime_warning
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|at| now.duration_since(at) < OVERSIZED_WARN_INTERVAL) {
            return;
        }
        *last = Some(now);
        drop(last);
        // Fails open: the session ran, but these responses are not metered,
        // so spend and token limits did not count them. Only the cluster name
        // and the reason labels are logged, never frame content.
        let reasons: Vec<&str> = missing.iter().map(|m| m.label()).collect();
        tracing::warn!(
            cluster = ?cluster,
            ?reasons,
            "usage: a realtime session had responses with no readable usage, so they were NOT \
             metered (no cost, spend and token limits did not count them). Exported as \
             envoy_llmproxy_realtime_usage_missing_total{{reason}}; this warning repeats at most \
             once per minute."
        );
    }

    /// An attempt with no response that its provider's
    /// `unanswered_usage: none` leaves uncharged. The operator chose this, but
    /// it is still a request the provider can bill that no budget counts, so
    /// it is loud (AGENTS.md "Fail-open controls"): counted, and warned about
    /// at most once per interval. Reached only by such an attempt.
    fn note_unanswered_uncharged(&self, cluster: &str) {
        self.unanswered_uncharged.incr();
        let now = Instant::now();
        let mut last = self
            .last_uncharged_warning
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|at| now.duration_since(at) < OVERSIZED_WARN_INTERVAL) {
            return;
        }
        *last = Some(now);
        drop(last);
        // Only the operator-chosen cluster name is logged.
        tracing::warn!(
            cluster = %cluster,
            "usage: an attempt sent this provider the whole request and got no response, and \
             the provider's `unanswered_usage` is `none`, so it was NOT charged (no cost, spend \
             and token limits did not count it). The provider can still bill it. Exported as \
             envoy_llmproxy_usage_unanswered_uncharged_total; this warning repeats at most once \
             per minute."
        );
    }

    fn note_oversized_unrecoverable(&self, cluster: Option<&str>) {
        self.oversized_unrecoverable.fetch_add(1, Ordering::Relaxed);
        if let Some((registry, handle)) = &self.exported {
            registry.incr(WorkerId(0), *handle, 1);
        }
        let now = Instant::now();
        let mut last = self
            .last_oversized_warning
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|at| now.duration_since(at) < OVERSIZED_WARN_INTERVAL) {
            return;
        }
        *last = Some(now);
        drop(last);
        // This control fails open: the response is delivered, but nothing is
        // metered or charged for it. Only the operator-chosen cluster name is
        // logged, never any body content.
        tracing::warn!(
            cluster = ?cluster,
            max_body_bytes = MAX_JSON_BODY_BYTES,
            tail_window_bytes = JSON_TAIL_WINDOW_BYTES,
            "usage: a JSON response over the size cap carried no recoverable `usage` object \
             in its tail window, so this request was NOT metered (no usage, no cost, spend and \
             token limits did not count it). Exported as envoy_llmproxy_usage_oversized_body_unmetered_total; \
             this warning repeats at most once per minute."
        );
    }
}

/// Writes a request charged across `charges` (at least one an attempt that
/// got no response): `usage` and `list_cost` are their sums, the record is
/// `partial` and estimated, and the breakdown stays in `attempt_charges` for
/// the spend filter and the per-attempt record. `list_cost` sums the entries
/// a rate card priced, and is `None` when none was.
fn write_charges(info: &mut StreamInfo, charges: Vec<AttemptCharge>, basis: Option<PriceBasis>) {
    let mut tokens = LlmTokenUsage::default();
    for charge in &charges {
        let t = charge.usage.tokens_or_zero();
        tokens.input_tokens += t.input_tokens;
        tokens.cached_tokens += t.cached_tokens;
        tokens.cache_creation_tokens += t.cache_creation_tokens;
        tokens.output_tokens += t.output_tokens;
    }
    let priced: Vec<&LlmListCost> = charges
        .iter()
        .filter_map(|c| c.list_cost.as_ref())
        .collect();
    info.llm.list_cost = priced.first().map(|first| {
        let nanodollars = priced.iter().map(|cost| cost.nanodollars).sum();
        LlmListCost {
            nanodollars,
            micro_usd: PricingRegistry::charge_micro_usd(nanodollars),
            rate_card_version: first.rate_card_version.clone(),
        }
    });
    info.llm.price_basis = info.llm.list_cost.as_ref().and(basis);
    info.llm.usage = Some(LlmUsage::from_tokens(tokens));
    info.llm.completeness = Some(UsageCompleteness::Partial);
    info.llm.input_estimated = charges.iter().any(|c| c.input_estimated);
    info.llm.output_estimated = charges.iter().any(|c| c.output_estimated);
    info.llm.attempt_charges = charges;
}

/// The provider's `usage` object as sent, from a media scanner's capture.
/// Media responses carry no response id.
fn media_upstream(usage: Option<&str>, oversized: bool) -> UpstreamEvidence {
    let mut evidence = UpstreamEvidence::default();
    if let Some(usage) = usage {
        evidence.set_usage(usage);
    }
    evidence.usage_oversized |= oversized;
    evidence
}

/// Convert a [`TokenUsage`] into the [`LlmTokenUsage`] that `StreamInfo`
/// carries. All four cost buckets cross the boundary intact — dropping the
/// cache buckets would leave anything downstream (billing, the token
/// limiter) unable to compute a correct cost, since the buckets are priced
/// differently.
///
/// A function, not a `From` impl: `TokenUsage` lives in proxy-control and
/// `LlmTokenUsage` in proxy-http, and Rust's orphan rule allows the impl only
/// in the crate that defines one of them. Neither crate depends on the other.
/// This is what `stream_info.rs`'s doc comment on `LlmTokenUsage` means by
/// "the usage filter converts at its boundary".
fn llm_token_usage(usage: TokenUsage) -> LlmTokenUsage {
    LlmTokenUsage {
        input_tokens: usage.input_tokens,
        cached_tokens: usage.cached_tokens,
        cache_creation_tokens: usage.cache_creation_tokens,
        output_tokens: usage.output_tokens,
        ..LlmTokenUsage::default()
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
        let registry = registry_for_chain(ctx)?;
        registry.apply_config(
            parsed.pricing,
            control_plane_of(ctx),
            "typed_config.pricing_json",
        )?;
        Ok(Box::new(UsageFilterInstanceFactory {
            dialect: parsed.dialect,
            registry,
            stats: stats_of(ctx)?,
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
    #[serde(default)]
    catalog: Option<serde_json::Value>,
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
    #[serde(default)]
    cached_input_unpriced: bool,
    #[serde(default)]
    cache_write_unpriced: bool,
    provider_type: String,
    model: String,
    /// `tokens` (the default), `images`, `characters` or `audio_seconds`
    /// (ADR-0010 decision 3).
    #[serde(default)]
    basis: Option<String>,
    /// Required for `tokens`, refused for every other basis.
    #[serde(default)]
    tier_mode: Option<String>,
    #[serde(default)]
    tiers: Option<Vec<TierWire>>,
    /// Required for `images`, refused for every other basis.
    #[serde(default)]
    image_prices: Option<Vec<ImagePriceWire>>,
    /// Required for `characters`, refused for every other basis.
    #[serde(default)]
    nanodollars_per_character: Option<u64>,
    /// Required for `audio_seconds`, refused for every other basis.
    #[serde(default)]
    nanodollars_per_second: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImagePriceWire {
    #[serde(default)]
    size: Option<String>,
    #[serde(default)]
    quality: Option<String>,
    nanodollars_per_image: u64,
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
    #[serde(default)]
    image_input_nanodollars_per_token: Option<u64>,
    #[serde(default)]
    image_output_nanodollars_per_token: Option<u64>,
    #[serde(default)]
    audio_input_nanodollars_per_token: Option<u64>,
    #[serde(default)]
    audio_output_nanodollars_per_token: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PricingWire {
    price_list: PriceListWire,
    providers: HashMap<String, String>,
    #[serde(default)]
    catalog: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PricingContext {
    /// The prices and the dialled-cluster -> provider-type map that decides
    /// which entry applies, versioned together.
    list: Arc<PriceList>,
    catalog: Option<Arc<serde_json::Value>>,
}

impl PricingContext {
    /// The card's immutable version, as request records and ledger entries
    /// name it.
    pub(crate) fn version(&self) -> &str {
        self.list.version().as_str()
    }

    /// The wire document `PUT /pricing` accepts, rendered from the parsed
    /// card: what the store keeps. Rendering it from the parsed card, not
    /// keeping the caller's text, means every source (configuration, a `PUT`,
    /// the legacy carrier) stores the same compact shape, and anything stored
    /// parses back to this exact card.
    /// The store row for this card. A card that uses an ADR-0010 field is
    /// written at schema version 2, which an older replica skips.
    fn stored_row(&self, chain: &str) -> StoredRateCard {
        StoredRateCard {
            chain: chain.to_string(),
            version: self.list.version().to_string(),
            card_json: self.to_wire_json(),
            schema_version: if self.list.uses_media_fields() {
                RATE_CARD_SCHEMA_V2
            } else {
                RATE_CARD_SCHEMA_V1
            },
        }
    }

    fn to_wire_json(&self) -> String {
        let view = PricingJsonView::from(self.clone());
        serde_json::json!({
            "price_list": view.price_list,
            "providers": view.providers,
            "catalog": view.catalog,
        })
        .to_string()
    }
}

/// Parses a pricing document in the wire shape used by configuration, `PUT
/// /pricing`, and the store.
fn parse_card_json(json: &str) -> Result<PricingContext, ConfigError> {
    let wire: PricingWire = serde_json::from_str(json)
        .map_err(|e| invalid_config(format!("pricing update is invalid JSON: {e}")))?;
    parse_pricing(wire)
}

#[derive(Serialize)]
pub struct PricingJsonView {
    rate_card_version: String,
    price_list: PriceListJsonView,
    providers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    catalog: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct PriceListJsonView {
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    effective_from: String,
    entries: Vec<PriceEntryJsonView>,
}

/// The ADR-0010 fields are left out while they hold their defaults, so a card
/// that uses none renders, stores and reads back exactly as before, and an
/// older replica can still parse it.
#[derive(Serialize)]
struct PriceEntryJsonView {
    cached_input_unpriced: bool,
    cache_write_unpriced: bool,
    provider_type: String,
    model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    basis: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tier_mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tiers: Option<Vec<TierJsonView>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_prices: Option<Vec<ImagePriceJsonView>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nanodollars_per_character: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nanodollars_per_second: Option<u64>,
}

#[derive(Serialize)]
struct TierJsonView {
    up_to: Option<u64>,
    input_nanodollars_per_token: u64,
    cached_input_nanodollars_per_token: u64,
    cache_write_nanodollars_per_token: u64,
    output_nanodollars_per_token: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_input_nanodollars_per_token: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_output_nanodollars_per_token: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audio_input_nanodollars_per_token: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audio_output_nanodollars_per_token: Option<u64>,
}

#[derive(Serialize)]
struct ImagePriceJsonView {
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quality: Option<String>,
    nanodollars_per_image: u64,
}

impl From<PricingContext> for PricingJsonView {
    fn from(pricing: PricingContext) -> Self {
        let version = pricing.list.version().as_str().to_string();
        let effective_from: chrono::DateTime<chrono::Utc> = pricing.list.effective_from().into();
        let entries = pricing
            .list
            .entries()
            .iter()
            .map(|entry| {
                let tokens = entry.basis == PriceBasis::Tokens;
                PriceEntryJsonView {
                    cached_input_unpriced: entry.cached_input_unpriced,
                    cache_write_unpriced: entry.cache_write_unpriced,
                    provider_type: entry.provider_type.clone(),
                    model: entry.model.clone(),
                    basis: (!tokens).then(|| entry.basis.as_str()),
                    tier_mode: tokens.then_some(match entry.tier_mode {
                        TierMode::WholeRequest => "whole_request",
                        TierMode::Graduated => "graduated",
                    }),
                    tiers: tokens.then(|| {
                        entry
                            .tiers
                            .iter()
                            .map(|tier| TierJsonView {
                                up_to: tier.up_to,
                                input_nanodollars_per_token: tier.input_nanodollars_per_token,
                                cached_input_nanodollars_per_token: tier
                                    .cached_input_nanodollars_per_token,
                                cache_write_nanodollars_per_token: tier
                                    .cache_write_nanodollars_per_token,
                                output_nanodollars_per_token: tier.output_nanodollars_per_token,
                                image_input_nanodollars_per_token: tier
                                    .image_input_nanodollars_per_token,
                                image_output_nanodollars_per_token: tier
                                    .image_output_nanodollars_per_token,
                                audio_input_nanodollars_per_token: tier
                                    .audio_input_nanodollars_per_token,
                                audio_output_nanodollars_per_token: tier
                                    .audio_output_nanodollars_per_token,
                            })
                            .collect()
                    }),
                    nanodollars_per_character: entry.nanodollars_per_character,
                    nanodollars_per_second: entry.nanodollars_per_second,
                    image_prices: (entry.basis == PriceBasis::Images).then(|| {
                        entry
                            .image_prices
                            .iter()
                            .map(|row| ImagePriceJsonView {
                                size: row.size.clone(),
                                quality: row.quality.clone(),
                                nanodollars_per_image: row.nanodollars_per_image,
                            })
                            .collect()
                    }),
                }
            })
            .collect();
        Self {
            rate_card_version: version.clone(),
            price_list: PriceListJsonView {
                version: pricing.list.label().map(str::to_owned),
                effective_from: effective_from.to_rfc3339(),
                entries,
            },
            providers: pricing.list.cluster_providers().clone(),
            catalog: pricing.catalog.map(|catalog| (*catalog).clone()),
        }
    }
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
        entries.push(parse_entry(entry_index, entry)?);
    }
    Ok(PricingContext {
        list: Arc::new(PriceList::new(
            wire.price_list.version.as_deref(),
            effective_from,
            entries,
            wire.providers.into_iter().collect(),
        )),
        catalog: wire.catalog.map(Arc::new),
    })
}

/// Parse one price entry. An entry prices only the meters of its basis, so a
/// field that belongs to the other basis is refused rather than ignored
/// (AGENTS.md invariant 1).
fn parse_entry(entry_index: usize, entry: PriceEntryWire) -> Result<PriceEntry, ConfigError> {
    let at = |field: &str| format!("price_list.entries[{entry_index}].{field}");
    if entry.provider_type.is_empty() || entry.model.is_empty() {
        return Err(invalid_config(format!(
            "price_list.entries[{entry_index}] requires provider_type and model"
        )));
    }
    let basis = match entry.basis.as_deref() {
        None | Some("tokens") => PriceBasis::Tokens,
        Some("images") => PriceBasis::Images,
        Some("characters") => PriceBasis::Characters,
        Some("audio_seconds") => PriceBasis::AudioSeconds,
        Some(other) => {
            return Err(invalid_config(format!(
                "{} must be tokens, images, characters or audio_seconds, got `{other}`",
                at("basis")
            )));
        }
    };
    // Each basis's own price field, refused on every other basis.
    for (set, field, owner) in [
        (
            entry.image_prices.is_some(),
            "image_prices",
            PriceBasis::Images,
        ),
        (
            entry.nanodollars_per_character.is_some(),
            "nanodollars_per_character",
            PriceBasis::Characters,
        ),
        (
            entry.nanodollars_per_second.is_some(),
            "nanodollars_per_second",
            PriceBasis::AudioSeconds,
        ),
    ] {
        if set && basis != owner {
            return Err(invalid_config(format!(
                "{} applies only to basis {}",
                at(field),
                owner.as_str()
            )));
        }
    }
    if basis != PriceBasis::Tokens {
        for (set, field) in [
            (entry.tier_mode.is_some(), "tier_mode"),
            (entry.tiers.is_some(), "tiers"),
            (entry.cached_input_unpriced, "cached_input_unpriced"),
            (entry.cache_write_unpriced, "cache_write_unpriced"),
        ] {
            if set {
                return Err(invalid_config(format!(
                    "{} does not apply to basis {}",
                    at(field),
                    basis.as_str()
                )));
            }
        }
    }
    let unit_entry = |nanodollars_per_character, nanodollars_per_second| PriceEntry {
        cached_input_unpriced: false,
        cache_write_unpriced: false,
        provider_type: entry.provider_type.clone(),
        model: entry.model.clone(),
        tier_basis: TierBasis::InputTokens,
        // Unused for a unit basis; fixed so the version hash is stable.
        tier_mode: TierMode::WholeRequest,
        tiers: Vec::new(),
        basis,
        image_prices: Vec::new(),
        nanodollars_per_character,
        nanodollars_per_second,
    };
    match basis {
        PriceBasis::Characters => {
            let Some(rate) = entry.nanodollars_per_character else {
                return Err(invalid_config(format!(
                    "{} is required for basis characters",
                    at("nanodollars_per_character")
                )));
            };
            return Ok(unit_entry(Some(rate), None));
        }
        PriceBasis::AudioSeconds => {
            let Some(rate) = entry.nanodollars_per_second else {
                return Err(invalid_config(format!(
                    "{} is required for basis audio_seconds",
                    at("nanodollars_per_second")
                )));
            };
            return Ok(unit_entry(None, Some(rate)));
        }
        PriceBasis::Tokens | PriceBasis::Images => {}
    }
    if basis == PriceBasis::Images {
        let rows: Vec<ImagePrice> = entry
            .image_prices
            .unwrap_or_default()
            .into_iter()
            .map(|row| ImagePrice {
                size: row.size,
                quality: row.quality,
                nanodollars_per_image: row.nanodollars_per_image,
            })
            .collect();
        if rows.is_empty() {
            return Err(invalid_config(format!(
                "{} requires at least one row for basis images",
                at("image_prices")
            )));
        }
        for (row_index, row) in rows.iter().enumerate() {
            if row.size.as_deref() == Some("") || row.quality.as_deref() == Some("") {
                return Err(invalid_config(format!(
                    "{}[{row_index}] size and quality must not be empty",
                    at("image_prices")
                )));
            }
        }
        if let Some((first, second)) = image_prices_conflict(&rows) {
            return Err(invalid_config(format!(
                "{}[{second}] can match the same request as image_prices[{first}] at the same \
                 specificity, so the price would be ambiguous",
                at("image_prices")
            )));
        }
        return Ok(PriceEntry {
            cached_input_unpriced: false,
            cache_write_unpriced: false,
            provider_type: entry.provider_type,
            model: entry.model,
            tier_basis: TierBasis::InputTokens,
            // Unused for basis images; fixed so the version hash is stable.
            tier_mode: TierMode::WholeRequest,
            tiers: Vec::new(),
            basis,
            image_prices: rows,
            nanodollars_per_character: None,
            nanodollars_per_second: None,
        });
    }
    let tiers = entry.tiers.unwrap_or_default();
    if tiers.is_empty() {
        return Err(invalid_config(format!(
            "price_list.entries[{entry_index}] requires provider_type, model, and tiers"
        )));
    }
    let tier_mode = match entry.tier_mode.as_deref() {
        Some("whole_request") => TierMode::WholeRequest,
        Some("graduated") => TierMode::Graduated,
        other => {
            return Err(invalid_config(format!(
                "price_list.entries[{entry_index}].tier_mode must be whole_request or graduated, got `{}`",
                other.unwrap_or_default()
            )));
        }
    };
    let mut previous = None;
    for (tier_index, tier) in tiers.iter().enumerate() {
        if tier.up_to.is_none() && tier_index + 1 != tiers.len() {
            return Err(invalid_config(format!(
                "price_list.entries[{entry_index}].tiers[{tier_index}] open-ended tier must be last"
            )));
        }
        if tier
            .up_to
            .is_some_and(|up_to| previous.is_some_and(|p| up_to <= p))
        {
            return Err(invalid_config(format!(
                "price_list.entries[{entry_index}].tiers[{tier_index}].up_to must strictly increase"
            )));
        }
        if tier.up_to.is_some() {
            previous = tier.up_to;
        }
    }
    if tiers.last().is_some_and(|tier| tier.up_to.is_some()) {
        return Err(invalid_config(format!(
            "price_list.entries[{entry_index}].tiers requires a final open-ended tier"
        )));
    }
    // A modality rate on some bands and not others would price the same
    // token at a modality rate in one band and the text rate in the next.
    type Field = fn(&TierWire) -> Option<u64>;
    let modality: [(&str, Field); 4] = [
        ("image_input_nanodollars_per_token", |t| {
            t.image_input_nanodollars_per_token
        }),
        ("image_output_nanodollars_per_token", |t| {
            t.image_output_nanodollars_per_token
        }),
        ("audio_input_nanodollars_per_token", |t| {
            t.audio_input_nanodollars_per_token
        }),
        ("audio_output_nanodollars_per_token", |t| {
            t.audio_output_nanodollars_per_token
        }),
    ];
    for (name, field) in modality {
        let set = field(&tiers[0]).is_some();
        if let Some(tier_index) = tiers.iter().position(|t| field(t).is_some() != set) {
            return Err(invalid_config(format!(
                "price_list.entries[{entry_index}].tiers[{tier_index}].{name} must be set on \
                 every tier of the entry or on none"
            )));
        }
    }
    Ok(PriceEntry {
        cached_input_unpriced: entry.cached_input_unpriced,
        cache_write_unpriced: entry.cache_write_unpriced,
        provider_type: entry.provider_type,
        model: entry.model,
        tier_basis: TierBasis::InputTokens,
        tier_mode,
        tiers: tiers
            .into_iter()
            .map(|tier| Tier {
                up_to: tier.up_to,
                input_nanodollars_per_token: tier.input_nanodollars_per_token,
                cached_input_nanodollars_per_token: tier.cached_input_nanodollars_per_token,
                cache_write_nanodollars_per_token: tier.cache_write_nanodollars_per_token,
                output_nanodollars_per_token: tier.output_nanodollars_per_token,
                image_input_nanodollars_per_token: tier.image_input_nanodollars_per_token,
                image_output_nanodollars_per_token: tier.image_output_nanodollars_per_token,
                audio_input_nanodollars_per_token: tier.audio_input_nanodollars_per_token,
                audio_output_nanodollars_per_token: tier.audio_output_nanodollars_per_token,
            })
            .collect(),
        basis,
        image_prices: Vec::new(),
        nanodollars_per_character: None,
        nanodollars_per_second: None,
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
        catalog: wire.catalog,
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
        ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        warn_legacy_config();
        let parsed = parse_legacy_factory_config(config)?;
        // The same registry the current carrier uses, so `PUT /pricing`, the
        // store and the spend filter all see this chain's card. A private
        // registry here left `/pricing` answering 503 for the whole chain and
        // gave the spend filter an empty card.
        let registry = registry_for_chain(ctx)?;
        registry.apply_config(
            parsed.pricing,
            control_plane_of(ctx),
            "typed_config.inline_string",
        )?;
        Ok(Box::new(UsageFilterInstanceFactory {
            dialect: parsed.dialect,
            registry,
            stats: stats_of(ctx)?,
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
    stats: Arc<UsageStats>,
}

impl FilterInstanceFactory for UsageFilterInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(UsageFilterInstance {
            dialect: self.dialect,
            pricing: self.registry.snapshot(),
            request_dialect: None,
            endpoint: Endpoint::Unmetered,
            request_size: None,
            request_quality: None,
            request_input_characters: None,
            stats: Arc::clone(&self.stats),
            mode: BodyMode::Inert,
            headers_at: None,
            last_chunk_at: None,
            time_to_first_byte: None,
            time_to_first_body_byte: None,
            max_inter_chunk: None,
            response_chunks: 0,
            response_ok: false,
            request_is_connect: false,
            finalized: false,
        })
    }
}

/// Rust note: an enum used as a small state machine — which strategy (if any)
/// this stream's body is being read with. Matching on it is exhaustive, so
/// adding a fourth mode later forces every call site here to decide what it
/// does in that case (AGENTS.md invariant 1's spirit, applied to our own code).
enum BodyMode {
    /// `text/event-stream`: feed chunks to the incremental SSE scanner.
    Sse(SseUsageScanner),
    /// `application/json`: accumulate the body, up to [`MAX_JSON_BODY_BYTES`],
    /// then keep only the last [`JSON_TAIL_WINDOW_BYTES`].
    Json(JsonBody),
    /// A media endpoint's JSON body (ADR-0010 decision 4): scanned
    /// structurally, never held, because its base64 images overflow
    /// [`MAX_JSON_BODY_BYTES`].
    MediaJson(MediaJsonScanner),
    /// A media endpoint's event stream, each `data:` line scanned the same way.
    MediaSse(MediaSseScanner),
    /// An accepted realtime session: the tunnel's server frames, read for
    /// `response.done` usage (ADR-0015).
    Realtime(RealtimeScanner),
    /// Anything else (including "haven't seen headers yet"): do nothing.
    Inert,
}

/// A JSON body being accumulated for usage extraction.
#[derive(Default)]
struct JsonBody {
    /// The whole body until it passes the cap; afterwards only its tail.
    buf: BytesMut,
    /// The body passed [`MAX_JSON_BODY_BYTES`]; `buf` is now a tail window.
    overflowed: bool,
    /// Total body bytes seen, including any dropped from the head.
    seen: u64,
    /// What one parse of the complete body found. Usage, served model and
    /// evidence are read at different points of `finalize`; the body is
    /// parsed once for all of them, and again only if more bytes arrive.
    ///
    /// Rust note: `OnceCell` fills itself on first read through a shared
    /// `&self`, which is what the `compute_*` readers hold.
    facts: OnceCell<JsonResponseFacts>,
}

impl JsonBody {
    fn push(&mut self, data: &[u8]) {
        self.facts.take();
        self.seen = self.seen.saturating_add(data.len() as u64);
        if !self.overflowed && self.buf.len() + data.len() <= MAX_JSON_BODY_BYTES {
            self.buf.extend_from_slice(data);
            return;
        }
        self.overflowed = true;
        self.buf.extend_from_slice(data);
        if self.buf.len() > JSON_TAIL_WINDOW_BYTES {
            // Rust note: `split_to` hands back the front part and leaves the
            // rest in place, so this discards the head without copying the tail.
            let excess = self.buf.len() - JSON_TAIL_WINDOW_BYTES;
            drop(self.buf.split_to(excess));
        }
    }

    /// The single parse of a body that stayed under the cap.
    fn facts(&self) -> &JsonResponseFacts {
        self.facts.get_or_init(|| extract_json_facts(&self.buf))
    }
}

/// Per-stream instance. One of these is created per response, per the frozen
/// `HttpFilter` contract (see `filter.rs`'s module doc) — so `!Send` interior
/// state (plain fields here, no `Rc`/`RefCell` needed) is safe: it never
/// leaves the worker thread that owns this stream.
struct UsageFilterInstance {
    /// The cluster's (or route's) configured dialect. Also labels
    /// `gen_ai.system`, which names the provider and so follows the cluster.
    dialect: Dialect,
    /// Parser chosen from the request's method and path, when it names an API
    /// whose response shape differs from the cluster's dialect. Only the
    /// parser follows the path; the provider label does not, since a gateway
    /// serving `/v1/messages` from an OpenAI-dialect cluster is still that
    /// cluster's provider.
    request_dialect: Option<Dialect>,
    /// The request's endpoint class, from stream info at `decode_headers`.
    endpoint: Endpoint,
    /// The request body's `size` and `quality`, the fallback when the
    /// response does not echo them. Read at `encode_headers`, after the
    /// body-rewrite filter published them.
    request_size: Option<String>,
    request_quality: Option<String>,
    /// The speech request's `input` characters, the request-side meter
    /// (ADR-0010 decision 2). Read at `encode_headers`.
    request_input_characters: Option<u64>,
    stats: Arc<UsageStats>,
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
    /// The response status was 2xx, or accepted a realtime session. Only
    /// such a response that is cut off is recorded as a partial, metered
    /// stream; an error body is not usage.
    response_ok: bool,
    /// The request is an h2 extended CONNECT, whose accept status is `200`.
    request_is_connect: bool,
    /// Guards against writing `StreamInfo` twice — `encode_data` with
    /// `end_stream=true` and a later `encode_trailers` (or vice versa) must
    /// not both finalize.
    finalized: bool,
}

/// Pick a [`BodyMode`] from the response's `content-type`, matching only the
/// media type (before any `;` parameters), ASCII-case-insensitively. Absent
/// or unrecognized content types get [`BodyMode::Inert`] — we do not guess.
fn classify_body(headers: &HeaderMap, dialect: Dialect, endpoint: Endpoint) -> BodyMode {
    let Some(value) = headers.get(http::header::CONTENT_TYPE) else {
        return BodyMode::Inert;
    };
    let Ok(value) = value.to_str() else {
        return BodyMode::Inert;
    };
    let media_type = value.split(';').next().unwrap_or("").trim();

    let media = is_media(endpoint);
    if media_type.eq_ignore_ascii_case("text/event-stream") {
        if media {
            BodyMode::MediaSse(MediaSseScanner::new())
        } else {
            BodyMode::Sse(SseUsageScanner::new(dialect))
        }
    } else if media_type.eq_ignore_ascii_case("application/json") {
        if media {
            BodyMode::MediaJson(MediaJsonScanner::new())
        } else {
            BodyMode::Json(JsonBody::default())
        }
    } else {
        BodyMode::Inert
    }
}

/// Pick the response parser from the downstream request. Only POST creates a
/// generation; a GET that retrieves a stored response must not be metered as a
/// new one, so it keeps the cluster dialect.
///
/// `/embeddings` is the OpenAI wire shape on every provider that serves it
/// (`usage.prompt_tokens`, no output tokens), so it is read with the OpenAI
/// parser even behind a cluster whose dialect is Anthropic: that parser would
/// look for `input_tokens` and meter nothing.
fn dialect_for_request(endpoint: Endpoint) -> Option<Dialect> {
    match endpoint {
        // The Images and Audio APIs report usage in the Responses shape
        // (`input_tokens`, `input_tokens_details.image_tokens`, transcription's
        // `input_token_details.audio_tokens`, ...). A duration-only usage
        // object carries none of those keys, so it reads as no tokens.
        Endpoint::Responses
        | Endpoint::ImageGeneration
        | Endpoint::ImageEdit
        | Endpoint::Speech
        | Endpoint::Transcription
        | Endpoint::Translation => Some(Dialect::OpenAiResponses),
        Endpoint::Messages => Some(Dialect::Anthropic),
        Endpoint::Embeddings => Some(Dialect::OpenAi),
        _ => None,
    }
}

/// Endpoints whose bodies are base64 media or audio, not generated text. They
/// are scanned structurally, and a cut response is never estimated from its
/// byte count: that would charge hundreds of thousands of output tokens for
/// one image (ADR-0010 decision 2, "Cut responses").
fn is_media(endpoint: Endpoint) -> bool {
    matches!(
        endpoint,
        Endpoint::ImageGeneration
            | Endpoint::ImageEdit
            | Endpoint::Speech
            | Endpoint::Transcription
            | Endpoint::Translation
    )
}

/// Audio duration from a transcription `usage` object, in milliseconds: the
/// `seconds` of a `{"type":"duration"}` usage, else `prompt_audio_seconds`.
/// The field names come from the API shape, never from a provider name.
fn audio_milliseconds_from_usage(usage: &str) -> Option<u64> {
    let usage: serde_json::Value = serde_json::from_str(usage).ok()?;
    let seconds = if usage.get("type").and_then(serde_json::Value::as_str) == Some("duration") {
        usage.get("seconds")
    } else {
        usage.get("prompt_audio_seconds")
    };
    seconds?.as_f64().and_then(seconds_to_millis)
}

/// A [`TokenUsage`] and its modality subsets as stream info's
/// [`LlmTokenUsage`].
fn llm_tokens(usage: TokenUsage, modality: Modality) -> LlmTokenUsage {
    LlmTokenUsage {
        input_image_tokens: modality.input_image_tokens,
        output_image_tokens: modality.output_image_tokens,
        input_audio_tokens: modality.input_audio_tokens,
        output_audio_tokens: modality.output_audio_tokens,
        ..llm_token_usage(usage)
    }
}

impl UsageFilterInstance {
    /// The dialect used to read the response body.
    fn parse_dialect(&self) -> Dialect {
        self.request_dialect.unwrap_or(self.dialect)
    }

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

    /// Compute the usage (if any) observed so far for the current body mode,
    /// without consuming `self.mode`: the token buckets with their modality
    /// subsets, and the count meters. `None` when nothing was observed.
    fn compute_usage(&self) -> Option<LlmUsage> {
        let dialect = self.parse_dialect();
        let parts = |raw: Option<&str>| raw.and_then(|raw| usage_object_parts(dialect, raw));
        let (tokens, mut meters) = match &self.mode {
            BodyMode::Sse(scanner) => (
                scanner.usage().map(|u| (u, scanner.modality())),
                LlmMeters::default(),
            ),
            BodyMode::Json(body) if body.overflowed => (
                extract_json_usage_parts_from_tail(dialect, &body.buf),
                LlmMeters::default(),
            ),
            BodyMode::Json(body) => (body.facts().usage_parts(dialect), LlmMeters::default()),
            BodyMode::MediaJson(scanner) => {
                let facts = scanner.facts();
                (
                    parts(facts.usage.as_deref()),
                    self.image_meters(facts.data_elements, &facts.size, &facts.quality),
                )
            }
            BodyMode::MediaSse(scanner) => {
                let facts = scanner.facts();
                (
                    parts(facts.usage.as_deref()),
                    self.image_meters(Some(facts.completed), &facts.size, &facts.quality),
                )
            }
            BodyMode::Realtime(scanner) => (scanner.usage(), LlmMeters::default()),
            BodyMode::Inert => (None, LlmMeters::default()),
        };
        meters.audio_milliseconds = match &self.mode {
            BodyMode::MediaJson(scanner) => {
                let facts = scanner.facts();
                self.audio_meter(facts.usage.as_deref(), facts.duration_ms)
            }
            BodyMode::MediaSse(scanner) => self.audio_meter(scanner.facts().usage.as_deref(), None),
            BodyMode::Sse(_) | BodyMode::Json(_) | BodyMode::Realtime(_) | BodyMode::Inert => None,
        };
        // A request-side meter: charged only when the response the client got
        // was 2xx, once, at the entry of the cluster dialled last. Speech's
        // response is audio, so this is often its only meter.
        if self.endpoint == Endpoint::Speech && self.response_ok {
            meters.input_characters = self.request_input_characters;
        }
        let usage = LlmUsage {
            tokens: tokens.map(|(usage, modality)| llm_tokens(usage, modality)),
            meters,
        };
        (!usage.is_empty()).then_some(usage)
    }

    /// The `audio_milliseconds` meter of a transcription or translation: the
    /// provider's duration usage (`{"type":"duration","seconds":..}`), else
    /// `usage.prompt_audio_seconds`, else the top-level `duration` of a
    /// `verbose_json` response (ADR-0010 decision 2).
    fn audio_meter(&self, usage: Option<&str>, duration_ms: Option<u64>) -> Option<u64> {
        if !matches!(
            self.endpoint,
            Endpoint::Transcription | Endpoint::Translation
        ) {
            return None;
        }
        usage
            .and_then(audio_milliseconds_from_usage)
            .or(duration_ms)
    }

    /// The `images` meter and its attributes, for image generation and
    /// edits; the attributes come from the response echo, then from the
    /// request body (ADR-0010 decision 2).
    fn image_meters(
        &self,
        images: Option<u64>,
        size: &Option<String>,
        quality: &Option<String>,
    ) -> LlmMeters {
        if !matches!(
            self.endpoint,
            Endpoint::ImageGeneration | Endpoint::ImageEdit
        ) {
            return LlmMeters::default();
        }
        let Some(images) = images else {
            return LlmMeters::default();
        };
        LlmMeters {
            images: Some(images),
            image_size: size.clone().or_else(|| self.request_size.clone()),
            image_quality: quality.clone().or_else(|| self.request_quality.clone()),
            ..LlmMeters::default()
        }
    }

    /// The provider-reported model for the current body mode. The oversized
    /// tail path yields `None`: `model` precedes the window.
    fn compute_served_model(&self) -> Option<String> {
        match &self.mode {
            BodyMode::Sse(scanner) => scanner.served_model(),
            BodyMode::Json(body) if body.overflowed => None,
            BodyMode::Json(body) => body.facts().served_model.clone(),
            BodyMode::MediaJson(scanner) => scanner.facts().model.clone(),
            BodyMode::MediaSse(scanner) => scanner.facts().model.clone(),
            BodyMode::Realtime(_) | BodyMode::Inert => None,
        }
    }

    /// The provider's response id and `usage` object as sent, for the current
    /// body mode.
    fn compute_upstream(&self) -> UpstreamEvidence {
        match &self.mode {
            BodyMode::Sse(scanner) => scanner.upstream(),
            BodyMode::Json(body) if body.overflowed => extract_json_upstream_from_tail(&body.buf),
            BodyMode::Json(body) => body.facts().upstream.clone(),
            BodyMode::MediaJson(scanner) => {
                let facts = scanner.facts();
                media_upstream(facts.usage.as_deref(), facts.usage_oversized)
            }
            BodyMode::MediaSse(scanner) => {
                let facts = scanner.facts();
                media_upstream(facts.usage.as_deref(), facts.usage_oversized)
            }
            BodyMode::Realtime(scanner) => media_upstream(scanner.last_usage_json(), false),
            BodyMode::Inert => UpstreamEvidence::default(),
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
        if usage.is_none() && matches!(&self.mode, BodyMode::Json(body) if body.overflowed) {
            let cluster = cb.stream_info().upstream_cluster.clone();
            self.stats.note_oversized_unrecoverable(cluster.as_deref());
        }
        self.report_realtime_missing(cb);
        self.write_stats(cb, usage, UsageCompleteness::Complete, Estimated::default());
    }

    /// Estimate what a stream that ended before the provider's final usage
    /// consumed, from what was actually seen (see [`BYTES_PER_TOKEN_ESTIMATE`]).
    /// Provider figures that did arrive are kept as they are.
    ///
    /// A media response is not estimated: it is charged the token figures
    /// already reported and the images completed so far, or nothing.
    fn estimate_partial_usage(&self, request_bytes: u64) -> (Option<LlmUsage>, Estimated) {
        let seen = self.compute_usage();
        if matches!(self.mode, BodyMode::Realtime(_)) {
            // A session's bytes are mostly base64 audio, so their size says
            // nothing about tokens. It is charged what its `response.done`
            // events reported; a response still in flight is reported by
            // `report_realtime_missing` instead (ADR-0015).
            return (seen, Estimated::default());
        }
        if is_media(self.endpoint) {
            // A cut before any image closed observed nothing. Zero images is
            // not a finding then, so the request stays without usage and the
            // spend filter's missing-usage warning names it.
            let seen = seen.and_then(|mut seen| {
                if seen.meters.images == Some(0) {
                    seen.meters.images = None;
                }
                (!seen.is_empty()).then_some(seen)
            });
            return (seen, Estimated::default());
        }
        let streamed_bytes = match &self.mode {
            BodyMode::Sse(scanner) => scanner.streamed_text_bytes(),
            // A cut-off JSON body cannot be parsed, so its size stands in for
            // the generated text.
            BodyMode::Json(body) => body.seen,
            BodyMode::MediaJson(_)
            | BodyMode::MediaSse(_)
            | BodyMode::Realtime(_)
            | BodyMode::Inert => 0,
        };
        let mut usage = seen.and_then(|seen| seen.tokens).unwrap_or_default();
        let mut estimated = Estimated::default();
        let input_seen = usage.input_tokens + usage.cached_tokens + usage.cache_creation_tokens > 0;
        if !input_seen {
            usage.input_tokens = request_bytes.div_ceil(BYTES_PER_TOKEN_ESTIMATE);
            estimated.input = usage.input_tokens > 0;
        }
        // A provider's early output figure (Anthropic's `message_start` reports
        // 1) understates a stream that kept going, so the larger of the two
        // stands.
        let output_estimate = streamed_bytes.div_ceil(BYTES_PER_TOKEN_ESTIMATE);
        if output_estimate > usage.output_tokens {
            usage.output_tokens = output_estimate;
            estimated.output = true;
        }
        let nothing = usage == LlmTokenUsage::default();
        ((!nothing).then(|| LlmUsage::from_tokens(usage)), estimated)
    }

    /// Count and warn about each realtime response the session did not pay
    /// for (ADR-0015). Runs once, where the stream ends.
    fn report_realtime_missing(&mut self, cb: &mut dyn EncoderCallbacks) {
        let BodyMode::Realtime(scanner) = &mut self.mode else {
            return;
        };
        let missing = scanner.take_missing(true);
        if missing.is_empty() {
            return;
        }
        let cluster = cb.stream_info().upstream_cluster.clone();
        self.stats
            .note_realtime_missing(&missing, cluster.as_deref());
    }

    /// Write usage, cost, timing and the provider's own evidence into
    /// `StreamInfo::llm`.
    /// The rate-card price of `usage` sent to `cluster` as `sent_model`, at
    /// the model the provider says it served when the card lists it
    /// (dated snapshots have no card entry). The spend filter prices with the
    /// same function (`PricingRegistry::price_served`).
    fn price(
        &self,
        cluster: &str,
        sent_model: &str,
        served_model: Option<&str>,
        usage: &LlmUsage,
    ) -> Option<(Priced, LlmListCost)> {
        let pricing = self.pricing.as_ref()?;
        let provider_type = pricing.list.provider_for(cluster)?;
        let (model, repriced) =
            pricing
                .list
                .model_to_price(cluster, sent_model, served_model, usage);
        let priced = pricing.list.price(provider_type, model, usage)?;
        if repriced {
            self.stats.note_served_model_repriced();
        }
        if priced.underpriced_modality {
            // Counted on every request; the spend filter warns where a
            // budget applies.
            self.stats.underpriced_modality.incr();
        }
        Some((
            priced,
            LlmListCost {
                nanodollars: priced.nanodollars,
                micro_usd: PricingRegistry::charge_micro_usd(priced.nanodollars),
                rate_card_version: pricing.list.version().as_str().to_string(),
            },
        ))
    }

    /// One charge per attempt that sent its provider the whole request and got
    /// no response, at that provider's `unanswered_usage` (AGENTS.md
    /// invariant 6): `input` charges the request size over
    /// [`BYTES_PER_TOKEN_ESTIMATE`], `output_cap` adds the output-token limit,
    /// `none` charges nothing and is counted and warned about. Only
    /// token-priced endpoints are charged.
    fn unanswered_charges(&self, info: &StreamInfo) -> Vec<AttemptCharge> {
        if !matches!(
            self.endpoint,
            Endpoint::ChatCompletions
                | Endpoint::Completions
                | Endpoint::Responses
                | Endpoint::Messages
                | Endpoint::Embeddings
        ) {
            return Vec::new();
        }
        let mut charges = Vec::new();
        for attempt in info.dispatched.iter().filter(|a| a.unanswered()) {
            let output_tokens = match attempt.unanswered {
                UnansweredUsage::None => {
                    self.stats.note_unanswered_uncharged(&attempt.cluster);
                    continue;
                }
                UnansweredUsage::Input => 0,
                // Embeddings produce no output tokens.
                UnansweredUsage::OutputCap if self.endpoint == Endpoint::Embeddings => 0,
                // The tighter of the request's own limit and the model's cap;
                // with neither there is no bound, so only input is charged.
                UnansweredUsage::OutputCap => {
                    let model_cap = info.max_output_tokens.map(u64::from);
                    match (info.requested_output_limit, model_cap) {
                        (Some(requested), Some(cap)) => requested.min(cap),
                        (Some(limit), None) | (None, Some(limit)) => limit,
                        (None, None) => 0,
                    }
                }
            };
            self.stats.unanswered.incr();
            let usage = LlmUsage::from_tokens(LlmTokenUsage {
                input_tokens: info.bytes_received.div_ceil(BYTES_PER_TOKEN_ESTIMATE),
                output_tokens,
                ..Default::default()
            });
            let model = attempt
                .model
                .clone()
                .or_else(|| info.routing_model().map(str::to_owned));
            let list_cost = model
                .as_deref()
                .and_then(|model| self.price(&attempt.cluster, model, None, &usage))
                .map(|(_, cost)| cost);
            charges.push(AttemptCharge {
                cluster: attempt.cluster.clone(),
                model,
                served_model: None,
                usage,
                input_estimated: true,
                output_estimated: output_tokens > 0,
                list_cost,
                attempt_index: attempt.attempt_index,
            });
        }
        charges
    }

    /// No upstream response was metered (none arrived, or an error answered):
    /// charge the attempts that the provider received in full and never
    /// answered, if any.
    fn charge_unanswered(&mut self, cb: &mut dyn EncoderCallbacks) {
        let charges = self.unanswered_charges(&cb.stream_info());
        if charges.is_empty() {
            return;
        }
        self.finalized = true;
        self.stats.partial.incr();
        self.stats.estimated.incr();
        let mut info = cb.stream_info();
        write_charges(&mut info, charges, Some(PriceBasis::Tokens));
        info.llm.system = Some(match self.dialect {
            Dialect::OpenAi | Dialect::OpenAiResponses => GenAiSystem::OpenAi,
            Dialect::Anthropic => GenAiSystem::Anthropic,
        });
    }

    fn write_stats(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        usage: Option<LlmUsage>,
        completeness: UsageCompleteness,
        estimated: Estimated,
    ) {
        // Rust note: `stream_info()` hands back a `RefMut` guard, not a plain
        // `&mut` — the stream's single `StreamInfo` is shared (`Rc<RefCell<_>>`)
        // between the filter chain and the router. `RefMut` derefs to
        // `&mut StreamInfo`, so the field writes below are unchanged; the guard
        // just must not be held across another `cb` call, or the `RefCell`
        // panics. It's dropped at the end of this function.
        let mut stream_info = cb.stream_info();
        let served_model = self.compute_served_model();
        let upstream = self.compute_upstream();
        if let Some(attempt) = &stream_info.selected_attempt {
            attempt.borrow_mut().served_model = served_model.clone();
        }
        // `None` must stay `None` here — never write `Some(0, 0)` for a
        // response that reported no usage at all (this number
        // feeds billing, and a wrong zero is worse than an honest "unknown").
        // The card is evaluated only after the terminal usage extractor has
        // seen the complete response. In particular, an SSE stream's partial
        // chunks cannot create a provisional price that later changes.
        let sent_model = stream_info
            .selected_model
            .clone()
            .or_else(|| stream_info.routing_model().map(str::to_owned));
        let priced = usage.as_ref().and_then(|usage| {
            self.price(
                stream_info.upstream_cluster.as_deref()?,
                sent_model.as_deref()?,
                served_model.as_deref(),
                usage,
            )
        });
        // An earlier attempt that sent the provider the whole request and got
        // no response is charged on top of this one, each at its own
        // provider's policy and rate card (ADR-0009 addendum "Unanswered attempts").
        let earlier = self.unanswered_charges(&stream_info);
        if earlier.is_empty() {
            stream_info.llm.price_basis = priced.as_ref().map(|(priced, _)| priced.basis);
            stream_info.llm.list_cost = priced.map(|(_, cost)| cost);
            stream_info.llm.usage = usage;
            stream_info.llm.completeness = Some(completeness);
            stream_info.llm.input_estimated = estimated.input;
            stream_info.llm.output_estimated = estimated.output;
        } else if let (Some(usage), Some(cluster)) = (usage, stream_info.upstream_cluster.clone()) {
            let own = AttemptCharge {
                cluster,
                model: sent_model,
                served_model: served_model.clone(),
                usage,
                input_estimated: estimated.input,
                output_estimated: estimated.output,
                list_cost: priced.as_ref().map(|(_, cost)| cost.clone()),
                attempt_index: stream_info
                    .selected_attempt
                    .as_ref()
                    .map(|attempt| attempt.borrow().attempt_index),
            };
            let basis = priced.map(|(priced, _)| priced.basis);
            let mut charges = earlier;
            charges.push(own);
            write_charges(&mut stream_info, charges, basis);
            // The cut-stream path counted it already.
            if completeness != UsageCompleteness::Partial {
                self.stats.partial.incr();
                self.stats.estimated.incr();
            }
        } else {
            // The answering attempt reported nothing; the earlier attempts
            // are what this request is charged.
            write_charges(&mut stream_info, earlier, Some(PriceBasis::Tokens));
            if completeness != UsageCompleteness::Partial {
                self.stats.partial.incr();
                self.stats.estimated.incr();
            }
        }
        stream_info.llm.served_model = served_model;
        // Evidence only. Nothing below reads a field of the provider's usage
        // object; the rate card is the only source of cost.
        if upstream.id_oversized {
            self.stats.upstream_id_oversized.incr();
        }
        if upstream.usage_oversized {
            self.stats.upstream_usage_oversized.incr();
        }
        if let Some(attempt) = &stream_info.selected_attempt {
            let mut attempt = attempt.borrow_mut();
            attempt.upstream_response_id = upstream.response_id.clone();
            attempt.upstream_usage = upstream.usage_json.clone();
        }
        stream_info.llm.upstream_response_id = upstream.response_id;
        stream_info.llm.upstream_usage = upstream.usage_json;
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
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        self.endpoint = cb.stream_info().llm.endpoint;
        self.request_dialect = dialect_for_request(self.endpoint);
        if self.endpoint == Endpoint::Realtime {
            // `permessage-deflate` would compress the event frames this filter
            // reads for usage. Without the client's offer the server cannot
            // negotiate it (RFC 7692 section 5), so the frames stay readable.
            headers.headers.remove("sec-websocket-extensions");
            self.request_is_connect = headers.method == http::Method::CONNECT;
        }
        FilterHeadersStatus::Continue
    }

    fn encode_headers(
        &mut self,
        cb: &mut dyn EncoderCallbacks,
        headers: &mut ResponseHeaders,
        end_stream: bool,
    ) -> FilterHeadersStatus {
        self.headers_at = Some(Instant::now());
        self.response_ok = headers.status.is_success();
        // The accept status of a realtime session: h1 `101`, or `200` to an
        // h2 extended CONNECT (RFC 8441). Its body is the session's frames.
        let realtime_accepted = self.endpoint == Endpoint::Realtime
            && (headers.status == http::StatusCode::SWITCHING_PROTOCOLS
                || (self.request_is_connect && headers.status == http::StatusCode::OK));
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
        self.mode = if realtime_accepted {
            self.response_ok = true;
            BodyMode::Realtime(RealtimeScanner::default())
        } else {
            classify_body(&headers.headers, self.parse_dialect(), self.endpoint)
        };
        if matches!(
            self.endpoint,
            Endpoint::ImageGeneration | Endpoint::ImageEdit | Endpoint::Speech
        ) {
            let info = cb.stream_info();
            self.request_size = info.request_facts.size.clone();
            self.request_quality = info.request_facts.quality.clone();
            self.request_input_characters = info.request_facts.input_characters;
        }

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
            // Past the cap `JsonBody` keeps only a tail window, never a
            // truncated prefix: a partial parse could silently produce a
            // wrong (not just missing) token count, and this number feeds
            // billing. The tail is read only for a whole `usage` object.
            BodyMode::Json(body) => body.push(data),
            BodyMode::MediaJson(scanner) => scanner.push(data),
            BodyMode::MediaSse(scanner) => scanner.push(data),
            BodyMode::Realtime(scanner) => scanner.push(data),
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

    /// A response that started but never reached its terminal frame (the
    /// client disconnected, or the upstream died) is recorded here as a
    /// partial: whatever the provider had reported, plus estimates for what it
    /// had not (see [`BYTES_PER_TOKEN_ESTIMATE`]), priced like a complete one
    /// so an aborted request still costs what it used. `finalized` makes this
    /// a no-op after a clean end, so nothing is written twice.
    ///
    /// This control fails toward charging, not toward free: the estimate is
    /// loud (`llmproxy_usage_partial_total`, `llmproxy_usage_estimated_total`,
    /// `completeness: partial`, `cost.kind: estimate`).
    fn on_stream_complete(&mut self, cb: &mut dyn EncoderCallbacks) {
        if self.finalized {
            return;
        }
        if self.headers_at.is_none() || !self.response_ok {
            // No successful response was metered: the client left or a timer
            // cut the wait before response headers, or an error answered.
            self.charge_unanswered(cb);
            return;
        }
        // An unread body is not usage, except that a cut speech response
        // still consumed its request's characters.
        if matches!(self.mode, BodyMode::Inert) && self.endpoint != Endpoint::Speech {
            return;
        }
        let (dialled, request_bytes) = {
            let info = cb.stream_info();
            (info.upstream_cluster.is_some(), info.bytes_received)
        };
        if !dialled {
            return;
        }
        self.finalized = true;
        self.report_realtime_missing(cb);
        let (usage, estimated) = self.estimate_partial_usage(request_bytes);
        self.stats.partial.incr();
        if estimated.input || estimated.output {
            self.stats.estimated.incr();
        }
        self.write_stats(cb, usage, UsageCompleteness::Partial, estimated);
    }
}

#[cfg(test)]
mod rate_card_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    use bytes::Bytes;
    use http::{HeaderValue, StatusCode};
    use std::sync::Arc;

    use proxy_http::filter::{BufferedBody, PerRouteConfig};
    use proxy_http::stream_info::{RequestFacts, StreamInfo};

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

    impl DecoderCallbacks for TestCallbacks {
        fn send_local_reply(
            &mut self,
            _code: StatusCode,
            _body: &str,
            _modify_headers: Option<proxy_http::filter::HeaderMutationFn>,
            _details: &str,
        ) {
            unimplemented!("usage filter must not send local replies")
        }
        fn continue_decoding(&mut self) {
            unimplemented!()
        }
        fn add_decoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!()
        }
        fn inject_decoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!()
        }
        fn decoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!()
        }
        fn modify_decoding_buffer(&mut self, _f: &mut dyn FnMut(&mut BytesMut)) {
            unimplemented!()
        }
        fn route(&mut self) -> Option<Arc<proxy_config::ir::RouteEntry>> {
            None
        }
        fn clear_route_cache(&mut self) {
            unimplemented!()
        }
        fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
            None
        }
        fn stream_info(&mut self) -> std::cell::RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
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
            request_dialect: None,
            endpoint: Endpoint::Unmetered,
            request_size: None,
            request_quality: None,
            request_input_characters: None,
            stats: Arc::new(UsageStats::default()),
            pricing: None,
            mode: BodyMode::Inert,
            headers_at: None,
            last_chunk_at: None,
            time_to_first_byte: None,
            time_to_first_body_byte: None,
            max_inter_chunk: None,
            response_chunks: 0,
            response_ok: false,
            request_is_connect: false,
            finalized: false,
        }
    }

    fn priced_filter() -> UsageFilterInstance {
        priced_filter_with(&[("gpt-5", 10, 100)])
    }

    /// A card pricing each `(model, input, output)` nanodollars per token for
    /// provider type `openai`.
    fn priced_filter_with(models: &[(&str, u64, u64)]) -> UsageFilterInstance {
        let list = PriceList::new(
            Some("2026-09"),
            std::time::SystemTime::UNIX_EPOCH,
            models
                .iter()
                .map(|&(model, input, output)| PriceEntry {
                    cached_input_unpriced: false,
                    cache_write_unpriced: false,
                    provider_type: "openai".into(),
                    model: model.into(),
                    tier_basis: TierBasis::InputTokens,
                    tier_mode: TierMode::WholeRequest,
                    tiers: vec![Tier {
                        up_to: None,
                        input_nanodollars_per_token: input,
                        cached_input_nanodollars_per_token: 1,
                        cache_write_nanodollars_per_token: 20,
                        output_nanodollars_per_token: output,
                        image_input_nanodollars_per_token: None,
                        image_output_nanodollars_per_token: None,
                        audio_input_nanodollars_per_token: None,
                        audio_output_nanodollars_per_token: None,
                    }],
                    basis: PriceBasis::Tokens,
                    image_prices: Vec::new(),
                    nanodollars_per_character: None,
                    nanodollars_per_second: None,
                })
                .collect(),
            BTreeMap::from([("provider:openai".to_string(), "openai".to_string())]),
        );
        UsageFilterInstance {
            pricing: Some(PricingContext {
                list: Arc::new(list),
                catalog: None,
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

        let usage = cb
            .llm()
            .usage
            .and_then(|u| u.tokens)
            .expect("usage should be found");
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

        let usage = cb
            .llm()
            .usage
            .and_then(|u| u.tokens)
            .expect("usage should be found");
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

        let usage = cb
            .llm()
            .usage
            .and_then(|u| u.tokens)
            .expect("usage should be found");
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

        let usage = cb
            .llm()
            .usage
            .and_then(|u| u.tokens)
            .expect("usage should be found");
        assert_eq!(usage.input_tokens, 1);
        assert_eq!(usage.output_tokens, 2);
    }

    /// A JSON body of `MAX + 1 MiB` bytes: `usage_at_start` puts the usage
    /// object first (beyond the tail window), otherwise last.
    fn oversized_json_chunks(usage_at_start: bool) -> Vec<Bytes> {
        let usage = r#""usage":{"prompt_tokens":11,"completion_tokens":13}"#;
        let filler = format!(r#""pad":"{}""#, "x".repeat(2 << 20));
        let body = if usage_at_start {
            format!("{{{usage},{filler}}}")
        } else {
            format!("{{{filler},{usage}}}")
        };
        body.into_bytes()
            .chunks(64 << 10)
            .map(Bytes::copy_from_slice)
            .collect()
    }

    fn run_json(filter: &mut UsageFilterInstance, cb: &mut TestCallbacks, chunks: Vec<Bytes>) {
        let mut headers = response_headers("application/json");
        filter.encode_headers(cb, &mut headers, false);
        let last = chunks.len() - 1;
        for (i, mut chunk) in chunks.into_iter().enumerate() {
            filter.encode_data(cb, &mut chunk, i == last);
        }
    }

    #[test]
    fn oversized_json_body_with_usage_in_the_tail_is_still_metered() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();
        run_json(&mut filter, &mut cb, oversized_json_chunks(false));

        let usage = cb
            .llm()
            .usage
            .and_then(|u| u.tokens)
            .expect("usage recovered from the tail");
        assert_eq!((usage.input_tokens, usage.output_tokens), (11, 13));
        assert_eq!(filter.stats.oversized_unrecoverable(), 0);
        if let BodyMode::Json(body) = &filter.mode {
            assert!(body.overflowed);
            assert!(
                body.buf.len() <= JSON_TAIL_WINDOW_BYTES,
                "tail stays bounded"
            );
        } else {
            panic!("expected JSON mode");
        }
    }

    #[test]
    fn oversized_json_body_with_usage_before_the_tail_yields_none_and_is_counted() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();
        run_json(&mut filter, &mut cb, oversized_json_chunks(true));

        // Never a partial count: no usage and no cost, but the miss is counted.
        assert_eq!(cb.llm().usage, None);
        assert_eq!(filter.stats.oversized_unrecoverable(), 1);
    }

    #[test]
    fn oversized_json_body_of_only_whitespace_then_usage_is_metered() {
        // The former behaviour dropped everything after the cap, including a
        // well-formed trailing usage object.
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();
        let mut headers = response_headers("application/json");
        filter.encode_headers(&mut cb, &mut headers, false);
        let mut oversized = Bytes::from(vec![b' '; MAX_JSON_BODY_BYTES + 1]);
        filter.encode_data(&mut cb, &mut oversized, false);
        let mut tail =
            Bytes::from_static(br#"{"usage":{"prompt_tokens":1,"completion_tokens":1}}"#);
        filter.encode_data(&mut cb, &mut tail, true);
        assert_eq!(
            cb.llm()
                .usage
                .and_then(|u| u.tokens)
                .map(|u| u.input_tokens),
            Some(1)
        );
    }

    #[test]
    fn oversized_warning_is_rate_limited_but_every_miss_is_counted() {
        let stats = UsageStats::default();
        stats.note_oversized_unrecoverable(Some("c"));
        let first = *stats.last_oversized_warning.lock().unwrap();
        stats.note_oversized_unrecoverable(Some("c"));
        assert_eq!(stats.oversized_unrecoverable(), 2);
        assert_eq!(
            *stats.last_oversized_warning.lock().unwrap(),
            first,
            "second miss inside the interval must not re-warn"
        );
    }

    // --- request-path dialect selection ------------------------------------

    fn request(method: Method, uri: &str) -> RequestHeaders {
        RequestHeaders {
            method,
            uri: uri.parse().unwrap(),
            headers: HeaderMap::new(),
        }
    }

    /// Drive one request/response through an OpenAI-dialect cluster filter.
    fn run_on_openai_cluster(
        method: Method,
        uri: &str,
        content_type: &str,
        body: &'static [u8],
    ) -> proxy_http::LlmStats {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();
        cb.stream_info.borrow_mut().upstream_usage_dialect =
            Some(proxy_config::ir::UsageDialect::OpenAi);
        decode(&mut filter, &mut cb, &mut request(method, uri), true);
        filter.encode_headers(&mut cb, &mut response_headers(content_type), false);
        filter.encode_data(&mut cb, &mut Bytes::from_static(body), true);
        cb.llm()
    }

    #[test]
    fn post_responses_on_an_openai_cluster_reads_responses_usage_json() {
        let llm = run_on_openai_cluster(
            Method::POST,
            "/v1/responses?x=1",
            "application/json",
            br#"{"usage":{"input_tokens":20,"output_tokens":4,"input_tokens_details":{"cached_tokens":5}}}"#,
        );
        let usage = llm.usage.and_then(|u| u.tokens).expect("responses usage");
        assert_eq!(
            (usage.input_tokens, usage.cached_tokens, usage.output_tokens),
            (15, 5, 4)
        );
        assert_eq!(llm.system, Some(GenAiSystem::OpenAi));
    }

    #[test]
    fn post_responses_on_an_openai_cluster_reads_the_completed_sse_frame() {
        let llm = run_on_openai_cluster(
            Method::POST,
            "/v1/responses",
            "text/event-stream",
            b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":8,\"output_tokens\":3}}}\n\n",
        );
        let usage = llm
            .usage
            .and_then(|u| u.tokens)
            .expect("responses sse usage");
        assert_eq!((usage.input_tokens, usage.output_tokens), (8, 3));
    }

    #[test]
    fn post_messages_on_an_openai_cluster_reads_anthropic_usage() {
        let llm = run_on_openai_cluster(
            Method::POST,
            "/v1/messages",
            "application/json",
            br#"{"usage":{"input_tokens":6,"output_tokens":2,"cache_read_input_tokens":4}}"#,
        );
        let usage = llm.usage.and_then(|u| u.tokens).expect("anthropic usage");
        assert_eq!(
            (usage.input_tokens, usage.cached_tokens, usage.output_tokens),
            (6, 4, 2)
        );
        // The provider label follows the cluster, not the path.
        assert_eq!(llm.system, Some(GenAiSystem::OpenAi));
    }

    /// An embeddings response carries `prompt_tokens` and `total_tokens` and
    /// no completion count: input is metered, output is zero.
    #[test]
    fn post_embeddings_on_an_openai_cluster_meters_input_and_no_output() {
        let llm = run_on_openai_cluster(
            Method::POST,
            "/v1/embeddings",
            "application/json",
            br#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,-0.2]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":12,"total_tokens":12}}"#,
        );
        let usage = llm.usage.and_then(|u| u.tokens).expect("embeddings usage");
        assert_eq!(
            (usage.input_tokens, usage.cached_tokens, usage.output_tokens),
            (12, 0, 0)
        );
        assert_eq!(llm.system, Some(GenAiSystem::OpenAi));
    }

    /// The parser follows the path: an Anthropic-dialect cluster serving
    /// `/v1/embeddings` still returns the OpenAI shape, which the Anthropic
    /// parser would not meter.
    #[test]
    fn post_embeddings_on_an_anthropic_cluster_reads_openai_usage() {
        let mut filter = filter_for(Dialect::Anthropic);
        let mut cb = TestCallbacks::new();
        decode(
            &mut filter,
            &mut cb,
            &mut request(Method::POST, "/v1/embeddings"),
            true,
        );
        filter.encode_headers(&mut cb, &mut response_headers("application/json"), false);
        filter.encode_data(
            &mut cb,
            &mut Bytes::from_static(br#"{"data":[],"usage":{"prompt_tokens":7,"total_tokens":7}}"#),
            true,
        );
        let usage = cb
            .llm()
            .usage
            .and_then(|u| u.tokens)
            .expect("embeddings usage");
        assert_eq!((usage.input_tokens, usage.output_tokens), (7, 0));
        // The provider label still follows the cluster.
        assert_eq!(cb.llm().system, Some(GenAiSystem::Anthropic));
    }

    /// A batch of embeddings is a large body with `usage` after the vectors.
    /// Past the whole-body bound only the tail is kept, and the usage object
    /// is still read from it.
    #[test]
    fn embeddings_usage_after_a_body_larger_than_the_json_bound_is_read_from_the_tail() {
        let mut filter = filter_for(Dialect::OpenAi);
        let mut cb = TestCallbacks::new();
        decode(
            &mut filter,
            &mut cb,
            &mut request(Method::POST, "/v1/embeddings"),
            true,
        );
        filter.encode_headers(&mut cb, &mut response_headers("application/json"), false);
        let vector = format!("[{}0.5]", "0.125,".repeat(1024));
        let mut sent = 0;
        let mut head = br#"{"object":"list","data":["#.to_vec();
        let mut index = 0;
        while sent + head.len() <= MAX_JSON_BODY_BYTES {
            if index > 0 {
                head.push(b',');
            }
            head.extend_from_slice(
                format!(r#"{{"object":"embedding","index":{index},"embedding":{vector}}}"#)
                    .as_bytes(),
            );
            index += 1;
            if head.len() > 64 << 10 {
                sent += head.len();
                filter.encode_data(&mut cb, &mut Bytes::from(std::mem::take(&mut head)), false);
            }
        }
        head.extend_from_slice(
            br#"],"model":"text-embedding-3-small","usage":{"prompt_tokens":4096,"total_tokens":4096}}"#,
        );
        sent += head.len();
        assert!(sent > MAX_JSON_BODY_BYTES, "the body must pass the bound");
        filter.encode_data(&mut cb, &mut Bytes::from(head), true);
        let usage = cb
            .llm()
            .usage
            .and_then(|u| u.tokens)
            .expect("usage read from the tail window");
        assert_eq!((usage.input_tokens, usage.output_tokens), (4096, 0));
    }

    #[test]
    fn get_of_a_stored_response_keeps_the_cluster_dialect_and_is_not_metered() {
        let llm = run_on_openai_cluster(
            Method::GET,
            "/v1/responses/resp_abc",
            "application/json",
            br#"{"usage":{"input_tokens":20,"output_tokens":4}}"#,
        );
        assert_eq!(llm.usage, None);
        let get_collection = run_on_openai_cluster(
            Method::GET,
            "/v1/responses",
            "application/json",
            br#"{"usage":{"input_tokens":20,"output_tokens":4}}"#,
        );
        assert_eq!(get_collection.usage, None);
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

    /// Run one priced response (2 input, 3 output tokens) for a request that
    /// asked for `gpt-5`, and return the final stats plus the repriced count.
    /// `sse` selects the streaming scanner instead of the JSON body path.
    fn run_served_model_case(body: &[u8], sse: bool) -> (proxy_http::LlmStats, u64) {
        let mut filter = priced_filter_with(&[("gpt-5", 10, 100), ("gpt-5-mini", 1, 10)]);
        let mut cb = TestCallbacks::new();
        {
            let mut info = cb.stream_info.borrow_mut();
            info.upstream_cluster = Some("provider:openai".into());
            info.requested_model = Some("gpt-5".into());
            info.metadata_enabled = true;
            let attempt = info.begin_attempt("provider:openai", "host", None).unwrap();
            info.selected_attempt = Some(attempt);
        }
        let content_type = if sse {
            "text/event-stream"
        } else {
            "application/json"
        };
        filter.encode_headers(&mut cb, &mut response_headers(content_type), false);
        filter.encode_data(&mut cb, &mut Bytes::copy_from_slice(body), true);
        let attempt_model = cb
            .stream_info
            .borrow()
            .selected_attempt
            .as_ref()
            .and_then(|a| a.borrow().served_model.clone());
        assert_eq!(
            cb.llm().served_model,
            attempt_model,
            "stats and attempt agree"
        );
        (cb.llm(), filter.stats.served_model_repriced())
    }

    #[test]
    fn served_model_with_a_card_entry_is_priced_at_that_entry_and_counted() {
        for (body, sse) in [
            (
                &br#"{"model":"gpt-5-mini","usage":{"prompt_tokens":2,"completion_tokens":3}}"#[..],
                false,
            ),
            (
                &b"data: {\"model\":\"gpt-5-mini\",\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":3}}\n\n"[..],
                true,
            ),
        ] {
            let (llm, repriced) = run_served_model_case(body, sse);
            // gpt-5-mini: 2 * 1 + 3 * 10 = 32 (gpt-5 would be 320).
            assert_eq!(llm.list_cost.expect("priced").nanodollars, 32, "sse={sse}");
            assert_eq!(llm.served_model.as_deref(), Some("gpt-5-mini"));
            assert_eq!(repriced, 1, "sse={sse}");
        }
    }

    #[test]
    fn served_model_without_a_card_entry_keeps_the_requested_price_and_is_not_counted() {
        // A dated snapshot, and the requested model echoed back: both price at
        // the requested model, neither counts, and the served name is kept.
        for served in ["gpt-5-2025-08-07", "gpt-5"] {
            let body = format!(
                r#"{{"model":"{served}","usage":{{"prompt_tokens":2,"completion_tokens":3}}}}"#
            );
            let (llm, repriced) = run_served_model_case(body.as_bytes(), false);
            assert_eq!(llm.list_cost.expect("priced").nanodollars, 320, "{served}");
            assert_eq!(llm.served_model.as_deref(), Some(served));
            assert_eq!(repriced, 0, "{served}");
        }
    }

    #[test]
    fn repriced_counter_is_exported_on_the_prometheus_surface() {
        let control = proxy_observability::stats::StatsControl::new(1);
        let registry = control.registry();
        let stats = UsageStats::new(Some(registry.clone()), "ingress");
        stats.note_served_model_repriced();
        let rendered = proxy_observability::stats::prometheus_render::render(&registry);
        let line = rendered
            .lines()
            .find(|l| l.starts_with("envoy_llmproxy_usage_served_model_repriced_total{"))
            .unwrap_or_else(|| panic!("counter missing from export:\n{rendered}"));
        assert!(line.contains(r#"scope="ingress""#), "{line}");
        assert!(line.ends_with(" 1"), "{line}");
    }

    /// The selected attempt's `(upstream_response_id, upstream_usage)`.
    type AttemptEvidence = (Option<String>, Option<String>);

    /// Run one response through the filter with a selected attempt present,
    /// returning the final stats, the attempt, and the filter's counters.
    fn run_upstream_case(
        dialect: Dialect,
        content_type: &str,
        body: &[u8],
    ) -> (
        proxy_http::LlmStats,
        Option<AttemptEvidence>,
        Arc<UsageStats>,
    ) {
        let mut filter = filter_for(dialect);
        let stats = Arc::clone(&filter.stats);
        let mut cb = TestCallbacks::new();
        {
            let mut info = cb.stream_info.borrow_mut();
            info.upstream_cluster = Some("provider:openai".into());
            info.metadata_enabled = true;
            let attempt = info.begin_attempt("provider:openai", "host", None).unwrap();
            info.selected_attempt = Some(attempt);
        }
        filter.encode_headers(&mut cb, &mut response_headers(content_type), false);
        filter.encode_data(&mut cb, &mut Bytes::copy_from_slice(body), true);
        let attempt = cb.stream_info.borrow().selected_attempt.as_ref().map(|a| {
            let a = a.borrow();
            (a.upstream_response_id.clone(), a.upstream_usage.clone())
        });
        (cb.llm(), attempt, stats)
    }

    #[test]
    fn upstream_id_and_raw_usage_reach_stats_and_the_selected_attempt_for_every_dialect() {
        let cases: [(Dialect, &str, &[u8], &str, &str); 4] = [
            (
                Dialect::OpenAi,
                "application/json",
                br#"{"id":"chatcmpl-1","usage":{"prompt_tokens":2,"completion_tokens":3,"cost":0.5}}"#,
                "chatcmpl-1",
                r#"{"prompt_tokens":2,"completion_tokens":3,"cost":0.5}"#,
            ),
            (
                Dialect::OpenAi,
                "text/event-stream",
                b"data: {\"id\":\"chatcmpl-2\",\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":3}}\n\n",
                "chatcmpl-2",
                r#"{"prompt_tokens":2,"completion_tokens":3}"#,
            ),
            (
                Dialect::Anthropic,
                "text/event-stream",
                b"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":9,\"output_tokens\":1}}}\n\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":4}}\n\n",
                "msg_1",
                r#"{"output_tokens":4}"#,
            ),
            (
                Dialect::OpenAiResponses,
                "text/event-stream",
                b"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"usage\":{\"input_tokens\":4,\"output_tokens\":2}}}\n\n",
                "resp_1",
                r#"{"input_tokens":4,"output_tokens":2}"#,
            ),
        ];
        for (dialect, content_type, body, id, usage) in cases {
            let (llm, attempt, _) = run_upstream_case(dialect, content_type, body);
            assert_eq!(llm.upstream_response_id.as_deref(), Some(id), "{id}");
            assert_eq!(llm.upstream_usage.as_deref(), Some(usage), "{id}");
            assert_eq!(
                attempt,
                Some((Some(id.to_owned()), Some(usage.to_owned()))),
                "{id}"
            );
        }
    }

    /// The provider's own `cost` is evidence, never billing: rate-card cost is
    /// what the stats carry, whatever the provider said.
    #[test]
    fn provider_reported_cost_never_becomes_the_recorded_cost() {
        let mut filter = priced_filter();
        let mut cb = TestCallbacks::new();
        {
            let mut info = cb.stream_info.borrow_mut();
            info.upstream_cluster = Some("provider:openai".into());
            info.requested_model = Some("gpt-5".into());
        }
        filter.encode_headers(&mut cb, &mut response_headers("application/json"), false);
        let body = br#"{"usage":{"prompt_tokens":2,"completion_tokens":3,"cost":999.0}}"#;
        filter.encode_data(&mut cb, &mut Bytes::from_static(body), true);
        let llm = cb.llm();
        assert_eq!(llm.list_cost.expect("priced").nanodollars, 320);
        assert!(llm.upstream_usage.unwrap().contains("999.0"));
    }

    #[test]
    fn oversized_upstream_fields_are_not_stored_and_are_counted() {
        let pad = "p".repeat(crate::usage::MAX_UPSTREAM_USAGE_BYTES);
        let id = "i".repeat(crate::usage::MAX_UPSTREAM_ID_BYTES + 1);
        let body = format!(
            r#"{{"id":"{id}","usage":{{"prompt_tokens":2,"completion_tokens":3,"k":"{pad}"}}}}"#
        );
        let (llm, attempt, stats) =
            run_upstream_case(Dialect::OpenAi, "application/json", body.as_bytes());
        assert_eq!(llm.upstream_response_id, None);
        assert_eq!(llm.upstream_usage, None);
        assert_eq!(attempt, Some((None, None)));
        assert_eq!(stats.upstream_id_oversized(), 1);
        assert_eq!(stats.upstream_usage_oversized(), 1);
        // Token counts are unaffected by dropping the raw text.
        assert_eq!(llm.usage.and_then(|u| u.tokens).unwrap().input_tokens, 2);
    }

    #[test]
    fn oversized_counters_are_exported_on_the_prometheus_surface() {
        let control = proxy_observability::stats::StatsControl::new(1);
        let registry = control.registry();
        let stats = UsageStats::new(Some(registry.clone()), "ingress");
        stats.upstream_usage_oversized.incr();
        stats.upstream_id_oversized.incr();
        let rendered = proxy_observability::stats::prometheus_render::render(&registry);
        for name in [
            "envoy_llmproxy_usage_upstream_usage_oversized_total{",
            "envoy_llmproxy_usage_upstream_id_oversized_total{",
        ] {
            let line = rendered
                .lines()
                .find(|l| l.starts_with(name))
                .unwrap_or_else(|| panic!("{name} missing from export:\n{rendered}"));
            assert!(
                line.contains(r#"scope="ingress""#) && line.ends_with(" 1"),
                "{line}"
            );
        }
    }

    // ---- partial (cut-off) streams ------------------------------------

    /// Feed `frames` of an SSE response to `filter` without ending it, then
    /// complete the stream the way the filter manager does for an abandoned
    /// one. `request_bytes` stands in for the downstream request body size.
    fn abort_after(
        filter: &mut UsageFilterInstance,
        request_bytes: u64,
        frames: &[&str],
    ) -> proxy_http::LlmStats {
        let mut cb = TestCallbacks::new();
        {
            let mut info = cb.stream_info.borrow_mut();
            info.upstream_cluster = Some("provider:openai".into());
            info.requested_model = Some("gpt-5".into());
            info.bytes_received = request_bytes;
        }
        filter.encode_headers(&mut cb, &mut response_headers("text/event-stream"), false);
        for frame in frames {
            filter.encode_data(
                &mut cb,
                &mut Bytes::copy_from_slice(frame.as_bytes()),
                false,
            );
        }
        filter.on_stream_complete(&mut cb);
        cb.llm()
    }

    const CHAT_ID: &str =
        "data: {\"id\":\"chatcmpl-9\",\"choices\":[{\"delta\":{\"content\":\"abcdefgh\"}}]}\n\n";
    const CHAT_MORE: &str =
        "data: {\"id\":\"chatcmpl-9\",\"choices\":[{\"delta\":{\"content\":\"ijkl\"}}]}\n\n";

    #[test]
    fn a_cut_off_stream_is_partial_estimated_priced_and_counted() {
        let mut filter = priced_filter();
        let stats = Arc::clone(&filter.stats);
        let llm = abort_after(&mut filter, 40, &[CHAT_ID, CHAT_MORE]);
        assert_eq!(llm.completeness, Some(UsageCompleteness::Partial));
        // 40 request bytes -> 10 input tokens; 12 streamed bytes -> 3 output.
        let usage = llm.usage.and_then(|u| u.tokens).expect("estimated usage");
        assert_eq!((usage.input_tokens, usage.output_tokens), (10, 3));
        assert!(llm.input_estimated && llm.output_estimated);
        // Same card path as a complete record: 10 * 10 + 3 * 100.
        assert_eq!(llm.list_cost.expect("priced").nanodollars, 400);
        assert_eq!(llm.upstream_response_id.as_deref(), Some("chatcmpl-9"));
        assert_eq!((stats.partial(), stats.estimated()), (1, 1));
    }

    #[test]
    fn exact_input_from_anthropic_message_start_beats_the_body_estimate() {
        let mut filter = filter_for(Dialect::Anthropic);
        let stats = Arc::clone(&filter.stats);
        let start = "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\n";
        let delta = format!(
            "data: {{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"text_delta\",\"text\":\"{}\"}}}}\n\n",
            "x".repeat(40)
        );
        let llm = abort_after(&mut filter, 4000, &[start, &delta]);
        let usage = llm.usage.and_then(|u| u.tokens).expect("usage");
        assert_eq!(usage.input_tokens, 25, "exact, not 4000 / 4");
        assert_eq!(usage.output_tokens, 10, "the larger of 1 and 40 / 4");
        assert!(!llm.input_estimated && llm.output_estimated);
        assert_eq!(llm.upstream_response_id.as_deref(), Some("msg_1"));
        assert_eq!(stats.partial(), 1);
    }

    #[test]
    fn a_partial_with_every_figure_from_the_provider_is_not_marked_estimated() {
        let mut filter = filter_for(Dialect::OpenAi);
        let stats = Arc::clone(&filter.stats);
        let usage_frame = "data: {\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":50}}\n\n";
        let llm = abort_after(&mut filter, 4000, &[CHAT_ID, usage_frame]);
        let usage = llm.usage.and_then(|u| u.tokens).unwrap();
        assert_eq!((usage.input_tokens, usage.output_tokens), (5, 50));
        assert!(!llm.input_estimated && !llm.output_estimated);
        assert_eq!(llm.completeness, Some(UsageCompleteness::Partial));
        assert_eq!((stats.partial(), stats.estimated()), (1, 0));
    }

    #[test]
    fn a_stream_that_ended_cleanly_is_complete_and_not_rewritten_on_completion() {
        let mut filter = priced_filter();
        let stats = Arc::clone(&filter.stats);
        let mut cb = TestCallbacks::new();
        {
            let mut info = cb.stream_info.borrow_mut();
            info.upstream_cluster = Some("provider:openai".into());
            info.requested_model = Some("gpt-5".into());
            info.bytes_received = 4000;
        }
        filter.encode_headers(&mut cb, &mut response_headers("text/event-stream"), false);
        let last = "data: {\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":3}}\n\n";
        filter.encode_data(
            &mut cb,
            &mut Bytes::copy_from_slice(CHAT_ID.as_bytes()),
            false,
        );
        filter.encode_data(&mut cb, &mut Bytes::copy_from_slice(last.as_bytes()), true);
        let before = cb.llm();
        filter.on_stream_complete(&mut cb);
        assert_eq!(cb.llm(), before);
        assert_eq!(before.completeness, Some(UsageCompleteness::Complete));
        assert_eq!(before.list_cost.unwrap().nanodollars, 320);
        assert!(!before.input_estimated && !before.output_estimated);
        assert_eq!((stats.partial(), stats.estimated()), (0, 0));
    }

    #[test]
    fn error_bodies_and_unrecognised_content_are_never_recorded_as_partial() {
        // A non-2xx response that is cut off carries no usage to estimate.
        let mut filter = priced_filter();
        let mut cb = TestCallbacks::new();
        cb.stream_info.borrow_mut().upstream_cluster = Some("provider:openai".into());
        let mut headers = response_headers("text/event-stream");
        headers.status = StatusCode::BAD_GATEWAY;
        filter.encode_headers(&mut cb, &mut headers, false);
        filter.on_stream_complete(&mut cb);
        assert_eq!(cb.llm().completeness, None);
        // So is a body the filter does not read.
        let mut filter = priced_filter();
        let mut cb = TestCallbacks::new();
        cb.stream_info.borrow_mut().upstream_cluster = Some("provider:openai".into());
        filter.encode_headers(&mut cb, &mut response_headers("text/plain"), false);
        filter.on_stream_complete(&mut cb);
        assert_eq!(cb.llm().completeness, None);
        // And a response that never came from an upstream (a local reply).
        let mut filter = priced_filter();
        let mut cb = TestCallbacks::new();
        filter.encode_headers(&mut cb, &mut response_headers("application/json"), false);
        filter.on_stream_complete(&mut cb);
        assert_eq!(cb.llm().completeness, None);
        assert_eq!(filter.stats.partial(), 0);
    }

    #[test]
    fn partial_counters_are_exported_on_the_prometheus_surface() {
        let control = proxy_observability::stats::StatsControl::new(1);
        let registry = control.registry();
        let stats = UsageStats::new(Some(registry.clone()), "ingress");
        stats.partial.incr();
        stats.estimated.incr();
        let rendered = proxy_observability::stats::prometheus_render::render(&registry);
        for name in [
            "envoy_llmproxy_usage_partial_total{",
            "envoy_llmproxy_usage_estimated_total{",
        ] {
            let line = rendered
                .lines()
                .find(|l| l.starts_with(name))
                .unwrap_or_else(|| panic!("{name} missing from export:\n{rendered}"));
            assert!(
                line.contains(r#"scope="ingress""#) && line.ends_with(" 1"),
                "{line}"
            );
        }
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

        let usage = cb
            .llm()
            .usage
            .and_then(|u| u.tokens)
            .expect("usage should be found");
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

        let usage = cb
            .llm()
            .usage
            .and_then(|u| u.tokens)
            .expect("usage should be found");
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
    fn gateway_cache_write_tokens_are_charged_the_cache_write_rate() {
        let mut filter = priced_filter();
        let mut cb = TestCallbacks::new();
        {
            let mut info = cb.stream_info.borrow_mut();
            info.upstream_cluster = Some("provider:openai".into());
            info.requested_model = Some("gpt-5".into());
        }
        filter.encode_headers(&mut cb, &mut response_headers("application/json"), false);
        let mut body = Bytes::from_static(
            br#"{"usage":{"prompt_tokens":100,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":10,"cache_write_tokens":30}}}"#,
        );
        filter.encode_data(&mut cb, &mut body, true);
        // 60 input * 10 + 10 cached * 1 + 30 cache-write * 20 + 5 output * 100
        assert_eq!(cb.llm().list_cost.expect("priced").nanodollars, 1710);
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

    /// Built through the real factory with the registry seeded the way the
    /// listener seeds it, then read back from the rendered Prometheus text
    /// that `/stats/prometheus` serves.
    #[test]
    fn unmetered_oversized_body_is_exported_on_the_prometheus_surface() {
        let control = proxy_observability::stats::StatsControl::new(1);
        let ctx = FactoryContext {
            stat_prefix: "ingress".into(),
            ..Default::default()
        };
        let registry = control.registry();
        ctx.shared
            .get_or_try_init("", "", STATS_REGISTRY_KEY, || {
                Ok(registry.clone() as Arc<dyn std::any::Any + Send + Sync>)
            })
            .unwrap();
        let instance_factory = UsageFilterFactory
            .create(&usage_config("openai"), &ctx)
            .expect("valid config builds a factory");

        let mut filter = instance_factory.create_filter();
        let mut cb = TestCallbacks::new();
        run_json_boxed(&mut *filter, &mut cb, oversized_json_chunks(true));
        // A metered oversized response must not count.
        let mut metered = instance_factory.create_filter();
        run_json_boxed(
            &mut *metered,
            &mut TestCallbacks::new(),
            oversized_json_chunks(false),
        );

        let rendered = proxy_observability::stats::prometheus_render::render(&registry);
        let line = rendered
            .lines()
            .find(|l| l.starts_with("envoy_llmproxy_usage_oversized_body_unmetered_total{"))
            .unwrap_or_else(|| panic!("counter missing from export:\n{rendered}"));
        assert!(line.contains(r#"scope="ingress""#), "{line}");
        assert!(line.ends_with(" 1"), "{line}");
    }

    fn run_json_boxed(filter: &mut dyn HttpFilter, cb: &mut TestCallbacks, chunks: Vec<Bytes>) {
        filter.encode_headers(cb, &mut response_headers("application/json"), false);
        let last = chunks.len() - 1;
        for (i, mut chunk) in chunks.into_iter().enumerate() {
            filter.encode_data(cb, &mut chunk, i == last);
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

        let usage = cb
            .llm()
            .usage
            .and_then(|u| u.tokens)
            .expect("usage should be found");
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

        let usage = cb
            .llm()
            .usage
            .and_then(|u| u.tokens)
            .expect("usage should be found");
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

        let usage = cb
            .llm()
            .usage
            .and_then(|u| u.tokens)
            .expect("usage should be found");
        assert_eq!(usage.input_tokens, 7);
        assert_eq!(usage.output_tokens, 9);
    }

    /// The load-bearing property behind per-route dialect validation: an
    /// invalid per-route dialect must come back as `ConfigError::InvalidValue`,
    /// never `ConfigError::Unimplemented`.
    /// `filter_manager::resolve_per_filter_row` swallows exactly
    /// `Unimplemented` under `is_optional: true` (its default meaning "this
    /// filter has no per-route config at all"). If `parse_per_route`'s error
    /// variant here ever regressed to `Unimplemented`, a typo'd per-route
    /// dialect on an `is_optional: true` entry would be silently dropped
    /// instead of failing the build, and the route would go on to meter with
    /// the wrong (fallback) dialect -- exactly the silent field drop AGENTS.md
    /// invariant 1 forbids.
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
        assert_eq!(
            cb.llm()
                .usage
                .and_then(|u| u.tokens)
                .expect("legacy filter runs")
                .input_tokens,
            2
        );
    }

    #[test]
    fn live_rate_card_update_does_not_reprice_an_existing_request_snapshot() {
        let registry = PricingRegistry::new("chain");
        let first = registry
            .publish_json(
                r#"{
                  "price_list": {"version":"v1","effective_from":"2026-09-25T00:00:00Z",
                    "entries":[{"provider_type":"openai","model":"gpt-5","tier_mode":"whole_request",
                      "tiers":[{"up_to":null,"input_nanodollars_per_token":10,"cached_input_nanodollars_per_token":0,
                        "cache_write_nanodollars_per_token":0,"output_nanodollars_per_token":20}]}]},
                  "providers":{"provider:p1":"openai"}
                }"#,
            )
            .expect("first card validates")
            .rate_card_version;
        let in_flight = registry.snapshot().expect("first card snapshot");
        let second = registry
            .publish_json(
                r#"{
                  "price_list": {"version":"v2","effective_from":"2026-09-25T01:00:00Z",
                    "entries":[{"provider_type":"openai","model":"gpt-5","tier_mode":"whole_request",
                      "tiers":[{"up_to":null,"input_nanodollars_per_token":99,"cached_input_nanodollars_per_token":0,
                        "cache_write_nanodollars_per_token":0,"output_nanodollars_per_token":99}]}]},
                  "providers":{"provider:p1":"openai"}
                }"#,
            )
            .expect("second card validates")
            .rate_card_version;
        assert_ne!(first, second);
        assert_eq!(in_flight.list.version().as_str(), first);
        assert_eq!(registry.snapshot().unwrap().list.version().as_str(), second);
    }

    #[test]
    fn pricing_json_view_exposes_exact_active_rates_mappings_and_catalog() {
        let registry = PricingRegistry::new("chain");
        let version = registry
            .publish_json(
                r#"{
                  "price_list": {"version":"catalog-469","effective_from":"2026-10-08T12:34:56Z",
                    "entries":[{"provider_type":"anthropic","model":"claude-sonnet","tier_mode":"graduated",
                      "tiers":[{"up_to":200000,"input_nanodollars_per_token":3000,"cached_input_nanodollars_per_token":300,
                        "cache_write_nanodollars_per_token":3750,"output_nanodollars_per_token":15000},
                        {"up_to":null,"input_nanodollars_per_token":6000,"cached_input_nanodollars_per_token":600,
                        "cache_write_nanodollars_per_token":7500,"output_nanodollars_per_token":22500}]}]},
                  "providers":{"provider:anthropic":"anthropic"},
                  "catalog":{"source":"public","unsupported":{"model-x":"non-integer nanodollar rate"}}
                }"#,
            )
            .expect("card validates")
            .rate_card_version;

        let value = serde_json::to_value(registry.json_view().expect("active view")).unwrap();
        assert_eq!(value["rate_card_version"], version);
        assert_eq!(value["price_list"]["version"], "catalog-469");
        let replacement = registry.publish_json(&serde_json::json!({"price_list": value["price_list"], "providers": value["providers"], "catalog": value["catalog"]}).to_string()).unwrap().rate_card_version;
        assert_eq!(
            replacement, version,
            "GET/PUT must preserve the card version"
        );
        assert_eq!(
            value["price_list"]["effective_from"],
            "2026-10-08T12:34:56+00:00"
        );
        assert_eq!(
            value["price_list"]["entries"][0]["tiers"][1]["output_nanodollars_per_token"],
            22500
        );
        assert_eq!(value["providers"]["provider:anthropic"], "anthropic");
        assert_eq!(value["catalog"]["source"], "public");
        assert_eq!(
            value["catalog"]["unsupported"]["model-x"],
            "non-integer nanodollar rate"
        );
    }

    // --- ADR-0010 phase 2: image generation and modality rates -------------

    /// A card in the wire shape, for the `openai` provider type on cluster
    /// `provider:openai`.
    fn card(entries: serde_json::Value) -> PricingContext {
        parse_card_json(
            &serde_json::json!({
                "price_list": {"version": "media", "effective_from": "2026-01-01T00:00:00Z",
                               "entries": entries},
                "providers": {"provider:openai": "openai"},
            })
            .to_string(),
        )
        .expect("the card parses")
    }

    fn card_error(entries: serde_json::Value) -> String {
        match parse_card_json(
            &serde_json::json!({
                "price_list": {"effective_from": "2026-01-01T00:00:00Z", "entries": entries},
                "providers": {},
            })
            .to_string(),
        ) {
            Err(ConfigError::InvalidValue { reason, .. }) => reason,
            other => panic!("expected a load error, got {other:?}"),
        }
    }

    fn token_tier(input: u64, output: u64) -> serde_json::Value {
        serde_json::json!({"input_nanodollars_per_token": input,
            "cached_input_nanodollars_per_token": 0, "cache_write_nanodollars_per_token": 0,
            "output_nanodollars_per_token": output})
    }

    /// Drive one request through the filter as the chain does: classified
    /// endpoint, published request facts, a dialled OpenAI cluster.
    fn drive(
        pricing: PricingContext,
        path: &str,
        facts: (Option<&str>, Option<&str>),
        content_type: &str,
        chunks: Vec<Bytes>,
        end: bool,
    ) -> (proxy_http::LlmStats, Arc<UsageStats>) {
        let request_facts = RequestFacts {
            size: facts.0.map(str::to_owned),
            quality: facts.1.map(str::to_owned),
            ..RequestFacts::default()
        };
        drive_with(
            pricing,
            path,
            request_facts,
            StatusCode::OK,
            content_type,
            chunks,
            end,
        )
    }

    /// [`drive`] with the whole request facts and the response status.
    fn drive_with(
        pricing: PricingContext,
        path: &str,
        facts: RequestFacts,
        status: StatusCode,
        content_type: &str,
        chunks: Vec<Bytes>,
        end: bool,
    ) -> (proxy_http::LlmStats, Arc<UsageStats>) {
        let mut filter = UsageFilterInstance {
            pricing: Some(pricing),
            ..filter_for(Dialect::OpenAi)
        };
        let stats = Arc::clone(&filter.stats);
        let mut cb = TestCallbacks::new();
        {
            let mut info = cb.stream_info.borrow_mut();
            info.upstream_cluster = Some("provider:openai".into());
            info.requested_model = Some("img".into());
            info.request_facts = facts;
            info.bytes_received = 4000;
        }
        decode(
            &mut filter,
            &mut cb,
            &mut request(Method::POST, path),
            false,
        );
        let mut headers = response_headers(content_type);
        headers.status = status;
        filter.encode_headers(&mut cb, &mut headers, false);
        let last = chunks.len().saturating_sub(1);
        for (i, mut chunk) in chunks.into_iter().enumerate() {
            filter.encode_data(&mut cb, &mut chunk, end && i == last);
        }
        if !end {
            filter.on_stream_complete(&mut cb);
        }
        (cb.llm(), stats)
    }

    fn image_response(images: usize, b64_len: usize, echo: bool, usage: bool) -> Vec<Bytes> {
        let b64 = "A".repeat(b64_len);
        let data: Vec<String> = (0..images)
            .map(|_| format!(r#"{{"b64_json":"{b64}"}}"#))
            .collect();
        let echo = if echo {
            r#","size":"1024x1024","quality":"high""#
        } else {
            ""
        };
        let usage = if usage {
            r#","usage":{"input_tokens":50,"input_tokens_details":{"text_tokens":40,"image_tokens":10},"output_tokens":4000,"output_tokens_details":{"text_tokens":100,"image_tokens":3900},"total_tokens":4050}"#
        } else {
            ""
        };
        format!(
            r#"{{"created":1,"data":[{}]{echo}{usage}}}"#,
            data.join(",")
        )
        .into_bytes()
        .chunks(64 << 10)
        .map(Bytes::copy_from_slice)
        .collect()
    }

    fn per_image_card() -> PricingContext {
        card(serde_json::json!([{
        "provider_type": "openai", "model": "img", "basis": "images",
        "image_prices": [
            {"nanodollars_per_image": 10_000_000},
            {"size": "1024x1024", "nanodollars_per_image": 20_000_000},
            {"size": "1024x1024", "quality": "high", "nanodollars_per_image": 70_000_000}
        ]}]))
    }

    /// A per-image card prices the elements of `data[]` at the most specific
    /// matching row, reading the attributes from the response echo, then
    /// from the request body, and a multi-megabyte body is scanned, not held.
    #[test]
    fn a_per_image_card_prices_data_elements_at_the_most_specific_row() {
        let images = Endpoint::classify(&Method::POST, "/v1/images/generations");
        assert_eq!(images, Endpoint::ImageGeneration);
        let path = "/v1/images/generations";
        for (echo, facts, expected) in [
            // Both attributes echoed: the two-attribute row.
            (true, (None, None), 2 * 70_000_000),
            // No echo: the request's size alone selects the size-only row.
            (false, (Some("1024x1024"), Some("low")), 2 * 20_000_000),
            // Nothing matches a specific row: the catch-all.
            (false, (Some("512x512"), None), 2 * 10_000_000),
        ] {
            let (llm, _) = drive(
                per_image_card(),
                path,
                facts,
                "application/json",
                image_response(2, 3 << 20, echo, false),
                true,
            );
            let usage = llm.usage.clone().expect("images are usage");
            assert_eq!(usage.meters.images, Some(2));
            assert_eq!(usage.tokens, None, "this response reported no tokens");
            assert_eq!(
                llm.list_cost.map(|c| c.nanodollars),
                Some(expected),
                "{echo} {facts:?}"
            );
            assert_eq!(llm.price_basis, Some(PriceBasis::Images));
        }
        // No row matches and no catch-all: unpriced, never a guess.
        let strict = card(serde_json::json!([{
            "provider_type": "openai", "model": "img", "basis": "images",
            "image_prices": [{"size": "1024x1024", "nanodollars_per_image": 1}]}]));
        let (llm, _) = drive(
            strict,
            path,
            (Some("256x256"), None),
            "application/json",
            image_response(1, 10, false, false),
            true,
        );
        assert_eq!(llm.usage.and_then(|u| u.meters.images), Some(1));
        assert_eq!(llm.list_cost, None);
        assert_eq!(llm.price_basis, None);
    }

    /// gpt-image usage is priced per modality: image tokens split out of the
    /// text buckets at their own rates.
    #[test]
    fn gpt_image_usage_is_priced_per_modality() {
        let mut tier = token_tier(5, 1);
        tier["image_input_nanodollars_per_token"] = 10.into();
        tier["image_output_nanodollars_per_token"] = 40.into();
        let tokens_card = card(serde_json::json!([{
            "provider_type": "openai", "model": "img",
            "tier_mode": "whole_request", "tiers": [tier]}]));
        let (llm, stats) = drive(
            tokens_card,
            "/v1/images/generations",
            (None, None),
            "application/json",
            image_response(1, 1 << 20, true, true),
            true,
        );
        let tokens = llm.usage.as_ref().and_then(|u| u.tokens).expect("tokens");
        assert_eq!((tokens.input_tokens, tokens.input_image_tokens), (50, 10));
        assert_eq!(
            (tokens.output_tokens, tokens.output_image_tokens),
            (4000, 3900)
        );
        assert_eq!(
            llm.list_cost.map(|c| c.nanodollars),
            Some(40 * 5 + 10 * 10 + 100 + 3900 * 40)
        );
        assert_eq!(llm.price_basis, Some(PriceBasis::Tokens));
        assert_eq!(stats.underpriced_modality(), 0);
    }

    /// A cut image response is charged what closed before the cut: the
    /// images completed so far, never an estimate from the base64 bytes.
    #[test]
    fn a_cut_image_response_is_not_byte_estimated() {
        let mut chunks = image_response(3, 1 << 20, true, true);
        // Cut inside the third image: two images closed, no usage yet.
        chunks.truncate(chunks.len() * 5 / 6);
        let (llm, stats) = drive(
            per_image_card(),
            "/v1/images/generations",
            (Some("1024x1024"), None),
            "application/json",
            chunks.clone(),
            false,
        );
        assert_eq!(llm.completeness, Some(UsageCompleteness::Partial));
        let usage = llm.usage.expect("the closed images");
        assert_eq!(usage.meters.images, Some(2));
        assert_eq!(usage.tokens, None, "no token estimate from base64 bytes");
        assert!(!llm.input_estimated && !llm.output_estimated);
        assert_eq!(llm.list_cost.map(|c| c.nanodollars), Some(2 * 20_000_000));
        assert_eq!(stats.estimated(), 0);

        // Cut before any image closed: nothing to charge, not an estimate.
        let (llm, _) = drive(
            per_image_card(),
            "/v1/images/generations",
            (None, None),
            "application/json",
            vec![Bytes::from_static(
                br#"{"created":1,"data":[{"b64_json":"AAAA"#,
            )],
            false,
        );
        assert_eq!(llm.usage, None);
        assert_eq!(llm.list_cost, None);
    }

    /// An image stream counts `*.completed` events, not partial images.
    #[test]
    fn an_image_stream_counts_completed_events() {
        let b64 = "B".repeat(2 << 20);
        let stream = format!(
            "data: {{\"type\":\"image_generation.partial_image\",\"b64_json\":\"{b64}\"}}\n\n\
             data: {{\"type\":\"image_generation.completed\",\"b64_json\":\"{b64}\",\"size\":\"1024x1024\",\"quality\":\"high\"}}\n\n"
        );
        let chunks = stream
            .into_bytes()
            .chunks(50_000)
            .map(Bytes::copy_from_slice)
            .collect();
        let (llm, _) = drive(
            per_image_card(),
            "/v1/images/generations",
            (None, None),
            "text/event-stream",
            chunks,
            true,
        );
        assert_eq!(llm.usage.and_then(|u| u.meters.images), Some(1));
        assert_eq!(llm.list_cost.map(|c| c.nanodollars), Some(70_000_000));
    }

    /// A chat response that reports audio tokens, under a card with no audio
    /// rate, charges exactly what it charged before modality rates existed,
    /// and is counted. With an audio rate, those tokens move to it.
    #[test]
    fn chat_audio_without_an_audio_rate_charges_todays_amount_and_is_counted() {
        let body = br#"{"usage":{"prompt_tokens":100,"prompt_tokens_details":{"audio_tokens":60},"completion_tokens":50,"completion_tokens_details":{"audio_tokens":30}}}"#;
        let chat = |tier: serde_json::Value| {
            drive(
                card(
                    serde_json::json!([{"provider_type": "openai", "model": "img",
                    "tier_mode": "whole_request", "tiers": [tier]}]),
                ),
                "/v1/chat/completions",
                (None, None),
                "application/json",
                vec![Bytes::from_static(body)],
                true,
            )
        };
        let (llm, stats) = chat(token_tier(2, 3));
        assert_eq!(llm.list_cost.map(|c| c.nanodollars), Some(100 * 2 + 50 * 3));
        assert_eq!(stats.underpriced_modality(), 1);
        let tokens = llm.usage.and_then(|u| u.tokens).unwrap();
        assert_eq!(
            (tokens.input_audio_tokens, tokens.output_audio_tokens),
            (60, 30)
        );

        let mut tier = token_tier(2, 3);
        tier["audio_input_nanodollars_per_token"] = 7.into();
        tier["audio_output_nanodollars_per_token"] = 11.into();
        let (llm, stats) = chat(tier);
        assert_eq!(
            llm.list_cost.map(|c| c.nanodollars),
            Some(40 * 2 + 60 * 7 + 20 * 3 + 30 * 11)
        );
        assert_eq!(stats.underpriced_modality(), 0);
    }

    /// The shipped example card, priced with this build, has the version and
    /// the charge the build before ADR-0010 gave it (values recorded from
    /// that build), and is stored at schema version 1.
    #[test]
    fn an_existing_card_keeps_its_version_and_charge_across_the_upgrade() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/llmproxy-openrouter.yaml"
        );
        let config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("the example ships"))
                .expect("the example is JSON");
        let body = serde_json::json!({
            "price_list": config["pricing"]["price_list"],
            "providers": {"provider:openrouter": "openrouter"},
        })
        .to_string();
        let pricing = parse_card_json(&body).expect("the example parses");
        assert_eq!(
            pricing.version(),
            "openrouter-2026-10-09T04:01:00.459203+00:00+6b5605a2f7a5"
        );
        let usage = LlmUsage::from_tokens(LlmTokenUsage {
            input_tokens: 1234,
            cached_tokens: 567,
            output_tokens: 89,
            ..LlmTokenUsage::default()
        });
        assert_eq!(
            pricing
                .list
                .list_cost_for_cluster("provider:openrouter", "aion-labs/aion-2.0", &usage),
            Some(1_243_000)
        );
        let row = pricing.stored_row("chain");
        assert_eq!(row.schema_version, RATE_CARD_SCHEMA_V1);
        // Writing `basis: tokens` explicitly is still the default.
        let mut explicit = config["pricing"]["price_list"].clone();
        explicit["entries"][0]["basis"] = "tokens".into();
        let explicit = parse_card_json(
            &serde_json::json!({"price_list": explicit,
                "providers": {"provider:openrouter": "openrouter"}})
            .to_string(),
        )
        .unwrap();
        assert_eq!(explicit.version(), pricing.version());
        // The rendered wire document parses back to the same card.
        assert_eq!(
            parse_card_json(&pricing.to_wire_json()).unwrap().version(),
            pricing.version()
        );
    }

    /// A card using an ADR-0010 field is stored at schema version 2, has a
    /// version of its own, and round-trips through the wire document.
    #[test]
    fn a_media_card_is_stored_at_schema_version_2_and_round_trips() {
        let media = per_image_card();
        assert_eq!(
            media.stored_row("chain").schema_version,
            RATE_CARD_SCHEMA_V2
        );
        let reparsed = parse_card_json(&media.to_wire_json()).unwrap();
        assert_eq!(reparsed.version(), media.version());
        let mut tier = token_tier(1, 1);
        tier["image_input_nanodollars_per_token"] = 2.into();
        let modality = card(
            serde_json::json!([{"provider_type": "openai", "model": "img",
            "tier_mode": "whole_request", "tiers": [tier]}]),
        );
        let plain = card(
            serde_json::json!([{"provider_type": "openai", "model": "img",
            "tier_mode": "whole_request", "tiers": [token_tier(1, 1)]}]),
        );
        assert_ne!(modality.version(), plain.version());
        assert_eq!(modality.stored_row("c").schema_version, RATE_CARD_SCHEMA_V2);
        assert_eq!(plain.stored_row("c").schema_version, RATE_CARD_SCHEMA_V1);
        assert_eq!(
            parse_card_json(&modality.to_wire_json()).unwrap().version(),
            modality.version()
        );
    }

    /// An entry prices only the meters of its basis, so a field of the other
    /// basis is a load error, never ignored.
    #[test]
    fn a_field_of_the_other_basis_or_an_ambiguous_row_fails_to_load() {
        let images = |extra: serde_json::Value| {
            let mut entry = serde_json::json!({"provider_type": "openai", "model": "img",
                "basis": "images", "image_prices": [{"nanodollars_per_image": 1}]});
            entry
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            card_error(serde_json::json!([entry]))
        };
        assert!(images(serde_json::json!({"tiers": [token_tier(1, 1)]}))
            .contains("entries[0].tiers does not apply to basis images"));
        assert!(images(serde_json::json!({"tier_mode": "whole_request"}))
            .contains("entries[0].tier_mode"));
        assert!(images(serde_json::json!({"cached_input_unpriced": true}))
            .contains("entries[0].cached_input_unpriced"));
        assert!(images(serde_json::json!({"image_prices": []})).contains("at least one row"));
        assert!(images(serde_json::json!({"image_prices": [
            {"size": "1", "nanodollars_per_image": 1}, {"quality": "q", "nanodollars_per_image": 2}]}))
        .contains("image_prices[1] can match the same request as image_prices[0]"));
        assert!(images(serde_json::json!({"image_prices": [
            {"nanodollars_per_image": 1}, {"nanodollars_per_image": 2}]}))
        .contains("image_prices[1]"));
        assert!(
            card_error(serde_json::json!([{"provider_type": "openai", "model": "m",
            "basis": "bytes", "nanodollars_per_character": 1}]))
            .contains("entries[0].basis must be tokens, images, characters or audio_seconds")
        );
        // Each unit basis requires its own rate and refuses every other
        // basis's fields.
        let unit = |entry: serde_json::Value| {
            let mut full = serde_json::json!({"provider_type": "openai", "model": "m"});
            full.as_object_mut()
                .unwrap()
                .extend(entry.as_object().unwrap().clone());
            card_error(serde_json::json!([full]))
        };
        for (entry, error) in [
            (
                serde_json::json!({"basis": "characters"}),
                "entries[0].nanodollars_per_character is required for basis characters",
            ),
            (
                serde_json::json!({"basis": "audio_seconds"}),
                "entries[0].nanodollars_per_second is required for basis audio_seconds",
            ),
            (
                serde_json::json!({"basis": "characters", "image_prices": []}),
                "entries[0].image_prices applies only to basis images",
            ),
            (
                serde_json::json!({"basis": "audio_seconds", "nanodollars_per_second": 1,
                    "nanodollars_per_character": 1}),
                "entries[0].nanodollars_per_character applies only to basis characters",
            ),
            (
                serde_json::json!({"basis": "characters", "nanodollars_per_character": 1,
                    "tier_mode": "whole_request"}),
                "entries[0].tier_mode does not apply to basis characters",
            ),
            (
                serde_json::json!({"basis": "audio_seconds", "nanodollars_per_second": 1,
                    "cache_write_unpriced": true}),
                "entries[0].cache_write_unpriced does not apply to basis audio_seconds",
            ),
            (
                serde_json::json!({"tier_mode": "whole_request", "tiers": [token_tier(1, 1)],
                    "nanodollars_per_second": 1}),
                "entries[0].nanodollars_per_second applies only to basis audio_seconds",
            ),
        ] {
            let got = unit(entry.clone());
            assert!(got.contains(error), "{entry}: {got}");
        }
        assert!(
            card_error(serde_json::json!([{"provider_type": "openai", "model": "m",
            "tier_mode": "whole_request", "tiers": [token_tier(1, 1)],
            "image_prices": [{"nanodollars_per_image": 1}]}]))
            .contains("entries[0].image_prices applies only to basis images")
        );
        let mut banded = token_tier(1, 1);
        banded["up_to"] = 10.into();
        banded["audio_input_nanodollars_per_token"] = 3.into();
        assert!(
            card_error(serde_json::json!([{"provider_type": "openai", "model": "m",
            "tier_mode": "graduated", "tiers": [banded, token_tier(2, 2)]}]))
            .contains(
                "entries[0].tiers[1].audio_input_nanodollars_per_token must be set on every tier"
            )
        );
    }

    // ---- ADR-0010 phase 3: speech, transcription, image edits ----------

    /// The drive helpers price model `img` on `provider:openai`.
    fn unit_card(basis: &str, field: &str, rate: u64) -> PricingContext {
        card(serde_json::json!([{
            "provider_type": "openai", "model": "img", "basis": basis, field: rate}]))
    }

    fn speech_facts(characters: u64) -> RequestFacts {
        RequestFacts {
            input_characters: Some(characters),
            complete: true,
            ..RequestFacts::default()
        }
    }

    /// Speech is charged ceil(characters x rate): the request's characters
    /// at the dialled entry, rounded up to a whole micro-USD, only when the
    /// response was 2xx. A cut audio response still consumed its input.
    #[test]
    fn speech_is_charged_its_input_characters_only_on_a_2xx_response() {
        let audio = || vec![Bytes::from_static(b"ID3\x04\x00 mp3 frames")];
        let (llm, _) = drive_with(
            unit_card("characters", "nanodollars_per_character", 15),
            "/v1/audio/speech",
            speech_facts(1001),
            StatusCode::OK,
            "audio/mpeg",
            audio(),
            true,
        );
        let usage = llm.usage.expect("the request-side meter");
        assert_eq!(usage.meters.input_characters, Some(1001));
        assert_eq!(usage.tokens, None);
        assert_eq!(llm.price_basis, Some(PriceBasis::Characters));
        let cost = llm.list_cost.expect("priced");
        assert_eq!(cost.nanodollars, 15_015);
        assert_eq!(cost.micro_usd, 16, "15.015 micro-USD rounds up");

        let (llm, _) = drive_with(
            unit_card("characters", "nanodollars_per_character", 15),
            "/v1/audio/speech",
            speech_facts(1001),
            StatusCode::BAD_REQUEST,
            "application/json",
            vec![Bytes::from_static(br#"{"error":{"message":"bad voice"}}"#)],
            true,
        );
        assert_eq!(llm.usage, None, "a non-2xx speech response charges nothing");
        assert_eq!(llm.list_cost, None);

        let (llm, stats) = drive_with(
            unit_card("characters", "nanodollars_per_character", 15),
            "/v1/audio/speech",
            speech_facts(1001),
            StatusCode::OK,
            "audio/mpeg",
            audio(),
            false,
        );
        assert_eq!(llm.completeness, Some(UsageCompleteness::Partial));
        assert_eq!(llm.list_cost.map(|c| c.nanodollars), Some(15_015));
        assert_eq!(stats.estimated(), 0, "no byte estimate from audio");
    }

    /// Transcription and translation are charged their audio duration in
    /// milliseconds at a per-second rate, rounded up to a whole nanodollar,
    /// from each place a response reports it.
    #[test]
    fn transcription_is_charged_its_reported_audio_duration() {
        let rate = 100_000; // 0.006 USD per minute
        for (path, body, ms) in [
            (
                "/v1/audio/transcriptions",
                r#"{"text":"hi","usage":{"type":"duration","seconds":2.5}}"#,
                2500,
            ),
            (
                "/v1/audio/translations",
                r#"{"task":"translate","language":"english","duration":0.1,"text":"hi","segments":[]}"#,
                100,
            ),
            (
                "/v1/audio/transcriptions",
                r#"{"model":"m","text":"hi","usage":{"prompt_audio_seconds":3,"prompt_tokens":4}}"#,
                3000,
            ),
            (
                "/v1/audio/transcriptions",
                r#"{"text":"hi","usage":{"type":"duration","seconds":1.0005}}"#,
                1001,
            ),
        ] {
            let (llm, _) = drive_with(
                unit_card("audio_seconds", "nanodollars_per_second", rate),
                path,
                RequestFacts::default(),
                StatusCode::OK,
                "application/json",
                vec![Bytes::from(body)],
                true,
            );
            let usage = llm.usage.expect(body);
            assert_eq!(usage.meters.audio_milliseconds, Some(ms), "{body}");
            assert_eq!(
                llm.list_cost.map(|c| c.nanodollars),
                Some((ms * rate).div_ceil(1000)),
                "{body}"
            );
        }
        // A token-reporting model under a per-second entry observed no
        // duration: unpriced, not charged zero as a price.
        let (llm, _) = drive_with(
            unit_card("audio_seconds", "nanodollars_per_second", rate),
            "/v1/audio/transcriptions",
            RequestFacts::default(),
            StatusCode::OK,
            "application/json",
            vec![Bytes::from_static(
                br#"{"text":"hi","usage":{"type":"tokens","input_tokens":14,"input_token_details":{"text_tokens":0,"audio_tokens":14},"output_tokens":45,"total_tokens":59}}"#,
            )],
            true,
        );
        let usage = llm.usage.expect("tokens");
        assert_eq!(usage.meters.audio_milliseconds, None);
        assert_eq!(usage.tokens.map(|t| t.input_audio_tokens), Some(14));
        assert_eq!(llm.list_cost, None);
    }

    /// The unverified provider shapes (ADR-0010, "How providers bill"), as
    /// the provider documents them. No recorded response exists yet, so these
    /// pin the documented shape, and the example rate card marks each as an
    /// assumption until one is recorded.
    #[test]
    fn documented_stream_usage_shapes_are_read() {
        let tokens = card(serde_json::json!([{
            "provider_type": "openai", "model": "img",
            "tier_mode": "whole_request", "tiers": [token_tier(600, 12_000)]}]));
        // `gpt-4o-mini-tts` with `stream_format: sse`: usage only on
        // `speech.audio.done`.
        let (llm, _) = drive_with(
            tokens.clone(),
            "/v1/audio/speech",
            speech_facts(5),
            StatusCode::OK,
            "text/event-stream",
            vec![Bytes::from_static(
                b"data: {\"type\":\"speech.audio.delta\",\"audio\":\"AAAA\"}\n\n\
                  data: {\"type\":\"speech.audio.done\",\"usage\":{\"input_tokens\":14,\"output_tokens\":101,\"total_tokens\":115}}\n\n",
            )],
            true,
        );
        let usage = llm.usage.expect("speech.audio.done usage");
        let read = usage.tokens.expect("tokens");
        assert_eq!((read.input_tokens, read.output_tokens), (14, 101));
        assert_eq!(usage.meters.input_characters, Some(5));
        assert_eq!(
            llm.list_cost.map(|c| c.nanodollars),
            Some(14 * 600 + 101 * 12_000),
            "a tokens entry prices only the tokens"
        );
        // Streamed transcription: usage on `transcript.text.done`.
        let (llm, _) = drive_with(
            unit_card("audio_seconds", "nanodollars_per_second", 1000),
            "/v1/audio/transcriptions",
            RequestFacts::default(),
            StatusCode::OK,
            "text/event-stream",
            vec![Bytes::from_static(
                b"data: {\"type\":\"transcript.text.delta\",\"delta\":\"hi\"}\n\n\
                  data: {\"type\":\"transcript.text.done\",\"text\":\"hi\",\"usage\":{\"type\":\"duration\",\"seconds\":4}}\n\n",
            )],
            true,
        );
        assert_eq!(llm.list_cost.map(|c| c.nanodollars), Some(4000));
    }

    /// An image edit is charged like a generation: elements of `data[]`, or
    /// `image_edit.completed` events, with the size from the form when the
    /// response does not echo it.
    #[test]
    fn an_image_edit_is_charged_per_image() {
        let form_facts = RequestFacts {
            size: Some("1024x1024".into()),
            complete: true,
            ..RequestFacts::default()
        };
        let (llm, _) = drive_with(
            per_image_card(),
            "/v1/images/edits",
            form_facts.clone(),
            StatusCode::OK,
            "application/json",
            image_response(2, 1 << 10, false, false),
            true,
        );
        assert_eq!(llm.list_cost.map(|c| c.nanodollars), Some(2 * 20_000_000));
        let (llm, _) = drive_with(
            per_image_card(),
            "/v1/images/edits",
            form_facts,
            StatusCode::OK,
            "text/event-stream",
            vec![Bytes::from_static(
                b"data: {\"type\":\"image_edit.partial_image\",\"b64_json\":\"QQ\"}\n\n\
                  data: {\"type\":\"image_edit.completed\",\"b64_json\":\"QUJD\",\"quality\":\"high\"}\n\n",
            )],
            true,
        );
        assert_eq!(llm.usage.as_ref().and_then(|u| u.meters.images), Some(1));
        assert_eq!(llm.list_cost.map(|c| c.nanodollars), Some(70_000_000));
    }

    // --- realtime sessions (ADR-0015) ---------------------------------------

    /// One unmasked server text frame.
    fn ws_text(event: &str) -> Vec<u8> {
        let payload = event.as_bytes();
        let mut frame = vec![0x81];
        if payload.len() < 126 {
            frame.push(payload.len() as u8);
        } else {
            frame.push(126);
            frame.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        }
        frame.extend_from_slice(payload);
        frame
    }

    const RT_DONE_A: &str = r#"{"type":"response.done","response":{"usage":{"input_tokens":12,"output_tokens":7,"input_token_details":{"audio_tokens":9},"output_token_details":{"audio_tokens":5}}}}"#;
    const RT_DONE_B: &str =
        r#"{"type":"response.done","response":{"usage":{"input_tokens":3,"output_tokens":1}}}"#;

    /// Open a priced realtime session: the request headers, then the `101`.
    fn realtime_session(cb: &mut TestCallbacks) -> UsageFilterInstance {
        let mut filter = priced_filter_with(&[("gpt-realtime", 10, 100)]);
        {
            let mut info = cb.stream_info.borrow_mut();
            info.llm.endpoint = Endpoint::Realtime;
            info.upstream_cluster = Some("provider:openai".into());
            info.requested_model = Some("gpt-realtime".into());
        }
        let mut request = RequestHeaders {
            method: Method::GET,
            uri: "/v1/realtime?model=gpt-realtime".parse().unwrap(),
            headers: HeaderMap::new(),
        };
        request.headers.insert(
            "sec-websocket-extensions",
            HeaderValue::from_static("permessage-deflate; client_max_window_bits"),
        );
        filter.decode_headers(cb, &mut request, true);
        assert!(
            !request.headers.contains_key("sec-websocket-extensions"),
            "the compression offer is removed so frames stay readable"
        );
        let mut accept = ResponseHeaders {
            status: StatusCode::SWITCHING_PROTOCOLS,
            headers: HeaderMap::new(),
        };
        filter.encode_headers(cb, &mut accept, false);
        filter
    }

    /// A session's usage is the sum of its `response.done` events, priced
    /// once at the session's end at the rate card's token rates.
    #[test]
    fn a_realtime_session_is_metered_from_its_response_done_events() {
        let mut cb = TestCallbacks::new();
        let mut filter = realtime_session(&mut cb);
        let mut frames = ws_text(r#"{"type":"response.created"}"#);
        frames.extend(ws_text(RT_DONE_A));
        frames.extend(ws_text(r#"{"type":"response.created"}"#));
        frames.extend(ws_text(RT_DONE_B));
        // Split mid-frame, as TCP may.
        let (a, b) = frames.split_at(17);
        filter.encode_data(&mut cb, &mut Bytes::copy_from_slice(a), false);
        filter.encode_data(&mut cb, &mut Bytes::copy_from_slice(b), false);
        assert_eq!(cb.llm().usage, None, "nothing is written before the end");
        filter.encode_data(&mut cb, &mut Bytes::new(), true);

        let llm = cb.llm();
        let tokens = llm.usage.and_then(|u| u.tokens).expect("metered");
        assert_eq!((tokens.input_tokens, tokens.output_tokens), (15, 8));
        assert_eq!(
            (tokens.input_audio_tokens, tokens.output_audio_tokens),
            (9, 5)
        );
        assert_eq!(llm.completeness, Some(UsageCompleteness::Complete));
        assert_eq!(
            llm.list_cost.expect("priced").nanodollars,
            15 * 10 + 8 * 100,
            "audio without a modality rate is priced at the text rate"
        );
        assert_eq!(filter.stats.realtime_missing(), 0);
    }

    /// A session cut while a response is in flight is recorded partial and
    /// charged what its events reported, never an estimate from the audio
    /// bytes; the in-flight response is counted as missing usage.
    #[test]
    fn a_cut_realtime_session_is_partial_and_its_in_flight_response_is_counted() {
        let mut cb = TestCallbacks::new();
        let mut filter = realtime_session(&mut cb);
        let mut frames = ws_text(r#"{"type":"response.created"}"#);
        frames.extend(ws_text(RT_DONE_B));
        frames.extend(ws_text(r#"{"type":"response.created"}"#));
        frames.extend(ws_text(r#"{"type":"response.audio.delta","delta":"AAAA"}"#));
        filter.encode_data(&mut cb, &mut Bytes::from(frames), false);
        filter.on_stream_complete(&mut cb);

        let llm = cb.llm();
        assert_eq!(llm.completeness, Some(UsageCompleteness::Partial));
        let tokens = llm.usage.and_then(|u| u.tokens).expect("charged once");
        assert_eq!((tokens.input_tokens, tokens.output_tokens), (3, 1));
        assert!(!llm.input_estimated && !llm.output_estimated);
        assert_eq!(llm.list_cost.expect("priced").nanodollars, 3 * 10 + 100);
        assert_eq!(filter.stats.realtime_missing(), 1, "the in-flight response");
        filter.on_stream_complete(&mut cb);
        assert_eq!(filter.stats.realtime_missing(), 1, "reported once");
    }

    /// A `response.done` with no usage is counted, never silently free.
    #[test]
    fn a_response_done_without_usage_is_counted() {
        let mut cb = TestCallbacks::new();
        let mut filter = realtime_session(&mut cb);
        let frames = ws_text(r#"{"type":"response.done","response":{"status":"failed"}}"#);
        filter.encode_data(&mut cb, &mut Bytes::from(frames), true);
        assert_eq!(cb.llm().usage, None);
        assert_eq!(filter.stats.realtime_missing(), 1);
    }
}
