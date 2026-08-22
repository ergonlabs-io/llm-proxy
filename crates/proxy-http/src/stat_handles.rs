//! WP-23 increment 6a: the router-side half of wiring the stats registry to
//! real traffic. This module owns exactly two things: a per-cluster lookup
//! table of pre-resolved [`Handle`]/[`HistogramHandle`]s
//! ([`StatHandles`]/[`ClusterStatHandles`]), and a thin, panic-free recording
//! API over it ([`RouterStats`]) that `router.rs` calls from the attempt
//! loop. See `router.rs`'s module doc for exactly where/why each of the two
//! instruments (`UPSTREAM_RQ`, `UPSTREAM_RQ_TIME`) is recorded.
//!
//! # Why resolution happens once, at boot, on the control side
//!
//! `proxy_observability::stats::Registry` (the hot-path type every worker
//! holds as `Arc<Registry>`) deliberately has no public `resolve` -- only
//! [`proxy_observability::stats::StatsControl`] can grow the registry (see
//! that module's "Increment 5" doc section). [`StatHandles::build`] is the
//! one call site in the whole data plane that touches `StatsControl`: it
//! runs once, in `crates/proxy/src/main.rs`, against the boot-time config
//! snapshot's cluster names, and the resulting table is hands out as
//! `Arc<StatHandles>` to every worker -- exactly the "control computes,
//! workers `load`" shape the registry itself already uses internally.
//!
//! # A cluster with no entry is a no-op, not a panic
//!
//! `StatHandles` is built once, from the cluster names present in the boot
//! snapshot -- but the table itself is not frozen after that:
//! [`StatHandles::resolve_missing`] lets a SIGHUP config reload
//! (`crates/proxy/src/main.rs`) extend the SAME table (every worker holds a
//! clone of the one `Arc<StatHandles>`, so a resolve there is visible to
//! every worker's `for_cluster` immediately) with any cluster name the new
//! snapshot introduces. Until a reload does that, though -- and for any
//! cluster this process never learns about at all -- a name the router asks
//! about that isn't in the table is a real possibility, and must never be
//! allowed to fail a request: [`RouterStats::record_attempt`]/
//! [`RouterStats::record_attempt_duration_ms`] silently no-op on a lookup
//! miss, logging at most once per unique unknown name (see
//! [`RouterStats::warn_unknown_cluster_once`]) so the gap stays visible
//! without spamming a line per request.
//!
//! # WP-23 increment 6b: the other two instruments
//!
//! [`DownstreamStatHandles`]/[`DownstreamStats`] and
//! [`TokenUsageStatHandles`]/[`GenAiTokenStats`] mirror
//! [`StatHandles`]/[`RouterStats`]'s shape exactly (same
//! resolve-once-at-boot, `ArcSwap`-not-`Mutex`, warn-once-on-a-miss rules),
//! just for `DOWNSTREAM_CX_TOTAL{listener}` (`crate::listener`'s accept
//! loop, `proxy-core`) and `GEN_AI_CLIENT_TOKEN_USAGE{provider,type}`
//! (`crate::access_logging::LoggingBody::finish`) respectively, instead of
//! `UPSTREAM_RQ`/`UPSTREAM_RQ_TIME`. See each type's own doc for what's
//! different: a single instrument keyed by listener name for the first, and
//! four handles per provider (one per token bucket) for the second.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use arc_swap::ArcSwap;
use proxy_observability::access_log::LlmTokens;
use proxy_observability::stats::{
    instruments, Handle, HistogramHandle, Registry, StatsControl, WorkerId,
};

/// One cluster's pre-resolved handles: the `upstream_rq` counter and the
/// `upstream_rq_time` histogram, both already resolved with `cluster` =
/// this cluster's name (see [`StatHandles::build`]). Plain, `Copy` fields --
/// a `Handle`/`HistogramHandle` is just an opaque index (see
/// `proxy_observability::stats`'s module doc), so there's nothing to borrow
/// or clone expensively here.
#[derive(Debug, Clone, Copy)]
pub struct ClusterStatHandles {
    pub rq: Handle,
    pub rq_time: HistogramHandle,
}

/// Cluster name -> [`ClusterStatHandles`], built at boot from the config
/// snapshot's cluster set and, since the SIGHUP reload path landed, grown in
/// place by [`Self::resolve_missing`] for any cluster a later reload
/// introduces. See the module doc for why growing this table is safe to do
/// from outside the router.
///
/// Rust note: `by_cluster` is an `ArcSwap`, not a plain `HashMap` behind a
/// `Mutex` -- the same "control computes, workers `load`" shape
/// `proxy_observability::stats::Registry` uses for its own `Snapshot` and
/// `ClusterManager` uses for `HostSet` (see ADR-0005). `for_cluster` runs on
/// every upstream attempt and `StatHandles` is shared across every worker
/// through one `Arc`, so a `Mutex` here would be a single lock every worker
/// contends on for every request -- not the "uncontended lock" an earlier
/// version of this comment claimed. `ArcSwap::load` is lock-free, so
/// `for_cluster` costs a pointer load + a `HashMap::get`, no matter how many
/// workers call it concurrently. [`Self::resolve_missing`] (control side,
/// reload-only) builds a whole new map and swaps it in -- see that method's
/// doc for why copying the map is fine here specifically, which is NOT the
/// general rule for this codebase's `Arc`-swapped state.
pub struct StatHandles {
    by_cluster: ArcSwap<HashMap<String, ClusterStatHandles>>,
}

impl StatHandles {
    /// Resolves `UPSTREAM_RQ`/`UPSTREAM_RQ_TIME` for every name in
    /// `cluster_names`, against `control`. Called once, at boot
    /// (`crates/proxy/src/main.rs`), before any worker starts serving
    /// traffic -- `control` is the control-side-only
    /// [`StatsControl`], never handed to a worker.
    ///
    /// Rust note: `impl IntoIterator<Item = &'a str>` (rather than, say,
    /// `&[String]`) so a caller can hand this `snapshot.clusters.keys()`
    /// (an iterator of `&String`, `map`ped to `&str`) without collecting an
    /// intermediate `Vec` first.
    pub fn build<'a>(
        control: &StatsControl,
        cluster_names: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let table = Self {
            by_cluster: ArcSwap::from_pointee(HashMap::new()),
        };
        table.resolve_missing(control, cluster_names);
        table
    }

    /// Resolves `UPSTREAM_RQ`/`UPSTREAM_RQ_TIME` for every name in
    /// `cluster_names` this table doesn't already have an entry for -- a
    /// no-op for any name already present. [`Self::build`] is just this
    /// called once against an empty table; the SIGHUP reload path
    /// (`crates/proxy/src/main.rs`) calls it again, against the SAME
    /// `Arc<StatHandles>` every worker already holds, for every cluster name
    /// in the freshly reloaded snapshot -- so a cluster introduced after
    /// boot gets counted from its first request instead of silently falling
    /// into the unknown-cluster path the module doc describes.
    ///
    /// Builds a fresh `HashMap` (the current entries plus whatever's new)
    /// and swaps it in, rather than mutating in place -- `ArcSwap` has no
    /// in-place insert, only `load`/`store`/`rcu`. Copying the map here is
    /// safe and cheap: this runs only on the rare, config-reload path, and
    /// [`ClusterStatHandles`] is `Copy` (two handle indices), so the copy
    /// carries no live state that could be lost mid-swap. **This is NOT the
    /// same argument as the stats `Registry`'s own shard storage**, which
    /// deliberately never copies on growth (see that module's "Growth must
    /// not move or copy a live atomic" doc section) -- there, the values
    /// being copied would be live `AtomicU64` counters, and any increment
    /// landing between the snapshot read and the new registry's publish
    /// would be lost. Here, a handle is just an index into that registry;
    /// copying the index loses nothing, because the counter it points to
    /// still lives in the registry's own `Arc`'d storage, untouched by this
    /// swap.
    pub fn resolve_missing<'a>(
        &self,
        control: &StatsControl,
        cluster_names: impl IntoIterator<Item = &'a str>,
    ) {
        let current = self.by_cluster.load();
        let mut next: HashMap<String, ClusterStatHandles> = (**current).clone();
        let mut changed = false;
        for name in cluster_names {
            if next.contains_key(name) {
                continue;
            }
            let rq = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", name)]);
            let rq_time =
                control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", name)]);
            next.insert(name.to_string(), ClusterStatHandles { rq, rq_time });
            changed = true;
        }
        if changed {
            self.by_cluster.store(Arc::new(next));
        }
    }

    /// Looks up `cluster`'s pre-resolved handles, or `None` if this table
    /// was never told about that cluster -- see the module doc for why that
    /// has to be a lookup miss the caller can handle, not a panic.
    ///
    /// Rust note: returns an owned `ClusterStatHandles` (it's `Copy` --
    /// two handle indices, nothing to avoid cloning) rather than a
    /// reference, because the value now lives behind an `ArcSwap`: a
    /// reference into the loaded `Arc` couldn't outlive this call. This is
    /// a lock-free `load()`, not a lock -- see the struct doc.
    pub fn for_cluster(&self, cluster: &str) -> Option<ClusterStatHandles> {
        self.by_cluster.load().get(cluster).copied()
    }
}

/// The router's recording API over [`StatHandles`] + the shared
/// [`Registry`]: one instance per worker (workers don't share a `WorkerId`,
/// so each worker builds its own -- see `crates/proxy/src/main.rs`'s
/// `worker_main`), cheap to construct (`registry`/`handles` are `Arc`
/// clones).
pub struct RouterStats {
    registry: Arc<Registry>,
    handles: Arc<StatHandles>,
    worker: WorkerId,
    /// Rust note: interior mutability for the "warn once per unknown
    /// cluster" dedup set. `record_attempt`/`record_attempt_duration_ms`
    /// take `&self` (this type is shared behind `Arc`, same shape as
    /// `ClusterManager`), so mutating a plain `HashSet` through a shared
    /// reference needs a lock. Only ever touched on the rare,
    /// config-shaped "unknown cluster" path -- never on the common
    /// per-request path -- so a `Mutex` here costs nothing that matters.
    warned_unknown_clusters: Mutex<HashSet<String>>,
}

impl RouterStats {
    pub fn new(registry: Arc<Registry>, handles: Arc<StatHandles>, worker: WorkerId) -> Self {
        Self {
            registry,
            handles,
            worker,
            warned_unknown_clusters: Mutex::new(HashSet::new()),
        }
    }

    /// The shared [`Registry`] this recorder writes into -- a plain `Arc`
    /// clone (pointer bump). Exposed mainly for tests that need to render
    /// (`proxy_observability::stats::envoy_render::render`) or otherwise
    /// inspect what got recorded; production code reaches the same registry
    /// through `proxy-admin`'s `/stats` route, not through this accessor.
    pub fn registry(&self) -> Arc<Registry> {
        self.registry.clone()
    }

    /// Records one upstream attempt dispatched to `cluster` -- see
    /// `router.rs`'s attempt loop for exactly what "dispatched" means (past
    /// the S5 circuit breaker and host selection, i.e. an attempt that is
    /// actually about to be dialed). A no-op, not a panic, for a cluster
    /// this table never resolved a handle for.
    pub fn record_attempt(&self, cluster: &str) {
        match self.handles.for_cluster(cluster) {
            Some(h) => self.registry.incr(self.worker, h.rq, 1),
            None => self.warn_unknown_cluster_once(cluster),
        }
    }

    /// Records one completed attempt's duration, in milliseconds, against
    /// `cluster`'s `upstream_rq_time` histogram. Callers must only call this
    /// for an attempt that was actually dialed -- see `router.rs` for why a
    /// circuit-breaker rejection (which never reaches this function at all)
    /// must never contribute a zero-duration observation. A no-op for an
    /// unresolved cluster, same as [`Self::record_attempt`] -- already
    /// warned once by the paired `record_attempt` call for the same
    /// attempt, so this doesn't warn again.
    pub fn record_attempt_duration_ms(&self, cluster: &str, millis: f64) {
        if let Some(h) = self.handles.for_cluster(cluster) {
            self.registry.observe(self.worker, h.rq_time, millis);
        }
    }

    /// `cluster`'s `upstream_rq_time` observation count so far, or `None` if
    /// this table never resolved a handle for it. Exists mainly for tests
    /// that need to assert exactly how many attempts recorded a duration
    /// (e.g. that a circuit-breaker rejection added zero) -- production code
    /// reads histogram data through `proxy-admin`'s `/stats` route instead.
    pub fn rq_time_observation_count(&self, cluster: &str) -> Option<u64> {
        let h = self.handles.for_cluster(cluster)?;
        Some(self.registry.histogram_snapshot(h.rq_time).count)
    }

    /// The sum, in milliseconds, of every `upstream_rq_time` observation
    /// recorded for `cluster` so far, or `None` if this table never
    /// resolved a handle for it. Paired with [`Self::rq_time_observation_count`]
    /// so a test can check "recorded a plausible, non-zero duration" without
    /// reaching for a raw [`HistogramHandle`] (which this module doesn't
    /// expose outside itself).
    pub fn rq_time_sum_ms(&self, cluster: &str) -> Option<f64> {
        let h = self.handles.for_cluster(cluster)?;
        Some(self.registry.histogram_snapshot(h.rq_time).sum)
    }

    /// Convenience for `router.rs`: turns an [`Instant`] captured at
    /// dispatch time into the millisecond `f64` [`Self::record_attempt_duration_ms`]
    /// wants, in one call.
    pub fn record_attempt_duration_since(&self, cluster: &str, dispatched_at: Instant) {
        self.record_attempt_duration_ms(cluster, dispatched_at.elapsed().as_secs_f64() * 1000.0);
    }

    fn warn_unknown_cluster_once(&self, cluster: &str) {
        let mut warned = self
            .warned_unknown_clusters
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if warned.insert(cluster.to_string()) {
            tracing::warn!(
                cluster,
                "stats: no resolved upstream_rq/upstream_rq_time handles for this cluster -- \
                 traffic to it will not be counted in /stats (the cluster was not present in \
                 the config snapshot the stats handle table was built from)"
            );
        }
    }
}

/// One listener's pre-resolved `downstream_cx_total` handle.
#[derive(Debug, Clone, Copy)]
pub struct ListenerStatHandles {
    pub cx_total: Handle,
}

/// Listener name -> [`ListenerStatHandles`], mirroring [`StatHandles`]'s
/// `by_cluster` table exactly -- same `ArcSwap` (not `Mutex`) reasoning, same
/// build-once/`resolve_missing`-on-reload cadence. See [`StatHandles`]'s own
/// doc for the full "control computes, workers `load`" rationale, unchanged
/// here.
pub struct DownstreamStatHandles {
    by_listener: ArcSwap<HashMap<String, ListenerStatHandles>>,
}

impl DownstreamStatHandles {
    /// Resolves `DOWNSTREAM_CX_TOTAL` for every name in `listener_names`,
    /// against `control`. Called once, at boot (`crates/proxy/src/main.rs`),
    /// from the boot snapshot's listener names -- mirrors
    /// [`StatHandles::build`] exactly.
    pub fn build<'a>(
        control: &StatsControl,
        listener_names: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let table = Self {
            by_listener: ArcSwap::from_pointee(HashMap::new()),
        };
        table.resolve_missing(control, listener_names);
        table
    }

    /// Resolves `DOWNSTREAM_CX_TOTAL` for every name in `listener_names` this
    /// table doesn't already have an entry for -- a no-op for any name
    /// already present. Called again on a SIGHUP reload
    /// (`crates/proxy/src/main.rs`'s `reload`), against the SAME
    /// `Arc<DownstreamStatHandles>` every worker's accept loop already
    /// holds, so a listener introduced after boot is counted from its first
    /// accepted connection instead of silently falling into the
    /// unknown-listener path below. See [`StatHandles::resolve_missing`]'s
    /// doc for why copying the map here is safe and cheap.
    pub fn resolve_missing<'a>(
        &self,
        control: &StatsControl,
        listener_names: impl IntoIterator<Item = &'a str>,
    ) {
        let current = self.by_listener.load();
        let mut next: HashMap<String, ListenerStatHandles> = (**current).clone();
        let mut changed = false;
        for name in listener_names {
            if next.contains_key(name) {
                continue;
            }
            let cx_total =
                control.resolve(&instruments::DOWNSTREAM_CX_TOTAL, &[("listener", name)]);
            next.insert(name.to_string(), ListenerStatHandles { cx_total });
            changed = true;
        }
        if changed {
            self.by_listener.store(Arc::new(next));
        }
    }

    /// Looks up `listener`'s pre-resolved handle, or `None` if this table
    /// was never told about that listener -- same lookup-miss-not-panic
    /// contract as [`StatHandles::for_cluster`].
    pub fn for_listener(&self, listener: &str) -> Option<ListenerStatHandles> {
        self.by_listener.load().get(listener).copied()
    }
}

/// `crate::listener`'s accept-loop recorder for `downstream_cx_total`: one
/// instance per worker (bakes in that worker's own `WorkerId`, same shape as
/// [`RouterStats`]), held as `Arc<DownstreamStats>`. A no-op, not a panic,
/// for a listener this table never resolved a handle for -- warns at most
/// once per unique unknown name, same convention as
/// [`RouterStats::warn_unknown_cluster_once`].
pub struct DownstreamStats {
    registry: Arc<Registry>,
    handles: Arc<DownstreamStatHandles>,
    worker: WorkerId,
    warned_unknown_listeners: Mutex<HashSet<String>>,
}

impl DownstreamStats {
    pub fn new(
        registry: Arc<Registry>,
        handles: Arc<DownstreamStatHandles>,
        worker: WorkerId,
    ) -> Self {
        Self {
            registry,
            handles,
            worker,
            warned_unknown_listeners: Mutex::new(HashSet::new()),
        }
    }

    /// Records one accepted downstream connection on `listener`. Callers
    /// must only call this for a connection `accept()` actually handed
    /// back -- see `crate::listener`'s accept loop, which increments
    /// exactly once per `Ok` from `accept()` and never for the `Err` arm
    /// (which already logs and `continue`s before reaching this call).
    pub fn record_connection_accepted(&self, listener: &str) {
        match self.handles.for_listener(listener) {
            Some(h) => self.registry.incr(self.worker, h.cx_total, 1),
            None => self.warn_unknown_listener_once(listener),
        }
    }

    fn warn_unknown_listener_once(&self, listener: &str) {
        let mut warned = self
            .warned_unknown_listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if warned.insert(listener.to_string()) {
            tracing::warn!(
                listener,
                "stats: no resolved downstream_cx_total handle for this listener -- \
                 connections accepted on it will not be counted in /stats (the listener was \
                 not present in the config snapshot the stats handle table was built from)"
            );
        }
    }
}

/// One provider's four pre-resolved `gen_ai.client.token.usage` handles, one
/// per token bucket `LlmTokenUsage`/[`LlmTokens`] carries.
#[derive(Debug, Clone, Copy)]
pub struct TokenUsageHandles {
    pub input: Handle,
    pub output: Handle,
    pub cached: Handle,
    pub cache_creation: Handle,
}

/// Provider (= cluster) name -> [`TokenUsageHandles`], mirroring
/// [`StatHandles`]'s `by_cluster` table shape and cadence exactly -- see that
/// struct's doc.
pub struct TokenUsageStatHandles {
    by_provider: ArcSwap<HashMap<String, TokenUsageHandles>>,
}

impl TokenUsageStatHandles {
    /// Resolves all four `gen_ai.client.token.usage` series for every name
    /// in `provider_names` (the boot snapshot's cluster names -- any
    /// cluster can be the member a request actually dials, ground rule #6)
    /// against `control`. Called once, at boot.
    pub fn build<'a>(
        control: &StatsControl,
        provider_names: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let table = Self {
            by_provider: ArcSwap::from_pointee(HashMap::new()),
        };
        table.resolve_missing(control, provider_names);
        table
    }

    /// Resolves all four buckets for every name in `provider_names` this
    /// table doesn't already have an entry for. Called again on a SIGHUP
    /// reload, same as [`StatHandles::resolve_missing`] -- see that doc.
    pub fn resolve_missing<'a>(
        &self,
        control: &StatsControl,
        provider_names: impl IntoIterator<Item = &'a str>,
    ) {
        let current = self.by_provider.load();
        let mut next: HashMap<String, TokenUsageHandles> = (**current).clone();
        let mut changed = false;
        for name in provider_names {
            if next.contains_key(name) {
                continue;
            }
            // Rust note: a small local closure, not a free function -- it
            // only ever needs `control`/`name` from this call's scope, and
            // naming the four calls below `resolve_bucket("input")` etc.
            // reads clearer than four near-identical `control.resolve(...)`
            // lines.
            let resolve_bucket = |bucket: &str| {
                control.resolve(
                    &instruments::GEN_AI_CLIENT_TOKEN_USAGE,
                    &[("provider", name), ("type", bucket)],
                )
            };
            let handles = TokenUsageHandles {
                input: resolve_bucket("input"),
                output: resolve_bucket("output"),
                cached: resolve_bucket("cached"),
                cache_creation: resolve_bucket("cache_creation"),
            };
            next.insert(name.to_string(), handles);
            changed = true;
        }
        if changed {
            self.by_provider.store(Arc::new(next));
        }
    }

    /// Looks up `provider`'s pre-resolved handles, or `None` if this table
    /// was never told about that provider.
    pub fn for_provider(&self, provider: &str) -> Option<TokenUsageHandles> {
        self.by_provider.load().get(provider).copied()
    }
}

/// `crate::access_logging::LoggingBody::finish`'s recorder for
/// `gen_ai.client.token.usage`: one instance per worker (bakes in that
/// worker's own `WorkerId`, same shape as [`RouterStats`]/[`DownstreamStats`]),
/// reached via `crate::filter_manager::FilterChainHandler`'s stored
/// `Arc<GenAiTokenStats>` (see [`crate::filter_manager::FilterChainHandler::with_token_stats`]).
/// A no-op, not a panic, for a provider this table never resolved handles
/// for -- warns at most once per unique unknown name.
pub struct GenAiTokenStats {
    registry: Arc<Registry>,
    handles: Arc<TokenUsageStatHandles>,
    worker: WorkerId,
    warned_unknown_providers: Mutex<HashSet<String>>,
}

impl GenAiTokenStats {
    pub fn new(
        registry: Arc<Registry>,
        handles: Arc<TokenUsageStatHandles>,
        worker: WorkerId,
    ) -> Self {
        Self {
            registry,
            handles,
            worker,
            warned_unknown_providers: Mutex::new(HashSet::new()),
        }
    }

    /// Records one completed stream's token usage against `provider`'s four
    /// series -- one `incr` per bucket, including a bucket that's genuinely
    /// zero (a provider reporting `cache_creation_tokens: 0` really did
    /// create zero cache entries this request, a fact worth adding to the
    /// running total -- unlike "no usage was reported at all", which is
    /// `LlmTokens` being entirely absent; see the call site in
    /// `access_logging::LoggingBody::finish`, which only calls this when
    /// usage IS present at all). `provider` must be the cluster actually
    /// dialled, never the routed cluster name -- see ground rule #6. A
    /// no-op, not a panic, for an unresolved provider.
    pub fn record_usage(&self, provider: &str, tokens: LlmTokens) {
        match self.handles.for_provider(provider) {
            Some(h) => {
                self.registry.incr(self.worker, h.input, tokens.input);
                self.registry.incr(self.worker, h.output, tokens.output);
                self.registry.incr(self.worker, h.cached, tokens.cached);
                self.registry
                    .incr(self.worker, h.cache_creation, tokens.cache_creation);
            }
            None => self.warn_unknown_provider_once(provider),
        }
    }

    fn warn_unknown_provider_once(&self, provider: &str) {
        let mut warned = self
            .warned_unknown_providers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if warned.insert(provider.to_string()) {
            tracing::warn!(
                provider,
                "stats: no resolved gen_ai.client.token.usage handles for this provider -- \
                 token usage will not be counted in /stats (the cluster was not present in the \
                 config snapshot the stats handle table was built from)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control_and_handles(names: &[&str]) -> (StatsControl, Arc<StatHandles>) {
        let control = StatsControl::new(1);
        let handles = Arc::new(StatHandles::build(&control, names.iter().copied()));
        (control, handles)
    }

    #[test]
    fn for_cluster_finds_a_built_cluster() {
        let (_control, handles) = control_and_handles(&["openai"]);
        assert!(handles.for_cluster("openai").is_some());
    }

    #[test]
    fn for_cluster_is_none_for_an_unbuilt_cluster() {
        let (_control, handles) = control_and_handles(&["openai"]);
        assert!(handles.for_cluster("anthropic").is_none());
    }

    #[test]
    fn resolve_missing_adds_a_new_cluster_without_disturbing_existing_ones() {
        let (control, handles) = control_and_handles(&["openai"]);
        let registry = control.registry();
        let stats = RouterStats::new(registry.clone(), handles.clone(), WorkerId(0));
        stats.record_attempt("openai");

        // Simulates a SIGHUP reload's snapshot naming a cluster this table
        // never saw at boot.
        handles.resolve_missing(&control, ["openai", "anthropic"]);

        assert!(
            handles.for_cluster("anthropic").is_some(),
            "resolve_missing should have added the new cluster"
        );
        // The pre-existing cluster's handle (and what it already counted)
        // must survive untouched -- `resolve_missing` skips names already
        // present rather than re-resolving (which would hand back a fresh,
        // zeroed handle).
        let h = handles.for_cluster("openai").unwrap();
        assert_eq!(registry.value(h.rq), 1);

        stats.record_attempt("anthropic");
        let h2 = handles.for_cluster("anthropic").unwrap();
        assert_eq!(registry.value(h2.rq), 1);
    }

    #[test]
    fn resolve_missing_is_visible_through_every_arc_clone() {
        // The whole point of the `Mutex`-backed table: a reload resolves
        // through ONE `Arc<StatHandles>`, but every worker holds its own
        // clone of that same `Arc` -- so the insert has to show up there
        // too, not just on the handle that made the call.
        let (control, handles) = control_and_handles(&["openai"]);
        let worker_clone = handles.clone();

        handles.resolve_missing(&control, ["anthropic"]);

        assert!(worker_clone.for_cluster("anthropic").is_some());
    }

    #[test]
    fn record_attempt_increments_the_resolved_counter() {
        let (control, handles) = control_and_handles(&["openai"]);
        let registry = control.registry();
        let stats = RouterStats::new(registry.clone(), handles.clone(), WorkerId(0));

        stats.record_attempt("openai");
        stats.record_attempt("openai");

        let h = handles.for_cluster("openai").unwrap();
        assert_eq!(registry.value(h.rq), 2);
    }

    #[test]
    fn record_attempt_on_an_unknown_cluster_does_not_panic() {
        let (control, handles) = control_and_handles(&["openai"]);
        let registry = control.registry();
        let stats = RouterStats::new(registry, handles, WorkerId(0));

        // Must not panic -- "openai" is known, "anthropic" is not.
        stats.record_attempt("anthropic");
        stats.record_attempt_duration_ms("anthropic", 12.0);
    }

    #[test]
    fn record_attempt_duration_ms_observes_into_the_resolved_histogram() {
        let (control, handles) = control_and_handles(&["openai"]);
        let registry = control.registry();
        let stats = RouterStats::new(registry.clone(), handles.clone(), WorkerId(0));

        stats.record_attempt_duration_ms("openai", 42.0);

        let h = handles.for_cluster("openai").unwrap();
        let snapshot = registry.histogram_snapshot(h.rq_time);
        assert_eq!(snapshot.count, 1);
        assert_eq!(snapshot.sum, 42.0);
    }

    // ---- WP-23 increment 6b: DownstreamStats -----------------------------

    #[test]
    fn record_connection_accepted_increments_the_resolved_counter() {
        let control = StatsControl::new(1);
        let handles = Arc::new(DownstreamStatHandles::build(&control, ["ingress"]));
        let registry = control.registry();
        let stats = DownstreamStats::new(registry.clone(), handles.clone(), WorkerId(0));

        stats.record_connection_accepted("ingress");
        stats.record_connection_accepted("ingress");

        let h = handles.for_listener("ingress").unwrap();
        assert_eq!(registry.value(h.cx_total), 2);
    }

    #[test]
    fn record_connection_accepted_on_an_unknown_listener_does_not_panic() {
        let control = StatsControl::new(1);
        let handles = Arc::new(DownstreamStatHandles::build(&control, ["ingress"]));
        let registry = control.registry();
        let stats = DownstreamStats::new(registry, handles, WorkerId(0));

        // Must not panic -- "ingress" is known, "admin" is not.
        stats.record_connection_accepted("admin");
    }

    #[test]
    fn downstream_resolve_missing_adds_a_new_listener_without_disturbing_existing_ones() {
        let control = StatsControl::new(1);
        let handles = Arc::new(DownstreamStatHandles::build(&control, ["ingress"]));
        let registry = control.registry();
        let stats = DownstreamStats::new(registry.clone(), handles.clone(), WorkerId(0));
        stats.record_connection_accepted("ingress");

        // Simulates a SIGHUP reload's snapshot naming a listener this table
        // never saw at boot.
        handles.resolve_missing(&control, ["ingress", "admin"]);

        assert!(handles.for_listener("admin").is_some());
        let h = handles.for_listener("ingress").unwrap();
        assert_eq!(
            registry.value(h.cx_total),
            1,
            "resolve_missing must not disturb an existing listener's already-counted total"
        );
    }

    // ---- WP-23 increment 6b: GenAiTokenStats ------------------------------

    fn sample_tokens() -> LlmTokens {
        LlmTokens {
            input: 40,
            cached: 10,
            cache_creation: 0,
            output: 7,
        }
    }

    #[test]
    fn record_usage_adds_each_bucket_to_its_own_series() {
        let control = StatsControl::new(1);
        let handles = Arc::new(TokenUsageStatHandles::build(&control, ["openai"]));
        let registry = control.registry();
        let stats = GenAiTokenStats::new(registry.clone(), handles.clone(), WorkerId(0));

        stats.record_usage("openai", sample_tokens());

        let h = handles.for_provider("openai").unwrap();
        assert_eq!(registry.value(h.input), 40);
        assert_eq!(registry.value(h.cached), 10);
        assert_eq!(registry.value(h.cache_creation), 0);
        assert_eq!(registry.value(h.output), 7);
    }

    #[test]
    fn record_usage_sums_across_calls_not_a_collapsed_total() {
        let control = StatsControl::new(1);
        let handles = Arc::new(TokenUsageStatHandles::build(&control, ["openai"]));
        let registry = control.registry();
        let stats = GenAiTokenStats::new(registry.clone(), handles.clone(), WorkerId(0));

        stats.record_usage("openai", sample_tokens());
        stats.record_usage("openai", sample_tokens());

        // Each bucket accumulates independently -- proves the four `incr`
        // calls are wired to four distinct handles, not one shared one that
        // would just double whichever bucket happened to be resolved last.
        let h = handles.for_provider("openai").unwrap();
        assert_eq!(registry.value(h.input), 80);
        assert_eq!(registry.value(h.output), 14);
    }

    #[test]
    fn record_usage_on_an_unknown_provider_does_not_panic() {
        let control = StatsControl::new(1);
        let handles = Arc::new(TokenUsageStatHandles::build(&control, ["openai"]));
        let registry = control.registry();
        let stats = GenAiTokenStats::new(registry, handles, WorkerId(0));

        // Must not panic -- "openai" is known, "anthropic" is not.
        stats.record_usage("anthropic", sample_tokens());
    }
}
