//! The router-side half of wiring the stats registry to
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
//! that module's docs). [`StatHandles::build`] is the
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
//! A miss also happens for a name that WAS configured: once a name is absent
//! from two consecutive configs, the registry drains its series and
//! `resolve_missing` drops the entry, but a minutes-long stream dialled
//! before that still finishes against it. Under config churn those names are
//! unbounded, so the per-worker dedup sets hold at most
//! `UNKNOWN_NAME_WARN_CAP` names each and then log one line saying further
//! names are suppressed (see `UnknownNames`).
//!
//! # The other two instruments
//!
//! [`DownstreamStatHandles`]/[`DownstreamStats`] and
//! [`TokenUsageStatHandles`]/[`GenAiTokenStats`] mirror
//! [`StatHandles`]/[`RouterStats`]'s shape exactly (same
//! resolve-once-at-boot, `ArcSwap`-not-`Mutex`, warn-once-on-a-miss rules),
//! just for `DOWNSTREAM_CX_TOTAL{listener}` (`crate::listener`'s accept
//! loop, `proxy-core`) and `LLM_CLIENT_TOKEN_USAGE{provider,type,tenant}`
//! (`crate::access_logging::LoggingBody::finish`) respectively, instead of
//! `UPSTREAM_RQ`/`UPSTREAM_RQ_TIME`. See each type's own doc for what's
//! different: a single instrument keyed by listener name for the first, and
//! four handles per provider (one per token bucket) for the second.
//!
//! # `tenant` is the one attribute this file resolves OFF the boot
//! control side
//!
//! Every other resolve in this module happens once, at boot (or on a SIGHUP
//! reload), against this process's own config -- exactly the "why resolution
//! happens once, at boot" section above. `tenant` cannot follow that rule:
//! it comes from a caller's credential
//! (`proxy_http::stream_info::AuthInfo::tenant`), so it isn't known until a
//! request actually authenticates. [`GenAiTokenStats::record_usage`] resolves
//! it per call, via [`proxy_observability::stats::Registry::resolve_capped_memo`]
//! -- reachable from a worker's plain `Arc<Registry>`, unlike the general
//! `resolve`, and capped so a caller cannot grow the registry without bound
//! (see that method's doc). A per-worker memo serves a tenant already seen,
//! so only a new tenant takes the registry's lock. [`TokenUsageStatHandles`] still pre-resolves,
//! at boot, the ONE tenant value that IS known ahead of time for every
//! provider: "no tenant at all"
//! (`instruments::LLM_CLIENT_TOKEN_USAGE_NO_TENANT`) -- unauthenticated
//! traffic is the common case and stays on the fast, boot-resolved path.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use proxy_observability::access_log::LlmTokens;
use proxy_observability::stats::{
    instruments, record_tenant_credential_request, Handle, HandleMemo, HistogramHandle, Instrument,
    InstrumentKind, Registry, StatsControl, WorkerId,
};

/// Requests refused with 400 because of the configured `max_output_tokens`
/// cap: a limit above it, a repeated limit key, or one that is not a
/// non-negative integer. Defined beside the router that records it. No labels:
/// model, tenant and route are unbounded or config-sized and belong in usage
/// records. Prometheus surface only.
pub const MAX_OUTPUT_TOKENS_REJECTED: Instrument = Instrument {
    name: "llmproxy_router_max_output_tokens_rejected_total",
    kind: InstrumentKind::Counter,
    unit: "{request}",
    attribute_keys: &[],
    buckets: None,
};

/// How many distinct unknown names each per-worker dedup set remembers, and
/// so warns about, before it stops growing. Names are configured, not
/// client-supplied, so a real deployment that misses this many is already
/// churning clusters; the cap bounds memory, and the first name past it logs
/// one suppression line so the gap stays visible.
const UNKNOWN_NAME_WARN_CAP: usize = 64;

/// What a recorder should log for a lookup miss on one name.
#[derive(Debug, PartialEq, Eq)]
enum UnknownNameWarning {
    /// First miss on this name, and the set has room: warn naming it.
    First,
    /// First miss on a name after the set filled: log the one suppression
    /// line, which names no label value.
    CapReached,
    /// Already warned about this name, or already logged the suppression
    /// line: stay silent.
    Silent,
}

/// The warn-once dedup state behind every recorder's lookup-miss path,
/// bounded by [`UNKNOWN_NAME_WARN_CAP`]. AGENTS.md "Fail-open controls":
/// repeats are suppressed so the log does not become the incident, and the
/// state is touched only on a miss, never on the healthy lookup-hit path.
///
/// Rust note: interior mutability because the recorders take `&self` (they
/// are shared behind `Arc`, same shape as `ClusterManager`), so mutating
/// the set through a shared reference needs a lock. Only the rare miss path
/// takes it, so a `Mutex` costs nothing that matters.
#[derive(Default)]
struct UnknownNames(Mutex<UnknownNamesState>);

#[derive(Default)]
struct UnknownNamesState {
    names: HashSet<String>,
    suppressed: bool,
}

impl UnknownNames {
    fn note(&self, name: &str) -> UnknownNameWarning {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if state.names.contains(name) {
            UnknownNameWarning::Silent
        } else if state.names.len() < UNKNOWN_NAME_WARN_CAP {
            state.names.insert(name.to_string());
            UnknownNameWarning::First
        } else if !state.suppressed {
            state.suppressed = true;
            UnknownNameWarning::CapReached
        } else {
            UnknownNameWarning::Silent
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .names
            .len()
    }
}

/// Logs the one line a recorder emits when its [`UnknownNames`] set fills.
/// `kind` is a fixed word ("cluster", "listener", "provider"), never a name.
fn warn_unknown_names_suppressed(kind: &'static str) {
    tracing::warn!(
        kind,
        cap = UNKNOWN_NAME_WARN_CAP,
        "stats: already warned about the maximum number of unknown names of this kind on \
         this worker -- traffic to further unknown names is still not counted in /stats, \
         but is no longer logged"
    );
}

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
    ///
    /// Also drops every entry whose handles went stale: the registry drained
    /// that series after its name was absent from two consecutive configs
    /// (see `proxy_observability::stats`' "Series are retired, drained, then
    /// reused"). A stale handle records nothing, so a name that returns must
    /// be resolved again rather than skipped as present. An absent name that
    /// is not drained yet keeps its entry, so a request still finishing
    /// against it counts into its hidden series.
    pub fn resolve_missing<'a>(
        &self,
        control: &StatsControl,
        cluster_names: impl IntoIterator<Item = &'a str>,
    ) {
        let current = self.by_cluster.load();
        let mut next: HashMap<String, ClusterStatHandles> = (**current).clone();
        let registry = control.registry();
        next.retain(|_, h| registry.is_current(h.rq) && registry.is_current_histogram(h.rq_time));
        let mut changed = next.len() != current.len();
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
    warned_unknown_clusters: UnknownNames,
    rejected_memo: HandleMemo<Handle>,
}

impl RouterStats {
    pub fn new(registry: Arc<Registry>, handles: Arc<StatHandles>, worker: WorkerId) -> Self {
        Self {
            registry,
            handles,
            worker,
            warned_unknown_clusters: UnknownNames::default(),
            rejected_memo: HandleMemo::new(),
        }
    }

    /// Counts one request refused by the output-token cap. The series carries
    /// no labels, so it is resolved once per worker through the memo and later
    /// calls skip the registry's lock.
    pub fn record_output_cap_rejected(&self) {
        let handle = self.registry.resolve_capped_memo(
            &self.rejected_memo,
            &MAX_OUTPUT_TOKENS_REJECTED,
            &[],
            1,
            &[],
        );
        self.registry.incr(self.worker, handle, 1);
    }

    /// The shared [`Registry`] this recorder writes into -- a plain `Arc`
    /// clone (pointer bump). Exposed mainly for tests that need to render
    /// (`proxy_observability::stats::envoy_render::render`) or otherwise
    /// inspect what got recorded; production code reaches the same registry
    /// through `proxy-admin`'s `/stats` route, not through this accessor.
    pub fn registry(&self) -> Arc<Registry> {
        self.registry.clone()
    }

    /// Counts one tenant-mode credential decision (`applied`, `missing`, or
    /// `unusable`) against `provider`. Called only from the router's
    /// tenant-mode credential steps, so platform-mode requests never reach
    /// it. See `proxy_observability::stats::record_tenant_credential_request`
    /// for why the series is resolved per call.
    pub fn record_tenant_credential(&self, provider: &str, outcome: &'static str) {
        record_tenant_credential_request(&self.registry, self.worker, provider, outcome);
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
    #[cfg(test)]
    pub(crate) fn rq_time_observation_count(&self, cluster: &str) -> Option<u64> {
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
        match self.warned_unknown_clusters.note(cluster) {
            UnknownNameWarning::First => tracing::warn!(
                cluster,
                "stats: no resolved upstream_rq/upstream_rq_time handles for this cluster -- \
                 traffic to it will not be counted in /stats (no applied config has named \
                 the cluster yet, or it left the config and its series was retired)"
            ),
            UnknownNameWarning::CapReached => warn_unknown_names_suppressed("cluster"),
            UnknownNameWarning::Silent => {}
        }
    }
}

/// One listener's pre-resolved `downstream_cx_total`,
/// `downstream_global_cx_overflow` and
/// `downstream_cx_transport_socket_connect_timeout` handles.
#[derive(Debug, Clone, Copy)]
pub struct ListenerStatHandles {
    pub cx_total: Handle,
    pub global_cx_overflow: Handle,
    pub transport_socket_connect_timeout: Handle,
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
    /// doc for why copying the map here is safe and cheap, and why stale
    /// entries are dropped first.
    pub fn resolve_missing<'a>(
        &self,
        control: &StatsControl,
        listener_names: impl IntoIterator<Item = &'a str>,
    ) {
        let current = self.by_listener.load();
        let mut next: HashMap<String, ListenerStatHandles> = (**current).clone();
        let registry = control.registry();
        next.retain(|_, h| {
            registry.is_current(h.cx_total) && registry.is_current(h.global_cx_overflow)
        });
        let mut changed = next.len() != current.len();
        for name in listener_names {
            if next.contains_key(name) {
                continue;
            }
            let cx_total =
                control.resolve(&instruments::DOWNSTREAM_CX_TOTAL, &[("listener", name)]);
            let global_cx_overflow = control.resolve(
                &instruments::DOWNSTREAM_GLOBAL_CX_OVERFLOW,
                &[("listener", name)],
            );
            let transport_socket_connect_timeout = control.resolve(
                &instruments::DOWNSTREAM_CX_TRANSPORT_SOCKET_CONNECT_TIMEOUT,
                &[("listener", name)],
            );
            next.insert(
                name.to_string(),
                ListenerStatHandles {
                    cx_total,
                    global_cx_overflow,
                    transport_socket_connect_timeout,
                },
            );
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
    warned_unknown_listeners: UnknownNames,
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
            warned_unknown_listeners: UnknownNames::default(),
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

    /// Records one connection closed at accept because the global
    /// downstream connection limit was reached (Envoy's
    /// `downstream_global_cx_overflow`). Such a connection is never passed
    /// to [`Self::record_connection_accepted`].
    pub fn record_global_cx_overflow(&self, listener: &str) {
        match self.handles.for_listener(listener) {
            Some(h) => self.registry.incr(self.worker, h.global_cx_overflow, 1),
            None => self.warn_unknown_listener_once(listener),
        }
    }

    /// Records one accepted connection closed because its transport socket
    /// (TLS) handshake missed the filter chain's
    /// `transport_socket_connect_timeout` (Envoy's
    /// `downstream_cx_transport_socket_connect_timeout`). The connection was
    /// already counted by [`Self::record_connection_accepted`].
    pub fn record_transport_socket_connect_timeout(&self, listener: &str) {
        match self.handles.for_listener(listener) {
            Some(h) => self
                .registry
                .incr(self.worker, h.transport_socket_connect_timeout, 1),
            None => self.warn_unknown_listener_once(listener),
        }
    }

    fn warn_unknown_listener_once(&self, listener: &str) {
        match self.warned_unknown_listeners.note(listener) {
            UnknownNameWarning::First => tracing::warn!(
                listener,
                "stats: no resolved downstream_cx_total handle for this listener -- \
                 connections accepted on it will not be counted in /stats (no applied config has named \
                 the listener yet, or it left the config and its series was retired)"
            ),
            UnknownNameWarning::CapReached => warn_unknown_names_suppressed("listener"),
            UnknownNameWarning::Silent => {}
        }
    }
}

/// Four pre-resolved `llm.client.token.usage` handles, one per token bucket
/// `LlmTokenUsage`/[`LlmTokens`] carries, ALL sharing the same `provider`
/// and `tenant` attribute values. [`TokenUsageStatHandles::for_provider`]
/// hands back the sentinel-tenant ("no authenticated caller") set;
/// [`GenAiTokenStats::record_usage`] builds the real-tenant equivalent
/// per call, via [`Registry::resolve_capped`] -- see that method's doc and
/// the module doc's `tenant` section for why this one attribute can't be
/// pre-resolved at boot the way the other two are.
#[derive(Debug, Clone, Copy)]
pub struct TokenUsageHandles {
    pub input: Handle,
    pub output: Handle,
    pub cached: Handle,
    pub cache_creation: Handle,
}

/// Provider (= cluster) name -> [`TokenUsageHandles`] resolved for
/// [`instruments::LLM_CLIENT_TOKEN_USAGE_NO_TENANT`] (the one tenant
/// value known ahead of time, for unauthenticated traffic), mirroring
/// [`StatHandles`]'s `by_cluster` table shape and cadence exactly -- see that
/// struct's doc. Also doubles as the "is this a known provider at all" gate
/// [`GenAiTokenStats::record_usage`] checks before resolving anything
/// tenant-specific -- an unresolved provider must stay a no-op regardless of
/// tenant.
pub struct TokenUsageStatHandles {
    by_provider: ArcSwap<HashMap<String, TokenUsageHandles>>,
}

impl TokenUsageStatHandles {
    /// Resolves the sentinel-tenant `llm.client.token.usage` series for
    /// every name in `provider_names` (the boot snapshot's cluster names --
    /// any cluster can be the member a request actually dials,
    /// AGENTS.md invariant 6) against `control`. Called once, at boot.
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

    /// Resolves the sentinel-tenant buckets for every name in
    /// `provider_names` this table doesn't already have an entry for.
    /// Called again on a SIGHUP reload, and drops stale entries first, same
    /// as [`StatHandles::resolve_missing`] -- see that doc.
    pub fn resolve_missing<'a>(
        &self,
        control: &StatsControl,
        provider_names: impl IntoIterator<Item = &'a str>,
    ) {
        let current = self.by_provider.load();
        let mut next: HashMap<String, TokenUsageHandles> = (**current).clone();
        let registry = control.registry();
        next.retain(|_, h| {
            [h.input, h.output, h.cached, h.cache_creation]
                .into_iter()
                .all(|handle| registry.is_current(handle))
        });
        let mut changed = next.len() != current.len();
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
                    &instruments::LLM_CLIENT_TOKEN_USAGE,
                    &[
                        ("provider", name),
                        ("type", bucket),
                        ("tenant", instruments::LLM_CLIENT_TOKEN_USAGE_NO_TENANT),
                    ],
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

    /// Looks up `provider`'s pre-resolved (sentinel-tenant) handles, or
    /// `None` if this table was never told about that provider.
    pub fn for_provider(&self, provider: &str) -> Option<TokenUsageHandles> {
        self.by_provider.load().get(provider).copied()
    }
}

/// `crate::access_logging::LoggingBody::finish`'s recorder for
/// `llm.client.token.usage`: one instance per worker (bakes in that
/// worker's own `WorkerId`, same shape as [`RouterStats`]/[`DownstreamStats`]),
/// reached via `crate::filter_manager::FilterChainHandler`'s stored
/// `Arc<GenAiTokenStats>` (see [`crate::filter_manager::FilterChainHandler::with_token_stats`]).
/// A no-op, not a panic, for a provider this table never resolved handles
/// for -- warns at most once per unique unknown name, up to
/// `UNKNOWN_NAME_WARN_CAP` names.
pub struct GenAiTokenStats {
    registry: Arc<Registry>,
    handles: Arc<TokenUsageStatHandles>,
    worker: WorkerId,
    warned_unknown_providers: UnknownNames,
    /// Worker-local memo of `(provider, type, tenant)` -> handle, in front of
    /// `resolve_capped`. A tenant seen before records without the registry's
    /// process-wide lock; a tenant folded into the overflow series is never
    /// memoized, so it is retried once retirement frees a slot.
    tenant_memo: HandleMemo<Handle>,
}

/// Upper bound for each GenAI latency histogram's model-labelled series.
/// `requested_model` is body-derived but still supplied by callers, unlike a
/// cluster name from this process's configuration. Once the ceiling is hit,
/// new model values fold into one visible overflow series instead of growing
/// the registry without bound.
pub const GEN_AI_LATENCY_MODEL_CARDINALITY_CEILING: usize = 1_000;
pub const GEN_AI_LATENCY_MODEL_CARDINALITY_OVERFLOW: &str = "-cardinality-overflow-";

/// Records OTel GenAI latency histograms at stream completion. Unlike token
/// usage, model labels cannot be resolved at boot: the model is extracted
/// from each request body by the body-rewrite filter. `resolve_histogram_capped`
/// is therefore intentionally the only request-path resolution involved.
pub struct GenAiLatencyStats {
    registry: Arc<Registry>,
    worker: WorkerId,
    /// Worker-local memos in front of `resolve_histogram_capped`, one per
    /// instrument, so a model seen before records without the registry's
    /// process-wide lock. See `proxy_observability::stats::HandleMemo`.
    ttft_memo: HandleMemo<HistogramHandle>,
    tpot_memo: HandleMemo<HistogramHandle>,
}

impl GenAiLatencyStats {
    pub fn new(registry: Arc<Registry>, worker: WorkerId) -> Self {
        Self {
            registry,
            worker,
            ttft_memo: HandleMemo::new(),
            tpot_memo: HandleMemo::new(),
        }
    }

    /// Records the semconv-v1.27 TTFT histogram whenever the response
    /// successfully reached a first body byte. Records TPOT only when the
    /// provider reported at least two output tokens and the total duration is
    /// no shorter than TTFT: semconv defines it as time *after the first
    /// token*, divided by output tokens after that first token.
    pub fn record(
        &self,
        operation: &str,
        model: &str,
        system: &str,
        time_to_first_body_byte: Option<Duration>,
        stream_duration: Duration,
        output_tokens: Option<u64>,
    ) {
        let attrs = [
            ("gen_ai.operation.name", operation),
            ("gen_ai.request.model", model),
            ("gen_ai.system", system),
        ];
        let overflow_attrs = [
            ("gen_ai.operation.name", operation),
            (
                "gen_ai.request.model",
                GEN_AI_LATENCY_MODEL_CARDINALITY_OVERFLOW,
            ),
            ("gen_ai.system", system),
        ];

        if let Some(ttft) = time_to_first_body_byte {
            let handle = self.registry.resolve_histogram_capped_memo(
                &self.ttft_memo,
                &instruments::GEN_AI_SERVER_TIME_TO_FIRST_TOKEN,
                &attrs,
                GEN_AI_LATENCY_MODEL_CARDINALITY_CEILING,
                &overflow_attrs,
            );
            self.registry
                .observe(self.worker, handle, ttft.as_secs_f64());
        }

        let Some(output_tokens) = output_tokens.filter(|&n| n >= 2) else {
            return;
        };
        let Some(ttft) = time_to_first_body_byte else {
            return;
        };
        let Some(after_first) = stream_duration.checked_sub(ttft) else {
            return;
        };
        let handle = self.registry.resolve_histogram_capped_memo(
            &self.tpot_memo,
            &instruments::GEN_AI_SERVER_TIME_PER_OUTPUT_TOKEN,
            &attrs,
            GEN_AI_LATENCY_MODEL_CARDINALITY_CEILING,
            &overflow_attrs,
        );
        self.registry.observe(
            self.worker,
            handle,
            after_first.as_secs_f64() / (output_tokens - 1) as f64,
        );
    }
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
            warned_unknown_providers: UnknownNames::default(),
            tenant_memo: HandleMemo::new(),
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
    /// dialled, never the routed cluster name -- see AGENTS.md invariant 6. A
    /// no-op, not a panic, for an unresolved provider -- checked BEFORE
    /// `tenant` is even looked at, so an unknown provider stays silent
    /// regardless of tenant.
    ///
    /// `tenant` is `StreamInfo::auth.tenant` verbatim (see
    /// `access_logging::LoggingBody::finish`'s call site), never a
    /// `LimitKey`/`CredentialDigest` or anything else credential-shaped --
    /// `AuthInfo::tenant` is a plain `Option<String>`, the identifier the
    /// auth filter resolved, not the credential that resolved it. `None`
    /// uses the pre-resolved sentinel-tenant handles
    /// (`self.handles.for_provider`, the boot-resolved fast path);
    /// `Some` resolves per call, capped, via
    /// [`Registry::resolve_capped`] -- see the module doc's `tenant` section
    /// for why this ONE attribute can't be pre-resolved at boot.
    pub fn record_usage(&self, provider: &str, tenant: Option<&str>, tokens: LlmTokens) {
        let Some(no_tenant) = self.handles.for_provider(provider) else {
            self.warn_unknown_provider_once(provider);
            return;
        };
        let h = match tenant {
            None => no_tenant,
            Some(tenant_id) => self.resolve_tenant_handles(provider, tenant_id),
        };
        self.registry.incr(self.worker, h.input, tokens.input);
        self.registry.incr(self.worker, h.output, tokens.output);
        self.registry.incr(self.worker, h.cached, tokens.cached);
        self.registry
            .incr(self.worker, h.cache_creation, tokens.cache_creation);
    }

    /// The dynamic half of tenant resolution -- called once per
    /// [`Self::record_usage`] when `tenant` is `Some`. A series this worker
    /// has seen is served from `tenant_memo`; only a new one (or one folded
    /// into the overflow series) reaches `Registry::resolve_capped` and its
    /// process-wide lock. `provider` is assumed already known (`record_usage`
    /// checks that first), so every bucket resolved here is real, budgeted
    /// growth or a reuse of the shared overflow series -- never wasted on a
    /// provider this process doesn't serve.
    fn resolve_tenant_handles(&self, provider: &str, tenant: &str) -> TokenUsageHandles {
        // Rust note: `overflow_attrs` is built INSIDE the closure, one array
        // per call, rather than factored into its own closure returning
        // `[(&str, &str); 3]` -- that shape ties the returned array's
        // lifetime to the closure parameter `bucket`'s own per-call
        // lifetime, and a plain (non-generic) closure can't be generic over
        // that the way a `fn` can, so the borrow checker can't unify it
        // across the four calls below. Inlining sidesteps the question
        // entirely: each call's `overflow_attrs` only needs to live for the
        // one `resolve_capped` call that borrows it.
        let resolve_bucket = |bucket: &str| {
            let overflow_attrs = [
                ("provider", provider),
                ("type", bucket),
                (
                    "tenant",
                    instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW,
                ),
            ];
            self.registry.resolve_capped_memo(
                &self.tenant_memo,
                &instruments::LLM_CLIENT_TOKEN_USAGE,
                &[("provider", provider), ("type", bucket), ("tenant", tenant)],
                instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CEILING,
                &overflow_attrs,
            )
        };
        TokenUsageHandles {
            input: resolve_bucket("input"),
            output: resolve_bucket("output"),
            cached: resolve_bucket("cached"),
            cache_creation: resolve_bucket("cache_creation"),
        }
    }

    fn warn_unknown_provider_once(&self, provider: &str) {
        match self.warned_unknown_providers.note(provider) {
            UnknownNameWarning::First => tracing::warn!(
                provider,
                "stats: no resolved llm.client.token.usage handles for this provider -- \
                 token usage will not be counted in /stats (no applied config has named the \
                 cluster yet, or it left the config and its series was retired)"
            ),
            UnknownNameWarning::CapReached => warn_unknown_names_suppressed("provider"),
            UnknownNameWarning::Silent => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn latency_histogram(
        registry: &Registry,
        name: &str,
    ) -> (
        HistogramHandle,
        proxy_observability::stats::HistogramSnapshot,
    ) {
        let (handle, _, _) = registry
            .histograms()
            .find(|(_, instrument, _)| instrument.name == name)
            .unwrap_or_else(|| panic!("missing histogram {name}"));
        let snapshot = registry.histogram_snapshot(handle);
        (handle, snapshot)
    }

    #[test]
    fn gen_ai_latency_records_semconv_ttft_and_tpot_with_correct_units_and_formula() {
        let control = StatsControl::new(1);
        let registry = control.registry();
        let stats = GenAiLatencyStats::new(registry.clone(), WorkerId(0));

        stats.record(
            "chat",
            "gpt-4o",
            "openai",
            Some(Duration::from_millis(100)),
            Duration::from_secs(1),
            Some(5),
        );

        let (_, ttft) = latency_histogram(&registry, "gen_ai.server.time_to_first_token");
        assert_eq!(ttft.count, 1);
        assert!((ttft.sum - 0.1).abs() < f64::EPSILON, "TTFT is seconds");

        let (_, tpot) = latency_histogram(&registry, "gen_ai.server.time_per_output_token");
        assert_eq!(tpot.count, 1);
        assert!(
            (tpot.sum - 0.225).abs() < f64::EPSILON,
            "(1.0 - 0.1) / (5 - 1) seconds"
        );
    }

    #[test]
    fn gen_ai_latency_does_not_invent_tpot_without_two_output_tokens() {
        let control = StatsControl::new(1);
        let registry = control.registry();
        let stats = GenAiLatencyStats::new(registry.clone(), WorkerId(0));

        stats.record(
            "chat",
            "gpt-4o",
            "openai",
            Some(Duration::from_millis(100)),
            Duration::from_secs(1),
            Some(1),
        );

        let (_, ttft) = latency_histogram(&registry, "gen_ai.server.time_to_first_token");
        assert_eq!(ttft.count, 1);
        assert!(
            registry
                .histograms()
                .all(|(_, instrument, _)| instrument.name != "gen_ai.server.time_per_output_token"),
            "one output token leaves no post-first-token duration to report"
        );
    }

    fn control_and_handles(names: &[&str]) -> (StatsControl, Arc<StatHandles>) {
        let control = StatsControl::new(1);
        let handles = Arc::new(StatHandles::build(&control, names.iter().copied()));
        (control, handles)
    }

    /// A `tracing` writer that appends to a shared buffer.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `f` under a subscriber that captures every log line, and returns
    /// those lines.
    fn capture_logs(f: impl FnOnce()) -> Vec<String> {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = captured.0.lock().unwrap().clone();
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn count_containing(lines: &[String], needle: &str) -> usize {
        lines.iter().filter(|l| l.contains(needle)).count()
    }

    const CLUSTER_MISS: &str = "no resolved upstream_rq/upstream_rq_time handles";
    const LISTENER_MISS: &str = "no resolved downstream_cx_total handle";
    const PROVIDER_MISS: &str = "no resolved llm.client.token.usage handles";
    const SUPPRESSED: &str = "maximum number of unknown names";

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
    fn a_name_that_returns_after_its_series_was_freed_records_again() {
        let control = StatsControl::new(1);
        let registry = control.registry();
        let router = Arc::new(StatHandles::build(&control, ["gone"]));
        let downstream = Arc::new(DownstreamStatHandles::build(&control, ["gone"]));
        let token_usage = Arc::new(TokenUsageStatHandles::build(&control, ["gone"]));
        let router_stats = RouterStats::new(registry.clone(), router.clone(), WorkerId(0));
        let downstream_stats =
            DownstreamStats::new(registry.clone(), downstream.clone(), WorkerId(0));
        let token_stats = GenAiTokenStats::new(registry.clone(), token_usage.clone(), WorkerId(0));

        // The config apply order: scope first, then the table refreshes.
        let apply = |names: &[&str]| {
            let set: HashSet<String> = names.iter().map(|n| n.to_string()).collect();
            control.set_live_scope(proxy_observability::stats::LiveScope {
                clusters: Some(set.clone()),
                listeners: Some(set),
                ..Default::default()
            });
            router.resolve_missing(&control, names.iter().copied());
            downstream.resolve_missing(&control, names.iter().copied());
            token_usage.resolve_missing(&control, names.iter().copied());
        };
        apply(&[]);
        apply(&[]); // absent from two configs: drained and freed
        apply(&["gone"]);

        router_stats.record_attempt("gone");
        downstream_stats.record_connection_accepted("gone");
        token_stats.record_usage("gone", None, sample_tokens());
        let total = |name: &str| -> u64 {
            registry
                .counters()
                .filter(|(instrument, _, _)| instrument.name == name)
                .map(|(_, _, value)| value)
                .sum()
        };
        assert_eq!(total("upstream_rq"), 1, "a stale table entry drops writes");
        assert_eq!(total("downstream_cx_total"), 1);
        assert_eq!(total("llm.client.token.usage"), 40 + 10 + 7);
    }

    #[test]
    fn churned_out_names_warn_within_a_bounded_set_then_one_suppression_line() {
        // More removed names than the dedup cap, each configured once and
        // then pruned by two configs that omit it: the case of a long
        // stream finishing against a cluster that left the config.
        let churned: Vec<String> = (0..UNKNOWN_NAME_WARN_CAP + 10)
            .map(|i| format!("churned-{i}"))
            .collect();
        let control = StatsControl::new(1);
        let registry = control.registry();
        let names = || churned.iter().map(String::as_str).chain(["kept"]);
        let router = Arc::new(StatHandles::build(&control, names()));
        let downstream = Arc::new(DownstreamStatHandles::build(&control, names()));
        let token_usage = Arc::new(TokenUsageStatHandles::build(&control, names()));
        let router_stats = RouterStats::new(registry.clone(), router.clone(), WorkerId(0));
        let downstream_stats =
            DownstreamStats::new(registry.clone(), downstream.clone(), WorkerId(0));
        let token_stats = GenAiTokenStats::new(registry.clone(), token_usage.clone(), WorkerId(0));
        let apply_only_kept = || {
            let kept: HashSet<String> = ["kept".to_string()].into();
            control.set_live_scope(proxy_observability::stats::LiveScope {
                clusters: Some(kept.clone()),
                listeners: Some(kept),
                ..Default::default()
            });
            router.resolve_missing(&control, ["kept"]);
            downstream.resolve_missing(&control, ["kept"]);
            token_usage.resolve_missing(&control, ["kept"]);
        };
        let record_all = |name: &str| {
            router_stats.record_attempt(name);
            downstream_stats.record_connection_accepted(name);
            token_stats.record_usage(name, None, sample_tokens());
        };

        // Absent from one config: the entry stays, so a finishing request
        // still counts into the hidden series and nothing warns.
        apply_only_kept();
        let logs = capture_logs(|| record_all("churned-0"));
        assert!(logs.is_empty(), "{logs:?}");

        // Absent from a second config: drained and pruned.
        apply_only_kept();
        assert!(router.for_cluster("churned-0").is_none());
        let logs = capture_logs(|| {
            for name in &churned {
                record_all(name);
                record_all(name);
                record_all("kept");
            }
        });

        for (miss, kind) in [
            (CLUSTER_MISS, "cluster"),
            (LISTENER_MISS, "listener"),
            (PROVIDER_MISS, "provider"),
        ] {
            let named: Vec<&String> = logs.iter().filter(|l| l.contains(miss)).collect();
            assert_eq!(named.len(), UNKNOWN_NAME_WARN_CAP, "{kind}: {logs:?}");
            assert!(
                named.iter().all(|l| l.contains("series was retired")),
                "{kind}: the warning must cover a retired name: {named:?}"
            );
            let suppressed: Vec<&String> = logs
                .iter()
                .filter(|l| l.contains(SUPPRESSED) && l.contains(kind))
                .collect();
            assert_eq!(suppressed.len(), 1, "{kind}: {logs:?}");
            assert!(
                !suppressed[0].contains("churned-"),
                "the suppression line names no label value: {suppressed:?}"
            );
        }
        assert_eq!(count_containing(&logs, "kept"), 0, "a hit never warns");
        assert_eq!(
            router_stats.warned_unknown_clusters.len(),
            UNKNOWN_NAME_WARN_CAP
        );
        assert_eq!(
            downstream_stats.warned_unknown_listeners.len(),
            UNKNOWN_NAME_WARN_CAP
        );
        assert_eq!(
            token_stats.warned_unknown_providers.len(),
            UNKNOWN_NAME_WARN_CAP
        );
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
    fn record_attempt_on_an_unknown_cluster_bumps_nothing_and_warns_once() {
        // Reload-race fail-soft: "openai" is known, "anthropic" is not.
        let (control, handles) = control_and_handles(&["openai"]);
        let registry = control.registry();
        let stats = RouterStats::new(registry.clone(), handles.clone(), WorkerId(0));

        let logs = capture_logs(|| {
            stats.record_attempt("anthropic");
            stats.record_attempt("anthropic");
            stats.record_attempt_duration_ms("anthropic", 12.0);
        });

        let h = handles.for_cluster("openai").unwrap();
        assert_eq!(registry.value(h.rq), 0);
        assert_eq!(registry.histogram_snapshot(h.rq_time).count, 0);
        assert!(handles.for_cluster("anthropic").is_none());
        assert_eq!(count_containing(&logs, CLUSTER_MISS), 1, "{logs:?}");
        assert_eq!(count_containing(&logs, "anthropic"), 1, "{logs:?}");
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

    // ---- DownstreamStats -----------------------------

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
    fn record_connection_accepted_on_an_unknown_listener_bumps_nothing_and_warns_once() {
        let control = StatsControl::new(1);
        let handles = Arc::new(DownstreamStatHandles::build(&control, ["ingress"]));
        let registry = control.registry();
        let stats = DownstreamStats::new(registry.clone(), handles.clone(), WorkerId(0));

        // "ingress" is known, "admin" is not.
        let logs = capture_logs(|| {
            stats.record_connection_accepted("admin");
            stats.record_connection_accepted("admin");
        });

        let h = handles.for_listener("ingress").unwrap();
        assert_eq!(registry.value(h.cx_total), 0);
        assert!(handles.for_listener("admin").is_none());
        assert_eq!(count_containing(&logs, LISTENER_MISS), 1, "{logs:?}");
        assert_eq!(count_containing(&logs, "admin"), 1, "{logs:?}");
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

    // ---- GenAiTokenStats ------------------------------

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

        stats.record_usage("openai", None, sample_tokens());

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

        stats.record_usage("openai", None, sample_tokens());
        stats.record_usage("openai", None, sample_tokens());

        // Each bucket accumulates independently -- proves the four `incr`
        // calls are wired to four distinct handles, not one shared one that
        // would just double whichever bucket happened to be resolved last.
        let h = handles.for_provider("openai").unwrap();
        assert_eq!(registry.value(h.input), 80);
        assert_eq!(registry.value(h.output), 14);
    }

    #[test]
    fn record_usage_on_an_unknown_provider_bumps_nothing_and_warns_once() {
        let control = StatsControl::new(1);
        let handles = Arc::new(TokenUsageStatHandles::build(&control, ["openai"]));
        let registry = control.registry();
        let stats = GenAiTokenStats::new(registry.clone(), handles.clone(), WorkerId(0));

        // "openai" is known, "anthropic" is not. Checked with a real tenant
        // too: an unknown provider must stay silent regardless of the
        // tenant dimension.
        let logs = capture_logs(|| {
            stats.record_usage("anthropic", None, sample_tokens());
            stats.record_usage("anthropic", Some("acme"), sample_tokens());
        });

        let h = handles.for_provider("openai").unwrap();
        assert_eq!(registry.value(h.input), 0);
        assert_eq!(registry.value(h.cached), 0);
        assert_eq!(registry.value(h.cache_creation), 0);
        assert_eq!(registry.value(h.output), 0);
        assert_eq!(count_containing(&logs, PROVIDER_MISS), 1, "{logs:?}");
        assert_eq!(count_containing(&logs, "anthropic"), 1, "{logs:?}");
        assert_eq!(count_containing(&logs, "acme"), 0, "{logs:?}");
    }

    // ---- the `tenant` dimension ------------------------------------

    #[test]
    fn a_known_tenant_gets_its_own_series_carrying_its_own_id() {
        let control = StatsControl::new(1);
        let handles = Arc::new(TokenUsageStatHandles::build(&control, ["openai"]));
        let registry = control.registry();
        let stats = GenAiTokenStats::new(registry.clone(), handles, WorkerId(0));

        stats.record_usage("openai", Some("acme-corp"), sample_tokens());

        // Resolved independently, straight off the instrument's own attrs
        // -- proves the value landed on the wire as the literal tenant id
        // "acme-corp", not a hash, a digest, or a generic "authenticated"
        // marker.
        let independently_resolved = registry.resolve_capped(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", "acme-corp"),
            ],
            instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CEILING,
            &[
                ("provider", "openai"),
                ("type", "input"),
                (
                    "tenant",
                    instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW,
                ),
            ],
        );
        assert_eq!(registry.value(independently_resolved), 40);
    }

    #[test]
    fn two_tenants_of_the_same_provider_get_independent_series() {
        let control = StatsControl::new(1);
        let handles = Arc::new(TokenUsageStatHandles::build(&control, ["openai"]));
        let registry = control.registry();
        let stats = GenAiTokenStats::new(registry.clone(), handles, WorkerId(0));

        stats.record_usage("openai", Some("acme-corp"), sample_tokens());
        stats.record_usage(
            "openai",
            Some("widgetco"),
            LlmTokens {
                input: 1,
                output: 1,
                cached: 0,
                cache_creation: 0,
            },
        );

        let for_tenant = |tenant: &str| {
            registry.resolve_capped(
                &instruments::LLM_CLIENT_TOKEN_USAGE,
                &[
                    ("provider", "openai"),
                    ("type", "input"),
                    ("tenant", tenant),
                ],
                instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CEILING,
                &[
                    ("provider", "openai"),
                    ("type", "input"),
                    (
                        "tenant",
                        instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW,
                    ),
                ],
            )
        };
        assert_eq!(registry.value(for_tenant("acme-corp")), 40);
        assert_eq!(registry.value(for_tenant("widgetco")), 1);
    }

    #[test]
    fn unauthenticated_traffic_still_records_under_the_no_tenant_sentinel() {
        // Requirement 2: usage is not skipped just because there was no
        // authenticated caller -- it lands on the boot-resolved sentinel
        // series (`for_provider`'s own handles), same place it landed before
        // the tenant dimension existed.
        let control = StatsControl::new(1);
        let handles = Arc::new(TokenUsageStatHandles::build(&control, ["openai"]));
        let registry = control.registry();
        let stats = GenAiTokenStats::new(registry.clone(), handles.clone(), WorkerId(0));

        stats.record_usage("openai", None, sample_tokens());

        let h = handles.for_provider("openai").unwrap();
        assert_eq!(
            registry.value(h.input),
            40,
            "unauthenticated usage must still be counted"
        );

        // And it is genuinely a DIFFERENT series from any real tenant's --
        // an unauthenticated caller must never be folded into (or mistaken
        // for) an authenticated tenant's usage.
        let acme = registry.resolve_capped(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", "acme-corp"),
            ],
            instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CEILING,
            &[
                ("provider", "openai"),
                ("type", "input"),
                (
                    "tenant",
                    instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW,
                ),
            ],
        );
        assert_ne!(h.input, acme);
        assert_eq!(registry.value(acme), 0);
    }

    /// Requirement 4 (rule 17: verify in the code, not the comment claiming
    /// it): `record_usage` takes `tenant: Option<&str>` -- a plain string,
    /// the SAME type `StreamInfo::auth.tenant` is. There is no `LimitKey`,
    /// no `CredentialDigest`, no hashing anywhere on this path; the value
    /// that reaches the registry's `tenant` attribute is byte-for-byte
    /// whatever this test passes in, including a string that LOOKS like key
    /// material -- proving nothing here transforms, hashes, or otherwise
    /// launders it (there is simply nothing in this file capable of doing
    /// that to it).
    #[test]
    fn the_tenant_attribute_is_the_plain_id_never_a_digest_or_key() {
        let control = StatsControl::new(1);
        let handles = Arc::new(TokenUsageStatHandles::build(&control, ["openai"]));
        let registry = control.registry();
        let stats = GenAiTokenStats::new(registry.clone(), handles, WorkerId(0));

        let credential_shaped_tenant = "llmp_should-never-be-hashed";
        stats.record_usage("openai", Some(credential_shaped_tenant), sample_tokens());

        let h = registry.resolve_capped(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", credential_shaped_tenant),
            ],
            instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CEILING,
            &[
                ("provider", "openai"),
                ("type", "input"),
                (
                    "tenant",
                    instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW,
                ),
            ],
        );
        assert_eq!(
            registry.value(h),
            40,
            "the exact string passed as `tenant` must be the attribute value resolved against \
             -- a hash or digest would resolve a DIFFERENT series and this lookup would find 0"
        );
    }

    /// Requirement 3: the cardinality mitigation. A ceiling of 4 (one
    /// tenant's worth of buckets) lets exactly one real tenant through;
    /// every subsequent, never-seen tenant collapses onto the single
    /// overflow series instead of growing the registry further -- proven
    /// through the real production entry point (`record_usage`), not just
    /// `Registry::resolve_capped` in isolation (that mechanism is unit
    /// tested directly in `proxy_observability::stats`).
    #[test]
    fn cardinality_ceiling_folds_excess_tenants_into_one_shared_series() {
        const CEILING: usize = instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CEILING;
        // Sanity on the fixture, not the mitigation: this test only holds
        // together if a whole tenant (4 buckets) fits under the real
        // ceiling, which it always will unless the ceiling is ever dropped
        // below 4 -- fail loudly, at COMPILE time, rather than let a
        // nonsensical low ceiling silently defeat the test below.
        const _: () = assert!(instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CEILING >= 4);

        let control = StatsControl::new(1);
        let handles = Arc::new(TokenUsageStatHandles::build(&control, ["openai"]));
        let registry = control.registry();
        let stats = GenAiTokenStats::new(registry.clone(), handles, WorkerId(0));

        // Exhaust the ceiling with distinct tenants first (each resolved
        // directly, cheaply -- one bucket is enough to consume its "slot"
        // for this test's purposes since the ceiling counts raw series).
        for i in 0..CEILING {
            let tenant = format!("filler-tenant-{i}");
            registry.resolve_capped(
                &instruments::LLM_CLIENT_TOKEN_USAGE,
                &[
                    ("provider", "openai"),
                    ("type", "input"),
                    ("tenant", tenant.as_str()),
                ],
                CEILING,
                &[
                    ("provider", "openai"),
                    ("type", "input"),
                    (
                        "tenant",
                        instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW,
                    ),
                ],
            );
        }

        // Two BRAND NEW tenants, past the ceiling, via the real
        // `record_usage` entry point.
        stats.record_usage("openai", Some("tenant-over-the-line-a"), sample_tokens());
        stats.record_usage("openai", Some("tenant-over-the-line-b"), sample_tokens());

        let overflow = registry.resolve_capped(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("provider", "openai"),
                ("type", "input"),
                (
                    "tenant",
                    instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW,
                ),
            ],
            CEILING,
            &[
                ("provider", "openai"),
                ("type", "input"),
                (
                    "tenant",
                    instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW,
                ),
            ],
        );
        assert_eq!(
            registry.value(overflow),
            80,
            "both overflowing tenants' usage (40 input tokens each) must land on the ONE \
             shared overflow series -- the mitigation drops the DIMENSION, not the \
             MEASUREMENT: usage is still counted, just no longer distinguishable by tenant"
        );

        // Neither overflowing tenant got its own series.
        let a = registry.resolve_capped(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", "tenant-over-the-line-a"),
            ],
            CEILING,
            &[
                ("provider", "openai"),
                ("type", "input"),
                (
                    "tenant",
                    instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW,
                ),
            ],
        );
        assert_eq!(
            a, overflow,
            "an overflowing tenant must resolve to the shared series"
        );
    }

    /// The recorder's memo is what keeps a tenant's second request off the
    /// registry's process-wide lock: `capped_lock_acquisitions` is the same
    /// counter every capped resolution increments in production.
    #[test]
    fn a_warm_tenant_series_takes_no_registry_lock() {
        let control = StatsControl::new(1);
        let handles = Arc::new(TokenUsageStatHandles::build(&control, ["openai"]));
        let registry = control.registry();
        let stats = GenAiTokenStats::new(registry.clone(), handles, WorkerId(0));

        stats.record_usage("openai", Some("acme"), sample_tokens());
        let after_cold = registry.capped_lock_acquisitions();
        assert!(after_cold > 0, "the first request resolves its series");

        for _ in 0..5 {
            stats.record_usage("openai", Some("acme"), sample_tokens());
        }
        assert_eq!(
            registry.capped_lock_acquisitions(),
            after_cold,
            "a warm series must not touch the registry's lock"
        );
        let total: u64 = registry
            .counters()
            .filter(|(_, attrs, _)| attrs.iter().any(|(k, v)| k == "tenant" && v == "acme"))
            .filter(|(_, attrs, _)| attrs.iter().any(|(k, v)| k == "type" && v == "input"))
            .map(|(_, _, value)| value)
            .sum();
        assert_eq!(total, 6 * 40, "the memoized handle still counts");
    }

    #[test]
    fn a_warm_model_series_takes_no_registry_lock() {
        let control = StatsControl::new(1);
        let registry = control.registry();
        let stats = GenAiLatencyStats::new(registry.clone(), WorkerId(0));
        let record = || {
            stats.record(
                "chat",
                "gpt-4o",
                "openai",
                Some(Duration::from_millis(100)),
                Duration::from_secs(1),
                Some(5),
            )
        };

        record();
        let after_cold = registry.capped_lock_acquisitions();
        assert_eq!(after_cold, 2, "TTFT and TPOT each resolve once");
        record();
        record();
        assert_eq!(registry.capped_lock_acquisitions(), after_cold);
        let (_, ttft) = latency_histogram(&registry, "gen_ai.server.time_to_first_token");
        assert_eq!(ttft.count, 3);
    }

    #[test]
    fn a_tenant_folded_into_the_overflow_series_is_retried_after_its_slot_frees() {
        let control = StatsControl::new(1);
        let handles = Arc::new(TokenUsageStatHandles::build(&control, ["gone", "kept"]));
        let registry = control.registry();
        let stats = GenAiTokenStats::new(registry.clone(), handles, WorkerId(0));
        let ceiling = instruments::LLM_CLIENT_TOKEN_USAGE_TENANT_CEILING;

        // Fill every slot with tenants of the soon-to-be-removed provider.
        for i in 0..ceiling {
            stats.record_usage("gone", Some(&format!("t{i}")), sample_tokens());
        }
        stats.record_usage("kept", Some("late"), sample_tokens());
        let tenant_series = |tenant: &str| {
            registry
                .counters()
                .filter(|(_, attrs, _)| attrs.iter().any(|(k, v)| k == "tenant" && v == tenant))
                .count()
        };
        assert_eq!(tenant_series("late"), 0, "folded while the cap is full");

        control.set_live_scope(proxy_observability::stats::LiveScope {
            clusters: Some(["kept".to_string()].into()),
            ..Default::default()
        });
        stats.record_usage("kept", Some("late"), sample_tokens());
        assert_eq!(tenant_series("late"), 4, "late now has its own series");
    }
}
