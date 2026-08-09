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
//! snapshot. Dynamic cluster addition after that (config reload growing the
//! cluster set) isn't wired into this table yet -- nothing in this binary
//! republishes into it today, matching `start_admin`'s own note that dynamic
//! config updates (WP-20/21/22) haven't landed. So a cluster name the router
//! asks about that isn't in the table is a real, if rare, possibility, and
//! must never be allowed to fail a request: [`RouterStats::record_attempt`]/
//! [`RouterStats::record_attempt_duration_ms`] silently no-op on a lookup
//! miss, logging at most once per unique unknown name (see
//! [`RouterStats::warn_unknown_cluster_once`]) so the gap stays visible
//! without spamming a line per request.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

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

/// Cluster name -> [`ClusterStatHandles`], built once at boot from the
/// config snapshot's cluster set. See the module doc for why this is a
/// fixed, boot-time table rather than something the router grows itself.
pub struct StatHandles {
    by_cluster: HashMap<String, ClusterStatHandles>,
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
        let mut by_cluster = HashMap::new();
        for name in cluster_names {
            let rq = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", name)]);
            let rq_time =
                control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", name)]);
            by_cluster.insert(name.to_string(), ClusterStatHandles { rq, rq_time });
        }
        Self { by_cluster }
    }

    /// Looks up `cluster`'s pre-resolved handles, or `None` if this table
    /// was never told about that cluster -- see the module doc for why that
    /// has to be a lookup miss the caller can handle, not a panic.
    pub fn for_cluster(&self, cluster: &str) -> Option<&ClusterStatHandles> {
        self.by_cluster.get(cluster)
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
}
