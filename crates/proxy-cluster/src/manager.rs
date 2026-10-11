//! Cluster manager: owns per-cluster discovery state and
//! publishes [`HostSet`] snapshots. Built/updated on the control runtime; the
//! router only ever talks to it through [`ClusterManager::cluster`]'s
//! `Arc<dyn ClusterEntry>` handle, never touching discovery internals.
//!
//! Warming ("is this cluster ready to serve") tracking lives here --
//! [`ClusterManager::is_initialized`] flips once a cluster's first
//! resolution lands, or, for a cluster that never resolves in time,
//! [`ClusterManager::force_initialize`] mimics Envoy's
//! `initial_fetch_timeout` "proceed empty" behavior.
//! [`ClusterManager::warming_clusters`] is what a
//! readiness probe reads; this crate has no opinion on what a caller does
//! with a non-empty result -- see `proxy-admin`'s `ReadinessProbe` and
//! `proxy/src/main.rs` for the production wiring, and note this only gates
//! `/ready`, not request routing.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use proxy_config::ir::{
    ClusterConfig, ClusterKind, ClusterName, DiscoveryType, EndpointIR, LbPolicy,
};
use tokio::task::JoinHandle;

use crate::discovery;
use crate::health_check::HealthCheckEngine;
use crate::host_set::{carry_over_health_flags, diff_host_sets, HostSet, HostSetDiff};
use crate::load_balancer::{self, HostPicker, LbError};
use crate::outlier::{OutlierDetector, RequestResult, TracingEventSink};
use crate::resolver::HostResolver;
use crate::transport::{
    self, TransportSocketBuilder, TransportSocketError, UpstreamTransportSocket,
};
use crate::{
    CircuitBreakerState, ClusterEntry, Host, HostSelection, HttpConnPool, LoadBalancerContext,
    RoutingPriority, SelectedMember, UpstreamProtocol,
};

/// Failure to build a cluster: either its `lb_policy` isn't implemented
/// ([`LbError`]) or its `transport_socket` couldn't be built
/// ([`TransportSocketError`]). Kept as one enum (rather than two separate
/// `Vec`s of rejections) because both are "this cluster didn't make it into
/// the cluster set" outcomes the same callers need to report the same way.
#[derive(Debug, thiserror::Error)]
pub enum ClusterBuildError {
    #[error(transparent)]
    Lb(#[from] LbError),
    #[error(transparent)]
    TransportSocket(#[from] TransportSocketError),
}

/// A copyable, control-plane-facing snapshot of one cluster's active host
/// set. This deliberately contains only runtime values and standard-library
/// types: consumers such as the admin server need no generated-proto
/// dependency (and never receive a `ManagedCluster` internals handle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveCluster {
    pub name: ClusterName,
    pub initialized: bool,
    pub endpoints: Vec<LiveEndpoint>,
}

/// One endpoint selected from a [`LiveCluster`]'s current host set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveEndpoint {
    pub address: SocketAddr,
    /// The DNS origin, when discovery resolved a DNS endpoint. `address` is
    /// always the actual address traffic dials; this is supplementary SNI /
    /// operator context, never a replacement for it.
    pub hostname: Option<String>,
    pub weight: u32,
    pub priority: u32,
    pub health_flags: String,
    /// The explicitly accepted endpoint-label namespace. Values are copied
    /// into the immutable host set on discovery/EDS ingest, so this follows
    /// live membership rather than the configured endpoint shape.
    pub metadata: BTreeMap<String, String>,
}

/// One cluster's live state: where its membership comes from, its current
/// host-set snapshot, and its warming status.
///
/// Rust note: `ArcSwap<HostSet>` is the same "control computes, workers
/// swap" pattern `proxy_core::WorkerConfigHandle` uses for `ConfigSnapshot`
/// (ADR-0003) -- discovery recomputes whole host sets on the control
/// runtime; readers (`select_host`) only ever `load`.
///
/// For an aggregate cluster (`ClusterConfig::kind` is `Aggregate`),
/// `host_set`/`host_picker`/`transport`/`upstream_protocol` below are all
/// inert placeholders -- see [`ManagedCluster::from_config`]'s aggregate arm.
struct ManagedCluster {
    /// The config this cluster was built from; discovery follows its
    /// `DiscoveryType` (STATIC/STRICT_DNS/LOGICAL_DNS -- see
    /// [`crate::discovery`]), except `EDS`, whose membership arrives through
    /// [`ClusterManager::accept_eds_update`] instead.
    config: Arc<ClusterConfig>,
    /// Rust note: `Arc<ArcSwap<..>>` (not a bare `ArcSwap<..>`) so
    /// [`health_check::HealthCheckEngine::spawn_for_host`] -- which needs an
    /// owned handle to publish transitions onto, since its check loop
    /// outlives any single call into this manager -- can hold a clone of the
    /// exact swap cell every reader of this cluster shares, rather than a
    /// borrow tied to `&self`. `.load()`/`.store()`/`.rcu()` still work
    /// unchanged through `Arc`'s `Deref`.
    ///
    /// [`health_check::HealthCheckEngine::spawn_for_host`]: crate::health_check::HealthCheckEngine::spawn_for_host
    host_set: Arc<ArcSwap<HostSet>>,
    /// Flips to `true` once the cluster's first resolution (or, for EDS, its
    /// first externally-supplied set) has landed. Also `true` from
    /// construction for an aggregate, which has nothing of its own to
    /// resolve (see `from_config`'s aggregate arm).
    initialized: AtomicBool,
    /// S7 host selection: the configured `lb_policy`'s [`LoadBalancer`],
    /// plus the priority-spillover / healthy-panic-threshold logic shared by
    /// every policy. Built once at cluster construction -- see
    /// [`load_balancer::build`] for why `RING_HASH`/`MAGLEV` fail here
    /// instead of falling back to something else.
    ///
    /// [`LoadBalancer`]: crate::load_balancer::LoadBalancer
    host_picker: HostPicker,
    /// S5 circuit-breaker budgets for this cluster, one bucket per routing
    /// priority; these are the buckets `ClusterEntry::circuit_breaker` hands
    /// back. An aggregate's members therefore share the aggregate's own
    /// budget today -- see `router.rs`'s `apply_forward` for where that's
    /// acquired.
    default_cb: CircuitBreakerState,
    high_cb: CircuitBreakerState,
    /// Which HTTP protocol the router speaks to this cluster's upstreams.
    /// Captured from the config at build time (Envoy default HTTP/1.1); EDS
    /// clusters, which have no `ClusterConfig`, default to HTTP/1.1.
    upstream_protocol: UpstreamProtocol,
    /// What [`crate::pool::ConnectPool`] wraps a freshly-dialed TCP
    /// connection in: plaintext, or a TLS originator built from
    /// `config.transport_socket`. Built once at cluster construction via the
    /// manager's [`TransportSocketBuilder`]; EDS clusters, which have no
    /// `ClusterConfig`, always get plaintext.
    transport: Arc<dyn UpstreamTransportSocket>,
    /// `ClusterConfig::connect_timeout` (Envoy default 5s), handed to every
    /// [`crate::pool::ConnectPool`] built for this cluster. EDS clusters and
    /// aggregates, which have no `ClusterConfig` of their own to read (the
    /// aggregate arm's own pool is never actually dialed -- see
    /// `ClusterHandle::http_pool`), fall back to the same Envoy default.
    connect_timeout: std::time::Duration,
    /// S6 active health checking: built once from
    /// `config.health_check` at construction, same as `host_picker`/
    /// `transport` above. `None` when the config configures no health check
    /// (Envoy's own default, every host healthy), and always `None` for an
    /// aggregate (no hosts of its own to probe -- see the aggregate arm) or
    /// an EDS cluster (no `ClusterConfig` to read one from -- see [`Self::eds`]).
    health_engine: Option<Arc<HealthCheckEngine>>,
    /// Live probe tasks, one per currently-probed host address. Reconciled
    /// against membership on every `refresh_cluster`/`accept_eds_update`
    /// call by [`Self::reconcile_probes`]. Kept here (not on the engine
    /// itself) because it's per-*cluster* membership, and a `ManagedCluster`
    /// is what actually gets discarded wholesale on a config reload -- see
    /// this type's `Drop` impl for why that discard must abort every handle
    /// here rather than just letting them go.
    ///
    /// Rust note: `std::sync::Mutex`, not `tokio::sync::Mutex` -- every
    /// critical section here is a plain, non-async `HashMap` insert/remove/
    /// drain, so there's no `.await` under the lock to require the async
    /// variant (same reasoning as `resolver::FakeResolver::records`).
    probes: Mutex<HashMap<SocketAddr, JoinHandle<()>>>,
    /// S6 passive outlier detection, or `None` when the config
    /// configures none. Fed one [`RequestResult`] per upstream attempt by the
    /// router (via [`ClusterEntry::report_outlier_result`]); it ejects a host
    /// by setting `failed_outlier_check` on it in this same cluster's
    /// `host_set`, so ejections and active-health-check failures share one
    /// snapshot (see `HealthFlags`). Holds an `Arc<ArcSwap<HostSet>>` clone of
    /// `host_set` below, so it always ejects into the current membership even
    /// across a DNS re-resolution.
    outlier_detector: Option<Arc<OutlierDetector>>,
    /// The detector's periodic success-rate / failure-percentage sweep task
    /// ([`OutlierDetector::spawn`]). Aborted on `Drop` for the identical
    /// reason as `probes` -- a dropped `JoinHandle` detaches rather than
    /// stops, so without this a config reload leaks one sweep loop per
    /// cluster, forever.
    outlier_sweep: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for ManagedCluster {
    /// A dropped `JoinHandle` does **not** abort its task -- it only detaches
    /// from it, and the check loop keeps running with nobody left to stop it.
    /// `ClusterManager::update_from_snapshot` rebuilds a config-sourced
    /// cluster whenever its config actually changed
    /// (unless it is carried forward unchanged, see that method's own doc),
    /// so without this, every rebuild -- and this proxy reloads on SIGHUP in
    /// production -- would leak one permanently-running probe loop per host,
    /// forever.
    fn drop(&mut self) {
        // Rust note: `Mutex::lock`'s `Err` case is poisoning (a prior holder
        // panicked mid-critical-section) -- `if let Ok` rather than
        // `.unwrap()` here so a poisoned lock still aborts whatever handles
        // it can reach instead of panicking again inside a `Drop` (a
        // double-panic during unwind aborts the whole process).
        if let Ok(mut probes) = self.probes.lock() {
            for (_, handle) in probes.drain() {
                handle.abort();
            }
        }
        // Same reasoning for the outlier-detection sweep: a dropped handle
        // detaches, so without this a config reload leaks one sweep loop per
        // cluster that configures outlier detection.
        if let Ok(mut sweep) = self.outlier_sweep.lock() {
            if let Some(handle) = sweep.take() {
                handle.abort();
            }
        }
    }
}

impl ManagedCluster {
    /// Builds a config-sourced cluster's state. Branches on `config.kind`:
    /// an `Endpoints` cluster gets a real load balancer and transport socket
    /// (failing if `config.lb_policy` isn't implemented yet -- `RING_HASH`/
    /// `MAGLEV`, see [`load_balancer::build`] -- or if `config.transport_socket`
    /// doesn't build; AGENTS.md invariant 1 forbids silently substituting another
    /// policy or downgrading to plaintext); an `Aggregate` cluster has no
    /// hosts, load balancer, or transport socket of its own to build at all
    /// (see the aggregate arm below).
    fn from_config(
        config: Arc<ClusterConfig>,
        transport_builder: &TransportSocketBuilder,
    ) -> Result<Self, ClusterBuildError> {
        let default_cb = CircuitBreakerState::from_thresholds(config.circuit_breakers.default);
        let high_cb = CircuitBreakerState::from_thresholds(config.circuit_breakers.high);
        match &config.kind {
            ClusterKind::Endpoints => {
                let policy = load_balancer::build(config.lb_policy)?;
                let transport = transport_builder(&config)?;
                // Read + map (IR → runtime enum) before `config` is moved
                // into `source` below.
                let upstream_protocol = UpstreamProtocol::from(config.upstream_protocol);
                let connect_timeout = config.connect_timeout;
                // Build the engine now, from the lowered config, same as
                // `policy`/`transport` above --
                // `None` means the config configures no health check at all
                // (Envoy's own default), not that this cluster is exempt.
                let health_engine = config.health_check.as_ref().map(HealthCheckEngine::from_ir);
                // The detector must eject into the SAME
                // `host_set` the router picks from, so build the `Arc` here
                // and hand the detector a clone. It ejects by publishing a new
                // snapshot with `failed_outlier_check` set, which the picker
                // then skips -- see `OutlierDetector`. Its periodic sweep is
                // spawned now and its handle stashed for `Drop` to abort.
                let host_set = Arc::new(ArcSwap::from_pointee(HostSet::default()));
                let (outlier_detector, outlier_sweep) = match &config.outlier_detection {
                    Some(od) => {
                        let detector = OutlierDetector::new(
                            od.into(),
                            config.name.clone(),
                            Arc::clone(&host_set),
                            Arc::new(TracingEventSink),
                        );
                        let sweep = detector.spawn();
                        (Some(detector), Some(sweep))
                    }
                    None => (None, None),
                };
                Ok(Self {
                    config,
                    host_set,
                    initialized: AtomicBool::new(false),
                    host_picker: HostPicker::new(policy),
                    default_cb,
                    high_cb,
                    upstream_protocol,
                    transport,
                    connect_timeout,
                    health_engine,
                    probes: Mutex::new(HashMap::new()),
                    outlier_detector,
                    outlier_sweep: Mutex::new(outlier_sweep),
                })
            }
            ClusterKind::Aggregate { .. } => {
                // `select_host` never reads this
                // cluster's own `host_set`/`host_picker`/`transport`/
                // `upstream_protocol`/`connect_timeout` for an aggregate --
                // it resolves straight through to whichever member actually
                // served the host (see `ClusterHandle::select_aggregate_member`)
                // -- so `RoundRobin`/`RawTransportSocket`/`Http1` here are
                // inert placeholders, never real answers. `initialized` starts
                // `true`: there is nothing here to resolve, and leaving it `false`
                // would make warming wait forever on a cluster that never runs
                // discovery -- and, since the router refuses an un-initialized
                // cluster before host selection, would 503 every request routed at
                // an aggregate.
                // `connect_timeout` is read from the real config anyway (it
                // costs nothing and stays correct if this arm's pool is ever
                // actually dialed). `health_engine`
                // stays `None` for the same reason as the rest of this arm:
                // an aggregate has no hosts of its own to probe -- probing
                // happens on the member cluster, which has its own real
                // `ManagedCluster` and its own `health_engine`.
                let connect_timeout = config.connect_timeout;
                Ok(Self {
                    config,
                    host_set: Arc::new(ArcSwap::from_pointee(HostSet::default())),
                    initialized: AtomicBool::new(true),
                    host_picker: HostPicker::new(
                        load_balancer::build(LbPolicy::RoundRobin)
                            .expect("round robin always builds"),
                    ),
                    default_cb,
                    high_cb,
                    upstream_protocol: UpstreamProtocol::Http1,
                    transport: Arc::new(transport::RawTransportSocket),
                    connect_timeout,
                    health_engine: None,
                    probes: Mutex::new(HashMap::new()),
                    // An aggregate has no hosts of its own to eject -- outlier
                    // detection runs on the member cluster, same as probing.
                    outlier_detector: None,
                    outlier_sweep: Mutex::new(None),
                })
            }
        }
    }

    /// Reconcile this cluster's active-health-check probes against a
    /// membership diff: stop the probe for every
    /// `removed` address (aborting its task, not just dropping the handle --
    /// see this type's `Drop` impl for why a drop alone isn't enough), and
    /// start one for every `added` address. `unchanged` addresses are left
    /// alone -- their probe, if any, is already running against this same
    /// `host_set`, and re-spawning would just be a second task racing the
    /// first over the same host.
    ///
    /// A no-op when this cluster has no health check configured
    /// (`health_engine` is `None`).
    fn reconcile_probes(&self, diff: &HostSetDiff) {
        let Some(engine) = &self.health_engine else {
            return;
        };
        let mut probes = self.probes.lock().unwrap();
        for addr in &diff.removed {
            if let Some(handle) = probes.remove(addr) {
                handle.abort();
            }
        }
        for &addr in &diff.added {
            // Hand the probe a clone of this cluster's own
            // detector (if any) so a recovery here also clears an outlier
            // ejection -- see `HealthCheckEngine::spawn_for_host`'s doc for
            // why this is one-way (active HC recovery -> un-eject, never the
            // reverse).
            let handle = engine.spawn_for_host(
                addr,
                Arc::clone(&self.host_set),
                self.outlier_detector.clone(),
            );
            probes.insert(addr, handle);
        }
    }

    /// True for an aggregate cluster (`ClusterConfig::kind` is `Aggregate`).
    /// [`ClusterHandle::select_aggregate_member`] uses this to refuse
    /// recursing into a member that is itself an aggregate.
    fn is_aggregate(&self) -> bool {
        matches!(self.config.kind, ClusterKind::Aggregate { .. })
    }

    /// This cluster's aggregate member list, in config order -- `None` for
    /// anything [`Self::is_aggregate`] says isn't one.
    fn aggregate_members(&self) -> Option<&[ClusterName]> {
        match &self.config.kind {
            ClusterKind::Aggregate { members } => Some(members),
            ClusterKind::Endpoints => None,
        }
    }
}

fn not_found(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("unknown cluster `{name}`"))
}

/// Owns every cluster's discovery state. `&self`-based throughout (the
/// per-cluster map lives behind an `ArcSwap`, like `HostSet` itself) so a
/// single manager can be shared (`Arc<ClusterManager>`) between whatever
/// drives config reloads and whatever drives DNS refresh timers.
pub struct ClusterManager {
    // Rust note: wrapped in an extra `Arc` around the `ArcSwap` (not just
    // `ArcSwap<..>` directly) so a [`ClusterHandle`] can hold a *clone of
    // this exact registry* rather than a snapshot of what it pointed to when
    // the handle was built. That's what makes aggregate member resolution
    // late-bound: `Arc::clone` here is just a refcount bump (the `ArcSwap`
    // itself, and the `HashMap` it wraps, are never copied), and every clone
    // still `.load()`s whatever `update_from_snapshot` most recently
    // published. Late binding matters because `update_from_snapshot`
    // rebuilds a config-sourced cluster whenever its own config changed
    // (unless it is carried forward unchanged, see that
    // method's own doc) -- a member resolved *eagerly*, at the aggregate's
    // own construction time, would keep pointing at a specific
    // `Arc<ManagedCluster>` that a later reload replaces, silently freezing
    // that member's discovery even though the config for it kept updating.
    clusters: Arc<ArcSwap<HashMap<ClusterName, Arc<ManagedCluster>>>>,
    resolver: Arc<dyn HostResolver>,
    transport_builder: TransportSocketBuilder,
}

/// Immutable view of the cluster registry captured for one listener/HCM
/// configuration generation. Existing downstream connections retain their
/// generation's view while a newly published configuration serves new
/// connections from the replacement registry.
#[derive(Clone)]
pub struct ClusterRegistrySnapshot {
    // This is intentionally a distinct, never-updated `ArcSwap`, seeded with
    // one published registry. `ClusterHandle` still uses an `ArcSwap` for
    // aggregate member resolution, but its members must resolve within this
    // generation rather than against a later reload's registry.
    clusters: Arc<ArcSwap<HashMap<ClusterName, Arc<ManagedCluster>>>>,
}

impl ClusterManager {
    pub fn new(resolver: Arc<dyn HostResolver>, transport_builder: TransportSocketBuilder) -> Self {
        Self {
            clusters: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            resolver,
            transport_builder,
        }
    }

    /// Convenience constructor for callers that don't (yet) wire real
    /// upstream TLS: installs [`transport::reject_tls_builder`], so
    /// plaintext clusters work and a `transport_socket`-configured one fails
    /// loudly instead of silently downgrading. Used throughout this crate's
    /// own tests.
    pub fn with_default_transport(resolver: Arc<dyn HostResolver>) -> Self {
        Self::new(resolver, transport::reject_tls_builder())
    }

    /// Capture the registry currently published by this manager for a
    /// connection-facing configuration generation. Unlike [`Self::cluster`],
    /// handles obtained through this view never observe a later replacement
    /// registry; this keeps in-flight requests routed by an older HCM from
    /// losing their selected clusters during a listener rename/reload.
    pub fn routing_snapshot(&self) -> ClusterRegistrySnapshot {
        ClusterRegistrySnapshot {
            clusters: Arc::new(ArcSwap::from(self.clusters.load_full())),
        }
    }

    /// Reconcile against a config snapshot's cluster map and kick off each
    /// current cluster's initial resolution.
    ///
    /// A cluster whose config is unchanged from the
    /// currently-published one is carried forward as the exact same
    /// `Arc<ManagedCluster>` -- host set, health-check engine, outlier
    /// detector and its running task handles all survive untouched -- rather
    /// than being rebuilt and re-resolved. "Unchanged" is `Arc::ptr_eq` OR
    /// `ClusterConfig`'s derived `PartialEq` (see that type's doc for why the
    /// derive, not a hand-written `eq`, is load-bearing here). Both halves
    /// earn their place:
    /// - `Arc::ptr_eq` is the free short-circuit that covers the ADS path.
    ///   `SotwSet::apply` (`proxy-xds/src/store.rs`) keeps the *old* resource
    ///   entry when a CDS push compares a resource `unchanged`, and
    ///   `ResourceApplier::assemble_snapshot` (`proxy-xds/src/apply.rs`)
    ///   `Arc::clone`s it into the next snapshot -- so a CDS push that only
    ///   changes cluster B hands this method the pointer-identical
    ///   `Arc<ClusterConfig>` for cluster A. Statically-declared clusters are
    ///   likewise never re-lowered across a call. This is the motivating
    ///   scenario: a control-plane heartbeat silently
    ///   clearing ejection state proxy-wide.
    /// - Content equality is what additionally covers a SIGHUP file reload,
    ///   where every `Arc` is freshly lowered from scratch and no pointer
    ///   from the previous generation survives at all.
    ///   Pointer equality alone is conservative in the safe direction (two
    ///   pointer-equal `Arc`s are trivially content-equal too, since these
    ///   `ClusterConfig`s are never mutated in place) -- content equality is
    ///   what makes the carry-forward complete rather than just cheap.
    ///
    /// A cluster whose config DID change still goes through the full
    /// rebuild-then-resolve path below, in `next`'s own resolve loop -- only
    /// freshly-built clusters ever reach it now.
    ///
    /// Every freshly-built cluster is
    /// resolved *before* the map is published (`self.clusters.store` below),
    /// not after. The previous ordering stored every cluster with an empty
    /// `HostSet` first and resolved them one at a time afterward -- for the
    /// whole span of that serial loop, EVERY cluster (including ones like
    /// `STATIC` that need no I/O at all) was empty and rejecting traffic, and
    /// a slow `STRICT_DNS` cluster in the same reload stretched that window
    /// for everyone else too. Resolving into `next` first means the
    /// previously-published map keeps serving, untouched, until the
    /// fully-resolved replacement is ready to swap in atomically.
    ///
    /// **EDS-delivered membership on a config-sourced EDS cluster now
    /// survives an unrelated reload, via the same carry-forward.** Previously
    /// this was the sharpest consequence of the missing carry-forward: a
    /// cluster declared `discovery: eds` is an ordinary config-sourced
    /// cluster like any other, so every reload
    /// rebuilt it from scratch with an empty `HostSet`, and `resolve_cluster`
    /// deliberately does not resolve an EDS-typed config cluster (there is
    /// nothing to resolve) -- so a SIGHUP reload emptied it until the control
    /// plane next pushed that resource. Since that config never changes on
    /// an unrelated reload, it now takes the carry-forward branch below like
    /// any other cluster, and its externally-delivered `host_set` (installed
    /// by [`Self::accept_eds_update`]) rides along on the same `Arc`.
    ///
    /// A cluster whose `lb_policy` isn't implemented (`RING_HASH`/`MAGLEV`)
    /// is rejected rather than silently substituted with another
    /// policy (AGENTS.md invariant 1): it's left out of the resulting cluster set
    /// entirely and its name+error is returned here so the caller can
    /// surface it (e.g. as a config error) instead of it disappearing
    /// silently.
    pub async fn update_from_snapshot(
        &self,
        clusters: &HashMap<ClusterName, Arc<ClusterConfig>>,
    ) -> Vec<(ClusterName, ClusterBuildError)> {
        let previous = self.clusters.load_full();
        let mut next: HashMap<ClusterName, Arc<ManagedCluster>> =
            HashMap::with_capacity(clusters.len());
        let mut rejected = Vec::new();
        // Freshly-built clusters only -- these are the only ones that need
        // `resolve_cluster` below. A carried-forward cluster's `host_set` is
        // already live and must not be touched (see this method's own doc).
        let mut freshly_built: Vec<ClusterName> = Vec::new();
        for (name, config) in clusters {
            let carried = match previous.get(name) {
                Some(managed)
                    if Arc::ptr_eq(&managed.config, config) || *managed.config == **config =>
                {
                    Some(Arc::clone(managed))
                }
                _ => None,
            };
            match carried {
                Some(managed) => {
                    next.insert(name.clone(), managed);
                }
                None => {
                    match ManagedCluster::from_config(Arc::clone(config), &self.transport_builder) {
                        Ok(managed) => {
                            next.insert(name.clone(), Arc::new(managed));
                            freshly_built.push(name.clone());
                        }
                        Err(err) => {
                            tracing::error!(cluster = %name, error = %err, "cluster rejected");
                            rejected.push((name.clone(), err));
                        }
                    }
                }
            }
        }

        // Resolve each freshly-built cluster's own discovery into ITS OWN
        // `host_set` -- nothing here is reachable through `self.clusters` yet
        // (the `store` below hasn't happened), so nothing else can observe
        // these half-resolved `ManagedCluster`s mid-loop. `resolve_cluster`
        // is the same logic `refresh_cluster` runs (it's the extraction of
        // that method's body -- see its own doc), so an EDS-typed cluster
        // still isn't resolved here either (it would return empty, and there
        // is no membership to carry over at construction time).
        for name in &freshly_built {
            let managed = &next[name];
            if let Err(err) = self.resolve_cluster(managed).await {
                // Rust note: a discovery failure doesn't take the cluster
                // manager down -- Envoy keeps serving the last-known-good
                // (here: empty, since this is the first resolution) host set
                // and logs. Real retry/backoff on DNS failure is a future
                // refinement. Crucially, this is scoped
                // to the ONE cluster that failed -- every other entry in
                // `next` already resolved (or failed) independently above,
                // so one bad DNS answer never blocks or fails the reload.
                tracing::warn!(cluster = %name, error = %err, "initial cluster discovery failed");
            }
        }
        self.clusters.store(Arc::new(next));
        rejected
    }

    /// Apply an externally-supplied endpoint set to an EDS-registered
    /// cluster, publishing a new host set and marking it initialized.
    pub fn accept_eds_update(
        &self,
        name: &str,
        endpoints: &[EndpointIR],
    ) -> io::Result<HostSetDiff> {
        let managed = self
            .clusters
            .load()
            .get(name)
            .cloned()
            .ok_or_else(|| not_found(name))?;
        // Rust note: `static_hosts` just turns literal-IP `EndpointIR`s into
        // `Host`s -- no I/O either way, whether they came from a STATIC
        // cluster's config or an externally-pushed EDS response.
        let hosts = discovery::static_hosts(endpoints)?;
        let new_set = HostSet::from_hosts(hosts);
        let old_set = managed.host_set.load();
        let diff = diff_host_sets(&old_set, &new_set);
        // Carry `health_flags` over for every address
        // still present, or an active-check flip would be silently erased
        // by the next EDS push -- see `host_set::carry_over_health_flags`.
        let new_set = carry_over_health_flags(&old_set, new_set, &diff);
        drop(old_set);
        managed.host_set.store(Arc::new(new_set));
        managed.initialized.store(true, Ordering::Release);
        managed.reconcile_probes(&diff);
        Ok(diff)
    }

    /// Re-run discovery for one cluster and publish the resulting host set,
    /// returning the diff against the previous one. A no-op (empty diff) for
    /// EDS-sourced clusters, which have no self-driven resolution -- use
    /// [`Self::accept_eds_update`] for those.
    ///
    /// Intended to be re-run on a timer ([`discovery::DEFAULT_DNS_REFRESH_RATE`])
    /// for DNS-discovered clusters; no production timer calls it yet. Tests
    /// call it directly to drive discovery deterministically instead of
    /// waiting on a real timer.
    ///
    /// This method's contract is unchanged -- it still
    /// looks the cluster up by name in the CURRENTLY PUBLISHED registry and
    /// resolves it there. [`Self::resolve_cluster`] is just this method's
    /// former body, factored out so [`Self::update_from_snapshot`] can run
    /// the identical resolution logic against a `ManagedCluster` that isn't
    /// registered yet (see that method's doc for why).
    pub async fn refresh_cluster(&self, name: &str) -> io::Result<HostSetDiff> {
        let managed = self
            .clusters
            .load()
            .get(name)
            .cloned()
            .ok_or_else(|| not_found(name))?;
        self.resolve_cluster(&managed).await
    }

    /// Run discovery for `managed` and publish the result into ITS OWN
    /// `host_set`, returning the diff against whatever it held before. Does
    /// not touch `self.clusters` at all -- the caller decides whether/how
    /// `managed` is registered ([`Self::refresh_cluster`] looks it up there
    /// first; [`Self::update_from_snapshot`] calls this on a cluster that
    /// hasn't been published yet).
    async fn resolve_cluster(&self, managed: &ManagedCluster) -> io::Result<HostSetDiff> {
        // Two shapes have nothing to resolve, and both return an explicit
        // no-op rather than a resolve of zero endpoints (which would go
        // through `discovery::resolve` and diff against an always-empty set
        // for no reason).
        //
        // An aggregate has no endpoints or discovery of its own.
        //
        // An EDS cluster's membership arrives through
        // [`ClusterManager::accept_eds_update`], and short-circuiting matters
        // here. A DNS refresh re-runs this; `discovery::resolve` returns an
        // EMPTY host set for `DiscoveryType::Eds`, so falling through would
        // diff the EDS-delivered membership against nothing and wipe it on
        // the next refresh.
        let config = &managed.config;
        if matches!(config.kind, ClusterKind::Aggregate { .. })
            || config.discovery == DiscoveryType::Eds
        {
            return Ok(HostSetDiff::default());
        }
        let new_set = discovery::resolve(config, self.resolver.as_ref()).await?;
        let old_set = managed.host_set.load();
        let diff = diff_host_sets(&old_set, &new_set);
        // `discovery::resolve` always builds fresh
        // `Host`s with `HealthFlags::default()`, so without this a DNS
        // refresh would silently re-mark every unchanged host healthy --
        // see `host_set::carry_over_health_flags`.
        let new_set = carry_over_health_flags(&old_set, new_set, &diff);
        drop(old_set);
        managed.host_set.store(Arc::new(new_set));
        managed.initialized.store(true, Ordering::Release);
        managed.reconcile_probes(&diff);
        Ok(diff)
    }

    /// The router-facing handle for a cluster, or `None` if no cluster with
    /// that name is currently known.
    pub fn cluster(&self, name: &str) -> Option<Arc<dyn ClusterEntry>> {
        self.clusters.load().get(name).cloned().map(|managed| {
            Arc::new(ClusterHandle {
                managed,
                // Rust note: cloning the `Arc<ArcSwap<..>>` itself (not the
                // map it currently points at) -- see `ClusterManager::clusters`'s
                // doc for why this is what makes aggregate member lookups
                // late-bound.
                registry: Arc::clone(&self.clusters),
            }) as Arc<dyn ClusterEntry>
        })
    }

    /// Whether a cluster's first resolution/EDS update has landed (or it was
    /// force-initialized, see [`Self::force_initialize`]). `false` for an
    /// unknown cluster name.
    pub fn is_initialized(&self, name: &str) -> bool {
        self.clusters
            .load()
            .get(name)
            .map(|managed| managed.initialized.load(Ordering::Acquire))
            .unwrap_or(false)
    }

    /// Envoy's `initial_fetch_timeout` "proceed empty" escape hatch: mark a
    /// cluster initialized even though it never resolved, so downstream
    /// warming doesn't wait on it forever. A no-op for an unknown
    /// cluster name.
    pub fn force_initialize(&self, name: &str) {
        if let Some(managed) = self.clusters.load().get(name) {
            managed.initialized.store(true, Ordering::Release);
        }
    }

    /// The names of every currently-registered cluster still waiting on its
    /// first resolution/EDS update -- built on [`Self::is_initialized`], not
    /// a second copy of its logic. This is what gives
    /// `is_initialized` a production caller -- `/ready` gates on whether this
    /// is empty (see `proxy-admin`'s `ReadinessProbe` and `proxy/src/main.rs`).
    pub fn warming_clusters(&self) -> Vec<ClusterName> {
        self.clusters
            .load()
            .keys()
            .filter(|name| !self.is_initialized(name))
            .cloned()
            .collect()
    }

    /// Snapshot the runtime host sets whose cluster configuration matches the
    /// supplied config snapshot. A reload installs a replacement manager map
    /// before it publishes the matching `ConfigSnapshot`; filtering by the
    /// exact/equal config prevents an admin reader holding the old snapshot
    /// from accidentally reporting endpoints from that next, unpublished
    /// configuration. The returned endpoint lists are copies, so callers
    /// cannot retain a `ManagedCluster` or mutate a live host set.
    pub fn live_clusters_for(
        &self,
        configs: &HashMap<ClusterName, Arc<ClusterConfig>>,
    ) -> Vec<LiveCluster> {
        let registry = self.clusters.load();
        let mut clusters = Vec::with_capacity(configs.len());
        for (name, config) in configs {
            let Some(managed) = registry.get(name) else {
                continue;
            };
            if !Arc::ptr_eq(&managed.config, config) && *managed.config != **config {
                continue;
            }
            let host_set = managed.host_set.load();
            let mut endpoints: Vec<LiveEndpoint> = host_set
                .all_hosts()
                .into_iter()
                .map(|host| LiveEndpoint {
                    address: host.address,
                    hostname: host.hostname.clone(),
                    weight: host.weight,
                    priority: host.priority,
                    health_flags: host.health_flags.to_string(),
                    metadata: host.metadata.clone(),
                })
                .collect();
            endpoints.sort_by(|a, b| {
                (a.priority, a.address, &a.hostname).cmp(&(b.priority, b.address, &b.hostname))
            });
            clusters.push(LiveCluster {
                name: name.clone(),
                initialized: managed.initialized.load(Ordering::Acquire),
                endpoints,
            });
        }
        clusters.sort_by(|a, b| a.name.cmp(&b.name));
        clusters
    }
}

impl ClusterRegistrySnapshot {
    /// The router-facing handle for a cluster in this generation, or `None`
    /// when that generation did not contain the name.
    pub fn cluster(&self, name: &str) -> Option<Arc<dyn ClusterEntry>> {
        self.clusters.load().get(name).cloned().map(|managed| {
            Arc::new(ClusterHandle {
                managed,
                registry: Arc::clone(&self.clusters),
            }) as Arc<dyn ClusterEntry>
        })
    }

    /// Whether a cluster in this generation completed its initial discovery.
    pub fn is_initialized(&self, name: &str) -> bool {
        self.clusters
            .load()
            .get(name)
            .map(|managed| managed.initialized.load(Ordering::Acquire))
            .unwrap_or(false)
    }
}

/// The router-facing view of one cluster (implements [`ClusterEntry`]).
/// Cheap to clone -- both fields are `Arc`s.
struct ClusterHandle {
    managed: Arc<ManagedCluster>,
    /// A clone of the manager's own registry `Arc<ArcSwap<..>>` -- used only
    /// by the aggregate arm of [`ClusterEntry::select_host`]
    /// ([`Self::select_aggregate_member`]) to resolve a member *name* to its
    /// *current* [`ManagedCluster`] at pick time. See
    /// `ClusterManager::clusters`'s doc for why late binding matters here.
    registry: Arc<ArcSwap<HashMap<ClusterName, Arc<ManagedCluster>>>>,
}

impl ClusterHandle {
    /// The aggregate host-selection algorithm: walk `members` in
    /// config order, skipping any name already in `ctx.attempted_clusters`
    /// (so a retry falls over instead of re-picking the member that just
    /// failed); for each remaining candidate, resolve it against the
    /// *current* registry, skip it (logging, not erroring -- a transient
    /// config-reload race is real) if it isn't currently registered or is
    /// itself an aggregate, and otherwise ask that member's own
    /// [`HostPicker`] for a host from its own host set. The first member
    /// that yields a host wins.
    ///
    /// A member that is itself an aggregate is never followed. Nested
    /// aggregates are deliberately unsupported, and
    /// refusing to recurse makes a member cycle structurally impossible
    /// rather than something this loop has to detect.
    ///
    /// Deliberate divergence from Envoy: each member's own `HostPicker`
    /// still applies that member's full S7 logic (panic threshold, priority
    /// spillover, overprovisioning) *within* that member, but this loop does
    /// **not** implement Envoy's cross-member combined priority set, where a
    /// member at partial health bleeds a *fraction* of traffic across the
    /// member boundary. This is strict member-order failover: a member is
    /// skipped only when it yields no host at all. For LLM provider
    /// fallback that's the wanted semantic -- nobody wants a silent 40% of
    /// traffic quietly landing on the fallback provider (with its own
    /// billing and rate limits) just because the primary is partially
    /// degraded -- but it is coarser than Envoy for the homogeneous
    /// same-service-different-zone failover Envoy's aggregate cluster was
    /// originally designed for.
    fn select_aggregate_member(
        &self,
        members: &[ClusterName],
        ctx: &LoadBalancerContext,
    ) -> Option<HostSelection> {
        let registry = self.registry.load();
        for name in members {
            if ctx.attempted_clusters.contains(name) {
                continue;
            }
            let Some(member) = registry.get(name) else {
                tracing::warn!(
                    cluster = %name,
                    "aggregate member not found in cluster registry (config-reload race?), skipping"
                );
                continue;
            };
            if member.is_aggregate() {
                tracing::warn!(
                    cluster = %name,
                    "aggregate member is itself an aggregate cluster; nested aggregates are not \
                     supported yet, skipping"
                );
                continue;
            }
            let host_set = member.host_set.load();
            if let Some(host) = member.host_picker.pick(&host_set, ctx) {
                return Some(HostSelection {
                    host,
                    member: Some(SelectedMember {
                        name: name.clone(),
                        entry: Arc::new(ClusterHandle {
                            managed: Arc::clone(member),
                            registry: Arc::clone(&self.registry),
                        }),
                    }),
                });
            }
        }
        None
    }
}

impl ClusterEntry for ClusterHandle {
    fn select_host(&self, ctx: &LoadBalancerContext) -> Option<HostSelection> {
        match self.managed.aggregate_members() {
            None => {
                let host_set = self.managed.host_set.load();
                self.managed
                    .host_picker
                    .pick(&host_set, ctx)
                    .map(|host| HostSelection { host, member: None })
            }
            Some(members) => self.select_aggregate_member(members, ctx),
        }
    }

    fn http_pool(&self, host: &Arc<Host>, _proto: UpstreamProtocol) -> Arc<dyn HttpConnPool> {
        // v1 is connect-per-stream: `ConnectPool` just opens a fresh TCP
        // connection per request and hands it to the cluster's transport
        // socket (plaintext passthrough, or a TLS handshake). The resulting
        // byte stream is protocol-agnostic -- the router applies h1 or h2c on
        // top by picking the upstream codec -- so `_proto` doesn't change the
        // pool today. Real h2 multiplexing pools are a follow-up.
        let server_name = host
            .hostname
            .clone()
            .unwrap_or_else(|| host.address.ip().to_string());
        // Rust note: this slice enforces the DEFAULT-priority connection
        // budget only. `RoutingPriority::High` is a rare path and the router
        // doesn't thread priority into `http_pool` today, so a HIGH-priority
        // route's dials are still counted against `default_cb` here; wiring
        // per-priority connection budgets through is a follow-up, not this
        // slice. `.clone()` shares the same gauge (`CircuitBreakerState`'s
        // `Arc`-backed handles) across every per-call `ConnectPool` this
        // method builds for the cluster, so the count stays global per
        // cluster as intended.
        Arc::new(crate::pool::ConnectPool::new(
            host.address,
            Arc::clone(&self.managed.transport),
            server_name,
            self.managed.connect_timeout,
            self.circuit_breaker(RoutingPriority::Default).clone(),
        ))
    }

    fn upstream_protocol(&self) -> UpstreamProtocol {
        self.managed.upstream_protocol
    }

    fn circuit_breaker(&self, prio: RoutingPriority) -> &CircuitBreakerState {
        match prio {
            RoutingPriority::Default => &self.managed.default_cb,
            RoutingPriority::High => &self.managed.high_cb,
        }
    }

    fn request_headers_to_add(&self) -> &[proxy_config::ir::HeaderMutation] {
        // An aggregate's own `request_headers_to_add` is never read here: the
        // router calls this on the *member's* entry
        // (`HostSelection::member`), not the aggregate's. AGENTS.md invariant 6 --
        // anything per-provider belongs on the cluster that is actually
        // dialled -- is the reason that matters.
        &self.managed.config.request_headers_to_add
    }

    fn request_path_rewrite(&self) -> Option<&proxy_config::ir::RequestPathRewrite> {
        self.managed.config.request_path_rewrite.as_ref()
    }

    fn provider_runtime(&self) -> Option<&proxy_config::ir::ProviderRuntimeConfig> {
        self.managed.config.provider_runtime.as_ref()
    }

    fn usage_dialect(&self) -> Option<proxy_config::ir::UsageDialect> {
        self.managed.config.usage_dialect
    }

    fn report_outlier_result(&self, addr: SocketAddr, result: RequestResult) {
        // No-op unless this cluster configures outlier detection. For an
        // aggregate the router calls this on the *member's* entry (the one
        // that owns the dialed host), never the aggregate's own, so this
        // reaches the member's detector -- the same routing `request_headers_to_add`
        // above relies on.
        if let Some(detector) = &self.managed.outlier_detector {
            detector.report_result(addr, result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::FakeResolver;
    use crate::HealthFlags;
    use proxy_config::ir::{DiscoveryType, LbPolicy};
    use std::net::{IpAddr, SocketAddr};
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    use tokio::net::TcpListener;

    fn cluster_config(
        name: &str,
        discovery: DiscoveryType,
        endpoints: Vec<EndpointIR>,
    ) -> Arc<ClusterConfig> {
        Arc::new(ClusterConfig {
            // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
            eds: None,
            name: name.to_string(),
            discovery,
            lb_policy: LbPolicy::RoundRobin,
            connect_timeout: Duration::from_secs(5),
            endpoints,
            kind: ClusterKind::Endpoints,
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1 << 20,
            circuit_breakers: Default::default(),
            upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
            request_headers_to_add: Vec::new(),
            request_path_rewrite: None,
            provider_runtime: None,
            usage_dialect: None,
            health_check: None,
            outlier_detection: None,
        })
    }

    /// Same shape as `cluster_config`, plus a caller-supplied
    /// `connect_timeout`. Tests use this to build a
    /// second config that's a genuine, if inconsequential, content change
    /// from the first (`ClusterConfig` has no `Clone`, only `PartialEq`, so
    /// this is a second constructor rather than a `..base` update).
    fn cluster_config_with_connect_timeout(
        name: &str,
        discovery: DiscoveryType,
        endpoints: Vec<EndpointIR>,
        connect_timeout: Duration,
    ) -> Arc<ClusterConfig> {
        Arc::new(ClusterConfig {
            eds: None,
            name: name.to_string(),
            discovery,
            lb_policy: LbPolicy::RoundRobin,
            connect_timeout,
            endpoints,
            kind: ClusterKind::Endpoints,
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1 << 20,
            circuit_breakers: Default::default(),
            upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
            request_headers_to_add: Vec::new(),
            request_path_rewrite: None,
            provider_runtime: None,
            usage_dialect: None,
            health_check: None,
            outlier_detection: None,
        })
    }

    /// A config-sourced EDS cluster (`discovery: eds`): membership arrives
    /// via [`ClusterManager::accept_eds_update`], never
    /// `endpoints`/`discovery` resolution. Tests the paragraph in
    /// `update_from_snapshot`'s own doc about this shape surviving a reload.
    fn cluster_config_eds(name: &str) -> Arc<ClusterConfig> {
        Arc::new(ClusterConfig {
            eds: Some(proxy_config::ir::EdsClusterConfig {
                service_name: name.to_string(),
            }),
            name: name.to_string(),
            discovery: DiscoveryType::Eds,
            lb_policy: LbPolicy::RoundRobin,
            connect_timeout: Duration::from_secs(5),
            endpoints: Vec::new(),
            kind: ClusterKind::Endpoints,
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1 << 20,
            circuit_breakers: Default::default(),
            upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
            request_headers_to_add: Vec::new(),
            request_path_rewrite: None,
            provider_runtime: None,
            usage_dialect: None,
            health_check: None,
            outlier_detection: None,
        })
    }

    /// A STATIC cluster carrying an outlier-detection config that ejects on
    /// `consecutive_5xx` consecutive 5xx, enforced 100%, with a 100% ejection
    /// cap so a single-host cluster can eject its only host (the default 10%
    /// rounds down to zero for one host).
    fn cluster_config_with_outlier(
        name: &str,
        endpoints: Vec<EndpointIR>,
        consecutive_5xx: u32,
    ) -> Arc<ClusterConfig> {
        let od = proxy_config::ir::OutlierDetectionIR {
            consecutive_5xx,
            enforcing_consecutive_5xx: 100,
            max_ejection_percent: 100,
            ..proxy_config::ir::OutlierDetectionIR::ENVOY_DEFAULT
        };
        Arc::new(ClusterConfig {
            // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
            eds: None,
            name: name.to_string(),
            discovery: DiscoveryType::Static,
            lb_policy: LbPolicy::RoundRobin,
            connect_timeout: Duration::from_secs(5),
            endpoints,
            kind: ClusterKind::Endpoints,
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1 << 20,
            circuit_breakers: Default::default(),
            upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
            request_headers_to_add: Vec::new(),
            request_path_rewrite: None,
            provider_runtime: None,
            usage_dialect: None,
            health_check: None,
            outlier_detection: Some(od),
        })
    }

    /// An aggregate cluster over `members`, in the given order.
    /// `endpoints`/`discovery` are unused for an
    /// aggregate (see `ClusterKind::Aggregate`'s doc) but still need
    /// *something* syntactically valid to satisfy `ClusterConfig`'s shape.
    fn aggregate_config(name: &str, members: &[&str]) -> Arc<ClusterConfig> {
        Arc::new(ClusterConfig {
            // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
            eds: None,
            name: name.to_string(),
            discovery: DiscoveryType::Static,
            lb_policy: LbPolicy::RoundRobin,
            connect_timeout: Duration::from_secs(5),
            endpoints: Vec::new(),
            kind: ClusterKind::Aggregate {
                members: members.iter().map(|m| m.to_string()).collect(),
            },
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1 << 20,
            circuit_breakers: Default::default(),
            upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
            request_headers_to_add: Vec::new(),
            request_path_rewrite: None,
            provider_runtime: None,
            usage_dialect: None,
            health_check: None,
            outlier_detection: None,
        })
    }

    fn endpoint(host: &str, port: u16) -> EndpointIR {
        EndpointIR {
            metadata: Default::default(),
            host: host.to_string(),
            port,
            weight: 1,
            priority: 0,
        }
    }

    // --------------------------------------------- active health checks --

    /// Same shape as `cluster_config` above, plus a `health_check` -- kept
    /// separate rather than adding a parameter to `cluster_config` so the
    /// many call sites above that don't care about health checking stay
    /// untouched.
    fn cluster_config_with_health_check(
        name: &str,
        discovery: DiscoveryType,
        endpoints: Vec<EndpointIR>,
        health_check: proxy_config::ir::HealthCheckIR,
    ) -> Arc<ClusterConfig> {
        Arc::new(ClusterConfig {
            // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
            eds: None,
            name: name.to_string(),
            discovery,
            lb_policy: LbPolicy::RoundRobin,
            connect_timeout: Duration::from_secs(5),
            endpoints,
            kind: ClusterKind::Endpoints,
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1 << 20,
            circuit_breakers: Default::default(),
            upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
            request_headers_to_add: Vec::new(),
            request_path_rewrite: None,
            provider_runtime: None,
            usage_dialect: None,
            health_check: Some(health_check),
            outlier_detection: None,
        })
    }

    /// A bare-TCP-connect health check (empty `send`/`expect`, see
    /// `HealthCheckKindIR::Tcp`'s own doc) with the given thresholds/interval
    /// and a generous fixed timeout -- these tests care about threshold and
    /// scheduling behavior, not timeout edge cases (`health_check.rs`'s own
    /// test module already covers those).
    fn tcp_health_check(
        unhealthy_threshold: u32,
        healthy_threshold: u32,
        interval: Duration,
    ) -> proxy_config::ir::HealthCheckIR {
        proxy_config::ir::HealthCheckIR {
            interval,
            timeout: Duration::from_millis(500),
            interval_jitter: Duration::ZERO,
            unhealthy_threshold,
            healthy_threshold,
            no_traffic_interval: crate::health_check::DEFAULT_NO_TRAFFIC_INTERVAL,
            kind: proxy_config::ir::HealthCheckKindIR::Tcp {
                send: Vec::new(),
                expect: Vec::new(),
            },
        }
    }

    /// A cluster carrying BOTH a health check and outlier detection:
    /// `uneject_on_healthy_active_hc` is the
    /// one field the two tests below vary. `consecutive_5xx: 2`,
    /// `enforcing_consecutive_5xx: 100`, `max_ejection_percent: 100` mirror
    /// `cluster_config_with_outlier` -- enforced deterministically, and able
    /// to eject a single-host cluster's only host.
    fn cluster_config_with_health_check_and_outlier(
        name: &str,
        endpoints: Vec<EndpointIR>,
        health_check: proxy_config::ir::HealthCheckIR,
        uneject_on_healthy_active_hc: bool,
    ) -> Arc<ClusterConfig> {
        let od = proxy_config::ir::OutlierDetectionIR {
            consecutive_5xx: 2,
            enforcing_consecutive_5xx: 100,
            max_ejection_percent: 100,
            uneject_on_healthy_active_hc,
            ..proxy_config::ir::OutlierDetectionIR::ENVOY_DEFAULT
        };
        Arc::new(ClusterConfig {
            // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
            eds: None,
            name: name.to_string(),
            discovery: DiscoveryType::Static,
            lb_policy: LbPolicy::RoundRobin,
            connect_timeout: Duration::from_secs(5),
            endpoints,
            kind: ClusterKind::Endpoints,
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1 << 20,
            circuit_breakers: Default::default(),
            upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
            request_headers_to_add: Vec::new(),
            request_path_rewrite: None,
            provider_runtime: None,
            usage_dialect: None,
            health_check: Some(health_check),
            outlier_detection: Some(od),
        })
    }

    /// Spawns a task that accepts connections forever and counts each one --
    /// the observable signal these tests use to prove a probe loop is (or
    /// isn't) still running, since a `JoinHandle` living or dying isn't
    /// otherwise visible from outside `manager.rs`.
    fn spawn_counting_acceptor(listener: TcpListener, hits: Arc<AtomicUsize>) {
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_ok() {
                    hits.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }

    /// Poll `cond` on real wall-clock time until it's true or `deadline`
    /// elapses -- same rationale as `health_check`'s own `wait_until`: these
    /// tests assert on genuine TCP connect/accept timing, which races
    /// unpredictably against a paused clock's auto-advance.
    async fn wait_until(deadline: Duration, mut cond: impl FnMut() -> bool) {
        let start = std::time::Instant::now();
        while !cond() {
            assert!(
                start.elapsed() < deadline,
                "condition not met within {deadline:?}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn static_cluster_becomes_available_and_initialized() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "static-svc".to_string(),
            cluster_config(
                "static-svc",
                DiscoveryType::Static,
                vec![endpoint("10.0.0.1", 80)],
            ),
        );

        assert!(manager.cluster("static-svc").is_none());
        manager.update_from_snapshot(&snapshot).await;

        assert!(manager.cluster("static-svc").is_some());
        assert!(manager.is_initialized("static-svc"));
    }

    #[tokio::test]
    async fn removing_a_cluster_from_the_snapshot_drops_it() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "svc".to_string(),
            cluster_config("svc", DiscoveryType::Static, vec![endpoint("10.0.0.1", 80)]),
        );
        manager.update_from_snapshot(&snapshot).await;
        assert!(manager.cluster("svc").is_some());

        snapshot.clear();
        manager.update_from_snapshot(&snapshot).await;
        assert!(manager.cluster("svc").is_none());
    }

    #[tokio::test]
    async fn routing_snapshot_keeps_removed_cluster_for_its_generation() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "svc".to_string(),
            cluster_config("svc", DiscoveryType::Static, vec![endpoint("10.0.0.1", 80)]),
        );
        manager.update_from_snapshot(&snapshot).await;
        let routing = manager.routing_snapshot();

        snapshot.clear();
        manager.update_from_snapshot(&snapshot).await;

        assert!(manager.cluster("svc").is_none());
        assert!(routing.cluster("svc").is_some());
        assert!(routing.is_initialized("svc"));
    }

    #[tokio::test]
    async fn strict_dns_refresh_reflects_a_flap() {
        let resolver = Arc::new(FakeResolver::new());
        resolver.set(
            "svc.internal",
            vec![IpAddr::from([10, 0, 0, 1]), IpAddr::from([10, 0, 0, 2])],
        );
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "dns-svc".to_string(),
            cluster_config(
                "dns-svc",
                DiscoveryType::StrictDns,
                vec![endpoint("svc.internal", 80)],
            ),
        );
        manager.update_from_snapshot(&snapshot).await;

        // Flap the record set and re-resolve manually (no real timer).
        resolver.set(
            "svc.internal",
            vec![IpAddr::from([10, 0, 0, 2]), IpAddr::from([10, 0, 0, 3])],
        );
        let diff = manager.refresh_cluster("dns-svc").await.unwrap();

        assert_eq!(
            diff.added,
            vec![SocketAddr::new(IpAddr::from([10, 0, 0, 3]), 80)]
        );
        assert_eq!(
            diff.removed,
            vec![SocketAddr::new(IpAddr::from([10, 0, 0, 1]), 80)]
        );
        assert_eq!(
            diff.unchanged,
            vec![SocketAddr::new(IpAddr::from([10, 0, 0, 2]), 80)]
        );
        let live = manager.live_clusters_for(&snapshot);
        assert_eq!(live[0].endpoints.len(), 2);
        assert_eq!(live[0].endpoints[0].address, "10.0.0.2:80".parse().unwrap());
        assert_eq!(
            live[0].endpoints[0].hostname.as_deref(),
            Some("svc.internal")
        );
        assert_eq!(live[0].endpoints[1].address, "10.0.0.3:80".parse().unwrap());
    }

    #[tokio::test]
    async fn eds_cluster_starts_uninitialized_then_accepts_an_update() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert("eds-svc".to_string(), cluster_config_eds("eds-svc"));
        manager.update_from_snapshot(&snapshot).await;

        assert!(manager.cluster("eds-svc").is_some());
        assert!(!manager.is_initialized("eds-svc"));

        let diff = manager
            .accept_eds_update("eds-svc", &[endpoint("10.0.0.5", 80)])
            .unwrap();
        assert_eq!(
            diff.added,
            vec![SocketAddr::new(IpAddr::from([10, 0, 0, 5]), 80)]
        );
        assert!(manager.is_initialized("eds-svc"));
    }

    /// The admin seam must snapshot what EDS installed, including the
    /// endpoint labels, rather than falling back to the empty configured
    /// endpoint list that an EDS cluster necessarily has.
    #[tokio::test]
    async fn live_cluster_snapshot_exposes_eds_membership_and_metadata() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert("eds-svc".to_string(), cluster_config_eds("eds-svc"));
        manager.update_from_snapshot(&snapshot).await;

        let mut eds_endpoint = endpoint("10.0.0.55", 8443);
        eds_endpoint
            .metadata
            .insert("node_id".to_string(), "gpu-a7".to_string());
        manager
            .accept_eds_update("eds-svc", &[eds_endpoint])
            .expect("EDS update");

        let live = manager.live_clusters_for(&snapshot);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].name, "eds-svc");
        assert!(live[0].initialized);
        assert_eq!(live[0].endpoints.len(), 1);
        assert_eq!(
            live[0].endpoints[0].address,
            "10.0.0.55:8443".parse().unwrap()
        );
        assert_eq!(
            live[0].endpoints[0]
                .metadata
                .get("node_id")
                .map(String::as_str),
            Some("gpu-a7")
        );

        // A config snapshot that differs from the installed manager entry
        // must not borrow its host set during the manager-first half of a
        // reload. Empty is safe; a future endpoint would not be.
        let changed = HashMap::from([(
            "eds-svc".to_string(),
            cluster_config(
                "eds-svc",
                DiscoveryType::Static,
                vec![endpoint("10.0.0.99", 80)],
            ),
        )]);
        assert!(manager.live_clusters_for(&changed).is_empty());
    }

    #[tokio::test]
    async fn force_initialize_marks_an_unresolved_cluster_ready() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert("never-fed".to_string(), cluster_config_eds("never-fed"));
        manager.update_from_snapshot(&snapshot).await;
        assert!(!manager.is_initialized("never-fed"));
        manager.force_initialize("never-fed");
        assert!(manager.is_initialized("never-fed"));
    }

    #[tokio::test]
    async fn warming_clusters_reports_unresolved_and_omits_resolved() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "static-svc".to_string(),
            cluster_config(
                "static-svc",
                DiscoveryType::Static,
                vec![endpoint("10.0.0.1", 80)],
            ),
        );
        snapshot.insert("never-fed".to_string(), cluster_config_eds("never-fed"));
        manager.update_from_snapshot(&snapshot).await;

        let warming = manager.warming_clusters();
        assert_eq!(warming, vec!["never-fed".to_string()]);
    }

    #[tokio::test]
    async fn pick_host_round_robins_priority_zero() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "rr-svc".to_string(),
            cluster_config(
                "rr-svc",
                DiscoveryType::Static,
                vec![endpoint("10.0.0.1", 80), endpoint("10.0.0.2", 80)],
            ),
        );
        manager.update_from_snapshot(&snapshot).await;
        let entry = manager.cluster("rr-svc").unwrap();

        let ctx = LoadBalancerContext::default();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..4 {
            let sel = entry.select_host(&ctx).unwrap();
            // A non-aggregate cluster's pick never carries a `member` --
            // the entry the caller already holds is the owner, so there's
            // nothing further to resolve.
            assert!(sel.member.is_none());
            seen.insert(sel.host.address);
        }
        assert_eq!(seen.len(), 2);
    }

    // --------------------------------------------------- aggregate ---

    /// Build a manager with two `Endpoints` clusters `"a"`/`"b"` (each one
    /// healthy host) plus an aggregate `"providers"` over `["a", "b"]`.
    async fn aggregate_over_a_and_b(a_endpoints: Vec<EndpointIR>) -> ClusterManager {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "a".to_string(),
            cluster_config("a", DiscoveryType::Static, a_endpoints),
        );
        snapshot.insert(
            "b".to_string(),
            cluster_config("b", DiscoveryType::Static, vec![endpoint("10.0.0.2", 80)]),
        );
        snapshot.insert(
            "providers".to_string(),
            aggregate_config("providers", &["a", "b"]),
        );
        manager.update_from_snapshot(&snapshot).await;
        manager
    }

    #[tokio::test]
    async fn aggregate_selects_the_first_member_with_a_healthy_host() {
        let manager = aggregate_over_a_and_b(vec![endpoint("10.0.0.1", 80)]).await;
        let entry = manager.cluster("providers").unwrap();

        let ctx = LoadBalancerContext::default();
        let sel = entry.select_host(&ctx).expect("aggregate should serve a");
        assert_eq!(
            sel.host.address,
            SocketAddr::new(IpAddr::from([10, 0, 0, 1]), 80)
        );
        let member = sel.member.expect("aggregate pick must carry its member");
        assert_eq!(member.name, "a");
    }

    #[tokio::test]
    async fn aggregate_falls_over_to_the_next_member_when_the_first_has_no_hosts() {
        // "a" configured with no endpoints at all -- an empty host set.
        let manager = aggregate_over_a_and_b(Vec::new()).await;
        let entry = manager.cluster("providers").unwrap();

        let ctx = LoadBalancerContext::default();
        let sel = entry.select_host(&ctx).expect("aggregate should serve b");
        assert_eq!(
            sel.host.address,
            SocketAddr::new(IpAddr::from([10, 0, 0, 2]), 80)
        );
        let member = sel.member.expect("aggregate pick must carry its member");
        assert_eq!(member.name, "b");
    }

    #[tokio::test]
    async fn aggregate_skips_members_already_attempted_this_request() {
        let manager = aggregate_over_a_and_b(vec![endpoint("10.0.0.1", 80)]).await;
        let entry = manager.cluster("providers").unwrap();

        let ctx = LoadBalancerContext {
            attempted_clusters: vec!["a".to_string()],
            ..LoadBalancerContext::default()
        };
        let sel = entry
            .select_host(&ctx)
            .expect("aggregate should fall over to b");
        assert_eq!(sel.member.unwrap().name, "b");

        let ctx_exhausted = LoadBalancerContext {
            attempted_clusters: vec!["a".to_string(), "b".to_string()],
            ..LoadBalancerContext::default()
        };
        assert!(
            entry.select_host(&ctx_exhausted).is_none(),
            "every member already attempted -- no host to serve"
        );
    }

    #[tokio::test]
    async fn aggregate_member_resolution_is_late_bound_across_a_reload() {
        let manager = aggregate_over_a_and_b(vec![endpoint("10.0.0.1", 80)]).await;
        let entry = manager.cluster("providers").unwrap();

        // Force "a" out so only "b" can serve, then reload "b" to point at a
        // different address entirely.
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "a".to_string(),
            cluster_config("a", DiscoveryType::Static, Vec::new()),
        );
        snapshot.insert(
            "b".to_string(),
            cluster_config("b", DiscoveryType::Static, vec![endpoint("10.0.0.99", 80)]),
        );
        snapshot.insert(
            "providers".to_string(),
            aggregate_config("providers", &["a", "b"]),
        );
        manager.update_from_snapshot(&snapshot).await;

        // The SAME `entry`, obtained before the reload, must still see the
        // new address -- proving member resolution isn't pinned to whatever
        // `ManagedCluster` existed when the aggregate's handle was built.
        let ctx = LoadBalancerContext::default();
        let sel = entry.select_host(&ctx).expect("aggregate should serve b");
        assert_eq!(
            sel.host.address,
            SocketAddr::new(IpAddr::from([10, 0, 0, 99]), 80)
        );
    }

    #[tokio::test]
    async fn aggregate_skips_a_member_name_that_resolves_to_no_cluster() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "b".to_string(),
            cluster_config("b", DiscoveryType::Static, vec![endpoint("10.0.0.2", 80)]),
        );
        // "a" is named as a member but never registered.
        snapshot.insert(
            "providers".to_string(),
            aggregate_config("providers", &["a", "b"]),
        );
        manager.update_from_snapshot(&snapshot).await;
        let entry = manager.cluster("providers").unwrap();

        let ctx = LoadBalancerContext::default();
        let sel = entry
            .select_host(&ctx)
            .expect("aggregate should skip the missing member and serve b");
        assert_eq!(sel.member.unwrap().name, "b");
    }

    #[tokio::test]
    async fn aggregate_skips_a_member_that_is_itself_an_aggregate() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "b".to_string(),
            cluster_config("b", DiscoveryType::Static, vec![endpoint("10.0.0.2", 80)]),
        );
        // "inner" is itself an aggregate -- must not be recursed into.
        snapshot.insert("inner".to_string(), aggregate_config("inner", &["b"]));
        snapshot.insert(
            "providers".to_string(),
            aggregate_config("providers", &["inner", "b"]),
        );
        manager.update_from_snapshot(&snapshot).await;
        let entry = manager.cluster("providers").unwrap();

        let ctx = LoadBalancerContext::default();
        let sel = entry
            .select_host(&ctx)
            .expect("aggregate should skip the nested aggregate and serve b");
        assert_eq!(sel.member.unwrap().name, "b");
    }

    // --------------------------------------------- active health checks --

    /// An active health check must actually run: two static hosts -- one a live
    /// listener, one a bound-then-dropped port so nothing answers -- with `unhealthy_threshold: 1`
    /// and a short interval; `all_healthy_hosts()` must converge to exactly
    /// the live host.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn health_check_converges_to_only_the_live_host() {
        let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let _ = live.accept().await;
            }
        });

        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead); // nothing listens here -> every connect attempt fails

        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "hc-svc".to_string(),
            cluster_config_with_health_check(
                "hc-svc",
                DiscoveryType::Static,
                vec![
                    endpoint(&live_addr.ip().to_string(), live_addr.port()),
                    endpoint(&dead_addr.ip().to_string(), dead_addr.port()),
                ],
                tcp_health_check(1, 1, Duration::from_millis(10)),
            ),
        );
        manager.update_from_snapshot(&snapshot).await;

        wait_until(Duration::from_secs(5), || {
            let clusters = manager.clusters.load();
            let managed = clusters.get("hc-svc").expect("cluster must exist");
            let healthy: Vec<SocketAddr> = managed
                .host_set
                .load()
                .all_healthy_hosts()
                .iter()
                .map(|h| h.address)
                .collect();
            healthy == vec![live_addr]
        })
        .await;
    }

    /// `discovery::resolve` builds
    /// every `Host` fresh with `HealthFlags::default()`, so a naive
    /// `host_set.store(new_set)` on refresh would silently re-mark an
    /// already-unhealthy host healthy on every DNS cycle. Flip a host
    /// unhealthy directly (simulating an active-check failure that already
    /// landed), re-run discovery against an unchanged DNS record set, and
    /// confirm the flag survives.
    #[tokio::test]
    async fn refresh_cluster_carries_over_health_flags_for_unchanged_hosts() {
        let resolver = Arc::new(FakeResolver::new());
        resolver.set("svc.internal", vec![IpAddr::from([10, 0, 0, 1])]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "dns-svc".to_string(),
            cluster_config(
                "dns-svc",
                DiscoveryType::StrictDns,
                vec![endpoint("svc.internal", 80)],
            ),
        );
        manager.update_from_snapshot(&snapshot).await;

        let addr = SocketAddr::new(IpAddr::from([10, 0, 0, 1]), 80);
        let managed = manager.clusters.load().get("dns-svc").unwrap().clone();
        managed
            .host_set
            .store(Arc::new(HostSet::from_hosts(vec![Arc::new(Host {
                address: addr,
                hostname: Some("svc.internal".to_string()),
                metadata: Default::default(),
                weight: 1,
                priority: 0,
                health_flags: HealthFlags {
                    failed_active_hc: true,
                    failed_outlier_check: false,
                },
                active_requests: std::sync::atomic::AtomicU64::new(0),
            })])));

        // Same DNS record set -- `addr` is `unchanged`, so its flipped flag
        // must survive, not be reset to `HealthFlags::default()` by the
        // freshly-resolved `Host` this refresh builds.
        manager.refresh_cluster("dns-svc").await.unwrap();

        let host = managed
            .host_set
            .load()
            .all_hosts()
            .into_iter()
            .find(|h| h.address == addr)
            .expect("host must still be present after refresh");
        assert!(
            !host.is_healthy(),
            "an unchanged host's health flag was reset by refresh_cluster"
        );
    }

    /// A removed host's probe must stop: flip `host-doomed`'s DNS record to
    /// empty and re-resolve the *same* cluster (`refresh_cluster`, not a
    /// config reload) -- `reconcile_probes`'s `removed` path must abort its
    /// task, not just drop the map entry (a bare drop doesn't abort the
    /// underlying tokio task -- see `ManagedCluster`'s `Drop` impl doc).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_removed_hosts_probe_stops() {
        let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        let live_hits = Arc::new(AtomicUsize::new(0));
        spawn_counting_acceptor(live, Arc::clone(&live_hits));

        let doomed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let doomed_addr = doomed.local_addr().unwrap();
        let doomed_hits = Arc::new(AtomicUsize::new(0));
        spawn_counting_acceptor(doomed, Arc::clone(&doomed_hits));

        let resolver = Arc::new(FakeResolver::new());
        resolver.set("host-live", vec![live_addr.ip()]);
        resolver.set("host-doomed", vec![doomed_addr.ip()]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "removal".to_string(),
            cluster_config_with_health_check(
                "removal",
                DiscoveryType::StrictDns,
                vec![
                    endpoint("host-live", live_addr.port()),
                    endpoint("host-doomed", doomed_addr.port()),
                ],
                tcp_health_check(1, 1, Duration::from_millis(15)),
            ),
        );
        manager.update_from_snapshot(&snapshot).await;
        wait_until(Duration::from_secs(5), || {
            live_hits.load(Ordering::SeqCst) >= 2 && doomed_hits.load(Ordering::SeqCst) >= 2
        })
        .await;

        resolver.set("host-doomed", vec![]);
        manager.refresh_cluster("removal").await.unwrap();

        let doomed_after_removal = doomed_hits.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            doomed_hits.load(Ordering::SeqCst),
            doomed_after_removal,
            "a removed host's probe kept connecting after it left the cluster"
        );
        // host-live's own probe is unaffected by host-doomed's removal.
        wait_until(Duration::from_secs(5), || {
            live_hits.load(Ordering::SeqCst) > doomed_after_removal
        })
        .await;
    }

    /// A config reload must not leak the previous generation's probes.
    /// `update_from_snapshot` rebuilds a config-sourced `ManagedCluster`
    /// whenever its config actually changed -- reload a single-host config
    /// several times, each with a genuinely different `interval`. Reloading the SAME config
    /// would now hit the carry-forward, which skips the rebuild entirely and no probe is ever
    /// aborted -- it would pass without exercising the `Drop` path it exists
    /// to prove), and confirm the hit rate against that host's listener stays
    /// at roughly one generation's worth, rather than scaling with the number
    /// of reloads (which is exactly what a dropped-but-not-aborted
    /// `JoinHandle` per reload would produce).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_config_reload_does_not_leak_the_previous_generations_probes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        spawn_counting_acceptor(listener, Arc::clone(&hits));

        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let reload_config = |interval_ms: u64| {
            let mut snapshot = HashMap::new();
            snapshot.insert(
                "reload".to_string(),
                cluster_config_with_health_check(
                    "reload",
                    DiscoveryType::Static,
                    vec![endpoint(&addr.ip().to_string(), addr.port())],
                    tcp_health_check(1, 1, Duration::from_millis(interval_ms)),
                ),
            );
            snapshot
        };
        manager.update_from_snapshot(&reload_config(15)).await;
        wait_until(Duration::from_secs(5), || hits.load(Ordering::SeqCst) >= 3).await;

        let baseline_start = hits.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(250)).await;
        let baseline = hits.load(Ordering::SeqCst) - baseline_start;

        // Each reload's `interval` differs from the last, so
        // `ClusterConfig`'s content equality never carry-forwards this
        // cluster -- every one of these four calls really rebuilds it.
        for i in 0..4u64 {
            manager.update_from_snapshot(&reload_config(15 + i)).await;
        }

        let after_start = hits.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(250)).await;
        let after = hits.load(Ordering::SeqCst) - after_start;

        assert!(
            after <= baseline * 3,
            "hit rate after 4 reloads ({after} hits/250ms) is far above the \
             single-generation baseline ({baseline} hits/250ms) -- earlier \
             generations' probes were never aborted and are still running"
        );
    }

    /// Acceptance test: a cluster configured with outlier detection
    /// ejects a host once it has returned `consecutive_5xx` consecutive 5xx --
    /// fed through the exact `ClusterEntry::report_outlier_result` seam the
    /// router uses.
    #[tokio::test]
    async fn outlier_detection_ejects_a_host_after_consecutive_5xx() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "od-svc".to_string(),
            cluster_config_with_outlier("od-svc", vec![endpoint("10.0.0.1", 80)], 3),
        );
        manager.update_from_snapshot(&snapshot).await;
        let entry = manager.cluster("od-svc").unwrap();
        let target = SocketAddr::new(IpAddr::from([10, 0, 0, 1]), 80);

        let healthy = || {
            manager
                .clusters
                .load()
                .get("od-svc")
                .unwrap()
                .host_set
                .load()
                .all_healthy_hosts()
                .iter()
                .any(|h| h.address == target)
        };
        assert!(healthy(), "host starts healthy");

        // Two 5xx below the threshold: still healthy.
        entry.report_outlier_result(target, RequestResult::Http5xx);
        entry.report_outlier_result(target, RequestResult::Http5xx);
        assert!(
            healthy(),
            "two 5xx is below the consecutive_5xx=3 threshold"
        );

        // The third crosses it and ejects (enforced 100%, 100% cap).
        entry.report_outlier_result(target, RequestResult::Http5xx);
        assert!(
            !healthy(),
            "three consecutive 5xx must eject the host via report_outlier_result"
        );
    }

    /// A `Success` in the middle of a 5xx run resets the consecutive counter,
    /// so the host is NOT ejected -- proving the report seam carries the
    /// result kind through, not just "something happened".
    #[tokio::test]
    async fn a_success_through_the_report_seam_resets_the_run() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "od-svc".to_string(),
            cluster_config_with_outlier("od-svc", vec![endpoint("10.0.0.1", 80)], 3),
        );
        manager.update_from_snapshot(&snapshot).await;
        let entry = manager.cluster("od-svc").unwrap();
        let target = SocketAddr::new(IpAddr::from([10, 0, 0, 1]), 80);

        entry.report_outlier_result(target, RequestResult::Http5xx);
        entry.report_outlier_result(target, RequestResult::Http5xx);
        entry.report_outlier_result(target, RequestResult::Success); // resets
        entry.report_outlier_result(target, RequestResult::Http5xx);
        entry.report_outlier_result(target, RequestResult::Http5xx);

        let healthy = manager
            .clusters
            .load()
            .get("od-svc")
            .unwrap()
            .host_set
            .load()
            .all_healthy_hosts()
            .iter()
            .any(|h| h.address == target);
        assert!(
            healthy,
            "a Success reset the run, so two more 5xx must not reach the threshold of 3"
        );
    }

    /// A cluster with no `outlier_detection` builds no detector, so reporting
    /// against it is a harmless no-op -- the router calls the seam
    /// unconditionally after every attempt.
    #[tokio::test]
    async fn report_is_a_noop_without_outlier_detection_configured() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "plain".to_string(),
            cluster_config(
                "plain",
                DiscoveryType::Static,
                vec![endpoint("10.0.0.1", 80)],
            ),
        );
        manager.update_from_snapshot(&snapshot).await;
        let entry = manager.cluster("plain").unwrap();
        let target = SocketAddr::new(IpAddr::from([10, 0, 0, 1]), 80);

        for _ in 0..10 {
            entry.report_outlier_result(target, RequestResult::Http5xx);
        }
        let healthy = manager
            .clusters
            .load()
            .get("plain")
            .unwrap()
            .host_set
            .load()
            .all_healthy_hosts()
            .iter()
            .any(|h| h.address == target);
        assert!(healthy, "no detector configured -> reporting is a no-op");
    }

    // ---------------------------- active-HC clears outlier --

    /// Active-HC recovery must clear an outlier ejection: a host outlier-ejected via
    /// `report_outlier_result` must be un-ejected once a REAL active health
    /// check against it passes -- not just have `failed_active_hc` flip, but
    /// the whole host must rejoin `all_healthy_hosts()`.
    ///
    /// The address starts with nothing listening (bind, then drop -- the
    /// same "dead, then stood up later" shape `health_check.rs`'s own
    /// `a_transition_publishes_a_host_set_the_picker_then_observes` uses),
    /// so the probe's first check fails and its `ConsecutiveTracker` (see
    /// `health_check.rs`) actually crosses into `Unhealthy` -- that edge is
    /// what makes the *later* recovery a real `Some(Healthy)` transition,
    /// which is the only thing `HealthCheckEngine::run_host_loop` calls
    /// `on_active_health_check_pass` on. `report_outlier_result` then ejects
    /// the same host independently through the outlier path, so it carries
    /// both flags (`failed_active_hc` from the real failing probe,
    /// `failed_outlier_check` from the manual report) before a real listener
    /// stands up and both must clear.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn active_health_check_recovery_also_clears_an_outlier_ejection() {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe); // nothing listens yet -> connect fails -> first check fails

        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "hc-od-svc".to_string(),
            cluster_config_with_health_check_and_outlier(
                "hc-od-svc",
                vec![endpoint(&addr.ip().to_string(), addr.port())],
                tcp_health_check(1, 1, Duration::from_millis(10)),
                true, // uneject_on_healthy_active_hc (S6 default)
            ),
        );
        manager.update_from_snapshot(&snapshot).await;
        let entry = manager.cluster("hc-od-svc").unwrap();

        let flags = || {
            manager
                .clusters
                .load()
                .get("hc-od-svc")
                .unwrap()
                .host_set
                .load()
                .all_hosts()
                .into_iter()
                .find(|h| h.address == addr)
                .expect("host must still be present")
                .health_flags
        };

        // The real probe crosses `unhealthy_threshold: 1` against the dead
        // address -- confirms the edge this test depends on actually fires
        // before layering the outlier ejection on top.
        wait_until(Duration::from_secs(5), || flags().failed_active_hc).await;

        // Eject via the outlier path too, independent of the active check.
        entry.report_outlier_result(addr, RequestResult::Http5xx);
        entry.report_outlier_result(addr, RequestResult::Http5xx);
        assert!(
            flags().failed_outlier_check,
            "two consecutive 5xx (consecutive_5xx: 2) must eject via report_outlier_result"
        );

        // Now stand up a real listener at the same address so the probe
        // starts passing.
        let listener = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        wait_until(Duration::from_secs(5), || {
            manager
                .clusters
                .load()
                .get("hc-od-svc")
                .unwrap()
                .host_set
                .load()
                .all_healthy_hosts()
                .iter()
                .any(|h| h.address == addr)
        })
        .await;
    }

    /// The negative half of the same acceptance test: with
    /// `uneject_on_healthy_active_hc: false`, the identical recovery must
    /// flip `failed_active_hc` back to `false` (the active-HC engine itself
    /// doesn't know or care about outlier state) but must NOT touch
    /// `failed_outlier_check` -- the host stays out of `all_healthy_hosts()`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn uneject_on_healthy_active_hc_false_leaves_the_outlier_ejection_in_place() {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "hc-od-svc-2".to_string(),
            cluster_config_with_health_check_and_outlier(
                "hc-od-svc-2",
                vec![endpoint(&addr.ip().to_string(), addr.port())],
                tcp_health_check(1, 1, Duration::from_millis(10)),
                false, // uneject_on_healthy_active_hc disabled
            ),
        );
        manager.update_from_snapshot(&snapshot).await;
        let entry = manager.cluster("hc-od-svc-2").unwrap();

        let flags = || {
            manager
                .clusters
                .load()
                .get("hc-od-svc-2")
                .unwrap()
                .host_set
                .load()
                .all_hosts()
                .into_iter()
                .find(|h| h.address == addr)
                .expect("host must still be present")
                .health_flags
        };

        wait_until(Duration::from_secs(5), || flags().failed_active_hc).await;

        entry.report_outlier_result(addr, RequestResult::Http5xx);
        entry.report_outlier_result(addr, RequestResult::Http5xx);
        assert!(flags().failed_outlier_check, "must eject via outlier path");

        let listener = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        // The active-HC side recovers on its own regardless of the outlier
        // config -- the two subsystems are independent.
        wait_until(Duration::from_secs(5), || !flags().failed_active_hc).await;

        // But the outlier ejection must survive: give the (now-passing)
        // probe several more ticks so a wiring bug that ignores the config
        // flag has ample opportunity to un-eject anyway, then assert it
        // didn't.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            flags().failed_outlier_check,
            "uneject_on_healthy_active_hc: false must leave the outlier ejection in place"
        );
        assert!(
            !manager
                .clusters
                .load()
                .get("hc-od-svc-2")
                .unwrap()
                .host_set
                .load()
                .all_healthy_hosts()
                .iter()
                .any(|h| h.address == addr),
            "host must stay out of all_healthy_hosts() while outlier-ejected"
        );
    }

    // -------------------------------------------- reload ordering --------

    /// The bug: the old `update_from_snapshot` stored every rebuilt cluster
    /// with an EMPTY `HostSet` first and resolved them one at a time
    /// afterward, serially. A `STRICT_DNS` cluster slow to resolve therefore
    /// left every OTHER cluster in the same reload -- including a `STATIC`
    /// one that needs no I/O at all -- serving empty for the whole span of
    /// that loop. `#[tokio::test(flavor = "multi_thread")]` is required, not
    /// `current_thread`: a single-threaded runtime can't run the spawned
    /// reload and this test's sampling loop concurrently, so it would never
    /// actually observe the mid-resolution window (AGENTS.md "Build And Test").
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_slow_dns_cluster_does_not_empty_other_clusters_mid_reload() {
        let resolver = Arc::new(FakeResolver::new());
        resolver.set("svc.internal", vec![IpAddr::from([10, 0, 0, 1])]);
        let manager = Arc::new(ClusterManager::with_default_transport(resolver.clone()));

        let snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::from([
            (
                "dns-svc".to_string(),
                cluster_config(
                    "dns-svc",
                    DiscoveryType::StrictDns,
                    vec![endpoint("svc.internal", 80)],
                ),
            ),
            (
                "static-svc".to_string(),
                cluster_config(
                    "static-svc",
                    DiscoveryType::Static,
                    vec![endpoint("10.0.0.9", 80)],
                ),
            ),
        ]);
        // First reload: both clusters get real, populated host sets.
        manager.update_from_snapshot(&snapshot).await;
        assert!(manager
            .cluster("static-svc")
            .unwrap()
            .select_host(&LoadBalancerContext::default())
            .is_some());

        // Make the second reload's DNS resolution slow enough to hold the
        // reload open for the whole sampling window below.
        resolver.set_delay("svc.internal", Duration::from_millis(300));

        // Reloading the identical `snapshot` map (as this
        // test used to) now carries BOTH clusters forward by content
        // equality, so `dns-svc` is never rebuilt or resolved and the
        // reload returns near-instantly -- defeating the whole point of this
        // test. Give `dns-svc` a real, if inconsequential, config change (a
        // different `connect_timeout`) so it still takes the rebuild path
        // and its slow resolution genuinely holds the reload open;
        // `static-svc`'s `Arc<ClusterConfig>` is untouched, so it is exactly
        // the carried-forward cluster this sampling loop is asserting stays
        // populated throughout.
        let mut snapshot_for_reload = snapshot.clone();
        snapshot_for_reload.insert(
            "dns-svc".to_string(),
            Arc::new(ClusterConfig {
                // Same shape as `cluster_config`'s literal, but a genuinely
                // different `connect_timeout` -- `ClusterConfig` has no
                // `Clone` (only `PartialEq`), so this is
                // written out rather than `..base.clone()`.
                eds: None,
                name: "dns-svc".to_string(),
                discovery: DiscoveryType::StrictDns,
                lb_policy: LbPolicy::RoundRobin,
                connect_timeout: Duration::from_secs(6),
                endpoints: vec![endpoint("svc.internal", 80)],
                kind: ClusterKind::Endpoints,
                transport_socket: None,
                per_connection_buffer_limit_bytes: 1 << 20,
                circuit_breakers: Default::default(),
                upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
                request_headers_to_add: Vec::new(),
                request_path_rewrite: None,
                provider_runtime: None,
                usage_dialect: None,
                health_check: None,
                outlier_detection: None,
            }),
        );

        let manager_for_reload = Arc::clone(&manager);
        let reload = tokio::spawn(async move {
            manager_for_reload
                .update_from_snapshot(&snapshot_for_reload)
                .await;
        });

        // Sample static-svc's host set repeatedly while the reload is still
        // in flight. On the buggy sequencing this window goes empty the
        // instant `update_from_snapshot` stores its freshly-built (all-empty)
        // map, well before the slow DNS cluster finishes resolving.
        let ctx = LoadBalancerContext::default();
        let mut samples = 0;
        while !reload.is_finished() {
            let entry = manager
                .cluster("static-svc")
                .expect("static-svc must stay registered across the whole reload");
            assert!(
                entry.select_host(&ctx).is_some(),
                "static-svc's host set was empty while an unrelated STRICT_DNS \
                 cluster in the same reload was still resolving"
            );
            samples += 1;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        reload.await.unwrap();
        assert!(
            samples > 10,
            "sampling window too short to actually exercise the concurrent \
             reload (got {samples} samples) -- resolver delay may need to be longer"
        );
    }

    // -------------------------------------------- carry-forward --------

    /// The ADS path: `SotwSet::apply` (`proxy-xds/src/store.rs`) keeps the
    /// OLD resource `Arc` for anything a CDS push compares `unchanged`, and
    /// `ResourceApplier::assemble_snapshot` (`proxy-xds/src/apply.rs`)
    /// `Arc::clone`s it into the next snapshot -- so this method sees the
    /// exact same `Arc<ClusterConfig>` pointer again for a cluster nothing
    /// changed. Proves the cheap `Arc::ptr_eq` half of the carry-forward
    /// condition: reload with the SAME `Arc`, and the published
    /// `Arc<ManagedCluster>` must be the same one too.
    #[tokio::test]
    async fn pointer_equal_config_is_carried_forward() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "a".to_string(),
            cluster_config("a", DiscoveryType::Static, vec![endpoint("10.0.0.1", 80)]),
        );
        manager.update_from_snapshot(&snapshot).await;
        let managed_before = manager.clusters.load().get("a").unwrap().clone();

        // Reload with the IDENTICAL map -- every `Arc<ClusterConfig>` inside
        // it is `Arc::clone`d, not rebuilt, so this is pointer-identical to
        // what `update_from_snapshot` already saw, exactly like a CDS push
        // that only touched some other resource.
        manager.update_from_snapshot(&snapshot).await;
        let managed_after = manager.clusters.load().get("a").unwrap().clone();

        assert!(
            Arc::ptr_eq(&managed_before, &managed_after),
            "a pointer-identical ClusterConfig must carry the ManagedCluster forward"
        );
    }

    /// The SIGHUP path: every `Arc<ClusterConfig>` is freshly lowered from
    /// bytes on disk, so no pointer from the previous generation survives at
    /// all -- content equality is the only signal available. Built via the
    /// same `cluster_config` helper twice, deliberately, to prove this is
    /// content equality doing the work, not `Arc::ptr_eq` (test above) by
    /// accident.
    #[tokio::test]
    async fn content_equal_config_is_carried_forward() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "a".to_string(),
            cluster_config("a", DiscoveryType::Static, vec![endpoint("10.0.0.1", 80)]),
        );
        manager.update_from_snapshot(&snapshot).await;
        let managed_before = manager.clusters.load().get("a").unwrap().clone();

        let fresh = cluster_config("a", DiscoveryType::Static, vec![endpoint("10.0.0.1", 80)]);
        assert!(
            !Arc::ptr_eq(&snapshot["a"], &fresh),
            "test setup: must be a distinct Arc, or this doesn't exercise content equality"
        );
        let mut snapshot2 = HashMap::new();
        snapshot2.insert("a".to_string(), fresh);
        manager.update_from_snapshot(&snapshot2).await;
        let managed_after = manager.clusters.load().get("a").unwrap().clone();

        assert!(
            Arc::ptr_eq(&managed_before, &managed_after),
            "a freshly-lowered but content-equal ClusterConfig must still carry \
             the ManagedCluster forward"
        );
    }

    /// The other side of the same condition: a real change to a cluster's
    /// own config (`connect_timeout` here) must rebuild it, not carry the
    /// old `ManagedCluster` forward serving a stale value.
    #[tokio::test]
    async fn a_changed_cluster_is_rebuilt() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "a".to_string(),
            cluster_config("a", DiscoveryType::Static, vec![endpoint("10.0.0.1", 80)]),
        );
        manager.update_from_snapshot(&snapshot).await;
        let managed_before = manager.clusters.load().get("a").unwrap().clone();
        assert_eq!(managed_before.connect_timeout, Duration::from_secs(5));

        let mut snapshot2 = HashMap::new();
        snapshot2.insert(
            "a".to_string(),
            cluster_config_with_connect_timeout(
                "a",
                DiscoveryType::Static,
                vec![endpoint("10.0.0.1", 80)],
                Duration::from_secs(9),
            ),
        );
        manager.update_from_snapshot(&snapshot2).await;
        let managed_after = manager.clusters.load().get("a").unwrap().clone();

        assert!(
            !Arc::ptr_eq(&managed_before, &managed_after),
            "a real config change must rebuild the ManagedCluster, not carry the old one forward"
        );
        assert_eq!(
            managed_after.connect_timeout,
            Duration::from_secs(9),
            "the rebuilt cluster must serve the new connect_timeout, not the stale one"
        );
    }

    /// Acceptance test and motivating scenario for carry-forward: a
    /// control-plane heartbeat that only changes cluster B must not silently
    /// clear an ejection on unrelated cluster A. Eject A's only host, push a
    /// snapshot where only B's config changed, and confirm both that A's
    /// `ManagedCluster` is the exact same `Arc` (not just behaviorally
    /// equivalent) and that its ejection survived.
    #[tokio::test]
    async fn an_unrelated_clusters_change_leaves_an_ejection_in_place() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "a".to_string(),
            cluster_config_with_outlier("a", vec![endpoint("10.0.0.1", 80)], 3),
        );
        snapshot.insert(
            "b".to_string(),
            cluster_config("b", DiscoveryType::Static, vec![endpoint("10.0.0.2", 80)]),
        );
        manager.update_from_snapshot(&snapshot).await;
        let entry_a = manager.cluster("a").unwrap();
        let target = SocketAddr::new(IpAddr::from([10, 0, 0, 1]), 80);

        let a_healthy = || {
            manager
                .clusters
                .load()
                .get("a")
                .unwrap()
                .host_set
                .load()
                .all_healthy_hosts()
                .iter()
                .any(|h| h.address == target)
        };

        // Three consecutive 5xx crosses the threshold (enforced 100%, 100%
        // cap) and ejects a's only host.
        entry_a.report_outlier_result(target, RequestResult::Http5xx);
        entry_a.report_outlier_result(target, RequestResult::Http5xx);
        entry_a.report_outlier_result(target, RequestResult::Http5xx);
        assert!(!a_healthy(), "three consecutive 5xx must eject a's host");

        let managed_a_before = manager.clusters.load().get("a").unwrap().clone();

        // Reload with ONLY b's config changed -- a's config is byte-for-byte
        // the same (a fresh, content-equal Arc, same shape as a real SIGHUP
        // reload's lowering).
        let mut snapshot2 = HashMap::new();
        snapshot2.insert(
            "a".to_string(),
            cluster_config_with_outlier("a", vec![endpoint("10.0.0.1", 80)], 3),
        );
        snapshot2.insert(
            "b".to_string(),
            cluster_config("b", DiscoveryType::Static, vec![endpoint("10.0.0.99", 80)]),
        );
        manager.update_from_snapshot(&snapshot2).await;

        let managed_a_after = manager.clusters.load().get("a").unwrap().clone();
        assert!(
            Arc::ptr_eq(&managed_a_before, &managed_a_after),
            "a's ManagedCluster must be carried forward, not rebuilt, by an unrelated \
             cluster's config change"
        );
        assert!(
            !a_healthy(),
            "an unrelated cluster's config change must not clear a's outlier ejection"
        );
    }

    /// The paragraph `update_from_snapshot`'s own doc now makes about EDS
    /// membership surviving a reload: a config-sourced EDS cluster
    /// (`discovery: eds` -- see [`cluster_config_eds`]) fed via
    /// [`ClusterManager::accept_eds_update`], then a reload that changes an
    /// unrelated cluster's config, must not empty it.
    #[tokio::test]
    async fn eds_membership_survives_an_unrelated_config_reload() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert("eds-cfg".to_string(), cluster_config_eds("eds-cfg"));
        snapshot.insert(
            "b".to_string(),
            cluster_config("b", DiscoveryType::Static, vec![endpoint("10.0.0.2", 80)]),
        );
        manager.update_from_snapshot(&snapshot).await;

        let eds_target = SocketAddr::new(IpAddr::from([10, 0, 0, 50]), 80);
        manager
            .accept_eds_update("eds-cfg", &[endpoint("10.0.0.50", 80)])
            .unwrap();
        let eds_has_host = || {
            manager
                .clusters
                .load()
                .get("eds-cfg")
                .unwrap()
                .host_set
                .load()
                .all_hosts()
                .iter()
                .any(|h| h.address == eds_target)
        };
        assert!(eds_has_host(), "the externally-fed EDS update must land");

        // Reload with ONLY b's config changed.
        let mut snapshot2 = HashMap::new();
        snapshot2.insert("eds-cfg".to_string(), cluster_config_eds("eds-cfg"));
        snapshot2.insert(
            "b".to_string(),
            cluster_config("b", DiscoveryType::Static, vec![endpoint("10.0.0.99", 80)]),
        );
        manager.update_from_snapshot(&snapshot2).await;

        assert!(
            eds_has_host(),
            "an unrelated cluster's config change must not empty EDS-delivered \
             membership on a config-sourced EDS cluster"
        );
    }

    /// Mirrors `refresh_cluster_carries_over_health_flags_for_unchanged_hosts`,
    /// but across `update_from_snapshot` rather than `refresh_cluster`: an
    /// active-health-check failure flag flipped directly on a host must
    /// survive an unrelated cluster's config change in the same snapshot.
    #[tokio::test]
    async fn active_health_check_flags_survive_an_unrelated_config_reload() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        // A very long interval: the probe this spawns must not fire (and
        // overwrite the flag this test sets) during the test's own runtime.
        let hc = tcp_health_check(1, 1, Duration::from_secs(3600));
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "hc-svc".to_string(),
            cluster_config_with_health_check(
                "hc-svc",
                DiscoveryType::Static,
                vec![endpoint("10.0.0.1", 80)],
                hc.clone(),
            ),
        );
        snapshot.insert(
            "b".to_string(),
            cluster_config("b", DiscoveryType::Static, vec![endpoint("10.0.0.2", 80)]),
        );
        manager.update_from_snapshot(&snapshot).await;

        let addr = SocketAddr::new(IpAddr::from([10, 0, 0, 1]), 80);
        let managed = manager.clusters.load().get("hc-svc").unwrap().clone();
        managed
            .host_set
            .store(Arc::new(HostSet::from_hosts(vec![Arc::new(Host {
                address: addr,
                hostname: None,
                metadata: Default::default(),
                weight: 1,
                priority: 0,
                health_flags: HealthFlags {
                    failed_active_hc: true,
                    failed_outlier_check: false,
                },
                active_requests: std::sync::atomic::AtomicU64::new(0),
            })])));

        // Reload with ONLY b's config changed.
        let mut snapshot2 = HashMap::new();
        snapshot2.insert(
            "hc-svc".to_string(),
            cluster_config_with_health_check(
                "hc-svc",
                DiscoveryType::Static,
                vec![endpoint("10.0.0.1", 80)],
                hc,
            ),
        );
        snapshot2.insert(
            "b".to_string(),
            cluster_config("b", DiscoveryType::Static, vec![endpoint("10.0.0.99", 80)]),
        );
        manager.update_from_snapshot(&snapshot2).await;

        let host = manager
            .clusters
            .load()
            .get("hc-svc")
            .unwrap()
            .host_set
            .load()
            .all_hosts()
            .into_iter()
            .find(|h| h.address == addr)
            .expect("host must still be present after the reload");
        assert!(
            !host.is_healthy(),
            "an unrelated cluster's config change must not clear an active-health-check flag"
        );
    }
}
