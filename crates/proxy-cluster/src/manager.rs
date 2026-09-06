//! Cluster manager (WP-16 §3): owns per-cluster discovery state and
//! publishes [`HostSet`] snapshots. Built/updated on the control runtime; the
//! router (WP-13) only ever talks to it through [`ClusterManager::cluster`]'s
//! `Arc<dyn ClusterEntry>` handle, never touching discovery internals.
//!
//! Warming ("is this cluster ready to serve") is a stub here --
//! [`ClusterManager::is_initialized`] flips once a cluster's first
//! resolution lands, or, for a cluster that never resolves in time,
//! [`ClusterManager::force_initialize`] mimics Envoy's
//! `initial_fetch_timeout` "proceed empty" behavior. Real warming order is
//! WP-21.

use std::collections::HashMap;
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

/// Where a managed cluster's membership comes from.
enum ClusterSource {
    /// A cluster present in the config snapshot; discovery follows its
    /// `DiscoveryType` (STATIC/STRICT_DNS/LOGICAL_DNS -- see
    /// [`crate::discovery`]).
    Config(Arc<ClusterConfig>),
    /// Membership fed externally (EDS, WP-20). The IR's `DiscoveryType` has
    /// no EDS variant yet (`lower.rs` rejects EDS clusters at proto
    /// conversion), so these are registered directly against the manager via
    /// [`ClusterManager::add_eds_cluster`] rather than arriving through
    /// [`ClusterManager::update_from_snapshot`] -- a stand-in for the real
    /// xDS wiring.
    Eds,
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
    source: ClusterSource,
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
    /// every policy (WP-17). Built once at cluster construction -- see
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
    /// S6 active health checking (WP-18 runtime wiring): built once from
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
    /// S6 passive outlier detection (WP-19), or `None` when the config
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
    /// `ClusterManager::update_from_snapshot` rebuilds every config-sourced
    /// cluster wholesale on each call (its own doc says so), so without this,
    /// every config reload -- and this proxy reloads on SIGHUP in production
    /// -- would leak one permanently-running probe loop per host, forever.
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

/// Envoy's own default for `Cluster.connect_timeout` when a config doesn't
/// set one -- see `ClusterConfig::connect_timeout`'s doc comment in the IR.
const DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl ManagedCluster {
    /// Builds a config-sourced cluster's state. Branches on `config.kind`:
    /// an `Endpoints` cluster gets a real load balancer and transport socket
    /// (failing if `config.lb_policy` isn't implemented yet -- `RING_HASH`/
    /// `MAGLEV`, see [`load_balancer::build`] -- or if `config.transport_socket`
    /// doesn't build; ground rule #1 forbids silently substituting another
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
                // WP-18 runtime wiring: build the engine now, from the
                // lowered config, same as `policy`/`transport` above --
                // `None` means the config configures no health check at all
                // (Envoy's own default), not that this cluster is exempt.
                let health_engine = config.health_check.as_ref().map(HealthCheckEngine::from_ir);
                // WP-19 runtime wiring: the detector must eject into the SAME
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
                    source: ClusterSource::Config(config),
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
                // WP-35 increment 2a: `select_host` never reads this
                // cluster's own `host_set`/`host_picker`/`transport`/
                // `upstream_protocol`/`connect_timeout` for an aggregate --
                // it resolves straight through to whichever member actually
                // served the host (see `ClusterHandle::select_aggregate_member`)
                // -- so `RoundRobin`/`RawTransportSocket`/`Http1` here are
                // inert placeholders, never real answers, exactly like
                // `eds()`'s defaults below. `initialized` starts `true`:
                // there is nothing here to resolve, and leaving it `false`
                // would make WP-21 warming wait forever on a cluster that
                // never runs discovery. `connect_timeout` is read from the
                // real config anyway (it costs nothing and stays correct if
                // this arm's pool is ever actually dialed). `health_engine`
                // stays `None` for the same reason as the rest of this arm:
                // an aggregate has no hosts of its own to probe -- probing
                // happens on the member cluster, which has its own real
                // `ManagedCluster` and its own `health_engine`.
                let connect_timeout = config.connect_timeout;
                Ok(Self {
                    source: ClusterSource::Config(config),
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
    /// membership diff (WP-18 runtime wiring): stop the probe for every
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
            // WP-19 gap closed: hand the probe a clone of this cluster's own
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

    /// EDS clusters have no `ClusterConfig`/`lb_policy` of their own (see
    /// [`ClusterSource::Eds`]); default to `ROUND_ROBIN`, matching Envoy's
    /// own cluster-wide default, to plaintext (there's no
    /// `transport_socket` field to read), and to Envoy's own
    /// `connect_timeout` default (there's no field to read that either).
    /// `health_engine` is `None` for the same reason: there's no
    /// `ClusterConfig.health_check` to build one from.
    fn eds() -> Self {
        Self {
            source: ClusterSource::Eds,
            host_set: Arc::new(ArcSwap::from_pointee(HostSet::default())),
            initialized: AtomicBool::new(false),
            host_picker: HostPicker::new(
                load_balancer::build(LbPolicy::RoundRobin).expect("round robin always builds"),
            ),
            default_cb: CircuitBreakerState::default(),
            high_cb: CircuitBreakerState::default(),
            upstream_protocol: UpstreamProtocol::Http1,
            transport: Arc::new(transport::RawTransportSocket),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            health_engine: None,
            probes: Mutex::new(HashMap::new()),
            // EDS clusters have no `ClusterConfig` to read an
            // `outlier_detection` block from (see `ClusterSource::Eds`).
            outlier_detector: None,
            outlier_sweep: Mutex::new(None),
        }
    }

    /// True for an aggregate cluster (`ClusterConfig::kind` is `Aggregate`).
    /// [`ClusterHandle::select_aggregate_member`] uses this to refuse
    /// recursing into a member that is itself an aggregate.
    fn is_aggregate(&self) -> bool {
        matches!(
            &self.source,
            ClusterSource::Config(c) if matches!(c.kind, ClusterKind::Aggregate { .. })
        )
    }

    /// This cluster's aggregate member list, in config order -- `None` for
    /// anything [`Self::is_aggregate`] says isn't one (an `Endpoints`
    /// cluster, or an EDS cluster, which has no `ClusterConfig` at all).
    fn aggregate_members(&self) -> Option<&[ClusterName]> {
        match &self.source {
            ClusterSource::Config(c) => match &c.kind {
                ClusterKind::Aggregate { members } => Some(members),
                ClusterKind::Endpoints => None,
            },
            ClusterSource::Eds => None,
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
    // rebuilds every config-sourced cluster wholesale on every call (see its
    // own doc) -- a member resolved *eagerly*, at the aggregate's own
    // construction time, would keep pointing at a specific `Arc<ManagedCluster>`
    // that the very next reload replaces, silently freezing that member's
    // discovery even though the config for it kept updating.
    clusters: Arc<ArcSwap<HashMap<ClusterName, Arc<ManagedCluster>>>>,
    resolver: Arc<dyn HostResolver>,
    transport_builder: TransportSocketBuilder,
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

    /// Reconcile against a config snapshot's cluster map and kick off each
    /// current cluster's initial resolution.
    ///
    /// v1 rebuilds config-sourced clusters wholesale on every call (a
    /// cluster whose config changed gets a fresh, empty host set until its
    /// resolution completes a few lines below) rather than diffing
    /// `ClusterConfig` for real changes -- `ClusterConfig` has no
    /// `PartialEq`, and Envoy's own cluster-update semantics are a larger
    /// piece of work than this WP. EDS-registered clusters (which never
    /// appear in a config snapshot) are carried over untouched.
    ///
    /// A cluster whose `lb_policy` isn't implemented (`RING_HASH`/`MAGLEV`,
    /// WP-17) is rejected rather than silently substituted with another
    /// policy (ground rule #1): it's left out of the resulting cluster set
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
        for (name, config) in clusters {
            match ManagedCluster::from_config(Arc::clone(config), &self.transport_builder) {
                Ok(managed) => {
                    next.insert(name.clone(), Arc::new(managed));
                }
                Err(err) => {
                    tracing::error!(cluster = %name, error = %err, "cluster rejected");
                    rejected.push((name.clone(), err));
                }
            }
        }
        for (name, managed) in previous.iter() {
            if matches!(managed.source, ClusterSource::Eds) {
                next.entry(name.clone())
                    .or_insert_with(|| Arc::clone(managed));
            }
        }
        self.clusters.store(Arc::new(next));

        for name in clusters.keys() {
            if rejected
                .iter()
                .any(|(rejected_name, _)| rejected_name == name)
            {
                continue;
            }
            if let Err(err) = self.refresh_cluster(name).await {
                // Rust note: a discovery failure doesn't take the cluster
                // manager down -- Envoy keeps serving the last-known-good
                // (here: empty, since this is the first resolution) host set
                // and logs. Real retry/backoff on DNS failure is a future
                // refinement, not part of this WP.
                tracing::warn!(cluster = %name, error = %err, "initial cluster discovery failed");
            }
        }
        rejected
    }

    /// Register a cluster whose membership will arrive via
    /// [`Self::accept_eds_update`] rather than self-driven discovery. A
    /// no-op if a cluster of that name already exists.
    pub fn add_eds_cluster(&self, name: ClusterName) {
        self.clusters.rcu(|current| {
            let mut next = (**current).clone();
            next.entry(name.clone())
                .or_insert_with(|| Arc::new(ManagedCluster::eds()));
            next
        });
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
        // WP-18 runtime wiring: carry `health_flags` over for every address
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
    /// Production callers re-run this on a timer
    /// ([`discovery::DEFAULT_DNS_REFRESH_RATE`]) for DNS-discovered
    /// clusters; tests call it directly to drive discovery deterministically
    /// instead of waiting on a real timer.
    pub async fn refresh_cluster(&self, name: &str) -> io::Result<HostSetDiff> {
        let managed = self
            .clusters
            .load()
            .get(name)
            .cloned()
            .ok_or_else(|| not_found(name))?;
        let config = match &managed.source {
            ClusterSource::Eds => return Ok(HostSetDiff::default()),
            // An aggregate has no endpoints/discovery of its own to
            // resolve -- an explicit no-op arm, the same as `Eds` above,
            // not a resolve of zero endpoints (which would go through
            // `discovery::resolve` and diff against an always-empty set for
            // no reason).
            ClusterSource::Config(config)
                if matches!(config.kind, ClusterKind::Aggregate { .. }) =>
            {
                return Ok(HostSetDiff::default())
            }
            // WP-21 increment 1: an EDS cluster declared in STATIC config is
            // `ClusterSource::Config`, not `ClusterSource::Eds` (that variant
            // is for clusters `add_eds_cluster` registered), so it reaches
            // here -- and it must short-circuit for the same reason the two
            // arms above do, plus a sharper one. Production re-runs this on
            // the DNS refresh timer; `discovery::resolve` returns an EMPTY
            // host set for `DiscoveryType::Eds`, so falling through would
            // diff the EDS-delivered membership against nothing and wipe it
            // on the next tick. Found while adding the IR variant, not by a
            // test -- there is no EDS delivery path to regress yet.
            ClusterSource::Config(config) if config.discovery == DiscoveryType::Eds => {
                return Ok(HostSetDiff::default())
            }
            ClusterSource::Config(config) => config,
        };
        let new_set = discovery::resolve(config, self.resolver.as_ref()).await?;
        let old_set = managed.host_set.load();
        let diff = diff_host_sets(&old_set, &new_set);
        // WP-18 runtime wiring: `discovery::resolve` always builds fresh
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
    /// warming (WP-21) doesn't wait on it forever. A no-op for an unknown
    /// cluster name.
    pub fn force_initialize(&self, name: &str) {
        if let Some(managed) = self.clusters.load().get(name) {
            managed.initialized.store(true, Ordering::Release);
        }
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
    /// The aggregate host-selection algorithm (WP-35): walk `members` in
    /// config order, skipping any name already in `ctx.attempted_clusters`
    /// (so a retry falls over instead of re-picking the member that just
    /// failed); for each remaining candidate, resolve it against the
    /// *current* registry, skip it (logging, not erroring -- a transient
    /// config-reload race is real) if it isn't currently registered or is
    /// itself an aggregate, and otherwise ask that member's own
    /// [`HostPicker`] for a host from its own host set. The first member
    /// that yields a host wins.
    ///
    /// A member that is itself an aggregate is never followed -- WP-35
    /// increment 2a deliberately does not support nested aggregates, and
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
                     supported (WP-35 increment 2a), skipping"
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
        // pool today. Real h2 multiplexing pools are a WP-15 follow-up.
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
        // EDS clusters have no `ClusterConfig` (see `ClusterSource::Eds`), so
        // there's nowhere for this to come from -- empty, same as the
        // `upstream_protocol`/`transport` defaults above. An aggregate's own
        // `request_headers_to_add` is likewise never read here: the router
        // calls this on the *member's* entry (`HostSelection::member`), not
        // the aggregate's, so this arm never actually executes for an
        // aggregate in practice -- but it stays correct (empty) rather than
        // panicking if it ever did.
        match &self.managed.source {
            ClusterSource::Config(config) => &config.request_headers_to_add,
            ClusterSource::Eds => &[],
        }
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
            usage_dialect: None,
            health_check: None,
            outlier_detection: Some(od),
        })
    }

    /// An aggregate cluster over `members`, in the given order -- WP-35's
    /// fallback construct. `endpoints`/`discovery` are unused for an
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
            usage_dialect: None,
            health_check: None,
            outlier_detection: None,
        })
    }

    fn endpoint(host: &str, port: u16) -> EndpointIR {
        EndpointIR {
            host: host.to_string(),
            port,
            weight: 1,
            priority: 0,
        }
    }

    // ------------------------------------------------- WP-18 runtime wiring --

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

    /// A cluster carrying BOTH a health check and outlier detection (the last
    /// WP-19 gap's acceptance shape): `uneject_on_healthy_active_hc` is the
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
    }

    #[tokio::test]
    async fn eds_cluster_starts_uninitialized_then_accepts_an_update() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        manager.add_eds_cluster("eds-svc".to_string());

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

    #[tokio::test]
    async fn force_initialize_marks_an_unresolved_cluster_ready() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        manager.add_eds_cluster("never-fed".to_string());
        assert!(!manager.is_initialized("never-fed"));
        manager.force_initialize("never-fed");
        assert!(manager.is_initialized("never-fed"));
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

    // --------------------------------------------------- WP-35 aggregate ---

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
            ..Default::default()
        };
        let sel = entry
            .select_host(&ctx)
            .expect("aggregate should fall over to b");
        assert_eq!(sel.member.unwrap().name, "b");

        let ctx_exhausted = LoadBalancerContext {
            attempted_clusters: vec!["a".to_string(), "b".to_string()],
            ..Default::default()
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

    // ------------------------------------------------- WP-18 runtime wiring --

    /// The acceptance test named in the WP-18 runtime-wiring brief: before
    /// this task, no configuration could make an active health check
    /// actually run. Two static hosts -- one a live listener, one a bound-
    /// then-dropped port so nothing answers -- with `unhealthy_threshold: 1`
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

    /// The second WP-18 runtime-wiring hazard: `discovery::resolve` builds
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
    /// `update_from_snapshot` rebuilds every config-sourced `ManagedCluster`
    /// wholesale on every call (its own doc comment says so) -- reload the
    /// identical single-host config several times and confirm the hit rate
    /// against that host's listener stays at roughly one generation's worth,
    /// rather than scaling with the number of reloads (which is exactly what
    /// a dropped-but-not-aborted `JoinHandle` per reload would produce).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_config_reload_does_not_leak_the_previous_generations_probes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        spawn_counting_acceptor(listener, Arc::clone(&hits));

        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "reload".to_string(),
            cluster_config_with_health_check(
                "reload",
                DiscoveryType::Static,
                vec![endpoint(&addr.ip().to_string(), addr.port())],
                tcp_health_check(1, 1, Duration::from_millis(15)),
            ),
        );
        manager.update_from_snapshot(&snapshot).await;
        wait_until(Duration::from_secs(5), || hits.load(Ordering::SeqCst) >= 3).await;

        let baseline_start = hits.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(250)).await;
        let baseline = hits.load(Ordering::SeqCst) - baseline_start;

        for _ in 0..4 {
            manager.update_from_snapshot(&snapshot).await;
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

    /// WP-19 runtime acceptance: a cluster configured with outlier detection
    /// ejects a host once it has returned `consecutive_5xx` consecutive 5xx --
    /// fed through the exact `ClusterEntry::report_outlier_result` seam the
    /// router uses. Before this wiring, no configuration could produce an
    /// ejection at all.
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

    // ---------------------------- last WP-19 gap: active-HC clears outlier --

    /// The acceptance test for the last WP-19 gap: a host outlier-ejected via
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
}
