//! Cluster manager: owns per-cluster discovery state and publishes [`HostSet`] snapshots. It is built
//! and updated on the control runtime; the router reaches it only through [`ClusterManager::cluster`]'s
//! `Arc<dyn ClusterEntry>` handle.
//!
//! Warming: [`ClusterManager::is_initialized`] flips once a cluster's first resolution lands. A cluster
//! that never resolves in time is marked by [`ClusterManager::force_initialize`], which mimics Envoy's
//! `initial_fetch_timeout` "proceed empty" behavior. [`ClusterManager::warming_clusters`] feeds `/ready`
//! only; it does not gate request routing.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use proxy_config::ir::{
    ClusterConfig, ClusterKind, ClusterName, DiscoveryType, EndpointIR, LbPolicy,
    ProviderCredential,
};
use tokio::task::JoinHandle;

use crate::discovery::{self, RefreshSchedule};
use crate::health_check::HealthCheckEngine;
use crate::host_set::{carry_over_health_flags, diff_host_sets, HostSet, HostSetDiff};
use crate::latency::LatencyEwma;
use crate::load_balancer::{self, HostPicker, LbError};
use crate::minted_credential::MintedCredential;
use crate::outlier::{OutlierDetector, RequestResult, TracingEventSink};
use crate::resolver::HostResolver;
use crate::transport::{
    self, TransportSocketBuilder, TransportSocketError, UpstreamTransportSocket,
};
use crate::{
    CircuitBreakerState, ClusterEntry, Host, HostSelection, HttpConnPool, LoadBalancerContext,
    RoutingPriority, SelectedMember, UpstreamProtocol,
};

/// Failure to build a cluster: an unimplemented `lb_policy` ([`LbError`]) or a `transport_socket` that
/// will not build ([`TransportSocketError`]). One enum, because callers report both the same way.
#[derive(Debug, thiserror::Error)]
pub enum ClusterBuildError {
    #[error(transparent)]
    Lb(#[from] LbError),
    #[error(transparent)]
    TransportSocket(#[from] TransportSocketError),
}

/// A copyable, control-plane-facing snapshot of one cluster's active host set. It holds only runtime
/// and std types, so the admin server needs no generated-proto dependency.
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
    /// The DNS origin, when discovery resolved one. `address` is always what traffic dials; this is for
    /// SNI and operator context only.
    pub hostname: Option<String>,
    pub weight: u32,
    pub priority: u32,
    pub health_flags: String,
    /// Endpoint labels. Copied into the immutable host set on ingest, so they follow live membership.
    pub metadata: BTreeMap<String, String>,
}

/// One cluster's live state: its membership source, current host-set snapshot, and warming status.
///
/// Rust note: `ArcSwap<HostSet>` is the "control computes, workers swap" pattern from `WorkerConfigHandle`
/// (ADR-0003). Discovery recomputes whole host sets on the control runtime; readers only `load`.
///
/// For an aggregate cluster, `host_set`, `host_picker`, `transport`, and `upstream_protocol` are inert
/// placeholders (see the aggregate arm of [`ManagedCluster::from_config`]).
struct ManagedCluster {
    /// The config this cluster was built from. Discovery follows its `DiscoveryType` (see [`crate::discovery`]),
    /// except `EDS`, whose membership arrives via [`ClusterManager::accept_eds_update`].
    config: Arc<ClusterConfig>,
    /// Rust note: `Arc<ArcSwap<..>>` lets [`health_check::HealthCheckEngine::spawn_for_host`] hold a clone of
    /// the swap cell. Its check loop outlives any single call, so a borrow tied to `&self` will not do.
    /// `.load()`, `.store()`, and `.rcu()` work unchanged through `Deref`.
    /// [`health_check::HealthCheckEngine::spawn_for_host`]: crate::health_check::HealthCheckEngine::spawn_for_host
    host_set: Arc<ArcSwap<HostSet>>,
    /// Set once the first resolution (or, for EDS, the first externally supplied set) lands. Always true
    /// for an aggregate, which has nothing to resolve.
    initialized: AtomicBool,
    /// S7 host selection: the configured `lb_policy`'s [`LoadBalancer`], plus the priority-spillover and
    /// healthy-panic logic shared by all policies. Built once at construction; see [`load_balancer::build`]
    /// for why `RING_HASH`/`MAGLEV` fail here rather than falling back.
    ///
    /// [`LoadBalancer`]: crate::load_balancer::LoadBalancer
    host_picker: HostPicker,
    /// S5 circuit-breaker budgets, one bucket per routing priority, as `ClusterEntry::circuit_breaker`
    /// returns them. An aggregate's members share the aggregate's budget today (see `router.rs`'s
    /// `apply_forward`).
    default_cb: CircuitBreakerState,
    high_cb: CircuitBreakerState,
    /// The HTTP protocol the router speaks to this cluster's upstreams. EDS clusters, which have no
    /// `ClusterConfig`, default to HTTP/1.1.
    upstream_protocol: UpstreamProtocol,
    /// The wrapper for a freshly dialed TCP connection: plaintext, or TLS built from
    /// `config.transport_socket`. EDS clusters always get plaintext.
    transport: Arc<dyn UpstreamTransportSocket>,
    /// `ClusterConfig::connect_timeout` (Envoy default 5s). EDS clusters and aggregates use the same
    /// default; an aggregate's own pool is never dialed.
    connect_timeout: std::time::Duration,
    /// S6 active health checks, built once from `config.health_check`. `None` when none is configured
    /// (Envoy's default: every host healthy), and always `None` for aggregates and EDS clusters.
    health_engine: Option<Arc<HealthCheckEngine>>,
    /// Live probe tasks, one per probed host address, reconciled on every resolve or EDS update by
    /// [`Self::reconcile_probes`]. They live here, not on the engine, because a `ManagedCluster` is what
    /// gets discarded on reload. The `Drop` impl aborts them all.
    ///
    /// Rust note: `std::sync::Mutex`, not `tokio::sync::Mutex`. Every critical section is a plain
    /// `HashMap` edit with no `.await`.
    probes: Mutex<HashMap<SocketAddr, JoinHandle<()>>>,
    /// S6 passive outlier detection, or `None` when unconfigured. The router feeds it one
    /// [`RequestResult`] per upstream attempt. It ejects by setting `failed_outlier_check` in this
    /// cluster's `host_set`, so ejections and active-check failures share one snapshot (see `HealthFlags`).
    /// It holds a clone of `host_set`, so it ejects into current membership across DNS re-resolution.
    outlier_detector: Option<Arc<OutlierDetector>>,
    /// Periodic outlier sweep task ([`OutlierDetector::spawn`]). Aborted on `Drop`: a dropped `JoinHandle`
    /// detaches rather than stops, so a reload would leak one sweep loop per cluster.
    outlier_sweep: Mutex<Option<JoinHandle<()>>>,
    /// Timer that re-resolves a `STRICT_DNS`/`LOGICAL_DNS` cluster ([`run_dns_refresh`]); `None` for others.
    /// Set by [`ClusterManager::start_dns_refresh`] once the cluster is behind its `Arc`, since the task
    /// holds only a `Weak`. Aborted on `Drop`; the task also ends once its `Weak` stops upgrading.
    dns_refresh_task: Mutex<Option<JoinHandle<()>>>,
    /// The published token for an `OAuth2JwtBearer` credential, or `None` for every other credential. Only the
    /// cluster's refresher writes it; workers read it through [`ClusterEntry::minted_credential`].
    minted: Option<Arc<MintedCredential>>,
    /// The task that keeps `minted` fresh ([`run_token_refresh`]). Set by [`ClusterManager::install`] after the
    /// first mint; it holds only a `Weak`. Aborted on `Drop`.
    token_refresh_task: Mutex<Option<JoinHandle<()>>>,
    /// Moving average of this cluster's response latency, sampled by the router on routes in latency
    /// selection mode. It lives here so a cluster carried forward across a reload keeps it, and a rebuilt
    /// one starts afresh.
    latency: Arc<LatencyEwma>,
}

impl Drop for ManagedCluster {
    /// Aborts every background task on drop. A dropped `JoinHandle` detaches rather than stops, and a
    /// check loop with no owner runs forever. Config reloads rebuild clusters, so without this each
    /// reload would leak one probe loop per host.
    fn drop(&mut self) {
        // Rust note: `Mutex::lock` errs only on poisoning. `if let Ok` still aborts reachable handles, where
        // `.unwrap()` would panic inside `Drop` during unwind and abort the process.
        if let Ok(mut probes) = self.probes.lock() {
            for (_, handle) in probes.drain() {
                handle.abort();
            }
        }
        // Same for the outlier sweep, so a reload does not leak it.
        if let Ok(mut sweep) = self.outlier_sweep.lock() {
            if let Some(handle) = sweep.take() {
                handle.abort();
            }
        }
        // Pending un-eject timers belong to the cluster too.
        if let Some(detector) = &self.outlier_detector {
            detector.shutdown();
        }
        // The DNS refresh timer. Its `Weak` stops upgrading, but the task would sleep until its next tick
        // to find that out, so abort it now.
        if let Ok(mut task) = self.dns_refresh_task.lock() {
            if let Some(handle) = task.take() {
                handle.abort();
            }
        }
        // The token refresher, for the same reason: it may be sleeping for most of a token's lifetime.
        if let Ok(mut task) = self.token_refresh_task.lock() {
            if let Some(handle) = task.take() {
                handle.abort();
            }
        }
    }
}

impl ManagedCluster {
    /// Builds a config-sourced cluster's state, branching on `config.kind`. An `Endpoints` cluster gets a
    /// real load balancer and transport socket. Either failing fails the build: AGENTS.md invariant 1
    /// forbids silently substituting a policy or downgrading to plaintext. An `Aggregate` cluster has no
    /// hosts, load balancer, or transport socket (see the aggregate arm below).
    fn from_config(
        config: Arc<ClusterConfig>,
        transport_builder: &TransportSocketBuilder,
    ) -> Result<Self, ClusterBuildError> {
        let default_cb = CircuitBreakerState::from_thresholds(config.circuit_breakers.default);
        let high_cb = CircuitBreakerState::from_thresholds(config.circuit_breakers.high);
        match &config.kind {
            ClusterKind::Endpoints => {
                let policy = load_balancer::build(config.lb_policy)?;
                let minted = match config
                    .provider_runtime
                    .as_ref()
                    .and_then(|runtime| runtime.credential.as_ref())
                {
                    Some(ProviderCredential::OAuth2JwtBearer(oauth2)) => {
                        Some(Arc::new(MintedCredential::new(&config.name, oauth2)))
                    }
                    _ => None,
                };
                let transport = transport_builder(&config)?;
                // Read and map the IR enum before `config` moves into `source`.
                let upstream_protocol = UpstreamProtocol::from(config.upstream_protocol);
                let connect_timeout = config.connect_timeout;
                // Build the engine from the lowered config, like `policy` and `transport`. `None` means no
                // health check is configured, not that this cluster is exempt.
                let health_engine = config.health_check.as_ref().map(HealthCheckEngine::from_ir);
                // The detector must eject into the same `host_set` the router picks from, so build the `Arc`
                // here and give the detector a clone. Its periodic sweep is spawned now; the handle is stashed
                // for `Drop` to abort.
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
                    dns_refresh_task: Mutex::new(None),
                    minted,
                    token_refresh_task: Mutex::new(None),
                    latency: Arc::new(LatencyEwma::default()),
                })
            }
            ClusterKind::Aggregate { .. } => {
                // Inert placeholders: `select_host` never reads this cluster's own `host_set`, `host_picker`,
                // `transport`, or `upstream_protocol`. It resolves straight to the member that served the host
                // (see `ClusterHandle::select_aggregate_member`), so `RoundRobin`, `RawTransportSocket`, and
                // `Http1` here are never real answers. `initialized` starts `true` because there is nothing to
                // resolve; `false` would make warming wait forever and the router would 503 every request.
                // `connect_timeout` is read from the config anyway, so it stays correct if the pool is ever
                // dialed. `health_engine` stays `None`: probing happens on the member cluster.
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
                    // Outlier detection runs on the member cluster, not on an aggregate.
                    outlier_detector: None,
                    outlier_sweep: Mutex::new(None),
                    // An aggregate resolves nothing itself; its members
                    // each run their own refresh.
                    dns_refresh_task: Mutex::new(None),
                    // Credentials live on the member actually dialled (AGENTS.md invariant 6).
                    minted: None,
                    token_refresh_task: Mutex::new(None),
                    // Never sampled: the router records on the member it dialled.
                    latency: Arc::new(LatencyEwma::default()),
                })
            }
        }
    }

    /// Reconciles this cluster's active-health-check probes against a membership diff: aborts the probe for
    /// each `removed` address (see the `Drop` impl) and starts one for each `added`. `unchanged` addresses keep
    /// their running probe, since it already targets this `host_set`. A no-op without a health check.
    fn reconcile_probes(&self, diff: &HostSetDiff) {
        let Some(engine) = &self.health_engine else {
            return;
        };
        let mut probes = self
            .probes
            .lock()
            .expect("lock poisoned: a holder panicked");
        for addr in &diff.removed {
            if let Some(handle) = probes.remove(addr) {
                handle.abort();
            }
        }
        for &addr in &diff.added {
            // Hand the probe a clone of the cluster's detector, so a recovery also clears an outlier ejection.
            // The reverse does not happen (see `HealthCheckEngine::spawn_for_host`).
            let handle = engine.spawn_for_host(
                addr,
                Arc::clone(&self.host_set),
                self.outlier_detector.clone(),
            );
            probes.insert(addr, handle);
        }
    }

    /// Runs discovery and publishes the result to this cluster's `host_set`, returning the diff from the
    /// previous set. The initial resolution and the DNS refresh timer both go through here.
    ///
    /// An aggregate and an EDS cluster return an explicit no-op rather than resolving zero endpoints. For
    /// EDS, `discovery::resolve` returns an empty set, so falling through would wipe the membership
    /// delivered by [`ClusterManager::accept_eds_update`] on the next refresh.
    ///
    /// A changed set is published; an unchanged one is not. DNS can only change a host's address, so
    /// "unchanged" is exact. Skipping the publish keeps the live `Host`s and their health flags, in-flight
    /// counters, and identity.
    async fn resolve_and_publish(&self, resolver: &dyn HostResolver) -> io::Result<HostSetDiff> {
        let config = &self.config;
        if matches!(config.kind, ClusterKind::Aggregate { .. })
            || config.discovery == DiscoveryType::Eds
        {
            return Ok(HostSetDiff::default());
        }
        // Rust note: `load_full` hands back an owned `Arc<HostSet>`, where
        // `load` returns a short-lived guard that must not be held across an
        // `.await` -- and the lookup below can take as long as the
        // platform's DNS timeouts.
        let previous = self.host_set.load_full();
        let resolved = discovery::resolve(config, resolver, &previous).await?;
        drop(previous);

        let mut diff = HostSetDiff::default();
        // Rust note: `rcu` (read-copy-update) instead of `load` then `store`,
        // for the reason spelled out in `health_check::apply_health_transition`:
        // health checks and outlier ejection publish into this same cell from
        // their own tasks, and a plain store here would overwrite a flag they
        // set while the lookup was in flight. `rcu` re-runs the closure on the
        // newest set if it loses a race, so it must stay pure and cheap --
        // which is why it rebuilds the candidate from `resolved`'s hosts
        // each time rather than consuming them.
        self.host_set.rcu(|live| {
            let candidate = HostSet::from_hosts(resolved.all_hosts());
            diff = diff_host_sets(live, &candidate);
            if diff.added.is_empty() && diff.removed.is_empty() {
                return Arc::clone(live);
            }
            // `discovery::resolve` builds every `Host` fresh, with
            // `HealthFlags::default()`, so without this a refresh that adds
            // one address would silently re-mark every other host healthy --
            // see `host_set::carry_over_health_flags`.
            Arc::new(carry_over_health_flags(live, candidate, &diff))
        });
        self.initialized.store(true, Ordering::Release);
        self.reconcile_probes(&diff);
        Ok(diff)
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

/// The refresh timer of one `STRICT_DNS`/`LOGICAL_DNS` cluster: wait, look the
/// hostnames up, publish what changed, repeat -- until the cluster is gone.
/// [`ClusterManager::start_dns_refresh`] spawns it; `wait` is the delay before
/// the first lookup.
///
/// A failed lookup leaves the published host set alone (the last good one
/// keeps serving, or the empty one a cluster whose first lookup failed started
/// with) and retries after the schedule's failure backoff. The first failure
/// of a streak logs at `warn`, then only every power of two (see
/// [`discovery::should_warn`]); the lookup that ends a streak logs the
/// recovery once. The streak counter behind that is a field of the task's own
/// `schedule`, so none of the suppression state is shared and none of it is
/// on a request path.
async fn run_dns_refresh(
    cluster: Weak<ManagedCluster>,
    resolver: Arc<dyn HostResolver>,
    mut schedule: RefreshSchedule,
    mut wait: Duration,
) {
    loop {
        tokio::time::sleep(wait).await;
        // Hold a strong reference for the length of one lookup only. Sleeping
        // while holding it would keep a replaced cluster alive; letting go
        // before each sleep is what lets `Weak::upgrade` fail once the last
        // real owner is gone, which ends this loop.
        let Some(managed) = cluster.upgrade() else {
            return;
        };
        let name = managed.config.name.as_str();
        match managed.resolve_and_publish(resolver.as_ref()).await {
            Ok(diff) => {
                let (ended_streak, next_wait) = schedule.lookup_succeeded();
                wait = next_wait;
                if ended_streak > 0 {
                    tracing::info!(
                        cluster = %name,
                        failed_lookups = ended_streak,
                        "DNS lookup recovered"
                    );
                }
                if !diff.added.is_empty() || !diff.removed.is_empty() {
                    tracing::debug!(
                        cluster = %name,
                        added = ?diff.added,
                        removed = ?diff.removed,
                        "DNS answer changed the cluster's hosts"
                    );
                }
            }
            Err(err) => {
                let (streak, next_wait) = schedule.lookup_failed();
                wait = next_wait;
                let hosts = managed.host_set.load().all_hosts().len();
                // Rust note: `tracing` levels are fixed per call site, so choosing `warn` or `debug` at run time takes two macro calls.
                if !discovery::should_warn(streak) {
                    tracing::debug!(
                        cluster = %name,
                        error = %err,
                        consecutive_failures = streak,
                        retry_in = ?wait,
                        hosts,
                        "DNS lookup failed again"
                    );
                } else if hosts == 0 {
                    tracing::warn!(
                        cluster = %name,
                        error = %err,
                        consecutive_failures = streak,
                        retry_in = ?wait,
                        "DNS lookup failed and the cluster has no hosts; retrying"
                    );
                } else {
                    tracing::warn!(
                        cluster = %name,
                        error = %err,
                        consecutive_failures = streak,
                        retry_in = ?wait,
                        hosts,
                        "DNS lookup failed; keeping the last resolved hosts and retrying"
                    );
                }
            }
        }
    }
}

/// Owns every cluster's discovery state. `&self`-based, so one manager can be shared as
/// `Arc<ClusterManager>` between config reloads and DNS refresh timers.
pub struct ClusterManager {
    // Rust note: the registry sits behind an extra `Arc`, so a [`ClusterHandle`] holds a clone of this exact
    // registry rather than a snapshot. Aggregate member resolution is late-bound: a member resolved at the
    // aggregate's construction would keep pointing at a `ManagedCluster` that a later reload replaces,
    // silently freezing its discovery.
    clusters: Arc<ArcSwap<HashMap<ClusterName, Arc<ManagedCluster>>>>,
    resolver: Arc<dyn HostResolver>,
    transport_builder: TransportSocketBuilder,
}

/// A cluster set built by [`ClusterManager::stage`] and not yet installed. Dropping it discards the built
/// clusters and aborts their tasks.
pub struct StagedClusters {
    next: HashMap<ClusterName, Arc<ManagedCluster>>,
    freshly_built: Vec<ClusterName>,
    rejected: Vec<(ClusterName, ClusterBuildError)>,
}

impl StagedClusters {
    /// Clusters whose config could not be built, with the reason.
    pub fn rejected(&self) -> &[(ClusterName, ClusterBuildError)] {
        &self.rejected
    }

    /// Discards the staged clusters, keeping only the rejections.
    pub fn into_rejected(self) -> Vec<(ClusterName, ClusterBuildError)> {
        self.rejected
    }
}

/// Clusters [`ClusterManager::install`] kept only for workers still on the
/// previous snapshot; [`ClusterManager::retire`] removes them.
#[must_use = "dropped clusters stay in the registry until this is passed to `retire`"]
pub struct PendingRemoval {
    names: Vec<ClusterName>,
}

/// Re-mints a cluster's token on the schedule [`MintedCredential::mint_and_publish`] returns. The token cluster
/// is looked up in the live registry on every mint, so a reload that rebuilds it is picked up. A cluster from
/// an older generation keeps refreshing while connections built on that generation still route through it.
async fn run_token_refresh(
    cluster: Weak<ManagedCluster>,
    registry: Weak<ArcSwap<HashMap<ClusterName, Arc<ManagedCluster>>>>,
    mut wait: Duration,
) {
    loop {
        tokio::time::sleep(wait).await;
        let (Some(managed), Some(registry)) = (cluster.upgrade(), registry.upgrade()) else {
            return;
        };
        let Some(minted) = managed.minted.clone() else {
            return;
        };
        // Do not hold the cluster itself across the mint: its last connection may close meanwhile.
        drop(managed);
        let token_cluster = registry
            .load()
            .get(minted.token_cluster())
            .map(|token_cluster| ClusterHandle {
                managed: Arc::clone(token_cluster),
                registry: Arc::clone(&registry),
            });
        wait = minted
            .mint_and_publish(token_cluster.as_ref().map(|h| h as &dyn ClusterEntry))
            .await;
    }
}

/// Immutable view of the registry for one listener/HCM configuration generation. Existing connections keep
/// their generation's view, while a new configuration serves new connections from its replacement.
#[derive(Clone)]
pub struct ClusterRegistrySnapshot {
    // A distinct, never-updated `ArcSwap`, seeded with one published registry. Aggregate members must resolve
    // within this generation, not against a later reload's registry.
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

    /// Convenience constructor for callers without real upstream TLS. It installs
    /// [`transport::reject_tls_builder`], so a `transport_socket` cluster fails loudly rather than
    /// downgrading to plaintext. Used by this crate's tests.
    pub fn with_default_transport(resolver: Arc<dyn HostResolver>) -> Self {
        Self::new(resolver, transport::reject_tls_builder())
    }

    /// Captures the currently published registry for a connection-facing configuration generation. Handles
    /// from this view never see a later replacement, so requests routed by an older HCM keep their clusters
    /// through a reload.
    pub fn routing_snapshot(&self) -> ClusterRegistrySnapshot {
        ClusterRegistrySnapshot {
            clusters: Arc::new(ArcSwap::from(self.clusters.load_full())),
        }
    }

    /// Reconciles against a config snapshot's cluster map and starts each current cluster's initial resolution.
    ///
    /// A cluster whose config is unchanged is carried forward as the same `Arc<ManagedCluster>`: its host set,
    /// health engine, outlier detector, refresh timer, and task handles all survive, and it is not re-resolved.
    /// "Unchanged" means `Arc::ptr_eq` or equal `ClusterConfig` (derived `PartialEq`). Both are needed:
    /// - `Arc::ptr_eq` covers the ADS path. When a CDS push changes only cluster B, `ResourceApplier` keeps
    ///   cluster A's `Arc<ClusterConfig>` pointer-identical. Without carry-forward, a control-plane heartbeat
    ///   would clear ejection state proxy-wide.
    /// - Content equality covers a SIGHUP reload, where every `Arc` is freshly lowered and no pointer
    ///   survives. Pointer equality alone is conservative; content equality makes carry-forward complete.
    ///
    /// A changed cluster takes the full rebuild-then-resolve path in `next`'s resolve loop. A freshly built
    /// `STRICT_DNS`/`LOGICAL_DNS` cluster starts its refresh timer right after its initial lookup (see
    /// `start_dns_refresh`). The replaced cluster keeps its timer until its last reference drops, so a
    /// connection that predates the reload stays fresh while it routes through the old cluster.
    ///
    /// Every freshly built cluster is resolved before the map is published. Publishing empty placeholders
    /// first would reject traffic for every cluster, including static ones, for as long as a slow DNS lookup
    /// took. Resolving into `next` first lets the old map serve until the new one swaps in atomically.
    ///
    /// EDS-delivered membership on a config-sourced EDS cluster survives an unrelated reload through the same
    /// carry-forward, since its config does not change. Its `host_set` (installed by
    /// [`Self::accept_eds_update`]) rides along on the same `Arc`.
    ///
    /// A cluster whose `lb_policy` is unimplemented (`RING_HASH`/`MAGLEV`) is rejected, not substituted
    /// (AGENTS.md invariant 1). It is left out of the set, and its name and error are returned so the caller
    /// can surface them as a config error.
    ///
    /// This builds, installs, and retires in one step, for callers with no workers to publish to (boot,
    /// tests). A live apply uses [`Self::stage`], [`Self::install`], and [`Self::retire`] so removal is
    /// two-phase.
    pub async fn update_from_snapshot(
        &self,
        clusters: &HashMap<ClusterName, Arc<ClusterConfig>>,
    ) -> Vec<(ClusterName, ClusterBuildError)> {
        let (pending, rejected) = self.install(self.stage(clusters)).await;
        self.retire(pending);
        rejected
    }

    /// Builds every cluster in `clusters` whose config differs from the live one, without installing anything.
    /// Unchanged clusters are carried forward (see [`Self::update_from_snapshot`]). An all-or-nothing caller (an
    /// xDS response, S8) checks [`StagedClusters::rejected`] and drops the result to discard it; the live
    /// registry is untouched until [`Self::install`].
    pub fn stage(&self, clusters: &HashMap<ClusterName, Arc<ClusterConfig>>) -> StagedClusters {
        let previous = self.clusters.load_full();
        let mut next: HashMap<ClusterName, Arc<ManagedCluster>> =
            HashMap::with_capacity(clusters.len());
        let mut rejected = Vec::new();
        // Only freshly built clusters need `resolve_cluster` in `install`. A carried-forward cluster's
        // `host_set` is already live and must not be touched.
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
        StagedClusters {
            next,
            freshly_built,
            rejected,
        }
    }

    /// Resolves the staged clusters and installs them, keeping live clusters the new set dropped. Dropped
    /// names come back as a [`PendingRemoval`] for [`Self::retire`], along with the clusters `stage` rejected.
    ///
    /// Removal waits because a worker builds a connection's router against the registry as it stands when
    /// that worker first serves a snapshot. A worker still on the previous snapshot may route to a dropped
    /// cluster and would answer 503 "unknown cluster" for that connection's lifetime. So new and changed
    /// clusters must be present before workers see the new snapshot, and dropped ones must stay until then.
    pub async fn install(
        &self,
        staged: StagedClusters,
    ) -> (PendingRemoval, Vec<(ClusterName, ClusterBuildError)>) {
        let StagedClusters {
            mut next,
            freshly_built,
            rejected,
        } = staged;
        // Resolve each freshly built cluster into its own `host_set`. Nothing here is reachable through
        // `self.clusters` yet, so no one can observe a half-resolved cluster. `resolve_cluster` runs the same
        // path as the refresh timer, so an EDS-typed cluster still resolves to nothing here: there is no
        // membership to carry over at construction.
        for name in &freshly_built {
            let managed = &next[name];
            let resolved = self.resolve_cluster(managed).await;
            if let Err(err) = &resolved {
                // Rust note: a discovery failure does not take the manager down. Envoy keeps serving the
                // last-known-good set (here, empty, since this is the first resolution) and logs. A DNS cluster
                // retries on its refresh timer, and the failure is scoped to this one cluster.
                tracing::warn!(
                    cluster = %name,
                    error = %err,
                    retrying = managed.config.discovery.dns_refresh().is_some(),
                    "initial cluster discovery failed"
                );
            }
            self.start_dns_refresh(managed, resolved.is_ok());
        }
        // Mint each freshly built cluster's first token before the set is published, so a new provider or a
        // rotated key serves at once instead of refusing requests until the refresher's first tick. Mints run
        // concurrently, each bounded by its own request timeout; a failure publishes nothing, warns, and leaves
        // retrying to the refresher. A carried-forward cluster keeps its token and refresher.
        let minting: Vec<(Arc<ManagedCluster>, Arc<MintedCredential>)> = freshly_built
            .iter()
            .filter_map(|name| {
                let managed = &next[name];
                managed
                    .minted
                    .clone()
                    .map(|minted| (Arc::clone(managed), minted))
            })
            .collect();
        let waits = futures::future::join_all(minting.iter().map(|(_, minted)| {
            let token_cluster =
                next.get(minted.token_cluster())
                    .map(|token_cluster| ClusterHandle {
                        managed: Arc::clone(token_cluster),
                        registry: Arc::clone(&self.clusters),
                    });
            async move {
                minted
                    .mint_and_publish(token_cluster.as_ref().map(|h| h as &dyn ClusterEntry))
                    .await
            }
        }))
        .await;
        for ((managed, _), wait) in minting.iter().zip(waits) {
            self.start_token_refresh(managed, wait);
        }
        let previous = self.clusters.load_full();
        let mut dropped = Vec::new();
        for (name, managed) in previous.iter() {
            // A live cluster whose new definition was rejected is retired the same way: it is not in the new
            // set, but workers on the previous snapshot still route to it.
            if !next.contains_key(name) {
                next.insert(name.clone(), Arc::clone(managed));
                dropped.push(name.clone());
            }
        }
        self.clusters.store(Arc::new(next));
        (PendingRemoval { names: dropped }, rejected)
    }

    /// Removes the clusters an earlier [`Self::install`] kept for workers on the previous snapshot. Call only
    /// after the new snapshot is published. Connections built earlier keep their own registry view, so a
    /// retired cluster lives until they close.
    pub fn retire(&self, pending: PendingRemoval) {
        if pending.names.is_empty() {
            return;
        }
        let mut next = HashMap::clone(&self.clusters.load_full());
        for name in &pending.names {
            next.remove(name);
        }
        self.clusters.store(Arc::new(next));
    }

    /// Starts the timer that re-resolves `managed`'s hostnames. Only `STRICT_DNS` and `LOGICAL_DNS` clusters get
    /// one. Without it, a DNS cluster would keep its first lookup's addresses forever, and one whose first
    /// lookup failed would stay empty.
    ///
    /// `initial_lookup_succeeded` decides the first wait: the refresh rate, or the first failure backoff.
    ///
    /// The task runs on the control runtime, since `update_from_snapshot` is only called from control-side
    /// code, never from a worker. Like the probes and the outlier sweep, it needs a Tokio runtime.
    fn start_dns_refresh(&self, managed: &Arc<ManagedCluster>, initial_lookup_succeeded: bool) {
        let Some(refresh) = managed.config.discovery.dns_refresh() else {
            return;
        };
        let mut schedule = RefreshSchedule::new(refresh);
        let first_wait = if initial_lookup_succeeded {
            schedule.lookup_succeeded().1
        } else {
            schedule.lookup_failed().1
        };
        // Rust note: the task holds a `Weak`, not an `Arc`. The cluster owns this task's `JoinHandle`, so a
        // strong reference would form a cycle: `Drop` would never run and the timer would outlive every reload.
        let task = tokio::spawn(run_dns_refresh(
            Arc::downgrade(managed),
            Arc::clone(&self.resolver),
            schedule,
            first_wait,
        ));
        if let Some(previous) = managed
            .dns_refresh_task
            .lock()
            .expect("lock poisoned: a holder panicked")
            .replace(task)
        {
            previous.abort();
        }
    }

    /// Starts the task that re-mints `managed`'s token, first after `wait`. Like the DNS timer it runs on the
    /// control runtime and holds `Weak`s, so it ends with the cluster.
    fn start_token_refresh(&self, managed: &Arc<ManagedCluster>, wait: Duration) {
        let task = tokio::spawn(run_token_refresh(
            Arc::downgrade(managed),
            Arc::downgrade(&self.clusters),
            wait,
        ));
        if let Some(previous) = managed
            .token_refresh_task
            .lock()
            .expect("lock poisoned: a holder panicked")
            .replace(task)
        {
            previous.abort();
        }
    }

    /// Applies an externally supplied endpoint set to an EDS cluster, publishing a new host set and marking it
    /// initialized.
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
        // Rust note: `static_hosts` turns literal-IP `EndpointIR`s into `Host`s. It does no I/O, whatever the source.
        let hosts = discovery::static_hosts(endpoints)?;
        let new_set = HostSet::from_hosts(hosts);
        let old_set = managed.host_set.load();
        let diff = diff_host_sets(&old_set, &new_set);
        // Carry `health_flags` over for every address still present. Otherwise the next EDS push would erase an
        // active-check result. See `host_set::carry_over_health_flags`.
        let new_set = carry_over_health_flags(&old_set, new_set, &diff);
        drop(old_set);
        managed.host_set.store(Arc::new(new_set));
        managed.initialized.store(true, Ordering::Release);
        managed.reconcile_probes(&diff);
        Ok(diff)
    }

    /// Runs discovery for `managed` and publishes into its own `host_set`, returning the diff. Does not touch
    /// `self.clusters`: it serves [`Self::update_from_snapshot`], which resolves clusters not yet published.
    async fn resolve_cluster(&self, managed: &ManagedCluster) -> io::Result<HostSetDiff> {
        managed.resolve_and_publish(self.resolver.as_ref()).await
    }

    /// The router-facing handle for a cluster, or `None` if no cluster with that name is known.
    pub fn cluster(&self, name: &str) -> Option<Arc<dyn ClusterEntry>> {
        self.clusters.load().get(name).cloned().map(|managed| {
            Arc::new(ClusterHandle {
                managed,
                // Rust note: clone the `Arc<ArcSwap<..>>` itself, not the map it points at. That keeps aggregate
                // member lookups late-bound (see `ClusterManager::clusters`).
                registry: Arc::clone(&self.clusters),
            }) as Arc<dyn ClusterEntry>
        })
    }

    /// Whether the currently published cluster `name` has a host at `addr`. `false` for an unknown cluster.
    /// Reads the live registry, not a generation snapshot, so the upstream pool sees membership changes and
    /// drains removed endpoints.
    pub fn has_host(&self, name: &str, addr: SocketAddr) -> bool {
        self.clusters
            .load()
            .get(name)
            .is_some_and(|managed| managed.host_set.load().contains_address(addr))
    }

    /// Whether a cluster's first resolution or EDS update has landed, or it was force-initialized. `false`
    /// for an unknown name.
    pub fn is_initialized(&self, name: &str) -> bool {
        self.clusters
            .load()
            .get(name)
            .map(|managed| managed.initialized.load(Ordering::Acquire))
            .unwrap_or(false)
    }

    /// Envoy's `initial_fetch_timeout` "proceed empty" escape hatch: marks a cluster initialized even though it
    /// never resolved, so warming does not wait on it forever. No-op for an unknown name.
    pub fn force_initialize(&self, name: &str) {
        if let Some(managed) = self.clusters.load().get(name) {
            managed.initialized.store(true, Ordering::Release);
        }
    }

    /// Names of every registered cluster still waiting on its first resolution or EDS update, built on
    /// [`Self::is_initialized`]. `/ready` gates on whether this is empty (see `proxy-admin`'s `ReadinessProbe`).
    pub fn warming_clusters(&self) -> Vec<ClusterName> {
        self.clusters
            .load()
            .keys()
            .filter(|name| !self.is_initialized(name))
            .cloned()
            .collect()
    }

    /// Snapshots the runtime host sets whose cluster config matches `config`. A reload installs its
    /// replacement map before publishing the matching `ConfigSnapshot`. Filtering on an exact config match
    /// keeps an admin reader on the old snapshot from reporting endpoints from that unpublished configuration.
    /// The returned lists are copies.
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

    /// Whether a weighted route may draw `name`: false only when the cluster
    /// exists and has no healthy host (every host ejected by S6 outlier
    /// detection or failing active health checks). An aggregate counts as
    /// healthy while any member it would walk has a healthy host. An unknown
    /// cluster counts as healthy, so the draw leaves it to the router's own
    /// `NC` answer rather than hiding it.
    pub fn is_drawable(&self, name: &str) -> bool {
        let registry = self.clusters.load();
        let Some(managed) = registry.get(name) else {
            return true;
        };
        match managed.aggregate_members() {
            None => managed.host_set.load().has_healthy_host(),
            Some(members) => members.iter().any(|member| {
                registry.get(member).is_some_and(|member| {
                    !member.is_aggregate() && member.host_set.load().has_healthy_host()
                })
            }),
        }
    }

    /// Where to record a latency sample for a response from `name`, the cluster actually dialled.
    pub fn latency_recorder(&self, name: &str) -> Option<Arc<LatencyEwma>> {
        self.clusters
            .load()
            .get(name)
            .map(|managed| Arc::clone(&managed.latency))
    }

    /// The latency a weighted draw expects from `name`, in microseconds; `None` before any sample or for
    /// an unknown cluster. An aggregate answers with the member its walk would dial first: the first member
    /// with a healthy host, or its first member when none has one.
    pub fn expected_latency_micros(&self, name: &str) -> Option<f64> {
        let registry = self.clusters.load();
        let managed = registry.get(name)?;
        let Some(members) = managed.aggregate_members() else {
            return managed.latency.micros();
        };
        let walkable =
            |member: &ClusterName| registry.get(member).filter(|member| !member.is_aggregate());
        members
            .iter()
            .filter_map(walkable)
            .find(|member| member.host_set.load().has_healthy_host())
            .or_else(|| members.iter().find_map(walkable))
            .and_then(|member| member.latency.micros())
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
    /// When `ctx.credential_providers` is set (tenant mode), members without a
    /// tenant credential slot for one of those providers are skipped too.
    ///
    /// A member that is itself an aggregate is never followed. Nested
    /// aggregates are deliberately unsupported, and
    /// refusing to recurse makes a member cycle structurally impossible
    /// rather than something this loop has to detect.
    ///
    /// A member none of whose hosts is healthy (every host ejected by S6
    /// outlier detection or failing active health checks) is passed over
    /// while a later member still has a healthy host. As in Envoy, where such
    /// a member contributes no healthy load to the combined priority set.
    /// When no remaining member has a healthy host, the walk runs again
    /// without that preference, so the first member's own S7 panic pick
    /// serves the request and the retry chain still reaches every member.
    ///
    /// Deliberate divergence from Envoy: each member's own `HostPicker`
    /// still applies that member's full S7 logic (panic threshold, priority
    /// spillover, overprovisioning) *within* that member, but this loop does
    /// **not** implement Envoy's cross-member combined priority set, where a
    /// member at partial health bleeds a *fraction* of traffic across the
    /// member boundary. This is strict member-order failover: a member with
    /// any healthy host keeps all of its traffic. For LLM provider
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
        self.walk_aggregate_members(&registry, members, ctx, true)
            .or_else(|| self.walk_aggregate_members(&registry, members, ctx, false))
    }

    /// One pass of [`Self::select_aggregate_member`]. With `require_healthy`, a member with no healthy host is
    /// skipped.
    fn walk_aggregate_members(
        &self,
        registry: &HashMap<ClusterName, Arc<ManagedCluster>>,
        members: &[ClusterName],
        ctx: &LoadBalancerContext,
        require_healthy: bool,
    ) -> Option<HostSelection> {
        for name in members {
            if ctx.attempted_clusters.contains(name) {
                continue;
            }
            // The second pass revisits members the first already warned about, so only the first warns.
            let Some(member) = registry.get(name) else {
                if require_healthy {
                    tracing::warn!(
                        cluster = %name,
                        "aggregate member not found in cluster registry (config-reload race?), skipping"
                    );
                }
                continue;
            };
            if member.is_aggregate() {
                if require_healthy {
                    tracing::warn!(
                        cluster = %name,
                        "aggregate member is itself an aggregate cluster; nested aggregates are not \
                         supported yet, skipping"
                    );
                }
                continue;
            }
            // Tenant mode (ADR-0007): a member is eligible only if it holds a tenant credential slot for a
            // provider the tenant has. Checked before the host pick, so an ineligible member is never dialled.
            if let Some(providers) = &ctx.credential_providers {
                let eligible = member
                    .config
                    .provider_runtime
                    .as_ref()
                    .and_then(|runtime| runtime.tenant_credential.as_ref())
                    .is_some_and(|slot| providers.contains(&slot.provider));
                if !eligible {
                    continue;
                }
            }
            let host_set = member.host_set.load();
            if require_healthy && !host_set.has_healthy_host() {
                continue;
            }
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
        // Connect-per-stream: `ConnectPool` opens a fresh TCP connection per request and hands it to the
        // cluster's transport socket. The byte stream is protocol-agnostic (the router picks h1 or h2c on top),
        // so `_proto` does not change the pool today. Real h2 multiplexing pools are a follow-up.
        let server_name = host
            .hostname
            .clone()
            .unwrap_or_else(|| host.address.ip().to_string());
        // Rust note: this slice enforces only the DEFAULT-priority connection budget. The router does not thread
        // priority into `http_pool`, so HIGH-priority dials count against `default_cb`. `.clone()` shares the same
        // gauge (its handles are `Arc`-backed) across every per-call `ConnectPool`, so the count stays global per cluster.
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
        // An aggregate's own `request_headers_to_add` is never read: the router calls this on the member's entry
        // (`HostSelection::member`). AGENTS.md invariant 6 is why: anything per-provider belongs on the cluster
        // actually dialled.
        &self.managed.config.request_headers_to_add
    }

    fn request_path_rewrite(&self) -> Option<&proxy_config::ir::RequestPathRewrite> {
        self.managed.config.request_path_rewrite.as_ref()
    }

    fn provider_runtime(&self) -> Option<&proxy_config::ir::ProviderRuntimeConfig> {
        self.managed.config.provider_runtime.as_ref()
    }

    fn minted_credential(&self) -> Option<&MintedCredential> {
        self.managed.minted.as_deref()
    }

    fn usage_dialect(&self) -> Option<proxy_config::ir::UsageDialect> {
        self.managed.config.usage_dialect
    }

    fn unanswered_usage(&self) -> proxy_config::ir::UnansweredUsage {
        self.managed.config.unanswered_usage
    }

    fn report_outlier_result(&self, addr: SocketAddr, result: RequestResult) {
        // No-op unless this cluster configures outlier detection. For an aggregate, the router calls this on the
        // member's entry (the one owning the dialled host), which is why it reaches the member's detector.
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
    use proxy_config::ir::{DiscoveryType, DnsRefresh, LbPolicy};
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
            unanswered_usage: proxy_config::ir::UnansweredUsage::default(),
            health_check: None,
            outlier_detection: None,
        })
    }

    /// Re-resolves the published cluster `name` through the production path
    /// (`ManagedCluster::resolve_and_publish`, which the refresh timer also uses), without waiting for the timer.
    async fn resolve_now(manager: &ClusterManager, name: &str) -> io::Result<HostSetDiff> {
        let managed = manager.clusters.load().get(name).cloned().unwrap();
        managed.resolve_and_publish(manager.resolver.as_ref()).await
    }

    /// Like `cluster_config`, plus a `connect_timeout`. A real but inconsequential content change, for reload
    /// tests. `ClusterConfig` has no `Clone`, so this is a second constructor.
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
            unanswered_usage: proxy_config::ir::UnansweredUsage::default(),
            health_check: None,
            outlier_detection: None,
        })
    }

    /// A config-sourced EDS cluster (`discovery: eds`): membership arrives via
    /// [`ClusterManager::accept_eds_update`]. Tests the EDS carry-forward described in `update_from_snapshot`.
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
            unanswered_usage: proxy_config::ir::UnansweredUsage::default(),
            health_check: None,
            outlier_detection: None,
        })
    }

    /// A STATIC cluster whose outlier detection ejects after `consecutive_5xx` 5xx responses. Enforcement is
    /// 100% and the ejection cap is 100%, so a single-host cluster can eject its only host (the default 10%
    /// rounds to zero for one host).
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
            unanswered_usage: proxy_config::ir::UnansweredUsage::default(),
            health_check: None,
            outlier_detection: Some(od),
        })
    }

    /// An aggregate cluster over `members`, in the given order. `endpoints` and `discovery` are unused for an
    /// aggregate (see `ClusterKind::Aggregate`), but `ClusterConfig` still needs valid values.
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
            unanswered_usage: proxy_config::ir::UnansweredUsage::default(),
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

    /// Like `cluster_config`, plus a `health_check`. Kept separate so the call sites that ignore health checks
    /// stay untouched.
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
            unanswered_usage: proxy_config::ir::UnansweredUsage::default(),
            health_check: Some(health_check),
            outlier_detection: None,
        })
    }

    /// A bare TCP-connect health check (empty `send`/`expect`; see `HealthCheckKindIR::Tcp`) with the given
    /// thresholds and interval, plus a generous timeout. These tests care about threshold and scheduling, not
    /// timeout edges.
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

    /// A cluster with both a health check and outlier detection. `uneject_on_healthy_active_hc` is the one
    /// field the tests vary. The outlier settings mirror `cluster_config_with_outlier`.
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
            unanswered_usage: proxy_config::ir::UnansweredUsage::default(),
            health_check: Some(health_check),
            outlier_detection: Some(od),
        })
    }

    /// Accepts connections forever and counts them. This is the observable signal that a probe loop is still
    /// running, since a `JoinHandle`'s fate is not visible from outside `manager.rs`.
    fn spawn_counting_acceptor(listener: TcpListener, hits: Arc<AtomicUsize>) {
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_ok() {
                    hits.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }

    /// Polls `cond` on real wall-clock time until it holds or `deadline` elapses. These tests assert on real TCP
    /// timing, which races a paused clock's auto-advance.
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

    /// Two-phase removal (make-before-break). Between `install` and `retire`, a worker on the previous snapshot
    /// builds its router from `routing_snapshot`, so the dropped cluster must still be there, or that
    /// connection answers 503 for its whole life. The new cluster must be there too.
    #[tokio::test]
    async fn a_dropped_cluster_stays_routable_until_it_is_retired() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "old".to_string(),
            cluster_config("old", DiscoveryType::Static, vec![endpoint("10.0.0.1", 80)]),
        );
        manager.update_from_snapshot(&snapshot).await;

        let mut next = HashMap::new();
        next.insert(
            "new".to_string(),
            cluster_config("new", DiscoveryType::Static, vec![endpoint("10.0.0.2", 80)]),
        );
        let (pending, rejected) = manager.install(manager.stage(&next)).await;
        assert!(rejected.is_empty());
        let between = manager.routing_snapshot();
        assert!(between.cluster("old").is_some(), "dropped before retire");
        assert!(between.cluster("new").is_some(), "added after install");

        manager.retire(pending);
        assert!(manager.cluster("old").is_none());
        assert!(manager.cluster("new").is_some());
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
                DiscoveryType::StrictDns(DnsRefresh::ENVOY_DEFAULT),
                vec![endpoint("svc.internal", 80)],
            ),
        );
        manager.update_from_snapshot(&snapshot).await;

        // Flap the record set and re-resolve manually (no real timer).
        resolver.set(
            "svc.internal",
            vec![IpAddr::from([10, 0, 0, 2]), IpAddr::from([10, 0, 0, 3])],
        );
        let diff = resolve_now(&manager, "dns-svc").await.unwrap();

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

    /// The upstream pool's drain oracle: an endpoint EDS replaces stops
    /// being a member at once, the replacement starts being one, and an
    /// unknown cluster has no members.
    #[tokio::test]
    async fn has_host_follows_an_eds_replacement() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert("eds-svc".to_string(), cluster_config_eds("eds-svc"));
        manager.update_from_snapshot(&snapshot).await;
        let a = SocketAddr::new(IpAddr::from([10, 0, 0, 5]), 80);
        let b = SocketAddr::new(IpAddr::from([10, 0, 0, 6]), 80);

        manager
            .accept_eds_update("eds-svc", &[endpoint("10.0.0.5", 80)])
            .unwrap();
        assert!(manager.has_host("eds-svc", a));
        assert!(!manager.has_host("eds-svc", b));

        manager
            .accept_eds_update("eds-svc", &[endpoint("10.0.0.6", 80)])
            .unwrap();
        assert!(!manager.has_host("eds-svc", a), "replaced endpoint is gone");
        assert!(manager.has_host("eds-svc", b));
        assert!(!manager.has_host("no-such-cluster", b));
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
            // A non-aggregate pick never carries a `member`: the caller's entry is the owner.
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

    /// An aggregate `"providers"` over `["a", "b"]` whose members each have one host and eject it after a single
    /// 5xx, with the S6 default 30 s ejection.
    async fn aggregate_over_ejectable_a_and_b() -> ClusterManager {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::with_default_transport(resolver);
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "a".to_string(),
            cluster_config_with_outlier("a", vec![endpoint("10.0.0.1", 80)], 1),
        );
        snapshot.insert(
            "b".to_string(),
            cluster_config_with_outlier("b", vec![endpoint("10.0.0.2", 80)], 1),
        );
        snapshot.insert(
            "providers".to_string(),
            aggregate_config("providers", &["a", "b"]),
        );
        manager.update_from_snapshot(&snapshot).await;
        manager
    }

    /// Ejects the only host of member `name` through the router's report seam.
    fn eject_only_host(manager: &ClusterManager, name: &str, addr: SocketAddr) {
        manager
            .cluster(name)
            .unwrap()
            .report_outlier_result(addr, RequestResult::Http5xx);
    }

    /// A member whose every host is ejected yields a host through its own S7 panic pick, so without the healthy
    /// preference the aggregate would keep dialling it. The pick must pass over it while `b` is healthy, and
    /// return to it once the ejection expires.
    #[tokio::test(start_paused = true)]
    async fn aggregate_passes_over_an_ejected_member_until_it_recovers() {
        let manager = aggregate_over_ejectable_a_and_b().await;
        let entry = manager.cluster("providers").unwrap();
        let a = SocketAddr::new(IpAddr::from([10, 0, 0, 1]), 80);
        let ctx = LoadBalancerContext::default();
        assert_eq!(entry.select_host(&ctx).unwrap().member.unwrap().name, "a");

        eject_only_host(&manager, "a", a);
        for _ in 0..10 {
            let sel = entry.select_host(&ctx).expect("b is healthy");
            assert_eq!(sel.member.unwrap().name, "b", "ejected `a` was picked");
        }

        // Past the 30 s base ejection, the un-eject timer restores `a`.
        tokio::time::sleep(Duration::from_secs(31)).await;
        assert_eq!(
            entry.select_host(&ctx).unwrap().member.unwrap().name,
            "a",
            "a recovered member must take its traffic back"
        );
    }

    /// With every member ejected there is no healthy member to prefer, so the walk falls back to member order
    /// and panic picks. The retry chain still reaches every member once, then ends.
    #[tokio::test]
    async fn aggregate_with_every_member_ejected_still_walks_the_whole_chain() {
        let manager = aggregate_over_ejectable_a_and_b().await;
        let entry = manager.cluster("providers").unwrap();
        eject_only_host(
            &manager,
            "a",
            SocketAddr::new(IpAddr::from([10, 0, 0, 1]), 80),
        );
        eject_only_host(
            &manager,
            "b",
            SocketAddr::new(IpAddr::from([10, 0, 0, 2]), 80),
        );

        let mut ctx = LoadBalancerContext::default();
        let first = entry.select_host(&ctx).expect("panic pick serves a");
        assert_eq!(first.member.unwrap().name, "a");
        ctx.attempted_clusters.push("a".to_string());
        let second = entry.select_host(&ctx).expect("panic pick serves b");
        assert_eq!(second.member.unwrap().name, "b");
        ctx.attempted_clusters.push("b".to_string());
        assert!(entry.select_host(&ctx).is_none(), "chain exhausted");
    }

    /// `cluster_config` with a tenant credential slot for `provider`.
    fn cluster_config_with_slot(
        name: &str,
        endpoints: Vec<EndpointIR>,
        provider: Option<&str>,
    ) -> Arc<ClusterConfig> {
        // Rust note: `ClusterConfig` is not `Clone`, but this `Arc` has one owner, so `try_unwrap` returns the value to mutate.
        let mut config = Arc::try_unwrap(cluster_config(name, DiscoveryType::Static, endpoints))
            .unwrap_or_else(|_| unreachable!("fresh Arc has one owner"));
        config.provider_runtime =
            provider.map(|provider| proxy_config::ir::ProviderRuntimeConfig {
                credential: None,
                path_template: None,
                model_rewrites: Vec::new(),
                request_field_policy: Default::default(),
                tenant_credential: Some(proxy_config::ir::TenantCredentialSlot {
                    provider: provider.to_string(),
                    header: "authorization".to_string(),
                    value_prefix: "Bearer ".to_string(),
                    verify_path: None,
                }),
            });
        Arc::new(config)
    }

    #[tokio::test]
    async fn aggregate_in_tenant_mode_skips_members_without_a_matching_slot() {
        let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
        let mut snapshot = HashMap::new();
        // "a": no slot. "b": slot for a provider the tenant lacks. "c": held.
        snapshot.insert(
            "a".to_string(),
            cluster_config_with_slot("a", vec![endpoint("10.0.0.1", 80)], None),
        );
        snapshot.insert(
            "b".to_string(),
            cluster_config_with_slot("b", vec![endpoint("10.0.0.2", 80)], Some("openai")),
        );
        snapshot.insert(
            "c".to_string(),
            cluster_config_with_slot("c", vec![endpoint("10.0.0.3", 80)], Some("anthropic")),
        );
        snapshot.insert(
            "providers".to_string(),
            aggregate_config("providers", &["a", "b", "c"]),
        );
        manager.update_from_snapshot(&snapshot).await;
        let entry = manager.cluster("providers").unwrap();

        let ctx = LoadBalancerContext {
            credential_providers: Some(Arc::from(vec!["anthropic".to_string()])),
            ..LoadBalancerContext::default()
        };
        let sel = entry.select_host(&ctx).expect("c is eligible");
        assert_eq!(sel.member.unwrap().name, "c");

        let none_held = LoadBalancerContext {
            credential_providers: Some(Arc::from(vec!["gemini".to_string()])),
            ..LoadBalancerContext::default()
        };
        assert!(entry.select_host(&none_held).is_none());

        // Platform mode (`None`) still picks the first member.
        let sel = entry
            .select_host(&LoadBalancerContext::default())
            .expect("platform mode serves a");
        assert_eq!(sel.member.unwrap().name, "a");
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

        // The SAME `entry`, obtained before the reload, must see the new address: member resolution is not
        // pinned to the `ManagedCluster` that existed when the handle was built.
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

    /// An active health check must actually run. Two static hosts: one a live listener, one a bound-then-dropped
    /// port. With `unhealthy_threshold: 1` and a short interval, `all_healthy_hosts()` must converge to the live
    /// host alone.
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

    /// `discovery::resolve` builds every `Host` fresh with `HealthFlags::default()`, so a naive `host_set.store`
    /// on refresh would re-mark an unhealthy host healthy every DNS cycle. Flip a host unhealthy directly,
    /// re-run discovery on an unchanged record set, and confirm the flag survives.
    #[tokio::test]
    async fn resolve_carries_over_health_flags_for_unchanged_hosts() {
        let resolver = Arc::new(FakeResolver::new());
        resolver.set("svc.internal", vec![IpAddr::from([10, 0, 0, 1])]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "dns-svc".to_string(),
            cluster_config(
                "dns-svc",
                DiscoveryType::StrictDns(DnsRefresh::ENVOY_DEFAULT),
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
                active_requests: Default::default(),
            })])));

        // Same DNS record set -- `addr` is `unchanged`, so its flipped flag
        // must survive, not be reset to `HealthFlags::default()` by the
        // freshly-resolved `Host` this refresh builds.
        resolve_now(&manager, "dns-svc").await.unwrap();

        let host = managed
            .host_set
            .load()
            .all_hosts()
            .into_iter()
            .find(|h| h.address == addr)
            .expect("host must still be present after refresh");
        assert!(
            !host.is_healthy(),
            "an unchanged host's health flag was reset by a re-resolve"
        );
    }

    /// A removed host's probe must stop. Empty `host-doomed`'s DNS record and re-resolve the same
    /// `ManagedCluster`. `reconcile_probes`'s `removed` path must abort the task, not just drop the map entry
    /// (see `ManagedCluster`'s `Drop` impl).
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
                DiscoveryType::StrictDns(DnsRefresh::ENVOY_DEFAULT),
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
        resolve_now(&manager, "removal").await.unwrap();

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

    /// A config reload must not leak the previous generation's probes. `update_from_snapshot` rebuilds a
    /// config-sourced cluster only when its config changes, so reload a single-host config several times, each
    /// with a different `interval` (a same-config reload hits carry-forward and aborts nothing). The hit rate
    /// against that host's listener must stay near one generation's worth, not scale with reloads, which is
    /// what a dropped-but-not-aborted `JoinHandle` per reload would produce.
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

        // Each reload's `interval` differs, so content equality never carry-forwards this cluster.
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

    /// Active-HC recovery must clear an outlier ejection. A host ejected via `report_outlier_result` must rejoin
    /// `all_healthy_hosts()` once a real active health check passes, not just flip `failed_active_hc`.
    ///
    /// The address starts with nothing listening, so the probe's first check fails and its `ConsecutiveTracker`
    /// reaches `Unhealthy`. That edge makes the later recovery a real `Some(Healthy)` transition, the only one
    /// `HealthCheckEngine::run_host_loop` reports to `on_active_health_check_pass`. The host then carries both
    /// flags, `failed_active_hc` from the real probe and `failed_outlier_check` from the manual report, and both
    /// must clear once a listener stands up.
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

        // The probe crosses `unhealthy_threshold: 1` against the dead address before the outlier ejection is layered on.
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

    /// The negative half: with `uneject_on_healthy_active_hc: false`, the same recovery flips `failed_active_hc`
    /// back but must NOT clear `failed_outlier_check`. The host stays out of `all_healthy_hosts()`.
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

        // Give the now-passing probe several more ticks, so a wiring bug that ignores the flag has room to
        // un-eject, then assert it did not.
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

    /// Regression test for reload ordering. The old `update_from_snapshot` stored every rebuilt cluster with an
    /// EMPTY `HostSet` and resolved them serially afterward. A slow `STRICT_DNS` cluster then left every other
    /// cluster in the reload, even a `STATIC` one, empty for the whole loop. This needs `multi_thread`: a
    /// `current_thread` runtime cannot run the reload and the sampling loop concurrently, so it would never see
    /// the mid-resolution window (AGENTS.md "Build And Test").
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
                    DiscoveryType::StrictDns(DnsRefresh::ENVOY_DEFAULT),
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

        // Reloading the identical map would carry BOTH clusters forward by content equality, so `dns-svc` would
        // never resolve and the reload would return at once. Give `dns-svc` a real but inconsequential change (a
        // different `connect_timeout`) so its slow resolution holds the reload open. `static-svc`'s
        // `Arc<ClusterConfig>` is untouched, so it is the carried-forward cluster this loop asserts on.
        let mut snapshot_for_reload = snapshot.clone();
        snapshot_for_reload.insert(
            "dns-svc".to_string(),
            Arc::new(ClusterConfig {
                // Same shape as `cluster_config`, with a different `connect_timeout`. `ClusterConfig` has no `Clone`.
                eds: None,
                name: "dns-svc".to_string(),
                discovery: DiscoveryType::StrictDns(DnsRefresh::ENVOY_DEFAULT),
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
                unanswered_usage: proxy_config::ir::UnansweredUsage::default(),
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

        // Sample static-svc's host set while the reload is in flight. The buggy ordering empties it as soon as the
        // all-empty map is stored, well before the slow DNS lookup finishes.
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

    /// The ADS path: `SotwSet::apply` (`proxy-xds/src/store.rs`) keeps the old resource `Arc` for an unchanged CDS
    /// entry, and `ResourceApplier::assemble_snapshot` (`proxy-xds/src/apply.rs`) clones it into the next snapshot.
    /// So this method sees the same `Arc<ClusterConfig>` pointer. Covers the cheap `Arc::ptr_eq` half of the
    /// carry-forward condition.
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

    /// The SIGHUP path: every `Arc<ClusterConfig>` is freshly lowered, so only content equality can match. Built
    /// twice via `cluster_config`, on purpose, so this exercises content equality and not `Arc::ptr_eq`.
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

    /// Acceptance test for carry-forward. A control-plane push that changes only cluster B must not clear an
    /// ejection on cluster A. Eject A's only host, push a snapshot where only B's config changed, and confirm A's
    /// `ManagedCluster` is the same `Arc` and its ejection survived.
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

        // Reload with ONLY b's config changed. a's config is content-equal (a fresh `Arc`, as a SIGHUP lowering produces).
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

    /// EDS membership survives an unrelated reload (see `update_from_snapshot`). A config-sourced EDS cluster
    /// (see [`cluster_config_eds`]) fed by [`ClusterManager::accept_eds_update`] must not be emptied by a reload
    /// that changes another cluster's config.
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

    /// An active-health-check failure flag set on a host must survive an unrelated cluster's config change in the
    /// same snapshot, as in `resolve_carries_over_health_flags_for_unchanged_hosts`.
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
                active_requests: Default::default(),
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

    // DNS refresh tests run on tokio's paused clock (`start_paused`). Sleeping advances virtual time to the next
    // timer, so a 5s interval costs no wall time. Tests sleep to just past an interval (5.1s), never to its exact
    // edge, where the test's timer and the refresh timer race.

    use futures::future::BoxFuture;

    /// A resolver that scripts each host's answer and records every lookup with its tokio-clock time.
    /// `FakeResolver` can do neither.
    #[derive(Default)]
    struct ScriptedResolver {
        /// `None` is a failing lookup.
        answers: Mutex<HashMap<String, Option<Vec<IpAddr>>>>,
        calls: Mutex<Vec<(String, tokio::time::Instant)>>,
        /// Runs inside every lookup before it answers: the test's way to make
        /// something else happen while a lookup is in flight.
        during_lookup: Mutex<Option<Box<dyn Fn() + Send>>>,
    }

    impl ScriptedResolver {
        fn answer(&self, host: &str, ips: Vec<IpAddr>) {
            self.answers
                .lock()
                .unwrap()
                .insert(host.to_string(), Some(ips));
        }

        fn fail(&self, host: &str) {
            self.answers.lock().unwrap().insert(host.to_string(), None);
        }

        fn lookups(&self, host: &str) -> Vec<tokio::time::Instant> {
            let calls = self.calls.lock().unwrap();
            calls
                .iter()
                .filter(|(h, _)| h == host)
                .map(|(_, at)| *at)
                .collect()
        }

        fn total_lookups(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        /// Time between consecutive lookups of `host`.
        fn gaps(&self, host: &str) -> Vec<Duration> {
            self.lookups(host).windows(2).map(|w| w[1] - w[0]).collect()
        }
    }

    impl HostResolver for ScriptedResolver {
        fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
            self.calls
                .lock()
                .unwrap()
                .push((host.to_string(), tokio::time::Instant::now()));
            if let Some(hook) = self.during_lookup.lock().unwrap().as_ref() {
                hook();
            }
            let answer = self.answers.lock().unwrap().get(host).cloned().flatten();
            Box::pin(
                async move { answer.ok_or_else(|| io::Error::other("scripted lookup failure")) },
            )
        }
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    fn dns_refresh(
        rate_secs: u64,
        jitter_secs: u64,
        failure_base_ms: u64,
        failure_max_ms: u64,
    ) -> DnsRefresh {
        DnsRefresh {
            refresh_rate: Duration::from_secs(rate_secs),
            jitter: Duration::from_secs(jitter_secs),
            failure_base_interval: Duration::from_millis(failure_base_ms),
            failure_max_interval: Duration::from_millis(failure_max_ms),
        }
    }

    /// One DNS cluster with a single hostname endpoint on port 80.
    fn dns_cluster(
        name: &str,
        host: &str,
        discovery: fn(DnsRefresh) -> DiscoveryType,
        refresh: DnsRefresh,
    ) -> Arc<ClusterConfig> {
        cluster_config(name, discovery(refresh), vec![endpoint(host, 80)])
    }

    fn snapshot_of(configs: Vec<Arc<ClusterConfig>>) -> HashMap<ClusterName, Arc<ClusterConfig>> {
        configs.into_iter().map(|c| (c.name.clone(), c)).collect()
    }

    /// The addresses `name` currently serves, sorted.
    fn live(
        manager: &ClusterManager,
        snapshot: &HashMap<ClusterName, Arc<ClusterConfig>>,
        name: &str,
    ) -> Vec<String> {
        manager
            .live_clusters_for(snapshot)
            .into_iter()
            .find(|c| c.name == name)
            .map(|c| c.endpoints.iter().map(|e| e.address.to_string()).collect())
            .unwrap_or_default()
    }

    /// The very `Arc<HostSet>` currently published for `name`, so a test can
    /// tell "republished an equal set" from "left it alone".
    fn published(manager: &ClusterManager, name: &str) -> Arc<HostSet> {
        manager
            .clusters
            .load()
            .get(name)
            .expect("cluster is registered")
            .host_set
            .load_full()
    }

    /// Recorded waits are exact on the paused clock apart from the timer
    /// wheel's whole-millisecond rounding, so allow a few.
    const SLACK: Duration = Duration::from_millis(5);

    fn assert_within(actual: Duration, low: Duration, high: Duration, what: &str) {
        assert!(
            actual + SLACK >= low && actual <= high + SLACK,
            "{what}: {actual:?} not in [{low:?}, {high:?}]"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_address_added_in_dns_appears_after_one_refresh_and_a_removed_one_disappears() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("svc.internal", vec![ip(1), ip(2)]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "svc.internal",
            DiscoveryType::StrictDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&snapshot).await;
        assert_eq!(
            live(&manager, &snapshot, "dns-svc"),
            ["10.0.0.1:80", "10.0.0.2:80"]
        );

        // DNS drops .1 and adds .3. Nothing moves before the refresh is due...
        resolver.answer("svc.internal", vec![ip(2), ip(3)]);
        tokio::time::sleep(Duration::from_millis(4900)).await;
        assert_eq!(
            live(&manager, &snapshot, "dns-svc"),
            ["10.0.0.1:80", "10.0.0.2:80"]
        );

        // ...and one refresh interval after the first lookup both are in.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            live(&manager, &snapshot, "dns-svc"),
            ["10.0.0.2:80", "10.0.0.3:80"]
        );
    }

    /// The timer must not republish an unchanged answer: that would replace every live `Host` (health flags,
    /// in-flight counters) with an equal fresh one every few seconds.
    #[tokio::test(start_paused = true)]
    async fn a_refresh_that_changes_nothing_leaves_the_published_host_set_alone() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("svc.internal", vec![ip(1), ip(2)]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "svc.internal",
            DiscoveryType::StrictDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&snapshot).await;
        let before = published(&manager, "dns-svc");

        tokio::time::sleep(Duration::from_secs(12)).await;
        assert_eq!(resolver.lookups("svc.internal").len(), 3, "it did look up");
        assert!(Arc::ptr_eq(&before, &published(&manager, "dns-svc")));

        // The same records in another order are not a change either.
        resolver.answer("svc.internal", vec![ip(2), ip(1)]);
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert!(resolver.lookups("svc.internal").len() >= 4);
        assert!(Arc::ptr_eq(&before, &published(&manager, "dns-svc")));
    }

    #[tokio::test(start_paused = true)]
    async fn a_cluster_whose_first_lookup_failed_fills_in_on_the_retry() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.fail("svc.internal");
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "svc.internal",
            DiscoveryType::StrictDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&snapshot).await;
        // Published but empty and still warming: `/ready` semantics are
        // exactly what they were before the timer existed.
        assert!(manager.cluster("dns-svc").is_some());
        assert!(live(&manager, &snapshot, "dns-svc").is_empty());
        assert_eq!(manager.warming_clusters(), vec!["dns-svc".to_string()]);

        // DNS comes back; the next retry picks it up with no reload.
        resolver.answer("svc.internal", vec![ip(1)]);
        tokio::time::sleep(Duration::from_millis(5100)).await;
        assert_eq!(live(&manager, &snapshot, "dns-svc"), ["10.0.0.1:80"]);
        assert!(manager.is_initialized("dns-svc"));
        assert!(manager.warming_clusters().is_empty());
    }

    /// A successful lookup with no records changes nothing, so the no-republish shortcut applies. The cluster
    /// is still resolved and must stop warming.
    #[tokio::test(start_paused = true)]
    async fn an_empty_answer_still_marks_the_cluster_initialized() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("svc.internal", Vec::new());
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "svc.internal",
            DiscoveryType::StrictDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&snapshot).await;
        assert!(manager.is_initialized("dns-svc"));
        assert!(live(&manager, &snapshot, "dns-svc").is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_after_success_keeps_the_last_good_hosts_and_keeps_retrying() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("svc.internal", vec![ip(1), ip(2)]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "svc.internal",
            DiscoveryType::StrictDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&snapshot).await;

        resolver.fail("svc.internal");
        tokio::time::sleep(Duration::from_secs(31)).await;
        assert_eq!(
            live(&manager, &snapshot, "dns-svc"),
            ["10.0.0.1:80", "10.0.0.2:80"],
            "an outage must not empty the cluster"
        );
        assert!(manager.is_initialized("dns-svc"));
        assert!(resolver.lookups("svc.internal").len() >= 6, "kept retrying");

        // And it heals: the next retry applies the new answer.
        resolver.answer("svc.internal", vec![ip(3)]);
        tokio::time::sleep(Duration::from_millis(5100)).await;
        assert_eq!(live(&manager, &snapshot, "dns-svc"), ["10.0.0.3:80"]);
    }

    /// Envoy's default when `dns_failure_refresh_rate` is unset: failures
    /// retry at the refresh rate, no growth.
    #[tokio::test(start_paused = true)]
    async fn failures_retry_at_the_refresh_rate_when_no_failure_rate_is_configured() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.fail("svc.internal");
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "svc.internal",
            DiscoveryType::StrictDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&snapshot).await;
        tokio::time::sleep(Duration::from_secs(60)).await;

        let gaps = resolver.gaps("svc.internal");
        assert!(gaps.len() >= 11, "{gaps:?}");
        for gap in gaps {
            assert_within(gap, Duration::from_secs(5), Duration::from_secs(5), "retry");
        }
    }

    /// With base 1s and max 6s the exponential step is 1, 2, 4, 6, 6, 6...
    /// seconds and each wait lies in (step/2, step]. The max is deliberately
    /// not a power-of-two multiple of the base, so reaching it takes the cap,
    /// not just the doubling.
    #[tokio::test(start_paused = true)]
    async fn failure_backoff_grows_and_is_capped_at_the_max() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.fail("svc.internal");
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "svc.internal",
            DiscoveryType::StrictDns,
            dns_refresh(5, 0, 1000, 6000),
        )]);
        manager.update_from_snapshot(&snapshot).await;
        tokio::time::sleep(Duration::from_secs(100)).await;

        let gaps = resolver.gaps("svc.internal");
        assert!(gaps.len() >= 14, "{gaps:?}");
        for (i, gap) in gaps.iter().enumerate() {
            let step = Duration::from_secs([1, 2, 4, 6][i.min(3)]);
            assert_within(*gap, step / 2, step, &format!("wait {i}"));
        }
        // Grown past anything the first wait could have been, and held at the
        // cap rather than growing on.
        assert!(gaps[3] > Duration::from_secs(3));
        assert!(gaps[0] <= Duration::from_secs(1) + SLACK);
        assert!(gaps.iter().all(|g| *g <= Duration::from_secs(6) + SLACK));
    }

    /// Success waits are the refresh rate plus a random share of `dns_jitter`.
    #[tokio::test(start_paused = true)]
    async fn jitter_spreads_the_refresh_waits_inside_its_bound() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("svc.internal", vec![ip(1)]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "svc.internal",
            DiscoveryType::StrictDns,
            dns_refresh(5, 3, 5000, 5000),
        )]);
        manager.update_from_snapshot(&snapshot).await;
        tokio::time::sleep(Duration::from_secs(100)).await;

        let gaps = resolver.gaps("svc.internal");
        assert!(gaps.len() >= 12, "{gaps:?}");
        for gap in &gaps {
            assert_within(
                *gap,
                Duration::from_secs(5),
                Duration::from_secs(8),
                "refresh",
            );
        }
        assert!(
            gaps.iter().any(|g| *g != gaps[0]),
            "a jittered wait is not the same every time: {gaps:?}"
        );
    }

    /// Round-robin DNS reorders its answers. The logical host must stay on its
    /// address while that address is still answered, and move only when it is
    /// gone.
    #[tokio::test(start_paused = true)]
    async fn logical_dns_keeps_its_host_while_the_answer_still_contains_it() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("svc.internal", vec![ip(1), ip(2)]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "svc.internal",
            DiscoveryType::LogicalDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&snapshot).await;
        assert_eq!(live(&manager, &snapshot, "dns-svc"), ["10.0.0.1:80"]);
        let before = published(&manager, "dns-svc");

        for answer in [
            vec![ip(2), ip(1)],
            vec![ip(1), ip(2)],
            vec![ip(2), ip(3), ip(1)],
        ] {
            resolver.answer("svc.internal", answer);
            tokio::time::sleep(Duration::from_millis(5100)).await;
            assert_eq!(live(&manager, &snapshot, "dns-svc"), ["10.0.0.1:80"]);
        }
        assert!(
            Arc::ptr_eq(&before, &published(&manager, "dns-svc")),
            "rotating answers must not republish the host"
        );

        // .1 leaves the answer: now, and only now, the host moves.
        resolver.answer("svc.internal", vec![ip(2), ip(3)]);
        tokio::time::sleep(Duration::from_millis(5100)).await;
        assert_eq!(live(&manager, &snapshot, "dns-svc"), ["10.0.0.2:80"]);
    }

    #[tokio::test(start_paused = true)]
    async fn removing_a_dns_cluster_stops_its_refresh_timer() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("svc.internal", vec![ip(1)]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "svc.internal",
            DiscoveryType::StrictDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&snapshot).await;
        tokio::time::sleep(Duration::from_secs(12)).await;
        assert_eq!(resolver.lookups("svc.internal").len(), 3);

        manager.update_from_snapshot(&HashMap::new()).await;
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(
            resolver.lookups("svc.internal").len(),
            3,
            "a removed cluster is not resolved any more"
        );
    }

    /// The timer task is cancelled when its cluster is dropped, not left to notice at its next tick. With a
    /// refresh rate of an hour the tick is far away, so a task still alive after the drop is a leak per reload.
    /// Observed through the resolver: the task holds the manager's `Arc<dyn HostResolver>`, released only when
    /// the task is dropped.
    #[tokio::test(start_paused = true)]
    async fn dropping_a_dns_cluster_cancels_its_timer_task_at_once() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("svc.internal", vec![ip(1)]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "svc.internal",
            DiscoveryType::StrictDns,
            dns_refresh(3600, 0, 3_600_000, 3_600_000),
        )]);
        assert_eq!(Arc::strong_count(&resolver), 2, "this test and the manager");

        manager.update_from_snapshot(&snapshot).await;
        assert_eq!(Arc::strong_count(&resolver), 3, "the timer task holds one");

        manager.update_from_snapshot(&HashMap::new()).await;
        // One scheduler turn lets the runtime process the abort.
        tokio::task::yield_now().await;
        assert_eq!(Arc::strong_count(&resolver), 2, "the timer task is gone");
    }

    /// A reload that changes a DNS cluster rebuilds it. Its predecessor's timer must stop, or a stale timer
    /// would republish into a cluster nobody routes to.
    #[tokio::test(start_paused = true)]
    async fn replacing_a_dns_cluster_on_reload_stops_the_old_timer() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("old.internal", vec![ip(1)]);
        resolver.answer("new.internal", vec![ip(2)]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let old = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "old.internal",
            DiscoveryType::StrictDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&old).await;
        tokio::time::sleep(Duration::from_secs(12)).await;
        assert_eq!(resolver.lookups("old.internal").len(), 3);

        // The operator moves the cluster to another hostname and a slower refresh.
        let new = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "new.internal",
            DiscoveryType::StrictDns,
            dns_refresh(20, 0, 20_000, 20_000),
        )]);
        manager.update_from_snapshot(&new).await;
        assert_eq!(live(&manager, &new, "dns-svc"), ["10.0.0.2:80"]);
        tokio::time::sleep(Duration::from_secs(100)).await;

        assert_eq!(
            resolver.lookups("old.internal").len(),
            3,
            "the replaced cluster's timer is gone"
        );
        let gaps = resolver.gaps("new.internal");
        assert!(gaps.len() >= 4, "{gaps:?}");
        for gap in gaps {
            assert_within(
                gap,
                Duration::from_secs(20),
                Duration::from_secs(20),
                "new timer",
            );
        }
    }

    /// A connection that predates a reload keeps routing through the cluster it was built against
    /// (`routing_snapshot`), so that cluster keeps its addresses fresh until its last reference drops.
    #[tokio::test(start_paused = true)]
    async fn a_replaced_cluster_keeps_refreshing_until_its_last_reference_is_dropped() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("old.internal", vec![ip(1)]);
        resolver.answer("new.internal", vec![ip(2)]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let old = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "old.internal",
            DiscoveryType::StrictDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&old).await;
        let older_generation = manager.routing_snapshot();

        let new = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "new.internal",
            DiscoveryType::StrictDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&new).await;
        tokio::time::sleep(Duration::from_secs(21)).await;
        assert_eq!(
            resolver.lookups("old.internal").len(),
            5,
            "still referenced, so still refreshed"
        );

        drop(older_generation);
        let after_drop = resolver.lookups("old.internal").len();
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(resolver.lookups("old.internal").len(), after_drop);
        assert!(
            resolver.lookups("new.internal").len() >= 13,
            "the current cluster is unaffected"
        );
    }

    /// A SIGHUP re-lowers every cluster into fresh, content-equal configs. Such
    /// a cluster is carried forward, so its timer must neither restart nor
    /// double.
    #[tokio::test(start_paused = true)]
    async fn an_unchanged_reload_keeps_the_running_timer() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("svc.internal", vec![ip(1)]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let config = || {
            snapshot_of(vec![dns_cluster(
                "dns-svc",
                "svc.internal",
                DiscoveryType::StrictDns,
                DnsRefresh::ENVOY_DEFAULT,
            )])
        };
        manager.update_from_snapshot(&config()).await;
        tokio::time::sleep(Duration::from_secs(3)).await;

        manager.update_from_snapshot(&config()).await;
        assert_eq!(
            resolver.lookups("svc.internal").len(),
            1,
            "carried forward, so not resolved again"
        );
        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert_eq!(
            resolver.lookups("svc.internal").len(),
            2,
            "the next lookup stays on the original schedule (t=5s), not t=8s"
        );

        tokio::time::sleep(Duration::from_secs(50)).await;
        for gap in resolver.gaps("svc.internal") {
            assert_within(
                gap,
                Duration::from_secs(5),
                Duration::from_secs(5),
                "one timer",
            );
        }
    }

    /// Only DNS clusters resolve on a timer. A refresh must never reach an EDS cluster: resolving it yields an
    /// empty set that would wipe the membership its stream delivered.
    #[tokio::test(start_paused = true)]
    async fn only_dns_clusters_get_a_refresh_timer() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("svc.internal", vec![ip(1)]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![
            cluster_config_eds("eds-svc"),
            cluster_config(
                "static-svc",
                DiscoveryType::Static,
                vec![endpoint("10.0.0.9", 80)],
            ),
            aggregate_config("agg", &["static-svc"]),
            dns_cluster(
                "dns-svc",
                "svc.internal",
                DiscoveryType::LogicalDns,
                DnsRefresh::ENVOY_DEFAULT,
            ),
        ]);
        manager.update_from_snapshot(&snapshot).await;
        manager
            .accept_eds_update("eds-svc", &[endpoint("10.0.0.5", 80)])
            .unwrap();

        // Which clusters own a refresh task. A stray one on a non-DNS cluster
        // would be invisible through the resolver, which these never reach.
        let has_task = |name: &str| {
            let managed = manager.clusters.load().get(name).unwrap().clone();
            let task = managed.dns_refresh_task.lock().unwrap();
            task.is_some()
        };
        for name in ["eds-svc", "static-svc", "agg"] {
            assert!(!has_task(name), "{name} has no hostnames to refresh");
        }
        assert!(has_task("dns-svc"));

        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(
            resolver.total_lookups(),
            resolver.lookups("svc.internal").len(),
            "only the DNS cluster's hostname is ever looked up"
        );
        assert_eq!(live(&manager, &snapshot, "eds-svc"), ["10.0.0.5:80"]);

        // The by-name path shares the guard.
        let diff = resolve_now(&manager, "eds-svc").await.unwrap();
        assert_eq!(diff, HostSetDiff::default());
        assert_eq!(live(&manager, &snapshot, "eds-svc"), ["10.0.0.5:80"]);
    }

    /// A health check can mark a host while a lookup is in flight. The publish must build on the set as it is
    /// when the lookup returns, or the mark is silently undone. A health check publishes only on an edge, so
    /// nothing would set it again.
    #[tokio::test(start_paused = true)]
    async fn a_health_flag_set_during_the_lookup_survives_the_publish() {
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("svc.internal", vec![ip(1), ip(2)]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "svc.internal",
            DiscoveryType::StrictDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&snapshot).await;

        // During the next lookup the health checker fails .2 (published with
        // `rcu`, as `health_check::apply_health_transition` does), while DNS
        // answers with a new address too.
        let host_set = Arc::clone(&manager.clusters.load().get("dns-svc").unwrap().host_set);
        let failing = SocketAddr::new(ip(2), 80);
        *resolver.during_lookup.lock().unwrap() = Some(Box::new(move || {
            host_set.rcu(|current| {
                let hosts: Vec<Arc<Host>> = current
                    .all_hosts()
                    .into_iter()
                    .map(|h| {
                        if h.address != failing {
                            return h;
                        }
                        Arc::new(Host {
                            address: h.address,
                            hostname: h.hostname.clone(),
                            metadata: h.metadata.clone(),
                            weight: h.weight,
                            priority: h.priority,
                            health_flags: HealthFlags {
                                failed_active_hc: true,
                                failed_outlier_check: false,
                            },
                            active_requests: Default::default(),
                        })
                    })
                    .collect();
                Arc::new(HostSet::from_hosts(hosts))
            });
        }));
        resolver.answer("svc.internal", vec![ip(1), ip(2), ip(3)]);
        tokio::time::sleep(Duration::from_millis(5100)).await;
        *resolver.during_lookup.lock().unwrap() = None;

        let flags: Vec<(String, bool)> = {
            let mut flags: Vec<_> = published(&manager, "dns-svc")
                .all_hosts()
                .iter()
                .map(|h| (h.address.to_string(), h.is_healthy()))
                .collect();
            flags.sort();
            flags
        };
        assert_eq!(
            flags,
            vec![
                ("10.0.0.1:80".to_string(), true),
                ("10.0.0.2:80".to_string(), false),
                ("10.0.0.3:80".to_string(), true),
            ]
        );
    }

    /// Fails the first `failures` lookups, then answers through the platform resolver. Production never gets
    /// injected failures; everything after them is the real thing.
    struct FailsThenResolves {
        failures_left: Mutex<usize>,
        real: crate::resolver::TokioResolver,
    }

    impl HostResolver for FailsThenResolves {
        fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
            let inject = {
                let mut left = self.failures_left.lock().unwrap();
                let inject = *left > 0;
                *left = left.saturating_sub(1);
                inject
            };
            if inject {
                return Box::pin(async { Err(io::Error::other("injected outage")) });
            }
            self.real.resolve(host)
        }
    }

    /// The timer on a real multi-thread runtime, with the real clock and the real `TokioResolver`, not a
    /// scripted resolver on a paused clock: after the first lookups fail, the cluster fills in by itself. The
    /// hostname is a numeric address, which `getaddrinfo` answers without touching the network. The test waits
    /// for the outcome rather than asserting how long it took.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cluster_heals_through_the_platform_resolver_on_a_real_runtime() {
        let resolver = Arc::new(FailsThenResolves {
            failures_left: Mutex::new(2),
            real: crate::resolver::TokioResolver,
        });
        let manager = ClusterManager::with_default_transport(resolver);
        let snapshot = snapshot_of(vec![dns_cluster(
            "dns-svc",
            "127.0.0.1",
            DiscoveryType::StrictDns,
            DnsRefresh {
                refresh_rate: Duration::from_millis(20),
                jitter: Duration::ZERO,
                failure_base_interval: Duration::from_millis(20),
                failure_max_interval: Duration::from_millis(20),
            },
        )]);
        manager.update_from_snapshot(&snapshot).await;
        // The first lookup (in `update_from_snapshot`) was an injected failure.
        assert!(!manager.is_initialized("dns-svc"));

        wait_until(Duration::from_secs(20), || {
            manager.is_initialized("dns-svc")
        })
        .await;
        assert_eq!(live(&manager, &snapshot, "dns-svc"), ["127.0.0.1:80"]);
    }

    // ---------------------------------------------- DNS refresh logging --

    /// Records every tracing event this crate emits: level plus the rendered
    /// message and fields.
    #[derive(Default)]
    struct EventCapture {
        events: Mutex<Vec<(tracing::Level, String)>>,
    }

    impl EventCapture {
        /// The rendered events at `level` that name `cluster`.
        fn rendered(&self, cluster: &str, level: tracing::Level) -> Vec<String> {
            let tag = format!("cluster={cluster} ");
            let events = self.events.lock().unwrap();
            events
                .iter()
                .filter(|(l, text)| *l == level && format!("{text} ").contains(&tag))
                .map(|(_, text)| text.clone())
                .collect()
        }

        fn count(&self, cluster: &str, level: tracing::Level) -> usize {
            self.rendered(cluster, level).len()
        }
    }

    /// Rust note: `tracing::Subscriber` receives every emitted event.
    impl tracing::Subscriber for EventCapture {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if !event.metadata().target().starts_with("proxy_cluster") {
                return;
            }
            struct Render(String);
            impl tracing::field::Visit for Render {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if !self.0.is_empty() {
                        self.0.push(' ');
                    }
                    self.0.push_str(&format!("{}={value:?}", field.name()));
                }
            }
            let mut render = Render(String::new());
            event.record(&mut render);
            self.events
                .lock()
                .unwrap()
                .push((*event.metadata().level(), render.0));
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// The one capture for this test process, installed as the GLOBAL default subscriber the first time a
    /// logging test asks for it. Each logging test uses its own cluster name and reads back only events naming
    /// it.
    ///
    /// Rust note: not `tracing::subscriber::set_default`, which scopes the capture to one thread. `tracing`
    /// caches whether each call site is enabled process-wide, so a call site first reached on a thread with no
    /// subscriber is cached as disabled and the scoped capture never sees it. A global default is every
    /// thread's fallback, so no call site is cached as disabled.
    fn capture() -> Arc<EventCapture> {
        static CAPTURE: std::sync::OnceLock<Arc<EventCapture>> = std::sync::OnceLock::new();
        Arc::clone(CAPTURE.get_or_init(|| {
            let capture = Arc::new(EventCapture::default());
            tracing::subscriber::set_global_default(Arc::clone(&capture))
                .expect("this test binary installs no other global subscriber");
            capture
        }))
    }

    /// 40 failed lookups in a row log six warnings (the 1st, 2nd, 4th, 8th, 16th and 32nd), not forty. Recovery
    /// logs once, and nothing logs after that.
    #[tokio::test(start_paused = true)]
    async fn a_dns_outage_warns_loudly_then_rarely_and_recovery_is_logged_once() {
        use tracing::Level;
        let capture = capture();
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.fail("svc.internal");
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "log-outage",
            "svc.internal",
            DiscoveryType::StrictDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&snapshot).await;
        // Lookups happen at t = 0, 5, ..., 195s: the 40th is the last in range.
        tokio::time::sleep(Duration::from_millis(195_500)).await;
        assert_eq!(resolver.lookups("svc.internal").len(), 40);

        let warnings = capture.rendered("log-outage", Level::WARN);
        assert_eq!(warnings.len(), 6, "{warnings:#?}");
        assert!(
            warnings.iter().any(|w| w.contains("has no hosts")),
            "an outage with nothing to fall back on says so: {warnings:#?}"
        );
        assert_eq!(capture.count("log-outage", Level::INFO), 0);

        resolver.answer("svc.internal", vec![ip(1)]);
        tokio::time::sleep(Duration::from_millis(5100)).await;
        let recovered = capture.rendered("log-outage", Level::INFO);
        assert_eq!(recovered.len(), 1, "recovery, once: {recovered:?}");
        assert!(recovered[0].contains("failed_lookups=40"), "{recovered:?}");

        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(capture.count("log-outage", Level::INFO), 1);
        assert_eq!(
            capture.count("log-outage", Level::WARN),
            6,
            "no repeats once healthy"
        );
    }

    /// With hosts to fall back on, the warning says the last resolved hosts
    /// stay in service.
    #[tokio::test(start_paused = true)]
    async fn an_outage_after_success_warns_that_the_last_hosts_are_kept() {
        use tracing::Level;
        let capture = capture();
        let resolver = Arc::new(ScriptedResolver::default());
        resolver.answer("svc.internal", vec![ip(1), ip(2)]);
        let manager = ClusterManager::with_default_transport(resolver.clone());
        let snapshot = snapshot_of(vec![dns_cluster(
            "log-kept",
            "svc.internal",
            DiscoveryType::StrictDns,
            DnsRefresh::ENVOY_DEFAULT,
        )]);
        manager.update_from_snapshot(&snapshot).await;
        assert_eq!(
            capture.count("log-kept", Level::WARN),
            0,
            "healthy is silent"
        );

        resolver.fail("svc.internal");
        // Three failed lookups (t = 5, 10, 15s): warn on the 1st and 2nd.
        tokio::time::sleep(Duration::from_millis(15_500)).await;
        let warnings = capture.rendered("log-kept", Level::WARN);
        assert_eq!(warnings.len(), 2, "{warnings:#?}");
        for warning in &warnings {
            assert!(
                warning.contains("keeping the last resolved hosts"),
                "{warning}"
            );
            assert!(warning.contains("hosts=2"), "{warning}");
        }
    }
}
