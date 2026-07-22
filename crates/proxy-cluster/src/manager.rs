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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use proxy_config::ir::{ClusterConfig, ClusterName, EndpointIR};

use crate::discovery;
use crate::host_set::{diff_host_sets, HostSet, HostSetDiff};
use crate::resolver::HostResolver;
use crate::{
    CircuitBreakerState, ClusterEntry, HealthStatus, Host, HttpConnPool, LoadBalancerContext,
    RoutingPriority, UpstreamProtocol,
};

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
/// runtime; readers (`pick_host`) only ever `load`.
struct ManagedCluster {
    source: ClusterSource,
    host_set: ArcSwap<HostSet>,
    /// Flips to `true` once the cluster's first resolution (or, for EDS, its
    /// first externally-supplied set) has landed.
    initialized: AtomicBool,
    /// Round-robin cursor for `pick_host`. TODO(WP-17): replace with the
    /// configured `lb_policy` (round-robin/least-request/ring-hash/random/
    /// Maglev); v1 always round-robins priority 0's healthy hosts.
    rr_cursor: AtomicUsize,
    /// TODO(WP-15): real circuit-breaker accounting/stats; these are just
    /// the buckets `ClusterEntry::circuit_breaker` hands back.
    default_cb: CircuitBreakerState,
    high_cb: CircuitBreakerState,
}

impl ManagedCluster {
    fn from_config(config: Arc<ClusterConfig>) -> Self {
        Self {
            source: ClusterSource::Config(config),
            host_set: ArcSwap::from_pointee(HostSet::default()),
            initialized: AtomicBool::new(false),
            rr_cursor: AtomicUsize::new(0),
            default_cb: CircuitBreakerState::default(),
            high_cb: CircuitBreakerState::default(),
        }
    }

    fn eds() -> Self {
        Self {
            source: ClusterSource::Eds,
            host_set: ArcSwap::from_pointee(HostSet::default()),
            initialized: AtomicBool::new(false),
            rr_cursor: AtomicUsize::new(0),
            default_cb: CircuitBreakerState::default(),
            high_cb: CircuitBreakerState::default(),
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
    clusters: ArcSwap<HashMap<ClusterName, Arc<ManagedCluster>>>,
    resolver: Arc<dyn HostResolver>,
}

impl ClusterManager {
    pub fn new(resolver: Arc<dyn HostResolver>) -> Self {
        Self {
            clusters: ArcSwap::from_pointee(HashMap::new()),
            resolver,
        }
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
    pub async fn update_from_snapshot(&self, clusters: &HashMap<ClusterName, Arc<ClusterConfig>>) {
        let previous = self.clusters.load_full();
        let mut next: HashMap<ClusterName, Arc<ManagedCluster>> =
            HashMap::with_capacity(clusters.len());
        for (name, config) in clusters {
            next.insert(
                name.clone(),
                Arc::new(ManagedCluster::from_config(Arc::clone(config))),
            );
        }
        for (name, managed) in previous.iter() {
            if matches!(managed.source, ClusterSource::Eds) {
                next.entry(name.clone())
                    .or_insert_with(|| Arc::clone(managed));
            }
        }
        self.clusters.store(Arc::new(next));

        for name in clusters.keys() {
            if let Err(err) = self.refresh_cluster(name).await {
                // Rust note: a discovery failure doesn't take the cluster
                // manager down -- Envoy keeps serving the last-known-good
                // (here: empty, since this is the first resolution) host set
                // and logs. Real retry/backoff on DNS failure is a future
                // refinement, not part of this WP.
                tracing::warn!(cluster = %name, error = %err, "initial cluster discovery failed");
            }
        }
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
        let diff = diff_host_sets(&managed.host_set.load(), &new_set);
        managed.host_set.store(Arc::new(new_set));
        managed.initialized.store(true, Ordering::Release);
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
            ClusterSource::Config(config) => config,
        };
        let new_set = discovery::resolve(config, self.resolver.as_ref()).await?;
        let diff = diff_host_sets(&managed.host_set.load(), &new_set);
        managed.host_set.store(Arc::new(new_set));
        managed.initialized.store(true, Ordering::Release);
        Ok(diff)
    }

    /// The router-facing handle for a cluster, or `None` if no cluster with
    /// that name is currently known.
    pub fn cluster(&self, name: &str) -> Option<Arc<dyn ClusterEntry>> {
        self.clusters
            .load()
            .get(name)
            .cloned()
            .map(|managed| Arc::new(ClusterHandle(managed)) as Arc<dyn ClusterEntry>)
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
/// Cheap to clone -- it's just an `Arc` to the manager's internal state.
struct ClusterHandle(Arc<ManagedCluster>);

impl ClusterEntry for ClusterHandle {
    fn pick_host(&self, _ctx: &LoadBalancerContext) -> Option<Arc<Host>> {
        // TODO(WP-17): real load balancing -- configured `lb_policy`, panic
        // threshold, priority spillover, and honoring `ctx` (hash/host
        // override). v1 round-robins priority 0's healthy hosts only.
        let host_set = self.0.host_set.load();
        let healthy: Vec<&Arc<Host>> = host_set
            .hosts_for_priority(0)
            .iter()
            .filter(|h| h.health == HealthStatus::Healthy)
            .collect();
        if healthy.is_empty() {
            return None;
        }
        let idx = self.0.rr_cursor.fetch_add(1, Ordering::Relaxed) % healthy.len();
        Some(Arc::clone(healthy[idx]))
    }

    fn http_pool(&self, _host: &Arc<Host>, _proto: UpstreamProtocol) -> Arc<dyn HttpConnPool> {
        // TODO(WP-15): upstream connection pools + circuit breakers. Nothing
        // in WP-16's scope calls this yet.
        unimplemented!("upstream connection pools land in WP-15")
    }

    fn circuit_breaker(&self, prio: RoutingPriority) -> &CircuitBreakerState {
        match prio {
            RoutingPriority::Default => &self.0.default_cb,
            RoutingPriority::High => &self.0.high_cb,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::FakeResolver;
    use proxy_config::ir::{DiscoveryType, LbPolicy};
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    fn cluster_config(
        name: &str,
        discovery: DiscoveryType,
        endpoints: Vec<EndpointIR>,
    ) -> Arc<ClusterConfig> {
        Arc::new(ClusterConfig {
            name: name.to_string(),
            discovery,
            lb_policy: LbPolicy::RoundRobin,
            connect_timeout: Duration::from_secs(5),
            endpoints,
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1 << 20,
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

    #[tokio::test]
    async fn static_cluster_becomes_available_and_initialized() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::new(resolver);
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
        let manager = ClusterManager::new(resolver);
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
        let manager = ClusterManager::new(resolver.clone());
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
        let manager = ClusterManager::new(resolver);
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
        let manager = ClusterManager::new(resolver);
        manager.add_eds_cluster("never-fed".to_string());
        assert!(!manager.is_initialized("never-fed"));
        manager.force_initialize("never-fed");
        assert!(manager.is_initialized("never-fed"));
    }

    #[tokio::test]
    async fn pick_host_round_robins_priority_zero() {
        let resolver = Arc::new(FakeResolver::new());
        let manager = ClusterManager::new(resolver);
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
            seen.insert(entry.pick_host(&ctx).unwrap().address);
        }
        assert_eq!(seen.len(), 2);
    }
}
