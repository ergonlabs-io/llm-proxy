//! Cluster subsystem: cluster manager & discovery (WP-16), load balancers (WP-17),
//! active health checking (WP-18), outlier detection (WP-19), and upstream
//! connection pools + circuit breakers (WP-15).
//!
//! [`ClusterEntry`] / [`HttpConnPool`] are THE seam between the HTTP lane (router,
//! WP-13) and the cluster lane — changes to these traits require cross-lane review
//! (ground rule #4).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures::future::BoxFuture;

pub mod discovery;
pub mod host_set;
pub mod load_balancer;
pub mod manager;
pub mod pool;
pub mod resolver;

/// Envoy routing priority: selects the circuit-breaker bucket (S5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoutingPriority {
    #[default]
    Default,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProtocol {
    Http1,
    Http2,
}

/// A host's health, as tracked by active health checking. Every host starts
/// (and, until WP-18 lands, stays) `Healthy` -- discovery (WP-16) never
/// itself marks a host unhealthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HealthStatus {
    #[default]
    Healthy,
    // TODO(WP-18): Unhealthy (failing active health checks) and the
    // outlier-detection ejection states (WP-19).
    Unhealthy,
}

/// An upstream endpoint. Host sets are built on the control runtime (WP-16) and
/// shared with workers as immutable snapshots.
#[derive(Debug)]
pub struct Host {
    pub address: SocketAddr,
    pub weight: u32,
    /// Failover priority this host belongs to; 0 = primary (S5/S7).
    pub priority: u32,
    /// TODO(WP-18): flips to `Unhealthy` on failed active health checks;
    /// TODO(WP-19): outlier-detection ejection state.
    pub health: HealthStatus,
    /// In-flight request count, read by `LEAST_REQUEST`'s power-of-two-choices
    /// pick (WP-17, S7). TODO(WP-15/WP-13): the connection pool and router
    /// are what actually `fetch_add`/`fetch_sub` this as requests start and
    /// finish; until those land it stays 0 for every host, which just makes
    /// `LEAST_REQUEST` degrade to uniform random.
    pub active_requests: AtomicU64,
    // TODO(WP-16+): locality, metadata.
}

impl Host {
    /// Current in-flight request count (see [`Host::active_requests`]).
    ///
    /// Rust note: `Relaxed` is enough here -- this counter has no other
    /// memory it needs to be ordered with (we're not using it to publish or
    /// guard access to anything else), it's just a number LB picks read.
    pub fn active_request_count(&self) -> u64 {
        self.active_requests.load(Ordering::Relaxed)
    }

    /// Test seam for [`crate::load_balancer`]'s `LEAST_REQUEST` tests: set
    /// the counter directly instead of going through fetch_add/fetch_sub
    /// (which is what real callers, once WP-15/WP-13 land, will use).
    #[cfg(test)]
    pub(crate) fn set_active_requests_for_test(&self, n: u64) {
        self.active_requests.store(n, Ordering::Relaxed);
    }
}

/// Per-request input to host selection (S7).
#[derive(Debug, Default)]
pub struct LoadBalancerContext {
    /// Result of the route's `hash_policy` chain, if any (ring hash / Maglev).
    pub hash: Option<u64>,
    /// Host override from an endpoint picker (`x-gateway-destination-endpoint`, WP-36).
    pub host_override: Option<SocketAddr>,
}

/// Circuit-breaker accounting for one (cluster, priority) — S5 semantics/defaults.
/// TODO(WP-15): counters/gauges with Envoy stat names, `track_remaining`.
#[derive(Debug, Default)]
pub struct CircuitBreakerState {}

/// A stream slot on a pooled upstream connection. v1 ([`pool::Http1ConnectPool`])
/// is connect-per-stream: this just carries a freshly-dialed transport, no
/// pooling/reuse yet.
pub struct UpstreamStream {
    /// The connected upstream transport. v1 (no reuse): a freshly-dialed
    /// plaintext TCP connection, one per stream. The router runs the
    /// upstream h1 codec over it.
    pub io: tokio::net::TcpStream,
    // TODO(WP-15): release-on-drop pool guard + `active_requests` dec, and
    // (for keep-alive reuse) hold the codec `SendRequest` handle rather than
    // a raw transport -- at which point this seam changes shape.
}

/// Pool failures are distinct variants because the retry engine (S3 trigger
/// mapping), response flags, and stats all depend on which one occurred.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// Circuit breaker / pending queue overflow -> 503 + `UO` + `x-envoy-overloaded`.
    #[error("pool overflow (circuit breaker)")]
    Overflow,
    /// TCP/TLS connect failure -> retriable under `connect-failure` (S3.2).
    #[error("upstream connect failure: {0}")]
    ConnectFailure(std::io::Error),
    /// `connect_timeout` elapsed -> retriable under `connect-failure` (S3.2).
    #[error("upstream connect timeout")]
    ConnectTimeout,
    /// Connection died before response headers -> retriable under `reset` (S3.2).
    #[error("upstream reset before response headers")]
    ResetBeforeHeaders,
}

/// Per-worker, per-host, per-protocol connection pool (WP-15).
pub trait HttpConnPool: Send + Sync {
    /// Resolves when a stream slot is available (may open a new connection,
    /// subject to circuit breakers).
    fn new_stream(&self) -> BoxFuture<'static, Result<UpstreamStream, PoolError>>;
}

/// What the router (WP-13) sees of a cluster.
pub trait ClusterEntry: Send + Sync {
    /// Load-balancer host pick (S7: policy, panic threshold, priority spillover).
    fn pick_host(&self, ctx: &LoadBalancerContext) -> Option<Arc<Host>>;

    /// The pool for a picked host.
    fn http_pool(&self, host: &Arc<Host>, proto: UpstreamProtocol) -> Arc<dyn HttpConnPool>;

    /// Circuit-breaker bucket for the request's priority (S5).
    fn circuit_breaker(&self, prio: RoutingPriority) -> &CircuitBreakerState;
}
