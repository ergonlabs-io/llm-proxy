//! Cluster subsystem: cluster manager & discovery (WP-16), load balancers (WP-17),
//! active health checking (WP-18), outlier detection (WP-19), and upstream
//! connection pools + circuit breakers (WP-15).
//!
//! [`ClusterEntry`] / [`HttpConnPool`] are THE seam between the HTTP lane (router,
//! WP-13) and the cluster lane — changes to these traits require cross-lane review
//! (ground rule #4).

use std::net::SocketAddr;
use std::sync::Arc;

use futures::future::BoxFuture;

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

/// An upstream endpoint. Host sets are built on the control runtime (WP-16) and
/// shared with workers as immutable snapshots.
#[derive(Debug)]
pub struct Host {
    pub address: SocketAddr,
    pub weight: u32,
    // TODO(WP-16): locality, metadata, health status, outlier ejection state.
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

/// A stream slot on a pooled upstream connection. TODO(WP-15): wraps the codec
/// send-request handle plus pool bookkeeping (release-on-drop).
pub struct UpstreamStream {}

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
