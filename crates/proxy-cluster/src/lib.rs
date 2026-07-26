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
pub mod transport;

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

// Rust note: the config IR carries its own `UpstreamProtocol` (protos stay in
// `proxy-config`; the data plane consumes the IR). This `From` is the one place
// that bridges the two, so cluster-build code maps config → runtime once and
// stays decoupled from the IR enum's identity.
impl From<proxy_config::ir::UpstreamProtocol> for UpstreamProtocol {
    fn from(proto: proxy_config::ir::UpstreamProtocol) -> Self {
        match proto {
            proxy_config::ir::UpstreamProtocol::Http1 => UpstreamProtocol::Http1,
            proxy_config::ir::UpstreamProtocol::Http2 => UpstreamProtocol::Http2,
        }
    }
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
    /// The DNS name this host was resolved from (`STRICT_DNS`/`LOGICAL_DNS`),
    /// or `None` for `STATIC` clusters whose endpoints are literal IPs.
    ///
    /// This is what upstream TLS uses as the SNI / certificate-verification
    /// name when the cluster's `transport_socket` doesn't override it with an
    /// explicit `sni`: by the time a host exists, `address` is an IP, and no
    /// public CA issues certificates for IP addresses. Envoy keeps the same
    /// thing on its own `Host` (`hostname()`), for the same reason.
    pub hostname: Option<String>,
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

/// Circuit-breaker accounting for one (cluster, priority) — S5's four
/// per-priority budgets. Only `max_requests` is checked at a call site today
/// (the router, WP-13/WP-15 thin slice); the other three keep real
/// counters/guards so wiring them up later is additive, not a redesign.
///
/// Rust note: the gauges live behind `Arc<AtomicU32>` rather than borrowed --
/// [`CbGuard`] rides inside a streaming response body that must outlive the
/// handler stack frame that acquired it, so it can't hold a borrow of
/// `self`.
#[derive(Debug, Clone)]
pub struct CircuitBreakerState {
    connections: BudgetHandle,
    pending: BudgetHandle,
    requests: BudgetHandle,
    retries: BudgetHandle,
}

/// A budget's live gauge plus its limit, with the gauge pre-wrapped in `Arc`
/// so a guard can clone just the atomic out without holding the whole
/// `CircuitBreakerState` alive.
#[derive(Debug, Clone)]
struct BudgetHandle {
    active: Arc<std::sync::atomic::AtomicU32>,
    limit: u32,
}

impl BudgetHandle {
    fn new(limit: u32) -> Self {
        Self {
            active: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            limit,
        }
    }

    /// Optimistic increment-then-check-then-rollback: claim a slot first,
    /// and only give it back if that claim turned out to overflow the
    /// limit. This avoids a check-then-act race between two threads racing
    /// the same budget (both could pass a `load` check before either
    /// increments) at the cost of a harmless bounce off the limit under
    /// contention.
    ///
    /// Rust note: the claiming `fetch_add` uses `Acquire` so a prior
    /// release (another guard's `Drop`, below) is visible before we decide
    /// whether we're over budget; the rollback `fetch_sub` uses `Release`
    /// so a losing thread's "give the slot back" is visible to whoever
    /// reads `active` next. A successful acquire doesn't need to *release*
    /// anything itself -- the guard's `Drop` is the operation other threads
    /// need to observe, and that already uses `Release`.
    fn try_acquire(&self) -> Option<CbGuard> {
        let prev = self
            .active
            .fetch_add(1, std::sync::atomic::Ordering::Acquire);
        if prev >= self.limit {
            self.active
                .fetch_sub(1, std::sync::atomic::Ordering::Release);
            return None;
        }
        Some(CbGuard {
            active: Arc::clone(&self.active),
        })
    }
}

/// An acquired S5 budget slot. Owns a clone of the budget's gauge (not a
/// borrow), so it's `'static` and can be moved into a response body that
/// outlives the request handler; dropping it releases the slot.
#[derive(Debug)]
pub struct CbGuard {
    active: Arc<std::sync::atomic::AtomicU32>,
}

impl Drop for CbGuard {
    fn drop(&mut self) {
        self.active
            .fetch_sub(1, std::sync::atomic::Ordering::Release);
    }
}

impl CircuitBreakerState {
    /// Builds all four budgets from a cluster's lowered [`CircuitBreakerThresholds`].
    pub fn from_thresholds(t: proxy_config::ir::CircuitBreakerThresholds) -> Self {
        Self {
            connections: BudgetHandle::new(t.max_connections),
            pending: BudgetHandle::new(t.max_pending_requests),
            requests: BudgetHandle::new(t.max_requests),
            retries: BudgetHandle::new(t.max_retries),
        }
    }

    /// The one budget wired to a real call site today: the router acquires
    /// this before dialing/forwarding and holds it for the full response
    /// stream (LLM streaming keeps a request "active" far longer than
    /// time-to-headers).
    pub fn try_acquire_request(&self) -> Option<CbGuard> {
        self.requests.try_acquire()
    }

    // TODO(WP-15 pooling): check max_connections in the pool on dial.
    #[allow(dead_code)]
    pub fn try_acquire_connection(&self) -> Option<CbGuard> {
        self.connections.try_acquire()
    }

    // TODO: max_pending_requests engages once there's a real pending queue (WP-15).
    #[allow(dead_code)]
    pub fn try_acquire_pending(&self) -> Option<CbGuard> {
        self.pending.try_acquire()
    }

    // TODO(WP-14 retries): check max_retries in the retry engine.
    #[allow(dead_code)]
    pub fn try_acquire_retry(&self) -> Option<CbGuard> {
        self.retries.try_acquire()
    }
}

impl Default for CircuitBreakerState {
    /// Used where no cluster config is available yet (e.g. `manager::eds()`,
    /// which has no `ClusterConfig` to read thresholds from).
    fn default() -> Self {
        Self::from_thresholds(proxy_config::ir::CircuitBreakerThresholds::ENVOY_DEFAULT)
    }
}

/// A stream slot on a pooled upstream connection. v1 ([`pool::ConnectPool`])
/// is connect-per-stream: this just carries a freshly-dialed transport, no
/// pooling/reuse yet.
pub struct UpstreamStream {
    /// The connected upstream transport: a freshly-dialed TCP connection,
    /// already wrapped by the cluster's [`transport::UpstreamTransportSocket`]
    /// (plaintext passthrough, or a completed TLS handshake). The router runs
    /// the upstream h1/h2 codec over it, and both codecs are generic over
    /// `AsyncRead + AsyncWrite + Unpin`, so they don't care which it is.
    pub io: BoxedUpstreamIo,
    // TODO(WP-15): release-on-drop pool guard + `active_requests` dec, and
    // (for keep-alive reuse) hold the codec `SendRequest` handle rather than
    // a raw transport -- at which point this seam changes shape.
}

/// The byte transport under an upstream HTTP stream, type-erased so a cluster
/// can be plaintext or TLS without every consumer becoming generic over the
/// transport.
///
/// Rust note: this is the standard "trait alias by blanket impl" idiom --
/// `dyn AsyncRead + AsyncWrite + Unpin` is not a legal trait object (only one
/// non-auto trait per object), so we declare a single trait with the three as
/// supertraits and blanket-impl it for everything that qualifies.
pub trait UpstreamIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static {}

impl<T> UpstreamIo for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static {}

/// A boxed [`UpstreamIo`]. `Box<T>` itself implements `AsyncRead`/`AsyncWrite`
/// (tokio provides those forwarding impls for `Box<T: ?Sized>`), so the box is
/// directly usable as codec IO -- no manual projection needed.
pub type BoxedUpstreamIo = Box<dyn UpstreamIo>;

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
    /// The TCP connect succeeded but the transport socket's handshake failed
    /// (TLS: bad certificate, no shared ALPN protocol, protocol version
    /// mismatch...). Envoy folds this into the same `UF`/`connect-failure`
    /// bucket as a TCP failure; it is a separate variant here so the log line
    /// says which half actually broke.
    #[error("upstream TLS handshake failed: {0}")]
    TlsHandshake(std::io::Error),
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

    /// Which HTTP protocol the router must speak to this cluster's upstreams,
    /// from the cluster's `upstream_protocol` config (Envoy default HTTP/1.1).
    /// The router reads this to pick both the pool and the upstream codec.
    fn upstream_protocol(&self) -> UpstreamProtocol;

    /// Circuit-breaker bucket for the request's priority (S5).
    fn circuit_breaker(&self, prio: RoutingPriority) -> &CircuitBreakerState;
}

#[cfg(test)]
mod cb_tests {
    use super::*;

    fn thresholds(max_requests: u32) -> proxy_config::ir::CircuitBreakerThresholds {
        proxy_config::ir::CircuitBreakerThresholds {
            max_requests,
            ..proxy_config::ir::CircuitBreakerThresholds::ENVOY_DEFAULT
        }
    }

    #[test]
    fn max_requests_sheds_load_past_the_limit() {
        let cb = CircuitBreakerState::from_thresholds(thresholds(2));
        let g1 = cb.try_acquire_request().expect("1st acquire under budget");
        let g2 = cb.try_acquire_request().expect("2nd acquire under budget");
        assert!(
            cb.try_acquire_request().is_none(),
            "3rd acquire must be shed (limit is 2)"
        );
        drop(g1);
        drop(g2);
    }

    #[test]
    fn dropping_a_guard_frees_a_slot() {
        let cb = CircuitBreakerState::from_thresholds(thresholds(1));
        let g1 = cb.try_acquire_request().expect("1st acquire under budget");
        assert!(cb.try_acquire_request().is_none(), "budget is exhausted");
        drop(g1);
        let g2 = cb
            .try_acquire_request()
            .expect("acquire must succeed again after the guard freed a slot");
        drop(g2);
    }

    #[test]
    fn guards_decrement_active_on_drop() {
        let cb = CircuitBreakerState::from_thresholds(thresholds(2));
        let g1 = cb.try_acquire_request().expect("acquire 1");
        let g2 = cb.try_acquire_request().expect("acquire 2");
        drop(g1);
        drop(g2);
        // Rust note: `requests.active` is private, so we prove "back to
        // zero" behaviorally -- re-acquiring up to the full limit must
        // succeed again, which is only possible if both prior guards
        // actually released their slots.
        let g3 = cb
            .try_acquire_request()
            .expect("full budget available again");
        let g4 = cb
            .try_acquire_request()
            .expect("full budget available again");
        assert!(cb.try_acquire_request().is_none());
        drop(g3);
        drop(g4);
    }
}
