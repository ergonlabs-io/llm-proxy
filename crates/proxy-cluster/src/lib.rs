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
use proxy_config::ir::ClusterName;

pub mod discovery;
pub mod health_check;
pub mod host_set;
pub mod load_balancer;
pub mod manager;
pub mod outlier;
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

/// A host's *derived* health, as a simple two-state view. This is what
/// [`health_check::HealthCheckEngine`]'s internal consecutive-count tracker
/// uses (it only ever cares "did active HC just flip me") and what callers
/// get back from [`HealthFlags::status`]. It is deliberately not the type
/// stored on [`Host`] any more -- see [`HealthFlags`] for why a host needs
/// two independent axes, not one enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HealthStatus {
    #[default]
    Healthy,
    Unhealthy,
}

/// A host's health as two independent axes, matching Envoy's own
/// `Host::HealthFlag` bitset model: active health checking (WP-18) and
/// outlier detection (WP-19) each fail/clear a host *independently* --  a
/// host can be ejected by the outlier detector while still passing its
/// active health check (or vice versa), and either one alone is enough to
/// make the host unusable for new traffic.
///
/// Rust note: this used to be the single two-state `HealthStatus` enum
/// directly on `Host`. A `struct` of two `bool`s (rather than a 4-variant
/// enum) is the right shape here because the two axes are genuinely
/// independent and owned by two different subsystems -- `health_check.rs`
/// only ever touches `failed_active_hc`, `outlier.rs` only ever touches
/// `failed_outlier_check`, and neither has to know the other's bit exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HealthFlags {
    /// Set by [`health_check::HealthCheckEngine`] on a failed consecutive-
    /// threshold run of active health checks; cleared on a passing run.
    pub failed_active_hc: bool,
    /// Set by [`outlier::OutlierDetector`] when a host is ejected; cleared
    /// when its ejection expires, an active health check passes (if
    /// configured to do so), or it's manually un-ejected.
    pub failed_outlier_check: bool,
}

impl HealthFlags {
    /// A host is usable for new traffic only when *no* flag is set --
    /// matching Envoy's `Host::healthy()`, which is `!healthFlagsGet(...)`
    /// across every flag it tracks.
    pub fn is_healthy(&self) -> bool {
        !self.failed_active_hc && !self.failed_outlier_check
    }

    /// The derived two-state view some older call sites still want (e.g.
    /// [`health_check::ConsecutiveTracker`]'s own bookkeeping, which only
    /// ever sees its own axis and has no use for the finer-grained struct).
    pub fn status(&self) -> HealthStatus {
        if self.is_healthy() {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        }
    }
}

impl std::fmt::Display for HealthFlags {
    /// Envoy-compatible rendering for the admin endpoint (WP-25) and the
    /// diff rig: `""` when healthy, else each failing flag's
    /// `/failed_active_hc`/`/failed_outlier_check` token concatenated in
    /// that fixed order (Envoy always lists `FAILED_ACTIVE_HC` before
    /// `FAILED_OUTLIER_CHECK` in its own health-flag enum ordering).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.failed_active_hc {
            write!(f, "/failed_active_hc")?;
        }
        if self.failed_outlier_check {
            write!(f, "/failed_outlier_check")?;
        }
        Ok(())
    }
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
    /// Active-health-check state (WP-18) and outlier-ejection state
    /// (WP-19), tracked independently -- see [`HealthFlags`].
    pub health_flags: HealthFlags,
    /// In-flight request count, read by `LEAST_REQUEST`'s power-of-two-choices
    /// pick (WP-17, S7). TODO(WP-15/WP-13): the connection pool and router
    /// are what actually `fetch_add`/`fetch_sub` this as requests start and
    /// finish; until those land it stays 0 for every host, which just makes
    /// `LEAST_REQUEST` degrade to uniform random.
    pub active_requests: AtomicU64,
    // TODO(WP-16+): locality, metadata.
}

impl Host {
    /// Usable for new traffic -- no health flag set. Load balancers (S7)
    /// and priority spillover both read this rather than comparing
    /// `health_flags` to a specific variant, so a third flag (should one
    /// ever get added) doesn't require touching every call site.
    pub fn is_healthy(&self) -> bool {
        self.health_flags.is_healthy()
    }

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
    /// Cluster names an earlier attempt of this same request already dialed
    /// (WP-35). An aggregate skips these when choosing a member, so a retry
    /// falls over to the next provider instead of re-picking the one that
    /// just failed. Empty on the first attempt; ignored by non-aggregate
    /// clusters, which have no members to skip among.
    ///
    /// Rust note: a plain `Vec`, not a `HashSet` -- member lists and retry
    /// counts are both single digits, so a linear scan is cheaper than
    /// hashing, and there's no risk of the list growing large enough for
    /// that to matter.
    pub attempted_clusters: Vec<ClusterName>,
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

    /// The `max_connections` budget: acquired in [`pool::ConnectPool::new_stream`]
    /// before dialing (so an over-budget cluster never opens the socket), and
    /// held for the life of the physical connection -- see
    /// [`UpstreamStream::cb_guard`].
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
    /// The S5 `max_connections` slot this physical connection holds (see
    /// [`CircuitBreakerState::try_acquire_connection`]). Dropping it releases
    /// the slot, so it must live exactly as long as `io`'s underlying
    /// connection does -- for h1 (connect-per-stream) that's this struct's
    /// own lifetime; for the h2 cache (`proxy-http`'s `UpstreamConnCache`)
    /// the caller moves it into the cached connection's own entry so it
    /// outlives this `UpstreamStream`, not the other way round.
    ///
    /// `None` only on paths with no real budget to acquire against (test
    /// helpers, or a caller that never runs `new_stream` through a
    /// `ConnectPool`) -- every real dial sets it.
    pub cb_guard: Option<CbGuard>,
    // TODO(WP-15): (for keep-alive reuse on the h1 path) hold the codec
    // `SendRequest` handle rather than a raw transport -- at which point
    // this seam changes shape. The pool-guard half of this TODO is done.
}

/// The byte transport under an upstream HTTP stream, type-erased so a cluster
/// can be plaintext or TLS without every consumer becoming generic over the
/// transport.
///
/// Rust note: this is the standard "trait alias by blanket impl" idiom --
/// `dyn AsyncRead + AsyncWrite + Unpin` is not a legal trait object (only one
/// non-auto trait per object), so we declare a single trait with the three as
/// supertraits and blanket-impl it for everything that qualifies.
// Rust note: `Send` (WP-10 S10 increment 2b) is required by hyper's low-level
// CLIENT upgrade API (`http1::Connection::with_upgrades`), symmetric to
// increment 2a adding it to the downstream `serve_http1`. It is a pure
// bound-widening, not an ADR-0003 breach: `UpstreamTransportSocket::wrap` only
// ever boxes a `TcpStream` or a rustls-wrapped `TcpStream` (both already
// `Send`), and ADR-0003's `!Send` rule governs handler/body/filter STATE (the
// `StreamBody`, `Rc`/`RefCell` data-plane state), not the raw upstream byte
// stream. Making the stream `Send` only ALLOWS thread-hopping; the workers
// still run on per-worker current_thread runtimes.
pub trait UpstreamIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {}

impl<T> UpstreamIo for T where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static
{
}

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

/// One attempt's host selection: the picked host, plus (WP-35) the cluster
/// that actually owns it.
#[derive(Debug)]
pub struct HostSelection {
    pub host: Arc<Host>,
    /// Set **only** when the entry that made the pick is an aggregate: the
    /// member cluster the host actually belongs to. `None` means the entry
    /// the caller already holds owns the host -- true for every
    /// non-aggregate cluster -- so the common path allocates nothing.
    ///
    /// The owning cluster, not the routed one, is what supplies the
    /// transport socket, the upstream protocol, and (WP-35) the provider
    /// credentials. A caller that ignores this field sends the aggregate's
    /// (empty) credentials to a real provider.
    pub member: Option<SelectedMember>,
}

/// The member cluster [`ClusterEntry::select_host`] actually resolved a host
/// against, when the entry making the pick was an aggregate.
#[derive(Clone)]
pub struct SelectedMember {
    pub name: ClusterName,
    pub entry: Arc<dyn ClusterEntry>,
}

impl std::fmt::Debug for SelectedMember {
    // Rust note: `dyn ClusterEntry` has no `Debug` bound (adding one would
    // ripple through every implementor for a field only ever inspected in
    // tests/logs), so this writes the one field that actually identifies the
    // member instead of deriving.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedMember")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// What the router (WP-13) sees of a cluster.
pub trait ClusterEntry: Send + Sync {
    /// Load-balancer host pick (S7: policy, panic threshold, priority
    /// spillover), plus the cluster that owns the picked host (WP-35: an
    /// aggregate's members are different providers with different
    /// credentials, so "which cluster owns this host" is no longer always
    /// the entry the caller already holds).
    ///
    /// This is the *only* way to get a host out of a `ClusterEntry` --
    /// there is exactly one implementation and two call sites, both updated
    /// alongside this trait, so there is no reason to keep an old
    /// `pick_host` around next to it. A second way to get a host that
    /// silently drops the owner is a way to send provider A's API key to
    /// provider B (ground rule #1: dropping that information is exactly the
    /// class of silent config error the rule exists to prevent, even though
    /// no proto field is involved here).
    fn select_host(&self, ctx: &LoadBalancerContext) -> Option<HostSelection>;

    /// The pool for a picked host.
    fn http_pool(&self, host: &Arc<Host>, proto: UpstreamProtocol) -> Arc<dyn HttpConnPool>;

    /// Which HTTP protocol the router must speak to this cluster's upstreams,
    /// from the cluster's `upstream_protocol` config (Envoy default HTTP/1.1).
    /// The router reads this to pick both the pool and the upstream codec.
    fn upstream_protocol(&self) -> UpstreamProtocol;

    /// Circuit-breaker bucket for the request's priority (S5).
    fn circuit_breaker(&self, prio: RoutingPriority) -> &CircuitBreakerState;

    /// Request header mutations to apply because this cluster was the one the
    /// attempt dialed. Carries provider credentials under the `llmproxy`
    /// dialect -- see `ClusterConfig::request_headers_to_add`.
    fn request_headers_to_add(&self) -> &[proxy_config::ir::HeaderMutation];

    /// Feed one upstream attempt's outcome to this cluster's S6 outlier
    /// detector (WP-19). `addr` is the host the attempt actually dialed. A
    /// no-op when the cluster configures no outlier detection, so the router
    /// can call it unconditionally after every attempt. Takes `&self` (not
    /// `&mut`) because the detector owns its own interior locking -- the
    /// router holds only a shared `&dyn ClusterEntry`.
    fn report_outlier_result(&self, addr: std::net::SocketAddr, result: outlier::RequestResult);
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
