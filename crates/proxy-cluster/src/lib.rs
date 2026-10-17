//! Cluster subsystem: cluster manager and discovery, load balancers, active health checking, outlier
//! detection, and upstream connection pools with circuit breakers.
//!
//! [`ClusterEntry`] and [`HttpConnPool`] are the seam between the HTTP router and this subsystem. Changes to
//! these traits need review from both sides (AGENTS.md invariant 8).

use std::collections::BTreeMap;
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

// Rust note: the IR carries its own `UpstreamProtocol` (protos stay in `proxy-config`). This `From` is the one
// bridge between the two, so cluster-build code maps config to runtime once.
impl From<proxy_config::ir::UpstreamProtocol> for UpstreamProtocol {
    fn from(proto: proxy_config::ir::UpstreamProtocol) -> Self {
        match proto {
            proxy_config::ir::UpstreamProtocol::Http1 => UpstreamProtocol::Http1,
            proxy_config::ir::UpstreamProtocol::Http2 => UpstreamProtocol::Http2,
        }
    }
}

/// A two-state health view, used by [`health_check::HealthCheckEngine`]'s consecutive-count tracker. It is not
/// the type stored on [`Host`]: a host needs two independent axes (see [`HealthFlags`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HealthStatus {
    #[default]
    Healthy,
    Unhealthy,
}

/// A host's health as two independent axes, matching Envoy's `Host::HealthFlag` bitset. Active health checking
/// and outlier detection each set and clear their own flag, so either one alone makes the host unusable for new
/// traffic.
///
/// Rust note: two `bool`s rather than a 4-variant enum, because the axes are independent and owned by different
/// subsystems. `health_check.rs` only touches `failed_active_hc`, and `outlier.rs` only touches
/// `failed_outlier_check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HealthFlags {
    /// Set by [`health_check::HealthCheckEngine`] on a failed consecutive-
    /// threshold run of active health checks; cleared on a passing run.
    pub failed_active_hc: bool,
    /// Set by [`outlier::OutlierDetector`] on ejection. Cleared when the ejection expires, when an active health
    /// check passes (if configured to), or on manual un-ejection.
    pub failed_outlier_check: bool,
}

impl HealthFlags {
    /// Usable for new traffic only when no flag is set (Envoy's `Host::healthy()`).
    pub fn is_healthy(&self) -> bool {
        !self.failed_active_hc && !self.failed_outlier_check
    }
}

impl std::fmt::Display for HealthFlags {
    /// Envoy-compatible rendering for the admin endpoint and the diff rig: `""` when healthy, else each failing
    /// flag's token (`/failed_active_hc`, `/failed_outlier_check`) in Envoy's fixed order.
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

/// An upstream endpoint. Host sets are built on the control runtime and
/// shared with workers as immutable snapshots.
#[derive(Debug)]
pub struct Host {
    pub address: SocketAddr,
    /// The DNS name this host was resolved from (`STRICT_DNS`/`LOGICAL_DNS`), or `None` for literal-IP `STATIC`
    /// endpoints. Upstream TLS uses it as the SNI and verification name unless `sni` overrides it. By the time a
    /// host exists `address` is an IP, and no public CA issues certificates for IPs. Envoy keeps the same value
    /// on its `Host` (`hostname()`).
    pub hostname: Option<String>,
    /// Operator-facing endpoint labels, copied from the `io.llmproxy.endpoint` metadata namespace. They live with
    /// the live host, not in config, because EDS can deliver the set and `/clusters` must describe what traffic
    /// can select.
    pub metadata: BTreeMap<String, String>,
    pub weight: u32,
    /// Failover priority this host belongs to; 0 = primary (S5/S7).
    pub priority: u32,
    /// Active-health-check state and outlier-ejection state, tracked
    /// independently -- see [`HealthFlags`].
    pub health_flags: HealthFlags,
    /// In-flight request count, read by `LEAST_REQUEST`'s power-of-two-choices pick (S7). The router takes an
    /// [`ActiveRequestGuard`] from [`Host::begin_request`] per upstream attempt and holds it until the response
    /// body completes or drops.
    ///
    /// Rust note: an `Arc`, because health checks, outlier detection, and discovery rebuild `Host` snapshots.
    /// Every rebuild of the same endpoint clones this `Arc`, so a guard taken on an old snapshot still decrements
    /// the counter the new one reads.
    pub active_requests: Arc<AtomicU64>,
    // TODO: locality.
}

impl Host {
    /// Usable for new traffic: no health flag set. Load balancers and priority spillover read this, rather than
    /// matching on `health_flags`, so a new flag does not touch every call site.
    pub fn is_healthy(&self) -> bool {
        self.health_flags.is_healthy()
    }

    /// Current in-flight request count (see [`Host::active_requests`]).
    ///
    /// Rust note: `Relaxed` is enough. The counter publishes nothing else, and LB picks only read the number.
    pub fn active_request_count(&self) -> u64 {
        self.active_requests.load(Ordering::Relaxed)
    }

    /// Count one in-flight request against this host until the returned
    /// guard drops.
    pub fn begin_request(&self) -> ActiveRequestGuard {
        self.active_requests.fetch_add(1, Ordering::Relaxed);
        ActiveRequestGuard {
            counter: Arc::clone(&self.active_requests),
        }
    }

    /// Test seam for [`crate::load_balancer`]'s `LEAST_REQUEST` tests: set
    /// the counter directly for pick-algorithm unit tests.
    #[cfg(test)]
    pub(crate) fn set_active_requests_for_test(&self, n: u64) {
        self.active_requests.store(n, Ordering::Relaxed);
    }
}

/// RAII handle for one in-flight request on a [`Host`]. Dropping it decrements the counter, so every exit path
/// (completion, error, downstream cancel) stays balanced.
#[derive(Debug)]
pub struct ActiveRequestGuard {
    counter: Arc<AtomicU64>,
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Per-request input to host selection (S7).
#[derive(Debug, Default)]
pub struct LoadBalancerContext {
    /// Result of the route's `hash_policy` chain, if any (ring hash / Maglev).
    pub hash: Option<u64>,
    /// Host override from an endpoint picker (`x-gateway-destination-endpoint`).
    pub host_override: Option<SocketAddr>,
    /// Cluster names an earlier attempt of this request already dialed. An aggregate skips them when choosing a
    /// member, so a retry falls over to the next provider instead of re-picking the one that just failed. Empty
    /// on the first attempt, and ignored by non-aggregate clusters.
    ///
    /// Rust note: a plain `Vec`, not a `HashSet`. Member lists are single digits, so a linear scan is cheaper.
    pub attempted_clusters: Vec<ClusterName>,
    /// Socket addresses dispatched by earlier attempts of this request. Consulted only when the route configured
    /// Envoy's `previous_hosts` retry predicate, which applies to every LB policy.
    pub attempted_hosts: Vec<SocketAddr>,
    /// Whether [`Self::attempted_hosts`] must reject a selected host, and how many times a picker may re-run
    /// selection after such a rejection. These are route policy, not cluster policy.
    pub avoid_previous_hosts: bool,
    pub host_selection_retry_max_attempts: u32,
    /// When `Some`, the request may use only a tenant's own credential, and these are the providers it holds one
    /// for (ADR-0007). An aggregate skips a member whose credential slot names a provider not in this list, or
    /// that has no slot. `None` means no restriction.
    ///
    /// Rust note: `Arc<[String]>` because the list is built once per snapshot and shared by every request of that
    /// tenant. Each request clones a pointer, not the strings.
    pub credential_providers: Option<std::sync::Arc<[String]>>,
}

/// Circuit-breaker accounting for one (cluster, priority): S5's four per-priority budgets. The router enforces
/// `max_requests` and retry admission. Connection and pending limits are enforced by the pool.
///
/// Rust note: the gauges sit behind `Arc<AtomicU32>`, because a [`CbGuard`] rides inside a streaming response body
/// that outlives the handler's stack frame, so it cannot borrow `self`.
#[derive(Debug, Clone)]
pub struct CircuitBreakerState {
    connections: BudgetHandle,
    pending: BudgetHandle,
    requests: BudgetHandle,
    retries: RetryLimit,
}

/// The retry breaker is either Envoy's fixed `max_retries` ceiling or its dynamic `retry_budget`. One acquisition
/// method covers both, so a call site cannot treat a percentage budget as an extra fixed cap (Envoy says it
/// *replaces* `max_retries`).
#[derive(Debug, Clone)]
enum RetryLimit {
    Fixed(BudgetHandle),
    Budget {
        retries: BudgetHandle,
        requests: BudgetHandle,
        pending: BudgetHandle,
        config: proxy_config::ir::RetryBudget,
    },
}

/// A budget's live gauge plus its limit. The gauge is pre-wrapped in `Arc`, so a guard clones only the atomic.
#[derive(Debug, Clone)]
struct BudgetHandle {
    active: Arc<std::sync::atomic::AtomicU32>,
    limit: u32,
    /// Wakes a parked waiter when a slot frees. `max_pending_requests` is a real parking queue in front of
    /// `max_connections`. `Some` only for the `connections` budget; a `Notify` nobody waits on would be dead weight.
    ///
    /// Rust note: `Arc<Notify>`, because the waiter (`pool::ConnectPool::new_stream`) holds no `CbGuard` yet, so it
    /// must clone an owned handle out of the budget before it waits.
    notify: Option<Arc<tokio::sync::Notify>>,
}

impl BudgetHandle {
    fn new(limit: u32) -> Self {
        Self {
            active: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            limit,
            notify: None,
        }
    }

    /// Same as [`Self::new`], but wired with a [`tokio::sync::Notify`] a
    /// parked caller can wait on for a released slot.
    fn new_with_notify(limit: u32) -> Self {
        Self {
            active: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            limit,
            notify: Some(Arc::new(tokio::sync::Notify::new())),
        }
    }

    /// Optimistic increment, then check, then roll back: claim a slot first, and give it back only if the claim
    /// overflowed the limit. This avoids a check-then-act race between threads at the cost of a harmless bounce off
    /// the limit under contention.
    ///
    /// Rust note: the claiming `fetch_add` uses `Acquire`, so a prior release (another guard's `Drop`) is visible
    /// before we decide. The rollback uses `Release`. A successful acquire needs no release of its own: the guard's
    /// `Drop` is what other threads must observe.
    fn try_acquire(&self) -> Option<CbGuard> {
        self.try_acquire_with_limit(self.limit)
    }

    /// The same atomic claim as [`Self::try_acquire`], with a limit computed at the call site. Used only for Envoy's
    /// dynamic retry budget, and the claimed gauge stays the atomic itself, so two workers cannot over-admit.
    fn try_acquire_with_limit(&self, limit: u32) -> Option<CbGuard> {
        let prev = self
            .active
            .fetch_add(1, std::sync::atomic::Ordering::Acquire);
        if prev >= limit {
            self.active
                .fetch_sub(1, std::sync::atomic::Ordering::Release);
            return None;
        }
        Some(CbGuard {
            active: Arc::clone(&self.active),
            notify: self.notify.clone(),
        })
    }
}

/// An acquired S5 budget slot. It owns a clone of the gauge, so it is `'static` and can move into a response body.
/// Dropping it releases the slot.
#[derive(Debug)]
pub struct CbGuard {
    active: Arc<std::sync::atomic::AtomicU32>,
    /// Set only on a `max_connections` slot: wakes one parked waiter after this guard's `Drop` frees the slot.
    notify: Option<Arc<tokio::sync::Notify>>,
}

impl Drop for CbGuard {
    fn drop(&mut self) {
        self.active
            .fetch_sub(1, std::sync::atomic::Ordering::Release);
        // Rust note: the release must come BEFORE `notify_one`. A waiter woken early could re-check the gauge, still
        // see it full, and go back to sleep. Releasing first guarantees the woken waiter sees the freed slot.
        if let Some(notify) = &self.notify {
            notify.notify_one();
        }
    }
}

impl CircuitBreakerState {
    /// The shared `max_connections` counter. Its allocation is unique per
    /// built cluster, which is what [`pool::ClusterBuildId`] keys on.
    pub(crate) fn connections_counter(&self) -> Arc<std::sync::atomic::AtomicU32> {
        Arc::clone(&self.connections.active)
    }

    /// Builds all four budgets from a cluster's lowered [`CircuitBreakerThresholds`].
    pub fn from_thresholds(t: proxy_config::ir::CircuitBreakerThresholds) -> Self {
        let connections = BudgetHandle::new_with_notify(t.max_connections);
        let pending = BudgetHandle::new(t.max_pending_requests);
        let requests = BudgetHandle::new(t.max_requests);
        let retries = match t.retry_budget {
            None => RetryLimit::Fixed(BudgetHandle::new(t.max_retries)),
            Some(config) => RetryLimit::Budget {
                retries: BudgetHandle::new(u32::MAX),
                requests: requests.clone(),
                pending: pending.clone(),
                config,
            },
        };
        Self {
            connections,
            pending,
            requests,
            retries,
        }
    }

    /// The one budget wired to a real call site today. The router holds it for the full response stream, since LLM
    /// streaming keeps a request active far longer than time-to-headers.
    pub fn try_acquire_request(&self) -> Option<CbGuard> {
        self.requests.try_acquire()
    }

    /// The `max_connections` budget, acquired in [`pool::ConnectPool::new_stream`] before dialing (so an over-budget
    /// cluster never opens a socket). It is held for the life of the physical connection (see
    /// [`UpstreamStream::cb_guard`]).
    pub fn try_acquire_connection(&self) -> Option<CbGuard> {
        self.connections.try_acquire()
    }

    /// The `max_pending_requests` budget: a bounded parking queue in front of `max_connections`. It is acquired only
    /// after `try_acquire_connection` fails, and dropped the instant a connection slot opens, so pending and active
    /// never double-count a request.
    pub fn try_acquire_pending(&self) -> Option<CbGuard> {
        self.pending.try_acquire()
    }

    /// A clone of the `connections` budget's wake channel. A caller that fails `try_acquire_connection` clones this
    /// before parking and awaits it, so a later release wakes it. Only `connections` carries a `Notify`, so this
    /// panics rather than hand back a handle that nobody will wake, which would be a hang.
    pub(crate) fn connections_notify(&self) -> Arc<tokio::sync::Notify> {
        self.connections
            .notify
            .clone()
            .expect("the connections budget always carries a Notify (see from_thresholds)")
    }

    /// Claim a slot for a retry or hedge. A configured `retry_budget` overrides `max_retries` with
    /// `max(min_retry_concurrency, floor(percent * (active + pending)))`. The request and pending gauges are sampled
    /// just before the retry gauge's atomic claim. The retry gauge itself is claimed and rolled back atomically, so
    /// concurrent workers never consume the same slot.
    pub fn try_acquire_retry(&self) -> Option<CbGuard> {
        match &self.retries {
            RetryLimit::Fixed(retries) => retries.try_acquire(),
            RetryLimit::Budget {
                retries,
                requests,
                pending,
                config,
            } => {
                let denominator = requests
                    .active
                    .load(std::sync::atomic::Ordering::Acquire)
                    .saturating_add(pending.active.load(std::sync::atomic::Ordering::Acquire));
                let proportional = ((f64::from(denominator) * config.budget_percent) / 100.0)
                    .floor()
                    .min(f64::from(u32::MAX)) as u32;
                let limit = proportional.max(config.min_retry_concurrency);
                retries.try_acquire_with_limit(limit)
            }
        }
    }
}

impl Default for CircuitBreakerState {
    /// Used where no cluster config is available to read thresholds from
    /// (test fixtures and similar callers).
    fn default() -> Self {
        Self::from_thresholds(proxy_config::ir::CircuitBreakerThresholds::ENVOY_DEFAULT)
    }
}

/// A stream slot on a pooled upstream connection. v1 ([`pool::ConnectPool`]) is connect-per-stream, so this carries
/// a freshly dialed transport with no reuse yet.
pub struct UpstreamStream {
    /// The connected upstream transport, already wrapped by the cluster's [`transport::UpstreamTransportSocket`]
    /// (plaintext, or a completed TLS handshake). The router runs the h1 or h2 codec over it. Both codecs are generic
    /// over `AsyncRead + AsyncWrite + Unpin`.
    pub io: BoxedUpstreamIo,
    /// The S5 `max_connections` slot this physical connection holds (see
    /// [`CircuitBreakerState::try_acquire_connection`]). Dropping it releases the slot, so it must live as long as
    /// the connection. For h1 that is this struct's lifetime. For a pooled connection (`proxy-http`'s
    /// `upstream_pool`), the caller moves the guard into the byte stream (`SlotIo`), so the slot is released when
    /// the socket drops.
    ///
    /// `None` only on paths with no real budget (test helpers, or callers that bypass `ConnectPool`).
    pub cb_guard: Option<CbGuard>,
    /// When this connection was dialed. A pooled connection keeps it for its
    /// whole life, so every request it carries reports the same values, as
    /// Envoy's `US_CX_*` and `US_HS_END` points do.
    pub timing: ConnectTiming,
    // TODO: (for keep-alive reuse on the h1 path) hold the codec
    // `SendRequest` handle rather than a raw transport -- at which point
    // this seam changes shape. The pool-guard half of this TODO is done.
}

/// The connection-establishment instants of one upstream connection, for
/// `%COMMON_DURATION%`'s `US_CX_BEG`, `US_CX_END` and `US_HS_END`.
///
/// `None` means the point was not observed: a stream built outside
/// [`pool::ConnectPool`] has no connect timing, and a plaintext transport has
/// no handshake.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectTiming {
    /// The TCP connect began, after the connection slot was acquired.
    pub connect_start: Option<std::time::Instant>,
    /// The TCP connect completed.
    pub connect_end: Option<std::time::Instant>,
    /// The transport handshake completed. Set only when the transport has one
    /// ([`transport::UpstreamTransportSocket::has_handshake`]).
    pub handshake_end: Option<std::time::Instant>,
}

/// The byte transport under an upstream HTTP stream, type-erased so a cluster can be plaintext or TLS without
/// every consumer becoming generic.
///
/// Rust note: this is the "trait alias by blanket impl" idiom. `dyn AsyncRead + AsyncWrite + Unpin` is not a legal
/// trait object (only one non-auto trait per object), so one trait takes the three as supertraits and is
/// blanket-implemented for everything that qualifies.
// `Send` (S10) is required by hyper's low-level client upgrade API, symmetric to the downstream `serve_http1`
// bound. It only widens the bound: the transports boxed here are already `Send`, and the workers still run on
// per-worker current_thread runtimes (ADR-0003).
pub trait UpstreamIo:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static
{
}

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
    /// The TCP connect succeeded but the transport handshake failed (TLS: bad certificate, no shared ALPN, protocol
    /// version mismatch). Envoy folds this into the connect-failure bucket. It is a separate variant so the log
    /// says which half broke.
    #[error("upstream TLS handshake failed: {0}")]
    TlsHandshake(std::io::Error),
    /// Connection died before response headers -> retriable under `reset` (S3.2).
    #[error("upstream reset before response headers")]
    ResetBeforeHeaders,
}

/// Per-worker, per-host, per-protocol connection pool.
pub trait HttpConnPool: Send + Sync {
    /// Resolves when a stream slot is available (may open a new connection,
    /// subject to circuit breakers).
    fn new_stream(&self) -> BoxFuture<'static, Result<UpstreamStream, PoolError>>;
}

/// One attempt's host selection: the picked host, plus the cluster
/// that actually owns it.
#[derive(Debug)]
pub struct HostSelection {
    pub host: Arc<Host>,
    /// Set only when the entry that made the pick is an aggregate: the member cluster the host belongs to. `None`
    /// means the caller's entry owns the host, which is true for every non-aggregate cluster.
    ///
    /// The owning cluster supplies the transport socket, the upstream protocol, and the provider credentials. A
    /// caller that ignores this field sends the aggregate's (empty) credentials to a real provider.
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

/// What the router sees of a cluster.
pub trait ClusterEntry: Send + Sync {
    /// Load-balancer host pick (S7: policy, panic threshold, priority spillover), plus the cluster that owns the
    /// picked host. An aggregate's members are different providers with different credentials, so the owner is
    /// not always the entry the caller holds.
    ///
    /// This is the only way to get a host out of a `ClusterEntry`. A second path that drops the owner could send
    /// provider A's API key to provider B (AGENTS.md invariant 1).
    fn select_host(&self, ctx: &LoadBalancerContext) -> Option<HostSelection>;

    /// The pool for a picked host.
    fn http_pool(&self, host: &Arc<Host>, proto: UpstreamProtocol) -> Arc<dyn HttpConnPool>;

    /// Which HTTP protocol the router must speak to this cluster's upstreams (Envoy default HTTP/1.1). The router
    /// uses it to pick both the pool and the upstream codec.
    fn upstream_protocol(&self) -> UpstreamProtocol;

    /// Circuit-breaker bucket for the request's priority (S5).
    fn circuit_breaker(&self, prio: RoutingPriority) -> &CircuitBreakerState;

    /// Request header mutations for this cluster, applied when it is the cluster the attempt dialed. Carries
    /// provider credentials under the `llmproxy` dialect (see `ClusterConfig::request_headers_to_add`).
    fn request_headers_to_add(&self) -> &[proxy_config::ir::HeaderMutation];

    /// Provider-owned path/query rewrite to apply after route transforms.
    fn request_path_rewrite(&self) -> Option<&proxy_config::ir::RequestPathRewrite>;

    /// Provider-specific credential and model path behavior for this cluster.
    fn provider_runtime(&self) -> Option<&proxy_config::ir::ProviderRuntimeConfig>;

    /// Which usage dialect the provider behind this cluster speaks. Returns
    /// `None` for ordinary clusters that never set the llmproxy usage metadata.
    fn usage_dialect(&self) -> Option<proxy_config::ir::UsageDialect>;

    /// Feeds one upstream attempt's outcome to this cluster's S6 outlier detector. `addr` is the host the attempt
    /// dialed. A no-op without outlier detection, so the router can call it after every attempt. Takes `&self`
    /// because the detector does its own interior locking.
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
    fn retry_budget_uses_percent_floor_and_minimum_concurrency() {
        let cb = CircuitBreakerState::from_thresholds(proxy_config::ir::CircuitBreakerThresholds {
            max_requests: 10,
            retry_budget: Some(proxy_config::ir::RetryBudget {
                budget_percent: 20.0,
                min_retry_concurrency: 1,
            }),
            ..proxy_config::ir::CircuitBreakerThresholds::ENVOY_DEFAULT
        });

        // Two active requests make 20% == 0.4, floored to zero, so the
        // configured minimum admits exactly one retry.
        let _rq1 = cb.try_acquire_request().unwrap();
        let _rq2 = cb.try_acquire_request().unwrap();
        let retry1 = cb.try_acquire_retry().expect("minimum permits one retry");
        assert!(cb.try_acquire_retry().is_none(), "minimum is a real cap");

        // Ten active requests make the proportional cap two. The existing retry takes one, and eight more raise the
        // cap enough for a second without replacing the dynamic budget with `max_retries`.
        let _more: Vec<_> = (0..8).map(|_| cb.try_acquire_request().unwrap()).collect();
        let retry2 = cb.try_acquire_retry().expect("20% of ten permits two");
        assert!(cb.try_acquire_retry().is_none());
        drop((retry1, retry2));
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
        // Rust note: `requests.active` is private, so "back to zero" is proven behaviorally. Re-acquiring up to the
        // full limit succeeds only if both prior guards released their slots.
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
