//! Active health checking (WP-18): periodically probes hosts and flips
//! [`HealthStatus`] on consecutive pass/fail runs, publishing the transition
//! as a fresh [`HostSet`] snapshot rather than mutating a `Host` in place --
//! the same "control computes, workers swap" model discovery already uses
//! (see [`crate::manager`]/ADR-0003). This module runs entirely on the
//! control runtime; the only thing that crosses to workers is the `Arc<Host>`
//! snapshot itself.
//!
//! **IR wiring landed (WP-18 runtime wiring).** `proxy_config::ir::ClusterConfig`
//! carries `health_check: Option<HealthCheckIR>`; [`HealthCheckConfig`]/
//! [`HealthCheckKind`] are still defined here rather than in the IR (ground
//! rule #2 keeps proto/IR types from leaking past `proxy-config`), and
//! [`HealthCheckEngine::from_ir`] is the one conversion site. `crate::manager`
//! builds an engine per config-sourced `Endpoints` cluster and calls
//! [`HealthCheckEngine::spawn_for_host`]/aborts its `JoinHandle` as
//! `diff_host_sets` reports hosts added/removed on each refresh.
//!
//! gRPC health checks (`grpc.health.v1.Health/Check`) are **out of scope**
//! here -- see [`HealthCheckKind`]'s doc comment for why silently reporting
//! "healthy" would be worse than not supporting the mode at all.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use crate::host_set::HostSet;
use crate::outlier::OutlierDetector;
use crate::{HealthFlags, HealthStatus, Host};

/// Envoy's documented default expected HTTP status for an HTTP health check
/// with no explicit `expected_statuses`: 200 and nothing else.
pub const DEFAULT_EXPECTED_HTTP_STATUS: u16 = 200;

/// Envoy's default `no_traffic_interval`: the interval used for a host that
/// hasn't received any traffic since its last check.
///
/// TODO(WP-18 follow-up): this constant exists so the config surface is
/// complete, but nothing in this engine actually switches to it yet --
/// "has this host received traffic recently" is a signal `Host` doesn't
/// carry today (`active_requests` is a live gauge, not a
/// since-last-check-count), and wiring it correctly is the router/pool's
/// job (WP-13/WP-15), not this one. Every check loop here always sleeps
/// `interval` (+ jitter). Getting `no_traffic_interval` right without a real
/// traffic signal would mean guessing, which ground rule #1's spirit
/// (no silent approximations) argues against -- better to leave it unwired
/// and documented than to fake the behavior.
pub const DEFAULT_NO_TRAFFIC_INTERVAL: Duration = Duration::from_secs(60);

/// What a health check sends and expects, per protocol.
#[derive(Debug, Clone)]
pub enum HealthCheckKind {
    /// Envoy's `HttpHealthCheck`: a `GET` to `path`, `Connection: close`, with
    /// an optional `Host` header override. `expected_statuses.is_empty()`
    /// means "use [`DEFAULT_EXPECTED_HTTP_STATUS`]" (Envoy's own
    /// zero-value-means-default convention for this field).
    Http {
        path: String,
        expected_statuses: Vec<u16>,
        host: Option<String>,
    },
    /// Envoy's `TcpHealthCheck`: after connecting, optionally write `send`,
    /// then optionally read exactly `expect.len()` bytes and require an exact
    /// match. An empty `send` skips the write; an empty `expect` makes a bare
    /// TCP connect the whole check (Envoy allows this too -- it's the
    /// "just prove something's listening" mode).
    Tcp { send: Vec<u8>, expect: Vec<u8> },
    // TODO(WP-18 follow-up, out of scope here): `grpc.health.v1.Health/Check`.
    // Deliberately not a variant yet -- a stub that always reports healthy
    // would be worse than refusing the config outright (ground rule #1), and
    // a real implementation needs an h2 client call, which this crate's pool
    // doesn't expose as a reusable primitive today. Building a cluster whose
    // config asks for a gRPC health check must be rejected at construction,
    // not silently downgraded to "always healthy".
}

/// Timing + thresholds for one health check (Envoy's `HealthCheck` message,
/// minus the parts covered by [`HealthCheckKind`]).
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// How often to check a host that has recent traffic.
    pub interval: Duration,
    /// How long a single check attempt (connect + probe) may take before
    /// counting as a failure.
    pub timeout: Duration,
    /// Consecutive failures required to flip `Healthy` -> `Unhealthy`.
    pub unhealthy_threshold: u32,
    /// Consecutive successes required to flip `Unhealthy` -> `Healthy`.
    pub healthy_threshold: u32,
    /// See [`DEFAULT_NO_TRAFFIC_INTERVAL`]'s doc comment -- accepted here for
    /// config-surface completeness, not yet acted on.
    pub no_traffic_interval: Duration,
    /// Uniform random jitter added to `interval` on every scheduling
    /// decision, to avoid every host's checks landing in lockstep.
    pub interval_jitter: Duration,
}

/// A host's per-check consecutive-count state machine (Envoy's threshold
/// semantics): thresholds are *consecutive* counts, not ratios, and any
/// result of the opposite kind resets the run back to zero. This is a plain
/// data type (no I/O, no async) so its transition logic is unit-testable in
/// isolation from the network/timing code around it.
struct ConsecutiveTracker {
    healthy_threshold: u32,
    unhealthy_threshold: u32,
    current: HealthStatus,
    consecutive_successes: u32,
    consecutive_failures: u32,
}

impl ConsecutiveTracker {
    /// A tracked host starts `Healthy`, matching `Host::health`'s own default
    /// -- WP-18 doesn't introduce a separate "unknown" initial state.
    fn new(healthy_threshold: u32, unhealthy_threshold: u32) -> Self {
        Self {
            healthy_threshold: healthy_threshold.max(1),
            unhealthy_threshold: unhealthy_threshold.max(1),
            current: HealthStatus::Healthy,
            consecutive_successes: 0,
            consecutive_failures: 0,
        }
    }

    /// Feed one check result. Returns `Some(new_status)` only when this
    /// result actually caused a transition, so callers know to republish;
    /// `None` covers both "still within threshold" and "already settled"
    /// (e.g. a success while already `Healthy` just resets the failure run).
    fn record(&mut self, success: bool) -> Option<HealthStatus> {
        if success {
            self.consecutive_failures = 0;
            self.consecutive_successes += 1;
            if self.current == HealthStatus::Unhealthy
                && self.consecutive_successes >= self.healthy_threshold
            {
                self.current = HealthStatus::Healthy;
                return Some(HealthStatus::Healthy);
            }
        } else {
            self.consecutive_successes = 0;
            self.consecutive_failures += 1;
            if self.current == HealthStatus::Healthy
                && self.consecutive_failures >= self.unhealthy_threshold
            {
                self.current = HealthStatus::Unhealthy;
                return Some(HealthStatus::Unhealthy);
            }
        }
        None
    }
}

/// Runs one cluster's active health checks and publishes transitions onto a
/// shared [`HostSet`] slot.
///
/// Rust note: `Send + Sync` (not `!Send` -- see ADR-0003) is exactly right
/// here: this type only ever runs on the control runtime, spawning one
/// `tokio::spawn`ed loop per host, and hands the *results* to workers only
/// via the `Arc<HostSet>` it stores into `host_set`.
pub struct HealthCheckEngine {
    config: HealthCheckConfig,
    kind: HealthCheckKind,
}

impl HealthCheckEngine {
    pub fn new(config: HealthCheckConfig, kind: HealthCheckKind) -> Arc<Self> {
        Arc::new(Self { config, kind })
    }

    /// Builds an engine from the lowered IR (WP-18 runtime wiring): the
    /// module doc's wiring plan, now that `ClusterConfig::health_check`
    /// exists. This is the one place `proxy_config::ir::HealthCheckIR`/
    /// `HealthCheckKindIR` convert to this module's own
    /// `HealthCheckConfig`/`HealthCheckKind` -- ground rule #2 keeps the IR
    /// types from leaking any further than this call site.
    pub fn from_ir(ir: &proxy_config::ir::HealthCheckIR) -> Arc<Self> {
        let config = HealthCheckConfig {
            interval: ir.interval,
            timeout: ir.timeout,
            unhealthy_threshold: ir.unhealthy_threshold,
            healthy_threshold: ir.healthy_threshold,
            no_traffic_interval: ir.no_traffic_interval,
            interval_jitter: ir.interval_jitter,
        };
        let kind = match &ir.kind {
            proxy_config::ir::HealthCheckKindIR::Http {
                path,
                expected_statuses,
                host,
            } => HealthCheckKind::Http {
                path: path.clone(),
                expected_statuses: expected_statuses.clone(),
                host: host.clone(),
            },
            proxy_config::ir::HealthCheckKindIR::Tcp { send, expect } => HealthCheckKind::Tcp {
                send: send.clone(),
                expect: expect.clone(),
            },
        };
        Self::new(config, kind)
    }

    /// Spawn a check loop for one host address on the current (control)
    /// runtime. The first check fires immediately -- there is no initial
    /// `interval` sleep before it -- matching Envoy's own "check as soon as a
    /// host is added" behavior; every following check is spaced `interval`
    /// (+ jitter) apart, timed from when the previous check *finished* (a
    /// slow upstream doesn't get checked back-to-back).
    ///
    /// The loop runs until `host_set`'s last strong reference is dropped
    /// (aside from this task's own clone) or the returned handle is aborted.
    /// `ManagedCluster::reconcile_probes` aborts the handle of a host that
    /// leaves membership (see the module doc's IR-wiring note).
    ///
    /// `outlier_detector` is the last WP-19 gap: active HC (this module,
    /// WP-18) and outlier detection (WP-19) are otherwise independent, but a
    /// host that recovers here should also clear an outlier ejection --
    /// [`OutlierDetector::on_active_health_check_pass`] already implements
    /// that (including its own `uneject_on_healthy_active_hc` check), it
    /// just had nothing calling it. `None` when the cluster configures no
    /// outlier detection at all, in which case this is a no-op. The
    /// direction is one-way: an *unhealthy* active-check transition never
    /// touches the detector, and outlier ejection never touches
    /// `failed_active_hc`.
    pub fn spawn_for_host(
        self: &Arc<Self>,
        addr: SocketAddr,
        host_set: Arc<ArcSwap<HostSet>>,
        outlier_detector: Option<Arc<OutlierDetector>>,
    ) -> JoinHandle<()> {
        let engine = Arc::clone(self);
        tokio::spawn(async move { engine.run_host_loop(addr, host_set, outlier_detector).await })
    }

    async fn run_host_loop(
        &self,
        addr: SocketAddr,
        host_set: Arc<ArcSwap<HostSet>>,
        outlier_detector: Option<Arc<OutlierDetector>>,
    ) {
        let mut tracker = ConsecutiveTracker::new(
            self.config.healthy_threshold,
            self.config.unhealthy_threshold,
        );
        loop {
            let passed = self.run_single_check(addr).await;
            if let Some(new_status) = tracker.record(passed) {
                apply_health_transition(&host_set, addr, new_status);
                // Recovery only -- see this method's doc for why an
                // `Unhealthy` transition must not reach the detector.
                if new_status == HealthStatus::Healthy {
                    if let Some(detector) = &outlier_detector {
                        detector.on_active_health_check_pass(addr);
                    }
                }
            }
            tokio::time::sleep(self.next_delay()).await;
        }
    }

    /// `interval` plus a uniform-random draw in `[0, interval_jitter)`.
    ///
    /// Rust note: a fresh `rand::thread_rng()` per call rather than a stored
    /// `Mutex<StdRng>` (like the load balancers use) -- this runs on its own
    /// task with no shared state to protect, so there's nothing to guard.
    fn next_delay(&self) -> Duration {
        if self.config.interval_jitter.is_zero() {
            return self.config.interval;
        }
        let jitter_nanos = self
            .config
            .interval_jitter
            .as_nanos()
            .min(u128::from(u64::MAX));
        let jitter = rand::thread_rng().gen_range(0..=jitter_nanos as u64);
        self.config.interval + Duration::from_nanos(jitter)
    }

    /// One check attempt, `timeout`-bounded: a timeout or any I/O failure
    /// counts as a failure (Envoy makes no distinction there either -- both
    /// just mean "the host didn't answer this probe in time").
    async fn run_single_check(&self, addr: SocketAddr) -> bool {
        matches!(
            tokio::time::timeout(self.config.timeout, self.attempt_check(addr)).await,
            Ok(Ok(true))
        )
    }

    async fn attempt_check(&self, addr: SocketAddr) -> io::Result<bool> {
        match &self.kind {
            HealthCheckKind::Http {
                path,
                expected_statuses,
                host,
            } => http_check(addr, path, expected_statuses, host.as_deref()).await,
            HealthCheckKind::Tcp { send, expect } => tcp_check(addr, send, expect).await,
        }
    }
}

/// Replace one host's `failed_active_hc` flag in `host_set` and publish the
/// result, but only if the address is still present and that flag actually
/// differs -- a no-op store would just be needless churn for every reader
/// watching this `ArcSwap`. The outlier-detection flag
/// (`failed_outlier_check`, WP-19) is carried over untouched: active HC and
/// outlier detection are independent axes (see [`crate::HealthFlags`]), so a
/// health-check transition must never clobber an outlier ejection that's
/// concurrently in effect.
///
/// Rust note: `Host` has no interior mutability for `health_flags` (unlike
/// `active_requests`'s `AtomicU64`) precisely so this can't race with a
/// reader mid-read -- a whole new `Arc<Host>` is built and the whole
/// `HostSet` swapped, the same "control computes, workers swap" discipline
/// [`crate::discovery`] already uses for DNS flaps.
fn apply_health_transition(host_set: &ArcSwap<HostSet>, addr: SocketAddr, status: HealthStatus) {
    // Rust note: `rcu` (read-copy-update), NOT `load()` then `store()`.
    //
    // There is one of these tasks *per host*, all sharing this one `ArcSwap`,
    // so a plain load/modify/store is a lost-update race: task A and task B
    // both load snapshot S, A stores S+{a: Unhealthy}, then B stores
    // S+{b: Unhealthy} -- computed from the stale S, so it silently reverts
    // A's transition. And because `ConsecutiveTracker::record` only returns
    // `Some` on the *edge*, A never re-publishes: the host stays wrongly
    // Healthy until it happens to flap again. That is a permanent lost
    // transition, and it is likeliest exactly when it matters most -- a
    // provider outage flips many hosts at once.
    //
    // `rcu` re-runs the closure against the newest value whenever it loses
    // the compare-and-swap, so concurrent transitions compose instead of
    // clobbering. The closure must therefore be pure and cheap; rebuilding a
    // `HostSet` is both.
    let failed_active_hc = status == HealthStatus::Unhealthy;
    host_set.rcu(|current| {
        let updated: Vec<Arc<Host>> = current
            .all_hosts()
            .into_iter()
            .map(|h| {
                if h.address == addr && h.health_flags.failed_active_hc != failed_active_hc {
                    Arc::new(Host {
                        address: h.address,
                        hostname: h.hostname.clone(),
                        metadata: h.metadata.clone(),
                        weight: h.weight,
                        priority: h.priority,
                        health_flags: HealthFlags {
                            failed_active_hc,
                            failed_outlier_check: h.health_flags.failed_outlier_check,
                        },
                        // Carried over, not reset -- a health flip must not
                        // erase in-flight accounting that `LeastRequestLb`
                        // reads. (A concurrent increment landing between this
                        // read and the swap is still lost; that is inherent to
                        // rebuilding an immutable `Host` and is transient
                        // counter drift, not lost health state.)
                        active_requests: AtomicU64::new(h.active_request_count()),
                    })
                } else {
                    h
                }
            })
            .collect();
        Arc::new(HostSet::from_hosts(updated))
    });
}

/// A minimal HTTP/1.1 `GET`, hand-rolled rather than pulled in via `hyper` --
/// a health check only needs to send one fixed request and read a status
/// line back, and this crate has no HTTP client dependency to reuse today.
async fn http_check(
    addr: SocketAddr,
    path: &str,
    expected_statuses: &[u16],
    host_header: Option<&str>,
) -> io::Result<bool> {
    let mut stream = TcpStream::connect(addr).await?;
    let host = host_header
        .map(str::to_string)
        .unwrap_or_else(|| addr.to_string());
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    // `Connection: close` means the server closes once it's done responding,
    // so reading to EOF gets the whole response without needing to parse
    // `Content-Length`/chunked framing -- we only need the status line.
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    let status_line = response
        .split(|&b| b == b'\n')
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty health check response"))?;
    let status_line = String::from_utf8_lossy(status_line);
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("could not parse HTTP status from {status_line:?}"),
            )
        })?;

    if expected_statuses.is_empty() {
        Ok(status == DEFAULT_EXPECTED_HTTP_STATUS)
    } else {
        Ok(expected_statuses.contains(&status))
    }
}

/// Envoy's `TcpHealthCheck`: connect, optionally send fixed bytes, optionally
/// require an exact-length, exact-match response.
async fn tcp_check(addr: SocketAddr, send: &[u8], expect: &[u8]) -> io::Result<bool> {
    let mut stream = TcpStream::connect(addr).await?;
    if !send.is_empty() {
        stream.write_all(send).await?;
    }
    if expect.is_empty() {
        return Ok(true);
    }
    let mut buf = vec![0u8; expect.len()];
    stream.read_exact(&mut buf).await?;
    Ok(buf == expect)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_balancer::{HostPicker, RoundRobinLb};
    use crate::LoadBalancerContext;
    use tokio::net::TcpListener;
    use tokio::sync::Notify;

    fn host(addr: SocketAddr, priority: u32) -> Arc<Host> {
        Arc::new(Host {
            address: addr,
            hostname: None,
            metadata: Default::default(),
            weight: 1,
            priority,
            health_flags: HealthFlags::default(),
            active_requests: AtomicU64::new(0),
        })
    }

    // -------------------------------------------- ConsecutiveTracker (pure) --

    #[test]
    fn healthy_host_needs_consecutive_failures_to_flip() {
        let mut t = ConsecutiveTracker::new(2, 3);
        assert_eq!(t.record(false), None); // 1 failure
        assert_eq!(t.record(false), None); // 2 failures
        assert_eq!(t.record(false), Some(HealthStatus::Unhealthy)); // 3rd: flips
    }

    #[test]
    fn an_interleaved_success_resets_the_failure_run() {
        let mut t = ConsecutiveTracker::new(2, 3);
        assert_eq!(t.record(false), None);
        assert_eq!(t.record(false), None);
        assert_eq!(t.record(true), None); // resets the run
        assert_eq!(t.record(false), None); // back to 1
        assert_eq!(t.record(false), None); // 2
        assert!(t.record(false).is_some()); // 3rd since the reset: flips
    }

    #[test]
    fn unhealthy_host_needs_consecutive_successes_to_recover() {
        let mut t = ConsecutiveTracker::new(2, 1);
        assert_eq!(t.record(false), Some(HealthStatus::Unhealthy));
        assert_eq!(t.record(true), None); // 1 success, threshold is 2
        assert_eq!(t.record(true), Some(HealthStatus::Healthy)); // 2nd: recovers
    }

    #[test]
    fn an_interleaved_failure_resets_the_success_run_during_recovery() {
        let mut t = ConsecutiveTracker::new(3, 1);
        assert_eq!(t.record(false), Some(HealthStatus::Unhealthy));
        assert_eq!(t.record(true), None);
        assert_eq!(t.record(true), None);
        assert_eq!(t.record(false), None); // resets the success run
        assert_eq!(t.record(true), None); // back to 1 of 3
        assert_eq!(t.record(true), None); // 2 of 3
        assert!(t.record(true).is_some()); // 3rd since reset: recovers
    }

    #[test]
    fn no_transition_reported_while_settled() {
        // Already healthy: further successes are a no-op report-wise.
        let mut t = ConsecutiveTracker::new(2, 2);
        assert_eq!(t.record(true), None);
        assert_eq!(t.record(true), None);
    }

    // ------------------------------------------------------------ http_check --

    async fn serve_once(listener: TcpListener, response: &'static [u8]) {
        let (mut sock, _) = listener.accept().await.unwrap();
        // Drain the request so the client's write doesn't block on a full
        // socket buffer, then respond and close.
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf).await;
        sock.write_all(response).await.unwrap();
        sock.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn http_check_passes_on_default_200() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_once(
            listener,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ));
        let ok = http_check(addr, "/healthz", &[], None).await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn http_check_fails_on_non_default_status_with_empty_expected_list() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_once(
            listener,
            b"HTTP/1.1 503 Service Unavailable\r\n\r\n",
        ));
        let ok = http_check(addr, "/healthz", &[], None).await.unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn http_check_honors_explicit_expected_statuses() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_once(listener, b"HTTP/1.1 204 No Content\r\n\r\n"));
        let ok = http_check(addr, "/healthz", &[204, 200], None)
            .await
            .unwrap();
        assert!(ok);
    }

    // ------------------------------------------------------------- tcp_check --

    #[tokio::test]
    async fn tcp_check_bare_connect_succeeds_with_no_send_or_expect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });
        let ok = tcp_check(addr, &[], &[]).await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn tcp_check_matches_expected_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"PING");
            sock.write_all(b"PONG").await.unwrap();
        });
        let ok = tcp_check(addr, b"PING", b"PONG").await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn tcp_check_rejects_mismatched_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).await.unwrap();
            sock.write_all(b"NOPE").await.unwrap();
        });
        let ok = tcp_check(addr, b"PING", b"PONG").await.unwrap();
        assert!(!ok);
    }

    // -------------------------------------------- timeout counts as failure --

    #[tokio::test(start_paused = true)]
    async fn timeout_shorter_than_the_response_counts_as_a_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Sleep past the health check's timeout before ever responding.
            tokio::time::sleep(Duration::from_secs(10)).await;
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
        });
        let config = HealthCheckConfig {
            interval: Duration::from_secs(1),
            timeout: Duration::from_millis(50),
            unhealthy_threshold: 1,
            healthy_threshold: 1,
            no_traffic_interval: DEFAULT_NO_TRAFFIC_INTERVAL,
            interval_jitter: Duration::ZERO,
        };
        let engine = HealthCheckEngine::new(
            config,
            HealthCheckKind::Http {
                path: "/".to_string(),
                expected_statuses: vec![],
                host: None,
            },
        );
        assert!(!engine.run_single_check(addr).await);
    }

    // ---------------------------------------- first check fires immediately --

    #[tokio::test]
    async fn first_check_fires_immediately_not_after_one_interval() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let checked = Arc::new(Notify::new());
        let checked_for_server = Arc::clone(&checked);
        tokio::spawn(async move {
            loop {
                let (_sock, _) = listener.accept().await.unwrap();
                checked_for_server.notify_one();
            }
        });

        let config = HealthCheckConfig {
            interval: Duration::from_secs(3600), // deliberately huge
            timeout: Duration::from_secs(1),
            unhealthy_threshold: 1,
            healthy_threshold: 1,
            no_traffic_interval: DEFAULT_NO_TRAFFIC_INTERVAL,
            interval_jitter: Duration::ZERO,
        };
        let engine = HealthCheckEngine::new(
            config,
            HealthCheckKind::Tcp {
                send: vec![],
                expect: vec![],
            },
        );
        let host_set = Arc::new(ArcSwap::from_pointee(HostSet::from_hosts(vec![host(
            addr, 0,
        )])));
        engine.spawn_for_host(addr, host_set, None);

        // If the first check waited a full `interval` before firing, this
        // would time out (the interval is an hour); it must resolve almost
        // immediately. Real (unpaused) time here: mixing a paused clock with
        // genuine socket I/O races the paused-clock auto-advance against the
        // OS actually delivering the connect event, which is exactly the
        // flakiness this bounded real-time wait avoids -- the bound itself
        // (2s) is generous but the loopback connect resolves in microseconds.
        tokio::time::timeout(Duration::from_secs(2), checked.notified())
            .await
            .expect("first health check must fire immediately on host add");
    }

    // --------------------------- publishes a new HostSet HostPicker observes --

    /// Poll `cond` on real wall-clock time until it's true or `deadline`
    /// elapses. Used instead of a fixed sleep count so these tests aren't
    /// tuned to a guessed number of check ticks -- see the module test
    /// notes on why real time (not `tokio::time::pause`) is used here: these
    /// tests assert on genuine TCP connect/refuse timing, which races
    /// unpredictably against paused-clock auto-advance.
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

    /// Every host has its own check task writing to one shared `ArcSwap`, so
    /// `apply_health_transition` must compose concurrent updates rather than
    /// clobber them. With a `load()`/`store()` implementation this loses
    /// transitions and the assertion below fails; with `rcu` it holds.
    ///
    /// The lost update is *permanent*, not transient, which is what makes it
    /// worth a dedicated test: `ConsecutiveTracker` only reports the edge, so
    /// a clobbered transition is never re-published.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_transitions_on_different_hosts_do_not_clobber_each_other() {
        const HOSTS: u16 = 64;

        let addrs: Vec<SocketAddr> = (0..HOSTS)
            .map(|i| SocketAddr::from(([127, 0, 0, 1], 20_000 + i)))
            .collect();
        let host_set = Arc::new(ArcSwap::from_pointee(HostSet::from_hosts(
            addrs.iter().map(|a| host(*a, 0)).collect(),
        )));

        // All 64 tasks flip their own host at once -- the provider-outage
        // shape, where every host goes unhealthy at nearly the same instant.
        let mut tasks = Vec::new();
        for addr in &addrs {
            let host_set = Arc::clone(&host_set);
            let addr = *addr;
            tasks.push(tokio::spawn(async move {
                apply_health_transition(&host_set, addr, HealthStatus::Unhealthy);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }

        let final_set = host_set.load();
        let still_healthy: Vec<SocketAddr> = final_set
            .all_hosts()
            .into_iter()
            .filter(|h| h.is_healthy())
            .map(|h| h.address)
            .collect();
        assert!(
            still_healthy.is_empty(),
            "{} of {HOSTS} health transitions were lost to a read-modify-write \
             race and will never be re-published: {still_healthy:?}",
            still_healthy.len(),
        );
    }

    #[tokio::test]
    async fn a_transition_publishes_a_host_set_the_picker_then_observes() {
        // Two hosts at the same priority: `flaky` starts with nothing
        // listening (its checks fail), `steady` has a real listener and is
        // never health-checked (so it's always `Healthy`, a stable baseline
        // to assert the picker's behavior against). With 2 hosts and 1
        // healthy (50%, not below the panic threshold, see
        // `load_balancer::PANIC_THRESHOLD_PERCENT`), the picker should
        // exclude `flaky` once it flips -- unlike a *single*-host set, where
        // panic-widening would select it anyway (see
        // `load_balancer::tests::all_unhealthy_everywhere_still_returns_a_host_via_panic`).
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let flaky_addr = probe.local_addr().unwrap();
        drop(probe); // nothing listens yet -> connect fails -> check fails

        let steady_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let steady_addr = steady_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let _ = steady_listener.accept().await;
            }
        });

        let config = HealthCheckConfig {
            interval: Duration::from_millis(10),
            timeout: Duration::from_millis(200),
            unhealthy_threshold: 2,
            healthy_threshold: 1,
            no_traffic_interval: DEFAULT_NO_TRAFFIC_INTERVAL,
            interval_jitter: Duration::ZERO,
        };
        let engine = HealthCheckEngine::new(
            config,
            HealthCheckKind::Tcp {
                send: vec![],
                expect: vec![],
            },
        );
        let host_set = Arc::new(ArcSwap::from_pointee(HostSet::from_hosts(vec![
            host(flaky_addr, 0),
            host(steady_addr, 0),
        ])));
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let ctx = LoadBalancerContext::default();

        engine.spawn_for_host(flaky_addr, Arc::clone(&host_set), None);

        // Two consecutive failed connects (unhealthy_threshold=2) must flip
        // `flaky`, and once it does, every pick over a wider sample should
        // land only on `steady`.
        wait_until(Duration::from_secs(2), || {
            (0..20).all(|_| picker.pick(&host_set.load(), &ctx).unwrap().address == steady_addr)
        })
        .await;

        // Now stand up a real listener at `flaky`'s address so its checks
        // succeed, and confirm the picker observes it rejoining the pool.
        let listener = TcpListener::bind(flaky_addr).await.unwrap();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });
        wait_until(Duration::from_secs(2), || {
            let seen: std::collections::HashSet<_> = (0..20)
                .map(|_| picker.pick(&host_set.load(), &ctx).unwrap().address)
                .collect();
            seen.contains(&flaky_addr)
        })
        .await;
    }

    // ------------------------------- interaction with the panic threshold --

    #[tokio::test]
    async fn enough_unhealthy_hosts_trip_the_panic_threshold() {
        // Three hosts; two never accept a connection (fail forever), one is
        // always healthy. unhealthy_threshold=1 so a single failed check
        // flips a host. 2 of 3 unhealthy -> 33% healthy < 50% panic
        // threshold -> HostPicker should widen to all three rather than
        // starving on the one healthy host.
        let bad1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad1_addr = bad1.local_addr().unwrap();
        drop(bad1);
        let bad2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad2_addr = bad2.local_addr().unwrap();
        drop(bad2);

        let good_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = good_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let _ = good_listener.accept().await;
            }
        });

        let config = HealthCheckConfig {
            interval: Duration::from_millis(10),
            timeout: Duration::from_millis(200),
            unhealthy_threshold: 1,
            healthy_threshold: 1,
            no_traffic_interval: DEFAULT_NO_TRAFFIC_INTERVAL,
            interval_jitter: Duration::ZERO,
        };
        let engine = HealthCheckEngine::new(
            config,
            HealthCheckKind::Tcp {
                send: vec![],
                expect: vec![],
            },
        );
        let host_set = Arc::new(ArcSwap::from_pointee(HostSet::from_hosts(vec![
            host(bad1_addr, 0),
            host(bad2_addr, 0),
            host(good_addr, 0),
        ])));
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let ctx = LoadBalancerContext::default();

        engine.spawn_for_host(bad1_addr, Arc::clone(&host_set), None);
        engine.spawn_for_host(bad2_addr, Arc::clone(&host_set), None);
        engine.spawn_for_host(good_addr, Arc::clone(&host_set), None);

        wait_until(Duration::from_secs(2), || {
            let seen: std::collections::HashSet<_> = (0..50)
                .map(|_| picker.pick(&host_set.load(), &ctx).unwrap().address)
                .collect();
            seen.len() == 3
        })
        .await;
    }
}
