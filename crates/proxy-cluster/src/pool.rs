//! v1 upstream connection pool: connect-per-stream, with no reuse. [`ConnectPool::new_stream`] dials a fresh
//! TCP connection per call, wraps it in the cluster's transport socket (plaintext or TLS), and returns an
//! [`UpstreamStream`] for the router's h1 or h2 codec.
//!
//! There is no keep-alive reuse, no h2 multiplexing, and no connection-level circuit breaking yet (see the
//! `TODO` on [`UpstreamStream`]). The pool is protocol-agnostic: it produces bytes, and the router picks the
//! codec from `upstream_protocol`.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;

use crate::transport::UpstreamTransportSocket;
use crate::{CircuitBreakerState, HttpConnPool, PoolError, UpstreamStream};

/// Identifies one *build* of a cluster, so a worker's connection caches can tell a connection dialed under the
/// current build from one dialed under a build the control plane has since replaced.
///
/// A changed cluster is rebuilt from scratch (`ClusterManager::update_from_snapshot`) with a new transport socket
/// (new TLS trust roots and client certificates) and new circuit-breaker gauges. Its name and addresses are often
/// unchanged, so a cache keyed on those alone would reuse a connection negotiated under the old settings. This id
/// is the part of the key that changes when the build does.
///
/// It is the identity of the build's `max_connections` gauge, the one per-build object reachable through
/// `ClusterEntry::circuit_breaker`. Every `ConnectPool` for a cluster clones that gauge, so they share one id, and a
/// carried-forward cluster keeps it across unrelated reloads.
///
/// Rust note: equality is `Arc::ptr_eq`, and the id holds a strong `Arc` clone. That stops an address from being
/// freed and reused by a later build while the old id is still in a map.
#[derive(Clone)]
pub struct ClusterBuildId(Arc<AtomicU32>);

impl ClusterBuildId {
    /// The id of the build that owns `breaker`. Pass the budget the cluster's pools charge dials to, or two builds
    /// can collide on one id.
    pub fn of(breaker: &CircuitBreakerState) -> Self {
        Self(breaker.connections_counter())
    }
}

impl PartialEq for ClusterBuildId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ClusterBuildId {}

impl Hash for ClusterBuildId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Must agree with `eq`: the address, never the counter's value, which
        // changes with every dial.
        Arc::as_ptr(&self.0).hash(state);
    }
}

impl fmt::Debug for ClusterBuildId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The derived `Debug` would print the gauge's live value, which says
        // nothing about which build this is.
        write!(f, "ClusterBuildId({:p})", Arc::as_ptr(&self.0))
    }
}

/// One pool per (worker, host, protocol) in the real design; v1 is just a
/// dialer for a single fixed address plus the cluster's transport socket.
pub struct ConnectPool {
    addr: SocketAddr,
    transport: Arc<dyn UpstreamTransportSocket>,
    /// The name for SNI and certificate verification: the configured DNS name if there is one, else the IP
    /// literal. See [`crate::Host::hostname`].
    server_name: String,
    /// `ClusterConfig::connect_timeout` (Envoy default 5s). One budget covers the TCP connect and the transport
    /// `wrap` (TLS handshake) together, as in Envoy's connecting window. A TCP-only timeout would let a peer that
    /// accepts the SYN and then stalls the handshake hold the connection forever.
    connect_timeout: Duration,
    /// The cluster's S5 `max_connections` and `max_pending_requests` budgets. A clone of the shared state, so every
    /// per-call pool counts against one global limit. `new_stream` parks a caller that cannot get a slot, holding a
    /// pending slot, until one frees or `connect_timeout` elapses.
    connections: CircuitBreakerState,
}

impl ConnectPool {
    pub fn new(
        addr: SocketAddr,
        transport: Arc<dyn UpstreamTransportSocket>,
        server_name: String,
        connect_timeout: Duration,
        connections: CircuitBreakerState,
    ) -> Self {
        Self {
            addr,
            transport,
            server_name,
            connect_timeout,
            connections,
        }
    }
}

/// Projects a failed `TcpStream::connect` onto a [`PoolError`]. Most failures are `ConnectFailure` (Envoy `UF`).
/// `ConnectionReset` and `ConnectionAborted` mean the peer accepted and then reset the connection, which is Envoy's
/// `UR`, so they map to `ResetBeforeHeaders`. The distinction changes retry behavior: a reset is retriable under
/// S3.2's `reset` policy, and a connect failure under `connect-failure`.
///
/// Rust note: `.kind()` matches on the `Copy` `ErrorKind`, leaving the `io::Error` owned for the `ConnectFailure`
/// arm, so its OS message survives.
fn classify_connect_error(err: std::io::Error) -> PoolError {
    match err.kind() {
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
            PoolError::ResetBeforeHeaders
        }
        _ => PoolError::ConnectFailure(err),
    }
}

impl HttpConnPool for ConnectPool {
    fn new_stream(&self) -> BoxFuture<'static, Result<UpstreamStream, PoolError>> {
        // Rust note: the returned future is `'static` and may outlive this call, so it cannot borrow `self`. Copy the
        // `Copy` fields out and clone the `Arc`s and `String`s into the `async move` block.
        let addr = self.addr;
        let transport = Arc::clone(&self.transport);
        let server_name = self.server_name.clone();
        let connect_timeout = self.connect_timeout;
        let connections = self.connections.clone();
        let has_handshake = self.transport.has_handshake();
        Box::pin(async move {
            // S5's `max_connections` and `max_pending_requests`: claim a connection slot before dialing, so an
            // over-budget cluster never opens a socket. A caller that loses the race parks in the pending queue until
            // a slot frees or the deadline passes. The guard releases the slot on any early `?` return, so a failed
            // dial does not leak budget.
            //
            // Rust note: acquire-or-park and dial share one `tokio::time::timeout`, so a park that never gets a slot
            // fails the same way as a dial that never connects. Envoy bounds a pending request by the request timeout,
            // not the connect timeout. This is an MVP simplification: a long request timeout with a short
            // `connect_timeout` sheds load here sooner than Envoy would.
            let (guard, connected, timing) = tokio::time::timeout(connect_timeout, async {
                let guard = match connections.try_acquire_connection() {
                    Some(guard) => guard,
                    None => {
                        // Saturated: park in the pending queue, which has its own bound (`max_pending_requests`), so
                        // a cluster that is fully connected and fully queued still overflows here.
                        let pending_guard = connections
                            .try_acquire_pending()
                            .ok_or(PoolError::Overflow)?;
                        let notify = connections.connections_notify();
                        let guard = loop {
                            // Rust note: arm `notified()` BEFORE re-checking `try_acquire_connection`. A slot released
                            // between the check and the arm would call `notify_one()` with no waiter, and that wakeup
                            // would be lost.
                            let notified = notify.notified();
                            tokio::pin!(notified);
                            if let Some(guard) = connections.try_acquire_connection() {
                                break guard;
                            }
                            notified.await;
                        };
                        // Holding an active connection slot now -- the
                        // pending slot served its purpose.
                        drop(pending_guard);
                        guard
                    }
                };
                // `US_CX_BEG` is taken after the slot, as Envoy starts its
                // connect timer only once the pool decides to dial.
                let connect_start = std::time::Instant::now();
                let tcp = tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(classify_connect_error)?;
                let connect_end = std::time::Instant::now();
                // Envoy sets `TCP_NODELAY` on every upstream connection. Without it, Nagle holds a small request
                // write until the upstream's delayed ACK arrives. A failure is logged and the connection is still
                // used, matching the dial in `proxy-core`'s `tcp_proxy`.
                if let Err(err) = tcp.set_nodelay(true) {
                    tracing::debug!(%addr, error = %err, "failed to set TCP_NODELAY on upstream socket");
                }
                let io = transport
                    .wrap(tcp, &server_name)
                    .await
                    .map_err(PoolError::TlsHandshake)?;
                let timing = crate::ConnectTiming {
                    connect_start: Some(connect_start),
                    connect_end: Some(connect_end),
                    handshake_end: has_handshake.then(std::time::Instant::now),
                };
                Ok((guard, io, timing))
            })
            .await
            .map_err(|_elapsed| PoolError::ConnectTimeout)??;
            Ok(UpstreamStream {
                io: connected,
                cb_guard: Some(guard),
                timing,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::RawTransportSocket;
    use std::io::ErrorKind;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Large enough that it never fires under normal test load, so it cannot cause a flake.
    const AMPLE_TIMEOUT: Duration = Duration::from_secs(30);

    #[test]
    fn classify_connect_error_splits_reset_from_plain_failure() {
        // A reset (half-)connection maps to `ResetBeforeHeaders` (Envoy `UR`), not `ConnectFailure`. This is the one
        // path that makes `PoolError::ResetBeforeHeaders` reachable from connect; see `classify_connect_error`.
        for kind in [ErrorKind::ConnectionReset, ErrorKind::ConnectionAborted] {
            match classify_connect_error(std::io::Error::from(kind)) {
                PoolError::ResetBeforeHeaders => {}
                other => panic!("expected ResetBeforeHeaders for {kind:?}, got {other}"),
            }
        }
        // Everything else stays a connect failure (Envoy `UF`) and carries
        // the original OS error through for the log line.
        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::HostUnreachable,
            ErrorKind::TimedOut,
        ] {
            match classify_connect_error(std::io::Error::from(kind)) {
                PoolError::ConnectFailure(io_err) => assert_eq!(io_err.kind(), kind),
                other => panic!("expected ConnectFailure for {kind:?}, got {other}"),
            }
        }
    }

    fn plaintext_pool(addr: SocketAddr) -> ConnectPool {
        ConnectPool::new(
            addr,
            Arc::new(RawTransportSocket),
            addr.ip().to_string(),
            AMPLE_TIMEOUT,
            CircuitBreakerState::default(),
        )
    }

    #[tokio::test]
    async fn new_stream_connects_to_the_configured_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pool = plaintext_pool(addr);

        let stream = pool.new_stream().await.expect("connect should succeed");
        let (mut accepted, _client_addr) = listener.accept().await.unwrap();

        // Prove the connection is actually live end-to-end, not just
        // notionally connected.
        let mut io = stream.io;
        io.write_all(b"x").await.unwrap();
        let mut buf = [0u8; 1];
        accepted.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, *b"x");
    }

    /// `US_CX_BEG`/`US_CX_END` come from the real dial, and a plaintext
    /// transport leaves `US_HS_END` unset.
    #[tokio::test]
    async fn new_stream_records_connect_timing_and_no_handshake_for_plaintext() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let before = std::time::Instant::now();
        let stream = plaintext_pool(addr).new_stream().await.unwrap();
        let timing = stream.timing;
        let start = timing.connect_start.expect("connect start recorded");
        let end = timing.connect_end.expect("connect end recorded");
        assert!(before <= start && start <= end, "{timing:?}");
        assert_eq!(timing.handshake_end, None);
    }

    /// A transport with a handshake gets `US_HS_END` after the handshake, not
    /// at the TCP connect: the slow handshake below must show up between them.
    #[tokio::test]
    async fn new_stream_records_handshake_end_after_a_handshaking_transport() {
        struct SlowHandshake;
        impl UpstreamTransportSocket for SlowHandshake {
            fn wrap(
                &self,
                io: tokio::net::TcpStream,
                _server_name: &str,
            ) -> BoxFuture<'static, std::io::Result<crate::BoxedUpstreamIo>> {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok(Box::new(io) as crate::BoxedUpstreamIo)
                })
            }
            fn has_handshake(&self) -> bool {
                true
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pool = ConnectPool::new(
            addr,
            Arc::new(SlowHandshake),
            addr.ip().to_string(),
            AMPLE_TIMEOUT,
            CircuitBreakerState::default(),
        );
        let timing = pool.new_stream().await.unwrap().timing;
        let connected = timing.connect_end.expect("connect end recorded");
        let handshaken = timing.handshake_end.expect("handshake end recorded");
        assert!(
            handshaken.duration_since(connected) >= Duration::from_millis(30),
            "{timing:?}"
        );
    }

    /// Records whether the dialled socket had `TCP_NODELAY` when the pool handed it to the transport, then passes
    /// it through as plaintext.
    struct NodelayProbe(std::sync::Mutex<Option<bool>>);

    impl UpstreamTransportSocket for NodelayProbe {
        fn wrap(
            &self,
            io: tokio::net::TcpStream,
            _server_name: &str,
        ) -> BoxFuture<'static, std::io::Result<crate::BoxedUpstreamIo>> {
            *self.0.lock().unwrap() = Some(io.nodelay().unwrap());
            Box::pin(async move { Ok(Box::new(io) as crate::BoxedUpstreamIo) })
        }
    }

    #[tokio::test]
    async fn new_stream_sets_nodelay_on_the_dialled_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let probe = Arc::new(NodelayProbe(std::sync::Mutex::new(None)));
        let pool = ConnectPool::new(
            addr,
            probe.clone(),
            addr.ip().to_string(),
            AMPLE_TIMEOUT,
            CircuitBreakerState::default(),
        );

        let _stream = pool.new_stream().await.expect("connect should succeed");
        let (accepted, _client_addr) = listener.accept().await.unwrap();

        assert!(
            !accepted.nodelay().unwrap(),
            "kernel default must be Nagle on"
        );
        assert_eq!(
            *probe.0.lock().unwrap(),
            Some(true),
            "upstream socket must have TCP_NODELAY"
        );
    }

    #[tokio::test]
    async fn new_stream_surfaces_connect_failure() {
        // Bind, learn the port, then drop the listener. Nothing listens there, so the connect is refused on loopback.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let pool = plaintext_pool(addr);
        match pool.new_stream().await {
            Err(PoolError::ConnectFailure(io_err)) => {
                assert_eq!(io_err.kind(), ErrorKind::ConnectionRefused);
            }
            Err(other) => panic!("expected ConnectFailure, got {other}"),
            Ok(_) => panic!("expected connect failure, nothing should be listening"),
        }
    }

    #[tokio::test]
    async fn transport_socket_handshake_failure_is_reported_separately() {
        // The transport fails on purpose. The TCP connect succeeds, so the error must come back as `TlsHandshake`,
        // not `ConnectFailure`.
        struct FailingTransport;
        impl UpstreamTransportSocket for FailingTransport {
            fn wrap(
                &self,
                _io: tokio::net::TcpStream,
                _server_name: &str,
            ) -> BoxFuture<'static, std::io::Result<crate::BoxedUpstreamIo>> {
                Box::pin(async { Err(std::io::Error::new(ErrorKind::InvalidData, "bad cert")) })
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pool = ConnectPool::new(
            addr,
            Arc::new(FailingTransport),
            "host".to_string(),
            AMPLE_TIMEOUT,
            CircuitBreakerState::default(),
        );

        match pool.new_stream().await {
            Err(PoolError::TlsHandshake(err)) => assert_eq!(err.kind(), ErrorKind::InvalidData),
            Err(other) => panic!("expected TlsHandshake, got {other}"),
            Ok(_) => panic!("handshake must fail"),
        }
    }

    #[tokio::test]
    async fn server_name_reaches_the_transport_socket() {
        // The SNI/verification name is the pool's contract with the transport
        // socket; assert it is actually threaded through rather than dropped.
        struct RecordingTransport(std::sync::Mutex<Option<String>>);
        impl UpstreamTransportSocket for RecordingTransport {
            fn wrap(
                &self,
                io: tokio::net::TcpStream,
                server_name: &str,
            ) -> BoxFuture<'static, std::io::Result<crate::BoxedUpstreamIo>> {
                *self.0.lock().unwrap() = Some(server_name.to_string());
                Box::pin(async move { Ok(Box::new(io) as crate::BoxedUpstreamIo) })
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let transport = Arc::new(RecordingTransport(std::sync::Mutex::new(None)));
        let pool = ConnectPool::new(
            addr,
            transport.clone(),
            "api.example.com".to_string(),
            AMPLE_TIMEOUT,
            CircuitBreakerState::default(),
        );

        pool.new_stream().await.expect("connect should succeed");
        assert_eq!(
            transport.0.lock().unwrap().as_deref(),
            Some("api.example.com")
        );
    }

    /// TEST-NET-1 (RFC 5737, `192.0.2.0/24`) is reserved for documentation and nothing routes it. A SYN there is
    /// dropped rather than refused, which gives a real blackhole for the timeout path. This differs from the
    /// bind-then-drop trick in `new_stream_surfaces_connect_failure`, where something answers with a refusal.
    ///
    /// Hermetic in practice, not by protocol: no DNS, no external host. It assumes the local routing table does not
    /// reject the destination before the timeout fires, which holds on macOS and Linux CI.
    const BLACKHOLE_ADDR: &str = "192.0.2.1:80";

    #[tokio::test]
    async fn new_stream_times_out_a_connect_that_never_completes() {
        let addr: SocketAddr = BLACKHOLE_ADDR.parse().unwrap();
        let short_timeout = Duration::from_millis(200);
        let pool = ConnectPool::new(
            addr,
            Arc::new(RawTransportSocket),
            "host".to_string(),
            short_timeout,
            CircuitBreakerState::default(),
        );

        let started = tokio::time::Instant::now();
        match pool.new_stream().await {
            Err(PoolError::ConnectTimeout) => {
                // Loose, one-sided bound: "took at least the configured timeout". Never a tight window.
                assert!(
                    started.elapsed() >= short_timeout,
                    "timeout fired before the configured duration elapsed"
                );
            }
            Err(other) => panic!("expected ConnectTimeout, got {other}"),
            Ok(_) => panic!("a blackholed address must never complete a connect"),
        }
    }

    #[tokio::test]
    async fn new_stream_times_out_a_handshake_that_never_completes() {
        // The transport's `wrap` never resolves, standing in for a TLS peer that completes TCP but stalls the
        // handshake. This proves the timeout covers `wrap`, not only the connect.
        struct HangingTransport;
        impl UpstreamTransportSocket for HangingTransport {
            fn wrap(
                &self,
                _io: tokio::net::TcpStream,
                _server_name: &str,
            ) -> BoxFuture<'static, std::io::Result<crate::BoxedUpstreamIo>> {
                Box::pin(std::future::pending())
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Keep the listener alive (accepting) for the duration of the test so
        // the TCP connect itself succeeds instantly and only `wrap` hangs.
        let _accept_task = tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let short_timeout = Duration::from_millis(200);
        let pool = ConnectPool::new(
            addr,
            Arc::new(HangingTransport),
            "host".to_string(),
            short_timeout,
            CircuitBreakerState::default(),
        );

        let started = tokio::time::Instant::now();
        match pool.new_stream().await {
            Err(PoolError::ConnectTimeout) => {
                assert!(
                    started.elapsed() >= short_timeout,
                    "timeout fired before the configured duration elapsed"
                );
            }
            Err(other) => panic!("expected ConnectTimeout, got {other}"),
            Ok(_) => panic!("a hanging transport socket must never resolve"),
        }
    }

    #[tokio::test]
    async fn max_connections_is_enforced_at_dial_and_released_on_drop() {
        // Acquire, reject at the limit, and release on drop, in one test. `max_pending_requests: 0` closes the parking
        // queue, so this tests `max_connections` alone and saturated connections overflow at once.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let one_connection = proxy_config::ir::CircuitBreakerThresholds {
            max_connections: 1,
            max_pending_requests: 0,
            ..proxy_config::ir::CircuitBreakerThresholds::ENVOY_DEFAULT
        };
        let pool = ConnectPool::new(
            addr,
            Arc::new(RawTransportSocket),
            addr.ip().to_string(),
            AMPLE_TIMEOUT,
            CircuitBreakerState::from_thresholds(one_connection),
        );

        let first = pool.new_stream().await.expect("first dial is under budget");
        let (_accepted1, _client_addr1) = listener.accept().await.unwrap();

        match pool.new_stream().await {
            Err(PoolError::Overflow) => {}
            Err(other) => panic!("expected Overflow, got {other}"),
            Ok(_) => panic!("second dial must be shed (max_connections is 1)"),
        }

        // Dropping the first connection's stream releases its `CbGuard`,
        // freeing the slot for a third dial.
        drop(first);
        let third = pool.new_stream().await;
        let (_accepted2, _client_addr2) = listener.accept().await.unwrap();
        third.expect("dial must succeed again once the slot was released");
    }

    /// Builds a pool with a `max_connections: 1, max_pending_requests: 1`
    /// budget -- the fixture shared by the parking-queue tests below.
    fn one_connection_one_pending(addr: SocketAddr, connect_timeout: Duration) -> ConnectPool {
        let thresholds = proxy_config::ir::CircuitBreakerThresholds {
            max_connections: 1,
            max_pending_requests: 1,
            ..proxy_config::ir::CircuitBreakerThresholds::ENVOY_DEFAULT
        };
        ConnectPool::new(
            addr,
            Arc::new(RawTransportSocket),
            addr.ip().to_string(),
            connect_timeout,
            CircuitBreakerState::from_thresholds(thresholds),
        )
    }

    #[tokio::test]
    async fn second_request_parks_then_completes_when_a_connection_slot_frees() {
        // With connections saturated and a pending slot free, a second request must PARK and then complete once the
        // first connection's guard drops.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pool = one_connection_one_pending(addr, AMPLE_TIMEOUT);

        let first = pool.new_stream().await.expect("first dial is under budget");
        let (_accepted1, _client_addr1) = listener.accept().await.unwrap();

        // Spawned so the main task can keep running while the second request parks.
        let second_handle = tokio::spawn(pool.new_stream());

        // Give it time to reach the parked state, so this exercises the park path and not a race that finished early.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !second_handle.is_finished(),
            "second request should still be parked while the only connection slot is held"
        );

        // Freeing the first connection must wake the parked waiter. The outer timeout turns a broken wakeup into a
        // failure, not a hang. Unwrap down to the `UpstreamStream` before touching `listener`: if the parked dial
        // failed, nothing is incoming, and `accept()` would add a second hang.
        drop(first);
        let second = tokio::time::timeout(AMPLE_TIMEOUT, second_handle)
            .await
            .expect("parked request must not hang once a slot frees")
            .expect("spawned task must not panic")
            .expect("parked dial must succeed once woken");
        let (_accepted2, _client_addr2) = listener.accept().await.unwrap();
        drop(second);
    }

    #[tokio::test]
    async fn third_concurrent_request_overflows_once_pending_queue_is_also_full() {
        // With connections and pending both saturated, a third request sheds at once with `Overflow`.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pool = one_connection_one_pending(addr, AMPLE_TIMEOUT);

        let first = pool.new_stream().await.expect("first dial is under budget");
        let (_accepted1, _client_addr1) = listener.accept().await.unwrap();

        let second_handle = tokio::spawn(pool.new_stream());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !second_handle.is_finished(),
            "second request should be parked, holding the one pending slot"
        );

        match pool.new_stream().await {
            Err(PoolError::Overflow) => {}
            Err(other) => panic!("expected Overflow, got {other}"),
            Ok(_) => panic!("third request must be shed once the pending queue is also full"),
        }

        // Free the connection so the parked request and its task do not outlive the test. Unwrap before touching
        // `listener`, as above.
        drop(first);
        let second = tokio::time::timeout(AMPLE_TIMEOUT, second_handle)
            .await
            .expect("parked second request must not hang")
            .expect("spawned task must not panic")
            .expect("second request must still succeed once freed");
        let (_accepted2, _client_addr2) = listener.accept().await.unwrap();
        drop(second);
    }

    #[tokio::test]
    async fn parked_request_times_out_if_a_connection_slot_never_frees() {
        // A parked request is bounded by `connect_timeout`, not left to wait forever.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let short_timeout = Duration::from_millis(200);
        let pool = one_connection_one_pending(addr, short_timeout);

        // Hold the only connection slot for the rest of the test -- never
        // dropped -- so the second request has nothing to wake it.
        let _first = pool.new_stream().await.expect("first dial is under budget");
        let (_accepted1, _client_addr1) = listener.accept().await.unwrap();

        let started = tokio::time::Instant::now();
        // The outer bound makes a regression to an unbounded park fail the test instead of hanging the suite.
        match tokio::time::timeout(Duration::from_secs(5), pool.new_stream()).await {
            Ok(Err(PoolError::ConnectTimeout)) => {
                assert!(
                    started.elapsed() >= short_timeout,
                    "timeout fired before the configured duration elapsed"
                );
            }
            Ok(Err(other)) => panic!("expected ConnectTimeout, got {other}"),
            Ok(Ok(_)) => panic!("a parked request with no freed slot must never succeed"),
            Err(_) => panic!(
                "parked request hung past the test's own outer bound -- connect_timeout \
                 did not fire for a parked waiter"
            ),
        }
    }
}
