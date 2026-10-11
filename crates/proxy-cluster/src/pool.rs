//! v1 upstream connection pool: connect-per-stream, no
//! reuse. [`ConnectPool::new_stream`] dials a fresh TCP connection for every
//! call, hands it to the cluster's transport socket (plaintext passthrough or
//! a TLS handshake), and returns the resulting byte stream as an
//! [`UpstreamStream`] -- the router runs the h1/h2 codec over it.
//!
//! There is no keep-alive reuse, no h2 multiplexing, and no connection-level
//! circuit breaking yet; all of that is follow-up work (see the `TODO`
//! on [`UpstreamStream`]). The pool is protocol-agnostic: it produces bytes,
//! and the router picks the codec from the cluster's `upstream_protocol`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;

use crate::transport::UpstreamTransportSocket;
use crate::{CircuitBreakerState, HttpConnPool, PoolError, UpstreamStream};

/// One pool per (worker, host, protocol) in the real design; v1 is just a
/// dialer for a single fixed address plus the cluster's transport socket.
pub struct ConnectPool {
    addr: SocketAddr,
    transport: Arc<dyn UpstreamTransportSocket>,
    /// The name handed to the transport socket for SNI / certificate
    /// verification: the endpoint's configured DNS name where there is one,
    /// otherwise the IP literal. See [`crate::Host::hostname`].
    server_name: String,
    /// `ClusterConfig::connect_timeout` (Envoy default 5s). Bounds the
    /// *whole* job of getting a usable upstream connection: the TCP connect
    /// AND the transport socket's `wrap` (TLS handshake), as one shared
    /// budget rather than one timeout per phase.
    ///
    /// Envoy's own `connect_timeout` is documented as the time allowed to
    /// establish a connection, and Envoy's transport-socket handshake runs
    /// inside that same connecting window (`ConnectionImpl` doesn't start a
    /// second timer for the TLS handshake) -- so a single budget spanning
    /// both phases here matches Envoy's semantics, not just the easiest
    /// implementation. A slow-loris TLS peer that completes the TCP SYN/ACK
    /// instantly but never finishes the handshake would sail past a
    /// TCP-only timeout; wrapping both phases in the same deadline closes
    /// that gap.
    connect_timeout: Duration,
    /// The cluster's S5 `max_connections` AND `max_pending_requests` budgets.
    /// A whole [`CircuitBreakerState`] clone, not a borrow -- it
    /// shares the same underlying gauge (`CircuitBreakerState` is
    /// `Clone`-and-shared, see its own doc), so every per-call `ConnectPool`
    /// built for a cluster (`ClusterHandle::http_pool` makes a fresh one per
    /// call) still enforces one global count. `new_stream` uses both: a
    /// caller that can't get a connection slot right away parks, holding a
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

/// Project a failed `TcpStream::connect` onto the right [`PoolError`].
///
/// Almost every connect failure is a genuine "never got a connection" and
/// maps to [`PoolError::ConnectFailure`] -> Envoy `UF` (connection refused,
/// host unreachable, timeout surfaced as an error, ...). Two kinds are
/// different: `ConnectionReset` (`ECONNRESET`) and `ConnectionAborted`
/// (`ECONNABORTED`) mean the peer accepted or half-accepted the connection
/// and then *reset* it, rather than never answering -- which is Envoy's `UR`
/// (upstream remote reset), not `UF`. Splitting them out is what finally
/// *constructs* [`PoolError::ResetBeforeHeaders`]: the variant, its
/// `from_pool_error` -> `ResetBeforeHeaders` mapping, and the router arm that
/// turns it into `UR` all already existed, but nothing produced it, so a
/// connect-time reset reported `UF`. A reset before any response headers is
/// retriable under S3.2's `reset`, whereas a plain connect failure is
/// retriable under `connect-failure` -- so the distinction changes retry
/// behaviour, not only the logged flag.
///
/// Rust note: `io::Error` is matched on its `ErrorKind` (a `Copy` enum) via
/// `.kind()`, leaving the original error owned to move into the
/// `ConnectFailure` arm unchanged -- so the `{0}` in `PoolError`'s `#[error]`
/// still carries the OS message.
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
        // Rust note: the returned future is `'static` (it may outlive this
        // call, e.g. spawned onto a task), so it can't borrow `self`. Copy
        // `addr`/`connect_timeout` out (both `Copy`) and clone the
        // `Arc`/`String` into the `async move` block instead.
        let addr = self.addr;
        let transport = Arc::clone(&self.transport);
        let server_name = self.server_name.clone();
        let connect_timeout = self.connect_timeout;
        let connections = self.connections.clone();
        Box::pin(async move {
            // S5's `max_connections` and `max_pending_requests`: a
            // connection slot is claimed before the dial so an over-budget
            // cluster never opens the socket, but a caller that loses that
            // race no longer overflows immediately -- it parks, holding a
            // pending-queue slot, until either a slot frees or the deadline
            // below elapses. `CbGuard` is `Send + 'static`, so it's fine to
            // hold across the `.await`s here; if anything after acquiring it
            // returns early via `?` (connect/handshake failure, timeout),
            // the guard drops right there and releases the slot -- exactly
            // the "failed dial doesn't leak budget" behaviour this exists
            // for.
            //
            // Rust note: the whole "acquire-or-park, then dial" job runs
            // inside one `tokio::time::timeout`, so a park that never gets a
            // slot fails through the exact same path as a dial that never
            // connects -- `PoolError::ConnectTimeout`, not a new variant.
            // This is a deliberate MVP simplification: Envoy bounds a
            // pending request by the *request* timeout, not the connect
            // timeout, so a request configured with a long request timeout
            // but a short `connect_timeout` will shed load here sooner than
            // Envoy would. Flagged for later work, not a gap anyone
            // is meant to rely on.
            let (guard, connected) = tokio::time::timeout(connect_timeout, async {
                let guard = match connections.try_acquire_connection() {
                    Some(guard) => guard,
                    None => {
                        // Saturated: try to park instead of shedding
                        // immediately. This acquire has its own bound
                        // (`max_pending_requests`), so a cluster that's both
                        // fully connected AND fully queued still overflows
                        // right here rather than growing an unbounded
                        // waiter list.
                        let pending_guard = connections
                            .try_acquire_pending()
                            .ok_or(PoolError::Overflow)?;
                        let notify = connections.connections_notify();
                        let guard = loop {
                            // Rust note: `notify.notified()` must be created
                            // (armed) BEFORE re-checking
                            // `try_acquire_connection`, not after. If we
                            // checked first and only then armed `notified`,
                            // a slot released in between the two would call
                            // `notify_one()` while nobody was listening yet
                            // -- that wakeup is simply lost, and we'd wait
                            // for a release that already happened.
                            // Registering the waiter first means any release
                            // from this point onward is guaranteed to
                            // resolve `notified`.
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
                let tcp = tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(classify_connect_error)?;
                let io = transport
                    .wrap(tcp, &server_name)
                    .await
                    .map_err(PoolError::TlsHandshake)?;
                Ok((guard, io))
            })
            .await
            .map_err(|_elapsed| PoolError::ConnectTimeout)??;
            Ok(UpstreamStream {
                io: connected,
                cb_guard: Some(guard),
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

    /// A generous timeout for tests that expect to succeed quickly -- large
    /// enough that it never fires under normal test-machine load, so it
    /// can't be the reason a non-timeout test flakes.
    const AMPLE_TIMEOUT: Duration = Duration::from_secs(30);

    #[test]
    fn classify_connect_error_splits_reset_from_plain_failure() {
        // A peer that reset the (half-)connection -> `ResetBeforeHeaders`
        // (Envoy `UR`), NOT `ConnectFailure`. This is the one behaviour that
        // makes `PoolError::ResetBeforeHeaders` reachable at all from the
        // connect path -- see `classify_connect_error`'s own doc.
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

    #[tokio::test]
    async fn new_stream_surfaces_connect_failure() {
        // Bind a listener, learn its address, then drop it so nothing is
        // listening there -- reliably refused on loopback rather than
        // relying on a "probably unused" fixed port.
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
        // A transport socket that always fails stands in for a TLS handshake
        // that can't complete: the TCP connect succeeded, so the error must
        // come back as `TlsHandshake`, not `ConnectFailure`.
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

    /// TEST-NET-1 (RFC 5737, `192.0.2.0/24`) is reserved for documentation:
    /// nothing routes it, so a SYN sent there is silently dropped rather than
    /// answered with an RST -- the "blackhole" a connect-timeout test needs,
    /// as opposed to a refused connect (which returns immediately and proves
    /// nothing about the timeout path). This is deliberately NOT the same
    /// trick `new_stream_surfaces_connect_failure` uses (bind-then-drop),
    /// which resolves fast because something *did* answer, just with a
    /// refusal.
    ///
    /// Hermeticity: this makes no real network trip -- `192.0.2.0/24` is
    /// non-forwarded per RFC 5737 and the kernel routes the SYN out but
    /// nothing on the link ever responds, so there's no DNS lookup and no
    /// dependency on an external host being reachable. The residual
    /// assumption is that the test host's own network stack doesn't
    /// immediately reject the destination as unreachable (e.g. "no route to
    /// host") before the timeout fires; that has held on both macOS and
    /// Linux CI in this repo's experience, but it is a property of the local
    /// routing table, not a guarantee, so this is "hermetic in practice",
    /// not "hermetic by protocol".
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
                // Loose, one-sided bound: "took at least the configured
                // timeout", never a tight window -- this repo has already
                // lost a session to a test misdiagnosed as timing-flaky.
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
        // A transport socket whose `wrap` never resolves stands in for a TLS
        // peer that completes the TCP handshake but stalls the handshake
        // itself (slow-loris) -- proving the timeout budget covers `wrap`,
        // not just `TcpStream::connect`.
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
        // S5's `max_connections`: a cluster with a budget of 1 must
        // reject a second concurrent dial with `PoolError::Overflow`, and
        // must accept a new dial again once the first connection is dropped
        // -- acquire, reject-at-limit, and release-on-drop, in one test.
        //
        // `max_pending_requests: 0` here is deliberate: this test is about
        // `max_connections` specifically, not the parking queue (that's
        // `second_request_parks_...` and friends, below), so it closes the
        // pending queue to keep the old "saturated connections overflow
        // immediately" behaviour rather than parking.
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
        // With the connection budget saturated but a pending slot
        // free, a second concurrent request must PARK rather than overflow
        // immediately, and must complete once the first connection's
        // `CbGuard` drops and wakes it.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pool = one_connection_one_pending(addr, AMPLE_TIMEOUT);

        let first = pool.new_stream().await.expect("first dial is under budget");
        let (_accepted1, _client_addr1) = listener.accept().await.unwrap();

        // Spawn so the main task can keep running while the second request
        // parks -- `new_stream()`'s returned future is already `'static`
        // and boxed, so it can be handed to `tokio::spawn` directly without
        // moving `pool` itself.
        let second_handle = tokio::spawn(pool.new_stream());

        // Give it a moment to actually reach the parked state, then confirm
        // it's still pending -- proving this exercises the park path rather
        // than a lucky race where it happened to finish first.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !second_handle.is_finished(),
            "second request should still be parked while the only connection slot is held"
        );

        // Freeing the held connection's `CbGuard` must wake the parked
        // waiter -- bound the join with an outer timeout so a broken wakeup
        // fails the test instead of hanging it. Unwrap all the way down to
        // the `UpstreamStream` BEFORE touching `listener` again: if the
        // parked dial never actually happened (e.g. it failed instead of
        // succeeding), there's nothing incoming for `accept()` to receive,
        // and calling it first would trade a clear assertion failure for a
        // second, unrelated hang.
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
        // Connections AND pending both saturated (1 held, 1 parked)
        // must shed a third concurrent request immediately with
        // `PoolError::Overflow`, not grow the waiter list further.
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

        // Clean up: free the connection so the parked second request (and
        // its background task) don't outlive the test. Unwrap fully before
        // touching `listener` again -- see the sibling test's comment on
        // why that ordering matters.
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
        // A parked request is bounded by `connect_timeout`, not left to
        // wait forever -- see `new_stream`'s doc for why `connect_timeout`
        // rather than a request timeout is the (deliberately stricter) MVP
        // bound.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let short_timeout = Duration::from_millis(200);
        let pool = one_connection_one_pending(addr, short_timeout);

        // Hold the only connection slot for the rest of the test -- never
        // dropped -- so the second request has nothing to wake it.
        let _first = pool.new_stream().await.expect("first dial is under budget");
        let (_accepted1, _client_addr1) = listener.accept().await.unwrap();

        let started = tokio::time::Instant::now();
        // Outer bound is defensive only: if the implementation regresses
        // back to an unbounded park, fail the test instead of hanging the
        // suite (nextest's `terminate-after` would otherwise be what
        // catches this, minutes later).
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
