//! v1 upstream connection pool (WP-15, first slice): connect-per-stream, no
//! reuse. [`ConnectPool::new_stream`] dials a fresh TCP connection for every
//! call, hands it to the cluster's transport socket (plaintext passthrough or
//! a TLS handshake), and returns the resulting byte stream as an
//! [`UpstreamStream`] -- the router runs the h1/h2 codec over it.
//!
//! There is no keep-alive reuse, no h2 multiplexing, and no connection-level
//! circuit breaking yet; all of that is WP-15 follow-up (see the `TODO(WP-15)`
//! on [`UpstreamStream`]). The pool is protocol-agnostic: it produces bytes,
//! and the router picks the codec from the cluster's `upstream_protocol`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;

use crate::transport::UpstreamTransportSocket;
use crate::{HttpConnPool, PoolError, UpstreamStream};

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
}

impl ConnectPool {
    pub fn new(
        addr: SocketAddr,
        transport: Arc<dyn UpstreamTransportSocket>,
        server_name: String,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            addr,
            transport,
            server_name,
            connect_timeout,
        }
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
        Box::pin(async move {
            // Rust note: `tokio::time::timeout` races the given future
            // against a deadline and returns `Err(Elapsed)` if the deadline
            // wins; it does not cancel/abort anything on its own, but
            // dropping the future it was racing (which happens here, since
            // we never poll it again) drops the in-flight `connect`/`wrap`
            // and releases its resources -- same as any other dropped
            // future in Rust's async model.
            let connected = tokio::time::timeout(connect_timeout, async {
                let tcp = tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(PoolError::ConnectFailure)?;
                let io = transport
                    .wrap(tcp, &server_name)
                    .await
                    .map_err(PoolError::TlsHandshake)?;
                Ok(io)
            })
            .await
            .map_err(|_elapsed| PoolError::ConnectTimeout)??;
            Ok(UpstreamStream { io: connected })
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

    fn plaintext_pool(addr: SocketAddr) -> ConnectPool {
        ConnectPool::new(
            addr,
            Arc::new(RawTransportSocket),
            addr.ip().to_string(),
            AMPLE_TIMEOUT,
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
}
