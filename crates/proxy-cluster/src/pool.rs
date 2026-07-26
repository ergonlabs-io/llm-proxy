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
}

impl ConnectPool {
    pub fn new(
        addr: SocketAddr,
        transport: Arc<dyn UpstreamTransportSocket>,
        server_name: String,
    ) -> Self {
        Self {
            addr,
            transport,
            server_name,
        }
    }
}

impl HttpConnPool for ConnectPool {
    fn new_stream(&self) -> BoxFuture<'static, Result<UpstreamStream, PoolError>> {
        // Rust note: the returned future is `'static` (it may outlive this
        // call, e.g. spawned onto a task), so it can't borrow `self`. Copy
        // `addr` out (`SocketAddr` is `Copy`) and clone the `Arc`/`String`
        // into the `async move` block instead.
        let addr = self.addr;
        let transport = Arc::clone(&self.transport);
        let server_name = self.server_name.clone();
        Box::pin(async move {
            let tcp = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(PoolError::ConnectFailure)?;
            let io = transport
                .wrap(tcp, &server_name)
                .await
                .map_err(PoolError::TlsHandshake)?;
            Ok(UpstreamStream { io })
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

    fn plaintext_pool(addr: SocketAddr) -> ConnectPool {
        ConnectPool::new(addr, Arc::new(RawTransportSocket), addr.ip().to_string())
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
        let pool = ConnectPool::new(addr, Arc::new(FailingTransport), "host".to_string());

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
        let pool = ConnectPool::new(addr, transport.clone(), "api.example.com".to_string());

        pool.new_stream().await.expect("connect should succeed");
        assert_eq!(
            transport.0.lock().unwrap().as_deref(),
            Some("api.example.com")
        );
    }
}
