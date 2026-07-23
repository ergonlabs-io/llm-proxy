//! v1 upstream HTTP connection pool (WP-15, first slice): connect-per-stream,
//! no reuse. [`Http1ConnectPool::new_stream`] dials a fresh plaintext TCP
//! connection for every call and hands the raw transport back as an
//! [`UpstreamStream`] -- the router runs the h1 codec over it. There is no
//! keep-alive reuse, no h2 multiplexing, and no circuit breakers yet; all of
//! that is WP-15 follow-up (see the `TODO(WP-15)` on [`UpstreamStream`]).

use std::net::SocketAddr;

use futures::future::BoxFuture;

use crate::{HttpConnPool, PoolError, UpstreamStream};

/// One pool per (worker, host, protocol) in the real design; v1 is just a
/// dialer for a single fixed address.
pub struct Http1ConnectPool {
    addr: SocketAddr,
}

impl Http1ConnectPool {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

impl HttpConnPool for Http1ConnectPool {
    fn new_stream(&self) -> BoxFuture<'static, Result<UpstreamStream, PoolError>> {
        // Rust note: the returned future is `'static` (it may outlive this
        // call, e.g. spawned onto a task), so it can't borrow `self`. Copy
        // `addr` out (`SocketAddr` is `Copy`) and move the copy into the
        // `async move` block instead.
        let addr = self.addr;
        Box::pin(async move {
            let io = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(PoolError::ConnectFailure)?;
            Ok(UpstreamStream { io })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn new_stream_connects_to_the_configured_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pool = Http1ConnectPool::new(addr);

        let stream = pool.new_stream().await.expect("connect should succeed");
        assert_eq!(stream.io.peer_addr().unwrap(), addr);
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

        let pool = Http1ConnectPool::new(addr);
        match pool.new_stream().await {
            Err(PoolError::ConnectFailure(io_err)) => {
                assert_eq!(io_err.kind(), ErrorKind::ConnectionRefused);
            }
            Err(other) => panic!("expected ConnectFailure, got {other}"),
            Ok(_) => panic!("expected connect failure, nothing should be listening"),
        }
    }
}
