//! Transport socket abstraction: raw TCP and TLS (rustls), selected by
//! filter-chain match. SDS-driven cert rotation swaps the resolver behind an
//! `ArcSwap` without touching established connections.

use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Object-safe byte-stream IO, produced by transport sockets.
pub trait AsyncIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncIo for T {}

pub type BoxedIo = Box<dyn AsyncIo>;

/// Upstream TLS parameters resolved from the cluster's `UpstreamTlsContext` IR.
/// TODO: SNI override, ALPN, validation context, client cert.
#[derive(Debug, Default)]
pub struct UpstreamTlsCtx {}

/// Factory selected by filter-chain matching (downstream) or cluster config
/// (upstream). Implementations: `RawBufferSocket`, `TlsDownstream`, `TlsUpstream`.
pub trait TransportSocketFactory: Send + Sync {
    /// Wrap an accepted downstream connection (e.g. run the TLS server handshake).
    fn wrap_downstream(&self, io: TcpStream) -> BoxFuture<'static, std::io::Result<BoxedIo>>;

    /// Wrap a new upstream connection (e.g. run the TLS client handshake).
    fn wrap_upstream(
        &self,
        io: TcpStream,
        ctx: &UpstreamTlsCtx,
    ) -> BoxFuture<'static, std::io::Result<BoxedIo>>;
}
