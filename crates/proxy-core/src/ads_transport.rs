//! The gRPC channel to the ADS control plane.
//!
//! The channel is built from the ADS cluster's own `transport_socket` (an `UpstreamTlsContext`), and TLS is originated
//! by the same [`UpstreamTlsFactory`]. Provider credentials travel in cluster headers, so a plaintext channel to a
//! remote control plane would expose them (architecture.md section 11, H7). Loading refuses that unless the operator
//! opts in (`envoy-divergences.md` row 33).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_util::rt::TokioIo;
use proxy_config::ir::{is_loopback_host, AdsConfig, ClusterConfig};
use tokio::net::TcpStream;
use tonic::codegen::Service;
use tonic::transport::{Channel, Endpoint, Uri};

use crate::tls::UpstreamTlsFactory;

/// How the channel reaches the control plane, for the startup log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdsTransport {
    /// TLS from the cluster's `transport_socket`. `server_verified` is false with no `validation_context`. Envoy then
    /// accepts any server certificate, and so does this channel.
    Tls { server_verified: bool },
    /// No `transport_socket`, and every endpoint is on this machine.
    PlaintextLoopback,
    /// No `transport_socket` to a remote control plane, which the operator
    /// allowed with `io.llmproxy.ads.allow_plaintext`. The caller must warn.
    PlaintextAllowed,
}

/// A lazily connected ADS channel and how it reaches the control plane.
pub struct AdsChannel {
    pub channel: Channel,
    pub transport: AdsTransport,
    /// `host:port` of the endpoint dialled, for logs.
    pub target: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AdsChannelError {
    #[error("ADS cluster `{0}` has no endpoints")]
    NoEndpoints(String),
    #[error("ADS cluster `{cluster}` address is not a valid URI: {reason}")]
    InvalidUri { cluster: String, reason: String },
    #[error("{0}")]
    Tls(String),
    #[error(
        "ADS cluster `{cluster}` would dial `{target}` in plaintext, which is not loopback \
         and io.llmproxy.ads.allow_plaintext is not set"
    )]
    PlaintextRefused { cluster: String, target: String },
}

/// Builds the channel to the first endpoint of `cluster`, connected lazily so a control plane that is down at boot
/// does not stop the proxy (the ADS client reconnects with backoff). `connect_timeout` bounds each dial.
///
/// Loading already refuses a plaintext channel unless `ads.allow_plaintext` is set. This re-checks it, so a gap in
/// that check fails closed instead of dialing.
pub fn ads_channel(
    cluster: &ClusterConfig,
    ads: &AdsConfig,
) -> Result<AdsChannel, AdsChannelError> {
    let endpoint = cluster
        .endpoints
        .first()
        .ok_or_else(|| AdsChannelError::NoEndpoints(cluster.name.clone()))?;
    let host = endpoint.host.clone();
    let port = endpoint.port;
    // An IPv6 literal needs brackets in a URI authority.
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let invalid_uri = |reason: String| AdsChannelError::InvalidUri {
        cluster: cluster.name.clone(),
        reason,
    };

    let Some(spec) = &cluster.transport_socket else {
        let transport = if cluster.endpoints.iter().all(|e| is_loopback_host(&e.host)) {
            AdsTransport::PlaintextLoopback
        } else if ads.allow_plaintext {
            AdsTransport::PlaintextAllowed
        } else {
            return Err(AdsChannelError::PlaintextRefused {
                cluster: cluster.name.clone(),
                target: authority,
            });
        };
        let channel = Endpoint::from_shared(format!("http://{authority}"))
            .map_err(|e| invalid_uri(e.to_string()))?
            .connect_timeout(cluster.connect_timeout)
            .connect_lazy();
        return Ok(AdsChannel {
            channel,
            transport,
            target: authority,
        });
    };

    // gRPC runs over HTTP/2 whatever the cluster's `upstream_protocol` says,
    // so offer `h2` unless the operator configured ALPN explicitly.
    let h2 = ["h2".to_string()];
    let alpn = spec.alpn_protocols.is_empty().then_some(&h2[..]);
    let context = format!("ADS cluster `{}` transport_socket", cluster.name);
    let factory = UpstreamTlsFactory::build_with_alpn(spec, alpn, &context)
        .map_err(|e| AdsChannelError::Tls(e.to_string()))?;
    let connector = TlsConnector {
        factory: Arc::new(factory),
        host,
        port,
        cluster: cluster.name.clone(),
    };
    // tonic only uses the URI for the `:scheme` and `:authority` pseudo
    // headers here; the connector below does the dialling and TLS.
    let channel = Endpoint::from_shared(format!("https://{authority}"))
        .map_err(|e| invalid_uri(e.to_string()))?
        .connect_timeout(cluster.connect_timeout)
        .connect_with_connector_lazy(connector);
    Ok(AdsChannel {
        channel,
        transport: AdsTransport::Tls {
            server_verified: spec.validation.is_some(),
        },
        target: authority,
    })
}

/// Dials the ADS endpoint and originates TLS on it.
///
/// Rust note: tonic accepts any `tower::Service<Uri>` yielding a `hyper::rt::Read + Write` stream. `TokioIo` adapts
/// tokio's `AsyncRead` and `AsyncWrite` to hyper's traits.
#[derive(Clone)]
struct TlsConnector {
    factory: Arc<UpstreamTlsFactory>,
    host: String,
    port: u16,
    cluster: String,
}

type TlsIo = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;

impl Service<Uri> for TlsConnector {
    type Response = TlsIo;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<TlsIo>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let tcp = TcpStream::connect((this.host.as_str(), this.port)).await?;
            tcp.set_nodelay(true)?;
            match this.factory.wrap(tcp, &this.host).await {
                Ok(tls) => Ok(TokioIo::new(tls)),
                Err(error) => {
                    // tonic reports a failed connect as a bare "transport error", so name the TLS cause here. An operator
                    // with a wrong CA would otherwise see only reconnects. The reconnect backoff bounds how often this logs.
                    tracing::warn!(
                        cluster = %this.cluster,
                        target = %format!("{}:{}", this.host, this.port),
                        %error,
                        "ADS TLS handshake with the control plane failed"
                    );
                    Err(error)
                }
            }
        })
    }
}
