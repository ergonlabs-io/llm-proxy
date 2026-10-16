//! Upstream transport sockets: what a cluster's connection pool wraps a freshly dialed TCP connection in before the
//! HTTP codec runs over it.
//!
//! The rustls machinery (crypto provider, cert resolvers, Envoy-parity verifiers) lives in `proxy-core::tls`, and
//! `proxy-core` already depends on this crate, so this crate cannot reach up to it without a cycle. The dependency is
//! inverted: this crate declares [`UpstreamTransportSocket`], and `proxy-core` implements it. The cluster manager takes
//! a [`TransportSocketBuilder`] at construction as the single injection point for TLS.

use std::io;
use std::sync::Arc;

use futures::future::BoxFuture;
use proxy_config::ir::ClusterConfig;
use tokio::net::TcpStream;

use crate::BoxedUpstreamIo;

/// Wraps a connected TCP stream in whatever the cluster's `transport_socket`
/// configures. One instance per cluster, shared by every worker (`Send +
/// Sync`, built on the control runtime alongside the cluster itself).
pub trait UpstreamTransportSocket: Send + Sync {
    /// `server_name` is the endpoint's DNS name (see [`crate::Host::hostname`]), or the IP literal for `STATIC`. TLS
    /// uses it as the SNI and verification name unless the config sets `sni`. Plaintext ignores it.
    ///
    /// Rust note: the returned future is `'static`, so a pool can move it into a task. Implementations clone their
    /// `Arc`-backed state out of `&self`.
    fn wrap(
        &self,
        io: TcpStream,
        server_name: &str,
    ) -> BoxFuture<'static, io::Result<BoxedUpstreamIo>>;
}

/// Plaintext: hand the TCP stream straight through. Used by every cluster
/// with no `transport_socket` configured.
pub struct RawTransportSocket;

impl UpstreamTransportSocket for RawTransportSocket {
    fn wrap(
        &self,
        io: TcpStream,
        _server_name: &str,
    ) -> BoxFuture<'static, io::Result<BoxedUpstreamIo>> {
        Box::pin(async move { Ok(Box::new(io) as BoxedUpstreamIo) })
    }
}

/// Failure to build a cluster's transport socket from its config (bad
/// certificate PEM, unsupported TLS parameters, ...). Carries a
/// human-readable reason that already names the offending cluster/field --
/// the builder is on the `proxy-core` side, which owns that context.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TransportSocketError(pub String);

/// How the cluster manager turns a `ClusterConfig` into a transport socket.
/// `proxy-core` installs the real one (plaintext, or rustls from
/// `ClusterConfig::transport_socket`); [`reject_tls_builder`] is the default
/// for anyone who doesn't.
pub type TransportSocketBuilder = Arc<
    dyn Fn(&ClusterConfig) -> Result<Arc<dyn UpstreamTransportSocket>, TransportSocketError>
        + Send
        + Sync,
>;

/// The default builder: plaintext clusters work, and a cluster that configures upstream TLS is **rejected**, not
/// downgraded to cleartext. AGENTS.md invariant 1 forbids silently ignoring a configured field, and "TLS requested,
/// plaintext sent" is the worst way to ignore one. Production installs the real builder from `proxy-core`.
pub fn reject_tls_builder() -> TransportSocketBuilder {
    Arc::new(|config: &ClusterConfig| {
        if config.transport_socket.is_some() {
            return Err(TransportSocketError(format!(
                "cluster `{}` configures a transport_socket (upstream TLS), but no \
                 transport-socket builder is installed; refusing to fall back to plaintext",
                config.name
            )));
        }
        Ok(Arc::new(RawTransportSocket) as Arc<dyn UpstreamTransportSocket>)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn cluster(name: &str) -> ClusterConfig {
        ClusterConfig {
            // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
            eds: None,
            name: name.to_string(),
            discovery: proxy_config::ir::DiscoveryType::Static,
            lb_policy: proxy_config::ir::LbPolicy::RoundRobin,
            connect_timeout: std::time::Duration::from_secs(5),
            endpoints: Vec::new(),
            kind: proxy_config::ir::ClusterKind::Endpoints,
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1 << 20,
            circuit_breakers: Default::default(),
            upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
            request_headers_to_add: Vec::new(),
            usage_dialect: None,
            request_path_rewrite: None,
            provider_runtime: None,
            health_check: None,
            outlier_detection: None,
        }
    }

    #[tokio::test]
    async fn raw_transport_socket_passes_bytes_through() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        let mut wrapped = RawTransportSocket.wrap(client, "ignored").await.unwrap();
        wrapped.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn default_builder_accepts_plaintext_clusters() {
        assert!(reject_tls_builder()(&cluster("plain")).is_ok());
    }

    #[test]
    fn default_builder_refuses_to_downgrade_a_tls_cluster() {
        let mut config = cluster("secure");
        config.transport_socket = Some(proxy_config::ir::UpstreamTlsSpec {
            sni: Some("example.com".to_string()),
            params: proxy_config::ir::TlsParametersIR {
                min_version: proxy_config::ir::TlsVersion::V1_2,
                max_version: proxy_config::ir::TlsVersion::V1_2,
                cipher_suites: Vec::new(),
                ecdh_curves: Vec::new(),
            },
            alpn_protocols: Vec::new(),
            client_certificate: None,
            validation: None,
        });
        // Rust note: `expect_err` needs `T: Debug`, which `Arc<dyn UpstreamTransportSocket>` lacks, so match instead.
        let err = match reject_tls_builder()(&config) {
            Err(err) => err,
            Ok(_) => panic!("TLS must not silently downgrade"),
        };
        assert!(err.to_string().contains("secure"), "{err}");
    }
}
