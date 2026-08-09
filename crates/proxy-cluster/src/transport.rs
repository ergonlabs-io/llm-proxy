//! Upstream transport sockets: what a cluster's connection pool wraps a
//! freshly-dialed TCP connection in before the HTTP codec runs over it.
//!
//! # Why the trait lives here and the TLS implementation doesn't
//!
//! The rustls machinery (crypto provider, cert resolvers, the Envoy-parity
//! verifiers) lives in `proxy-core::tls`, and `proxy-core` already depends on
//! this crate -- so `proxy-cluster` cannot reach up to it without a
//! dependency cycle. The standard Rust answer is to invert the dependency:
//! the *consumer* (this crate) declares the [`UpstreamTransportSocket`] trait,
//! and the *implementor* (`proxy-core`) provides it. The cluster manager is
//! then handed a [`TransportSocketBuilder`] at construction time, which is
//! the single injection point for "how do I turn an `UpstreamTlsSpec` into a
//! working TLS originator".
//!
//! This also matches the plan's `TransportSocketFactory` seam
//! (IMPLEMENTATION_PLAN §1.1) and Envoy's own layering, where transport
//! sockets sit *below* clusters.

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
    /// `server_name` is the endpoint's DNS name (see [`crate::Host::hostname`]),
    /// falling back to the IP literal for `STATIC` clusters. TLS uses it as
    /// the SNI / verification name unless the config sets an explicit `sni`;
    /// the plaintext socket ignores it entirely.
    ///
    /// Rust note: the returned future is `'static` so a pool can move it into
    /// a task -- implementations clone the (cheap, `Arc`-backed) state they
    /// need out of `&self` rather than borrowing it.
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

/// The default builder: plaintext clusters work, and a cluster that actually
/// configures upstream TLS is **rejected** rather than silently downgraded to
/// cleartext.
///
/// That refusal is the point. Ground rule #1 says a configured field must
/// never be silently ignored, and "you asked for TLS, you got plaintext to
/// port 443" is the worst possible way to ignore one. Production installs the
/// real builder from `proxy-core`; this fallback exists so `proxy-cluster`'s
/// own tests (and any embedder that forgets to install one) fail loudly.
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
        // Rust note: not `.expect_err(...)` -- that requires `T: Debug`
        // (here, `Arc<dyn UpstreamTransportSocket>`, which isn't and
        // shouldn't be `Debug`), so match instead.
        let err = match reject_tls_builder()(&config) {
            Err(err) => err,
            Ok(_) => panic!("TLS must not silently downgrade"),
        };
        assert!(err.to_string().contains("secure"), "{err}");
    }
}
