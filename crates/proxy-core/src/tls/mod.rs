//! Compiled TLS transport sockets (WP-08 chunks B1+B2): builds `rustls`
//! `ServerConfig`/`ClientConfig` straight from the WP-08 chunk A IR
//! (`DownstreamTlsSpec`/`UpstreamTlsSpec`), one factory per filter chain /
//! cluster. This module never sees Envoy protos -- ground rule #2 -- and
//! never silently drops a configured field -- ground rule #1: every
//! `ValidationContextIR` field (`ca`, `san_matchers`,
//! `allow_expired_certificate`) is honored by the verifiers in [`verify`].
//!
//! Split into:
//! - this file: crypto-provider construction (versions/suites/curves) and
//!   the two public factories.
//! - [`resolver`]: certificate loading + the hot-swappable cert resolver.
//! - [`verify`]: the custom `ServerCertVerifier`/`ClientCertVerifier`
//!   wrappers Envoy parity needs (hostname bypass, SAN matchers,
//!   `allow_expired_certificate`).

mod resolver;
mod verify;

use std::io;
use std::sync::Arc;

use futures::future::BoxFuture;
use proxy_cluster::transport::UpstreamTransportSocket;
use proxy_cluster::BoxedUpstreamIo;
use proxy_config::ir::{
    CaSource, ClusterConfig, DownstreamTlsSpec, TlsCertificateIR, TlsCipherSuite, TlsEcdhCurve,
    TlsParametersIR, TlsVersion, UpstreamProtocol, UpstreamTlsSpec,
};
use rustls::crypto::ring::{cipher_suite, kx_group};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::server::{ResolvesServerCert, WebPkiClientVerifier};
use rustls::{version, ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use resolver::SwapCertResolver;
use verify::{
    clone_san_matchers, AcceptAnyServerCert, CarveoutClientCertVerifier,
    HostnameBypassServerCertVerifier,
};

/// Error building a TLS factory from IR. `context` is caller-supplied (e.g.
/// `listener 'x' filter_chains[0]`) -- ground rule #1's "where" for the parts
/// of config-loading that happen after IR conversion, at socket build time.
#[derive(Debug, thiserror::Error)]
#[error("TLS config error in {context}: {reason}")]
pub struct TlsBuildError {
    pub context: String,
    pub reason: String,
}

impl TlsBuildError {
    fn new(context: &str, reason: impl Into<String>) -> Self {
        Self {
            context: context.to_string(),
            reason: reason.into(),
        }
    }
}

// --------------------------------------------------------- crypto provider --

// Rust note: these need to be named `static`s (not inline `&[...]` literals in
// the `match` arms below) so the compiler can see they live for `'static` --
// an array of `&'static` references isn't automatically promoted when it's
// built as a temporary inside a function body.
static VERSIONS_V12: &[&rustls::SupportedProtocolVersion] = &[&version::TLS12];
static VERSIONS_V13: &[&rustls::SupportedProtocolVersion] = &[&version::TLS13];
static VERSIONS_BOTH: &[&rustls::SupportedProtocolVersion] = &[&version::TLS13, &version::TLS12];

/// `&[&SupportedProtocolVersion]` for `min_version..=max_version`. Rust note:
/// rustls builders take a slice of *enabled* versions, not a min/max pair, so
/// this expands the IR's inclusive range into that list.
fn protocol_versions(
    params: &TlsParametersIR,
) -> &'static [&'static rustls::SupportedProtocolVersion] {
    match (params.min_version, params.max_version) {
        (TlsVersion::V1_2, TlsVersion::V1_2) => VERSIONS_V12,
        (TlsVersion::V1_3, TlsVersion::V1_3) => VERSIONS_V13,
        // V1_2..=V1_3 (or an inverted range, which lowering already rejects).
        _ => VERSIONS_BOTH,
    }
}

fn map_cipher_suite(suite: TlsCipherSuite) -> rustls::SupportedCipherSuite {
    match suite {
        TlsCipherSuite::EcdheEcdsaAes128GcmSha256 => {
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        }
        TlsCipherSuite::EcdheRsaAes128GcmSha256 => {
            cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        }
        TlsCipherSuite::EcdheEcdsaAes256GcmSha384 => {
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        }
        TlsCipherSuite::EcdheRsaAes256GcmSha384 => {
            cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        }
        TlsCipherSuite::EcdheEcdsaChacha20Poly1305 => {
            cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        }
        TlsCipherSuite::EcdheRsaChacha20Poly1305 => {
            cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        }
    }
}

fn map_ecdh_curve(curve: TlsEcdhCurve) -> &'static dyn rustls::crypto::SupportedKxGroup {
    match curve {
        TlsEcdhCurve::X25519 => kx_group::X25519,
        TlsEcdhCurve::P256 => kx_group::SECP256R1,
        TlsEcdhCurve::P384 => kx_group::SECP384R1,
    }
}

/// Build the `CryptoProvider` a `TlsParametersIR` implies. Empty
/// `cipher_suites`/`ecdh_curves` mean "ring's defaults"; non-empty means a
/// preference-ordered custom list -- see the module doc on TLS 1.3 suites
/// never being filtered.
fn build_crypto_provider(params: &TlsParametersIR) -> CryptoProvider {
    let default = rustls::crypto::ring::default_provider();

    let cipher_suites = if params.cipher_suites.is_empty() {
        default.cipher_suites.clone()
    } else {
        let mut suites: Vec<rustls::SupportedCipherSuite> = params
            .cipher_suites
            .iter()
            .copied()
            .map(map_cipher_suite)
            .collect();
        // TLS 1.3 suites are fixed (Envoy/BoringSSL parity) -- always appended,
        // never subject to the configured TLS 1.2 preference list.
        suites.push(cipher_suite::TLS13_AES_128_GCM_SHA256);
        suites.push(cipher_suite::TLS13_AES_256_GCM_SHA384);
        suites.push(cipher_suite::TLS13_CHACHA20_POLY1305_SHA256);
        suites
    };

    let kx_groups = if params.ecdh_curves.is_empty() {
        default.kx_groups.clone()
    } else {
        params
            .ecdh_curves
            .iter()
            .copied()
            .map(map_ecdh_curve)
            .collect()
    };

    CryptoProvider {
        cipher_suites,
        kx_groups,
        ..default
    }
}

// -------------------------------------------------------------- trust/roots --

fn build_root_store(ca: &CaSource, context: &str) -> Result<RootCertStore, TlsBuildError> {
    let mut roots = RootCertStore::empty();
    match ca {
        CaSource::TrustedCa(source) => {
            let bytes = resolver::read_data_source(source, context)?;
            let mut reader = std::io::Cursor::new(&bytes);
            let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
            let certs = certs
                .map_err(|e| TlsBuildError::new(context, format!("parsing trusted_ca PEM: {e}")))?;
            let (added, ignored) = roots.add_parsable_certificates(certs);
            if added == 0 {
                return Err(TlsBuildError::new(
                    context,
                    "trusted_ca PEM bundle contained no valid certificates",
                ));
            }
            // Envoy/BoringSSL fail on malformed entries in an explicit CA
            // bundle; silently dropping some of a configured trust anchor set
            // is exactly the degradation ground rule #1 forbids. (System
            // roots below are different: platform stores routinely contain
            // entries webpki can't parse, and skipping those matches how
            // every TLS stack consumes them.)
            if ignored > 0 {
                return Err(TlsBuildError::new(
                    context,
                    format!("trusted_ca PEM bundle contained {ignored} unparsable certificate(s)"),
                ));
            }
        }
        CaSource::SystemRoots => {
            let result = rustls_native_certs::load_native_certs();
            if result.certs.is_empty() {
                return Err(TlsBuildError::new(
                    context,
                    format!(
                        "system_root_certs: no native root certificates found ({} errors)",
                        result.errors.len()
                    ),
                ));
            }
            let (added, _ignored) = roots.add_parsable_certificates(result.certs);
            if added == 0 {
                return Err(TlsBuildError::new(
                    context,
                    "system_root_certs: no parsable native root certificates",
                ));
            }
        }
    }
    Ok(roots)
}

// -------------------------------------------------------------- downstream --

/// Downstream (server-side) TLS termination for one filter chain.
pub struct DownstreamTlsFactory {
    server_config: Arc<ServerConfig>,
    // Rust note: kept as the concrete resolver type (not `Arc<dyn
    // ResolvesServerCert>`) purely so `update_certificates` can call
    // `SwapCertResolver::store` directly without downcasting.
    cert_resolver: Arc<SwapCertResolver>,
}

impl DownstreamTlsFactory {
    pub fn build(spec: &DownstreamTlsSpec, context: &str) -> Result<Self, TlsBuildError> {
        let provider = build_crypto_provider(&spec.params);
        let cert_set = resolver::build_cert_set(&spec.certificates, &provider, context)?;
        let cert_resolver = Arc::new(SwapCertResolver::new(cert_set));

        let versions = protocol_versions(&spec.params);
        let builder = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)
            .map_err(|e| TlsBuildError::new(context, format!("protocol versions: {e}")))?;

        let mut server_config = match &spec.validation {
            None => builder
                .with_no_client_auth()
                .with_cert_resolver(cert_resolver.clone() as Arc<dyn ResolvesServerCert>),
            Some(vc) => {
                let roots = Arc::new(build_root_store(&vc.ca, context)?);
                let mut cv_builder = WebPkiClientVerifier::builder(roots);
                if !spec.require_client_certificate {
                    cv_builder = cv_builder.allow_unauthenticated();
                }
                let inner = cv_builder
                    .build()
                    .map_err(|e| TlsBuildError::new(context, format!("client verifier: {e}")))?;
                let verifier = Arc::new(CarveoutClientCertVerifier::new(
                    inner,
                    clone_san_matchers(&vc.san_matchers),
                    vc.allow_expired_certificate,
                ));
                builder
                    .with_client_cert_verifier(verifier)
                    .with_cert_resolver(cert_resolver.clone() as Arc<dyn ResolvesServerCert>)
            }
        };

        server_config.alpn_protocols = spec
            .alpn_protocols
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();

        if !spec.disable_stateless_session_resumption {
            server_config.ticketer = rustls::crypto::ring::Ticketer::new()
                .map_err(|e| TlsBuildError::new(context, format!("session ticketer: {e}")))?;
        }

        Ok(Self {
            server_config: Arc::new(server_config),
            cert_resolver,
        })
    }

    /// TLS-terminate an accepted connection.
    pub async fn wrap<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: IO,
    ) -> io::Result<tokio_rustls::server::TlsStream<IO>> {
        TlsAcceptor::from(self.server_config.clone())
            .accept(io)
            .await
    }

    /// Hot-swap the serving certificates without rebuilding the
    /// `ServerConfig` -- the ArcSwap resolver seam SDS (WP-22) drives.
    pub fn update_certificates(
        &self,
        certs: &[TlsCertificateIR],
        context: &str,
    ) -> Result<(), TlsBuildError> {
        // Rust note: re-derive the provider from the already-built config so
        // the new certs are validated against the same algorithm set as the
        // ones `build` loaded -- `ServerConfig` doesn't expose its provider
        // directly, but `crypto_provider()` returns it.
        let provider = self.server_config.crypto_provider();
        let set = resolver::build_cert_set(certs, provider, context)?;
        self.cert_resolver.store(set);
        Ok(())
    }
}

// ---------------------------------------------------------------- upstream --

/// Upstream (client-side) TLS origination for one cluster.
pub struct UpstreamTlsFactory {
    client_config: Arc<ClientConfig>,
    /// `Some` = explicit SNI override; `None` = Envoy sends no SNI extension
    /// and the `ServerName` is derived from the endpoint at `wrap` time.
    sni: Option<String>,
}

impl UpstreamTlsFactory {
    pub fn build(spec: &UpstreamTlsSpec, context: &str) -> Result<Self, TlsBuildError> {
        Self::build_with_alpn(spec, None, context)
    }

    /// Like [`Self::build`], but `alpn_override`, when `Some`, replaces
    /// `spec.alpn_protocols` for the `ClientConfig`'s ALPN offer. Used by
    /// [`transport_socket_builder`] to derive ALPN from the cluster's
    /// `upstream_protocol` when the spec doesn't configure one explicitly --
    /// see that function's doc comment for why. Doesn't mutate `spec` itself,
    /// so callers that only have a borrowed IR (never `proxy-cluster`'s
    /// concern to own) don't need to clone it.
    pub fn build_with_alpn(
        spec: &UpstreamTlsSpec,
        alpn_override: Option<&[String]>,
        context: &str,
    ) -> Result<Self, TlsBuildError> {
        let provider = Arc::new(build_crypto_provider(&spec.params));
        let versions = protocol_versions(&spec.params);
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .map_err(|e| TlsBuildError::new(context, format!("protocol versions: {e}")))?;

        let builder = match &spec.validation {
            None => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert::new(
                    provider.clone(),
                ))),
            Some(vc) => {
                let roots = Arc::new(build_root_store(&vc.ca, context)?);
                let webpki_verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                    roots,
                    provider.clone(),
                )
                .build()
                .map_err(|e| TlsBuildError::new(context, format!("server verifier: {e}")))?;
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(
                        HostnameBypassServerCertVerifier::new(
                            webpki_verifier,
                            clone_san_matchers(&vc.san_matchers),
                            vc.allow_expired_certificate,
                        ),
                    ))
            }
        };

        let mut client_config = match &spec.client_certificate {
            Some(cert) => {
                let (chain, key) = resolver::load_cert_and_key(cert, context)?;
                builder
                    .with_client_auth_cert(chain, key)
                    .map_err(|e| TlsBuildError::new(context, format!("client certificate: {e}")))?
            }
            None => builder.with_no_client_auth(),
        };

        client_config.alpn_protocols = alpn_override
            .unwrap_or(&spec.alpn_protocols)
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();
        // Envoy parity: no `sni` configured means no SNI extension is sent at
        // all, not "SNI = endpoint host" (see `wrap`'s doc comment).
        client_config.enable_sni = spec.sni.is_some();

        Ok(Self {
            client_config: Arc::new(client_config),
            sni: spec.sni.clone(),
        })
    }

    /// TLS-originate to an upstream. `endpoint_host` is the cluster
    /// endpoint's host (DNS name or IP); used as the rustls `ServerName` when
    /// no explicit `sni` was configured (rustls never sends SNI for IP
    /// literals regardless, and with `enable_sni = false` the name only feeds
    /// the, possibly bypassed, verifier).
    pub async fn wrap<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: IO,
        endpoint_host: &str,
    ) -> io::Result<tokio_rustls::client::TlsStream<IO>> {
        let server_name = server_name_for(&self.sni, endpoint_host)?;
        TlsConnector::from(self.client_config.clone())
            .connect(server_name, io)
            .await
    }
}

/// Shared by [`UpstreamTlsFactory::wrap`] and its
/// [`UpstreamTransportSocket`] impl below: the explicit `sni` override wins,
/// otherwise fall back to the endpoint host.
fn server_name_for(sni: &Option<String>, endpoint_host: &str) -> io::Result<ServerName<'static>> {
    let name = sni.as_deref().unwrap_or(endpoint_host).to_string();
    ServerName::try_from(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

// Rust note: `wrap`'s signature is fixed by the `UpstreamTransportSocket`
// trait (`proxy-cluster`, see that module's doc comment on why the trait
// lives there and the impl lives here) -- it takes a concrete `TcpStream` and
// returns a `'static` boxed future, unlike the inherent `wrap` above which is
// generic over `IO` and returns the concrete `TlsStream<IO>`. Cloning
// `client_config` (an `Arc`) and `sni` out of `&self` up front is what makes
// the future `'static`: it can't borrow `self`, because a pool may move it
// onto a spawned task that outlives this call.
impl UpstreamTransportSocket for UpstreamTlsFactory {
    fn wrap(
        &self,
        io: TcpStream,
        server_name: &str,
    ) -> BoxFuture<'static, io::Result<BoxedUpstreamIo>> {
        let client_config = Arc::clone(&self.client_config);
        let sni = self.sni.clone();
        let endpoint_host = server_name.to_string();
        Box::pin(async move {
            let name = server_name_for(&sni, &endpoint_host)?;
            let stream = TlsConnector::from(client_config).connect(name, io).await?;
            Ok(Box::new(stream) as BoxedUpstreamIo)
        })
    }
}

/// Builds the real [`proxy_cluster::transport::TransportSocketBuilder`]:
/// plaintext for clusters with no `transport_socket`, upstream TLS
/// (rustls, via [`UpstreamTlsFactory`]) for clusters that configure one.
///
/// # ALPN derivation
///
/// If `spec.alpn_protocols` is empty, this offers exactly one protocol
/// derived from the cluster's `upstream_protocol`: `Http2` -> `["h2"]`,
/// `Http1` -> `["http/1.1"]`. A non-empty `alpn_protocols` is used verbatim
/// (explicit config wins).
///
/// Our upstream codec is chosen from `upstream_protocol` at config time, not
/// negotiated -- so offering the *matching* ALPN makes a misconfigured server
/// (one that doesn't support the protocol we're about to speak) fail loudly
/// at the TLS handshake instead of us silently speaking the wrong protocol
/// over an already-established connection. Envoy derives its ALPN offer from
/// the cluster's protocol options the same way.
pub fn transport_socket_builder() -> proxy_cluster::transport::TransportSocketBuilder {
    Arc::new(|config: &ClusterConfig| {
        let Some(spec) = &config.transport_socket else {
            return Ok(Arc::new(proxy_cluster::transport::RawTransportSocket)
                as Arc<dyn UpstreamTransportSocket>);
        };
        let context = format!("cluster `{}` transport_socket", config.name);
        let derived_alpn;
        let alpn_override: Option<&[String]> = if spec.alpn_protocols.is_empty() {
            derived_alpn = match config.upstream_protocol {
                UpstreamProtocol::Http2 => vec!["h2".to_string()],
                UpstreamProtocol::Http1 => vec!["http/1.1".to_string()],
            };
            Some(derived_alpn.as_slice())
        } else {
            None
        };
        let factory = UpstreamTlsFactory::build_with_alpn(spec, alpn_override, &context)
            .map_err(|e| proxy_cluster::transport::TransportSocketError(e.to_string()))?;
        Ok(Arc::new(factory) as Arc<dyn UpstreamTransportSocket>)
    })
}
