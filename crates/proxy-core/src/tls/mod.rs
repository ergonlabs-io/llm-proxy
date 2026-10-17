//! Compiled TLS transport sockets: builds `rustls` `ServerConfig` and `ClientConfig` straight from the IR, one
//! factory per filter chain or cluster. No Envoy protos reach this module (AGENTS.md invariant 2). Every
//! `ValidationContextIR` field (`ca`, `san_matchers`, `allow_expired_certificate`) is honored by the verifiers in
//! [`verify`] (invariant 1).
//!
//! Split into:
//! - this file: crypto-provider construction (versions/suites/curves) and
//!   the two public factories.
//! - [`resolver`]: certificate loading + the hot-swappable cert resolver.
//! - [`verify`]: the custom `ServerCertVerifier`/`ClientCertVerifier`
//!   wrappers Envoy parity needs (hostname bypass, SAN matchers,
//!   `allow_expired_certificate`).

mod resolver;
mod secret_registry;
mod verify;

use std::io;
use std::sync::Arc;

use arc_swap::ArcSwap;
use futures::future::BoxFuture;
use proxy_cluster::transport::UpstreamTransportSocket;
use proxy_cluster::BoxedUpstreamIo;
use proxy_config::ir::{
    CaSource, ClusterConfig, DownstreamTlsSpec, TlsCertificateIR, TlsCipherSuite, TlsEcdhCurve,
    TlsParametersIR, TlsVersion, UpstreamProtocol, UpstreamTlsSpec, ValidationContextIR,
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
pub use secret_registry::SdsSecretRegistry;
use verify::{
    clone_san_matchers, AcceptAnyServerCert, CarveoutClientCertVerifier,
    HostnameBypassServerCertVerifier, PendingSdsClientCertVerifier,
};

/// Error building a TLS factory from IR. `context` is caller-supplied (for example `listener 'x' filter_chains[0]`),
/// so the error says where, per AGENTS.md invariant 1.
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

// Rust note: these must be named `static`s, not inline `&[...]` literals in the `match` arms. An array of `&'static`
// references is not promoted to `'static` when built as a temporary inside a function body.
static VERSIONS_V12: &[&rustls::SupportedProtocolVersion] = &[&version::TLS12];
static VERSIONS_V13: &[&rustls::SupportedProtocolVersion] = &[&version::TLS13];
static VERSIONS_BOTH: &[&rustls::SupportedProtocolVersion] = &[&version::TLS13, &version::TLS12];

/// The enabled versions for `min_version..=max_version`. rustls takes a list of enabled versions, not a min and max
/// pair, so this expands the IR's inclusive range.
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

/// Builds the `CryptoProvider` a `TlsParametersIR` implies. Empty `cipher_suites` or `ecdh_curves` mean ring's
/// defaults. A non-empty list is a preference-ordered custom list (see the module doc on TLS 1.3 suites).
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
            // Envoy and BoringSSL fail on malformed entries in an explicit CA bundle. Silently dropping part of a
            // configured trust-anchor set is the degradation AGENTS.md invariant 1 forbids. System roots differ:
            // platform stores contain entries webpki cannot parse, and every TLS stack skips those.
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
    // A trust-anchor rotation changes rustls's client verifier, unlike a certificate (already hot-swappable). The
    // whole immutable `ServerConfig` sits behind `ArcSwap`, so a completed SDS update takes effect atomically for new
    // handshakes while established connections keep their config.
    server_config: ArcSwap<ServerConfig>,
    // Rust note: kept as the concrete resolver type, not `Arc<dyn ResolvesServerCert>`, so `update_certificates` can
    // call `SwapCertResolver::store` without a downcast.
    cert_resolver: Arc<SwapCertResolver>,
    provider: Arc<CryptoProvider>,
    params: TlsParametersIR,
    alpn_protocols: Vec<String>,
    require_client_certificate: bool,
    disable_stateless_session_resumption: bool,
}

impl DownstreamTlsFactory {
    pub fn build(spec: &DownstreamTlsSpec, context: &str) -> Result<Self, TlsBuildError> {
        let provider = Arc::new(build_crypto_provider(&spec.params));
        // An SDS-named chain binds with an EMPTY cert set. `SwapCertResolver::resolve` answers `None`, so the listener
        // accepts TCP and fails every handshake until the control plane delivers. It never serves in the clear. A
        // spec with neither certificates nor SDS names still errors in `build_cert_set`, since that breaks the lowering
        // invariant. This is a control that has not engaged yet, so it is loud. It fires per accept-loop worker on bind
        // and on each snapshot rebuild, not per connection.
        let cert_set = if spec.certificates.is_empty() && !spec.certificate_sds_names.is_empty() {
            tracing::warn!(
                context,
                secrets = ?spec.certificate_sds_names,
                "TLS chain has no certificates yet: its serving certificates arrive over SDS \
                 and none have been delivered, so every TLS handshake on this chain will fail \
                 until the control plane sends them"
            );
            resolver::CertSet::default()
        } else {
            resolver::build_cert_set(&spec.certificates, &provider, context)?
        };
        let cert_resolver = Arc::new(SwapCertResolver::new(cert_set));
        let server_config = Self::build_server_config(
            &provider,
            &spec.params,
            &spec.alpn_protocols,
            spec.require_client_certificate,
            spec.disable_stateless_session_resumption,
            &cert_resolver,
            spec.validation.as_ref(),
            spec.validation_sds_name.is_some(),
            context,
        )?;

        Ok(Self {
            server_config: ArcSwap::new(Arc::new(server_config)),
            cert_resolver,
            provider,
            params: spec.params.clone(),
            alpn_protocols: spec.alpn_protocols.clone(),
            require_client_certificate: spec.require_client_certificate,
            disable_stateless_session_resumption: spec.disable_stateless_session_resumption,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_server_config(
        provider: &Arc<CryptoProvider>,
        params: &TlsParametersIR,
        alpn_protocols: &[String],
        require_client_certificate: bool,
        disable_stateless_session_resumption: bool,
        cert_resolver: &Arc<SwapCertResolver>,
        validation: Option<&ValidationContextIR>,
        pending_sds_validation: bool,
        context: &str,
    ) -> Result<ServerConfig, TlsBuildError> {
        let builder = ServerConfig::builder_with_provider(Arc::clone(provider))
            .with_protocol_versions(protocol_versions(params))
            .map_err(|e| TlsBuildError::new(context, format!("protocol versions: {e}")))?;
        let resolver = cert_resolver.clone() as Arc<dyn ResolvesServerCert>;
        let mut server_config = match validation {
            Some(vc) => {
                let roots = Arc::new(build_root_store(&vc.ca, context)?);
                let mut cv_builder = WebPkiClientVerifier::builder(roots);
                if !require_client_certificate {
                    cv_builder = cv_builder.allow_unauthenticated();
                }
                let inner = cv_builder
                    .build()
                    .map_err(|e| TlsBuildError::new(context, format!("client verifier: {e}")))?;
                builder
                    .with_client_cert_verifier(Arc::new(CarveoutClientCertVerifier::new(
                        inner,
                        clone_san_matchers(&vc.san_matchers),
                        vc.allow_expired_certificate,
                    )))
                    .with_cert_resolver(resolver)
            }
            None if pending_sds_validation => builder
                .with_client_cert_verifier(Arc::new(PendingSdsClientCertVerifier::new(Arc::clone(
                    provider,
                ))))
                .with_cert_resolver(resolver),
            None => builder.with_no_client_auth().with_cert_resolver(resolver),
        };
        server_config.alpn_protocols = alpn_protocols
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();
        if !disable_stateless_session_resumption {
            server_config.ticketer = rustls::crypto::ring::Ticketer::new()
                .map_err(|e| TlsBuildError::new(context, format!("session ticketer: {e}")))?;
        }
        Ok(server_config)
    }

    /// TLS-terminate an accepted connection.
    pub async fn wrap<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: IO,
    ) -> io::Result<tokio_rustls::server::TlsStream<IO>> {
        TlsAcceptor::from(self.server_config.load_full())
            .accept(io)
            .await
    }

    /// Hot-swap the serving certificates without rebuilding the
    /// `ServerConfig` -- the ArcSwap resolver seam SDS drives.
    pub fn update_certificates(
        &self,
        certs: &[TlsCertificateIR],
        context: &str,
    ) -> Result<(), TlsBuildError> {
        // Rust note: re-derive the provider from the built config, so new certs are validated against the same
        // algorithm set. `ServerConfig` exposes its provider through `crypto_provider()`.
        let set = resolver::build_cert_set(certs, &self.provider, context)?;
        self.cert_resolver.store(set);
        Ok(())
    }

    /// Remove every serving certificate from this factory. New handshakes
    /// fail closed until a later SDS delivery installs another certificate.
    pub fn remove_certificates(&self) {
        self.cert_resolver.store(resolver::CertSet::default());
    }

    /// Atomically replaces the downstream client-auth trust anchors after an SDS validation-context delivery.
    /// Construction happens before the swap, so bad PEM leaves the prior config serving.
    pub fn update_validation_context(
        &self,
        validation: &ValidationContextIR,
        context: &str,
    ) -> Result<(), TlsBuildError> {
        let config = Self::build_server_config(
            &self.provider,
            &self.params,
            &self.alpn_protocols,
            self.require_client_certificate,
            self.disable_stateless_session_resumption,
            &self.cert_resolver,
            Some(validation),
            false,
            context,
        )?;
        self.server_config.store(Arc::new(config));
        Ok(())
    }

    /// Returns this factory to its pre-delivery SDS validation state. The pending verifier rejects every client
    /// certificate until a later delivery installs trust anchors.
    pub fn remove_validation_context(&self, context: &str) -> Result<(), TlsBuildError> {
        let config = Self::build_server_config(
            &self.provider,
            &self.params,
            &self.alpn_protocols,
            self.require_client_certificate,
            self.disable_stateless_session_resumption,
            &self.cert_resolver,
            None,
            true,
            context,
        )?;
        self.server_config.store(Arc::new(config));
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

    /// Like [`Self::build`], but `alpn_override`, when `Some`, replaces `spec.alpn_protocols` for the client's ALPN
    /// offer. [`transport_socket_builder`] uses it to derive ALPN from the cluster's `upstream_protocol`. It does not
    /// mutate `spec`.
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

    /// TLS-originates to an upstream. `endpoint_host` is the endpoint's DNS name or IP. It is the `ServerName` when no
    /// explicit `sni` is set, and rustls never sends SNI for IP literals. With `enable_sni = false` it only feeds the
    /// verifier, which may be bypassed.
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

/// Shared by [`UpstreamTlsFactory::wrap`] and its [`UpstreamTransportSocket`] impl: the explicit `sni` wins,
/// otherwise the endpoint host.
fn server_name_for(sni: &Option<String>, endpoint_host: &str) -> io::Result<ServerName<'static>> {
    let name = sni.as_deref().unwrap_or(endpoint_host).to_string();
    ServerName::try_from(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

// Rust note: `wrap`'s signature is fixed by the `UpstreamTransportSocket` trait, which takes a concrete `TcpStream`
// and returns a `'static` boxed future. The inherent `wrap` above is generic over `IO`. Cloning `client_config` (an
// `Arc`) and `sni` out of `&self` makes the future `'static`, since a pool may move it onto a task that outlives this call.
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

    fn has_handshake(&self) -> bool {
        true
    }
}

/// Builds the [`proxy_cluster::transport::TransportSocketBuilder`]: plaintext for a cluster with no
/// `transport_socket`, upstream TLS (rustls, via [`UpstreamTlsFactory`]) otherwise.
///
/// # ALPN derivation
///
/// With empty `spec.alpn_protocols`, the offer is the one protocol implied by the cluster's `upstream_protocol`:
/// `Http2` gives `["h2"]`, and `Http1` gives `["http/1.1"]`. A non-empty list is used verbatim.
///
/// The upstream codec is chosen from `upstream_protocol` at config time, not negotiated. Offering the matching ALPN
/// makes a server that does not speak that protocol fail at the handshake, rather than silently speaking the wrong
/// protocol on an open connection. Envoy derives its offer the same way.
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
