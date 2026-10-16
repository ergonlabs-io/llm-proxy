//! Certificate loading + the hot-swappable downstream cert resolver.
//!
//! `SwapCertResolver` is the seam SDS will drive: `DownstreamTlsFactory`
//! builds one `rustls::ServerConfig` up front, but the certificates it serves
//! can be replaced afterwards by swapping the `ArcSwap<CertSet>` underneath
//! it -- no rebuild, no dropped connections.

use std::io::Cursor;
use std::sync::Arc;

use arc_swap::ArcSwap;
use proxy_config::ir::{DataSourceIR, TlsCertificateIR};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::SignatureScheme;

use super::TlsBuildError;

/// The two key types Envoy/BoringSSL (and this proxy) support serving
/// simultaneously: at most one certificate per type, selected per-handshake.
#[derive(Debug, Default)]
pub(super) struct CertSet {
    pub(super) rsa: Option<Arc<CertifiedKey>>,
    pub(super) ecdsa: Option<Arc<CertifiedKey>>,
}

/// Read a [`DataSourceIR`] into bytes. `context` names the field for error
/// messages (AGENTS.md invariant 1: never fail silently/anonymously).
pub(super) fn read_data_source(
    source: &DataSourceIR,
    context: &str,
) -> Result<Vec<u8>, TlsBuildError> {
    match source {
        DataSourceIR::File(path) => std::fs::read(path)
            .map_err(|e| TlsBuildError::new(context, format!("reading `{}`: {e}", path.display()))),
        DataSourceIR::Inline(s) => Ok(s.clone().into_bytes()),
    }
}

/// Parse a PEM certificate chain (full chain, in order) from bytes.
fn parse_cert_chain(
    bytes: &[u8],
    context: &str,
) -> Result<Vec<CertificateDer<'static>>, TlsBuildError> {
    let mut reader = Cursor::new(bytes);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs =
        certs.map_err(|e| TlsBuildError::new(context, format!("parsing PEM chain: {e}")))?;
    if certs.is_empty() {
        return Err(TlsBuildError::new(
            context,
            "no certificates found in PEM data",
        ));
    }
    Ok(certs)
}

/// Parse a PEM private key (any of PKCS8/RSA/SEC1 -- `rustls_pemfile::private_key`
/// tries them all).
fn parse_private_key(bytes: &[u8], context: &str) -> Result<PrivateKeyDer<'static>, TlsBuildError> {
    let mut reader = Cursor::new(bytes);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TlsBuildError::new(context, format!("parsing PEM private key: {e}")))?
        .ok_or_else(|| TlsBuildError::new(context, "no private key found in PEM data"))
}

/// Load one [`TlsCertificateIR`] into a chain + key, resolving `DataSourceIR`
/// on both sides.
pub(super) fn load_cert_and_key(
    cert: &TlsCertificateIR,
    context: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsBuildError> {
    let chain_bytes = read_data_source(&cert.cert_chain, context)?;
    let key_bytes = read_data_source(&cert.private_key, context)?;
    let chain = parse_cert_chain(&chain_bytes, context)?;
    let key = parse_private_key(&key_bytes, context)?;
    Ok((chain, key))
}

/// Load every configured `TlsCertificateIR` into a `CertSet`, keyed by
/// signing-key type. Envoy allows at most one certificate per key type; the
/// count (<= 2) is bounded at lowering, but *which* two types is checked here.
pub(super) fn build_cert_set(
    certs: &[TlsCertificateIR],
    provider: &CryptoProvider,
    context: &str,
) -> Result<CertSet, TlsBuildError> {
    let mut set = CertSet::default();
    for cert in certs {
        let (chain, key) = load_cert_and_key(cert, context)?;
        let certified_key = CertifiedKey::from_der(chain, key, provider)
            .map_err(|e| TlsBuildError::new(context, format!("loading certificate/key: {e}")))?;
        match certified_key.key.algorithm() {
            rustls::SignatureAlgorithm::RSA => {
                if set.rsa.is_some() {
                    return Err(TlsBuildError::new(
                        context,
                        "at most one certificate per key type (RSA, ECDSA)",
                    ));
                }
                set.rsa = Some(Arc::new(certified_key));
            }
            rustls::SignatureAlgorithm::ECDSA => {
                if set.ecdsa.is_some() {
                    return Err(TlsBuildError::new(
                        context,
                        "at most one certificate per key type (RSA, ECDSA)",
                    ));
                }
                set.ecdsa = Some(Arc::new(certified_key));
            }
            other => {
                return Err(TlsBuildError::new(
                    context,
                    format!("unsupported key type: {other:?}"),
                ))
            }
        }
    }
    if set.rsa.is_none() && set.ecdsa.is_none() {
        return Err(TlsBuildError::new(
            context,
            "at least one certificate is required",
        ));
    }
    Ok(set)
}

/// `ResolvesServerCert` backed by an `ArcSwap<CertSet>`, the hot-reload seam.
/// Rust note: `ArcSwap` gives lock-free reads on the hot path (every accepted connection resolves a cert) and a cheap
/// atomic swap on update. It is the same pattern `WorkerConfigHandle` uses.
#[derive(Debug)]
pub(super) struct SwapCertResolver(ArcSwap<CertSet>);

impl SwapCertResolver {
    pub(super) fn new(initial: CertSet) -> Self {
        Self(ArcSwap::new(Arc::new(initial)))
    }

    pub(super) fn store(&self, set: CertSet) {
        self.0.store(Arc::new(set));
    }
}

/// Signature schemes whose name starts with `ECDSA_`, used to decide whether a ClientHello can accept an ECDSA
/// certificate. `SignatureScheme` does not expose its algorithm, so this matches the concrete schemes rustls defines.
fn is_ecdsa_scheme(scheme: SignatureScheme) -> bool {
    matches!(
        scheme,
        SignatureScheme::ECDSA_SHA1_Legacy
            | SignatureScheme::ECDSA_NISTP256_SHA256
            | SignatureScheme::ECDSA_NISTP384_SHA384
            | SignatureScheme::ECDSA_NISTP521_SHA512
    )
}

impl ResolvesServerCert for SwapCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let set = self.0.load();
        // BoringSSL (and so Envoy) prefers ECDSA when the client supports it.
        let wants_ecdsa = client_hello
            .signature_schemes()
            .iter()
            .copied()
            .any(is_ecdsa_scheme);
        if wants_ecdsa {
            if let Some(k) = &set.ecdsa {
                return Some(k.clone());
            }
        }
        set.rsa.clone().or_else(|| set.ecdsa.clone())
    }
}
