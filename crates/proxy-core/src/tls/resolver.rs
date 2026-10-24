//! Certificate loading + the hot-swappable downstream cert resolver.
//!
//! `SwapCertResolver` is the seam SDS will drive: `DownstreamTlsFactory`
//! builds one `rustls::ServerConfig` up front, but the certificates it serves
//! can be replaced afterwards by swapping the `ArcSwap<CertSet>` underneath
//! it -- no rebuild, no dropped connections.

use std::sync::Arc;

use arc_swap::ArcSwap;
use proxy_config::ir::{DataSourceIR, TlsCertificateIR};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::{self, PemObject};
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
    let certs: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(bytes).collect();
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

/// Parse the first PEM private key: PKCS#8 (`PRIVATE KEY`), PKCS#1
/// (`RSA PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`).
fn parse_private_key(bytes: &[u8], context: &str) -> Result<PrivateKeyDer<'static>, TlsBuildError> {
    PrivateKeyDer::from_pem_slice(bytes).map_err(|e| match e {
        pem::Error::NoItemsFound => TlsBuildError::new(context, "no private key found in PEM data"),
        e => TlsBuildError::new(context, format!("parsing PEM private key: {e}")),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A PEM block of `label` around the DER `30 03 02 01 01`. The loaders
    /// never inspect the DER; the label alone picks the key format.
    fn block(label: &str) -> String {
        format!("-----BEGIN {label}-----\nMAMCAQE=\n-----END {label}-----\n")
    }

    fn load(
        chain: &str,
        key: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsBuildError> {
        let cert = TlsCertificateIR {
            cert_chain: DataSourceIR::Inline(chain.to_string()),
            private_key: DataSourceIR::Inline(key.to_string()),
        };
        load_cert_and_key(&cert, "test")
    }

    /// Operators supply PKCS#8, PKCS#1 and SEC1 keys; each loads as its own
    /// format, and the first key in the file wins over later sections.
    #[test]
    fn each_private_key_format_loads_and_the_first_key_wins() {
        let chain = block("CERTIFICATE");
        let cases = [
            ("PRIVATE KEY", "pkcs8"),
            ("RSA PRIVATE KEY", "pkcs1"),
            ("EC PRIVATE KEY", "sec1"),
        ];
        for (label, want) in cases {
            // A certificate before the key and another key after it.
            let key_pem = format!(
                "{}{}{}",
                block("CERTIFICATE"),
                block(label),
                block("PRIVATE KEY")
            );
            let (_, key) =
                load(&chain, &key_pem).unwrap_or_else(|e| panic!("{label}: {}", e.reason));
            let got = match &key {
                PrivateKeyDer::Pkcs8(_) => "pkcs8",
                PrivateKeyDer::Pkcs1(_) => "pkcs1",
                PrivateKeyDer::Sec1(_) => "sec1",
                _ => "other",
            };
            assert_eq!(
                got, want,
                "a `{label}` block must load as {want}, got {got}"
            );
            assert_eq!(
                key.secret_der(),
                [0x30, 0x03, 0x02, 0x01, 0x01],
                "{label}: DER changed in loading"
            );
        }
    }

    /// The chain is served in file order (leaf first); key sections in the
    /// chain file are skipped, not refused.
    #[test]
    fn a_cert_chain_keeps_file_order_and_skips_other_sections() {
        let leaf = "-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n";
        let intermediate = "-----BEGIN CERTIFICATE-----\nAg==\n-----END CERTIFICATE-----\n";
        let chain = format!(
            "{}{leaf}{}{intermediate}",
            block("PRIVATE KEY"),
            block("EC PRIVATE KEY")
        );
        let (certs, _) =
            load(&chain, &block("PRIVATE KEY")).unwrap_or_else(|e| panic!("{}", e.reason));
        let ders: Vec<&[u8]> = certs.iter().map(|c| c.as_ref()).collect();
        assert_eq!(
            ders,
            [&[1u8][..], &[2u8][..]],
            "chain must be leaf then intermediate, keys skipped"
        );
    }

    /// A PEM with nothing usable, or a block that is not base64, is refused
    /// with a reason that names what is wrong (AGENTS.md invariant 1).
    #[test]
    fn missing_or_malformed_pem_is_refused_with_a_named_reason() {
        let good_chain = block("CERTIFICATE");
        let good_key = block("PRIVATE KEY");
        let malformed = "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n";
        let malformed_cert = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        let cases = [
            (
                good_chain.as_str(),
                block("CERTIFICATE"),
                "no private key found in PEM data",
            ),
            (
                good_chain.as_str(),
                malformed.to_string(),
                "parsing PEM private key: ",
            ),
            (
                good_key.as_str(),
                good_key.clone(),
                "no certificates found in PEM data",
            ),
            (malformed_cert, good_key.clone(), "parsing PEM chain: "),
        ];
        for (chain, key, want) in cases {
            let Err(err) = load(chain, &key) else {
                panic!("expected a refusal starting {want:?} for chain {chain:?} key {key:?}");
            };
            assert!(
                err.reason.starts_with(want),
                "reason {:?} must start with {want:?}",
                err.reason
            );
        }
    }
}
