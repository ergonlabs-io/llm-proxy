//! Custom `rustls` server-cert verifiers implementing Envoy-parity behavior
//! that the stock `webpki` verifiers don't provide out of the box.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use proxy_config::ir::{SanMatcherIR, SanType, StringMatcherIR};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

/// `validation: None` on an `UpstreamTlsSpec` means Envoy does not verify the upstream certificate at all. That is
/// documented Envoy behavior, not a shortcut. `supported_verify_schemes` still limits signatures to the provider's
/// algorithms, so the handshake signature is checked.
#[derive(Debug)]
pub(super) struct AcceptAnyServerCert {
    provider: Arc<CryptoProvider>,
}

impl AcceptAnyServerCert {
    pub(super) fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The IR's matchers are not `Clone`, but these wrappers must own their list past the borrowed `ValidationContextIR`
/// that the factory build sees. So this rebuilds an owned copy field by field. A `Regex` clone is cheap (an `Arc`
/// inside), so nothing is recompiled.
pub(super) fn clone_san_matchers(matchers: &[SanMatcherIR]) -> Vec<SanMatcherIR> {
    matchers
        .iter()
        .map(|m| SanMatcherIR {
            san_type: m.san_type,
            matcher: clone_string_matcher(&m.matcher),
        })
        .collect()
}

fn clone_string_matcher(matcher: &StringMatcherIR) -> StringMatcherIR {
    match matcher {
        StringMatcherIR::Exact { value, ignore_case } => StringMatcherIR::Exact {
            value: value.clone(),
            ignore_case: *ignore_case,
        },
        StringMatcherIR::Prefix { value, ignore_case } => StringMatcherIR::Prefix {
            value: value.clone(),
            ignore_case: *ignore_case,
        },
        StringMatcherIR::Suffix { value, ignore_case } => StringMatcherIR::Suffix {
            value: value.clone(),
            ignore_case: *ignore_case,
        },
        StringMatcherIR::Contains { value, ignore_case } => StringMatcherIR::Contains {
            value: value.clone(),
            ignore_case: *ignore_case,
        },
        StringMatcherIR::SafeRegex(re) => StringMatcherIR::SafeRegex(re.clone()),
    }
}

// ------------------------------------------------------------ SAN matching --

/// The peer certificate's SANs, grouped by type and formatted the way
/// [`SanMatcherIR`] matchers expect to compare against them.
struct ExtractedSans {
    dns: Vec<String>,
    uri: Vec<String>,
    ip: Vec<String>,
}

/// Parses `cert_der`'s `subjectAltName` extension. A parse failure is `Error::InvalidCertificate(BadEncoding)`, the
/// same error webpki returns for a certificate it cannot decode.
fn extract_sans(cert_der: &CertificateDer<'_>) -> Result<ExtractedSans, Error> {
    let bad_encoding = || Error::InvalidCertificate(CertificateError::BadEncoding);

    let (_, cert) =
        x509_parser::parse_x509_certificate(cert_der.as_ref()).map_err(|_| bad_encoding())?;
    let san_ext = cert
        .subject_alternative_name()
        .map_err(|_| bad_encoding())?;

    let mut sans = ExtractedSans {
        dns: Vec::new(),
        uri: Vec::new(),
        ip: Vec::new(),
    };
    let Some(san_ext) = san_ext else {
        return Ok(sans);
    };
    for name in &san_ext.value.general_names {
        match name {
            x509_parser::extensions::GeneralName::DNSName(name) => sans.dns.push(name.to_string()),
            x509_parser::extensions::GeneralName::URI(uri) => sans.uri.push(uri.to_string()),
            x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                if let Some(formatted) = format_ip_san(bytes) {
                    sans.ip.push(formatted);
                }
                // A malformed-length IP SAN (not 4 or 16 bytes) cannot match anything, as in Envoy.
            }
            _ => {
                // Envoy's SAN matchers cover only DNS, URI, and IP address (lowering rejects the rest). A cert with
                // other SAN kinds has nothing to match for those, which is not an error.
            }
        }
    }
    Ok(sans)
}

/// `iPAddress` SAN bytes -> canonical string form, matching how Envoy
/// compares IP SANs (`127.0.0.1`, `::1`).
fn format_ip_san(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes.try_into().ok()?;
            Some(Ipv4Addr::from(octets).to_string())
        }
        16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}

/// Envoy `match_typed_subject_alt_names` semantics: accept if ANY matcher matches ANY SAN of that matcher's type.
/// The caller skips this for an empty `san_matchers`. When called, it always enforces a match.
fn check_san_matchers(
    cert_der: &CertificateDer<'_>,
    san_matchers: &[SanMatcherIR],
) -> Result<(), Error> {
    let sans = extract_sans(cert_der)?;

    let matched = san_matchers.iter().any(|san_matcher| {
        let candidates = match san_matcher.san_type {
            SanType::Dns => &sans.dns,
            SanType::Uri => &sans.uri,
            SanType::IpAddress => &sans.ip,
        };
        candidates
            .iter()
            .any(|value| san_matcher.matcher.matches(value))
    });

    if matched {
        Ok(())
    } else {
        Err(Error::General(format!(
            "SAN mismatch: none of the configured SAN matchers matched the peer certificate's \
             SANs (dns={:?}, uri={:?}, ip={:?})",
            sans.dns, sans.uri, sans.ip
        )))
    }
}

/// If `err` is rustls reporting an expired or not-yet-valid leaf, and carries enough context to compute a timestamp
/// inside that certificate's validity window, returns that timestamp.
///
/// Why not just accept the expiry error? webpki checks a leaf's validity before path building. An expired leaf signed
/// by an untrusted CA can then come back as `Expired` and never reach the `UnknownIssuer` check. Trusting "the only
/// error was expiry" would accept a certificate from the wrong CA. So this re-runs the entire inner verification
/// (chain, signatures, hostname) at a moment the certificate was valid. Any other problem still surfaces normally.
///
/// The plain `Expired` and `NotValidYet` variants carry no timestamp. They arise only for `InvalidCertValidity`, a
/// malformed validity range, which is not fixed by retrying, so they return `None` and the original error propagates.
fn expiry_bypass_time(err: &Error) -> Option<UnixTime> {
    match err {
        Error::InvalidCertificate(CertificateError::ExpiredContext { not_after, .. }) => Some(
            UnixTime::since_unix_epoch(Duration::from_secs(not_after.as_secs().saturating_sub(1))),
        ),
        Error::InvalidCertificate(CertificateError::NotValidYetContext { not_before, .. }) => Some(
            UnixTime::since_unix_epoch(Duration::from_secs(not_before.as_secs().saturating_add(1))),
        ),
        _ => None,
    }
}

// ---------------------------------------------------- upstream (server) side --

/// Wraps a `WebPkiServerVerifier` (chain-trust validation against `trusted_ca` and `system_root_certs`) and applies
/// the Envoy-parity carve-outs:
/// - Envoy's `trusted_ca`-only validation does not do RFC 6125 hostname or SNI verification. Only
///   `match_typed_subject_alt_names` does, so a hostname mismatch from the inner verifier is downgraded to success.
///   SAN matchers are the real hostname-shaped check.
/// - `allow_expired_certificate`: an expired or not-yet-valid leaf is downgraded to success, only when the IR asks.
/// - `san_matchers`: after the inner verifier succeeds, including through either bypass, the peer's SANs must satisfy
///   at least one matcher.
#[derive(Debug)]
pub(super) struct HostnameBypassServerCertVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    san_matchers: Vec<SanMatcherIR>,
    allow_expired_certificate: bool,
}

impl HostnameBypassServerCertVerifier {
    pub(super) fn new(
        inner: Arc<rustls::client::WebPkiServerVerifier>,
        san_matchers: Vec<SanMatcherIR>,
        allow_expired_certificate: bool,
    ) -> Self {
        Self {
            inner,
            san_matchers,
            allow_expired_certificate,
        }
    }
}

impl HostnameBypassServerCertVerifier {
    /// Handles an inner-verifier error. A hostname mismatch is downgraded to success unconditionally, per the struct
    /// doc. Only when configured, an expiry-shaped failure is retried at a moment the leaf was valid (see
    /// `expiry_bypass_time`). Any other error, or a retry that still fails, propagates unchanged.
    fn retry_bypassing_hostname_and_expiry(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        err: Error,
    ) -> Result<ServerCertVerified, Error> {
        if matches!(
            err,
            Error::InvalidCertificate(CertificateError::NotValidForName)
                | Error::InvalidCertificate(CertificateError::NotValidForNameContext { .. })
        ) {
            return Ok(ServerCertVerified::assertion());
        }
        if self.allow_expired_certificate {
            if let Some(retry_now) = expiry_bypass_time(&err) {
                return match self.inner.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    retry_now,
                ) {
                    Ok(verified) => Ok(verified),
                    Err(Error::InvalidCertificate(CertificateError::NotValidForName))
                    | Err(Error::InvalidCertificate(CertificateError::NotValidForNameContext {
                        ..
                    })) => Ok(ServerCertVerified::assertion()),
                    Err(other) => Err(other),
                };
            }
        }
        Err(err)
    }
}

impl ServerCertVerifier for HostnameBypassServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let result = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        let verified = match result {
            Ok(verified) => verified,
            Err(err) => self.retry_bypassing_hostname_and_expiry(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                err,
            )?,
        };

        // AGENTS.md invariant 1: SAN matching only runs after (real or bypassed)
        // chain-trust success -- an unauthenticated SAN check is meaningless.
        if !self.san_matchers.is_empty() {
            check_san_matchers(end_entity, &self.san_matchers)?;
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// --------------------------------------------------- downstream (client) side --

/// Downstream mirror of [`HostnameBypassServerCertVerifier`]: wraps a `WebPkiClientVerifier` (built from `validation.ca`
/// and `require_client_certificate`) and applies the same `allow_expired_certificate` and `san_matchers` carve-outs to
/// the client certificate. There is no hostname to bypass, since `verify_client_cert` never takes a `ServerName`.
#[derive(Debug)]
pub(super) struct CarveoutClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    san_matchers: Vec<SanMatcherIR>,
    allow_expired_certificate: bool,
}

/// Fail-closed verifier used while a downstream `validation_context_sds_secret_config` is named but not yet delivered.
/// A bare `with_no_client_auth` would silently turn an mTLS listener into a non-mTLS one. This version requests a
/// certificate, requires one, and rejects every offered certificate until real trust anchors replace it atomically.
#[derive(Debug)]
pub(super) struct PendingSdsClientCertVerifier {
    provider: Arc<CryptoProvider>,
}

impl PendingSdsClientCertVerifier {
    pub(super) fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ClientCertVerifier for PendingSdsClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Err(Error::General(
            "client trust anchors are waiting for SDS validation_context delivery".to_string(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl CarveoutClientCertVerifier {
    pub(super) fn new(
        inner: Arc<dyn ClientCertVerifier>,
        san_matchers: Vec<SanMatcherIR>,
        allow_expired_certificate: bool,
    ) -> Self {
        Self {
            inner,
            san_matchers,
            allow_expired_certificate,
        }
    }

    /// The same retry-at-a-valid-time strategy as `HostnameBypassServerCertVerifier::retry_bypassing_hostname_and_expiry`,
    /// minus the hostname carve-out.
    fn retry_bypassing_expiry(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        err: Error,
    ) -> Result<ClientCertVerified, Error> {
        if self.allow_expired_certificate {
            if let Some(retry_now) = expiry_bypass_time(&err) {
                return self
                    .inner
                    .verify_client_cert(end_entity, intermediates, retry_now);
            }
        }
        Err(err)
    }
}

// Rust note: `ClientCertVerifier` is the server side of mTLS, mirroring `ServerCertVerifier`. It lives under
// `rustls::server::danger` rather than `rustls::client::danger`, and adds `offer_client_auth`,
// `client_auth_mandatory`, and `root_hint_subjects`. Those have no upstream equivalent, so they simply delegate.
impl ClientCertVerifier for CarveoutClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let result = self
            .inner
            .verify_client_cert(end_entity, intermediates, now);
        let verified = match result {
            Ok(verified) => verified,
            Err(err) => self.retry_bypassing_expiry(end_entity, intermediates, err)?,
        };

        if !self.san_matchers.is_empty() {
            check_san_matchers(end_entity, &self.san_matchers)?;
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
