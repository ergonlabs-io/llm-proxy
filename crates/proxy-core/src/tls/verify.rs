//! Custom `rustls` server-cert verifiers implementing Envoy-parity behavior
//! that the stock `webpki` verifiers don't provide out of the box (WP-08).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use proxy_config::ir::{SanMatcherIR, SanType, StringMatcherIR};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

/// `validation: None` on an `UpstreamTlsSpec` means Envoy does not verify the
/// upstream certificate at all -- this is documented (if dangerous) Envoy
/// behavior, not a shortcut we're taking. `supported_verify_schemes` still
/// constrains signature verification to the provider's algorithms so at
/// least the handshake signature itself is checked.
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

/// `SanMatcherIR`/`StringMatcherIR` don't derive `Clone` in the IR (its
/// public shape is frozen outside WP-08 chunk A) -- the two verifier wrappers
/// below need to own their matcher list past the borrowed `&ValidationContextIR`
/// that `DownstreamTlsFactory::build`/`UpstreamTlsFactory::build` only see for
/// the duration of the call, so this rebuilds an owned copy field-by-field.
/// `regex::Regex` itself is `Clone` (cheap: an `Arc` inside), so this isn't
/// recompiling anything.
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

/// Parse `cert_der`'s `subjectAltName` extension. Any parse failure is
/// reported as `Error::InvalidCertificate(BadEncoding)` -- same class of
/// error webpki itself returns for a cert it can't decode, per that trait
/// method's doc comment.
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
                // Malformed-length IP SANs (not 4 or 16 bytes) are simply not
                // matchable -- Envoy's own `match_typed_subject_alt_names`
                // has nothing to compare a matcher against either.
            }
            _ => {
                // Envoy's SAN matcher config only supports DNS/URI/IP_ADDRESS
                // (lowering already rejects EMAIL/OTHER_NAME matchers -- see
                // `SanType`'s doc comment); a cert presenting other SAN kinds
                // just has nothing to match against for those, not an error.
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

/// Envoy `match_typed_subject_alt_names` semantics: accept if ANY matcher in
/// `san_matchers` matches ANY of the peer cert's SANs of that matcher's type.
/// Empty `san_matchers` is the caller's job to skip -- this function always
/// enforces a match when called.
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

/// If `err` is rustls reporting an expired/not-yet-valid leaf *and* carries
/// enough context to compute a timestamp inside that cert's validity window,
/// return that timestamp.
///
/// Why not just catch the error and assert success (the way the hostname
/// bypass above does)? Because webpki checks a certificate's own
/// notBefore/notAfter before it finishes path building -- an expired leaf
/// signed by a completely untrusted CA can come back as `Expired`/
/// `ExpiredContext`, never reaching the `UnknownIssuer` check at all. Blindly
/// trusting "the only error was expiry" would silently accept a cert from
/// the wrong CA. So instead this re-runs the *entire* inner verification
/// (chain trust, signatures, hostname -- everything) at a moment the cert
/// was actually valid; any other problem still surfaces normally.
///
/// The plain (context-free) `Expired`/`NotValidYet` variants carry no
/// timestamp to retry with -- per rustls's webpki glue they only occur for
/// `InvalidCertValidity` (a malformed notBefore/notAfter ordering), which
/// isn't a "just retry at a different time" situation anyway -- so those
/// return `None` and the caller lets the original error propagate.
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

/// Wraps a `WebPkiServerVerifier` (chain-trust validation against
/// `trusted_ca`/`system_root_certs`) and applies the Envoy-parity twists chunk
/// B1/B2 need:
/// - Envoy's `trusted_ca`-only validation context does *not* do RFC 6125
///   hostname/SNI verification -- only `match_typed_subject_alt_names` does.
///   So a hostname mismatch from the inner verifier is always downgraded to
///   success; SAN matchers (below) are the real hostname-shaped check.
/// - `allow_expired_certificate`: an expired/not-yet-valid leaf is downgraded
///   to success too, but only when the IR asked for it.
/// - `san_matchers`: after the inner verifier succeeds (including via either
///   bypass above), the peer cert's SANs must satisfy at least one matcher.
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
    /// Handle an inner-verifier error: downgrade a hostname mismatch to
    /// success unconditionally (Envoy's `trusted_ca`-only model, see the
    /// struct doc), and -- only when configured -- retry the whole
    /// verification at a moment the leaf was valid when the failure looked
    /// like expiry (see `expiry_bypass_time`'s doc comment for why a retry,
    /// not a blind assert). Any other error, or a retry that still fails,
    /// propagates unchanged.
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

        // Ground rule #1: SAN matching only runs after (real or bypassed)
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

/// Downstream mirror of [`HostnameBypassServerCertVerifier`]: wraps a
/// `WebPkiClientVerifier` (built from `validation.ca` +
/// `require_client_certificate`) and applies the same
/// `allow_expired_certificate`/`san_matchers` carve-outs to the *client*
/// certificate a peer presents during mTLS. There's no hostname to bypass
/// here -- `ClientCertVerifier::verify_client_cert` never took a
/// `ServerName` in the first place, only `verify_server_cert` did -- so this
/// wrapper is strictly smaller than the upstream one.
#[derive(Debug)]
pub(super) struct CarveoutClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    san_matchers: Vec<SanMatcherIR>,
    allow_expired_certificate: bool,
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

    /// Same retry-at-a-valid-time strategy as
    /// `HostnameBypassServerCertVerifier::retry_bypassing_hostname_and_expiry`,
    /// minus the hostname carve-out (there's no `ServerName` on this side).
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

// Rust note: `ClientCertVerifier` is the server-side-of-mTLS mirror of
// `ServerCertVerifier` -- same shape (delegate signature checks, override
// `verify_client_cert`), but its methods live under
// `rustls::server::danger` instead of `rustls::client::danger`, and it adds
// `offer_client_auth`/`client_auth_mandatory`/`root_hint_subjects`, which
// have no upstream-side equivalent, so those are pure delegation too.
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
