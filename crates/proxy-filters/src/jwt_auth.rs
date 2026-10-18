//! Verifies JWTs against a cached JWKS snapshot. Virtual-key authentication
//! runs first; this authenticator claims other `Bearer` values and treats
//! verification failures as terminal (see [`crate::auth::AuthOutcome`]).
//!
//! Only RS256 is accepted, preventing algorithm confusion. The tenant claim
//! is configurable and required; JWT `key_id` records the JWKS `kid` for audit
//! and rotation. Network discovery and refresh live in [`crate::jwks_refresh`];
//! this module only reads the published snapshot.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use base64::Engine as _;
use http::header::AUTHORIZATION;
use http::HeaderMap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

use crate::auth::{
    AuthError, AuthOutcome, Authenticator, KeyId, Principal, TenantId, TenantPolicy, BEARER_PREFIX,
    KEY_PREFIX,
};
use crate::jwks_refresh::JwksSnapshot;

/// Clock-skew leeway (seconds) applied to `exp`/`nbf` when
/// [`JwtValidationConfig::leeway_seconds`] is left unset.
///
/// 60 seconds, matching two independent precedents rather than an arbitrary
/// choice: it is `jsonwebtoken::Validation`'s own default, and it is Envoy's
/// `envoy.extensions.filters.http.jwt_authn.v3.JwtProvider.clock_skew_seconds`
/// default ("If not specified, default is 60 seconds") -- the config surface
/// this project's data plane already speaks. Keeping ours the same means an
/// operator migrating a `jwt_authn` config does not have to re-derive a
/// different clock-skew tolerance from scratch.
pub const DEFAULT_LEEWAY_SECONDS: u64 = 60;

/// One RSA public key from a JWKS, in the form this module needs to build a
/// [`jsonwebtoken::DecodingKey`] -- already-decoded bytes, not the JWKS's own
/// base64url `n`/`e` strings.
///
/// Rust note: raw bytes rather than the base64url text `n`/`e` arrive in a
/// JWKS document -- exactly the same layering [`crate::auth::KeySet`] uses
/// (it takes already-computed digest bytes, not a hex string): decoding
/// base64url text is a CONFIG-PARSING concern, and this module's constructors
/// take already-valid Rust values, the same "library only" scope
/// [`crate::auth::VirtualKeyAuthenticator::new`] has today. A future 2c-ii
/// parser is what will decode a JWKS document's `n`/`e` text into these
/// bytes, the same way `auth_filter::parse_config` decodes `digest_hex` into
/// the bytes `KeySet::insert_digest` takes.
pub struct JwkRsaKey {
    /// Selects this key at verification time against a token's `kid` header.
    pub kid: String,
    /// RSA modulus, big-endian.
    pub n: Vec<u8>,
    /// RSA public exponent, big-endian.
    pub e: Vec<u8>,
}

/// A statically configured JWKS, keyed by `kid`. See [`JwkRsaKey`]'s doc for
/// why this takes decoded bytes rather than a JWKS document directly.
pub struct JwtKeySet {
    keys: HashMap<String, DecodingKey>,
}

impl JwtKeySet {
    pub fn new() -> Self {
        JwtKeySet {
            keys: HashMap::new(),
        }
    }

    /// Adds one key. `DecodingKey::from_rsa_raw_components` is infallible --
    /// unlike `DecodingKey::from_rsa_components` (which this module
    /// deliberately does NOT call), it takes already-decoded bytes rather
    /// than base64url text, so there is no decode step here that could fail.
    pub fn insert(&mut self, key: JwkRsaKey) {
        self.keys.insert(
            key.kid,
            DecodingKey::from_rsa_raw_components(&key.n, &key.e),
        );
    }

    fn get(&self, kid: &str) -> Option<&DecodingKey> {
        self.keys.get(kid)
    }

    /// Number of keys in the set. Used by the refresh path to refuse to
    /// publish an empty set, and by refresh logging -- not a general
    /// accessor, and it leaks nothing `Debug` doesn't already print.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Default for JwtKeySet {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for JwtKeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A public key is not secret, but the convention in this crate (see
        // `auth`'s module doc) is to spell every `Debug` impl out explicitly
        // rather than derive it, so a future field addition has to make the
        // same call rather than inherit one. Only the `kid`s, for the same
        // "count/identifiers only" shape `KeySet`'s `Debug` uses.
        f.debug_struct("JwtKeySet")
            .field("kids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Which claim becomes [`Principal::tenant`], plus the token-content checks
/// this authenticator applies. See the module doc's "tenant claim is
/// configurable" section for why [`Self::tenant_claim`] has no default.
pub struct JwtValidationConfig {
    /// Required. Which claim in a verified token becomes `Principal.tenant`.
    pub tenant_claim: String,
    /// If `Some`, the token's `iss` claim must equal this value, AND must be
    /// present (see [`build_validation`]'s doc for why presence is enforced
    /// explicitly rather than left to `jsonwebtoken`'s default).
    pub issuer: Option<String>,
    /// If `Some`, the token's `aud` claim must contain this value, AND must
    /// be present.
    pub audience: Option<String>,
    /// Clock-skew leeway (seconds) for `exp`/`nbf`. `None` means
    /// [`DEFAULT_LEEWAY_SECONDS`] -- deliberately distinct from `Some(0)`
    /// ("no leeway at all", a real, stricter, operator-chosen policy), the
    /// same `None`-vs-`Some(0)` distinction
    /// [`crate::auth::TenantPolicy::budget`] already documents for the same
    /// reason.
    pub leeway_seconds: Option<u64>,
    /// Optional. Maps a verified token's tenant-claim VALUE to the
    /// llm-proxy tenant to admit it as. Empty means the claim value is used
    /// directly; non-empty means only mapped values are admitted and anything
    /// else is [`crate::auth::AuthError::JwtTenantNotMapped`].
    pub tenant_map: HashMap<String, String>,
    /// Optional verified claim used to distinguish JWT callers for accounting.
    pub subject_claim: Option<String>,
}

/// Builds the one [`Validation`] a [`JwtAuthenticator`] checks every token
/// against.
///
/// # Why `iss`/`aud` presence is enforced here, not left to `jsonwebtoken`'s
/// default
///
/// `jsonwebtoken::validate` only checks `iss`/`aud` **if the claim is present
/// in the token** unless that claim name is also added to
/// `required_spec_claims` -- so configuring `Validation::set_issuer` alone
/// does NOT reject a token that omits `iss` entirely. That is documented
/// behavior, not a bug, but it is exactly the fail-open shape AGENTS.md "Fail-open controls" warns
/// about: an operator who configures an expected issuer has stated an intent
/// ("only tokens from this issuer"), and a token that dodges the check by
/// omitting the claim must not silently pass it. So whenever
/// [`JwtValidationConfig::issuer`]/`audience` is `Some`, this function also
/// adds `"iss"`/`"aud"` to `required_spec_claims`, closing that gap.
fn build_validation(config: &JwtValidationConfig) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = config.leeway_seconds.unwrap_or(DEFAULT_LEEWAY_SECONDS);
    // `exp` is already required and validated by `Validation::new`'s
    // defaults; `nbf` is validated only if present -- opt in explicitly,
    // since `jsonwebtoken` defaults `validate_nbf` to `false`.
    validation.validate_nbf = true;

    if let Some(issuer) = &config.issuer {
        validation.set_issuer(&[issuer.as_str()]);
        validation.required_spec_claims.insert("iss".to_string());
    }
    if let Some(audience) = &config.audience {
        validation.set_audience(&[audience.as_str()]);
        validation.required_spec_claims.insert("aud".to_string());
    } else {
        // No configured audience: do not require or check one. `Validation`
        // defaults `validate_aud` to `true`, which -- per its own doc --
        // still rejects a token that carries an `aud` claim when none is
        // configured to compare it against ("the JWT MUST be rejected" per
        // RFC 7519 §4.1.3, which `jsonwebtoken` quotes verbatim). That is the
        // conservative, spec-correct default and this authenticator keeps
        // it; it is not disabled here.
    }

    validation
}

/// [`Authenticator`] for JWTs verified against a JWKS.
///
/// The key set is a lock-free [`ArcSwap`] snapshot, never fetched on the
/// request path: static configs publish once at build
/// ([`JwtAuthenticator::new`]); discovery-configured providers are
/// republished by [`crate::jwks_refresh::start_jwks_refresher`]
/// ([`JwtAuthenticator::new_shared`]). See that module's doc for the
/// failure semantics. This answers the module doc's old open question in
/// the affirmative: the synchronous [`Authenticator`] trait accommodates
/// asynchronous refresh with no reshaping, because refresh publishes and
/// verification only ever loads.
pub struct JwtAuthenticator {
    snapshot: Arc<ArcSwap<JwksSnapshot>>,
    validation: Validation,
    tenant_claim: String,
    tenant_map: HashMap<String, String>,
    subject_claim: Option<String>,
    expected_issuer: Option<String>,
    /// Fail-closed staleness bound for discovery snapshots (`None` for
    /// static seeds, which never go stale). See
    /// [`JwksSnapshot::is_stale`].
    max_stale: Option<Duration>,
    /// Where a JWT tenant's trace-export opt-in is read. `None` (no control
    /// plane, as in tests and static seeds) captures nothing.
    trace_consent: Option<Arc<crate::auth::TraceConsent>>,
}

impl JwtAuthenticator {
    pub fn new(keys: JwtKeySet, config: JwtValidationConfig) -> Self {
        JwtAuthenticator {
            snapshot: Arc::new(ArcSwap::new(Arc::new(JwksSnapshot::seeded(keys)))),
            validation: build_validation(&config),
            tenant_claim: config.tenant_claim,
            tenant_map: config.tenant_map,
            subject_claim: config.subject_claim,
            expected_issuer: config.issuer,
            max_stale: None,
            trace_consent: None,
        }
    }

    /// Shares a refreshable snapshot (see [`JwksSnapshot`]). `max_stale`
    /// must be `Some` for discovery snapshots so a snapshot whose refreshes
    /// stopped landing is refused rather than served forever.
    /// Read trace-export consent through `consent` (ADR-0008 decision 2).
    pub fn with_trace_consent(mut self, consent: Arc<crate::auth::TraceConsent>) -> Self {
        self.trace_consent = Some(consent);
        self
    }

    pub fn new_shared(
        snapshot: Arc<ArcSwap<JwksSnapshot>>,
        config: JwtValidationConfig,
        max_stale: Option<Duration>,
    ) -> Self {
        JwtAuthenticator {
            snapshot,
            validation: build_validation(&config),
            tenant_claim: config.tenant_claim,
            tenant_map: config.tenant_map,
            subject_claim: config.subject_claim,
            expected_issuer: config.issuer,
            max_stale,
            trace_consent: None,
        }
    }
}

impl fmt::Debug for JwtAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtAuthenticator")
            .field("snapshot", &self.snapshot.load())
            .field("tenant_claim", &self.tenant_claim)
            .field("subject_claim", &self.subject_claim)
            .field("max_stale", &self.max_stale)
            .finish()
    }
}

/// Maps a `jsonwebtoken` verification failure onto this crate's shared
/// [`AuthError`]. Exhaustive over `jsonwebtoken::errors::ErrorKind`'s
/// variants that this authenticator's own `Validation` can ever produce;
/// every kind this authenticator does not specifically expect (a
/// non-exhaustive enum upstream, plus JSON/base64/UTF-8 decode failures that
/// surface as `ErrorKind::Json`/`Base64`/`Utf8`) folds into `JwtMalformed`
/// rather than panicking on an unmatched variant.
fn map_verification_error(kind: &jsonwebtoken::errors::ErrorKind) -> AuthError {
    use jsonwebtoken::errors::ErrorKind;
    match kind {
        // Covers both a bad signature AND `header.alg` not being in this
        // authenticator's allow-list (`InvalidAlgorithm`) -- see the module
        // doc for why an attacker must not be able to tell these apart.
        ErrorKind::InvalidSignature | ErrorKind::InvalidAlgorithm => AuthError::JwtInvalidSignature,
        ErrorKind::ExpiredSignature => AuthError::JwtExpired,
        ErrorKind::ImmatureSignature => AuthError::JwtNotYetValid,
        ErrorKind::InvalidIssuer => AuthError::JwtIssuerMismatch,
        ErrorKind::InvalidAudience => AuthError::JwtAudienceMismatch,
        // `build_validation` adds "iss"/"aud" to `required_spec_claims`
        // whenever an issuer/audience is configured (see its doc for why); a
        // token that omits the claim entirely fails HERE, as
        // `MissingRequiredClaim`, rather than as `InvalidIssuer`/
        // `InvalidAudience` above. Mapped by claim name so "no iss at all"
        // reads the same as "wrong iss" -- both are, from an operator's
        // point of view, the same fact: this token did not come from the
        // configured issuer/audience.
        ErrorKind::MissingRequiredClaim(claim) if claim == "iss" => AuthError::JwtIssuerMismatch,
        ErrorKind::MissingRequiredClaim(claim) if claim == "aud" => AuthError::JwtAudienceMismatch,
        _ => AuthError::JwtMalformed,
    }
}

impl Authenticator for JwtAuthenticator {
    fn authenticate(&self, headers: &HeaderMap) -> AuthOutcome {
        let Some(value) = headers.get(AUTHORIZATION) else {
            return AuthOutcome::NoCredential;
        };
        let Ok(value) = value.to_str() else {
            return AuthOutcome::NoCredential;
        };
        let Some(presented) = value.strip_prefix(BEARER_PREFIX) else {
            return AuthOutcome::NoCredential;
        };
        if presented.starts_with(KEY_PREFIX) {
            // Virtual-key territory -- see the module doc's "NoCredential
            // split, mirrored" section.
            return AuthOutcome::NoCredential;
        }

        // An issuer is safe to read before verification only as a routing hint:
        // it chooses the verifier, never grants access. This lets independent
        // OIDC providers coexist without one provider claiming every JWT.
        if let Some(expected) = &self.expected_issuer {
            let issuer = presented
                .split('.')
                .nth(1)
                .and_then(|segment| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(segment)
                        .ok()
                })
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .and_then(|claims| {
                    claims
                        .get("iss")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                });
            if issuer.as_deref().is_some_and(|issuer| issuer != expected) {
                return AuthOutcome::NoCredential;
            }
        }

        // From here on every outcome is terminal: this authenticator has
        // claimed the credential as a JWT.
        let snapshot = self.snapshot.load();
        // Fail closed on staleness: a discovery snapshot whose refreshes
        // stopped landing must not be served forever. Static seeds carry
        // `max_stale: None` and skip this entirely; a discovery snapshot
        // with no successful refresh yet reports an unbounded age and is
        // refused, which is exactly the fail-closed birth state the
        // snapshot constructor documents.
        if let Some(max_stale) = self.max_stale {
            let stale = snapshot.age().map(|age| age > max_stale).unwrap_or(true);
            if stale {
                return AuthOutcome::Rejected(AuthError::JwtJwksStale);
            }
        }
        let header = match jsonwebtoken::decode_header(presented) {
            Ok(header) => header,
            Err(_) => return AuthOutcome::Rejected(AuthError::JwtMalformed),
        };

        let Some(kid) = header.kid.as_deref() else {
            return AuthOutcome::Rejected(AuthError::JwtUnknownKid);
        };
        let Some(key) = snapshot.keys().get(kid) else {
            return AuthOutcome::Rejected(AuthError::JwtUnknownKid);
        };

        let data = match jsonwebtoken::decode::<serde_json::Value>(presented, key, &self.validation)
        {
            Ok(data) => data,
            Err(err) => return AuthOutcome::Rejected(map_verification_error(err.kind())),
        };

        let tenant = data
            .claims
            .get(&self.tenant_claim)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        let Some(tenant) = tenant else {
            return AuthOutcome::Rejected(AuthError::JwtMissingTenantClaim);
        };

        // A non-empty map means "only these mappings": the claim value is a
        // lookup key, never a tenant name.
        let tenant = if self.tenant_map.is_empty() {
            tenant.to_string()
        } else {
            match self.tenant_map.get(tenant) {
                Some(mapped) => mapped.clone(),
                None => return AuthOutcome::Rejected(AuthError::JwtTenantNotMapped),
            }
        };

        // The subject, scoped by issuer and tenant so two issuers' `sub`
        // values cannot collide, is both the key id and the user. Without a
        // subject claim the key id is the signing key's `kid`, which names
        // no user.
        let key_id = match &self.subject_claim {
            Some(claim) => match data
                .claims
                .get(claim)
                .and_then(|value| value.as_str())
                .filter(|s| !s.is_empty())
            {
                Some(subject) => KeyId::new(format!(
                    "jwt:{}:{}:{}",
                    self.expected_issuer.as_deref().unwrap_or("issuerless"),
                    tenant,
                    subject
                )),
                None => return AuthOutcome::Rejected(AuthError::JwtMissingTenantClaim),
            },
            None => KeyId::new(kid.to_string()),
        };
        let user_id = self
            .subject_claim
            .is_some()
            .then(|| key_id.as_str().to_owned());
        let tenant = TenantId::new(tenant);
        let trace_export = self
            .trace_consent
            .as_ref()
            .is_some_and(|consent| consent.opted_in(&tenant));
        AuthOutcome::Authenticated(Principal {
            tenant,
            // See the module doc's "`Principal::key_id` for a JWT" section.
            key_id,
            user_id,
            policy: Arc::new(TenantPolicy::default()),
            // JWT principals stay in platform mode; see ADR-0007. This path
            // reads the JWKS snapshot, not the control-plane snapshot, and
            // must not add a second load to reach tenant credentials.
            tenant_credentials: None,
            policy_generation: None,
            trace_export,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use http::HeaderValue;

    // --- test key generation -------------------------------------------------
    //
    // `ring`/`rcgen` can SIGN with RSA but cannot GENERATE an RSA keypair --
    // see this crate's `Cargo.toml` `rsa` dev-dependency comment. `rsa`
    // builds a fresh 2048-bit keypair per test process (never commit a private key, even
    // a test one); this
    // module then signs every test token with `ring` directly, the same
    // primitive `jsonwebtoken` uses in production, so tests exercise the real
    // verification path rather than a stand-in for it.

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rsa::traits::PublicKeyParts;

    /// The test RSA keypair plus the pieces this module's tests need
    /// repeatedly: PKCS#1 DER (for `ring` signing) and the raw (n, e)
    /// components (for building a [`JwkRsaKey`]).
    struct TestKey {
        der: Vec<u8>,
        n: Vec<u8>,
        e: Vec<u8>,
    }

    /// The SAME 2048-bit RSA key `crates/proxy-core/tests/tls.rs` already
    /// commits as `RSA_TEST_KEY_PEM`, reused here deliberately rather than
    /// generating a fresh one per test.
    ///
    /// **Why a committed key and not `RsaPrivateKey::new`.** `ring` (and so
    /// `rcgen`) can SIGN with RSA but cannot GENERATE an RSA keypair, which
    /// is why `tls.rs` embedded this key in the first place — the same
    /// constraint, met the same way. Generating instead costs 2048-bit RSA
    /// keygen **per test process**, and nextest runs one process per test:
    /// measured, that took this crate from ~2s to 30.6s and the workspace
    /// suite from ~23s to 60.7s. A `OnceLock` does not help, because the
    /// cache only ever serves the single test sharing that process.
    ///
    /// This is test-only key material for verifying signatures we produce in
    /// the same function. It authenticates nothing, is not a credential for
    /// any system, and reusing the one already in the tree avoids adding a
    /// second piece of committed key material for no gain.
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCTqRdE9Hfk0JVI
xm1L0/pCnijfoIVFq2Eab+f6alpA9yGbFAk6hI8v2lPmeH+77UuMVv+6PaL3tfQp
5HXc1g1eEg80aLbZ6w3aHDWfyowMWkOt3VfpSJq9Sjy5GvlQnmXHBmVsoSAjb3NT
vMhcoT4avTu3QpN08Zlz2qlHI7ck+1yW8KtusuOyIHIRCfukdRzMkWaPA5lZNARK
MYMXJ8MsKDMpFde4QqypJNTOEf8eURGdwmRv03lB3QToqhsVg8QXow1bNVkU5MnM
d1Go+6Z8Ol3EREpgtp1/iTr1lM1dtWztSYZtOugWc2Cp0WjvtFzVCT2dahs12heX
SN0idXIrAgMBAAECggEABq9WDVof/2zuBUBufEtZfiCY6x7iSbgrij3cu7qK4XwO
um2ayVps/RaeS8XSyphAnlbl9vGJajuDlU3xhBDww/x/UbkX5h+9Hc2/I7/QvVJs
0/c8XqRZ1Q4CV8L/3IV/SBZjCxr0UIZgKz9VttPZ8u30QSSzdkzlzJfup/jW9saU
2+2IDje7b20PrHj530waaEsk5f5L1MveMq3A2D8oyInKR8UfyUfu65EAqmJca7xX
b8rvdX2IRSahD9BgLLTW3m/NlMuwz+GSWCzkgGTv1+ZifQt5sdJdJ+ZL3jHjXcQt
+nXqFhcRIVL8ha9VDY24bY0yLT12Cf9nV3oARGxJiQKBgQDGTUWUNUP42XLB+ucv
fSwxvjktFbNecIvehxAG2tmqj8O0e95L8sQIO8P76a0hiSlSHYZb2RV1zf8ZYWRa
O6eyYbUCtdc8hFWXtGUaHQv5wLQsN+1dEN9cwA/myzk4ML2H/h2qfZOuLdCu+Jx6
jZoetGyHEVFSUYQ6NYakur/ZBQKBgQC+n76XjEhhCilogyQP3JD9UE2YX2lwkYma
oLVUByeckBdJpp/mVUPz78H7Mv65Ve5E4cmwBrzTgcRcsVcu8LkpVAcP24ePnbo7
LO5Z8tVWjOl4m51bH7CvxU1YQ77ugf7nufG+bVqAilGaFEWFIOR9hYI/cJqdn/Yl
9KsITyhFbwKBgGkWBetWluDHCyN0/RKTeNobfl1ABL/lUJnqZTncvEDA0utQQStq
SSw7z84ttUvyTe1wLAV8cvzs32Tp0a5nsqS7VptLFfbCAkHUnUdLYU9HKbPNJ4KM
MHIMbeDWjUoTujzZE4uH5L0HFnHC2dmwNJ5U6rZhHQFMpY/bUbD2LjipAoGAUa1+
686XAMVq4rY2UHmQwomTBfPz6ODjVhcAOyXpqiLvZ4Z2wynLuQ0FUA4UqPMR6f/Y
/IyWggX7TkBKe/l3TScM85V762SI9GwXIQF0ueYc76m17eKRQW9H6cb1W5rlzwKU
e6S9f5BE0MFY3GcwoDwBiA9GoL12qeLBGglY1w8CgYAkmoNroaLtlMc9yuotXvEW
ftXH1exAPxFtFRzfxD1V1Du8hrIwlGEtLOyOUgTUQoF2TW25ECtaFt2HRFYPnwkO
7TqEO0AxyAFJehappUq3Zcj35q/fkiPETxvE1nANFCRUHCBaW+l2EPR0DjrMNTa9
GdGIML90cFtpXr13uutgIg==
-----END PRIVATE KEY-----
";

    /// Parses [`TEST_KEY_PEM`] into the pieces these tests need: PKCS#1 DER
    /// (for `ring` signing through `jsonwebtoken`) and the raw (n, e)
    /// components (for building a [`JwkRsaKey`]). Parsing is microseconds,
    /// against seconds for generation — that difference is the whole reason
    /// this function replaced a generator.
    fn load_test_key() -> TestKey {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::RsaPrivateKey;

        let private_key = RsaPrivateKey::from_pkcs8_pem(TEST_KEY_PEM).expect("test key parses");
        let public_key = private_key.to_public_key();
        let der = private_key
            .to_pkcs1_der()
            .expect("PKCS#1 DER encoding")
            .as_bytes()
            .to_vec();

        TestKey {
            der,
            n: public_key.n().to_bytes_be(),
            e: public_key.e().to_bytes_be(),
        }
    }

    fn shared_test_key() -> &'static TestKey {
        static KEY: std::sync::OnceLock<TestKey> = std::sync::OnceLock::new();
        KEY.get_or_init(load_test_key)
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Signs `message` (already `header_b64.payload_b64`) with the test RSA
    /// key via `ring` directly -- the same primitive `jsonwebtoken` calls
    /// internally, exercised here so a test token's signature is real rather
    /// than a stand-in for one.
    fn sign_rs256(key: &TestKey, message: &[u8]) -> String {
        let key_pair = ring::signature::RsaKeyPair::from_der(&key.der).expect("parse PKCS#1 DER");
        let mut signature = vec![0u8; key_pair.public().modulus_len()];
        let rng = ring::rand::SystemRandom::new();
        key_pair
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &rng,
                message,
                &mut signature,
            )
            .expect("RS256 sign");
        b64(&signature)
    }

    /// Builds a complete, validly RS256-signed JWT from raw header/payload
    /// JSON text -- lower-level than `jsonwebtoken::encode` on purpose, so
    /// tests can construct headers/payloads `jsonwebtoken`'s own `encode`
    /// could never produce (e.g. non-JSON claims bytes) while still
    /// producing a signature this module's production `decode` call
    /// verifies for real.
    fn build_jwt(key: &TestKey, header_json: &str, payload_bytes: &[u8]) -> String {
        let header_b64 = b64(header_json.as_bytes());
        let payload_b64 = b64(payload_bytes);
        let message = format!("{header_b64}.{payload_b64}");
        let sig_b64 = sign_rs256(key, message.as_bytes());
        format!("{message}.{sig_b64}")
    }

    /// Flips one character in the INTERIOR of a token's signature segment,
    /// producing a well-formed-but-wrong signature.
    ///
    /// Deliberately NOT the segment's last one or two characters: an
    /// RSA-2048 signature is 256 bytes, which base64 encodes with a 1-byte
    /// remainder in its final quantum -- so the signature's very last
    /// character carries only the leftover byte's low 2 bits plus 4 forced
    /// **padding** bits that a canonical/strict base64 decoder requires to
    /// be zero. Flipping THAT character is a coin flip between "still
    /// decodes, now wrong" and "no longer decodes as valid base64 at all"
    /// depending on the (freshly regenerated, per test process) key's actual
    /// last byte -- which is exactly the flakiness this helper replaces.
    /// Flipping an interior character avoids the padding-bit boundary
    /// entirely, so the result reliably still decodes and reliably no
    /// longer verifies.
    fn tamper_signature(token: &str) -> String {
        let (message, signature) = token
            .rsplit_once('.')
            .expect("test token has a signature segment");
        let mut chars: Vec<char> = signature.chars().collect();
        let idx = chars.len() / 2;
        chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        format!("{message}.{tampered}")
    }

    fn headers_with_bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    fn authenticator_with_key(
        key: &TestKey,
        kid: &str,
        config: JwtValidationConfig,
    ) -> JwtAuthenticator {
        let mut keys = JwtKeySet::new();
        keys.insert(JwkRsaKey {
            kid: kid.to_string(),
            n: key.n.clone(),
            e: key.e.clone(),
        });
        JwtAuthenticator::new(keys, config)
    }

    /// An authenticator with NO configured keys, for tests whose outcome is
    /// decided before `self.keys` is ever consulted (a malformed shape, or a
    /// value this authenticator declines outright) -- deliberately avoids
    /// [`shared_test_key`]'s RSA keygen, which real 2048-bit RSA keygen makes
    /// noticeably slow (seconds) under `nextest`'s one-process-per-test
    /// model, where nothing is shared across the tests that DO need it.
    fn authenticator_with_no_keys(config: JwtValidationConfig) -> JwtAuthenticator {
        JwtAuthenticator::new(JwtKeySet::new(), config)
    }

    fn default_config() -> JwtValidationConfig {
        JwtValidationConfig {
            tenant_claim: "tenant".to_string(),
            issuer: None,
            audience: None,
            leeway_seconds: None,
            tenant_map: HashMap::new(),
            subject_claim: None,
        }
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Default header JSON: RS256, naming `kid`.
    fn header_json(kid: &str) -> String {
        format!(r#"{{"alg":"RS256","kid":"{kid}"}}"#)
    }

    /// Valid claims (as JSON text, ready to sign): `exp` an hour out, a
    /// `tenant` claim, plus any `extra` fields layered on top (later keys win
    /// on collision since this is a flat string template, so callers needing
    /// to OVERRIDE `exp`/`tenant` pass those same names in `extra`... this
    /// helper instead builds through `serde_json::Value` so overrides are
    /// real map overwrites, not string concatenation).
    fn claims(overrides: &[(&str, serde_json::Value)]) -> String {
        let mut map = serde_json::json!({
            "tenant": "tenant-a",
            "exp": now() + 3600,
        });
        for (key, value) in overrides {
            map[*key] = value.clone();
        }
        map.to_string()
    }

    // --- 1: structurally malformed (not three segments) -> Rejected, not
    // NoCredential -- the first test written, per the task's "write one
    // rejection test, then the rest" instruction.
    #[test]
    fn a_bearer_value_with_the_wrong_segment_count_is_rejected_as_malformed() {
        let auth = authenticator_with_no_keys(default_config());

        let headers = headers_with_bearer("not.a.jwt.at.all.too-many-dots");
        match auth.authenticate(&headers) {
            AuthOutcome::Rejected(AuthError::JwtMalformed) => {}
            AuthOutcome::Rejected(other) => panic!("expected JwtMalformed, got {other:?}"),
            AuthOutcome::NoCredential => panic!(
                "a non-llmp_-prefixed Bearer value is THIS authenticator's kind of credential; \
                 a malformed one must be Rejected, not deferred -- see the module doc's mirrored \
                 NoCredential/Rejected split"
            ),
            AuthOutcome::Authenticated(_) => panic!("a malformed token must not authenticate"),
        }
    }

    // --- 2: a validly signed, well-formed token authenticates with the
    // configured tenant claim AND the JWKS `kid` as key_id.
    #[test]
    fn a_valid_token_authenticates_with_the_configured_tenant_claim_and_kid() {
        let key = shared_test_key();
        let auth = authenticator_with_key(key, "key-1", default_config());
        let token = build_jwt(key, &header_json("key-1"), claims(&[]).as_bytes());

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Authenticated(principal) => {
                assert_eq!(principal.tenant.as_str(), "tenant-a");
                assert_eq!(principal.key_id.as_str(), "key-1");
                // A `kid` names the signing key, shared by every caller.
                assert_eq!(principal.user_id, None);
            }
            other => panic!(
                "expected Authenticated; Rejected={} NoCredential={}",
                matches!(other, AuthOutcome::Rejected(_)),
                matches!(other, AuthOutcome::NoCredential)
            ),
        }
    }

    // --- 2a: with a subject claim, the user is the issuer- and tenant-scoped
    // subject, so two callers sharing a signing key are two users.
    #[test]
    fn a_configured_subject_claim_names_the_user() {
        let key = shared_test_key();
        let config = JwtValidationConfig {
            issuer: Some("https://idp.example".to_string()),
            subject_claim: Some("sub".to_string()),
            ..default_config()
        };
        let auth = authenticator_with_key(key, "key-1", config);
        let user_of = |sub: &str| {
            let token = build_jwt(
                key,
                &header_json("key-1"),
                claims(&[
                    ("sub", serde_json::Value::String(sub.to_string())),
                    ("iss", "https://idp.example".into()),
                ])
                .as_bytes(),
            );
            match auth.authenticate(&headers_with_bearer(&token)) {
                AuthOutcome::Authenticated(principal) => principal.user_id,
                _ => panic!("expected Authenticated for subject {sub}"),
            }
        };
        assert_eq!(
            user_of("alice").as_deref(),
            Some("jwt:https://idp.example:tenant-a:alice")
        );
        assert_eq!(
            user_of("bob").as_deref(),
            Some("jwt:https://idp.example:tenant-a:bob")
        );
    }

    // --- 3: a DIFFERENT tenant claim name is honored -- proves the claim is
    // read by configured name, not hardcoded to `sub`.
    #[test]
    fn the_tenant_claim_name_is_configurable_not_hardcoded_to_sub() {
        let key = shared_test_key();
        let config = JwtValidationConfig {
            tenant_claim: "https://example.com/tenant".to_string(),
            ..default_config()
        };
        let auth = authenticator_with_key(key, "key-1", config);
        let token = build_jwt(
            key,
            &header_json("key-1"),
            claims(&[
                ("tenant", serde_json::Value::Null),
                (
                    "https://example.com/tenant",
                    serde_json::Value::String("custom-tenant".to_string()),
                ),
            ])
            .as_bytes(),
        );

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Authenticated(principal) => {
                assert_eq!(principal.tenant.as_str(), "custom-tenant");
            }
            other => panic!(
                "expected Authenticated reading the custom claim; Rejected={}",
                matches!(other, AuthOutcome::Rejected(_))
            ),
        }
    }

    // --- 4: exp in the past (beyond leeway) -> Rejected(JwtExpired).
    #[test]
    fn an_expired_token_is_rejected() {
        let key = shared_test_key();
        let auth = authenticator_with_key(key, "key-1", default_config());
        // Well beyond the default 60s leeway.
        let token = build_jwt(
            key,
            &header_json("key-1"),
            claims(&[("exp", serde_json::json!(now() - 3600))]).as_bytes(),
        );

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(AuthError::JwtExpired) => {}
            other => panic!(
                "expected Rejected(JwtExpired); Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 5: nbf in the future (beyond leeway) -> Rejected(JwtNotYetValid).
    #[test]
    fn a_not_yet_valid_token_is_rejected() {
        let key = shared_test_key();
        let auth = authenticator_with_key(key, "key-1", default_config());
        let token = build_jwt(
            key,
            &header_json("key-1"),
            claims(&[("nbf", serde_json::json!(now() + 3600))]).as_bytes(),
        );

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(AuthError::JwtNotYetValid) => {}
            other => panic!(
                "expected Rejected(JwtNotYetValid); Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 6: a configured leeway of 0 makes a just-in-the-past exp reject --
    // proves `Some(0)` is honored as "no leeway", distinct from the `None`
    // default, per the module doc's `None`-vs-`Some(0)` distinction.
    #[test]
    fn a_configured_zero_leeway_is_honored_not_treated_as_the_default() {
        let key = shared_test_key();
        let config = JwtValidationConfig {
            leeway_seconds: Some(0),
            ..default_config()
        };
        let auth = authenticator_with_key(key, "key-1", config);
        // 5 seconds past exp: within the 60s DEFAULT leeway, but not within
        // an explicit zero.
        let token = build_jwt(
            key,
            &header_json("key-1"),
            claims(&[("exp", serde_json::json!(now() - 5))]).as_bytes(),
        );

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(AuthError::JwtExpired) => {}
            other => panic!(
                "a configured zero leeway must reject a 5s-past-exp token \
                 (the 60s default would have accepted it); Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 7: a foreign issuer defers to a later configured provider; a missing
    // issuer remains rejected (the fail-open gap `build_validation` closes).
    #[test]
    fn foreign_issuer_defers_but_a_missing_issuer_is_rejected() {
        let key = shared_test_key();
        let config = JwtValidationConfig {
            issuer: Some("https://issuer.example".to_string()),
            ..default_config()
        };
        let auth = authenticator_with_key(key, "key-1", config);

        let wrong_issuer = build_jwt(
            key,
            &header_json("key-1"),
            claims(&[("iss", serde_json::json!("https://someone-else.example"))]).as_bytes(),
        );
        match auth.authenticate(&headers_with_bearer(&wrong_issuer)) {
            AuthOutcome::NoCredential => {}
            other => panic!(
                "a foreign issuer must defer to a later provider; Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }

        let no_issuer_claim = build_jwt(key, &header_json("key-1"), claims(&[]).as_bytes());
        match auth.authenticate(&headers_with_bearer(&no_issuer_claim)) {
            AuthOutcome::Rejected(AuthError::JwtIssuerMismatch) => {}
            other => panic!(
                "an `issuer` was configured; a token with NO `iss` claim at all must still be \
                 rejected, not silently pass (see build_validation's fail-open-gap doc); \
                 Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 8: audience mismatch -> Rejected, both wrong `aud` and missing.
    #[test]
    fn audience_mismatch_is_rejected_including_a_missing_aud_claim() {
        let key = shared_test_key();
        let config = JwtValidationConfig {
            audience: Some("llm-proxy".to_string()),
            ..default_config()
        };
        let auth = authenticator_with_key(key, "key-1", config);

        let wrong_audience = build_jwt(
            key,
            &header_json("key-1"),
            claims(&[("aud", serde_json::json!("someone-else"))]).as_bytes(),
        );
        match auth.authenticate(&headers_with_bearer(&wrong_audience)) {
            AuthOutcome::Rejected(AuthError::JwtAudienceMismatch) => {}
            other => panic!(
                "expected Rejected(JwtAudienceMismatch); Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }

        let no_audience_claim = build_jwt(key, &header_json("key-1"), claims(&[]).as_bytes());
        match auth.authenticate(&headers_with_bearer(&no_audience_claim)) {
            AuthOutcome::Rejected(AuthError::JwtAudienceMismatch) => {}
            other => panic!(
                "an `audience` was configured; a token with NO `aud` claim at all must still be \
                 rejected; Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 9: `kid` naming a key absent from the JWKS -> Rejected(JwtUnknownKid).
    #[test]
    fn an_unknown_kid_is_rejected() {
        let key = shared_test_key();
        let auth = authenticator_with_key(key, "the-real-kid", default_config());
        let token = build_jwt(key, &header_json("no-such-kid"), claims(&[]).as_bytes());

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(AuthError::JwtUnknownKid) => {}
            other => panic!(
                "expected Rejected(JwtUnknownKid); Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 10: no `kid` header at all -> Rejected(JwtUnknownKid) (can't select
    // a key, same reason as an unknown one -- see AuthError::JwtUnknownKid's
    // doc).
    #[test]
    fn a_token_with_no_kid_at_all_is_rejected() {
        let key = shared_test_key();
        let auth = authenticator_with_key(key, "key-1", default_config());
        let token = build_jwt(key, r#"{"alg":"RS256"}"#, claims(&[]).as_bytes());

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(AuthError::JwtUnknownKid) => {}
            other => panic!(
                "expected Rejected(JwtUnknownKid); Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 11: signature invalid for the named key -> Rejected(JwtInvalidSignature).
    #[test]
    fn a_bad_signature_is_rejected() {
        let key = shared_test_key();
        let auth = authenticator_with_key(key, "key-1", default_config());
        let token = tamper_signature(&build_jwt(
            key,
            &header_json("key-1"),
            claims(&[]).as_bytes(),
        ));

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(AuthError::JwtInvalidSignature) => {}
            other => panic!(
                "expected Rejected(JwtInvalidSignature); Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 12: `alg: none` is rejected. `jsonwebtoken::Algorithm` has no
    // `none` variant, so the header fails to deserialize at all -- proven
    // here rather than assumed, per the task's "if the library handles them,
    // prove it with a test" instruction.
    #[test]
    fn alg_none_is_rejected() {
        // No real key needed: `jsonwebtoken::Algorithm` has no `none` variant
        // at all, so the header fails to deserialize before `self.keys` is
        // ever consulted -- see `authenticator_with_no_keys`'s doc.
        let auth = authenticator_with_no_keys(default_config());
        // No real signature is even possible for `alg: none` under RFC 7519's
        // own definition (an empty third segment) -- build exactly that.
        let header_b64 = b64(r#"{"alg":"none","kid":"key-1"}"#.as_bytes());
        let payload_b64 = b64(claims(&[]).as_bytes());
        let token = format!("{header_b64}.{payload_b64}.");

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(_) => {}
            other => panic!(
                "alg:none must be rejected; Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 13: algorithm confusion -- a token signed with HMAC, using the
    // RSA public key's own bytes as the HMAC secret (the classic attack: an
    // attacker who only ever saw the PUBLIC key tries to forge a token by
    // treating it as a symmetric secret) -- must be rejected, because this
    // authenticator's `Validation` only allows RS256. Proven directly rather
    // than trusted, per the task's instruction.
    #[test]
    fn algorithm_confusion_hmac_signed_with_the_rsa_public_key_is_rejected() {
        let key = shared_test_key();
        let auth = authenticator_with_key(key, "key-1", default_config());

        let header_b64 = b64(r#"{"alg":"HS256","kid":"key-1"}"#.as_bytes());
        let payload_b64 = b64(claims(&[]).as_bytes());
        let message = format!("{header_b64}.{payload_b64}");

        // The "secret" is the RSA modulus bytes -- exactly what an attacker
        // holding only the JWKS (public) would have.
        let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key.n);
        let tag = ring::hmac::sign(&hmac_key, message.as_bytes());
        let sig_b64 = b64(tag.as_ref());
        let token = format!("{message}.{sig_b64}");

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(AuthError::JwtInvalidSignature) => {}
            other => panic!(
                "an HS256 token must never authenticate against an RS256-only allow-list, \
                 regardless of what bytes it was 'signed' with; Rejected(other)={} \
                 Authenticated={}",
                matches!(other, AuthOutcome::Rejected(_)),
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 14: non-JSON claims, VALIDLY signed -- proves a real signature over
    // garbled claims bytes does not somehow authenticate with empty/default
    // claims.
    #[test]
    fn validly_signed_non_json_claims_are_rejected() {
        let key = shared_test_key();
        let auth = authenticator_with_key(key, "key-1", default_config());
        let token = build_jwt(key, &header_json("key-1"), b"this is not json at all");

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(_) => {}
            other => panic!(
                "non-JSON claims must be rejected even with a valid signature; Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 15: bad base64 in the payload segment -> Rejected.
    #[test]
    fn bad_base64_in_the_payload_segment_is_rejected() {
        let key = shared_test_key();
        let auth = authenticator_with_key(key, "key-1", default_config());
        let header_b64 = b64(header_json("key-1").as_bytes());
        // `!` is not in the base64url alphabet.
        let token = format!("{header_b64}.!!!not-base64!!!.whatever-signature");

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(AuthError::JwtMalformed) => {}
            other => panic!(
                "bad base64 must be Rejected(JwtMalformed); Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 16: verified token missing the configured tenant claim entirely ->
    // Rejected, never a default tenant.
    #[test]
    fn a_missing_tenant_claim_is_rejected_never_defaulted() {
        let key = shared_test_key();
        let auth = authenticator_with_key(key, "key-1", default_config());
        let token = build_jwt(
            key,
            &header_json("key-1"),
            claims(&[("tenant", serde_json::Value::Null)]).as_bytes(),
        );

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(AuthError::JwtMissingTenantClaim) => {}
            other => panic!(
                "a verified token with no tenant claim must be Rejected, never given a default \
                 tenant; Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 17: tenant claim present but an empty string -> Rejected, same as
    // absent -- an empty tenant is not a real tenant either.
    #[test]
    fn an_empty_string_tenant_claim_is_rejected() {
        let key = shared_test_key();
        let auth = authenticator_with_key(key, "key-1", default_config());
        let token = build_jwt(
            key,
            &header_json("key-1"),
            claims(&[("tenant", serde_json::json!(""))]).as_bytes(),
        );

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(AuthError::JwtMissingTenantClaim) => {}
            other => panic!(
                "an empty-string tenant claim must be Rejected like a missing one; \
                 Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 18: an `llmp_`-prefixed Bearer value is NoCredential -- mirrors
    // `auth`'s own "jwt-shaped value defers to a later authenticator" test
    // from the other side of the seam.
    #[test]
    fn an_llmp_prefixed_bearer_value_is_no_credential() {
        let auth = authenticator_with_no_keys(default_config());
        let headers = headers_with_bearer("llmp_looks-like-a-virtual-key");

        match auth.authenticate(&headers) {
            AuthOutcome::NoCredential => {}
            other => panic!(
                "an llmp_-prefixed value is virtual-key territory, not this authenticator's; \
                 Rejected={} Authenticated={}",
                matches!(other, AuthOutcome::Rejected(_)),
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 19: absent header, non-Bearer scheme, non-UTF-8 header value -> all
    // NoCredential.
    #[test]
    fn absent_header_and_non_bearer_scheme_are_no_credential() {
        let auth = authenticator_with_no_keys(default_config());

        assert!(matches!(
            auth.authenticate(&HeaderMap::new()),
            AuthOutcome::NoCredential
        ));

        let mut basic_scheme = HeaderMap::new();
        basic_scheme.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert!(matches!(
            auth.authenticate(&basic_scheme),
            AuthOutcome::NoCredential
        ));
    }

    // --- 20: THE non-fall-through test. A bad-signature JWT must be
    // terminal: a chain that places another authenticator AFTER this one
    // must never consult it. This is the security property the task calls
    // out explicitly, not a style detail -- see `crate::auth::AuthOutcome`'s
    // doc and the module doc's "NoCredential split, mirrored" section.
    //
    // Mutation check (a): if `JwtAuthenticator::authenticate` returned
    // `NoCredential` instead of `Rejected` for a bad signature, this chain
    // would fall through to `AlwaysAuthenticates` below and this test would
    // go red -- see this crate's task report for the actual mutation run.
    #[test]
    fn a_bad_signature_does_not_fall_through_to_a_later_authenticator() {
        use std::sync::atomic::{AtomicBool, Ordering};

        /// A stub `Authenticator` that would authenticate ANY request --
        /// standing in for "some other authenticator later in the chain",
        /// so this test does not depend on `VirtualKeyAuthenticator`'s own
        /// (incidental, from this test's point of view) refusal of a
        /// non-`llmp_`-prefixed value.
        struct AlwaysAuthenticates {
            called: Arc<AtomicBool>,
        }

        impl Authenticator for AlwaysAuthenticates {
            fn authenticate(&self, _headers: &HeaderMap) -> AuthOutcome {
                self.called.store(true, Ordering::SeqCst);
                AuthOutcome::Authenticated(Principal {
                    tenant: TenantId::new("should-never-be-reached"),
                    key_id: KeyId::new("should-never-be-reached"),
                    user_id: None,
                    policy: Arc::new(TenantPolicy::default()),
                    tenant_credentials: None,
                    policy_generation: None,
                    trace_export: false,
                })
            }
        }

        let key = shared_test_key();
        let jwt_auth = authenticator_with_key(key, "key-1", default_config());
        let token = tamper_signature(&build_jwt(
            key,
            &header_json("key-1"),
            claims(&[]).as_bytes(),
        ));

        let called = Arc::new(AtomicBool::new(false));
        let chain = crate::auth::AuthenticatorChain::new(vec![
            Box::new(jwt_auth),
            Box::new(AlwaysAuthenticates {
                called: Arc::clone(&called),
            }),
        ]);

        match chain.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(AuthError::JwtInvalidSignature) => {}
            other => panic!(
                "expected the chain to stop at JwtAuthenticator's Rejected(JwtInvalidSignature); \
                 Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
        assert!(
            !called.load(Ordering::SeqCst),
            "a Rejected credential of a KNOWN kind must be terminal -- the later authenticator \
             must never have been consulted"
        );
    }

    // --- 21: a non-empty tenant map translates the claim value into the
    // configured tenant.
    #[test]
    fn a_configured_tenant_map_translates_the_claim_value() {
        let key = shared_test_key();
        let config = JwtValidationConfig {
            tenant_map: HashMap::from([("entra-tid-1".to_string(), "acme".to_string())]),
            ..default_config()
        };
        let auth = authenticator_with_key(key, "key-1", config);
        let token = build_jwt(
            key,
            &header_json("key-1"),
            claims(&[("tenant", serde_json::json!("entra-tid-1"))]).as_bytes(),
        );

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Authenticated(principal) => {
                assert_eq!(principal.tenant.as_str(), "acme");
            }
            other => panic!(
                "expected Authenticated as the mapped tenant; Rejected={}",
                matches!(other, AuthOutcome::Rejected(_))
            ),
        }
    }

    /// ADR-0008 decision 2 for JWT tenants: the opt-in is read from the
    /// control-plane snapshot, and past its staleness bound it is withheld
    /// (counted), since the snapshot may still list a tenant that opted out
    /// on another replica. The token stays valid either way.
    #[test]
    fn a_jwt_tenants_trace_export_opt_in_is_honoured_only_on_a_fresh_snapshot() {
        use crate::auth::{HmacSecret, KeySet, TraceConsent};
        use crate::control::{ControlPlane, InMemoryControlPlaneStore};

        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::new()),
            HmacSecret::new(b"s"),
            KeySet::new(),
        )
        .unwrap();
        cp.create_tenant(&TenantId::new("acme")).unwrap();
        cp.set_trace_export(&TenantId::new("acme"), true).unwrap();
        cp.freshness().set_max_staleness(Duration::from_secs(3600));
        let control = proxy_observability::stats::StatsControl::new(1);
        let consent = Arc::new(TraceConsent::new(
            cp.handle(),
            cp.freshness(),
            Some(control.registry()),
        ));
        let key = shared_test_key();
        let auth =
            authenticator_with_key(key, "key-1", default_config()).with_trace_consent(consent);
        let opted_in = |tenant: &str| {
            let token = build_jwt(
                key,
                &header_json("key-1"),
                claims(&[("tenant", serde_json::json!(tenant))]).as_bytes(),
            );
            match auth.authenticate(&headers_with_bearer(&token)) {
                AuthOutcome::Authenticated(principal) => principal.trace_export,
                _ => panic!("a valid token must authenticate"),
            }
        };
        let stale_count = || {
            proxy_observability::stats::prometheus_render::render(&control.registry())
                .lines()
                .find(|l| l.starts_with("envoy_llmproxy_trace_consent_stale_total"))
                .and_then(|l| l.rsplit(' ').next())
                .map(str::to_owned)
        };

        assert!(opted_in("acme"));
        assert!(!opted_in("other"), "a tenant without a row is not opted in");
        cp.freshness().set_max_staleness(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(!opted_in("acme"), "a stale snapshot withholds the opt-in");
        assert!(!opted_in("other"));
        assert_eq!(
            stale_count().as_deref(),
            Some("1"),
            "only the withheld opt-in counts"
        );
    }

    // --- 23: a discovery snapshot past its staleness bound is Rejected,
    // even with a signature that would otherwise verify.
    #[test]
    fn a_stale_discovery_snapshot_is_rejected() {
        use crate::jwks_refresh::JwksSnapshot;

        let key = shared_test_key();
        let mut keys = JwtKeySet::new();
        keys.insert(JwkRsaKey {
            kid: "key-1".to_string(),
            n: key.n.clone(),
            e: key.e.clone(),
        });
        let snapshot = std::sync::Arc::new(arc_swap::ArcSwap::new(std::sync::Arc::new(
            JwksSnapshot::discovering(keys),
        )));
        let auth = JwtAuthenticator::new_shared(
            snapshot,
            JwtValidationConfig {
                tenant_map: HashMap::new(),
                ..default_config()
            },
            // Zero bound: any nonzero age is stale. No sleeping needed.
            Some(std::time::Duration::ZERO),
        );
        let token = build_jwt(key, &header_json("key-1"), claims(&[]).as_bytes());

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(AuthError::JwtJwksStale) => {}
            other => panic!(
                "a stale snapshot must be Rejected(JwtJwksStale); Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 22: a claim value absent from a non-empty map is Rejected, never
    // passed through as a tenant name.
    #[test]
    fn an_unmapped_tenant_claim_value_is_rejected_never_passed_through() {
        let key = shared_test_key();
        let config = JwtValidationConfig {
            tenant_map: HashMap::from([("entra-tid-1".to_string(), "acme".to_string())]),
            ..default_config()
        };
        let auth = authenticator_with_key(key, "key-1", config);
        let token = build_jwt(
            key,
            &header_json("key-1"),
            claims(&[("tenant", serde_json::json!("some-other-tid"))]).as_bytes(),
        );

        match auth.authenticate(&headers_with_bearer(&token)) {
            AuthOutcome::Rejected(AuthError::JwtTenantNotMapped) => {}
            other => panic!(
                "an unmapped claim value must be Rejected(JwtTenantNotMapped), never admitted \
                 under the raw value; Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }
}
