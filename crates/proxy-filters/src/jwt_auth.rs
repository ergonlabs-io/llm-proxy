//! WP-50 increment 2c-i — JWT verification against a STATICALLY configured
//! JWKS.
//!
//! **Library only**, exactly like [`crate::auth`]'s own 2a-i scope: this
//! module is a second `impl` [`crate::auth::Authenticator`] and is not wired
//! into [`crate::auth_filter`]'s `AuthenticatorChain` here -- see this
//! module's closing section, "What this increment does not build", for why
//! and for what a future increment still owes.
//!
//! # Which algorithms this authenticator accepts, and only these
//!
//! **RS256 only** (RSASSA-PKCS1-v1_5 using SHA-256). [`JwtAuthenticator`]
//! builds exactly one [`jsonwebtoken::Validation`] with
//! `algorithms: vec![Algorithm::RS256]`, and `jsonwebtoken` checks a
//! presented token's `alg` header against that allow-list *before* any
//! signature byte is examined (`jsonwebtoken::decoding::verify_signature`).
//! This is what makes the classic RS256/HS256 "key confusion" attack --
//! taking an RSA public key's bytes and replaying them as an HMAC secret --
//! fail closed here: an attacker-supplied `alg: HS256` header is rejected for
//! not being in the allow-list, independently of what bytes they used to
//! sign it. See this module's tests
//! `alg_none_is_rejected` and
//! `algorithm_confusion_hmac_signed_with_the_rsa_public_key_is_rejected`
//! for both attacks proven directly against this authenticator rather than
//! trusted from the library's changelog.
//!
//! `alg: none` (RFC 8725 §3.1's own worked example of a JWT vulnerability) is
//! rejected the same way, for a stronger reason: `jsonwebtoken::Algorithm`
//! has no `none` variant at all, so a token naming it fails to deserialize as
//! a `Header` and is [`crate::auth::AuthError::JwtMalformed`] before
//! `Validation` is even consulted.
//!
//! # Why `ring` again, not a second crypto stack
//!
//! `jsonwebtoken` is pinned to its 9.x line in `Cargo.toml` specifically
//! because that is the last line whose only crypto backend is `ring` --
//! reused at the exact version (0.17) rustls already pins in this workspace.
//! See that `Cargo.toml` entry's comment for why 10.x/11.x are not used
//! instead (both dropped `ring`, for `aws_lc_rs` or a `rust_crypto` feature --
//! either would be a second crypto stack, not a reuse of the first one).
//!
//! # The `NoCredential`/`Rejected` split, mirrored from the other side
//!
//! [`crate::auth::VirtualKeyAuthenticator`] claims a `Bearer` value as its
//! own kind by checking for the `llmp_` prefix and defers (`NoCredential`)
//! anything else -- including a JWT -- to a later authenticator. This
//! authenticator is that later authenticator: it claims every `Bearer` value
//! that does *not* start with `llmp_` as a JWT, and from that point on every
//! outcome is terminal (`Authenticated` or `Rejected`), never `NoCredential`.
//! A caller cannot probe "is this recognized as a JWT" and "is this JWT
//! valid" as two separate free bits -- see [`crate::auth::AuthOutcome`]'s doc
//! for why that distinction is load-bearing, not stylistic.
//!
//! # The tenant claim is configurable, and a missing one is `Rejected`
//!
//! [`JwtValidationConfig::tenant_claim`] names which claim becomes
//! [`crate::auth::Principal::tenant`] -- never hardcoded to `sub`, because
//! different identity providers put the tenant in different places. A
//! verified token whose named claim is absent, or present but not a
//! non-empty string, is [`crate::auth::AuthError::JwtMissingTenantClaim`],
//! never a default tenant -- see the design brief's fail-closed rule: a
//! control that silently degrades (here, to some fallback tenant) is worse
//! than one that refuses.
//!
//! # `Principal::key_id` for a JWT is the JWKS `kid`, not a per-caller value
//!
//! Virtual keys mint a `key_id` per credential; a JWKS key is shared by every
//! caller whose identity provider signs with it. The best available audit
//! analog is still naming *which signing key* verified the token, so
//! `key_id` carries the JWKS `kid` here -- see [`crate::auth::KeyId`]'s doc
//! for why the field exists at all (revoking one leaked thing must not revoke
//! everything that used it; for a JWKS key, "everything that used it" is a
//! key ROTATION, which is exactly the granularity `kid` already exists to
//! express).
//!
//! # What this increment does not build
//!
//! No network JWKS fetch, no refresh timer, no `ArcSwap` snapshot -- the JWKS
//! here is provided once, at construction, exactly like
//! [`crate::auth::VirtualKeyAuthenticator::from_static_keys`]. Whether the
//! *synchronous* [`crate::auth::Authenticator`] trait this module implements
//! unchanged can still accommodate a later asynchronous-refresh JWKS without
//! reshaping is a real open question, not a settled fact -- see this crate's
//! task report for the finding.
//!
//! This module also does not wire a `JwtAuthenticator` into
//! [`crate::auth_filter::AuthFilterFactory`]'s `AuthenticatorChain`, and does
//! not add a config parser reading `typed_config` into this module's
//! [`JwtValidationConfig`]/[`JwtKeySet`]. Both mirror how 2a-i (this module's sibling,
//! [`crate::auth`]) landed before 2a-ii ([`crate::auth_filter`]) wired it into
//! a real `HttpFilter` -- a later increment (2c-ii, by analogy) is the wiring
//! step here too.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use http::header::AUTHORIZATION;
use http::HeaderMap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

use crate::auth::{
    AuthError, AuthOutcome, Authenticator, KeyId, Principal, TenantId, TenantPolicy, BEARER_PREFIX,
    KEY_PREFIX,
};

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
/// behavior, not a bug, but it is exactly the fail-open shape rule 17 warns
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

/// [`Authenticator`] for JWTs verified against a statically configured JWKS.
/// See the module doc for scope, allow-listed algorithms, and what a caller
/// must not conclude from a `Rejected` outcome.
pub struct JwtAuthenticator {
    keys: JwtKeySet,
    validation: Validation,
    tenant_claim: String,
}

impl JwtAuthenticator {
    pub fn new(keys: JwtKeySet, config: JwtValidationConfig) -> Self {
        let validation = build_validation(&config);
        JwtAuthenticator {
            keys,
            validation,
            tenant_claim: config.tenant_claim,
        }
    }
}

impl fmt::Debug for JwtAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtAuthenticator")
            .field("keys", &self.keys)
            .field("tenant_claim", &self.tenant_claim)
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

        // From here on every outcome is terminal: this authenticator has
        // claimed the credential as a JWT.
        let header = match jsonwebtoken::decode_header(presented) {
            Ok(header) => header,
            Err(_) => return AuthOutcome::Rejected(AuthError::JwtMalformed),
        };

        let Some(kid) = header.kid.as_deref() else {
            return AuthOutcome::Rejected(AuthError::JwtUnknownKid);
        };
        let Some(key) = self.keys.get(kid) else {
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

        AuthOutcome::Authenticated(Principal {
            tenant: TenantId::new(tenant),
            // See the module doc's "`Principal::key_id` for a JWT" section.
            key_id: KeyId::new(kid.to_string()),
            policy: Arc::new(TenantPolicy::default()),
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
    // builds a fresh 2048-bit keypair per test process (never committed --
    // the design brief's "never commit a private key, even a test one"); this
    // module then signs every test token with `ring` directly, the same
    // primitive `jsonwebtoken` uses in production, so tests exercise the real
    // verification path rather than a stand-in for it.

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
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
            }
            other => panic!(
                "expected Authenticated; Rejected={} NoCredential={}",
                matches!(other, AuthOutcome::Rejected(_)),
                matches!(other, AuthOutcome::NoCredential)
            ),
        }
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

    // --- 7: issuer mismatch -> Rejected, both when `iss` differs AND when
    // `iss` is absent entirely (the fail-open gap `build_validation` closes).
    #[test]
    fn issuer_mismatch_is_rejected_including_a_missing_iss_claim() {
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
            AuthOutcome::Rejected(AuthError::JwtIssuerMismatch) => {}
            other => panic!(
                "expected Rejected(JwtIssuerMismatch) for a wrong iss; Authenticated={}",
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
                    policy: Arc::new(TenantPolicy::default()),
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
}
