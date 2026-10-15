//! The downstream-authentication core.
//!
//! **Library only.** This module resolves an inbound request's credential to
//! a [`Principal`] (or refuses it); it is not wired into an `HttpFilter`
//! here (`auth_filter` does that). Scope is virtual keys, held in memory or
//! in the `ControlPlane` snapshot.
//!
//! # Why an `Authenticator` trait, not "the virtual-key filter"
//!
//! OIDC/JWT is a second credential kind, so [`Authenticator`] is deliberately a
//! trait ([`VirtualKeyAuthenticator`] and `JwtAuthenticator` implement it)
//! rather than a concrete type baked into a filter -- a new credential kind
//! slots in beside the existing ones without reshaping anything above.
//!
//! # `NoCredential` vs `Rejected`: the load-bearing distinction
//!
//! See [`AuthOutcome`]'s doc. In short: a chain of authenticators must not
//! become a probing oracle. A credential of a kind this authenticator
//! doesn't recognize (absent header, wrong scheme, a JWT rather than a
//! virtual key) is `NoCredential` -- try the next authenticator. A credential
//! that *is* shaped like this authenticator's kind but fails verification is
//! `Rejected` and terminal: falling through to another authenticator after a
//! bad credential of a *known* kind would let a caller learn something (e.g.
//! "that `llmp_`-prefixed value was recognized as a virtual key, just an
//! invalid one") one probe at a time.
//!
//! # Why keyed HMAC-SHA256, not Argon2/bcrypt, and not a plain hash
//!
//! Virtual keys are high-entropy values the proxy itself generates, not
//! user-chosen passwords. Password hashing is deliberately slow to survive
//! *low*-entropy secrets; that reasoning does not transfer here, and a
//! per-request Argon2 on the hot path would be a denial-of-service the
//! operator inflicts on themselves. A **keyed** hash (HMAC with an
//! operator-configured secret) is used instead of a plain digest so that
//! read access to the stored [`KeySet`] (a config file, a future
//! `CredentialStore`) does not by itself permit offline precomputation of
//! matching keys.
//!
//! Do **not** reach for [`crate::token_limit_filter::hash_credential`]
//! (aliased for readers coming from that module: FNV-1a) for this. That
//! function is a stable, *non-cryptographic* hash chosen so a distributed
//! budget store derives the same bucket key on any toolchain for a
//! *non-adversarial* input -- it offers neither preimage resistance nor a
//! constant-time comparison, both of which this module requires. Both
//! functions are spelled "hash a credential"; that they solve different
//! problems is exactly the trap to avoid.
//!
//! # No byte comparison of secrets happens here
//!
//! [`KeySet::find`] derives `HMAC-SHA256(secret, presented_key)` with
//! `ring::hmac::sign` and looks that digest up in a `HashMap`. The lookup is
//! the decision. There is no second, "constant-time" comparison after it: an
//! earlier version called `ring::hmac::verify(secret, presented, digest)` on
//! the digest it had just computed from the same input, which always succeeds
//! and so verified nothing (review M9). Why the lookup itself is not a timing
//! side channel is the next section. Where two secrets ARE compared byte for
//! byte (the admin bearer token), `proxy-admin`'s `secrets_match` uses the
//! double-HMAC compare, because `ring::constant_time::verify_slices_are_equal`
//! is deprecated in the pinned `ring` (0.17.14) with "no promises regarding
//! side channels".
//!
//! # `KeySet` is a `HashMap` keyed on the digest
//!
//! An earlier version scanned a `Vec`, verifying every configured record with
//! `hmac::verify`, to avoid a table lookup short-circuiting before a
//! constant-time comparison could run. That reasoning does not survive
//! contact with either the cost or the mechanism, and both halves are worth
//! keeping written down:
//!
//! - **Cost.** It was O(n) HMAC-SHA256 per request. At roughly 1µs each, a
//!   10,000-key deployment spends ~10ms of CPU on every request — and an
//!   unauthenticated caller could force the full scan, so it was a
//!   denial-of-service vector rather than a hardening measure.
//! - **Mechanism.** The scan used `iter().find_map(..)`, which stops at the
//!   first match. A key stored first cost one verification and a key stored
//!   last cost n, so it leaked *position* while paying the full price. It did
//!   not deliver the property it was chosen for.
//!
//! The digest is `HMAC-SHA256(secret, presented_key)`, which an attacker
//! cannot steer without the secret, so they can neither aim at a bucket nor
//! walk the digest byte by byte. And the only coarse fact a lookup could leak
//! — whether that digest exists — is exactly what the response already tells
//! them (200 vs 401).
//!
//! # Nothing here leaks key material through `Debug`
//!
//! [`KeyRecord`], [`KeySet`], [`Principal`], [`HmacSecret`] and
//! [`VirtualKeyAuthenticator`] all have hand-written `Debug` impls (nothing
//! is `#[derive(Debug)]`d on a type that could carry a plaintext key, a
//! digest, or the HMAC secret) so that a stray `tracing::debug!(?principal)`
//! or similar can never become a leak channel. `tenant`/`key_id` are
//! identifiers, not secrets -- they must stay nameable in audit logs -- so only the fields that touch key material are
//! actually redacted; the rest are still hand-written, on purpose, so a
//! future field addition to one of these types has to make the same call
//! explicitly rather than inherit it from `#[derive]`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use http::header::AUTHORIZATION;
use http::HeaderMap;

use crate::control::ControlPlaneSnapshot;
use proxy_http::tenant_credentials::TenantCredentialSet;

/// Scheme prefix this authenticator recognizes on the `authorization`
/// header. Anything else (no header, a different scheme, a bare token) is
/// simply not a credential this authenticator understands -- see
/// [`AuthOutcome::NoCredential`].
///
/// `pub(crate)`, not private: [`crate::jwt_auth::JwtAuthenticator`] parses the same `Bearer ` scheme over the same header --
/// sharing the constant means the two authenticators cannot silently drift
/// on it.
pub(crate) const BEARER_PREFIX: &str = "Bearer ";

/// Printable prefix every virtual key carries -- greppable in incident response, revocable by prefix
/// scan, and distinguishable from a provider key pasted into the wrong
/// field. A `Bearer` value without this prefix is assumed to belong to a
/// later authenticator (e.g. a JWT) rather than being a malformed virtual
/// key -- this is the OIDC seam, and it is why that case is
/// `NoCredential`, not `Rejected`.
///
/// `pub(crate)`, not private: [`crate::jwt_auth::JwtAuthenticator`] checks
/// the SAME prefix (in the opposite direction -- a value that starts with it
/// is NOT a JWT, see that module's doc) so the two authenticators' notions of
/// "whose kind is this" cannot silently drift apart.
pub(crate) const KEY_PREFIX: &str = "llmp_";

/// Rejects a tenant or key id that is empty or longer than
/// [`proxy_observability::records::MAX_PRINCIPAL_ID_BYTES`]. A free function
/// rather than a check inside [`TenantId::new`]/[`KeyId::new`] because those
/// constructors are infallible and shared across crates; every site that
/// accepts a NEW id from outside (mint, config load) calls this first.
/// `field` names the offending input in the message.
pub fn check_principal_id(field: &str, id: &str) -> Result<(), String> {
    let max = proxy_observability::records::MAX_PRINCIPAL_ID_BYTES;
    if id.len() > max {
        return Err(format!(
            "{field} is {} bytes; the maximum is {max} (longer ids cannot be recorded without \
             truncation, which could merge two distinct ids)",
            id.len()
        ));
    }
    Ok(())
}

/// Identifies the tenant (account/team) a request was authenticated as.
///
/// Rust note: a one-field tuple struct ("newtype") rather than a bare
/// `String` -- it exists so the compiler rejects a `TenantId` where a
/// `KeyId` was meant (and vice versa) even though both wrap a `String`
/// underneath. See [`Principal`]'s doc for why the two are kept distinct.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TenantId(String);

impl TenantId {
    pub fn new(id: impl Into<String>) -> Self {
        TenantId(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Rust note: hand-written even though a `#[derive(Debug)]` here would be
// exactly as safe (a tenant id is an identifier, not a secret) -- see the
// module doc's closing paragraph for why every type this file exports
// spells its `Debug` out explicitly rather than mixing derived and
// hand-written impls across neighboring types.
impl fmt::Debug for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TenantId").field(&self.0).finish()
    }
}

/// Identifies WHICH credential authenticated a request.
///
/// Kept distinct from [`TenantId`]: revoking one leaked key must not revoke
/// the whole team, and an audit trail needs to name the key, not just the
/// account it belongs to.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(id: impl Into<String>) -> Self {
        KeyId(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyId").field(&self.0).finish()
    }
}

/// Per-tenant authorization policy.
///
/// Its first field is [`Self::model_access`] --
/// exactly the shape this doc predicted before any field existed, carried by
/// [`Principal`] behind an `Arc`, so that adding it was a change to this one
/// struct rather than a signature change through every call site that
/// carries a `Principal`.
///
/// # No model policy is not a grant
///
/// [`Self::model_access`] is `None` when no model policy is stored for the
/// tenant (a tenant known only by its keys, or by a budget). What `None`
/// permits is decided by `llmproxy.model_authz`'s `tenants_without_policy`
/// setting, which denies by default (review H4; AGENTS.md "Fail-open
/// controls": unset never means open). `Some(ModelAccess::All)` is an
/// explicit grant of every model.
///
/// *Authentication* and *authorization* are separate axes: an unknown or
/// revoked credential is a 401; a known tenant asking for a model it may not
/// use is a 403.
///
/// # The trap, for whoever adds a field
///
/// "No policy configured" and "a configured policy that failed to load" must
/// **not** produce the same value. A configured policy that fails to load is
/// a config error with its dotted path (AGENTS.md invariant 1), never `None`
/// and never `All`. [`crate::model_authz_filter::parse_config`] is the one
/// place that loads this struct's `model_access` field from configuration,
/// and it is careful about exactly this: see that function's doc.
#[derive(Clone, Default)]
pub struct TenantPolicy {
    /// Which models this tenant may use, or `None` when no model policy is
    /// stored for it (see the type doc). See
    /// [`crate::model_authz::ModelAccess`]'s doc for why this is an explicit
    /// enum (`All` / `Only(Vec<ModelPattern>)`) rather than a bare `Vec`
    /// whose emptiness would have to be interpreted as either "everything" or
    /// "nothing".
    pub model_access: Option<crate::model_authz::ModelAccess>,
    /// This tenant's spend ceiling, if any. See
    /// [`crate::spend::TenantBudget`]'s doc for the full reasoning; in short:
    ///
    /// **`None` means unlimited, and that is the deliberate default**:
    /// a budget is an opt-in ceiling, not a default-deny, so an operator
    /// enabling the (separate) spend enforcement filter must not have it
    /// silently deny every tenant's very first request. Restriction is
    /// opt-in: an operator sets a ceiling when they want one.
    ///
    /// `None` is a different fact from a configured ceiling of zero. `Some(TenantBudget
    /// { max_micros: MicroUsd::from_micros(0), .. })` is a real, legitimate,
    /// deliberate policy -- deny every priced request this period -- exactly
    /// like `ModelAccess::Only(vec![])` denying every model. Storage and admin
    /// CRUD keep the two distinguishable end to end; see [`crate::control::ControlPlane::set_budget`]
    /// and its store methods.
    pub budget: Option<crate::spend::TenantBudget>,
}

impl fmt::Debug for TenantPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Rust note: unlike every other hand-written `Debug` in this module,
        // `model_access`/`budget` ARE included -- both are configuration (a
        // list of model name patterns, a spend ceiling), not secrets, and an
        // operator debugging "why was this tenant refused" needs to see them.
        // Contrast `KeyRecord`/`KeySet`, which redact exactly because their
        // fields ARE key-material-adjacent.
        f.debug_struct("TenantPolicy")
            .field("model_access", &self.model_access)
            .field("budget", &self.budget)
            .finish()
    }
}

/// The caller identity a successful authentication resolves to.
pub struct Principal {
    pub tenant: TenantId,
    /// WHICH credential authenticated -- see [`KeyId`]'s doc.
    pub key_id: KeyId,
    /// Model allow-lists and budgets. An
    /// `Arc` so the hot path clones a pointer, and so a future policy change
    /// is a snapshot swap rather than a per-request lookup.
    pub policy: Arc<TenantPolicy>,
    /// The tenant's provider credentials, taken from the same snapshot that
    /// verified the key (ADR-0007 decision 4). `None` for a tenant with no
    /// credentials, and for authenticators that do not read the control-plane
    /// snapshot. Left out of the hand-written `Debug` below on purpose: it
    /// holds plaintext keys.
    pub tenant_credentials: Option<Arc<TenantCredentialSet>>,
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Principal")
            .field("tenant", &self.tenant)
            .field("key_id", &self.key_id)
            .field("policy", &self.policy)
            .finish()
    }
}

/// Why a credential presented to an [`Authenticator`] was rejected.
///
/// Never carries key material -- only which of the two terminal failure
/// modes applies. See [`AuthOutcome::Rejected`] for why this is terminal
/// rather than something a caller can retry against another authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// The presented value was shaped like a credential this authenticator
    /// handles (the `llmp_` prefix), but its digest matched no configured
    /// [`KeyRecord`].
    UnknownKey,
    /// The presented value's digest matched a configured [`KeyRecord`], but
    /// that record is marked `revoked`.
    RevokedKey,

    // -- `crate::jwt_auth::JwtAuthenticator`'s
    // rejection reasons. Added here (not on a separate error type) for the
    // same reason `UnknownKey`/`RevokedKey` already share this enum: both
    // authenticators feed the same `AuthOutcome::Rejected`, and the "nothing above [`Authenticator`] changes"
    // promise covers this
    // enum too -- it is part of the seam, not part of one implementation.
    /// The bearer value was not a well-formed JWT: not three
    /// `.`-separated segments, invalid base64, or a segment that did not
    /// decode to JSON (including a header naming an algorithm this crate
    /// does not model at all, e.g. `alg: none` -- see the module's `alg`
    /// allow-list doc).
    JwtMalformed,
    /// The token's `kid` header named no configured JWKS key -- including a
    /// token with no `kid` at all, which is indistinguishable from "names an
    /// absent key" once there is more than one configured key to choose
    /// among.
    JwtUnknownKid,
    /// Signature verification failed: a bad signature, OR the token's `alg`
    /// header is not in this authenticator's allow-list (this is what stops
    /// the classic RS256/HS256 key-confusion attack -- see the module doc).
    /// Both collapse to one reason so neither a caller nor the access log can
    /// distinguish "wrong algorithm" from "wrong signature" -- the same
    /// non-disclosure the virtual-key authenticator applies to
    /// `UnknownKey`/`RevokedKey` on the wire (see `auth_filter`'s module
    /// doc), applied here at the reason-enum level since this authenticator
    /// has no filter wiring yet to enforce it downstream.
    JwtInvalidSignature,
    /// The token's `exp` claim is in the past (beyond the configured
    /// leeway).
    JwtExpired,
    /// The token's `nbf` claim is in the future (beyond the configured
    /// leeway).
    JwtNotYetValid,
    /// An `issuer` was configured and the token's `iss` claim did not match
    /// it (including a token with no `iss` claim at all).
    JwtIssuerMismatch,
    /// An `audience` was configured and the token's `aud` claim did not
    /// contain it (including a token with no `aud` claim at all).
    JwtAudienceMismatch,
    /// The token verified, but the configured tenant claim was absent or was
    /// not a non-empty string. Never defaulted: a missing tenant claim is
    /// Rejected, never mapped to a default tenant.
    JwtMissingTenantClaim,
    /// The token verified and carried the configured tenant claim, but that
    /// claim's value appears in no configured `tenant_values` map entry, so
    /// there is no llm-proxy tenant to admit it as. Never passed through --
    /// a non-empty map means "only these mappings", and an unmapped value is
    /// refused rather than trusted as a tenant name (an Entra `tid` must not
    /// become an implicitly trusted tenant).
    JwtTenantNotMapped,
    /// The provider's JWKS snapshot is older than its staleness bound
    /// (background refreshes stopped landing, or never landed). Fail closed:
    /// serving indefinitely old keys would trust a rotation that already
    /// happened.
    JwtJwksStale,
    /// The control-plane snapshot the virtual keys are checked against has
    /// not been confirmed against the store for longer than
    /// `max_policy_staleness_seconds` (review H4). Fail closed: it may still
    /// hold a key another replica revoked. The filter answers 503, not 401,
    /// because the credential itself may be fine.
    PolicyStale,
}

/// The result of asking one [`Authenticator`] to resolve a request.
///
/// # `NoCredential` vs `Rejected` is not a stylistic choice
///
/// These two failure cases must stay separate, or a chain of authenticators
/// becomes a probing oracle: present a malformed JWT to a chain that tries a
/// `VirtualKeyAuthenticator` first, fall through to a `JwtAuthenticator`,
/// and you've learned "the key authenticator didn't recognize this as one of
/// its own" -- one bit of information per probe, for free, before any real
/// credential was ever presented. Collapsing the two into one "failed" case
/// would erase exactly the distinction that prevents this: absence of a
/// credential this authenticator understands is not the same claim as
/// "this IS my kind of credential, and it's bad."
pub enum AuthOutcome {
    /// A credential was verified and resolves to this caller.
    Authenticated(Principal),
    /// No credential OF THIS AUTHENTICATOR'S KIND was presented. Not a
    /// failure -- the caller (a chain of authenticators) should try the
    /// next one. See the enum's doc for why this must never collapse into
    /// [`AuthOutcome::Rejected`].
    NoCredential,
    /// A credential of this authenticator's kind WAS presented and is bad.
    /// TERMINAL: the caller must stop here, not fall through to another
    /// authenticator. See the enum's doc.
    Rejected(AuthError),
}

/// Resolves a request to a caller identity, or declines to.
///
/// `Send + Sync`: implementations are shared across worker threads behind an
/// `Arc`, the same shape `BudgetStore` and `ClusterManager` already use
/// elsewhere in this workspace.
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, headers: &HeaderMap) -> AuthOutcome;
}

/// The operator-configured secret [`VirtualKeyAuthenticator`] keys its HMAC
/// with.
///
/// A newtype around `ring::hmac::Key` rather than a raw `&[u8]`/`Vec<u8>`
/// passed around loose -- `ring::hmac::Key` is itself not `Copy` and its
/// internal representation is already the algorithm-specific padded key
/// material HMAC needs, so there's no reason to keep the original bytes
/// around once this is constructed.
pub struct HmacSecret(ring::hmac::Key);

impl HmacSecret {
    /// Rust note: `ring::hmac::Key::new` copies `secret_bytes` into its own
    /// padded internal representation, so the caller's buffer does not need
    /// to outlive this call and this type does not borrow from it.
    pub fn new(secret_bytes: &[u8]) -> Self {
        HmacSecret(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret_bytes))
    }
}

// `ring::hmac::Key` already hand-writes a redacted `Debug` (it prints only
// the digest algorithm), but this wrapper hand-writes its own anyway rather
// than deriving through to `ring`'s impl -- see the module doc's closing
// paragraph: every secret-adjacent type here spells its `Debug` out
// explicitly so a dependency changing its own `Debug` impl can't silently
// change what this crate prints.
impl fmt::Debug for HmacSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HmacSecret").field(&"<redacted>").finish()
    }
}

/// The secret bytes to key an HMAC with, given the raw contents of a secret
/// **file** -- trailing ASCII whitespace removed.
///
/// # Why this exists at all, and why it is not optional
///
/// `echo "s3cret" > /etc/llmproxy/auth-secret` -- the most obvious way an
/// operator creates this file -- appends a newline. Without trimming, that
/// newline becomes part of the HMAC key, and then the digest the proxy
/// computes matches only a tool that ALSO included it. The documented
/// fallback (`openssl dgst -hmac "$(cat file)"`) does not: shell command
/// substitution strips trailing newlines. The two disagree, every key fails,
/// and the only symptom is a 401 with nothing in it to explain why. Trimming
/// is what the `hmac_secret_file` schema description has always promised;
/// until 2026-08-08 the code did not do it.
///
/// # Files only, deliberately
///
/// An inline secret (`hmac_secret: ...`, or `$LLMPROXY_AUTH_SECRET` for
/// `--mode keygen`) is NOT trimmed. YAML already strips whitespace around a
/// plain scalar, and a secret someone deliberately quoted with trailing
/// spaces should be taken literally. The newline problem is specific to
/// files, because it is a file-creation tool that adds one.
///
/// # Both readers must call this
///
/// `auth_filter::parse_hmac_secret` (which VERIFIES keys) and
/// `llm-proxy --mode keygen` (which GENERATES them) both read this file. If
/// only one trimmed, every generated key would fail to authenticate -- the
/// same drift [`digest_hex`] exists to prevent, one layer up.
pub fn secret_bytes_from_file(raw: &[u8]) -> &[u8] {
    // Rust note: `rposition` finds the last non-whitespace byte; `map_or(0,
    // ..)` makes an all-whitespace file trim to empty rather than panicking,
    // and callers already reject an empty secret.
    let end = raw
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |i| i + 1);
    &raw[..end]
}

/// `HMAC-SHA256(secret, plaintext_key)` as a raw 32-byte array -- the value
/// [`StoredKey::digest`](crate::control::StoredKey) carries and
/// [`digest_hex`] hex-encodes for config/display. This is the ONE place in
/// the codebase an HMAC is actually computed over a plaintext key; both
/// [`digest_hex`] below and [`crate::control::ControlPlane::mint_key`] call
/// it rather than reaching for `ring::hmac::sign` themselves.
///
/// Rust note: `.try_into().expect(..)` converts the `hmac::Tag`'s `&[u8]`
/// into a fixed `[u8; 32]` -- infallible in practice because HMAC-SHA256
/// always produces exactly 32 bytes, but the conversion itself is fallible
/// (a `TryFrom<&[u8]>` for `[u8; N]` checks the length at runtime), so the
/// `expect` names why this particular call can never actually hit that
/// branch.
pub fn digest_bytes(secret: &HmacSecret, plaintext_key: &str) -> [u8; 32] {
    let digest = ring::hmac::sign(&secret.0, plaintext_key.as_bytes());
    digest.as_ref().try_into().expect("HMAC-SHA256 is 32 bytes")
}

/// `hex(HMAC-SHA256(secret, plaintext_key))` -- the value that goes in a
/// config's `digest` / `digest_hex` field.
///
/// This is the ONE place in the codebase a digest is derived from a
/// plaintext key: [`KeySet::insert`] below calls this directly (rather than
/// duplicating the HMAC-and-hex-encode), and so does `llm-proxy --mode
/// keygen` (`crates/proxy/src/keygen.rs`) -- the tool
/// that GENERATES a key and the code path that later loads a [`KeySet`] to
/// VERIFY one both call this exact function, so they cannot drift apart.
/// `HmacSecret`'s inner `ring::hmac::Key` is private to this module, which is
/// why this has to live here rather than alongside the rest of `--mode
/// keygen` in `crates/proxy`. Delegates to [`digest_bytes`] for the actual
/// HMAC computation, so there is exactly one place that call happens.
pub fn digest_hex(secret: &HmacSecret, plaintext_key: &str) -> String {
    digest_bytes(secret, plaintext_key)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// 256 bits of key material -- the point past which brute-forcing a virtual
/// key stops being the attack anyone bothers with, and the property the
/// module doc's "high-entropy, proxy-generated, not user-chosen" argument for
/// a fast keyed hash (over a slow password hash) actually rests on.
const KEY_ENTROPY_BYTES: usize = 32;

/// Generates a fresh plaintext virtual key from the OS CSPRNG: [`KEY_PREFIX`]
/// plus [`KEY_ENTROPY_BYTES`] random bytes, base64url-encoded (RFC 4648 §5)
/// without padding. The single shared generator: `llm-proxy --mode keygen`
/// (`crates/proxy/src/keygen.rs`) and [`crate::control::ControlPlane::mint_key`]
/// both call this rather than each rolling their own, so the two paths that
/// mint a key cannot silently drift in prefix, entropy, or encoding.
///
/// Rust note: `ring::rand::SystemRandom`, not `rand::thread_rng()`. Both are
/// CSPRNG-backed today, but `rand::thread_rng()`'s CSPRNG guarantee is a
/// property of that crate's current internals rather than something the
/// call site can rely on being true forever; `ring::rand::SystemRandom`
/// documents it as the contract. This is the one place in the tree where the
/// entropy source is load-bearing enough to name explicitly rather than
/// reach for whatever RNG is already in scope.
pub fn generate_plaintext_key(rng: &ring::rand::SystemRandom) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ring::rand::SecureRandom;

    let mut bytes = [0u8; KEY_ENTROPY_BYTES];
    rng.fill(&mut bytes)
        .expect("the OS CSPRNG is unavailable -- cannot generate a virtual key without it");
    format!("{KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Reverses [`digest_hex`]'s formatting. Private and infallible-by-panic
/// rather than returning a `Result`: unlike `auth_filter::parse_digest_hex`
/// (which validates untrusted config text character by character and must
/// name a dotted field path on failure, AGENTS.md invariant 1), the only strings
/// this is ever handed are ones [`digest_hex`] just produced a few lines
/// above, so there is nothing external to validate.
fn decode_hex_digest(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let s = std::str::from_utf8(pair).expect("digest_hex output is ASCII");
            u8::from_str_radix(s, 16).expect("digest_hex output is valid hex")
        })
        .collect()
}

/// A single configured virtual key, identified only by the HMAC digest of
/// its plaintext value -- the plaintext is never retained anywhere.
pub struct KeyRecord {
    pub key_id: KeyId,
    pub tenant: TenantId,
    pub revoked: bool,
}

impl fmt::Debug for KeyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRecord")
            .field("key_id", &self.key_id)
            .field("tenant", &self.tenant)
            .field("revoked", &self.revoked)
            .finish()
    }
}

/// The configured set of virtual keys, keyed by digest. Plaintext keys are
/// never stored -- see [`KeySet::insert`].
///
/// **Why a `HashMap` keyed on the digest, and not a `Vec` scanned with
/// `hmac::verify`.** The scanning version was written first, to avoid a
/// hash-table lookup short-circuiting before a constant-time comparison could
/// run. It was replaced because it lost on both counts:
///
/// - **It cost O(n) HMAC-SHA256 operations per request.** At ~1µs each, a
///   10,000-key deployment burns ~10ms of CPU on every request. That is
///   disqualifying for a proxy, and it is a denial-of-service vector in its
///   own right -- an unauthenticated caller could force the full scan.
/// - **It did not actually buy constant time.** The scan used
///   `iter().find_map(..)`, which stops at the first match, so a key stored
///   first cost one verification and a key stored last cost n. It leaked
///   position while paying the full price.
///
/// The lookup key here is `HMAC-SHA256(secret, presented_key)`, which an
/// attacker cannot steer without the secret, so they cannot aim at buckets or
/// walk the digest byte by byte. And the coarse signal a table lookup could
/// leak -- "does this digest exist" -- is already the response the caller
/// gets (200 vs 401).
pub struct KeySet {
    entries: HashMap<Vec<u8>, KeyRecord>,
}

impl KeySet {
    pub fn new() -> Self {
        KeySet {
            entries: HashMap::new(),
        }
    }

    /// Adds a key to this set. `presented_key` is the caller-facing
    /// plaintext value (e.g. `llmp_abc123...`); only `HMAC-SHA256(secret,
    /// presented_key)` is retained.
    ///
    /// Goes through [`digest_hex`] (and back) rather than calling
    /// `ring::hmac::sign` directly -- see that function's doc for why: it is
    /// the single derivation this whole module and `--mode keygen` share.
    pub fn insert(&mut self, secret: &HmacSecret, presented_key: &str, record: KeyRecord) {
        let digest = decode_hex_digest(&digest_hex(secret, presented_key));
        self.entries.insert(digest, record);
    }

    /// Adds a key to this set from an already-computed digest. This is the
    /// path `auth_filter::parse_config` uses: configuration carries
    /// `digest_hex`, never a plaintext key (see the `VirtualKey.digest_hex`
    /// proto doc), so [`Self::insert`] -- which hashes a plaintext -- cannot
    /// be the config-loading entry point. [`Self::insert`] itself stays,
    /// unchanged, because the tests in this module still build a `KeySet`
    /// from plaintext keys directly.
    pub fn insert_digest(&mut self, digest: Vec<u8>, record: KeyRecord) {
        self.entries.insert(digest, record);
    }

    /// Finds the record for `presented`: one HMAC to derive the digest, then
    /// one table lookup, which is the whole decision. See the module doc's
    /// "No byte comparison of secrets happens here" for why there is no
    /// verify step after it, and [`KeySet`]'s doc for why the lookup is not a
    /// meaningful side channel.
    fn find(&self, secret: &HmacSecret, presented: &str) -> Option<&KeyRecord> {
        let digest = ring::hmac::sign(&secret.0, presented.as_bytes());
        self.entries.get(digest.as_ref())
    }

    /// Iterates this set's `(digest, record)` pairs.
    ///
    /// Used only by `crate::control::ControlPlane::rebuild`'s bootstrap/store
    /// merge, which needs to re-key a bootstrap `KeySet` (digest-keyed) by
    /// `key_id` in order to detect a `key_id` collision against the store --
    /// something a `find`-by-digest lookup cannot answer. Not a general-purpose
    /// accessor: nothing else in this module needs to walk every entry, and
    /// this still leaks nothing `KeySet::find`'s doc doesn't already call
    /// non-sensitive (the digest itself, never a plaintext key).
    ///
    /// Rust note: `impl Iterator` rather than a named type -- the caller only
    /// ever `for`-loops or `.collect()`s this, so there is nothing gained by
    /// naming the concrete `std::collections::hash_map::Iter` type.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&[u8], &KeyRecord)> {
        self.entries
            .iter()
            .map(|(digest, record)| (digest.as_slice(), record))
    }
}

impl Default for KeySet {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for KeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only the count -- never a digest.
        f.debug_struct("KeySet")
            .field("len", &self.entries.len())
            .finish()
    }
}

/// [`Authenticator`] for virtual keys: a printable `llmp_`-prefixed bearer
/// token, verified as a keyed HMAC-SHA256 digest against a configured
/// [`KeySet`]. See the module doc for the full reasoning.
pub struct VirtualKeyAuthenticator {
    secret: HmacSecret,
    // Rust note: an `Arc<ArcSwap<T>>`, not an owned `ArcSwap<T>` -- the swap
    // itself is owned by `crate::control::ControlPlane` (which republishes
    // into it), and this authenticator only ever needs a cheap, cloneable
    // *handle* to the same swap. `ArcSwap::load` is a lock-free `Arc` clone
    // (see `authenticate` below), so this field costs nothing on the hot
    // path beyond that one atomic load -- no store I/O happens here. See
    // `crate::control`'s module doc for the full publish/read seam.
    snapshot: Arc<ArcSwap<ControlPlaneSnapshot>>,
    /// The staleness clock of the control plane that publishes `snapshot`.
    /// `None` only for an authenticator over keys no control plane
    /// republishes ([`Self::from_static_keys`], and unit tests).
    freshness: Option<Arc<crate::control::PolicyFreshness>>,
}

impl VirtualKeyAuthenticator {
    pub fn new(secret: HmacSecret, snapshot: Arc<ArcSwap<ControlPlaneSnapshot>>) -> Self {
        VirtualKeyAuthenticator {
            secret,
            snapshot,
            freshness: None,
        }
    }

    /// Enforces the control plane's staleness bound: once its snapshot is
    /// older than the bound, every virtual key is refused with
    /// [`AuthError::PolicyStale`]. The auth filter always wires this.
    pub fn with_freshness(mut self, freshness: Arc<crate::control::PolicyFreshness>) -> Self {
        self.freshness = Some(freshness);
        self
    }

    /// Build an authenticator over a fixed [`KeySet`] (no policies) whose
    /// snapshot is never republished. The live path wires the handle from a
    /// [`crate::control::ControlPlane`] via [`Self::new`] so revocations take
    /// effect on the next publish; this constructor is for callers that only
    /// ever verify against one static set of keys -- notably the `keygen`
    /// end-to-end test, which proves a printed digest authenticates and has
    /// no store to rebuild from. It also keeps `arc_swap` out of such callers,
    /// since [`Self::new`]'s handle type would otherwise force them to depend
    /// on it directly just to wrap the `KeySet`.
    pub fn from_static_keys(secret: HmacSecret, keys: KeySet) -> Self {
        let snapshot = Arc::new(ArcSwap::new(Arc::new(ControlPlaneSnapshot {
            keys,
            policies: crate::model_authz::TenantPolicyMap::new(),
            key_budgets: Default::default(),
            key_policies: Default::default(),
            key_tenants: Default::default(),
            tenant_credentials: HashMap::new(),
        })));
        VirtualKeyAuthenticator {
            secret,
            snapshot,
            freshness: None,
        }
    }
}

impl fmt::Debug for VirtualKeyAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `load()` here is the same lock-free `Arc` clone `authenticate` uses
        // -- reused only to reach `KeySet`'s own redacted `Debug` (count
        // only). `HmacSecret`'s own redacted `Debug` covers the secret.
        let snapshot = self.snapshot.load();
        f.debug_struct("VirtualKeyAuthenticator")
            .field("secret", &self.secret)
            .field("keys", &snapshot.keys)
            .finish()
    }
}

impl Authenticator for VirtualKeyAuthenticator {
    fn authenticate(&self, headers: &HeaderMap) -> AuthOutcome {
        let Some(value) = headers.get(AUTHORIZATION) else {
            return AuthOutcome::NoCredential;
        };
        // A header value that isn't valid UTF-8 isn't a `Bearer llmp_...`
        // credential this authenticator can even parse -- treat it the same
        // as "wrong shape", not as a known-bad credential.
        let Ok(value) = value.to_str() else {
            return AuthOutcome::NoCredential;
        };
        let Some(presented) = value.strip_prefix(BEARER_PREFIX) else {
            return AuthOutcome::NoCredential;
        };
        if !presented.starts_with(KEY_PREFIX) {
            // Not shaped like a virtual key -- may be a JWT (or anything
            // else) meant for a later authenticator. This is the OIDC seam;
            // see the module doc and `AuthOutcome::NoCredential`'s doc for
            // why this must not become `Rejected`.
            return AuthOutcome::NoCredential;
        }

        // Past the staleness bound the snapshot may still hold a key that was
        // revoked elsewhere, so no virtual key is trusted (fail closed). Two
        // relaxed atomic loads; nothing is logged here, the policy poller
        // announces the transition once.
        if self
            .freshness
            .as_ref()
            .is_some_and(|freshness| freshness.is_expired())
        {
            return AuthOutcome::Rejected(AuthError::PolicyStale);
        }

        // Rust note: `ArcSwap::load` returns a guard that derefs to the
        // currently-published `Arc<ControlPlaneSnapshot>` without taking any
        // lock -- this is the ONLY place the hot path touches the control
        // plane, and it never blocks on (or even reaches) the store. See
        // `crate::control::ControlPlane::rebuild` for where a new snapshot
        // actually gets published.
        let snapshot = self.snapshot.load();
        match snapshot.keys.find(&self.secret, presented) {
            Some(record) if record.revoked => AuthOutcome::Rejected(AuthError::RevokedKey),
            // The credential set comes from this same guard, never a second
            // load, so a key revoked between two loads cannot mix states
            // (ADR-0007 decision 4).
            Some(record) => AuthOutcome::Authenticated(Principal {
                tenant: record.tenant.clone(),
                key_id: record.key_id.clone(),
                policy: Arc::new(TenantPolicy::default()),
                tenant_credentials: snapshot.tenant_credentials.get(&record.tenant).cloned(),
            }),
            None => AuthOutcome::Rejected(AuthError::UnknownKey),
        }
    }
}

/// Walks a sequence of [`Authenticator`]s and produces one [`AuthOutcome`]
/// for a request -- the seam that lets a new credential
/// kind slot in beside the existing ones without this type, or anything above
/// it, changing shape.
///
/// Rust note: `Vec<Box<dyn Authenticator>>` -- a trait object per entry,
/// since the chain is heterogeneous (a virtual-key authenticator today, a
/// JWT one later) and its length is a runtime config choice, not something
/// generics could express.
pub struct AuthenticatorChain {
    authenticators: Vec<Box<dyn Authenticator>>,
}

impl AuthenticatorChain {
    pub fn new(authenticators: Vec<Box<dyn Authenticator>>) -> Self {
        AuthenticatorChain { authenticators }
    }

    /// Tries each authenticator in configured order and returns the first
    /// terminal outcome:
    /// - the first `Authenticated` wins immediately;
    /// - the first `Rejected` is returned **immediately, without trying the
    ///   rest**. This is the entire reason [`AuthOutcome`] has three variants
    ///   instead of two -- see its doc. A "simplification" that turns this
    ///   loop into "keep going until something authenticates" would treat
    ///   `Rejected` the same as `NoCredential` and reopen exactly the
    ///   probing oracle that distinction exists to close: a caller could
    ///   present a bad credential of one kind, learn it was recognized as
    ///   that kind (from the fact that a *different* authenticator's
    ///   `Rejected` did not stop the chain), and repeat per authenticator.
    /// - if every authenticator answers `NoCredential`, so does this method.
    pub fn authenticate(&self, headers: &HeaderMap) -> AuthOutcome {
        for authenticator in &self.authenticators {
            match authenticator.authenticate(headers) {
                AuthOutcome::Authenticated(principal) => {
                    return AuthOutcome::Authenticated(principal)
                }
                AuthOutcome::Rejected(err) => return AuthOutcome::Rejected(err),
                AuthOutcome::NoCredential => continue,
            }
        }
        AuthOutcome::NoCredential
    }
}

impl fmt::Debug for AuthenticatorChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Count only, consistent with every other Debug in this module (see
        // the module doc's closing paragraph) -- there is nothing secret in
        // an authenticator list, but the convention here is to spell every
        // impl out explicitly rather than mix derived and hand-written ones.
        f.debug_struct("AuthenticatorChain")
            .field("authenticators", &self.authenticators.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use http::HeaderValue;

    use crate::control::test_snapshot_handle;
    use proxy_http::tenant_credentials::{TenantCredential, TenantSecret};

    fn headers_with_authorization(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        headers
    }

    fn authenticator_with(
        secret_bytes: &[u8],
        record: KeyRecord,
        plaintext_key: &str,
    ) -> VirtualKeyAuthenticator {
        let secret = HmacSecret::new(secret_bytes);
        let mut keys = KeySet::new();
        keys.insert(&secret, plaintext_key, record);
        VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), test_snapshot_handle(keys))
    }

    // --- 1: a correct key authenticates with the right tenant and key_id ---

    #[test]
    fn a_correct_key_authenticates_with_the_right_tenant_and_key_id() {
        let auth = authenticator_with(
            b"operator-secret",
            KeyRecord {
                key_id: KeyId::new("key-1"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
            },
            "llmp_correct-key",
        );

        let headers = headers_with_authorization("Bearer llmp_correct-key");
        match auth.authenticate(&headers) {
            AuthOutcome::Authenticated(principal) => {
                assert_eq!(principal.tenant.as_str(), "tenant-a");
                assert_eq!(principal.key_id.as_str(), "key-1");
            }
            other => panic!("expected Authenticated, got a different outcome (variant only, no Debug on AuthOutcome): matched={}", matches!(other, AuthOutcome::Authenticated(_))),
        }
    }

    /// One snapshot holding a key for `tenant-t` (which has an `openrouter`
    /// credential) and a key for `tenant-u` (which has none). Built by hand
    /// so these tests cover only the hand-off from snapshot to `StreamInfo`.
    /// The decrypt path that fills `tenant_credentials` in a real snapshot is
    /// covered in `control.rs`.
    fn snapshot_with_tenant_credentials(secret: &HmacSecret) -> Arc<ArcSwap<ControlPlaneSnapshot>> {
        let mut keys = KeySet::new();
        keys.insert(
            secret,
            "llmp_key-t",
            KeyRecord {
                key_id: KeyId::new("key-t"),
                tenant: TenantId::new("tenant-t"),
                revoked: false,
            },
        );
        keys.insert(
            secret,
            "llmp_key-u",
            KeyRecord {
                key_id: KeyId::new("key-u"),
                tenant: TenantId::new("tenant-u"),
                revoked: false,
            },
        );
        let set = TenantCredentialSet::new(HashMap::from([(
            "openrouter".to_string(),
            TenantCredential::Usable(TenantSecret::new("sk-or-test-secret".to_string())),
        )]));
        Arc::new(ArcSwap::new(Arc::new(ControlPlaneSnapshot {
            keys,
            policies: crate::model_authz::TenantPolicyMap::new(),
            key_budgets: HashMap::new(),
            key_policies: HashMap::new(),
            key_tenants: HashMap::new(),
            tenant_credentials: HashMap::from([(TenantId::new("tenant-t"), Arc::new(set))]),
        })))
    }

    // --- the principal carries its own tenant's credential set, read from the
    // --- same snapshot that verified its key (ADR-0007 decision 4) ---

    #[test]
    fn a_principal_carries_its_tenants_credential_set_from_the_same_snapshot() {
        let secret = HmacSecret::new(b"operator-secret");
        let auth = VirtualKeyAuthenticator::new(
            HmacSecret::new(b"operator-secret"),
            snapshot_with_tenant_credentials(&secret),
        );

        match auth.authenticate(&headers_with_authorization("Bearer llmp_key-t")) {
            AuthOutcome::Authenticated(principal) => {
                let set = principal
                    .tenant_credentials
                    .as_ref()
                    .expect("tenant-t holds a credential set");
                assert!(matches!(
                    set.get("openrouter"),
                    Some(TenantCredential::Usable(_))
                ));
                // The Debug of a principal must never print the plaintext key.
                assert!(!format!("{principal:?}").contains("sk-or-test-secret"));
            }
            _ => panic!("tenant-t's key must authenticate"),
        }

        match auth.authenticate(&headers_with_authorization("Bearer llmp_key-u")) {
            AuthOutcome::Authenticated(principal) => {
                assert!(principal.tenant_credentials.is_none());
            }
            _ => panic!("tenant-u's key must authenticate"),
        }
    }

    // --- 2: an unknown llmp_ key is Rejected, not NoCredential ---

    #[test]
    fn an_unknown_llmp_key_is_rejected() {
        let auth = authenticator_with(
            b"operator-secret",
            KeyRecord {
                key_id: KeyId::new("key-1"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
            },
            "llmp_the-configured-key",
        );

        let headers = headers_with_authorization("Bearer llmp_some-other-key");
        match auth.authenticate(&headers) {
            AuthOutcome::Rejected(AuthError::UnknownKey) => {}
            AuthOutcome::Rejected(other) => panic!("expected UnknownKey, got {other:?}"),
            AuthOutcome::Authenticated(_) => panic!("an unknown key must not authenticate"),
            AuthOutcome::NoCredential => {
                panic!("an unrecognized llmp_-prefixed key must be Rejected, not NoCredential")
            }
        }
    }

    // --- 3: absent header -> NoCredential, NOT Rejected (the oracle distinction) ---

    #[test]
    fn absent_authorization_header_is_no_credential_not_rejected() {
        let auth = authenticator_with(
            b"operator-secret",
            KeyRecord {
                key_id: KeyId::new("key-1"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
            },
            "llmp_the-configured-key",
        );

        let headers = HeaderMap::new();
        match auth.authenticate(&headers) {
            AuthOutcome::NoCredential => {}
            AuthOutcome::Rejected(err) => {
                panic!("an absent header must be NoCredential, not Rejected({err:?}) -- see the oracle distinction in the module doc")
            }
            AuthOutcome::Authenticated(_) => panic!("an absent header must not authenticate"),
        }
    }

    // --- 4: a JWT-shaped Bearer value -> NoCredential, protects the OIDC seam ---

    #[test]
    fn jwt_shaped_bearer_value_is_no_credential_protecting_the_oidc_seam() {
        let auth = authenticator_with(
            b"operator-secret",
            KeyRecord {
                key_id: KeyId::new("key-1"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
            },
            "llmp_the-configured-key",
        );

        // Not a real signed JWT, just shaped like one (header.payload.signature,
        // base64url header starting `eyJ`) -- this authenticator must never
        // try to interpret it, only recognize "not mine".
        let headers = headers_with_authorization(
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        );
        match auth.authenticate(&headers) {
            AuthOutcome::NoCredential => {}
            AuthOutcome::Rejected(err) => panic!(
                "a JWT-shaped bearer value must be NoCredential (deferred to a future \
                 JwtAuthenticator), not Rejected({err:?}) -- this is exactly the OIDC seam"
            ),
            AuthOutcome::Authenticated(_) => panic!("a JWT-shaped value must not authenticate"),
        }
    }

    // --- 5: a revoked key -> Rejected ---

    #[test]
    fn a_revoked_key_is_rejected() {
        let auth = authenticator_with(
            b"operator-secret",
            KeyRecord {
                key_id: KeyId::new("key-1"),
                tenant: TenantId::new("tenant-a"),
                revoked: true,
            },
            "llmp_revoked-key",
        );

        let headers = headers_with_authorization("Bearer llmp_revoked-key");
        match auth.authenticate(&headers) {
            AuthOutcome::Rejected(AuthError::RevokedKey) => {}
            AuthOutcome::Rejected(other) => panic!("expected RevokedKey, got {other:?}"),
            AuthOutcome::Authenticated(_) => panic!("a revoked key must not authenticate"),
            AuthOutcome::NoCredential => {
                panic!("a revoked key is a known credential; must be Rejected")
            }
        }
    }

    // --- 6: the same key under a different HMAC secret does not authenticate ---

    #[test]
    fn the_same_key_under_a_different_hmac_secret_does_not_authenticate() {
        // Build the KeySet keyed under one secret, but hand the
        // authenticator a different one -- proves the digest is actually
        // keyed rather than a plain, secret-independent hash.
        let build_secret = HmacSecret::new(b"secret-one");
        let mut keys = KeySet::new();
        keys.insert(
            &build_secret,
            "llmp_same-plaintext-key",
            KeyRecord {
                key_id: KeyId::new("key-1"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
            },
        );
        let auth = VirtualKeyAuthenticator::new(
            HmacSecret::new(b"secret-two"),
            test_snapshot_handle(keys),
        );

        let headers = headers_with_authorization("Bearer llmp_same-plaintext-key");
        match auth.authenticate(&headers) {
            AuthOutcome::Rejected(AuthError::UnknownKey) => {}
            other_outcome => panic!(
                "the same plaintext key under a DIFFERENT secret must not authenticate; \
                 got Authenticated={}",
                matches!(other_outcome, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 7: no Debug output anywhere contains the plaintext key, digest, or secret ---

    #[test]
    fn no_debug_output_contains_plaintext_key_digest_or_secret() {
        let plaintext_key = "llmp_very-secret-plaintext-value";
        let secret_bytes = b"the-operator-hmac-secret";
        let secret = HmacSecret::new(secret_bytes);

        let record = KeyRecord {
            key_id: KeyId::new("key-1"),
            tenant: TenantId::new("tenant-a"),
            revoked: false,
        };
        let mut keys = KeySet::new();
        keys.insert(&secret, plaintext_key, record);
        let handle = test_snapshot_handle(keys);

        let auth = VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), Arc::clone(&handle));

        let headers = headers_with_authorization(&format!("Bearer {plaintext_key}"));
        let outcome = auth.authenticate(&headers);
        let principal = match outcome {
            AuthOutcome::Authenticated(p) => p,
            _ => panic!("expected Authenticated for this test's setup"),
        };

        // The actual digest, so we can also assert it never appears verbatim.
        let digest = ring::hmac::sign(&HmacSecret::new(secret_bytes).0, plaintext_key.as_bytes());
        let digest_hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();

        let keys_debug = format!("{:?}", handle.load().keys);
        let rendered = [
            format!("{:?}", auth),
            keys_debug,
            format!("{principal:?}"),
            format!("{:?}", HmacSecret::new(secret_bytes)),
        ]
        .join(" | ");

        assert!(
            !rendered.contains(plaintext_key),
            "Debug output must never contain the plaintext key: {rendered}"
        );
        assert!(
            !rendered.contains(std::str::from_utf8(secret_bytes).unwrap()),
            "Debug output must never contain the HMAC secret: {rendered}"
        );
        assert!(
            !rendered.contains(&digest_hex),
            "Debug output must never contain the digest: {rendered}"
        );
    }

    // --- generate_plaintext_key: llmp_ prefix, 32-byte body, two draws differ ---

    #[test]
    fn generated_key_has_the_llmp_prefix_and_decodes_to_32_bytes() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let rng = ring::rand::SystemRandom::new();
        let key = generate_plaintext_key(&rng);
        let encoded = key.strip_prefix(KEY_PREFIX).expect("missing llmp_ prefix");
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .expect("key body must be valid base64url without padding");
        assert_eq!(decoded.len(), KEY_ENTROPY_BYTES);
    }

    #[test]
    fn two_generated_keys_differ() {
        let rng = ring::rand::SystemRandom::new();
        assert_ne!(generate_plaintext_key(&rng), generate_plaintext_key(&rng));
    }

    // --- 8: a key differing only in its last byte -> Rejected ---

    #[test]
    fn a_key_differing_only_in_its_last_byte_is_rejected() {
        let auth = authenticator_with(
            b"operator-secret",
            KeyRecord {
                key_id: KeyId::new("key-1"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
            },
            "llmp_almost-the-right-key-A",
        );

        // Differs only in the final character.
        let headers = headers_with_authorization("Bearer llmp_almost-the-right-key-B");
        match auth.authenticate(&headers) {
            AuthOutcome::Rejected(AuthError::UnknownKey) => {}
            other_outcome => panic!(
                "a key differing only in its last byte must be Rejected as unknown \
                 (sanity that comparison covers the whole digest); got Authenticated={}",
                matches!(other_outcome, AuthOutcome::Authenticated(_))
            ),
        }
    }
}
