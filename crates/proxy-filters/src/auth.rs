//! WP-50 increment 2a-i — the downstream-authentication core.
//!
//! **Library only.** This module resolves an inbound request's credential to
//! a [`Principal`] (or refuses it); it is not wired into an `HttpFilter`
//! here, and the token limiter is not yet re-keyed onto `Principal.tenant` --
//! both are a separate increment. See `docs/wp-50-auth-design-brief.md`,
//! which is normative and agreed with the repo owner; this module implements
//! its increment 2a ("virtual keys, in-memory") exactly as scoped there.
//!
//! # Why an `Authenticator` trait, not "the virtual-key filter"
//!
//! The owner intends OIDC/JWT as a second credential kind later (increment
//! 2c). So [`Authenticator`] is deliberately a trait with one implementation
//! today ([`VirtualKeyAuthenticator`]) rather than a concrete type baked into
//! a filter -- a future `JwtAuthenticator` is meant to slot in beside it
//! without reshaping anything above.
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
//! problems is exactly the trap the design brief calls out.
//!
//! # Constant-time comparison: `ring::hmac::verify`, not `constant_time::verify_slices_are_equal`
//!
//! The design brief calls for `ring::constant_time::verify_slices_are_equal`.
//! In the `ring` version this workspace pins (0.17.14), that function has
//! been deprecated with the note "Internal function not intended for
//! external use with **no promises regarding side channels**" -- i.e. `ring`
//! itself no longer documents it as constant-time for callers outside the
//! crate, which is the entire property this module needs. `ring::hmac::verify`
//! is the documented replacement for exactly this shape of check ("The
//! verification will be done in constant time to prevent timing attacks.")
//! and is implemented in terms of the same internal primitive, so this module
//! uses it instead. [`KeySet::find`] derives the digest with
//! `ring::hmac::sign` to look the record up, then calls
//! `ring::hmac::verify(secret, presented_bytes, digest)` **once**, on the
//! single candidate — so the byte comparison that actually decides
//! authentication is the documented constant-time one rather than
//! `HashMap`'s `Eq`, which short-circuits. `ring::hmac::sign` is also what
//! *produces* a digest when a record is inserted into a [`KeySet`] (there is
//! nothing to verify at insert time).
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
//! them (200 vs 401). The comparison that decides authentication is still the
//! documented constant-time one, performed once on the single candidate.
//!
//! # Nothing here leaks key material through `Debug`
//!
//! [`KeyRecord`], [`KeySet`], [`Principal`], [`HmacSecret`] and
//! [`VirtualKeyAuthenticator`] all have hand-written `Debug` impls (nothing
//! is `#[derive(Debug)]`d on a type that could carry a plaintext key, a
//! digest, or the HMAC secret) so that a stray `tracing::debug!(?principal)`
//! or similar can never become a leak channel. `tenant`/`key_id` are
//! identifiers, not secrets -- the design brief explicitly wants them
//! nameable in audit logs -- so only the fields that touch key material are
//! actually redacted; the rest are still hand-written, on purpose, so a
//! future field addition to one of these types has to make the same call
//! explicitly rather than inherit it from `#[derive]`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use http::header::AUTHORIZATION;
use http::HeaderMap;

/// Scheme prefix this authenticator recognizes on the `authorization`
/// header. Anything else (no header, a different scheme, a bare token) is
/// simply not a credential this authenticator understands -- see
/// [`AuthOutcome::NoCredential`].
const BEARER_PREFIX: &str = "Bearer ";

/// Printable prefix every virtual key carries -- see the design brief's "Key
/// format" section: greppable in incident response, revocable by prefix
/// scan, and distinguishable from a provider key pasted into the wrong
/// field. A `Bearer` value without this prefix is assumed to belong to a
/// later authenticator (e.g. a JWT) rather than being a malformed virtual
/// key -- this is the OIDC seam, and it is why that case is
/// `NoCredential`, not `Rejected`.
const KEY_PREFIX: &str = "llmp_";

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
/// Deliberately EMPTY in this increment -- WP-50 increment 3 is where model
/// allow-lists and budgets land. It exists now, carried by [`Principal`]
/// behind an `Arc`, so that adding the first policy field is a change to
/// this one struct rather than a signature change through every call site
/// that carries a `Principal`.
///
/// # The default grants everything (owner decision, 2026-08-08)
///
/// A tenant with no policy configured may use every model and every provider.
/// Restriction is opt-in: an operator adds an allow-list when they want one.
///
/// **This does not contradict the module's fail-closed rule, and the two axes
/// must not be confused.** *Authentication* fails closed — an unknown or
/// revoked credential is a 401, always. *Authorization* defaults open — once
/// we know who you are, absent any configured restriction, you may proceed.
///
/// # The trap this creates, for whoever adds the first field
///
/// "No policy configured" and "a configured policy that failed to load" must
/// **not** produce the same value. The first is this `Default` and grants
/// everything; the second is a config error and must fail loudly with its
/// dotted path (ground rule #1), because silently substituting the permissive
/// default for a policy the operator *wrote* would turn a typo into a
/// privilege escalation.
///
/// For the same reason, express access as an explicit enum rather than a
/// collection whose emptiness has to be interpreted:
///
/// ```ignore
/// enum ModelAccess { All, Only(Vec<ModelPattern>) }   // do this
/// models: Vec<ModelPattern>                            // NOT this
/// ```
///
/// With a bare `Vec`, `vec![]` has to mean either "everything" or "nothing",
/// and whichever you pick, the other becomes inexpressible — while
/// `ModelAccess::Only(vec![])` says "deny all" unambiguously and
/// `ModelAccess::All` is the documented default.
#[derive(Clone, Default)]
pub struct TenantPolicy {}

impl fmt::Debug for TenantPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TenantPolicy").finish()
    }
}

/// The caller identity a successful authentication resolves to.
pub struct Principal {
    pub tenant: TenantId,
    /// WHICH credential authenticated -- see [`KeyId`]'s doc.
    pub key_id: KeyId,
    /// Model allow-lists, budgets, quotas (increment 3; empty today). An
    /// `Arc` so the hot path clones a pointer, and so a future policy change
    /// is a snapshot swap rather than a per-request lookup.
    pub policy: Arc<TenantPolicy>,
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
/// gets (200 vs 401). The constant-time comparison that matters is still
/// performed, once, on the single candidate: see [`KeySet::find`].
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
    pub fn insert(&mut self, secret: &HmacSecret, presented_key: &str, record: KeyRecord) {
        let digest = ring::hmac::sign(&secret.0, presented_key.as_bytes());
        self.entries.insert(digest.as_ref().to_vec(), record);
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

    /// Finds the record for `presented`: one HMAC to derive the digest, one
    /// table lookup, then one constant-time verification of the candidate.
    ///
    /// The `hmac::verify` call is deliberately kept even though the lookup
    /// already matched. It costs one HMAC on the success path only, and it
    /// means the byte comparison that decides authentication is the
    /// documented constant-time one rather than `HashMap`'s `Eq`, which
    /// short-circuits. See [`KeySet`]'s doc for why the lookup itself is not
    /// a meaningful side channel.
    fn find(&self, secret: &HmacSecret, presented: &str) -> Option<&KeyRecord> {
        let digest = ring::hmac::sign(&secret.0, presented.as_bytes());
        let record = self.entries.get(digest.as_ref())?;
        ring::hmac::verify(&secret.0, presented.as_bytes(), digest.as_ref())
            .ok()
            .map(|()| record)
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
    keys: Arc<KeySet>,
}

impl VirtualKeyAuthenticator {
    pub fn new(secret: HmacSecret, keys: Arc<KeySet>) -> Self {
        VirtualKeyAuthenticator { secret, keys }
    }
}

impl fmt::Debug for VirtualKeyAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtualKeyAuthenticator")
            // `HmacSecret`'s own redacted `Debug` covers the secret; `KeySet`'s
            // covers the digests. Neither field is skipped -- both are just
            // safe to print because their own impls already redact.
            .field("secret", &self.secret)
            .field("keys", &self.keys)
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

        match self.keys.find(&self.secret, presented) {
            Some(record) if record.revoked => AuthOutcome::Rejected(AuthError::RevokedKey),
            Some(record) => AuthOutcome::Authenticated(Principal {
                tenant: record.tenant.clone(),
                key_id: record.key_id.clone(),
                policy: Arc::new(TenantPolicy::default()),
            }),
            None => AuthOutcome::Rejected(AuthError::UnknownKey),
        }
    }
}

/// Walks a sequence of [`Authenticator`]s and produces one [`AuthOutcome`]
/// for a request -- the seam the design brief's "authenticator is a trait"
/// section names: today this chain holds exactly one
/// [`VirtualKeyAuthenticator`], and a future `JwtAuthenticator` (increment
/// 2c) is meant to slot in beside it without this type, or anything above
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
        VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), Arc::new(keys))
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
        let auth = VirtualKeyAuthenticator::new(HmacSecret::new(b"secret-two"), Arc::new(keys));

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
        let keys = Arc::new(keys);

        let auth = VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), Arc::clone(&keys));

        let headers = headers_with_authorization(&format!("Bearer {plaintext_key}"));
        let outcome = auth.authenticate(&headers);
        let principal = match outcome {
            AuthOutcome::Authenticated(p) => p,
            _ => panic!("expected Authenticated for this test's setup"),
        };

        // The actual digest, so we can also assert it never appears verbatim.
        let digest = ring::hmac::sign(&HmacSecret::new(secret_bytes).0, plaintext_key.as_bytes());
        let digest_hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();

        let rendered = [
            format!("{:?}", auth),
            format!("{keys:?}"),
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
