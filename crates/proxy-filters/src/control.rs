//! WP-50 increment 3b-i — the control-plane store seam, its published
//! snapshot, and `ControlPlane`, the type that turns one into the other.
//!
//! **Normative:** `internal-docs/wp-50-3b-store-design-brief.md`, sections
//! "the seam", "`ControlPlaneStore` trait", and "Snapshot rebuild + bootstrap
//! merge". This module implements exactly the 3b-i slice that brief scopes:
//! the trait, an in-memory store, the published snapshot, and rewiring
//! [`crate::auth::VirtualKeyAuthenticator`] onto it. **No `redb`** (3b-ii),
//! **no admin write API** (3b-ii), **no `model_authz_filter` migration**
//! (still reads its own `typed_config` this increment) — see the brief's
//! "sub-increments" section for the full split.
//!
//! # The seam, restated for this crate
//!
//! ```text
//!                     admin write (mint/revoke/CRUD) -- NOT built yet (3b-ii)
//!                                    │  rebuild + swap
//! store.load() ──▶ ControlPlane ──publish──▶ Arc<ArcSwap<ControlPlaneSnapshot>>
//!  (control-side)   (owns store,                     ▲
//!                  HMAC secret, bootstrap)    lock-free load
//!                                              auth filter (this increment)
//! ```
//!
//! [`ControlPlane`] owns the [`ControlPlaneStore`], the operator's HMAC
//! secret, the config's bootstrap [`crate::auth::KeySet`], and the published
//! `Arc<ArcSwap<ControlPlaneSnapshot>>`. [`VirtualKeyAuthenticator`] (in
//! `auth.rs`) holds a clone of that same `Arc<ArcSwap<..>>` and `load()`s it
//! on every request -- a lock-free `Arc` clone, no store I/O on the hot path.
//!
//! # Boot vs. refresh: the fail-closed split that must not be "simplified"
//!
//! A `load()` failure means two different things depending on when it
//! happens, and conflating them is exactly the P0 this split exists to avoid:
//!
//! - **At boot** ([`ControlPlane::new`]): there is no snapshot yet to fall
//!   back to, so a `load` failure is a **hard error** -- the caller (the auth
//!   filter's factory) must refuse to start rather than publish an empty
//!   snapshot and silently 401 every request with nothing in the logs to
//!   explain why.
//! - **On refresh** ([`ControlPlane::rebuild`]): a *previous* good snapshot
//!   is already published and serving traffic. A transient store blip must
//!   not nuke it -- see CLAUDE.md rule 17 ("a security control that fails
//!   open must be loud"; the mirror image applies here too: a control that
//!   fails *closed* on a blip is its own outage). `rebuild` on `Err` leaves
//!   `published` untouched and `tracing::warn!`s loudly instead.
//!
//! [`VirtualKeyAuthenticator`]: crate::auth::VirtualKeyAuthenticator

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::auth::{HmacSecret, KeyId, KeyRecord, KeySet, TenantId, TenantPolicy};
use crate::model_authz::{ModelAccess, TenantPolicyMap};

/// One key row exactly as a [`ControlPlaneStore`] persists it -- the
/// admin-write shape, not the digest-keyed [`KeySet`] the data plane reads.
/// [`ControlPlane::rebuild`] converts a `Vec<StoredKey>` into a [`KeySet`]
/// once per rebuild; nothing on the request path ever sees a `StoredKey`.
#[derive(Clone)]
pub struct StoredKey {
    pub key_id: KeyId,
    pub digest: [u8; 32],
    pub tenant: TenantId,
    pub revoked: bool,
}

// Rust note: hand-written, not derived -- same convention `auth.rs`'s module
// doc explains at length: `digest` is key-material-adjacent (a caller with
// only the digest still cannot forge a key, but it is not something to print
// on a whim either), so every `Debug` in this file that could touch one is
// spelled out explicitly rather than inheriting whatever `#[derive]` would
// have done.
impl std::fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredKey")
            .field("key_id", &self.key_id)
            .field("tenant", &self.tenant)
            .field("revoked", &self.revoked)
            .finish()
    }
}

/// Everything one [`ControlPlaneStore::load`] call returns -- the whole
/// control-plane state, read in one shot so a rebuild is one I/O round trip
/// rather than N.
pub struct StoredControlPlane {
    pub tenants: Vec<TenantId>,
    pub keys: Vec<StoredKey>,
    pub policies: HashMap<TenantId, ModelAccess>,
}

/// Why a [`ControlPlaneStore`] call failed.
///
/// Deliberately small in this increment (`InMemoryControlPlaneStore`'s writes
/// are infallible; only a test double's `load` ever returns this). A future
/// `redb` implementation (3b-ii) is expected to widen this with e.g. an I/O
/// variant, but the two call sites that interpret it -- [`ControlPlane::new`]
/// (hard error) and [`ControlPlane::rebuild`] (log and keep serving) -- do
/// not need to distinguish reasons, only "it failed".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The backend could not be reached or read at all.
    Unavailable(String),
    /// A write targeted a row the store has never seen (e.g. revoking an
    /// unknown `key_id`).
    NotFound,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Unavailable(reason) => {
                write!(f, "control-plane store unavailable: {reason}")
            }
            StoreError::NotFound => write!(f, "control-plane store: not found"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Where the control plane's durable state lives. ADR-0005's four
/// requirements, explicitly: a failure channel on reads (`load`'s `Result`),
/// a stated boot/refresh failure policy (see the module doc, not this
/// trait -- the policy lives in [`ControlPlane`], the trait only reports),
/// one isolated call per write (so a future remote impl has one swap site per
/// call), and no timestamp claims of an authority this trait doesn't have.
///
/// `Send + Sync`: a `Box<dyn ControlPlaneStore>` is meant to be shared the
/// same way `Box<dyn Authenticator>` already is elsewhere in this crate --
/// see `auth.rs`'s `Authenticator` trait doc.
pub trait ControlPlaneStore: Send + Sync {
    /// The snapshot-build read: everything a rebuild needs, in one call.
    fn load(&self) -> Result<StoredControlPlane, StoreError>;

    // Writes. The data plane never calls any of these -- only a future admin
    // API (3b-ii) does, off the request path.
    fn create_tenant(&self, tenant: &TenantId) -> Result<(), StoreError>;
    fn delete_tenant(&self, tenant: &TenantId) -> Result<(), StoreError>;
    /// Inserts or overwrites the row for `rec.key_id`.
    fn put_key(&self, rec: &StoredKey) -> Result<(), StoreError>;
    /// Sets `revoked = true` on the row named by `key_id` and keeps it (the
    /// audit trail survives a revoke) -- see `StoredKey::revoked`'s use in
    /// [`ControlPlane::rebuild`] for why the row is not deleted.
    fn revoke_key(&self, key_id: &KeyId) -> Result<(), StoreError>;
    fn set_policy(&self, tenant: &TenantId, access: &ModelAccess) -> Result<(), StoreError>;
}

/// The two things the data plane reads per request, built wholesale by
/// [`ControlPlane::rebuild`] and swapped in atomically. Immutable once
/// constructed -- a filter never mutates a `ControlPlaneSnapshot`; a new one
/// entirely replaces it.
pub struct ControlPlaneSnapshot {
    pub keys: KeySet,
    pub policies: TenantPolicyMap,
}

/// In-memory [`ControlPlaneStore`]. The whole of 3b-i's storage engine --
/// `redb` is 3b-ii. Backed by a `Mutex` because the trait's write methods
/// take `&self` (so a `Box<dyn ControlPlaneStore>` can be shared without the
/// caller synchronizing), not `&mut self`.
///
/// Rust note: interior mutability via `std::sync::Mutex`, the standard
/// pattern for "shared, `Send + Sync`, occasionally written" state -- see
/// `crate::token_limit`'s `BudgetStore` impls for the same shape used
/// elsewhere in this crate.
pub struct InMemoryControlPlaneStore {
    state: std::sync::Mutex<InMemoryState>,
}

struct InMemoryState {
    tenants: Vec<TenantId>,
    keys: HashMap<KeyId, StoredKey>,
    policies: HashMap<TenantId, ModelAccess>,
}

impl InMemoryControlPlaneStore {
    pub fn new() -> Self {
        InMemoryControlPlaneStore {
            state: std::sync::Mutex::new(InMemoryState {
                tenants: Vec::new(),
                keys: HashMap::new(),
                policies: HashMap::new(),
            }),
        }
    }
}

impl Default for InMemoryControlPlaneStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlPlaneStore for InMemoryControlPlaneStore {
    fn load(&self) -> Result<StoredControlPlane, StoreError> {
        // Rust note: `.expect` on the lock, not `?`/graceful handling -- a
        // poisoned mutex means an earlier writer PANICKED mid-update, which
        // is a bug (not an operational condition like "the store is
        // unavailable") and the crash should propagate rather than silently
        // hand back a possibly torn snapshot.
        let state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        Ok(StoredControlPlane {
            tenants: state.tenants.clone(),
            keys: state.keys.values().cloned().collect(),
            policies: state.policies.clone(),
        })
    }

    fn create_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        if !state.tenants.contains(tenant) {
            state.tenants.push(tenant.clone());
        }
        Ok(())
    }

    fn delete_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        state.tenants.retain(|t| t != tenant);
        state.policies.remove(tenant);
        Ok(())
    }

    fn put_key(&self, rec: &StoredKey) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        state.keys.insert(rec.key_id.clone(), rec.clone());
        Ok(())
    }

    fn revoke_key(&self, key_id: &KeyId) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        match state.keys.get_mut(key_id) {
            Some(rec) => {
                rec.revoked = true;
                Ok(())
            }
            None => Err(StoreError::NotFound),
        }
    }

    fn set_policy(&self, tenant: &TenantId, access: &ModelAccess) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        state.policies.insert(tenant.clone(), access.clone());
        Ok(())
    }
}

/// Owns the store, the operator's HMAC secret, the config bootstrap keys, and
/// the published snapshot. See the module doc for the full seam and the
/// boot/refresh fail-closed split.
pub struct ControlPlane {
    store: Box<dyn ControlPlaneStore>,
    secret: HmacSecret,
    bootstrap_keys: KeySet,
    published: Arc<ArcSwap<ControlPlaneSnapshot>>,
}

impl ControlPlane {
    /// Builds the initial snapshot from `store.load()` merged with
    /// `bootstrap_keys` and publishes it. **A `load` failure here is a hard
    /// error** -- see the module doc's "boot vs. refresh" section. There is
    /// no prior snapshot to fall back to, so this returns `Err` rather than
    /// publishing anything, and the caller (the auth filter's factory) is
    /// expected to propagate that into filter-config-load failure -- refusing
    /// to start is correct; starting and 401-ing every request with no
    /// explanation in the logs is not.
    pub fn new(
        store: Box<dyn ControlPlaneStore>,
        secret: HmacSecret,
        bootstrap_keys: KeySet,
    ) -> Result<Self, StoreError> {
        let loaded = store.load()?;
        let snapshot = Self::merge(&bootstrap_keys, loaded);
        // Rust note: `ArcSwap::new` takes the initial `Arc<T>` directly --
        // unlike `rebuild` below, there is no "leave it alone on error"
        // question at construction time, because there is nothing published
        // yet to leave alone. The `?` above already returned before this
        // line runs if `load` failed.
        let published = Arc::new(ArcSwap::new(Arc::new(snapshot)));
        Ok(ControlPlane {
            store,
            secret,
            bootstrap_keys,
            published,
        })
    }

    /// Re-reads the store and republishes -- OR, on a read failure, leaves
    /// the previously published snapshot exactly as it was.
    ///
    /// Rust note: the `Err` arm deliberately does not touch `self.published`
    /// at all. `ArcSwap` keeps serving whatever `Arc` is currently stored
    /// until something calls `.store()` on it, so "do nothing" here **is**
    /// "keep serving the last good snapshot" -- there is no separate
    /// "restore" step. Replacing it with an empty `ControlPlaneSnapshot`
    /// instead would look like the safe, symmetric thing to do and would
    /// actually be the fail-OPEN-shaped bug this split exists to prevent:
    /// every key that used to authenticate would start 401-ing the instant a
    /// store read hiccuped, silently, with no distinguishing signal from "the
    /// key was actually revoked". See the module doc and CLAUDE.md rule 17.
    pub fn rebuild(&self) {
        match self.store.load() {
            Ok(loaded) => {
                let snapshot = Self::merge(&self.bootstrap_keys, loaded);
                self.published.store(Arc::new(snapshot));
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "control-plane store refresh failed; keeping the last published snapshot"
                );
            }
        }
    }

    /// A cloned handle to the published snapshot -- what
    /// [`crate::auth::VirtualKeyAuthenticator`] holds and `load()`s on every
    /// request. Cloning an `Arc` is cheap and does not clone the snapshot
    /// itself.
    pub fn handle(&self) -> Arc<ArcSwap<ControlPlaneSnapshot>> {
        Arc::clone(&self.published)
    }

    /// The HMAC secret this control plane was built with. Unused by 3b-i's
    /// data-plane path (the authenticator keeps its own copy -- see
    /// `auth_filter::AuthFilterFactory::create`'s doc for why two independent
    /// `HmacSecret`s exist rather than one shared); this accessor exists for
    /// 3b-ii's key-minting endpoint, which needs the same secret to compute a
    /// digest a minted key will actually authenticate against.
    pub fn secret(&self) -> &HmacSecret {
        &self.secret
    }

    /// Bootstrap keys layered under the store's, then the store's layered on
    /// top -- on a `key_id` collision the store wins. See the design brief's
    /// "Snapshot rebuild + bootstrap merge" section, which this implements
    /// exactly.
    fn merge(bootstrap_keys: &KeySet, loaded: StoredControlPlane) -> ControlPlaneSnapshot {
        // Rust note: keyed by `KeyId`, not by digest -- `KeySet` itself is
        // digest-keyed (see its doc for why), which is exactly the wrong
        // shape for detecting a `key_id` collision between two sources. This
        // map exists only to re-key long enough to resolve collisions; it is
        // consumed into a real (digest-keyed) `KeySet` before this function
        // returns.
        let mut by_key_id: HashMap<KeyId, (Vec<u8>, KeyRecord)> = HashMap::new();

        for (digest, record) in bootstrap_keys.iter() {
            by_key_id.insert(
                record.key_id.clone(),
                (
                    digest.to_vec(),
                    KeyRecord {
                        key_id: record.key_id.clone(),
                        tenant: record.tenant.clone(),
                        revoked: record.revoked,
                    },
                ),
            );
        }

        for stored in loaded.keys {
            if by_key_id.contains_key(&stored.key_id) {
                // Names ONLY the key_id -- never a digest or any key
                // material. See `StoredKey`'s Debug and the design brief's
                // collision-log rule.
                tracing::warn!(
                    key_id = stored.key_id.as_str(),
                    "control-plane store key_id collides with a config bootstrap key; \
                     the store record wins"
                );
            }
            by_key_id.insert(
                stored.key_id.clone(),
                (
                    stored.digest.to_vec(),
                    KeyRecord {
                        key_id: stored.key_id,
                        tenant: stored.tenant,
                        revoked: stored.revoked,
                    },
                ),
            );
        }

        let mut keys = KeySet::new();
        for (_key_id, (digest, record)) in by_key_id {
            keys.insert_digest(digest, record);
        }

        // 3b-i populates `policies` from the store only -- there is no
        // config-bootstrap policy source yet (bootstrap virtual keys carry no
        // `ModelAccess`), so there is nothing to layer under it. A tenant
        // absent here simply falls back to `TenantPolicy::default()`
        // (`ModelAccess::All`) wherever a policy lookup misses, exactly as it
        // does today via `model_authz_filter`'s own `typed_config`, which
        // this snapshot does not yet replace.
        let mut policies: TenantPolicyMap = HashMap::new();
        for (tenant, access) in loaded.policies {
            policies.insert(
                tenant.as_str().to_string(),
                Arc::new(TenantPolicy {
                    model_access: access,
                }),
            );
        }

        ControlPlaneSnapshot { keys, policies }
    }
}

/// Test helper shared across this crate's test modules (`auth.rs`,
/// `auth_filter.rs`): wraps a fixed [`KeySet`] (no policies) in a fresh
/// handle that is never [`ControlPlane::rebuild`]-ed. Every filter-behavior
/// test that only cares about "authenticate against this static key set" uses
/// this instead of standing up a full [`ControlPlane`] + store.
#[cfg(test)]
pub(crate) fn test_snapshot_handle(keys: KeySet) -> Arc<ArcSwap<ControlPlaneSnapshot>> {
    Arc::new(ArcSwap::new(Arc::new(ControlPlaneSnapshot {
        keys,
        policies: TenantPolicyMap::new(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicBool, Ordering};

    use http::header::AUTHORIZATION;
    use http::{HeaderMap, HeaderValue};

    use crate::auth::{AuthError, AuthOutcome, Authenticator, VirtualKeyAuthenticator};

    fn headers_with_authorization(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        headers
    }

    fn digest_bytes(secret_bytes: &[u8], plaintext: &str) -> [u8; 32] {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret_bytes);
        let sig = ring::hmac::sign(&key, plaintext.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(sig.as_ref());
        out
    }

    /// A `ControlPlaneStore` that forwards to a shared `InMemoryControlPlaneStore`
    /// -- used so a test can keep writing to the same store after handing a
    /// `Box<dyn ControlPlaneStore>` off to a `ControlPlane` (which otherwise
    /// takes ownership and leaves the test no way back in).
    struct SharedStore(Arc<InMemoryControlPlaneStore>);

    impl ControlPlaneStore for SharedStore {
        fn load(&self) -> Result<StoredControlPlane, StoreError> {
            self.0.load()
        }
        fn create_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
            self.0.create_tenant(tenant)
        }
        fn delete_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
            self.0.delete_tenant(tenant)
        }
        fn put_key(&self, rec: &StoredKey) -> Result<(), StoreError> {
            self.0.put_key(rec)
        }
        fn revoke_key(&self, key_id: &KeyId) -> Result<(), StoreError> {
            self.0.revoke_key(key_id)
        }
        fn set_policy(&self, tenant: &TenantId, access: &ModelAccess) -> Result<(), StoreError> {
            self.0.set_policy(tenant, access)
        }
    }

    /// A store whose `load` can be toggled to fail on command, via a shared
    /// flag the test keeps a handle to -- proves the fail-closed REFRESH path
    /// (as opposed to boot, which `FailingStore` below covers).
    struct ToggleStore {
        inner: InMemoryControlPlaneStore,
        fail: Arc<AtomicBool>,
    }

    impl ControlPlaneStore for ToggleStore {
        fn load(&self) -> Result<StoredControlPlane, StoreError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(StoreError::Unavailable("toggled off for test".to_string()));
            }
            self.inner.load()
        }
        fn create_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
            self.inner.create_tenant(tenant)
        }
        fn delete_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
            self.inner.delete_tenant(tenant)
        }
        fn put_key(&self, rec: &StoredKey) -> Result<(), StoreError> {
            self.inner.put_key(rec)
        }
        fn revoke_key(&self, key_id: &KeyId) -> Result<(), StoreError> {
            self.inner.revoke_key(key_id)
        }
        fn set_policy(&self, tenant: &TenantId, access: &ModelAccess) -> Result<(), StoreError> {
            self.inner.set_policy(tenant, access)
        }
    }

    /// `load` always fails; every write no-ops successfully (this double
    /// exists only to prove the BOOT fail-closed path, which never reaches a
    /// write). See the module doc's "boot vs. refresh" section.
    struct FailingStore;

    impl ControlPlaneStore for FailingStore {
        fn load(&self) -> Result<StoredControlPlane, StoreError> {
            Err(StoreError::Unavailable(
                "test double: load always fails".to_string(),
            ))
        }
        fn create_tenant(&self, _tenant: &TenantId) -> Result<(), StoreError> {
            Ok(())
        }
        fn delete_tenant(&self, _tenant: &TenantId) -> Result<(), StoreError> {
            Ok(())
        }
        fn put_key(&self, _rec: &StoredKey) -> Result<(), StoreError> {
            Ok(())
        }
        fn revoke_key(&self, _key_id: &KeyId) -> Result<(), StoreError> {
            Ok(())
        }
        fn set_policy(&self, _tenant: &TenantId, _access: &ModelAccess) -> Result<(), StoreError> {
            Ok(())
        }
    }

    // --- 1: a key seeded into the store authenticates after rebuild() -- proves the swap takes effect

    #[test]
    fn a_key_seeded_into_the_store_authenticates_after_rebuild() {
        let secret_bytes = b"operator-secret";
        let shared = Arc::new(InMemoryControlPlaneStore::default());
        let cp = ControlPlane::new(
            Box::new(SharedStore(Arc::clone(&shared))),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");
        let authenticator =
            VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp.handle());

        let headers = headers_with_authorization("Bearer llmp_store-seeded-key");

        // Before seeding: unknown.
        match authenticator.authenticate(&headers) {
            AuthOutcome::Rejected(AuthError::UnknownKey) => {}
            other => panic!(
                "expected UnknownKey before the store was seeded; got Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }

        // Seed the store directly (bypassing ControlPlane, which only reads
        // it) and rebuild.
        shared
            .put_key(&StoredKey {
                key_id: KeyId::new("store-key-1"),
                digest: digest_bytes(secret_bytes, "llmp_store-seeded-key"),
                tenant: TenantId::new("tenant-store"),
                revoked: false,
            })
            .expect("put_key must succeed against an in-memory store");
        cp.rebuild();

        match authenticator.authenticate(&headers) {
            AuthOutcome::Authenticated(principal) => {
                assert_eq!(principal.tenant.as_str(), "tenant-store");
                assert_eq!(principal.key_id.as_str(), "store-key-1");
            }
            other => panic!(
                "expected Authenticated after rebuild(); got Rejected={} NoCredential={}",
                matches!(other, AuthOutcome::Rejected(_)),
                matches!(other, AuthOutcome::NoCredential)
            ),
        }
    }

    // --- 2: a store key with revoked=true -> Rejected(RevokedKey)

    #[test]
    fn a_revoked_store_key_is_rejected() {
        let secret_bytes = b"operator-secret";
        let store = InMemoryControlPlaneStore::default();
        store
            .put_key(&StoredKey {
                key_id: KeyId::new("revoked-1"),
                digest: digest_bytes(secret_bytes, "llmp_revoked-store-key"),
                tenant: TenantId::new("tenant-a"),
                revoked: true,
            })
            .unwrap();

        let cp = ControlPlane::new(
            Box::new(store),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("boot must succeed");
        let authenticator =
            VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp.handle());

        let headers = headers_with_authorization("Bearer llmp_revoked-store-key");
        match authenticator.authenticate(&headers) {
            AuthOutcome::Rejected(AuthError::RevokedKey) => {}
            other => panic!(
                "expected Rejected(RevokedKey); got Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 3: a config bootstrap key still authenticates (no store keys at all)

    #[test]
    fn a_config_bootstrap_key_still_authenticates() {
        let secret_bytes = b"operator-secret";
        let secret_for_bootstrap = HmacSecret::new(secret_bytes);
        let mut bootstrap = KeySet::new();
        bootstrap.insert(
            &secret_for_bootstrap,
            "llmp_bootstrap-key",
            KeyRecord {
                key_id: KeyId::new("bootstrap-1"),
                tenant: TenantId::new("tenant-bootstrap"),
                revoked: false,
            },
        );

        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            bootstrap,
        )
        .expect("boot must succeed with an empty store");
        let authenticator =
            VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp.handle());

        let headers = headers_with_authorization("Bearer llmp_bootstrap-key");
        match authenticator.authenticate(&headers) {
            AuthOutcome::Authenticated(principal) => {
                assert_eq!(principal.tenant.as_str(), "tenant-bootstrap");
                assert_eq!(principal.key_id.as_str(), "bootstrap-1");
            }
            other => panic!(
                "expected a config bootstrap key to still authenticate; got Rejected={}",
                matches!(other, AuthOutcome::Rejected(_))
            ),
        }
    }

    // --- 4: store wins a key_id collision

    #[test]
    fn store_wins_a_key_id_collision() {
        let secret_bytes = b"operator-secret";

        let secret_for_bootstrap = HmacSecret::new(secret_bytes);
        let mut bootstrap = KeySet::new();
        bootstrap.insert(
            &secret_for_bootstrap,
            "llmp_bootstrap-value",
            KeyRecord {
                key_id: KeyId::new("k1"),
                tenant: TenantId::new("tenant-bootstrap"),
                revoked: false,
            },
        );

        let store = InMemoryControlPlaneStore::default();
        store
            .put_key(&StoredKey {
                key_id: KeyId::new("k1"),
                digest: digest_bytes(secret_bytes, "llmp_store-value"),
                tenant: TenantId::new("tenant-store"),
                revoked: false,
            })
            .unwrap();

        let cp = ControlPlane::new(Box::new(store), HmacSecret::new(secret_bytes), bootstrap)
            .expect("boot must succeed");
        cp.rebuild();
        let authenticator =
            VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp.handle());

        // The store's credential authenticates, as the store's tenant.
        let store_headers = headers_with_authorization("Bearer llmp_store-value");
        match authenticator.authenticate(&store_headers) {
            AuthOutcome::Authenticated(principal) => {
                assert_eq!(principal.tenant.as_str(), "tenant-store");
                assert_eq!(principal.key_id.as_str(), "k1");
            }
            other => panic!(
                "expected the store's credential to authenticate as the store's tenant; \
                 got Rejected={}",
                matches!(other, AuthOutcome::Rejected(_))
            ),
        }

        // The bootstrap's credential (same key_id, different digest) no
        // longer resolves to anything -- the store record replaced it
        // outright, it did not merely shadow it.
        let bootstrap_headers = headers_with_authorization("Bearer llmp_bootstrap-value");
        match authenticator.authenticate(&bootstrap_headers) {
            AuthOutcome::Rejected(AuthError::UnknownKey) => {}
            other => panic!(
                "the bootstrap credential must not authenticate once the store has \
                 overridden its key_id; got Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- 5: fail-closed boot -- a store whose load() errors makes ControlPlane::new fail

    #[test]
    fn fail_closed_boot_a_failing_store_makes_new_return_an_error() {
        let result = ControlPlane::new(
            Box::new(FailingStore),
            HmacSecret::new(b"operator-secret"),
            KeySet::new(),
        );
        assert!(
            result.is_err(),
            "a store whose load() fails at boot must make ControlPlane::new fail -- \
             starting and publishing an empty snapshot would silently 401 every request"
        );
    }

    // --- 6: fail-closed refresh -- rebuild() on a load() error keeps the previous snapshot

    #[test]
    fn fail_closed_refresh_keeps_the_previous_snapshot_on_a_load_error() {
        let secret_bytes = b"operator-secret";
        let fail_flag = Arc::new(AtomicBool::new(false));
        let inner = InMemoryControlPlaneStore::default();
        inner
            .put_key(&StoredKey {
                key_id: KeyId::new("k1"),
                digest: digest_bytes(secret_bytes, "llmp_still-good-key"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
            })
            .unwrap();
        let store = ToggleStore {
            inner,
            fail: Arc::clone(&fail_flag),
        };

        let cp = ControlPlane::new(
            Box::new(store),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("boot must succeed while the store is healthy");
        let authenticator =
            VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp.handle());
        let headers = headers_with_authorization("Bearer llmp_still-good-key");

        // Sanity: the key works before anything goes wrong.
        assert!(matches!(
            authenticator.authenticate(&headers),
            AuthOutcome::Authenticated(_)
        ));

        // Now the store starts failing, and a refresh is attempted.
        fail_flag.store(true, Ordering::SeqCst);
        cp.rebuild();

        // The previously published snapshot must still be in effect -- the
        // same key still authenticates. It must NOT have been replaced by an
        // empty snapshot.
        match authenticator.authenticate(&headers) {
            AuthOutcome::Authenticated(principal) => {
                assert_eq!(principal.tenant.as_str(), "tenant-a");
            }
            other => panic!(
                "a failed refresh must keep the last published snapshot, not wipe it; \
                 got Rejected={} NoCredential={}",
                matches!(other, AuthOutcome::Rejected(_)),
                matches!(other, AuthOutcome::NoCredential)
            ),
        }
    }
}
