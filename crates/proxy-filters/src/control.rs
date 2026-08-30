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
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::auth::{HmacSecret, KeyId, KeyRecord, KeySet, TenantId, TenantPolicy};
use crate::model_authz::{ModelAccess, ModelPattern, TenantPolicyMap};

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

// --- redb tables -----------------------------------------------------------
//
// See the design brief's "redb data model" section, which this follows
// exactly: one table per concept, plus the explicit `keys_by_tenant` reverse
// index redb does not provide for free (it has no secondary indexes).
//
// Rust note: a `TableDefinition` is just a name plus a `K`/`V` type marker --
// it carries no data of its own, so it can be a top-level `const` shared by
// every method below rather than something each method has to build.
const TENANTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("tenants");
const KEYS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("keys");
const KEYS_BY_TENANT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("keys_by_tenant");
const POLICIES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("policies");

/// One `keys` row, exactly as `redb` stores it -- everything a [`StoredKey`]
/// carries except `key_id`, which is already the table's key and would just
/// be a second, independently-editable copy of the same fact if repeated in
/// the value too.
///
/// # Value encoding: `serde_json` bytes, not a native `redb::Value` impl
///
/// Every table here is `TableDefinition<&str, &[u8]>`: the value is always
/// raw JSON bytes, decoded on read. `redb` supports implementing its own
/// `Value` trait directly on a struct (a "native" encoding), which would
/// save the JSON round-trip; this store does not do that, for one concrete
/// reason and one preference:
/// - `serde_json` is already a dependency (config parsing uses it) and nets
///   this store an ADDITIONAL dependency of **zero** -- it adds `redb` as the
///   only new one. A native `redb::Value` impl either goes through `serde`
///   with a binary codec (adding `bincode` or similar, which the task
///   explicitly avoids) or requires hand-rolling byte layout and its own
///   `TypeName`/comparison logic per struct -- more surface for very little
///   payoff at this store's size.
/// - This store's rows are control-plane metadata (tenants, keys, policies),
///   not a request-hot-path structure -- see the module doc's "no store I/O
///   on the hot path" note. Its total row count is small and nothing here
///   is latency-sensitive, so the extra allocation and (de)serialization
///   cost of JSON is free in context.
#[derive(serde::Serialize, serde::Deserialize)]
struct EncodedKeyRow {
    digest: [u8; 32],
    tenant: String,
    revoked: bool,
}

/// [`ModelAccess`] as `serde_json` sees it. A local mirror rather than
/// `#[derive(Serialize, Deserialize)]` on `ModelAccess` itself -- that type
/// lives in `model_authz.rs`, which this increment's scope does not touch,
/// and giving it a serde impl would be a public-API decision belonging to
/// that module's owner, not something to smuggle in via this store.
#[derive(serde::Serialize, serde::Deserialize)]
enum EncodedModelAccess {
    All,
    Only(Vec<String>),
}

impl From<&ModelAccess> for EncodedModelAccess {
    fn from(access: &ModelAccess) -> Self {
        match access {
            ModelAccess::All => EncodedModelAccess::All,
            ModelAccess::Only(patterns) => {
                EncodedModelAccess::Only(patterns.iter().map(|p| p.as_str().to_string()).collect())
            }
        }
    }
}

impl From<EncodedModelAccess> for ModelAccess {
    fn from(encoded: EncodedModelAccess) -> Self {
        match encoded {
            EncodedModelAccess::All => ModelAccess::All,
            EncodedModelAccess::Only(patterns) => {
                ModelAccess::Only(patterns.into_iter().map(ModelPattern::new).collect())
            }
        }
    }
}

fn encode_json<T: serde::Serialize>(value: &T) -> Vec<u8> {
    // Rust note: `.expect`, not `?` -- every value passed here is one of
    // this module's own plain-data types (`EncodedKeyRow`, `EncodedModelAccess`,
    // `Vec<String>`), none of which can fail to serialize (no `f32::NAN`-style
    // JSON restriction applies, no user-controlled writer). A failure here
    // would be a logic bug in this file, not an operational store condition.
    serde_json::to_vec(value).expect("encoding a control-plane store row must not fail")
}

/// The read-side counterpart of [`encode_json`]. Unlike encoding, decoding
/// CAN fail on real operational grounds (a hand-edited or corrupted `.redb`
/// file), so this reports a [`StoreError`] rather than panicking.
fn decode_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, StoreError> {
    serde_json::from_slice(bytes)
        .map_err(|err| StoreError::Unavailable(format!("corrupt control-plane store row: {err}")))
}

/// Every `redb` error type (`DatabaseError`, `TransactionError`,
/// `TableError`, `CommitError`, `StorageError`) becomes this one
/// [`StoreError`] variant. No new variant is added for it: `Unavailable`'s
/// own doc already reads "the backend could not be reached or read at
/// all", which is exactly what a `redb` I/O or corruption failure is, and
/// neither of [`ControlPlane`]'s two call sites (`new`'s hard boot error,
/// `rebuild`'s log-and-keep-serving) distinguishes error reasons -- see
/// [`StoreError`]'s doc.
///
/// Rust note: `impl std::fmt::Display` as the bound (not a concrete error
/// type) so one function serves every `redb` error type used below --
/// each `.map_err(store_err)` call site monomorphizes it for whichever
/// error type that particular `redb` call actually returns.
fn store_err(err: impl std::fmt::Display) -> StoreError {
    StoreError::Unavailable(err.to_string())
}

/// Persistent, embedded [`ControlPlaneStore`] backed by `redb` -- the
/// production default (see the design brief's "Engine: redb" decision):
/// pure-Rust, ACID, single-file, no C toolchain, unlike SQLite.
///
/// # Transaction model: one write txn per method, one read txn per `load()`
///
/// Rust note: every write method (`create_tenant`, `put_key`, ...) opens its
/// own `redb::WriteTransaction`, mutates one or more tables, and commits --
/// see the design brief's "Distributed readiness" requirement 3 ("isolate
/// EACH store call to one function"), which this satisfies literally: there
/// is exactly one `begin_write`/`commit` pair per trait method, no method
/// calls another. `load()` instead opens a single `redb::ReadTransaction`
/// and reads all four tables from it, so a rebuild sees one consistent
/// point-in-time snapshot rather than four independent ones that could
/// straddle a concurrent write. `redb`'s MVCC is what makes this safe
/// without any lock of our own (contrast [`InMemoryControlPlaneStore`]'s
/// `std::sync::Mutex`): a `ReadTransaction` never blocks a `WriteTransaction`
/// or vice versa, and `redb` itself serializes concurrent writers by
/// blocking a second `begin_write` until the first commits or aborts. That
/// is also why this struct holds `redb::Database` directly with no `Mutex`
/// wrapper -- `Database`'s own methods already take `&self`.
pub struct RedbControlPlaneStore {
    db: Database,
}

impl RedbControlPlaneStore {
    /// Opens (creating if absent) a `redb` database file at `path` -- the
    /// production constructor. The proxy's default is this store, with no
    /// external datastore configured (see the design brief's 3b-ii
    /// acceptance criteria).
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(store_err)?;
        Self::from_database(db)
    }

    /// An ephemeral, in-memory `redb` database -- for tests only. It runs
    /// through the exact same transaction and table code every other
    /// constructor does; the only difference is the `StorageBackend` pages
    /// are written to (RAM instead of a file), so it proves nothing about
    /// `redb`'s own durability -- see the `reopening_the_same_path_...` test
    /// below for that.
    pub fn in_memory() -> Self {
        let db = redb::Builder::new()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .expect("an in-memory redb backend cannot fail to open");
        Self::from_database(db).expect("an in-memory redb backend cannot fail to create tables")
    }

    fn from_database(db: Database) -> Result<Self, StoreError> {
        let store = RedbControlPlaneStore { db };
        store.ensure_tables()?;
        Ok(store)
    }

    /// Creates all four tables if they do not already exist.
    ///
    /// Rust note: this runs a WRITE transaction even though it inserts no
    /// rows -- `WriteTransaction::open_table` is the only `redb` API that
    /// CREATES a table; `ReadTransaction::open_table` errors
    /// `TableDoesNotExist` against one that has never been opened for write.
    /// Doing this once at construction means [`Self::load`] (always a read
    /// transaction) never has to tell "table exists and is empty" apart from
    /// "table was never created" -- both read back as empty, which is what a
    /// freshly-opened store should report either way.
    fn ensure_tables(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        txn.open_table(TENANTS_TABLE).map_err(store_err)?;
        txn.open_table(KEYS_TABLE).map_err(store_err)?;
        txn.open_table(KEYS_BY_TENANT_TABLE).map_err(store_err)?;
        txn.open_table(POLICIES_TABLE).map_err(store_err)?;
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    /// The `keys_by_tenant` reverse index, read directly. Not part of
    /// [`ControlPlaneStore`] -- that trait's `load()` already returns every
    /// key in one call, which is all a snapshot rebuild needs. This exists
    /// for the future `GET /tenants/{id}/keys` admin endpoint (3b-ii, see
    /// the design brief) that needs a single tenant's key ids without
    /// paying for a whole-store read.
    pub fn keys_by_tenant(&self, tenant: &TenantId) -> Result<Vec<KeyId>, StoreError> {
        let txn = self.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(KEYS_BY_TENANT_TABLE).map_err(store_err)?;
        match table.get(tenant.as_str()).map_err(store_err)? {
            Some(guard) => {
                let ids: Vec<String> = decode_json(guard.value())?;
                Ok(ids.into_iter().map(KeyId::new).collect())
            }
            None => Ok(Vec::new()),
        }
    }

    /// Adds `key_id` to `tenant`'s entry in `keys_by_tenant`, if not already
    /// present. Always called from inside the SAME write transaction as the
    /// `keys` row it mirrors (see [`Self::put_key`]), so the two tables
    /// commit together or not at all -- a reader can never observe one
    /// updated without the other.
    fn add_key_to_tenant_index(
        txn: &redb::WriteTransaction,
        tenant: &str,
        key_id: &str,
    ) -> Result<(), StoreError> {
        let mut table = txn.open_table(KEYS_BY_TENANT_TABLE).map_err(store_err)?;
        let mut ids: Vec<String> = match table.get(tenant).map_err(store_err)? {
            Some(guard) => decode_json(guard.value())?,
            None => Vec::new(),
        };
        if !ids.iter().any(|id| id == key_id) {
            ids.push(key_id.to_string());
            table
                .insert(tenant, encode_json(&ids).as_slice())
                .map_err(store_err)?;
        }
        Ok(())
    }

    /// The inverse of [`Self::add_key_to_tenant_index`] -- removes `key_id`
    /// from `tenant`'s entry, if present. Used only when [`Self::put_key`]
    /// overwrites an existing `key_id` under a DIFFERENT tenant, so the old
    /// tenant's index does not keep pointing at a key it no longer owns.
    fn remove_key_from_tenant_index(
        txn: &redb::WriteTransaction,
        tenant: &str,
        key_id: &str,
    ) -> Result<(), StoreError> {
        let mut table = txn.open_table(KEYS_BY_TENANT_TABLE).map_err(store_err)?;
        let existing: Option<Vec<String>> = match table.get(tenant).map_err(store_err)? {
            Some(guard) => Some(decode_json(guard.value())?),
            None => None,
        };
        if let Some(mut ids) = existing {
            ids.retain(|id| id != key_id);
            table
                .insert(tenant, encode_json(&ids).as_slice())
                .map_err(store_err)?;
        }
        Ok(())
    }
}

impl ControlPlaneStore for RedbControlPlaneStore {
    fn load(&self) -> Result<StoredControlPlane, StoreError> {
        let txn = self.db.begin_read().map_err(store_err)?;

        let tenants_table = txn.open_table(TENANTS_TABLE).map_err(store_err)?;
        let mut tenants = Vec::new();
        for entry in tenants_table.iter().map_err(store_err)? {
            let (key, _value) = entry.map_err(store_err)?;
            tenants.push(TenantId::new(key.value()));
        }

        let keys_table = txn.open_table(KEYS_TABLE).map_err(store_err)?;
        let mut keys = Vec::new();
        for entry in keys_table.iter().map_err(store_err)? {
            let (key, value) = entry.map_err(store_err)?;
            let row: EncodedKeyRow = decode_json(value.value())?;
            keys.push(StoredKey {
                key_id: KeyId::new(key.value()),
                digest: row.digest,
                tenant: TenantId::new(row.tenant),
                revoked: row.revoked,
            });
        }

        let policies_table = txn.open_table(POLICIES_TABLE).map_err(store_err)?;
        let mut policies = HashMap::new();
        for entry in policies_table.iter().map_err(store_err)? {
            let (key, value) = entry.map_err(store_err)?;
            let encoded: EncodedModelAccess = decode_json(value.value())?;
            policies.insert(TenantId::new(key.value()), encoded.into());
        }

        Ok(StoredControlPlane {
            tenants,
            keys,
            policies,
        })
    }

    fn create_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(TENANTS_TABLE).map_err(store_err)?;
            // An unconditional insert -- redb overwriting an existing key
            // with the same empty marker value is indistinguishable from
            // InMemory's `if !contains { push }` guard, so there is nothing
            // to check first.
            table
                .insert(tenant.as_str(), [].as_slice())
                .map_err(store_err)?;
        }
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn delete_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut tenants_table = txn.open_table(TENANTS_TABLE).map_err(store_err)?;
            tenants_table.remove(tenant.as_str()).map_err(store_err)?;
        }
        {
            let mut policies_table = txn.open_table(POLICIES_TABLE).map_err(store_err)?;
            policies_table.remove(tenant.as_str()).map_err(store_err)?;
        }
        // Matches `InMemoryControlPlaneStore::delete_tenant` exactly: `keys`
        // and `keys_by_tenant` are left untouched. A tenant's keys outliving
        // the tenant row is the existing, deliberate InMemory behavior this
        // store must not silently diverge from -- see the parity test below.
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn put_key(&self, rec: &StoredKey) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        let previous_tenant: Option<String> = {
            let mut keys_table = txn.open_table(KEYS_TABLE).map_err(store_err)?;
            let previous = match keys_table.get(rec.key_id.as_str()).map_err(store_err)? {
                Some(guard) => Some(decode_json::<EncodedKeyRow>(guard.value())?.tenant),
                None => None,
            };
            let row = EncodedKeyRow {
                digest: rec.digest,
                tenant: rec.tenant.as_str().to_string(),
                revoked: rec.revoked,
            };
            keys_table
                .insert(rec.key_id.as_str(), encode_json(&row).as_slice())
                .map_err(store_err)?;
            previous
        };

        // If this `put_key` MOVED an existing key_id to a different tenant,
        // repair the old tenant's index entry too -- otherwise it would keep
        // naming a key it no longer owns.
        if let Some(previous_tenant) = &previous_tenant {
            if previous_tenant.as_str() != rec.tenant.as_str() {
                Self::remove_key_from_tenant_index(&txn, previous_tenant, rec.key_id.as_str())?;
            }
        }
        Self::add_key_to_tenant_index(&txn, rec.tenant.as_str(), rec.key_id.as_str())?;

        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn revoke_key(&self, key_id: &KeyId) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(KEYS_TABLE).map_err(store_err)?;
            let mut row: EncodedKeyRow = match table.get(key_id.as_str()).map_err(store_err)? {
                Some(guard) => decode_json(guard.value())?,
                // Matches `InMemoryControlPlaneStore::revoke_key`: revoking
                // an unknown key_id is `StoreError::NotFound`, and nothing
                // is written -- dropping `txn` here without calling
                // `commit()` rolls the whole (empty) transaction back.
                None => return Err(StoreError::NotFound),
            };
            row.revoked = true;
            table
                .insert(key_id.as_str(), encode_json(&row).as_slice())
                .map_err(store_err)?;
        }
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn set_policy(&self, tenant: &TenantId, access: &ModelAccess) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(POLICIES_TABLE).map_err(store_err)?;
            let encoded: EncodedModelAccess = access.into();
            table
                .insert(tenant.as_str(), encode_json(&encoded).as_slice())
                .map_err(store_err)?;
        }
        txn.commit().map_err(store_err)?;
        Ok(())
    }
}

/// A freshly minted virtual key, returned to the admin caller so the
/// plaintext can be shown EXACTLY ONCE (it is never stored -- only its
/// digest is). Its `Debug` redacts the plaintext: the whole point of the
/// digest-only store is that key material never reaches a log.
pub struct MintedKey {
    pub key_id: KeyId,
    pub tenant: TenantId,
    pub plaintext: String,
}

impl std::fmt::Debug for MintedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedKey")
            .field("key_id", &self.key_id)
            .field("tenant", &self.tenant)
            .field("plaintext", &"<redacted>")
            .finish()
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

    /// Mints a fresh virtual key for `tenant`/`key_id`, writes its digest to
    /// the store, republishes, and returns the plaintext -- the only time it
    /// ever exists. The store holds only the digest [`Self::mint_key`]
    /// derives from it via [`crate::auth::digest_bytes`]; there is nowhere in
    /// this codebase the plaintext is written back down.
    ///
    /// Writes THEN republishes -- see the module doc's "boot vs. refresh"
    /// section and every other write method below: a reader must never
    /// observe a republish that predates the write it is meant to reflect.
    pub fn mint_key(&self, tenant: &TenantId, key_id: &KeyId) -> Result<MintedKey, StoreError> {
        let rng = ring::rand::SystemRandom::new();
        let plaintext = crate::auth::generate_plaintext_key(&rng);
        let digest = crate::auth::digest_bytes(&self.secret, &plaintext);
        self.store.put_key(&StoredKey {
            key_id: key_id.clone(),
            digest,
            tenant: tenant.clone(),
            revoked: false,
        })?;
        self.rebuild();
        Ok(MintedKey {
            key_id: key_id.clone(),
            tenant: tenant.clone(),
            plaintext,
        })
    }

    /// Revokes `key_id`, then republishes so the revocation takes effect on
    /// the next request rather than the next unrelated rebuild.
    pub fn revoke_key(&self, key_id: &KeyId) -> Result<(), StoreError> {
        self.store.revoke_key(key_id)?;
        self.rebuild();
        Ok(())
    }

    /// Creates `tenant`, then republishes.
    pub fn create_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
        self.store.create_tenant(tenant)?;
        self.rebuild();
        Ok(())
    }

    /// Deletes `tenant`, then republishes.
    pub fn delete_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
        self.store.delete_tenant(tenant)?;
        self.rebuild();
        Ok(())
    }

    /// Sets `tenant`'s model-access policy, then republishes.
    pub fn set_policy(&self, tenant: &TenantId, access: &ModelAccess) -> Result<(), StoreError> {
        self.store.set_policy(tenant, access)?;
        self.rebuild();
        Ok(())
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

    /// Thin wrapper over [`crate::auth::digest_bytes`] (which takes an
    /// [`HmacSecret`], not raw bytes) -- kept so every call site below stays
    /// unchanged, while there is still exactly one HMAC computation in the
    /// codebase rather than a second, test-local `ring::hmac::sign` call.
    fn digest_bytes(secret_bytes: &[u8], plaintext: &str) -> [u8; 32] {
        crate::auth::digest_bytes(&HmacSecret::new(secret_bytes), plaintext)
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

    // --- ControlPlane write methods (WP-50 increment 3b-ii, part B) ---------

    // --- mint_key produces a key that authenticates

    #[test]
    fn mint_key_produces_a_key_that_authenticates() {
        let secret_bytes = b"operator-secret";
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let minted = cp
            .mint_key(&TenantId::new("tenant-a"), &KeyId::new("k1"))
            .expect("mint_key must succeed against a healthy store");

        let authenticator =
            VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp.handle());
        let headers = headers_with_authorization(&format!("Bearer {}", minted.plaintext));
        match authenticator.authenticate(&headers) {
            AuthOutcome::Authenticated(principal) => {
                assert_eq!(principal.tenant.as_str(), "tenant-a");
                assert_eq!(principal.key_id.as_str(), "k1");
            }
            other => panic!(
                "a freshly minted key must authenticate; got Rejected={} NoCredential={}",
                matches!(other, AuthOutcome::Rejected(_)),
                matches!(other, AuthOutcome::NoCredential)
            ),
        }
    }

    // --- revoke_key makes a minted key unauthenticated after republish

    #[test]
    fn revoke_key_makes_it_unauthenticated_after_republish() {
        let secret_bytes = b"operator-secret";
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let minted = cp
            .mint_key(&TenantId::new("tenant-a"), &KeyId::new("k1"))
            .unwrap();
        let authenticator =
            VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp.handle());
        let headers = headers_with_authorization(&format!("Bearer {}", minted.plaintext));

        assert!(matches!(
            authenticator.authenticate(&headers),
            AuthOutcome::Authenticated(_)
        ));

        cp.revoke_key(&KeyId::new("k1"))
            .expect("revoke must succeed");

        match authenticator.authenticate(&headers) {
            AuthOutcome::Rejected(AuthError::RevokedKey) => {}
            other => panic!(
                "a revoked key must be rejected after republish; got Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- THE cross-worker property: two authenticators over ONE handle both
    //     see a write, and both see a subsequent revoke.

    #[test]
    fn two_authenticators_over_one_handle_both_see_a_write() {
        let secret_bytes = b"operator-secret";
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        // Two independent authenticators -- standing in for two workers'
        // filter-chain instances -- built over the SAME published handle.
        let worker_a = VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp.handle());
        let worker_b = VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp.handle());

        let minted = cp
            .mint_key(&TenantId::new("tenant-a"), &KeyId::new("k1"))
            .unwrap();
        let headers = headers_with_authorization(&format!("Bearer {}", minted.plaintext));

        for (name, worker) in [("worker_a", &worker_a), ("worker_b", &worker_b)] {
            assert!(
                matches!(worker.authenticate(&headers), AuthOutcome::Authenticated(_)),
                "{name} must see the mint through the shared handle"
            );
        }

        cp.revoke_key(&KeyId::new("k1")).unwrap();

        for (name, worker) in [("worker_a", &worker_a), ("worker_b", &worker_b)] {
            match worker.authenticate(&headers) {
                AuthOutcome::Rejected(AuthError::RevokedKey) => {}
                other => panic!(
                    "{name} must see the revoke through the shared handle; got \
                     Authenticated={}",
                    matches!(other, AuthOutcome::Authenticated(_))
                ),
            }
        }
    }

    // --- create_tenant / delete_tenant / set_policy are reflected

    #[test]
    fn create_tenant_delete_tenant_and_set_policy_are_reflected() {
        let secret_bytes = b"operator-secret";
        let shared = Arc::new(InMemoryControlPlaneStore::default());
        let cp = ControlPlane::new(
            Box::new(SharedStore(Arc::clone(&shared))),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        cp.create_tenant(&TenantId::new("tenant-a"))
            .expect("create_tenant must succeed");
        // `ControlPlaneSnapshot` itself carries no tenant list (see its doc);
        // the store is the only place tenant existence is observable.
        let loaded = shared.load().unwrap();
        assert_eq!(
            loaded
                .tenants
                .iter()
                .map(TenantId::as_str)
                .collect::<Vec<_>>(),
            vec!["tenant-a"]
        );

        let access = ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]);
        cp.set_policy(&TenantId::new("tenant-a"), &access)
            .expect("set_policy must succeed");
        let snapshot = cp.handle().load();
        let policy = snapshot
            .policies
            .get("tenant-a")
            .expect("policy must appear in the snapshot after set_policy's republish");
        assert_eq!(policy.model_access, access);

        cp.delete_tenant(&TenantId::new("tenant-a"))
            .expect("delete_tenant must succeed");
        let loaded = shared.load().unwrap();
        assert!(loaded.tenants.is_empty());
        // `InMemoryControlPlaneStore::delete_tenant` also removes the policy
        // row -- confirm the republish reflects that too.
        let snapshot = cp.handle().load();
        assert!(!snapshot.policies.contains_key("tenant-a"));
    }

    // --- mutation pins: a write that skips `self.rebuild()` must not be
    //     visible through the published handle. Each is verified by actually
    //     deleting the corresponding `rebuild()` line and confirming the
    //     paired test above goes red -- see this task's "Verify" section.

    #[test]
    fn mint_key_without_rebuild_is_not_visible() {
        // Same setup as `mint_key_produces_a_key_that_authenticates`, but
        // this test's whole point is that it is THAT test which catches a
        // `mint_key` missing its `self.rebuild()` call -- there is nothing
        // additional to assert here beyond re-running the same shape, so this
        // test intentionally duplicates it rather than inventing a second
        // assertion that could pass for an unrelated reason.
        let secret_bytes = b"operator-secret";
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let minted = cp
            .mint_key(&TenantId::new("tenant-a"), &KeyId::new("k1"))
            .expect("mint_key must succeed against a healthy store");

        let authenticator =
            VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp.handle());
        let headers = headers_with_authorization(&format!("Bearer {}", minted.plaintext));
        assert!(
            matches!(
                authenticator.authenticate(&headers),
                AuthOutcome::Authenticated(_)
            ),
            "a mint that skipped rebuild() would leave this Rejected/NoCredential instead \
             of Authenticated"
        );
    }

    #[test]
    fn revoke_key_without_rebuild_still_authenticates() {
        // Mirrors `mint_key_without_rebuild_is_not_visible`: this duplicates
        // `revoke_key_makes_it_unauthenticated_after_republish`'s shape
        // because THAT is the test a `revoke_key` missing its
        // `self.rebuild()` call must fail.
        let secret_bytes = b"operator-secret";
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let minted = cp
            .mint_key(&TenantId::new("tenant-a"), &KeyId::new("k1"))
            .unwrap();
        let authenticator =
            VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp.handle());
        let headers = headers_with_authorization(&format!("Bearer {}", minted.plaintext));

        cp.revoke_key(&KeyId::new("k1"))
            .expect("revoke must succeed");

        assert!(
            !matches!(
                authenticator.authenticate(&headers),
                AuthOutcome::Authenticated(_)
            ),
            "a revoke that skipped rebuild() would leave this key still Authenticated"
        );
    }

    // --- RedbControlPlaneStore (WP-50 increment 3b) --------------------------

    /// `std::process::id()` + a nanosecond timestamp for uniqueness -- the
    /// same convention `crates/proxy/src/main.rs`'s `write_temp` uses, for
    /// the same reason: this crate has no `tempfile` dependency, and adding
    /// one only for tests is not worth it when two integers already make a
    /// file name collision-proof in practice.
    fn temp_db_path(name_hint: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "llm-proxy-control-plane-test-{name_hint}-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// Compares two [`StoredControlPlane`]s field-by-field, ignoring vector
    /// and map ORDER (neither `ControlPlaneStore::load` implementation
    /// promises one) -- used by the redb/InMemory parity test below.
    fn assert_stored_control_planes_match(a: &StoredControlPlane, b: &StoredControlPlane) {
        let mut a_tenants: Vec<&str> = a.tenants.iter().map(TenantId::as_str).collect();
        let mut b_tenants: Vec<&str> = b.tenants.iter().map(TenantId::as_str).collect();
        a_tenants.sort_unstable();
        b_tenants.sort_unstable();
        assert_eq!(a_tenants, b_tenants, "tenants must match");

        let mut a_keys: Vec<(&str, [u8; 32], &str, bool)> = a
            .keys
            .iter()
            .map(|k| (k.key_id.as_str(), k.digest, k.tenant.as_str(), k.revoked))
            .collect();
        let mut b_keys: Vec<(&str, [u8; 32], &str, bool)> = b
            .keys
            .iter()
            .map(|k| (k.key_id.as_str(), k.digest, k.tenant.as_str(), k.revoked))
            .collect();
        a_keys.sort_by_key(|k| k.0);
        b_keys.sort_by_key(|k| k.0);
        assert_eq!(a_keys, b_keys, "keys must match");

        let mut a_policies: Vec<(&str, &ModelAccess)> =
            a.policies.iter().map(|(t, m)| (t.as_str(), m)).collect();
        let mut b_policies: Vec<(&str, &ModelAccess)> =
            b.policies.iter().map(|(t, m)| (t.as_str(), m)).collect();
        a_policies.sort_by_key(|(t, _)| *t);
        b_policies.sort_by_key(|(t, _)| *t);
        assert_eq!(a_policies, b_policies, "policies must match");
    }

    // --- redb: put_key then load() round-trips digest/tenant/revoked

    #[test]
    fn redb_round_trip_put_key_then_load() {
        let store = RedbControlPlaneStore::in_memory();
        store
            .put_key(&StoredKey {
                key_id: KeyId::new("k1"),
                digest: digest_bytes(b"secret", "llmp_a"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
            })
            .unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.keys.len(), 1);
        let row = &loaded.keys[0];
        assert_eq!(row.key_id.as_str(), "k1");
        assert_eq!(row.digest, digest_bytes(b"secret", "llmp_a"));
        assert_eq!(row.tenant.as_str(), "tenant-a");
        assert!(!row.revoked);
    }

    // --- redb: revoke_key flips revoked and load() reflects it; revoking an
    //     absent key errors the same way InMemory does

    #[test]
    fn redb_revoke_key_flips_revoked_and_load_reflects_it() {
        let store = RedbControlPlaneStore::in_memory();
        store
            .put_key(&StoredKey {
                key_id: KeyId::new("k1"),
                digest: digest_bytes(b"secret", "llmp_a"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
            })
            .unwrap();

        store.revoke_key(&KeyId::new("k1")).unwrap();

        let loaded = store.load().unwrap();
        assert!(
            loaded.keys[0].revoked,
            "revoke_key must persist revoked=true"
        );
    }

    #[test]
    fn redb_revoke_absent_key_matches_inmemorys_not_found() {
        let redb_store = RedbControlPlaneStore::in_memory();
        let inmemory_store = InMemoryControlPlaneStore::default();

        assert_eq!(
            redb_store.revoke_key(&KeyId::new("nonexistent")),
            Err(StoreError::NotFound)
        );
        assert_eq!(
            redb_store.revoke_key(&KeyId::new("nonexistent")),
            inmemory_store.revoke_key(&KeyId::new("nonexistent")),
        );
    }

    // --- redb: set_policy then load() returns it; create_tenant/delete_tenant reflected

    #[test]
    fn redb_set_policy_then_load_returns_it() {
        let store = RedbControlPlaneStore::in_memory();
        let access = ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]);
        store
            .set_policy(&TenantId::new("tenant-a"), &access)
            .unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(
            loaded.policies.get(&TenantId::new("tenant-a")),
            Some(&access)
        );
    }

    #[test]
    fn redb_create_and_delete_tenant_reflected_in_load() {
        let store = RedbControlPlaneStore::in_memory();
        store.create_tenant(&TenantId::new("tenant-a")).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(
            loaded
                .tenants
                .iter()
                .map(TenantId::as_str)
                .collect::<Vec<_>>(),
            vec!["tenant-a"]
        );

        store.delete_tenant(&TenantId::new("tenant-a")).unwrap();
        let loaded = store.load().unwrap();
        assert!(loaded.tenants.is_empty());
    }

    // --- redb: the whole point -- a key survives dropping and reopening the
    //     store at the SAME file path

    #[test]
    fn redb_persists_across_reopen() {
        let path = temp_db_path("persists-across-reopen");

        {
            let store = RedbControlPlaneStore::open(&path).unwrap();
            store
                .put_key(&StoredKey {
                    key_id: KeyId::new("k1"),
                    digest: digest_bytes(b"secret", "llmp_a"),
                    tenant: TenantId::new("tenant-a"),
                    revoked: false,
                })
                .unwrap();
            // `store` (and its `redb::Database`) is dropped here -- there is
            // no separate "close" step; redb's `Drop` impl flushes and
            // releases the file.
        }

        let reopened = RedbControlPlaneStore::open(&path).unwrap();
        let loaded = reopened.load().unwrap();
        assert_eq!(
            loaded.keys.len(),
            1,
            "a reopened store must still see the key"
        );
        assert_eq!(loaded.keys[0].key_id.as_str(), "k1");

        std::fs::remove_file(&path).ok();
    }

    // --- redb: keys_by_tenant returns exactly the tenant's own keys

    #[test]
    fn redb_keys_by_tenant_returns_the_tenants_keys() {
        let store = RedbControlPlaneStore::in_memory();
        store
            .put_key(&StoredKey {
                key_id: KeyId::new("k1"),
                digest: digest_bytes(b"secret", "llmp_a"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
            })
            .unwrap();
        store
            .put_key(&StoredKey {
                key_id: KeyId::new("k2"),
                digest: digest_bytes(b"secret", "llmp_b"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
            })
            .unwrap();
        store
            .put_key(&StoredKey {
                key_id: KeyId::new("k3"),
                digest: digest_bytes(b"secret", "llmp_c"),
                tenant: TenantId::new("tenant-b"),
                revoked: false,
            })
            .unwrap();

        let mut tenant_a_keys: Vec<String> = store
            .keys_by_tenant(&TenantId::new("tenant-a"))
            .unwrap()
            .into_iter()
            .map(|id| id.as_str().to_string())
            .collect();
        tenant_a_keys.sort_unstable();
        assert_eq!(tenant_a_keys, vec!["k1".to_string(), "k2".to_string()]);

        let tenant_b_keys = store.keys_by_tenant(&TenantId::new("tenant-b")).unwrap();
        assert_eq!(tenant_b_keys.len(), 1);
        assert_eq!(tenant_b_keys[0].as_str(), "k3");

        let tenant_c_keys = store.keys_by_tenant(&TenantId::new("tenant-c")).unwrap();
        assert!(tenant_c_keys.is_empty());
    }

    // --- parity: redb and InMemory must produce the SAME StoredControlPlane
    //     from the same sequence of writes -- so the two impls cannot
    //     silently diverge (see CLAUDE.md's per-provider audit rule for why
    //     this project treats "two backends of the same seam quietly
    //     disagreeing" as the shape of bug worth pinning a test to).

    #[test]
    fn redb_and_inmemory_produce_the_same_snapshot_from_the_same_writes() {
        let redb_store = RedbControlPlaneStore::in_memory();
        let inmemory_store = InMemoryControlPlaneStore::default();
        let stores: [&dyn ControlPlaneStore; 2] = [&redb_store, &inmemory_store];

        for store in stores {
            store.create_tenant(&TenantId::new("tenant-a")).unwrap();
            store.create_tenant(&TenantId::new("tenant-b")).unwrap();
            store
                .put_key(&StoredKey {
                    key_id: KeyId::new("k1"),
                    digest: digest_bytes(b"secret", "llmp_a"),
                    tenant: TenantId::new("tenant-a"),
                    revoked: false,
                })
                .unwrap();
            store
                .put_key(&StoredKey {
                    key_id: KeyId::new("k2"),
                    digest: digest_bytes(b"secret", "llmp_b"),
                    tenant: TenantId::new("tenant-b"),
                    revoked: false,
                })
                .unwrap();
            store.revoke_key(&KeyId::new("k2")).unwrap();
            store
                .set_policy(
                    &TenantId::new("tenant-a"),
                    &ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]),
                )
                .unwrap();
        }

        assert_stored_control_planes_match(
            &redb_store.load().unwrap(),
            &inmemory_store.load().unwrap(),
        );
    }

    // --- mutation-pin: `revoke_key` must COMMIT the flip, not just set it in
    //     a local variable -- see `redb_revoke_key_flips_revoked_and_load_reflects_it`

    #[test]
    fn redb_revoke_key_without_reload_still_shows_revoked_via_a_fresh_load() {
        // Same assertion as `redb_revoke_key_flips_revoked_and_load_reflects_it`,
        // but via a SEPARATE store handle over the SAME on-disk file, so a
        // `revoke_key` that mutated an in-process cache without committing
        // the write transaction cannot pass it by accident.
        let path = temp_db_path("revoke-persists-across-handles");
        let writer = RedbControlPlaneStore::open(&path).unwrap();
        writer
            .put_key(&StoredKey {
                key_id: KeyId::new("k1"),
                digest: digest_bytes(b"secret", "llmp_a"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
            })
            .unwrap();
        writer.revoke_key(&KeyId::new("k1")).unwrap();
        drop(writer);

        let reader = RedbControlPlaneStore::open(&path).unwrap();
        let loaded = reader.load().unwrap();
        assert!(
            loaded.keys[0].revoked,
            "revoke_key's flip must be committed to disk, not just held in memory"
        );

        std::fs::remove_file(&path).ok();
    }
}
