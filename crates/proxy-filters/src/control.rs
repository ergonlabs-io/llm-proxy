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
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use rand::Rng;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::auth::{HmacSecret, KeyId, KeyRecord, KeySet, TenantId, TenantPolicy};
use crate::model_authz::{ModelAccess, ModelPattern, TenantPolicyMap};
// WP-50 increment 3c-ii-b: spend rows are keyed by a `PeriodKey`, which
// `spend.rs` owns (it also owns the calendar-alignment logic that produces
// one) -- `control.rs` only stores and retrieves values already computed
// there. See `spend.rs`'s module doc for why the boundary is drawn there.
use crate::spend::{PeriodKey, TenantBudget};

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
    // WP-50 increment 3c-iii-a: a tenant's budget, keyed independently of
    // `policies` above -- a tenant can have a stored `ModelAccess`, a stored
    // `TenantBudget`, both, or neither, and [`ControlPlane::merge`] combines
    // them by tenant rather than assuming one row implies the other. See
    // that function's doc for why this is deliberate, not an oversight.
    pub budgets: HashMap<TenantId, TenantBudget>,
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

    /// A monotonic counter bumped by every TIER-2 write -- tenants, keys,
    /// policies, budgets -- and NEVER by a spend write (WP-61, ADR-0006 §3).
    /// [`ControlPlane`]'s poller reads only this value on every tick and does
    /// the full [`Self::load`] + republish ONLY when it has moved, which is
    /// what lets N replicas notice a revocation without every replica
    /// re-reading the whole store every tick.
    ///
    /// # Why spend must never bump this
    ///
    /// Spend rows are written every flush interval by the data plane --
    /// [`crate::spend::SpendAccumulator`]'s flusher thread, on a cadence
    /// measured in seconds, from every replica, continuously. Bumping this
    /// counter on a spend write would make every poller see the stamp move
    /// every flush interval and trigger a full policy rebuild on every
    /// replica every flush interval, for a write this counter has nothing to
    /// say about (tier 2 identity/policy, not tier 3 accrued counters -- see
    /// ADR-0006 §1's tier table). [`Self::set_spend`] does not call this.
    ///
    /// # A never-written store reads `0`
    ///
    /// Same "absence is the zero value" convention this store already uses
    /// elsewhere (see [`Self::load_spend`]'s doc) -- a fresh store or a store
    /// double that never bumps reads back `0`, not an error.
    ///
    /// # Bump unconditionally -- do not try to detect a no-op write
    ///
    /// Every write listed above bumps the counter even if, say, `set_policy`
    /// was called with the exact `ModelAccess` already stored. Detecting "did
    /// this write actually change anything" would need a read-before-write
    /// comparison this trait's write methods do not otherwise need, purely to
    /// save one poller's one redundant rebuild -- and a bug in that
    /// comparison fails in the dangerous direction: a spurious bump costs one
    /// wasted rebuild, but a MISSED bump is a revocation that never
    /// propagates, silently, forever (the poller only rebuilds when the stamp
    /// moves -- see [`ControlPlane::poll_once`]). Unconditional-bump is the
    /// only implementation that cannot have that bug.
    ///
    /// `revoke_key` on an unknown `key_id` returns [`StoreError::NotFound`]
    /// and must NOT bump -- nothing was written, so there is nothing for a
    /// poller to notice.
    fn policy_generation(&self) -> Result<u64, StoreError>;

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

    /// Sets or clears `tenant`'s spend budget (WP-50 increment 3c-iii-a).
    /// `Some(budget)` replaces whatever was stored; `None` clears it,
    /// reverting the tenant to unlimited -- see [`TenantBudget`]'s doc for
    /// why an absent budget must never be confused with a configured
    /// `max_micros` of `0`. Stored independently of [`Self::set_policy`]'s
    /// `ModelAccess` row: setting one must never touch the other.
    fn set_budget(
        &self,
        tenant: &TenantId,
        budget: Option<&TenantBudget>,
    ) -> Result<(), StoreError>;

    // WP-50 increment 3c-ii-b: spend rows, keyed `(stat_prefix, tenant,
    // period)`. `stat_prefix` is a plain `&str` (not this crate's
    // `TenantId`/`KeyId` newtypes) because it names a FILTER CHAIN, per the
    // "external name" split in `internal-docs/wp-50-3c-spend-budgets.md`'s
    // "RESOLVED -- addressing follows Envoy" section -- the same
    // operator-chosen `stat_prefix` A1 already uses to address a chain from
    // the admin server.
    /// Sets the ABSOLUTE spend total for `(stat_prefix, tenant, period)`,
    /// overwriting whatever was stored. Deliberately NOT additive.
    ///
    /// An absolute write is idempotent: a caller that retries after an
    /// AMBIGUOUS failure (a timeout or a dropped connection, where the
    /// first attempt's outcome is unknown) simply re-sends the same total
    /// it already computed, and the retry is a no-op rather than a second
    /// charge. An additive write is not idempotent -- a retried delta
    /// double-counts -- and for a spend CEILING a double-count denies a
    /// tenant service they already paid for, which is the wrong direction
    /// to fail in for a control whose entire job is "did they pay enough".
    /// [`crate::spend::SpendAccumulator`] is the only production caller,
    /// and it always sends the FULL current total for the bucket it is
    /// flushing, never a delta -- see that module's doc.
    ///
    /// # SINGLE-WRITER ONLY. Read this before implementing a remote store.
    ///
    /// "Absolute" is correct for ONE writer and actively wrong for two. Two
    /// processes flushing the same `(stat_prefix, tenant, period)` are
    /// last-writer-wins: process A flushes 300, process B flushes 200, the
    /// row is 200, and A's 300 is silently GONE. Sharing a store between
    /// replicas would therefore LOSE spend rather than double-count it --
    /// quieter, and worse, than the per-process ceiling it looks like it
    /// would fix.
    ///
    /// Today that is unreachable rather than guarded: [`RedbControlPlaneStore`]
    /// takes an exclusive file lock, so a second process fails loudly at
    /// open. The trap opens the moment someone implements a REMOTE
    /// `ControlPlaneStore` (Redis, Postgres) behind this trait -- which is
    /// exactly what the trait was shaped to allow (see the 3b brief's
    /// distributed-readiness section). Such an implementation MUST NOT reuse
    /// these absolute-write semantics for spend: it needs an additive or
    /// compare-and-swap primitive plus a way for enforcement to see other
    /// writers' totals, because
    /// [`crate::spend::SpendAccumulator::current_total`] reads THIS process's
    /// memory and nothing else.
    ///
    /// The ceiling is consequently enforced PER PROCESS: N replicas enforce
    /// N independent budgets. That is the same shape as the per-worker budget
    /// bug fixed in `0dc91d1`, one level up, and it is documented rather than
    /// solved -- see `internal-docs/wp-50-3c-spend-budgets.md`.
    fn set_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        total_micros: u64,
    ) -> Result<(), StoreError>;

    /// Reads the spend total for `(stat_prefix, tenant, period)`. A row
    /// that has never been written -- a period nothing has charged yet, or
    /// a fresh store -- reads as `0`, not an error, the same "absence is
    /// the zero value" convention the rest of this store already uses.
    fn load_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
    ) -> Result<u64, StoreError>;
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
    // WP-50 increment 3c-iii-a: independent of `policies` above -- see
    // `StoredControlPlane::budgets`'s doc.
    budgets: HashMap<TenantId, TenantBudget>,
    // WP-50 increment 3c-ii-b: keyed on the full `(stat_prefix, tenant,
    // period)` triple as one tuple key -- there is no `load()`-style
    // wholesale read for spend (each row is read/written independently by
    // its own key), so this needs no separate reverse index the way
    // `keys_by_tenant` does for `keys`.
    spend: HashMap<(String, TenantId, PeriodKey), u64>,
    // WP-61: bumped by every tier-2 write below, under this SAME mutex
    // acquisition -- see `ControlPlaneStore::policy_generation`'s doc for why
    // a spend write (`set_spend` above) must never touch this field.
    generation: u64,
}

impl InMemoryControlPlaneStore {
    pub fn new() -> Self {
        InMemoryControlPlaneStore {
            state: std::sync::Mutex::new(InMemoryState {
                tenants: Vec::new(),
                keys: HashMap::new(),
                policies: HashMap::new(),
                budgets: HashMap::new(),
                spend: HashMap::new(),
                generation: 0,
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
            budgets: state.budgets.clone(),
        })
    }

    fn policy_generation(&self) -> Result<u64, StoreError> {
        let state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        Ok(state.generation)
    }

    fn create_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        if !state.tenants.contains(tenant) {
            state.tenants.push(tenant.clone());
        }
        state.generation += 1;
        Ok(())
    }

    fn delete_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        state.tenants.retain(|t| t != tenant);
        state.policies.remove(tenant);
        // Parity with `policies` above: a deleted tenant's budget row goes
        // with it, the same "a deleted tenant carries no leftover
        // configuration" rule `set_policy`'s removal already follows.
        state.budgets.remove(tenant);
        state.generation += 1;
        Ok(())
    }

    fn put_key(&self, rec: &StoredKey) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        state.keys.insert(rec.key_id.clone(), rec.clone());
        state.generation += 1;
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
                state.generation += 1;
                Ok(())
            }
            // Nothing was written -- must NOT bump. See
            // `ControlPlaneStore::policy_generation`'s doc.
            None => Err(StoreError::NotFound),
        }
    }

    fn set_policy(&self, tenant: &TenantId, access: &ModelAccess) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        state.policies.insert(tenant.clone(), access.clone());
        state.generation += 1;
        Ok(())
    }

    fn set_budget(
        &self,
        tenant: &TenantId,
        budget: Option<&TenantBudget>,
    ) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        match budget {
            Some(budget) => {
                state.budgets.insert(tenant.clone(), *budget);
            }
            None => {
                state.budgets.remove(tenant);
            }
        }
        state.generation += 1;
        Ok(())
    }

    fn set_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        total_micros: u64,
    ) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        state.spend.insert(
            (stat_prefix.to_string(), tenant.clone(), period.clone()),
            total_micros,
        );
        Ok(())
    }

    fn load_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
    ) -> Result<u64, StoreError> {
        let state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        Ok(state
            .spend
            .get(&(stat_prefix.to_string(), tenant.clone(), period.clone()))
            .copied()
            .unwrap_or(0))
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
// WP-50 increment 3c-iii-a: a tenant's budget, JSON-encoded like every other
// table here -- see `EncodedTenantBudget`'s doc. Independent of
// `POLICIES_TABLE`: a tenant may have a row in one, the other, both, or
// neither.
const BUDGETS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("budgets");
// WP-50 increment 3c-ii-b: a spend row's key is the 3-part
// `(stat_prefix, tenant, period)` tuple, not a single `&str` like every
// table above -- `redb::Key` has a native impl for tuples of `Key` types
// (see `tuple_types.rs` upstream), so this uses that directly rather than
// hand-rolling a delimiter-joined single string the way `keys_by_tenant`'s
// VALUE does for `Vec<String>`. The value is a plain `u64`, not JSON bytes
// like the other tables: `u64` already has a native fixed-width `redb::Value`
// impl, so encoding a bare integer through `serde_json` would only add an
// allocation and a round trip for no benefit.
const SPEND_TABLE: TableDefinition<(&str, &str, &str), u64> = TableDefinition::new("spend");
// WP-61: a single row, keyed `"policy"`, holding the tier-2 generation
// counter -- see `ControlPlaneStore::policy_generation`'s doc. A dedicated
// table (rather than a row inside, say, `TENANTS_TABLE`) so bumping it is one
// `insert` regardless of which of the six tier-2 tables the accompanying
// write actually touched.
const GENERATION_TABLE: TableDefinition<&str, u64> = TableDefinition::new("generation");

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

/// [`crate::spend::Period`] as `serde_json` sees it. A local mirror, not a
/// `serde` derive on `Period` itself -- same reasoning as
/// [`EncodedModelAccess`]'s doc: `Period` lives in `spend.rs`, which this
/// increment's scope does not otherwise need to touch for a serde impl.
#[derive(serde::Serialize, serde::Deserialize)]
enum EncodedPeriod {
    Daily,
    Monthly,
}

impl From<crate::spend::Period> for EncodedPeriod {
    fn from(period: crate::spend::Period) -> Self {
        match period {
            crate::spend::Period::Daily => EncodedPeriod::Daily,
            crate::spend::Period::Monthly => EncodedPeriod::Monthly,
        }
    }
}

impl From<EncodedPeriod> for crate::spend::Period {
    fn from(encoded: EncodedPeriod) -> Self {
        match encoded {
            EncodedPeriod::Daily => crate::spend::Period::Daily,
            EncodedPeriod::Monthly => crate::spend::Period::Monthly,
        }
    }
}

/// [`TenantBudget`] as `serde_json` sees it -- same "local mirror, not a
/// derive on the real type" reasoning as [`EncodedModelAccess`] and
/// [`EncodedPeriod`] above.
#[derive(serde::Serialize, serde::Deserialize)]
struct EncodedTenantBudget {
    max_micros: u64,
    period: EncodedPeriod,
}

impl From<&TenantBudget> for EncodedTenantBudget {
    fn from(budget: &TenantBudget) -> Self {
        EncodedTenantBudget {
            max_micros: budget.max_micros.as_micros(),
            period: budget.period.into(),
        }
    }
}

impl From<EncodedTenantBudget> for TenantBudget {
    fn from(encoded: EncodedTenantBudget) -> Self {
        TenantBudget {
            max_micros: crate::spend::MicroUsd::from_micros(encoded.max_micros),
            period: encoded.period.into(),
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

    /// Creates all tables if they do not already exist -- six as of WP-61
    /// (the doc used to say "all four"; `SPEND_TABLE` and `GENERATION_TABLE`
    /// are the two that arrived since).
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
        txn.open_table(BUDGETS_TABLE).map_err(store_err)?;
        txn.open_table(SPEND_TABLE).map_err(store_err)?;
        txn.open_table(GENERATION_TABLE).map_err(store_err)?;
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    /// Reads the current generation (or `0` if the row has never been
    /// written -- same "absence is the zero value" convention as everywhere
    /// else in this store) and writes back `+1`, inside `txn` -- the SAME
    /// write transaction as the tier-2 row the caller is about to commit, so
    /// the bump and the write it accompanies commit atomically or not at all.
    /// A reader must never observe the new stamp without the write it stands
    /// for. See [`ControlPlaneStore::policy_generation`]'s doc.
    fn bump_generation(txn: &redb::WriteTransaction) -> Result<(), StoreError> {
        let mut table = txn.open_table(GENERATION_TABLE).map_err(store_err)?;
        let current = table.get("policy").map_err(store_err)?.map(|g| g.value());
        table
            .insert("policy", current.unwrap_or(0) + 1)
            .map_err(store_err)?;
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
    fn policy_generation(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(GENERATION_TABLE).map_err(store_err)?;
        Ok(table
            .get("policy")
            .map_err(store_err)?
            .map(|g| g.value())
            .unwrap_or(0))
    }

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

        let budgets_table = txn.open_table(BUDGETS_TABLE).map_err(store_err)?;
        let mut budgets = HashMap::new();
        for entry in budgets_table.iter().map_err(store_err)? {
            let (key, value) = entry.map_err(store_err)?;
            let encoded: EncodedTenantBudget = decode_json(value.value())?;
            budgets.insert(TenantId::new(key.value()), encoded.into());
        }

        Ok(StoredControlPlane {
            tenants,
            keys,
            policies,
            budgets,
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
        Self::bump_generation(&txn)?;
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
        {
            // Parity with `policies_table` above and with
            // `InMemoryControlPlaneStore::delete_tenant` -- see that impl's
            // comment.
            let mut budgets_table = txn.open_table(BUDGETS_TABLE).map_err(store_err)?;
            budgets_table.remove(tenant.as_str()).map_err(store_err)?;
        }
        // Matches `InMemoryControlPlaneStore::delete_tenant` exactly: `keys`
        // and `keys_by_tenant` are left untouched. A tenant's keys outliving
        // the tenant row is the existing, deliberate InMemory behavior this
        // store must not silently diverge from -- see the parity test below.
        Self::bump_generation(&txn)?;
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

        Self::bump_generation(&txn)?;
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
                // `commit()` rolls the whole (empty) transaction back, and
                // returning before `bump_generation` means the stamp is not
                // touched either. See `ControlPlaneStore::policy_generation`'s
                // doc.
                None => return Err(StoreError::NotFound),
            };
            row.revoked = true;
            table
                .insert(key_id.as_str(), encode_json(&row).as_slice())
                .map_err(store_err)?;
        }
        Self::bump_generation(&txn)?;
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
        Self::bump_generation(&txn)?;
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn set_budget(
        &self,
        tenant: &TenantId,
        budget: Option<&TenantBudget>,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(BUDGETS_TABLE).map_err(store_err)?;
            match budget {
                Some(budget) => {
                    let encoded: EncodedTenantBudget = budget.into();
                    table
                        .insert(tenant.as_str(), encode_json(&encoded).as_slice())
                        .map_err(store_err)?;
                }
                None => {
                    table.remove(tenant.as_str()).map_err(store_err)?;
                }
            }
        }
        Self::bump_generation(&txn)?;
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn set_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        total_micros: u64,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(SPEND_TABLE).map_err(store_err)?;
            table
                .insert(
                    (stat_prefix, tenant.as_str(), period.as_str()),
                    total_micros,
                )
                .map_err(store_err)?;
        }
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn load_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
    ) -> Result<u64, StoreError> {
        let txn = self.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(SPEND_TABLE).map_err(store_err)?;
        let total = table
            .get((stat_prefix, tenant.as_str(), period.as_str()))
            .map_err(store_err)?
            .map(|guard| guard.value())
            .unwrap_or(0);
        Ok(total)
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

/// The policy poller thread's stop condition, plus the [`Condvar`] that wakes
/// it immediately on shutdown rather than sleeping out up to one full
/// interval.
///
/// Rust note: this is a deliberate TWIN of `spend.rs`'s private
/// `ShutdownSignal` -- same shape (one waiter, one notifier, a `Mutex<bool>`
/// plus a bare `Condvar`), same reason (a poll trades wakeup latency for CPU
/// burned every tick even when nothing changed, and this has exactly one
/// waiter and one notifier) -- not a shared type the two modules both import.
/// Each stays private to its own module: `spend.rs`'s flusher and this
/// module's poller are two independent background threads with independent
/// lifetimes ([`SpendAccumulator`](crate::spend::SpendAccumulator) and
/// [`ControlPlane`] are not the same object and do not share a shutdown
/// signal), and duplicating ~6 lines of struct definition is cheaper than the
/// coupling a shared type would introduce between two modules that otherwise
/// have no reason to know about each other.
struct PollShutdown {
    stop: Mutex<bool>,
    cv: Condvar,
}

/// A started policy-poller thread's handle -- kept so [`ControlPlane`] can
/// signal and join it, from either [`ControlPlane::start_policy_poller`]
/// (replacing a previous thread) or `Drop` (shutting down for good). Mirrors
/// `spend.rs`'s private `Flusher`.
struct PolicyPoller {
    shutdown: Arc<PollShutdown>,
    join: JoinHandle<()>,
}

/// Owns the store, the operator's HMAC secret, the config bootstrap keys, and
/// the published snapshot. See the module doc for the full seam and the
/// boot/refresh fail-closed split.
pub struct ControlPlane {
    /// Rust note: `Arc`, not `Box`, purely so [`ControlPlane::store`] can
    /// hand a SHARED handle to it out. [`ControlPlane::new`] still takes a
    /// `Box` (every call site already passes one, and `Arc::from(Box<dyn T>)`
    /// converts for free), so widening this cost no caller a change.
    store: Arc<dyn ControlPlaneStore>,
    secret: HmacSecret,
    bootstrap_keys: KeySet,
    published: Arc<ArcSwap<ControlPlaneSnapshot>>,
    /// WP-61: the `policy_generation` stamp the currently-published snapshot
    /// reflects. `None` means "unknown" -- a stamp read that failed at boot,
    /// or a store whose `policy_generation` errored -- which forces the next
    /// poll to rebuild rather than risk comparing against a stale or
    /// meaningless number. See [`Self::poll_once`].
    last_generation: Mutex<Option<u64>>,
    /// WP-61: when a poll (or a `rebuild()`) last SUCCEEDED. See
    /// [`Self::snapshot_age`].
    last_reconciled_at: Mutex<Instant>,
    poller: Mutex<Option<PolicyPoller>>,
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
        let store: Arc<dyn ControlPlaneStore> = Arc::from(store);
        // WP-61: read the generation stamp BEFORE `load()`, not after.
        //
        // Rust note: this ordering is load-bearing, not incidental. If a
        // concurrent admin write lands between the two reads, reading the
        // stamp SECOND would observe the new (post-write) generation
        // alongside data that predates it, and `last_generation` would then
        // already match a later `policy_generation()` that reflects a write
        // this snapshot never saw -- the next `poll_once` would see "no
        // change" and skip the rebuild that write was supposed to trigger,
        // permanently (until the NEXT write bumps the stamp again). Reading
        // the stamp FIRST means the worst case is the opposite and harmless:
        // `load()` picks up that same write anyway, and the stamp we recorded
        // is merely a little older than what we loaded, so the next poll
        // just does one redundant rebuild.
        //
        // A stamp-read failure here is deliberately `.ok()`, not `?`: this is
        // still the "boot" side of the boot/refresh split (see the module
        // doc), and only `load()` failing is a hard error. Losing the
        // opening stamp only means the first poll tick always rebuilds
        // (`last_generation` starts `None`), which is one redundant rebuild,
        // not a missed revocation.
        let generation = store.policy_generation().ok();
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
            last_generation: Mutex::new(generation),
            last_reconciled_at: Mutex::new(Instant::now()),
            poller: Mutex::new(None),
        })
    }

    /// Re-reads the store and republishes -- OR, on a read failure, leaves
    /// the previously published snapshot exactly as it was.
    ///
    /// This is the ADMIN-WRITE path's refresh (`mint_key`, `revoke_key`, and
    /// friends call it right after their own write -- see their "writes THEN
    /// republishes" docs) and is UNCONDITIONAL: it always re-reads and
    /// republishes, unlike [`Self::poll_once`], which only does that work
    /// when the generation stamp has actually moved. That is deliberate --
    /// the caller here just performed a write and already knows the store
    /// changed, so checking the stamp first would only add a redundant read
    /// before the read it was always going to do anyway.
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
    ///
    /// WP-61: on success, also records the generation stamp the fresh
    /// snapshot reflects and marks `last_reconciled_at` as now -- both read
    /// BEFORE `load()`, for the same reason [`Self::new`]'s doc explains.
    /// `Err` leaves both untouched, exactly like `published`: a failed
    /// refresh is not a reconciliation and must not reset the staleness
    /// clock [`Self::snapshot_age`] reports.
    pub fn rebuild(&self) {
        let generation = self.store.policy_generation().ok();
        match self.store.load() {
            Ok(loaded) => {
                let snapshot = Self::merge(&self.bootstrap_keys, loaded);
                self.published.store(Arc::new(snapshot));
                *self
                    .last_generation
                    .lock()
                    .expect("control plane mutex poisoned") = generation;
                *self
                    .last_reconciled_at
                    .lock()
                    .expect("control plane mutex poisoned") = Instant::now();
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "control-plane store refresh failed; keeping the last published snapshot"
                );
            }
        }
    }

    /// WP-61's replica-to-replica propagation step: reads ONLY the
    /// generation stamp, and does the full `load()` + republish (identical to
    /// [`Self::rebuild`]) ONLY if it moved since the last successful poll or
    /// rebuild. Returns `Ok(true)` if a rebuild happened, `Ok(false)` if the
    /// stamp was unchanged.
    ///
    /// An unchanged stamp still means this replica IS reconciled as of now --
    /// it just confirmed the store agrees with what it already has -- so
    /// `last_reconciled_at` advances either way on success. See
    /// [`Self::snapshot_age`].
    ///
    /// On a stamp-read failure, propagates `Err` and touches neither
    /// `published` nor `last_reconciled_at` -- same fail-closed-on-the-
    /// snapshot, loud-on-the-log shape as [`Self::rebuild`]'s `Err` arm; the
    /// caller (the policy-poller thread) is what logs it, so the staleness
    /// warning's suppression state lives with the thread, not here.
    pub fn poll_once(&self) -> Result<bool, StoreError> {
        let generation = self.store.policy_generation()?;
        let previous = *self
            .last_generation
            .lock()
            .expect("control plane mutex poisoned");
        if previous == Some(generation) {
            *self
                .last_reconciled_at
                .lock()
                .expect("control plane mutex poisoned") = Instant::now();
            return Ok(false);
        }
        let loaded = self.store.load()?;
        let snapshot = Self::merge(&self.bootstrap_keys, loaded);
        self.published.store(Arc::new(snapshot));
        *self
            .last_generation
            .lock()
            .expect("control plane mutex poisoned") = Some(generation);
        *self
            .last_reconciled_at
            .lock()
            .expect("control plane mutex poisoned") = Instant::now();
        Ok(true)
    }

    /// How long since this replica's snapshot was last confirmed to match
    /// the store -- either a successful [`Self::poll_once`] (moved or not)
    /// or [`Self::rebuild`]. This is the raw number; the Prometheus
    /// `spend_reconciliation_age_seconds` gauge (ADR-0006 §5) that exports it
    /// lands with WP-62 -- this accessor, plus the policy poller's own
    /// staleness warning (see [`Self::start_policy_poller`]), is WP-61's half
    /// of that observability requirement.
    pub fn snapshot_age(&self) -> Duration {
        self.last_reconciled_at
            .lock()
            .expect("control plane mutex poisoned")
            .elapsed()
    }

    /// Starts the background policy-poller thread, ticking roughly every
    /// `interval` (jittered -- see below). See the module's `PollShutdown`/
    /// `PolicyPoller` doc for the shutdown shape, which mirrors
    /// `spend.rs`'s flusher.
    ///
    /// Runs UNCONDITIONALLY -- there is no "single replica, skip polling"
    /// shortcut, including for [`InMemoryControlPlaneStore`]. ADR-0006 §6:
    /// the embedded store implements the identical contract on purpose, and
    /// polling against it is nearly free, so the multi-replica code path is
    /// exercised in every deployment rather than only ever executing for the
    /// first time in production.
    ///
    /// Calling this twice cleanly shuts down and joins the previous thread
    /// first, same as `spend.rs`'s `start_flusher`.
    pub fn start_policy_poller(self: &Arc<Self>, interval: Duration) {
        self.stop_poller_if_running();

        let shutdown = Arc::new(PollShutdown {
            stop: Mutex::new(false),
            cv: Condvar::new(),
        });
        // Rust note: the thread holds a `Weak<ControlPlane>`, NOT an `Arc`.
        // `Drop for ControlPlane` is what stops this thread, but `Drop` only
        // runs once the LAST `Arc<ControlPlane>` is dropped -- if the thread
        // itself held a strong `Arc`, it would BE that last reference, so
        // `Drop` (and therefore the thread's own stop signal) could never
        // fire. The thread upgrades the `Weak` once per tick and returns as
        // soon as that upgrade yields `None`, which is how it notices its
        // owner is gone with no `Arc` cycle to break.
        let weak = Arc::downgrade(self);
        let thread_shutdown = Arc::clone(&shutdown);
        let join = std::thread::Builder::new()
            .name("policy-poller".to_string())
            .spawn(move || run_policy_poller(weak, thread_shutdown, interval))
            .expect("spawning the policy poller thread must not fail");

        *self.poller.lock().expect("control plane mutex poisoned") =
            Some(PolicyPoller { shutdown, join });
    }

    /// Signals and joins a currently-running policy-poller thread, if any --
    /// shared by [`Self::start_policy_poller`] (replacing a previous thread)
    /// and `Drop` (shutting down for good). Mirrors `spend.rs`'s
    /// `stop_flusher_if_running`.
    fn stop_poller_if_running(&self) {
        let poller = self
            .poller
            .lock()
            .expect("control plane mutex poisoned")
            .take();
        if let Some(poller) = poller {
            *poller
                .shutdown
                .stop
                .lock()
                .expect("policy poller shutdown mutex poisoned") = true;
            poller.shutdown.cv.notify_all();
            // Rust note: DO NOT join if we ARE the poller thread. That is
            // reachable, and it is the one sharp edge of the `Weak` design:
            // the thread upgrades its `Weak` once per tick, so if the last
            // external `Arc<ControlPlane>` is dropped DURING a tick, the
            // thread's own upgraded `Arc` becomes the last strong reference,
            // and dropping it at the end of the tick runs `Drop for
            // ControlPlane` on the poller thread itself. `pthread_join` on
            // the calling thread returns `EDEADLK`, which std turns into a
            // panic inside a `Drop` -- so check first. Setting the stop flag
            // above is all this case needs anyway: the thread is provably
            // alive and about to re-lock, see the flag, and return.
            if std::thread::current().id() == poller.join.thread().id() {
                return;
            }
            // Rust note: ignoring the `Result` matches `stop_flusher_if_
            // running`'s own note -- `.join()` only errors if the thread
            // panicked, and that should surface via the usual panic
            // machinery, not be swallowed here.
            let _ = poller.join.join();
        }
    }

    /// A cloned handle to the published snapshot -- what
    /// [`crate::auth::VirtualKeyAuthenticator`] holds and `load()`s on every
    /// request. Cloning an `Arc` is cheap and does not clone the snapshot
    /// itself.
    pub fn handle(&self) -> Arc<ArcSwap<ControlPlaneSnapshot>> {
        Arc::clone(&self.published)
    }

    /// A shared handle to the SAME store this control plane reads and writes.
    ///
    /// Exists for `spend_limit_filter`'s [`crate::spend::SpendAccumulator`],
    /// which must persist spend into the very store the operator configured
    /// (`typed_config.store` on `llmproxy.auth` -- in-memory or a redb file),
    /// not a private one of its own. Handing back a fresh
    /// `InMemoryControlPlaneStore` instead would leave 3c-ii-b's whole
    /// persistence path -- `set_spend`/`load_spend` on redb, absolute writes,
    /// restart-resume -- wired to nothing, and a monthly ceiling would reset
    /// to zero on every process restart: a budget an operator could escape by
    /// bouncing the proxy. See `spend_limit_filter`'s module doc.
    pub fn store(&self) -> Arc<dyn ControlPlaneStore> {
        Arc::clone(&self.store)
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

    /// Sets or clears `tenant`'s spend budget, then republishes (WP-50
    /// increment 3c-iii-a) -- store-then-`rebuild()`, exactly like
    /// [`Self::set_policy`], so a budget change reaches every worker's
    /// `VirtualKeyAuthenticator` (and, later, 3c-iii-b's enforcement filter)
    /// on the next request rather than the next unrelated rebuild.
    /// `Some(budget)` sets it; `None` clears it, reverting the tenant to
    /// unlimited -- see [`crate::spend::TenantBudget`]'s doc.
    pub fn set_budget(
        &self,
        tenant: &TenantId,
        budget: Option<&TenantBudget>,
    ) -> Result<(), StoreError> {
        self.store.set_budget(tenant, budget)?;
        self.rebuild();
        Ok(())
    }

    /// Seeds `bootstrap` (`llmproxy.model_authz`'s `typed_config.policies`,
    /// parsed by `model_authz_filter::parse_config`) into the store, then
    /// republishes -- store-wins on a tenant collision, the identical rule
    /// and rationale as [`Self::merge`]'s bootstrap-KEY merge: the store is
    /// authoritative (an admin `PUT /tenants/{id}/policy` must never be
    /// silently reverted by a static config value), and a collision is
    /// logged by TENANT ID ONLY -- never a policy's contents. See WP-50
    /// increment 3b-iv's design brief, "`typed_config.policies` stays, as
    /// BOOTSTRAP".
    ///
    /// # Idempotence is required, not incidental
    ///
    /// `model_authz_filter::create` runs once per worker (ADR-0003) and
    /// calls this every time with the SAME bootstrap map -- store-wins makes
    /// every call after the first a genuine no-op: once a tenant's row
    /// exists in the store (whether THIS method wrote it or an admin did),
    /// no later call here ever touches it again. See
    /// `seeding_the_same_bootstrap_map_twice_is_a_no_op` below; the failure
    /// mode this exists to catch is a re-seed silently reverting an admin
    /// write that landed between two worker builds.
    ///
    /// # Pinned at first build, like `bootstrap_keys` and `store`
    ///
    /// Because the `ControlPlane` singleton is per-SERVE and a SIGHUP reload
    /// reuses it (see `auth_filter::AuthFilterFactory::create`'s doc), a
    /// tenant this method has already written is fixed at whatever value it
    /// had on the first build that seeded it -- editing
    /// `typed_config.policies` for that tenant and reloading does NOT
    /// re-seed it; store-wins means the OLD stored value keeps winning. A
    /// genuinely new tenant added to `typed_config.policies` DOES get seeded
    /// on the next call, since it has no store row yet to collide with.
    ///
    /// The operator-facing surprise worth stating outright: seeding WRITES
    /// into the store, so REMOVING a tenant from `typed_config.policies`
    /// does not remove its policy -- the row this method wrote outlives the
    /// config line that produced it. With the default in-memory store that
    /// is invisible (the store dies with the process); with
    /// `store: persistent` it is durable, and the only way to change that
    /// tenant's policy afterwards is an admin write. That is the same
    /// store-authoritative trade `virtual_keys` already makes, but policies
    /// are likelier to be edited in place, so it will be met sooner.
    pub fn seed_bootstrap_policies(&self, bootstrap: &TenantPolicyMap) -> Result<(), StoreError> {
        let loaded = self.store.load()?;
        // Rust note: a `HashSet<String>` snapshot of the store's current
        // tenants, built once up front -- avoids re-`load()`ing the store
        // (an I/O round trip) once per bootstrap entry, and also lets this
        // loop track tenants IT just wrote so two identical `key`s within one
        // `bootstrap` map (impossible today -- `parse_config` dedupes -- but
        // this function should not depend on that) can't double-log.
        let mut existing: std::collections::HashSet<String> = loaded
            .policies
            .keys()
            .map(|t| t.as_str().to_string())
            .collect();

        for (tenant, policy) in bootstrap {
            if existing.contains(tenant) {
                tracing::warn!(
                    tenant = tenant.as_str(),
                    "control-plane store policy collides with a config bootstrap policy; \
                     the store record wins"
                );
                continue;
            }
            self.store
                .set_policy(&TenantId::new(tenant.clone()), &policy.model_access)?;
            existing.insert(tenant.clone());
        }

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
        //
        // WP-50 increment 3c-iii-a: `loaded.budgets` is a SEPARATE store
        // table from `loaded.policies` (see `StoredControlPlane::budgets`'s
        // doc) -- a tenant can have a `ModelAccess` row, a `TenantBudget`
        // row, both, or neither, entirely independently, because
        // `set_policy`/`set_budget` are two independent writes with two
        // independent store methods. This loop therefore drains
        // `loaded.budgets` by tenant as it walks `loaded.policies` (the
        // common case: both rows exist), then a second pass below picks up
        // any tenant that has a budget but was never given a policy row --
        // neither field may silently vanish because the OTHER one happened
        // to be present or absent. `seed_bootstrap_policies` only ever calls
        // `store.set_policy` (never `set_budget`), so a bootstrap policy
        // seed can never observe, let alone clobber, a budget an admin set:
        // the two writes are to different tables, and this merge always
        // looks a tenant's budget up independently of where its policy row
        // came from.
        let mut budgets = loaded.budgets;
        let mut policies: TenantPolicyMap = HashMap::new();
        for (tenant, access) in loaded.policies {
            let budget = budgets.remove(&tenant);
            policies.insert(
                tenant.as_str().to_string(),
                Arc::new(TenantPolicy {
                    model_access: access,
                    budget,
                }),
            );
        }
        for (tenant, budget) in budgets {
            policies.insert(
                tenant.as_str().to_string(),
                Arc::new(TenantPolicy {
                    model_access: ModelAccess::default(),
                    budget: Some(budget),
                }),
            );
        }

        ControlPlaneSnapshot { keys, policies }
    }
}

impl Drop for ControlPlane {
    /// Shuts the policy-poller thread down, if one was started -- mirrors
    /// `SpendAccumulator`'s `Drop`, minus the final flush: there is nothing
    /// for a poller to flush, only a read loop to stop.
    fn drop(&mut self) {
        self.stop_poller_if_running();
    }
}

/// The policy-poller thread's body. Same `Condvar::wait_timeout` loop shape
/// as `spend.rs`'s `run_flusher` -- wakes immediately on shutdown, otherwise
/// wakes once per (jittered) interval, releases the shutdown lock before any
/// store I/O, and loops back around on a spurious wakeup.
///
/// Rust note: `control` is a `Weak<ControlPlane>`, upgraded once per tick.
/// `None` means the owning `ControlPlane` (and therefore every strong `Arc`
/// to it) is gone, which is this thread's own signal to return -- see
/// [`ControlPlane::start_policy_poller`]'s doc for why it cannot hold a
/// strong `Arc` itself.
fn run_policy_poller(control: Weak<ControlPlane>, shutdown: Arc<PollShutdown>, interval: Duration) {
    // CLAUDE.md rule 17: a control that degrades must be loud, but a poller
    // ticking every tens of seconds must not re-warn every tick while the
    // store stays down -- that turns the log itself into the incident. These
    // two fields, private to this one thread, are the suppression state:
    // warn on the FIRST failure since the last success, or once `last_warn`
    // is at least ten intervals old, whichever comes first.
    let mut last_warn: Option<Instant> = None;
    let mut warned_since_success = false;

    let mut guard = shutdown
        .stop
        .lock()
        .expect("policy poller shutdown mutex poisoned");
    loop {
        if *guard {
            return;
        }
        let wait_for = next_poll_delay(interval);
        let (new_guard, wait_result) = shutdown
            .cv
            .wait_timeout(guard, wait_for)
            .expect("policy poller shutdown condvar poisoned");
        guard = new_guard;
        if *guard {
            return;
        }
        if wait_result.timed_out() {
            // Release the shutdown lock before store I/O -- a concurrent
            // shutdown request must never wait on this tick's poll to finish
            // before it can even set the flag.
            drop(guard);

            // The owning `ControlPlane` (and every strong `Arc` to it) is
            // gone -- nothing left to poll for, so stop.
            let Some(cp) = control.upgrade() else {
                return;
            };
            let bound = interval + interval / 4;
            match cp.poll_once() {
                Ok(_rebuilt) => {
                    warned_since_success = false;
                }
                Err(err) => {
                    let snapshot_age = cp.snapshot_age();
                    let should_warn = !warned_since_success
                        || last_warn.is_none_or(|at| at.elapsed() >= interval * 10);
                    if should_warn {
                        tracing::warn!(
                            error = %err,
                            snapshot_age_seconds = snapshot_age.as_secs_f64(),
                            bound_seconds = bound.as_secs_f64(),
                            stale = snapshot_age > bound,
                            "control-plane policy poll failed; serving a stale snapshot"
                        );
                        last_warn = Some(Instant::now());
                        warned_since_success = true;
                    }
                }
            }
            // `cp` is dropped here, at the end of the tick -- holding it any
            // longer than one tick's work would be a strong reference this
            // thread has no business keeping.
            drop(cp);

            guard = shutdown
                .stop
                .lock()
                .expect("policy poller shutdown mutex poisoned");
        }
        // A spurious wakeup with neither shutdown signalled nor a timeout:
        // loop and wait again.
    }
}

/// `interval` plus a uniform-random draw in `[0, interval / 4)` -- the same
/// shape as `proxy-cluster::health_check`'s `next_delay`, adapted to a fixed
/// quarter-of-interval jitter rather than a separately configured one: N
/// replicas that all observed the same generation bump at nearly the same
/// instant must not all rebuild at the same instant too, or the store sees a
/// synchronized load spike every time anything changes instead of one read
/// spread out across up to `interval / 4`.
///
/// Rust note: a fresh `rand::thread_rng()` per call, not a stored
/// `Mutex<StdRng>` -- this runs on its own thread with no shared state to
/// protect, so (as `next_delay`'s own note says) there is nothing to guard.
fn next_poll_delay(interval: Duration) -> Duration {
    let jitter = interval / 4;
    let jitter_nanos = jitter.as_nanos().min(u128::from(u64::MAX)) as u64;
    if jitter_nanos == 0 {
        // Guard against an empty `gen_range` -- an `interval` under 4ns
        // (never a real config, but not this function's job to assume) would
        // otherwise panic rather than simply skip the jitter.
        return interval;
    }
    let extra = rand::thread_rng().gen_range(0..jitter_nanos);
    interval + Duration::from_nanos(extra)
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

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use http::header::AUTHORIZATION;
    use http::{HeaderMap, HeaderValue};

    use crate::auth::{AuthError, AuthOutcome, Authenticator, VirtualKeyAuthenticator};
    use crate::spend::{MicroUsd, Period};

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
        fn policy_generation(&self) -> Result<u64, StoreError> {
            self.0.policy_generation()
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
        fn set_budget(
            &self,
            tenant: &TenantId,
            budget: Option<&TenantBudget>,
        ) -> Result<(), StoreError> {
            self.0.set_budget(tenant, budget)
        }
        fn set_spend(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
            total_micros: u64,
        ) -> Result<(), StoreError> {
            self.0.set_spend(stat_prefix, tenant, period, total_micros)
        }
        fn load_spend(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
        ) -> Result<u64, StoreError> {
            self.0.load_spend(stat_prefix, tenant, period)
        }
    }

    /// A store whose `load` can be toggled to fail on command, via a shared
    /// flag the test keeps a handle to -- proves the fail-closed REFRESH path
    /// (as opposed to boot, which `FailingStore` below covers). Also counts
    /// `load()` calls (WP-61: `load_calls`, `Arc<AtomicUsize>` so a test keeps
    /// a handle after the store moves into a `ControlPlane`) -- used by
    /// `a_generation_that_has_not_moved_does_no_load_work` to prove
    /// `poll_once` skips `load()` entirely when the stamp is unchanged, per
    /// this struct's spec rather than a second, near-identical double.
    struct ToggleStore {
        inner: InMemoryControlPlaneStore,
        fail: Arc<AtomicBool>,
        load_calls: Arc<AtomicUsize>,
    }

    impl ControlPlaneStore for ToggleStore {
        fn load(&self) -> Result<StoredControlPlane, StoreError> {
            self.load_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(StoreError::Unavailable("toggled off for test".to_string()));
            }
            self.inner.load()
        }
        fn policy_generation(&self) -> Result<u64, StoreError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(StoreError::Unavailable("toggled off for test".to_string()));
            }
            self.inner.policy_generation()
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
        fn set_budget(
            &self,
            tenant: &TenantId,
            budget: Option<&TenantBudget>,
        ) -> Result<(), StoreError> {
            self.inner.set_budget(tenant, budget)
        }
        fn set_spend(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
            total_micros: u64,
        ) -> Result<(), StoreError> {
            self.inner
                .set_spend(stat_prefix, tenant, period, total_micros)
        }
        fn load_spend(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
        ) -> Result<u64, StoreError> {
            self.inner.load_spend(stat_prefix, tenant, period)
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
        fn policy_generation(&self) -> Result<u64, StoreError> {
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
        fn set_budget(
            &self,
            _tenant: &TenantId,
            _budget: Option<&TenantBudget>,
        ) -> Result<(), StoreError> {
            Ok(())
        }
        fn set_spend(
            &self,
            _stat_prefix: &str,
            _tenant: &TenantId,
            _period: &PeriodKey,
            _total_micros: u64,
        ) -> Result<(), StoreError> {
            Ok(())
        }
        fn load_spend(
            &self,
            _stat_prefix: &str,
            _tenant: &TenantId,
            _period: &PeriodKey,
        ) -> Result<u64, StoreError> {
            Ok(0)
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
            load_calls: Arc::new(AtomicUsize::new(0)),
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

    // --- seed_bootstrap_policies (WP-50 increment 3b-iv) ---------------------

    #[test]
    fn seed_bootstrap_policies_writes_a_new_tenant_and_republishes() {
        let secret_bytes = b"operator-secret";
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let access = ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]);
        let mut bootstrap: TenantPolicyMap = HashMap::new();
        bootstrap.insert(
            "tenant-a".to_string(),
            Arc::new(TenantPolicy {
                model_access: access.clone(),
                budget: None,
            }),
        );

        cp.seed_bootstrap_policies(&bootstrap)
            .expect("seeding into an empty store must succeed");

        let snapshot = cp.handle().load();
        let policy = snapshot
            .policies
            .get("tenant-a")
            .expect("a bootstrap policy for a tenant absent from the store must be seeded");
        assert_eq!(policy.model_access, access);
    }

    #[test]
    fn seed_bootstrap_policies_does_not_overwrite_an_existing_store_policy() {
        let secret_bytes = b"operator-secret";
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let store_access = ModelAccess::All;
        cp.set_policy(&TenantId::new("tenant-a"), &store_access)
            .expect("set_policy must succeed");

        let bootstrap_access = ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]);
        let mut bootstrap: TenantPolicyMap = HashMap::new();
        bootstrap.insert(
            "tenant-a".to_string(),
            Arc::new(TenantPolicy {
                model_access: bootstrap_access,
                budget: None,
            }),
        );

        cp.seed_bootstrap_policies(&bootstrap)
            .expect("seeding over an already-populated tenant must still succeed (no-op write)");

        let snapshot = cp.handle().load();
        assert_eq!(
            snapshot.policies["tenant-a"].model_access, store_access,
            "the store's policy must win a tenant collision against the bootstrap map"
        );
    }

    // --- THE re-seed property: re-seeding an identical bootstrap map must
    //     not clobber a store write that landed in between -- see
    //     `seed_bootstrap_policies`'s doc, "Idempotence is required, not
    //     incidental". This models `model_authz_filter::create` being called
    //     once per worker with the SAME parsed `typed_config.policies`.

    #[test]
    fn seeding_the_same_bootstrap_map_twice_is_a_no_op() {
        let secret_bytes = b"operator-secret";
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let bootstrap_access = ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]);
        let mut bootstrap: TenantPolicyMap = HashMap::new();
        bootstrap.insert(
            "tenant-a".to_string(),
            Arc::new(TenantPolicy {
                model_access: bootstrap_access.clone(),
                budget: None,
            }),
        );

        // First worker's `create()`: the store has nothing for `tenant-a`
        // yet, so this WRITES the bootstrap policy.
        cp.seed_bootstrap_policies(&bootstrap)
            .expect("first seed must succeed");
        assert_eq!(
            cp.handle().load().policies["tenant-a"].model_access,
            bootstrap_access
        );

        // An admin `PUT /tenants/tenant-a/policy` lands in between two
        // worker builds -- exactly `ControlPlane::set_policy`, what that
        // endpoint calls.
        let admin_access = ModelAccess::All;
        cp.set_policy(&TenantId::new("tenant-a"), &admin_access)
            .expect("admin set_policy must succeed");
        assert_eq!(
            cp.handle().load().policies["tenant-a"].model_access,
            admin_access
        );

        // A second worker's `create()` seeds the exact same bootstrap map
        // again -- store-wins must make this a no-op, not a revert.
        cp.seed_bootstrap_policies(&bootstrap)
            .expect("re-seeding an identical bootstrap map must succeed");
        assert_eq!(
            cp.handle().load().policies["tenant-a"].model_access,
            admin_access,
            "re-seeding identical bootstrap policies must not clobber a store policy \
             that landed in between -- this is the silent-policy-revert \
             `seed_bootstrap_policies`'s idempotence exists to prevent"
        );
    }

    // --- ControlPlane::set_budget / TenantBudget storage (WP-50 increment 3c-iii-a) ---

    /// `None` round-trips as unlimited (no `TenantPolicy` at all -- the
    /// tenant falls back to `TenantPolicy::default()`, `budget: None`), and
    /// `Some(TenantBudget { max_micros: 0, .. })` round-trips as a REAL zero
    /// ceiling, never confused with the absent case. Mutation pin A targets
    /// this test: making `None` deserialize/behave as `Some(0)` must turn it
    /// red.
    #[test]
    fn none_budget_round_trips_as_unlimited_and_some_zero_as_a_real_ceiling() {
        let secret_bytes = b"operator-secret";
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        // A tenant nobody has ever set a budget for: `budget` is `None`.
        cp.create_tenant(&TenantId::new("tenant-unset"))
            .expect("create_tenant must succeed");
        let snapshot = cp.handle().load();
        assert!(
            snapshot
                .policies
                .get("tenant-unset")
                .map(|p| p.budget)
                .unwrap_or(None)
                .is_none(),
            "a tenant with no budget ever set must read back as `None` (unlimited), \
             not as a zero ceiling"
        );

        // A tenant with a stored POLICY but no stored budget -- exercises
        // `merge()`'s "policy row present, budget row absent" path
        // specifically (distinct from `tenant-unset` above, which has
        // neither row at all, and hits a different branch of `merge`).
        cp.set_policy(
            &TenantId::new("tenant-policy-only"),
            &ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]),
        )
        .expect("set_policy must succeed");
        let snapshot = cp.handle().load();
        assert!(
            snapshot
                .policies
                .get("tenant-policy-only")
                .expect("the policy row must be present")
                .budget
                .is_none(),
            "a tenant with a stored policy but no stored budget must read back `budget: None`, \
             not a zero ceiling"
        );

        // A tenant with an explicit zero-micro-dollar ceiling: `Some`, and
        // its `max_micros` really is 0.
        let zero_budget = TenantBudget {
            max_micros: MicroUsd::from_micros(0),
            period: Period::Daily,
        };
        cp.set_budget(&TenantId::new("tenant-zero"), Some(&zero_budget))
            .expect("set_budget must succeed");
        let snapshot = cp.handle().load();
        let budget = snapshot
            .policies
            .get("tenant-zero")
            .and_then(|p| p.budget)
            .expect(
                "a tenant with an explicitly configured zero-micro-dollar budget must read \
                 back Some(..), never None",
            );
        assert_eq!(
            budget.max_micros,
            MicroUsd::from_micros(0),
            "the configured ceiling must round-trip as exactly zero, not some other value"
        );
        assert_ne!(
            snapshot.policies.get("tenant-unset").and_then(|p| p.budget),
            snapshot.policies.get("tenant-zero").and_then(|p| p.budget),
            "an unset budget (None) must never compare equal to an explicit zero ceiling \
             (Some(0)) -- collapsing the two is exactly the bug this test pins"
        );
    }

    /// `ControlPlane::set_budget` republishes: the new budget must be visible
    /// through `handle().load()` immediately, with no separate `rebuild()`
    /// call from the test. Mutation pin B (skip `rebuild()` inside
    /// `set_budget`) must turn this red.
    #[test]
    fn set_budget_republishes_immediately() {
        let secret_bytes = b"operator-secret";
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let budget = TenantBudget {
            max_micros: MicroUsd::from_micros(500_000_000),
            period: Period::Monthly,
        };
        cp.set_budget(&TenantId::new("tenant-a"), Some(&budget))
            .expect("set_budget must succeed");

        let snapshot = cp.handle().load();
        assert_eq!(
            snapshot.policies.get("tenant-a").and_then(|p| p.budget),
            Some(budget),
            "a budget set through ControlPlane::set_budget must be visible through the \
             published handle right away -- a set_budget that skipped rebuild() would leave \
             this None"
        );
    }

    /// Clearing a budget (`set_budget(.., None)`) removes it from the
    /// published snapshot and republishes.
    #[test]
    fn clearing_a_budget_removes_it_and_republishes() {
        let secret_bytes = b"operator-secret";
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let budget = TenantBudget {
            max_micros: MicroUsd::from_micros(1_000_000),
            period: Period::Daily,
        };
        cp.set_budget(&TenantId::new("tenant-a"), Some(&budget))
            .expect("set_budget must succeed");
        assert!(cp
            .handle()
            .load()
            .policies
            .get("tenant-a")
            .and_then(|p| p.budget)
            .is_some());

        cp.set_budget(&TenantId::new("tenant-a"), None)
            .expect("clearing a budget must succeed");
        let snapshot = cp.handle().load();
        assert!(
            snapshot
                .policies
                .get("tenant-a")
                .and_then(|p| p.budget)
                .is_none(),
            "set_budget(.., None) must clear the budget in the republished snapshot"
        );
    }

    /// Setting a budget must not clobber an already-set `model_access` for
    /// the SAME tenant. Mutation pin C (make `set_budget`'s merge overwrite
    /// the whole `TenantPolicy` rather than just its `budget` field) must
    /// turn this red.
    #[test]
    fn setting_a_budget_does_not_clobber_model_access() {
        let secret_bytes = b"operator-secret";
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let access = ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]);
        cp.set_policy(&TenantId::new("tenant-a"), &access)
            .expect("set_policy must succeed");

        let budget = TenantBudget {
            max_micros: MicroUsd::from_micros(2_000_000),
            period: Period::Daily,
        };
        cp.set_budget(&TenantId::new("tenant-a"), Some(&budget))
            .expect("set_budget must succeed");

        let snapshot = cp.handle().load();
        let policy = snapshot
            .policies
            .get("tenant-a")
            .expect("tenant must exist");
        assert_eq!(
            policy.model_access, access,
            "setting a budget must not clobber the tenant's already-configured model_access"
        );
        assert_eq!(policy.budget, Some(budget));
    }

    /// The other direction: setting a policy must not clobber an
    /// already-set budget for the same tenant.
    #[test]
    fn setting_a_policy_does_not_clobber_a_budget() {
        let secret_bytes = b"operator-secret";
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let budget = TenantBudget {
            max_micros: MicroUsd::from_micros(3_000_000),
            period: Period::Monthly,
        };
        cp.set_budget(&TenantId::new("tenant-a"), Some(&budget))
            .expect("set_budget must succeed");

        let access = ModelAccess::Only(vec![ModelPattern::new("claude-*")]);
        cp.set_policy(&TenantId::new("tenant-a"), &access)
            .expect("set_policy must succeed");

        let snapshot = cp.handle().load();
        let policy = snapshot
            .policies
            .get("tenant-a")
            .expect("tenant must exist");
        assert_eq!(
            policy.budget,
            Some(budget),
            "setting a policy must not clobber the tenant's already-configured budget"
        );
        assert_eq!(policy.model_access, access);
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

        // WP-50 increment 3c-iii-a.
        let mut a_budgets: Vec<(&str, &TenantBudget)> =
            a.budgets.iter().map(|(t, b)| (t.as_str(), b)).collect();
        let mut b_budgets: Vec<(&str, &TenantBudget)> =
            b.budgets.iter().map(|(t, b)| (t.as_str(), b)).collect();
        a_budgets.sort_by_key(|(t, _)| *t);
        b_budgets.sort_by_key(|(t, _)| *t);
        assert_eq!(a_budgets, b_budgets, "budgets must match");
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

    // --- redb: set_budget then load() returns it; None clears it; parity
    //     with InMemory; persistence across reopen (WP-50 increment 3c-iii-a)

    #[test]
    fn redb_set_budget_then_load_returns_it_and_none_clears_it() {
        let store = RedbControlPlaneStore::in_memory();
        let budget = TenantBudget {
            max_micros: MicroUsd::from_micros(9_000_000),
            period: Period::Daily,
        };
        store
            .set_budget(&TenantId::new("tenant-a"), Some(&budget))
            .unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(
            loaded.budgets.get(&TenantId::new("tenant-a")),
            Some(&budget)
        );

        store.set_budget(&TenantId::new("tenant-a"), None).unwrap();
        let loaded = store.load().unwrap();
        assert!(
            !loaded.budgets.contains_key(&TenantId::new("tenant-a")),
            "set_budget(.., None) must clear the row, not merely blank its value"
        );
    }

    #[test]
    fn redb_persists_a_budget_across_reopen() {
        let path = temp_db_path("budget-persists-across-reopen");
        let budget = TenantBudget {
            max_micros: MicroUsd::from_micros(42_000_000),
            period: Period::Monthly,
        };

        {
            let store = RedbControlPlaneStore::open(&path).unwrap();
            store
                .set_budget(&TenantId::new("tenant-a"), Some(&budget))
                .unwrap();
        }

        let reopened = RedbControlPlaneStore::open(&path).unwrap();
        let loaded = reopened.load().unwrap();
        assert_eq!(
            loaded.budgets.get(&TenantId::new("tenant-a")),
            Some(&budget),
            "a reopened store must still see the budget"
        );

        std::fs::remove_file(&path).ok();
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
            // WP-50 increment 3c-iii-a: a budget IS part of `StoredControlPlane`
            // (unlike spend rows below), so it is compared through
            // `assert_stored_control_planes_match` like `keys`/`policies`.
            store
                .set_budget(
                    &TenantId::new("tenant-a"),
                    Some(&TenantBudget {
                        max_micros: MicroUsd::from_micros(500_000_000),
                        period: Period::Monthly,
                    }),
                )
                .unwrap();
            // WP-50 increment 3c-ii-b: spend rows, keyed `(stat_prefix,
            // tenant, period)`, are not part of `StoredControlPlane` (there
            // is no wholesale `load()` for them -- see the trait doc), so
            // they are checked directly against BOTH stores below rather
            // than through `assert_stored_control_planes_match`.
            store
                .set_spend(
                    "chain-a",
                    &TenantId::new("tenant-a"),
                    &PeriodKey::for_test("2026-08"),
                    12_500_000,
                )
                .unwrap();
        }

        assert_stored_control_planes_match(
            &redb_store.load().unwrap(),
            &inmemory_store.load().unwrap(),
        );

        assert_eq!(
            redb_store
                .load_spend(
                    "chain-a",
                    &TenantId::new("tenant-a"),
                    &PeriodKey::for_test("2026-08"),
                )
                .unwrap(),
            inmemory_store
                .load_spend(
                    "chain-a",
                    &TenantId::new("tenant-a"),
                    &PeriodKey::for_test("2026-08"),
                )
                .unwrap(),
            "redb and InMemory must agree on a spend row written identically to both"
        );
        assert_eq!(
            redb_store
                .load_spend(
                    "chain-a",
                    &TenantId::new("tenant-a"),
                    &PeriodKey::for_test("2026-09"),
                )
                .unwrap(),
            0,
            "a period never written must read as 0, not an error"
        );
        assert_eq!(
            redb_store
                .load_spend(
                    "chain-a",
                    &TenantId::new("tenant-a"),
                    &PeriodKey::for_test("2026-09"),
                )
                .unwrap(),
            inmemory_store
                .load_spend(
                    "chain-a",
                    &TenantId::new("tenant-a"),
                    &PeriodKey::for_test("2026-09"),
                )
                .unwrap(),
            "both stores must agree that an unwritten period reads as 0"
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

    // --- WP-61: policy propagation by version-stamp polling ------------------

    // --- the acceptance criterion itself: two `ControlPlane`s over one store,
    //     one revokes, the other picks it up via `poll_once` -- no shared
    //     `rebuild()` call between them, only the store and the stamp.

    #[test]
    fn a_revocation_on_one_control_plane_reaches_another_sharing_the_store() {
        let secret_bytes = b"operator-secret";
        let shared = Arc::new(InMemoryControlPlaneStore::default());
        let cp_a = ControlPlane::new(
            Box::new(SharedStore(Arc::clone(&shared))),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");
        let cp_b = ControlPlane::new(
            Box::new(SharedStore(Arc::clone(&shared))),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let minted = cp_a
            .mint_key(&TenantId::new("tenant-a"), &KeyId::new("k1"))
            .expect("mint_key must succeed against a healthy store");
        let authenticator_b =
            VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp_b.handle());
        let headers = headers_with_authorization(&format!("Bearer {}", minted.plaintext));

        // `cp_b` booted before the mint, so its own poll must pick the new
        // key up before it can even see it -- this also proves `poll_once`
        // itself does the rebuild, not just `mint_key`'s own `rebuild()` on
        // `cp_a`.
        assert_eq!(
            cp_b.poll_once(),
            Ok(true),
            "a moved generation must trigger a rebuild and report it"
        );
        assert!(
            matches!(
                authenticator_b.authenticate(&headers),
                AuthOutcome::Authenticated(_)
            ),
            "cp_b must see the key cp_a minted, once polled"
        );

        // The revocation itself -- written on `cp_a`, never `rebuild()`-ed on
        // `cp_b` directly. Only `poll_once` closes the gap.
        cp_a.revoke_key(&KeyId::new("k1"))
            .expect("revoke must succeed");

        assert_eq!(
            cp_b.poll_once(),
            Ok(true),
            "the revocation bumped the generation again; poll_once must rebuild once more"
        );
        match authenticator_b.authenticate(&headers) {
            AuthOutcome::Rejected(AuthError::RevokedKey) => {}
            other => panic!(
                "a key revoked on cp_a must stop authenticating on cp_b after poll_once; \
                 got Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // --- a failed poll must leave the published snapshot untouched (same
    //     fail-closed contract as `rebuild`) and must not reset the
    //     reconciliation clock `snapshot_age` reports.

    #[test]
    fn a_failed_poll_leaves_the_published_snapshot_intact_and_ages_it() {
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
            load_calls: Arc::new(AtomicUsize::new(0)),
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

        // Let the snapshot visibly age BEFORE sampling the baseline: sampling
        // it at t=0 would make the final assertion pass even if the failed
        // poll reset the clock, because both readings would be microseconds.
        std::thread::sleep(Duration::from_millis(20));
        let age_before = cp.snapshot_age();

        fail_flag.store(true, Ordering::SeqCst);
        assert!(
            cp.poll_once().is_err(),
            "a stamp read against a failing store must propagate Err"
        );

        assert!(
            matches!(
                authenticator.authenticate(&headers),
                AuthOutcome::Authenticated(_)
            ),
            "a failed poll must keep the last published snapshot, not wipe it"
        );
        assert!(
            cp.snapshot_age() >= age_before,
            "a failed poll must not reset last_reconciled_at -- the snapshot is getting \
             staler, not fresher, while the store is down"
        );
    }

    // --- an unmoved generation must skip `load()` entirely -- the whole
    //     point of polling the stamp instead of re-reading everything.

    #[test]
    fn a_generation_that_has_not_moved_does_no_load_work() {
        let secret_bytes = b"operator-secret";
        let load_calls = Arc::new(AtomicUsize::new(0));
        let store = ToggleStore {
            inner: InMemoryControlPlaneStore::default(),
            fail: Arc::new(AtomicBool::new(false)),
            load_calls: Arc::clone(&load_calls),
        };
        let cp = ControlPlane::new(
            Box::new(store),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let calls_after_boot = load_calls.load(Ordering::SeqCst);
        assert_eq!(
            calls_after_boot, 1,
            "ControlPlane::new must load() exactly once at boot"
        );

        assert_eq!(
            cp.poll_once(),
            Ok(false),
            "nothing wrote to the store since boot -- the generation has not moved"
        );
        assert_eq!(
            load_calls.load(Ordering::SeqCst),
            calls_after_boot,
            "poll_once must not call load() when the generation stamp is unchanged"
        );
    }

    // --- every tier-2 write bumps InMemoryControlPlaneStore's generation;
    //     set_spend (tier-3) and a revoke of an unknown key (nothing written)
    //     must not.

    #[test]
    fn every_tier_two_write_bumps_the_generation_and_a_spend_write_does_not() {
        let store = InMemoryControlPlaneStore::default();
        assert_eq!(store.policy_generation().unwrap(), 0);

        let tenant = TenantId::new("tenant-a");
        let mut expected = 0u64;

        store.create_tenant(&tenant).unwrap();
        expected += 1;
        assert_eq!(store.policy_generation().unwrap(), expected);

        store
            .put_key(&StoredKey {
                key_id: KeyId::new("k1"),
                digest: digest_bytes(b"secret", "llmp_a"),
                tenant: tenant.clone(),
                revoked: false,
            })
            .unwrap();
        expected += 1;
        assert_eq!(store.policy_generation().unwrap(), expected);

        store.set_policy(&tenant, &ModelAccess::All).unwrap();
        expected += 1;
        assert_eq!(store.policy_generation().unwrap(), expected);

        let budget = TenantBudget {
            max_micros: MicroUsd::from_micros(1_000_000),
            period: Period::Monthly,
        };
        store.set_budget(&tenant, Some(&budget)).unwrap();
        expected += 1;
        assert_eq!(store.policy_generation().unwrap(), expected);

        store.revoke_key(&KeyId::new("k1")).unwrap();
        expected += 1;
        assert_eq!(store.policy_generation().unwrap(), expected);

        // Revoking an UNKNOWN key writes nothing -- must not bump.
        assert!(matches!(
            store.revoke_key(&KeyId::new("no-such-key")),
            Err(StoreError::NotFound)
        ));
        assert_eq!(
            store.policy_generation().unwrap(),
            expected,
            "a NotFound revoke wrote nothing and must not bump the generation"
        );

        // set_spend is tier-3, not tier-2 -- must never bump.
        store
            .set_spend(
                "chain-a",
                &tenant,
                &PeriodKey::for_test("2026-09"),
                5_000_000,
            )
            .unwrap();
        assert_eq!(
            store.policy_generation().unwrap(),
            expected,
            "set_spend is a tier-3 write and must never bump the tier-2 policy generation"
        );

        store.delete_tenant(&tenant).unwrap();
        expected += 1;
        assert_eq!(store.policy_generation().unwrap(), expected);
    }

    // --- same contract, against RedbControlPlaneStore -- proves the bump is
    //     inside the SAME write transaction as the accompanying write, not a
    //     separately committed (and therefore possibly torn) step.

    #[test]
    fn redb_bumps_the_generation_on_tier_two_writes_only() {
        let path = temp_db_path("generation-bumps");
        let store = RedbControlPlaneStore::open(&path).unwrap();
        assert_eq!(store.policy_generation().unwrap(), 0);

        let tenant = TenantId::new("tenant-a");
        let mut expected = 0u64;

        store.create_tenant(&tenant).unwrap();
        expected += 1;
        assert_eq!(store.policy_generation().unwrap(), expected);

        store
            .put_key(&StoredKey {
                key_id: KeyId::new("k1"),
                digest: digest_bytes(b"secret", "llmp_a"),
                tenant: tenant.clone(),
                revoked: false,
            })
            .unwrap();
        expected += 1;
        assert_eq!(store.policy_generation().unwrap(), expected);

        store.set_policy(&tenant, &ModelAccess::All).unwrap();
        expected += 1;
        assert_eq!(store.policy_generation().unwrap(), expected);

        let budget = TenantBudget {
            max_micros: MicroUsd::from_micros(1_000_000),
            period: Period::Monthly,
        };
        store.set_budget(&tenant, Some(&budget)).unwrap();
        expected += 1;
        assert_eq!(store.policy_generation().unwrap(), expected);

        store.revoke_key(&KeyId::new("k1")).unwrap();
        expected += 1;
        assert_eq!(store.policy_generation().unwrap(), expected);

        assert!(matches!(
            store.revoke_key(&KeyId::new("no-such-key")),
            Err(StoreError::NotFound)
        ));
        assert_eq!(store.policy_generation().unwrap(), expected);

        store
            .set_spend(
                "chain-a",
                &tenant,
                &PeriodKey::for_test("2026-09"),
                5_000_000,
            )
            .unwrap();
        assert_eq!(
            store.policy_generation().unwrap(),
            expected,
            "set_spend must not bump the redb-backed generation either"
        );

        store.delete_tenant(&tenant).unwrap();
        expected += 1;
        assert_eq!(store.policy_generation().unwrap(), expected);

        std::fs::remove_file(&path).ok();
    }

    // --- the poller thread itself, not just poll_once -- proves
    //     start_policy_poller actually drives poll_once on a timer and picks
    //     up a revocation with no test code calling poll_once directly.
    //     Bounded: polls a condition in a loop with a hard deadline rather
    //     than an unbounded sleep, so a regression fails fast instead of
    //     hanging out nextest's `terminate-after`.

    #[test]
    fn the_policy_poller_thread_picks_up_a_revocation_on_its_own() {
        let secret_bytes = b"operator-secret";
        let shared = Arc::new(InMemoryControlPlaneStore::default());
        let cp_a = Arc::new(
            ControlPlane::new(
                Box::new(SharedStore(Arc::clone(&shared))),
                HmacSecret::new(secret_bytes),
                KeySet::new(),
            )
            .expect("empty store must not fail boot"),
        );
        let cp_b = Arc::new(
            ControlPlane::new(
                Box::new(SharedStore(Arc::clone(&shared))),
                HmacSecret::new(secret_bytes),
                KeySet::new(),
            )
            .expect("empty store must not fail boot"),
        );

        let minted = cp_a
            .mint_key(&TenantId::new("tenant-a"), &KeyId::new("k1"))
            .expect("mint_key must succeed against a healthy store");
        let authenticator_b =
            VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp_b.handle());
        let headers = headers_with_authorization(&format!("Bearer {}", minted.plaintext));

        // A short interval -- this test's own bound is a small multiple of
        // it, not the real 48s default (see `parse_poll_interval`'s doc).
        cp_b.start_policy_poller(Duration::from_millis(20));

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(
                authenticator_b.authenticate(&headers),
                AuthOutcome::Authenticated(_)
            ) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the policy poller must pick up cp_a's mint within the test's bound"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        cp_a.revoke_key(&KeyId::new("k1"))
            .expect("revoke must succeed");

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(
                authenticator_b.authenticate(&headers),
                AuthOutcome::Rejected(AuthError::RevokedKey)
            ) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the policy poller must pick up cp_a's revoke within the test's bound, with \
                 no test code calling poll_once directly"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
