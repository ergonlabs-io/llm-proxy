//! Control-plane stores, the immutable snapshot published to request workers,
//! and the admin writes that rebuild it. Authentication reads the shared
//! snapshot on each request; store I/O stays off the hot path.
//!
//! At boot, a failed load is fatal because there is no safe snapshot to serve.
//! On refresh, a failed load leaves the last good snapshot published and logs
//! a warning, avoiding an outage from a transient store failure (AGENTS.md
//! "Fail-open controls").
//!
//! [`VirtualKeyAuthenticator`]: crate::auth::VirtualKeyAuthenticator

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use rand::Rng;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::auth::{HmacSecret, KeyId, KeyRecord, KeySet, TenantId, TenantPolicy};
use crate::model_authz::{ModelAccess, ModelPattern, TenantPolicyMap};
use crate::tenant_credential_crypto::{
    self as credential_crypto, CryptoError, KeyRing, TenantSecret,
};
use proxy_credentials::{CredentialSource, TenantCredential, TenantCredentialSet};
use proxy_observability::chargeback::ChargebackTags;
use zeroize::Zeroizing;
// Spend owns period-key and calendar-alignment logic; this module only stores
// and retrieves the resulting keys.
use crate::spend::{key_spend_subject, KeyBudget, PeriodKey, TenantBudget};

/// Names a key's row in both the budgets and policies tables.
fn key_budget_subject(key_id: &KeyId) -> TenantId {
    key_spend_subject(key_id)
}

/// Recovers the key identity from its budgets or policies table subject.
pub(crate) fn key_id_from_budget_subject(subject: &TenantId) -> Option<KeyId> {
    subject.as_str().strip_prefix("\u{1f}key:").map(KeyId::new)
}

fn reject_control_characters(field: &str, id: &str) -> Result<(), StoreError> {
    if id.chars().any(|ch| ch.is_ascii_control()) {
        return Err(StoreError::InvalidInput(format!(
            "{field} contains an ASCII control character"
        )));
    }
    Ok(())
}

/// Request records give `default` and `unauthenticated` their own meanings
/// (ADR-0011 decision 3); a tenant under either name would be
/// indistinguishable from them. Tenants that already exist are untouched.
fn reject_reserved_tenant(tenant: &TenantId) -> Result<(), StoreError> {
    if proxy_observability::records::RESERVED_TENANT_IDS.contains(&tenant.as_str()) {
        return Err(StoreError::InvalidInput(format!(
            "tenant `{}` is reserved for request records",
            tenant.as_str()
        )));
    }
    Ok(())
}

/// Persisted admin-write shape. Rebuild converts rows to the digest-keyed
/// [`KeySet`] before publishing; request workers never see `StoredKey`.
#[derive(Clone)]
pub struct StoredKey {
    pub key_id: KeyId,
    pub digest: [u8; 32],
    pub tenant: TenantId,
    pub revoked: bool,
    /// Chargeback tags the admin set on the key (key metadata). Empty when
    /// none; validated by `chargeback::validate_key_tags` before a write.
    pub tags: ChargebackTags,
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
            .field("tags", &self.tags)
            .finish()
    }
}

/// One tenant provider credential exactly as a [`ControlPlaneStore`]
/// persists it (ADR-0007). Only ciphertext is stored: [`ControlPlane::rebuild`]
/// decrypts rows into the snapshot, and nothing on the request path sees a
/// `StoredTenantCredential`.
///
/// Plain byte fields keep the storage format independent of the crypto type.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredTenantCredential {
    pub schema_version: u16,
    pub tenant: TenantId,
    pub provider: String,
    /// Id of the key-encryption key that sealed `ciphertext`.
    pub key_id: String,
    pub nonce: [u8; 12],
    /// AES-256-GCM output, tag included.
    pub ciphertext: Vec<u8>,
    pub last4: String,
    pub fingerprint: String,
    /// RFC 3339 timestamps, as written by the admin API.
    pub created_at: String,
    pub updated_at: String,
    pub verified_at: Option<String>,
}

// Rust note: hand-written `Debug`, like `StoredKey`'s. A derive would print
// `nonce` and `ciphertext` byte-for-byte; they are not plaintext, but a log
// line or panic message holding sealed credentials is exactly what a copied
// database is, so only their lengths are rendered (ADR-0007 decision 2).
impl std::fmt::Debug for StoredTenantCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredTenantCredential")
            .field("schema_version", &self.schema_version)
            .field("tenant", &self.tenant)
            .field("provider", &self.provider)
            .field("key_id", &self.key_id)
            .field("nonce_len", &self.nonce.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .field("last4", &self.last4)
            .field("fingerprint", &self.fingerprint)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("verified_at", &self.verified_at)
            .finish()
    }
}

/// One filter chain's rate card exactly as a [`ControlPlaneStore`] persists
/// it (ADR-0006 §1 puts price in tier 2: read per request, written rarely,
/// and versioned).
///
/// The store treats the card as an opaque document. `card_json` is the
/// validated pricing document that `PUT /pricing` accepts and `GET /pricing`
/// serves, and only `proxy_filters::usage_filter` parses it. That keeps price
/// arithmetic out of the storage layer and lets a store hold a card that a
/// newer or older build would read differently.
///
/// Keyed by `chain`, the usage filter's `stat_prefix`: the registry is per
/// chain, so one global card would re-price chains that were configured
/// differently on purpose.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredRateCard {
    /// The chain's operator-chosen `stat_prefix`.
    pub chain: String,
    /// The card's `rate_card_version` as the writer computed it. Informational
    /// for a reader: each build recomputes the version from `card_json`, so
    /// two builds that hash differently still agree on the content.
    pub version: String,
    /// The pricing document, as compact JSON.
    pub card_json: String,
    /// [`RATE_CARD_SCHEMA_V1`], or [`RATE_CARD_SCHEMA_V2`] for a card that
    /// uses a field added by ADR-0010 (a price basis, modality rates, image
    /// prices). An older replica skips a v2 row and keeps its last card,
    /// rather than misreading one (ADR-0010 decision 3, "Mixed fleets").
    pub schema_version: u16,
}

/// A rate card that uses only the original token fields.
pub const RATE_CARD_SCHEMA_V1: u16 = 1;
/// A rate card that uses a field added by ADR-0010.
pub const RATE_CARD_SCHEMA_V2: u16 = 2;

// Rust note: hand-written, not derived. A derived `Debug` would print the
// whole document, which for the shipped OpenRouter card is a quarter of a
// megabyte inside every failed assertion; the length is enough to tell two
// cards apart in a test failure.
impl std::fmt::Debug for StoredRateCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredRateCard")
            .field("chain", &self.chain)
            .field("version", &self.version)
            .field("schema_version", &self.schema_version)
            .field("card_json_len", &self.card_json.len())
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
    // A tenant's budget, keyed independently of
    // `policies` above -- a tenant can have a stored `ModelAccess`, a stored
    // `TenantBudget`, both, or neither, and [`ControlPlane::merge`] combines
    // them by tenant rather than assuming one row implies the other. See
    // that function's doc for why this is deliberate, not an oversight.
    pub budgets: HashMap<TenantId, TenantBudget>,
    /// Key budgets, filed in the same budgets table under the key's subject
    /// (see [`EncodedKeyBudget`]) and split out on load.
    pub key_budgets: HashMap<KeyId, KeyBudget>,
    pub limits: HashMap<TenantId, LimitPolicy>,
    /// Every tenant credential row. A store that does not support them yet
    /// returns an empty list here and refuses writes.
    pub tenant_credentials: Vec<StoredTenantCredential>,
    /// Every readable rate card, one per chain. A row this build cannot read
    /// is left out and logged; it never fails the load (see
    /// [`decode_rate_card_row`] for why a price must not hold up a
    /// revocation). A store without rate card support returns an empty list.
    pub rate_cards: Vec<StoredRateCard>,
    /// Tenants that opted in to trace export (ADR-0008 decision 2). A tenant
    /// without a row is not opted in. A store without opt-in support returns
    /// an empty set and refuses writes.
    pub trace_export: HashSet<TenantId>,
}

/// Optional per-process rate ceilings. An absent field sets no ceiling at
/// this level; zero explicitly refuses all traffic for that counter. Tenant
/// and key ceilings are independent buckets, and both apply when configured.
/// With N replicas, local counters can admit up to N times a ceiling until a
/// shared counter backend exists (AGENTS.md "Policy Domains").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LimitPolicy {
    pub tokens_per_minute: Option<u64>,
    pub requests_per_minute: Option<u64>,
    pub concurrent_streams: Option<u32>,
}

impl LimitPolicy {
    fn is_empty(self) -> bool {
        self.tokens_per_minute.is_none()
            && self.requests_per_minute.is_none()
            && self.concurrent_streams.is_none()
    }
}

/// Version 2 uses stable key budget subjects; absent versions are legacy version 1.
pub const SPEND_SCHEMA_VERSION: u32 = 2;
fn legacy_schema_version() -> u32 {
    1
}
fn read_schema_version<'de, D: serde::Deserializer<'de>>(de: D) -> Result<u32, D::Error> {
    let version = <u32 as serde::Deserialize>::deserialize(de)?;
    if matches!(version, 1 | SPEND_SCHEMA_VERSION) {
        Ok(version)
    } else {
        Err(serde::de::Error::custom(format!(
            "unsupported spend schema version {version}"
        )))
    }
}

fn validate_key_update(previous: &StoredKey, next: &StoredKey) -> Result<(), StoreError> {
    if previous.tenant != next.tenant {
        return Err(StoreError::Conflict("key ownership is immutable".into()));
    }
    if previous.revoked && (!next.revoked || previous.digest != next.digest) {
        return Err(StoreError::Conflict(
            "revoked key IDs cannot be reused".into(),
        ));
    }
    Ok(())
}

/// Why a [`ControlPlaneStore`] call failed.
///
/// Deliberately small (`InMemoryControlPlaneStore`'s writes
/// are infallible; the `redb` and Redis stores map their I/O errors onto it),
/// because the two call sites that interpret it -- [`ControlPlane::new`]
/// (hard error) and [`ControlPlane::rebuild`] (log and keep serving) -- do
/// not need to distinguish reasons, only "it failed".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The backend could not be reached or read at all.
    Unavailable(String),
    /// A write targeted a row the store has never seen (e.g. revoking an
    /// unknown `key_id`).
    NotFound,
    /// Stable key ownership or terminal revocation forbids this update.
    Conflict(String),
    /// The caller supplied a value the store must never hold (for example an
    /// over-long principal id). Maps to a client error, not a store outage.
    InvalidInput(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Unavailable(reason) => {
                write!(f, "control-plane store unavailable: {reason}")
            }
            StoreError::NotFound => write!(f, "control-plane store: not found"),
            StoreError::Conflict(reason) => write!(f, "control-plane store conflict: {reason}"),
            StoreError::InvalidInput(reason) => write!(f, "invalid input: {reason}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Identifies ONE spend flush attempt, so [`ControlPlaneStore::add_spend`]
/// can drop a replay instead of charging twice. ADR-0006 §2.
///
/// # Both fields are required, and the `node_id` is the one that is easy to
/// drop
///
/// A store MUST compare `seq` against the highest sequence it has accepted
/// **for this `node_id` and this spend row**, and apply the delta only when
/// `seq` is strictly greater. Dedup state keyed by `seq` alone is the trap
/// this type exists to prevent: two replicas both reach seq 7, the store
/// treats the second one as a duplicate and silently drops a real charge, and
/// spend goes missing exactly the way the absolute writes it replaced used to
/// lose it. The bug arrives from the opposite direction and looks impossible,
/// because additive writes are supposed to have fixed precisely this.
///
/// `node_id` comes from `service_node` / `NodeIdentity`, which already exists
/// as an xDS concept; this path is what makes it REQUIRED rather than
/// optional. Two replicas sharing one node id are indistinguishable to the
/// store and WILL lose each other's writes, so the caller is responsible for
/// it being genuinely per-replica -- see
/// [`crate::spend::SpendAccumulator::new`]'s doc for how that is enforced.
///
/// # Why a sequence number and not a UUID
///
/// A monotonic per-row sequence lets the store keep ONE `u64` per
/// (writer, row) instead of an ever-growing set of seen tokens with a
/// retention policy of its own. "Highest accepted wins" is O(1) state and
/// needs no expiry. The cost is that the caller must not advance its sequence
/// until a write is CONFIRMED -- an unconfirmed attempt has to be retried
/// under the SAME number, or the retry is a fresh charge rather than a
/// replay. [`crate::spend::SpendAccumulator`]'s flusher does exactly that.
///
/// Borrowed rather than owned: the node id is fixed for the process's
/// lifetime and one is built per bucket per flush, so there is no reason to
/// allocate a `String` on each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushToken<'a> {
    /// This replica's identity. See the type doc: dedup keyed without it
    /// loses spend across replicas.
    pub node_id: &'a str,
    /// Monotonic per spend row, per writer. Advances only after a confirmed
    /// write.
    pub seq: u64,
}

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
///
/// # Counters only. Usage history does not belong here.
///
/// The spend rows this trait holds ([`Self::add_spend`]) are CURRENT-WINDOW
/// COUNTERS and nothing else. Per-request usage history is EXPORTED --
/// access logs and the usage filter -- and is never written into this store.
/// ADR-0006 §7 puts this sentence in the trait's own doc rather than only in
/// a backlog note, because the trait is what the next person reads, and
/// The moment the pressure would arrive is easy to predict:
///
/// > the day a shared store arrives for rate limiting, writing usage history
/// > into it will be tempting because the dependency is already there -- that
/// > is how (b) arrives without anyone deciding it.
///
/// The owner decided export-only on 2026-09-06 and that decision stands. A
/// counter store sized for a bounded set of live windows becomes an unbounded
/// event log the moment history lands in it, with a retention question, a
/// cardinality question, and a privacy question nobody scoped.
///
/// # Policy calls and spend calls must not queue behind each other
///
/// The policy poller calls [`Self::policy_generation`] and [`Self::load`] (the
/// whole policy state in one call) and the admin API calls the tier-2 writes.
/// The spend flusher calls [`Self::add_spend_batch`],
/// [`Self::last_flush_seq_batch`] and [`Self::load_spend_batch`], and
/// bind-time prefetch calls [`Self::load_spend_batch`]. A store that funnels
/// both groups through one shared resource (a connection, a lock) lets each
/// delay the other: a long flush delays a revocation pickup, a large load
/// delays reconciliation. ADR-0006 §4 keeps the two on separate intervals for
/// the same reason, and a store with such a resource gives the spend group its
/// own, as [`crate::control_redis::RedisControlPlaneStore`] does with a
/// connection per group.
pub trait ControlPlaneStore: Send + Sync {
    /// The snapshot-build read: everything a rebuild needs, in one call.
    fn load(&self) -> Result<StoredControlPlane, StoreError>;

    /// A monotonic counter bumped by every TIER-2 write -- tenants, keys,
    /// policies, budgets, tenant credentials, rate cards -- and NEVER by a
    /// spend write (ADR-0006 §3).
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
    /// ADR-0006 §1's tier table). [`Self::add_spend`] and [`Self::overwrite_spend`] do not call this.
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

    // Tier-2 writes. The data plane never calls any of these -- only the
    // admin API does, off the request path.
    fn create_tenant(&self, tenant: &TenantId) -> Result<(), StoreError>;
    fn delete_tenant(&self, tenant: &TenantId) -> Result<(), StoreError>;
    /// Creates or replaces the credential row for (`rec.tenant`,
    /// `rec.provider`) and bumps the generation. Deleting a tenant must also
    /// delete its credential rows in the same write.
    ///
    /// The default refuses the write. A store without credential support
    /// therefore fails closed instead of accepting a key it cannot hold.
    fn put_tenant_credential(&self, rec: &StoredTenantCredential) -> Result<(), StoreError> {
        let _ = rec;
        Err(StoreError::Unavailable(
            "tenant credentials are not supported by this store".into(),
        ))
    }
    /// Deletes one credential row and bumps the generation.
    /// [`StoreError::NotFound`] if there was no such row, without a bump.
    fn delete_tenant_credential(
        &self,
        tenant: &TenantId,
        provider: &str,
    ) -> Result<(), StoreError> {
        let _ = (tenant, provider);
        Err(StoreError::Unavailable(
            "tenant credentials are not supported by this store".into(),
        ))
    }
    /// Creates or rotates a stable key atomically. Ownership is immutable;
    /// revoked IDs are permanent tombstones. Updating an active key's digest
    /// immediately replaces its secret with no overlap, preserving budget/spend.
    fn put_key(&self, rec: &StoredKey) -> Result<(), StoreError>;
    /// Sets `revoked = true` on the row named by `key_id` and keeps it (the
    /// audit trail survives a revoke) -- see `StoredKey::revoked`'s use in
    /// [`ControlPlane::rebuild`] for why the row is not deleted.
    fn revoke_key(&self, key_id: &KeyId) -> Result<(), StoreError>;
    fn set_policy(&self, tenant: &TenantId, access: &ModelAccess) -> Result<(), StoreError>;

    /// Sets or clears `tenant`'s spend budget.
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

    /// Sets or clears a key's spend budget, the key-level twin of
    /// [`Self::set_budget`]. Each write bumps the policy generation.
    fn set_key_budget(&self, key_id: &KeyId, budget: Option<&KeyBudget>) -> Result<(), StoreError>;

    /// An absent or all-empty policy removes the row. Each write bumps the
    /// policy generation, including removals.
    fn set_limits(
        &self,
        subject: &TenantId,
        limits: Option<&LimitPolicy>,
    ) -> Result<(), StoreError>;

    /// Creates or replaces the rate card for `card.chain` and bumps the
    /// generation, in one atomic write. Price is tier-2 state (ADR-0006 §1),
    /// so it propagates like a policy: the other replicas notice the bump on
    /// their next poll and re-read (§3).
    ///
    /// The card and the bump land together or not at all. A card without a
    /// bump is never noticed by another replica's poller, which compares only
    /// the stamp. A bump without the card makes every replica rebuild for
    /// nothing. Redis does both in one `MULTI`/`EXEC`, redb in one write
    /// transaction, and the in-memory store under one lock.
    ///
    /// Bumps unconditionally, even when the stored card is byte-identical, for
    /// the reason [`Self::policy_generation`] gives: a missed bump never
    /// propagates, a spurious one costs one rebuild.
    ///
    /// The default refuses the write. A store without rate card support
    /// therefore fails closed instead of accepting a card it cannot hold,
    /// which is the rule [`Self::put_tenant_credential`] follows.
    fn put_rate_card(&self, card: &StoredRateCard) -> Result<(), StoreError> {
        let _ = card;
        Err(StoreError::Unavailable(
            "rate cards are not supported by this store".into(),
        ))
    }

    /// As [`Self::put_rate_card`], but writes only when the store has no row
    /// for `card.chain`. Returns `Ok(true)` when it wrote, and `Ok(false)`
    /// when a row was already there, in which case nothing is written and the
    /// generation does not move. A row this build cannot read still counts as
    /// there: it is somebody's card, and overwriting it would hide it.
    ///
    /// This is how a configured card seeds the store at boot, the way
    /// `ControlPlane::seed_bootstrap_policies` seeds policies. The check and
    /// the write must be one atomic step. With a separate read first, a
    /// replica booting at the same moment an operator publishes a card could
    /// overwrite the operator's card with its configured one.
    ///
    /// The default refuses, for the reason [`Self::put_rate_card`] gives.
    fn put_rate_card_if_absent(&self, card: &StoredRateCard) -> Result<bool, StoreError> {
        let _ = card;
        Err(StoreError::Unavailable(
            "rate cards are not supported by this store".into(),
        ))
    }

    /// Records whether `tenant` opted in to trace export (ADR-0008
    /// decision 2) and bumps the generation in the same write; `false`
    /// removes the row. Deleting a tenant must delete its row in the same
    /// write.
    ///
    /// The default refuses the write, so a store without opt-in support
    /// fails closed: a tenant cannot be recorded as consenting where the
    /// row would not survive a rebuild.
    fn set_trace_export(&self, tenant: &TenantId, enabled: bool) -> Result<(), StoreError> {
        let _ = (tenant, enabled);
        Err(StoreError::Unavailable(
            "trace export opt-in is not supported by this store".into(),
        ))
    }

    /// Whether what this store holds survives a restart of this process. The
    /// admin API uses it to say honestly whether a published rate card was
    /// persisted. `false` is the safe default: claiming durability a store
    /// does not have is the one wrong answer.
    fn is_durable(&self) -> bool {
        false
    }

    /// Whether other replicas read and write the same rows through their own
    /// handles, so this replica's local counters are not the whole fleet.
    /// Not the same question as [`Self::is_durable`]: redb survives a restart
    /// but belongs to one process. `GET /v1/usage` uses it to decide between
    /// the local exact answer and a store read (ADR-0006 addendum §4).
    /// `false` is the safe default: a store wrongly called shared only costs
    /// a store read, but one wrongly called local reports a replica's own
    /// counters as the fleet's.
    fn is_shared(&self) -> bool {
        false
    }

    // Object ownership. A provider issues file and batch IDs in one namespace
    // per provider account, and every tenant reaches the provider through the
    // proxy's account, so only the proxy knows which tenant created an
    // object. These rows record that. They are not tier-2 policy: `load`
    // does not return them and writing one bumps no generation, because a
    // row per created object would make every replica reload the whole store
    // on every create. The data plane writes them, off the worker, as the
    // provider answers a create. A row claimed with a time to live expires
    // (ADR-0013 §6); any other row is never removed: deleting a tenant leaves
    // its rows, so a tenant id must not be reused for another customer while
    // its objects exist at the provider.

    /// Records `tenant` as the owner of `object_id` unless the object
    /// already has a live owner, and returns the owner the store holds
    /// afterwards. Never overwrites or extends a live row: a claim by a
    /// second tenant returns the first. A row past its expiry is absent, so a
    /// claim replaces it. With `ttl` the new row expires that long from now
    /// (whole seconds); without, it never does. The row returned may already
    /// be past its expiry (a zero `ttl`, or replicas whose clocks disagree),
    /// so a caller checks [`ObjectOwner::is_live`].
    ///
    /// The default refuses, so a store without ownership rows fails closed:
    /// an object whose owner cannot be recorded stays unreachable.
    fn claim_object(
        &self,
        object_id: &str,
        tenant: &TenantId,
        ttl: Option<Duration>,
    ) -> Result<ObjectOwner, StoreError> {
        let _ = (object_id, tenant, ttl);
        Err(StoreError::Unavailable(
            "object ownership is not supported by this store".into(),
        ))
    }

    /// The live owner of `object_id`, or `None` when none has claimed it or
    /// its row has expired. The default refuses, for the reason
    /// [`Self::claim_object`]'s does.
    fn object_owner(&self, object_id: &str) -> Result<Option<ObjectOwner>, StoreError> {
        let _ = object_id;
        Err(StoreError::Unavailable(
            "object ownership is not supported by this store".into(),
        ))
    }

    // Spend rows, keyed `(stat_prefix, tenant,
    // period)`. `stat_prefix` is a plain `&str` (not this crate's
    // `TenantId`/`KeyId` newtypes) because it names a FILTER CHAIN by its
    // external, Envoy-style name -- the same operator-chosen `stat_prefix`
    // the admin server uses to address a chain.
    /// Adds `delta_micros` to the spend total for `(stat_prefix, tenant,
    /// period)` and returns the **new authoritative total**. ADR-0006 §2,
    /// which is normative for this method.
    ///
    /// Three properties, each load-bearing, and none of them optional for an
    /// implementation of this trait:
    ///
    /// **Additive.** Deltas compose, so two writers cannot clobber each
    /// other. The absolute write this replaced was last-writer-wins: A
    /// flushes 1300, B flushes 1200, the row reads 1200, and A's spend is
    /// silently GONE. Under-counting makes budgets trip late or never, which
    /// is the unsafe direction for a spend ceiling. `INCRBY` in Redis; a
    /// read-modify-write inside ONE transaction here and in redb.
    ///
    /// **Idempotent per writer, via `token`.** Additive writes are not
    /// idempotent on their own -- a retried delta double-charges -- so the
    /// caller carries a [`FlushToken`] and the store drops a replay. An
    /// implementation MUST key its dedup state per writer
    /// ([`FlushToken::node_id`]) and MUST NOT key it by the sequence number
    /// alone: two replicas both emit seq 7, a store that dedups on the
    /// number alone treats the second as a duplicate and drops it, and spend
    /// is lost again -- the original bug through the opposite door, now
    /// disguised by additive writes that look like they made it impossible.
    /// See [`FlushToken`]'s own doc for the required comparison.
    ///
    /// **Returns the new total.** `INCRBY` returns it for free and redb can
    /// too, so every flush hands back the authoritative global number at no
    /// extra cost and [`crate::spend::SpendAccumulator`] adopts it as its new
    /// base. This is what makes the flusher a RECONCILIATION POINT rather
    /// than a write-only mirror, and it is what fixes enforcement across
    /// replicas without leases, extra round trips, or hot-path I/O.
    ///
    /// A deduplicated call is not an error: it returns the current total
    /// unchanged, exactly as if the delta had been applied once (which, on
    /// the accepted attempt, it was). The caller cannot tell the difference
    /// and must not need to.
    ///
    /// A `delta_micros` of `0` is legal: it applies nothing and returns the
    /// total. [`crate::spend::SpendAccumulator`] does not send one; it learns
    /// what the other replicas spent on a row it owes nothing with
    /// [`Self::load_spend_batch`] instead, which neither writes nor uses up a
    /// flush sequence.
    fn add_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        delta_micros: u64,
        token: FlushToken<'_>,
    ) -> Result<u64, StoreError>;

    /// Sets the ABSOLUTE spend total for `(stat_prefix, tenant, period)`,
    /// overwriting whatever was stored.
    ///
    /// # ADMIN ONLY. The flush path must never reach this.
    ///
    /// This exists for an operator zeroing or correcting a tenant's spend,
    /// and for nothing else. It is last-writer-wins by construction, so a
    /// second writer's total is silently discarded -- which is precisely the
    /// bug [`Self::add_spend`] was introduced to fix (ADR-0006 §2). The
    /// hazard existed in the first place partly because ONE method served
    /// both purposes and only its doc distinguished them; the rename is the
    /// guard rail, so do not route flushing back through here for
    /// convenience.
    ///
    /// It also does not touch dedup state. An `overwrite_spend` followed by
    /// a replayed [`Self::add_spend`] with an already-seen token stays
    /// deduplicated: the operator's correction stands, and the replay does
    /// not re-apply on top of it.
    fn overwrite_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        total_micros: u64,
    ) -> Result<(), StoreError>;

    /// The highest flush sequence this store has accepted from `node_id` for
    /// this spend row, or `0` if it has accepted none.
    ///
    /// # This is what makes a RESTART safe, and it is not optional
    ///
    /// [`Self::add_spend`] drops a token whose `seq` is not greater than the
    /// last one accepted from the same writer. A replica that restarts and
    /// begins counting from 1 again would therefore have every flush
    /// silently dropped until it caught up with its own pre-restart
    /// sequence -- spend accruing in memory, the store never moving, and no
    /// error anywhere. [`crate::spend::SpendAccumulator`]'s flusher calls
    /// this once per spend row to seed itself with `last + 1`, so the
    /// sequence continues across restarts without the store having to
    /// remember which process wrote it.
    ///
    /// A caller that cannot read this MUST NOT guess: flushing under a
    /// guessed sequence is exactly the silent-loss case above. Skip the
    /// flush and retry -- the spend is still in memory, and enforcement
    /// reads memory, not the store.
    fn last_flush_seq(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        node_id: &str,
    ) -> Result<u64, StoreError>;

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

    // Batched spend calls. The flusher and the bind-time prefetch touch every
    // live spend row, so one round trip per row grows with the number of keys
    // (review H5: 20k keys made 80k sequential reads before a listener could
    // bind). A store with a network hop sends a batch in as few round trips
    // as it can; the defaults below call the single-row methods in order,
    // which is right for a store with no round trip to save.
    //
    // Every batch answers one result per input row, in input order. A store
    // that sends rows in groups may fail a whole group together (every row of
    // it gets the error), and a row of a failed group may still have been
    // applied: the caller retries under the same token, and the store's
    // dedup makes that a no-op, exactly as for a single `add_spend` whose
    // response was lost.

    /// [`Self::add_spend`] for many rows of one `stat_prefix`, all written by
    /// `node_id`. Each result is that row's new total or its error.
    fn add_spend_batch(
        &self,
        stat_prefix: &str,
        node_id: &str,
        rows: &[SpendDelta<'_>],
    ) -> Vec<Result<u64, StoreError>> {
        rows.iter()
            .map(|row| {
                self.add_spend(
                    stat_prefix,
                    row.tenant,
                    row.period,
                    row.delta_micros,
                    FlushToken {
                        node_id,
                        seq: row.seq,
                    },
                )
            })
            .collect()
    }

    /// [`Self::last_flush_seq`] for many rows of one `stat_prefix`.
    fn last_flush_seq_batch(
        &self,
        stat_prefix: &str,
        node_id: &str,
        rows: &[(TenantId, PeriodKey)],
    ) -> Vec<Result<u64, StoreError>> {
        rows.iter()
            .map(|(tenant, period)| self.last_flush_seq(stat_prefix, tenant, period, node_id))
            .collect()
    }

    /// [`Self::load_spend`] for many rows of one `stat_prefix`.
    fn load_spend_batch(
        &self,
        stat_prefix: &str,
        rows: &[(TenantId, PeriodKey)],
    ) -> Vec<Result<u64, StoreError>> {
        rows.iter()
            .map(|(tenant, period)| self.load_spend(stat_prefix, tenant, period))
            .collect()
    }

    // Tier-3 window counters (ADR-0006 amendment C). They follow the spend
    // contract: additive deltas, dedup that keeps the highest accepted `seq`
    // per (scope, row, node_id), and a replayed or older `seq` is a no-op that
    // returns the current total. They never bump `policy_generation`, and rows
    // expire `WINDOW_ROW_GRACE_SECS` after their window ends. There are no
    // defaults: every store decides how it retains and batches them. Every
    // batch answers one result per row, in input order.

    /// Adds each row's delta under `(scope, node_id)` and returns the new
    /// total per row. `scope` plays the role `stat_prefix` plays for spend
    /// (the filter chain), so two chains never share a row.
    fn add_window_batch(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[WindowDelta<'_>],
    ) -> Vec<Result<u64, StoreError>>;

    /// The highest `seq` accepted from `node_id` per row, `0` if none.
    fn last_window_seq_batch(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[WindowRow],
    ) -> Vec<Result<u64, StoreError>>;

    /// The total per row, `0` if absent.
    fn load_window_batch(&self, scope: &str, rows: &[WindowRow]) -> Vec<Result<u64, StoreError>>;
}

/// One row of [`ControlPlaneStore::add_spend_batch`]: the spend row, the delta
/// to add, and the flush sequence it is sent under (the other half of its
/// [`FlushToken`] is the batch's `node_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendDelta<'a> {
    pub tenant: &'a TenantId,
    pub period: &'a PeriodKey,
    pub delta_micros: u64,
    pub seq: u64,
}

/// What a tier-3 window counter counts (ADR-0006 amendment C).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WindowDimension {
    InputTokens,
    OutputTokens,
    TotalTokens,
    Requests,
}

impl WindowDimension {
    /// The stable name stores key rows by. Never rename: it is part of the
    /// persisted key.
    pub fn as_str(self) -> &'static str {
        match self {
            WindowDimension::InputTokens => "input_tokens",
            WindowDimension::OutputTokens => "output_tokens",
            WindowDimension::TotalTokens => "total_tokens",
            WindowDimension::Requests => "requests",
        }
    }
}

/// An epoch-aligned fixed window (amendment B): index = floor(unix_secs / length_secs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WindowKey {
    pub length_secs: u64,
    pub index: u64,
}

impl WindowKey {
    /// The window of `length_secs` containing `unix_secs`. A zero length is
    /// treated as 1 so the division cannot panic.
    pub fn containing(unix_secs: u64, length_secs: u64) -> Self {
        let length_secs = length_secs.max(1);
        WindowKey {
            length_secs,
            index: unix_secs / length_secs,
        }
    }

    pub fn start_secs(self) -> u64 {
        self.index.saturating_mul(self.length_secs)
    }

    pub fn end_secs(self) -> u64 {
        self.start_secs().saturating_add(self.length_secs)
    }
}

/// One window counter row. `subject` is an opaque, bounded identifier the
/// limiter builds (a tenant, a key id, or a hashed credential), never a raw credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WindowRow {
    pub subject: String,
    pub dimension: WindowDimension,
    pub window: WindowKey,
}

/// One row of [`ControlPlaneStore::add_window_batch`]: the row, the delta to
/// add, and the flush sequence it is sent under.
#[derive(Debug, Clone, Copy)]
pub struct WindowDelta<'a> {
    pub row: &'a WindowRow,
    pub delta: u64,
    pub seq: u64,
}

/// How long a window row outlives its window end, so a late flush still lands.
pub const WINDOW_ROW_GRACE_SECS: u64 = 300;

/// Unix seconds now; `0` if the clock is before the epoch.
pub(crate) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The two things the data plane reads per request, built wholesale by
/// [`ControlPlane::rebuild`] and swapped in atomically. Immutable once
/// constructed -- a filter never mutates a `ControlPlaneSnapshot`; a new one
/// entirely replaces it.
pub struct ControlPlaneSnapshot {
    pub keys: KeySet,
    pub policies: TenantPolicyMap,
    /// Spend ceilings by stable key identity. This is deliberately separate
    /// from tenant authorization policy: keys authenticate to tenants, but a
    /// key budget neither grants models nor shares spend with sibling keys.
    pub key_budgets: HashMap<KeyId, KeyBudget>,
    pub tenant_limits: HashMap<TenantId, LimitPolicy>,
    pub key_limits: HashMap<KeyId, LimitPolicy>,
    /// A key's own allow-list. Effective models are the tenant grant
    /// intersected with this list, so it only narrows access; absent means
    /// the key inherits the tenant grant exactly.
    pub key_policies: HashMap<KeyId, ModelAccess>,
    /// Ownership copied from the durable key rows so admin writes can reject
    /// budgets for unknown keys without a hot-path store lookup.
    pub key_tenants: HashMap<KeyId, TenantId>,
    /// Decrypted tenant provider credentials (ADR-0007). A tenant with no
    /// entry is in platform mode. A row that failed to decrypt is present as
    /// `TenantCredential::Unusable`, never absent, so that tenant fails
    /// closed.
    pub tenant_credentials: HashMap<TenantId, Arc<proxy_credentials::TenantCredentialSet>>,
    /// The store's `policy_generation`, read before the load this snapshot
    /// was built from, so it can lag the data by one write but never lead
    /// it. `None` when that read failed. Request records carry it.
    pub generation: Option<u64>,
    /// Tenants opted in to trace export (ADR-0008 decision 2). The auth
    /// filter copies membership onto the request at admission.
    pub trace_export: HashSet<TenantId>,
}

/// In-memory [`ControlPlaneStore`]. Backed by a `Mutex` because the trait's write methods
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
    // Independent of `policies` above -- see
    // `StoredControlPlane::budgets`'s doc.
    budgets: HashMap<TenantId, TenantBudget>,
    key_budgets: HashMap<KeyId, KeyBudget>,
    limits: HashMap<TenantId, LimitPolicy>,
    // Credential rows keyed by `(tenant, provider)` -- the exact
    // create-or-replace identity `put_tenant_credential` names (ADR-0007
    // §2). A map rather than a `Vec` so a second put for the same pair
    // replaces in place and `load` can never return duplicates for it.
    tenant_credentials: HashMap<(TenantId, String), StoredTenantCredential>,
    // Rate cards keyed by chain (`stat_prefix`): one row per chain, replaced
    // in place by a second put for the same chain.
    rate_cards: HashMap<String, StoredRateCard>,
    // Tenants opted in to trace export (ADR-0008 decision 2).
    trace_export: HashSet<TenantId>,
    // Object id -> owner. Not tier 2: no generation bump.
    object_owners: HashMap<String, ObjectOwner>,
    // (expires_at, object id) of every row that expires, so a claim can
    // remove expired rows without scanning them all.
    object_expiry: std::collections::BTreeSet<(u64, String)>,
    // Keyed on the full `(stat_prefix, tenant,
    // period)` triple as one tuple key -- there is no `load()`-style
    // wholesale read for spend (each row is read/written independently by
    // its own key), so this needs no separate reverse index the way
    // `keys_by_tenant` does for `keys`.
    spend: HashMap<(String, TenantId, PeriodKey), u64>,
    // The highest flush sequence accepted for each (row, writer). One
    // `u64` per writer per row, not a set of every token ever seen -- see
    // `FlushToken`'s doc for why "highest accepted wins" is the whole dedup
    // policy. `overwrite_spend` does NOT touch this map.
    spend_seq: HashMap<SpendWriter, u64>,
    // Tier-3 window counters, keyed `(scope, row)`, and their per-writer
    // high-water marks. Pruned on every `add_window_batch` (see
    // `prune_windows`) because rows are per window and would otherwise grow
    // without bound.
    windows: HashMap<(String, WindowRow), u64>,
    window_seq: HashMap<(String, WindowRow, String), u64>,
    // Bumped by every tier-2 write below, under this SAME mutex
    // acquisition -- see `ControlPlaneStore::policy_generation`'s doc for why
    // a spend write (`add_spend` above) must never touch this field.
    generation: u64,
}

/// The dedup key for [`InMemoryControlPlaneStore`]: one spend row plus the
/// replica writing it.
///
/// A named struct rather than a 4-tuple because the tuple trips clippy's
/// `type_complexity` inside the `HashMap`, and because the `node_id` field is
/// the one a future edit is most likely to drop -- naming it makes its
/// absence visible in a diff. See [`FlushToken`] for what dropping it costs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SpendWriter {
    stat_prefix: String,
    tenant: TenantId,
    period: PeriodKey,
    node_id: String,
}

impl InMemoryControlPlaneStore {
    pub fn new() -> Self {
        InMemoryControlPlaneStore {
            state: std::sync::Mutex::new(InMemoryState {
                tenants: Vec::new(),
                keys: HashMap::new(),
                policies: HashMap::new(),
                budgets: HashMap::new(),
                key_budgets: HashMap::new(),
                limits: HashMap::new(),
                tenant_credentials: HashMap::new(),
                rate_cards: HashMap::new(),
                trace_export: HashSet::new(),
                object_owners: HashMap::new(),
                object_expiry: std::collections::BTreeSet::new(),
                spend: HashMap::new(),
                spend_seq: HashMap::new(),
                windows: HashMap::new(),
                window_seq: HashMap::new(),
                generation: 0,
            }),
        }
    }
}

impl InMemoryControlPlaneStore {
    fn prune_windows_locked(state: &mut InMemoryState, now_secs: u64) {
        let expired = |row: &WindowRow| {
            row.window.end_secs().saturating_add(WINDOW_ROW_GRACE_SECS) < now_secs
        };
        // Rust note: `retain` keeps the entries the closure returns true for.
        state.windows.retain(|(_, row), _| !expired(row));
        state.window_seq.retain(|(_, row, _), _| !expired(row));
    }

    fn add_window_batch_at(
        &self,
        now_secs: u64,
        scope: &str,
        node_id: &str,
        rows: &[WindowDelta<'_>],
    ) -> Vec<Result<u64, StoreError>> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        Self::prune_windows_locked(&mut state, now_secs);
        rows.iter()
            .map(|delta| {
                let row = (scope.to_string(), delta.row.clone());
                let current = state.windows.get(&row).copied().unwrap_or(0);
                let writer = (scope.to_string(), delta.row.clone(), node_id.to_string());
                if state
                    .window_seq
                    .get(&writer)
                    .is_some_and(|last| delta.seq <= *last)
                {
                    return Ok(current);
                }
                let total = current.saturating_add(delta.delta);
                state.windows.insert(row, total);
                state.window_seq.insert(writer, delta.seq);
                Ok(total)
            })
            .collect()
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
            key_budgets: state.key_budgets.clone(),
            limits: state.limits.clone(),
            tenant_credentials: state.tenant_credentials.values().cloned().collect(),
            rate_cards: state.rate_cards.values().cloned().collect(),
            trace_export: state.trace_export.clone(),
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
        state.limits.remove(tenant);
        // A deleted tenant's consent goes with it: re-creating the id must
        // not inherit an opt-in someone else gave.
        state.trace_export.remove(tenant);
        // A deleted tenant takes its credential rows with it too (ADR-0007
        // §2), under this SAME lock acquisition so the single generation
        // bump below covers the whole deletion -- a reader never observes
        // the tenant gone while one of its credential rows is still there
        // to be applied upstream.
        state.tenant_credentials.retain(|(t, _), _| t != tenant);
        state.generation += 1;
        Ok(())
    }

    // No tenant-existence check, exactly like `set_policy` and `put_key`
    // above: both write their row for any tenant id without consulting
    // `state.tenants` first, so the row is valid the moment it is written
    // and credential rows follow the same rule (ADR-0007 §2).
    fn put_tenant_credential(&self, rec: &StoredTenantCredential) -> Result<(), StoreError> {
        // Reject an unknown schema_version BEFORE any write: a row stamped
        // by a future build must never enter a store this build's `load`
        // would then refuse to read back (ADR-0007 §2). Nothing was
        // written, so there is NO generation bump -- see
        // `ControlPlaneStore::policy_generation`'s doc.
        if rec.schema_version != TENANT_CREDENTIALS_SCHEMA_VERSION {
            return Err(StoreError::Conflict(
                "unsupported tenant credential schema_version".into(),
            ));
        }
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        state
            .tenant_credentials
            .insert((rec.tenant.clone(), rec.provider.clone()), rec.clone());
        state.generation += 1;
        Ok(())
    }

    fn delete_tenant_credential(
        &self,
        tenant: &TenantId,
        provider: &str,
    ) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        match state
            .tenant_credentials
            .remove(&(tenant.clone(), provider.to_string()))
        {
            // A successful delete is a tier-2 write and bumps like every
            // other one -- see `ControlPlaneStore::policy_generation`'s doc.
            Some(_) => {
                state.generation += 1;
                Ok(())
            }
            // Nothing was written -- must NOT bump, mirroring
            // `revoke_key`'s NotFound arm above.
            None => Err(StoreError::NotFound),
        }
    }

    fn put_key(&self, rec: &StoredKey) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        if let Some(previous) = state.keys.get(&rec.key_id) {
            validate_key_update(previous, rec)?;
        }
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

    fn set_key_budget(&self, key_id: &KeyId, budget: Option<&KeyBudget>) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        match budget {
            Some(budget) => {
                state.key_budgets.insert(key_id.clone(), *budget);
            }
            None => {
                state.key_budgets.remove(key_id);
            }
        }
        state.generation += 1;
        Ok(())
    }

    fn set_limits(
        &self,
        subject: &TenantId,
        limits: Option<&LimitPolicy>,
    ) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        match limits.filter(|limits| !limits.is_empty()) {
            Some(limits) => {
                state.limits.insert(subject.clone(), *limits);
            }
            None => {
                state.limits.remove(subject);
            }
        }
        state.generation += 1;
        Ok(())
    }

    fn set_trace_export(&self, tenant: &TenantId, enabled: bool) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        if enabled {
            state.trace_export.insert(tenant.clone());
        } else {
            state.trace_export.remove(tenant);
        }
        state.generation += 1;
        Ok(())
    }

    fn put_rate_card(&self, card: &StoredRateCard) -> Result<(), StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        // The card and the bump share this one lock acquisition, so no
        // reader sees the new stamp without the card it stands for.
        state.rate_cards.insert(card.chain.clone(), card.clone());
        state.generation += 1;
        Ok(())
    }

    fn put_rate_card_if_absent(&self, card: &StoredRateCard) -> Result<bool, StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        if state.rate_cards.contains_key(&card.chain) {
            // Nothing written, so nothing for a poller to notice: no bump.
            return Ok(false);
        }
        state.rate_cards.insert(card.chain.clone(), card.clone());
        state.generation += 1;
        Ok(true)
    }

    fn claim_object(
        &self,
        object_id: &str,
        tenant: &TenantId,
        ttl: Option<Duration>,
    ) -> Result<ObjectOwner, StoreError> {
        check_object_id(object_id)?;
        let now = unix_now_secs();
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        let state = &mut *state;
        // Remove a bounded number of expired rows, so they cannot pile up.
        let expired: Vec<(u64, String)> = state
            .object_expiry
            .iter()
            .take_while(|(at, _)| *at <= now)
            .take(OBJECT_SWEEP_PER_CLAIM)
            .cloned()
            .collect();
        for entry in expired {
            state.object_expiry.remove(&entry);
            if state
                .object_owners
                .get(&entry.1)
                .is_some_and(|row| row.expires_at == Some(entry.0))
            {
                state.object_owners.remove(&entry.1);
            }
        }
        if let Some(owner) = state.object_owners.get(object_id) {
            if owner.is_live(now) {
                return Ok(owner.clone());
            }
        }
        let owner = ObjectOwner::new(tenant.clone(), ttl, now);
        if let Some(at) = owner.expires_at {
            state.object_expiry.insert((at, object_id.to_string()));
        }
        state
            .object_owners
            .insert(object_id.to_string(), owner.clone());
        Ok(owner)
    }

    fn object_owner(&self, object_id: &str) -> Result<Option<ObjectOwner>, StoreError> {
        check_object_id(object_id)?;
        let now = unix_now_secs();
        let state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        Ok(state
            .object_owners
            .get(object_id)
            .filter(|owner| owner.is_live(now))
            .cloned())
    }

    // Rust note: an explicit override rather than the trait default, so the
    // fact that this store dies with the process is stated where it is true.
    fn is_durable(&self) -> bool {
        false
    }

    fn add_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        delta_micros: u64,
        token: FlushToken<'_>,
    ) -> Result<u64, StoreError> {
        let mut state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        let row = (stat_prefix.to_string(), tenant.clone(), period.clone());
        let writer = SpendWriter {
            stat_prefix: stat_prefix.to_string(),
            tenant: tenant.clone(),
            period: period.clone(),
            node_id: token.node_id.to_string(),
        };
        let current = state.spend.get(&row).copied().unwrap_or(0);
        // The dedup check and the add happen under ONE mutex acquisition, so
        // no second writer can slip between them and apply a delta this
        // replay would then be compared against.
        let last_seq = state.spend_seq.get(&writer).copied();
        if last_seq.is_some_and(|last| token.seq <= last) {
            // Replay. Return the CURRENT total rather than an error: the
            // caller's flush did land, it just landed already, and the total
            // is what it needs to reconcile against.
            return Ok(current);
        }
        // Rust note: `saturating_add` rather than `+`. A u64 of micro-dollars
        // cannot realistically overflow, but a panic here would take down the
        // flusher thread of every replica sharing this store at once.
        let total = current.saturating_add(delta_micros);
        state.spend.insert(row, total);
        state.spend_seq.insert(writer, token.seq);
        Ok(total)
    }

    fn overwrite_spend(
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

    fn last_flush_seq(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        node_id: &str,
    ) -> Result<u64, StoreError> {
        let state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        Ok(state
            .spend_seq
            .get(&SpendWriter {
                stat_prefix: stat_prefix.to_string(),
                tenant: tenant.clone(),
                period: period.clone(),
                node_id: node_id.to_string(),
            })
            .copied()
            .unwrap_or(0))
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

    fn add_window_batch(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[WindowDelta<'_>],
    ) -> Vec<Result<u64, StoreError>> {
        self.add_window_batch_at(unix_now_secs(), scope, node_id, rows)
    }

    fn last_window_seq_batch(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[WindowRow],
    ) -> Vec<Result<u64, StoreError>> {
        let state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        rows.iter()
            .map(|row| {
                Ok(state
                    .window_seq
                    .get(&(scope.to_string(), row.clone(), node_id.to_string()))
                    .copied()
                    .unwrap_or(0))
            })
            .collect()
    }

    fn load_window_batch(&self, scope: &str, rows: &[WindowRow]) -> Vec<Result<u64, StoreError>> {
        let state = self
            .state
            .lock()
            .expect("control-plane store mutex poisoned");
        rows.iter()
            .map(|row| {
                Ok(state
                    .windows
                    .get(&(scope.to_string(), row.clone()))
                    .copied()
                    .unwrap_or(0))
            })
            .collect()
    }
}

// --- redb tables -----------------------------------------------------------
//
// One table per concept, plus the explicit `keys_by_tenant` reverse
// index redb does not provide for free (it has no secondary indexes).
//
// Rust note: a `TableDefinition` is just a name plus a `K`/`V` type marker --
// it carries no data of its own, so it can be a top-level `const` shared by
// every method below rather than something each method has to build.
const TENANTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("tenants");
const KEYS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("keys");
const KEYS_BY_TENANT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("keys_by_tenant");
const POLICIES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("policies");
// A tenant's budget, JSON-encoded like every other
// table here -- see `EncodedTenantBudget`'s doc. Independent of
// `POLICIES_TABLE`: a tenant may have a row in one, the other, both, or
// neither.
const BUDGETS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("budgets");
const LIMITS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("limits");
// Trace-export opt-in rows (ADR-0008 decision 2), one per opted-in tenant;
// opting out removes the row. Decoded by `decode_trace_export_row`.
const TRACE_EXPORT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("trace_export");
// A spend row's key is the 3-part
// `(stat_prefix, tenant, period)` tuple, not a single `&str` like every
// table above -- `redb::Key` has a native impl for tuples of `Key` types
// (see `tuple_types.rs` upstream), so this uses that directly rather than
// hand-rolling a delimiter-joined single string the way `keys_by_tenant`'s
// VALUE does for `Vec<String>`. The value is a plain `u64`, not JSON bytes
// like the other tables: `u64` already has a native fixed-width `redb::Value`
// impl, so encoding a bare integer through `serde_json` would only add an
// allocation and a round trip for no benefit.
const SPEND_TABLE: TableDefinition<(&str, &str, &str), u64> = TableDefinition::new("spend");
// The redb twin of `InMemoryState::spend_seq`. Keyed on the spend row
// PLUS the writing node -- a key without the node id makes two replicas share
// one sequence space and silently drop each other's flushes. See
// `FlushToken`'s doc.
const SPEND_SEQ_TABLE: TableDefinition<(&str, &str, &str, &str), u64> =
    TableDefinition::new("spend_seq");
// Tier-3 window counters: (scope, subject, dimension, length_secs, index).
// The seq table adds the writing node, for the reason `SPEND_SEQ_TABLE` does.
type WindowRowKey<'a> = (&'a str, &'a str, &'a str, u64, u64);
const WINDOWS_TABLE: TableDefinition<WindowRowKey<'static>, u64> = TableDefinition::new("windows");
const WINDOW_SEQ_TABLE: TableDefinition<(&str, &str, &str, u64, u64, &str), u64> =
    TableDefinition::new("window_seq");
// A single row, keyed `"policy"`, holding the tier-2 generation
// counter -- see `ControlPlaneStore::policy_generation`'s doc. A dedicated
// table (rather than a row inside, say, `TENANTS_TABLE`) so bumping it is one
// `insert` regardless of which of the six tier-2 tables the accompanying
// write actually touched.
const GENERATION_TABLE: TableDefinition<&str, u64> = TableDefinition::new("generation");
// A tenant's own provider credential row (ADR-0007 §2), keyed
// `(tenant, provider)` -- the same create-or-replace identity
// `ControlPlaneStore::put_tenant_credential` names. A tuple key like
// `SPEND_TABLE`'s (redb implements `Key` for tuples natively), and the
// pair lets `delete_tenant` sweep one tenant's rows by filtering on the
// first component without a reverse index. The value is JSON bytes, same
// encoding as every other table here -- see [`EncodedKeyRow`]'s doc.
const TENANT_CREDENTIALS_TABLE: TableDefinition<(&str, &str), &[u8]> =
    TableDefinition::new("tenant_credentials");
// A chain's rate card, keyed by the chain's `stat_prefix`. JSON bytes like
// every other table here -- see `EncodedRateCardRow`.
const RATE_CARDS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("rate_cards");
// Object id -> `encode_object_owner_row`. Not tier 2: no generation bump.
const OBJECT_OWNERS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("object_owners");
// (expires_at, object id) of every owner row that expires, in expiry order,
// so a claim removes expired rows without scanning the owners table.
const OBJECT_EXPIRY_TABLE: TableDefinition<(u64, &str), ()> = TableDefinition::new("object_expiry");

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
pub(crate) struct EncodedKeyRow {
    #[serde(
        default = "legacy_schema_version",
        deserialize_with = "read_key_row_schema_version"
    )]
    pub(crate) schema_version: u32,
    pub(crate) digest: [u8; 32],
    pub(crate) tenant: String,
    pub(crate) revoked: bool,
    /// Key metadata tags. Absent in rows below [`KEY_TAGS_SCHEMA_VERSION`]
    /// and in rows written without tags. Skipped when empty: Redis's Lua
    /// `cjson` re-encodes an empty object as `[]` on revoke, which would not
    /// decode back into a map.
    #[serde(default, skip_serializing_if = "ChargebackTags::is_empty")]
    pub(crate) tags: ChargebackTags,
}

/// The key-row version that adds `tags`. A row is stamped with it only when
/// it carries tags, so a store without tagged keys still opens in a build
/// from before tags. A build from before tags refuses a tagged row instead of
/// reading it without its tags and losing them on its next rewrite (a
/// revoke): the downgrade fails loudly rather than dropping attribution.
pub(crate) const KEY_TAGS_SCHEMA_VERSION: u32 = 3;

fn read_key_row_schema_version<'de, D: serde::Deserializer<'de>>(de: D) -> Result<u32, D::Error> {
    let version = <u32 as serde::Deserialize>::deserialize(de)?;
    if matches!(version, 1 | SPEND_SCHEMA_VERSION | KEY_TAGS_SCHEMA_VERSION) {
        Ok(version)
    } else {
        Err(serde::de::Error::custom(format!(
            "unsupported key row schema version {version}"
        )))
    }
}

impl EncodedKeyRow {
    pub(crate) fn from_stored(key: &StoredKey) -> Self {
        Self {
            schema_version: if key.tags.is_empty() {
                SPEND_SCHEMA_VERSION
            } else {
                KEY_TAGS_SCHEMA_VERSION
            },
            digest: key.digest,
            tenant: key.tenant.as_str().to_owned(),
            revoked: key.revoked,
            tags: key.tags.clone(),
        }
    }

    pub(crate) fn into_stored(self, key_id: KeyId) -> StoredKey {
        StoredKey {
            key_id,
            digest: self.digest,
            tenant: TenantId::new(self.tenant),
            revoked: self.revoked,
            tags: self.tags,
        }
    }
}

/// [`ModelAccess`] as `serde_json` sees it. A local mirror rather than
/// `#[derive(Serialize, Deserialize)]` on `ModelAccess` itself -- that type
/// lives in `model_authz.rs`, which this type has no reason to touch,
/// and giving it a serde impl would be a public-API decision belonging to
/// that module's owner, not something to smuggle in via this store.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) enum EncodedModelAccess {
    All,
    Only(Vec<String>),
    WithDeny {
        allow: Box<EncodedModelAccess>,
        deny: Vec<String>,
    },
}

impl From<&ModelAccess> for EncodedModelAccess {
    fn from(access: &ModelAccess) -> Self {
        match access {
            ModelAccess::All => EncodedModelAccess::All,
            ModelAccess::Only(patterns) => {
                EncodedModelAccess::Only(patterns.iter().map(|p| p.as_str().to_string()).collect())
            }
            ModelAccess::WithDeny { allow, deny } => EncodedModelAccess::WithDeny {
                allow: Box::new(EncodedModelAccess::from(allow.as_ref())),
                deny: deny.iter().map(|p| p.as_str().to_string()).collect(),
            },
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
            EncodedModelAccess::WithDeny { allow, deny } => ModelAccess::WithDeny {
                allow: Box::new(ModelAccess::from(*allow)),
                deny: deny.into_iter().map(ModelPattern::new).collect(),
            },
        }
    }
}

/// [`crate::spend::Period`] as `serde_json` sees it. A local mirror, not a
/// `serde` derive on `Period` itself -- same reasoning as
/// [`EncodedModelAccess`]'s doc: `Period` lives in `spend.rs`, which this
/// store has no other reason to touch for a serde impl.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) enum EncodedPeriod {
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

/// [`CredentialSource`] as `serde_json` sees it -- the same local-mirror
/// reasoning as [`EncodedPeriod`] above. The stored spelling is snake_case
/// (`"platform"`/`"tenant"`), matching the representation records already
/// use for the same enum (ADR-0007 decision 7).
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EncodedCredentialSource {
    Platform,
    Tenant,
}

impl From<CredentialSource> for EncodedCredentialSource {
    fn from(source: CredentialSource) -> Self {
        match source {
            CredentialSource::Platform => EncodedCredentialSource::Platform,
            CredentialSource::Tenant => EncodedCredentialSource::Tenant,
        }
    }
}

impl From<EncodedCredentialSource> for CredentialSource {
    fn from(encoded: EncodedCredentialSource) -> Self {
        match encoded {
            EncodedCredentialSource::Platform => CredentialSource::Platform,
            EncodedCredentialSource::Tenant => CredentialSource::Tenant,
        }
    }
}

/// The scope a budget row written BEFORE ADR-0007 decision 8 carried no
/// `credential_source` field at all. Every such budget was enforced against
/// -- and charged by -- the operator's credential, so `Platform` is the
/// value that preserves its meaning on read rather than inventing one.
fn legacy_credential_source() -> EncodedCredentialSource {
    EncodedCredentialSource::Platform
}

/// [`TenantBudget`] as `serde_json` sees it -- same "local mirror, not a
/// derive on the real type" reasoning as [`EncodedModelAccess`] and
/// [`EncodedPeriod`] above.
///
/// `credential_source` defaults to [`legacy_credential_source`] when a row
/// lacks it: rows written before ADR-0007 decision 8 scoped budgets keep
/// their platform meaning, and `SPEND_SCHEMA_VERSION` does NOT bump -- the
/// field is additive for every reader that ignores unknown fields.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct EncodedTenantBudget {
    #[serde(
        default = "legacy_schema_version",
        deserialize_with = "read_schema_version"
    )]
    schema_version: u32,
    max_micros: u64,
    period: EncodedPeriod,
    #[serde(default = "legacy_credential_source")]
    credential_source: EncodedCredentialSource,
}

impl From<&TenantBudget> for EncodedTenantBudget {
    fn from(budget: &TenantBudget) -> Self {
        EncodedTenantBudget {
            schema_version: SPEND_SCHEMA_VERSION,
            max_micros: budget.max_micros.as_micros(),
            period: budget.period.into(),
            credential_source: budget.credential_source.into(),
        }
    }
}

impl From<EncodedTenantBudget> for TenantBudget {
    fn from(encoded: EncodedTenantBudget) -> Self {
        TenantBudget {
            max_micros: crate::spend::MicroUsd::from_micros(encoded.max_micros),
            period: encoded.period.into(),
            credential_source: encoded.credential_source.into(),
        }
    }
}

/// [`KeyBudget`] as `serde_json` sees it. Key budgets share the budgets
/// table with tenant budgets, filed under the key's subject, so a row written
/// before ADR-0007 amendment 1 is an [`EncodedTenantBudget`] with an optional
/// `credential_source` and no flag. Such a row reads through
/// [`KeyBudget::from_scoped`]: `tenant` becomes `true`; `platform` or absent
/// becomes `false`. A row written now carries only the flag, and
/// `SPEND_SCHEMA_VERSION` does not bump: a build from before the flag ignores
/// it and reads the row as platform-scoped, so a rollback keeps enforcing
/// the key budget on operator spend.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct EncodedKeyBudget {
    #[serde(
        default = "legacy_schema_version",
        deserialize_with = "read_schema_version"
    )]
    schema_version: u32,
    max_micros: u64,
    period: EncodedPeriod,
    /// Read only, from rows written before the flag; never written.
    #[serde(default, skip_serializing)]
    credential_source: Option<EncodedCredentialSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    include_byok_in_limit: Option<bool>,
}

impl From<&KeyBudget> for EncodedKeyBudget {
    fn from(budget: &KeyBudget) -> Self {
        EncodedKeyBudget {
            schema_version: SPEND_SCHEMA_VERSION,
            max_micros: budget.max_micros.as_micros(),
            period: budget.period.into(),
            credential_source: None,
            include_byok_in_limit: Some(budget.include_byok_in_limit),
        }
    }
}

impl From<EncodedKeyBudget> for KeyBudget {
    fn from(encoded: EncodedKeyBudget) -> Self {
        let max_micros = crate::spend::MicroUsd::from_micros(encoded.max_micros);
        let period = encoded.period.into();
        match encoded.include_byok_in_limit {
            Some(include_byok_in_limit) => KeyBudget {
                max_micros,
                period,
                include_byok_in_limit,
            },
            None => KeyBudget::from_scoped(TenantBudget {
                max_micros,
                period,
                credential_source: encoded
                    .credential_source
                    .unwrap_or_else(legacy_credential_source)
                    .into(),
            }),
        }
    }
}

/// Versioned durable row kept separate from budget and model policy rows.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct EncodedLimitPolicy {
    #[serde(
        default = "legacy_schema_version",
        deserialize_with = "read_limits_schema_version"
    )]
    schema_version: u32,
    tokens_per_minute: Option<u64>,
    requests_per_minute: Option<u64>,
    concurrent_streams: Option<u32>,
}

pub(crate) const TRACE_EXPORT_SCHEMA_VERSION: u32 = 1;

/// A tenant's trace-export opt-in row, the same JSON in redb and Redis.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct EncodedTraceExport {
    schema_version: u32,
    enabled: bool,
}

pub(crate) fn encode_trace_export_row() -> Vec<u8> {
    serde_json::to_vec(&EncodedTraceExport {
        schema_version: TRACE_EXPORT_SCHEMA_VERSION,
        enabled: true,
    })
    .expect("a two-field struct always serializes")
}

/// Whether a stored opt-in row says the tenant opted in. A row this build
/// cannot read is not consent: it is ignored with a warning rather than
/// failing the whole load, so an unreadable opt-in can never hold up a key
/// revocation, and never captures.
pub(crate) fn decode_trace_export_row(tenant: &str, value: &[u8]) -> bool {
    match serde_json::from_slice::<EncodedTraceExport>(value) {
        Ok(row) if row.schema_version == TRACE_EXPORT_SCHEMA_VERSION => row.enabled,
        Ok(row) => {
            tracing::warn!(
                tenant,
                schema_version = row.schema_version,
                "trace export opt-in row has an unsupported schema version; treating the tenant \
                 as not opted in"
            );
            false
        }
        Err(_) => {
            tracing::warn!(
                tenant,
                "trace export opt-in row does not parse; treating the tenant as not opted in"
            );
            false
        }
    }
}

pub(crate) const OBJECT_OWNER_SCHEMA_VERSION: u32 = 1;

/// Longest object id an ownership row may name. Provider ids are short; the
/// cap keeps a hostile response or path from writing an unbounded key.
pub const MAX_OBJECT_ID_BYTES: usize = 256;

/// Refuses an object id the store must never hold.
pub(crate) fn check_object_id(object_id: &str) -> Result<(), StoreError> {
    if object_id.is_empty() || object_id.len() > MAX_OBJECT_ID_BYTES {
        return Err(StoreError::InvalidInput(format!(
            "object id must be 1 to {MAX_OBJECT_ID_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Most expired owner rows one claim removes. Claims outnumber expiries in
/// steady state, so a small bound keeps up without making one claim slow.
const OBJECT_SWEEP_PER_CLAIM: usize = 16;

/// An object's owner, as the store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectOwner {
    pub tenant: TenantId,
    /// Unix seconds at which the row stops counting; `None` never expires.
    pub expires_at: Option<u64>,
}

impl ObjectOwner {
    /// A row claimed at `now` (Unix seconds) that lives for `ttl`.
    pub fn new(tenant: TenantId, ttl: Option<Duration>, now: u64) -> Self {
        ObjectOwner {
            tenant,
            expires_at: ttl.map(|ttl| now.saturating_add(ttl.as_secs())),
        }
    }

    /// Whether the row still counts at `now` (Unix seconds).
    pub fn is_live(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|at| now < at)
    }
}

/// An object-ownership row, the same JSON in redb and Redis. A row without
/// `expires_at` never expires.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct EncodedObjectOwner {
    schema_version: u32,
    tenant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
}

pub(crate) fn encode_object_owner_row(owner: &ObjectOwner) -> Vec<u8> {
    encode_json(&EncodedObjectOwner {
        schema_version: OBJECT_OWNER_SCHEMA_VERSION,
        tenant: owner.tenant.as_str().to_string(),
        expires_at: owner.expires_at,
    })
}

/// The owner a stored row names, expired or not. A row this build cannot
/// read is an error, not "no owner": an unreadable row must not let the
/// object be claimed by, or opened to, someone else.
pub(crate) fn decode_object_owner_row(value: &[u8]) -> Result<ObjectOwner, StoreError> {
    match serde_json::from_slice::<EncodedObjectOwner>(value) {
        Ok(row) if row.schema_version == OBJECT_OWNER_SCHEMA_VERSION => Ok(ObjectOwner {
            tenant: TenantId::new(row.tenant),
            expires_at: row.expires_at,
        }),
        Ok(row) => Err(StoreError::Unavailable(format!(
            "object owner row has unsupported schema version {}",
            row.schema_version
        ))),
        Err(_) => Err(StoreError::Unavailable(
            "object owner row does not parse".into(),
        )),
    }
}

fn read_limits_schema_version<'de, D: serde::Deserializer<'de>>(de: D) -> Result<u32, D::Error> {
    let version = <u32 as serde::Deserialize>::deserialize(de)?;
    if version == 1 {
        Ok(version)
    } else {
        Err(serde::de::Error::custom(format!(
            "unsupported limits schema version {version}"
        )))
    }
}

impl From<&LimitPolicy> for EncodedLimitPolicy {
    fn from(limits: &LimitPolicy) -> Self {
        Self {
            schema_version: 1,
            tokens_per_minute: limits.tokens_per_minute,
            requests_per_minute: limits.requests_per_minute,
            concurrent_streams: limits.concurrent_streams,
        }
    }
}

impl From<EncodedLimitPolicy> for LimitPolicy {
    fn from(encoded: EncodedLimitPolicy) -> Self {
        Self {
            tokens_per_minute: encoded.tokens_per_minute,
            requests_per_minute: encoded.requests_per_minute,
            concurrent_streams: encoded.concurrent_streams,
        }
    }
}

/// Only version this build understands for a tenant credential row
/// (ADR-0007 §2). A row stamped by a future build fails closed on load
/// rather than being half-read -- see [`decode_tenant_credential_row`].
pub(crate) const TENANT_CREDENTIALS_SCHEMA_VERSION: u16 = 1;

/// One `tenant_credentials` row, exactly as `redb` stores it -- a private
/// mirror, following [`EncodedKeyRow`]'s precedent: `tenant` and `provider`
/// are NOT repeated in the value because the table's composite key already
/// holds them, and a second, independently-editable copy of the same fact
/// could disagree with the key it is filed under.
///
/// Two deliberate differences from the public [`StoredTenantCredential`],
/// both about the stored form being inert bytes-in-JSON:
/// - `nonce` and `ciphertext` are LOWERCASE hex strings, not raw byte
///   arrays: JSON strings must be valid UTF-8, so arbitrary ciphertext
///   bytes cannot ride in them unescaped, and hex keeps a row readable in
///   a dump with no binary codec (the same rendering `auth::digest_hex`
///   uses for digests).
/// - serde lives only on THIS type; [`StoredTenantCredential`] stays a
///   plain data struct whose serialization this store alone defines.
///
/// `schema_version` rides along for the fail-closed check in
/// [`decode_tenant_credential_row`] -- see [`EncodedKeyRow`]'s
/// `schema_version` for the same convention on key rows.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct EncodedTenantCredentialRow {
    schema_version: u16,
    key_id: String,
    nonce: String,
    ciphertext: String,
    last4: String,
    fingerprint: String,
    created_at: String,
    updated_at: String,
    verified_at: Option<String>,
}

impl From<&StoredTenantCredential> for EncodedTenantCredentialRow {
    fn from(rec: &StoredTenantCredential) -> Self {
        EncodedTenantCredentialRow {
            schema_version: rec.schema_version,
            key_id: rec.key_id.clone(),
            nonce: encode_hex_lower(&rec.nonce),
            ciphertext: encode_hex_lower(&rec.ciphertext),
            last4: rec.last4.clone(),
            fingerprint: rec.fingerprint.clone(),
            created_at: rec.created_at.clone(),
            updated_at: rec.updated_at.clone(),
            verified_at: rec.verified_at.clone(),
        }
    }
}

/// Lowercase hex rendering of `bytes` -- the encoding
/// [`EncodedTenantCredentialRow`] stores `nonce`/`ciphertext` in.
fn encode_hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Inverse of [`encode_hex_lower`]. Deliberately accepts ONLY `0-9a-f`:
/// the store writes lowercase, so an uppercase digit in a stored row means
/// it was written by something other than this code path, and failing
/// closed on that beats silently accepting two spellings of one value
/// (the same "must be lowercase hex" rule
/// `auth_filter::parse_digest_hex` enforces). `None` on any violation --
/// the caller builds the error, which must never quote the value itself.
fn decode_hex_lower(hex: &str) -> Option<Vec<u8>> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    let raw = hex.as_bytes();
    // `as_chunks` gives the pairs plus whatever trailing half-pair remains;
    // an odd-length string is exactly a non-empty remainder.
    let (pairs, remainder) = raw.as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(pairs.len());
    for pair in pairs {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

/// Decodes one stored credential row, failing CLOSED with a message that
/// names the tenant and provider -- always known here, since they come from
/// the table's own key -- and nothing else about the row.
///
/// Every failure path (unparseable JSON, a `schema_version` that is not
/// [`TENANT_CREDENTIALS_SCHEMA_VERSION`], bad hex, a wrong-length nonce)
/// returns [`StoreError::Unavailable`] for the WHOLE [`ControlPlaneStore::load`]:
/// a row this build cannot fully understand is not a row to skip, because
/// silently loading the other rows would drop a tenant's credential from
/// the snapshot and let that tenant fall back to the platform key
/// (ADR-0007 §3). The serde error text is deliberately NOT propagated --
/// a serde message can echo the offending field's value, and the one thing
/// that must never render here is ciphertext (AGENTS.md "Fail-open
/// controls": check what the log line renders).
pub(crate) fn decode_tenant_credential_row(
    tenant: &str,
    provider: &str,
    value: &[u8],
) -> Result<StoredTenantCredential, StoreError> {
    let bad = |detail: String| {
        StoreError::Unavailable(format!(
            "tenant credential row for tenant {tenant:?} provider {provider:?} {detail}; \
             refusing the whole control-plane load"
        ))
    };
    let row: EncodedTenantCredentialRow = serde_json::from_slice(value)
        .map_err(|_| bad("does not parse as a tenant credential row".to_string()))?;
    if row.schema_version != TENANT_CREDENTIALS_SCHEMA_VERSION {
        return Err(bad(format!(
            "has schema_version {}, but only {TENANT_CREDENTIALS_SCHEMA_VERSION} is supported",
            row.schema_version
        )));
    }
    let nonce: [u8; 12] = decode_hex_lower(&row.nonce)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| bad("has a nonce that is not exactly 12 lowercase hex bytes".into()))?;
    let ciphertext = decode_hex_lower(&row.ciphertext)
        .ok_or_else(|| bad("has a ciphertext that is not lowercase hex".into()))?;
    Ok(StoredTenantCredential {
        schema_version: row.schema_version,
        tenant: TenantId::new(tenant),
        provider: provider.to_string(),
        key_id: row.key_id,
        nonce,
        ciphertext,
        last4: row.last4,
        fingerprint: row.fingerprint,
        created_at: row.created_at,
        updated_at: row.updated_at,
        verified_at: row.verified_at,
    })
}

/// The newest rate card row version this build understands; it reads every
/// version from [`RATE_CARD_SCHEMA_V1`] up to this one.
pub(crate) const RATE_CARD_SCHEMA_VERSION: u16 = RATE_CARD_SCHEMA_V2;

/// One `rate_cards` row as the persistent stores keep it. The chain is the
/// table key (redb) or hash field (Redis), so it is not repeated in the value,
/// where a second copy could disagree with the key it is filed under.
///
/// `card` is the pricing document as a JSON string inside the JSON row, not
/// as nested JSON. The store never looks inside it, and nothing at the storage
/// layer can reorder its keys or re-render its numbers; what `usage_filter`
/// wrote is what it reads back.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct EncodedRateCardRow {
    schema_version: u16,
    version: String,
    card: String,
}

impl From<&StoredRateCard> for EncodedRateCardRow {
    fn from(card: &StoredRateCard) -> Self {
        EncodedRateCardRow {
            schema_version: card.schema_version,
            version: card.version.clone(),
            card: card.card_json.clone(),
        }
    }
}

/// Decodes one stored rate card row. A row this build cannot read is logged
/// and left out: `None`, never an error for the whole load.
///
/// That is the opposite of [`decode_tenant_credential_row`], and on purpose.
/// Dropping a credential row would let that tenant fall back to the platform
/// key, so one unreadable row has to fail the load closed. Dropping a rate
/// card only leaves this replica on the card it already has, and failing the
/// load for it would stop key revocations and policy changes from reaching
/// the replica, over a price list. The loss is not silent: the warning names
/// the chain, and requests the missing card would have priced are reported by
/// the spend filter's unpriced warning where a budget applies.
///
/// The log line carries the chain and a fixed reason only. A serde message
/// can echo a field's value, and nothing about a row is worth risking in a
/// log (AGENTS.md "Fail-open controls": check what the log line renders).
pub(crate) fn decode_rate_card_row(chain: &str, value: &[u8]) -> Option<StoredRateCard> {
    let row: EncodedRateCardRow = match serde_json::from_slice(value) {
        Ok(row) => row,
        Err(_) => {
            tracing::warn!(
                chain,
                "stored rate card row does not parse as a rate card row; ignoring it"
            );
            return None;
        }
    };
    if !(RATE_CARD_SCHEMA_V1..=RATE_CARD_SCHEMA_VERSION).contains(&row.schema_version) {
        tracing::warn!(
            chain,
            schema_version = row.schema_version,
            supported = RATE_CARD_SCHEMA_VERSION,
            "stored rate card row has a schema_version this build does not understand; \
             ignoring it"
        );
        return None;
    }
    Some(StoredRateCard {
        chain: chain.to_string(),
        version: row.version,
        card_json: row.card,
        schema_version: row.schema_version,
    })
}

pub(crate) fn encode_json<T: serde::Serialize>(value: &T) -> Vec<u8> {
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
pub(crate) fn decode_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, StoreError> {
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
pub(crate) fn store_err(err: impl std::fmt::Display) -> StoreError {
    StoreError::Unavailable(err.to_string())
}

/// Persistent, embedded [`ControlPlaneStore`] backed by `redb` -- the
/// production default (chosen because it is
/// pure-Rust, ACID, single-file, no C toolchain, unlike SQLite).
///
/// # Transaction model: one write txn per method, one read txn per `load()`
///
/// Rust note: every write method (`create_tenant`, `put_key`, ...) opens its
/// own `redb::WriteTransaction`, mutates one or more tables, and commits --
/// isolating EACH store call to one function keeps a future
/// distributed backend a drop-in, and this satisfies that literally: there
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
    /// external datastore configured.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(store_err)?;
        Self::from_database(db)
    }

    /// An ephemeral, in-memory `redb` database. It runs through the same
    /// transaction and table code as every other constructor; only the
    /// `StorageBackend` differs, so it proves nothing about `redb`'s own
    /// durability -- see the `reopening_the_same_path_...` test for that.
    #[cfg(test)]
    pub(crate) fn in_memory() -> Self {
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

    /// Creates all tables if they do not already exist, including limits.
    ///
    /// Rust note: this runs a WRITE transaction even though it inserts no
    /// rows -- `WriteTransaction::open_table` is the only `redb` API that
    /// CREATES a table; `ReadTransaction::open_table` errors
    /// `TableDoesNotExist` against one that has never been opened for write.
    /// Doing this once at construction means [`Self::load`] (always a read
    /// transaction) never has to tell "table exists and is empty" apart from
    /// "table was never created" -- both read back as empty, which is what a
    /// freshly-opened store should report either way. It is also what makes
    /// an EXISTING database file from before a newer table existed still
    /// openable: `open_table` creates the missing table rather than erroring
    /// on it, so the file gains the table on first open (pinned by
    /// `redb_opens_a_database_file_created_before_the_tenant_credentials_table_existed`
    /// and `redb_opens_a_database_file_created_before_the_rate_cards_table_existed`).
    fn ensure_tables(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        txn.open_table(TENANTS_TABLE).map_err(store_err)?;
        txn.open_table(KEYS_TABLE).map_err(store_err)?;
        txn.open_table(KEYS_BY_TENANT_TABLE).map_err(store_err)?;
        txn.open_table(POLICIES_TABLE).map_err(store_err)?;
        txn.open_table(BUDGETS_TABLE).map_err(store_err)?;
        txn.open_table(LIMITS_TABLE).map_err(store_err)?;
        txn.open_table(TRACE_EXPORT_TABLE).map_err(store_err)?;
        txn.open_table(TENANT_CREDENTIALS_TABLE)
            .map_err(store_err)?;
        txn.open_table(RATE_CARDS_TABLE).map_err(store_err)?;
        txn.open_table(OBJECT_OWNERS_TABLE).map_err(store_err)?;
        txn.open_table(OBJECT_EXPIRY_TABLE).map_err(store_err)?;
        txn.open_table(SPEND_TABLE).map_err(store_err)?;
        txn.open_table(SPEND_SEQ_TABLE).map_err(store_err)?;
        txn.open_table(WINDOWS_TABLE).map_err(store_err)?;
        txn.open_table(WINDOW_SEQ_TABLE).map_err(store_err)?;
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
    /// for the future `GET /tenants/{id}/keys` admin endpoint that needs a single tenant's key ids without
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
            keys.push(row.into_stored(KeyId::new(key.value())));
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
        let mut key_budgets = HashMap::new();
        for entry in budgets_table.iter().map_err(store_err)? {
            let (key, value) = entry.map_err(store_err)?;
            let subject = TenantId::new(key.value());
            if let Some(key_id) = key_id_from_budget_subject(&subject) {
                let encoded: EncodedKeyBudget = decode_json(value.value())?;
                key_budgets.insert(key_id, encoded.into());
            } else {
                let encoded: EncodedTenantBudget = decode_json(value.value())?;
                budgets.insert(subject, encoded.into());
            }
        }

        let limits_table = txn.open_table(LIMITS_TABLE).map_err(store_err)?;
        let mut limits = HashMap::new();
        for entry in limits_table.iter().map_err(store_err)? {
            let (key, value) = entry.map_err(store_err)?;
            let encoded: EncodedLimitPolicy = decode_json(value.value())?;
            let policy: LimitPolicy = encoded.into();
            if !policy.is_empty() {
                limits.insert(TenantId::new(key.value()), policy);
            }
        }

        let trace_export_table = txn.open_table(TRACE_EXPORT_TABLE).map_err(store_err)?;
        let mut trace_export = HashSet::new();
        for entry in trace_export_table.iter().map_err(store_err)? {
            let (key, value) = entry.map_err(store_err)?;
            if decode_trace_export_row(key.value(), value.value()) {
                trace_export.insert(TenantId::new(key.value()));
            }
        }

        // Credential rows decode through their own fail-closed helper: one
        // row this build cannot fully understand makes the WHOLE load an
        // `Err`, so a half-understood store never becomes a snapshot that
        // silently drops a tenant's credential (ADR-0007 §2-3).
        let credentials_table = txn
            .open_table(TENANT_CREDENTIALS_TABLE)
            .map_err(store_err)?;
        let mut tenant_credentials = Vec::new();
        for entry in credentials_table.iter().map_err(store_err)? {
            let (key, value) = entry.map_err(store_err)?;
            let (tenant, provider) = key.value();
            tenant_credentials.push(decode_tenant_credential_row(
                tenant,
                provider,
                value.value(),
            )?);
        }

        // Rate cards are the opposite case: a row this build cannot read is
        // skipped and logged, never an `Err` -- see `decode_rate_card_row`.
        let rate_cards_table = txn.open_table(RATE_CARDS_TABLE).map_err(store_err)?;
        let mut rate_cards = Vec::new();
        for entry in rate_cards_table.iter().map_err(store_err)? {
            let (key, value) = entry.map_err(store_err)?;
            if let Some(card) = decode_rate_card_row(key.value(), value.value()) {
                rate_cards.push(card);
            }
        }

        Ok(StoredControlPlane {
            tenants,
            keys,
            policies,
            budgets,
            key_budgets,
            limits,
            tenant_credentials,
            rate_cards,
            trace_export,
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
        {
            let mut limits_table = txn.open_table(LIMITS_TABLE).map_err(store_err)?;
            limits_table.remove(tenant.as_str()).map_err(store_err)?;
        }
        {
            let mut table = txn.open_table(TRACE_EXPORT_TABLE).map_err(store_err)?;
            table.remove(tenant.as_str()).map_err(store_err)?;
        }
        {
            // A deleted tenant's credential rows go with it (ADR-0007 §2),
            // inside this SAME write transaction so the single
            // `bump_generation` below covers the whole deletion -- a reader
            // never observes the tenant gone with its rows still filed (or
            // the reverse). The table is keyed `(tenant, provider)` and
            // redb has no prefix-delete, so collect this tenant's keys
            // first -- the read guards must drop before `remove` can take
            // the table mutably -- then remove them. The range starts at
            // `(tenant, "")`: `""` sorts before every provider name, so
            // the bound covers all of this tenant's rows, and because keys
            // sort by tenant first, the first row past this tenant ends
            // the scan instead of walking the rest of the table.
            let mut table = txn
                .open_table(TENANT_CREDENTIALS_TABLE)
                .map_err(store_err)?;
            let mut doomed: Vec<(String, String)> = Vec::new();
            for entry in table.range((tenant.as_str(), "")..).map_err(store_err)? {
                let (key, _value) = entry.map_err(store_err)?;
                let (row_tenant, provider) = key.value();
                if row_tenant != tenant.as_str() {
                    break;
                }
                doomed.push((row_tenant.to_string(), provider.to_string()));
            }
            for (row_tenant, provider) in &doomed {
                table
                    .remove((row_tenant.as_str(), provider.as_str()))
                    .map_err(store_err)?;
            }
        }
        // Matches `InMemoryControlPlaneStore::delete_tenant` exactly: `keys`
        // and `keys_by_tenant` are left untouched. A tenant's keys outliving
        // the tenant row is the existing, deliberate InMemory behavior this
        // store must not silently diverge from -- see the parity test below.
        Self::bump_generation(&txn)?;
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn put_tenant_credential(&self, rec: &StoredTenantCredential) -> Result<(), StoreError> {
        // Reject an unknown schema_version BEFORE any write -- before the
        // write transaction even begins: a row stamped by a future build
        // must never enter a store this build's `load` would then refuse
        // to read back (ADR-0007 §2). Nothing was written, so the
        // generation is NOT bumped -- see
        // `ControlPlaneStore::policy_generation`'s doc.
        if rec.schema_version != TENANT_CREDENTIALS_SCHEMA_VERSION {
            return Err(StoreError::Conflict(
                "unsupported tenant credential schema_version".into(),
            ));
        }
        // No tenant-existence check, exactly like `set_policy` and
        // `put_key` below: neither consults `TENANTS_TABLE` first, so the
        // row is valid the moment it is written and credential rows follow
        // the same rule (ADR-0007 §2).
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn
                .open_table(TENANT_CREDENTIALS_TABLE)
                .map_err(store_err)?;
            let encoded = EncodedTenantCredentialRow::from(rec);
            // redb's insert is last-writer-wins on an existing composite
            // key, which IS the required create-or-replace semantics.
            table
                .insert(
                    (rec.tenant.as_str(), rec.provider.as_str()),
                    encode_json(&encoded).as_slice(),
                )
                .map_err(store_err)?;
        }
        Self::bump_generation(&txn)?;
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn delete_tenant_credential(
        &self,
        tenant: &TenantId,
        provider: &str,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn
                .open_table(TENANT_CREDENTIALS_TABLE)
                .map_err(store_err)?;
            // `remove` reports `None` for a key never written. Matches
            // `InMemoryControlPlaneStore::delete_tenant_credential`: that is
            // `NotFound` with NOTHING written and NO bump -- returning
            // before `bump_generation` and dropping `txn` uncommitted
            // leaves the generation table untouched. See
            // `ControlPlaneStore::policy_generation`'s doc.
            if table
                .remove((tenant.as_str(), provider))
                .map_err(store_err)?
                .is_none()
            {
                return Err(StoreError::NotFound);
            }
        }
        Self::bump_generation(&txn)?;
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn put_key(&self, rec: &StoredKey) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        let previous_tenant: Option<String> = {
            let mut keys_table = txn.open_table(KEYS_TABLE).map_err(store_err)?;
            let previous = match keys_table.get(rec.key_id.as_str()).map_err(store_err)? {
                Some(guard) => {
                    let previous: EncodedKeyRow = decode_json(guard.value())?;
                    let previous = previous.into_stored(rec.key_id.clone());
                    validate_key_update(&previous, rec)?;
                    Some(previous.tenant.as_str().to_owned())
                }
                None => None,
            };
            let row = EncodedKeyRow::from_stored(rec);
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

    fn set_key_budget(&self, key_id: &KeyId, budget: Option<&KeyBudget>) -> Result<(), StoreError> {
        let subject = key_budget_subject(key_id);
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(BUDGETS_TABLE).map_err(store_err)?;
            match budget {
                Some(budget) => {
                    let encoded: EncodedKeyBudget = budget.into();
                    table
                        .insert(subject.as_str(), encode_json(&encoded).as_slice())
                        .map_err(store_err)?;
                }
                None => {
                    table.remove(subject.as_str()).map_err(store_err)?;
                }
            }
        }
        Self::bump_generation(&txn)?;
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn set_limits(
        &self,
        subject: &TenantId,
        limits: Option<&LimitPolicy>,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(LIMITS_TABLE).map_err(store_err)?;
            match limits.filter(|limits| !limits.is_empty()) {
                Some(limits) => {
                    let encoded: EncodedLimitPolicy = limits.into();
                    table
                        .insert(subject.as_str(), encode_json(&encoded).as_slice())
                        .map_err(store_err)?;
                }
                None => {
                    table.remove(subject.as_str()).map_err(store_err)?;
                }
            }
        }
        Self::bump_generation(&txn)?;
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn set_trace_export(&self, tenant: &TenantId, enabled: bool) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(TRACE_EXPORT_TABLE).map_err(store_err)?;
            if enabled {
                table
                    .insert(tenant.as_str(), encode_trace_export_row().as_slice())
                    .map_err(store_err)?;
            } else {
                table.remove(tenant.as_str()).map_err(store_err)?;
            }
        }
        Self::bump_generation(&txn)?;
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn put_rate_card(&self, card: &StoredRateCard) -> Result<(), StoreError> {
        // The row and the bump share one write transaction: they commit
        // together or not at all.
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(RATE_CARDS_TABLE).map_err(store_err)?;
            table
                .insert(
                    card.chain.as_str(),
                    encode_json(&EncodedRateCardRow::from(card)).as_slice(),
                )
                .map_err(store_err)?;
        }
        Self::bump_generation(&txn)?;
        txn.commit().map_err(store_err)?;
        Ok(())
    }

    fn put_rate_card_if_absent(&self, card: &StoredRateCard) -> Result<bool, StoreError> {
        // redb serializes write transactions, so the existence check and the
        // insert below cannot interleave with another writer's.
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(RATE_CARDS_TABLE).map_err(store_err)?;
            if table.get(card.chain.as_str()).map_err(store_err)?.is_some() {
                // Nothing to write and no bump. Dropping `txn` without a
                // commit rolls the empty transaction back.
                return Ok(false);
            }
            table
                .insert(
                    card.chain.as_str(),
                    encode_json(&EncodedRateCardRow::from(card)).as_slice(),
                )
                .map_err(store_err)?;
        }
        Self::bump_generation(&txn)?;
        txn.commit().map_err(store_err)?;
        Ok(true)
    }

    fn claim_object(
        &self,
        object_id: &str,
        tenant: &TenantId,
        ttl: Option<Duration>,
    ) -> Result<ObjectOwner, StoreError> {
        check_object_id(object_id)?;
        let now = unix_now_secs();
        // redb serializes write transactions, so the read and the insert
        // below cannot interleave with another claim.
        let txn = self.db.begin_write().map_err(store_err)?;
        let owner = {
            let mut table = txn.open_table(OBJECT_OWNERS_TABLE).map_err(store_err)?;
            let mut expiry = txn.open_table(OBJECT_EXPIRY_TABLE).map_err(store_err)?;
            // Remove a bounded number of expired rows, so they cannot pile
            // up. An index entry whose row was replaced since is dropped
            // without touching the row.
            let mut expired = Vec::new();
            for entry in expiry
                .range::<(u64, &str)>(..(now.saturating_add(1), ""))
                .map_err(store_err)?
                .take(OBJECT_SWEEP_PER_CLAIM)
            {
                let (key, _) = entry.map_err(store_err)?;
                let (at, id) = key.value();
                expired.push((at, id.to_string()));
            }
            for (at, id) in expired {
                expiry.remove((at, id.as_str())).map_err(store_err)?;
                let current = table
                    .get(id.as_str())
                    .map_err(store_err)?
                    .map(|row| decode_object_owner_row(row.value()));
                if let Some(Ok(row)) = current {
                    if row.expires_at == Some(at) {
                        table.remove(id.as_str()).map_err(store_err)?;
                    }
                }
            }
            let existing = table
                .get(object_id)
                .map_err(store_err)?
                .map(|row| decode_object_owner_row(row.value()))
                .transpose()?;
            match existing {
                Some(owner) if owner.is_live(now) => owner,
                _ => {
                    let owner = ObjectOwner::new(tenant.clone(), ttl, now);
                    table
                        .insert(object_id, encode_object_owner_row(&owner).as_slice())
                        .map_err(store_err)?;
                    if let Some(at) = owner.expires_at {
                        expiry.insert((at, object_id), ()).map_err(store_err)?;
                    }
                    owner
                }
            }
        };
        txn.commit().map_err(store_err)?;
        Ok(owner)
    }

    fn object_owner(&self, object_id: &str) -> Result<Option<ObjectOwner>, StoreError> {
        check_object_id(object_id)?;
        let now = unix_now_secs();
        let txn = self.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(OBJECT_OWNERS_TABLE).map_err(store_err)?;
        Ok(table
            .get(object_id)
            .map_err(store_err)?
            .map(|row| decode_object_owner_row(row.value()))
            .transpose()?
            .filter(|owner| owner.is_live(now)))
    }

    fn is_durable(&self) -> bool {
        // Both file-backed stores survive a restart; the in-memory `redb`
        // backend `in_memory()` builds for tests does not, but only tests
        // can construct it.
        true
    }

    fn add_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        delta_micros: u64,
        token: FlushToken<'_>,
    ) -> Result<u64, StoreError> {
        // ONE write transaction covers the dedup read, the read-modify-write
        // of the total, and the sequence update. redb serializes write
        // transactions, so this is what makes concurrent replicas add rather
        // than clobber -- splitting it into a read txn plus a write txn would
        // reintroduce exactly the lost-update race the absolute writes had.
        let txn = self.db.begin_write().map_err(store_err)?;
        let total = {
            let mut seq_table = txn.open_table(SPEND_SEQ_TABLE).map_err(store_err)?;
            let mut spend_table = txn.open_table(SPEND_TABLE).map_err(store_err)?;
            let row = (stat_prefix, tenant.as_str(), period.as_str());
            let current = spend_table
                .get(row)
                .map_err(store_err)?
                .map(|guard| guard.value())
                .unwrap_or(0);
            let seq_key = (stat_prefix, tenant.as_str(), period.as_str(), token.node_id);
            let last_seq = seq_table
                .get(seq_key)
                .map_err(store_err)?
                .map(|guard| guard.value());
            if last_seq.is_some_and(|last| token.seq <= last) {
                // Replay: abort rather than commit, so a duplicate leaves no
                // trace in the WAL at all.
                drop(spend_table);
                drop(seq_table);
                txn.abort().map_err(store_err)?;
                return Ok(current);
            }
            let total = current.saturating_add(delta_micros);
            spend_table.insert(row, total).map_err(store_err)?;
            seq_table.insert(seq_key, token.seq).map_err(store_err)?;
            total
        };
        txn.commit().map_err(store_err)?;
        Ok(total)
    }

    fn overwrite_spend(
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

    fn last_flush_seq(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        node_id: &str,
    ) -> Result<u64, StoreError> {
        let txn = self.db.begin_read().map_err(store_err)?;
        let table = txn.open_table(SPEND_SEQ_TABLE).map_err(store_err)?;
        let seq = table
            .get((stat_prefix, tenant.as_str(), period.as_str(), node_id))
            .map_err(store_err)?
            .map(|guard| guard.value())
            .unwrap_or(0);
        Ok(seq)
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

    /// ONE write transaction, so one commit and one fsync, however many rows
    /// the flusher delivers in a tick; each row is the same dedup read and
    /// read-modify-write [`Self::add_spend`] does. A failure fails every row
    /// of the batch, and nothing of it is committed: the flusher retries each
    /// row under the same token next tick. A batch of nothing but replays
    /// writes nothing and is aborted, like a single replay.
    fn add_spend_batch(
        &self,
        stat_prefix: &str,
        node_id: &str,
        rows: &[SpendDelta<'_>],
    ) -> Vec<Result<u64, StoreError>> {
        match self.add_spend_batch_inner(stat_prefix, node_id, rows) {
            Ok(totals) => totals.into_iter().map(Ok).collect(),
            Err(err) => rows.iter().map(|_| Err(err.clone())).collect(),
        }
    }

    /// One read transaction for the whole batch.
    fn last_flush_seq_batch(
        &self,
        stat_prefix: &str,
        node_id: &str,
        rows: &[(TenantId, PeriodKey)],
    ) -> Vec<Result<u64, StoreError>> {
        self.read_spend_rows(rows, SPEND_SEQ_TABLE, |(tenant, period)| {
            (stat_prefix, tenant.as_str(), period.as_str(), node_id)
        })
    }

    /// One read transaction for the whole batch.
    fn load_spend_batch(
        &self,
        stat_prefix: &str,
        rows: &[(TenantId, PeriodKey)],
    ) -> Vec<Result<u64, StoreError>> {
        self.read_spend_rows(rows, SPEND_TABLE, |(tenant, period)| {
            (stat_prefix, tenant.as_str(), period.as_str())
        })
    }

    fn add_window_batch(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[WindowDelta<'_>],
    ) -> Vec<Result<u64, StoreError>> {
        match self.add_window_batch_inner(unix_now_secs(), scope, node_id, rows) {
            Ok(results) => results.into_iter().map(Ok).collect(),
            // One transaction: a failure fails every row of the batch.
            Err(err) => rows.iter().map(|_| Err(err.clone())).collect(),
        }
    }

    fn last_window_seq_batch(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[WindowRow],
    ) -> Vec<Result<u64, StoreError>> {
        self.read_windows(rows, |table_txn, row| {
            let table = table_txn.open_table(WINDOW_SEQ_TABLE).map_err(store_err)?;
            let (dim, len, idx) = (
                row.dimension.as_str(),
                row.window.length_secs,
                row.window.index,
            );
            Ok(table
                .get((scope, row.subject.as_str(), dim, len, idx, node_id))
                .map_err(store_err)?
                .map(|guard| guard.value())
                .unwrap_or(0))
        })
    }

    fn load_window_batch(&self, scope: &str, rows: &[WindowRow]) -> Vec<Result<u64, StoreError>> {
        self.read_windows(rows, |table_txn, row| {
            let table = table_txn.open_table(WINDOWS_TABLE).map_err(store_err)?;
            let (dim, len, idx) = (
                row.dimension.as_str(),
                row.window.length_secs,
                row.window.index,
            );
            Ok(table
                .get((scope, row.subject.as_str(), dim, len, idx))
                .map_err(store_err)?
                .map(|guard| guard.value())
                .unwrap_or(0))
        })
    }
}

impl RedbControlPlaneStore {
    /// [`ControlPlaneStore::add_spend_batch`]'s transaction.
    fn add_spend_batch_inner(
        &self,
        stat_prefix: &str,
        node_id: &str,
        rows: &[SpendDelta<'_>],
    ) -> Result<Vec<u64>, StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        let mut totals = Vec::with_capacity(rows.len());
        let mut wrote = false;
        {
            let mut seq_table = txn.open_table(SPEND_SEQ_TABLE).map_err(store_err)?;
            let mut spend_table = txn.open_table(SPEND_TABLE).map_err(store_err)?;
            for delta in rows {
                let row = (stat_prefix, delta.tenant.as_str(), delta.period.as_str());
                let seq_key = (
                    stat_prefix,
                    delta.tenant.as_str(),
                    delta.period.as_str(),
                    node_id,
                );
                let current = spend_table
                    .get(row)
                    .map_err(store_err)?
                    .map(|guard| guard.value())
                    .unwrap_or(0);
                let last_seq = seq_table
                    .get(seq_key)
                    .map_err(store_err)?
                    .map(|guard| guard.value());
                if last_seq.is_some_and(|last| delta.seq <= last) {
                    totals.push(current);
                    continue;
                }
                let total = current.saturating_add(delta.delta_micros);
                spend_table.insert(row, total).map_err(store_err)?;
                seq_table.insert(seq_key, delta.seq).map_err(store_err)?;
                totals.push(total);
                wrote = true;
            }
        }
        if wrote {
            txn.commit().map_err(store_err)?;
        } else {
            txn.abort().map_err(store_err)?;
        }
        Ok(totals)
    }

    /// Reads one `u64` per spend row inside a single read transaction; a
    /// missing row reads as `0`, as [`ControlPlaneStore::load_spend`] does.
    fn read_spend_rows<'r, K: redb::Key + 'static>(
        &self,
        rows: &'r [(TenantId, PeriodKey)],
        table: redb::TableDefinition<'_, K, u64>,
        key: impl Fn(&'r (TenantId, PeriodKey)) -> K::SelfType<'r>,
    ) -> Vec<Result<u64, StoreError>> {
        let read = || -> Result<Vec<u64>, StoreError> {
            let txn = self.db.begin_read().map_err(store_err)?;
            let table = txn.open_table(table).map_err(store_err)?;
            rows.iter()
                .map(|row| {
                    Ok(table
                        .get(key(row))
                        .map_err(store_err)?
                        .map(|guard| guard.value())
                        .unwrap_or(0))
                })
                .collect()
        };
        match read() {
            Ok(values) => values.into_iter().map(Ok).collect(),
            Err(err) => rows.iter().map(|_| Err(err.clone())).collect(),
        }
    }

    /// Reads one value per row inside a single read transaction.
    fn read_windows(
        &self,
        rows: &[WindowRow],
        read: impl Fn(&redb::ReadTransaction, &WindowRow) -> Result<u64, StoreError>,
    ) -> Vec<Result<u64, StoreError>> {
        let txn = match self.db.begin_read().map_err(store_err) {
            Ok(txn) => txn,
            Err(err) => return rows.iter().map(|_| Err(err.clone())).collect(),
        };
        rows.iter().map(|row| read(&txn, row)).collect()
    }

    /// One write transaction for the whole batch: prune expired rows, then
    /// the same read-modify-write `add_spend` does, per row.
    fn add_window_batch_inner(
        &self,
        now_secs: u64,
        scope: &str,
        node_id: &str,
        rows: &[WindowDelta<'_>],
    ) -> Result<Vec<u64>, StoreError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        let mut totals = Vec::with_capacity(rows.len());
        {
            let mut windows = txn.open_table(WINDOWS_TABLE).map_err(store_err)?;
            let mut seqs = txn.open_table(WINDOW_SEQ_TABLE).map_err(store_err)?;
            prune_expired_windows(&mut windows, &mut seqs, now_secs)?;
            for delta in rows {
                let row = delta.row;
                let (dim, len, idx) = (
                    row.dimension.as_str(),
                    row.window.length_secs,
                    row.window.index,
                );
                let key = (scope, row.subject.as_str(), dim, len, idx);
                let seq_key = (scope, row.subject.as_str(), dim, len, idx, node_id);
                let current = windows
                    .get(key)
                    .map_err(store_err)?
                    .map(|guard| guard.value())
                    .unwrap_or(0);
                let last = seqs
                    .get(seq_key)
                    .map_err(store_err)?
                    .map(|guard| guard.value());
                if last.is_some_and(|last| delta.seq <= last) {
                    totals.push(current);
                    continue;
                }
                let total = current.saturating_add(delta.delta);
                windows.insert(key, total).map_err(store_err)?;
                seqs.insert(seq_key, delta.seq).map_err(store_err)?;
                totals.push(total);
            }
        }
        txn.commit().map_err(store_err)?;
        Ok(totals)
    }
}

/// Deletes window rows and seq entries past end + grace. A full scan: the
/// tables hold only live windows plus the grace tail, so they stay small.
fn prune_expired_windows(
    windows: &mut redb::Table<'_, WindowRowKey<'static>, u64>,
    seqs: &mut redb::Table<
        '_,
        (
            &'static str,
            &'static str,
            &'static str,
            u64,
            u64,
            &'static str,
        ),
        u64,
    >,
    now_secs: u64,
) -> Result<(), StoreError> {
    let expired = |len: u64, idx: u64| {
        let key = WindowKey {
            length_secs: len,
            index: idx,
        };
        key.end_secs().saturating_add(WINDOW_ROW_GRACE_SECS) < now_secs
    };
    let dead: Vec<(String, String, String, u64, u64)> = windows
        .iter()
        .map_err(store_err)?
        .filter_map(|entry| {
            let (k, _) = entry.ok()?;
            let (scope, subject, dim, len, idx) = k.value();
            expired(len, idx).then(|| {
                (
                    scope.to_string(),
                    subject.to_string(),
                    dim.to_string(),
                    len,
                    idx,
                )
            })
        })
        .collect();
    for (scope, subject, dim, len, idx) in &dead {
        windows
            .remove((scope.as_str(), subject.as_str(), dim.as_str(), *len, *idx))
            .map_err(store_err)?;
    }
    let dead: Vec<(String, String, String, u64, u64, String)> = seqs
        .iter()
        .map_err(store_err)?
        .filter_map(|entry| {
            let (k, _) = entry.ok()?;
            let (scope, subject, dim, len, idx, node) = k.value();
            expired(len, idx).then(|| {
                (
                    scope.to_string(),
                    subject.to_string(),
                    dim.to_string(),
                    len,
                    idx,
                    node.to_string(),
                )
            })
        })
        .collect();
    for (scope, subject, dim, len, idx, node) in &dead {
        seqs.remove((
            scope.as_str(),
            subject.as_str(),
            dim.as_str(),
            *len,
            *idx,
            node.as_str(),
        ))
        .map_err(store_err)?;
    }
    Ok(())
}

/// A freshly minted virtual key, returned to the admin caller so the
/// plaintext can be shown EXACTLY ONCE (it is never stored -- only its
/// digest is). Its `Debug` redacts the plaintext: the whole point of the
/// digest-only store is that key material never reaches a log.
pub struct MintedKey {
    pub key_id: KeyId,
    pub tenant: TenantId,
    pub plaintext: String,
    /// The key's chargeback tags after the mint.
    pub tags: ChargebackTags,
}

impl std::fmt::Debug for MintedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedKey")
            .field("key_id", &self.key_id)
            .field("tenant", &self.tenant)
            .field("tags", &self.tags)
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

/// One key as a LISTING sees it: stable identity, owning tenant, revocation
/// state, and the configured ceiling.
///
/// Deliberately the same "never key material" rule [`StoredKey`]'s `Debug`
/// follows -- there is no digest field here (an admin listing has no use for
/// it) and no plaintext field (the plaintext is not stored anywhere to
/// return; see [`MintedKey`] for the one place it exists at all).
///
/// Produced by [`ControlPlane::list_keys`]; `proxy-admin`'s gated
/// `GET /keys` renders it.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyListing {
    pub key_id: KeyId,
    pub tenant: TenantId,
    /// Whether this key is revoked. Revoked keys STAY in the snapshot (the
    /// authenticator rejects them there -- see `crate::auth::KeyRecord`), so
    /// a listing that dropped them would hide exactly the rows an operator
    /// auditing "what was revoked" came to see.
    pub revoked: bool,
    /// The key's own spend ceiling, or `None` when none is configured
    /// (unlimited) -- see [`crate::spend::TenantBudget`]'s doc for why an
    /// absent budget and an explicit zero ceiling are not the same thing.
    pub budget: Option<KeyBudget>,
    pub limits: Option<LimitPolicy>,
    /// The key's own model allow-list, or `None` when it inherits its tenant.
    pub model_access: Option<ModelAccess>,
    /// Chargeback tags set on the key (key metadata); empty when none.
    pub tags: Arc<ChargebackTags>,
}

// Rust note: hand-written, not derived, matching every other `Debug` in this
// file and in `auth.rs`: derived would print the same fields, but the
// convention across the key-handling types is that a reader can tell at a
// glance nothing secret is ever printed by accident.
impl std::fmt::Debug for KeyListing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyListing")
            .field("key_id", &self.key_id)
            .field("tenant", &self.tenant)
            .field("revoked", &self.revoked)
            .field("budget", &self.budget)
            .field("limits", &self.limits)
            .field("model_access", &self.model_access)
            .field("tags", &self.tags)
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

/// The key-encryption keys for tenant provider credentials plus the secret
/// that keys their fingerprints (ADR-0007 decision 2).
///
/// The fingerprint secret is the auth `hmac_secret` bytes. [`HmacSecret`]
/// deliberately has no accessor back to its bytes, so the raw bytes are kept
/// here, zeroized on drop, for exactly this one use.
pub struct CredentialKeys {
    ring: KeyRing,
    fingerprint_secret: Zeroizing<Vec<u8>>,
}

impl CredentialKeys {
    pub fn new(ring: KeyRing, hmac_secret: &[u8]) -> Self {
        Self {
            ring,
            fingerprint_secret: Zeroizing::new(hmac_secret.to_vec()),
        }
    }
}

impl std::fmt::Debug for CredentialKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialKeys")
            .field("ring", &self.ring)
            .finish_non_exhaustive()
    }
}

/// What the admin API may show about a stored tenant credential. There is no
/// field that can hold the secret or the sealed bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TenantCredentialMetadata {
    pub tenant: String,
    pub provider: String,
    pub last4: String,
    pub fingerprint: String,
    pub created_at: String,
    pub updated_at: String,
    pub verified_at: Option<String>,
    pub policy_generation: u64,
}

impl TenantCredentialMetadata {
    fn from_row(row: &StoredTenantCredential, policy_generation: u64) -> Self {
        Self {
            tenant: row.tenant.as_str().to_string(),
            provider: row.provider.clone(),
            last4: row.last4.clone(),
            fingerprint: row.fingerprint.clone(),
            created_at: row.created_at.clone(),
            updated_at: row.updated_at.clone(),
            verified_at: row.verified_at.clone(),
            policy_generation,
        }
    }
}

/// Why [`ControlPlane::store_tenant_secret`] did not store a credential.
///
/// A local enum rather than another [`StoreError`] variant: the admin layer
/// must tell "this deployment has no credential keys" (a clear refusal the
/// operator fixes in config) apart from a store outage (a retryable 5xx), and
/// `StoreError` is matched exhaustively by every store backend.
#[derive(Debug, PartialEq, Eq)]
pub enum CredentialStoreError {
    /// `typed_config.tenant_credentials` is not configured.
    NotConfigured,
    Crypto(CryptoError),
    Store(StoreError),
}

impl From<StoreError> for CredentialStoreError {
    fn from(err: StoreError) -> Self {
        CredentialStoreError::Store(err)
    }
}

impl std::fmt::Display for CredentialStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialStoreError::NotConfigured => write!(
                f,
                "tenant credentials are not enabled: `tenant_credentials` is not configured \
                 on the auth filter"
            ),
            CredentialStoreError::Crypto(err) => write!(f, "{err}"),
            CredentialStoreError::Store(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for CredentialStoreError {}

/// Suppression state for the "credential row is unusable" warning. Lives on
/// the [`ControlPlane`], touched only during a rebuild, so the request path
/// never sees it.
#[derive(Default)]
struct CredentialWarnings {
    /// (tenant, provider, reason) triples already logged and still failing.
    seen: Mutex<HashSet<(String, String, &'static str)>>,
    emitted: AtomicU64,
}

/// Opens every stored row into the per-tenant sets the snapshot publishes
/// (ADR-0007 decision 3). A row that cannot be opened becomes
/// [`TenantCredential::Unusable`] and is never dropped, so that tenant fails
/// closed instead of falling back to the platform key. This path fails
/// closed but must be visible (AGENTS.md "Fail-open controls"): one warning
/// per (tenant, provider, reason) until the row is usable again or gone, so a
/// poller rebuilding every 48 s does not repeat it forever. Warnings name
/// tenant, provider and key id only, never sealed or plaintext bytes.
fn decrypt_credentials(
    keys: Option<&CredentialKeys>,
    warnings: &CredentialWarnings,
    rows: Vec<StoredTenantCredential>,
) -> HashMap<TenantId, Arc<TenantCredentialSet>> {
    let mut by_tenant: HashMap<TenantId, HashMap<String, TenantCredential>> = HashMap::new();
    let mut failing: HashSet<(String, String, &'static str)> = HashSet::new();
    let mut to_warn = Vec::new();
    for row in rows {
        let outcome = match keys {
            None => Err("key_ring_not_configured"),
            Some(keys) => credential_crypto::open(
                &keys.ring,
                row.tenant.as_str(),
                &row.provider,
                &credential_crypto::SealedCredential {
                    key_id: row.key_id.clone(),
                    nonce: row.nonce,
                    ciphertext: row.ciphertext.clone(),
                },
            )
            .map_err(|err| match err {
                CryptoError::UnknownKeyId(_) => "unknown_key_id",
                _ => "decrypt_failed",
            }),
        };
        let entry = match outcome {
            Ok(secret) => TenantCredential::Usable(secret),
            Err(reason) => {
                let id = (
                    row.tenant.as_str().to_string(),
                    row.provider.clone(),
                    reason,
                );
                failing.insert(id.clone());
                to_warn.push((id, row.key_id.clone()));
                TenantCredential::Unusable
            }
        };
        by_tenant
            .entry(row.tenant)
            .or_default()
            .insert(row.provider, entry);
    }
    {
        let mut seen = warnings
            .seen
            .lock()
            .expect("credential warning mutex poisoned");
        // Forget entries that recovered, so a later regression warns again.
        seen.retain(|id| failing.contains(id));
        for (id, key_id) in to_warn {
            if !seen.insert(id.clone()) {
                continue;
            }
            warnings.emitted.fetch_add(1, Ordering::Relaxed);
            let (tenant, provider, reason) = id;
            if reason == "key_ring_not_configured" {
                tracing::warn!(
                    tenant = tenant.as_str(),
                    provider = provider.as_str(),
                    key_id = key_id.as_str(),
                    "tenant credentials are stored but `tenant_credentials` is not configured \
                     on the auth filter; this tenant's requests fail closed (503)"
                );
            } else {
                tracing::warn!(
                    tenant = tenant.as_str(),
                    provider = provider.as_str(),
                    key_id = key_id.as_str(),
                    reason,
                    "stored tenant credential cannot be decrypted; this tenant's requests \
                     fail closed (503)"
                );
            }
        }
    }
    by_tenant
        .into_iter()
        .map(|(tenant, set)| (tenant, Arc::new(TenantCredentialSet::new(set))))
        .collect()
}

/// When this replica last confirmed its published snapshot against the store,
/// and how stale virtual-key authentication may let it get (review H4).
///
/// Shared by the [`ControlPlane`] (which marks it on every successful poll or
/// rebuild) and every worker's `VirtualKeyAuthenticator` (which reads it per
/// request). Two atomics, so the request path takes no lock: a read is one
/// `Instant::now()` and two relaxed loads.
///
/// ADR-0005 makes authentication fail CLOSED. At boot an unreachable store
/// already refuses to bind; at runtime the poller keeps serving the last-good
/// snapshot so a store blip does not 401 every request, but only up to
/// [`Self::max_staleness`]. Past it the snapshot may hold a key revoked since
/// on another replica, so virtual-key authentication refuses every request
/// until a poll succeeds again.
#[derive(Debug)]
pub struct PolicyFreshness {
    epoch: Instant,
    /// Milliseconds after `epoch` of the last successful reconciliation.
    reconciled_at_ms: AtomicU64,
    /// The bound, in milliseconds. `0` means no bound has been configured,
    /// which only test-built control planes ever have: the auth filter sets
    /// one for every chain it builds (see `auth_filter::parse_config`).
    max_staleness_ms: AtomicU64,
}

impl PolicyFreshness {
    fn new() -> Self {
        PolicyFreshness {
            epoch: Instant::now(),
            reconciled_at_ms: AtomicU64::new(0),
            max_staleness_ms: AtomicU64::new(0),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn mark_reconciled(&self) {
        self.reconciled_at_ms
            .store(self.now_ms(), Ordering::Relaxed);
    }

    /// Time since the last successful reconciliation.
    pub fn age(&self) -> Duration {
        let reconciled = self.reconciled_at_ms.load(Ordering::Relaxed);
        Duration::from_millis(self.now_ms().saturating_sub(reconciled))
    }

    /// Sets the staleness bound. Called by the auth filter each time it builds
    /// the chain, so a reload that changes the bound takes effect.
    pub fn set_max_staleness(&self, bound: Duration) {
        let ms = u64::try_from(bound.as_millis()).unwrap_or(u64::MAX);
        self.max_staleness_ms.store(ms, Ordering::Relaxed);
    }

    /// The configured bound, if any.
    pub fn max_staleness(&self) -> Option<Duration> {
        match self.max_staleness_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        }
    }

    /// Whether the snapshot is older than the bound, so authentication must
    /// fail closed.
    pub fn is_expired(&self) -> bool {
        self.max_staleness().is_some_and(|bound| self.age() > bound)
    }
}

/// The `llmproxy_policy_snapshot_age_seconds` series for one control plane.
/// The registry only takes deltas, so the last published value is kept.
struct AgeGauge {
    registry: Arc<proxy_observability::stats::Registry>,
    handle: proxy_observability::stats::Handle,
    last: u64,
}

/// Tenant and key row counts of one control-plane load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct LoadedRows {
    tenants: usize,
    keys: usize,
}

impl LoadedRows {
    fn of(loaded: &StoredControlPlane) -> Self {
        LoadedRows {
            tenants: loaded.tenants.len(),
            keys: loaded.keys.len(),
        }
    }

    /// Whether `self` lost every key, or every tenant, that `before` held.
    /// Per set rather than both at once: zero keys refuses every stored key
    /// even while tenants remain.
    fn emptied_since(self, before: LoadedRows) -> bool {
        (before.keys > 0 && self.keys == 0) || (before.tenants > 0 && self.tenants == 0)
    }
}

/// The `llmproxy_policy_store_emptied_total` and `llmproxy_policy_store_rows`
/// series for one control plane. The rows gauges only take deltas, so the
/// last published counts are kept.
struct StoreRowMetrics {
    registry: Arc<proxy_observability::stats::Registry>,
    emptied: proxy_observability::stats::Handle,
    keys: proxy_observability::stats::Handle,
    tenants: proxy_observability::stats::Handle,
    published: LoadedRows,
}

impl StoreRowMetrics {
    fn publish(&mut self, rows: LoadedRows) {
        let worker = proxy_observability::stats::WorkerId(0);
        self.registry.add(
            worker,
            self.keys,
            rows.keys as i64 - self.published.keys as i64,
        );
        self.registry.add(
            worker,
            self.tenants,
            rows.tenants as i64 - self.published.tenants as i64,
        );
        self.published = rows;
    }
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
    /// The `policy_generation` stamp the currently-published snapshot
    /// reflects. `None` means "unknown" -- a stamp read that failed at boot,
    /// or a store whose `policy_generation` errored -- which forces the next
    /// poll to rebuild rather than risk comparing against a stale or
    /// meaningless number. See [`Self::poll_once`].
    last_generation: Mutex<Option<u64>>,
    /// When a poll (or a `rebuild()`) last SUCCEEDED, and the staleness
    /// bound. See [`Self::snapshot_age`] and [`PolicyFreshness`].
    freshness: Arc<PolicyFreshness>,
    /// Set by [`Self::export_snapshot_age`]; published by the poller.
    age_gauge: Mutex<Option<AgeGauge>>,
    /// Tenant and key rows in the last load this replica published, so a
    /// load that finds the store suddenly empty can say what it lost. See
    /// [`Self::note_loaded_rows`].
    loaded_rows: Mutex<LoadedRows>,
    /// `llmproxy_policy_store_emptied_total` and `llmproxy_policy_store_rows`,
    /// resolved alongside the age gauge by [`Self::export_snapshot_age`].
    row_metrics: Mutex<Option<StoreRowMetrics>>,
    poller: Mutex<Option<PolicyPoller>>,
    /// Key-encryption keys for tenant provider credentials (ADR-0007
    /// decision 2). `None` means `typed_config.tenant_credentials` is not
    /// configured: stored rows then decrypt to `Unusable` and nothing can be
    /// sealed.
    credential_keys: Option<CredentialKeys>,
    credential_warnings: CredentialWarnings,
    /// The rate cards of the last successful load, by chain. Not part of
    /// [`ControlPlaneSnapshot`]: the data plane never reads cards here, it
    /// reads the chain's own registry, which a watch below keeps current.
    rate_cards: Mutex<HashMap<String, StoredRateCard>>,
    rate_card_watches: Mutex<Vec<RateCardWatch>>,
    /// Where `llmproxy.token_limit` publishes concurrent-stream leases
    /// (ADR-0006 amendment E): set for a shared store, so the leases live in
    /// the same Redis as the counters; `None` keeps them in process.
    lease_store: Option<Arc<dyn crate::window_counter::LeaseStore>>,
}

/// Who wants to hear when a chain's stored rate card changes.
struct RateCardWatch {
    chain: String,
    /// The card this watcher last settled, so an unrelated generation bump
    /// (a key minted, say) does not hand it the same card again. A deferred
    /// card is not recorded here, so it is offered again.
    last_delivered: Option<StoredRateCard>,
    callback: Box<dyn Fn(&StoredRateCard) -> RateCardDelivery + Send + Sync>,
}

/// What a rate-card watcher did with a card it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateCardDelivery {
    /// Installed, or refused for a reason that a later offer cannot change.
    /// The card is not offered again.
    Settled,
    /// Refused for now, for example because the card is dated ahead of this
    /// replica's clock. The card is offered again on every policy poll until
    /// the watcher settles it, even when the store does not change.
    Deferred,
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
        Self::new_with_credential_keys(store, secret, bootstrap_keys, None)
    }

    /// As [`Self::new`], with the key-encryption keys that seal and open
    /// tenant provider credentials. A separate constructor rather than a new
    /// `new` parameter so the many existing call sites, which have no tenant
    /// credentials, stay unchanged.
    pub fn new_with_credential_keys(
        store: Box<dyn ControlPlaneStore>,
        secret: HmacSecret,
        bootstrap_keys: KeySet,
        credential_keys: Option<CredentialKeys>,
    ) -> Result<Self, StoreError> {
        let credential_warnings = CredentialWarnings::default();
        let store: Arc<dyn ControlPlaneStore> = Arc::from(store);
        // Read the generation stamp BEFORE `load()`, not after.
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
        let mut loaded = store.load()?;
        let loaded_rows = LoadedRows::of(&loaded);
        let rate_cards = Self::take_rate_cards(&mut loaded);
        let snapshot = Self::build_snapshot(
            &bootstrap_keys,
            credential_keys.as_ref(),
            &credential_warnings,
            loaded,
            generation,
        );
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
            freshness: {
                let freshness = PolicyFreshness::new();
                freshness.mark_reconciled();
                Arc::new(freshness)
            },
            age_gauge: Mutex::new(None),
            loaded_rows: Mutex::new(loaded_rows),
            row_metrics: Mutex::new(None),
            poller: Mutex::new(None),
            credential_keys,
            credential_warnings,
            rate_cards: Mutex::new(rate_cards),
            rate_card_watches: Mutex::new(Vec::new()),
            lease_store: None,
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
    /// key was actually revoked". See the module doc and AGENTS.md "Fail-open controls".
    ///
    /// On success, also records the generation stamp the fresh
    /// snapshot reflects and marks `last_reconciled_at` as now -- both read
    /// BEFORE `load()`, for the same reason [`Self::new`]'s doc explains.
    /// `Err` leaves both untouched, exactly like `published`: a failed
    /// refresh is not a reconciliation and must not reset the staleness
    /// clock [`Self::snapshot_age`] reports.
    pub fn rebuild(&self) {
        let generation = self.store.policy_generation().ok();
        match self.store.load() {
            Ok(loaded) => {
                let snapshot = self.snapshot_from(loaded, generation);
                self.published.store(Arc::new(snapshot));
                *self
                    .last_generation
                    .lock()
                    .expect("control plane mutex poisoned") = generation;
                self.freshness.mark_reconciled();
                self.notify_rate_card_watches();
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "control-plane store refresh failed; keeping the last published snapshot"
                );
            }
        }
    }

    /// Replica-to-replica propagation step: reads ONLY the
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
            self.freshness.mark_reconciled();
            // Nothing changed, but a deferred rate card may have become
            // usable since the last poll.
            self.notify_rate_card_watches();
            return Ok(false);
        }
        let loaded = self.store.load()?;
        let snapshot = self.snapshot_from(loaded, Some(generation));
        self.published.store(Arc::new(snapshot));
        *self
            .last_generation
            .lock()
            .expect("control plane mutex poisoned") = Some(generation);
        self.freshness.mark_reconciled();
        self.notify_rate_card_watches();
        Ok(true)
    }

    /// How long since this replica's snapshot was last confirmed to match
    /// the store -- either a successful [`Self::poll_once`] (moved or not)
    /// or [`Self::rebuild`]. This is the raw number; the Prometheus
    /// `spend_reconciliation_age_seconds` value (ADR-0006 §5) that exports it
    /// is surfaced through the admin API -- this accessor, plus the
    /// policy poller's own staleness warning (see
    /// [`Self::start_policy_poller`]), is the replica-side half of that
    /// observability requirement.
    pub fn snapshot_age(&self) -> Duration {
        self.freshness.age()
    }

    /// The freshness clock and staleness bound this control plane marks,
    /// for the authenticator that enforces the bound.
    pub fn freshness(&self) -> Arc<PolicyFreshness> {
        Arc::clone(&self.freshness)
    }

    /// Exports [`Self::snapshot_age`] as `llmproxy_policy_snapshot_age_seconds`
    /// with `scope` (the chain's `stat_prefix`; bounded by the operator's
    /// config, never request data). The poller publishes it every tick, so a
    /// scrape lags the true age by at most one poll interval. The first call
    /// wins; later calls (one per worker build) change nothing.
    pub fn export_snapshot_age(
        &self,
        registry: Arc<proxy_observability::stats::Registry>,
        scope: &str,
    ) {
        let mut gauge = self.age_gauge.lock().expect("control plane mutex poisoned");
        if gauge.is_some() {
            return;
        }
        let handle = registry.resolve_capped(
            &proxy_observability::stats::instruments::POLICY_SNAPSHOT_AGE_SECONDS,
            &[("scope", scope)],
            256,
            &[("scope", "overflow")],
        );
        let rows_gauge = |kind: &str| {
            registry.resolve_capped(
                &proxy_observability::stats::instruments::POLICY_STORE_ROWS,
                &[("scope", scope), ("kind", kind)],
                256,
                &[("scope", "overflow"), ("kind", kind)],
            )
        };
        let mut row_metrics = StoreRowMetrics {
            emptied: registry.resolve_capped(
                &proxy_observability::stats::instruments::POLICY_STORE_EMPTIED,
                &[("scope", scope)],
                256,
                &[("scope", "overflow")],
            ),
            keys: rows_gauge("keys"),
            tenants: rows_gauge("tenants"),
            registry: Arc::clone(&registry),
            published: LoadedRows::default(),
        };
        // The boot load ran before the registry existed; publish its counts
        // now. `loaded_rows` is read under the `row_metrics` lock (the same
        // order `note_loaded_rows` takes them), so a load racing this is
        // either seen here or published by that load after this returns.
        let mut slot = self
            .row_metrics
            .lock()
            .expect("control plane mutex poisoned");
        row_metrics.publish(
            *self
                .loaded_rows
                .lock()
                .expect("control plane mutex poisoned"),
        );
        *slot = Some(row_metrics);
        drop(slot);
        *gauge = Some(AgeGauge {
            registry,
            handle,
            last: 0,
        });
        drop(gauge);
        self.publish_snapshot_age();
    }

    /// Sets the age gauge to the current [`Self::snapshot_age`], whole
    /// seconds. A no-op until [`Self::export_snapshot_age`] has run.
    pub fn publish_snapshot_age(&self) {
        let mut gauge = self.age_gauge.lock().expect("control plane mutex poisoned");
        let Some(gauge) = gauge.as_mut() else {
            return;
        };
        let age = self.snapshot_age().as_secs();
        // Rust note: the wrapping difference, applied back as an i64, is how
        // the registry's delta-only `add` sets a gauge to an absolute value
        // (the same trick the other delta-only gauges use).
        gauge.registry.add(
            proxy_observability::stats::WorkerId(0),
            gauge.handle,
            age.wrapping_sub(gauge.last) as i64,
        );
        gauge.last = age;
    }

    /// Records the row counts of a load in `llmproxy_policy_store_rows`, and
    /// makes a load that finds no keys, or no tenants, after the last load
    /// found some, loud: an ERROR with both counts and generation stamps,
    /// and one increment of `llmproxy_policy_store_emptied_total`.
    ///
    /// AGENTS.md "Fail-open controls": the replica adopts the empty state,
    /// which fails closed (every virtual key the store held now gets 401),
    /// but at INFO it was indistinguishable from a quiet store. The store
    /// stays the source of truth: keeping the last-good snapshot would keep
    /// serving keys the store no longer has, which fails open on revocation
    /// (ADR-0006 addendum 2026-10-16). A shared Redis restarted without
    /// persistence, or flushed, looks exactly like this: its generation
    /// stamp also reads back as 0. One line per transition, not per poll:
    /// once this load is recorded as empty, the next empty load compares
    /// equal and stays silent until a load finds rows again. The state is
    /// two counts on the poll path, never on a request worker.
    fn note_loaded_rows(&self, loaded: &StoredControlPlane, generation: Option<u64>) {
        let now = LoadedRows::of(loaded);
        let before = std::mem::replace(
            &mut *self
                .loaded_rows
                .lock()
                .expect("control plane mutex poisoned"),
            now,
        );
        let emptied = now.emptied_since(before);
        let mut metrics = self
            .row_metrics
            .lock()
            .expect("control plane mutex poisoned");
        if let Some(metrics) = metrics.as_mut() {
            // Re-read rather than publish `now`: a later load may already
            // have replaced it, and the gauge must end at the latest counts.
            let latest = *self
                .loaded_rows
                .lock()
                .expect("control plane mutex poisoned");
            metrics.publish(latest);
            if emptied {
                metrics
                    .registry
                    .incr(proxy_observability::stats::WorkerId(0), metrics.emptied, 1);
            }
        }
        drop(metrics);
        if !emptied {
            return;
        }
        let generation_before = *self
            .last_generation
            .lock()
            .expect("control plane mutex poisoned");
        tracing::error!(
            tenants_before = before.tenants,
            keys_before = before.keys,
            tenants_after = now.tenants,
            keys_after = now.keys,
            generation_before = ?generation_before,
            generation_after = ?generation,
            "control-plane store is now EMPTY of keys or tenants it held; every \
             virtual key it held now gets 401. Unless an operator removed them, the \
             store lost its data: a Redis restarted without persistence (AOF or RDB) \
             or flushed revokes every key fleet-wide"
        );
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
    /// `InMemoryControlPlaneStore` instead would leave the whole spend
    /// persistence path -- `add_spend`/`load_spend` on redb, additive writes,
    /// restart-resume -- wired to nothing, and a monthly ceiling would reset
    /// to zero on every process restart: a budget an operator could escape by
    /// bouncing the proxy. See `spend_limit_filter`'s module doc.
    ///
    /// Sharing the store does not make the flusher and the policy poller share
    /// a bottleneck: see [`ControlPlaneStore`]'s "Policy calls and spend calls
    /// must not queue behind each other".
    pub fn store(&self) -> Arc<dyn ControlPlaneStore> {
        Arc::clone(&self.store)
    }

    /// Publish concurrent-stream leases to `leases` rather than in process.
    /// Set before the control plane is shared, alongside the store it
    /// belongs with.
    pub fn with_lease_store(mut self, leases: Arc<dyn crate::window_counter::LeaseStore>) -> Self {
        self.lease_store = Some(leases);
        self
    }

    /// The lease store [`Self::with_lease_store`] set, if any. A chain whose
    /// counters are shared must share its stream leases too, or N replicas
    /// admit N times a concurrent-stream ceiling.
    pub fn lease_store(&self) -> Option<Arc<dyn crate::window_counter::LeaseStore>> {
        self.lease_store.clone()
    }

    /// How many unusable-credential warnings have been emitted, for tests of
    /// the suppression.
    #[cfg(test)]
    fn credential_warnings_emitted(&self) -> u64 {
        self.credential_warnings.emitted.load(Ordering::Relaxed)
    }

    /// The HMAC secret this control plane was built with. Unused by the
    /// data-plane path (the authenticator keeps its own copy -- see
    /// `auth_filter::AuthFilterFactory::create`'s doc for why two independent
    /// `HmacSecret`s exist rather than one shared); this accessor exists for
    /// the key-minting endpoint, which needs the same secret to compute a
    /// digest a minted key will actually authenticate against.
    pub fn secret(&self) -> &HmacSecret {
        &self.secret
    }

    /// Every key this control plane currently serves -- bootstrap keys from
    /// config AND store keys, which [`ControlPlane::merge`] has already
    /// de-duplicated by `key_id` (one row per key, store wins a collision),
    /// so this cannot double-count a key that exists in both sources.
    ///
    /// Reads the PUBLISHED snapshot, never the store: a listing is a control
    /// read over the same state the data plane authenticates against, it
    /// costs no I/O, and it therefore cannot show a key that has not been
    /// republished yet (or hide one that has) -- the same "what is actually
    /// in effect" property every other snapshot reader here relies on.
    ///
    /// Sorted by `(tenant, key_id)` so the admin API answers the same bytes
    /// for the same state: a `HashMap` iteration order would make the
    /// response body flap between identical calls, which is exactly the kind
    /// of noise that hides a real diff.
    pub fn list_keys(&self) -> Vec<KeyListing> {
        let snapshot = self.published.load();
        let mut keys: Vec<KeyListing> = snapshot
            .keys
            .iter()
            .map(|(_digest, record)| KeyListing {
                key_id: record.key_id.clone(),
                tenant: record.tenant.clone(),
                revoked: record.revoked,
                budget: snapshot.key_budgets.get(&record.key_id).copied(),
                limits: snapshot.key_limits.get(&record.key_id).copied(),
                model_access: snapshot.key_policies.get(&record.key_id).cloned(),
                tags: record.tags.clone(),
            })
            .collect();
        keys.sort_by(|a, b| {
            (a.tenant.as_str(), a.key_id.as_str()).cmp(&(b.tenant.as_str(), b.key_id.as_str()))
        });
        keys
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
        self.mint_key_with_tags(tenant, key_id, None)
    }

    /// [`Self::mint_key`] with chargeback tags as the key's metadata,
    /// validated by `chargeback::validate_key_tags`. `None` keeps the tags a
    /// re-minted (rotated) key already has, so a rotation that does not
    /// mention tags does not drop its attribution; a new key gets none.
    pub fn mint_key_with_tags(
        &self,
        tenant: &TenantId,
        key_id: &KeyId,
        tags: Option<&ChargebackTags>,
    ) -> Result<MintedKey, StoreError> {
        if let Some(tags) = tags {
            proxy_observability::chargeback::validate_key_tags(tags)
                .map_err(|e| StoreError::InvalidInput(format!("tags: {e}")))?;
        }
        crate::auth::check_principal_id("tenant", tenant.as_str())
            .and_then(|()| crate::auth::check_principal_id("key_id", key_id.as_str()))
            .map_err(StoreError::InvalidInput)?;
        reject_control_characters("tenant", tenant.as_str())?;
        reject_control_characters("key_id", key_id.as_str())?;
        reject_reserved_tenant(tenant)?;
        let snapshot = self.published.load();
        if let Some(owner) = snapshot.key_tenants.get(key_id) {
            if owner != tenant {
                return Err(StoreError::Conflict("key ownership is immutable".into()));
            }
            if snapshot
                .keys
                .iter()
                .any(|(_, record)| &record.key_id == key_id && record.revoked)
            {
                return Err(StoreError::Conflict(
                    "revoked key IDs cannot be reused".into(),
                ));
            }
        }
        let tags = match tags {
            Some(tags) => tags.clone(),
            None => snapshot
                .keys
                .iter()
                .find(|(_, record)| &record.key_id == key_id)
                .map(|(_, record)| (*record.tags).clone())
                .unwrap_or_default(),
        };
        drop(snapshot);
        let rng = ring::rand::SystemRandom::new();
        let plaintext = crate::auth::generate_plaintext_key(&rng);
        let digest = crate::auth::digest_bytes(&self.secret, &plaintext);
        self.store.put_key(&StoredKey {
            key_id: key_id.clone(),
            digest,
            tenant: tenant.clone(),
            revoked: false,
            tags: tags.clone(),
        })?;
        self.rebuild();
        Ok(MintedKey {
            key_id: key_id.clone(),
            tenant: tenant.clone(),
            plaintext,
            tags,
        })
    }

    /// Replaces the chargeback tags of the store key `key_id` (an empty map
    /// clears them), then republishes. The tags apply to requests
    /// authenticated after the republish.
    ///
    /// A key defined in configuration is refused (`Conflict`): a store row
    /// for it would win the `key_id` collision in [`Self::merge`] and shadow
    /// a later revocation in the configuration. Its tags are set there. A
    /// revoked key is refused too; the store's own check also catches a
    /// revoke that races this write.
    pub fn set_key_tags(&self, key_id: &KeyId, tags: &ChargebackTags) -> Result<(), StoreError> {
        proxy_observability::chargeback::validate_key_tags(tags)
            .map_err(|e| StoreError::InvalidInput(format!("tags: {e}")))?;
        if self
            .bootstrap_keys
            .iter()
            .any(|(_, record)| &record.key_id == key_id)
        {
            return Err(StoreError::Conflict(
                "key is defined in the configuration; set its tags there".into(),
            ));
        }
        let snapshot = self.published.load();
        let Some((digest, record)) = snapshot
            .keys
            .iter()
            .find(|(_, record)| &record.key_id == key_id)
        else {
            return Err(StoreError::NotFound);
        };
        if record.revoked {
            return Err(StoreError::Conflict("key is revoked".into()));
        }
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| StoreError::InvalidInput("key digest is not 32 bytes".into()))?;
        let next = StoredKey {
            key_id: key_id.clone(),
            digest,
            tenant: record.tenant.clone(),
            revoked: false,
            tags: tags.clone(),
        };
        drop(snapshot);
        self.store.put_key(&next)?;
        self.rebuild();
        Ok(())
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
        reject_control_characters("tenant", tenant.as_str())?;
        reject_reserved_tenant(tenant)?;
        self.store.create_tenant(tenant)?;
        self.rebuild();
        Ok(())
    }

    /// Deletes `tenant` and revokes every key that authenticates as it, then
    /// republishes. Returns how many keys this call revoked.
    ///
    /// Deleting a tenant offboards it, so none of its keys may keep
    /// authenticating (review H4). The stores' own `delete_tenant` leaves the
    /// key rows alone, so the cascade lives here, once, for every store:
    ///
    /// - an active store key is revoked, which keeps its row as the audit
    ///   trail, exactly as `DELETE /keys/{id}` does;
    /// - an active config (bootstrap) key gets a revoked store row under the
    ///   same `key_id` and digest. The store wins a `key_id` collision in
    ///   [`Self::merge`], so the config key stops authenticating here and on
    ///   every replica that shares the store, and stays revoked across a
    ///   restart. Revoked IDs are permanent tombstones, as for any key.
    ///
    /// Keys are revoked BEFORE the tenant row goes, so a failure part way
    /// leaves the tenant present with some keys revoked: the safe direction,
    /// and a retry finishes the job. A second sweep runs after the row is
    /// deleted to catch a key minted concurrently with the first one. A key
    /// minted after this returns belongs to a new tenant of the same name,
    /// because tenants are implicit (a key or a policy creates one).
    pub fn delete_tenant(&self, tenant: &TenantId) -> Result<usize, StoreError> {
        let mut revoked = self.revoke_tenant_keys(tenant)?;
        self.store.delete_tenant(tenant)?;
        revoked += self.revoke_tenant_keys(tenant)?;
        self.rebuild();
        Ok(revoked)
    }

    /// The cascade step of [`Self::delete_tenant`]: revokes every active key
    /// of `tenant`, store and bootstrap alike. Reads the store, not the
    /// published snapshot, so a key another replica minted since our last
    /// poll is included.
    fn revoke_tenant_keys(&self, tenant: &TenantId) -> Result<usize, StoreError> {
        let loaded = self.store.load()?;
        let mut revoked = 0;
        for key in loaded
            .keys
            .iter()
            .filter(|key| &key.tenant == tenant && !key.revoked)
        {
            match self.store.revoke_key(&key.key_id) {
                Ok(()) => revoked += 1,
                // Gone between the load and the revoke: nothing to revoke.
                Err(StoreError::NotFound) => {}
                Err(err) => return Err(err),
            }
        }
        let stored: HashSet<&KeyId> = loaded.keys.iter().map(|key| &key.key_id).collect();
        for (digest, record) in self.bootstrap_keys.iter() {
            if &record.tenant != tenant || record.revoked || stored.contains(&record.key_id) {
                continue;
            }
            // Bootstrap digests are HMAC-SHA256 outputs, so always 32 bytes;
            // a length mismatch would be a parse bug, and skipping the row
            // would leave the key live, so it is an error rather than a skip.
            let digest: [u8; 32] = digest.try_into().map_err(|_| {
                StoreError::InvalidInput("bootstrap key digest is not 32 bytes".into())
            })?;
            self.store.put_key(&StoredKey {
                key_id: record.key_id.clone(),
                digest,
                tenant: tenant.clone(),
                revoked: true,
                tags: (*record.tags).clone(),
            })?;
            revoked += 1;
        }
        Ok(revoked)
    }

    /// Sets `tenant`'s model-access policy, then republishes.
    pub fn set_policy(&self, tenant: &TenantId, access: &ModelAccess) -> Result<(), StoreError> {
        self.store.set_policy(tenant, access)?;
        self.rebuild();
        Ok(())
    }

    /// Sets or clears `tenant`'s spend budget, then republishes --
    /// store-then-`rebuild()`, exactly like
    /// [`Self::set_policy`], so a budget change reaches every worker's
    /// `VirtualKeyAuthenticator` (and the spend enforcement filter)
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

    /// Records `tenant`'s trace-export opt-in (ADR-0008 decision 2) and
    /// republishes, so this replica's next request sees it; other replicas
    /// see it on their next poll.
    pub fn set_trace_export(&self, tenant: &TenantId, enabled: bool) -> Result<(), StoreError> {
        self.store.set_trace_export(tenant, enabled)?;
        self.rebuild();
        Ok(())
    }

    /// Whether `tenant` is opted in to trace export in the published
    /// snapshot.
    pub fn trace_export(&self, tenant: &TenantId) -> bool {
        self.handle().load().trace_export.contains(tenant)
    }

    /// Sets or clears a tenant's independent rate ceiling and republishes.
    pub fn set_tenant_limits(
        &self,
        tenant: &TenantId,
        limits: Option<&LimitPolicy>,
    ) -> Result<(), StoreError> {
        self.store.set_limits(tenant, limits)?;
        self.rebuild();
        Ok(())
    }

    /// Creates or replaces `rec`'s credential row -- keyed
    /// (`rec.tenant`, `rec.provider`) -- then republishes. Store-then-
    /// `rebuild()`, exactly the shape [`Self::set_policy`] and
    /// [`Self::set_budget`] use, so the write lands before any snapshot
    /// that could claim to reflect it (see the module doc's boot-vs-refresh
    /// section).
    ///
    /// Takes an already-sealed row. Callers holding a plaintext key use
    /// [`Self::store_tenant_secret`], which seals it first.
    pub fn put_tenant_credential(&self, rec: &StoredTenantCredential) -> Result<(), StoreError> {
        self.store.put_tenant_credential(rec)?;
        self.rebuild();
        Ok(())
    }

    /// Deletes one credential row (keyed (`tenant`, `provider`)), then
    /// republishes. [`StoreError::NotFound`] propagates exactly as the
    /// store returned it, with no rebuild -- the `?` returns first, and a
    /// row that was never there is nothing to republish (see
    /// [`ControlPlaneStore::delete_tenant_credential`]).
    pub fn delete_tenant_credential(
        &self,
        tenant: &TenantId,
        provider: &str,
    ) -> Result<(), StoreError> {
        self.store.delete_tenant_credential(tenant, provider)?;
        self.rebuild();
        Ok(())
    }

    /// Whether key-encryption keys are configured, so that
    /// [`Self::store_tenant_secret`] can store anything. The admin API checks
    /// this before the save-time probe, so a candidate key is never sent to a
    /// provider when it could not be stored afterwards.
    pub fn tenant_credentials_configured(&self) -> bool {
        self.credential_keys.is_some()
    }

    /// Seals `secret` under the current key-encryption key, stores it as
    /// (`tenant`, `provider`)'s credential row, republishes, and returns the
    /// row's metadata (ADR-0007 decisions 2 and 3). The plaintext is never
    /// part of the return value.
    ///
    /// Replacing an existing row keeps its `created_at`. `verified` records
    /// that the caller confirmed the key works upstream; the new row's
    /// `verified_at` is set only then, because a replaced secret has not been
    /// verified just because its predecessor was.
    ///
    /// Refuses with [`CredentialStoreError::NotConfigured`] when no
    /// key-encryption keys are configured: storing plaintext, or a row nothing
    /// could ever open, would both be worse than a refusal.
    pub fn store_tenant_secret(
        &self,
        tenant: &TenantId,
        provider: &str,
        secret: &TenantSecret,
        verified: bool,
    ) -> Result<TenantCredentialMetadata, CredentialStoreError> {
        let keys = self
            .credential_keys
            .as_ref()
            .ok_or(CredentialStoreError::NotConfigured)?;
        let sealed = credential_crypto::seal(&keys.ring, tenant.as_str(), provider, secret)
            .map_err(CredentialStoreError::Crypto)?;
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        // Admin-path read of the whole store, only to find the row being
        // replaced. Request workers never reach this.
        let created_at = self
            .store
            .load()?
            .tenant_credentials
            .into_iter()
            .find(|row| &row.tenant == tenant && row.provider == provider)
            .map(|row| row.created_at)
            .unwrap_or_else(|| now.clone());
        let row = StoredTenantCredential {
            schema_version: TENANT_CREDENTIALS_SCHEMA_VERSION,
            tenant: tenant.clone(),
            provider: provider.to_string(),
            key_id: sealed.key_id,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            last4: credential_crypto::last4(secret),
            fingerprint: credential_crypto::fingerprint(&keys.fingerprint_secret, secret),
            created_at,
            updated_at: now.clone(),
            verified_at: verified.then_some(now),
        };
        self.put_tenant_credential(&row)?;
        // Read after the write so the stamp is the one this write produced.
        // A failed read degrades to 0 rather than failing a write that
        // already landed.
        let policy_generation = self.store.policy_generation().unwrap_or(0);
        Ok(TenantCredentialMetadata::from_row(&row, policy_generation))
    }

    /// Metadata for every credential `tenant` holds, sorted by provider,
    /// without decrypting anything.
    ///
    /// Read from the store, not the snapshot: the snapshot holds only
    /// decrypted secrets and adding a metadata map to it would change a type
    /// every filter test constructs. This is an admin GET, never on the
    /// request path, and reading the store means the answer reflects the
    /// latest write even before the next republish.
    pub fn tenant_credential_metadata(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<TenantCredentialMetadata>, StoreError> {
        let policy_generation = self.store.policy_generation().unwrap_or(0);
        let mut out: Vec<TenantCredentialMetadata> = self
            .store
            .load()?
            .tenant_credentials
            .iter()
            .filter(|row| &row.tenant == tenant)
            .map(|row| TenantCredentialMetadata::from_row(row, policy_generation))
            .collect();
        out.sort_by(|a, b| a.provider.cmp(&b.provider));
        Ok(out)
    }

    /// Sets or clears a budget for an existing stable key identity. The
    /// special durable row is private to this module; tenant budgets remain
    /// readable for migration but are no longer consumed by spend_limit.
    pub fn set_key_budget(
        &self,
        key_id: &KeyId,
        budget: Option<&KeyBudget>,
    ) -> Result<(), StoreError> {
        if !self.handle().load().key_tenants.contains_key(key_id) {
            return Err(StoreError::NotFound);
        }
        self.store.set_key_budget(key_id, budget)?;
        self.rebuild();
        Ok(())
    }

    /// A key's ceiling can only narrow its tenant's bucket at enforcement.
    pub fn set_key_limits(
        &self,
        key_id: &KeyId,
        limits: Option<&LimitPolicy>,
    ) -> Result<(), StoreError> {
        if !self.handle().load().key_tenants.contains_key(key_id) {
            return Err(StoreError::NotFound);
        }
        self.store.set_limits(&key_budget_subject(key_id), limits)?;
        self.rebuild();
        Ok(())
    }

    /// Sets a key's own model allow-list and republishes. `ModelAccess::All`
    /// returns the key to inheriting its tenant because All intersected with
    /// the tenant grant is the tenant grant.
    pub fn set_key_policy(&self, key_id: &KeyId, access: &ModelAccess) -> Result<(), StoreError> {
        if !self.handle().load().key_tenants.contains_key(key_id) {
            return Err(StoreError::NotFound);
        }
        self.store.set_policy(&key_budget_subject(key_id), access)?;
        self.rebuild();
        Ok(())
    }

    /// Moves the rate cards out of a load into a by-chain map, before the
    /// rest of the load is consumed to build the snapshot.
    fn take_rate_cards(loaded: &mut StoredControlPlane) -> HashMap<String, StoredRateCard> {
        std::mem::take(&mut loaded.rate_cards)
            .into_iter()
            .map(|card| (card.chain.clone(), card))
            .collect()
    }

    /// The rate card the store held for `chain` at the last load, if any.
    pub fn rate_card(&self, chain: &str) -> Option<StoredRateCard> {
        self.rate_cards
            .lock()
            .expect("control plane mutex poisoned")
            .get(chain)
            .cloned()
    }

    /// Whether the store behind this control plane survives a restart. See
    /// [`ControlPlaneStore::is_durable`].
    pub fn store_is_durable(&self) -> bool {
        self.store.is_durable()
    }

    /// Whether other replicas read this control plane's store. See
    /// [`ControlPlaneStore::is_shared`].
    pub fn store_is_shared(&self) -> bool {
        self.store.is_shared()
    }

    /// Calls `callback` with `chain`'s rate card now, if the store has one,
    /// and again every time a load brings a different card for that chain.
    /// Loads happen on this replica's policy poll (a generation bump from any
    /// replica), after one of its own writes, and on `rebuild`. A card the
    /// callback defers is offered again on every poll, changed or not, until
    /// it settles; see [`RateCardDelivery`]. The callback
    /// runs on whichever thread did the load while a lock is held, so it must
    /// be quick and must not call back into this control plane.
    ///
    /// The initial delivery and the registration are one step under the
    /// watches lock, so a card cannot arrive between them and be missed or
    /// delivered out of order.
    pub fn watch_rate_card(
        &self,
        chain: &str,
        callback: impl Fn(&StoredRateCard) -> RateCardDelivery + Send + Sync + 'static,
    ) {
        let mut watches = self
            .rate_card_watches
            .lock()
            .expect("control plane mutex poisoned");
        let last_delivered = self
            .rate_card(chain)
            .filter(|card| callback(card) == RateCardDelivery::Settled);
        watches.push(RateCardWatch {
            chain: chain.to_string(),
            last_delivered,
            callback: Box::new(callback),
        });
    }

    /// Offers each watcher its chain's card unless it already settled that
    /// card. Cheap when nothing is deferred: one map read per watcher.
    fn notify_rate_card_watches(&self) {
        let mut watches = self
            .rate_card_watches
            .lock()
            .expect("control plane mutex poisoned");
        for watch in watches.iter_mut() {
            let Some(card) = self.rate_card(&watch.chain) else {
                continue;
            };
            if watch.last_delivered.as_ref() != Some(&card)
                && (watch.callback)(&card) == RateCardDelivery::Settled
            {
                watch.last_delivered = Some(card);
            }
        }
    }

    /// Replaces `card.chain`'s rate card, bumping the generation so the other
    /// replicas pick it up on their next poll (ADR-0006 section 3), then
    /// republishes. The card is also recorded and delivered to this
    /// replica's watchers directly, so the write takes effect here even if
    /// the read-back that `rebuild` does fails.
    pub fn put_rate_card(&self, card: &StoredRateCard) -> Result<(), StoreError> {
        self.store.put_rate_card(card)?;
        self.record_rate_card(card);
        self.rebuild();
        Ok(())
    }

    /// Writes `card` only if the store has no card for its chain. `Ok(true)`
    /// means it was written. `Ok(false)` means another card was already there
    /// (this replica's load predates it), and the republish that follows
    /// brings that card to the watchers, so the store's card wins.
    pub fn seed_rate_card(&self, card: &StoredRateCard) -> Result<bool, StoreError> {
        let wrote = self.store.put_rate_card_if_absent(card)?;
        if wrote {
            self.record_rate_card(card);
        }
        self.rebuild();
        Ok(wrote)
    }

    fn record_rate_card(&self, card: &StoredRateCard) {
        self.rate_cards
            .lock()
            .expect("control plane mutex poisoned")
            .insert(card.chain.clone(), card.clone());
        self.notify_rate_card_watches();
    }

    /// Seeds `bootstrap` (`llmproxy.model_authz`'s `typed_config.policies`,
    /// parsed by `model_authz_filter::parse_config`) into the store, then
    /// republishes -- store-wins on a tenant collision, the identical rule
    /// and rationale as [`Self::merge`]'s bootstrap-KEY merge: the store is
    /// authoritative (an admin `PUT /tenants/{id}/policy` must never be
    /// silently reverted by a static config value), and a collision is
    /// logged by TENANT ID ONLY -- never a policy's contents. `typed_config.policies` stays, as
    /// BOOTSTRAP data.
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
            // `parse_config` always yields `Some`; a policy without a model
            // grant has nothing to seed.
            let Some(access) = &policy.model_access else {
                continue;
            };
            self.store
                .set_policy(&TenantId::new(tenant.clone()), access)?;
            existing.insert(tenant.clone());
        }

        self.rebuild();
        Ok(())
    }

    /// `generation` is the stamp read before `loaded`, for the log line of
    /// [`Self::note_loaded_rows`]; `last_generation` still holds the
    /// previous one when this runs.
    fn snapshot_from(
        &self,
        mut loaded: StoredControlPlane,
        generation: Option<u64>,
    ) -> ControlPlaneSnapshot {
        self.note_loaded_rows(&loaded, generation);
        let cards = Self::take_rate_cards(&mut loaded);
        *self
            .rate_cards
            .lock()
            .expect("control plane mutex poisoned") = cards;
        Self::build_snapshot(
            &self.bootstrap_keys,
            self.credential_keys.as_ref(),
            &self.credential_warnings,
            loaded,
            generation,
        )
    }

    /// [`Self::merge`] plus decryption of the tenant credential rows
    /// (ADR-0007 decision 3). An associated function rather than a method so
    /// [`Self::new_with_credential_keys`] can call it before `self` exists.
    fn build_snapshot(
        bootstrap_keys: &KeySet,
        credential_keys: Option<&CredentialKeys>,
        warnings: &CredentialWarnings,
        mut loaded: StoredControlPlane,
        generation: Option<u64>,
    ) -> ControlPlaneSnapshot {
        let rows = std::mem::take(&mut loaded.tenant_credentials);
        let mut snapshot = Self::merge(bootstrap_keys, loaded);
        snapshot.tenant_credentials = decrypt_credentials(credential_keys, warnings, rows);
        snapshot.generation = generation;
        snapshot
    }

    /// Bootstrap keys layered under the store's, then the store's layered on
    /// top -- on a `key_id` collision the store wins.
    fn merge(bootstrap_keys: &KeySet, loaded: StoredControlPlane) -> ControlPlaneSnapshot {
        // Rust note: keyed by `KeyId`, not by digest -- `KeySet` itself is
        // digest-keyed (see its doc for why), which is exactly the wrong
        // shape for detecting a `key_id` collision between two sources. This
        // map exists only to re-key long enough to resolve collisions; it is
        // consumed into a real (digest-keyed) `KeySet` before this function
        // returns.
        let mut by_key_id: HashMap<KeyId, (Vec<u8>, KeyRecord)> = HashMap::new();
        let mut key_tenants = HashMap::new();

        for (digest, record) in bootstrap_keys.iter() {
            key_tenants.insert(record.key_id.clone(), record.tenant.clone());
            by_key_id.insert(
                record.key_id.clone(),
                (
                    digest.to_vec(),
                    KeyRecord {
                        key_id: record.key_id.clone(),
                        tenant: record.tenant.clone(),
                        revoked: record.revoked,
                        tags: record.tags.clone(),
                    },
                ),
            );
        }

        for stored in loaded.keys {
            key_tenants.insert(stored.key_id.clone(), stored.tenant.clone());
            if by_key_id.contains_key(&stored.key_id) {
                // Names ONLY the key_id -- never a digest or any key
                // material. See `StoredKey`'s Debug: a collision
                // log never renders key material.
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
                        tags: Arc::new(stored.tags),
                    },
                ),
            );
        }

        let mut keys = KeySet::new();
        for (_key_id, (digest, record)) in by_key_id {
            keys.insert_digest(digest, record);
        }

        // `policies` is populated from the store only -- there is no
        // config-bootstrap policy source yet (bootstrap virtual keys carry no
        // `ModelAccess`), so there is nothing to layer under it. A tenant
        // with no model policy row gets `model_access: None`, whether it is
        // absent here or present only for its budget; `llmproxy.model_authz`
        // decides what `None` permits (`tenants_without_policy`, deny by
        // default).
        //
        // `loaded.budgets` is a SEPARATE store
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
        let key_budgets = loaded.key_budgets;
        let mut tenant_limits = loaded.limits;
        let mut key_limits = HashMap::new();
        tenant_limits.retain(|subject, limits| {
            if let Some(key_id) = key_id_from_budget_subject(subject) {
                key_limits.insert(key_id, *limits);
                false
            } else {
                true
            }
        });
        let mut policies: TenantPolicyMap = HashMap::new();
        let mut key_policies = HashMap::new();
        for (tenant, access) in loaded.policies {
            if let Some(key_id) = key_id_from_budget_subject(&tenant) {
                key_policies.insert(key_id, access);
                continue;
            }
            let budget = budgets.remove(&tenant);
            policies.insert(
                tenant.as_str().to_string(),
                Arc::new(TenantPolicy {
                    model_access: Some(access),
                    budget,
                }),
            );
        }
        for (tenant, budget) in budgets {
            policies.insert(
                tenant.as_str().to_string(),
                Arc::new(TenantPolicy {
                    // A budget row is not a model grant (review H4).
                    model_access: None,
                    budget: Some(budget),
                }),
            );
        }

        ControlPlaneSnapshot {
            keys,
            policies,
            key_budgets,
            tenant_limits,
            key_limits,
            key_policies,
            key_tenants,
            tenant_credentials: HashMap::new(),
            generation: None,
            trace_export: loaded.trace_export,
        }
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
    // AGENTS.md "Fail-open controls": a control that degrades must be loud, but a poller
    // ticking every tens of seconds must not re-warn every tick while the
    // store stays down -- that turns the log itself into the incident. These
    // two fields, private to this one thread, are the suppression state:
    // warn on the FIRST failure since the last success, or once `last_warn`
    // is at least ten intervals old, whichever comes first.
    let mut last_warn: Option<Instant> = None;
    let mut warned_since_success = false;
    // Whether this thread already announced that authentication fails
    // closed, so the transition is logged once per outage, not per tick.
    let mut announced_expiry = false;

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
            let polled = cp.poll_once();
            cp.publish_snapshot_age();
            match polled {
                Ok(_rebuilt) => {
                    if announced_expiry {
                        tracing::warn!(
                            "control-plane policy poll succeeded again; virtual-key \
                             authentication is serving requests again"
                        );
                    }
                    warned_since_success = false;
                    announced_expiry = false;
                }
                Err(err) => {
                    let snapshot_age = cp.snapshot_age();
                    let expired = cp.freshness.is_expired();
                    if expired && !announced_expiry {
                        tracing::error!(
                            error = %err,
                            snapshot_age_seconds = snapshot_age.as_secs_f64(),
                            max_staleness_seconds = cp
                                .freshness
                                .max_staleness()
                                .map(|bound| bound.as_secs_f64())
                                .unwrap_or_default(),
                            "control-plane policy snapshot is older than \
                             max_policy_staleness_seconds; virtual-key authentication now \
                             FAILS CLOSED (503 auth_policy_stale) until a poll succeeds"
                        );
                        announced_expiry = true;
                    }
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
#[cfg(any(test, feature = "test-support"))]
pub fn test_snapshot_handle(keys: KeySet) -> Arc<ArcSwap<ControlPlaneSnapshot>> {
    Arc::new(ArcSwap::new(Arc::new(ControlPlaneSnapshot {
        keys,
        policies: TenantPolicyMap::new(),
        key_budgets: HashMap::new(),
        tenant_limits: HashMap::new(),
        key_limits: HashMap::new(),
        key_policies: HashMap::new(),
        key_tenants: HashMap::new(),
        tenant_credentials: HashMap::new(),
        generation: None,
        trace_export: HashSet::new(),
    })))
}

/// Records every ERROR event's message and fields, rendered as one line, for
/// tests that assert a control is loud. Install it with
/// `tracing::subscriber::set_default`, which is per thread, so the code under
/// test must run on the test's own thread.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Default)]
pub struct ErrorCapture {
    pub lines: Arc<Mutex<Vec<String>>>,
}

#[cfg(any(test, feature = "test-support"))]
impl tracing::Subscriber for ErrorCapture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() != tracing::Level::ERROR {
            return;
        }
        struct Line(String);
        impl tracing::field::Visit for Line {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={:?} ", field.name(), value));
            }
        }
        let mut line = Line(String::new());
        event.record(&mut line);
        self.lines
            .lock()
            .expect("capture mutex poisoned")
            .push(line.0);
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

/// The value of `llmproxy_policy_store_emptied_total{scope}` in `registry`'s
/// Prometheus rendering.
#[cfg(any(test, feature = "test-support"))]
pub fn rendered_emptied_count(registry: &proxy_observability::stats::Registry, scope: &str) -> u64 {
    let prefix = format!("envoy_llmproxy_policy_store_emptied_total{{scope=\"{scope}\"}}");
    proxy_observability::stats::prometheus_render::render(registry)
        .lines()
        .find(|line| line.starts_with(&prefix))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse::<u64>().ok())
        .expect("the emptied counter is exported")
}

/// The value of `llmproxy_policy_store_rows{scope, kind}` in `registry`'s
/// Prometheus rendering. `kind` is `keys` or `tenants`.
#[cfg(any(test, feature = "test-support"))]
pub fn rendered_store_rows(
    registry: &proxy_observability::stats::Registry,
    scope: &str,
    kind: &str,
) -> i64 {
    let series = "envoy_llmproxy_policy_store_rows{";
    proxy_observability::stats::prometheus_render::render(registry)
        .lines()
        .find(|line| {
            line.starts_with(series)
                && line.contains(&format!("scope=\"{scope}\""))
                && line.contains(&format!("kind=\"{kind}\""))
        })
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse::<i64>().ok())
        .expect("the store rows gauge is exported")
}

/// A store several [`ControlPlane`]s can share in a test, standing in for a
/// shared durable store (Redis) without a server: every handle forwards to one
/// [`InMemoryControlPlaneStore`], so a write through one is visible to a poll
/// through another, which is the property replica propagation depends on.
/// Reports itself durable and shared because it plays the part of a store
/// that is both.
#[cfg(any(test, feature = "test-support"))]
pub struct SharedMemoryStore {
    pub inner: Arc<InMemoryControlPlaneStore>,
    /// Makes rate card writes fail, to test what a refused write leaves behind.
    pub refuse_rate_cards: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(any(test, feature = "test-support"))]
impl SharedMemoryStore {
    pub fn new() -> (Self, Arc<InMemoryControlPlaneStore>) {
        let inner = Arc::new(InMemoryControlPlaneStore::default());
        (
            SharedMemoryStore {
                inner: Arc::clone(&inner),
                refuse_rate_cards: Arc::default(),
            },
            inner,
        )
    }

    /// Another handle on the same underlying store.
    pub fn handle(&self) -> Self {
        SharedMemoryStore {
            inner: Arc::clone(&self.inner),
            refuse_rate_cards: Arc::clone(&self.refuse_rate_cards),
        }
    }

    fn check_rate_cards(&self) -> Result<(), StoreError> {
        if self.refuse_rate_cards.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable("refused by the test".into()));
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "test-support"))]
impl ControlPlaneStore for SharedMemoryStore {
    fn add_window_batch(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[WindowDelta<'_>],
    ) -> Vec<Result<u64, StoreError>> {
        self.inner.add_window_batch(scope, node_id, rows)
    }
    fn last_window_seq_batch(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[WindowRow],
    ) -> Vec<Result<u64, StoreError>> {
        self.inner.last_window_seq_batch(scope, node_id, rows)
    }
    fn load_window_batch(&self, scope: &str, rows: &[WindowRow]) -> Vec<Result<u64, StoreError>> {
        self.inner.load_window_batch(scope, rows)
    }
    fn load(&self) -> Result<StoredControlPlane, StoreError> {
        self.inner.load()
    }
    fn policy_generation(&self) -> Result<u64, StoreError> {
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
    fn set_key_budget(&self, key_id: &KeyId, budget: Option<&KeyBudget>) -> Result<(), StoreError> {
        self.inner.set_key_budget(key_id, budget)
    }
    fn set_limits(
        &self,
        subject: &TenantId,
        limits: Option<&LimitPolicy>,
    ) -> Result<(), StoreError> {
        self.inner.set_limits(subject, limits)
    }

    fn set_trace_export(&self, tenant: &TenantId, enabled: bool) -> Result<(), StoreError> {
        self.inner.set_trace_export(tenant, enabled)
    }
    fn claim_object(
        &self,
        object_id: &str,
        tenant: &TenantId,
        ttl: Option<Duration>,
    ) -> Result<ObjectOwner, StoreError> {
        self.inner.claim_object(object_id, tenant, ttl)
    }
    fn object_owner(&self, object_id: &str) -> Result<Option<ObjectOwner>, StoreError> {
        self.inner.object_owner(object_id)
    }
    fn put_rate_card(&self, card: &StoredRateCard) -> Result<(), StoreError> {
        self.check_rate_cards()?;
        self.inner.put_rate_card(card)
    }
    fn put_rate_card_if_absent(&self, card: &StoredRateCard) -> Result<bool, StoreError> {
        self.check_rate_cards()?;
        self.inner.put_rate_card_if_absent(card)
    }
    fn is_durable(&self) -> bool {
        true
    }
    fn is_shared(&self) -> bool {
        true
    }
    fn add_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        delta_micros: u64,
        token: FlushToken<'_>,
    ) -> Result<u64, StoreError> {
        self.inner
            .add_spend(stat_prefix, tenant, period, delta_micros, token)
    }
    fn overwrite_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        total_micros: u64,
    ) -> Result<(), StoreError> {
        self.inner
            .overwrite_spend(stat_prefix, tenant, period, total_micros)
    }
    fn last_flush_seq(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        node_id: &str,
    ) -> Result<u64, StoreError> {
        self.inner
            .last_flush_seq(stat_prefix, tenant, period, node_id)
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

/// Captures `tracing` events for tests that assert on what a log line says,
/// which the crate's fail-open rules ask for (AGENTS.md "Fail-open controls":
/// check what the log line renders). Shared by this crate's test modules, like
/// [`test_snapshot_handle`].
#[cfg(any(test, feature = "test-support"))]
pub mod log_capture {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    /// One captured event: its level and every field rendered to a string. The
    /// message is the field named `message`.
    pub type Event = (tracing::Level, BTreeMap<String, String>);

    /// Records every event emitted on the current thread (`set_default` is
    /// thread-local, so an event from the policy poller's own thread is not
    /// seen; tests that need one call the function the poller calls).
    #[derive(Default)]
    pub struct Capture {
        events: Mutex<Vec<Event>>,
    }

    impl Capture {
        /// Starts capturing on this thread until the guard drops.
        pub fn start() -> (Arc<Capture>, tracing::subscriber::DefaultGuard) {
            let capture = Arc::new(Capture::default());
            let guard = tracing::subscriber::set_default(Arc::clone(&capture));
            (capture, guard)
        }

        pub fn events(&self) -> Vec<Event> {
            self.events.lock().unwrap().clone()
        }

        /// Every captured event at `level` or more severe, with its fields
        /// joined into one string: what an operator would read on one line.
        pub fn rendered_at_or_above(&self, level: tracing::Level) -> Vec<String> {
            self.events()
                .into_iter()
                .filter(|(event_level, _)| *event_level <= level)
                .map(|(_, fields)| {
                    fields
                        .iter()
                        .map(|(name, value)| format!("{name}={value}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .collect()
        }
    }

    impl tracing::Subscriber for Capture {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            // Rust note: `Visit`'s typed `record_u64`, `record_str` and friends
            // all default to calling `record_debug`, so implementing that one
            // method renders every field, whatever its type.
            struct Fields(BTreeMap<String, String>);
            impl tracing::field::Visit for Fields {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0
                        .insert(field.name().to_string(), format!("{value:?}"));
                }
            }
            let mut fields = Fields(BTreeMap::new());
            event.record(&mut fields);
            self.events
                .lock()
                .unwrap()
                .push((*event.metadata().level(), fields.0));
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }
}

/// Key budget rows as builds before `include_byok_in_limit` wrote them, one
/// per stored scope, with the budget each must load as (ADR-0007 amendment
/// 1). Shared by the redb and Redis upgrade tests so both stores are held to
/// one mapping.
#[cfg(test)]
pub(crate) fn pre_flag_key_budget_rows() -> Vec<(KeyId, &'static str, KeyBudget)> {
    use crate::spend::{MicroUsd, Period};
    let budget = |micros, period, include_byok_in_limit| KeyBudget {
        max_micros: MicroUsd::from_micros(micros),
        period,
        include_byok_in_limit,
    };
    vec![
        // Before ADR-0007 decision 8: no scope, no version. Platform.
        (
            KeyId::new("key-unscoped"),
            r#"{"max_micros":5,"period":"Daily"}"#,
            budget(5, Period::Daily, false),
        ),
        (
            KeyId::new("key-platform"),
            r#"{"schema_version":2,"max_micros":6,"period":"Daily","credential_source":"platform"}"#,
            budget(6, Period::Daily, false),
        ),
        // Counted only BYOK spend; now counts BYOK and operator spend.
        (
            KeyId::new("key-tenant"),
            r#"{"schema_version":2,"max_micros":7,"period":"Monthly","credential_source":"tenant"}"#,
            budget(7, Period::Monthly, true),
        ),
    ]
}

#[cfg(test)]
mod redb_spend_batch_tests;

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
        fn add_window_batch(
            &self,
            scope: &str,
            node_id: &str,
            rows: &[WindowDelta<'_>],
        ) -> Vec<Result<u64, StoreError>> {
            self.0.add_window_batch(scope, node_id, rows)
        }
        fn last_window_seq_batch(
            &self,
            scope: &str,
            node_id: &str,
            rows: &[WindowRow],
        ) -> Vec<Result<u64, StoreError>> {
            self.0.last_window_seq_batch(scope, node_id, rows)
        }
        fn load_window_batch(
            &self,
            scope: &str,
            rows: &[WindowRow],
        ) -> Vec<Result<u64, StoreError>> {
            self.0.load_window_batch(scope, rows)
        }
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
        fn put_tenant_credential(&self, rec: &StoredTenantCredential) -> Result<(), StoreError> {
            self.0.put_tenant_credential(rec)
        }
        fn delete_tenant_credential(
            &self,
            tenant: &TenantId,
            provider: &str,
        ) -> Result<(), StoreError> {
            self.0.delete_tenant_credential(tenant, provider)
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
        fn set_key_budget(
            &self,
            key_id: &KeyId,
            budget: Option<&KeyBudget>,
        ) -> Result<(), StoreError> {
            self.0.set_key_budget(key_id, budget)
        }
        fn set_limits(
            &self,
            subject: &TenantId,
            limits: Option<&LimitPolicy>,
        ) -> Result<(), StoreError> {
            self.0.set_limits(subject, limits)
        }
        fn add_spend(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
            delta_micros: u64,
            token: FlushToken<'_>,
        ) -> Result<u64, StoreError> {
            self.0
                .add_spend(stat_prefix, tenant, period, delta_micros, token)
        }
        fn overwrite_spend(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
            total_micros: u64,
        ) -> Result<(), StoreError> {
            self.0
                .overwrite_spend(stat_prefix, tenant, period, total_micros)
        }
        fn last_flush_seq(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
            node_id: &str,
        ) -> Result<u64, StoreError> {
            self.0.last_flush_seq(stat_prefix, tenant, period, node_id)
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
    /// `load()` calls (`load_calls`, `Arc<AtomicUsize>` so a test keeps
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
        fn add_window_batch(
            &self,
            scope: &str,
            node_id: &str,
            rows: &[WindowDelta<'_>],
        ) -> Vec<Result<u64, StoreError>> {
            self.inner.add_window_batch(scope, node_id, rows)
        }
        fn last_window_seq_batch(
            &self,
            scope: &str,
            node_id: &str,
            rows: &[WindowRow],
        ) -> Vec<Result<u64, StoreError>> {
            self.inner.last_window_seq_batch(scope, node_id, rows)
        }
        fn load_window_batch(
            &self,
            scope: &str,
            rows: &[WindowRow],
        ) -> Vec<Result<u64, StoreError>> {
            self.inner.load_window_batch(scope, rows)
        }
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
        fn put_tenant_credential(&self, rec: &StoredTenantCredential) -> Result<(), StoreError> {
            self.inner.put_tenant_credential(rec)
        }
        fn delete_tenant_credential(
            &self,
            tenant: &TenantId,
            provider: &str,
        ) -> Result<(), StoreError> {
            self.inner.delete_tenant_credential(tenant, provider)
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
        fn set_key_budget(
            &self,
            key_id: &KeyId,
            budget: Option<&KeyBudget>,
        ) -> Result<(), StoreError> {
            self.inner.set_key_budget(key_id, budget)
        }
        fn set_limits(
            &self,
            subject: &TenantId,
            limits: Option<&LimitPolicy>,
        ) -> Result<(), StoreError> {
            self.inner.set_limits(subject, limits)
        }
        fn add_spend(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
            delta_micros: u64,
            token: FlushToken<'_>,
        ) -> Result<u64, StoreError> {
            self.inner
                .add_spend(stat_prefix, tenant, period, delta_micros, token)
        }
        fn overwrite_spend(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
            total_micros: u64,
        ) -> Result<(), StoreError> {
            self.inner
                .overwrite_spend(stat_prefix, tenant, period, total_micros)
        }
        fn last_flush_seq(
            &self,
            stat_prefix: &str,
            tenant: &TenantId,
            period: &PeriodKey,
            node_id: &str,
        ) -> Result<u64, StoreError> {
            self.inner
                .last_flush_seq(stat_prefix, tenant, period, node_id)
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
        fn add_window_batch(
            &self,
            _scope: &str,
            _node_id: &str,
            rows: &[WindowDelta<'_>],
        ) -> Vec<Result<u64, StoreError>> {
            rows.iter().map(|_| Ok(0)).collect()
        }
        fn last_window_seq_batch(
            &self,
            _scope: &str,
            _node_id: &str,
            rows: &[WindowRow],
        ) -> Vec<Result<u64, StoreError>> {
            rows.iter().map(|_| Ok(0)).collect()
        }
        fn load_window_batch(
            &self,
            _scope: &str,
            rows: &[WindowRow],
        ) -> Vec<Result<u64, StoreError>> {
            rows.iter().map(|_| Ok(0)).collect()
        }
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
        fn put_tenant_credential(&self, _rec: &StoredTenantCredential) -> Result<(), StoreError> {
            Ok(())
        }
        fn delete_tenant_credential(
            &self,
            _tenant: &TenantId,
            _provider: &str,
        ) -> Result<(), StoreError> {
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
        fn set_key_budget(
            &self,
            _key_id: &KeyId,
            _budget: Option<&KeyBudget>,
        ) -> Result<(), StoreError> {
            Ok(())
        }
        fn set_limits(
            &self,
            _subject: &TenantId,
            _limits: Option<&LimitPolicy>,
        ) -> Result<(), StoreError> {
            Ok(())
        }
        fn add_spend(
            &self,
            _stat_prefix: &str,
            _tenant: &TenantId,
            _period: &PeriodKey,
            _delta_micros: u64,
            _token: FlushToken<'_>,
        ) -> Result<u64, StoreError> {
            Ok(0)
        }
        fn overwrite_spend(
            &self,
            _stat_prefix: &str,
            _tenant: &TenantId,
            _period: &PeriodKey,
            _total_micros: u64,
        ) -> Result<(), StoreError> {
            Ok(())
        }
        fn last_flush_seq(
            &self,
            _stat_prefix: &str,
            _tenant: &TenantId,
            _period: &PeriodKey,
            _node_id: &str,
        ) -> Result<u64, StoreError> {
            Ok(0)
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
                tags: Default::default(),
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
                tags: Default::default(),
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
                tags: Default::default(),
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
                tags: Default::default(),
            },
        );

        let store = InMemoryControlPlaneStore::default();
        store
            .put_key(&StoredKey {
                key_id: KeyId::new("k1"),
                digest: digest_bytes(secret_bytes, "llmp_store-value"),
                tenant: TenantId::new("tenant-store"),
                revoked: false,
                tags: Default::default(),
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
                tags: Default::default(),
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

    // --- ControlPlane write methods ---------

    #[test]
    fn tenant_and_key_limits_publish_in_separate_buckets_and_clear() {
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(b"secret"),
            KeySet::new(),
        )
        .unwrap();
        let tenant = TenantId::new("tenant-a");
        let key = KeyId::new("key-a");
        cp.mint_key(&tenant, &key).unwrap();
        let tenant_limit = LimitPolicy {
            tokens_per_minute: Some(0),
            ..Default::default()
        };
        let key_limit = LimitPolicy {
            requests_per_minute: Some(4),
            concurrent_streams: Some(1),
            ..Default::default()
        };
        cp.set_tenant_limits(&tenant, Some(&tenant_limit)).unwrap();
        cp.set_key_limits(&key, Some(&key_limit)).unwrap();
        let snapshot = cp.handle().load();
        assert_eq!(snapshot.tenant_limits.get(&tenant), Some(&tenant_limit));
        assert_eq!(snapshot.key_limits.get(&key), Some(&key_limit));
        assert!(!snapshot
            .tenant_limits
            .contains_key(&key_budget_subject(&key)));
        assert_eq!(cp.list_keys()[0].limits, Some(key_limit));
        drop(snapshot);
        cp.set_key_limits(&key, Some(&LimitPolicy::default()))
            .unwrap();
        cp.set_tenant_limits(&tenant, None).unwrap();
        assert!(cp.handle().load().key_limits.is_empty());
        assert!(cp.handle().load().tenant_limits.is_empty());
        assert!(cp.store().load().unwrap().limits.is_empty());
        cp.set_tenant_limits(&tenant, Some(&tenant_limit)).unwrap();
        cp.delete_tenant(&tenant).unwrap();
        assert!(cp.store().load().unwrap().limits.is_empty());
    }

    #[test]
    fn unknown_key_limits_write_does_not_change_store_or_generation() {
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(b"secret"),
            KeySet::new(),
        )
        .unwrap();
        let before = cp.store().policy_generation().unwrap();
        let limits = LimitPolicy {
            tokens_per_minute: Some(1),
            ..Default::default()
        };
        assert_eq!(
            cp.set_key_limits(&KeyId::new("missing"), Some(&limits)),
            Err(StoreError::NotFound)
        );
        assert_eq!(cp.store().policy_generation().unwrap(), before);
        assert!(cp.store().load().unwrap().limits.is_empty());
    }

    #[test]
    fn key_limits_budget_and_model_policy_do_not_clobber_each_other() {
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(b"secret"),
            KeySet::new(),
        )
        .unwrap();
        let key = KeyId::new("key-a");
        cp.mint_key(&TenantId::new("tenant-a"), &key).unwrap();
        let limits = LimitPolicy {
            concurrent_streams: Some(2),
            ..Default::default()
        };
        let budget = KeyBudget {
            max_micros: MicroUsd::from_micros(8),
            period: Period::Daily,
            include_byok_in_limit: true,
        };
        let access = ModelAccess::Only(vec![ModelPattern::new("gpt-*")]);
        cp.set_key_limits(&key, Some(&limits)).unwrap();
        cp.set_key_budget(&key, Some(&budget)).unwrap();
        cp.set_key_policy(&key, &access).unwrap();
        let snapshot = cp.handle().load();
        assert_eq!(snapshot.key_limits.get(&key), Some(&limits));
        assert_eq!(snapshot.key_budgets.get(&key), Some(&budget));
        assert_eq!(snapshot.key_policies.get(&key), Some(&access));
    }

    #[test]
    fn set_key_policy_publishes_separately_from_tenant_policies() {
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(b"secret"),
            KeySet::new(),
        )
        .unwrap();
        let key = KeyId::new("key-a");
        cp.mint_key(&TenantId::new("tenant-a"), &key).unwrap();
        let access = ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]);
        cp.set_key_policy(&key, &access).unwrap();
        let snapshot = cp.handle().load();
        assert_eq!(snapshot.key_policies.get(&key), Some(&access));
        assert!(!snapshot
            .policies
            .contains_key(key_budget_subject(&key).as_str()));
        assert_eq!(
            cp.store()
                .load()
                .unwrap()
                .policies
                .get(&key_budget_subject(&key)),
            Some(&access)
        );
        cp.set_key_policy(&key, &ModelAccess::All).unwrap();
        assert_eq!(
            cp.handle().load().key_policies.get(&key),
            Some(&ModelAccess::All)
        );
    }

    #[test]
    fn set_key_policy_unknown_key_writes_nothing() {
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(b"secret"),
            KeySet::new(),
        )
        .unwrap();
        let before = cp.store().policy_generation().unwrap();
        let published = cp.handle().load_full();
        assert_eq!(
            cp.set_key_policy(&KeyId::new("missing"), &ModelAccess::All),
            Err(StoreError::NotFound)
        );
        assert_eq!(cp.store().policy_generation().unwrap(), before);
        assert!(cp.store().load().unwrap().policies.is_empty());
        assert!(Arc::ptr_eq(&published, &cp.handle().load_full()));
    }

    #[test]
    fn key_policy_and_budget_survive_both_write_orders() {
        for policy_first in [true, false] {
            let cp = ControlPlane::new(
                Box::new(InMemoryControlPlaneStore::default()),
                HmacSecret::new(b"secret"),
                KeySet::new(),
            )
            .unwrap();
            let key = KeyId::new("key-a");
            cp.mint_key(&TenantId::new("tenant-a"), &key).unwrap();
            let access = ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]);
            let budget = KeyBudget {
                max_micros: MicroUsd::from_micros(50),
                period: Period::Daily,
                include_byok_in_limit: true,
            };
            if policy_first {
                cp.set_key_policy(&key, &access).unwrap();
                cp.set_key_budget(&key, Some(&budget)).unwrap();
            } else {
                cp.set_key_budget(&key, Some(&budget)).unwrap();
                cp.set_key_policy(&key, &access).unwrap();
            }
            let snapshot = cp.handle().load();
            assert_eq!(snapshot.key_policies.get(&key), Some(&access));
            assert_eq!(snapshot.key_budgets.get(&key), Some(&budget));
            assert!(!snapshot
                .policies
                .contains_key(key_budget_subject(&key).as_str()));
        }
    }

    fn chargeback(pairs: &[(&str, &str)]) -> ChargebackTags {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn snapshot_tags(cp: &ControlPlane, key: &KeyId) -> ChargebackTags {
        cp.list_keys()
            .into_iter()
            .find(|listing| &listing.key_id == key)
            .map(|listing| (*listing.tags).clone())
            .expect("key is listed")
    }

    /// Key metadata tags survive a reopen of the durable store, a rotation
    /// that does not mention them, a replacement, and a revoke.
    #[test]
    fn redb_key_tags_survive_reopen_rotation_and_revoke() {
        let path = temp_db_path("key-tags-survive-reopen");
        let tenant = TenantId::new("tenant-a");
        let key = KeyId::new("key-a");
        let open = || {
            ControlPlane::new(
                Box::new(RedbControlPlaneStore::open(&path).unwrap()),
                HmacSecret::new(b"secret"),
                KeySet::new(),
            )
            .unwrap()
        };
        {
            let cp = open();
            let minted = cp
                .mint_key_with_tags(&tenant, &key, Some(&chargeback(&[("team", "infra")])))
                .unwrap();
            assert_eq!(minted.tags, chargeback(&[("team", "infra")]));
        }
        let cp = open();
        assert_eq!(snapshot_tags(&cp, &key), chargeback(&[("team", "infra")]));
        let rotated = cp.mint_key(&tenant, &key).unwrap();
        assert_eq!(rotated.tags, chargeback(&[("team", "infra")]));
        assert_eq!(snapshot_tags(&cp, &key), chargeback(&[("team", "infra")]));
        cp.set_key_tags(&key, &chargeback(&[("project", "ads")]))
            .unwrap();
        assert_eq!(snapshot_tags(&cp, &key), chargeback(&[("project", "ads")]));
        cp.revoke_key(&key).unwrap();
        let loaded = cp.store().load().unwrap();
        let row = loaded.keys.iter().find(|k| k.key_id == key).unwrap();
        assert!(row.revoked);
        assert_eq!(row.tags, chargeback(&[("project", "ads")]));
        assert!(matches!(
            cp.set_key_tags(&key, &ChargebackTags::new()),
            Err(StoreError::Conflict(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    /// Only a row that carries tags is stamped version 3, so a store with no
    /// tagged key still opens in a build from before tags; that build's key
    /// row reader accepted versions 1 and 2 only, so it refuses a tagged row
    /// rather than reading it without its tags.
    #[test]
    fn key_rows_are_stamped_version_3_only_when_tagged() {
        let mut key = StoredKey {
            key_id: KeyId::new("k"),
            digest: [7; 32],
            tenant: TenantId::new("t"),
            revoked: false,
            tags: ChargebackTags::new(),
        };
        let untagged = encode_json(&EncodedKeyRow::from_stored(&key));
        let text = String::from_utf8(untagged.clone()).unwrap();
        assert!(text.contains(r#""schema_version":2"#), "{text}");
        assert!(
            !text.contains("tags"),
            "an empty map is not written: {text}"
        );

        key.tags = chargeback(&[("team", "infra")]);
        let tagged = encode_json(&EncodedKeyRow::from_stored(&key));
        let text = String::from_utf8(tagged.clone()).unwrap();
        assert!(text.contains(r#""schema_version":3"#), "{text}");
        let back = decode_json::<EncodedKeyRow>(&tagged)
            .unwrap()
            .into_stored(KeyId::new("k"));
        assert_eq!(back.tags, key.tags);

        // The pre-tags reader was `read_schema_version` (1 or 2).
        #[derive(serde::Deserialize)]
        struct PreTagsRow {
            #[serde(deserialize_with = "read_schema_version")]
            #[allow(dead_code)]
            schema_version: u32,
        }
        assert!(decode_json::<PreTagsRow>(&untagged).is_ok());
        assert!(decode_json::<PreTagsRow>(&tagged).is_err());
    }

    /// A key defined in configuration has its tags there: a store row would
    /// win the key_id collision and shadow a later revocation in the config.
    #[test]
    fn set_key_tags_refuses_config_keys_and_invalid_tags() {
        let secret = HmacSecret::new(b"secret");
        let mut bootstrap = KeySet::new();
        bootstrap.insert(
            &secret,
            "llmp_config-key",
            KeyRecord {
                key_id: KeyId::new("config-key"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
                tags: Arc::new(chargeback(&[("team", "infra")])),
            },
        );
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(b"secret"),
            bootstrap,
        )
        .unwrap();
        let key = KeyId::new("config-key");
        assert_eq!(snapshot_tags(&cp, &key), chargeback(&[("team", "infra")]));
        assert!(matches!(
            cp.set_key_tags(&key, &chargeback(&[("team", "ads")])),
            Err(StoreError::Conflict(_))
        ));
        assert!(cp.store().load().unwrap().keys.is_empty());

        let tenant = TenantId::new("tenant-a");
        let store_key = KeyId::new("store-key");
        cp.mint_key(&tenant, &store_key).unwrap();
        assert!(matches!(
            cp.set_key_tags(&store_key, &chargeback(&[("team", "a b")])),
            Err(StoreError::InvalidInput(_))
        ));
        assert!(matches!(
            cp.mint_key_with_tags(&tenant, &store_key, Some(&chargeback(&[("Team", "x")]))),
            Err(StoreError::InvalidInput(_))
        ));
        assert!(matches!(
            cp.set_key_tags(&KeyId::new("absent"), &ChargebackTags::new()),
            Err(StoreError::NotFound)
        ));
    }

    #[test]
    fn redb_key_policy_survives_reopen_and_rebuild() {
        let path = temp_db_path("key-policy-survives-reopen");
        let key = KeyId::new("key-a");
        let access = ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]);
        {
            let cp = ControlPlane::new(
                Box::new(RedbControlPlaneStore::open(&path).unwrap()),
                HmacSecret::new(b"secret"),
                KeySet::new(),
            )
            .unwrap();
            cp.mint_key(&TenantId::new("tenant-a"), &key).unwrap();
            cp.set_key_policy(&key, &access).unwrap();
        }
        let cp = ControlPlane::new(
            Box::new(RedbControlPlaneStore::open(&path).unwrap()),
            HmacSecret::new(b"secret"),
            KeySet::new(),
        )
        .unwrap();
        cp.rebuild();
        assert_eq!(cp.handle().load().key_policies.get(&key), Some(&access));
        assert!(!cp
            .handle()
            .load()
            .policies
            .contains_key(key_budget_subject(&key).as_str()));
    }

    #[test]
    fn list_keys_reports_optional_key_model_access() {
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(b"secret"),
            KeySet::new(),
        )
        .unwrap();
        let tenant = TenantId::new("tenant-a");
        let restricted = KeyId::new("restricted");
        let inherited = KeyId::new("inherited");
        cp.mint_key(&tenant, &restricted).unwrap();
        cp.mint_key(&tenant, &inherited).unwrap();
        let access = ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]);
        cp.set_key_policy(&restricted, &access).unwrap();
        let listing = cp.list_keys();
        assert_eq!(
            listing
                .iter()
                .find(|row| row.key_id == restricted)
                .unwrap()
                .model_access,
            Some(access)
        );
        assert_eq!(
            listing
                .iter()
                .find(|row| row.key_id == inherited)
                .unwrap()
                .model_access,
            None
        );
    }

    #[test]
    fn control_characters_in_tenant_and_key_ids_write_nothing() {
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(b"secret"),
            KeySet::new(),
        )
        .unwrap();
        let before = cp.store().policy_generation().unwrap();
        let bad_tenant = TenantId::new("\u{1f}key:x");
        assert!(matches!(
            cp.create_tenant(&bad_tenant),
            Err(StoreError::InvalidInput(_))
        ));
        assert!(matches!(
            cp.mint_key(&bad_tenant, &KeyId::new("ok")),
            Err(StoreError::InvalidInput(_))
        ));
        assert!(matches!(
            cp.mint_key(&TenantId::new("ok"), &KeyId::new("bad\nkey")),
            Err(StoreError::InvalidInput(_))
        ));
        let loaded = cp.store().load().unwrap();
        assert!(loaded.tenants.is_empty());
        assert!(loaded.keys.is_empty());
        assert!(loaded.policies.is_empty());
        assert_eq!(cp.store().policy_generation().unwrap(), before);
    }

    // --- mint_key produces a key that authenticates

    #[test]
    fn mint_key_enforces_the_principal_id_length_bound() {
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(b"operator-secret"),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");
        let max = proxy_observability::records::MAX_PRINCIPAL_ID_BYTES;
        cp.mint_key(
            &TenantId::new("t".repeat(max)),
            &KeyId::new("k".repeat(max)),
        )
        .expect("ids at the bound are accepted");
        for (tenant, key) in [
            ("t".repeat(max + 1), "ok".to_string()),
            ("ok".into(), "k".repeat(max + 1)),
        ] {
            match cp.mint_key(&TenantId::new(tenant), &KeyId::new(key)) {
                Err(StoreError::InvalidInput(reason)) => {
                    assert!(reason.contains("maximum"), "{reason}")
                }
                other => panic!("over-long id must be refused, got {other:?}"),
            }
        }
    }

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
        assert_eq!(policy.model_access, Some(access));

        cp.delete_tenant(&TenantId::new("tenant-a"))
            .expect("delete_tenant must succeed");
        let loaded = shared.load().unwrap();
        assert!(loaded.tenants.is_empty());
        // `InMemoryControlPlaneStore::delete_tenant` also removes the policy
        // row -- confirm the republish reflects that too.
        let snapshot = cp.handle().load();
        assert!(!snapshot.policies.contains_key("tenant-a"));
    }

    // --- delete_tenant cascades to the tenant's keys (review H4) ----------
    //
    // Offboarding by deleting the tenant must stop every key that
    // authenticates as it: the minted store key AND the config bootstrap key,
    // on this replica and on a second replica that shares the store and boots
    // with the same config. Another tenant's keys are untouched.
    #[test]
    fn deleting_a_tenant_revokes_its_store_and_config_keys_on_every_replica() {
        let secret_bytes = b"operator-secret";
        let bootstrap = || {
            let mut keys = KeySet::new();
            keys.insert(
                &HmacSecret::new(secret_bytes),
                "llmp_config-key-a",
                KeyRecord {
                    key_id: KeyId::new("config-a"),
                    tenant: TenantId::new("tenant-a"),
                    revoked: false,
                    tags: Default::default(),
                },
            );
            keys
        };
        let shared = Arc::new(InMemoryControlPlaneStore::default());
        let cp = ControlPlane::new(
            Box::new(SharedStore(Arc::clone(&shared))),
            HmacSecret::new(secret_bytes),
            bootstrap(),
        )
        .unwrap();
        let minted_a = cp
            .mint_key(&TenantId::new("tenant-a"), &KeyId::new("minted-a"))
            .unwrap();
        let minted_b = cp
            .mint_key(&TenantId::new("tenant-b"), &KeyId::new("minted-b"))
            .unwrap();
        let replica = ControlPlane::new(
            Box::new(SharedStore(Arc::clone(&shared))),
            HmacSecret::new(secret_bytes),
            bootstrap(),
        )
        .unwrap();

        let revoked = cp.delete_tenant(&TenantId::new("tenant-a")).unwrap();
        assert_eq!(revoked, 2, "the minted key and the config key");
        replica.poll_once().unwrap();

        for (name, plane) in [("deleting replica", &cp), ("other replica", &replica)] {
            let authenticator =
                VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), plane.handle());
            for key in [minted_a.plaintext.as_str(), "llmp_config-key-a"] {
                let headers = headers_with_authorization(&format!("Bearer {key}"));
                assert!(
                    matches!(
                        authenticator.authenticate(&headers),
                        AuthOutcome::Rejected(AuthError::RevokedKey)
                    ),
                    "{name}: a key of the deleted tenant must be revoked"
                );
            }
            let other = headers_with_authorization(&format!("Bearer {}", minted_b.plaintext));
            assert!(
                matches!(
                    authenticator.authenticate(&other),
                    AuthOutcome::Authenticated(_)
                ),
                "{name}: another tenant's key must keep authenticating"
            );
        }
    }

    // --- seed_bootstrap_policies ---------------------

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
                model_access: Some(access.clone()),
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
        assert_eq!(policy.model_access, Some(access));
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
                model_access: Some(bootstrap_access),
                budget: None,
            }),
        );

        cp.seed_bootstrap_policies(&bootstrap)
            .expect("seeding over an already-populated tenant must still succeed (no-op write)");

        let snapshot = cp.handle().load();
        assert_eq!(
            snapshot.policies["tenant-a"].model_access,
            Some(store_access),
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
                model_access: Some(bootstrap_access.clone()),
                budget: None,
            }),
        );

        // First worker's `create()`: the store has nothing for `tenant-a`
        // yet, so this WRITES the bootstrap policy.
        cp.seed_bootstrap_policies(&bootstrap)
            .expect("first seed must succeed");
        assert_eq!(
            cp.handle().load().policies["tenant-a"].model_access,
            Some(bootstrap_access)
        );

        // An admin `PUT /tenants/tenant-a/policy` lands in between two
        // worker builds -- exactly `ControlPlane::set_policy`, what that
        // endpoint calls.
        let admin_access = ModelAccess::All;
        cp.set_policy(&TenantId::new("tenant-a"), &admin_access)
            .expect("admin set_policy must succeed");
        assert_eq!(
            cp.handle().load().policies["tenant-a"].model_access,
            Some(admin_access.clone())
        );

        // A second worker's `create()` seeds the exact same bootstrap map
        // again -- store-wins must make this a no-op, not a revert.
        cp.seed_bootstrap_policies(&bootstrap)
            .expect("re-seeding an identical bootstrap map must succeed");
        assert_eq!(
            cp.handle().load().policies["tenant-a"].model_access,
            Some(admin_access),
            "re-seeding identical bootstrap policies must not clobber a store policy \
             that landed in between -- this is the silent-policy-revert \
             `seed_bootstrap_policies`'s idempotence exists to prevent"
        );
    }

    // --- ControlPlane::set_budget / TenantBudget storage ---

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
            credential_source: CredentialSource::Platform,
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
            credential_source: CredentialSource::Platform,
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
            credential_source: CredentialSource::Platform,
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
            credential_source: CredentialSource::Platform,
        };
        cp.set_budget(&TenantId::new("tenant-a"), Some(&budget))
            .expect("set_budget must succeed");

        let snapshot = cp.handle().load();
        let policy = snapshot
            .policies
            .get("tenant-a")
            .expect("tenant must exist");
        assert_eq!(
            policy.model_access,
            Some(access),
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
            credential_source: CredentialSource::Platform,
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
        assert_eq!(policy.model_access, Some(access));
    }

    #[test]
    fn rotation_preserves_key_budget_history_and_model_grants() {
        for store in [
            Box::new(InMemoryControlPlaneStore::default()) as Box<dyn ControlPlaneStore>,
            Box::new(RedbControlPlaneStore::in_memory()),
        ] {
            let cp = ControlPlane::new(store, HmacSecret::new(b"rotation-secret"), KeySet::new())
                .unwrap();
            let tenant = TenantId::new("tenant-a");
            let id = KeyId::new("stable-key");
            let first = cp.mint_key(&tenant, &id).unwrap();
            let budget = KeyBudget {
                max_micros: crate::spend::MicroUsd::from_micros(10),
                period: crate::spend::Period::Daily,
                include_byok_in_limit: true,
            };
            cp.set_policy(
                &tenant,
                &ModelAccess::Only(vec![ModelPattern::new("allowed")]),
            )
            .unwrap();
            cp.set_key_budget(&id, Some(&budget)).unwrap();
            let subject = key_spend_subject(&id);
            let period = budget.period.key_for_now();
            cp.store()
                .add_spend(
                    "chain",
                    &subject,
                    &period,
                    7,
                    FlushToken {
                        node_id: "node",
                        seq: 1,
                    },
                )
                .unwrap();
            let rotated = cp.mint_key(&tenant, &id).unwrap();
            let auth =
                VirtualKeyAuthenticator::new(HmacSecret::new(b"rotation-secret"), cp.handle());
            assert!(matches!(
                auth.authenticate(&headers_with_authorization(&format!(
                    "Bearer {}",
                    first.plaintext
                ))),
                AuthOutcome::Rejected(AuthError::UnknownKey)
            ));
            assert!(matches!(
                auth.authenticate(&headers_with_authorization(&format!(
                    "Bearer {}",
                    rotated.plaintext
                ))),
                AuthOutcome::Authenticated(_)
            ));
            assert_eq!(cp.handle().load().key_budgets.get(&id), Some(&budget));
            assert_eq!(
                cp.store().load_spend("chain", &subject, &period).unwrap(),
                7
            );
            assert_eq!(
                cp.handle().load().policies["tenant-a"].model_access,
                Some(ModelAccess::Only(vec![ModelPattern::new("allowed")]))
            );
            let generation = cp.store().policy_generation().unwrap();
            assert!(matches!(
                cp.mint_key(&TenantId::new("tenant-b"), &id),
                Err(StoreError::Conflict(_))
            ));
            assert_eq!(cp.store().policy_generation().unwrap(), generation);
            cp.revoke_key(&id).unwrap();
            cp.delete_tenant(&tenant).unwrap();
            let generation = cp.store().policy_generation().unwrap();
            assert!(matches!(
                cp.mint_key(&tenant, &id),
                Err(StoreError::Conflict(_))
            ));
            assert_eq!(cp.store().policy_generation().unwrap(), generation);
            assert_eq!(
                cp.store().load_spend("chain", &subject, &period).unwrap(),
                7
            );
        }
    }

    #[test]
    fn stored_schema_reads_legacy_rows_and_rejects_future_versions() {
        let legacy: EncodedTenantBudget =
            decode_json(br#"{"max_micros":5,"period":"Daily"}"#).unwrap();
        assert_eq!(legacy.schema_version, 1);
        let budget: TenantBudget = legacy.into();
        let encoded: EncodedTenantBudget = (&budget).into();
        let value: serde_json::Value = serde_json::from_slice(&encode_json(&encoded)).unwrap();
        assert_eq!(value["schema_version"], SPEND_SCHEMA_VERSION);
        assert!(decode_json::<EncodedTenantBudget>(
            br#"{"schema_version":99,"max_micros":5,"period":"Daily"}"#
        )
        .is_err());
        assert!(decode_json::<EncodedKeyRow>(br#"{"schema_version":99,"digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"tenant":"a","revoked":false}"#).is_err());
    }

    /// ADR-0007 decision 8: a budget row stored BEFORE budgets were scoped
    /// carries no `credential_source` and must decode as `Platform` -- the
    /// source every such budget was enforced and charged by -- both with an
    /// explicit `schema_version` on the row and without one (the oldest
    /// rows have neither field).
    #[test]
    fn budget_rows_without_a_credential_source_decode_as_platform() {
        let without_version: EncodedTenantBudget =
            decode_json(br#"{"max_micros":5,"period":"Daily"}"#).unwrap();
        let with_version: EncodedTenantBudget =
            decode_json(br#"{"schema_version":2,"max_micros":5,"period":"Daily"}"#).unwrap();
        for encoded in [without_version, with_version] {
            let budget: TenantBudget = encoded.into();
            assert_eq!(budget.credential_source, CredentialSource::Platform);
            assert_eq!(budget.max_micros, MicroUsd::from_micros(5));
            assert_eq!(budget.period, Period::Daily);
        }
    }

    /// The other direction: a `Tenant`-scoped budget survives the
    /// encode/decode round trip unchanged, and encodes under the same
    /// snake_case spelling records already use for this enum. This is the
    /// ONE serialization both the redb and the Redis store go through
    /// (`EncodedTenantBudget`), so it covers both without a live Redis.
    #[test]
    fn a_tenant_scoped_budget_round_trips_through_the_encoded_form() {
        let budget = TenantBudget {
            max_micros: MicroUsd::from_micros(7),
            period: Period::Monthly,
            credential_source: CredentialSource::Tenant,
        };
        let encoded: EncodedTenantBudget = (&budget).into();
        let value: serde_json::Value = serde_json::from_slice(&encode_json(&encoded)).unwrap();
        assert_eq!(value["credential_source"], "tenant");
        let decoded: EncodedTenantBudget = decode_json(&encode_json(&encoded)).unwrap();
        assert_eq!(
            TenantBudget::from(decoded),
            budget,
            "the scope must survive the round trip"
        );
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

    // --- RedbControlPlaneStore --------------------------

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

        // A.
        let mut a_budgets: Vec<(&str, &TenantBudget)> =
            a.budgets.iter().map(|(t, b)| (t.as_str(), b)).collect();
        let mut b_budgets: Vec<(&str, &TenantBudget)> =
            b.budgets.iter().map(|(t, b)| (t.as_str(), b)).collect();
        a_budgets.sort_by_key(|(t, _)| *t);
        b_budgets.sort_by_key(|(t, _)| *t);
        assert_eq!(a_budgets, b_budgets, "budgets must match");

        // Credential rows, ordered by their `(tenant, provider)` identity
        // (neither store's `load` promises vector order).
        let mut a_credentials: Vec<(&str, &str, &StoredTenantCredential)> = a
            .tenant_credentials
            .iter()
            .map(|r| (r.tenant.as_str(), r.provider.as_str(), r))
            .collect();
        let mut b_credentials: Vec<(&str, &str, &StoredTenantCredential)> = b
            .tenant_credentials
            .iter()
            .map(|r| (r.tenant.as_str(), r.provider.as_str(), r))
            .collect();
        a_credentials.sort_by_key(|(t, p, _)| (*t, *p));
        b_credentials.sort_by_key(|(t, p, _)| (*t, *p));
        assert_eq!(
            a_credentials, b_credentials,
            "tenant_credentials must match"
        );
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
                tags: Default::default(),
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
                tags: Default::default(),
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
        let access = ModelAccess::Only(vec![ModelPattern::new("gpt-*")])
            .with_deny(vec![ModelPattern::new("gpt-5*")]);
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
    //     with InMemory; persistence across reopen

    #[test]
    fn redb_set_budget_then_load_returns_it_and_none_clears_it() {
        let store = RedbControlPlaneStore::in_memory();
        let budget = TenantBudget {
            max_micros: MicroUsd::from_micros(9_000_000),
            period: Period::Daily,
            credential_source: CredentialSource::Platform,
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

    /// ADR-0007 decision 8, redb: a raw row written by a build that predates
    /// budget scoping -- no `credential_source`, no `schema_version` -- must
    /// `load()` as a `Platform`-scoped budget. Written directly into the
    /// `BUDGETS` table (bypassing `set_budget`, which only ever writes
    /// current-format rows), exactly like the other legacy-row fixtures in
    /// this module.
    #[test]
    fn redb_load_reads_a_pre_scope_budget_row_as_platform() {
        let store = RedbControlPlaneStore::in_memory();
        {
            let txn = store.db.begin_write().unwrap();
            {
                let mut table = txn.open_table(BUDGETS_TABLE).unwrap();
                table
                    .insert(
                        "tenant-a",
                        br#"{"max_micros":5,"period":"Daily"}"#.as_slice(),
                    )
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        let loaded = store.load().unwrap();
        let budget = loaded
            .budgets
            .get(&TenantId::new("tenant-a"))
            .expect("the pre-scope row must still load");
        assert_eq!(budget.credential_source, CredentialSource::Platform);
        assert_eq!(budget.max_micros, MicroUsd::from_micros(5));
        assert_eq!(budget.period, Period::Daily);
    }

    /// ADR-0007 decision 8, redb: `set_budget` + `load` round trip a
    /// `Tenant`-scoped budget without collapsing its scope to `Platform`.
    #[test]
    fn redb_round_trips_a_tenant_scoped_budget() {
        let store = RedbControlPlaneStore::in_memory();
        let budget = TenantBudget {
            max_micros: MicroUsd::from_micros(11),
            period: Period::Monthly,
            credential_source: CredentialSource::Tenant,
        };
        store
            .set_budget(&TenantId::new("tenant-a"), Some(&budget))
            .unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(
            loaded.budgets.get(&TenantId::new("tenant-a")),
            Some(&budget)
        );
    }

    /// ADR-0007 amendment 1, redb upgrade: a database written before
    /// `include_byok_in_limit` holds key budgets with one `credential_source`
    /// scope, or none. Reopened, each loads with the documented mapping, so
    /// no key budget stops counting what it counted, and a tenant budget in
    /// the same table keeps its scope. A key budget written now carries only
    /// the flag, so a build from before it reads the row as platform-scoped.
    #[test]
    fn redb_upgrade_loads_scoped_key_budgets_with_the_include_byok_mapping() {
        let path = temp_db_path("key-budget-upgrade");
        let tenant_row =
            br#"{"schema_version":2,"max_micros":8,"period":"Daily","credential_source":"tenant"}"#;
        {
            let store = RedbControlPlaneStore::open(&path).unwrap();
            let txn = store.db.begin_write().unwrap();
            {
                let mut table = txn.open_table(BUDGETS_TABLE).unwrap();
                for (key_id, row, _) in pre_flag_key_budget_rows() {
                    table
                        .insert(key_budget_subject(&key_id).as_str(), row.as_bytes())
                        .unwrap();
                }
                table.insert("tenant-a", tenant_row.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }

        let store = RedbControlPlaneStore::open(&path).unwrap();
        let loaded = store.load().unwrap();
        for (key_id, row, expected) in pre_flag_key_budget_rows() {
            assert_eq!(loaded.key_budgets.get(&key_id), Some(&expected), "{row}");
        }
        assert_eq!(loaded.key_budgets.len(), 3);
        assert_eq!(
            loaded.budgets.get(&TenantId::new("tenant-a")),
            Some(&TenantBudget {
                max_micros: MicroUsd::from_micros(8),
                period: Period::Daily,
                credential_source: CredentialSource::Tenant,
            }),
        );
        assert_eq!(
            loaded.budgets.len(),
            1,
            "key rows never load as tenant budgets"
        );

        let written = KeyBudget {
            max_micros: MicroUsd::from_micros(9),
            period: Period::Daily,
            include_byok_in_limit: true,
        };
        let key_id = KeyId::new("key-new");
        store.set_key_budget(&key_id, Some(&written)).unwrap();
        let raw: serde_json::Value = {
            let txn = store.db.begin_read().unwrap();
            let table = txn.open_table(BUDGETS_TABLE).unwrap();
            let row = table
                .get(key_budget_subject(&key_id).as_str())
                .unwrap()
                .unwrap();
            serde_json::from_slice(row.value()).unwrap()
        };
        assert_eq!(raw["include_byok_in_limit"], true, "{raw}");
        assert!(raw.get("credential_source").is_none(), "{raw}");
        assert_eq!(
            store.load().unwrap().key_budgets.get(&key_id),
            Some(&written)
        );
        drop(store);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn redb_limits_round_trip_across_reopen_and_delete_tenant() {
        let path = temp_db_path("limits-round-trip");
        let tenant = TenantId::new("tenant-a");
        let limits = LimitPolicy {
            tokens_per_minute: Some(0),
            requests_per_minute: Some(8),
            concurrent_streams: None,
        };
        {
            let store = RedbControlPlaneStore::open(&path).unwrap();
            store.create_tenant(&tenant).unwrap();
            store.set_limits(&tenant, Some(&limits)).unwrap();
        }
        {
            let store = RedbControlPlaneStore::open(&path).unwrap();
            assert_eq!(store.load().unwrap().limits.get(&tenant), Some(&limits));
            store.delete_tenant(&tenant).unwrap();
            assert!(!store.load().unwrap().limits.contains_key(&tenant));
        }
        let _ = std::fs::remove_file(path);
    }

    /// ADR-0008 decision 2, in both embedded stores: an opt-in is a durable
    /// row, an opt-out and a tenant delete remove it, and every write bumps
    /// the generation so other replicas notice.
    #[test]
    fn a_trace_export_opt_in_round_trips_and_goes_with_its_tenant() {
        let path = temp_db_path("trace-export-round-trip");
        type Open = Box<dyn Fn() -> Box<dyn ControlPlaneStore>>;
        let stores: Vec<(&str, Open)> = vec![
            ("in_memory", {
                let (store, _) = SharedMemoryStore::new();
                Box::new(move || Box::new(store.handle()))
            }),
            // Reopened for every step, so each read is what the file holds.
            ("redb", {
                let path = path.clone();
                Box::new(move || Box::new(RedbControlPlaneStore::open(&path).unwrap()))
            }),
        ];
        for (name, open) in stores {
            let (a, b) = (TenantId::new("a"), TenantId::new("b"));
            open().create_tenant(&a).unwrap();
            open().create_tenant(&b).unwrap();
            let before = open().policy_generation().unwrap();
            open().set_trace_export(&a, true).unwrap();
            open().set_trace_export(&b, true).unwrap();
            assert_eq!(
                open().load().unwrap().trace_export,
                HashSet::from([a.clone(), b.clone()]),
                "{name}"
            );
            open().set_trace_export(&b, false).unwrap();
            assert_eq!(
                open().load().unwrap().trace_export,
                HashSet::from([a.clone()]),
                "{name}"
            );
            open().delete_tenant(&a).unwrap();
            assert!(open().load().unwrap().trace_export.is_empty(), "{name}");
            assert_eq!(open().policy_generation().unwrap(), before + 4, "{name}");
        }
        let _ = std::fs::remove_file(path);
    }

    /// Object ownership in both embedded stores: the first claim wins and is
    /// never overwritten, the row survives reopening the redb file, and no
    /// claim bumps the generation (owner rows are not tier-2 policy).
    #[test]
    fn the_first_object_claim_wins_survives_a_reopen_and_bumps_no_generation() {
        let path = temp_db_path("object-owners");
        for (name, open) in object_stores(&path) {
            let (a, b) = (TenantId::new("a"), TenantId::new("b"));
            let tenant = |owner: Option<ObjectOwner>| owner.map(|o| o.tenant);
            let before = open().policy_generation().unwrap();
            assert_eq!(open().object_owner("file-1").unwrap(), None, "{name}");
            assert_eq!(
                open().claim_object("file-1", &a, None).unwrap().tenant,
                a,
                "{name}"
            );
            assert_eq!(
                open().claim_object("file-1", &b, None).unwrap().tenant,
                a,
                "{name}: a second claim must return the first owner"
            );
            assert_eq!(
                tenant(open().object_owner("file-1").unwrap()),
                Some(a.clone()),
                "{name}"
            );
            assert_eq!(open().object_owner("file-2").unwrap(), None, "{name}");
            assert_eq!(open().policy_generation().unwrap(), before, "{name}");
            for bad in ["", &"x".repeat(MAX_OBJECT_ID_BYTES + 1)] {
                assert!(
                    matches!(
                        open().claim_object(bad, &a, None),
                        Err(StoreError::InvalidInput(_))
                    ),
                    "{name}"
                );
            }
        }
        let _ = std::fs::remove_file(path);
    }

    type OpenStore = Box<dyn Fn() -> Box<dyn ControlPlaneStore>>;

    /// The in-memory store, and a redb file at `path`, each reopened per call.
    fn object_stores(path: &std::path::Path) -> Vec<(&'static str, OpenStore)> {
        let path = path.to_path_buf();
        vec![
            ("in_memory", {
                let (store, _) = SharedMemoryStore::new();
                Box::new(move || Box::new(store.handle()))
            }),
            (
                "redb",
                Box::new(move || Box::new(RedbControlPlaneStore::open(&path).unwrap())),
            ),
        ]
    }

    /// A row past its time to live is absent, and the next claim replaces
    /// it; a live row with a time to live is kept, with its expiry, and not
    /// extended by a later claim. A zero time to live is a row that has
    /// already expired, which makes this deterministic.
    #[test]
    fn an_expired_object_owner_is_absent_and_replaced_by_the_next_claim() {
        let path = temp_db_path("object-owner-expiry");
        let zero = Some(Duration::ZERO);
        let day = Some(Duration::from_secs(86_400));
        for (name, open) in object_stores(&path) {
            let (a, b) = (TenantId::new("a"), TenantId::new("b"));
            let claimed = open().claim_object("resp-1", &a, zero).unwrap();
            assert!(!claimed.is_live(unix_now_secs()), "{name}");
            assert_eq!(open().object_owner("resp-1").unwrap(), None, "{name}");
            let replaced = open().claim_object("resp-1", &b, None).unwrap();
            assert_eq!(
                (replaced.tenant, replaced.expires_at),
                (b.clone(), None),
                "{name}"
            );

            let kept = open().claim_object("resp-2", &a, day).unwrap();
            let at = kept.expires_at.expect("a row claimed with a ttl expires");
            assert!(at >= unix_now_secs() + 86_000, "{name}: {at}");
            assert_eq!(
                open().claim_object("resp-2", &b, day).unwrap(),
                kept,
                "{name}"
            );
            assert_eq!(
                open().claim_object("resp-2", &a, None).unwrap(),
                kept,
                "{name}"
            );
            assert_eq!(open().object_owner("resp-2").unwrap(), Some(kept), "{name}");
        }
        let _ = std::fs::remove_file(path);
    }

    /// Expired rows are removed by later claims, a bounded number per claim,
    /// so rows with a time to live cannot pile up. A row an expiry entry no
    /// longer describes (replaced since) is left alone.
    #[test]
    fn claims_remove_expired_object_owner_rows() {
        let store = RedbControlPlaneStore::in_memory();
        let (a, b) = (TenantId::new("a"), TenantId::new("b"));
        let count = |store: &RedbControlPlaneStore| {
            use redb::ReadableTableMetadata;
            let txn = store.db.begin_read().unwrap();
            let owners = txn.open_table(OBJECT_OWNERS_TABLE).unwrap().len().unwrap();
            let expiry = txn.open_table(OBJECT_EXPIRY_TABLE).unwrap().len().unwrap();
            (owners, expiry)
        };
        let expired = OBJECT_SWEEP_PER_CLAIM as u64 + 4;
        for i in 0..expired {
            store
                .claim_object(&format!("old-{i}"), &a, Some(Duration::ZERO))
                .unwrap();
        }
        // Each claim above swept the rows before it, so at most the last
        // one is left; replace it with a permanent row, which its stale
        // expiry entry must not remove.
        let last = format!("old-{}", expired - 1);
        store.claim_object(&last, &b, None).unwrap();
        store.claim_object("fresh", &a, None).unwrap();
        assert_eq!(count(&store), (2, 0), "only the permanent rows remain");
        assert_eq!(
            store.object_owner(&last).unwrap().map(|o| o.tenant),
            Some(b)
        );

        let memory = InMemoryControlPlaneStore::default();
        for i in 0..expired {
            memory
                .claim_object(&format!("old-{i}"), &a, Some(Duration::ZERO))
                .unwrap();
        }
        memory.claim_object("fresh", &a, None).unwrap();
        let state = memory.state.lock().unwrap();
        assert_eq!(
            state.object_owners.len(),
            1,
            "only the permanent row remains"
        );
        assert!(state.object_expiry.is_empty());
    }

    /// An owner row this build cannot read is an error, never "no owner":
    /// reading it as absent would let the object be claimed by someone else.
    #[test]
    fn an_unreadable_object_owner_row_is_an_error_not_an_absent_owner() {
        let store = RedbControlPlaneStore::in_memory();
        {
            let txn = store.db.begin_write().unwrap();
            {
                let mut table = txn.open_table(OBJECT_OWNERS_TABLE).unwrap();
                table.insert("garbled", b"{".as_slice()).unwrap();
                table
                    .insert("future", br#"{"schema_version":2,"tenant":"a"}"#.as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }
        for id in ["garbled", "future"] {
            assert!(store.object_owner(id).is_err(), "{id}");
            assert!(
                store.claim_object(id, &TenantId::new("b"), None).is_err(),
                "{id}"
            );
        }
    }

    /// A row this build cannot read is not consent, and it does not fail the
    /// load: a key revocation in the same load still has to propagate.
    #[test]
    fn an_unreadable_trace_export_row_is_not_consent_and_does_not_fail_the_load() {
        let store = RedbControlPlaneStore::in_memory();
        store.create_tenant(&TenantId::new("ok")).unwrap();
        store.set_trace_export(&TenantId::new("ok"), true).unwrap();
        {
            let txn = store.db.begin_write().unwrap();
            {
                let mut table = txn.open_table(TRACE_EXPORT_TABLE).unwrap();
                table.insert("garbled", b"{".as_slice()).unwrap();
                table
                    .insert(
                        "future",
                        br#"{"schema_version":2,"enabled":true}"#.as_slice(),
                    )
                    .unwrap();
            }
            txn.commit().unwrap();
        }
        let loaded = store
            .load()
            .expect("an unreadable opt-in row is not a load error");
        assert_eq!(loaded.trace_export, HashSet::from([TenantId::new("ok")]));
    }

    /// The opt-out path a tenant relies on: a write on one replica reaches
    /// another replica's snapshot on its next poll, with no other write.
    #[test]
    fn an_opt_out_written_on_another_replica_reaches_this_one_on_its_next_poll() {
        let (store, other_replica) = SharedMemoryStore::new();
        let tenant = TenantId::new("tenant-a");
        other_replica.create_tenant(&tenant).unwrap();
        other_replica.set_trace_export(&tenant, true).unwrap();
        let cp = ControlPlane::new(Box::new(store), HmacSecret::new(b"s"), KeySet::new()).unwrap();
        assert!(cp.trace_export(&tenant));

        other_replica.set_trace_export(&tenant, false).unwrap();
        assert!(cp.trace_export(&tenant), "nothing changes before the poll");
        assert!(cp.poll_once().unwrap(), "the opt-out moved the generation");
        assert!(!cp.trace_export(&tenant));
    }

    #[test]
    fn redb_rejects_future_limits_schema_on_load() {
        let store = RedbControlPlaneStore::in_memory();
        {
            let txn = store.db.begin_write().unwrap();
            {
                let mut table = txn.open_table(LIMITS_TABLE).unwrap();
                table.insert("tenant-a", br#"{"schema_version":2,"tokens_per_minute":5,"requests_per_minute":null,"concurrent_streams":null}"#.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }
        assert!(matches!(store.load(), Err(StoreError::Unavailable(_))));
    }

    #[test]
    fn redb_persists_a_budget_across_reopen() {
        let path = temp_db_path("budget-persists-across-reopen");
        let budget = TenantBudget {
            max_micros: MicroUsd::from_micros(42_000_000),
            period: Period::Monthly,
            credential_source: CredentialSource::Platform,
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
                    tags: Default::default(),
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
                tags: Default::default(),
            })
            .unwrap();
        store
            .put_key(&StoredKey {
                key_id: KeyId::new("k2"),
                digest: digest_bytes(b"secret", "llmp_b"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
                tags: Default::default(),
            })
            .unwrap();
        store
            .put_key(&StoredKey {
                key_id: KeyId::new("k3"),
                digest: digest_bytes(b"secret", "llmp_c"),
                tenant: TenantId::new("tenant-b"),
                revoked: false,
                tags: Default::default(),
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
    //     silently diverge (see AGENTS.md invariant 6 for why
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
                    tags: Default::default(),
                })
                .unwrap();
            store
                .put_key(&StoredKey {
                    key_id: KeyId::new("k2"),
                    digest: digest_bytes(b"secret", "llmp_b"),
                    tenant: TenantId::new("tenant-b"),
                    revoked: false,
                    tags: Default::default(),
                })
                .unwrap();
            store.revoke_key(&KeyId::new("k2")).unwrap();
            store
                .set_policy(
                    &TenantId::new("tenant-a"),
                    &ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]),
                )
                .unwrap();
            // A budget IS part of `StoredControlPlane`
            // (unlike spend rows below), so it is compared through
            // `assert_stored_control_planes_match` like `keys`/`policies`.
            store
                .set_budget(
                    &TenantId::new("tenant-a"),
                    Some(&TenantBudget {
                        max_micros: MicroUsd::from_micros(500_000_000),
                        period: Period::Monthly,
                        credential_source: CredentialSource::Platform,
                    }),
                )
                .unwrap();
            // Spend rows, keyed `(stat_prefix,
            // tenant, period)`, are not part of `StoredControlPlane` (there
            // is no wholesale `load()` for them -- see the trait doc), so
            // they are checked directly against BOTH stores below rather
            // than through `assert_stored_control_planes_match`.
            store
                .add_spend(
                    "chain-a",
                    &TenantId::new("tenant-a"),
                    &PeriodKey::for_test("2026-08"),
                    12_500_000,
                    FlushToken {
                        node_id: "node-a",
                        seq: 1,
                    },
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
                tags: Default::default(),
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

    // --- policy propagation by version-stamp polling ------------------

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
                tags: Default::default(),
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

    #[test]
    fn a_load_that_finds_the_store_emptied_logs_an_error_and_counts_once() {
        // The in-process path to an empty store: the last tenant is deleted.
        // A flushed Redis reaches the same transition; see
        // `control_redis.rs::redis_a_flushed_store_between_polls_is_loud`.
        let (store, inner) = SharedMemoryStore::new();
        inner.create_tenant(&TenantId::new("tenant-a")).unwrap();
        let cp = ControlPlane::new(Box::new(store), HmacSecret::new(b"s"), KeySet::new()).unwrap();
        let registry = proxy_observability::stats::StatsControl::new(1).registry();
        cp.export_snapshot_age(Arc::clone(&registry), "ingress");
        assert_eq!(rendered_emptied_count(&registry, "ingress"), 0);

        let capture = ErrorCapture::default();
        let _guard = tracing::subscriber::set_default(capture.clone());
        inner.delete_tenant(&TenantId::new("tenant-a")).unwrap();
        assert!(cp.poll_once().unwrap());
        // Still empty on the next change: one signal per transition.
        inner.create_tenant(&TenantId::new("tenant-b")).unwrap();
        inner.delete_tenant(&TenantId::new("tenant-b")).unwrap();
        assert!(cp.poll_once().unwrap());

        let lines = capture.lines.lock().unwrap().clone();
        let emptied: Vec<_> = lines
            .iter()
            .filter(|line| line.contains("store is now EMPTY"))
            .collect();
        assert_eq!(emptied.len(), 1, "one ERROR per transition: {lines:?}");
        assert!(
            emptied[0].contains("tenants_before=1") && emptied[0].contains("tenants_after=0"),
            "{}",
            emptied[0]
        );
        assert_eq!(rendered_emptied_count(&registry, "ingress"), 1);
    }

    #[test]
    fn a_load_that_loses_every_key_while_tenants_remain_is_loud_once_per_transition() {
        // Keys cannot be deleted through the API (a revoke keeps the row), so
        // the rows are cleared under the store as a lost Redis would, with
        // the tenant left in place: the transition is per set, not both.
        let (store, inner) = SharedMemoryStore::new();
        inner.create_tenant(&TenantId::new("tenant-a")).unwrap();
        let put = |id: &str| {
            inner
                .put_key(&StoredKey {
                    key_id: KeyId::new(id),
                    digest: digest_bytes(b"s", &format!("llmp_{id}")),
                    tenant: TenantId::new("tenant-a"),
                    revoked: false,
                    tags: Default::default(),
                })
                .unwrap();
        };
        let lose_keys = || {
            let mut state = inner.state.lock().unwrap();
            state.keys.clear();
            state.generation += 1;
        };
        put("k1");
        put("k2");
        let cp = ControlPlane::new(Box::new(store), HmacSecret::new(b"s"), KeySet::new()).unwrap();
        let registry = proxy_observability::stats::StatsControl::new(1).registry();
        cp.export_snapshot_age(Arc::clone(&registry), "ingress");
        assert_eq!(rendered_store_rows(&registry, "ingress", "keys"), 2);
        assert_eq!(rendered_store_rows(&registry, "ingress", "tenants"), 1);

        let capture = ErrorCapture::default();
        let _guard = tracing::subscriber::set_default(capture.clone());
        let emptied_lines = || {
            capture
                .lines
                .lock()
                .unwrap()
                .iter()
                .filter(|line| line.contains("store is now EMPTY"))
                .cloned()
                .collect::<Vec<_>>()
        };
        lose_keys();
        assert!(cp.poll_once().unwrap());
        let lines = emptied_lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("keys_before=2")
                && lines[0].contains("keys_after=0")
                && lines[0].contains("tenants_after=1"),
            "{}",
            lines[0]
        );
        assert_eq!(rendered_emptied_count(&registry, "ingress"), 1);
        assert_eq!(rendered_store_rows(&registry, "ingress", "keys"), 0);
        assert_eq!(rendered_store_rows(&registry, "ingress", "tenants"), 1);

        // Still keyless after another change: suppressed.
        inner.create_tenant(&TenantId::new("tenant-b")).unwrap();
        assert!(cp.poll_once().unwrap());
        assert_eq!(emptied_lines().len(), 1);
        assert_eq!(rendered_emptied_count(&registry, "ingress"), 1);

        // Keys come back, then go again: the next loss is loud again.
        put("k3");
        assert!(cp.poll_once().unwrap());
        assert_eq!(rendered_store_rows(&registry, "ingress", "keys"), 1);
        lose_keys();
        assert!(cp.poll_once().unwrap());
        assert_eq!(emptied_lines().len(), 2);
        assert_eq!(rendered_emptied_count(&registry, "ingress"), 2);
    }

    // --- the hard staleness bound (review H4; ADR-0005: auth fails closed) --
    //
    // Before the bound, a store outage keeps the last-good snapshot serving;
    // past it, virtual-key authentication refuses every key, and the age
    // gauge on /stats/prometheus shows how stale the snapshot is. A poll that
    // succeeds again restores service and resets the gauge.
    //
    // The bound is moved rather than the clock: "age > bound" is the whole
    // condition, and waiting out a real bound would make the test slow. The
    // one sleep is for the gauge, which counts whole seconds.
    #[test]
    fn past_the_staleness_bound_auth_fails_closed_and_the_age_gauge_shows_it() {
        let secret_bytes = b"operator-secret";
        let fail_flag = Arc::new(AtomicBool::new(false));
        let inner = InMemoryControlPlaneStore::default();
        inner
            .put_key(&StoredKey {
                key_id: KeyId::new("k1"),
                digest: digest_bytes(secret_bytes, "llmp_good-key"),
                tenant: TenantId::new("tenant-a"),
                revoked: false,
                tags: Default::default(),
            })
            .unwrap();
        let cp = ControlPlane::new(
            Box::new(ToggleStore {
                inner,
                fail: Arc::clone(&fail_flag),
                load_calls: Arc::new(AtomicUsize::new(0)),
            }),
            HmacSecret::new(secret_bytes),
            KeySet::new(),
        )
        .unwrap();
        let registry = proxy_observability::stats::StatsControl::new(1).registry();
        cp.export_snapshot_age(Arc::clone(&registry), "ingress");
        let authenticator =
            VirtualKeyAuthenticator::new(HmacSecret::new(secret_bytes), cp.handle())
                .with_freshness(cp.freshness());
        let headers = headers_with_authorization("Bearer llmp_good-key");
        let gauge = || {
            proxy_observability::stats::prometheus_render::render(&registry)
                .lines()
                .find(|line| {
                    line.starts_with(
                        "envoy_llmproxy_policy_snapshot_age_seconds{scope=\"ingress\"}",
                    )
                })
                .and_then(|line| line.rsplit(' ').next())
                .and_then(|value| value.parse::<u64>().ok())
                .expect("the age gauge is exported")
        };

        fail_flag.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(1100));
        assert!(cp.poll_once().is_err());
        cp.publish_snapshot_age();

        cp.freshness().set_max_staleness(Duration::from_secs(3600));
        assert!(
            matches!(
                authenticator.authenticate(&headers),
                AuthOutcome::Authenticated(_)
            ),
            "before the bound, the last-good snapshot keeps serving"
        );

        cp.freshness().set_max_staleness(Duration::from_millis(1));
        assert!(
            matches!(
                authenticator.authenticate(&headers),
                AuthOutcome::Rejected(AuthError::PolicyStale)
            ),
            "past the bound, a valid key is refused: the snapshot may hold a revoked key"
        );
        assert!(gauge() >= 1, "the gauge shows the stale snapshot's age");

        fail_flag.store(false, Ordering::SeqCst);
        cp.poll_once().unwrap();
        cp.publish_snapshot_age();
        cp.freshness().set_max_staleness(Duration::from_secs(3600));
        assert!(matches!(
            authenticator.authenticate(&headers),
            AuthOutcome::Authenticated(_)
        ));
        assert_eq!(gauge(), 0, "a successful poll resets the age");
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
    //     add_spend (tier-3) and a revoke of an unknown key (nothing written)
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
                tags: Default::default(),
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
            credential_source: CredentialSource::Platform,
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

        // add_spend is tier-3, not tier-2 -- must never bump.
        store
            .add_spend(
                "chain-a",
                &tenant,
                &PeriodKey::for_test("2026-09"),
                5_000_000,
                FlushToken {
                    node_id: "node-a",
                    seq: 1,
                },
            )
            .unwrap();
        assert_eq!(
            store.policy_generation().unwrap(),
            expected,
            "add_spend is a tier-3 write and must never bump the tier-2 policy generation"
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
                tags: Default::default(),
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
            credential_source: CredentialSource::Platform,
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
            .add_spend(
                "chain-a",
                &tenant,
                &PeriodKey::for_test("2026-09"),
                5_000_000,
                FlushToken {
                    node_id: "node-a",
                    seq: 1,
                },
            )
            .unwrap();
        assert_eq!(
            store.policy_generation().unwrap(),
            expected,
            "add_spend must not bump the redb-backed generation either"
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

    // --- additive spend, and the dedup that makes it at-most-once ----
    //
    // These test the STORE's half of the contract. The accumulator's half
    // (adopting the returned total, retrying under the same sequence) is in
    // `spend.rs`. Both backends are covered: the in-memory store is what
    // embedded mode runs, and ADR-0006 §5 forbids treating that as a special
    // case, so it must satisfy the identical contract.

    fn spend_row() -> (String, TenantId, PeriodKey) {
        (
            "chain-a".to_string(),
            TenantId::new("tenant-a"),
            PeriodKey::for_test("2026-09"),
        )
    }

    /// The property absolute writes could not have: two replicas' spend adds
    /// up instead of the later write erasing the earlier one.
    #[test]
    fn two_writers_add_to_the_same_row_instead_of_overwriting_each_other() {
        let store = InMemoryControlPlaneStore::default();
        let (prefix, tenant, period) = spend_row();

        let after_a = store
            .add_spend(
                &prefix,
                &tenant,
                &period,
                100,
                FlushToken {
                    node_id: "node-a",
                    seq: 1,
                },
            )
            .unwrap();
        let after_b = store
            .add_spend(
                &prefix,
                &tenant,
                &period,
                50,
                FlushToken {
                    node_id: "node-b",
                    seq: 1,
                },
            )
            .unwrap();

        assert_eq!(after_a, 100);
        assert_eq!(
            after_b, 150,
            "node-b's flush must ADD to node-a's, and must return the new total including \
             it -- returning only node-b's own contribution would leave every replica \
             enforcing against its own spend alone"
        );
        assert_eq!(store.load_spend(&prefix, &tenant, &period).unwrap(), 150);
    }

    /// The trap ADR-0006 §2 names: dedup keyed by the sequence alone would
    /// see node-b's `seq: 1` as a replay of node-a's and silently drop a real
    /// charge. Distinct from the test above -- that one would still pass if
    /// the two writers happened to pick different sequences.
    #[test]
    fn two_writers_using_the_same_sequence_number_both_land() {
        let store = InMemoryControlPlaneStore::default();
        let (prefix, tenant, period) = spend_row();

        for node_id in ["node-a", "node-b", "node-c"] {
            store
                .add_spend(
                    &prefix,
                    &tenant,
                    &period,
                    10,
                    FlushToken { node_id, seq: 7 },
                )
                .unwrap();
        }

        assert_eq!(
            store.load_spend(&prefix, &tenant, &period).unwrap(),
            30,
            "three replicas that all reached sequence 7 must all be charged; dedup state \
             keyed on the sequence alone drops two of them and loses the spend"
        );
    }

    /// A retry of a write that DID land must not charge twice, and must
    /// still hand back a usable total.
    #[test]
    fn a_replayed_flush_token_is_a_no_op_that_still_returns_the_total() {
        let store = InMemoryControlPlaneStore::default();
        let (prefix, tenant, period) = spend_row();
        let token = FlushToken {
            node_id: "node-a",
            seq: 1,
        };

        assert_eq!(
            store
                .add_spend(&prefix, &tenant, &period, 100, token)
                .unwrap(),
            100
        );
        assert_eq!(
            store
                .add_spend(&prefix, &tenant, &period, 100, token)
                .unwrap(),
            100,
            "a replay must return the CURRENT total, not an error and not a second charge \
             -- the caller cannot tell its first attempt landed, so this is the answer it \
             needs to reconcile against"
        );
        assert_eq!(store.load_spend(&prefix, &tenant, &period).unwrap(), 100);
    }

    /// Dedup is per ROW as well as per writer: the same sequence against a
    /// different period is a different flush, not a replay.
    #[test]
    fn the_same_sequence_against_a_different_row_is_not_a_replay() {
        let store = InMemoryControlPlaneStore::default();
        let (prefix, tenant, _) = spend_row();
        let token = FlushToken {
            node_id: "node-a",
            seq: 1,
        };
        let september = PeriodKey::for_test("2026-09");
        let october = PeriodKey::for_test("2026-10");

        store
            .add_spend(&prefix, &tenant, &september, 100, token)
            .unwrap();
        store
            .add_spend(&prefix, &tenant, &october, 40, token)
            .unwrap();

        assert_eq!(store.load_spend(&prefix, &tenant, &september).unwrap(), 100);
        assert_eq!(
            store.load_spend(&prefix, &tenant, &october).unwrap(),
            40,
            "a period rollover restarts the sequence for the new row; treating that as a \
             replay would lose the first flush of every period"
        );
    }

    /// What [`ControlPlaneStore::last_flush_seq`] exists for -- a restarted
    /// replica has to find out where its own sequence got to, or every flush
    /// it makes is dropped as a replay of its previous life.
    #[test]
    fn last_flush_seq_reports_this_writers_high_water_mark_only() {
        let store = InMemoryControlPlaneStore::default();
        let (prefix, tenant, period) = spend_row();

        assert_eq!(
            store
                .last_flush_seq(&prefix, &tenant, &period, "node-a")
                .unwrap(),
            0,
            "a writer that has never flushed this row starts at zero"
        );

        for seq in [1, 2, 3] {
            store
                .add_spend(
                    &prefix,
                    &tenant,
                    &period,
                    10,
                    FlushToken {
                        node_id: "node-a",
                        seq,
                    },
                )
                .unwrap();
        }
        store
            .add_spend(
                &prefix,
                &tenant,
                &period,
                10,
                FlushToken {
                    node_id: "node-b",
                    seq: 99,
                },
            )
            .unwrap();

        assert_eq!(
            store
                .last_flush_seq(&prefix, &tenant, &period, "node-a")
                .unwrap(),
            3
        );
        assert_eq!(
            store
                .last_flush_seq(&prefix, &tenant, &period, "node-b")
                .unwrap(),
            99,
            "each writer has its own sequence space; reading another writer's high-water \
             mark would make a restarted replica skip ahead or stall"
        );
    }

    /// `overwrite_spend` is the admin escape hatch, and it must stay
    /// absolute -- it is the only way to correct a row, so it must not be
    /// quietly additive too.
    #[test]
    fn overwrite_spend_replaces_the_total_and_leaves_dedup_state_alone() {
        let store = InMemoryControlPlaneStore::default();
        let (prefix, tenant, period) = spend_row();

        store
            .add_spend(
                &prefix,
                &tenant,
                &period,
                100,
                FlushToken {
                    node_id: "node-a",
                    seq: 1,
                },
            )
            .unwrap();
        store.overwrite_spend(&prefix, &tenant, &period, 7).unwrap();

        assert_eq!(store.load_spend(&prefix, &tenant, &period).unwrap(), 7);
        assert_eq!(
            store
                .last_flush_seq(&prefix, &tenant, &period, "node-a")
                .unwrap(),
            1,
            "an admin correction must not reset the writer's sequence -- that would make \
             the replica's next flush look like a replay of its own seq 1"
        );
    }

    // --- tier-3 window counters ----

    fn window_row(subject: &str, dimension: WindowDimension, window: WindowKey) -> WindowRow {
        WindowRow {
            subject: subject.to_string(),
            dimension,
            window,
        }
    }

    /// A window far in the future, so the stores' real-clock pruning keeps it.
    fn live_window() -> WindowKey {
        WindowKey::containing(unix_now_secs(), 60)
    }

    fn add_one(
        store: &dyn ControlPlaneStore,
        scope: &str,
        node: &str,
        row: &WindowRow,
        delta: u64,
        seq: u64,
    ) -> u64 {
        store
            .add_window_batch(scope, node, &[WindowDelta { row, delta, seq }])
            .remove(0)
            .unwrap()
    }

    fn load_one(store: &dyn ControlPlaneStore, scope: &str, row: &WindowRow) -> u64 {
        store
            .load_window_batch(scope, std::slice::from_ref(row))
            .remove(0)
            .unwrap()
    }

    fn assert_window_contract(store: &dyn ControlPlaneStore) {
        let win = live_window();
        let row = window_row("tenant-a", WindowDimension::TotalTokens, win);
        assert_eq!(load_one(store, "chain", &row), 0, "absent row reads 0");
        assert_eq!(
            store.last_window_seq_batch("chain", "node-a", std::slice::from_ref(&row)),
            vec![Ok(0)]
        );

        // Two nodes add to one row: the total is the sum.
        assert_eq!(add_one(store, "chain", "node-a", &row, 100, 1), 100);
        assert_eq!(add_one(store, "chain", "node-b", &row, 50, 1), 150);
        // Replay and older seq are no-ops that return the current total.
        assert_eq!(add_one(store, "chain", "node-a", &row, 100, 1), 150);
        assert_eq!(add_one(store, "chain", "node-a", &row, 7, 3), 157);
        assert_eq!(add_one(store, "chain", "node-a", &row, 999, 2), 157);
        assert_eq!(load_one(store, "chain", &row), 157);

        // High-water marks are per node.
        assert_eq!(
            store.last_window_seq_batch("chain", "node-a", std::slice::from_ref(&row)),
            vec![Ok(3)]
        );
        assert_eq!(
            store.last_window_seq_batch("chain", "node-b", std::slice::from_ref(&row)),
            vec![Ok(1)]
        );

        // Other dimension, other window, other subject, other scope: separate rows.
        let other_dim = window_row("tenant-a", WindowDimension::Requests, win);
        let other_win = window_row(
            "tenant-a",
            WindowDimension::TotalTokens,
            WindowKey {
                length_secs: win.length_secs,
                index: win.index + 1,
            },
        );
        let other_subject = window_row("tenant-b", WindowDimension::TotalTokens, win);
        assert_eq!(add_one(store, "chain", "node-a", &other_dim, 1, 1), 1);
        assert_eq!(add_one(store, "chain", "node-a", &other_win, 2, 1), 2);
        assert_eq!(add_one(store, "chain", "node-a", &other_subject, 3, 1), 3);
        assert_eq!(add_one(store, "chain-2", "node-a", &row, 4, 1), 4);
        assert_eq!(load_one(store, "chain", &row), 157);
        assert_eq!(load_one(store, "chain-2", &row), 4);

        // Results come back in input order, one per row.
        let batch = [other_subject.clone(), row.clone(), other_dim.clone()];
        assert_eq!(
            store.load_window_batch("chain", &batch),
            vec![Ok(3), Ok(157), Ok(1)]
        );
        let deltas = [
            WindowDelta {
                row: &other_dim,
                delta: 10,
                seq: 2,
            },
            WindowDelta {
                row: &row,
                delta: 1,
                seq: 4,
            },
        ];
        assert_eq!(
            store.add_window_batch("chain", "node-a", &deltas),
            vec![Ok(11), Ok(158)]
        );
    }

    #[test]
    fn memory_window_counters_satisfy_the_additive_and_dedup_contract() {
        assert_window_contract(&InMemoryControlPlaneStore::new());
    }

    #[test]
    fn redb_window_counters_satisfy_the_additive_and_dedup_contract() {
        assert_window_contract(&RedbControlPlaneStore::in_memory());
    }

    #[test]
    fn memory_prunes_window_rows_and_seq_entries_after_end_plus_grace() {
        let store = InMemoryControlPlaneStore::new();
        let old = window_row("t", WindowDimension::Requests, WindowKey::containing(0, 60));
        let live = window_row(
            "t",
            WindowDimension::Requests,
            WindowKey::containing(1000, 60),
        );
        let at = |now: u64, row: &WindowRow, seq: u64| {
            store.add_window_batch_at(now, "c", "n", &[WindowDelta { row, delta: 1, seq }])
        };
        // `old` ends at 60, so it survives until 60 + grace.
        at(60 + WINDOW_ROW_GRACE_SECS, &old, 1);
        at(60 + WINDOW_ROW_GRACE_SECS, &live, 1);
        assert_eq!(load_one(&store, "c", &old), 1, "inside the grace");
        // One second past end + grace: pruned along with its seq entry.
        at(61 + WINDOW_ROW_GRACE_SECS, &live, 2);
        assert_eq!(load_one(&store, "c", &old), 0);
        assert_eq!(load_one(&store, "c", &live), 2);
        {
            let state = store.state.lock().unwrap();
            assert_eq!(state.windows.len(), 1);
            assert_eq!(state.window_seq.len(), 1, "the seq entry is pruned too");
        }
        assert_eq!(
            store.last_window_seq_batch("c", "n", std::slice::from_ref(&old)),
            vec![Ok(0)]
        );
    }

    #[test]
    fn redb_prunes_window_rows_and_seq_entries_after_end_plus_grace() {
        let store = RedbControlPlaneStore::in_memory();
        let old = window_row("t", WindowDimension::Requests, WindowKey::containing(0, 60));
        let live = window_row(
            "t",
            WindowDimension::Requests,
            WindowKey::containing(1000, 60),
        );
        let at = |now: u64, row: &WindowRow, seq: u64| {
            store
                .add_window_batch_inner(now, "c", "n", &[WindowDelta { row, delta: 1, seq }])
                .unwrap()
        };
        at(60 + WINDOW_ROW_GRACE_SECS, &old, 1);
        at(60 + WINDOW_ROW_GRACE_SECS, &live, 1);
        assert_eq!(load_one(&store, "c", &old), 1, "inside the grace");
        at(61 + WINDOW_ROW_GRACE_SECS, &live, 2);
        assert_eq!(load_one(&store, "c", &old), 0);
        assert_eq!(load_one(&store, "c", &live), 2);
        assert_eq!(
            store.last_window_seq_batch("c", "n", std::slice::from_ref(&old)),
            vec![Ok(0)],
            "the seq entry is pruned too"
        );
    }

    #[test]
    fn redb_window_rows_survive_reopen() {
        let path = temp_db_path("window-rows-survive-reopen");
        let row = window_row("t", WindowDimension::InputTokens, live_window());
        {
            let store = RedbControlPlaneStore::open(&path).unwrap();
            assert_eq!(add_one(&store, "c", "node-a", &row, 42, 5), 42);
        }
        let store = RedbControlPlaneStore::open(&path).unwrap();
        assert_eq!(load_one(&store, "c", &row), 42);
        assert_eq!(
            store.last_window_seq_batch("c", "node-a", std::slice::from_ref(&row)),
            vec![Ok(5)]
        );
        // The restored high-water mark still dedups.
        assert_eq!(add_one(&store, "c", "node-a", &row, 42, 5), 42);
    }

    #[test]
    fn window_writes_never_bump_the_policy_generation() {
        let row = window_row("t", WindowDimension::Requests, live_window());
        let stores: [Box<dyn ControlPlaneStore>; 2] = [
            Box::new(InMemoryControlPlaneStore::new()),
            Box::new(RedbControlPlaneStore::in_memory()),
        ];
        for store in &stores {
            let before = store.policy_generation().unwrap();
            add_one(store.as_ref(), "c", "n", &row, 1, 1);
            add_one(store.as_ref(), "c", "n", &row, 1, 1);
            assert_eq!(store.policy_generation().unwrap(), before);
        }
    }

    /// Every assertion above, against the persistent backend. ADR-0006 §5:
    /// the two backends implement ONE contract, and a divergence here is how
    /// embedded mode ends up being the only path anyone ever exercises.
    #[test]
    fn the_redb_backend_satisfies_the_same_additive_and_dedup_contract() {
        let store = RedbControlPlaneStore::in_memory();
        let (prefix, tenant, period) = spend_row();

        assert_eq!(
            store
                .last_flush_seq(&prefix, &tenant, &period, "node-a")
                .unwrap(),
            0
        );

        let after_a = store
            .add_spend(
                &prefix,
                &tenant,
                &period,
                100,
                FlushToken {
                    node_id: "node-a",
                    seq: 1,
                },
            )
            .unwrap();
        let after_b = store
            .add_spend(
                &prefix,
                &tenant,
                &period,
                50,
                FlushToken {
                    node_id: "node-b",
                    seq: 1,
                },
            )
            .unwrap();
        assert_eq!((after_a, after_b), (100, 150));

        let replayed = store
            .add_spend(
                &prefix,
                &tenant,
                &period,
                50,
                FlushToken {
                    node_id: "node-b",
                    seq: 1,
                },
            )
            .unwrap();
        assert_eq!(
            replayed, 150,
            "the replay must be dropped and the current total returned, exactly as the \
             in-memory backend does"
        );

        assert_eq!(
            store
                .last_flush_seq(&prefix, &tenant, &period, "node-b")
                .unwrap(),
            1
        );
        assert_eq!(store.load_spend(&prefix, &tenant, &period).unwrap(), 150);

        store.overwrite_spend(&prefix, &tenant, &period, 7).unwrap();
        assert_eq!(store.load_spend(&prefix, &tenant, &period).unwrap(), 7);
        assert_eq!(
            store
                .last_flush_seq(&prefix, &tenant, &period, "node-b")
                .unwrap(),
            1
        );
    }

    /// A zero delta is a legal call (the trait allows it; the accumulator
    /// reads instead). It must still consume its sequence and still return
    /// the true total.
    #[test]
    fn a_zero_delta_flush_reads_the_true_total_and_still_advances_the_sequence() {
        let store = InMemoryControlPlaneStore::default();
        let (prefix, tenant, period) = spend_row();

        store
            .add_spend(
                &prefix,
                &tenant,
                &period,
                100,
                FlushToken {
                    node_id: "busy",
                    seq: 1,
                },
            )
            .unwrap();
        let seen = store
            .add_spend(
                &prefix,
                &tenant,
                &period,
                0,
                FlushToken {
                    node_id: "idle",
                    seq: 1,
                },
            )
            .unwrap();

        assert_eq!(
            seen, 100,
            "an idle replica must still see the busy one's spend, or it admits requests \
             against a ceiling it believes is empty"
        );
        assert_eq!(
            store
                .last_flush_seq(&prefix, &tenant, &period, "idle")
                .unwrap(),
            1
        );
    }

    // --- tenant provider credential rows (ADR-0007 §2) -------------------
    //
    // The shared-store pattern is the same one
    // `redb_and_inmemory_produce_the_same_snapshot_from_the_same_writes`
    // uses: one test body over `[&dyn ControlPlaneStore; 2]`, because the
    // trait promises ONE contract and a divergence between the two backends
    // is the bug shape this file pins tests to.

    /// A credential row for `(tenant, provider)` with `marker` stamped into
    /// every field a replace must overwrite -- so "the second put replaced
    /// the first" fails loudly if ANY field survives from the earlier row.
    /// The bytes are opaque to these tests on purpose: the store must
    /// persist ciphertext, never interpret it (ADR-0007 §2).
    fn credential_row(tenant: &str, provider: &str, marker: &str) -> StoredTenantCredential {
        let mut nonce = [0u8; 12];
        nonce[0] = marker.as_bytes()[0];
        StoredTenantCredential {
            schema_version: 1,
            tenant: TenantId::new(tenant),
            provider: provider.to_string(),
            key_id: format!("kek-{marker}"),
            nonce,
            ciphertext: format!("ciphertext-{marker}").into_bytes(),
            last4: format!("last4-{marker}"),
            fingerprint: format!("fp-{marker}"),
            created_at: "2026-10-11T00:00:00Z".to_string(),
            updated_at: "2026-10-11T00:00:01Z".to_string(),
            verified_at: None,
        }
    }

    #[test]
    fn tenant_credential_put_then_load_round_trips_and_replaces_by_tenant_and_provider() {
        let redb_store = RedbControlPlaneStore::in_memory();
        let inmemory_store = InMemoryControlPlaneStore::default();
        let stores: [&dyn ControlPlaneStore; 2] = [&redb_store, &inmemory_store];

        for store in stores {
            // No `create_tenant` first, deliberately: `set_policy` and
            // `put_key` both write for an UNKNOWN tenant with no existence
            // check in either store, and credential rows follow that same
            // rule rather than inventing a stricter one.
            let first = credential_row("tenant-a", "provider-x", "first");
            store.put_tenant_credential(&first).unwrap();
            let loaded = store.load().unwrap();
            assert_eq!(
                loaded.tenant_credentials,
                vec![first.clone()],
                "put then load must return exactly the row that was written"
            );

            // A second provider is a second row, not a replacement...
            store
                .put_tenant_credential(&credential_row("tenant-a", "provider-y", "other"))
                .unwrap();
            // ...while the SAME (tenant, provider) replaces in place.
            let second = credential_row("tenant-a", "provider-x", "second");
            store.put_tenant_credential(&second).unwrap();

            let loaded = store.load().unwrap();
            assert_eq!(
                loaded.tenant_credentials.len(),
                2,
                "a put for an existing (tenant, provider) must replace, not append"
            );
            let replaced = loaded
                .tenant_credentials
                .iter()
                .find(|r| r.provider == "provider-x")
                .expect("the replaced row must still be present");
            assert_eq!(
                replaced, &second,
                "the second put must fully replace the first row"
            );
            assert_ne!(
                replaced.ciphertext, first.ciphertext,
                "the replacement's ciphertext must be the new one, not the original's"
            );
            assert_ne!(replaced.last4, first.last4);
            assert_ne!(replaced.fingerprint, first.fingerprint);
            assert!(
                loaded
                    .tenant_credentials
                    .iter()
                    .any(|r| r.provider == "provider-y"),
                "the other provider's row must be untouched"
            );
        }
    }

    #[test]
    fn tenant_credential_delete_removes_the_row_and_an_absent_delete_is_not_found_without_a_bump() {
        let redb_store = RedbControlPlaneStore::in_memory();
        let inmemory_store = InMemoryControlPlaneStore::default();
        let stores: [&dyn ControlPlaneStore; 2] = [&redb_store, &inmemory_store];

        for store in stores {
            let tenant = TenantId::new("tenant-a");
            store
                .put_tenant_credential(&credential_row("tenant-a", "provider-x", "one"))
                .unwrap();
            let before = store.policy_generation().unwrap();

            store
                .delete_tenant_credential(&tenant, "provider-x")
                .expect("deleting an existing row must succeed");
            assert!(
                store.load().unwrap().tenant_credentials.is_empty(),
                "a deleted credential row must be gone from load()"
            );
            assert_eq!(
                store.policy_generation().unwrap(),
                before + 1,
                "a successful delete is a tier-2 write and bumps exactly once"
            );

            assert_eq!(
                store.delete_tenant_credential(&tenant, "provider-x"),
                Err(StoreError::NotFound),
                "deleting the same row a second time must be NotFound"
            );
            assert_eq!(
                store.delete_tenant_credential(&tenant, "never-written"),
                Err(StoreError::NotFound)
            );
            assert_eq!(
                store.policy_generation().unwrap(),
                before + 1,
                "a NotFound delete wrote nothing and must not bump -- see the trait's \
                 `policy_generation` doc"
            );
        }
    }

    #[test]
    fn each_tenant_credential_write_bumps_the_generation_by_exactly_as_much_as_any_other_write() {
        let redb_store = RedbControlPlaneStore::in_memory();
        let inmemory_store = InMemoryControlPlaneStore::default();
        let stores: [&dyn ControlPlaneStore; 2] = [&redb_store, &inmemory_store];

        for store in stores {
            let tenant = TenantId::new("tenant-a");
            let base = store.policy_generation().unwrap();

            store
                .put_tenant_credential(&credential_row("tenant-a", "provider-x", "one"))
                .unwrap();
            assert_eq!(store.policy_generation().unwrap(), base + 1);

            // A replacing put bumps unconditionally -- the trait forbids
            // read-before-write "did this change anything" checks.
            store
                .put_tenant_credential(&credential_row("tenant-a", "provider-x", "two"))
                .unwrap();
            assert_eq!(store.policy_generation().unwrap(), base + 2);

            // `set_policy` is the yardstick: a credential write must move
            // the stamp by exactly what any other tier-2 write does.
            store.set_policy(&tenant, &ModelAccess::All).unwrap();
            let after_set_policy = store.policy_generation().unwrap();
            assert_eq!(after_set_policy, base + 3);

            store
                .delete_tenant_credential(&tenant, "provider-x")
                .unwrap();
            assert_eq!(store.policy_generation().unwrap(), after_set_policy + 1);
        }
    }

    #[test]
    fn delete_tenant_removes_that_tenants_credential_rows_and_leaves_other_tenants() {
        let redb_store = RedbControlPlaneStore::in_memory();
        let inmemory_store = InMemoryControlPlaneStore::default();
        let stores: [&dyn ControlPlaneStore; 2] = [&redb_store, &inmemory_store];

        for store in stores {
            store
                .put_tenant_credential(&credential_row("tenant-a", "provider-x", "ax"))
                .unwrap();
            store
                .put_tenant_credential(&credential_row("tenant-a", "provider-y", "ay"))
                .unwrap();
            store
                .put_tenant_credential(&credential_row("tenant-b", "provider-x", "bx"))
                .unwrap();
            let before = store.policy_generation().unwrap();

            store.delete_tenant(&TenantId::new("tenant-a")).unwrap();

            let loaded = store.load().unwrap();
            assert_eq!(
                loaded.tenant_credentials.len(),
                1,
                "only tenant-b's row may survive tenant-a's deletion"
            );
            assert_eq!(
                loaded.tenant_credentials[0].tenant,
                TenantId::new("tenant-b")
            );
            assert_eq!(loaded.tenant_credentials[0].provider, "provider-x");
            assert_eq!(
                store.policy_generation().unwrap(),
                before + 1,
                "one delete_tenant bumps exactly once no matter how many rows it removed -- \
                 the deletion and its rows are one write"
            );
        }
    }

    #[test]
    fn put_tenant_credential_rejects_a_schema_version_this_build_does_not_understand() {
        let redb_store = RedbControlPlaneStore::in_memory();
        let inmemory_store = InMemoryControlPlaneStore::default();
        let stores: [&dyn ControlPlaneStore; 2] = [&redb_store, &inmemory_store];

        for store in stores {
            let before = store.policy_generation().unwrap();
            // The shape of a row a NEWER build would write -- rejected at
            // the write, so this build never stores something its own
            // `load` would then refuse to read back.
            let mut future = credential_row("tenant-a", "provider-x", "future");
            future.schema_version = 2;

            assert_eq!(
                store.put_tenant_credential(&future),
                Err(StoreError::Conflict(
                    "unsupported tenant credential schema_version".into()
                )),
                "a schema_version this build does not understand must be Conflict"
            );
            assert_eq!(
                store.policy_generation().unwrap(),
                before,
                "a rejected put wrote nothing and must not bump the generation"
            );
            let loaded = store.load().expect("the store must still load");
            assert!(
                loaded.tenant_credentials.is_empty(),
                "the rejected row must not have been stored: {:?}",
                loaded.tenant_credentials
            );
        }
    }

    // --- redb-only: durability and fail-closed decoding ------------------

    #[test]
    fn redb_tenant_credentials_survive_closing_and_reopening_the_database_file() {
        let path = temp_db_path("tenant-credential-persists-across-reopen");
        let row = credential_row("tenant-a", "provider-x", "one");

        {
            let store = RedbControlPlaneStore::open(&path).unwrap();
            store.put_tenant_credential(&row).unwrap();
            // `store` (and its `redb::Database`) drops here -- redb's Drop
            // flushes and releases the file, same as the other reopen tests.
        }

        let reopened = RedbControlPlaneStore::open(&path).unwrap();
        let loaded = reopened.load().unwrap();
        assert_eq!(
            loaded.tenant_credentials,
            vec![row],
            "a reopened store must still see the credential row"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn redb_opens_a_database_file_created_before_the_tenant_credentials_table_existed() {
        let path = temp_db_path("pre-tenant-credentials-table");

        // Build the fixture with raw `redb`, not through the store under
        // test: every table the PREVIOUS code opened, and deliberately NOT
        // `TENANT_CREDENTIALS_TABLE`, so the file is exactly what an
        // existing deployment's database looks like on first start after
        // this change.
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut tenants = txn.open_table(TENANTS_TABLE).unwrap();
                tenants.insert("tenant-a", [].as_slice()).unwrap();
            }
            txn.open_table(KEYS_TABLE).unwrap();
            txn.open_table(KEYS_BY_TENANT_TABLE).unwrap();
            txn.open_table(POLICIES_TABLE).unwrap();
            txn.open_table(BUDGETS_TABLE).unwrap();
            txn.open_table(SPEND_TABLE).unwrap();
            txn.open_table(SPEND_SEQ_TABLE).unwrap();
            txn.open_table(GENERATION_TABLE).unwrap();
            txn.commit().unwrap();
        }

        // Opening through the store must succeed: `ensure_tables` creates
        // the missing table on open rather than erroring on it.
        let store = RedbControlPlaneStore::open(&path).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(
            loaded
                .tenants
                .iter()
                .map(TenantId::as_str)
                .collect::<Vec<_>>(),
            vec!["tenant-a"],
            "the pre-existing tenant row must survive the open that adds the new table"
        );
        assert!(loaded.tenant_credentials.is_empty());

        // ...and the newly created table is fully usable afterwards.
        let row = credential_row("tenant-a", "provider-x", "one");
        store.put_tenant_credential(&row).unwrap();
        assert_eq!(store.load().unwrap().tenant_credentials, vec![row]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn redb_a_tenant_credential_row_with_schema_version_2_makes_the_whole_load_unavailable() {
        let path = temp_db_path("tenant-credential-schema-version-2");
        let store = RedbControlPlaneStore::open(&path).unwrap();
        store
            .put_tenant_credential(&credential_row("tenant-a", "provider-x", "good"))
            .unwrap();

        // Write a future-version row directly, bypassing
        // `put_tenant_credential` -- the shape of a row written by a NEWER
        // build, which this build must refuse to half-read.
        let mut future = credential_row("tenant-b", "provider-y", "future");
        future.schema_version = 2;
        let future_hex = encode_hex_lower(&future.ciphertext);
        {
            let txn = store.db.begin_write().unwrap();
            {
                let mut table = txn.open_table(TENANT_CREDENTIALS_TABLE).unwrap();
                let encoded = EncodedTenantCredentialRow::from(&future);
                table
                    .insert(("tenant-b", "provider-y"), encode_json(&encoded).as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        let err = match store.load() {
            Err(err) => err,
            Ok(_) => panic!("a schema_version 2 row must fail the WHOLE load, not be skipped"),
        };
        let StoreError::Unavailable(msg) = &err else {
            panic!("expected StoreError::Unavailable; got {err:?}");
        };
        assert!(
            msg.contains("tenant-b"),
            "the error must name the tenant: {msg}"
        );
        assert!(
            msg.contains("provider-y"),
            "the error must name the provider: {msg}"
        );
        // Never the row's content -- see `decode_tenant_credential_row`'s
        // doc and AGENTS.md "Fail-open controls" (check what the log line
        // renders).
        assert!(
            !msg.contains(&future_hex) && !msg.contains("ciphertext-future"),
            "the error must not render ciphertext: {msg}"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn redb_a_tenant_credential_row_with_an_11_byte_nonce_makes_the_whole_load_unavailable() {
        let store = RedbControlPlaneStore::in_memory();
        let row = credential_row("tenant-a", "provider-x", "short-nonce");
        let ciphertext_hex = encode_hex_lower(&row.ciphertext);

        // Written raw, bypassing `put_tenant_credential` (which only ever
        // writes valid rows) -- the shape of a hand-edited or corrupted
        // file: a nonce of 11 bytes, not the 12 the store requires.
        {
            let txn = store.db.begin_write().unwrap();
            {
                let mut table = txn.open_table(TENANT_CREDENTIALS_TABLE).unwrap();
                let mut encoded = EncodedTenantCredentialRow::from(&row);
                encoded.nonce = encode_hex_lower(&[7u8; 11]);
                table
                    .insert(("tenant-a", "provider-x"), encode_json(&encoded).as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        let err = match store.load() {
            Err(err) => err,
            Ok(_) => panic!("a wrong-length-nonce row must fail the WHOLE load, not be skipped"),
        };
        let StoreError::Unavailable(msg) = &err else {
            panic!("expected StoreError::Unavailable; got {err:?}");
        };
        assert!(
            msg.contains("tenant-a"),
            "the error must name the tenant: {msg}"
        );
        assert!(
            msg.contains("provider-x"),
            "the error must name the provider: {msg}"
        );
        // Never the row's content -- see `decode_tenant_credential_row`'s
        // doc and AGENTS.md "Fail-open controls" (check what the log line
        // renders).
        assert!(
            !msg.contains(&ciphertext_hex) && !msg.contains("ciphertext-short-nonce"),
            "the error must not render ciphertext: {msg}"
        );
    }

    #[test]
    fn redb_a_tenant_credential_row_with_uppercase_hex_ciphertext_makes_the_whole_load_unavailable()
    {
        let store = RedbControlPlaneStore::in_memory();
        let row = credential_row("tenant-a", "provider-x", "upper");
        let ciphertext_hex = encode_hex_lower(&row.ciphertext);
        let uppercase_hex = ciphertext_hex.to_uppercase();

        // Written raw, bypassing `put_tenant_credential` -- uppercase hex
        // is not the encoding this store writes, so it marks a row written
        // by something other than this code path.
        {
            let txn = store.db.begin_write().unwrap();
            {
                let mut table = txn.open_table(TENANT_CREDENTIALS_TABLE).unwrap();
                let mut encoded = EncodedTenantCredentialRow::from(&row);
                encoded.ciphertext = uppercase_hex.clone();
                table
                    .insert(("tenant-a", "provider-x"), encode_json(&encoded).as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        let err = match store.load() {
            Err(err) => err,
            Ok(_) => panic!("an uppercase-hex ciphertext row must fail the WHOLE load"),
        };
        let StoreError::Unavailable(msg) = &err else {
            panic!("expected StoreError::Unavailable; got {err:?}");
        };
        assert!(
            msg.contains("tenant-a"),
            "the error must name the tenant: {msg}"
        );
        assert!(
            msg.contains("provider-x"),
            "the error must name the provider: {msg}"
        );
        // Never the row's content, in either spelling -- see
        // `decode_tenant_credential_row`'s doc and AGENTS.md "Fail-open
        // controls" (check what the log line renders).
        assert!(
            !msg.contains(&uppercase_hex)
                && !msg.contains(&ciphertext_hex)
                && !msg.contains("ciphertext-upper"),
            "the error must not render ciphertext: {msg}"
        );
    }

    #[test]
    fn redb_an_unparseable_tenant_credential_row_makes_the_whole_load_unavailable() {
        let store = RedbControlPlaneStore::in_memory();

        // Bytes that are not a credential row at all -- a hand-edited or
        // corrupted file. Written raw, bypassing the API (which only ever
        // writes valid rows).
        {
            let txn = store.db.begin_write().unwrap();
            {
                let mut table = txn.open_table(TENANT_CREDENTIALS_TABLE).unwrap();
                table
                    .insert(
                        ("tenant-a", "provider-x"),
                        b"definitely not json".as_slice(),
                    )
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        let err = match store.load() {
            Err(err) => err,
            Ok(_) => panic!("an unparseable credential row must fail the whole load"),
        };
        let StoreError::Unavailable(msg) = &err else {
            panic!("expected StoreError::Unavailable; got {err:?}");
        };
        assert!(
            msg.contains("tenant-a"),
            "the error must name the tenant: {msg}"
        );
        assert!(
            msg.contains("provider-x"),
            "the error must name the provider: {msg}"
        );
        assert!(
            !msg.contains("definitely not json"),
            "the error must not echo the row's raw bytes: {msg}"
        );
    }

    // --- the ControlPlane wrappers, same store-then-rebuild shape as
    //     `delete_tenant`/`set_budget`

    #[test]
    fn control_plane_tenant_credential_wrappers_write_delete_and_republish() {
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(b"operator-secret"),
            KeySet::new(),
        )
        .expect("empty store must not fail boot");

        let rec = credential_row("tenant-a", "provider-x", "one");
        cp.put_tenant_credential(&rec)
            .expect("put_tenant_credential must succeed against a healthy store");
        assert_eq!(
            cp.store().load().unwrap().tenant_credentials,
            vec![rec.clone()],
            "the wrapper must reach the store, not merely return Ok"
        );
        // The wrapper's own rebuild recorded the POST-write generation
        // stamp, so the next poll has nothing left to do. A wrapper that
        // skipped `rebuild()` would leave the boot stamp behind and this
        // would be `Ok(true)` -- the same mutation pin as the other
        // wrappers' republish tests.
        assert_eq!(
            cp.poll_once(),
            Ok(false),
            "put_tenant_credential must republish exactly like set_policy/set_budget"
        );
        // No key ring is configured here, so the stored row must appear as
        // Unusable rather than be dropped (ADR-0007 decision 3).
        let snapshot = cp.handle().load();
        let set = snapshot
            .tenant_credentials
            .get(&TenantId::new("tenant-a"))
            .expect("a stored row must keep its tenant in tenant mode");
        assert!(matches!(
            set.get("provider-x"),
            Some(TenantCredential::Unusable)
        ));
        drop(snapshot);

        cp.delete_tenant_credential(&TenantId::new("tenant-a"), "provider-x")
            .expect("delete_tenant_credential must succeed");
        assert!(cp.store().load().unwrap().tenant_credentials.is_empty());

        assert_eq!(
            cp.delete_tenant_credential(&TenantId::new("tenant-a"), "provider-x"),
            Err(StoreError::NotFound),
            "the wrapper must propagate the store's NotFound unchanged"
        );
    }

    // --- tenant credential decryption and storage (ADR-0007 decisions 2, 3)

    /// Distinctive so any Debug, serde, or on-disk leak is visible to the
    /// assertions below.
    const CREDENTIAL_SENTINEL: &str = "sk-or-v1-SENTINEL-plaintext-do-not-leak";
    const KEK_A: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
    const KEK_B: [u8; 32] = *b"fedcba9876543210fedcba9876543210";

    fn credential_keys(current: (&str, [u8; 32]), previous: &[(&str, [u8; 32])]) -> CredentialKeys {
        use crate::tenant_credential_crypto::CredentialKek;
        let ring = KeyRing::new(
            CredentialKek::from_bytes(current.0, current.1).unwrap(),
            previous
                .iter()
                .map(|(id, bytes)| CredentialKek::from_bytes(id, *bytes).unwrap())
                .collect(),
        )
        .unwrap();
        CredentialKeys::new(ring, b"operator-secret")
    }

    fn control_plane_with(
        store: Box<dyn ControlPlaneStore>,
        keys: Option<CredentialKeys>,
    ) -> ControlPlane {
        ControlPlane::new_with_credential_keys(
            store,
            HmacSecret::new(b"operator-secret"),
            KeySet::new(),
            keys,
        )
        .expect("store must load")
    }

    fn in_memory_cp(keys: Option<CredentialKeys>) -> ControlPlane {
        control_plane_with(Box::new(InMemoryControlPlaneStore::default()), keys)
    }

    fn secret_for(cp: &ControlPlane, tenant: &str, provider: &str) -> Option<String> {
        let snapshot = cp.handle().load();
        let set = snapshot.tenant_credentials.get(&TenantId::new(tenant))?;
        match set.get(provider)? {
            TenantCredential::Usable(secret) => Some(secret.expose().to_string()),
            TenantCredential::Unusable => None,
        }
    }

    fn is_unusable(cp: &ControlPlane, tenant: &str, provider: &str) -> bool {
        let snapshot = cp.handle().load();
        matches!(
            snapshot
                .tenant_credentials
                .get(&TenantId::new(tenant))
                .and_then(|set| set.get(provider)),
            Some(TenantCredential::Unusable)
        )
    }

    fn sentinel() -> TenantSecret {
        TenantSecret::new(CREDENTIAL_SENTINEL.to_string())
    }

    #[test]
    fn stored_secret_rebuilds_as_usable_with_the_same_plaintext() {
        let cp = in_memory_cp(Some(credential_keys(("k1", KEK_A), &[])));
        let tenant = TenantId::new("tenant-a");
        cp.store_tenant_secret(&tenant, "openrouter", &sentinel(), false)
            .unwrap();
        assert_eq!(
            secret_for(&cp, "tenant-a", "openrouter").as_deref(),
            Some(CREDENTIAL_SENTINEL)
        );
    }

    #[test]
    fn a_row_copied_to_another_tenant_is_unusable_not_dropped() {
        let cp = in_memory_cp(Some(credential_keys(("k1", KEK_A), &[])));
        cp.store_tenant_secret(&TenantId::new("tenant-a"), "openrouter", &sentinel(), false)
            .unwrap();
        let mut copied = cp.store().load().unwrap().tenant_credentials.remove(0);
        copied.tenant = TenantId::new("tenant-b");
        cp.put_tenant_credential(&copied).unwrap();

        assert!(
            is_unusable(&cp, "tenant-b", "openrouter"),
            "AAD binds the row to its tenant; a copy must be Unusable, not absent and not Usable"
        );
        assert_eq!(
            secret_for(&cp, "tenant-a", "openrouter").as_deref(),
            Some(CREDENTIAL_SENTINEL),
            "the original tenant is unaffected"
        );
    }

    #[test]
    fn a_row_sealed_under_an_unknown_key_id_is_unusable() {
        let cp = in_memory_cp(Some(credential_keys(("k1", KEK_A), &[])));
        // `credential_row` stamps key id `kek-one`, which the ring lacks.
        cp.put_tenant_credential(&credential_row("tenant-a", "openrouter", "one"))
            .unwrap();
        assert!(is_unusable(&cp, "tenant-a", "openrouter"));
        assert_eq!(cp.credential_warnings_emitted(), 1);
    }

    #[test]
    fn rotation_keeps_old_rows_openable_only_while_the_old_key_is_listed() {
        let path = temp_db_path("credential-rotation");
        let tenant = TenantId::new("tenant-a");
        {
            let cp = control_plane_with(
                Box::new(RedbControlPlaneStore::open(&path).unwrap()),
                Some(credential_keys(("k1", KEK_A), &[])),
            );
            cp.store_tenant_secret(&tenant, "openrouter", &sentinel(), false)
                .unwrap();
        }
        {
            let cp = control_plane_with(
                Box::new(RedbControlPlaneStore::open(&path).unwrap()),
                Some(credential_keys(("k2", KEK_B), &[("k1", KEK_A)])),
            );
            assert_eq!(
                secret_for(&cp, "tenant-a", "openrouter").as_deref(),
                Some(CREDENTIAL_SENTINEL),
                "a row sealed under a previous key must still open"
            );
        }
        {
            let cp = control_plane_with(
                Box::new(RedbControlPlaneStore::open(&path).unwrap()),
                Some(credential_keys(("k2", KEK_B), &[])),
            );
            assert!(
                is_unusable(&cp, "tenant-a", "openrouter"),
                "dropping the old key from the ring must fail the row closed"
            );
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn stored_rows_without_a_key_ring_are_unusable_and_warn_once() {
        let cp = in_memory_cp(None);
        cp.put_tenant_credential(&credential_row("tenant-a", "openrouter", "one"))
            .unwrap();
        assert!(is_unusable(&cp, "tenant-a", "openrouter"));
        assert_eq!(cp.credential_warnings_emitted(), 1);
        cp.rebuild();
        cp.rebuild();
        assert!(is_unusable(&cp, "tenant-a", "openrouter"));
        assert_eq!(
            cp.credential_warnings_emitted(),
            1,
            "repeat rebuilds must not re-warn for the same (tenant, provider, reason)"
        );
        // A second row is a new offender and warns once.
        cp.put_tenant_credential(&credential_row("tenant-a", "anthropic", "two"))
            .unwrap();
        assert_eq!(cp.credential_warnings_emitted(), 2);
    }

    #[test]
    fn a_recovered_row_warns_again_if_it_regresses() {
        let cp = in_memory_cp(None);
        cp.put_tenant_credential(&credential_row("tenant-a", "openrouter", "one"))
            .unwrap();
        assert_eq!(cp.credential_warnings_emitted(), 1);
        cp.delete_tenant_credential(&TenantId::new("tenant-a"), "openrouter")
            .unwrap();
        cp.put_tenant_credential(&credential_row("tenant-a", "openrouter", "one"))
            .unwrap();
        assert_eq!(cp.credential_warnings_emitted(), 2);
    }

    #[test]
    fn replacing_a_secret_keeps_created_at_and_changes_fingerprint_and_last4() {
        let cp = in_memory_cp(Some(credential_keys(("k1", KEK_A), &[])));
        let tenant = TenantId::new("tenant-a");
        let first = cp
            .store_tenant_secret(&tenant, "openrouter", &sentinel(), false)
            .unwrap();
        assert_eq!(first.last4, "leak");
        assert_eq!(first.verified_at, None);

        // Backdate the stored row so a regression that stamps `created_at`
        // afresh cannot hide inside one clock second.
        let mut row = cp.store().load().unwrap().tenant_credentials.remove(0);
        row.created_at = "2020-01-01T00:00:00Z".to_string();
        cp.put_tenant_credential(&row).unwrap();

        let second = cp
            .store_tenant_secret(
                &tenant,
                "openrouter",
                &TenantSecret::new("sk-replacement-9999".to_string()),
                true,
            )
            .unwrap();
        assert_eq!(second.created_at, "2020-01-01T00:00:00Z");
        assert_ne!(second.updated_at, "2020-01-01T00:00:00Z");
        assert_eq!(second.last4, "9999");
        assert_ne!(second.fingerprint, first.fingerprint);
        assert!(second.verified_at.is_some());
        assert!(second.policy_generation >= first.policy_generation);
        assert_eq!(
            secret_for(&cp, "tenant-a", "openrouter").as_deref(),
            Some("sk-replacement-9999")
        );
        assert_eq!(
            cp.tenant_credential_metadata(&tenant).unwrap(),
            vec![second]
        );
    }

    #[test]
    fn metadata_and_stored_row_never_render_the_plaintext() {
        let cp = in_memory_cp(Some(credential_keys(("k1", KEK_A), &[])));
        let meta = cp
            .store_tenant_secret(&TenantId::new("tenant-a"), "openrouter", &sentinel(), false)
            .unwrap();
        assert!(!format!("{meta:?}").contains("SENTINEL"));
        assert!(!serde_json::to_string(&meta).unwrap().contains("SENTINEL"));
        let row = cp.store().load().unwrap().tenant_credentials.remove(0);
        let debug = format!("{row:?}");
        assert!(!debug.contains("SENTINEL"));
        assert!(
            !debug.contains("ciphertext: ["),
            "Debug must print lengths, not sealed bytes: {debug}"
        );
        assert!(!format!("{:?}", cp.credential_keys).contains("0123456789abcdef"));
    }

    #[test]
    fn store_tenant_secret_without_a_key_ring_is_refused_and_writes_nothing() {
        let cp = in_memory_cp(None);
        let err = cp
            .store_tenant_secret(&TenantId::new("tenant-a"), "openrouter", &sentinel(), false)
            .unwrap_err();
        assert_eq!(err, CredentialStoreError::NotConfigured);
        assert!(cp.store().load().unwrap().tenant_credentials.is_empty());
    }

    #[test]
    fn redb_round_trips_a_stored_secret_and_never_writes_the_plaintext_to_disk() {
        let path = temp_db_path("credential-e2e");
        let tenant = TenantId::new("tenant-a");
        {
            let cp = control_plane_with(
                Box::new(RedbControlPlaneStore::open(&path).unwrap()),
                Some(credential_keys(("k1", KEK_A), &[])),
            );
            cp.store_tenant_secret(&tenant, "openrouter", &sentinel(), false)
                .unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes
                .windows(CREDENTIAL_SENTINEL.len())
                .any(|w| w == CREDENTIAL_SENTINEL.as_bytes()),
            "the database file must not contain the plaintext"
        );
        assert!(
            bytes.windows(2).any(|w| w == b"k1"),
            "sanity: the scan reads the rows it is meant to protect"
        );
        let cp = control_plane_with(
            Box::new(RedbControlPlaneStore::open(&path).unwrap()),
            Some(credential_keys(("k1", KEK_A), &[])),
        );
        assert_eq!(
            secret_for(&cp, "tenant-a", "openrouter").as_deref(),
            Some(CREDENTIAL_SENTINEL)
        );
        drop(cp);
        std::fs::remove_file(&path).ok();
    }

    // --- rate card rows (ADR-0006 §1: price is tier-2 state) --------------
    //
    // The same pattern as the credential rows above: one test body over both
    // embedded backends, because the trait promises ONE contract.

    /// A rate card for `chain` with `marker` stamped into every field a
    /// replace must overwrite. The document is opaque to the store, so a
    /// placeholder object is enough.
    fn rate_card(chain: &str, marker: &str) -> StoredRateCard {
        StoredRateCard {
            chain: chain.to_string(),
            version: format!("version-{marker}"),
            card_json: format!(r#"{{"marker":"{marker}"}}"#),
            schema_version: crate::control::RATE_CARD_SCHEMA_V1,
        }
    }

    /// A watcher that defers a card is offered it again on a poll that finds
    /// the store unchanged, and is not offered it after it settles. Without
    /// the retry, a card refused once (dated ahead of this replica's clock)
    /// would stay refused until some unrelated write bumped the generation.
    #[test]
    fn a_deferred_rate_card_is_offered_again_on_each_poll_until_it_settles() {
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(b"secret"),
            KeySet::new(),
        )
        .unwrap();
        cp.put_rate_card(&rate_card("chain-a", "ahead")).unwrap();
        let offers = Arc::new(Mutex::new(0_u32));
        let seen = Arc::clone(&offers);
        cp.watch_rate_card("chain-a", move |_| {
            let mut offers = seen.lock().unwrap();
            *offers += 1;
            if *offers < 3 {
                RateCardDelivery::Deferred
            } else {
                RateCardDelivery::Settled
            }
        });
        assert_eq!(*offers.lock().unwrap(), 1, "offered once at registration");

        for expected in [2, 3, 3, 3] {
            assert!(!cp.poll_once().unwrap(), "the store did not change");
            assert_eq!(*offers.lock().unwrap(), expected);
        }
    }

    fn sorted_by_chain(mut cards: Vec<StoredRateCard>) -> Vec<StoredRateCard> {
        cards.sort_by(|a, b| a.chain.cmp(&b.chain));
        cards
    }

    #[test]
    fn a_rate_card_round_trips_and_a_second_put_for_the_same_chain_replaces_it() {
        let redb_store = RedbControlPlaneStore::in_memory();
        let inmemory_store = InMemoryControlPlaneStore::default();
        let stores: [&dyn ControlPlaneStore; 2] = [&redb_store, &inmemory_store];

        for store in stores {
            let first = rate_card("chain-a", "first");
            store.put_rate_card(&first).unwrap();
            assert_eq!(
                store.load().unwrap().rate_cards,
                vec![first.clone()],
                "put then load must return exactly the card that was written"
            );

            // Another chain is another row; the same chain replaces in place.
            store.put_rate_card(&rate_card("chain-b", "other")).unwrap();
            let second = rate_card("chain-a", "second");
            store.put_rate_card(&second).unwrap();

            let loaded = sorted_by_chain(store.load().unwrap().rate_cards);
            assert_eq!(
                loaded,
                vec![second, rate_card("chain-b", "other")],
                "a put for an existing chain must replace its card and leave the \
                 other chain's card alone"
            );
        }
    }

    #[test]
    fn a_rate_card_write_that_lands_bumps_the_generation_once_and_one_that_does_not_does_not() {
        let redb_store = RedbControlPlaneStore::in_memory();
        let inmemory_store = InMemoryControlPlaneStore::default();
        let stores: [&dyn ControlPlaneStore; 2] = [&redb_store, &inmemory_store];

        for store in stores {
            let base = store.policy_generation().unwrap();

            store.put_rate_card(&rate_card("chain-a", "one")).unwrap();
            assert_eq!(store.policy_generation().unwrap(), base + 1);

            // A byte-identical replacement bumps too: the trait forbids
            // read-before-write "did this change anything" checks.
            store.put_rate_card(&rate_card("chain-a", "one")).unwrap();
            assert_eq!(store.policy_generation().unwrap(), base + 2);

            // A seed that lands bumps once.
            assert_eq!(
                store.put_rate_card_if_absent(&rate_card("chain-b", "seed")),
                Ok(true)
            );
            assert_eq!(store.policy_generation().unwrap(), base + 3);

            // A seed that finds a card writes nothing, so nothing is bumped.
            assert_eq!(
                store.put_rate_card_if_absent(&rate_card("chain-b", "again")),
                Ok(false)
            );
            assert_eq!(
                store.policy_generation().unwrap(),
                base + 3,
                "a seed that wrote nothing must not move the stamp"
            );

            // The yardstick: a rate card write moves the stamp by exactly what
            // any other tier-2 write does.
            store
                .set_policy(&TenantId::new("tenant-a"), &ModelAccess::All)
                .unwrap();
            assert_eq!(store.policy_generation().unwrap(), base + 4);
        }
    }

    /// The restart case at the store level: the configured card seeds an
    /// empty store once, an operator publishes a replacement, and a later
    /// boot's seed must find the published card and leave it.
    #[test]
    fn seeding_never_overwrites_a_card_that_is_already_stored() {
        let redb_store = RedbControlPlaneStore::in_memory();
        let inmemory_store = InMemoryControlPlaneStore::default();
        let stores: [&dyn ControlPlaneStore; 2] = [&redb_store, &inmemory_store];

        for store in stores {
            let configured = rate_card("chain-a", "configured");
            assert_eq!(store.put_rate_card_if_absent(&configured), Ok(true));
            let published = rate_card("chain-a", "published");
            store.put_rate_card(&published).unwrap();

            assert_eq!(
                store.put_rate_card_if_absent(&configured),
                Ok(false),
                "the second boot's seed must report that a card was already there"
            );
            assert_eq!(
                store.load().unwrap().rate_cards,
                vec![published],
                "the published card must survive the later seed"
            );
        }
    }

    #[test]
    fn a_rate_card_write_leaves_every_other_kind_of_row_alone() {
        let redb_store = RedbControlPlaneStore::in_memory();
        let inmemory_store = InMemoryControlPlaneStore::default();
        let stores: [&dyn ControlPlaneStore; 2] = [&redb_store, &inmemory_store];

        for store in stores {
            store.put_rate_card(&rate_card("chain-a", "one")).unwrap();
            let loaded = store.load().unwrap();
            assert!(loaded.tenants.is_empty());
            assert!(loaded.keys.is_empty());
            assert!(loaded.policies.is_empty());
            assert!(loaded.budgets.is_empty());
            assert!(loaded.tenant_credentials.is_empty());

            // And the reverse: deleting a tenant does not touch a chain's card.
            store.delete_tenant(&TenantId::new("tenant-a")).unwrap();
            assert_eq!(store.load().unwrap().rate_cards.len(), 1);
        }
    }

    #[test]
    fn a_store_without_rate_card_support_refuses_the_write_and_does_not_claim_durability() {
        // `FailingStore` implements none of the rate card methods, so this
        // pins the trait defaults: a store that cannot hold a card says so
        // instead of accepting one it would lose.
        let store = FailingStore;
        assert!(matches!(
            store.put_rate_card(&rate_card("chain-a", "one")),
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            store.put_rate_card_if_absent(&rate_card("chain-a", "one")),
            Err(StoreError::Unavailable(_))
        ));
        assert!(!store.is_durable());
    }

    #[test]
    fn only_a_store_that_outlives_the_process_reports_durability() {
        assert!(!InMemoryControlPlaneStore::default().is_durable());

        let path = temp_db_path("durability-claim");
        assert!(RedbControlPlaneStore::open(&path).unwrap().is_durable());
        std::fs::remove_file(&path).ok();
    }

    /// redb is durable but private to one process, so durability must not
    /// stand in for sharing: `GET /v1/usage` would then read the store for a
    /// single replica, or (the default flipped) answer a fleet from one
    /// replica's counters. A store that does not say otherwise is local.
    #[test]
    fn only_a_store_other_replicas_write_through_reports_itself_shared() {
        assert!(!InMemoryControlPlaneStore::default().is_shared());
        assert!(!FailingStore.is_shared(), "the trait default is local");

        let path = temp_db_path("sharing-claim");
        let redb = RedbControlPlaneStore::open(&path).unwrap();
        assert!(redb.is_durable() && !redb.is_shared());
        drop(redb);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn redb_rate_cards_survive_closing_and_reopening_the_database_file() {
        let path = temp_db_path("rate-card-persists-across-reopen");
        let card = rate_card("chain-a", "one");

        {
            let store = RedbControlPlaneStore::open(&path).unwrap();
            store.put_rate_card(&card).unwrap();
        }

        let reopened = RedbControlPlaneStore::open(&path).unwrap();
        assert_eq!(reopened.load().unwrap().rate_cards, vec![card]);
        assert_eq!(
            reopened.policy_generation().unwrap(),
            1,
            "the bump that accompanied the card is durable too"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn redb_opens_a_database_file_created_before_the_rate_cards_table_existed() {
        let path = temp_db_path("pre-rate-cards-table");

        // Raw `redb`, not the store under test: every table the PREVIOUS code
        // opened and deliberately not `RATE_CARDS_TABLE`, so the file is what
        // an existing deployment's database looks like on first start after
        // this change.
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut tenants = txn.open_table(TENANTS_TABLE).unwrap();
                tenants.insert("tenant-a", [].as_slice()).unwrap();
            }
            txn.open_table(KEYS_TABLE).unwrap();
            txn.open_table(KEYS_BY_TENANT_TABLE).unwrap();
            txn.open_table(POLICIES_TABLE).unwrap();
            txn.open_table(BUDGETS_TABLE).unwrap();
            txn.open_table(TENANT_CREDENTIALS_TABLE).unwrap();
            txn.open_table(SPEND_TABLE).unwrap();
            txn.open_table(SPEND_SEQ_TABLE).unwrap();
            txn.open_table(GENERATION_TABLE).unwrap();
            txn.commit().unwrap();
        }

        let store = RedbControlPlaneStore::open(&path).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.tenants.len(), 1, "the existing rows must survive");
        assert!(loaded.rate_cards.is_empty());

        let card = rate_card("chain-a", "one");
        store.put_rate_card(&card).unwrap();
        assert_eq!(store.load().unwrap().rate_cards, vec![card]);

        std::fs::remove_file(&path).ok();
    }

    /// A rate card row this build cannot read must not fail the load: that
    /// would hold a key revocation hostage to a price list. It is skipped
    /// loudly instead, and the warning must not carry the row.
    #[test]
    fn redb_a_rate_card_row_this_build_cannot_read_is_skipped_and_logged_not_fatal() {
        let store = RedbControlPlaneStore::in_memory();
        let good = rate_card("chain-good", "good");
        store.put_rate_card(&good).unwrap();
        store
            .put_key(&StoredKey {
                key_id: KeyId::new("k1"),
                digest: [1; 32],
                tenant: TenantId::new("tenant-a"),
                revoked: true,
                tags: Default::default(),
            })
            .unwrap();

        // Written raw, bypassing `put_rate_card`: a hand-edited row, and the
        // shape of one a NEWER build would write (one past
        // `RATE_CARD_SCHEMA_VERSION`, which is 2).
        let future = br#"{"schema_version":3,"version":"v9","card":"FUTURE-CARD-CONTENT"}"#;
        {
            let txn = store.db.begin_write().unwrap();
            {
                let mut table = txn.open_table(RATE_CARDS_TABLE).unwrap();
                table
                    .insert("chain-garbage", b"GARBAGE-ROW-CONTENT".as_slice())
                    .unwrap();
                table.insert("chain-future", future.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }

        let (capture, guard) = log_capture::Capture::start();
        let loaded = store
            .load()
            .expect("an unreadable rate card must not fail the whole load");
        drop(guard);

        assert_eq!(
            loaded.rate_cards,
            vec![good],
            "only the readable card loads"
        );
        assert_eq!(
            loaded.keys.len(),
            1,
            "the rest of the control-plane state still loads"
        );

        let warnings = capture.rendered_at_or_above(tracing::Level::WARN);
        assert_eq!(
            warnings.len(),
            2,
            "one warning per unreadable row: {warnings:?}"
        );
        for chain in ["chain-garbage", "chain-future"] {
            assert!(
                warnings.iter().any(|line| line.contains(chain)),
                "the warning must name the chain {chain}: {warnings:?}"
            );
        }
        for line in &warnings {
            assert!(
                !line.contains("GARBAGE-ROW-CONTENT") && !line.contains("FUTURE-CARD-CONTENT"),
                "a warning must not render the row: {line}"
            );
        }
    }
}
