//! The token budget limiter, as a pure library.
//!
//! This module answers one question: **is the next request allowed against a
//! configured token budget, and if not, when will it be?** It does not touch
//! `HttpFilter`, config/IR, or response generation — those live in
//! `token_limit_filter`. This module is
//! the [`BudgetStore`] trait, its in-process implementation, and the types
//! around it.
//!
//! # The central semantic: retrospective enforcement, never mid-stream cutoff
//!
//! Token usage is not known until a response completes — [`crate::usage`]'s
//! extractors only produce a [`TokenUsage`] at the end of a (possibly
//! streaming) exchange. So this limiter is inherently *retrospective*: a
//! request is admitted against usage **already accumulated** from past
//! requests, and only once it finishes does its own cost get
//! [`BudgetStore::record`]ed against the budget. It follows that:
//!
//! - A request already in flight when its budget is exhausted by another,
//!   concurrent request is never affected — there is no mechanism here to cut
//!   off bytes already flowing to a client, and there must never be one.
//!   [`BudgetStore::record`] cannot fail or signal truncation; it only
//!   updates accounting for *future* [`BudgetStore::check`] calls.
//! - Over-limit means the *next* request is denied, not that the current one
//!   is truncated. Envoy AI Gateway's token-based rate limiting has the same
//!   shape, for the same reason.
//!
//! # Fixed window, not a leaky bucket
//!
//! Limits reset on a fixed window boundary rather than draining continuously.
//! This matches how providers publish `x-ratelimit-reset`-style semantics and
//! is far easier for an operator (or a client backing off) to reason about
//! than a continuously-draining bucket.
//!
//! # Cost weights
//!
//! Different models cost different amounts per token. Rather than complicate
//! `check` with a per-request price, the weight is applied once, at
//! [`BudgetStore::record`] time: a call with `weight: 2.0` consumes budget
//! twice as fast as one with `weight: 1.0` for the same [`TokenUsage`]. The
//! weighted count is rounded and saturated into a `u64` — see "Saturating
//! arithmetic" below.
//!
//! # Saturating arithmetic
//!
//! This is a billing path. A `u64` overflow here must be a can't-happen, not
//! a rare panic or (worse) a silent wraparound that resets a would-be-denied
//! customer's budget to near zero. Every arithmetic operation in this module
//! that combines usage, weights, or accumulated totals uses saturating (or
//! explicitly clamped) arithmetic.
//!
//! # `BudgetStore` is a seam, not a promise of two implementations today
//!
//! [`InProcessBudgetStore`] is the only implementation built so far
//! (and, by product decision, stays the *default* even once a remote one
//! exists): per-call rules, tracked per key,
//! shared by every worker in this process. The trait exists so a Redis-backed
//! (or otherwise control-plane-aggregated) store can land later behind the
//! same interface without callers changing — that store is explicitly **not**
//! built here. The rest of this section is about making that "later" actually
//! true rather than aspirational.
//!
//! # Making this distributed (the migration path, written down now)
//!
//! Each token call carries its current [`LimitRule`], so one store can serve
//! many policies and policy changes take effect on the next call. Request
//! counts use a separate, atomic [`BudgetStore::admit_request`] counter; stream
//! concurrency uses [`ConcurrencyLimiter`] and a drop-released [`StreamLease`].
//! A remote store needs network I/O, and [`BudgetStore::check`] /
//! [`BudgetStore::record`] are synchronous, `&self` methods — a remote
//! implementation cannot block a worker thread on a round trip inside them.
//! When that implementation lands, the filter calling this trait
//! (`crate::token_limit_filter`) will have to hold the stream with S2
//! `StopIteration` from `decode_headers` and resume via `continue_decoding()`
//! once the answer arrives — the same shape `ext_authz` / gRPC RLS
//! filters need for their own out-of-process calls. Three things fall
//! out of that:
//!
//! 1. **Fallibility has to exist from day one, not be retrofitted.**
//!    [`BudgetStore::check`] returns `Result<LimitDecision, BudgetUnavailable>`
//!    even though [`InProcessBudgetStore`] never produces the `Err` case —
//!    adding a failure channel after every call site already assumes
//!    infallibility would be both a breaking change and a security-relevant
//!    one (see the fail-open policy on [`BudgetUnavailable`] and in
//!    `token_limit_filter`'s module doc).
//! 2. **`record` stays infallible from the caller's perspective, but is only
//!    best-effort once a remote store exists.** The response path must never
//!    block on, or fail because of, budget bookkeeping — that would violate
//!    the central semantic above (never truncate/never fail an in-flight
//!    request over billing). A remote `record` is expected to queue or batch
//!    and to drop updates under backpressure rather than apply that
//!    consequence to the request. Callers must not treat a `record` call as
//!    a durability guarantee.
//! 3. **`now: Instant` is a known limitation of the seam, not a solved
//!    problem.** It is process-local monotonic time — authoritative for
//!    [`InProcessBudgetStore`], meaningless to compare across processes, and
//!    not transmissible over a wire. A remote store is its own time
//!    authority and may ignore the parameter entirely (using its own clock
//!    to decide window rollover instead). This is not redesigned here — that
//!    is a bigger refactor than warranted — but it is named
//!    rather than left to be rediscovered when the remote implementation
//!    lands.
//!
//! Finally: to keep that future swap contained to one place, callers isolate
//! the store call to exactly one function rather than calling `check` inline
//! from `decode_headers` — see `token_limit_filter`'s module doc.
//!
//! # Fail open, not fail closed
//!
//! See [`BudgetUnavailable`] for the policy `token_limit_filter` applies when
//! [`BudgetStore::check`] returns `Err`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::usage::TokenUsage;

/// The identity a budget is tracked against: which route, and who the budget
/// belongs to (see [`LimitSubject`]).
///
/// Previously this was a flattened, opaque `String` built by
/// `from_descriptors(&[("route", ..), ("tenant", ..)])` -- enough for
/// [`InProcessBudgetStore`]'s `Mutex<HashMap<LimitKey, Window>>` to compare
/// keys, but with no way back out to "which route" or "which tenant" short of
/// parsing a separator format that existed only by accident. The
/// per-tenant usage query needs exactly that (enumerating a tenant's keys
/// across routes), so this is now a struct with named fields -- The struct also does something
/// the flattened string could not: it makes "a credential was hashed before
/// it became part of a key" a property [`LimitSubject::Credential`] enforces
/// by only ever holding a [`CredentialDigest`], not a comment resting on every
/// call site remembering to hash first.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LimitKey {
    route: String,
    subject: LimitSubject,
}

/// Who a [`LimitKey`]'s budget belongs to. The two variants are two disjoint
/// key spaces -- previously that separation was enforced only by the
/// descriptor NAME differing (`tenant=` vs `cred=`) inside one flattened
/// string; as an enum it is enforced by the type. See
/// `token_limit_filter`'s module doc ("The two key spaces never overlap")
/// for why that separation is a security property, not a preference.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LimitSubject {
    /// An identity the proxy itself assigned (virtual keys).
    Tenant(String),
    /// No auth filter authenticated the stream, so the bucket is keyed on a
    /// digest of the credential the caller presented. See
    /// [`CredentialDigest`] -- a digest is the only thing this variant can
    /// hold; there is no way to construct it from a raw, unhashed value.
    Credential(CredentialDigest),
    /// The one bucket per route that unauthenticated credentials share once
    /// [`MAX_CREDENTIAL_WINDOWS`] distinct ones already hold a window. See
    /// [`InProcessBudgetStore`]'s "Bounded" section.
    CredentialOverflow,
}

impl LimitKey {
    /// Build a key for an identity the proxy itself assigned -- see
    /// [`LimitSubject::Tenant`].
    pub fn for_tenant(route: &str, tenant: &str) -> Self {
        LimitKey {
            route: route.to_string(),
            subject: LimitSubject::Tenant(tenant.to_string()),
        }
    }

    /// Build a key for the fallback path: no authenticated tenant, so the
    /// bucket is keyed on a digest of the credential the caller presented.
    /// Takes the RAW credential and hashes it internally -- unlike the old
    /// `from_descriptors(&[("cred", hash_credential(..))])` shape, the call
    /// site cannot forget to hash before constructing the key. See
    /// [`CredentialDigest::hash`].
    pub fn for_credential(route: &str, raw_credential: &str) -> Self {
        LimitKey {
            route: route.to_string(),
            subject: LimitSubject::Credential(CredentialDigest::hash(raw_credential)),
        }
    }

    /// The route name this key was bucketed under.
    pub fn route(&self) -> &str {
        &self.route
    }

    /// Who this key's budget belongs to.
    pub fn subject(&self) -> &LimitSubject {
        &self.subject
    }

    /// Whether this key is a [`LimitSubject::Tenant`] matching `tenant`
    /// exactly -- the shape the per-tenant usage query needs
    /// (enumerating every key belonging to one tenant, across routes)
    /// without building that query here.
    pub fn is_for_tenant(&self, tenant: &str) -> bool {
        matches!(&self.subject, LimitSubject::Tenant(t) if t == tenant)
    }
}

impl std::fmt::Display for LimitKey {
    /// Renders `route=<route>|tenant=<id>` or `route=<route>|cred=<hex
    /// digest>` -- unchanged from the pre-struct flattened-string rendering,
    /// because log lines and at least one test assert on this exact shape.
    /// Safe to log in both cases: a tenant id is an identifier the operator
    /// chose, not a secret, and [`LimitSubject::Credential`] can only ever
    /// hold an already-hashed [`CredentialDigest`] -- see that type's doc.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "route={}|", self.route)?;
        match &self.subject {
            LimitSubject::Tenant(tenant) => write!(f, "tenant={tenant}"),
            LimitSubject::Credential(digest) => write!(f, "cred={digest}"),
            LimitSubject::CredentialOverflow => f.write_str("cred=overflow"),
        }
    }
}

/// A hashed credential. Constructible ONLY by hashing -- there is no
/// `From<String>`, no public tuple constructor, and no `new` that accepts an
/// unhashed value, so a raw credential cannot become a
/// [`LimitSubject::Credential`] without going through [`Self::hash`] first.
/// That is the type-level version of what used to be a comment on
/// `token_limit_filter::hash_credential` (moved here as [`Self::hash`], see
/// its doc for the FNV-1a reasoning, carried forward unchanged).
///
/// `Debug` is derived rather than hand-rolled: it prints the hex digest, not
/// anything a raw credential could be recovered from, since a `CredentialDigest`
/// never holds anything but a digest to begin with.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialDigest(String);

impl CredentialDigest {
    /// A stable, non-cryptographic hash of a raw credential value, rendered
    /// as hex.
    ///
    /// This is not a security control against an attacker who already has the
    /// credential value — that isn't the threat model, and the value becomes
    /// neither more nor less usable for auth by being hashed. It exists so the
    /// credential never appears in cleartext anywhere a [`LimitKey`] could end
    /// up: a debug log, a metrics label, a future `%DYNAMIC_METADATA%`-style
    /// access-log field.
    ///
    /// # Why FNV-1a rather than `std`'s `DefaultHasher`
    ///
    /// `DefaultHasher` would be the obvious zero-dependency choice, and it is
    /// what this function used first. It is wrong here for one reason: `std`
    /// explicitly does **not** guarantee its algorithm is stable across Rust
    /// releases. That is harmless while every key is computed and compared
    /// inside one process — but this store sits behind [`BudgetStore`],
    /// whose entire purpose is to let a distributed (Redis/RLS) backend land
    /// later. The moment a budget is shared, two proxies built against
    /// different toolchains would hash the same credential to different keys
    /// and each be handed a full budget — a quota silently multiplied by the
    /// fleet size, which is the exact failure the shared store was chosen to
    /// avoid in the first place.
    ///
    /// FNV-1a 64 is a frozen, published specification: same input, same
    /// output, forever, on any machine and any compiler. It costs about eight
    /// lines and no new crate — relevant because this workspace's dependency
    /// tree is already slated for review. Collision resistance is irrelevant
    /// here; stability is the requirement, and it is the one `DefaultHasher`
    /// does not offer.
    pub fn hash(raw: &str) -> Self {
        // FNV-1a, 64-bit. Rust note: `wrapping_mul` is the defined behavior of
        // the algorithm (it is specified modulo 2^64), not a guard against a
        // bug -- a plain `*` would panic on overflow in debug builds on the
        // first byte.
        const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

        let mut hash = FNV_OFFSET_BASIS;
        for byte in raw.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        CredentialDigest(format!("{hash:016x}"))
    }
}

impl std::fmt::Display for CredentialDigest {
    /// Renders the hex digest -- safe to log; see [`Self::hash`]'s doc for
    /// why this is FNV-1a rather than a reversible encoding.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which bucket of [`TokenUsage`] a [`LimitRule`] is measured against.
///
/// `Total` is not simply "the sum of `Input` and `Output`" as a matter of
/// convenience — it is defined, deliberately, as [`TokenUsage::total`], which
/// includes the cached and cache-creation buckets too. Those buckets are
/// priced differently from plain input/output but still consume the same
/// per-key budget; a limiter that dropped them from `Total` would let a
/// heavy-cache workload evade the cap it was supposed to enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitOn {
    /// [`TokenUsage::input_tokens`] only (excludes cached/cache-creation).
    Input,
    /// [`TokenUsage::output_tokens`] only.
    Output,
    /// [`TokenUsage::total`] — every bucket.
    Total,
}

/// One configured budget: how many (weighted) tokens are allowed on a given
/// [`LimitOn`] bucket per fixed [`window`](Self::window).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitRule {
    pub on: LimitOn,
    pub max_tokens: u64,
    pub window: Duration,
}

/// A fixed-window request-count cap, separate from token accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimit {
    pub max_requests: u64,
    pub window: Duration,
}

/// The outcome of a [`BudgetStore::check`] call.
///
/// Both variants carry the same "how does this look to the caller" shape a
/// provider-style rate limiter publishes (`limit` / `remaining` /
/// `reset_after`), plus `retry_after` on `Deny` — the HTTP header mapping lives in the filter, and the fields are named to make that
/// mapping mechanical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitDecision {
    Allow {
        limit: u64,
        remaining: u64,
        reset_after: Duration,
    },
    Deny {
        limit: u64,
        remaining: u64,
        reset_after: Duration,
        retry_after: Duration,
    },
}

/// A [`BudgetStore::check`] call could not reach the budget authority (a
/// remote store's timeout, connection failure, etc.). [`InProcessBudgetStore`]
/// never produces this — it has no I/O to fail — but the type exists on the
/// trait from the start so callers (`crate::token_limit_filter`) have a real
/// error channel to design around, not one bolted on after every call site
/// already assumed infallibility.
///
/// **Policy: fail open.** `token_limit_filter` treats `Err` as "admit the
/// request" — matching Envoy's rate-limit filter default
/// (`failure_mode_deny: false`) — rather than rejecting or 500ing every
/// request while the budget backend blips. Fail-closed is real, defensible
/// behavior for some deployments, but it is not the default here and does not
/// exist yet as an option; it belongs behind a future config knob, not a
/// silent hardcoded choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BudgetUnavailable;

impl std::fmt::Display for BudgetUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "budget store unavailable")
    }
}

impl std::error::Error for BudgetUnavailable {}

/// Admission for simultaneous streams. A shared backend needs expiring
/// leases so a crashed process cannot leak slots forever.
pub trait ConcurrencyLimiter: Send + Sync {
    fn try_acquire(
        &self,
        key: &LimitKey,
        max_streams: u32,
    ) -> Result<Result<StreamLease, LimitDecision>, BudgetUnavailable>;
}

/// Releases one admitted stream when dropped. The release handle remains
/// independent of a held lock while the stream is alive.
pub struct StreamLease {
    release: Arc<dyn LeaseRelease>,
    key: LimitKey,
}

/// Backend hook invoked exactly once when an admitted stream ends.
pub trait LeaseRelease: Send + Sync {
    fn release(&self, key: &LimitKey);
}

impl StreamLease {
    /// Build a lease from a backend release hook without holding its lock.
    pub fn new(key: LimitKey, release: Arc<dyn LeaseRelease>) -> Self {
        Self { release, key }
    }
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        self.release.release(&self.key);
    }
}

#[derive(Default)]
struct StreamCounts {
    by_key: HashMap<LimitKey, u32>,
    credential_entries: usize,
    overflow_warned: bool,
}

#[derive(Default)]
pub struct InProcessConcurrencyLimiter {
    counts: Arc<Mutex<StreamCounts>>,
}

struct InProcessLeaseRelease(Arc<Mutex<StreamCounts>>);

impl LeaseRelease for InProcessLeaseRelease {
    fn release(&self, key: &LimitKey) {
        // Runs from `StreamLease::drop`, possibly while a panic is already
        // unwinding; a second panic there aborts the process, so recover the
        // counts from a poisoned lock instead of unwrapping.
        let mut counts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.by_key.get_mut(key) {
            *count -= 1;
            if *count == 0 {
                counts.by_key.remove(key);
                if matches!(key.subject, LimitSubject::Credential(_)) {
                    counts.credential_entries -= 1;
                }
            }
        }
    }
}

impl InProcessConcurrencyLimiter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ConcurrencyLimiter for InProcessConcurrencyLimiter {
    fn try_acquire(
        &self,
        key: &LimitKey,
        max_streams: u32,
    ) -> Result<Result<StreamLease, LimitDecision>, BudgetUnavailable> {
        const RETRY_HINT: Duration = Duration::from_secs(1);
        let mut counts = self.counts.lock().unwrap();
        let new_credential =
            matches!(key.subject, LimitSubject::Credential(_)) && !counts.by_key.contains_key(key);
        let overflow = new_credential && counts.credential_entries >= MAX_CREDENTIAL_WINDOWS;
        let first_fold = overflow && !std::mem::replace(&mut counts.overflow_warned, true);
        let key = if overflow {
            LimitKey {
                route: key.route.clone(),
                subject: LimitSubject::CredentialOverflow,
            }
        } else {
            key.clone()
        };
        let current = counts.by_key.get(&key).copied().unwrap_or(0);
        let outcome = if current >= max_streams {
            Err(LimitDecision::Deny {
                limit: u64::from(max_streams),
                remaining: 0,
                reset_after: RETRY_HINT,
                retry_after: RETRY_HINT,
            })
        } else {
            if current == 0 && matches!(key.subject, LimitSubject::Credential(_)) {
                counts.credential_entries += 1;
            }
            counts.by_key.insert(key.clone(), current + 1);
            Ok(StreamLease::new(
                key,
                Arc::new(InProcessLeaseRelease(Arc::clone(&self.counts))),
            ))
        };
        drop(counts);
        if first_fold {
            tracing::warn!(max_credential_windows = MAX_CREDENTIAL_WINDOWS,
                "llmproxy.token_limit: concurrent stream credential cap is full; further credentials share an overflow counter per route");
        }
        Ok(outcome)
    }
}

/// One [`LimitKey`]'s current-window standing, shaped for the `GET
/// /v1/usage` endpoint — see [`BudgetStore::usage_for_tenant`].
///
/// This is a read-only *rendering* of the same numbers [`LimitDecision::Allow`]
/// already carries; it deliberately does NOT hold a [`LimitKey`] or anything
/// built from one — `token_limit_filter`'s usage endpoint renders this
/// straight into a JSON response body, and the module doc's rule ("never
/// echo a `LimitKey`... into the response body") is easiest to keep if the
/// type handed to that response can't violate it in the first place.
#[derive(Debug, Clone, PartialEq)]
pub struct TenantUsage {
    /// The route this budget is bucketed under — see [`LimitKey::route`].
    /// Safe to expose: a route name is operator-chosen config, not a secret.
    pub route: String,
    /// Weighted tokens consumed in the current window.
    pub used: f64,
    /// The configured cap for this window.
    pub limit: f64,
    /// `limit - used`, floored at zero — never negative, matching
    /// [`LimitDecision`]'s own `remaining` fields.
    pub remaining: f64,
    /// How long until the current window rolls over.
    pub reset_after: Duration,
}

/// Seam for a token-budget backend. See the module docs (in particular
/// "Making this distributed") for why the trait is shaped this way ahead of
/// a second implementation.
///
/// Rust note: methods take `&self`, not `&mut self`. That is what lets a
/// single store be shared across concurrently-in-flight requests without the
/// caller juggling exclusive borrows; interior mutability (see
/// [`InProcessBudgetStore`]) does the actual mutating.
///
/// `Send + Sync`: unlike the worker-local `!Send` data-plane types (ADR-0003),
/// a budget is inherently cross-stream and, in this process, cross-worker —
/// see [`InProcessBudgetStore`]'s doc for why. Filter config-time plumbing
/// (`FilterInstanceFactory` etc.) is `Send + Sync` and shared via `Arc` across
/// every worker, so a `dyn BudgetStore` living there must be too.
pub trait BudgetStore: Send + Sync {
    /// Does `key` currently have room under the caller's rule? It may
    /// remember the rule for reporting, but must not consume tokens —
    /// calling this any number of times with no intervening
    /// [`record`](Self::record) must return the same answer (modulo
    /// wall-clock window rollover, which is why `now` is a parameter rather
    /// than read internally).
    ///
    /// `now` is process-local monotonic time: authoritative for
    /// [`InProcessBudgetStore`], but a known limitation of this seam for
    /// anything else — a remote store is its own time authority and may
    /// ignore it, using its own clock for window rollover instead. See the
    /// module doc's "Making this distributed" section.
    ///
    /// Returns `Err(BudgetUnavailable)` if the budget authority could not be
    /// reached — [`InProcessBudgetStore`] never does this — see
    /// [`BudgetUnavailable`] for the fail-open policy callers apply.
    fn check(
        &self,
        key: &LimitKey,
        rule: &LimitRule,
        now: Instant,
    ) -> Result<LimitDecision, BudgetUnavailable>;

    /// Record that `usage` (scaled by `weight`) actually happened against
    /// `key`. Infallible from the caller's side — see the module docs'
    /// central semantic: the response path must never block on, or fail
    /// because of, budget bookkeeping. For [`InProcessBudgetStore`] this is
    /// also durable. It is NOT guaranteed to be durable in general: a remote
    /// implementation is expected to queue/batch and may drop updates under
    /// backpressure rather than propagate that failure here — treat this as
    /// best-effort, not a commit.
    fn record(
        &self,
        key: &LimitKey,
        rule: &LimitRule,
        usage: &TokenUsage,
        weight: f64,
        now: Instant,
    );

    /// Atomically admit and count one request, or deny without counting it.
    /// Request windows do not share token-window state.
    fn admit_request(
        &self,
        key: &LimitKey,
        limit: &RequestLimit,
        now: Instant,
    ) -> Result<LimitDecision, BudgetUnavailable>;

    /// Every current-window budget belonging to `tenant`, across all routes
    /// — the query `GET /v1/usage` needs and neither `check` nor
    /// `record` can answer alone (both take a single, already-known
    /// [`LimitKey`]; this instead enumerates every key for one tenant).
    ///
    /// **This does NOT fail open.** Admission errors fail open in the filter
    /// (see [`BudgetUnavailable`]) because the alternative —
    /// refusing real LLM traffic over a metering hiccup — is worse. That
    /// reasoning inverts here: this is a read-only reporting endpoint with no
    /// traffic riding on it, so there is nothing an `Err` here could be
    /// worse than, and a usage number that is silently wrong (rather than
    /// visibly absent) is the actual hazard for a caller deciding whether to
    /// keep spending against a budget it can no longer see. Callers (see
    /// `token_limit_filter`'s usage-endpoint handler) turn `Err` into a 503,
    /// not a 200 with stale or empty numbers.
    ///
    /// Ordering is intentionally unspecified by this signature — see
    /// [`InProcessBudgetStore`]'s implementation for why the concrete
    /// ordering it commits to (by route name) is a property of that
    /// implementation, not a guarantee every `BudgetStore` must provide.
    fn usage_for_tenant(
        &self,
        tenant: &str,
        now: Instant,
    ) -> Result<Vec<TenantUsage>, BudgetUnavailable>;
}

/// One key's current fixed window: when it started, and how many (weighted)
/// tokens have been recorded in it so far.
#[derive(Debug, Clone, Copy)]
struct Window {
    started_at: Instant,
    used: u64,
    rule: LimitRule,
}

/// The only [`BudgetStore`] implementation (and, by
/// product decision, the deployment default even once a remote one exists): per-call [`LimitRule`]s, tracked per
/// [`LimitKey`], shared by every worker in this process.
///
/// Rust note: interior mutability here is a `Mutex`, not a `RefCell` — and
/// an earlier version chose `RefCell` by citing
/// ADR-0003's worker-local `!Send` data plane. That reasoning is correct for
/// *per-stream* state (a filter instance, `StreamInfo`, ...), which really
/// does live and die on one worker's thread. It is wrong for a budget: a
/// token cap is meaningful per *key* (an API credential, a route) across the
/// whole process, not per worker. `FilterInstanceFactory` is `Send + Sync`
/// and shared via one `Arc` across every worker (see `listener.rs`'s shared
/// `FilterRegistry`), so a store living there is inherently reached from
/// multiple threads. A `thread_local!`-sharded alternative (one store per
/// worker) was considered and rejected: with N workers a configured limit of
/// X would become an effective limit of N·X, silently — a quota feature that
/// is wrong by the worker count is worse than no quota feature at all.
/// `Mutex` costs one lock acquisition per `check` and one per `record` — once
/// per *request*, not per byte streamed — so it is not a hot-path concern for
/// this filter (see `token_limit_filter`'s module doc on where in the
/// request lifecycle those calls happen).
pub struct InProcessBudgetStore {
    windows: Mutex<Windows>,
    request_windows: Mutex<RequestWindows>,
}

/// Every key's window, plus when the next sweep for expired ones is due.
///
/// # Expired windows are evicted
///
/// A window whose time has run out reads exactly like no window at all (see
/// [`InProcessBudgetStore::used_in_current_window`]), so dropping it changes
/// no answer. Without dropping, the map kept one entry for every key that
/// ever recorded usage, for the life of the process (review M8). `record`
/// sweeps at most once per window length, so a sweep's O(n) cost is paid
/// once per window, not per request, and an expired entry is gone within
/// two window lengths of its last record.
///
/// # Bounded: credential-keyed windows are capped
///
/// Expiry alone does not bound the map against a caller: without an auth
/// filter the key is a digest of the `authorization` header, which the caller
/// chooses, so every invented header that records usage adds a window that
/// lives a full window length (review M8). At most
/// [`MAX_CREDENTIAL_WINDOWS`] credential windows exist at once; a credential
/// with no window of its own arriving after that draws on one shared
/// [`LimitSubject::CredentialOverflow`] bucket per route, for `check` and
/// `record` alike, so it is still limited, just not on its own. The first
/// fold logs one warning per store, naming no credential (AGENTS.md
/// "Fail-open controls"). Tenant windows are not capped: the proxy assigns
/// tenants, so a caller cannot invent them.
#[derive(Default)]
struct Windows {
    by_key: HashMap<LimitKey, Window>,
    /// `None` until the first `record`.
    next_sweep: Option<Instant>,
    /// How many keys in `by_key` are [`LimitSubject::Credential`].
    credential_windows: usize,
    /// Set by the first fold into an overflow bucket.
    overflow_warned: bool,
}

/// The most [`LimitSubject::Credential`] windows one store holds at once. A
/// window is a few hundred bytes, so this bounds the credential side of the
/// map to a few megabytes.
pub const MAX_CREDENTIAL_WINDOWS: usize = 10_000;

impl Windows {
    /// The key `key`'s usage is counted under: `key` itself, or the route's
    /// overflow bucket for a credential with no window once the cap is full.
    fn bounded(&self, key: &LimitKey) -> Option<LimitKey> {
        let new_credential =
            matches!(key.subject, LimitSubject::Credential(_)) && !self.by_key.contains_key(key);
        (new_credential && self.credential_windows >= MAX_CREDENTIAL_WINDOWS).then(|| LimitKey {
            route: key.route.clone(),
            subject: LimitSubject::CredentialOverflow,
        })
    }
}

struct RequestWindow {
    started_at: Instant,
    used: u64,
    limit: RequestLimit,
}

#[derive(Default)]
struct RequestWindows {
    by_key: HashMap<LimitKey, RequestWindow>,
    next_sweep: Option<Instant>,
    credential_windows: usize,
    overflow_warned: bool,
}

impl RequestWindows {
    fn bounded(&self, key: &LimitKey) -> Option<LimitKey> {
        let new_credential =
            matches!(key.subject, LimitSubject::Credential(_)) && !self.by_key.contains_key(key);
        (new_credential && self.credential_windows >= MAX_CREDENTIAL_WINDOWS).then(|| LimitKey {
            route: key.route.clone(),
            subject: LimitSubject::CredentialOverflow,
        })
    }
}

impl InProcessBudgetStore {
    pub fn new() -> Self {
        Self {
            windows: Mutex::new(Windows::default()),
            request_windows: Mutex::new(RequestWindows::default()),
        }
    }

    /// How many windows are held, expired or not.
    #[cfg(test)]
    pub(crate) fn tracked_windows(&self) -> usize {
        self.windows.lock().unwrap().by_key.len()
    }

    /// The bucket of `usage` the passed rule cares about, per
    /// [`LimitOn`]'s doc comment.
    fn bucket(rule: &LimitRule, usage: &TokenUsage) -> u64 {
        match rule.on {
            LimitOn::Input => usage.input_tokens,
            LimitOn::Output => usage.output_tokens,
            LimitOn::Total => usage.total(),
        }
    }

    /// The `used` count for `key`'s *current* window as of `now`, treating a
    /// window that has rolled past (or never existed) as freshly reset — but
    /// without consuming tokens. The check remembers the current rule for
    /// usage reporting, while `record` owns count changes.
    fn used_in_current_window(
        &self,
        key: &LimitKey,
        rule: &LimitRule,
        now: Instant,
    ) -> (u64, Duration) {
        // Rust note: `.lock().unwrap()` -- a poisoned mutex here would mean
        // some other call panicked while holding the lock, which never
        // happens in this function (no panicking code runs between lock and
        // unlock), so this can't actually fire; `sink.rs`'s `FileSink` makes
        // the same choice for the same reason.
        let mut windows = self.windows.lock().unwrap();
        let overflow = windows.bounded(key);
        match windows.by_key.get_mut(overflow.as_ref().unwrap_or(key)) {
            Some(w) => {
                // The caller's current policy wins immediately, including its
                // window length for rollover; previously counted usage stays.
                w.rule = *rule;
                let elapsed = now.saturating_duration_since(w.started_at);
                if elapsed >= rule.window {
                    // The window has rolled; a fresh one starts at `now`, so
                    // the full window remains until the next reset.
                    (0, rule.window)
                } else {
                    (w.used, rule.window - elapsed)
                }
            }
            None => (0, rule.window),
        }
    }
}

impl Default for InProcessBudgetStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BudgetStore for InProcessBudgetStore {
    fn check(
        &self,
        key: &LimitKey,
        rule: &LimitRule,
        now: Instant,
    ) -> Result<LimitDecision, BudgetUnavailable> {
        let (used, reset_after) = self.used_in_current_window(key, rule, now);
        let limit = rule.max_tokens;
        let remaining = limit.saturating_sub(used);
        if used < limit {
            Ok(LimitDecision::Allow {
                limit,
                remaining,
                reset_after,
            })
        } else {
            Ok(LimitDecision::Deny {
                limit,
                remaining,
                reset_after,
                retry_after: reset_after,
            })
        }
    }

    fn record(
        &self,
        key: &LimitKey,
        rule: &LimitRule,
        usage: &TokenUsage,
        weight: f64,
        now: Instant,
    ) {
        // Rust note: `f64::round` then saturating-cast via `as u64` — `as` on
        // a float-to-int in Rust is itself a saturating conversion (NaN -> 0,
        // out-of-range -> the type's min/max), which is exactly the "never
        // panic, never wrap" behavior this billing path requires even for a
        // pathological weight (e.g. `f64::MAX` or `f64::INFINITY`).
        let raw = Self::bucket(rule, usage);
        let weighted = (raw as f64 * weight).round();
        let weighted_tokens = if weighted.is_sign_negative() {
            0
        } else {
            weighted as u64
        };

        let mut guard = self.windows.lock().unwrap();
        let windows = &mut *guard;
        if windows.next_sweep.is_none_or(|due| now >= due) {
            let mut credentials_dropped = 0;
            windows.by_key.retain(|window_key, w| {
                let current = window_key == key
                    || (matches!(key.subject, LimitSubject::Credential(_))
                        && matches!(window_key.subject, LimitSubject::CredentialOverflow)
                        && window_key.route == key.route);
                let length = if current { rule.window } else { w.rule.window };
                let live = now.saturating_duration_since(w.started_at) < length;
                if !live && matches!(window_key.subject, LimitSubject::Credential(_)) {
                    credentials_dropped += 1;
                }
                live
            });
            windows.credential_windows -= credentials_dropped;
            windows.next_sweep = now.checked_add(rule.window);
        }
        if let Some(due) = now.checked_add(rule.window) {
            windows.next_sweep = Some(windows.next_sweep.map_or(due, |old| old.min(due)));
        }
        let overflow = windows.bounded(key);
        let first_fold =
            overflow.is_some() && !std::mem::replace(&mut windows.overflow_warned, true);
        let key = match overflow {
            Some(overflow) => overflow,
            None => key.clone(),
        };
        if matches!(key.subject, LimitSubject::Credential(_)) && !windows.by_key.contains_key(&key)
        {
            windows.credential_windows += 1;
        }
        let window = windows.by_key.entry(key).or_insert(Window {
            started_at: now,
            used: 0,
            rule: *rule,
        });
        let elapsed = now.saturating_duration_since(window.started_at);
        if elapsed >= rule.window {
            // The window rolled since we last saw this key; this record
            // starts a fresh one rather than adding onto a stale total.
            window.started_at = now;
            window.used = weighted_tokens;
        } else {
            window.used = window.used.saturating_add(weighted_tokens);
        }
        window.rule = *rule;
        drop(guard);
        if first_fold {
            tracing::warn!(
                max_credential_windows = MAX_CREDENTIAL_WINDOWS,
                "llmproxy.token_limit: the per-credential budget cap is full; further \
                 unauthenticated credentials share one overflow budget per route until \
                 windows expire. Configure llmproxy.auth to budget per tenant instead"
            );
        }
    }

    fn admit_request(
        &self,
        key: &LimitKey,
        limit: &RequestLimit,
        now: Instant,
    ) -> Result<LimitDecision, BudgetUnavailable> {
        let mut windows = self.request_windows.lock().unwrap();
        if windows.next_sweep.is_none_or(|due| now >= due) {
            let mut credentials_dropped = 0;
            windows.by_key.retain(|window_key, w| {
                let current = window_key == key
                    || (matches!(key.subject, LimitSubject::Credential(_))
                        && matches!(window_key.subject, LimitSubject::CredentialOverflow)
                        && window_key.route == key.route);
                let length = if current {
                    limit.window
                } else {
                    w.limit.window
                };
                let live = now.saturating_duration_since(w.started_at) < length;
                if !live && matches!(window_key.subject, LimitSubject::Credential(_)) {
                    credentials_dropped += 1;
                }
                live
            });
            windows.credential_windows -= credentials_dropped;
            windows.next_sweep = now.checked_add(limit.window);
        }
        if let Some(due) = now.checked_add(limit.window) {
            windows.next_sweep = Some(windows.next_sweep.map_or(due, |old| old.min(due)));
        }
        let overflow = windows.bounded(key);
        let first_fold =
            overflow.is_some() && !std::mem::replace(&mut windows.overflow_warned, true);
        let key = overflow.unwrap_or_else(|| key.clone());
        if matches!(key.subject, LimitSubject::Credential(_)) && !windows.by_key.contains_key(&key)
        {
            windows.credential_windows += 1;
        }
        let window = windows.by_key.entry(key).or_insert(RequestWindow {
            started_at: now,
            used: 0,
            limit: *limit,
        });
        let elapsed = now.saturating_duration_since(window.started_at);
        if elapsed >= limit.window {
            window.started_at = now;
            window.used = 0;
        }
        window.limit = *limit;
        let reset_after = limit
            .window
            .saturating_sub(now.saturating_duration_since(window.started_at));
        let decision = if window.used < limit.max_requests {
            window.used += 1;
            LimitDecision::Allow {
                limit: limit.max_requests,
                remaining: limit.max_requests - window.used,
                reset_after,
            }
        } else {
            LimitDecision::Deny {
                limit: limit.max_requests,
                remaining: 0,
                reset_after,
                retry_after: reset_after,
            }
        };
        drop(windows);
        if first_fold {
            tracing::warn!(max_credential_windows = MAX_CREDENTIAL_WINDOWS,
                "llmproxy.token_limit: request counter credential cap is full; further credentials share an overflow counter per route");
        }
        Ok(decision)
    }

    /// Sorted by [`LimitKey::route`] — see the trait method's doc for why
    /// ordering is this implementation's commitment, not the trait's. A
    /// `Vec` this is built from has no inherent order (it's collected out of
    /// a `HashMap`), so an unsorted result would make `GET /v1/usage`'s
    /// response body nondeterministic across otherwise-identical requests,
    /// which is both hard to test and a bad experience for anything that
    /// diffs the response.
    fn usage_for_tenant(
        &self,
        tenant: &str,
        now: Instant,
    ) -> Result<Vec<TenantUsage>, BudgetUnavailable> {
        let windows = self.windows.lock().unwrap();
        let mut usages: Vec<TenantUsage> = windows
            .by_key
            .iter()
            .filter(|(key, _)| key.is_for_tenant(tenant))
            .map(|(key, window)| {
                let limit = window.rule.max_tokens;
                let elapsed = now.saturating_duration_since(window.started_at);
                let (used, reset_after) = if elapsed >= window.rule.window {
                    (0, window.rule.window)
                } else {
                    (window.used, window.rule.window - elapsed)
                };
                TenantUsage {
                    route: key.route().to_string(),
                    used: used as f64,
                    limit: limit as f64,
                    remaining: limit.saturating_sub(used) as f64,
                    reset_after,
                }
            })
            .collect();
        // Rust note: `sort_by` (not `sort_by_key`) because `TenantUsage`
        // doesn't implement `Ord`/borrow a comparable key by reference
        // without cloning; comparing `&str` slices directly avoids an
        // allocation per comparison.
        usages.sort_by(|a, b| a.route.cmp(&b.route));
        Ok(usages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(input: u64, output: u64) -> TokenUsage {
        TokenUsage {
            input_tokens: input,
            output_tokens: output,
            ..Default::default()
        }
    }

    fn rule(on: LimitOn, max_tokens: u64, window: Duration) -> LimitRule {
        LimitRule {
            on,
            max_tokens,
            window,
        }
    }

    // ---- exact 429 onset ---------------------------------------------------

    /// A scripted sequence of ten-token responses against a 25-token budget:
    /// `remaining` must land on exact values, and `Deny` must first appear at
    /// the exact request index this pins (request 4, the third that would
    /// push cumulative usage past 25).
    #[test]
    fn exact_429_onset_and_remaining_track_scripted_usage() {
        let rule = rule(LimitOn::Total, 25, Duration::from_secs(60));
        let store = InProcessBudgetStore::new();
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        // Request 1: check (25 remaining), record 10 -> used 10.
        assert_eq!(
            store.check(&key, &rule, now).unwrap(),
            LimitDecision::Allow {
                limit: 25,
                remaining: 25,
                reset_after: Duration::from_secs(60),
            }
        );
        store.record(&key, &rule, &usage(6, 4), 1.0, now);

        // Request 2: check (15 remaining), record 10 -> used 20.
        assert_eq!(
            store.check(&key, &rule, now).unwrap(),
            LimitDecision::Allow {
                limit: 25,
                remaining: 15,
                reset_after: Duration::from_secs(60),
            }
        );
        store.record(&key, &rule, &usage(6, 4), 1.0, now);

        // Request 3: check (5 remaining) -- still allowed, used(20) < limit(25).
        assert_eq!(
            store.check(&key, &rule, now).unwrap(),
            LimitDecision::Allow {
                limit: 25,
                remaining: 5,
                reset_after: Duration::from_secs(60),
            }
        );
        store.record(&key, &rule, &usage(6, 4), 1.0, now);
        // Cumulative used is now 30, past the 25-token budget.

        // Request 4: THIS is the exact onset -- the first Deny.
        assert_eq!(
            store.check(&key, &rule, now).unwrap(),
            LimitDecision::Deny {
                limit: 25,
                remaining: 0,
                reset_after: Duration::from_secs(60),
                retry_after: Duration::from_secs(60),
            },
            "request 4 is the exact index at which Deny must first appear"
        );
    }

    // ---- central semantic: record never signals truncation -----------------

    /// A request already "in flight" (its usage recorded after the budget is
    /// already exhausted by other concurrent requests) must not be rejected,
    /// erred, or truncated by `record` -- the central semantic:
    /// over-limit rejects the *next* request, never an in-flight one.
    #[test]
    fn record_never_errors_or_signals_truncation_even_when_already_over_budget() {
        let rule = rule(LimitOn::Total, 10, Duration::from_secs(60));
        let store = InProcessBudgetStore::new();
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        // Exhaust the budget.
        store.record(&key, &rule, &usage(6, 4), 1.0, now);
        assert_eq!(
            store.check(&key, &rule, now).unwrap(),
            LimitDecision::Deny {
                limit: 10,
                remaining: 0,
                reset_after: Duration::from_secs(60),
                retry_after: Duration::from_secs(60),
            }
        );

        // A request that was already in flight before the budget ran out
        // finishes now, well over budget. `record`'s return type is `()`:
        // there is no error path to take here at all, which is the point --
        // the type system, not a runtime check, makes truncation impossible.
        store.record(&key, &rule, &usage(600, 400), 1.0, now);

        // The *next* request (not this one) is what pays for it: still
        // denied, with `remaining` saturated at 0, never negative/wrapped.
        assert_eq!(
            store.check(&key, &rule, now).unwrap(),
            LimitDecision::Deny {
                limit: 10,
                remaining: 0,
                reset_after: Duration::from_secs(60),
                retry_after: Duration::from_secs(60),
            }
        );
    }

    // ---- window rollover -----------------------------------------------

    #[test]
    fn window_rollover_restores_budget() {
        let window = Duration::from_secs(60);
        let rule = rule(LimitOn::Total, 10, window);
        let store = InProcessBudgetStore::new();
        let key = LimitKey::for_credential("r", "sk-1");
        let t0 = Instant::now();

        store.record(&key, &rule, &usage(6, 4), 1.0, t0);
        assert!(matches!(
            store.check(&key, &rule, t0).unwrap(),
            LimitDecision::Deny { .. }
        ));

        // Just before the window elapses: still denied.
        let just_before = t0 + window - Duration::from_millis(1);
        assert!(matches!(
            store.check(&key, &rule, just_before).unwrap(),
            LimitDecision::Deny { .. }
        ));

        // Exactly at / past the window boundary: budget is restored.
        let after = t0 + window;
        assert_eq!(
            store.check(&key, &rule, after).unwrap(),
            LimitDecision::Allow {
                limit: 10,
                remaining: 10,
                reset_after: window,
            }
        );

        // A `record` after rollover starts a fresh window rather than adding
        // onto the stale total.
        store.record(&key, &rule, &usage(1, 1), 1.0, after);
        assert_eq!(
            store.check(&key, &rule, after).unwrap(),
            LimitDecision::Allow {
                limit: 10,
                remaining: 8,
                reset_after: window,
            }
        );
    }

    // ---- check purity --------------------------------------------------

    #[test]
    fn check_is_pure_repeated_calls_agree() {
        let rule = rule(LimitOn::Total, 10, Duration::from_secs(60));
        let store = InProcessBudgetStore::new();
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        store.record(&key, &rule, &usage(3, 2), 1.0, now);

        let first = store.check(&key, &rule, now).unwrap();
        for _ in 0..5 {
            assert_eq!(
                store.check(&key, &rule, now).unwrap(),
                first,
                "repeated check() calls with no intervening record() must agree"
            );
        }
    }

    // ---- cost weights ----------------------------------------------------

    /// A 10x-weighted model exhausts an identical budget in 1/10th the
    /// requests: ten 1-token (unweighted-equivalent) responses at weight 1.0
    /// take ten `record`s to exhaust a 10-token budget; the same at weight
    /// 10.0 exhausts it in one.
    #[test]
    fn cost_weight_scales_consumption() {
        let window = Duration::from_secs(60);
        let now = Instant::now();

        let rule = rule(LimitOn::Total, 10, window);
        let unweighted = InProcessBudgetStore::new();
        let weighted = InProcessBudgetStore::new();
        let key = LimitKey::for_credential("r", "sk-1");

        let mut unweighted_denies_at = None;
        let mut weighted_denies_at = None;
        for i in 1..=10u32 {
            unweighted.record(&key, &rule, &usage(1, 0), 1.0, now);
            if unweighted_denies_at.is_none()
                && matches!(
                    unweighted.check(&key, &rule, now),
                    Ok(LimitDecision::Deny { .. })
                )
            {
                unweighted_denies_at = Some(i);
            }

            weighted.record(&key, &rule, &usage(1, 0), 10.0, now);
            if weighted_denies_at.is_none()
                && matches!(
                    weighted.check(&key, &rule, now),
                    Ok(LimitDecision::Deny { .. })
                )
            {
                weighted_denies_at = Some(i);
            }
        }

        assert_eq!(unweighted_denies_at, Some(10));
        assert_eq!(
            weighted_denies_at,
            Some(1),
            "a 10x weight must exhaust the same budget in 1/10th the requests"
        );
    }

    // ---- Input / Output / Total independence ------------------------------

    #[test]
    fn input_limit_ignores_output_tokens() {
        let rule = rule(LimitOn::Input, 10, Duration::from_secs(60));
        let store = InProcessBudgetStore::new();
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        // All output, no input: must never deny an Input-only rule.
        store.record(&key, &rule, &usage(0, 1_000_000), 1.0, now);
        assert_eq!(
            store.check(&key, &rule, now).unwrap(),
            LimitDecision::Allow {
                limit: 10,
                remaining: 10,
                reset_after: Duration::from_secs(60),
            }
        );

        store.record(&key, &rule, &usage(10, 0), 1.0, now);
        assert!(matches!(
            store.check(&key, &rule, now).unwrap(),
            LimitDecision::Deny { .. }
        ));
    }

    #[test]
    fn output_limit_ignores_input_tokens() {
        let rule = rule(LimitOn::Output, 10, Duration::from_secs(60));
        let store = InProcessBudgetStore::new();
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        store.record(&key, &rule, &usage(1_000_000, 0), 1.0, now);
        assert_eq!(
            store.check(&key, &rule, now).unwrap(),
            LimitDecision::Allow {
                limit: 10,
                remaining: 10,
                reset_after: Duration::from_secs(60),
            }
        );

        store.record(&key, &rule, &usage(0, 10), 1.0, now);
        assert!(matches!(
            store.check(&key, &rule, now).unwrap(),
            LimitDecision::Deny { .. }
        ));
    }

    /// `Total` uses `TokenUsage::total()`, which includes the cached and
    /// cache-creation buckets -- not just input + output. A rule that summed
    /// only input + output would under-count a heavy-cache workload.
    #[test]
    fn total_limit_includes_cached_and_cache_creation_buckets() {
        let rule = rule(LimitOn::Total, 10, Duration::from_secs(60));
        let store = InProcessBudgetStore::new();
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        let usage_with_cache = TokenUsage {
            input_tokens: 1,
            cached_tokens: 4,
            cache_creation_tokens: 5,
            output_tokens: 0,
        };
        assert_eq!(usage_with_cache.total(), 10);

        store.record(&key, &rule, &usage_with_cache, 1.0, now);
        assert!(
            matches!(
                store.check(&key, &rule, now).unwrap(),
                LimitDecision::Deny { .. }
            ),
            "cached/cache-creation tokens must count toward Total, not be dropped"
        );
    }

    // ---- saturating arithmetic ---------------------------------------------

    #[test]
    fn saturating_at_u64_max_does_not_panic_or_wrap() {
        // `LimitOn::Input` reads `input_tokens` directly (no summing across
        // buckets, unlike `Total` -- see `TokenUsage::total`), so this
        // exercises *this module's* saturating accumulation in isolation
        // without also depending on `TokenUsage::total`'s own arithmetic.
        let rule = rule(LimitOn::Input, 10, Duration::from_secs(60));
        let store = InProcessBudgetStore::new();
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        // A single pathological usage value at the u64 max.
        store.record(&key, &rule, &usage(u64::MAX, 0), 1.0, now);
        // Recording again must not wrap back around toward zero.
        store.record(&key, &rule, &usage(u64::MAX, 0), 1.0, now);

        match store.check(&key, &rule, now).unwrap() {
            LimitDecision::Deny { remaining, .. } => assert_eq!(remaining, 0),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn huge_weight_does_not_panic_or_wrap() {
        let rule = rule(LimitOn::Total, 10, Duration::from_secs(60));
        let store = InProcessBudgetStore::new();
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        for weight in [f64::MAX, f64::INFINITY, 1e300] {
            store.record(&key, &rule, &usage(1, 1), weight, now);
        }

        match store.check(&key, &rule, now).unwrap() {
            LimitDecision::Deny { remaining, .. } => assert_eq!(remaining, 0),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    // ---- distinct keys don't bleed into each other -------------------------

    #[test]
    fn distinct_keys_have_independent_budgets() {
        let rule = rule(LimitOn::Total, 10, Duration::from_secs(60));
        let store = InProcessBudgetStore::new();
        let key_a = LimitKey::for_credential("r", "sk-a");
        let key_b = LimitKey::for_credential("r", "sk-b");
        let now = Instant::now();

        store.record(&key_a, &rule, &usage(10, 0), 1.0, now);
        assert!(matches!(
            store.check(&key_a, &rule, now).unwrap(),
            LimitDecision::Deny { .. }
        ));
        assert_eq!(
            store.check(&key_b, &rule, now).unwrap(),
            LimitDecision::Allow {
                limit: 10,
                remaining: 10,
                reset_after: Duration::from_secs(60),
            },
            "key_b's budget must be untouched by key_a's usage"
        );
    }

    // ---- usage_for_tenant ------------------------------

    /// A tenant with budgets on more than one route gets all of them back,
    /// sorted by route -- the multi-route case the `LimitKey`
    /// struct exists specifically to make answerable.
    #[test]
    fn usage_for_tenant_reports_every_route_the_tenant_has_a_budget_on() {
        let rule = rule(LimitOn::Total, 100, Duration::from_secs(60));
        let store = InProcessBudgetStore::new();
        let now = Instant::now();

        store.record(
            &LimitKey::for_tenant("zebra", "acme"),
            &rule,
            &usage(30, 0),
            1.0,
            now,
        );
        store.record(
            &LimitKey::for_tenant("alpha", "acme"),
            &rule,
            &usage(10, 0),
            1.0,
            now,
        );

        let report = store.usage_for_tenant("acme", now).unwrap();
        assert_eq!(
            report,
            vec![
                TenantUsage {
                    route: "alpha".to_string(),
                    used: 10.0,
                    limit: 100.0,
                    remaining: 90.0,
                    reset_after: Duration::from_secs(60),
                },
                TenantUsage {
                    route: "zebra".to_string(),
                    used: 30.0,
                    limit: 100.0,
                    remaining: 70.0,
                    reset_after: Duration::from_secs(60),
                },
            ],
            "must report both routes, sorted by route name (alpha before zebra, not \
             insertion order)"
        );
    }

    /// A tenant with no recorded usage anywhere gets an empty list back, not
    /// an error -- a true (if unremarkable) answer, per the module doc.
    #[test]
    fn usage_for_tenant_with_no_budgets_returns_an_empty_list() {
        let rule = rule(LimitOn::Total, 100, Duration::from_secs(60));
        let store = InProcessBudgetStore::new();
        let now = Instant::now();

        store.record(
            &LimitKey::for_tenant("r1", "someone-else"),
            &rule,
            &usage(5, 0),
            1.0,
            now,
        );

        assert_eq!(store.usage_for_tenant("acme", now).unwrap(), vec![]);
    }

    /// A credential-keyed bucket (no authenticated tenant) must never be
    /// mistaken for a tenant's -- the same disjoint-key-space property
    /// [`LimitSubject`]'s doc already requires of `check`/`record`.
    #[test]
    fn usage_for_tenant_never_returns_a_credential_keyed_bucket() {
        let rule = rule(LimitOn::Total, 100, Duration::from_secs(60));
        let store = InProcessBudgetStore::new();
        let now = Instant::now();

        // A credential bucket whose route/value happen to look exactly like
        // the tenant being queried.
        store.record(
            &LimitKey::for_credential("r1", "acme"),
            &rule,
            &usage(5, 0),
            1.0,
            now,
        );

        assert_eq!(store.usage_for_tenant("acme", now).unwrap(), vec![]);
    }

    /// Expired windows leave the map (review M8): a window read as fresh is
    /// dropped by the next sweep, which runs at most once per window length.
    /// This is also what happens to a deleted tenant's window: the store is
    /// never told about the delete, and does not need to be, since the
    /// window frees itself within two window lengths.
    ///
    /// Mutation: skip the `retain` in `record`; the map keeps all 1000.
    #[test]
    fn expired_windows_are_evicted_by_the_next_sweep() {
        let window = Duration::from_secs(60);
        let rule = rule(LimitOn::Total, 100, window);
        let store = InProcessBudgetStore::new();
        let start = Instant::now();
        for i in 0..1000 {
            let key = LimitKey::for_tenant("r", &format!("tenant-{i}"));
            store.record(&key, &rule, &usage(5, 0), 1.0, start);
        }
        assert_eq!(store.tracked_windows(), 1000);

        // Inside the window: nothing expires, and no sweep is due.
        let live = LimitKey::for_tenant("r", "live");
        store.record(&live, &rule, &usage(1, 0), 1.0, start + window / 2);
        assert_eq!(store.tracked_windows(), 1001);

        // One window later the 1000 have expired; the live one has not.
        store.record(&live, &rule, &usage(1, 0), 1.0, start + window);
        assert_eq!(store.tracked_windows(), 1);
        assert_eq!(
            store.check(
                &LimitKey::for_tenant("r", "tenant-0"),
                &rule,
                start + window
            ),
            Ok(LimitDecision::Allow {
                limit: 100,
                remaining: 100,
                reset_after: window,
            }),
            "an evicted window reads the same as an expired one"
        );
    }

    /// Review M8: without an auth filter the key is a digest of a header the
    /// caller picks, so invented headers must not grow the map without
    /// bound. Past the cap, new credentials share one overflow budget per
    /// route, which still limits them (a check sees the overflow's usage),
    /// and the first fold warns once without naming a credential. When the
    /// windows expire the cap frees again.
    ///
    /// Mutation: have `Windows::bounded` always return `None`; the map then
    /// holds every credential.
    #[test]
    fn distinct_credentials_past_the_cap_share_one_overflow_budget() {
        let window = Duration::from_secs(60);
        let rule = rule(LimitOn::Total, 10, window);
        let store = InProcessBudgetStore::new();
        let start = Instant::now();
        let (capture, guard) = crate::control::log_capture::Capture::start();
        for i in 0..MAX_CREDENTIAL_WINDOWS + 100 {
            let key = LimitKey::for_credential("r", &format!("Bearer bogus-{i}"));
            store.record(&key, &rule, &usage(1, 0), 1.0, start);
        }
        drop(guard);

        assert_eq!(
            store.tracked_windows(),
            MAX_CREDENTIAL_WINDOWS + 1,
            "the cap, plus the route's one overflow bucket"
        );
        // The 100 past the cap spent 100 tokens of the shared overflow
        // budget, so a further new credential is denied on its first check.
        let late = LimitKey::for_credential("r", "Bearer one-more");
        assert!(matches!(
            store.check(&late, &rule, start),
            Ok(LimitDecision::Deny { .. })
        ));
        // A credential that got its own window keeps it.
        assert!(matches!(
            store.check(
                &LimitKey::for_credential("r", "Bearer bogus-0"),
                &rule,
                start
            ),
            Ok(LimitDecision::Allow { remaining: 9, .. })
        ));

        let warnings = capture.rendered_at_or_above(tracing::Level::WARN);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(!warnings[0].contains("bogus"), "{}", warnings[0]);

        // Once they expire, a new credential gets a window of its own again.
        store.record(&late, &rule, &usage(1, 0), 1.0, start + window);
        assert_eq!(store.tracked_windows(), 1);
        assert!(matches!(
            store.check(&late, &rule, start + window),
            Ok(LimitDecision::Allow { remaining: 9, .. })
        ));
    }

    #[test]
    fn one_store_enforces_two_rules_for_two_keys() {
        let store = InProcessBudgetStore::new();
        let now = Instant::now();
        let small = rule(LimitOn::Input, 2, Duration::from_secs(60));
        let large = rule(LimitOn::Output, 5, Duration::from_secs(120));
        let a = LimitKey::for_tenant("r", "a");
        let b = LimitKey::for_tenant("r", "b");
        store.record(&a, &small, &usage(2, 0), 1.0, now);
        store.record(&b, &large, &usage(100, 3), 1.0, now);
        assert!(matches!(
            store.check(&a, &small, now),
            Ok(LimitDecision::Deny { limit: 2, .. })
        ));
        assert!(matches!(
            store.check(&b, &large, now),
            Ok(LimitDecision::Allow {
                limit: 5,
                remaining: 2,
                ..
            })
        ));
    }

    #[test]
    fn changed_rule_takes_effect_on_next_check() {
        let store = InProcessBudgetStore::new();
        let now = Instant::now();
        let key = LimitKey::for_tenant("r", "a");
        let old = rule(LimitOn::Total, 10, Duration::from_secs(60));
        store.record(&key, &old, &usage(5, 0), 1.0, now);
        let lower = rule(LimitOn::Total, 4, Duration::from_secs(60));
        let higher = rule(LimitOn::Total, 6, Duration::from_secs(60));
        assert!(matches!(
            store.check(&key, &lower, now),
            Ok(LimitDecision::Deny { limit: 4, .. })
        ));
        assert!(matches!(
            store.check(&key, &higher, now),
            Ok(LimitDecision::Allow {
                limit: 6,
                remaining: 1,
                ..
            })
        ));
        let extended = rule(LimitOn::Total, 6, Duration::from_secs(120));
        store.record(
            &key,
            &extended,
            &usage(1, 0),
            1.0,
            now + Duration::from_secs(61),
        );
        assert!(matches!(
            store.check(&key, &extended, now + Duration::from_secs(61)),
            Ok(LimitDecision::Deny {
                limit: 6,
                remaining: 0,
                ..
            })
        ));
    }

    #[test]
    fn tenant_usage_uses_the_last_checked_rule() {
        let store = InProcessBudgetStore::new();
        let now = Instant::now();
        let key = LimitKey::for_tenant("r", "a");
        let old = rule(LimitOn::Total, 10, Duration::from_secs(60));
        let new = rule(LimitOn::Total, 7, Duration::from_secs(30));
        store.record(&key, &old, &usage(3, 0), 1.0, now);
        store.check(&key, &new, now).unwrap();
        assert_eq!(
            store.usage_for_tenant("a", now).unwrap(),
            vec![TenantUsage {
                route: "r".into(),
                used: 3.0,
                limit: 7.0,
                remaining: 4.0,
                reset_after: Duration::from_secs(30),
            }]
        );
    }

    #[test]
    fn request_admission_counts_only_admitted_requests_and_is_separate_from_tokens() {
        let store = InProcessBudgetStore::new();
        let now = Instant::now();
        let key = LimitKey::for_tenant("r", "a");
        let limit = RequestLimit {
            max_requests: 2,
            window: Duration::from_secs(60),
        };
        let token_rule = rule(LimitOn::Total, 1, Duration::from_secs(60));
        store.record(&key, &token_rule, &usage(1, 0), 1.0, now);
        assert!(matches!(
            store.check(&key, &token_rule, now),
            Ok(LimitDecision::Deny { .. })
        ));
        assert!(matches!(
            store.admit_request(&key, &limit, now),
            Ok(LimitDecision::Allow { remaining: 1, .. })
        ));
        assert!(matches!(
            store.admit_request(&key, &limit, now),
            Ok(LimitDecision::Allow { remaining: 0, .. })
        ));
        assert_eq!(
            store.admit_request(&key, &limit, now + Duration::from_secs(10)),
            Ok(LimitDecision::Deny {
                limit: 2,
                remaining: 0,
                reset_after: Duration::from_secs(50),
                retry_after: Duration::from_secs(50),
            })
        );
        assert_eq!(
            store
                .request_windows
                .lock()
                .unwrap()
                .by_key
                .get(&key)
                .unwrap()
                .used,
            2
        );
        assert!(matches!(
            store.admit_request(&key, &limit, now + limit.window),
            Ok(LimitDecision::Allow { remaining: 1, .. })
        ));
    }

    #[test]
    fn stream_leases_release_slots_and_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<StreamLease>();
        let limiter = InProcessConcurrencyLimiter::new();
        let key = LimitKey::for_tenant("r", "a");
        let first = limiter.try_acquire(&key, 2).unwrap().unwrap();
        let second = limiter.try_acquire(&key, 2).unwrap().unwrap();
        assert!(
            matches!(limiter.try_acquire(&key, 2), Ok(Err(LimitDecision::Deny { retry_after, .. })) if retry_after == Duration::from_secs(1))
        );
        drop(first);
        let third = limiter.try_acquire(&key, 2).unwrap().unwrap();
        drop(second);
        drop(third);
        assert!(!limiter.counts.lock().unwrap().by_key.contains_key(&key));
    }

    #[test]
    fn credential_cap_applies_to_request_and_concurrency_maps() {
        let store = InProcessBudgetStore::new();
        let limiter = InProcessConcurrencyLimiter::new();
        let now = Instant::now();
        let limit = RequestLimit {
            max_requests: 1,
            window: Duration::from_secs(60),
        };
        let mut leases = Vec::new();
        for i in 0..MAX_CREDENTIAL_WINDOWS + 2 {
            let key = LimitKey::for_credential("r", &format!("credential-{i}"));
            store.admit_request(&key, &limit, now).unwrap();
            if let Ok(lease) = limiter.try_acquire(&key, 1).unwrap() {
                leases.push(lease);
            }
        }
        assert_eq!(
            store.request_windows.lock().unwrap().by_key.len(),
            MAX_CREDENTIAL_WINDOWS + 1
        );
        assert_eq!(
            limiter.counts.lock().unwrap().by_key.len(),
            MAX_CREDENTIAL_WINDOWS + 1
        );
        let late = LimitKey::for_credential("r", "another");
        assert!(matches!(
            store.admit_request(&late, &limit, now),
            Ok(LimitDecision::Deny { .. })
        ));
        assert!(matches!(
            limiter.try_acquire(&late, 1),
            Ok(Err(LimitDecision::Deny { .. }))
        ));
        drop(leases);
        assert!(limiter.counts.lock().unwrap().by_key.is_empty());
    }
}
