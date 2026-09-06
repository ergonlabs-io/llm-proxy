//! WP-34 increment 1 — the token budget limiter, as a pure library.
//!
//! This module answers one question: **is the next request allowed against a
//! configured token budget, and if not, when will it be?** It does not touch
//! `HttpFilter`, config/IR, or response generation — those are later
//! increments (see `IMPLEMENTATION_PLAN.md`'s WP-34 entry). This increment is
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
//! [`InProcessBudgetStore`] is the only implementation built in this
//! increment (and, per the product decision behind WP-34 increment 2, stays
//! the *default* even once a remote one exists): one rule, tracked per key,
//! shared by every worker in this process. The trait exists so a Redis-backed
//! (or otherwise control-plane-aggregated) store can land later behind the
//! same interface without callers changing — that store is explicitly **not**
//! built here. The rest of this section is about making that "later" actually
//! true rather than aspirational.
//!
//! # Making this distributed (the migration path, written down now)
//!
//! A remote store needs network I/O, and [`BudgetStore::check`] /
//! [`BudgetStore::record`] are synchronous, `&self` methods — a remote
//! implementation cannot block a worker thread on a round trip inside them.
//! When that implementation lands, the filter calling this trait
//! (`crate::token_limit_filter`) will have to hold the stream with S2
//! `StopIteration` from `decode_headers` and resume via `continue_decoding()`
//! once the answer arrives — the same shape WP-32's `ext_authz` / gRPC RLS
//! filters already need for their own out-of-process calls. Three things fall
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
//!    is a bigger refactor than this increment warrants — but it is named
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
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::usage::TokenUsage;

/// The identity a budget is tracked against: which route, and who the budget
/// belongs to (see [`LimitSubject`]).
///
/// Previously this was a flattened, opaque `String` built by
/// `from_descriptors(&[("route", ..), ("tenant", ..)])` -- enough for
/// [`InProcessBudgetStore`]'s `Mutex<HashMap<LimitKey, Window>>` to compare
/// keys, but with no way back out to "which route" or "which tenant" short of
/// parsing a separator format that existed only by accident. WP-54's
/// per-tenant usage query needs exactly that (enumerating a tenant's keys
/// across routes), so this is now a struct with named fields -- see
/// `IMPLEMENTATION_PLAN.md`'s WP-54 entry ("Decision needed before
/// implementing") for the fuller reasoning. The struct also does something
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
    /// An identity the proxy itself assigned (WP-50 virtual keys).
    Tenant(String),
    /// No auth filter authenticated the stream, so the bucket is keyed on a
    /// digest of the credential the caller presented. See
    /// [`CredentialDigest`] -- a digest is the only thing this variant can
    /// hold; there is no way to construct it from a raw, unhashed value.
    Credential(CredentialDigest),
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
    /// exactly -- the shape a later increment's per-tenant usage query needs
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
#[derive(Debug, Clone, Copy)]
pub struct LimitRule {
    pub on: LimitOn,
    pub max_tokens: u64,
    pub window: Duration,
}

/// The outcome of a [`BudgetStore::check`] call.
///
/// Both variants carry the same "how does this look to the caller" shape a
/// provider-style rate limiter publishes (`limit` / `remaining` /
/// `reset_after`), plus `retry_after` on `Deny` — this increment does not
/// build the HTTP header mapping, but the fields are named to make that
/// mapping mechanical when a later increment adds it.
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

/// Seam for a token-budget backend. See the module docs (in particular
/// "Making this distributed") for why the trait is shaped this way ahead of
/// a second implementation.
///
/// Rust note: both methods take `&self`, not `&mut self`. That is what lets a
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
    /// Does `key` currently have room? Must not mutate window state —
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
    fn check(&self, key: &LimitKey, now: Instant) -> Result<LimitDecision, BudgetUnavailable>;

    /// Record that `usage` (scaled by `weight`) actually happened against
    /// `key`. Infallible from the caller's side — see the module docs'
    /// central semantic: the response path must never block on, or fail
    /// because of, budget bookkeeping. For [`InProcessBudgetStore`] this is
    /// also durable. It is NOT guaranteed to be durable in general: a remote
    /// implementation is expected to queue/batch and may drop updates under
    /// backpressure rather than propagate that failure here — treat this as
    /// best-effort, not a commit.
    fn record(&self, key: &LimitKey, usage: &TokenUsage, weight: f64, now: Instant);
}

/// One key's current fixed window: when it started, and how many (weighted)
/// tokens have been recorded in it so far.
#[derive(Debug, Clone, Copy)]
struct Window {
    started_at: Instant,
    used: u64,
}

/// The only [`BudgetStore`] implementation in this increment (and, per the
/// product decision behind WP-34 increment 2, the deployment default even
/// once a remote one exists): a single [`LimitRule`], tracked per
/// [`LimitKey`], shared by every worker in this process.
///
/// Rust note: interior mutability here is a `Mutex`, not a `RefCell` — and
/// that is a **reversal** from increment 1, which chose `RefCell` by citing
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
    rule: LimitRule,
    windows: Mutex<HashMap<LimitKey, Window>>,
}

impl InProcessBudgetStore {
    pub fn new(rule: LimitRule) -> Self {
        Self {
            rule,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// The bucket of `usage` this store's rule cares about, per
    /// [`LimitOn`]'s doc comment.
    fn bucket(&self, usage: &TokenUsage) -> u64 {
        match self.rule.on {
            LimitOn::Input => usage.input_tokens,
            LimitOn::Output => usage.output_tokens,
            LimitOn::Total => usage.total(),
        }
    }

    /// The `used` count for `key`'s *current* window as of `now`, treating a
    /// window that has rolled past (or never existed) as freshly reset — but
    /// never mutating `windows` (that is `record`'s job; `check` and this
    /// helper stay read-only, per the trait's purity requirement).
    fn used_in_current_window(&self, key: &LimitKey, now: Instant) -> (u64, Duration) {
        // Rust note: `.lock().unwrap()` -- a poisoned mutex here would mean
        // some other call panicked while holding the lock, which never
        // happens in this function (no panicking code runs between lock and
        // unlock), so this can't actually fire; `sink.rs`'s `FileSink` makes
        // the same choice for the same reason.
        let windows = self.windows.lock().unwrap();
        match windows.get(key) {
            Some(w) => {
                let elapsed = now.saturating_duration_since(w.started_at);
                if elapsed >= self.rule.window {
                    // The window has rolled; a fresh one starts at `now`, so
                    // the full window remains until the next reset.
                    (0, self.rule.window)
                } else {
                    (w.used, self.rule.window - elapsed)
                }
            }
            None => (0, self.rule.window),
        }
    }
}

impl BudgetStore for InProcessBudgetStore {
    fn check(&self, key: &LimitKey, now: Instant) -> Result<LimitDecision, BudgetUnavailable> {
        let (used, reset_after) = self.used_in_current_window(key, now);
        let limit = self.rule.max_tokens;
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

    fn record(&self, key: &LimitKey, usage: &TokenUsage, weight: f64, now: Instant) {
        // Rust note: `f64::round` then saturating-cast via `as u64` — `as` on
        // a float-to-int in Rust is itself a saturating conversion (NaN -> 0,
        // out-of-range -> the type's min/max), which is exactly the "never
        // panic, never wrap" behavior this billing path requires even for a
        // pathological weight (e.g. `f64::MAX` or `f64::INFINITY`).
        let raw = self.bucket(usage);
        let weighted = (raw as f64 * weight).round();
        let weighted_tokens = if weighted.is_sign_negative() {
            0
        } else {
            weighted as u64
        };

        let mut windows = self.windows.lock().unwrap();
        let window = windows.entry(key.clone()).or_insert(Window {
            started_at: now,
            used: 0,
        });
        let elapsed = now.saturating_duration_since(window.started_at);
        if elapsed >= self.rule.window {
            // The window rolled since we last saw this key; this record
            // starts a fresh one rather than adding onto a stale total.
            window.started_at = now;
            window.used = weighted_tokens;
        } else {
            window.used = window.used.saturating_add(weighted_tokens);
        }
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
        let store = InProcessBudgetStore::new(rule(LimitOn::Total, 25, Duration::from_secs(60)));
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        // Request 1: check (25 remaining), record 10 -> used 10.
        assert_eq!(
            store.check(&key, now).unwrap(),
            LimitDecision::Allow {
                limit: 25,
                remaining: 25,
                reset_after: Duration::from_secs(60),
            }
        );
        store.record(&key, &usage(6, 4), 1.0, now);

        // Request 2: check (15 remaining), record 10 -> used 20.
        assert_eq!(
            store.check(&key, now).unwrap(),
            LimitDecision::Allow {
                limit: 25,
                remaining: 15,
                reset_after: Duration::from_secs(60),
            }
        );
        store.record(&key, &usage(6, 4), 1.0, now);

        // Request 3: check (5 remaining) -- still allowed, used(20) < limit(25).
        assert_eq!(
            store.check(&key, now).unwrap(),
            LimitDecision::Allow {
                limit: 25,
                remaining: 5,
                reset_after: Duration::from_secs(60),
            }
        );
        store.record(&key, &usage(6, 4), 1.0, now);
        // Cumulative used is now 30, past the 25-token budget.

        // Request 4: THIS is the exact onset -- the first Deny.
        assert_eq!(
            store.check(&key, now).unwrap(),
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
    /// erred, or truncated by `record` -- the plan's central semantic:
    /// over-limit rejects the *next* request, never an in-flight one.
    #[test]
    fn record_never_errors_or_signals_truncation_even_when_already_over_budget() {
        let store = InProcessBudgetStore::new(rule(LimitOn::Total, 10, Duration::from_secs(60)));
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        // Exhaust the budget.
        store.record(&key, &usage(6, 4), 1.0, now);
        assert_eq!(
            store.check(&key, now).unwrap(),
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
        store.record(&key, &usage(600, 400), 1.0, now);

        // The *next* request (not this one) is what pays for it: still
        // denied, with `remaining` saturated at 0, never negative/wrapped.
        assert_eq!(
            store.check(&key, now).unwrap(),
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
        let store = InProcessBudgetStore::new(rule(LimitOn::Total, 10, window));
        let key = LimitKey::for_credential("r", "sk-1");
        let t0 = Instant::now();

        store.record(&key, &usage(6, 4), 1.0, t0);
        assert!(matches!(
            store.check(&key, t0).unwrap(),
            LimitDecision::Deny { .. }
        ));

        // Just before the window elapses: still denied.
        let just_before = t0 + window - Duration::from_millis(1);
        assert!(matches!(
            store.check(&key, just_before).unwrap(),
            LimitDecision::Deny { .. }
        ));

        // Exactly at / past the window boundary: budget is restored.
        let after = t0 + window;
        assert_eq!(
            store.check(&key, after).unwrap(),
            LimitDecision::Allow {
                limit: 10,
                remaining: 10,
                reset_after: window,
            }
        );

        // A `record` after rollover starts a fresh window rather than adding
        // onto the stale total.
        store.record(&key, &usage(1, 1), 1.0, after);
        assert_eq!(
            store.check(&key, after).unwrap(),
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
        let store = InProcessBudgetStore::new(rule(LimitOn::Total, 10, Duration::from_secs(60)));
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        store.record(&key, &usage(3, 2), 1.0, now);

        let first = store.check(&key, now).unwrap();
        for _ in 0..5 {
            assert_eq!(
                store.check(&key, now).unwrap(),
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

        let unweighted = InProcessBudgetStore::new(rule(LimitOn::Total, 10, window));
        let weighted = InProcessBudgetStore::new(rule(LimitOn::Total, 10, window));
        let key = LimitKey::for_credential("r", "sk-1");

        let mut unweighted_denies_at = None;
        let mut weighted_denies_at = None;
        for i in 1..=10u32 {
            unweighted.record(&key, &usage(1, 0), 1.0, now);
            if unweighted_denies_at.is_none()
                && matches!(unweighted.check(&key, now), Ok(LimitDecision::Deny { .. }))
            {
                unweighted_denies_at = Some(i);
            }

            weighted.record(&key, &usage(1, 0), 10.0, now);
            if weighted_denies_at.is_none()
                && matches!(weighted.check(&key, now), Ok(LimitDecision::Deny { .. }))
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
        let store = InProcessBudgetStore::new(rule(LimitOn::Input, 10, Duration::from_secs(60)));
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        // All output, no input: must never deny an Input-only rule.
        store.record(&key, &usage(0, 1_000_000), 1.0, now);
        assert_eq!(
            store.check(&key, now).unwrap(),
            LimitDecision::Allow {
                limit: 10,
                remaining: 10,
                reset_after: Duration::from_secs(60),
            }
        );

        store.record(&key, &usage(10, 0), 1.0, now);
        assert!(matches!(
            store.check(&key, now).unwrap(),
            LimitDecision::Deny { .. }
        ));
    }

    #[test]
    fn output_limit_ignores_input_tokens() {
        let store = InProcessBudgetStore::new(rule(LimitOn::Output, 10, Duration::from_secs(60)));
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        store.record(&key, &usage(1_000_000, 0), 1.0, now);
        assert_eq!(
            store.check(&key, now).unwrap(),
            LimitDecision::Allow {
                limit: 10,
                remaining: 10,
                reset_after: Duration::from_secs(60),
            }
        );

        store.record(&key, &usage(0, 10), 1.0, now);
        assert!(matches!(
            store.check(&key, now).unwrap(),
            LimitDecision::Deny { .. }
        ));
    }

    /// `Total` uses `TokenUsage::total()`, which includes the cached and
    /// cache-creation buckets -- not just input + output. A rule that summed
    /// only input + output would under-count a heavy-cache workload.
    #[test]
    fn total_limit_includes_cached_and_cache_creation_buckets() {
        let store = InProcessBudgetStore::new(rule(LimitOn::Total, 10, Duration::from_secs(60)));
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        let usage_with_cache = TokenUsage {
            input_tokens: 1,
            cached_tokens: 4,
            cache_creation_tokens: 5,
            output_tokens: 0,
        };
        assert_eq!(usage_with_cache.total(), 10);

        store.record(&key, &usage_with_cache, 1.0, now);
        assert!(
            matches!(store.check(&key, now).unwrap(), LimitDecision::Deny { .. }),
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
        let store = InProcessBudgetStore::new(rule(LimitOn::Input, 10, Duration::from_secs(60)));
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        // A single pathological usage value at the u64 max.
        store.record(&key, &usage(u64::MAX, 0), 1.0, now);
        // Recording again must not wrap back around toward zero.
        store.record(&key, &usage(u64::MAX, 0), 1.0, now);

        match store.check(&key, now).unwrap() {
            LimitDecision::Deny { remaining, .. } => assert_eq!(remaining, 0),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn huge_weight_does_not_panic_or_wrap() {
        let store = InProcessBudgetStore::new(rule(LimitOn::Total, 10, Duration::from_secs(60)));
        let key = LimitKey::for_credential("r", "sk-1");
        let now = Instant::now();

        for weight in [f64::MAX, f64::INFINITY, 1e300] {
            store.record(&key, &usage(1, 1), weight, now);
        }

        match store.check(&key, now).unwrap() {
            LimitDecision::Deny { remaining, .. } => assert_eq!(remaining, 0),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    // ---- distinct keys don't bleed into each other -------------------------

    #[test]
    fn distinct_keys_have_independent_budgets() {
        let store = InProcessBudgetStore::new(rule(LimitOn::Total, 10, Duration::from_secs(60)));
        let key_a = LimitKey::for_credential("r", "sk-a");
        let key_b = LimitKey::for_credential("r", "sk-b");
        let now = Instant::now();

        store.record(&key_a, &usage(10, 0), 1.0, now);
        assert!(matches!(
            store.check(&key_a, now).unwrap(),
            LimitDecision::Deny { .. }
        ));
        assert_eq!(
            store.check(&key_b, now).unwrap(),
            LimitDecision::Allow {
                limit: 10,
                remaining: 10,
                reset_after: Duration::from_secs(60),
            },
            "key_b's budget must be untouched by key_a's usage"
        );
    }
}
