//! Rate-limit counters for `llmproxy.token_limit`: tier-3 window counters and
//! tier-4 concurrent-stream gauges (ADR-0006, amendment and addendum of
//! 2026-10-15).
//!
//! # Window counters: accumulate locally, reconcile through the store
//!
//! Tokens per window and requests per window use spend's shape
//! ([`crate::spend::SpendAccumulator`]). A worker admits against
//! `base + pending` and records into `pending` under one short lock; it never
//! touches the store (addendum §1: admission never reads the store, in any
//! mode). A control-side flusher thread sends `pending` as additive deltas,
//! deduplicated by `(node_id, seq)`, and adopts each total the store returns
//! as the new `base`. `base` is therefore the fleet total the store last
//! confirmed, and `pending` is this replica's share not yet delivered.
//!
//! The backend is whatever `auth.store` selects, through
//! [`ControlPlaneStore`]'s window rows. With the in-memory store the
//! accumulator is exact; with a shared store every replica converges on the
//! fleet total one reconcile interval behind (amendment G).
//!
//! Windows are wall-clock keys aligned to the epoch ([`WindowKey`],
//! amendment B), so every replica names the same minute the same way. A
//! caller's first window can therefore be shorter than the configured length.
//! Counters are keyed by subject, dimension and window, never by the limit
//! (amendment C): the limit is compared at admission, so changing it keeps
//! the current counts.
//!
//! A replica learns another replica's usage only for subjects it has a
//! bucket for: a subject it has never served reads as zero until its first
//! request creates a bucket and the next reconcile fills `base`. That is the
//! accepted cost of keeping the store off the admission path.
//!
//! # Small limits: early flush
//!
//! When a bucket's pending count passes a quarter of its remaining allowance,
//! the worker wakes the flusher (addendum §2). The worker only signals; the
//! flush itself runs on the flusher thread. This bounds a multi-replica burst
//! by the allowance rather than by the reconcile interval.
//!
//! # Store outage: fail open, loudly
//!
//! A failed reconcile keeps enforcing against the last confirmed base plus
//! local activity (ADR-0006 §5). Past the reconciliation bound the
//! accumulator counts each admission it makes while unreconciled and warns,
//! at most once per [`STALE_WARN_INTERVAL`] (AGENTS.md "Fail-open controls").
//!
//! # Concurrent streams: a local gauge and a lease store
//!
//! Concurrency is a gauge, not a counter. [`LeaseGauge`] admits when
//! `local_in_flight + others_last_known < limit` and hands back a
//! [`StreamLease`] that frees the slot when dropped. A publisher thread
//! writes this replica's in-flight count per subject to a [`LeaseStore`] with
//! a TTL and keeps `fleet_sum - own_published` as `others_last_known`
//! (amendment E). Each publish returns the fleet sums of every subject in the
//! scope, so a replica that has never served a subject still counts the
//! streams other replicas hold for it. With [`InMemoryLeaseStore`] there are
//! no other replicas, so the gauge is exact.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::control::{
    ControlPlaneStore, StoreError, WindowDelta, WindowDimension, WindowKey, WindowRow,
};
use crate::reconciliation_age::{ReconciliationAgeGauge, Seam};
use crate::token_limit::{
    LeaseRelease, LimitDecision, LimitKey, StreamLease, MAX_CREDENTIAL_WINDOWS,
};
use proxy_observability::stats::Registry;

/// How often the flusher reconciles window counters by default (addendum §2:
/// about one second, separate from spend's flush and the policy poll).
pub const DEFAULT_WINDOW_FLUSH_INTERVAL: Duration = Duration::from_secs(1);

/// How stale the reconciled base may get before admissions are counted as
/// unreconciled and a warning is logged. Well under a one-minute window.
pub const DEFAULT_WINDOW_RECONCILIATION_BOUND: Duration = Duration::from_secs(10);

/// The least time between two stale-state warnings from one accumulator or
/// one gauge, so a long outage does not flood the log.
pub const STALE_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// How often the lease publisher runs by default: the same one-second
/// cadence as the window reconcile, so concurrency over-admission is bounded
/// by about one second of stream arrivals on the other replicas (amendment G).
pub const DEFAULT_LEASE_PUBLISH_INTERVAL: Duration = Duration::from_secs(1);

/// How long a published lease row lives without a refresh by default: five
/// publish intervals, above the minimum of three (addendum §3). A publish to
/// Redis can block for its one-second I/O timeout before the next interval
/// starts, so three intervals would leave room for only one slow publish
/// before a live replica's leases expired and the others over-admitted. Five
/// survive two failed publishes in a row. It is also how long a crashed
/// replica's slots stay held, and five seconds is short beside a stream.
pub const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(5);

/// The retry hint a concurrency refusal carries: a stream slot frees when a
/// stream ends, which has no schedule to report.
const STREAM_RETRY_HINT: Duration = Duration::from_secs(1);

/// `last_flush_millis` before the first successful reconcile.
const NEVER: i64 = i64::MIN;

fn unix_millis(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A node id for a replica whose config names none. Unique per boot, so a
/// restart never replays another boot's sequence numbers.
pub fn unconfigured_node_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("unconfigured-{}-{nanos}", std::process::id())
}

// ------------------------------------------------------- window counters --

type BucketKey = (LimitKey, WindowDimension, WindowKey);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlushAttempt {
    seq: u64,
    delta: u64,
}

#[derive(Debug, Default)]
struct Bucket {
    /// The fleet total the store last confirmed for this row.
    base: u64,
    /// This replica's counts not yet confirmed by the store, including any
    /// frozen in `attempt`.
    pending: u64,
    /// A delivery in flight or awaiting retry. Retried under the same seq and
    /// delta, so the store applies it at most once.
    attempt: Option<FlushAttempt>,
    /// The next seq to use; `None` until seeded from the store.
    next_seq: Option<u64>,
}

impl Bucket {
    fn used(&self) -> u64 {
        self.base.saturating_add(self.pending)
    }
}

#[derive(Default)]
struct Buckets {
    by_key: HashMap<BucketKey, Bucket>,
    /// Buckets held per credential-keyed [`LimitKey`]; its length is the
    /// number of distinct credentials tracked, which is capped.
    credential_refs: HashMap<LimitKey, usize>,
    overflow_warned: bool,
}

impl Buckets {
    /// The key a bucket for `key` lives under: itself, or the route's shared
    /// overflow key once [`MAX_CREDENTIAL_WINDOWS`] distinct credentials are
    /// already tracked. Returns whether this call is the first fold.
    fn bounded(&mut self, key: &LimitKey) -> (LimitKey, bool) {
        if key.is_credential()
            && !self.credential_refs.contains_key(key)
            && self.credential_refs.len() >= MAX_CREDENTIAL_WINDOWS
        {
            let first = !std::mem::replace(&mut self.overflow_warned, true);
            (key.credential_overflow(), first)
        } else {
            (key.clone(), false)
        }
    }

    /// Read-only form of [`Self::bounded`].
    fn bounded_ref(&self, key: &LimitKey) -> LimitKey {
        if key.is_credential()
            && !self.credential_refs.contains_key(key)
            && self.credential_refs.len() >= MAX_CREDENTIAL_WINDOWS
        {
            key.credential_overflow()
        } else {
            key.clone()
        }
    }

    fn entry(&mut self, key: BucketKey) -> &mut Bucket {
        if !self.by_key.contains_key(&key) && key.0.is_credential() {
            *self.credential_refs.entry(key.0.clone()).or_insert(0) += 1;
        }
        self.by_key.entry(key).or_default()
    }

    fn remove(&mut self, key: &BucketKey) {
        if self.by_key.remove(key).is_some() && key.0.is_credential() {
            if let Some(refs) = self.credential_refs.get_mut(&key.0) {
                *refs -= 1;
                if *refs == 0 {
                    self.credential_refs.remove(&key.0);
                }
            }
        }
    }
}

fn warn_overflow_fold() {
    tracing::warn!(
        max_credential_windows = MAX_CREDENTIAL_WINDOWS,
        "llmproxy.token_limit: the credential cap is full; further credentials share one \
         overflow counter per route"
    );
}

/// Wakes the flusher early, or tells it to stop.
#[derive(Default)]
struct Signal {
    state: Mutex<SignalState>,
    cond: Condvar,
}

#[derive(Default)]
struct SignalState {
    wake: bool,
    shutdown: bool,
}

struct Inner {
    scope: String,
    node_id: String,
    store: Arc<dyn ControlPlaneStore>,
    buckets: Mutex<Buckets>,
    /// Serialises flushes so a final flush on drop cannot interleave with a
    /// flusher tick.
    flush_lock: Mutex<()>,
    signal: Signal,
    /// Set by a worker that has already asked for an early flush, so a burst
    /// signals once rather than per request.
    wake_requested: AtomicBool,
    created_at_millis: i64,
    last_flush_millis: AtomicI64,
    bound: Duration,
    unreconciled_admissions: AtomicU64,
    last_stale_warn_millis: AtomicI64,
    age_gauge: OnceLock<ReconciliationAgeGauge>,
}

/// Tier-3 window counters for one filter chain. See the module doc.
pub struct WindowAccumulator {
    inner: Arc<Inner>,
    flusher: Mutex<Option<JoinHandle<()>>>,
}

/// The result of [`WindowAccumulator::admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Counted; the window's total after this request.
    Admitted { used: u64 },
    /// Refused and not counted; the window's total.
    Refused { used: u64 },
}

impl WindowAccumulator {
    /// `scope` names the filter chain, as spend's `stat_prefix` does, so two
    /// chains never share a row.
    pub fn new(scope: String, store: Arc<dyn ControlPlaneStore>, node_id: String) -> Self {
        Self::with_reconciliation_bound(scope, store, node_id, DEFAULT_WINDOW_RECONCILIATION_BOUND)
    }

    pub fn with_reconciliation_bound(
        scope: String,
        store: Arc<dyn ControlPlaneStore>,
        node_id: String,
        bound: Duration,
    ) -> Self {
        let now = unix_millis(SystemTime::now());
        WindowAccumulator {
            inner: Arc::new(Inner {
                scope,
                node_id,
                store,
                buckets: Mutex::new(Buckets::default()),
                flush_lock: Mutex::new(()),
                signal: Signal::default(),
                wake_requested: AtomicBool::new(false),
                created_at_millis: now,
                last_flush_millis: AtomicI64::new(NEVER),
                bound,
                unreconciled_admissions: AtomicU64::new(0),
                last_stale_warn_millis: AtomicI64::new(NEVER),
                age_gauge: OnceLock::new(),
            }),
            flusher: Mutex::new(None),
        }
    }

    /// The window's current total: the reconciled fleet base plus this
    /// replica's undelivered counts. Never reads the store; a row this
    /// replica holds no bucket for reads as zero.
    pub fn used(&self, key: &LimitKey, dimension: WindowDimension, window: WindowKey) -> u64 {
        let buckets = self.inner.lock_buckets();
        let key = buckets.bounded_ref(key);
        buckets
            .by_key
            .get(&(key, dimension, window))
            .map_or(0, Bucket::used)
    }

    /// Record `amount` against a row. `limit` is the limit the row is
    /// enforced against now; it only decides whether to wake the flusher
    /// early.
    pub fn add(
        &self,
        key: &LimitKey,
        dimension: WindowDimension,
        window: WindowKey,
        amount: u64,
        limit: u64,
    ) {
        if amount == 0 {
            return;
        }
        let (wake, first_fold) = {
            let mut buckets = self.inner.lock_buckets();
            let (key, first_fold) = buckets.bounded(key);
            let bucket = buckets.entry((key, dimension, window));
            bucket.pending = bucket.pending.saturating_add(amount);
            (needs_early_flush(bucket, limit), first_fold)
        };
        if first_fold {
            warn_overflow_fold();
        }
        if wake {
            self.inner.request_early_flush();
        }
    }

    /// Check and count one unit under one lock: admitted when the window's
    /// total is below `limit`, and a refused request is not counted.
    pub fn admit(
        &self,
        key: &LimitKey,
        dimension: WindowDimension,
        window: WindowKey,
        limit: u64,
    ) -> Admission {
        let (admission, wake, first_fold) = {
            let mut buckets = self.inner.lock_buckets();
            let (key, first_fold) = buckets.bounded(key);
            let row = (key, dimension, window);
            let used = buckets.by_key.get(&row).map_or(0, Bucket::used);
            if used >= limit {
                (Admission::Refused { used }, false, first_fold)
            } else {
                let bucket = buckets.entry(row);
                bucket.pending = bucket.pending.saturating_add(1);
                let wake = needs_early_flush(bucket, limit);
                (
                    Admission::Admitted {
                        used: bucket.used(),
                    },
                    wake,
                    first_fold,
                )
            }
        };
        if first_fold {
            warn_overflow_fold();
        }
        if wake {
            self.inner.request_early_flush();
        }
        admission
    }

    /// Every current-window total this replica holds for `tenant` on the
    /// static rule's tenant buckets (one per route), for `GET /v1/usage`.
    /// Exact with a single replica; with a shared store it is this replica's
    /// reconciled view.
    pub fn tenant_totals(
        &self,
        tenant: &str,
        dimension: WindowDimension,
        window: WindowKey,
    ) -> Vec<(String, u64)> {
        let buckets = self.inner.lock_buckets();
        let mut totals: Vec<(String, u64)> = buckets
            .by_key
            .iter()
            .filter(|((key, dim, win), _)| {
                *dim == dimension && *win == window && key.is_for_tenant(tenant)
            })
            .map(|((key, _, _), bucket)| (key.route().to_string(), bucket.used()))
            .collect();
        totals.sort_by(|a, b| a.0.cmp(&b.0));
        totals
    }

    /// Count an admission and warn if the accumulator is past its
    /// reconciliation bound. Returns whether it was.
    pub fn note_admission(&self, now: SystemTime) -> bool {
        self.inner.note_admission(now)
    }

    pub fn unreconciled_admissions(&self) -> u64 {
        self.inner.unreconciled_admissions.load(Ordering::Relaxed)
    }

    /// Time since the last successful reconcile, or since construction if
    /// none has succeeded.
    pub fn reconciliation_age(&self, now: SystemTime) -> Duration {
        self.inner.reconciliation_age(now)
    }

    /// Export [`Self::reconciliation_age`] as the `rate_window` series of
    /// `llmproxy_counter_reconciliation_age_seconds` under this accumulator's
    /// scope. The flusher updates it after every tick. Idempotent.
    pub fn export_reconciliation_age(&self, registry: Arc<Registry>) {
        let gauge = self.inner.age_gauge.get_or_init(|| {
            ReconciliationAgeGauge::new(registry, &self.inner.scope, Seam::RateWindow)
        });
        gauge.publish(self.inner.reconciliation_age(SystemTime::now()));
    }

    /// Set the exported gauge to the age as of `now`. A no-op until
    /// [`Self::export_reconciliation_age`] has run.
    pub fn publish_reconciliation_age(&self, now: SystemTime) {
        self.inner.publish_age(now);
    }

    /// Reconcile every bucket with the store once. See [`Inner::flush_at`].
    pub fn flush_at(&self, now: SystemTime) -> Result<(), StoreError> {
        self.inner.flush_at(now)
    }

    pub fn flush_now(&self) -> Result<(), StoreError> {
        self.inner.flush_at(SystemTime::now())
    }

    /// Start the control-side flusher thread. Idempotent.
    pub fn start_flusher(&self, interval: Duration) {
        let mut flusher = self.flusher.lock().unwrap_or_else(PoisonError::into_inner);
        if flusher.is_some() {
            return;
        }
        let inner = Arc::clone(&self.inner);
        let handle = std::thread::Builder::new()
            .name("rate-window-flusher".to_string())
            .spawn(move || inner.run_flusher(interval))
            .expect("spawning the rate-window flusher thread");
        *flusher = Some(handle);
    }

    #[cfg(test)]
    fn tracked_buckets(&self) -> usize {
        self.inner.lock_buckets().by_key.len()
    }
}

impl Drop for WindowAccumulator {
    /// Stop the flusher, then deliver what was counted since its last tick.
    fn drop(&mut self) {
        {
            let mut state = self
                .inner
                .signal
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.shutdown = true;
            self.inner.signal.cond.notify_all();
        }
        let handle = self
            .flusher
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
        if let Err(e) = self.inner.flush_at(SystemTime::now()) {
            tracing::warn!(error = %e, scope = %self.inner.scope,
                "llmproxy.token_limit: the final rate-window flush failed; counts since the last \
                 reconcile are lost");
        }
    }
}

/// A quarter of the remaining allowance is pending (addendum §2).
fn needs_early_flush(bucket: &Bucket, limit: u64) -> bool {
    let remaining = limit.saturating_sub(bucket.base);
    bucket.pending.saturating_mul(4) > remaining
}

fn row_of(key: &BucketKey) -> WindowRow {
    WindowRow {
        subject: key.0.to_string(),
        dimension: key.1,
        window: key.2,
    }
}

impl Inner {
    fn lock_buckets(&self) -> std::sync::MutexGuard<'_, Buckets> {
        self.buckets.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn request_early_flush(&self) {
        if self.wake_requested.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut state = self
            .signal
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.wake = true;
        self.signal.cond.notify_one();
    }

    fn publish_age(&self, now: SystemTime) {
        if let Some(gauge) = self.age_gauge.get() {
            gauge.publish(self.reconciliation_age(now));
        }
    }

    fn reconciliation_age(&self, now: SystemTime) -> Duration {
        let last = self.last_flush_millis.load(Ordering::Acquire);
        let since = if last == NEVER {
            self.created_at_millis
        } else {
            last
        };
        let age = unix_millis(now).saturating_sub(since).max(0);
        Duration::from_millis(age as u64)
    }

    fn note_admission(&self, now: SystemTime) -> bool {
        let age = self.reconciliation_age(now);
        if age <= self.bound {
            return false;
        }
        let count = self.unreconciled_admissions.fetch_add(1, Ordering::Relaxed) + 1;
        if self.stale_warn_due(now) {
            tracing::warn!(
                scope = %self.scope,
                reconciliation_age_seconds = age.as_secs(),
                unreconciled_admissions = count,
                "llmproxy.token_limit: rate-limit counters have not reconciled with the store \
                 within the bound; admitting against the last known fleet totals (fail open)"
            );
        }
        true
    }

    /// True at most once per [`STALE_WARN_INTERVAL`].
    fn stale_warn_due(&self, now: SystemTime) -> bool {
        let now = unix_millis(now);
        let last = self.last_stale_warn_millis.load(Ordering::Acquire);
        let interval = STALE_WARN_INTERVAL.as_millis() as i64;
        if last != NEVER && now.saturating_sub(last) < interval {
            return false;
        }
        self.last_stale_warn_millis
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn run_flusher(&self, interval: Duration) {
        loop {
            {
                let mut state = self
                    .signal
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if !state.wake && !state.shutdown {
                    state = self
                        .signal
                        .cond
                        .wait_timeout(state, interval)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
                if state.shutdown {
                    return;
                }
                state.wake = false;
            }
            self.wake_requested.store(false, Ordering::Release);
            let now = SystemTime::now();
            if let Err(e) = self.flush_at(now) {
                if self.stale_warn_due(now) {
                    tracing::warn!(error = %e, scope = %self.scope,
                        reconciliation_age_seconds = self.reconciliation_age(now).as_secs(),
                        "llmproxy.token_limit: rate-window reconcile failed; enforcing against \
                         the last known fleet totals");
                }
            }
            self.publish_age(SystemTime::now());
        }
    }

    /// One reconcile: deliver every bucket's pending count as an additive,
    /// sequenced delta, read back the total for buckets with nothing
    /// pending, adopt each total as the new base, and drop buckets whose
    /// window has ended with nothing left to deliver. Store calls run without
    /// the bucket lock, so admission never waits on the store.
    fn flush_at(&self, now: SystemTime) -> Result<(), StoreError> {
        let _flush = self
            .flush_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now_secs = unix_secs(now);

        let mut deliveries: Vec<(BucketKey, FlushAttempt)> = Vec::new();
        let mut unseeded: Vec<BucketKey> = Vec::new();
        let mut reads: Vec<BucketKey> = Vec::new();
        {
            let mut buckets = self.lock_buckets();
            for (key, bucket) in buckets.by_key.iter_mut() {
                if bucket.attempt.is_some() || bucket.pending > 0 {
                    match (bucket.attempt, bucket.next_seq) {
                        (Some(attempt), _) => deliveries.push((key.clone(), attempt)),
                        (None, Some(seq)) => {
                            let attempt = FlushAttempt {
                                seq,
                                delta: bucket.pending,
                            };
                            bucket.attempt = Some(attempt);
                            deliveries.push((key.clone(), attempt));
                        }
                        (None, None) => unseeded.push(key.clone()),
                    }
                } else if key.2.end_secs() > now_secs {
                    reads.push(key.clone());
                }
            }
        }

        let mut first_error: Option<StoreError> = None;

        if !unseeded.is_empty() {
            let rows: Vec<WindowRow> = unseeded.iter().map(row_of).collect();
            let results = self
                .store
                .last_window_seq_batch(&self.scope, &self.node_id, &rows);
            let mut buckets = self.lock_buckets();
            for (key, result) in unseeded.into_iter().zip(results) {
                match result {
                    Ok(last) => {
                        if let Some(bucket) = buckets.by_key.get_mut(&key) {
                            let seq = last.saturating_add(1);
                            bucket.next_seq = Some(seq);
                            if bucket.attempt.is_none() && bucket.pending > 0 {
                                let attempt = FlushAttempt {
                                    seq,
                                    delta: bucket.pending,
                                };
                                bucket.attempt = Some(attempt);
                                deliveries.push((key, attempt));
                            }
                        }
                    }
                    Err(e) => {
                        first_error.get_or_insert(e);
                    }
                }
            }
        }

        if !deliveries.is_empty() {
            let rows: Vec<WindowRow> = deliveries.iter().map(|(key, _)| row_of(key)).collect();
            let deltas: Vec<WindowDelta<'_>> = rows
                .iter()
                .zip(&deliveries)
                .map(|(row, (_, attempt))| WindowDelta {
                    row,
                    delta: attempt.delta,
                    seq: attempt.seq,
                })
                .collect();
            let results = self
                .store
                .add_window_batch(&self.scope, &self.node_id, &deltas);
            let mut buckets = self.lock_buckets();
            for ((key, attempt), result) in deliveries.iter().zip(results) {
                match result {
                    Ok(total) => {
                        if let Some(bucket) = buckets.by_key.get_mut(key) {
                            if bucket.attempt == Some(*attempt) {
                                bucket.base = total;
                                bucket.pending = bucket.pending.saturating_sub(attempt.delta);
                                bucket.next_seq = Some(attempt.seq.saturating_add(1));
                                bucket.attempt = None;
                            }
                        }
                    }
                    // Kept frozen: the next tick retries the same seq and
                    // delta, which the store applies at most once.
                    Err(e) => {
                        first_error.get_or_insert(e);
                    }
                }
            }
        }

        if !reads.is_empty() {
            let rows: Vec<WindowRow> = reads.iter().map(row_of).collect();
            let results = self.store.load_window_batch(&self.scope, &rows);
            let mut buckets = self.lock_buckets();
            for (key, result) in reads.iter().zip(results) {
                match result {
                    Ok(total) => {
                        if let Some(bucket) = buckets.by_key.get_mut(key) {
                            // A count recorded since the read was collected is
                            // still in `pending`, so adopting the store's total
                            // as `base` loses nothing.
                            if bucket.attempt.is_none() {
                                bucket.base = total;
                            }
                        }
                    }
                    Err(e) => {
                        first_error.get_or_insert(e);
                    }
                }
            }
        }

        {
            let mut buckets = self.lock_buckets();
            let ended: Vec<BucketKey> = buckets
                .by_key
                .iter()
                .filter(|(key, bucket)| {
                    key.2.end_secs() <= now_secs && bucket.pending == 0 && bucket.attempt.is_none()
                })
                .map(|(key, _)| key.clone())
                .collect();
            for key in &ended {
                buckets.remove(key);
            }
        }

        match first_error {
            None => {
                self.last_flush_millis
                    .store(unix_millis(now), Ordering::Release);
                Ok(())
            }
            Some(e) => Err(e),
        }
    }
}

// ------------------------------------------------------- stream leases --

/// One replica's in-flight stream count for one subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRow {
    pub subject: String,
    pub in_flight: u64,
}

/// The fleet sum of unexpired lease rows, by subject, for every subject in
/// one scope that has at least one such row.
pub type FleetLeases = HashMap<String, u64>;

/// Tier-4 seam (ADR-0006 amendment E): per-replica lease rows with a TTL.
/// Each publish writes this replica's count per subject (zero removes the
/// row) and returns [`FleetLeases`] for the whole scope, including subjects
/// this replica did not publish. A crashed replica's rows expire one TTL
/// after its last publish, so no reaper is needed.
///
/// The answer covers the whole scope, not only the rows written, so a
/// replica that has never served a subject still knows what the fleet
/// holds for it. Without that, its first stream for the subject reads zero
/// others and is admitted while other replicas hold the whole ceiling, and
/// the over-admission lasts as long as that stream.
pub trait LeaseStore: Send + Sync {
    fn publish_leases(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[LeaseRow],
        ttl: Duration,
    ) -> Result<FleetLeases, StoreError>;
}

/// [`LeaseStore`] for one process. It still keeps rows per node id with
/// their TTL, so its contract matches a shared implementation.
#[derive(Default)]
pub struct InMemoryLeaseStore {
    rows: Mutex<HashMap<(String, String), NodeLeases>>,
}

/// Per node id: the published in-flight count and when it expires.
type NodeLeases = HashMap<String, (u64, Instant)>;

impl LeaseStore for InMemoryLeaseStore {
    fn publish_leases(
        &self,
        scope: &str,
        node_id: &str,
        rows: &[LeaseRow],
        ttl: Duration,
    ) -> Result<FleetLeases, StoreError> {
        let now = Instant::now();
        let mut all = self.rows.lock().unwrap_or_else(PoisonError::into_inner);
        for row in rows {
            let nodes = all
                .entry((scope.to_string(), row.subject.clone()))
                .or_default();
            if row.in_flight == 0 {
                nodes.remove(node_id);
            } else {
                nodes.insert(node_id.to_string(), (row.in_flight, now + ttl));
            }
        }
        let mut fleet = FleetLeases::new();
        all.retain(|(row_scope, subject), nodes| {
            nodes.retain(|_, (_, expires)| *expires > now);
            if row_scope == scope && !nodes.is_empty() {
                let sum = nodes
                    .values()
                    .fold(0u64, |acc, (count, _)| acc.saturating_add(*count));
                fleet.insert(subject.clone(), sum);
            }
            !nodes.is_empty()
        });
        Ok(fleet)
    }
}

#[derive(Debug, Default)]
struct Slot {
    /// Streams this replica holds now.
    local: u32,
    /// The fleet sum minus this replica's own published count, as of the
    /// last publish.
    others: u64,
    /// The count this replica last published.
    published: u64,
}

#[derive(Default)]
struct Slots {
    by_key: HashMap<LimitKey, Slot>,
    /// The fleet sums of the last publish for subjects this replica holds no
    /// slot for. A new slot starts from its entry here, so the first stream
    /// a replica sees for a subject still counts the rest of the fleet.
    unserved: FleetLeases,
    credential_entries: usize,
    overflow_warned: bool,
}

struct GaugeInner {
    scope: String,
    node_id: String,
    store: Arc<dyn LeaseStore>,
    ttl: Duration,
    slots: Mutex<Slots>,
    signal: Signal,
    created_at_millis: i64,
    last_publish_millis: AtomicI64,
    last_stale_warn_millis: AtomicI64,
    age_gauge: OnceLock<ReconciliationAgeGauge>,
}

/// Tier-4 concurrent-stream gauges for one filter chain. See the module doc.
pub struct LeaseGauge {
    inner: Arc<GaugeInner>,
    publisher: Mutex<Option<JoinHandle<()>>>,
}

impl LeaseGauge {
    /// `ttl` should be at least three publish intervals (addendum §3).
    pub fn new(scope: String, store: Arc<dyn LeaseStore>, node_id: String, ttl: Duration) -> Self {
        LeaseGauge {
            inner: Arc::new(GaugeInner {
                scope,
                node_id,
                store,
                ttl,
                slots: Mutex::new(Slots::default()),
                signal: Signal::default(),
                created_at_millis: unix_millis(SystemTime::now()),
                last_publish_millis: AtomicI64::new(NEVER),
                last_stale_warn_millis: AtomicI64::new(NEVER),
                age_gauge: OnceLock::new(),
            }),
            publisher: Mutex::new(None),
        }
    }

    /// Admit one stream if `local + others_last_known < max_streams`. The
    /// returned lease frees the slot when dropped, on every way a stream can
    /// end.
    pub fn try_acquire(
        &self,
        key: &LimitKey,
        max_streams: u32,
    ) -> Result<StreamLease, LimitDecision> {
        let (outcome, first_fold) = {
            let mut slots = self.inner.lock_slots();
            let overflow = key.is_credential()
                && !slots.by_key.contains_key(key)
                && slots.credential_entries >= MAX_CREDENTIAL_WINDOWS;
            let first_fold = overflow && !std::mem::replace(&mut slots.overflow_warned, true);
            let key = if overflow {
                key.credential_overflow()
            } else {
                key.clone()
            };
            let is_new = !slots.by_key.contains_key(&key);
            let (local, others) = match slots.by_key.get(&key) {
                Some(slot) => (slot.local, slot.others),
                None if slots.unserved.is_empty() => (0, 0),
                None => (
                    0,
                    slots.unserved.get(&key.to_string()).copied().unwrap_or(0),
                ),
            };
            let in_use = u64::from(local).saturating_add(others);
            let outcome = if in_use >= u64::from(max_streams) {
                Err(LimitDecision::Deny {
                    limit: u64::from(max_streams),
                    remaining: 0,
                    reset_after: STREAM_RETRY_HINT,
                    retry_after: STREAM_RETRY_HINT,
                })
            } else {
                if is_new && key.is_credential() {
                    slots.credential_entries += 1;
                }
                let slot = slots.by_key.entry(key.clone()).or_default();
                slot.local = slot.local.saturating_add(1);
                slot.others = others;
                Ok(StreamLease::new(
                    key,
                    Arc::clone(&self.inner) as Arc<dyn LeaseRelease>,
                ))
            };
            (outcome, first_fold)
        };
        if first_fold {
            warn_overflow_fold();
        }
        outcome
    }

    /// Publish this replica's counts once. See [`GaugeInner::publish_at`].
    pub fn publish_now(&self) -> Result<(), StoreError> {
        self.inner.publish_at(SystemTime::now())
    }

    /// Time since the last successful lease publish, or since construction
    /// if none has succeeded: how stale `others_last_known` may be.
    pub fn reconciliation_age(&self, now: SystemTime) -> Duration {
        self.inner.reconciliation_age(now)
    }

    /// Export [`Self::reconciliation_age`] as the `stream_lease` series of
    /// `llmproxy_counter_reconciliation_age_seconds` under this gauge's
    /// scope. The publisher updates it after every tick. Idempotent.
    pub fn export_reconciliation_age(&self, registry: Arc<Registry>) {
        let gauge = self.inner.age_gauge.get_or_init(|| {
            ReconciliationAgeGauge::new(registry, &self.inner.scope, Seam::StreamLease)
        });
        gauge.publish(self.inner.reconciliation_age(SystemTime::now()));
    }

    /// Set the exported gauge to the age as of `now`. A no-op until
    /// [`Self::export_reconciliation_age`] has run.
    pub fn publish_reconciliation_age(&self, now: SystemTime) {
        self.inner.publish_age(now);
    }

    /// Start the control-side publisher thread. Idempotent.
    pub fn start_publisher(&self, interval: Duration) {
        let mut publisher = self
            .publisher
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if publisher.is_some() {
            return;
        }
        let inner = Arc::clone(&self.inner);
        let handle = std::thread::Builder::new()
            .name("stream-lease-publisher".to_string())
            .spawn(move || inner.run_publisher(interval))
            .expect("spawning the stream-lease publisher thread");
        *publisher = Some(handle);
    }

    #[cfg(test)]
    fn tracked_slots(&self) -> usize {
        self.inner.lock_slots().by_key.len()
    }
}

impl Drop for LeaseGauge {
    /// Stop the publisher. Rows this replica published expire one TTL later.
    fn drop(&mut self) {
        {
            let mut state = self
                .inner
                .signal
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.shutdown = true;
            self.inner.signal.cond.notify_all();
        }
        let handle = self
            .publisher
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

impl LeaseRelease for GaugeInner {
    fn release(&self, key: &LimitKey) {
        // Runs from `StreamLease::drop`, possibly while a panic is already
        // unwinding; a second panic there aborts the process, so recover the
        // slots from a poisoned lock instead of unwrapping.
        let mut slots = self.lock_slots();
        let remove = match slots.by_key.get_mut(key) {
            Some(slot) => {
                slot.local = slot.local.saturating_sub(1);
                slot.local == 0 && slot.others == 0 && slot.published == 0
            }
            None => false,
        };
        if remove {
            slots.by_key.remove(key);
            if key.is_credential() {
                slots.credential_entries = slots.credential_entries.saturating_sub(1);
            }
        }
    }
}

impl GaugeInner {
    fn lock_slots(&self) -> std::sync::MutexGuard<'_, Slots> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn reconciliation_age(&self, now: SystemTime) -> Duration {
        let last = self.last_publish_millis.load(Ordering::Acquire);
        let since = if last == NEVER {
            self.created_at_millis
        } else {
            last
        };
        Duration::from_millis(unix_millis(now).saturating_sub(since).max(0) as u64)
    }

    fn publish_age(&self, now: SystemTime) {
        if let Some(gauge) = self.age_gauge.get() {
            gauge.publish(self.reconciliation_age(now));
        }
    }

    fn run_publisher(&self, interval: Duration) {
        loop {
            {
                let state = self
                    .signal
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let state = if state.shutdown {
                    state
                } else {
                    self.signal
                        .cond
                        .wait_timeout(state, interval)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                };
                if state.shutdown {
                    return;
                }
            }
            let _ = self.tick(SystemTime::now());
        }
    }

    /// One publisher tick: publish, export the age, and on a failure warn at
    /// most once per [`STALE_WARN_INTERVAL`]. Admission is unaffected either
    /// way: it fails open against the last known fleet counts.
    fn tick(&self, now: SystemTime) -> Result<(), StoreError> {
        let published = self.publish_at(now);
        self.publish_age(SystemTime::now());
        if let Err(e) = &published {
            let lease_age = self.reconciliation_age(now);
            let warn_last = self.last_stale_warn_millis.load(Ordering::Acquire);
            let now_ms = unix_millis(now);
            if warn_last == NEVER
                || now_ms.saturating_sub(warn_last) >= STALE_WARN_INTERVAL.as_millis() as i64
            {
                self.last_stale_warn_millis.store(now_ms, Ordering::Release);
                tracing::warn!(error = %e, scope = %self.scope,
                    lease_age_seconds = lease_age.as_secs(),
                    "llmproxy.token_limit: stream-lease publish failed; enforcing concurrency \
                     against the last known fleet counts (fail open)");
            }
        }
        published
    }

    /// Publish every slot's local count (including a final zero for a slot
    /// that has gone idle), adopt `fleet_sum - own` as `others`, keep the
    /// fleet sums of subjects with no slot here as `unserved`, and drop slots
    /// with nothing local, nothing elsewhere and nothing published.
    ///
    /// Publishes even with no slots: that read is how a replica learns what
    /// the fleet holds for subjects it has not served yet.
    fn publish_at(&self, now: SystemTime) -> Result<(), StoreError> {
        let rows: Vec<(LimitKey, LeaseRow)> = {
            let slots = self.lock_slots();
            slots
                .by_key
                .iter()
                .filter(|(_, slot)| slot.local > 0 || slot.published > 0 || slot.others > 0)
                .map(|(key, slot)| {
                    (
                        key.clone(),
                        LeaseRow {
                            subject: key.to_string(),
                            in_flight: u64::from(slot.local),
                        },
                    )
                })
                .collect()
        };
        let lease_rows: Vec<LeaseRow> = rows.iter().map(|(_, row)| row.clone()).collect();
        let mut fleet =
            self.store
                .publish_leases(&self.scope, &self.node_id, &lease_rows, self.ttl)?;
        let mut slots = self.lock_slots();
        for (key, row) in &rows {
            if let Some(slot) = slots.by_key.get_mut(key) {
                slot.published = row.in_flight;
                slot.others = fleet
                    .get(&row.subject)
                    .copied()
                    .unwrap_or(0)
                    .saturating_sub(row.in_flight);
            }
        }
        let idle: Vec<LimitKey> = slots
            .by_key
            .iter()
            .filter(|(_, slot)| slot.local == 0 && slot.others == 0 && slot.published == 0)
            .map(|(key, _)| key.clone())
            .collect();
        for key in idle {
            slots.by_key.remove(&key);
            if key.is_credential() {
                slots.credential_entries = slots.credential_entries.saturating_sub(1);
            }
        }
        // A slot opened while the publish was in flight took its `others`
        // from the previous `unserved`; it is published on the next tick.
        for key in slots.by_key.keys() {
            fleet.remove(&key.to_string());
        }
        slots.unserved = fleet;
        drop(slots);
        self.last_publish_millis
            .store(unix_millis(now), Ordering::Release);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::InMemoryControlPlaneStore;

    const MINUTE: u64 = 60;

    /// 20 seconds into a minute.
    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000 + 20)
    }

    fn window_at(now: SystemTime) -> WindowKey {
        WindowKey::containing(unix_secs(now), MINUTE)
    }

    fn accumulator(store: &Arc<InMemoryControlPlaneStore>, node: &str) -> WindowAccumulator {
        WindowAccumulator::with_reconciliation_bound(
            "chain".to_string(),
            Arc::clone(store) as Arc<dyn ControlPlaneStore>,
            node.to_string(),
            Duration::MAX,
        )
    }

    fn tenant(route: &str, tenant: &str) -> LimitKey {
        LimitKey::for_tenant(route, tenant)
    }

    const TOTAL: WindowDimension = WindowDimension::TotalTokens;
    const REQUESTS: WindowDimension = WindowDimension::Requests;

    #[test]
    fn admission_reads_local_counts_and_a_refusal_is_not_counted() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let acc = accumulator(&store, "a");
        let key = tenant("r", "t");
        let w = window_at(t0());

        assert_eq!(
            acc.admit(&key, REQUESTS, w, 2),
            Admission::Admitted { used: 1 }
        );
        assert_eq!(
            acc.admit(&key, REQUESTS, w, 2),
            Admission::Admitted { used: 2 }
        );
        assert_eq!(
            acc.admit(&key, REQUESTS, w, 2),
            Admission::Refused { used: 2 }
        );
        assert_eq!(
            acc.admit(&key, REQUESTS, w, 2),
            Admission::Refused { used: 2 }
        );
        // Token and request counters for one key are separate rows.
        assert_eq!(acc.used(&key, TOTAL, w), 0);
        acc.add(&key, TOTAL, w, 7, 100);
        assert_eq!(acc.used(&key, TOTAL, w), 7);
        assert_eq!(acc.used(&key, REQUESTS, w), 2);
    }

    #[test]
    fn a_new_epoch_window_starts_empty_and_an_ended_window_is_dropped() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let acc = accumulator(&store, "a");
        let key = tenant("r", "t");
        let w = window_at(t0());
        acc.add(&key, TOTAL, w, 10, 10);
        let next = window_at(t0() + Duration::from_secs(MINUTE));
        assert_ne!(next, w);
        assert_eq!(acc.used(&key, TOTAL, next), 0);

        // Delivered, then past its end: nothing is left to keep.
        acc.flush_at(t0()).unwrap();
        assert_eq!(acc.tracked_buckets(), 1);
        acc.flush_at(t0() + Duration::from_secs(MINUTE)).unwrap();
        assert_eq!(acc.tracked_buckets(), 0);
    }

    #[test]
    fn two_replicas_sharing_one_store_converge_on_the_fleet_total() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let a = accumulator(&store, "a");
        let b = accumulator(&store, "b");
        let key = tenant("r", "t");
        let w = window_at(t0());

        a.add(&key, TOTAL, w, 30, 1_000);
        b.add(&key, TOTAL, w, 12, 1_000);
        a.flush_at(t0()).unwrap();
        b.flush_at(t0()).unwrap();
        // `a` delivered before `b`, so it learns `b`'s share on its next read.
        a.flush_at(t0()).unwrap();
        assert_eq!(a.used(&key, TOTAL, w), 42);
        assert_eq!(b.used(&key, TOTAL, w), 42);

        // Counts recorded after a reconcile stay local until the next one.
        a.add(&key, TOTAL, w, 1, 1_000);
        assert_eq!(a.used(&key, TOTAL, w), 43);
        assert_eq!(b.used(&key, TOTAL, w), 42);
    }

    #[test]
    fn repeated_flushes_never_count_a_delivery_twice() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let acc = accumulator(&store, "a");
        let key = tenant("r", "t");
        let w = window_at(t0());
        acc.add(&key, TOTAL, w, 5, 100);
        for _ in 0..3 {
            acc.flush_at(t0()).unwrap();
        }
        assert_eq!(acc.used(&key, TOTAL, w), 5);
        let row = WindowRow {
            subject: key.to_string(),
            dimension: TOTAL,
            window: w,
        };
        assert_eq!(store.load_window_batch("chain", &[row])[0], Ok(5));
    }

    #[test]
    fn dropping_an_accumulator_delivers_what_it_counted() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let key = tenant("r", "t");
        // A real clock: Drop flushes at the real time.
        let w = window_at(SystemTime::now());
        {
            let acc = accumulator(&store, "a");
            acc.add(&key, TOTAL, w, 9, 100);
        }
        let row = WindowRow {
            subject: key.to_string(),
            dimension: TOTAL,
            window: w,
        };
        assert_eq!(store.load_window_batch("chain", &[row])[0], Ok(9));
    }

    #[test]
    fn a_quarter_of_the_remaining_allowance_wakes_the_flusher_early() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let acc = accumulator(&store, "a");
        let key = tenant("r", "t");
        let w = window_at(t0());
        acc.add(&key, TOTAL, w, 25, 100);
        assert!(
            !acc.inner.wake_requested.load(Ordering::Acquire),
            "exactly a quarter"
        );
        acc.add(&key, TOTAL, w, 1, 100);
        assert!(acc.inner.wake_requested.load(Ordering::Acquire));
    }

    #[test]
    fn tenant_totals_list_only_that_tenants_route_buckets_in_route_order() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let acc = accumulator(&store, "a");
        let w = window_at(t0());
        acc.add(&tenant("images", "acme"), TOTAL, w, 5, 100);
        acc.add(&tenant("chat", "acme"), TOTAL, w, 7, 100);
        acc.add(&tenant("chat", "other"), TOTAL, w, 99, 100);
        acc.add(&LimitKey::for_credential("chat", "sk-1"), TOTAL, w, 1, 100);
        acc.add(&LimitKey::for_tenant_policy("acme"), TOTAL, w, 3, 100);
        assert_eq!(
            acc.tenant_totals("acme", TOTAL, w),
            vec![("chat".to_string(), 7), ("images".to_string(), 5)]
        );
    }

    #[test]
    fn credentials_past_the_cap_share_one_overflow_counter_per_route() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let acc = accumulator(&store, "a");
        let w = window_at(t0());
        for i in 0..MAX_CREDENTIAL_WINDOWS {
            acc.add(
                &LimitKey::for_credential("r", &format!("sk-{i}")),
                TOTAL,
                w,
                1,
                100,
            );
        }
        let late_1 = LimitKey::for_credential("r", "sk-late-1");
        let late_2 = LimitKey::for_credential("r", "sk-late-2");
        acc.add(&late_1, TOTAL, w, 4, 100);
        assert_eq!(
            acc.used(&late_2, TOTAL, w),
            4,
            "both fold into the overflow bucket"
        );
        assert_eq!(acc.tracked_buckets(), MAX_CREDENTIAL_WINDOWS + 1);
    }

    #[test]
    fn admissions_count_as_unreconciled_only_past_the_bound() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let acc = WindowAccumulator::with_reconciliation_bound(
            "chain".to_string(),
            Arc::clone(&store) as Arc<dyn ControlPlaneStore>,
            "a".to_string(),
            Duration::from_secs(10),
        );
        let now = SystemTime::now();
        assert!(!acc.note_admission(now));
        let later = now + Duration::from_secs(11);
        assert!(acc.note_admission(later));
        assert_eq!(acc.unreconciled_admissions(), 1);
        acc.flush_at(later).unwrap();
        assert!(!acc.note_admission(later));
        assert_eq!(acc.unreconciled_admissions(), 1);
    }

    // --- stream leases --------------------------------------------------

    fn gauge(store: &Arc<InMemoryLeaseStore>, node: &str, ttl: Duration) -> LeaseGauge {
        LeaseGauge::new(
            "chain".to_string(),
            Arc::clone(store) as Arc<dyn LeaseStore>,
            node.to_string(),
            ttl,
        )
    }

    #[test]
    fn a_lease_holds_a_slot_until_it_is_dropped() {
        let store = Arc::new(InMemoryLeaseStore::default());
        let g = gauge(&store, "a", Duration::from_secs(3));
        let key = tenant("", "t");
        let first = g.try_acquire(&key, 2).expect("slot 1");
        let second = g.try_acquire(&key, 2).expect("slot 2");
        assert!(g.try_acquire(&key, 2).is_err());
        drop(first);
        let third = g
            .try_acquire(&key, 2)
            .expect("a dropped lease frees its slot");
        drop((second, third));
        assert_eq!(g.tracked_slots(), 0, "an idle, unpublished slot is dropped");

        fn assert_send<T: Send>() {}
        assert_send::<StreamLease>();
    }

    #[test]
    fn a_replica_counts_the_streams_other_replicas_published() {
        let store = Arc::new(InMemoryLeaseStore::default());
        let a = gauge(&store, "a", Duration::from_secs(30));
        let b = gauge(&store, "b", Duration::from_secs(30));
        let key = tenant("", "t");
        let _held = [
            a.try_acquire(&key, 3).unwrap(),
            a.try_acquire(&key, 3).unwrap(),
        ];
        a.publish_now().unwrap();

        let _first = b.try_acquire(&key, 3).expect("nothing known yet");
        b.publish_now().unwrap();
        // b now knows of a's two streams: 1 local + 2 others = 3.
        assert!(b.try_acquire(&key, 3).is_err());
    }

    /// A replica learns the fleet's count for a subject it has never served
    /// from its own publish, so its first stream for that subject is refused
    /// while another replica holds the ceiling.
    #[test]
    fn a_replica_that_never_served_a_subject_counts_the_fleet_after_a_publish() {
        let store = Arc::new(InMemoryLeaseStore::default());
        let a = gauge(&store, "a", Duration::from_secs(30));
        let b = gauge(&store, "b", Duration::from_secs(30));
        let key = tenant("", "t");
        let held = a.try_acquire(&key, 1).unwrap();
        a.publish_now().unwrap();

        b.publish_now().unwrap();
        assert_eq!(b.tracked_slots(), 0, "b holds no slot for the subject");
        assert!(
            b.try_acquire(&key, 1).is_err(),
            "a holds the only slot, so b's first stream is refused"
        );
        assert!(
            b.try_acquire(&tenant("", "other"), 1).is_ok(),
            "a subject nobody holds is free"
        );
        // Under a ceiling of 2, b's first stream fits beside a's, and the
        // slot it opens keeps counting a's stream.
        let _mine = b.try_acquire(&key, 2).expect("1 elsewhere + 0 here < 2");
        assert!(
            b.try_acquire(&key, 2).is_err(),
            "1 elsewhere + 1 here reaches the ceiling of 2"
        );
        drop(_mine);

        drop(held);
        a.publish_now().unwrap();
        b.publish_now().unwrap();
        assert!(
            b.try_acquire(&key, 1).is_ok(),
            "once a releases and both publish, b admits"
        );
    }

    /// A failed publish keeps the last known fleet counts: enforcement fails
    /// open against them rather than forgetting them.
    #[test]
    fn a_failed_publish_keeps_the_last_known_fleet_counts() {
        let store = Arc::new(InMemoryLeaseStore::default());
        let a = gauge(&store, "a", Duration::from_secs(30));
        let key = tenant("", "t");
        let _held = a.try_acquire(&key, 1).unwrap();
        a.publish_now().unwrap();
        let flaky = Arc::new(FlakyLeaseStore {
            inner: Arc::clone(&store),
            fail: AtomicBool::new(false),
        });
        let b = LeaseGauge::new(
            "chain".to_string(),
            Arc::clone(&flaky) as Arc<dyn LeaseStore>,
            "b".to_string(),
            Duration::from_secs(30),
        );
        b.publish_now().unwrap();
        flaky.fail.store(true, Ordering::SeqCst);
        assert!(b.publish_now().is_err());
        assert!(
            b.try_acquire(&key, 1).is_err(),
            "the last known count still applies during the outage"
        );
    }

    /// A shared store that cannot be reached fails open, loudly: streams are
    /// still admitted up to the ceiling against local counts, every publish
    /// fails, and the warning is logged once per interval, not per tick. The
    /// store is the real Redis client pointed at a port nothing listens on.
    #[test]
    fn an_unreachable_redis_fails_open_and_warns_once_per_interval() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("reserve a port")
            .port();
        let store = crate::control_redis::RedisControlPlaneStore::open(&format!(
            "redis://:lease-test-password@127.0.0.1:{port}"
        ))
        .expect("open only parses the URL");
        let g = LeaseGauge::new(
            "ingress".to_string(),
            Arc::new(store),
            "a".to_string(),
            Duration::from_secs(3),
        );
        let key = tenant("", "acme");
        let (capture, _guard) = crate::control::log_capture::Capture::start();

        let _first = g.try_acquire(&key, 2).expect("fails open: admitted");
        let _second = g.try_acquire(&key, 2).expect("fails open: admitted");
        assert!(
            g.try_acquire(&key, 2).is_err(),
            "the local count still enforces the ceiling"
        );

        let now = SystemTime::now();
        for tick in 0..5 {
            assert!(
                g.inner.tick(now + Duration::from_secs(tick)).is_err(),
                "nothing listens on the port"
            );
        }
        let warned = || capture.rendered_at_or_above(tracing::Level::WARN);
        assert_eq!(warned().len(), 1, "one warning for five failed ticks");
        let line = &warned()[0];
        assert!(
            line.contains("fail open") && line.contains("scope=ingress"),
            "{line}"
        );
        assert!(
            !line.contains("lease-test-password"),
            "the Redis URL's password never reaches the log: {line}"
        );

        assert!(g.inner.tick(now + STALE_WARN_INTERVAL).is_err());
        assert_eq!(
            warned().len(),
            2,
            "a still-failing store warns again an interval later"
        );
    }

    struct FlakyLeaseStore {
        inner: Arc<InMemoryLeaseStore>,
        fail: AtomicBool,
    }

    impl LeaseStore for FlakyLeaseStore {
        fn publish_leases(
            &self,
            scope: &str,
            node_id: &str,
            rows: &[LeaseRow],
            ttl: Duration,
        ) -> Result<FleetLeases, StoreError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(StoreError::Unavailable("lease store down".into()));
            }
            self.inner.publish_leases(scope, node_id, rows, ttl)
        }
    }

    #[test]
    fn a_silent_replicas_leases_expire_after_the_ttl() {
        let store = Arc::new(InMemoryLeaseStore::default());
        let key = tenant("", "t");
        let a = gauge(&store, "a", Duration::from_millis(1));
        let held = a.try_acquire(&key, 1).unwrap();
        a.publish_now().unwrap();
        // `a` stops publishing, as a crashed replica would.
        std::mem::forget(held);
        std::mem::forget(a);
        std::thread::sleep(Duration::from_millis(5));

        let b = gauge(&store, "b", Duration::from_secs(30));
        let _mine = b.try_acquire(&key, 1).expect("b knows nothing yet");
        b.publish_now().unwrap();
        drop(_mine);
        b.publish_now().unwrap();
        assert!(
            b.try_acquire(&key, 1).is_ok(),
            "the silent replica's expired row no longer counts"
        );
    }

    // --- reconciliation-age gauges (ADR-0006 amendment F) ----------------------

    use crate::reconciliation_age::test_support::{rendered_age, wait_for_age};
    use crate::reconciliation_age::Seam;
    use crate::window_usage::test_store::ProbeStore;

    fn registry() -> Arc<Registry> {
        proxy_observability::stats::StatsControl::new(1).registry()
    }

    /// A window that has not ended, so every reconcile reads it back from
    /// the store whatever minute the test runs in.
    fn open_window() -> WindowKey {
        WindowKey::containing(unix_secs(SystemTime::now()) + 3_600, MINUTE)
    }

    #[test]
    fn the_rate_window_age_gauge_resets_on_a_reconcile_and_grows_while_the_store_fails() {
        let store = ProbeStore::default();
        let acc = WindowAccumulator::with_reconciliation_bound(
            "ingress".to_string(),
            Arc::new(store.clone()),
            "a".to_string(),
            Duration::MAX,
        );
        let registry = registry();
        acc.export_reconciliation_age(Arc::clone(&registry));
        let now = SystemTime::now();
        let age = || rendered_age(&registry, "ingress", Seam::RateWindow);

        acc.publish_reconciliation_age(now + Duration::from_secs(90));
        assert!(
            age().is_some_and(|age| age >= 90),
            "never reconciled: measured from construction, got {:?}",
            age()
        );

        acc.add(&tenant("chat", "acme"), TOTAL, open_window(), 5, 100);
        acc.flush_at(now).unwrap();
        acc.publish_reconciliation_age(now);
        assert_eq!(age(), Some(0));

        store.fail.store(true, Ordering::SeqCst);
        assert!(acc.flush_at(now).is_err(), "the read-back fails");
        acc.publish_reconciliation_age(now + Duration::from_secs(30));
        assert_eq!(age(), Some(30), "a failed reconcile does not reset the age");
    }

    /// The flusher thread publishes after every tick, including a failed one,
    /// so the outage shows without anything else calling the accumulator.
    #[test]
    fn the_flusher_publishes_the_rate_window_age_while_reconciles_fail() {
        let store = ProbeStore::default();
        let acc = WindowAccumulator::with_reconciliation_bound(
            "ingress".to_string(),
            Arc::new(store.clone()),
            "a".to_string(),
            Duration::MAX,
        );
        acc.add(&tenant("chat", "acme"), TOTAL, open_window(), 5, 100);
        acc.flush_now().unwrap();
        store.fail.store(true, Ordering::SeqCst);
        let registry = registry();
        acc.export_reconciliation_age(Arc::clone(&registry));

        acc.start_flusher(Duration::from_millis(20));

        assert!(wait_for_age(&registry, "ingress", Seam::RateWindow, 1));
        store.fail.store(false, Ordering::SeqCst);
    }

    struct FailingLeaseStore;

    impl LeaseStore for FailingLeaseStore {
        fn publish_leases(
            &self,
            _scope: &str,
            _node_id: &str,
            _rows: &[LeaseRow],
            _ttl: Duration,
        ) -> Result<FleetLeases, StoreError> {
            Err(StoreError::Unavailable("lease store down".into()))
        }
    }

    #[test]
    fn the_stream_lease_age_gauge_resets_on_a_publish() {
        let gauge = LeaseGauge::new(
            "ingress".to_string(),
            Arc::new(InMemoryLeaseStore::default()),
            "a".to_string(),
            Duration::from_secs(3),
        );
        let registry = registry();
        gauge.export_reconciliation_age(Arc::clone(&registry));
        let now = SystemTime::now();
        let age = || rendered_age(&registry, "ingress", Seam::StreamLease);

        gauge.publish_reconciliation_age(now + Duration::from_secs(90));
        assert!(age().is_some_and(|age| age >= 90), "got {:?}", age());

        let _lease = gauge.try_acquire(&tenant("", "acme"), 5).unwrap();
        gauge.publish_now().unwrap();
        gauge.publish_reconciliation_age(SystemTime::now());
        assert_eq!(age(), Some(0));
    }

    #[test]
    fn the_publisher_publishes_the_stream_lease_age_while_publishes_fail() {
        let gauge = LeaseGauge::new(
            "ingress".to_string(),
            Arc::new(FailingLeaseStore),
            "a".to_string(),
            Duration::from_secs(3),
        );
        let _lease = gauge.try_acquire(&tenant("", "acme"), 5).unwrap();
        let registry = registry();
        gauge.export_reconciliation_age(Arc::clone(&registry));

        gauge.start_publisher(Duration::from_millis(20));

        assert!(wait_for_age(&registry, "ingress", Seam::StreamLease, 1));
        assert!(gauge.reconciliation_age(SystemTime::now()) >= Duration::from_secs(1));
    }
}
