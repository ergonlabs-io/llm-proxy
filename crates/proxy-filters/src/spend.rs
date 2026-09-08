//! WP-50 increment 3c-i — the spend-budget filter's price table, as a pure
//! library. See `internal-docs/wp-50-3c-spend-budgets.md`, normative here.
//!
//! This module answers exactly one question: **what did this request cost?**
//! It does not touch `HttpFilter`, proto decoding, `StreamInfo`, or any
//! accumulation over time — those are [`crate::model_authz`]'s pattern
//! repeated for money: [`PriceTable`] and [`PriceTable::cost_of`] are the
//! pure core, and a later increment (3c-ii/iii) builds the filter that reads
//! `typed_config`, holds a shared accumulator, and enforces a ceiling.
//!
//! # Keyed on `(cluster, model)`, not `model` alone — CLAUDE.md ground rule 6
//!
//! This is the third documented instance of rule 6's hazard: a per-provider
//! value attached to the ROUTE (or, equivalently, resolved by model name
//! alone with no notion of which member served it) follows the routing
//! decision instead of the connection. The same model name can be served by
//! two clusters at two different prices — `gpt-4o` direct versus through a
//! discounted secondary — and a route only picks an *aggregate*; the cluster
//! is the *member* that actually gets dialled. A price that ignored which
//! cluster served the request would bill the primary's rate for a request a
//! fallback actually served, which is silently wrong billing that only shows
//! up on failover — the same shape as the credential and `host_rewrite_literal`
//! bugs rule 6 already names. [`PriceTable::cost_of`] therefore takes the
//! cluster *actually dialled* (a later increment resolves this from
//! `StreamInfo::upstream_cluster`, never from the route) as a first-class,
//! required-to-match input, not an afterthought.
//!
//! # Money is integer, never `f64`
//!
//! Every arithmetic operation in this module is on integers, in units of
//! **micro-dollars** (1e-6 USD, [`MicroUsd`]). Config supplies prices as
//! decimal strings (`"2.50"`) for operator readability; [`parse_micro_usd`]
//! parses each one EXACTLY ONCE, at load, into a `u64`. Binary floating point
//! does not round-trip decimal fractions — `0.1 + 0.2 != 0.3` in IEEE 754 —
//! and a spend ceiling (3c-iii) compared against a value that drifted through
//! repeated `f64` addition over millions of requests is an unreproducible
//! wrong answer, in the one subsystem whose entire job is to be right about
//! money. `f64` does not appear anywhere in this module; if a future edit
//! introduces one here, that is a bug.
//!
//! # Four buckets, priced independently
//!
//! Providers price standard input, cache-read input, cache-write input, and
//! output tokens independently — see [`crate::usage::TokenUsage`]'s doc.
//! [`PriceTable::cost_of`] charges each bucket at its own configured rate and
//! sums the (independently rounded) results; collapsing cached tokens into
//! the input rate would overcharge heavily on cache-heavy workloads, which is
//! exactly the workload this proxy attracts.
//!
//! # An unpriced `(cluster, model)` costs ZERO — and that is not the same as
//! a configured `"0.00"` rate
//!
//! Owner decision (see the design brief): a model or cluster with no
//! configured price is admitted and charged nothing, and this is the DEFINED
//! semantic, not a fallback from a failure — consistent with ground rule 17's
//! precedent that metering must not start refusing traffic. But "no price
//! configured" and "price configured as zero" are different facts an operator
//! may care to tell apart later (a 3c-ii/iii accumulator is expected to
//! report an unpriced-request count and the distinct unpriced `(cluster,
//! model)` pairs, so a config gap stays discoverable without reading logs).
//! [`Charge`] keeps them distinguishable: [`Charge::Unpriced`] is the former,
//! [`Charge::Priced`]`(MicroUsd(0))` is the latter. Collapsing them into one
//! "zero" would make that later reporting structurally impossible.
//!
//! # Rounding: half-up, ONCE per request, not per bucket
//!
//! At these rates, a single request's cost is routinely a fraction of a
//! micro-dollar (a $2.50-per-million-token rate charged against a 37-token
//! request is 92.5 ten-thousandths of a micro-dollar), so *some* rounding
//! decision is unavoidable once the result is forced into an integer.
//! Truncating (always rounding down) systematically UNDER-bills over millions
//! of requests — the same-direction error every time, compounding. `ceil`
//! (always rounding up) is the mirror-image bug: it would systematically
//! OVER-bill by the same mechanism, just in the other direction. Round-half-up
//! (ties away from zero) is the one option whose per-request rounding error
//! is not one-directional — over many requests, roughly as many round up as
//! round down, and the error cancels rather than accumulates.
//!
//! It is applied ONCE, to the sum of all four buckets' exact numerators —
//! never to each bucket separately. Rounding per bucket rounds up to four
//! times for one request, and on the small requests that dominate real
//! traffic that is a genuine overcharge rather than a rounding nicety: four
//! buckets each costing 0.6 micro-dollars are 2.4 micro-dollars in total, so
//! one rounding charges 2 and four roundings charge 4 — double. Each bucket
//! still gets its own independent RATE (see above); it is only the rounding
//! that is deferred. See [`bucket_numerator`] and [`round_once`].
//!
//! # `model` is an EXACT match here — no globs
//!
//! Deliberately unlike [`crate::model_authz`]'s `ModelPattern`, which allows
//! one trailing `*`. A glob that matched two models priced differently would
//! make the charged rate depend on iteration order over the configured price
//! list — an unreproducible wrong answer in the one subsystem that must never
//! produce one. So [`PriceTable`] is keyed on exact model strings, full stop.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

// WP-50 increment 3c-ii-b: UTC calendar-aligned period keys. `chrono` is
// already a workspace dependency (`proxy-cluster`, `proxy-observability`
// use it); this crate had no prior need for wall-clock rendering.
use chrono::{DateTime, Datelike, NaiveDate, Utc};

use crate::auth::TenantId;
use crate::control::{ControlPlaneStore, FlushToken, StoreError};
use crate::usage::TokenUsage;

/// An amount of money in integer micro-dollars (1e-6 USD). See the module
/// doc's "Money is integer, never `f64`" section for why.
///
/// Rust note: a newtype around `u64`, not a bare `u64` passed around — same
/// reasoning as `model_authz::ModelPattern`: a raw token count and a raw
/// money amount are both "just a `u64`" at the type level, and mixing them up
/// at a call site is exactly the kind of bug a newtype makes the compiler
/// catch instead of a reviewer. `u64` rather than `i64`: a price or a cost is
/// never negative in this module (negative prices are rejected by
/// [`parse_micro_usd`], and a cost is a sum of non-negative products), so the
/// sign bit `i64` would reserve is pure waste, and a `u64` overflow is a
/// harder, more obviously-wrong failure than an `i64` silently going negative
/// would be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct MicroUsd(u64);

impl MicroUsd {
    /// Construct directly from an already-computed micro-dollar amount.
    /// Public mainly for tests and for [`ModelPrices`] literals; production
    /// callers get a `MicroUsd` from [`parse_micro_usd`] or [`Charge`].
    pub const fn from_micros(micros: u64) -> Self {
        MicroUsd(micros)
    }

    /// The raw micro-dollar amount.
    pub const fn as_micros(&self) -> u64 {
        self.0
    }
}

/// Why [`parse_micro_usd`] rejected a configured price string.
///
/// Rust note: a plain enum with manual `Display`/`Error` impls, matching this
/// crate's existing style (see `token_limit::BudgetUnavailable`) rather than
/// pulling in a derive-macro error crate for one small type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsePriceError {
    /// The input was the empty string.
    Empty,
    /// The input started with `+` or `-`. Combined with rejecting anything
    /// that isn't an ASCII digit or `.` elsewhere, this is also how a
    /// negative price (e.g. `"-2.50"`) is refused — prices are never
    /// negative in this module.
    Signed,
    /// The input (outside of at most one `.`) contained a character that
    /// isn't an ASCII digit.
    NotNumeric,
    /// The fractional part had more than 6 digits. Rejected rather than
    /// truncated: silently dropping digits past the 6th is a silent pricing
    /// error nobody asked for, not a rounding an operator would expect.
    TooManyDecimalPlaces,
    /// The value is too large to represent in a `u64` count of
    /// micro-dollars.
    Overflow,
}

impl std::fmt::Display for ParsePriceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParsePriceError::Empty => write!(f, "price string is empty"),
            ParsePriceError::Signed => write!(f, "price string must not have a leading sign"),
            ParsePriceError::NotNumeric => write!(f, "price string is not a plain decimal number"),
            ParsePriceError::TooManyDecimalPlaces => {
                write!(f, "price string has more than 6 decimal places")
            }
            ParsePriceError::Overflow => write!(f, "price string is too large to represent"),
        }
    }
}

impl std::error::Error for ParsePriceError {}

/// Parses a decimal-string price (e.g. `"2.50"`, `"0.000001"`, or the
/// whole-dollar form `"3"`) into [`MicroUsd`]. See the module doc's "Money is
/// integer" section for why this exists instead of `str::parse::<f64>`.
///
/// A missing `.` is legal and means "a whole number of dollars" — `"3"` is
/// the same amount as `"3.00"` — because both are exact, unambiguous integer
/// readings of the string; there is no rounding decision to make either way.
/// Fewer than 6 digits after the `.` is legal and is zero-padded on the right
/// (`"2.5"` -> `2_500_000` micros): this is exact, not a truncation, since
/// appending zeros to a shorter decimal changes nothing about the value it
/// names. MORE than 6 digits after the `.` is rejected outright (see
/// [`ParsePriceError::TooManyDecimalPlaces`]) rather than truncated, because
/// dropping trailing digits silently would be a real, silent pricing error.
///
/// Rejects: the empty string, a leading `+`/`-` (so also every negative
/// price), any non-ASCII-digit character outside one decimal point, more
/// than one decimal point (caught as "not numeric" in the whole-part half),
/// more than 6 fractional digits, and any value whose integer micro-dollar
/// form would not fit in a `u64`.
pub fn parse_micro_usd(s: &str) -> Result<MicroUsd, ParsePriceError> {
    if s.is_empty() {
        return Err(ParsePriceError::Empty);
    }
    if s.starts_with('+') || s.starts_with('-') {
        return Err(ParsePriceError::Signed);
    }

    let (whole_str, frac_str) = match s.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (s, ""),
    };

    let is_digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    if !is_digits(whole_str) {
        // Also catches a bare "." (both halves empty) and a second "."
        // (whichever half absorbs it fails the all-digits check).
        return Err(ParsePriceError::NotNumeric);
    }
    if !frac_str.is_empty() && !frac_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParsePriceError::NotNumeric);
    }
    if frac_str.len() > 6 {
        return Err(ParsePriceError::TooManyDecimalPlaces);
    }

    let whole: u64 = whole_str.parse().map_err(|_| ParsePriceError::Overflow)?;
    // Zero-pad the fraction out to exactly 6 digits, then parse -- exact,
    // per the doc above, not a truncation.
    let mut frac_padded = frac_str.to_string();
    frac_padded.push_str(&"0".repeat(6 - frac_str.len()));
    let frac: u64 = frac_padded.parse().map_err(|_| ParsePriceError::Overflow)?;

    whole
        .checked_mul(1_000_000)
        .and_then(|dollars_in_micros| dollars_in_micros.checked_add(frac))
        .map(MicroUsd)
        .ok_or(ParsePriceError::Overflow)
}

/// One `(cluster, model)` pair's four independent per-1,000,000-token rates.
/// See the module doc's "Four buckets" section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ModelPrices {
    pub input_per_million: MicroUsd,
    pub output_per_million: MicroUsd,
    pub cached_per_million: MicroUsd,
    pub cache_creation_per_million: MicroUsd,
}

/// What one request cost, distinguishing "this rate is configured and
/// happens to be zero" from "no rate is configured at all". See the module
/// doc's "An unpriced ... costs ZERO" section for why collapsing these two
/// would break later reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// The `(cluster, model)` pair had a configured price (which may itself
    /// be `MicroUsd::from_micros(0)` — a deliberate free rate).
    Priced(MicroUsd),
    /// No price is configured for this exact `(cluster, model)` pair, or
    /// `cluster`/`model` was `None` (a request that never reached an
    /// upstream, or had no extractable model). Billed as zero, but kept
    /// distinct from `Priced(0)` — see the module doc.
    Unpriced,
}

/// The parsed `(cluster, model)` price lookup.
///
/// Rust note: `by_cluster` is a `HashMap<String, HashMap<String,
/// ModelPrices>>` -- nested, not a single `HashMap<(String, String),
/// ModelPrices>`. [`PriceTable::cost_of`] is meant to run on every priced
/// request once wired into a filter (3c-ii's hot path), and a flat
/// tuple-keyed map cannot be looked up by two borrowed `&str`s without
/// allocating a fresh owned `(String, String)` first -- a tuple's `Borrow`
/// impl does not let two owned `String`s be matched against two `&str`s the
/// way `HashMap<String, _>::get(&str)` can. Nesting looks up both levels by
/// `&str` with zero allocation, and it happens to mirror the actual config
/// shape one level deeper than the wire format collapses it: `ClusterPricing`
/// already groups a cluster's `ModelPrice`s together in `spend.proto`.
#[derive(Debug, Clone, Default)]
pub struct PriceTable {
    by_cluster: HashMap<String, HashMap<String, ModelPrices>>,
}

impl PriceTable {
    /// An empty table: every `(cluster, model)` pair is unpriced.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures `prices` for `(cluster, model)`, overwriting any price
    /// previously set for the same pair.
    pub fn insert(
        &mut self,
        cluster: impl Into<String>,
        model: impl Into<String>,
        prices: ModelPrices,
    ) {
        self.by_cluster
            .entry(cluster.into())
            .or_default()
            .insert(model.into(), prices);
    }

    /// What one request cost, given the cluster it was actually dialled
    /// against and its extracted model name.
    ///
    /// `cluster`/`model` are `Option<&str>` because either can be genuinely
    /// absent (a request refused before reaching an upstream has no dialled
    /// cluster; a request with no extractable model has no model) -- either
    /// `None` is [`Charge::Unpriced`], never an error. See the module doc's
    /// "Keyed on (cluster, model)" section for why BOTH must match a
    /// configured entry: this is what keeps a fallback's cost from being
    /// billed at the primary's rate.
    pub fn cost_of(
        &self,
        cluster: Option<&str>,
        model: Option<&str>,
        usage: &TokenUsage,
    ) -> Charge {
        let (Some(cluster), Some(model)) = (cluster, model) else {
            return Charge::Unpriced;
        };
        let Some(prices) = self
            .by_cluster
            .get(cluster)
            .and_then(|models| models.get(model))
        else {
            return Charge::Unpriced;
        };

        // Every bucket contributes its EXACT numerator; the sum is rounded
        // once, at the end. Rounding each bucket first would round up to four
        // times per request -- see the module doc's "Rounding" section for the
        // worked example of why that is a real overcharge on small requests,
        // not a theoretical one.
        let numerator = bucket_numerator(prices.input_per_million, usage.input_tokens)
            + bucket_numerator(prices.output_per_million, usage.output_tokens)
            + bucket_numerator(prices.cached_per_million, usage.cached_tokens)
            + bucket_numerator(
                prices.cache_creation_per_million,
                usage.cache_creation_tokens,
            );
        Charge::Priced(MicroUsd(round_once(numerator)))
    }
}

/// `tokens` priced at `rate_per_million` micro-dollars per 1,000,000 tokens,
/// as an EXACT un-rounded numerator over 1,000,000. Rounding happens once,
/// in [`round_once`], after all four buckets are summed -- see the module
/// doc's "Rounding" section for why not per bucket.
///
/// Rust note: the multiply happens in `u128`, not `u64`. `rate_per_million`
/// and `tokens` are each already-validated `u64`s, and their product can
/// exceed `u64::MAX` before the division by 1,000,000 brings it back down
/// (the worst case, `u64::MAX * u64::MAX`, still fits in a `u128` -- it is
/// about `2^128 - 2^65`, under `u128::MAX = 2^128 - 1`). Multiplying in `u64`
/// first and dividing after would be the classic "overflow the numerator of
/// an otherwise-in-range division" bug. The final `.min(u64::MAX as u128)` is
/// a saturate for the pathological case where even the rounded RESULT still
/// does not fit in a `u64` (an unrealistic rate/usage combination) -- this is
/// a billing path, so an overflow here must be a can't-happen, never a panic
/// or a silent wraparound.
fn bucket_numerator(rate_per_million: MicroUsd, tokens: u64) -> u128 {
    u128::from(rate_per_million.as_micros()) * u128::from(tokens)
}

/// Sums the four buckets' exact numerators and rounds ONCE, half-up, to whole
/// micro-dollars. See the module doc's "Rounding" section.
fn round_once(numerator: u128) -> u64 {
    // Round-half-up via "add half the divisor before flooring" -- the
    // standard integer trick, valid here because the operand is non-negative.
    let rounded = (numerator + 500_000) / 1_000_000;
    rounded.min(u128::from(u64::MAX)) as u64
}

// ============================================================================
// WP-50 increment 3c-ii-b -- periods, the accumulator, and the flusher.
// Normative: `internal-docs/wp-50-3c-spend-budgets.md`'s "3c-ii-b" section.
// ============================================================================
//
// [`PriceTable`] above answers "what did this request cost"; everything
// below answers "how much has this tenant spent this period, and when does
// the durable store find out".
//
// # Rollover happens on RECORD, never on the flush tick -- a correctness
// property, not an optimization
//
// [`SpendAccumulator::record`] computes its OWN period key from the
// timestamp it is called with, every time -- it never asks "what period is
// it right now" once and stamps a batch of pending work with that single
// answer. So two periods can coexist as two separate map entries for as
// long as requests straddle a boundary, and the periodic flush (which only
// ever iterates whatever keys already exist) can never observe them as
// anything but two rows. If rollover instead happened on the flush TICK --
// computing "now"'s period once per tick and charging every pending record
// to it -- a flusher that wakes late (a paused process, a slow disk, a GC
// pause) could fold a request that happened in period A into the row it
// writes for period B, silently moving spend across a billing boundary
// nobody can see happened. Pinned by
// `rollover_splits_into_two_period_rows_not_one_when_the_flush_ticks_late`;
// its mutation pin computes the key from the flush's own "now" instead.
//
// # `record` takes its `Period` explicitly -- a per-call parameter, not a
// per-accumulator constant (WP-50 3c-iii-b fixup)
//
// This was a live defect between two merged increments, not a design
// preference: [`TenantBudget`] (3c-iii-a) carries a budget's period PER
// TENANT, but this accumulator originally fixed ONE `Period` for its entire
// lifetime and `record` used that fixed value unconditionally. A daily-budget
// tenant and a monthly-budget tenant sharing one accumulator (the ordinary
// case -- one accumulator per chain, many tenants) could therefore never both
// be metered correctly: whichever period the accumulator was constructed
// with was the only one any tenant's spend was ever bucketed under, silently
// wrong for every tenant configured with the other period.
//
// So `record` takes `period: Period` as an explicit argument -- the caller
// (the 3c-iii-b enforcement filter) resolves the CALLING tenant's own
// `TenantBudget::period` (or, for a tenant with no budget at all, falls back
// to [`Self::default_period`] purely so spend history still accrues
// somewhere reportable) and passes it in per call. The constructor's
// erstwhile `period` field is renamed [`Inner::default_period`] to make that
// fallback-only role explicit at the type level rather than leaving a field
// named `period` that no longer means "the accumulator's period". Pinned by
// `two_tenants_with_different_periods_each_accrue_into_their_own_period_key`;
// its mutation pin has `record` ignore the passed period and use
// `default_period` instead.
//
// # Enforcement reads live memory; the flusher is durability, not security
//
// [`SpendAccumulator::current_total`] reads the in-memory bucket directly
// and never consults, or waits on, anything the flusher has or has not
// written. A slow or entirely dead flusher thread therefore cannot loosen a
// ceiling a future enforcement filter (3c-iii) checks against
// `current_total` -- it can only make the STORED total (what a restart
// resumes from) staler than it could be. Pinned by
// `a_dead_flusher_does_not_change_current_total`.
//
// # The flush driver is a plain `std::thread`, not tokio
//
// See the design brief's "3c-ii architecture -- who drives the flush"
// section for the three rejected alternatives (a tokio task from the
// filter factory, an inline flush on the request path, `run_serve` polling
// for the singleton). The short version: the data-plane runtime is
// `!Send`/worker-local (ADR-0003), a redb write on the request path
// violates 3b's rule outright, and `run_serve` cannot name a singleton
// nothing has published yet. [`SpendAccumulator`] is already
// `Send + Sync` -- a `SharedFactoryState` singleton reached from every
// worker -- so an independent OS thread needs no runtime and entangles
// with neither.

/// How many distinct unpriced `(cluster, model)` pairs one bucket
/// remembers before it stops inserting and only counts. `model` is read out
/// of the request body (see [`crate::usage`]), so a caller that varies it
/// on every request can grow this set without bound if nothing caps it --
/// a remote memory-growth vector, not a theoretical one. Pinned by
/// `unpriced_pairs_cap_at_32_pairs_and_set_the_truncated_flag`; its
/// mutation pin removes the cap.
const MAX_UNPRICED_PAIRS: usize = 32;

/// A calendar-aligned accounting window a spend total resets on. Always
/// UTC, never the local clock -- see the section above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Period {
    Daily,
    Monthly,
}

impl Period {
    /// The period `now` falls in, rendered as its [`PeriodKey`]. Called
    /// from [`SpendAccumulator::record`] with the RECORD's own timestamp --
    /// never with the flush tick's "now" -- see this section's "Rollover
    /// happens on RECORD" note for why that split matters.
    pub fn key_for(&self, now: DateTime<Utc>) -> PeriodKey {
        // `%Y-%m-%d`/`%Y-%m` are `chrono`'s strftime-style specifiers, both
        // zero-padded; `now` being a `DateTime<Utc>` (never naive or
        // local) is what makes the rendering UTC-safe by construction
        // rather than by convention.
        match self {
            Period::Daily => PeriodKey(now.format("%Y-%m-%d").to_string()),
            Period::Monthly => PeriodKey(now.format("%Y-%m").to_string()),
        }
    }

    /// The UTC instant this period's CURRENT window ends (exclusive) -- the
    /// next daily or monthly calendar boundary strictly after `now`. WP-50
    /// increment 3c-iii-b's enforcement filter uses this (never the
    /// accumulator itself, which has no notion of a ceiling) to compute
    /// `x-ratelimit-reset`/`retry-after` on a 429: "how many seconds until
    /// this tenant's ceiling resets", the same calendar alignment
    /// [`Self::key_for`] already uses so the two can never disagree about
    /// where a boundary falls.
    pub fn next_boundary(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        let next_date = match self {
            Period::Daily => now.date_naive() + chrono::Duration::days(1),
            Period::Monthly => {
                let (year, month) = (now.year(), now.month());
                let (next_year, next_month) = if month == 12 {
                    (year + 1, 1)
                } else {
                    (year, month + 1)
                };
                NaiveDate::from_ymd_opt(next_year, next_month, 1)
                    .expect("the first day of a valid year/month is always a valid date")
            }
        };
        next_date
            .and_hms_opt(0, 0, 0)
            .expect("midnight is always a valid time")
            .and_utc()
    }

    /// Seconds from `now` until [`Self::next_boundary`], for the enforcement
    /// filter's `x-ratelimit-reset`/`retry-after` headers.
    ///
    /// Rust note: `.max(0)` before the `as u64` -- `next_boundary` is always
    /// strictly later than `now` by construction (it is always at least the
    /// start of tomorrow, or of next month), so the subtraction is never
    /// negative in practice, but guarding the cast explicitly costs nothing
    /// and turns a "should never happen" into a documented saturate rather
    /// than a silent two's-complement wraparound if some future edit ever
    /// violates that invariant.
    pub fn seconds_until_reset(&self, now: DateTime<Utc>) -> u64 {
        let boundary = self.next_boundary(now);
        (boundary - now).num_seconds().max(0) as u64
    }

    /// The UTC instant this period's CURRENT window STARTED -- the mirror of
    /// [`Self::next_boundary`] (which names when it ENDS). Private: WP-50
    /// 3c-iv's only consumer of a period's start is [`Self::window_rfc3339_now`]
    /// below, which renders it as a string rather than handing back a raw
    /// `DateTime`.
    fn current_boundary(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        let start_date = match self {
            Period::Daily => now.date_naive(),
            Period::Monthly => NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
                .expect("the first day of a valid year/month is always a valid date"),
        };
        start_date
            .and_hms_opt(0, 0, 0)
            .expect("midnight is always a valid time")
            .and_utc()
    }

    /// [`Self::key_for`] evaluated against the real wall clock
    /// (`Utc::now()`) -- WP-50 increment 3c-iv's admin spend read
    /// (`proxy-admin`) needs "what period is it right now" and has no
    /// `chrono` dependency of its own to build a `DateTime<Utc>` with; this
    /// answers that without requiring one.
    pub fn key_for_now(&self) -> PeriodKey {
        self.key_for(Utc::now())
    }

    /// This period's `[start, end)` window around `Utc::now()` --
    /// [`Self::current_boundary`] and [`Self::next_boundary`] as a pair.
    ///
    /// Returns `DateTime<Utc>`, deliberately NOT formatted strings. How a
    /// timestamp is RENDERED is a presentation decision belonging to
    /// whatever is doing the presenting (today, `proxy-admin`'s spend read,
    /// which renders RFC 3339); this module is the integer-money domain and
    /// has no business owning a wire format. Contrast [`MicroUsd`], which
    /// likewise stores an integer and leaves decimal rendering to the caller.
    pub fn window_now(&self) -> (DateTime<Utc>, DateTime<Utc>) {
        let now = Utc::now();
        (self.current_boundary(now), self.next_boundary(now))
    }
}

/// A rendered [`Period`] -- `"2026-08-31"` for [`Period::Daily`],
/// `"2026-08"` for [`Period::Monthly`]. A newtype around `String`, same
/// reasoning as [`MicroUsd`]'s doc above: a raw period string and a raw
/// tenant id are both "just a `String`" at the type level, and this keeps a
/// call site from passing one where the other belongs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeriodKey(String);

impl PeriodKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Test-only: builds a `PeriodKey` directly from an already-rendered
    /// string, bypassing [`Period::key_for`]'s calendar logic. Exists for
    /// `control.rs`'s store parity test, which needs to write/read a spend
    /// row under an arbitrary period key without also exercising calendar
    /// alignment -- a separate concern that test does not want conflated
    /// with store parity.
    #[cfg(test)]
    pub(crate) fn for_test(key: &str) -> Self {
        PeriodKey(key.to_string())
    }
}

// ============================================================================
// WP-50 increment 3c-iii-a -- per-tenant budgets: storage and admin CRUD
// only. This increment carries a configured ceiling through
// `crate::control::ControlPlane`/`ControlPlaneStore` and out over the admin
// API; CHECKING a request against it is 3c-iii-b's filter, out of scope here.
// ============================================================================

/// A tenant's spend ceiling: at most `max_micros` per `period`. Carried on
/// [`crate::auth::TenantPolicy::budget`]; see that field's doc for the
/// `None`-vs-`Some(0)` distinction restated from the `TenantPolicy` side.
///
/// # `None` (on `TenantPolicy::budget`) means unlimited -- the deliberate default
///
/// Mirrors [`crate::model_authz::ModelAccess::default`]'s reasoning exactly,
/// restated for money: a budget is an opt-in ceiling, not a default-deny. If
/// an absent budget meant "spend nothing", turning WP-50 3c-iii-b's
/// enforcement filter on would deny every tenant's very first request the
/// moment an operator adds it to a chain -- that is an outage, not a safety
/// property. Restriction is opt-in: an operator sets a ceiling when they want
/// one.
///
/// # Unlike `ModelAccess`, `None` here is genuinely a different fact from a configured zero
///
/// `ModelAccess` has no missing-vs-configured distinction to make *inside*
/// the enum -- `All` and `Only(vec![])` are both fully-specified values, and
/// the only "is this tenant restricted at all" question lives one level up,
/// at `TenantPolicy::model_access` vs. `TenantPolicy::default()`.
/// `TenantBudget` has that identical two-level shape, restated for money:
/// `None` (no ceiling configured -- unlimited) vs. `Some(TenantBudget {
/// max_micros: MicroUsd::from_micros(0), .. })` (a ceiling IS configured, and
/// it happens to be zero -- deny every priced request for the rest of this
/// period). Both are legitimate, deliberate policies, exactly like
/// `ModelAccess::Only(vec![])` denying every model for a tenant -- see that
/// type's doc. Collapsing the two would make "an operator meant to lock a
/// tenant out entirely" indistinguishable from "no one has ever configured a
/// budget for this tenant", which is the same shape of silent privilege
/// escalation `ModelAccess`'s own doc warns about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantBudget {
    /// The ceiling, in integer micro-dollars -- see the module doc's "Money
    /// is integer, never `f64`" section. Config supplies this as a decimal
    /// string parsed once by [`parse_micro_usd`], the SAME parser a price
    /// uses, so an operator cannot express a budget more precisely than a
    /// price.
    pub max_micros: MicroUsd,
    /// The calendar-aligned window this ceiling resets on.
    pub period: Period,
}

/// What this replica does when its spend state has gone STALE -- when the
/// accumulator has not reconciled with the store for longer than
/// [`ReconciliationPolicy::bound`].
///
/// # Only one variant, deliberately
///
/// ADR-0006 §5 asks for this to be a NAMED behaviour with only `allow`
/// wired, so tightening the policy later is a config value rather than a
/// redesign. `deny` and `degrade` are named in the config surface
/// (`llmproxy.filters.v0.SpendLimit.on_reconciliation_expired`) and REJECTED
/// at config load, which is the strict-config-mode answer (ground rule 1):
/// an operator who asks for a behaviour this build does not implement gets a
/// load error naming the field, never a silent downgrade to `Allow`.
///
/// # Why `allow` is the one that ships
///
/// Same call budgets already make, and the same one Envoy's global rate
/// limit filter makes with `failure_mode_deny: false`: a metering hiccup
/// must not start refusing traffic (CLAUDE.md rule 17). Note what that buys
/// and what it does not -- the over-admission becomes VISIBLE
/// ([`SpendReport::unreconciled_admissions`], and the flusher's warning),
/// not CLOSED.
///
/// Our degradation is still better than Envoy's, because each replica keeps
/// enforcing against `last confirmed global total + its own accrual` and
/// still trips on its own traffic; Envoy holds no counter state at all and
/// admits everything for the duration of an outage. See ADR-0006 §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnReconciliationExpired {
    /// Keep serving. Each replica enforces against what it last confirmed
    /// plus what it has accrued locally since.
    #[default]
    Allow,
}

/// How long this replica may go without reconciling with the store before
/// it says so, and what it does about it.
///
/// # Why this has a default and `node_id` does not
///
/// [`SpendAccumulator::new`] takes `node_id` as a required argument because
/// a wrong value there loses money silently. This is the opposite kind of
/// knob: getting the bound wrong changes only WHEN an operator is warned,
/// never what is charged or admitted. So it defaults, and an operator who
/// never thinks about it gets a sane value instead of a load error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconciliationPolicy {
    /// How stale this replica's view of the global total may get before
    /// [`SpendAccumulator::is_reconciled`] reports `false`, the flusher
    /// warns, and admissions start being counted as unreconciled.
    ///
    /// Measured from the last flush in which EVERY bucket was written
    /// successfully -- or, if none ever has, from when the accumulator was
    /// constructed. A process that has never once reached the store is the
    /// most unreconciled a process can be, so it must not read as
    /// "reconciled" merely for lack of a previous flush to compare against.
    pub bound: Duration,
    /// What to do once `bound` has elapsed. See
    /// [`OnReconciliationExpired`].
    pub on_expired: OnReconciliationExpired,
}

/// The default staleness bound: 60 seconds.
///
/// Twelve missed ticks at the default 5-second flush interval -- far past
/// "one blip", squarely in "this replica cannot reach the store". Set
/// deliberately rather than derived from the flush interval, because
/// `start_flusher` learns the interval only after construction and a bound
/// that silently changes with an unrelated knob is worse than a stated one.
///
/// ADR-0006 §4 requires the three staleness bounds to be stated SEPARATELY.
/// This one happening to equal WP-61's 60-second revocation bound is a
/// coincidence of both meaning "about a minute", not a shared constant: a
/// deployment that tightens one has said nothing about the other.
pub const DEFAULT_RECONCILIATION_BOUND: Duration = Duration::from_secs(60);

impl Default for ReconciliationPolicy {
    fn default() -> Self {
        ReconciliationPolicy {
            bound: DEFAULT_RECONCILIATION_BOUND,
            on_expired: OnReconciliationExpired::Allow,
        }
    }
}

/// [`Inner::last_flush_millis`]'s "no flush has ever fully succeeded"
/// sentinel. `i64::MIN` rather than `0`, because `0` is a real
/// [`DateTime<Utc>`] (the Unix epoch) and a store of `0` would otherwise be
/// indistinguishable from a clock that genuinely read 1970.
const NEVER_FLUSHED: i64 = i64::MIN;

/// One `(tenant, period)`'s live, in-memory spend state. Same shape as
/// `crate::token_limit::InProcessBudgetStore`'s window map -- a plain
/// struct behind the accumulator's one `Mutex`, with no store I/O involved
/// in building or reading it.
#[derive(Debug, Clone, Default)]
struct Bucket {
    /// The last total the STORE confirmed for this row, in micro-dollars.
    /// Includes every other replica's spend, because it is whatever
    /// [`ControlPlaneStore::add_spend`] returned on the last successful
    /// flush -- this is the field that makes the flusher a reconciliation
    /// point rather than only a writer. Seeded from
    /// [`ControlPlaneStore::load_spend`] on first touch.
    base_micros: u64,
    /// Spend recorded in THIS process since `base_micros` was last
    /// confirmed. Handed to the store as a delta and folded into
    /// `base_micros` when the store confirms; never written to `base_micros`
    /// directly, or a replica would double-count its own spend the moment
    /// the store echoed it back.
    pending_delta_micros: u64,
    /// The sequence number the NEXT flush of this row will use, or `None`
    /// until it has been seeded from
    /// [`ControlPlaneStore::last_flush_seq`] -- see [`Inner::flush_now`] for
    /// why the seed is read at flush time and not when the bucket is
    /// created.
    next_seq: Option<u64>,
    /// Requests this period whose `(cluster, model)` had no configured
    /// price -- see [`Charge::Unpriced`]'s doc. Charged nothing, but kept
    /// discoverable per the design brief's "the gap must stay discoverable"
    /// requirement.
    unpriced_requests: u64,
    /// Distinct `(cluster, model)` pairs seen among this bucket's unpriced
    /// requests, capped at [`MAX_UNPRICED_PAIRS`].
    unpriced_pairs: BTreeSet<(String, String)>,
    /// Set once [`MAX_UNPRICED_PAIRS`] distinct pairs have been recorded --
    /// tells a later reader "there were more pairs than this set shows"
    /// without growing the set itself.
    unpriced_pairs_truncated: bool,
}

/// The state a [`SpendAccumulator`] and its flusher thread both need
/// access to. Split out from `SpendAccumulator` itself so the thread can
/// hold its own `Arc` clone of ONLY this, not of `SpendAccumulator` --
///
/// Rust note: if the thread instead held an `Arc<SpendAccumulator>`,
/// `SpendAccumulator`'s `Drop` (which shuts the thread down) could never
/// run: `Drop::drop` only fires once every clone of an `Arc` is gone, and
/// the thread's own clone would forever be one of them -- a deadlock in
/// waiting, not a panic, which is what makes it worth calling out. `Inner`
/// carries no handle back to `SpendAccumulator` or its flusher state, so
/// the thread's clone of `Inner` never keeps `SpendAccumulator` itself
/// alive, and dropping the last external `Arc<SpendAccumulator>` runs
/// `Drop` immediately regardless of whether the thread is still running.
struct Inner {
    stat_prefix: String,
    store: Arc<dyn ControlPlaneStore>,
    /// This replica's identity, from `service_node`. Half of every
    /// [`FlushToken`] this accumulator builds -- see that type's doc for
    /// what two replicas sharing one node id cost.
    node_id: String,
    /// The period used ONLY for a tenant with no configured [`TenantBudget`]
    /// -- see this section's "`record` takes its `Period` explicitly" note.
    /// Never consulted for a tenant `record` is called with an explicit
    /// period for.
    default_period: Period,
    buckets: Mutex<HashMap<(TenantId, PeriodKey), Bucket>>,
    /// WP-50 increment 3c-iv: when [`Inner::flush_now`] last wrote every
    /// bucket to the store WITHOUT ERROR, as Unix milliseconds, or
    /// [`NEVER_FLUSHED`] until the first such flush. A FAILED flush (see
    /// [`Inner::flush_now`]'s `first_err`) must NEVER advance this: it would
    /// otherwise claim durability the store does not actually have, which is
    /// exactly the kind of unreproducible wrong answer the module doc's
    /// "Money is integer" section warns against for a different reason. The
    /// admin spend read ([`SpendAccumulator::report`]) surfaces this so an
    /// operator can see the crash-refund window directly rather than
    /// assuming it.
    ///
    /// Rust note: an atomic, not the `Mutex<Option<DateTime<Utc>>>` this was
    /// before WP-62. Reading it moved onto the REQUEST path (see
    /// [`SpendAccumulator::note_admission`], called once per admitted
    /// request under a budget), and rule 17's "keep the suppression state
    /// off the healthy hot path" rules out taking a lock there. `Relaxed`
    /// ordering throughout: this value guards nothing else, and a reader
    /// that sees the previous flush's timestamp is off by one flush
    /// interval on a staleness estimate -- not wrong about money.
    last_flush_millis: AtomicI64,
    /// When this accumulator was constructed, as Unix milliseconds. The
    /// origin [`SpendAccumulator::reconciliation_age`] measures from when no
    /// flush has ever succeeded -- see [`ReconciliationPolicy::bound`]'s doc
    /// for why "never flushed" must read as very stale rather than as
    /// unknown.
    created_at_millis: i64,
    /// This accumulator's staleness bound and expiry behaviour.
    reconciliation: ReconciliationPolicy,
    /// Requests admitted under a configured budget while this replica was
    /// past its reconciliation bound -- ADR-0006 §5's required "counter of
    /// admissions made while unreconciled". Monotonic for the life of the
    /// process; it counts an operational event, not a per-period quantity,
    /// so it deliberately does NOT reset on a period rollover.
    unreconciled_admissions: AtomicU64,
}

impl Inner {
    /// Returns the bucket for `(tenant, period_key)`, inserting a freshly
    /// LOADED one on first touch if this process has not seen that period
    /// before. Both [`SpendAccumulator::record`] (which then mutates it)
    /// and [`SpendAccumulator::current_total`] (which only reads it) go
    /// through this, so a `current_total` read before any `record` call in
    /// a fresh period still resumes from the store rather than reporting
    /// zero for spend that already happened -- the "restart resume"
    /// property the design brief requires.
    ///
    /// A load failure here must NOT lose the request it is servicing: this
    /// logs loudly and starts the bucket at zero rather than propagating an
    /// error, per CLAUDE.md rule 17 ("a security control that fails open
    /// must be loud") -- the same "metering must not refuse traffic"
    /// precedent `token_limit`'s missing-usage path already sets.
    fn get_or_load_bucket<'a>(
        &self,
        buckets: &'a mut HashMap<(TenantId, PeriodKey), Bucket>,
        tenant: &TenantId,
        period_key: &PeriodKey,
    ) -> &'a mut Bucket {
        buckets
            .entry((tenant.clone(), period_key.clone()))
            .or_insert_with(|| {
                let total_micros =
                    match self.store.load_spend(&self.stat_prefix, tenant, period_key) {
                        Ok(total) => total,
                        Err(err) => {
                            tracing::warn!(
                                stat_prefix = %self.stat_prefix,
                                tenant = tenant.as_str(),
                                period = period_key.as_str(),
                                error = %err,
                                "spend accumulator: failed to load the stored total for a new \
                                 period; resuming from zero in this process rather than \
                                 refusing the request"
                            );
                            0
                        }
                    };
                Bucket {
                    base_micros: total_micros,
                    ..Bucket::default()
                }
            })
    }

    /// Flushes every in-memory bucket to the store as a DELTA, and adopts
    /// the total the store returns.
    ///
    /// # This is a reconciliation point, not only a write
    ///
    /// [`ControlPlaneStore::add_spend`] returns the row's new authoritative
    /// total -- this replica's delta plus everything every other replica has
    /// added since. Adopting it into `base_micros` is what makes two
    /// accumulators sharing one store converge; an implementation that
    /// discards the return value still writes correctly and still enforces
    /// against its own spend alone, which is the pre-WP-60 behaviour wearing
    /// a new signature.
    ///
    /// A bucket with NOTHING to add is flushed anyway, with a delta of zero.
    /// That is deliberate and is not a wasted call: a replica serving no
    /// traffic still has to learn what the others spent, or it admits
    /// requests against a ceiling it thinks is empty. There is likewise no
    /// single-replica short circuit -- the embedded store implements the
    /// same contract, and skipping the path in embedded mode would leave the
    /// multi-replica path exercised only in production (ADR-0006 §5).
    ///
    /// # At most once per flush window
    ///
    /// Additive writes are composable but not idempotent, so this owns
    /// delivery: each attempt carries `(node_id, seq)`, and `seq` advances
    /// ONLY after the store confirms. A failed or lost write is retried next
    /// tick under the SAME sequence, so if the first attempt did land and
    /// only its response was lost, the store recognises the replay and
    /// returns the total instead of charging twice. The cost of a crash is
    /// therefore bounded at one flush interval of un-flushed spend, never a
    /// double charge.
    ///
    /// Best-effort across buckets: one tenant's write failing does not stop
    /// the rest, but the first failure is returned so the caller (the
    /// flusher thread's warning, or a test) can tell the flush was not fully
    /// durable.
    ///
    /// [`Self::last_flush_at`] advances to `Utc::now()` ONLY when every
    /// bucket wrote successfully -- see that field's doc for why a partial
    /// or total failure must leave it exactly where it was: a report that
    /// claimed a flush just succeeded when it did not would be a durability
    /// lie.
    /// How long since the last flush in which EVERY bucket was written --
    /// or since construction, if there has never been one. See
    /// [`SpendAccumulator::reconciliation_age`], which is this method's
    /// public face and carries the reasoning.
    ///
    /// Lives on `Inner` (not only on [`SpendAccumulator`]) because the
    /// flusher thread holds an `Arc<Inner>` and nothing else -- see
    /// [`Inner`]'s own doc for why it cannot hold the accumulator.
    fn reconciliation_age(&self, now: DateTime<Utc>) -> Duration {
        let since_millis = match self.last_flush_millis.load(Ordering::Relaxed) {
            NEVER_FLUSHED => self.created_at_millis,
            millis => millis,
        };
        let elapsed = now.timestamp_millis().saturating_sub(since_millis);
        Duration::from_millis(u64::try_from(elapsed).unwrap_or(0))
    }

    fn flush_now(&self) -> Result<(), StoreError> {
        // Rust note: the buckets lock is held across store I/O, as it was
        // before WP-60. That blocks `record` for the duration of a flush,
        // and it is what lets the read-modify-write of `base_micros` and
        // `pending_delta_micros` below be a plain subtraction rather than a
        // compare-and-swap.
        let mut buckets = self
            .buckets
            .lock()
            .expect("spend accumulator mutex poisoned");
        let mut first_err = None;
        for ((tenant, period_key), bucket) in buckets.iter_mut() {
            // Seed the sequence from the store on first flush of this row.
            // Read here rather than in `get_or_load_bucket` because that
            // runs on the REQUEST path, where an extra store read costs
            // every first request of a period, and where a failure must not
            // be able to stop the flush from being retried.
            let seq = match bucket.next_seq {
                Some(seq) => seq,
                None => {
                    match self.store.last_flush_seq(
                        &self.stat_prefix,
                        tenant,
                        period_key,
                        &self.node_id,
                    ) {
                        Ok(last) => {
                            let seq = last + 1;
                            bucket.next_seq = Some(seq);
                            seq
                        }
                        Err(err) => {
                            // Do NOT guess a sequence -- see
                            // `ControlPlaneStore::last_flush_seq`'s doc. A
                            // guess that lands below the stored one makes
                            // every future flush of this row a silent no-op.
                            // Skipping costs one interval; guessing costs the
                            // spend.
                            if first_err.is_none() {
                                first_err = Some(err);
                            }
                            continue;
                        }
                    }
                }
            };
            let delta = bucket.pending_delta_micros;
            match self.store.add_spend(
                &self.stat_prefix,
                tenant,
                period_key,
                delta,
                FlushToken {
                    node_id: &self.node_id,
                    seq,
                },
            ) {
                Ok(total) => {
                    bucket.base_micros = total;
                    bucket.pending_delta_micros = bucket.pending_delta_micros.saturating_sub(delta);
                    bucket.next_seq = Some(seq + 1);
                }
                Err(err) => {
                    // Leave `next_seq` where it is: the retry must reuse this
                    // sequence, or a write that did land becomes a second
                    // charge instead of a recognised replay.
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }
        }
        match first_err {
            Some(err) => Err(err),
            None => {
                self.last_flush_millis
                    .store(Utc::now().timestamp_millis(), Ordering::Relaxed);
                Ok(())
            }
        }
    }
}

/// The flusher thread's stop condition, plus the [`Condvar`] that lets it
/// wake IMMEDIATELY on shutdown rather than sleeping out up to one full
/// interval.
///
/// Rust note: a `Condvar`, not a short poll loop -- a poll trades wakeup
/// latency for CPU burned on every tick even when nothing changed, and this
/// has exactly one waiter and one notifier, precisely the case a `Condvar`
/// is for. The boolean it guards is the actual shutdown flag; the `Condvar`
/// itself carries no state; it only wakes a thread already waiting on the
/// paired `Mutex`.
struct ShutdownSignal {
    stop: Mutex<bool>,
    cv: Condvar,
}

/// A started flusher thread's handle -- kept so [`SpendAccumulator`] can
/// signal and join it, from either [`SpendAccumulator::start_flusher`]
/// (replacing a previous thread) or `Drop` (shutting down for good).
struct Flusher {
    shutdown: Arc<ShutdownSignal>,
    join: JoinHandle<()>,
}

/// [`SpendAccumulator::report`]'s return value -- everything WP-50 increment
/// 3c-iv's admin spend read renders for one `(tenant, period)`. See that
/// method's doc for the "never-spent tenant reports zeros" guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendReport {
    /// The tenant's live spend total for this period, in micro-dollars.
    pub total_micros: u64,
    /// Requests this period whose `(cluster, model)` had no configured
    /// price -- see [`Charge::Unpriced`]'s doc.
    pub unpriced_requests: u64,
    /// Distinct unpriced `(cluster, model)` pairs, sorted (a `BTreeSet`'s
    /// iteration order is already sorted -- see [`Bucket::unpriced_pairs`]),
    /// capped at [`MAX_UNPRICED_PAIRS`].
    pub unpriced_pairs: Vec<(String, String)>,
    /// Set once more than [`MAX_UNPRICED_PAIRS`] distinct pairs were seen --
    /// tells a reader there were more than [`Self::unpriced_pairs`] shows.
    pub unpriced_pairs_truncated: bool,
    /// When this accumulator last flushed EVERY bucket to the store
    /// successfully -- `None` if it never has. See
    /// [`SpendAccumulator::last_flush_at`]'s doc.
    pub last_flush_at: Option<DateTime<Utc>>,
    /// Whole seconds since this replica last reconciled with the store --
    /// ADR-0006 §5's `spend_reconciliation_age_seconds`, surfaced through
    /// the admin API rather than the stats registry because filters have no
    /// handle to the registry today (see
    /// [`SpendAccumulator::reconciliation_age`], which this rounds down).
    /// A replica that has never flushed reports its age since construction,
    /// not zero.
    pub reconciliation_age_seconds: u64,
    /// `true` once [`Self::reconciliation_age_seconds`] has passed the
    /// configured bound: this replica's `total_micros` may be missing other
    /// replicas' spend, so a budget can be over-admitted by roughly
    /// `(N-1) x per-replica spend` for the duration. ADR-0006 §5.
    pub reconciliation_expired: bool,
    /// Requests this PROCESS has admitted under a configured budget while
    /// [`Self::reconciliation_expired`] was true. Process-wide and
    /// monotonic, unlike every other counter here, which is per
    /// `(tenant, period)` -- it measures an operational condition, not this
    /// tenant's usage.
    pub unreconciled_admissions: u64,
}

/// Per-`(tenant, period)` spend, accumulated in memory with no store I/O on
/// the record path, periodically flushed by a background OS thread. See
/// the section above for the rollover and enforcement properties, and the
/// design brief's "3c-ii architecture" section for why a plain thread.
pub struct SpendAccumulator {
    inner: Arc<Inner>,
    flusher: Mutex<Option<Flusher>>,
}

impl SpendAccumulator {
    /// Construction and starting the flusher thread are SEPARATE calls
    /// (see [`Self::start_flusher`]) so a test can exercise `record`/
    /// `current_total`/`flush_now` with no background thread involved at
    /// all.
    ///
    /// `default_period` is used ONLY for a tenant [`Self::record`] is never
    /// given an explicit period for -- see [`Inner::default_period`]'s doc.
    /// `node_id` MUST be unique per replica -- it is half of every
    /// [`FlushToken`] this accumulator writes, and two replicas sharing one
    /// id share one dedup sequence space, so each silently drops the other's
    /// flushes. It is a required argument rather than an `Option` with a
    /// default for exactly that reason: a wrong value here loses money
    /// quietly, so it must be a thing the caller states. `service_node` in
    /// the bootstrap supplies it; see `spend_limit_filter` for what happens
    /// when the operator left it unset.
    pub fn new(
        stat_prefix: String,
        store: Arc<dyn ControlPlaneStore>,
        default_period: Period,
        node_id: String,
    ) -> Self {
        Self::with_reconciliation(
            stat_prefix,
            store,
            default_period,
            node_id,
            ReconciliationPolicy::default(),
        )
    }

    /// [`Self::new`] with an explicit [`ReconciliationPolicy`] instead of
    /// the default one -- the form the filter factory uses, since the bound
    /// and the expiry behaviour are both config fields
    /// (`SpendLimit.reconciliation_bound_seconds`,
    /// `SpendLimit.on_reconciliation_expired`).
    ///
    /// A separate constructor rather than a fifth argument on [`Self::new`]
    /// because most callers -- every test that does not care about
    /// staleness, and any embedded single-replica setup -- want the default
    /// and gain nothing from restating it.
    pub fn with_reconciliation(
        stat_prefix: String,
        store: Arc<dyn ControlPlaneStore>,
        default_period: Period,
        node_id: String,
        reconciliation: ReconciliationPolicy,
    ) -> Self {
        SpendAccumulator {
            inner: Arc::new(Inner {
                stat_prefix,
                store,
                node_id,
                default_period,
                buckets: Mutex::new(HashMap::new()),
                last_flush_millis: AtomicI64::new(NEVER_FLUSHED),
                created_at_millis: Utc::now().timestamp_millis(),
                reconciliation,
                unreconciled_admissions: AtomicU64::new(0),
            }),
            flusher: Mutex::new(None),
        }
    }

    /// Records one request's charge against `tenant`'s bucket for the
    /// period `now` falls in, under `period` -- see this section's "`record`
    /// takes its `Period` explicitly" note for why the caller supplies this
    /// per call rather than the accumulator fixing one for its whole
    /// lifetime: a tenant with a configured [`TenantBudget`] passes that
    /// budget's OWN period, so a daily-budget tenant and a monthly-budget
    /// tenant sharing this accumulator each accrue into their own period key,
    /// correctly, from the same call. A tenant with no budget at all has
    /// nothing to derive a period from; the caller passes
    /// [`Self::default_period`] for that case purely so its spend history
    /// still accrues somewhere reportable.
    ///
    /// [`Charge::Priced`] adds to the tenant's total; [`Charge::Unpriced`]
    /// only increments the unpriced-request count and (if both are known)
    /// remembers the `(cluster, model)` pair, capped at
    /// [`MAX_UNPRICED_PAIRS`] -- see [`Bucket`]'s doc.
    pub fn record(
        &self,
        tenant: &TenantId,
        now: DateTime<Utc>,
        period: Period,
        charge: Charge,
        cluster: Option<&str>,
        model: Option<&str>,
    ) {
        // The period key is computed from THIS record's own timestamp, not
        // from whatever "now" the flusher last observed -- see this
        // section's "Rollover happens on RECORD" note. It is computed from
        // the CALLER-SUPPLIED period, not `self.inner.default_period` -- see
        // this section's "`record` takes its `Period` explicitly" note; using
        // the accumulator's default here regardless of what was passed is
        // exactly the bug this fixup closes.
        let period_key = period.key_for(now);
        let mut buckets = self
            .inner
            .buckets
            .lock()
            .expect("spend accumulator mutex poisoned");
        let bucket = self
            .inner
            .get_or_load_bucket(&mut buckets, tenant, &period_key);

        match charge {
            Charge::Priced(amount) => {
                bucket.pending_delta_micros = bucket
                    .pending_delta_micros
                    .saturating_add(amount.as_micros());
            }
            Charge::Unpriced => {
                bucket.unpriced_requests += 1;
                if let (Some(cluster), Some(model)) = (cluster, model) {
                    let pair = (cluster.to_string(), model.to_string());
                    if !bucket.unpriced_pairs.contains(&pair) {
                        if bucket.unpriced_pairs.len() < MAX_UNPRICED_PAIRS {
                            bucket.unpriced_pairs.insert(pair);
                        } else {
                            bucket.unpriced_pairs_truncated = true;
                        }
                    }
                }
            }
        }
    }

    /// [`Self::record`] against the real wall clock (`Utc::now()`) -- the
    /// `record`-side counterpart of [`Period::key_for_now`]'s cross-crate
    /// convenience: a caller with no `chrono` dependency of its own (WP-50
    /// 3c-iv's `proxy-admin` server tests, standing in for what the
    /// `llmproxy.spend_limit` filter's own `record_if_present` does with a
    /// real `Utc::now()`) can record a charge without constructing a
    /// `DateTime<Utc>` itself.
    pub fn record_now(
        &self,
        tenant: &TenantId,
        period: Period,
        charge: Charge,
        cluster: Option<&str>,
        model: Option<&str>,
    ) {
        self.record(tenant, Utc::now(), period, charge, cluster, model);
    }

    /// The period a tenant with NO configured [`TenantBudget`] is metered
    /// under -- see [`Inner::default_period`]'s doc. The 3c-iii-b enforcement
    /// filter reads this to build the `period` argument [`Self::record`]
    /// needs when the request's tenant has no budget at all.
    pub fn default_period(&self) -> Period {
        self.inner.default_period
    }

    /// The live in-memory total for `(tenant, period)` -- what a future
    /// enforcement filter (3c-iii) checks a ceiling against. See this
    /// section's "Enforcement reads live memory" note: this never consults
    /// the flusher or its state, so the flusher's liveness cannot affect
    /// what it returns.
    pub fn current_total(&self, tenant: &TenantId, period: &PeriodKey) -> u64 {
        let mut buckets = self
            .inner
            .buckets
            .lock()
            .expect("spend accumulator mutex poisoned");
        let bucket = self.inner.get_or_load_bucket(&mut buckets, tenant, period);
        // Everything the store has confirmed, plus what this replica has
        // recorded since. Enforcement reads THIS, not the store -- see this
        // section's "Enforcement reads live memory" note -- so a replica
        // never under-counts its own spend while waiting for a flush.
        bucket
            .base_micros
            .saturating_add(bucket.pending_delta_micros)
    }

    /// Writes every bucket's current absolute total to the store. Callable
    /// directly with no thread involved at all -- tests use this to assert
    /// against the store; the flusher thread also calls it on every tick,
    /// and `Drop` calls it once more on shutdown.
    pub fn flush_now(&self) -> Result<(), StoreError> {
        self.inner.flush_now()
    }

    /// The UTC instant [`Self::flush_now`] last completed with EVERY bucket
    /// written successfully -- `None` if no flush has ever fully succeeded.
    /// See [`Inner::last_flush_at`]'s doc for why a failed (even partially
    /// failed) flush must never advance this.
    pub fn last_flush_at(&self) -> Option<DateTime<Utc>> {
        let millis = self.inner.last_flush_millis.load(Ordering::Relaxed);
        if millis == NEVER_FLUSHED {
            return None;
        }
        DateTime::<Utc>::from_timestamp_millis(millis)
    }

    /// This accumulator's staleness bound and expiry behaviour, as
    /// configured.
    pub fn reconciliation_policy(&self) -> ReconciliationPolicy {
        self.inner.reconciliation
    }

    /// How long it has been since this replica last reconciled with the
    /// store -- ADR-0006 §5's required `spend_reconciliation_age_seconds`,
    /// as a [`Duration`] the caller renders.
    ///
    /// # Not an `Option`, on purpose
    ///
    /// A process that has NEVER completed a flush measures from its own
    /// construction, so it reports a growing age rather than `None`. Never
    /// having reached the store is the most unreconciled a replica can be;
    /// returning "unknown" for it would invite every caller to treat the
    /// worst case as the benign one, which is the fail-open-and-silent shape
    /// CLAUDE.md rule 17 exists to stop.
    ///
    /// Clock note: this is wall-clock arithmetic on [`Utc::now`], not a
    /// monotonic [`std::time::Instant`], because the value it derives from
    /// (`last_flush_at`) is itself a wall-clock timestamp an operator reads
    /// out of the admin API. A backwards NTP step can therefore make this
    /// briefly read `0`; it saturates rather than panicking, and one
    /// under-reported interval is not worth a second clock source here.
    pub fn reconciliation_age(&self, now: DateTime<Utc>) -> Duration {
        self.inner.reconciliation_age(now)
    }

    /// Whether this replica is within its configured reconciliation bound.
    pub fn is_reconciled(&self, now: DateTime<Utc>) -> bool {
        self.reconciliation_age(now) <= self.inner.reconciliation.bound
    }

    /// Counts one request admitted under a CONFIGURED BUDGET, and returns
    /// whether it was admitted while this replica was past its
    /// reconciliation bound.
    ///
    /// # Call this only where the control was meant to apply
    ///
    /// A tenant with no configured budget is unlimited, so admitting its
    /// request while stale is not an over-admission and must not be counted
    /// or warned about (CLAUDE.md rule 17: "only warn where the control was
    /// actually meant to apply"). `spend_limit_filter` calls this on the
    /// admit path only after it has resolved a budget.
    ///
    /// # Cost on the healthy path
    ///
    /// Two relaxed atomic loads and an integer comparison; the counter is
    /// touched only when the bound has already been exceeded. No lock, and
    /// nothing allocated.
    pub fn note_admission(&self, now: DateTime<Utc>) -> bool {
        if self.is_reconciled(now) {
            return false;
        }
        self.inner
            .unreconciled_admissions
            .fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Total requests this process admitted under a configured budget while
    /// past its reconciliation bound. Process-wide and monotonic: it counts
    /// an operational condition, not a tenant's usage, so it deliberately
    /// does not reset on a period rollover.
    pub fn unreconciled_admissions(&self) -> u64 {
        self.inner.unreconciled_admissions.load(Ordering::Relaxed)
    }

    /// WP-50 increment 3c-iv -- the admin spend read's data source. Returns
    /// `(tenant, period)`'s live spend, unpriced-request discoverability
    /// counters, and the accumulator's last successful flush time, all in
    /// one snapshot so a caller (`proxy-admin`'s spend endpoint) does not
    /// need to lock the buckets map itself or reason about torn reads across
    /// several separate calls.
    ///
    /// A `(tenant, period)` this process has never touched reports ZEROS,
    /// not an error -- it goes through the same [`Inner::get_or_load_bucket`]
    /// [`Self::current_total`] does, which resumes from the store (itself
    /// `0` for a row nothing has ever written, per
    /// [`ControlPlaneStore::load_spend`]'s doc) rather than treating "never
    /// spent" as a failure. An operator asking about a tenant that has not
    /// made a request yet gets a valid, boring answer.
    pub fn report(&self, tenant: &TenantId, period: &PeriodKey) -> SpendReport {
        let now = Utc::now();
        let mut buckets = self
            .inner
            .buckets
            .lock()
            .expect("spend accumulator mutex poisoned");
        let bucket = self.inner.get_or_load_bucket(&mut buckets, tenant, period);
        // Rust note: `unpriced_pairs` is a `BTreeSet`, so iterating it is
        // ALREADY in sorted order -- no separate `.sort()` needed to satisfy
        // the design brief's "sorted for stable output" requirement.
        let unpriced_pairs: Vec<(String, String)> = bucket.unpriced_pairs.iter().cloned().collect();
        let report = SpendReport {
            total_micros: bucket
                .base_micros
                .saturating_add(bucket.pending_delta_micros),
            unpriced_requests: bucket.unpriced_requests,
            unpriced_pairs,
            unpriced_pairs_truncated: bucket.unpriced_pairs_truncated,
            // `last_flush_at` locks a DIFFERENT mutex than `buckets` above,
            // so reading it while still holding `buckets`'s guard is not a
            // self-deadlock -- called here (rather than after `buckets`
            // drops) only so every field of `report` is assembled in one
            // place.
            last_flush_at: self.last_flush_at(),
            reconciliation_age_seconds: self.reconciliation_age(now).as_secs(),
            reconciliation_expired: !self.is_reconciled(now),
            unreconciled_admissions: self.unreconciled_admissions(),
        };
        drop(buckets);
        report
    }

    /// Starts the background flush thread, ticking every `interval`. See
    /// this section's "The flush driver is a plain `std::thread`" note for
    /// why not a tokio task.
    ///
    /// Rust note: `self: &Arc<Self>`, not `&self` -- this documents at the
    /// call site that `start_flusher` is meant to be called on an
    /// already-shared, already-`Arc`-wrapped accumulator (the shape a
    /// `SharedFactoryState` singleton holds it in), even though the thread
    /// closure below only clones [`Self::inner`], never `Self` -- see
    /// [`Inner`]'s doc for why.
    ///
    /// Calling this twice cleanly shuts down and joins the previous thread
    /// first (the same path `Drop` uses) rather than leaking a second one;
    /// production code starts it exactly once (the singleton guarantees
    /// that), but a silent thread leak on a hypothetical second call would
    /// be a strictly worse bug than the small cost of guarding against it.
    pub fn start_flusher(self: &Arc<Self>, interval: Duration) {
        self.stop_flusher_if_running();

        let shutdown = Arc::new(ShutdownSignal {
            stop: Mutex::new(false),
            cv: Condvar::new(),
        });
        let inner = Arc::clone(&self.inner);
        let thread_shutdown = Arc::clone(&shutdown);
        let join = std::thread::Builder::new()
            .name("spend-flusher".to_string())
            .spawn(move || run_flusher(inner, thread_shutdown, interval))
            .expect("spawning the spend flusher thread must not fail");

        *self
            .flusher
            .lock()
            .expect("spend accumulator mutex poisoned") = Some(Flusher { shutdown, join });
    }

    /// Signals and joins a currently-running flusher thread, if any --
    /// shared by [`Self::start_flusher`] (replacing a previous thread) and
    /// `Drop` (shutting down for good). Does NOT flush; the caller flushes
    /// afterward, so there is exactly one writer at the moment of shutdown
    /// rather than the outgoing thread and the caller racing each other.
    fn stop_flusher_if_running(&self) {
        let flusher = self
            .flusher
            .lock()
            .expect("spend accumulator mutex poisoned")
            .take();
        if let Some(flusher) = flusher {
            *flusher
                .shutdown
                .stop
                .lock()
                .expect("spend flusher shutdown mutex poisoned") = true;
            flusher.shutdown.cv.notify_all();
            // Rust note: `.join()` blocks THIS thread until the flusher
            // thread returns from `run_flusher`. Ignoring the `Result` (a
            // `join` only errors if the thread panicked) matches how a
            // background worker's panic is handled elsewhere in this
            // codebase: it should surface via the usual panic machinery
            // (a failed test, a process abort), not be silently swallowed
            // here.
            let _ = flusher.join.join();
        }
    }
}

/// The flusher thread's body: waits up to `interval` (woken immediately by
/// [`SpendAccumulator::stop_flusher_if_running`]'s `notify_all` on
/// shutdown), flushes on every timeout, and returns -- WITHOUT flushing --
/// as soon as shutdown is signalled. [`SpendAccumulator`]'s `Drop`
/// performs the final flush itself, once this thread has fully stopped, so
/// shutdown has exactly one writer rather than this thread's last flush
/// racing `Drop`'s.
fn run_flusher(inner: Arc<Inner>, shutdown: Arc<ShutdownSignal>, interval: Duration) {
    let mut guard = shutdown
        .stop
        .lock()
        .expect("spend flusher shutdown mutex poisoned");
    loop {
        if *guard {
            return;
        }
        let (new_guard, wait_result) = shutdown
            .cv
            .wait_timeout(guard, interval)
            .expect("spend flusher shutdown condvar poisoned");
        guard = new_guard;
        if *guard {
            return;
        }
        if wait_result.timed_out() {
            // Release the shutdown lock before store I/O -- a concurrent
            // shutdown request must never wait on this tick's flush to
            // finish before it can even set the flag.
            drop(guard);
            if let Err(err) = inner.flush_now() {
                // Two log lines, not one, because they say different things
                // and an operator acts on them differently: the first is
                // "this tick failed", the second is "enforcement has been
                // degraded for longer than you said you would tolerate"
                // (ADR-0006 §5's required warning past the bound).
                tracing::warn!(
                    stat_prefix = %inner.stat_prefix,
                    error = %err,
                    "spend flusher: periodic flush failed; will retry next interval"
                );
                // Only on a FAILED tick, which is what keeps this off the
                // healthy path entirely -- a replica flushing normally
                // evaluates none of it, and one that is broken logs at most
                // once per flush interval (CLAUDE.md rule 17: suppress
                // repeats, or the log becomes the incident).
                let age = inner.reconciliation_age(Utc::now());
                if age > inner.reconciliation.bound {
                    tracing::warn!(
                        stat_prefix = %inner.stat_prefix,
                        node_id = %inner.node_id,
                        age_seconds = age.as_secs(),
                        bound_seconds = inner.reconciliation.bound.as_secs(),
                        on_expired = ?inner.reconciliation.on_expired,
                        unreconciled_admissions =
                            inner.unreconciled_admissions.load(Ordering::Relaxed),
                        "spend accumulator has not reconciled with the store within its \
                         configured bound; this replica is enforcing against its own accrual \
                         only and budgets shared with other replicas may be over-admitted"
                    );
                }
            }
            guard = shutdown
                .stop
                .lock()
                .expect("spend flusher shutdown mutex poisoned");
        }
        // A spurious wakeup with neither shutdown signalled nor a timeout:
        // loop and wait again.
    }
}

impl Drop for SpendAccumulator {
    /// Shuts the flusher thread down (if one was started) and flushes once
    /// more, unconditionally. Without this final flush, every clean
    /// process exit would discard up to one flush interval of spend --
    /// turning the documented crash-refund (see the design brief's
    /// "Enforcement reads live memory" section) into an
    /// ORDINARY-OPERATION refund, which is a much larger and much more
    /// frequent hole than a crash. Pinned by
    /// `drop_flushes_what_was_recorded_since_the_last_tick`; its mutation
    /// pin skips this final flush.
    fn drop(&mut self) {
        self.stop_flusher_if_running();
        if let Err(err) = self.inner.flush_now() {
            tracing::warn!(
                stat_prefix = %self.inner.stat_prefix,
                error = %err,
                "spend accumulator: final flush on shutdown failed; up to one interval \
                 of spend may be lost on the next restart"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(input: u64, cached: u64, cache_creation: u64, output: u64) -> TokenUsage {
        TokenUsage {
            input_tokens: input,
            cached_tokens: cached,
            cache_creation_tokens: cache_creation,
            output_tokens: output,
        }
    }

    // --- parse_micro_usd ---------------------------------------------------

    #[test]
    fn parses_a_typical_two_decimal_price() {
        assert_eq!(
            parse_micro_usd("2.50"),
            Ok(MicroUsd::from_micros(2_500_000))
        );
    }

    #[test]
    fn parses_exactly_six_decimal_places() {
        assert_eq!(parse_micro_usd("0.000001"), Ok(MicroUsd::from_micros(1)));
    }

    #[test]
    fn parses_a_whole_number_with_no_decimal_point_as_whole_dollars() {
        assert_eq!(parse_micro_usd("3"), Ok(MicroUsd::from_micros(3_000_000)));
    }

    #[test]
    fn parses_zero_dot_zero_zero_as_a_genuine_zero_price() {
        assert_eq!(parse_micro_usd("0.00"), Ok(MicroUsd::from_micros(0)));
    }

    #[test]
    fn pads_fewer_than_six_decimal_places_exactly() {
        assert_eq!(parse_micro_usd("2.5"), Ok(MicroUsd::from_micros(2_500_000)));
        assert_eq!(parse_micro_usd("1.1"), Ok(MicroUsd::from_micros(1_100_000)));
    }

    #[test]
    fn rejects_more_than_six_decimal_places_instead_of_truncating() {
        assert_eq!(
            parse_micro_usd("1.1234567"),
            Err(ParsePriceError::TooManyDecimalPlaces)
        );
    }

    #[test]
    fn rejects_empty_string() {
        assert_eq!(parse_micro_usd(""), Err(ParsePriceError::Empty));
    }

    #[test]
    fn rejects_leading_plus() {
        assert_eq!(parse_micro_usd("+2.50"), Err(ParsePriceError::Signed));
    }

    #[test]
    fn rejects_negative_price() {
        assert_eq!(parse_micro_usd("-2.50"), Err(ParsePriceError::Signed));
    }

    #[test]
    fn rejects_non_numeric_input() {
        assert_eq!(parse_micro_usd("abc"), Err(ParsePriceError::NotNumeric));
        assert_eq!(parse_micro_usd("2.5a"), Err(ParsePriceError::NotNumeric));
        assert_eq!(parse_micro_usd("2..5"), Err(ParsePriceError::NotNumeric));
        assert_eq!(parse_micro_usd("."), Err(ParsePriceError::NotNumeric));
    }

    #[test]
    fn rejects_a_value_too_large_to_fit_in_u64_micros() {
        // u64::MAX is ~1.8e19; this whole-dollar value times 1_000_000
        // overflows a u64 outright.
        assert_eq!(
            parse_micro_usd("99999999999999999999"),
            Err(ParsePriceError::Overflow)
        );
    }

    // --- PriceTable::cost_of ------------------------------------------------

    /// The rule-6 centerpiece: the SAME model priced differently on two
    /// clusters must charge each cluster's own rate, keyed on the cluster the
    /// request was actually dialled against -- never the model alone. This is
    /// the exact hazard CLAUDE.md ground rule 6 names for credentials and
    /// `host_rewrite_literal`, restated for money: a lookup that ignored the
    /// cluster would bill a request the fallback served at the primary's
    /// rate.
    #[test]
    fn same_model_priced_differently_on_two_clusters_charges_the_dialled_clusters_own_rate() {
        let mut table = PriceTable::new();
        table.insert(
            "cluster-a",
            "shared-model",
            ModelPrices {
                input_per_million: MicroUsd::from_micros(10_000_000),
                output_per_million: MicroUsd::from_micros(0),
                cached_per_million: MicroUsd::from_micros(0),
                cache_creation_per_million: MicroUsd::from_micros(0),
            },
        );
        table.insert(
            "cluster-b",
            "shared-model",
            ModelPrices {
                input_per_million: MicroUsd::from_micros(1_000_000),
                output_per_million: MicroUsd::from_micros(0),
                cached_per_million: MicroUsd::from_micros(0),
                cache_creation_per_million: MicroUsd::from_micros(0),
            },
        );
        let u = usage(1_000_000, 0, 0, 0);

        assert_eq!(
            table.cost_of(Some("cluster-a"), Some("shared-model"), &u),
            Charge::Priced(MicroUsd::from_micros(10_000_000)),
            "cluster-a's own rate must apply when cluster-a was dialled"
        );
        assert_eq!(
            table.cost_of(Some("cluster-b"), Some("shared-model"), &u),
            Charge::Priced(MicroUsd::from_micros(1_000_000)),
            "cluster-b's own (cheaper) rate must apply when cluster-b was dialled, \
             even though cluster-a prices the identical model name"
        );
    }

    #[test]
    fn unpriced_cluster_is_distinct_from_a_configured_zero_rate() {
        let mut table = PriceTable::new();
        table.insert("priced-cluster", "m", ModelPrices::default());
        let u = usage(1_000_000, 0, 0, 0);

        assert_eq!(
            table.cost_of(Some("priced-cluster"), Some("m"), &u),
            Charge::Priced(MicroUsd::from_micros(0)),
            "an explicitly configured all-zero price is Priced(0), not Unpriced"
        );
        assert_eq!(
            table.cost_of(Some("unknown-cluster"), Some("m"), &u),
            Charge::Unpriced
        );
    }

    #[test]
    fn unpriced_model_on_a_known_cluster_is_unpriced() {
        let mut table = PriceTable::new();
        table.insert("cluster-a", "priced-model", ModelPrices::default());
        let u = usage(1_000_000, 0, 0, 0);

        assert_eq!(
            table.cost_of(Some("cluster-a"), Some("unpriced-model"), &u),
            Charge::Unpriced
        );
    }

    #[test]
    fn none_cluster_is_unpriced() {
        let mut table = PriceTable::new();
        table.insert("cluster-a", "m", ModelPrices::default());
        let u = usage(1_000_000, 0, 0, 0);

        assert_eq!(table.cost_of(None, Some("m"), &u), Charge::Unpriced);
    }

    #[test]
    fn none_model_is_unpriced() {
        let mut table = PriceTable::new();
        table.insert("cluster-a", "m", ModelPrices::default());
        let u = usage(1_000_000, 0, 0, 0);

        assert_eq!(table.cost_of(Some("cluster-a"), None, &u), Charge::Unpriced);
    }

    /// All four buckets charged at their own configured rate -- a usage with
    /// tokens in every bucket must not let any bucket "leak" into another's
    /// rate (in particular, cached tokens must not be billed at the input
    /// rate, the specific overcharge the module doc calls out).
    #[test]
    fn all_four_buckets_are_charged_at_their_own_independent_rate() {
        let mut table = PriceTable::new();
        table.insert(
            "cluster-a",
            "m",
            ModelPrices {
                input_per_million: MicroUsd::from_micros(4_000_000),
                cached_per_million: MicroUsd::from_micros(1_000_000),
                cache_creation_per_million: MicroUsd::from_micros(2_000_000),
                output_per_million: MicroUsd::from_micros(8_000_000),
            },
        );
        // 1,000,000 tokens in each bucket -> each bucket's cost is exactly
        // its own per-million rate.
        let u = usage(1_000_000, 1_000_000, 1_000_000, 1_000_000);

        let Charge::Priced(cost) = table.cost_of(Some("cluster-a"), Some("m"), &u) else {
            panic!("expected a priced charge");
        };
        assert_eq!(
            cost,
            MicroUsd::from_micros(4_000_000 + 1_000_000 + 2_000_000 + 8_000_000)
        );
    }

    #[test]
    fn a_usage_with_only_cached_tokens_is_not_charged_the_input_rate() {
        let mut table = PriceTable::new();
        table.insert(
            "cluster-a",
            "m",
            ModelPrices {
                input_per_million: MicroUsd::from_micros(100_000_000),
                cached_per_million: MicroUsd::from_micros(1_000_000),
                cache_creation_per_million: MicroUsd::from_micros(0),
                output_per_million: MicroUsd::from_micros(0),
            },
        );
        let u = usage(0, 1_000_000, 0, 0);

        assert_eq!(
            table.cost_of(Some("cluster-a"), Some("m"), &u),
            Charge::Priced(MicroUsd::from_micros(1_000_000)),
            "only cached tokens were used, so the cheap cached rate must apply, \
             not the far higher input rate"
        );
    }

    #[test]
    fn a_large_realistic_usage_computes_exactly_without_overflow() {
        let mut table = PriceTable::new();
        table.insert(
            "cluster-a",
            "big-model",
            ModelPrices {
                input_per_million: MicroUsd::from_micros(2_500_000), // $2.50
                output_per_million: MicroUsd::from_micros(10_000_000), // $10.00
                cached_per_million: MicroUsd::from_micros(250_000),  // $0.25
                cache_creation_per_million: MicroUsd::from_micros(3_125_000), // $3.125
            },
        );
        // 50 million input, 2 million output, 10 million cached, 1 million
        // cache-creation tokens -- a large but realistic single-request
        // usage (well within a day's aggregate for a busy tenant).
        let u = usage(50_000_000, 10_000_000, 1_000_000, 2_000_000);

        let expected = 50 * 2_500_000 + 2 * 10_000_000 + 10 * 250_000 + 3_125_000;
        assert_eq!(
            table.cost_of(Some("cluster-a"), Some("big-model"), &u),
            Charge::Priced(MicroUsd::from_micros(expected))
        );
    }

    #[test]
    fn rounding_is_half_up_rather_than_truncating() {
        // 1 micro-dollar per million tokens, 500,000 tokens -> exactly half a
        // micro-dollar -> rounds up to 1, not down to 0.
        assert_eq!(
            round_once(bucket_numerator(MicroUsd::from_micros(1), 500_000)),
            1
        );
        // 1 micro-dollar per million tokens, 499,999 tokens -> just under
        // half -> rounds down to 0.
        assert_eq!(
            round_once(bucket_numerator(MicroUsd::from_micros(1), 499_999)),
            0
        );
    }

    #[test]
    fn rounding_does_not_overflow_at_u64_extremes() {
        // The worst-case product (u64::MAX * u64::MAX) must not panic and
        // must saturate rather than wrap.
        let result = round_once(bucket_numerator(MicroUsd::from_micros(u64::MAX), u64::MAX));
        assert_eq!(result, u64::MAX);
    }

    /// Rounding happens ONCE over the summed buckets, never per bucket --
    /// the module doc's worked example, as an executable assertion.
    ///
    /// Four buckets each costing exactly 0.6 micro-dollars total 2.4, which
    /// rounds to 2. Rounding each bucket first would round each 0.6 up to 1
    /// and charge 4 -- double, on exactly the kind of small request that
    /// dominates real traffic.
    #[test]
    fn four_sub_micro_buckets_are_rounded_once_not_four_times() {
        // 600_000 micro-dollars per million tokens * 1 token = 0.6
        // micro-dollars per bucket, in each of the four buckets.
        let rate = parse_micro_usd("0.600000").expect("a valid rate");
        let mut table = PriceTable::new();
        table.insert(
            "cluster-a",
            "m",
            ModelPrices {
                input_per_million: rate,
                output_per_million: rate,
                cached_per_million: rate,
                cache_creation_per_million: rate,
            },
        );

        assert_eq!(
            table.cost_of(Some("cluster-a"), Some("m"), &usage(1, 1, 1, 1)),
            Charge::Priced(MicroUsd::from_micros(2)),
            "four 0.6-micro-dollar buckets are 2.4 in total and must round ONCE to 2 -- \
             a result of 4 means each bucket was rounded up separately, which doubles \
             the charge on small requests"
        );
    }

    // ------------------------------------------------------------------
    // 3c-ii-b: periods, the accumulator, and the flusher.
    // ------------------------------------------------------------------

    use crate::control::InMemoryControlPlaneStore;

    fn dt(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        use chrono::TimeZone;
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).unwrap()
    }

    /// A fresh [`SpendAccumulator`] and a handle to the [`InMemoryControlPlaneStore`]
    /// backing it, so a test can inspect what was actually flushed.
    fn test_accumulator(period: Period) -> (SpendAccumulator, Arc<InMemoryControlPlaneStore>) {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let accumulator = SpendAccumulator::new(
            "test-chain".to_string(),
            Arc::clone(&store) as Arc<dyn ControlPlaneStore>,
            period,
            "test-node".to_string(),
        );
        (accumulator, store)
    }

    // --- Period keys ----------------------------------------------------

    #[test]
    fn daily_period_renders_as_the_utc_calendar_date() {
        assert_eq!(
            Period::Daily.key_for(dt(2026, 8, 31, 12, 0, 0)),
            PeriodKey::for_test("2026-08-31")
        );
    }

    #[test]
    fn monthly_period_renders_as_the_utc_calendar_month() {
        assert_eq!(
            Period::Monthly.key_for(dt(2026, 8, 31, 12, 0, 0)),
            PeriodKey::for_test("2026-08")
        );
    }

    #[test]
    fn daily_period_differs_either_side_of_a_utc_day_boundary() {
        let before = Period::Daily.key_for(dt(2026, 8, 31, 23, 59, 59));
        let after = Period::Daily.key_for(dt(2026, 9, 1, 0, 0, 0));
        assert_ne!(before, after);
        assert_eq!(before, PeriodKey::for_test("2026-08-31"));
        assert_eq!(after, PeriodKey::for_test("2026-09-01"));
    }

    #[test]
    fn monthly_period_differs_either_side_of_a_utc_month_boundary() {
        let before = Period::Monthly.key_for(dt(2026, 8, 31, 23, 59, 59));
        let after = Period::Monthly.key_for(dt(2026, 9, 1, 0, 0, 0));
        assert_ne!(before, after);
        assert_eq!(before, PeriodKey::for_test("2026-08"));
        assert_eq!(after, PeriodKey::for_test("2026-09"));
    }

    #[test]
    fn daily_period_differs_either_side_of_a_leap_year_february_boundary() {
        // 2028 is a leap year: February has 29 days, not 28.
        let before = Period::Daily.key_for(dt(2028, 2, 29, 23, 59, 59));
        let after = Period::Daily.key_for(dt(2028, 3, 1, 0, 0, 0));
        assert_ne!(before, after);
        assert_eq!(before, PeriodKey::for_test("2028-02-29"));
        assert_eq!(after, PeriodKey::for_test("2028-03-01"));
    }

    #[test]
    fn daily_next_boundary_is_the_start_of_the_following_utc_day() {
        assert_eq!(
            Period::Daily.next_boundary(dt(2026, 8, 31, 13, 0, 0)),
            dt(2026, 9, 1, 0, 0, 0)
        );
        assert_eq!(
            Period::Daily.seconds_until_reset(dt(2026, 8, 31, 23, 59, 0)),
            60
        );
    }

    #[test]
    fn monthly_next_boundary_is_the_first_of_the_following_utc_month() {
        assert_eq!(
            Period::Monthly.next_boundary(dt(2026, 8, 15, 13, 0, 0)),
            dt(2026, 9, 1, 0, 0, 0)
        );
        // December must roll the YEAR over too, not just the month.
        assert_eq!(
            Period::Monthly.next_boundary(dt(2026, 12, 15, 13, 0, 0)),
            dt(2027, 1, 1, 0, 0, 0)
        );
    }

    // --- Rollover on record, not on the flush tick -----------------------

    #[test]
    fn rollover_splits_into_two_period_rows_not_one_when_the_flush_ticks_late() {
        let (accumulator, store) = test_accumulator(Period::Daily);
        let tenant = TenantId::new("tenant-a");

        let before_boundary = dt(2026, 8, 31, 23, 59, 59);
        let after_boundary = dt(2026, 9, 1, 0, 0, 1);

        accumulator.record(
            &tenant,
            before_boundary,
            Period::Daily,
            Charge::Priced(MicroUsd::from_micros(1_000_000)),
            Some("cluster-a"),
            Some("model-a"),
        );
        accumulator.record(
            &tenant,
            after_boundary,
            Period::Daily,
            Charge::Priced(MicroUsd::from_micros(2_000_000)),
            Some("cluster-a"),
            Some("model-a"),
        );

        // ONE flush, well after both records -- simulating a flusher that
        // woke up late, past the boundary. If rollover happened on the
        // flush tick's own "now" instead of on each record's own
        // timestamp, this single flush could fold both records into ONE
        // row instead of two.
        accumulator.flush_now().unwrap();

        let day_31 = store
            .load_spend("test-chain", &tenant, &PeriodKey::for_test("2026-08-31"))
            .unwrap();
        let day_01 = store
            .load_spend("test-chain", &tenant, &PeriodKey::for_test("2026-09-01"))
            .unwrap();

        assert_eq!(
            (day_31, day_01),
            (1_000_000, 2_000_000),
            "a record's period must be fixed at RECORD time, not recomputed on the flush \
             tick -- a late-waking flusher must never merge two periods' spend into one row"
        );
    }

    // --- record takes its period explicitly (WP-50 3c-iii-b fixup) -------

    /// The defect this fixup closes, as an executable assertion: ONE
    /// accumulator, TWO tenants, each with its OWN period -- a daily-budget
    /// tenant and a monthly-budget tenant, the exact combination that cannot
    /// coexist correctly if `record` uses a single accumulator-wide period
    /// instead of the caller-supplied one. Each tenant's charge must land in
    /// its OWN period's row, not both landing in whatever period the
    /// accumulator happened to be constructed with.
    #[test]
    fn two_tenants_with_different_periods_each_accrue_into_their_own_period_key() {
        // Constructed with a `default_period` that matches NEITHER tenant's
        // actual period below -- if `record` ever fell back to it instead of
        // the passed-in period, both charges would land in the wrong row (or
        // the same row), and this test would still have to fail to catch it.
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let accumulator = SpendAccumulator::new(
            "test-chain".to_string(),
            Arc::clone(&store) as Arc<dyn ControlPlaneStore>,
            Period::Monthly,
            "test-node".to_string(),
        );

        let daily_tenant = TenantId::new("tenant-daily");
        let monthly_tenant = TenantId::new("tenant-monthly");
        let now = dt(2026, 8, 31, 12, 0, 0);

        accumulator.record(
            &daily_tenant,
            now,
            Period::Daily,
            Charge::Priced(MicroUsd::from_micros(3_000_000)),
            Some("cluster-a"),
            Some("model-a"),
        );
        accumulator.record(
            &monthly_tenant,
            now,
            Period::Monthly,
            Charge::Priced(MicroUsd::from_micros(4_000_000)),
            Some("cluster-a"),
            Some("model-a"),
        );

        assert_eq!(
            accumulator.current_total(&daily_tenant, &Period::Daily.key_for(now)),
            3_000_000,
            "the daily-budget tenant's charge must land in ITS OWN daily period key"
        );
        assert_eq!(
            accumulator.current_total(&monthly_tenant, &Period::Monthly.key_for(now)),
            4_000_000,
            "the monthly-budget tenant's charge must land in ITS OWN monthly period key"
        );
        assert_eq!(
            accumulator.current_total(&daily_tenant, &Period::Monthly.key_for(now)),
            0,
            "the daily tenant's charge must NOT have leaked into a monthly-keyed row"
        );
        assert_eq!(
            accumulator.current_total(&monthly_tenant, &Period::Daily.key_for(now)),
            0,
            "the monthly tenant's charge must NOT have leaked into a daily-keyed row"
        );

        accumulator.flush_now().unwrap();
        assert_eq!(
            store
                .load_spend("test-chain", &daily_tenant, &Period::Daily.key_for(now))
                .unwrap(),
            3_000_000
        );
        assert_eq!(
            store
                .load_spend("test-chain", &monthly_tenant, &Period::Monthly.key_for(now))
                .unwrap(),
            4_000_000
        );
    }

    // --- Absolute-write idempotence --------------------------------------

    #[test]
    fn flush_now_twice_with_no_new_record_leaves_the_stored_total_unchanged() {
        let (accumulator, store) = test_accumulator(Period::Daily);
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 8, 31, 12, 0, 0);

        accumulator.record(
            &tenant,
            now,
            Period::Daily,
            Charge::Priced(MicroUsd::from_micros(5_000_000)),
            Some("cluster-a"),
            Some("model-a"),
        );
        accumulator.flush_now().unwrap();
        accumulator.flush_now().unwrap();

        let total = store
            .load_spend("test-chain", &tenant, &PeriodKey::for_test("2026-08-31"))
            .unwrap();
        assert_eq!(
            total, 5_000_000,
            "a second flush with nothing recorded in between must send a delta of ZERO. \
             WP-60 made the write additive, so a flusher that re-sent its running total \
             instead of what it has yet to hand over would double the charge on every \
             tick"
        );
    }

    // --- Restart resume ----------------------------------------------------

    #[test]
    fn a_new_accumulator_over_the_same_store_resumes_the_stored_total() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 8, 31, 12, 0, 0);

        {
            let accumulator_a = SpendAccumulator::new(
                "test-chain".to_string(),
                Arc::clone(&store) as Arc<dyn ControlPlaneStore>,
                Period::Daily,
                "test-node".to_string(),
            );
            accumulator_a.record(
                &tenant,
                now,
                Period::Daily,
                Charge::Priced(MicroUsd::from_micros(7_000_000)),
                Some("cluster-a"),
                Some("model-a"),
            );
            accumulator_a.flush_now().unwrap();
        }

        let accumulator_b = SpendAccumulator::new(
            "test-chain".to_string(),
            Arc::clone(&store) as Arc<dyn ControlPlaneStore>,
            Period::Daily,
            "test-node".to_string(),
        );
        let period_key = Period::Daily.key_for(now);
        assert_eq!(
            accumulator_b.current_total(&tenant, &period_key),
            7_000_000,
            "a fresh accumulator over the same store must resume the flushed total, \
             not reset to zero -- a restart must not forget spend that already happened"
        );
    }

    /// A `load_spend` failure on first touch of a period must not lose the
    /// request: the bucket resumes from zero (logged loudly) rather than
    /// the accumulator refusing to record at all. Per CLAUDE.md rule 17.
    #[test]
    fn a_load_spend_failure_on_first_touch_resumes_from_zero_instead_of_losing_the_request() {
        struct AlwaysFailsLoadSpend(InMemoryControlPlaneStore);

        impl ControlPlaneStore for AlwaysFailsLoadSpend {
            fn load(&self) -> Result<crate::control::StoredControlPlane, StoreError> {
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
            fn put_key(&self, rec: &crate::control::StoredKey) -> Result<(), StoreError> {
                self.0.put_key(rec)
            }
            fn revoke_key(&self, key_id: &crate::auth::KeyId) -> Result<(), StoreError> {
                self.0.revoke_key(key_id)
            }
            fn set_policy(
                &self,
                tenant: &TenantId,
                access: &crate::model_authz::ModelAccess,
            ) -> Result<(), StoreError> {
                self.0.set_policy(tenant, access)
            }
            fn set_budget(
                &self,
                tenant: &TenantId,
                budget: Option<&TenantBudget>,
            ) -> Result<(), StoreError> {
                self.0.set_budget(tenant, budget)
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
                _stat_prefix: &str,
                _tenant: &TenantId,
                _period: &PeriodKey,
            ) -> Result<u64, StoreError> {
                Err(StoreError::Unavailable(
                    "test double: load_spend always fails".to_string(),
                ))
            }
        }

        let store: Arc<dyn ControlPlaneStore> =
            Arc::new(AlwaysFailsLoadSpend(InMemoryControlPlaneStore::default()));
        let accumulator = SpendAccumulator::new(
            "test-chain".to_string(),
            store,
            Period::Daily,
            "test-node".to_string(),
        );
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 8, 31, 12, 0, 0);

        // Must not panic and must still record -- the load failure is
        // logged, not propagated as a lost request.
        accumulator.record(
            &tenant,
            now,
            Period::Daily,
            Charge::Priced(MicroUsd::from_micros(4_000_000)),
            Some("cluster-a"),
            Some("model-a"),
        );

        assert_eq!(
            accumulator.current_total(&tenant, &Period::Daily.key_for(now)),
            4_000_000,
            "a failed resume-load must start the bucket at zero and still record the \
             CURRENT request, not drop it"
        );
    }

    // --- Unpriced requests -------------------------------------------------

    #[test]
    fn unpriced_charge_increments_count_and_pair_but_not_total() {
        let (accumulator, _store) = test_accumulator(Period::Daily);
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 8, 31, 12, 0, 0);
        let period_key = Period::Daily.key_for(now);

        accumulator.record(
            &tenant,
            now,
            Period::Daily,
            Charge::Unpriced,
            Some("cluster-a"),
            Some("model-a"),
        );

        assert_eq!(
            accumulator.current_total(&tenant, &period_key),
            0,
            "an unpriced charge must not add anything to the spend total"
        );

        let buckets = accumulator.inner.buckets.lock().unwrap();
        let bucket = buckets.get(&(tenant.clone(), period_key.clone())).unwrap();
        assert_eq!(bucket.unpriced_requests, 1);
        assert!(
            bucket
                .unpriced_pairs
                .contains(&("cluster-a".to_string(), "model-a".to_string())),
            "the (cluster, model) pair of an unpriced request must be recorded"
        );
        assert!(!bucket.unpriced_pairs_truncated);
    }

    #[test]
    fn unpriced_pairs_cap_at_32_pairs_and_set_the_truncated_flag() {
        let (accumulator, _store) = test_accumulator(Period::Daily);
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 8, 31, 12, 0, 0);
        let period_key = Period::Daily.key_for(now);

        for i in 0..40 {
            accumulator.record(
                &tenant,
                now,
                Period::Daily,
                Charge::Unpriced,
                Some("cluster-a"),
                Some(&format!("model-{i}")),
            );
        }

        let buckets = accumulator.inner.buckets.lock().unwrap();
        let bucket = buckets.get(&(tenant.clone(), period_key.clone())).unwrap();
        assert_eq!(bucket.unpriced_requests, 40);
        assert_eq!(
            bucket.unpriced_pairs.len(),
            32,
            "the distinct-pair set must stop growing once MAX_UNPRICED_PAIRS is reached"
        );
        assert!(
            bucket.unpriced_pairs_truncated,
            "once the cap is hit, the truncated flag must be set so a reader knows there \
             were more distinct pairs than the set shows"
        );
    }

    // --- Flusher liveness is a durability concern, not a security one ------

    #[test]
    fn current_total_reflects_a_record_even_when_the_flusher_has_not_ticked() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let accumulator = Arc::new(SpendAccumulator::new(
            "test-chain".to_string(),
            Arc::clone(&store) as Arc<dyn ControlPlaneStore>,
            Period::Daily,
            "test-node".to_string(),
        ));
        // A very long interval: for the life of this test, the flusher
        // thread is running but will never tick -- functionally
        // indistinguishable, from `current_total`'s point of view, from a
        // thread that panicked and died outright. Enforcement (a future
        // 3c-iii filter) reads `current_total`, never the flusher's state,
        // so neither case can loosen what it sees.
        accumulator.start_flusher(Duration::from_secs(3600));

        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 8, 31, 12, 0, 0);
        let period_key = Period::Daily.key_for(now);
        accumulator.record(
            &tenant,
            now,
            Period::Daily,
            Charge::Priced(MicroUsd::from_micros(3_000_000)),
            Some("cluster-a"),
            Some("model-a"),
        );

        assert_eq!(
            accumulator.current_total(&tenant, &period_key),
            3_000_000,
            "current_total must reflect the live in-memory record regardless of whether \
             the flusher has ticked yet -- a dead or slow flusher must not change what \
             enforcement sees"
        );
        assert_eq!(
            store
                .load_spend("test-chain", &tenant, &period_key)
                .unwrap(),
            0,
            "the store must NOT have this total yet -- proves current_total reads live \
             memory rather than secretly reading the last flushed value"
        );
    }

    // --- Drop flushes --------------------------------------------------------

    #[test]
    fn drop_flushes_what_was_recorded_since_the_last_tick() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 8, 31, 12, 0, 0);

        {
            let accumulator = Arc::new(SpendAccumulator::new(
                "test-chain".to_string(),
                Arc::clone(&store) as Arc<dyn ControlPlaneStore>,
                Period::Daily,
                "test-node".to_string(),
            ));
            // A long interval so the flusher thread is started but has no
            // realistic chance to tick before the accumulator drops -- if
            // `Drop` itself did not flush, this record would be lost.
            accumulator.start_flusher(Duration::from_secs(3600));
            accumulator.record(
                &tenant,
                now,
                Period::Daily,
                Charge::Priced(MicroUsd::from_micros(9_000_000)),
                Some("cluster-a"),
                Some("model-a"),
            );
        } // The last `Arc<SpendAccumulator>` clone drops here.

        let period_key = Period::Daily.key_for(now);
        assert_eq!(
            store
                .load_spend("test-chain", &tenant, &period_key)
                .unwrap(),
            9_000_000,
            "Drop must flush what was recorded since the flusher's last tick -- \
             otherwise a clean shutdown loses up to one interval of spend, turning the \
             documented crash-refund into an ordinary-operation refund"
        );
    }

    // ------------------------------------------------------------------
    // 3c-iv: `SpendAccumulator::report` and `last_flush_at`.
    // ------------------------------------------------------------------

    #[test]
    fn last_flush_at_is_none_before_any_flush() {
        let (accumulator, _store) = test_accumulator(Period::Daily);
        assert_eq!(accumulator.last_flush_at(), None);
    }

    #[test]
    fn last_flush_at_advances_on_a_successful_flush() {
        let (accumulator, _store) = test_accumulator(Period::Daily);
        accumulator.flush_now().expect("flush must succeed");
        assert!(
            accumulator.last_flush_at().is_some(),
            "a successful flush (even of zero buckets) must set last_flush_at"
        );
    }

    /// A store double whose `add_spend` always fails -- the mirror image of
    /// `AlwaysFailsLoadSpend` above, used to prove a FAILED flush must not
    /// advance `last_flush_at`. Pinned by `a_failed_flush_does_not_advance_last_flush_at`;
    /// its mutation pin has `Inner::flush_now` set `last_flush_at`
    /// unconditionally instead of only in the `None` (no error) arm.
    struct AlwaysFailsAddSpend(InMemoryControlPlaneStore);

    impl ControlPlaneStore for AlwaysFailsAddSpend {
        fn load(&self) -> Result<crate::control::StoredControlPlane, StoreError> {
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
        fn put_key(&self, rec: &crate::control::StoredKey) -> Result<(), StoreError> {
            self.0.put_key(rec)
        }
        fn revoke_key(&self, key_id: &crate::auth::KeyId) -> Result<(), StoreError> {
            self.0.revoke_key(key_id)
        }
        fn set_policy(
            &self,
            tenant: &TenantId,
            access: &crate::model_authz::ModelAccess,
        ) -> Result<(), StoreError> {
            self.0.set_policy(tenant, access)
        }
        fn set_budget(
            &self,
            tenant: &TenantId,
            budget: Option<&TenantBudget>,
        ) -> Result<(), StoreError> {
            self.0.set_budget(tenant, budget)
        }
        fn add_spend(
            &self,
            _stat_prefix: &str,
            _tenant: &TenantId,
            _period: &PeriodKey,
            _delta_micros: u64,
            _token: FlushToken<'_>,
        ) -> Result<u64, StoreError> {
            Err(StoreError::Unavailable(
                "test double: add_spend always fails".to_string(),
            ))
        }
        fn overwrite_spend(
            &self,
            _stat_prefix: &str,
            _tenant: &TenantId,
            _period: &PeriodKey,
            _total_micros: u64,
        ) -> Result<(), StoreError> {
            Err(StoreError::Unavailable(
                "test double: overwrite_spend always fails".to_string(),
            ))
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

    #[test]
    fn a_failed_flush_does_not_advance_last_flush_at() {
        let store: Arc<dyn ControlPlaneStore> =
            Arc::new(AlwaysFailsAddSpend(InMemoryControlPlaneStore::default()));
        let accumulator = SpendAccumulator::new(
            "test-chain".to_string(),
            store,
            Period::Daily,
            "test-node".to_string(),
        );
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 8, 31, 12, 0, 0);

        // A bucket to flush, so `flush_now` actually attempts a write (and
        // fails) rather than trivially succeeding over zero buckets.
        accumulator.record(
            &tenant,
            now,
            Period::Daily,
            Charge::Priced(MicroUsd::from_micros(1_000_000)),
            Some("cluster-a"),
            Some("model-a"),
        );

        assert!(accumulator.flush_now().is_err(), "the flush must fail");
        assert_eq!(
            accumulator.last_flush_at(),
            None,
            "a FAILED flush must not advance last_flush_at -- doing so would claim \
             durability the store does not actually have"
        );
    }

    #[test]
    fn report_on_a_never_touched_tenant_period_is_all_zeros_not_an_error() {
        let (accumulator, _store) = test_accumulator(Period::Daily);
        let tenant = TenantId::new("tenant-never-spent");
        let period_key = PeriodKey::for_test("2026-08-31");

        let report = accumulator.report(&tenant, &period_key);

        assert_eq!(report.total_micros, 0);
        assert_eq!(report.unpriced_requests, 0);
        assert!(report.unpriced_pairs.is_empty());
        assert!(!report.unpriced_pairs_truncated);
        assert_eq!(report.last_flush_at, None);
    }

    #[test]
    fn report_reflects_live_spend_and_unpriced_discoverability() {
        let (accumulator, _store) = test_accumulator(Period::Daily);
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 8, 31, 12, 0, 0);
        let period_key = Period::Daily.key_for(now);

        accumulator.record(
            &tenant,
            now,
            Period::Daily,
            Charge::Priced(MicroUsd::from_micros(6_000_000)),
            Some("cluster-a"),
            Some("model-a"),
        );
        accumulator.record(
            &tenant,
            now,
            Period::Daily,
            Charge::Unpriced,
            Some("cluster-b"),
            Some("unpriced-model"),
        );
        accumulator.flush_now().expect("flush must succeed");

        let report = accumulator.report(&tenant, &period_key);

        assert_eq!(report.total_micros, 6_000_000);
        assert_eq!(report.unpriced_requests, 1);
        assert_eq!(
            report.unpriced_pairs,
            vec![("cluster-b".to_string(), "unpriced-model".to_string())]
        );
        assert!(!report.unpriced_pairs_truncated);
        assert!(
            report.last_flush_at.is_some(),
            "report must surface the accumulator's last successful flush time"
        );
    }

    #[test]
    fn report_sorts_unpriced_pairs_for_stable_output() {
        let (accumulator, _store) = test_accumulator(Period::Daily);
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 8, 31, 12, 0, 0);
        let period_key = Period::Daily.key_for(now);

        // Recorded in reverse-sorted order -- the report must still come
        // back sorted.
        for (cluster, model) in [("cluster-z", "model-z"), ("cluster-a", "model-a")] {
            accumulator.record(
                &tenant,
                now,
                Period::Daily,
                Charge::Unpriced,
                Some(cluster),
                Some(model),
            );
        }

        let report = accumulator.report(&tenant, &period_key);
        assert_eq!(
            report.unpriced_pairs,
            vec![
                ("cluster-a".to_string(), "model-a".to_string()),
                ("cluster-z".to_string(), "model-z".to_string()),
            ],
            "unpriced_pairs must be sorted regardless of record order"
        );
    }

    // --- WP-60: two replicas over one store ---------------------------------
    //
    // The acceptance test this work package exists for, plus the properties
    // that make it hold. `control.rs` covers the store contract these lean
    // on; these cover the accumulator's half -- adopting the returned total,
    // and never advancing a sequence the store has not confirmed.

    /// Builds an accumulator over an EXISTING store, so several can share
    /// one -- `test_accumulator` above always makes its own.
    fn accumulator_on(
        store: &Arc<InMemoryControlPlaneStore>,
        node_id: &str,
        period: Period,
    ) -> SpendAccumulator {
        SpendAccumulator::new(
            "test-chain".to_string(),
            Arc::clone(store) as Arc<dyn ControlPlaneStore>,
            period,
            node_id.to_string(),
        )
    }

    fn record_micros(accumulator: &SpendAccumulator, tenant: &TenantId, at: DateTime<Utc>, m: u64) {
        accumulator.record(
            tenant,
            at,
            Period::Daily,
            Charge::Priced(MicroUsd::from_micros(m)),
            Some("cluster-a"),
            Some("model-a"),
        );
    }

    /// THE acceptance test (ADR-0006 §3): two replicas metering the same
    /// tenant against one shared store converge on the true total. It was
    /// not writable while the store took absolute totals -- whichever
    /// replica flushed last simply erased the other, and the budget it
    /// enforced was its own traffic only.
    #[test]
    fn two_accumulators_sharing_one_store_converge_on_the_true_total() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 9, 3, 12, 0, 0);
        let period_key = Period::Daily.key_for(now);

        let replica_a = accumulator_on(&store, "node-a", Period::Daily);
        let replica_b = accumulator_on(&store, "node-b", Period::Daily);

        record_micros(&replica_a, &tenant, now, 10_000_000);
        record_micros(&replica_b, &tenant, now, 5_000_000);

        // Before any flush each replica knows only its own traffic. That is
        // expected, and it is the window the flush interval bounds.
        assert_eq!(replica_a.current_total(&tenant, &period_key), 10_000_000);
        assert_eq!(replica_b.current_total(&tenant, &period_key), 5_000_000);

        replica_a.flush_now().unwrap();
        replica_b.flush_now().unwrap();

        assert_eq!(
            store
                .load_spend("test-chain", &tenant, &period_key)
                .unwrap(),
            15_000_000,
            "both replicas' spend must be in the store; an absolute write would leave \
             whichever flushed last"
        );
        assert_eq!(
            replica_b.current_total(&tenant, &period_key),
            15_000_000,
            "replica B flushed second, so `add_spend` returned the combined total and B \
             must have ADOPTED it -- a replica that ignores the return value enforces \
             against its own traffic alone, which is the bug this replaces"
        );

        // One more tick and A, which has recorded nothing since, has caught
        // up too. A replica converges by FLUSHING, not by serving traffic.
        replica_a.flush_now().unwrap();
        assert_eq!(replica_a.current_total(&tenant, &period_key), 15_000_000);

        // And converged means STABLE: flushing again must not re-add either
        // replica's own contribution on top of the total it adopted.
        replica_a.flush_now().unwrap();
        replica_b.flush_now().unwrap();
        assert_eq!(
            store
                .load_spend("test-chain", &tenant, &period_key)
                .unwrap(),
            15_000_000,
            "a flush with nothing new recorded must be a zero delta; a replica that \
             re-sends its running total charges itself again on every tick"
        );
    }

    /// An idle replica still reconciles. This is why `flush_now` has no
    /// "nothing to do" early return, and why ADR-0006 §5 forbids a
    /// single-replica short circuit: a replica serving no traffic that never
    /// calls the store would admit requests against a ceiling it believes is
    /// empty.
    #[test]
    fn a_replica_that_recorded_nothing_still_learns_the_other_replicas_spend() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 9, 3, 12, 0, 0);
        let period_key = Period::Daily.key_for(now);

        let busy = accumulator_on(&store, "node-busy", Period::Daily);
        let idle = accumulator_on(&store, "node-idle", Period::Daily);

        record_micros(&busy, &tenant, now, 9_000_000);
        busy.flush_now().unwrap();

        // Touch the row on the idle replica so it has a bucket at all, then
        // flush with nothing of its own to contribute.
        assert_eq!(idle.current_total(&tenant, &period_key), 9_000_000);
        idle.flush_now().unwrap();

        assert_eq!(
            store
                .load_spend("test-chain", &tenant, &period_key)
                .unwrap(),
            9_000_000,
            "the idle replica's zero-delta flush must not disturb the total"
        );
        assert_eq!(idle.current_total(&tenant, &period_key), 9_000_000);
    }

    /// A restarted replica keeps its own sequence going. Without seeding
    /// from [`ControlPlaneStore::last_flush_seq`] the new process starts at
    /// 1, the store sees a sequence it has already accepted, and every flush
    /// is silently dropped as a replay -- spend accruing in memory forever
    /// while the store never moves.
    #[test]
    fn a_restarted_replica_reusing_its_node_id_still_gets_its_flushes_accepted() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 9, 3, 12, 0, 0);
        let period_key = Period::Daily.key_for(now);

        {
            let before_restart = accumulator_on(&store, "node-a", Period::Daily);
            record_micros(&before_restart, &tenant, now, 3_000_000);
            before_restart.flush_now().unwrap();
            // A second tick, so the pre-restart sequence is provably past 1.
            before_restart.flush_now().unwrap();
        }

        let after_restart = accumulator_on(&store, "node-a", Period::Daily);
        record_micros(&after_restart, &tenant, now, 4_000_000);
        after_restart.flush_now().unwrap();

        assert_eq!(
            store
                .load_spend("test-chain", &tenant, &period_key)
                .unwrap(),
            7_000_000,
            "the restarted process's flush must land; starting its sequence from 1 makes \
             the store read it as a replay of the previous process and drop it"
        );
        assert_eq!(after_restart.current_total(&tenant, &period_key), 7_000_000);
    }

    /// At-most-once delivery: a flush whose write landed but whose response
    /// was lost is retried under the SAME sequence, so the store recognises
    /// it rather than charging twice.
    #[test]
    fn a_failed_flush_is_retried_under_the_same_sequence_and_never_double_charges() {
        /// Fails the FIRST `add_spend` after the delta has already been
        /// applied to the wrapped store -- the "write landed, response lost"
        /// case, which is the only one a retry can get wrong.
        struct LosesTheFirstResponse {
            inner: InMemoryControlPlaneStore,
            failed_once: std::sync::atomic::AtomicBool,
        }

        impl ControlPlaneStore for LosesTheFirstResponse {
            fn load(&self) -> Result<crate::control::StoredControlPlane, StoreError> {
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
            fn put_key(&self, rec: &crate::control::StoredKey) -> Result<(), StoreError> {
                self.inner.put_key(rec)
            }
            fn revoke_key(&self, key_id: &crate::auth::KeyId) -> Result<(), StoreError> {
                self.inner.revoke_key(key_id)
            }
            fn set_policy(
                &self,
                tenant: &TenantId,
                access: &crate::model_authz::ModelAccess,
            ) -> Result<(), StoreError> {
                self.inner.set_policy(tenant, access)
            }
            fn set_budget(
                &self,
                tenant: &TenantId,
                budget: Option<&TenantBudget>,
            ) -> Result<(), StoreError> {
                self.inner.set_budget(tenant, budget)
            }
            fn add_spend(
                &self,
                stat_prefix: &str,
                tenant: &TenantId,
                period: &PeriodKey,
                delta_micros: u64,
                token: FlushToken<'_>,
            ) -> Result<u64, StoreError> {
                let total =
                    self.inner
                        .add_spend(stat_prefix, tenant, period, delta_micros, token)?;
                if !self
                    .failed_once
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(StoreError::Unavailable(
                        "test double: the write landed, the response did not".to_string(),
                    ));
                }
                Ok(total)
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

        let store = Arc::new(LosesTheFirstResponse {
            inner: InMemoryControlPlaneStore::default(),
            failed_once: std::sync::atomic::AtomicBool::new(false),
        });
        let accumulator = SpendAccumulator::new(
            "test-chain".to_string(),
            Arc::clone(&store) as Arc<dyn ControlPlaneStore>,
            Period::Daily,
            "node-a".to_string(),
        );
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 9, 3, 12, 0, 0);
        let period_key = Period::Daily.key_for(now);

        record_micros(&accumulator, &tenant, now, 6_000_000);
        accumulator
            .flush_now()
            .expect_err("the first flush must report the lost response");
        // The write DID land, so the store already holds it.
        assert_eq!(
            store
                .inner
                .load_spend("test-chain", &tenant, &period_key)
                .unwrap(),
            6_000_000
        );

        accumulator.flush_now().unwrap();
        assert_eq!(
            store
                .inner
                .load_spend("test-chain", &tenant, &period_key)
                .unwrap(),
            6_000_000,
            "the retry must reuse the sequence of the attempt that failed, so the store \
             recognises it as a replay; a fresh sequence charges the same spend twice"
        );
        assert_eq!(accumulator.current_total(&tenant, &period_key), 6_000_000);
    }

    /// The crash bound: everything recorded BEFORE a successful flush is
    /// durable, and only what was recorded after it is at risk. One flush
    /// interval, no more -- the "crash refund" the design accepts.
    #[test]
    fn a_crash_loses_at_most_the_spend_recorded_since_the_last_flush() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 9, 3, 12, 0, 0);
        let period_key = Period::Daily.key_for(now);

        let before_crash = accumulator_on(&store, "node-a", Period::Daily);
        record_micros(&before_crash, &tenant, now, 8_000_000);
        before_crash.flush_now().unwrap();
        record_micros(&before_crash, &tenant, now, 2_000_000);
        // No flush, and no `drop` either -- `Drop` flushes, which a crash
        // does not do. `forget` is what makes this a crash rather than a
        // clean shutdown.
        assert_eq!(before_crash.current_total(&tenant, &period_key), 10_000_000);
        std::mem::forget(before_crash);

        let after_crash = accumulator_on(&store, "node-a", Period::Daily);
        assert_eq!(
            after_crash.current_total(&tenant, &period_key),
            8_000_000,
            "the flushed 8 survives and only the unflushed 2 is refunded -- losing the 8 \
             as well would make a bounce reset the ceiling"
        );
    }

    /// `overwrite_spend` is admin-only. The flush path must never reach it,
    /// or a replica's absolute total would erase every other replica's
    /// spend -- the exact failure additive writes exist to remove.
    #[test]
    fn the_flush_path_never_calls_overwrite_spend() {
        struct PanicsOnOverwrite(InMemoryControlPlaneStore);

        impl ControlPlaneStore for PanicsOnOverwrite {
            fn load(&self) -> Result<crate::control::StoredControlPlane, StoreError> {
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
            fn put_key(&self, rec: &crate::control::StoredKey) -> Result<(), StoreError> {
                self.0.put_key(rec)
            }
            fn revoke_key(&self, key_id: &crate::auth::KeyId) -> Result<(), StoreError> {
                self.0.revoke_key(key_id)
            }
            fn set_policy(
                &self,
                tenant: &TenantId,
                access: &crate::model_authz::ModelAccess,
            ) -> Result<(), StoreError> {
                self.0.set_policy(tenant, access)
            }
            fn set_budget(
                &self,
                tenant: &TenantId,
                budget: Option<&TenantBudget>,
            ) -> Result<(), StoreError> {
                self.0.set_budget(tenant, budget)
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
                _stat_prefix: &str,
                _tenant: &TenantId,
                _period: &PeriodKey,
                _total_micros: u64,
            ) -> Result<(), StoreError> {
                panic!(
                    "the spend flush path reached overwrite_spend; an absolute write from a \
                     replica erases every other replica's spend"
                );
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

        let store: Arc<dyn ControlPlaneStore> =
            Arc::new(PanicsOnOverwrite(InMemoryControlPlaneStore::default()));
        let accumulator = SpendAccumulator::new(
            "test-chain".to_string(),
            store,
            Period::Daily,
            "node-a".to_string(),
        );
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 9, 3, 12, 0, 0);

        record_micros(&accumulator, &tenant, now, 1_000_000);
        accumulator.flush_now().unwrap();
        // And through `Drop`'s final flush, which is a second call site.
        drop(accumulator);
    }

    // --- WP-62: reconciliation staleness (ADR-0006 §5) ----------------------
    //
    // These read the clock, so they take `now` as `Utc::now()` offset by a
    // chrono `Duration` rather than the fixed `dt(...)` timestamps the rest
    // of this module uses: `reconciliation_age` measures against the
    // accumulator's own construction time, which is real wall-clock, and a
    // hardcoded 2026-09-03 would measure the distance to that date instead
    // of the thing under test. Only the STALENESS clock is real here; no
    // test sleeps.

    fn accumulator_with_bound(bound: Duration) -> SpendAccumulator {
        SpendAccumulator::with_reconciliation(
            "test-chain".to_string(),
            Arc::new(InMemoryControlPlaneStore::default()) as Arc<dyn ControlPlaneStore>,
            Period::Daily,
            "node-a".to_string(),
            ReconciliationPolicy {
                bound,
                on_expired: OnReconciliationExpired::Allow,
            },
        )
    }

    fn seconds_from_now(secs: i64) -> DateTime<Utc> {
        Utc::now() + chrono::Duration::seconds(secs)
    }

    /// A replica that has NEVER reached the store measures its staleness
    /// from construction, not from zero. This is the whole shape of the
    /// fix: a process that came up while the store was down is the MOST
    /// unreconciled it can be, and reporting that as "age 0, reconciled"
    /// would be the fail-open-and-silent failure rule 17 exists to stop.
    ///
    /// Mutation: have `Inner::reconciliation_age` return
    /// `Duration::ZERO` in the `NEVER_FLUSHED` arm.
    #[test]
    fn a_replica_that_never_reached_the_store_is_stale_from_construction() {
        let accumulator = accumulator_with_bound(Duration::from_secs(60));

        assert_eq!(
            accumulator.last_flush_at(),
            None,
            "precondition: nothing has flushed"
        );
        assert!(
            accumulator.reconciliation_age(seconds_from_now(90)) >= Duration::from_secs(90),
            "a never-flushed replica must measure its age from construction; reporting zero \
             would call the worst case healthy"
        );
        assert!(
            !accumulator.is_reconciled(seconds_from_now(90)),
            "90s past construction with a 60s bound is expired"
        );
        assert!(
            accumulator.is_reconciled(seconds_from_now(1)),
            "and it is NOT expired before the bound elapses -- otherwise every process would \
             warn for its first minute"
        );
    }

    /// A successful flush is the reconciliation point, so it resets the age.
    ///
    /// Mutation: drop the `last_flush_millis.store(...)` at the end of
    /// `Inner::flush_now`.
    #[test]
    fn a_successful_flush_resets_the_reconciliation_age() {
        let accumulator = accumulator_with_bound(Duration::from_secs(60));
        let tenant = TenantId::new("tenant-a");
        record_micros(&accumulator, &tenant, dt(2026, 9, 3, 12, 0, 0), 1_000_000);

        accumulator.flush_now().unwrap();

        // Measured against the recorded flush instant rather than against
        // `Utc::now()`: a never-flushed accumulator is also only
        // milliseconds old, so "the age is small" passes whether or not the
        // flush reset anything. Anchoring on `last_flush_at` is what makes
        // this assert the actual invariant -- after a flush the age is
        // measured FROM THE FLUSH, not from construction.
        let flushed_at = accumulator
            .last_flush_at()
            .expect("a successful flush is the reconciliation point");
        let now = flushed_at + chrono::Duration::seconds(10);
        assert_eq!(
            accumulator.reconciliation_age(now),
            Duration::from_secs(10),
            "a flush that wrote every bucket reconciled this replica with the store"
        );
        assert!(accumulator.is_reconciled(now));
    }

    /// A FAILED flush leaves the replica stale. Same reasoning as
    /// `a_failed_flush_does_not_advance_last_flush_at`, one level up: the
    /// age is what the warning and the admin read are computed from, so a
    /// failed flush that reset it would silence exactly the outage the
    /// bound exists to surface.
    ///
    /// Mutation: move the `last_flush_millis.store(...)` in
    /// `Inner::flush_now` above the `if let Some(err)` return.
    #[test]
    fn a_failed_flush_leaves_the_replica_unreconciled() {
        let store: Arc<dyn ControlPlaneStore> =
            Arc::new(AlwaysFailsAddSpend(InMemoryControlPlaneStore::default()));
        let accumulator = SpendAccumulator::with_reconciliation(
            "test-chain".to_string(),
            store,
            Period::Daily,
            "node-a".to_string(),
            ReconciliationPolicy {
                bound: Duration::from_secs(60),
                on_expired: OnReconciliationExpired::Allow,
            },
        );
        let tenant = TenantId::new("tenant-a");
        record_micros(&accumulator, &tenant, dt(2026, 9, 3, 12, 0, 0), 1_000_000);

        accumulator.flush_now().unwrap_err();

        assert!(
            accumulator.reconciliation_age(seconds_from_now(90)) >= Duration::from_secs(90),
            "the store rejected the write, so this replica has still never reconciled"
        );
        assert!(!accumulator.is_reconciled(seconds_from_now(90)));
    }

    /// `note_admission` counts an admission only once the bound has passed,
    /// and reports whether it counted so the caller can act on it.
    ///
    /// Mutation: drop the `is_reconciled` early return in
    /// `note_admission`, so every admission counts. The healthy assertions
    /// below go red.
    #[test]
    fn note_admission_counts_only_admissions_made_past_the_bound() {
        let accumulator = accumulator_with_bound(Duration::from_secs(60));

        assert!(
            !accumulator.note_admission(seconds_from_now(1)),
            "an admission made while reconciled is not an over-admission"
        );
        assert_eq!(accumulator.unreconciled_admissions(), 0);

        assert!(
            accumulator.note_admission(seconds_from_now(90)),
            "past the bound, this replica may be missing what other replicas spent"
        );
        assert!(accumulator.note_admission(seconds_from_now(91)));
        assert_eq!(
            accumulator.unreconciled_admissions(),
            2,
            "the counter is monotonic: it counts an operational condition, not a tenant's usage"
        );
    }

    /// The three ADR-0006 §5 observability values reach the admin read.
    /// Filters have no handle to the stats registry, so `SpendReport` IS
    /// the surface -- if these fields are not populated the numbers exist
    /// nowhere an operator can see them.
    ///
    /// Mutation: hardcode `reconciliation_expired: false` in `report`.
    #[test]
    fn the_spend_report_carries_the_reconciliation_state() {
        // `report` reads its own `Utc::now()`, so the only way to make it
        // observe an expired replica deterministically is a zero bound plus
        // a nonzero age. Spin (sub-millisecond, never a sleep) until the
        // clock has moved off the construction instant.
        let accumulator = accumulator_with_bound(Duration::ZERO);
        while accumulator.reconciliation_age(Utc::now()) == Duration::ZERO {
            std::hint::spin_loop();
        }
        let tenant = TenantId::new("tenant-a");
        accumulator.note_admission(seconds_from_now(90));

        let report = accumulator.report(&tenant, &PeriodKey::for_test("2026-09-03"));

        assert!(
            report.reconciliation_expired,
            "a zero bound on a replica that never flushed is expired once the clock moves"
        );
        assert_eq!(report.unreconciled_admissions, 1);
        assert_eq!(
            report.reconciliation_age_seconds,
            accumulator.reconciliation_age(Utc::now()).as_secs(),
            "the report rounds the same age down to whole seconds; it does not compute a \
             second, differently-shaped one"
        );
    }

    /// The default bound is 60 seconds, stated rather than derived from the
    /// flush interval -- ADR-0006 §4 requires each staleness bound to be
    /// stated separately, so a deployment that retunes `flush_interval_seconds`
    /// does not silently move how long it may go unnoticed while stale.
    #[test]
    fn the_default_reconciliation_policy_is_sixty_seconds_and_allow() {
        let policy = ReconciliationPolicy::default();
        assert_eq!(policy.bound, Duration::from_secs(60));
        assert_eq!(policy.bound, DEFAULT_RECONCILIATION_BOUND);
        assert_eq!(policy.on_expired, OnReconciliationExpired::Allow);

        let accumulator = SpendAccumulator::new(
            "test-chain".to_string(),
            Arc::new(InMemoryControlPlaneStore::default()) as Arc<dyn ControlPlaneStore>,
            Period::Daily,
            "node-a".to_string(),
        );
        assert_eq!(
            accumulator.reconciliation_policy(),
            ReconciliationPolicy::default(),
            "`new` is `with_reconciliation` at the default policy, not a second set of values"
        );
    }
}
