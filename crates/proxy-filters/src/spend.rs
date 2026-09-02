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
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

// WP-50 increment 3c-ii-b: UTC calendar-aligned period keys. `chrono` is
// already a workspace dependency (`proxy-cluster`, `proxy-observability`
// use it); this crate had no prior need for wall-clock rendering.
use chrono::{DateTime, Datelike, NaiveDate, Utc};

use crate::auth::TenantId;
use crate::control::{ControlPlaneStore, StoreError};
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

/// One `(tenant, period)`'s live, in-memory spend state. Same shape as
/// `crate::token_limit::InProcessBudgetStore`'s window map -- a plain
/// struct behind the accumulator's one `Mutex`, with no store I/O involved
/// in building or reading it.
#[derive(Debug, Clone, Default)]
struct Bucket {
    /// The tenant's absolute spend for this period, in micro-dollars.
    total_micros: u64,
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
    /// The period used ONLY for a tenant with no configured [`TenantBudget`]
    /// -- see this section's "`record` takes its `Period` explicitly" note.
    /// Never consulted for a tenant `record` is called with an explicit
    /// period for.
    default_period: Period,
    buckets: Mutex<HashMap<(TenantId, PeriodKey), Bucket>>,
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
                    total_micros,
                    ..Bucket::default()
                }
            })
    }

    /// Writes every in-memory bucket's ABSOLUTE total to the store. See
    /// [`ControlPlaneStore::set_spend`]'s doc for why absolute, not a
    /// delta. Best-effort across buckets: one tenant's write failing does
    /// not stop the rest from flushing, but the first failure is still
    /// returned so a caller (the flusher thread's warning, or a test) can
    /// tell the flush was not fully durable.
    fn flush_now(&self) -> Result<(), StoreError> {
        let buckets = self
            .buckets
            .lock()
            .expect("spend accumulator mutex poisoned");
        let mut first_err = None;
        for ((tenant, period_key), bucket) in buckets.iter() {
            if let Err(err) =
                self.store
                    .set_spend(&self.stat_prefix, tenant, period_key, bucket.total_micros)
            {
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
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
    pub fn new(
        stat_prefix: String,
        store: Arc<dyn ControlPlaneStore>,
        default_period: Period,
    ) -> Self {
        SpendAccumulator {
            inner: Arc::new(Inner {
                stat_prefix,
                store,
                default_period,
                buckets: Mutex::new(HashMap::new()),
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
                bucket.total_micros = bucket.total_micros.saturating_add(amount.as_micros());
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
        self.inner
            .get_or_load_bucket(&mut buckets, tenant, period)
            .total_micros
    }

    /// Writes every bucket's current absolute total to the store. Callable
    /// directly with no thread involved at all -- tests use this to assert
    /// against the store; the flusher thread also calls it on every tick,
    /// and `Drop` calls it once more on shutdown.
    pub fn flush_now(&self) -> Result<(), StoreError> {
        self.inner.flush_now()
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
                tracing::warn!(
                    stat_prefix = %inner.stat_prefix,
                    error = %err,
                    "spend flusher: periodic flush failed; will retry next interval"
                );
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
            "an absolute write flushed twice with no intervening record must leave the \
             stored total unchanged -- an additive write would double it"
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
        let accumulator = SpendAccumulator::new("test-chain".to_string(), store, Period::Daily);
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
}
