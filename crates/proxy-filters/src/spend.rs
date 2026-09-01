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

use std::collections::HashMap;

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
}
