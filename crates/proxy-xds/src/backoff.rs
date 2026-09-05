//! WP-20 increment 3b: the reconnect backoff, as pure arithmetic.
//!
//! **No I/O, no clock, no RNG of its own.** The delay is a function of the
//! attempt number and one caller-supplied draw, which is what makes every
//! claim below assertable without waiting for wall-clock time.
//!
//! WP-20 spells the requirement as "stream re-establishment with backoff
//! (jittered, 500ms–30s)". Those two numbers are Envoy's own
//! `RetryInitialDelayMs`/`RetryMaxDelayMs` for the xDS mux, so they are the
//! defaults here.
//!
//! # This is NOT the same curve as S3.3
//!
//! Easy to get wrong, because the repo already contains a fully-jittered
//! backoff: [`proxy_http::retry::backoff_delay`] draws from
//! `[0, (2^n - 1) * base]` per **S3.3**, which is the HTTP retry policy's
//! curve. Envoy's xDS mux uses `JitteredExponentialBackOffStrategy`, whose
//! interval is `base * 2^n` -- so the first xDS reconnect waits up to
//! `base` (500ms), not up to zero. Copying the retry curve here would make
//! the first reconnect instantaneous and turn a control plane restart into a
//! hot loop, which is precisely what PLAN.md Part 8.5 ("never NACK-storm")
//! forbids.
//!
//! One deliberate, harmless divergence: Envoy draws with an integer modulo,
//! giving the half-open range `[0, cap)`. We take a float draw in `[0, 1]`
//! and scale, giving the closed range `[0, cap]`. Nothing observes the
//! difference; a closed range is what lets a test pin an exact delay with a
//! constant draw of `1.0`.

use std::time::Duration;

/// The reconnect curve's two knobs. Not IR yet -- WP-20 increment 4 is what
/// wires bootstrap config in; until then these are constructed in code and
/// the defaults are what runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    /// The cap on the very first reconnect delay; doubles per consecutive
    /// failed attempt.
    pub base_interval: Duration,
    /// The ceiling the doubling saturates at.
    pub max_interval: Duration,
}

impl Default for BackoffPolicy {
    /// Envoy's xDS mux values: 500ms initial, 30s max.
    fn default() -> Self {
        Self {
            base_interval: Duration::from_millis(500),
            max_interval: Duration::from_secs(30),
        }
    }
}

/// The delay before reconnect attempt `attempt` (**0-based**: `0` is the
/// first reconnect after a stream that had been working, and draws from
/// `[0, base_interval]`).
///
/// Rust note: randomness arrives as an `FnMut() -> f64` rather than this
/// function reaching for a global RNG -- the same shape
/// `proxy_http::retry::backoff_delay` uses, and for the same reason: a test
/// supplies a constant and asserts an exact `Duration`. Values outside
/// `[0.0, 1.0]` are clamped rather than trusted, since a bare closure
/// carries no such guarantee in its type.
pub fn delay(policy: &BackoffPolicy, attempt: u32, rng: &mut impl FnMut() -> f64) -> Duration {
    // `2^attempt` in u128 so a long outage cannot panic on overflow; it
    // saturates, and the `.min(max)` below makes saturation harmless.
    let factor = 1u128.checked_shl(attempt).unwrap_or(u128::MAX);
    let cap_nanos = policy
        .base_interval
        .as_nanos()
        .saturating_mul(factor)
        .min(policy.max_interval.as_nanos());
    // `cap_nanos` is bounded above by a real `Duration`'s nanos, and
    // `u64::MAX` nanoseconds is ~584 years, so this only truncates for
    // absurd configs -- and truncating beats panicking in a timing path.
    let cap =
        Duration::from_nanos(u64::try_from(cap_nanos).unwrap_or(u64::MAX)).min(policy.max_interval);

    cap.mul_f64(rng().clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A draw that always returns the same value.
    fn rng_const(v: f64) -> impl FnMut() -> f64 {
        move || v
    }

    #[test]
    fn defaults_are_envoys_xds_mux_values() {
        let p = BackoffPolicy::default();
        assert_eq!(p.base_interval, Duration::from_millis(500));
        assert_eq!(p.max_interval, Duration::from_secs(30));
    }

    /// The rule that separates this curve from S3.3's: attempt 0 draws from
    /// `[0, base]`, NOT from `[0, 0]`. If this ever reads 0ms, a control
    /// plane restart has become a hot reconnect loop.
    #[test]
    fn first_attempt_caps_at_base_not_zero() {
        let p = BackoffPolicy::default();
        assert_eq!(
            delay(&p, 0, &mut rng_const(1.0)),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn cap_doubles_per_attempt() {
        let p = BackoffPolicy::default();
        let mut max = rng_const(1.0);
        assert_eq!(delay(&p, 1, &mut max), Duration::from_secs(1));
        assert_eq!(delay(&p, 2, &mut max), Duration::from_secs(2));
        assert_eq!(delay(&p, 3, &mut max), Duration::from_secs(4));
    }

    #[test]
    fn cap_clamps_at_max_interval() {
        let p = BackoffPolicy::default();
        // 500ms * 2^20 is ~145 hours; the cap must hold it at 30s.
        assert_eq!(delay(&p, 20, &mut rng_const(1.0)), Duration::from_secs(30));
        // And a pathological attempt number must saturate, not panic.
        assert_eq!(
            delay(&p, u32::MAX, &mut rng_const(1.0)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn jitter_scales_the_cap() {
        let p = BackoffPolicy::default();
        assert_eq!(delay(&p, 1, &mut rng_const(0.0)), Duration::ZERO);
        assert_eq!(
            delay(&p, 1, &mut rng_const(0.5)),
            Duration::from_millis(500)
        );
    }

    /// A closure is not a contract: an out-of-range draw is clamped rather
    /// than allowed to produce a negative or above-cap delay.
    #[test]
    fn out_of_range_draws_are_clamped() {
        let p = BackoffPolicy::default();
        assert_eq!(delay(&p, 0, &mut rng_const(-3.0)), Duration::ZERO);
        assert_eq!(
            delay(&p, 0, &mut rng_const(9.0)),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn custom_policy_is_honored() {
        let p = BackoffPolicy {
            base_interval: Duration::from_millis(10),
            max_interval: Duration::from_millis(25),
        };
        let mut max = rng_const(1.0);
        assert_eq!(delay(&p, 0, &mut max), Duration::from_millis(10));
        assert_eq!(delay(&p, 1, &mut max), Duration::from_millis(20));
        assert_eq!(delay(&p, 2, &mut max), Duration::from_millis(25));
    }
}
