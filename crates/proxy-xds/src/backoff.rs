//! The reconnect backoff, as pure arithmetic.
//!
//! **No I/O, no clock, no RNG of its own.** The delay is a function of the
//! attempt number and one caller-supplied draw, which is what makes every
//! claim below assertable without waiting for wall-clock time.
//!
//! Reconnects use jittered backoff from 500ms to 30s. Those are Envoy's xDS
//! mux defaults (`RetryInitialDelayMs` and `RetryMaxDelayMs`).
//!
//! This is NOT the HTTP retry curve. [`proxy_http::retry::backoff_delay`]
//! draws from `[0, (2^n - 1) * base]` (S3.3). Envoy's xDS mux draws from
//! `[0, base * 2^n]`, so the first reconnect waits up to `base`. Copying the
//! retry curve would turn a control plane restart into a hot loop, which
//! `internal-docs/architecture.md` §12.2 rule 5 forbids.
//!
//! One deliberate divergence: the draw is a float in `[0, 1]`, giving a
//! closed range, where Envoy's integer modulo gives a half-open one. A closed
//! range lets a test pin an exact delay with a draw of `1.0`.

use std::time::Duration;

/// The reconnect curve's two knobs. Not IR yet: they are constructed in code
/// and the defaults are what runs.
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
/// Rust note: randomness is an injected `FnMut() -> f64`, so a test can supply
/// a constant and assert an exact `Duration`. Out-of-range draws are clamped.
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
