//! envoy-semantics.md S3 — retry & hedging engine.
//!
//! Pure logic only: trigger evaluation (S3.2) and fully-jittered exponential
//! backoff (S3.3) are synchronous, allocation-free functions with randomness
//! injected through a closure, so every distribution/attempt-count claim can
//! be pinned with a deterministic unit test. `router.rs` consumes this pure
//! state to issue retries, enforce per-try timeouts, and launch safe hedges;
//! this module itself has no I/O.

use std::time::Duration;

use proxy_cluster::PoolError;
use proxy_config::ir::RetryPolicyIR;

use crate::codec::UpstreamCodecError;

/// What a completed upstream attempt produced, in the vocabulary S3.2's
/// trigger table needs. This is a *projection* of the existing
/// [`PoolError`]/[`UpstreamCodecError`] enums onto the handful of buckets S3
/// cares about -- see `from_pool_error`/`from_codec_error` below -- not a
/// parallel error hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// A full response came back with this status code.
    Response(u16),
    /// TCP/TLS connect failed or timed out before a stream was even opened.
    /// S3.2's `connect-failure` fires here; a per-try (request) timeout is
    /// deliberately a *different* variant ([`AttemptOutcome::PerTryTimeout`])
    /// so that distinction ("connect-failure excludes request timeout") is
    /// structural rather than something callers have to remember.
    ConnectFailure,
    /// Connection reset/closed before any response headers arrived --
    /// includes both "reset while waiting for a response" and "reset before
    /// the request finished sending" (S3.2's `reset` and
    /// `reset-before-request` respectively). See the module doc comment on
    /// [`trigger_fires`] for why these two are folded together here.
    ResetBeforeHeaders,
    /// Connection reset/closed after response headers arrived (mid-body).
    /// Nothing produces this yet: the current codec (`send_upstream_http1`)
    /// returns the full head before the caller can observe a body-phase
    /// failure separately. Kept as its own variant so the trigger table
    /// already has somewhere for it to route to once streaming responses
    /// exist.
    ResetAfterHeaders,
    /// h2 REFUSED_STREAM: the peer bounced the stream before doing any work,
    /// always safe to retry (S3.2's `refused-stream`). Produced by
    /// `codec::send_on_http2`, which decodes the reason off the
    /// `hyper::Error`'s source chain; `UpstreamCodecError::RefusedStream` is
    /// the carrier.
    RefusedStream,
    /// The per-try timeout (S4.2) fired before a response arrived.
    PerTryTimeout,
    /// Circuit-breaker / pending-queue overflow (S5): [`PoolError::Overflow`].
    PoolOverflow,
}

impl AttemptOutcome {
    /// Project a pool-acquisition failure onto the S3.2 vocabulary.
    pub fn from_pool_error(err: &PoolError) -> Self {
        match err {
            PoolError::Overflow => Self::PoolOverflow,
            // TLS handshake failure is folded into connect-failure, same as
            // Envoy folds it into `UF`: from the retry engine's point of
            // view a peer that never finished connecting never finished
            // connecting, regardless of which half of the handshake failed.
            PoolError::ConnectFailure(_)
            | PoolError::ConnectTimeout
            | PoolError::TlsHandshake(_) => Self::ConnectFailure,
            PoolError::ResetBeforeHeaders => Self::ResetBeforeHeaders,
        }
    }

    /// Project an upstream codec failure onto the S3.2 vocabulary.
    ///
    /// `UpstreamCodecError::MissingAuthority` is a local request-shape
    /// defect (no `Host`/absolute-form URI to derive `:authority` from), not
    /// a network failure -- retrying will reproduce it identically. There is
    /// no dedicated "not retriable, don't even ask" outcome yet, so it is
    /// conservatively folded into `ResetBeforeHeaders` (the "no response at
    /// all" bucket); this is flagged as a divergence rather than silently
    /// assumed, since it will report as retriable under `5xx`/`reset` even
    /// though a retry can never succeed.
    pub fn from_codec_error(err: &UpstreamCodecError) -> Self {
        match err {
            UpstreamCodecError::Handshake(_)
            | UpstreamCodecError::Connection(_)
            | UpstreamCodecError::Send(_)
            | UpstreamCodecError::MissingAuthority => Self::ResetBeforeHeaders,
            UpstreamCodecError::RefusedStream => Self::RefusedStream,
        }
    }
}

/// S3.2 trigger evaluation: does `outcome` fire under any token set in
/// `policy.retry_on`?
///
/// This function only evaluates the *trigger table* -- attempt budget (S3.1)
/// and body-retriability (S3.4) are separate concerns layered on top by
/// [`RetryState`]/[`should_retry`].
fn trigger_fires(policy: &RetryPolicyIR, outcome: &AttemptOutcome) -> bool {
    let on = &policy.retry_on;
    match outcome {
        AttemptOutcome::Response(status) => {
            let s = *status;
            (on.five_xx && (500..600).contains(&s))
                || (on.gateway_error && matches!(s, 502..=504))
                || (on.retriable_4xx && s == 409)
                || (on.retriable_status_codes && policy.retriable_status_codes.contains(&s))
        }
        // "No response at all" (connect failure, reset, pool overflow)
        // counts as 5xx/gateway-error per S3.2's `5xx` row ("any 5xx
        // response or no response at all").
        AttemptOutcome::ConnectFailure => on.connect_failure || on.five_xx || on.gateway_error,
        AttemptOutcome::ResetBeforeHeaders => {
            on.reset || on.reset_before_request || on.five_xx || on.gateway_error
        }
        AttemptOutcome::ResetAfterHeaders => on.reset || on.five_xx || on.gateway_error,
        AttemptOutcome::RefusedStream => on.refused_stream,
        // Per S3.2's `5xx` row annotation ("Envoy: timeout -> 504 counts
        // under 5xx") a per-try timeout is synthesized as a 504 internally,
        // so `5xx`/`gateway-error` fire; S3.2's `reset` row explicitly lists
        // "read timeout before response" as a `reset` trigger too.
        // `connect-failure` deliberately does NOT fire here (it excludes
        // request timeout -- see `AttemptOutcome::ConnectFailure`'s doc).
        AttemptOutcome::PerTryTimeout => on.five_xx || on.gateway_error || on.reset,
        // A pending-queue/CB overflow is answered with a synthesized 503
        // (S5), so it falls under the same "no response from upstream, but
        // Envoy would emit a 5xx" bucket as connect failures.
        AttemptOutcome::PoolOverflow => on.five_xx || on.gateway_error,
    }
}

/// S3.1 + S3.2: should another attempt be issued given `attempts_so_far`
/// retries have already been used and the most recent one produced
/// `outcome`?
///
/// `attempts_so_far` counts *retries already issued*, not total attempts
/// (see [`RetryState`]'s doc comment for the off-by-one this avoids):
/// `attempts_so_far == 0` means only the original attempt has run.
/// Budget (S3.1) is checked first -- an outcome that would otherwise trigger
/// a retry is still refused once `policy.num_retries` retries have been
/// spent.
pub fn should_retry(
    policy: &RetryPolicyIR,
    outcome: &AttemptOutcome,
    attempts_so_far: u32,
) -> bool {
    if attempts_so_far >= policy.num_retries {
        return false;
    }
    trigger_fires(policy, outcome)
}

/// S3.3 fully-jittered exponential backoff: attempt `n` (1-based, matching
/// Envoy's docs -- the first retry is attempt 1) draws uniformly from
/// `[0, min((2^n - 1) * base_interval, max_interval)]`.
///
/// Rust note: randomness is threaded through an `FnMut() -> f64` closure
/// instead of this function reaching for a global RNG, so tests can supply a
/// fixed sequence (or a constant) and assert *exact* delays -- see the tests
/// below. `rng` is expected to return a value in `[0.0, 1.0]`; out-of-range
/// values are clamped rather than trusted, since nothing in the type system
/// enforces the contract on a bare closure.
pub fn backoff_delay(
    policy: &RetryPolicyIR,
    attempt: u32,
    rng: &mut impl FnMut() -> f64,
) -> Duration {
    let base = policy.retry_back_off.base_interval;
    let max = policy.retry_back_off.max_interval;

    // 2^n - 1, computed in u128 so a pathologically large `attempt` can't
    // panic on overflow (it just saturates, and the `.min(max)` below makes
    // that harmless).
    let factor = 1u128
        .checked_shl(attempt)
        .unwrap_or(u128::MAX)
        .saturating_sub(1);
    let cap_nanos = base.as_nanos().saturating_mul(factor).min(max.as_nanos());
    // `cap_nanos` is bounded above by `max.as_nanos()`, i.e. by a real
    // config-supplied Duration -- `u64::MAX` nanoseconds is ~584 years, so
    // this only truncates for absurd configs, and truncating (rather than
    // panicking) is the safe failure mode for a hot-path timing function.
    let cap = Duration::from_nanos(u64::try_from(cap_nanos).unwrap_or(u64::MAX)).min(max);

    let draw = rng().clamp(0.0, 1.0);
    cap.mul_f64(draw)
}

/// Per-request retry bookkeeping: how many retries have been spent against
/// the policy's budget, and whether the request is retriable at all.
///
/// Rust note: this borrows the policy (`&'a RetryPolicyIR`) rather than
/// owning/cloning it -- `RetryPolicyIR` lives on the route's IR for the
/// whole config's lifetime, so a short-lived per-request `RetryState`
/// borrowing it is cheaper and avoids a `Clone` derive the IR doesn't
/// otherwise need.
///
/// S3.1's `num_retries` (Envoy default **1**) is the number of *retries*
/// allowed, not the number of total attempts -- the classic off-by-one: a
/// default policy permits the original attempt plus **one** retry, i.e.
/// **two** attempts total. `attempts_used` counts retries issued so far (0
/// before the first retry is issued), matching `should_retry`'s
/// `attempts_so_far` parameter.
#[derive(Debug)]
pub struct RetryState<'a> {
    policy: &'a RetryPolicyIR,
    attempts_used: u32,
    /// S3.4: a request whose body was streamed past the buffer limit is not
    /// retriable at all, regardless of what the trigger table says
    /// (Envoy's `no_retry_body_too_large`). The router marks it false when
    /// its captured request body exceeds the replay limit, so a hedge is
    /// structurally subject to this same gate as an ordinary retry.
    body_retriable: bool,
}

impl<'a> RetryState<'a> {
    pub fn new(policy: &'a RetryPolicyIR) -> Self {
        Self {
            policy,
            attempts_used: 0,
            body_retriable: true,
        }
    }

    /// S3.4: mark the request body as not retriable (streamed / exceeded
    /// the buffer limit -- Envoy's `no_retry_body_too_large`).
    pub fn mark_body_not_retriable(&mut self) {
        self.body_retriable = false;
    }

    pub fn attempts_used(&self) -> u32 {
        self.attempts_used
    }

    /// Whether another attempt may be issued for `outcome`, combining the
    /// S3.4 body constraint with [`should_retry`]'s trigger+budget check.
    pub fn should_retry(&self, outcome: &AttemptOutcome) -> bool {
        self.body_retriable && should_retry(self.policy, outcome, self.attempts_used)
    }

    /// Envoy's `URX` ("upstream retry limit exceeded") condition --
    /// `outcome` is one this policy's trigger table (S3.2) WOULD have
    /// retried, but [`Self::should_retry`] just said no because the S3.1
    /// attempt budget (`policy.num_retries`) is spent. Deliberately NOT the
    /// same as "`should_retry` returned false": that's also true when
    /// `outcome` was never retriable at all (wrong trigger token configured)
    /// or the body isn't replayable (S3.4) -- neither of those is a retry
    /// *limit* being exceeded, there was no limit in play. Router.rs calls
    /// this at exactly the sites that already call `should_retry`, right
    /// after it returns `false`, so `URX` only ever appears alongside (never
    /// instead of) the specific failure flag that outcome produces --
    /// matching Envoy, which renders combinations like `UF,URX`.
    pub fn retry_limit_exceeded(&self, outcome: &AttemptOutcome) -> bool {
        self.body_retriable
            && self.attempts_used >= self.policy.num_retries
            && trigger_fires(self.policy, outcome)
    }

    /// Compute this attempt's backoff delay (attempt numbers are 1-based:
    /// call this with `attempts_used + 1`, i.e. before `record_attempt`, or
    /// equivalently right after it -- both give the same 1-based number for
    /// the retry about to be issued).
    pub fn backoff_delay(&self, rng: &mut impl FnMut() -> f64) -> Duration {
        backoff_delay(self.policy, self.attempts_used + 1, rng)
    }

    /// Record that a retry attempt was just issued, consuming one unit of
    /// budget.
    pub fn record_attempt(&mut self) {
        self.attempts_used += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_config::ir::{RetryBackOff, RetryOn};

    fn policy(retry_on: &str, num_retries: u32) -> RetryPolicyIR {
        RetryPolicyIR {
            retry_on: RetryOn::parse(retry_on),
            num_retries,
            per_try_timeout: None,
            hedge_on_per_try_timeout: false,
            retriable_status_codes: vec![429],
            retry_back_off: RetryBackOff::ENVOY_DEFAULT,
            host_selection_retry_max_attempts: 1,
            avoid_previous_hosts: false,
        }
    }

    // -------------------------------------------------------------- S3.2 --

    #[test]
    fn five_xx_fires_on_5xx_response() {
        let p = policy("5xx", 1);
        assert!(should_retry(&p, &AttemptOutcome::Response(500), 0));
        assert!(should_retry(&p, &AttemptOutcome::Response(599), 0));
        assert!(!should_retry(&p, &AttemptOutcome::Response(499), 0));
        assert!(!should_retry(&p, &AttemptOutcome::Response(200), 0));
    }

    #[test]
    fn five_xx_fires_on_no_response_at_all() {
        let p = policy("5xx", 1);
        assert!(should_retry(&p, &AttemptOutcome::ConnectFailure, 0));
        assert!(should_retry(&p, &AttemptOutcome::ResetBeforeHeaders, 0));
        assert!(should_retry(&p, &AttemptOutcome::ResetAfterHeaders, 0));
        assert!(should_retry(&p, &AttemptOutcome::PoolOverflow, 0));
    }

    #[test]
    fn five_xx_does_not_fire_on_refused_stream_or_per_try_timeout_alone() {
        // refused-stream needs its own token, per S3.2's table.
        let p = policy("5xx", 1);
        assert!(!should_retry(&p, &AttemptOutcome::RefusedStream, 0));
        // per-try timeout DOES fire under 5xx per the plan's own resolution
        // of the ⚠️ (Envoy synthesizes a 504) -- covered by a dedicated test
        // below, not asserted false here.
    }

    #[test]
    fn per_try_timeout_fires_under_5xx_and_reset_not_connect_failure() {
        assert!(should_retry(
            &policy("5xx", 1),
            &AttemptOutcome::PerTryTimeout,
            0
        ));
        assert!(should_retry(
            &policy("gateway-error", 1),
            &AttemptOutcome::PerTryTimeout,
            0
        ));
        assert!(should_retry(
            &policy("reset", 1),
            &AttemptOutcome::PerTryTimeout,
            0
        ));
        // The subtle one: connect-failure excludes request/per-try timeout.
        assert!(!should_retry(
            &policy("connect-failure", 1),
            &AttemptOutcome::PerTryTimeout,
            0
        ));
    }

    #[test]
    fn connect_failure_fires_only_on_connect_failure_outcome() {
        let p = policy("connect-failure", 1);
        assert!(should_retry(&p, &AttemptOutcome::ConnectFailure, 0));
        assert!(!should_retry(&p, &AttemptOutcome::ResetBeforeHeaders, 0));
        assert!(!should_retry(&p, &AttemptOutcome::PerTryTimeout, 0));
        assert!(!should_retry(&p, &AttemptOutcome::Response(500), 0));
    }

    #[test]
    fn gateway_error_is_502_503_504_or_no_response_only() {
        let p = policy("gateway-error", 1);
        for status in [502, 503, 504] {
            assert!(should_retry(&p, &AttemptOutcome::Response(status), 0));
        }
        for status in [500, 501, 505, 599] {
            assert!(!should_retry(&p, &AttemptOutcome::Response(status), 0));
        }
        assert!(should_retry(&p, &AttemptOutcome::ConnectFailure, 0));
        assert!(should_retry(&p, &AttemptOutcome::ResetBeforeHeaders, 0));
        assert!(should_retry(&p, &AttemptOutcome::PoolOverflow, 0));
    }

    #[test]
    fn retriable_4xx_is_409_only() {
        let p = policy("retriable-4xx", 1);
        assert!(should_retry(&p, &AttemptOutcome::Response(409), 0));
        for status in [400, 401, 403, 404, 429, 499] {
            assert!(!should_retry(&p, &AttemptOutcome::Response(status), 0));
        }
    }

    #[test]
    fn reset_fires_before_and_after_headers_and_on_per_try_timeout() {
        let p = policy("reset", 1);
        assert!(should_retry(&p, &AttemptOutcome::ResetBeforeHeaders, 0));
        assert!(should_retry(&p, &AttemptOutcome::ResetAfterHeaders, 0));
        assert!(should_retry(&p, &AttemptOutcome::PerTryTimeout, 0));
        assert!(!should_retry(&p, &AttemptOutcome::ConnectFailure, 0));
        assert!(!should_retry(&p, &AttemptOutcome::Response(200), 0));
    }

    #[test]
    fn reset_before_request_fires_on_reset_before_headers() {
        let p = policy("reset-before-request", 1);
        assert!(should_retry(&p, &AttemptOutcome::ResetBeforeHeaders, 0));
        assert!(!should_retry(&p, &AttemptOutcome::ConnectFailure, 0));
    }

    #[test]
    fn refused_stream_fires_only_on_refused_stream_outcome() {
        let p = policy("refused-stream", 1);
        assert!(should_retry(&p, &AttemptOutcome::RefusedStream, 0));
        assert!(!should_retry(&p, &AttemptOutcome::ResetBeforeHeaders, 0));
        assert!(!should_retry(&p, &AttemptOutcome::Response(503), 0));
    }

    #[test]
    fn retriable_status_codes_consults_policy_list() {
        let p = policy("retriable-status-codes", 1); // policy() sets [429]
        assert!(should_retry(&p, &AttemptOutcome::Response(429), 0));
        assert!(!should_retry(&p, &AttemptOutcome::Response(500), 0));
        // Without the token, the list is not consulted even if the status matches.
        let p2 = policy("5xx", 1);
        assert!(!should_retry(&p2, &AttemptOutcome::Response(429), 0));
    }

    #[test]
    fn pool_overflow_is_treated_as_no_response_5xx() {
        let p = policy("5xx", 1);
        assert!(should_retry(&p, &AttemptOutcome::PoolOverflow, 0));
        let p2 = policy("connect-failure", 1);
        assert!(!should_retry(&p2, &AttemptOutcome::PoolOverflow, 0));
    }

    #[test]
    fn no_tokens_never_retries() {
        let p = policy("", 1);
        assert!(!should_retry(&p, &AttemptOutcome::Response(500), 0));
        assert!(!should_retry(&p, &AttemptOutcome::ConnectFailure, 0));
        assert!(!should_retry(&p, &AttemptOutcome::ResetBeforeHeaders, 0));
    }

    // ------------------------------------------------------ PoolError map --

    #[test]
    fn pool_error_projection() {
        assert_eq!(
            AttemptOutcome::from_pool_error(&PoolError::Overflow),
            AttemptOutcome::PoolOverflow
        );
        assert_eq!(
            AttemptOutcome::from_pool_error(&PoolError::ConnectTimeout),
            AttemptOutcome::ConnectFailure
        );
        assert_eq!(
            AttemptOutcome::from_pool_error(&PoolError::ConnectFailure(std::io::Error::other(
                "boom"
            ))),
            AttemptOutcome::ConnectFailure
        );
        assert_eq!(
            AttemptOutcome::from_pool_error(&PoolError::TlsHandshake(std::io::Error::other(
                "boom"
            ))),
            AttemptOutcome::ConnectFailure
        );
        assert_eq!(
            AttemptOutcome::from_pool_error(&PoolError::ResetBeforeHeaders),
            AttemptOutcome::ResetBeforeHeaders
        );
    }

    #[test]
    fn codec_error_projection() {
        assert_eq!(
            AttemptOutcome::from_codec_error(&UpstreamCodecError::MissingAuthority),
            AttemptOutcome::ResetBeforeHeaders
        );
    }

    // -------------------------------------------------------------- S3.3 --

    fn rng_const(v: f64) -> impl FnMut() -> f64 {
        move || v
    }

    #[test]
    fn backoff_progression_at_max_draw() {
        let p = policy("5xx", 10);
        // draw = 1.0 -> exact upper bound of the closed interval [0, cap].
        assert_eq!(
            backoff_delay(&p, 1, &mut rng_const(1.0)),
            Duration::from_millis(25)
        );
        assert_eq!(
            backoff_delay(&p, 2, &mut rng_const(1.0)),
            Duration::from_millis(75)
        );
        assert_eq!(
            backoff_delay(&p, 3, &mut rng_const(1.0)),
            Duration::from_millis(175)
        );
        // attempt 4 would be (2^4-1)*25ms = 375ms, clamped to max_interval=250ms.
        assert_eq!(
            backoff_delay(&p, 4, &mut rng_const(1.0)),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn backoff_draw_zero_is_always_zero() {
        let p = policy("5xx", 10);
        for attempt in 1..=5 {
            assert_eq!(
                backoff_delay(&p, attempt, &mut rng_const(0.0)),
                Duration::ZERO
            );
        }
    }

    #[test]
    fn backoff_draw_half_scales_linearly() {
        let p = policy("5xx", 10);
        assert_eq!(
            backoff_delay(&p, 1, &mut rng_const(0.5)),
            Duration::from_millis(12) + Duration::from_micros(500)
        );
        assert_eq!(
            backoff_delay(&p, 2, &mut rng_const(0.5)),
            Duration::from_millis(37) + Duration::from_micros(500)
        );
    }

    #[test]
    fn backoff_cap_clamps_regardless_of_draw() {
        let p = policy("5xx", 10);
        // Attempt 4's uncapped bound (375ms) exceeds max_interval (250ms);
        // even at draw=1.0 the result never exceeds max_interval.
        let delay = backoff_delay(&p, 4, &mut rng_const(1.0));
        assert!(delay <= p.retry_back_off.max_interval);
        assert_eq!(delay, p.retry_back_off.max_interval);
    }

    #[test]
    fn backoff_respects_custom_base_and_max() {
        let mut p = policy("5xx", 10);
        p.retry_back_off = RetryBackOff {
            base_interval: Duration::from_millis(10),
            max_interval: Duration::from_millis(20),
        };
        // attempt 1: (2^1-1)*10ms = 10ms, under max.
        assert_eq!(
            backoff_delay(&p, 1, &mut rng_const(1.0)),
            Duration::from_millis(10)
        );
        // attempt 2: (2^2-1)*10ms = 30ms, clamped to max=20ms.
        assert_eq!(
            backoff_delay(&p, 2, &mut rng_const(1.0)),
            Duration::from_millis(20)
        );
    }

    // -------------------------------------------------------------- S3.1 --

    #[test]
    fn num_retries_zero_never_retries() {
        let p = policy("5xx", 0);
        assert!(!should_retry(&p, &AttemptOutcome::Response(500), 0));
    }

    #[test]
    fn num_retries_one_allows_exactly_one_retry() {
        let p = policy("5xx", 1);
        assert!(should_retry(&p, &AttemptOutcome::Response(500), 0));
        assert!(!should_retry(&p, &AttemptOutcome::Response(500), 1));
    }

    #[test]
    fn num_retries_three_allows_exactly_three_retries() {
        let p = policy("5xx", 3);
        for attempts_so_far in 0..3 {
            assert!(should_retry(
                &p,
                &AttemptOutcome::Response(500),
                attempts_so_far
            ));
        }
        assert!(!should_retry(&p, &AttemptOutcome::Response(500), 3));
    }

    #[test]
    fn retry_state_tracks_budget_across_attempts() {
        let p = policy("5xx", 2);
        let mut state = RetryState::new(&p);
        assert_eq!(state.attempts_used(), 0);
        assert!(state.should_retry(&AttemptOutcome::Response(500)));
        state.record_attempt();
        assert_eq!(state.attempts_used(), 1);
        assert!(state.should_retry(&AttemptOutcome::Response(500)));
        state.record_attempt();
        assert_eq!(state.attempts_used(), 2);
        // Budget exhausted: two retries already issued for num_retries=2.
        assert!(!state.should_retry(&AttemptOutcome::Response(500)));
    }

    #[test]
    fn retry_state_backoff_delay_uses_1_based_attempt_number() {
        let p = policy("5xx", 10);
        let mut state = RetryState::new(&p);
        // Before any retry is issued, the *next* one is attempt 1.
        assert_eq!(
            state.backoff_delay(&mut rng_const(1.0)),
            Duration::from_millis(25)
        );
        state.record_attempt();
        // Now the next retry is attempt 2.
        assert_eq!(
            state.backoff_delay(&mut rng_const(1.0)),
            Duration::from_millis(75)
        );
    }

    // -------------------------------------------------------------- S3.4 --

    #[test]
    fn body_not_retriable_blocks_every_trigger() {
        let p = policy("5xx", 10);
        let mut state = RetryState::new(&p);
        assert!(state.should_retry(&AttemptOutcome::Response(500)));
        state.mark_body_not_retriable();
        assert!(!state.should_retry(&AttemptOutcome::Response(500)));
        assert!(!state.should_retry(&AttemptOutcome::ConnectFailure));
    }

    // ---------------------------------------- response flags (`URX`) --

    #[test]
    fn retry_limit_exceeded_fires_only_once_the_budget_is_actually_spent() {
        let p = policy("5xx", 1);
        let mut state = RetryState::new(&p);
        // Budget not yet spent: this outcome retries instead of exceeding
        // any limit.
        assert!(!state.retry_limit_exceeded(&AttemptOutcome::Response(500)));
        assert!(state.should_retry(&AttemptOutcome::Response(500)));
        state.record_attempt();
        // Budget now spent (num_retries=1, one retry already issued) and
        // this outcome would still have retried -- URX.
        assert!(state.retry_limit_exceeded(&AttemptOutcome::Response(500)));
        assert!(!state.should_retry(&AttemptOutcome::Response(500)));
    }

    #[test]
    fn retry_limit_exceeded_does_not_fire_for_an_outcome_the_policy_never_retries() {
        // Budget spent, but a 400 was never retriable under "5xx" in the
        // first place -- there was no limit to exceed.
        let p = policy("5xx", 1);
        let mut state = RetryState::new(&p);
        state.record_attempt();
        assert!(!state.retry_limit_exceeded(&AttemptOutcome::Response(400)));
    }

    #[test]
    fn retry_limit_exceeded_does_not_fire_when_the_body_made_it_unretriable() {
        // Budget spent AND the trigger fires, but the body itself ruled out
        // a retry (S3.4) -- this is "not retriable", not "limit exceeded".
        let p = policy("5xx", 1);
        let mut state = RetryState::new(&p);
        state.record_attempt();
        state.mark_body_not_retriable();
        assert!(!state.retry_limit_exceeded(&AttemptOutcome::Response(500)));
    }
}
