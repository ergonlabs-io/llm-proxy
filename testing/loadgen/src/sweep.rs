//! Ramp-hold-bisect search for the maximum concurrent-stream count a target
//! sustains within an SLO (WP-30 phase 2's headline question: "how much
//! scale can one instance support for a given memory/CPU budget?").
//!
//! Deliberately generic over how one level is *driven* -- callers pass an
//! async closure `concurrency -> LevelStats` -- so the ramp/bisect search
//! logic itself can be unit-tested against a synthetic SLO oracle with a
//! known breaking point, without spinning up a real proxy (see the tests
//! below). `main.rs` supplies the real closure: hold `concurrency` streams
//! via `driver::run_closed_loop` while `sampler` samples the proxy process
//! alongside it.

use std::future::Future;
use std::time::Duration;

use serde::Serialize;

/// Which SLO clause a level failed. Reported explicitly (not just a bool)
/// so a sweep report can say *why* a level failed rather than just that it
/// did -- see the crate's task brief.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SloViolation {
    P99Latency,
    TtftP99,
    ErrorRate,
}

/// The SLO gate: a ceiling on p99 total latency, a ceiling on p99
/// time-to-first-token, and a ceiling on the error rate. All three are
/// checked over the steady-state (post-warmup) window only -- scoring the
/// ramp transient is the classic way to get a number that's too
/// optimistic, so the warm-up prefix must already be excluded from the
/// `LevelStats` a caller hands to [`sweep`] (`driver::run_closed_loop`'s
/// own `--warmup` handling does this for the real implementation).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SloConfig {
    pub p99_ceiling: Duration,
    pub ttft_p99_ceiling: Duration,
    pub max_error_rate: f64,
}

impl SloConfig {
    /// All SLO clauses that `stats` violates, in a fixed order. Empty means
    /// the level passed.
    ///
    /// Rust note: `stats.p99_latency`/`ttft_p99` are `Option<Duration>` --
    /// `None` means the level had no successful streams to measure latency
    /// from (every request failed), not "0ms" or "infinitely slow". A `None`
    /// clause is skipped here rather than treated as a violation: a level
    /// with a 100% error rate must fail on `ErrorRate` alone, so the report
    /// names the real cause instead of a fabricated latency number riding
    /// along with it (see `report.rs`'s `CapacityRow`).
    pub fn evaluate(&self, stats: &LevelStats) -> Vec<SloViolation> {
        let mut violations = Vec::new();
        if stats.p99_latency.is_some_and(|d| d > self.p99_ceiling) {
            violations.push(SloViolation::P99Latency);
        }
        if stats.ttft_p99.is_some_and(|d| d > self.ttft_p99_ceiling) {
            violations.push(SloViolation::TtftP99);
        }
        if stats.error_rate > self.max_error_rate {
            violations.push(SloViolation::ErrorRate);
        }
        violations
    }
}

/// What one held level measured, steady-state only. `peak_rss_bytes` /
/// `mean_cpu_percent` / `peak_fds` are `None` when no process sampler was
/// attached (or it couldn't read anything) -- never a fabricated zero.
#[derive(Debug, Clone, Serialize)]
pub struct LevelStats {
    pub throughput_rps: f64,
    /// `None` when the level had no successful streams to compute a
    /// percentile from (e.g. every request errored) -- never a sentinel
    /// duration. See `SloConfig::evaluate` and `report::CapacityRow`.
    pub p50_latency: Option<Duration>,
    pub p99_latency: Option<Duration>,
    pub ttft_p99: Option<Duration>,
    pub error_rate: f64,
    /// Requests actually counted in the steady-state window (post-warmup).
    /// Used, alongside `steady_state_secs`, by the capacity report's
    /// cost-model fit (`report::fit_cost_model`).
    pub requests_completed: u64,
    /// Observed downstream TCP connections opened during this level.
    pub connections_opened: u64,
    pub steady_state_secs: f64,
    pub peak_rss_bytes: Option<u64>,
    pub mean_cpu_percent: Option<f64>,
    pub peak_fds: Option<u64>,
}

/// One level's full result: what was measured, which SLO clauses (if any)
/// it violated, and -- if the driver itself errored (e.g. the sampler lost
/// the proxy's pid) -- why. A driver error is treated as a failed level,
/// not silently skipped.
#[derive(Debug, Clone, Serialize)]
pub struct LevelResult {
    pub concurrency: usize,
    pub stats: LevelStats,
    pub violations: Vec<SloViolation>,
    pub driver_error: Option<String>,
}

impl LevelResult {
    pub fn passed(&self) -> bool {
        self.violations.is_empty() && self.driver_error.is_none()
    }
}

#[derive(Debug, Clone)]
pub struct SweepConfig {
    pub slo: SloConfig,
    /// First concurrency level to try.
    pub start_concurrency: usize,
    /// Safety cap -- the sweep will never drive past this even if every
    /// level so far has passed (e.g. set to the harness's own estimated
    /// max concurrency; see `rig::RigInfo`). Hitting this cap without ever
    /// failing the SLO means the run is harness-bound, not proxy-bound --
    /// see `rig::harness_bound`.
    pub max_concurrency: usize,
    /// Geometric ramp step multiplier (e.g. 2.0 doubles each step).
    pub growth_factor: f64,
    /// Bisection stops once the pass/fail boundary is narrowed to within
    /// this many streams.
    pub bisect_tolerance: usize,
}

/// A full sweep's result: every level driven (ramp then bisect, in order),
/// plus the derived boundary.
#[derive(Debug, Clone, Serialize)]
pub struct SweepReport {
    pub levels: Vec<LevelResult>,
    /// Largest concurrency that passed the SLO -- the sweep's headline
    /// number. `None` if even `start_concurrency` failed.
    pub max_sustainable: Option<usize>,
    /// Smallest concurrency known to fail (after bisection narrowed it to
    /// within `bisect_tolerance` of `max_sustainable`). `None` if the ramp
    /// never found a failure before hitting `max_concurrency` -- report
    /// this case as harness-bound, not as "the proxy has no ceiling".
    pub first_failing: Option<usize>,
}

/// Ramp-hold-bisect search for the largest concurrency `driver` sustains
/// within `cfg.slo`.
///
/// `driver(concurrency)` is expected to hold that concurrency for the
/// caller's chosen duration, discard its own warm-up prefix, and hand back
/// the steady-state [`LevelStats`] (or an `Err` if the level couldn't be
/// driven/measured at all, which counts as a failure).
///
/// Rust note: `driver` is generic (`FnMut(usize) -> Fut`) rather than a
/// boxed trait object -- the real caller's closure captures an `Arc<RunConfig>`
/// and a sampler handle, and generics let the compiler monomorphize instead
/// of requiring `dyn`/`Send` bounds this pure search logic doesn't need.
pub async fn sweep<F, Fut>(cfg: SweepConfig, mut driver: F) -> SweepReport
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = anyhow::Result<LevelStats>>,
{
    let mut levels: Vec<LevelResult> = Vec::new();
    let mut last_pass: Option<usize> = None;
    let mut first_fail: Option<usize> = None;

    // RAMP: geometric growth until a level fails the SLO or we hit the
    // safety cap.
    let mut concurrency = cfg.start_concurrency.max(1);
    loop {
        let result = drive_level(&mut driver, concurrency, &cfg.slo).await;
        let passed = result.passed();
        levels.push(result);
        if passed {
            last_pass = Some(concurrency);
        } else {
            first_fail = Some(concurrency);
            break;
        }
        if concurrency >= cfg.max_concurrency {
            break;
        }
        let grown = ((concurrency as f64) * cfg.growth_factor).ceil() as usize;
        concurrency = grown.max(concurrency + 1).min(cfg.max_concurrency);
    }

    // BISECT: narrow the pass/fail boundary, only once the ramp found both
    // a passing and a failing level.
    if let (Some(mut lo), Some(mut hi)) = (last_pass, first_fail) {
        while hi.saturating_sub(lo) > cfg.bisect_tolerance {
            let mid = lo + (hi - lo) / 2;
            if mid == lo || mid == hi {
                break;
            }
            let result = drive_level(&mut driver, mid, &cfg.slo).await;
            let passed = result.passed();
            levels.push(result);
            if passed {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        last_pass = Some(lo);
        first_fail = Some(hi);
    }

    SweepReport {
        levels,
        max_sustainable: last_pass,
        first_failing: first_fail,
    }
}

async fn drive_level<F, Fut>(driver: &mut F, concurrency: usize, slo: &SloConfig) -> LevelResult
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = anyhow::Result<LevelStats>>,
{
    match driver(concurrency).await {
        Ok(stats) => {
            let violations = slo.evaluate(&stats);
            LevelResult {
                concurrency,
                stats,
                violations,
                driver_error: None,
            }
        }
        Err(err) => LevelResult {
            concurrency,
            // A driver error (couldn't sample the pid, connection setup
            // fell over entirely, etc.) has no real measurement to report;
            // zeroed-out stats paired with an explicit `driver_error` and
            // an `ErrorRate` violation make sure it still counts as a
            // failed level rather than silently vanishing from the sweep.
            stats: LevelStats {
                throughput_rps: 0.0,
                p50_latency: None,
                p99_latency: None,
                ttft_p99: None,
                error_rate: 1.0,
                requests_completed: 0,
                connections_opened: 0,
                steady_state_secs: 0.0,
                peak_rss_bytes: None,
                mean_cpu_percent: None,
                peak_fds: None,
            },
            violations: vec![SloViolation::ErrorRate],
            driver_error: Some(err.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_slo() -> SloConfig {
        SloConfig {
            p99_ceiling: Duration::from_millis(500),
            ttft_p99_ceiling: Duration::from_millis(200),
            max_error_rate: 0.05,
        }
    }

    fn passing_stats(n: usize) -> LevelStats {
        LevelStats {
            throughput_rps: n as f64,
            p50_latency: Some(Duration::from_millis(10)),
            p99_latency: Some(Duration::from_millis(100)),
            ttft_p99: Some(Duration::from_millis(50)),
            error_rate: 0.0,
            requests_completed: n as u64 * 10,
            connections_opened: n as u64 * 10,
            steady_state_secs: 10.0,
            peak_rss_bytes: Some(1_000_000 + n as u64 * 10_000),
            mean_cpu_percent: Some(1.0 + n as f64 * 0.5),
            peak_fds: Some(n as u64 * 2),
        }
    }

    fn failing_stats(n: usize) -> LevelStats {
        let mut s = passing_stats(n);
        s.p99_latency = Some(Duration::from_millis(9_999));
        s
    }

    /// A synthetic oracle: every level at or below `threshold` passes, every
    /// level above it fails on p99 latency. Used to prove the bisect search
    /// actually finds a known boundary rather than trusting it blindly.
    fn synthetic_driver(
        threshold: usize,
    ) -> impl FnMut(usize) -> std::future::Ready<anyhow::Result<LevelStats>> {
        move |n| {
            let stats = if n <= threshold {
                passing_stats(n)
            } else {
                failing_stats(n)
            };
            std::future::ready(Ok(stats))
        }
    }

    #[test]
    fn slo_evaluate_reports_every_violated_clause() {
        let slo = default_slo();
        let mut stats = passing_stats(1);
        assert!(slo.evaluate(&stats).is_empty());

        stats.p99_latency = Some(Duration::from_secs(1));
        stats.error_rate = 0.5;
        let violations = slo.evaluate(&stats);
        assert_eq!(
            violations,
            vec![SloViolation::P99Latency, SloViolation::ErrorRate]
        );
    }

    #[test]
    fn slo_evaluate_flags_ttft_independently() {
        let slo = default_slo();
        let mut stats = passing_stats(1);
        stats.ttft_p99 = Some(Duration::from_secs(1));
        assert_eq!(slo.evaluate(&stats), vec![SloViolation::TtftP99]);
    }

    #[tokio::test]
    async fn bisection_finds_a_known_breaking_point() {
        let threshold = 37;
        let cfg = SweepConfig {
            slo: default_slo(),
            start_concurrency: 1,
            max_concurrency: 1_000,
            growth_factor: 2.0,
            bisect_tolerance: 0,
        };
        let report = sweep(cfg, synthetic_driver(threshold)).await;
        assert_eq!(report.max_sustainable, Some(threshold));
        assert_eq!(report.first_failing, Some(threshold + 1));
        assert!(
            report.levels.len() < 20,
            "bisection should need far fewer probes than the {threshold}-level gap; got {}",
            report.levels.len()
        );
        assert!(report.levels.iter().all(|l| l.driver_error.is_none()));
    }

    #[tokio::test]
    async fn bisect_tolerance_stops_early_within_the_configured_gap() {
        let threshold = 100;
        let cfg = SweepConfig {
            slo: default_slo(),
            start_concurrency: 1,
            max_concurrency: 1_000,
            growth_factor: 2.0,
            bisect_tolerance: 5,
        };
        let report = sweep(cfg, synthetic_driver(threshold)).await;
        let lo = report.max_sustainable.unwrap();
        let hi = report.first_failing.unwrap();
        assert!(lo <= threshold);
        assert!(hi > threshold);
        assert!(hi - lo <= 5);
    }

    #[tokio::test]
    async fn never_failing_ramp_is_capped_by_max_concurrency_not_declared_a_pass_forever() {
        // threshold beyond max_concurrency -> the ramp exhausts its safety
        // cap without ever finding a failure. The caller (main.rs/report.rs)
        // is expected to treat `first_failing: None` here as "check
        // rig::harness_bound", not as "infinite capacity".
        let cfg = SweepConfig {
            slo: default_slo(),
            start_concurrency: 1,
            max_concurrency: 64,
            growth_factor: 2.0,
            bisect_tolerance: 0,
        };
        let report = sweep(cfg, synthetic_driver(10_000)).await;
        assert_eq!(report.max_sustainable, Some(64));
        assert_eq!(report.first_failing, None);
        assert!(report.levels.iter().all(|l| l.passed()));
    }

    #[tokio::test]
    async fn a_driver_error_counts_as_a_failed_level() {
        let cfg = SweepConfig {
            slo: default_slo(),
            start_concurrency: 1,
            max_concurrency: 100,
            growth_factor: 2.0,
            bisect_tolerance: 0,
        };
        let report = sweep(cfg, |n| async move {
            if n >= 4 {
                anyhow::bail!("sampler lost the proxy pid")
            } else {
                Ok(passing_stats(n))
            }
        })
        .await;
        assert_eq!(report.max_sustainable, Some(3));
        assert_eq!(report.first_failing, Some(4));
        let failed = report.levels.iter().find(|l| l.concurrency == 4).unwrap();
        assert!(!failed.passed());
        assert!(failed.driver_error.is_some());
    }

    #[tokio::test]
    async fn first_level_failing_yields_no_max_sustainable() {
        let cfg = SweepConfig {
            slo: default_slo(),
            start_concurrency: 1,
            max_concurrency: 100,
            growth_factor: 2.0,
            bisect_tolerance: 0,
        };
        let report = sweep(cfg, synthetic_driver(0)).await;
        assert_eq!(report.max_sustainable, None);
        assert_eq!(report.first_failing, Some(1));
    }
}
