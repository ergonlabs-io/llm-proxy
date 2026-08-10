//! The self-describing JSON output this driver produces, and the compact
//! human summary printed alongside it. Phase 2 (the N-sweep search and
//! report rendering, not built here) is meant to consume exactly this JSON
//! shape.

use serde::Serialize;

use crate::driver::OpenLoopStats;
use crate::metrics::RunSummary;
use crate::rig::{self, RigInfo};
use crate::sweep::{self, SloViolation};

#[derive(Debug, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ModeConfig {
    Closed { concurrency: usize },
    Open { rate: f64 },
}

#[derive(Debug, Serialize)]
pub struct RunConfigEcho {
    pub targets: Vec<String>,
    pub baseline_targets: Option<Vec<String>>,
    pub endpoint: &'static str,
    pub model: String,
    pub max_tokens: u32,
    pub stream: bool,
    pub duration_secs: u64,
    pub warmup_secs: u64,
    pub timeout_secs: u64,
    #[serde(flatten)]
    pub mode: ModeConfig,
}

/// proxy-vs-baseline deltas on the two latencies that matter most for a
/// user-facing LLM stream: time to first token and total stream duration.
/// Computed from the *scheduled* histograms (the coordinated-omission
/// corrected ones, reported by default) so driver backlog in either leg
/// doesn't get silently absorbed into "overhead".
#[derive(Debug, Serialize)]
pub struct Overhead {
    pub ttft_p50_us: Option<i64>,
    pub ttft_p90_us: Option<i64>,
    pub ttft_p99_us: Option<i64>,
    pub total_p50_us: Option<i64>,
    pub total_p90_us: Option<i64>,
    pub total_p99_us: Option<i64>,
}

fn delta(proxy: Option<u64>, baseline: Option<u64>) -> Option<i64> {
    match (proxy, baseline) {
        (Some(p), Some(b)) => Some(p as i64 - b as i64),
        _ => None,
    }
}

fn ttft(s: &RunSummary) -> Option<&super::metrics::Percentiles> {
    s.ttft_from_scheduled_us.as_ref()
}

fn total(s: &RunSummary) -> Option<&super::metrics::Percentiles> {
    s.total_from_scheduled_us.as_ref()
}

pub fn compute_overhead(proxy: &RunSummary, baseline: &RunSummary) -> Overhead {
    Overhead {
        ttft_p50_us: delta(ttft(proxy).map(|p| p.p50), ttft(baseline).map(|p| p.p50)),
        ttft_p90_us: delta(ttft(proxy).map(|p| p.p90), ttft(baseline).map(|p| p.p90)),
        ttft_p99_us: delta(ttft(proxy).map(|p| p.p99), ttft(baseline).map(|p| p.p99)),
        total_p50_us: delta(total(proxy).map(|p| p.p50), total(baseline).map(|p| p.p50)),
        total_p90_us: delta(total(proxy).map(|p| p.p90), total(baseline).map(|p| p.p90)),
        total_p99_us: delta(total(proxy).map(|p| p.p99), total(baseline).map(|p| p.p99)),
    }
}

#[derive(Debug, Serialize)]
pub struct RunReport {
    pub config: RunConfigEcho,
    pub rig: RigInfo,
    pub result: RunSummary,
    pub open_loop: Option<OpenLoopStats>,
    /// Present only when `--baseline-target` was given. Documented in the
    /// CLI help and the crate's task brief: the baseline pass runs
    /// *sequentially* after the primary (proxy) pass, not interleaved --
    /// interleaving two full-throttle passes on the same 8-core/16GB box
    /// would have each pass steal CPU/fd/port budget from the other,
    /// contaminating exactly the overhead number this comparison exists to
    /// measure. Sequential costs wall-clock time, not correctness.
    pub baseline: Option<RunSummary>,
    pub overhead: Option<Overhead>,
}

/// Print the compact human-readable summary. Errors are surfaced loudly
/// (a nonzero error rate gets its own `!!!`-flagged line) rather than
/// folded quietly into an average.
pub fn print_summary(report: &RunReport) {
    let r = &report.result;
    println!("--- loadgen summary ---");
    println!(
        "streams: started={} counted={} (warmup-excluded={}) success={} error_rate={:.2}%",
        r.streams_started,
        r.streams_counted,
        r.warmup_excluded,
        r.success,
        r.error_rate * 100.0
    );
    if r.error_rate > 0.0 {
        println!(
            "!!! nonzero error rate: http_errors={:?} transport_errors={} timeouts={} \
             truncated={} -- latency percentiles below only cover successful streams, do not \
             read them as representative of the whole run",
            r.http_errors, r.transport_errors, r.timeouts, r.truncated
        );
        if r.truncated > 0 {
            println!(
                "!!! {} stream(s) ended without the dialect's terminal SSE frame -- the proxy \
                 (or upstream) truncated the response; this is a distinct failure from a \
                 transport error and must be investigated separately",
                r.truncated
            );
        }
    }
    if let Some(p) = &r.ttft_from_scheduled_us {
        println!(
            "ttft (from scheduled)  p50={:.1}ms p90={:.1}ms p99={:.1}ms max={:.1}ms",
            p.p50 as f64 / 1000.0,
            p.p90 as f64 / 1000.0,
            p.p99 as f64 / 1000.0,
            p.max as f64 / 1000.0
        );
    }
    if let Some(p) = &r.inter_token_us {
        println!(
            "inter-token gap        p50={:.1}ms p90={:.1}ms p99={:.1}ms max={:.1}ms",
            p.p50 as f64 / 1000.0,
            p.p90 as f64 / 1000.0,
            p.p99 as f64 / 1000.0,
            p.max as f64 / 1000.0
        );
    }
    if let Some(p) = &r.total_from_scheduled_us {
        println!(
            "total (from scheduled) p50={:.1}ms p90={:.1}ms p99={:.1}ms max={:.1}ms",
            p.p50 as f64 / 1000.0,
            p.p90 as f64 / 1000.0,
            p.p99 as f64 / 1000.0,
            p.max as f64 / 1000.0
        );
    }
    println!(
        "tokens_received={} bytes_received={}",
        r.tokens_received, r.bytes_received
    );

    if let Some(open) = &report.open_loop {
        println!(
            "open-loop: requested_rate={:.1}/s achieved_rate={:.1}/s requested_count={}",
            open.requested_rate, open.achieved_rate, open.requested_count
        );
        if open.driver_saturated {
            println!(
                "!!! driver fell behind its own schedule (max backlog {:.1}ms) -- the LOADGEN \
                 saturated, this run does not measure the target's real capacity",
                open.max_backlog_ms
            );
        }
    }

    if let (Some(baseline), Some(overhead)) = (&report.baseline, &report.overhead) {
        println!(
            "baseline: success={} error_rate={:.2}%",
            baseline.success,
            baseline.error_rate * 100.0
        );
        println!(
            "proxy overhead: ttft p50={}us p90={}us p99={}us | total p50={}us p90={}us p99={}us",
            fmt_delta(overhead.ttft_p50_us),
            fmt_delta(overhead.ttft_p90_us),
            fmt_delta(overhead.ttft_p99_us),
            fmt_delta(overhead.total_p50_us),
            fmt_delta(overhead.total_p90_us),
            fmt_delta(overhead.total_p99_us),
        );
    }
}

fn fmt_delta(v: Option<i64>) -> String {
    v.map(|v| v.to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

// ---------------------------------------------------------------------
// Capacity report (WP-30 phase 2): renders a `sweep::SweepReport` into a
// concurrency -> throughput/latency/resource-usage table, plus the derived
// cost model that is this tool's actual headline (see the module doc and
// the crate's task brief -- a single "max streams" number is far less
// useful than the marginal cost per stream).
// ---------------------------------------------------------------------

/// One row of the capacity table: everything measured at one concurrency
/// level.
#[derive(Debug, Clone, Serialize)]
pub struct CapacityRow {
    pub concurrency: usize,
    pub passed: bool,
    pub violations: Vec<SloViolation>,
    pub throughput_rps: f64,
    pub p50_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub ttft_p99_ms: f64,
    pub error_rate: f64,
    pub peak_rss_bytes: Option<u64>,
    pub mean_cpu_percent: Option<f64>,
    pub peak_fds: Option<u64>,
}

/// A linear cost model fit *across* the levels (not derived from a single
/// data point -- see the crate's task brief): bytes of RSS per additional
/// concurrent stream, and CPU-milliseconds per request. `None` fields mean
/// there weren't enough data points (or enough variance) to fit a line --
/// never a fabricated slope.
#[derive(Debug, Clone, Serialize)]
pub struct CostModel {
    /// Slope of peak RSS (bytes) vs. concurrency.
    pub bytes_per_stream: Option<f64>,
    /// Intercept -- the proxy's baseline RSS at zero concurrent streams.
    pub rss_baseline_bytes: Option<f64>,
    pub rss_fit_r_squared: Option<f64>,
    /// Slope of total steady-state CPU time (ms) vs. requests completed.
    pub cpu_ms_per_request: Option<f64>,
    /// Intercept -- fixed per-level CPU overhead independent of request count.
    pub cpu_ms_baseline: Option<f64>,
    pub cpu_fit_r_squared: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapacityReport {
    pub rows: Vec<CapacityRow>,
    pub max_sustainable: Option<usize>,
    pub first_failing: Option<usize>,
    pub cost_model: CostModel,
    /// Set when the sweep's furthest-reached concurrency landed at or near
    /// a harness ceiling rather than an SLO failure -- see
    /// `rig::harness_bound`. When this is `Some`, `max_sustainable` above
    /// is a HARNESS ceiling, not a proxy capacity result, and must be
    /// reported as such.
    pub harness_bound: Option<rig::HarnessBound>,
}

/// Ordinary least-squares fit of `y = slope * x + intercept` through
/// `points`, plus R^2. `None` if there are fewer than two points or all
/// `x` values are identical (a vertical/undefined line).
fn linear_fit(points: &[(f64, f64)]) -> Option<(f64, f64, f64)> {
    let n = points.len() as f64;
    if points.len() < 2 {
        return None;
    }
    let sum_x: f64 = points.iter().map(|p| p.0).sum();
    let sum_y: f64 = points.iter().map(|p| p.1).sum();
    let mean_x = sum_x / n;
    let mean_y = sum_y / n;
    let sum_xy: f64 = points.iter().map(|p| p.0 * p.1).sum();
    let sum_xx: f64 = points.iter().map(|p| p.0 * p.0).sum();
    let denom = sum_xx - n * mean_x * mean_x;
    if denom.abs() < f64::EPSILON {
        return None;
    }
    let slope = (sum_xy - n * mean_x * mean_y) / denom;
    let intercept = mean_y - slope * mean_x;

    let ss_tot: f64 = points.iter().map(|p| (p.1 - mean_y).powi(2)).sum();
    let ss_res: f64 = points
        .iter()
        .map(|p| (p.1 - (slope * p.0 + intercept)).powi(2))
        .sum();
    let r_squared = if ss_tot.abs() < f64::EPSILON {
        1.0
    } else {
        1.0 - ss_res / ss_tot
    };
    Some((slope, intercept, r_squared))
}

/// Fit the cost model across every level a sweep drove (ramp *and* bisect
/// levels both count -- more points make a steadier fit).
fn fit_cost_model(levels: &[sweep::LevelResult]) -> CostModel {
    let rss_points: Vec<(f64, f64)> = levels
        .iter()
        .filter_map(|l| {
            l.stats
                .peak_rss_bytes
                .map(|b| (l.concurrency as f64, b as f64))
        })
        .collect();
    let rss_fit = linear_fit(&rss_points);

    let cpu_points: Vec<(f64, f64)> = levels
        .iter()
        .filter_map(|l| {
            let pct = l.stats.mean_cpu_percent?;
            if l.stats.requests_completed == 0 {
                return None;
            }
            let total_cpu_ms = pct / 100.0 * l.stats.steady_state_secs * 1000.0;
            Some((l.stats.requests_completed as f64, total_cpu_ms))
        })
        .collect();
    let cpu_fit = linear_fit(&cpu_points);

    CostModel {
        bytes_per_stream: rss_fit.map(|f| f.0),
        rss_baseline_bytes: rss_fit.map(|f| f.1),
        rss_fit_r_squared: rss_fit.map(|f| f.2),
        cpu_ms_per_request: cpu_fit.map(|f| f.0),
        cpu_ms_baseline: cpu_fit.map(|f| f.1),
        cpu_fit_r_squared: cpu_fit.map(|f| f.2),
    }
}

/// Build the full capacity report from a sweep's result and the rig limits
/// detected before the sweep ran.
pub fn build_capacity_report(
    sweep_report: &sweep::SweepReport,
    rig_info: &RigInfo,
) -> CapacityReport {
    let mut rows: Vec<CapacityRow> = sweep_report
        .levels
        .iter()
        .map(|l| CapacityRow {
            concurrency: l.concurrency,
            passed: l.passed(),
            violations: l.violations.clone(),
            throughput_rps: l.stats.throughput_rps,
            p50_latency_ms: l.stats.p50_latency.as_secs_f64() * 1000.0,
            p99_latency_ms: l.stats.p99_latency.as_secs_f64() * 1000.0,
            ttft_p99_ms: l.stats.ttft_p99.as_secs_f64() * 1000.0,
            error_rate: l.stats.error_rate,
            peak_rss_bytes: l.stats.peak_rss_bytes,
            mean_cpu_percent: l.stats.mean_cpu_percent,
            peak_fds: l.stats.peak_fds,
        })
        .collect();
    rows.sort_by_key(|r| r.concurrency);

    let cost_model = fit_cost_model(&sweep_report.levels);

    // The furthest concurrency actually driven is the honest "how far did
    // this sweep get", regardless of whether it passed or failed -- that's
    // what a harness ceiling would show up as.
    let reached = sweep_report
        .levels
        .iter()
        .map(|l| l.concurrency)
        .max()
        .unwrap_or(0);
    let harness_bound = rig::harness_bound(reached, rig_info, 10);

    CapacityReport {
        rows,
        max_sustainable: sweep_report.max_sustainable,
        first_failing: sweep_report.first_failing,
        cost_model,
        harness_bound,
    }
}

/// Print the capacity table and cost model to stdout.
pub fn print_capacity_report(report: &CapacityReport) {
    println!("--- capacity sweep report ---");
    println!(
        "{:>12} {:>6} {:>12} {:>10} {:>10} {:>10} {:>9} {:>12} {:>9} {:>9}",
        "concurrency",
        "pass",
        "throughput",
        "p50_ms",
        "p99_ms",
        "ttft_p99",
        "err_rate",
        "peak_rss",
        "mean_cpu",
        "peak_fds"
    );
    for row in &report.rows {
        println!(
            "{:>12} {:>6} {:>12.1} {:>10.1} {:>10.1} {:>10.1} {:>9.2} {:>12} {:>9} {:>9}",
            row.concurrency,
            if row.passed { "ok" } else { "FAIL" },
            row.throughput_rps,
            row.p50_latency_ms,
            row.p99_latency_ms,
            row.ttft_p99_ms,
            row.error_rate,
            row.peak_rss_bytes
                .map(|b| format!("{:.1}MB", b as f64 / 1_048_576.0))
                .unwrap_or_else(|| "n/a".to_string()),
            row.mean_cpu_percent
                .map(|p| format!("{p:.0}%"))
                .unwrap_or_else(|| "n/a".to_string()),
            row.peak_fds
                .map(|f| f.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
        );
        if !row.violations.is_empty() {
            println!("             -> violated: {:?}", row.violations);
        }
    }

    println!();
    match report.max_sustainable {
        Some(n) => println!("max sustainable concurrency (within SLO): {n}"),
        None => println!(
            "max sustainable concurrency: none -- even the lowest level tried failed the SLO"
        ),
    }

    if let Some(bound) = &report.harness_bound {
        println!(
            "!!! HARNESS-BOUND: this run terminated at or near the harness's own {} \
             (~{} streams), NOT a proxy capacity result -- rerun with more loopback aliases / \
             a higher fd limit / a real multi-box rig before trusting this as the proxy's ceiling",
            bound.limit_name, bound.limit_value
        );
    }

    println!();
    println!(
        "--- cost model (fit across all {} driven levels) ---",
        report.rows.len()
    );
    match (
        report.cost_model.bytes_per_stream,
        report.cost_model.rss_baseline_bytes,
    ) {
        (Some(slope), Some(intercept)) => println!(
            "RSS      ~= {:.1}MB baseline + {:.1}KB / concurrent stream  (R^2={:.3})",
            intercept / 1_048_576.0,
            slope / 1024.0,
            report.cost_model.rss_fit_r_squared.unwrap_or(0.0)
        ),
        _ => println!("RSS      cost model: not enough data points to fit"),
    }
    match (
        report.cost_model.cpu_ms_per_request,
        report.cost_model.cpu_ms_baseline,
    ) {
        (Some(slope), Some(intercept)) => println!(
            "CPU      ~= {:.2}ms baseline + {:.3}ms / request  (R^2={:.3})",
            intercept,
            slope,
            report.cost_model.cpu_fit_r_squared.unwrap_or(0.0)
        ),
        _ => println!("CPU      cost model: not enough data points to fit"),
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    #[test]
    fn linear_fit_recovers_an_exact_line() {
        let points: Vec<(f64, f64)> = (0..10).map(|x| (x as f64, 2.0 * x as f64 + 3.0)).collect();
        let (slope, intercept, r_squared) = linear_fit(&points).expect("fit");
        assert!((slope - 2.0).abs() < 1e-9);
        assert!((intercept - 3.0).abs() < 1e-9);
        assert!((r_squared - 1.0).abs() < 1e-9);
    }

    #[test]
    fn linear_fit_needs_at_least_two_points() {
        assert!(linear_fit(&[]).is_none());
        assert!(linear_fit(&[(1.0, 1.0)]).is_none());
    }

    #[test]
    fn linear_fit_none_for_vertical_data() {
        // Every x identical -> the model is undefined, not "slope infinity".
        assert!(linear_fit(&[(5.0, 1.0), (5.0, 2.0), (5.0, 3.0)]).is_none());
    }

    fn level(
        concurrency: usize,
        rss_bytes: u64,
        mean_cpu_percent: f64,
        requests: u64,
    ) -> sweep::LevelResult {
        sweep::LevelResult {
            concurrency,
            stats: sweep::LevelStats {
                throughput_rps: requests as f64 / 10.0,
                p50_latency: std::time::Duration::from_millis(10),
                p99_latency: std::time::Duration::from_millis(50),
                ttft_p99: std::time::Duration::from_millis(20),
                error_rate: 0.0,
                requests_completed: requests,
                steady_state_secs: 10.0,
                peak_rss_bytes: Some(rss_bytes),
                mean_cpu_percent: Some(mean_cpu_percent),
                peak_fds: Some(concurrency as u64 * 2),
            },
            violations: Vec::new(),
            driver_error: None,
        }
    }

    #[test]
    fn fit_cost_model_recovers_a_known_bytes_per_stream_slope() {
        // Baseline 10MB + 100KB/stream, exactly linear across four levels.
        let levels: Vec<sweep::LevelResult> = [1usize, 2, 4, 8]
            .into_iter()
            .map(|n| {
                let rss = 10 * 1_048_576 + (n as u64) * 100 * 1024;
                level(n, rss, 5.0, n as u64 * 10)
            })
            .collect();
        let model = fit_cost_model(&levels);
        let bytes_per_stream = model.bytes_per_stream.expect("fit");
        assert!(
            (bytes_per_stream - 100.0 * 1024.0).abs() < 1.0,
            "expected ~100KB/stream, got {bytes_per_stream}"
        );
    }

    #[test]
    fn build_capacity_report_flags_harness_bound_when_reached_is_near_the_rig_ceiling() {
        let sweep_report = sweep::SweepReport {
            levels: vec![level(90, 1_000_000, 1.0, 900)],
            max_sustainable: Some(90),
            first_failing: None,
        };
        let rig_info = RigInfo {
            fd_soft_limit: Some(1_000),
            ephemeral_port_range: (49152, 65535),
            ephemeral_port_range_is_measured: true,
            somaxconn: Some(128),
            port_budget: 100,
            fd_budget: Some(1_000),
            estimated_max_concurrency: 100,
        };
        let report = build_capacity_report(&sweep_report, &rig_info);
        assert!(
            report.harness_bound.is_some(),
            "reaching 90/100 of the port budget should be flagged harness-bound"
        );
    }

    #[test]
    fn build_capacity_report_no_harness_bound_when_reached_is_well_clear() {
        let sweep_report = sweep::SweepReport {
            levels: vec![level(10, 1_000_000, 1.0, 100)],
            max_sustainable: Some(10),
            first_failing: Some(20),
        };
        let rig_info = RigInfo {
            fd_soft_limit: Some(1_000),
            ephemeral_port_range: (49152, 65535),
            ephemeral_port_range_is_measured: true,
            somaxconn: Some(128),
            port_budget: 8_000,
            fd_budget: Some(500_000),
            estimated_max_concurrency: 8_000,
        };
        let report = build_capacity_report(&sweep_report, &rig_info);
        assert!(report.harness_bound.is_none());
    }
}
