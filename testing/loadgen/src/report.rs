//! The self-describing JSON output this driver produces, and the compact
//! human summary printed alongside it. Phase 2 (the N-sweep search and
//! report rendering, not built here) is meant to consume exactly this JSON
//! shape.

use serde::Serialize;

use crate::driver::OpenLoopStats;
use crate::metrics::RunSummary;
use crate::rig::RigInfo;

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
             -- latency percentiles below only cover successful streams, do not read them \
             as representative of the whole run",
            r.http_errors, r.transport_errors, r.timeouts
        );
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
