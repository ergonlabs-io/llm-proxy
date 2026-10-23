use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use loadgen::dialect::Endpoint;
use loadgen::driver::{self, DownstreamMode, RunConfig, TransportConfig};
use loadgen::report::{self, ModeConfig, RunConfigEcho, RunReport};
use loadgen::rig;
use loadgen::sampler;
use loadgen::sweep::{self, SloConfig, SweepConfig};

/// LLM streaming load generator. See the crate doc for the full
/// measurement model. Phase 2 adds `--self-check` (print detected harness
/// limits and exit) and `--sweep` (ramp-hold-bisect capacity search).
#[derive(Parser)]
#[command(name = "loadgen")]
struct Cli {
    /// Downstream connection strategy. h2 requires an https target and ALPN h2.
    #[arg(long = "downstream-mode", value_enum, default_value_t = DownstreamMode::Short)]
    downstream_mode: DownstreamMode,

    /// Maximum persistent connections per target in h1-pool mode.
    #[arg(long = "downstream-h1-pool-size", default_value_t = 32)]
    downstream_h1_pool_size: usize,

    /// PEM CA bundle for a private TLS (https) target, in any mode.
    #[arg(long = "downstream-ca-file")]
    downstream_ca_file: Option<PathBuf>,

    /// Print the detected harness limits (fd limit, ephemeral port range,
    /// somaxconn) and the theoretical max concurrency they imply, then
    /// exit without driving any load. Use this before a long `--sweep` run
    /// to sanity-check the box.
    #[arg(long = "self-check")]
    self_check: bool,

    /// Ports budgeted per stream: two for unpooled HTTP/1.1 hops, one when the
    /// upstream HTTP/2 connection is multiplexed.
    #[arg(long = "rig-sockets-per-stream", default_value_t = rig::DEFAULT_SOCKETS_PER_STREAM)]
    rig_sockets_per_stream: u64,

    /// Upstream to send requests to, `http://host:port`. May be repeated
    /// and/or comma-separated to round-robin across several loopback
    /// aliases (mitigates the single-box ephemeral-port ceiling -- see
    /// `rig.rs`). Not required with `--self-check`.
    #[arg(long = "target", required_unless_present = "self_check")]
    target: Vec<String>,

    /// Optional second upstream (same syntax as `--target`) to run the
    /// identical workload against for an A/B "proxy overhead" comparison.
    /// Runs as a second, sequential pass -- see `report::RunReport::baseline`.
    /// Ignored by `--sweep`.
    #[arg(long = "baseline-target")]
    baseline_target: Vec<String>,

    /// Which endpoint shape to speak. Not required with `--self-check`.
    #[arg(long, value_enum, required_unless_present = "self_check")]
    endpoint: Option<Endpoint>,

    /// Run a capacity sweep (ramp-hold-bisect for max sustainable
    /// concurrency) instead of a single fixed-concurrency
    /// or fixed-rate run. Mutually exclusive with --concurrency/--rate.
    #[arg(long)]
    sweep: bool,

    /// PID of the proxy process to sample RSS/CPU/fd usage from during a
    /// sweep. Required with --sweep.
    #[arg(long = "sweep-pid")]
    sweep_pid: Option<u32>,

    /// First concurrency level the sweep's ramp tries.
    #[arg(long = "sweep-start", default_value_t = 1)]
    sweep_start: usize,

    /// Geometric ramp growth multiplier (2.0 doubles each step).
    #[arg(long = "sweep-growth", default_value_t = 2.0)]
    sweep_growth: f64,

    /// How long to hold each sweep level, in seconds (includes the
    /// discarded warm-up prefix below).
    #[arg(long = "sweep-hold-secs", default_value_t = 10)]
    sweep_hold_secs: u64,

    /// Warm-up prefix discarded from each held level's stats.
    #[arg(long = "sweep-warmup-secs", default_value_t = 3)]
    sweep_warmup_secs: u64,

    /// Sweep safety cap on concurrency. Defaults to this rig's own
    /// estimated max concurrency (`rig::detect`), so an unset sweep can
    /// never mistake a harness ceiling for "the proxy has no limit".
    #[arg(long = "sweep-max-concurrency")]
    sweep_max_concurrency: Option<usize>,

    /// Bisection stops once the pass/fail boundary is within this many
    /// streams.
    #[arg(long = "sweep-bisect-tolerance", default_value_t = 1)]
    sweep_bisect_tolerance: usize,

    /// SLO gate: p99 total-latency ceiling, in ms.
    #[arg(long = "slo-p99-ms", default_value_t = 2000)]
    slo_p99_ms: u64,

    /// SLO gate: p99 time-to-first-token ceiling, in ms.
    #[arg(long = "slo-ttft-p99-ms", default_value_t = 1000)]
    slo_ttft_p99_ms: u64,

    /// SLO gate: max acceptable error rate (0.01 = 1%).
    #[arg(long = "slo-max-error-rate", default_value_t = 0.01)]
    slo_max_error_rate: f64,

    /// Process-sampler interval during a sweep, in ms.
    #[arg(long = "sample-interval-ms", default_value_t = 500)]
    sample_interval_ms: u64,

    /// Closed-loop mode: hold exactly this many streams in flight
    /// (the CAPACITY mode). Exactly one of --concurrency/--rate is required.
    #[arg(long)]
    concurrency: Option<usize>,

    /// Open-loop mode: start streams on a fixed rate/sec schedule
    /// regardless of completions (the LATENCY mode, with
    /// coordinated-omission correction). Exactly one of
    /// --concurrency/--rate is required.
    #[arg(long)]
    rate: Option<f64>,

    /// How long to drive load, in seconds.
    #[arg(long = "duration", default_value_t = 30)]
    duration_secs: u64,

    /// Warmup period excluded from stats, in seconds.
    #[arg(long = "warmup", default_value_t = 0)]
    warmup_secs: u64,

    /// Skip SSE streaming and just measure total request latency.
    #[arg(long)]
    no_stream: bool,

    /// Per-stream timeout, in seconds.
    #[arg(long = "timeout", default_value_t = 30)]
    timeout_secs: u64,

    /// Write the full JSON report here (also always printed as a compact
    /// human summary to stdout).
    #[arg(long)]
    out: Option<PathBuf>,

    /// Bearer token / API key sent as the provider-appropriate auth header
    /// (see `dialect::Endpoint::auth_headers`). Omit when targeting a mock
    /// that doesn't check it.
    #[arg(long)]
    api_key: Option<String>,

    #[arg(long, default_value = "gpt-4o-mini")]
    model: String,

    #[arg(long, default_value_t = 128)]
    max_tokens: u32,

    #[arg(long, default_value = "Say hello in one short sentence.")]
    prompt: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Cli::parse();

    let rig_info = rig::detect(args.rig_sockets_per_stream);

    if args.self_check {
        rig::print_self_check(&rig_info);
        return Ok(ExitCode::SUCCESS);
    }

    rig::log_summary(&rig_info);

    // Rust note: `--endpoint`/`--target` are `required_unless_present =
    // "self_check"` in the clap attributes above, so by the time we're
    // past the `self_check` early-return, clap has already guaranteed
    // these are set -- `.expect` here documents that invariant rather than
    // silently trusting it.
    let endpoint = args
        .endpoint
        .expect("clap enforces --endpoint unless --self-check");

    if args.sweep {
        return run_sweep(&args, endpoint, &rig_info).await;
    }

    let mode = match (args.concurrency, args.rate) {
        (Some(_), Some(_)) | (None, None) => {
            anyhow::bail!("pass exactly one of --concurrency or --rate")
        }
        (Some(c), None) => ModeConfig::Closed { concurrency: c },
        (None, Some(r)) => ModeConfig::Open { rate: r },
    };

    let targets = driver::parse_targets(&args.target)?;
    let duration = Duration::from_secs(args.duration_secs);
    let warmup = Duration::from_secs(args.warmup_secs);

    let cfg = Arc::new(build_run_config(&args, endpoint, targets));
    let (result, open_loop) = run_mode(&mode, cfg, duration, warmup).await;

    let (baseline, overhead, baseline_target_strs) = if args.baseline_target.is_empty() {
        (None, None, None)
    } else {
        eprintln!("running baseline (A/B) pass sequentially against --baseline-target...");
        let baseline_targets = driver::parse_targets(&args.baseline_target)?;
        let echo = baseline_targets
            .iter()
            .map(|t| {
                format!(
                    "{}://{}:{}",
                    if t.tls { "https" } else { "http" },
                    t.host,
                    t.port
                )
            })
            .collect();
        let baseline_cfg = Arc::new(build_run_config(&args, endpoint, baseline_targets));
        let (baseline_result, _baseline_open_loop) =
            run_mode(&mode, baseline_cfg, duration, warmup).await;
        let overhead = report::compute_overhead(&result, &baseline_result);
        (Some(baseline_result), Some(overhead), Some(echo))
    };

    let config_echo = RunConfigEcho {
        targets: args.target.clone(),
        baseline_targets: baseline_target_strs,
        endpoint: endpoint_name(endpoint),
        model: args.model.clone(),
        max_tokens: args.max_tokens,
        stream: !args.no_stream,
        duration_secs: args.duration_secs,
        warmup_secs: args.warmup_secs,
        timeout_secs: args.timeout_secs,
        downstream_mode: args.downstream_mode,
        downstream_h1_pool_size: args.downstream_h1_pool_size,
        mode,
    };

    let full_report = RunReport {
        config: config_echo,
        rig: rig_info,
        result,
        open_loop,
        baseline,
        overhead,
    };

    report::print_summary(&full_report);

    if let Some(out) = &args.out {
        let json = serde_json::to_string_pretty(&full_report)?;
        std::fs::write(out, json)?;
        println!("wrote {}", out.display());
    }

    if full_report.result.error_rate > 0.0 {
        // Non-fatal: a nonzero error rate is data, but exiting nonzero makes
        // it hard to miss in a script/CI pipeline.
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn endpoint_name(endpoint: Endpoint) -> &'static str {
    match endpoint {
        Endpoint::Chat => "chat",
        Endpoint::Responses => "responses",
        Endpoint::Messages => "messages",
    }
}

fn build_run_config(args: &Cli, endpoint: Endpoint, targets: Vec<driver::Target>) -> RunConfig {
    RunConfig {
        targets,
        endpoint,
        model: args.model.clone(),
        prompt: args.prompt.clone(),
        max_tokens: args.max_tokens,
        api_key: args.api_key.clone(),
        stream: !args.no_stream,
        timeout: Duration::from_secs(args.timeout_secs),
        transport: TransportConfig {
            mode: args.downstream_mode,
            h1_pool_size: args.downstream_h1_pool_size,
            ca_file: args.downstream_ca_file.clone(),
        },
    }
}

/// Run a capacity sweep: ramp-hold-bisect for the largest
/// concurrency the target sustains within the configured SLO, sampling the
/// proxy process's RSS/CPU/fds alongside each held level.
async fn run_sweep(
    args: &Cli,
    endpoint: Endpoint,
    rig_info: &rig::RigInfo,
) -> anyhow::Result<ExitCode> {
    let pid = args.sweep_pid.ok_or_else(|| {
        anyhow::anyhow!("--sweep requires --sweep-pid <PID of the proxy process>")
    })?;
    let targets = driver::parse_targets(&args.target)?;
    let cfg = Arc::new(build_run_config(args, endpoint, targets));
    let hold = Duration::from_secs(args.sweep_hold_secs);
    let warmup = Duration::from_secs(args.sweep_warmup_secs);
    let steady_state_secs = (args.sweep_hold_secs.saturating_sub(args.sweep_warmup_secs)) as f64;
    let sample_interval = Duration::from_millis(args.sample_interval_ms);

    let max_concurrency = args
        .sweep_max_concurrency
        .unwrap_or(rig_info.estimated_max_concurrency as usize);
    if args.sweep_max_concurrency.is_none() {
        eprintln!(
            "no --sweep-max-concurrency given -- capping the ramp at this rig's own estimated \
             max concurrency (~{max_concurrency}) so the sweep can't mistake a harness ceiling \
             for the proxy's"
        );
    }

    let sweep_cfg = SweepConfig {
        slo: SloConfig {
            p99_ceiling: Duration::from_millis(args.slo_p99_ms),
            ttft_p99_ceiling: Duration::from_millis(args.slo_ttft_p99_ms),
            max_error_rate: args.slo_max_error_rate,
        },
        start_concurrency: args.sweep_start,
        max_concurrency,
        growth_factor: args.sweep_growth,
        bisect_tolerance: args.sweep_bisect_tolerance,
    };

    let sweep_report = sweep::sweep(sweep_cfg, |concurrency| {
        let cfg = cfg.clone();
        async move {
            let sampler_handle = sampler::spawn(pid, sample_interval);
            let summary = driver::run_closed_loop(cfg, concurrency, hold, warmup).await;
            let series = sampler_handle.stop().await?;
            let sample_summary = series.summarize().ok();
            Ok(level_stats(
                &summary,
                steady_state_secs,
                sample_summary.as_ref(),
            ))
        }
    })
    .await;

    let capacity_report = report::build_capacity_report(&sweep_report, rig_info);
    report::print_capacity_report(&capacity_report);

    if let Some(out) = &args.out {
        let json = serde_json::to_string_pretty(&capacity_report)?;
        std::fs::write(out, json)?;
        println!("wrote {}", out.display());
    }

    if capacity_report.harness_bound.is_some() || capacity_report.max_sustainable.is_none() {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// Turn one level's [`loadgen::metrics::RunSummary`] (already warm-up
/// excluded by `driver::run_closed_loop`) plus its process-sampler summary
/// into the [`sweep::LevelStats`] the search/SLO logic consumes.
///
/// Missing percentiles (no successful streams at all -- every request in
/// the level errored) map to `None`, not a sentinel duration. This used to
/// be `Duration::MAX`, which `report::build_capacity_report` then rendered
/// as the JSON number `1.8446744073709552e+22` and `SloConfig::evaluate`
/// read as a genuine (astronomically large) p99/ttft measurement, so a
/// level that failed purely on error rate was ALSO reported as failing its
/// latency SLO -- the wrong cause, riding along with the right one. A level
/// with no data still fails via `SloViolation::ErrorRate` (see
/// `sweep::SloConfig::evaluate`), it just no longer fabricates a latency
/// number to go with it.
fn level_stats(
    summary: &loadgen::metrics::RunSummary,
    steady_state_secs: f64,
    sample_summary: Option<&sampler::SamplerSummary>,
) -> sweep::LevelStats {
    let p50_latency = summary
        .total_from_scheduled_us
        .as_ref()
        .map(|p| Duration::from_micros(p.p50));
    let p99_latency = summary
        .total_from_scheduled_us
        .as_ref()
        .map(|p| Duration::from_micros(p.p99));
    let ttft_p99 = summary
        .ttft_from_scheduled_us
        .as_ref()
        .map(|p| Duration::from_micros(p.p99));
    let throughput_rps = if steady_state_secs > 0.0 {
        summary.streams_counted as f64 / steady_state_secs
    } else {
        0.0
    };

    sweep::LevelStats {
        throughput_rps,
        p50_latency,
        p99_latency,
        ttft_p99,
        error_rate: summary.error_rate,
        requests_completed: summary.streams_counted,
        connections_opened: summary.transport.connections_opened,
        steady_state_secs,
        peak_rss_bytes: sample_summary.map(|s| s.peak_rss_bytes),
        mean_cpu_percent: sample_summary.and_then(|s| s.mean_cpu_percent),
        peak_fds: sample_summary.map(|s| s.peak_fds),
    }
}

async fn run_mode(
    mode: &ModeConfig,
    cfg: Arc<RunConfig>,
    duration: Duration,
    warmup: Duration,
) -> (loadgen::metrics::RunSummary, Option<driver::OpenLoopStats>) {
    match *mode {
        ModeConfig::Closed { concurrency } => {
            let summary = driver::run_closed_loop(cfg, concurrency, duration, warmup).await;
            (summary, None)
        }
        ModeConfig::Open { rate } => {
            let (summary, stats) = driver::run_open_loop(cfg, rate, duration, warmup).await;
            (summary, Some(stats))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loadgen::metrics::{Aggregator, Outcome, StreamResult};
    use std::time::Instant;

    fn failed_result(now: Instant) -> StreamResult {
        StreamResult {
            scheduled_start: now,
            send_start: now,
            outcome: Outcome::HttpError(500),
            ttft_from_scheduled: None,
            ttft_from_send: None,
            // `failed_result`-shaped: a real failure still carries a
            // time-to-failure, but `Aggregator::record` never lets it reach
            // a latency histogram (see `metrics.rs`) -- that's what makes
            // the histograms genuinely empty below, not just zeroed.
            total_from_scheduled: Duration::from_millis(5),
            total_from_send: Duration::from_millis(5),
            inter_token_gaps: Vec::new(),
            tokens_received: 0,
            bytes_received: 0,
        }
    }

    /// Defect 1: a level where every stream fails must not fabricate a
    /// latency figure. Before the fix, `level_stats` mapped the empty
    /// histograms' missing percentiles to `Duration::MAX`, which
    /// `report::build_capacity_report` rendered as the JSON number
    /// `1.8446744073709552e+22` and the SLO gate then misread as a real
    /// (enormous) p99/ttft measurement -- so a level that failed on error
    /// rate alone was also reported as failing its latency SLO.
    #[test]
    fn level_stats_carries_no_fabricated_latency_when_every_stream_in_the_level_fails() {
        let now = Instant::now();
        let mut agg = Aggregator::new(now - Duration::from_secs(1));
        for _ in 0..5 {
            agg.record(failed_result(now));
        }
        let summary = agg.finish();
        assert_eq!(summary.error_rate, 1.0);
        assert!(summary.total_from_scheduled_us.is_none());
        assert!(summary.ttft_from_scheduled_us.is_none());

        let stats = level_stats(&summary, 10.0, None);
        assert!(stats.p50_latency.is_none());
        assert!(stats.p99_latency.is_none());
        assert!(stats.ttft_p99.is_none());
        assert_eq!(stats.error_rate, 1.0);

        // And the SLO gate must name the real cause alone.
        let slo = SloConfig {
            p99_ceiling: Duration::from_millis(500),
            ttft_p99_ceiling: Duration::from_millis(200),
            max_error_rate: 0.01,
        };
        assert_eq!(slo.evaluate(&stats), vec![sweep::SloViolation::ErrorRate]);
    }
}
