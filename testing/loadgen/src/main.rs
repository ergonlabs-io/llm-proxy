use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use loadgen::dialect::Endpoint;
use loadgen::driver::{self, RunConfig};
use loadgen::report::{self, ModeConfig, RunConfigEcho, RunReport};
use loadgen::rig;

/// LLM streaming load generator (Phase 1: driver + metrics). See the crate
/// doc for the full measurement model.
#[derive(Parser)]
#[command(name = "loadgen")]
struct Cli {
    /// Upstream to send requests to, `http://host:port`. May be repeated
    /// and/or comma-separated to round-robin across several loopback
    /// aliases (mitigates the single-box ephemeral-port ceiling -- see
    /// `rig.rs`).
    #[arg(long = "target", required = true)]
    target: Vec<String>,

    /// Optional second upstream (same syntax as `--target`) to run the
    /// identical workload against for an A/B "proxy overhead" comparison.
    /// Runs as a second, sequential pass -- see `report::RunReport::baseline`.
    #[arg(long = "baseline-target")]
    baseline_target: Vec<String>,

    /// Which endpoint shape to speak.
    #[arg(long, value_enum)]
    endpoint: Endpoint,

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

    let rig_info = rig::detect();
    rig::log_summary(&rig_info);

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

    let cfg = Arc::new(build_run_config(&args, targets));
    let (result, open_loop) = run_mode(&mode, cfg, duration, warmup).await;

    let (baseline, overhead, baseline_target_strs) = if args.baseline_target.is_empty() {
        (None, None, None)
    } else {
        eprintln!("running baseline (A/B) pass sequentially against --baseline-target...");
        let baseline_targets = driver::parse_targets(&args.baseline_target)?;
        let echo = baseline_targets
            .iter()
            .map(|t| format!("http://{}:{}", t.host, t.port))
            .collect();
        let baseline_cfg = Arc::new(build_run_config(&args, baseline_targets));
        let (baseline_result, _baseline_open_loop) =
            run_mode(&mode, baseline_cfg, duration, warmup).await;
        let overhead = report::compute_overhead(&result, &baseline_result);
        (Some(baseline_result), Some(overhead), Some(echo))
    };

    let config_echo = RunConfigEcho {
        targets: args.target.clone(),
        baseline_targets: baseline_target_strs,
        endpoint: endpoint_name(args.endpoint),
        model: args.model.clone(),
        max_tokens: args.max_tokens,
        stream: !args.no_stream,
        duration_secs: args.duration_secs,
        warmup_secs: args.warmup_secs,
        timeout_secs: args.timeout_secs,
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

fn build_run_config(args: &Cli, targets: Vec<driver::Target>) -> RunConfig {
    RunConfig {
        targets,
        endpoint: args.endpoint,
        model: args.model.clone(),
        prompt: args.prompt.clone(),
        max_tokens: args.max_tokens,
        api_key: args.api_key.clone(),
        stream: !args.no_stream,
        timeout: Duration::from_secs(args.timeout_secs),
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
