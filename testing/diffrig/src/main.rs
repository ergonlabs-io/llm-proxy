//! Differential test rig (WP-26): compares llm-proxy against the pinned real
//! Envoy image.
//!
//! **Landed (WP-26 chunk B):** `config-validate-diff` — the config-loading
//! differential: runs a curated set of Envoy bootstrap configs
//! (`testing/diffrig/configs/`) through both the real Envoy validator (in a
//! throwaway docker container, `envoyproxy/envoy:v1.38.0` — see
//! `config_diff::ENVOY_IMAGE`) and llm-proxy's own `--mode validate`, and
//! reports where they agree/diverge (`config_diff` module).
//!
//! **Deferred:** the full HTTP traffic-replay topology (docker-compose,
//! scriptable upstreams driving both proxies side by side, response/access-log
//! diffing — the scenario format already parsed by `scenario.rs`) waits on
//! WP-10 landing llm-proxy's HTTP data plane, plus an llm-proxy Docker image
//! to run it in-topology. llm-proxy today only does config-loading plus an L4
//! `tcp_proxy`/TLS data plane (no HTTP), so there is nothing yet to replay
//! requests against.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use diffrig::config_diff::{render_config_diff_report, run_config_diff, Verdict, ENVOY_IMAGE};

#[derive(Parser)]
#[command(name = "diffrig", about = "WP-26 differential test rig")]
struct Args {
    #[command(subcommand)]
    command: DiffrigCommand,
}

#[derive(Subcommand)]
enum DiffrigCommand {
    /// Run the config-loading differential: real Envoy vs. llm-proxy
    /// `--mode validate` over every config in `configs-dir`.
    ConfigValidateDiff {
        /// Directory of bootstrap configs to diff (default:
        /// `testing/diffrig/configs`).
        #[arg(long = "configs-dir", value_name = "DIR")]
        configs_dir: Option<PathBuf>,

        /// Envoy image to validate against (default: the pinned
        /// `config_diff::ENVOY_IMAGE`).
        #[arg(long = "envoy-image", value_name = "IMAGE")]
        envoy_image: Option<String>,

        /// Path to the `llm-proxy` binary (default: found next to this
        /// binary in the cargo target dir).
        #[arg(long = "llm-proxy-bin", value_name = "PATH")]
        llm_proxy_bin: Option<PathBuf>,

        /// Where to write the markdown report (default:
        /// `testing/diffrig/config-diff-report.md`).
        #[arg(long = "report-path", value_name = "PATH")]
        report_path: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();
    match args.command {
        DiffrigCommand::ConfigValidateDiff {
            configs_dir,
            envoy_image,
            llm_proxy_bin,
            report_path,
        } => run_config_validate_diff(configs_dir, envoy_image, llm_proxy_bin, report_path),
    }
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn default_configs_dir() -> PathBuf {
    manifest_dir().join("configs")
}

fn default_report_path() -> PathBuf {
    manifest_dir().join("config-diff-report.md")
}

/// The `llm-proxy` binary lives alongside every other workspace binary in the
/// cargo target dir — the same directory this `diffrig` binary itself runs
/// from (`cargo run -p diffrig` and `cargo run -p proxy` both build into
/// `target/<profile>/`). Rust note: `current_exe` can fail (e.g. the exe was
/// deleted after exec on some platforms), so this is fallible rather than a
/// hard assumption.
fn default_llm_proxy_bin() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| {
        anyhow::anyhow!("diffrig binary path {} has no parent dir", exe.display())
    })?;
    let bin_name = if cfg!(windows) {
        "llm-proxy.exe"
    } else {
        "llm-proxy"
    };
    Ok(dir.join(bin_name))
}

fn run_config_validate_diff(
    configs_dir: Option<PathBuf>,
    envoy_image: Option<String>,
    llm_proxy_bin: Option<PathBuf>,
    report_path: Option<PathBuf>,
) -> anyhow::Result<ExitCode> {
    let configs_dir = configs_dir.unwrap_or_else(default_configs_dir);
    let envoy_image = envoy_image.unwrap_or_else(|| ENVOY_IMAGE.to_string());
    let llm_proxy_bin = match llm_proxy_bin {
        Some(path) => path,
        None => default_llm_proxy_bin()?,
    };
    let report_path = report_path.unwrap_or_else(default_report_path);

    ensure_binary_exists(&llm_proxy_bin)?;

    let diffs = run_config_diff(&configs_dir, &envoy_image, &llm_proxy_bin)?;
    let report = render_config_diff_report(&diffs);
    std::fs::write(&report_path, &report)?;

    let bugs = diffs
        .iter()
        .filter(|d| d.verdict == Verdict::BugWeAccept)
        .count();
    let gaps = diffs
        .iter()
        .filter(|d| d.verdict == Verdict::GapWeReject)
        .count();
    println!(
        "config-validate-diff: {} configs, {} gap-we-reject, {} BUG-we-accept \
         (report: {})",
        diffs.len(),
        gaps,
        bugs,
        report_path.display()
    );

    // A BugWeAccept is a real defect surfacing (we are lenient where Envoy
    // is strict) — nonzero exit so CI/a human notices; GapWeReject is
    // expected data about compat gaps, so it exits 0.
    if bugs > 0 {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn ensure_binary_exists(path: &Path) -> anyhow::Result<()> {
    if !path.is_file() {
        anyhow::bail!(
            "llm-proxy binary not found at {} — build it first with `cargo build -p proxy`, \
             or pass --llm-proxy-bin",
            path.display()
        );
    }
    Ok(())
}
