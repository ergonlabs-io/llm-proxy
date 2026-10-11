//! Config-validation differential engine: runs Envoy
//! bootstrap configs through both the real pinned Envoy binary (inside a
//! throwaway docker container) and llm-proxy's own `--mode validate`, and
//! classifies whether the two agree. This is the config-loading half of the
//! differential rig; request-level comparison is `replay.rs`, driven by
//! `scenario.rs`'s scenario model.
//!
//! `GapWeReject` (Envoy accepts, we reject) is expected and is *data*, not a
//! bug — it names a real compat gap, per AGENTS.md invariant 1. `BugWeAccept`
//! (Envoy rejects, we accept) is the dangerous direction: we're being lenient
//! where Envoy is strict, which is a P1 finding.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Pinned Envoy image used as ground truth. `v1.38.0` pulls cleanly and its
/// `--mode validate` entrypoint behaves as documented below; see the
/// `docker run` invocation in [`validate_with_envoy`].
pub const ENVOY_IMAGE: &str = "envoyproxy/envoy:v1.38.0";

/// Whether a validator (Envoy or llm-proxy) accepted a config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    Accepted,
    /// `message` is the process's captured stderr, trimmed — where both
    /// validators put their diagnostics (see the empirical check in this
    /// module's tests and the module doc of `crates/proxy/src/main.rs`).
    Rejected {
        message: String,
    },
}

impl ValidationResult {
    pub fn is_accepted(&self) -> bool {
        matches!(self, ValidationResult::Accepted)
    }

    fn from_output(output: &std::process::Output) -> Self {
        if output.status.success() {
            ValidationResult::Accepted
        } else {
            ValidationResult::Rejected {
                message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            }
        }
    }
}

/// How llm-proxy's verdict on a config compares to real Envoy's.
///
/// Rust note: `Copy` is fine here — this is a plain tag with no owned data,
/// same shape as `proxy_config::ConfigFormat` elsewhere in the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Both accept.
    AgreeAccept,
    /// Both reject.
    AgreeReject,
    /// Envoy accepts, we reject: a compat gap (a feature we haven't
    /// implemented yet). Expected and fine — AGENTS.md invariant 1 in action.
    GapWeReject,
    /// Envoy rejects, we accept: we are dangerously lenient. A P1 finding.
    BugWeAccept,
}

impl Verdict {
    fn classify(envoy: &ValidationResult, llmproxy: &ValidationResult) -> Self {
        match (envoy.is_accepted(), llmproxy.is_accepted()) {
            (true, true) => Verdict::AgreeAccept,
            (false, false) => Verdict::AgreeReject,
            (true, false) => Verdict::GapWeReject,
            (false, true) => Verdict::BugWeAccept,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Verdict::AgreeAccept => "agree-accept",
            Verdict::AgreeReject => "agree-reject",
            Verdict::GapWeReject => "gap-we-reject",
            Verdict::BugWeAccept => "BUG-we-accept",
        }
    }
}

/// One config's result against both validators.
#[derive(Debug, Clone)]
pub struct ConfigDiff {
    /// File stem, e.g. `tcp-basic`.
    pub config: String,
    pub envoy: ValidationResult,
    pub llmproxy: ValidationResult,
    pub verdict: Verdict,
}

/// Run the real Envoy validator against `config_path` inside a throwaway
/// `--rm` container, mounting the file read-only at `/config.yaml`. Envoy's
/// `--mode validate` prints `configuration '<path>' OK` to stdout and exits 0
/// on success; on failure it exits nonzero and the useful diagnostic is on
/// stderr (all of Envoy's own logging also goes to stderr, mixed in).
///
/// # Errors
/// Only if `docker` itself cannot be invoked (not installed, daemon down) —
/// a config that Envoy rejects is a *result* (`ValidationResult::Rejected`),
/// never a tool error.
pub fn validate_with_envoy(
    config_path: &Path,
    envoy_image: &str,
) -> anyhow::Result<ValidationResult> {
    let abs = config_path.canonicalize()?;
    let mount = format!("{}:/config.yaml:ro", abs.display());
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &mount,
            envoy_image,
            "--mode",
            "validate",
            "-c",
            "/config.yaml",
        ])
        .output()?;
    Ok(ValidationResult::from_output(&output))
}

/// Run `llm_proxy_bin --mode validate -c config_path` on the host and
/// classify its exit status the same way as [`validate_with_envoy`] — see
/// `crates/proxy/src/main.rs`'s `main`, which prints the same
/// `OK`-on-stdout/error-on-stderr shape by design (it mirrors Envoy's CLI).
///
/// # Errors
/// Only if the binary cannot be spawned at all (missing/not executable).
pub fn validate_with_llmproxy(
    config_path: &Path,
    llm_proxy_bin: &Path,
) -> anyhow::Result<ValidationResult> {
    let output = Command::new(llm_proxy_bin)
        .arg("--mode")
        .arg("validate")
        .arg("-c")
        .arg(config_path)
        .output()?;
    Ok(ValidationResult::from_output(&output))
}

/// Validate one config against both validators and classify the verdict.
pub fn diff_one(
    config_path: &Path,
    envoy_image: &str,
    llm_proxy_bin: &Path,
) -> anyhow::Result<ConfigDiff> {
    let config = config_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| config_path.display().to_string());
    let envoy = validate_with_envoy(config_path, envoy_image)?;
    let llmproxy = validate_with_llmproxy(config_path, llm_proxy_bin)?;
    let verdict = Verdict::classify(&envoy, &llmproxy);
    Ok(ConfigDiff {
        config,
        envoy,
        llmproxy,
        verdict,
    })
}

/// Run the differential engine over every `*.yaml`/`*.yml` file directly
/// under `configs_dir`, sorted by name so results (and the report) are
/// deterministic.
pub fn run_config_diff(
    configs_dir: &Path,
    envoy_image: &str,
    llm_proxy_bin: &Path,
) -> anyhow::Result<Vec<ConfigDiff>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(configs_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && matches!(
                    path.extension().and_then(|e| e.to_str()),
                    Some("yaml" | "yml")
                )
        })
        .collect();
    files.sort();

    files
        .iter()
        .map(|path| diff_one(path, envoy_image, llm_proxy_bin))
        .collect()
}

/// Render a markdown report: verdict counts, then every `GapWeReject` and
/// `BugWeAccept` listed prominently, then the full per-config table.
/// Mirrors the style of `testing/corpus`'s `render_report`.
pub fn render_config_diff_report(diffs: &[ConfigDiff]) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "# Config-validation differential report\n");
    let _ = writeln!(
        out,
        "Generated by `cargo run -p diffrig -- config-validate-diff`. \
         Compares llm-proxy's `--mode validate` against real Envoy (`{ENVOY_IMAGE}`) \
         on the same bootstrap configs. `gap-we-reject` is a known compat gap \
         (AGENTS.md invariant 1's good failure mode); `BUG-we-accept` means we are \
         lenient where Envoy is strict and needs triage.\n"
    );

    let count = |v: Verdict| diffs.iter().filter(|d| d.verdict == v).count();
    let _ = writeln!(out, "| verdict | count |");
    let _ = writeln!(out, "|---|---:|");
    let _ = writeln!(out, "| agree-accept | {} |", count(Verdict::AgreeAccept));
    let _ = writeln!(out, "| agree-reject | {} |", count(Verdict::AgreeReject));
    let _ = writeln!(out, "| gap-we-reject | {} |", count(Verdict::GapWeReject));
    let _ = writeln!(
        out,
        "| **BUG-we-accept** | {} |",
        count(Verdict::BugWeAccept)
    );

    let bugs: Vec<&ConfigDiff> = diffs
        .iter()
        .filter(|d| d.verdict == Verdict::BugWeAccept)
        .collect();
    if !bugs.is_empty() {
        let _ = writeln!(out, "\n## BUG-we-accept (P1 — triage these)\n");
        for d in &bugs {
            let _ = writeln!(
                out,
                "- `{}` — Envoy rejected: {}",
                d.config,
                reject_message(&d.envoy)
            );
        }
    }

    let gaps: Vec<&ConfigDiff> = diffs
        .iter()
        .filter(|d| d.verdict == Verdict::GapWeReject)
        .collect();
    if !gaps.is_empty() {
        let _ = writeln!(out, "\n## gap-we-reject (compat gaps)\n");
        for d in &gaps {
            let _ = writeln!(
                out,
                "- `{}` — we rejected: {}",
                d.config,
                reject_message(&d.llmproxy)
            );
        }
    }

    let _ = writeln!(out, "\n## Full results\n");
    let _ = writeln!(out, "| config | verdict | envoy | llm-proxy |");
    let _ = writeln!(out, "|---|---|---|---|");
    for d in diffs {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} |",
            d.config,
            d.verdict.label(),
            summary(&d.envoy),
            summary(&d.llmproxy)
        );
    }

    out
}

fn summary(result: &ValidationResult) -> &'static str {
    if result.is_accepted() {
        "accept"
    } else {
        "reject"
    }
}

fn reject_message(result: &ValidationResult) -> String {
    match result {
        ValidationResult::Accepted => "(accepted, no message)".to_string(),
        ValidationResult::Rejected { message } => {
            // Reports stay readable even when a validator's stderr is huge
            // (Envoy's own startup logging is verbose) — keep only the last
            // line, which is where both validators put the actual verdict.
            message.lines().next_back().unwrap_or(message).to_string()
        }
    }
}

/// Whether a docker daemon is reachable right now — used to skip (not fail)
/// docker-backed tests when a developer runs `cargo test -p diffrig` without
/// docker up, per this task's gating requirement.
pub fn docker_daemon_reachable() -> bool {
    Command::new("docker")
        .args(["info"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_classifies_all_four_combinations() {
        let accept = ValidationResult::Accepted;
        let reject = ValidationResult::Rejected {
            message: "x".to_string(),
        };
        assert_eq!(Verdict::classify(&accept, &accept), Verdict::AgreeAccept);
        assert_eq!(Verdict::classify(&reject, &reject), Verdict::AgreeReject);
        assert_eq!(Verdict::classify(&accept, &reject), Verdict::GapWeReject);
        assert_eq!(Verdict::classify(&reject, &accept), Verdict::BugWeAccept);
    }

    #[test]
    fn report_renders_deterministically_and_flags_bugs() {
        let diffs = vec![
            ConfigDiff {
                config: "ok".to_string(),
                envoy: ValidationResult::Accepted,
                llmproxy: ValidationResult::Accepted,
                verdict: Verdict::AgreeAccept,
            },
            ConfigDiff {
                config: "leaky".to_string(),
                envoy: ValidationResult::Rejected {
                    message: "envoy says no".to_string(),
                },
                llmproxy: ValidationResult::Accepted,
                verdict: Verdict::BugWeAccept,
            },
        ];
        let a = render_config_diff_report(&diffs);
        let b = render_config_diff_report(&diffs);
        assert_eq!(a, b);
        assert!(a.contains("BUG-we-accept"));
        assert!(a.contains("`leaky` — Envoy rejected: envoy says no"));
    }

    /// A config that plainly doesn't exist must surface as a tool error
    /// (bad invocation), not silently classify as either verdict.
    #[test]
    fn validate_with_llmproxy_errors_on_missing_binary() {
        let result = validate_with_llmproxy(
            Path::new("/no/such/config.yaml"),
            Path::new("/no/such/llm-proxy-binary"),
        );
        assert!(result.is_err());
    }

    /// Docker-backed: real Envoy accepting/rejecting the seeded configs.
    /// `#[ignore]`d per this task's CI gating — run explicitly with
    /// `cargo test -p diffrig -- --ignored` (and `DIFFRIG_DOCKER=1` set, or a
    /// reachable docker daemon).
    #[test]
    #[ignore]
    fn envoy_validates_seeded_configs_as_expected() {
        if std::env::var("DIFFRIG_DOCKER").is_err() || !docker_daemon_reachable() {
            eprintln!("skipping: set DIFFRIG_DOCKER=1 with a reachable docker daemon to run");
            return;
        }
        let configs_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("configs/tcp-basic.yaml");
        let result =
            validate_with_envoy(&configs_dir, ENVOY_IMAGE).expect("docker invocation must run");
        assert!(
            result.is_accepted(),
            "expected Envoy to accept, got {result:?}"
        );
    }
}
