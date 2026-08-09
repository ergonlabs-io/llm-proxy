//! Scorecard core (WP-27): feeds fixture bytes through the *real* loader
//! pipeline (`proxy_config::parse_bootstrap` + `build_snapshot` — the same
//! entry points `llm-proxy --mode validate` uses, see `crates/proxy/src/main.rs`)
//! and classifies the result into one of three outcome classes.
//!
//! Classification is principled, not string-matching: it switches on
//! [`proxy_config::ConfigError`]'s variants, all of which carry a
//! `field_path` except [`proxy_config::ConfigError::Parse`] and
//! [`proxy_config::ConfigError::Io`] (which by construction fire *before*
//! any field-level walk — bad bytes/IO, not a bad field). See
//! [`Outcome::classify`] for the one place this mapping lives.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

/// One fixture's classification. `RejectedWithPath` is the *good* failure
/// mode (ground rule #2): it means we noticed a real gap and named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Loaded end-to-end into the IR.
    FullySupported,
    /// Strict-mode rejection naming a full dotted field path.
    RejectedWithPath { path: String, message: String },
    /// YAML/proto-shape failure before field-level analysis was possible.
    ParseError { message: String },
}

impl Outcome {
    /// Run the fixture bytes through the loader pipeline and classify the
    /// outcome. Fixtures are always YAML (Envoy bootstraps in this corpus
    /// are hand- or tool-authored, never `.pb`), and always strict — the
    /// scorecard measures ground-rule-#2 compliance, which permissive mode
    /// exists specifically to bypass.
    pub fn classify(bytes: &[u8]) -> Self {
        match parse_bootstrap(bytes, ConfigFormat::Yaml, StrictMode::Strict) {
            Err(err) => Self::from_error(err),
            Ok(loaded) => match build_snapshot(&loaded) {
                Ok(_) => Self::FullySupported,
                Err(err) => Self::from_error(err),
            },
        }
    }

    fn from_error(err: ConfigError) -> Self {
        // Rust note: `thiserror`'s `#[error(...)]` gives every variant a
        // `Display` impl; render it up front so the `match` below can move
        // the `field_path` fields out of `err` without also needing an
        // immutable borrow of the whole value at the same time.
        let message = err.to_string();
        match err {
            ConfigError::UnknownField { field_path }
            | ConfigError::UnsupportedField { field_path, .. }
            | ConfigError::InvalidValue { field_path, .. }
            | ConfigError::Validation { field_path, .. }
            | ConfigError::UnknownTypeUrl { field_path, .. }
            | ConfigError::Unimplemented { field_path, .. } => Self::RejectedWithPath {
                path: field_path,
                message,
            },
            // No field path exists: these fire before the field-level walk,
            // so they are parse failures for scorecard purposes, not
            // rejections.
            ConfigError::Parse(_) | ConfigError::Io { .. } => Self::ParseError { message },
        }
    }

    /// Short label used in the report table/detail list.
    pub fn label(&self) -> &'static str {
        match self {
            Self::FullySupported => "fully-supported",
            Self::RejectedWithPath { .. } => "rejected-with-path",
            Self::ParseError { .. } => "parse-error",
        }
    }
}

/// A fixture on disk, plus its classification.
#[derive(Debug, Clone)]
pub struct FixtureResult {
    /// Directory name under `fixtures/` the file came from (e.g. `local`).
    pub source: String,
    /// File stem (e.g. `tcp-proxy`).
    pub name: String,
    pub outcome: Outcome,
}

/// Walk `fixtures_dir` (one level of `<source>/<name>.yaml`) and classify
/// every fixture found. Returns results sorted by `(source, name)` so
/// reports are deterministic.
///
/// # Errors
/// Only on I/O failure reading the corpus directory itself — a fixture that
/// fails to load is a *result* (`Outcome::ParseError`/`RejectedWithPath`),
/// never a tool error.
pub fn run_scorecard(fixtures_dir: &Path) -> std::io::Result<Vec<FixtureResult>> {
    let mut results = Vec::new();
    let mut source_dirs: Vec<PathBuf> = fs::read_dir(fixtures_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    source_dirs.sort();

    for source_dir in source_dirs {
        let source = source_dir
            .file_name()
            .expect("read_dir entries always have a file name")
            .to_string_lossy()
            .into_owned();

        let mut fixture_files: Vec<PathBuf> = fs::read_dir(&source_dir)?
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
        fixture_files.sort();

        for path in fixture_files {
            let name = path
                .file_stem()
                .expect("filtered to files with a .yaml/.yml extension")
                .to_string_lossy()
                .into_owned();
            let bytes = fs::read(&path)?;
            let outcome = Outcome::classify(&bytes);
            results.push(FixtureResult {
                source: source.clone(),
                name,
                outcome,
            });
        }
    }

    Ok(results)
}

/// Per-source rollup for the summary table.
struct SourceTally {
    source: String,
    total: usize,
    supported: usize,
    rejected: usize,
    parse_error: usize,
}

impl SourceTally {
    fn support_pct(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            100.0 * self.supported as f64 / self.total as f64
        }
    }
}

/// Render `corpus-report.md`: a summary table per source, then a sorted
/// per-fixture detail list. Deterministic given deterministically-ordered
/// `results` (see [`run_scorecard`]).
pub fn render_report(results: &[FixtureResult]) -> String {
    let mut tallies: Vec<SourceTally> = Vec::new();
    for result in results {
        let tally = match tallies.iter_mut().find(|t| t.source == result.source) {
            Some(t) => t,
            None => {
                tallies.push(SourceTally {
                    source: result.source.clone(),
                    total: 0,
                    supported: 0,
                    rejected: 0,
                    parse_error: 0,
                });
                tallies.last_mut().expect("just pushed")
            }
        };
        tally.total += 1;
        match &result.outcome {
            Outcome::FullySupported => tally.supported += 1,
            Outcome::RejectedWithPath { .. } => tally.rejected += 1,
            Outcome::ParseError { .. } => tally.parse_error += 1,
        }
    }

    let mut out = String::new();
    let _ = writeln!(out, "# Config corpus scorecard\n");
    let _ = writeln!(
        out,
        "Generated by `cargo run -p corpus` (WP-27). Rejections that name a \
         field path are the *good* failure mode (ground rule #2) — they mean \
         a real gap was noticed and reported, not silently dropped.\n"
    );
    let _ = writeln!(
        out,
        "| source | total | supported | rejected | parse-error | support % |"
    );
    let _ = writeln!(out, "|---|---:|---:|---:|---:|---:|");
    for tally in &tallies {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {:.1}% |",
            tally.source,
            tally.total,
            tally.supported,
            tally.rejected,
            tally.parse_error,
            tally.support_pct()
        );
    }

    let _ = writeln!(out, "\n## Fixture detail\n");
    for result in results {
        match &result.outcome {
            Outcome::FullySupported => {
                let _ = writeln!(
                    out,
                    "- `{}/{}` — {}",
                    result.source,
                    result.name,
                    result.outcome.label()
                );
            }
            Outcome::RejectedWithPath { path, message } => {
                let _ = writeln!(
                    out,
                    "- `{}/{}` — {} at `{}`: {}",
                    result.source,
                    result.name,
                    result.outcome.label(),
                    path,
                    message
                );
            }
            Outcome::ParseError { message } => {
                let _ = writeln!(
                    out,
                    "- `{}/{}` — {}: {}",
                    result.source,
                    result.name,
                    result.outcome.label(),
                    message
                );
            }
        }
    }

    out
}

/// One-line summary printed to stdout by the binary.
pub fn summary_line(results: &[FixtureResult]) -> String {
    let total = results.len();
    let supported = results
        .iter()
        .filter(|r| r.outcome == Outcome::FullySupported)
        .count();
    let pct = if total == 0 {
        0.0
    } else {
        100.0 * supported as f64 / total as f64
    };
    format!("corpus scorecard: {supported}/{total} fixtures fully supported ({pct:.1}%)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
    }

    #[test]
    fn classifies_fully_supported() {
        let bytes = fs::read(fixtures_dir().join("local/tcp-proxy.yaml")).unwrap();
        assert_eq!(Outcome::classify(&bytes), Outcome::FullySupported);
    }

    #[test]
    fn classifies_rejected_with_path() {
        let bytes = fs::read(fixtures_dir().join("local/rejected-circuit-breakers.yaml")).unwrap();
        match Outcome::classify(&bytes) {
            Outcome::RejectedWithPath { path, .. } => {
                assert_eq!(
                    path,
                    "static_resources.clusters[0].circuit_breakers.per_host_thresholds"
                );
            }
            other => panic!("expected RejectedWithPath, got {other:?}"),
        }
    }

    #[test]
    fn classifies_parse_error() {
        let bytes = fs::read(fixtures_dir().join("local/malformed.yaml")).unwrap();
        match Outcome::classify(&bytes) {
            Outcome::ParseError { .. } => {}
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn scorecard_runs_over_seeded_fixtures() {
        let results = run_scorecard(&fixtures_dir()).unwrap();
        // Results are sorted by `(source, name)`, and `envoy-examples` sorts
        // before `local`, so the seeded `local/` fixtures are the last three
        // — restrict to them so this test doesn't churn every time the
        // harvested corpus grows.
        let local: Vec<_> = results.iter().filter(|r| r.source == "local").collect();
        assert_eq!(local.len(), 3);
        assert_eq!(local[0].name, "malformed");
        assert_eq!(local[1].name, "rejected-circuit-breakers");
        assert_eq!(local[2].name, "tcp-proxy");
    }

    /// WP-27 chunk B: the scorecard must discover the harvested
    /// `envoy-examples` source alongside `local`, and every fixture in it
    /// must classify as `FullySupported` or `RejectedWithPath` — real Envoy
    /// bootstraps should never hit `ParseError` (that class is reserved for
    /// malformed bytes, not unsupported-but-well-formed fields), since a
    /// `ParseError` there would suggest a loader bug rather than a
    /// documented compat gap.
    #[test]
    fn scorecard_discovers_harvested_envoy_examples() {
        let results = run_scorecard(&fixtures_dir()).unwrap();

        let local_count = results.iter().filter(|r| r.source == "local").count();
        assert_eq!(local_count, 3, "existing local/ fixtures must stay intact");

        let envoy_examples: Vec<_> = results
            .iter()
            .filter(|r| r.source == "envoy-examples")
            .collect();
        assert!(
            envoy_examples.len() >= 12,
            "expected a curated set of harvested Envoy bootstraps, got {}",
            envoy_examples.len()
        );

        for result in &envoy_examples {
            assert!(
                !matches!(result.outcome, Outcome::ParseError { .. }),
                "envoy-examples/{} unexpectedly hit ParseError: {:?} \
                 (real bootstraps should reject with a field path, not fail to parse)",
                result.name,
                result.outcome
            );
        }

        // Overall total grew beyond just the local/ seed fixtures.
        assert!(results.len() > local_count);
    }

    #[test]
    fn report_renders_deterministically() {
        let results = run_scorecard(&fixtures_dir()).unwrap();
        let a = render_report(&results);
        let b = render_report(&results);
        assert_eq!(a, b);
        assert!(a.contains("| local | 3 | 1 | 1 | 1 | 33.3% |"));
        assert!(a.contains("local/tcp-proxy` — fully-supported"));
        assert!(a.contains(
            "local/rejected-circuit-breakers` — rejected-with-path at \
             `static_resources.clusters[0].circuit_breakers.per_host_thresholds`"
        ));
        assert!(a.contains("local/malformed` — parse-error"));
    }
}
