//! Config-corpus scorecard (WP-27): feeds every fixture under
//! `testing/corpus/fixtures/` through `proxy_config`'s real loader pipeline
//! (`lib.rs`) and classifies each as fully-supported / rejected-with-path /
//! parse-error. Emits `corpus-report.md` — the project's headline
//! compatibility metric.
//!
//! A rejected fixture is *data*, not a tool failure: this binary only exits
//! nonzero on I/O/internal errors (bad fixtures dir, can't write the report).
//!
//! `fixtures/envoy-examples/` (WP-27 chunk B) harvests real static bootstraps
//! from the pinned `envoyproxy/envoy` release tag — see its `SOURCES.md` for
//! provenance. TODO(WP-27 next chunk): also harvest Envoy Gateway translator
//! output, istioctl dumps, and Gloo/Contour examples into further
//! `fixtures/<source>/` directories; CI wiring to post the report as a PR
//! comment.

use std::path::PathBuf;

use corpus::{render_report, run_scorecard, summary_line};

fn main() -> anyhow::Result<()> {
    // Rust note: `env::args()` skips arg0; a single optional positional arg
    // overrides the default report path so tests/CI can point it elsewhere.
    let report_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(default_report_path);
    let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");

    let results = run_scorecard(&fixtures_dir)?;
    let report = render_report(&results);
    std::fs::write(&report_path, report)?;

    println!("{}", summary_line(&results));
    println!("report written to {}", report_path.display());
    Ok(())
}

fn default_report_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus-report.md")
}
