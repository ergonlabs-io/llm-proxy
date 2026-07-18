//! Config-corpus scorecard (WP-27): feeds every harvested real-world Envoy config
//! (fixtures under `testing/corpus/fixtures/`) through `proxy_config::load_bootstrap`
//! and classifies each as fully-supported / rejected-with-path / parse-error.
//! Emits `corpus-report.md` — the project's headline compatibility metric.
//!
//! TODO(WP-27): fixture harvesting scripts (envoyproxy examples, Envoy Gateway
//! translator output, istioctl dumps), report generation, CI integration.

fn main() -> anyhow::Result<()> {
    anyhow::bail!("corpus scaffold: implementation is WP-27 (see IMPLEMENTATION_PLAN.md)")
}
