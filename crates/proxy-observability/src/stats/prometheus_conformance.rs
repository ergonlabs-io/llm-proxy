//! Provisional Grafana-dashboard conformance check. It is **not** yet checked
//! against Envoy's own dashboard.
//!
//! As of 2026-08-09, neither this repo nor `envoyproxy/envoy` contained an
//! Envoy-published Grafana dashboard. A "Envoy Clusters" dashboard on
//! grafana.com is a third-party contribution, so it was not used.
//!
//! This file asserts that every instrument in [`crate::stats::instruments`]
//! renders a Prometheus series. That is necessary but not sufficient. Replace
//! it once an authoritative Envoy dashboard, or its PromQL metric list, is
//! available.

use super::prometheus_render::render;
use super::{instruments, StatsControl, WorkerId};

/// One family name per instrument in `crate::stats::instruments`, in
/// `envoy_<sanitized name>` form. Update this list when an instrument is added
/// or renamed. The test covers only this list.
const EXPECTED_METRIC_FAMILIES: &[&str] = &[
    "envoy_upstream_rq",
    "envoy_downstream_cx_total",
    "envoy_llm_client_token_usage",
    "envoy_upstream_rq_time",
];

/// Resolves and records one measurement against every instrument named in
/// [`EXPECTED_METRIC_FAMILIES`], then asserts the rendered Prometheus output
/// contains each family name, and lists any that are missing on failure.
#[test]
fn renderer_produces_a_series_for_every_known_instrument() {
    let control = StatsControl::new(1);
    let rq = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
    let cx = control.resolve(
        &instruments::DOWNSTREAM_CX_TOTAL,
        &[("listener", "ingress")],
    );
    let tokens = control.resolve(
        &instruments::LLM_CLIENT_TOKEN_USAGE,
        &[
            ("provider", "openai"),
            ("type", "input"),
            ("tenant", "acme"),
        ],
    );
    let latency =
        control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "openai")]);

    let registry = control.registry();
    registry.incr(WorkerId(0), rq, 1);
    registry.incr(WorkerId(0), cx, 1);
    registry.incr(WorkerId(0), tokens, 128);
    registry.observe(WorkerId(0), latency, 12.5);

    let output = render(&registry);

    let missing: Vec<&&str> = EXPECTED_METRIC_FAMILIES
        .iter()
        .filter(|family| !output.contains(*family))
        .collect();
    assert!(
        missing.is_empty(),
        "renderer failed to produce these expected metric families: {missing:?}\n\
         full output:\n{output}"
    );
}
