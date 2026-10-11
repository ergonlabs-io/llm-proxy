//! Grafana-dashboard conformance test.
//!
//! Status: **provisional — not yet checked against Envoy's own dashboard.**
//!
//! # What was actually checked before writing this file
//!
//! The design brief's acceptance criterion is "Envoy's own Grafana dashboard
//! queries populating against our Prometheus output". Before writing a
//! fixture, this repo and `envoyproxy/envoy` were both searched for one:
//!
//! 1. **This repo** (`testing/`, `examples/`, anything vendored under
//!    `crates/proxy-api/vendor/`): no Grafana JSON, no PromQL, nothing
//!    dashboard-shaped anywhere.
//! 2. **`envoyproxy/envoy` itself**, fetched directly (network available,
//!    checked 2026-08-09): the repository's **full recursive git tree** at
//!    `main` (commit `d57118924c85fcaa07758dddbb9c5da4e89045af`) was pulled
//!    via GitHub's Git Trees API with `recursive=1` and confirmed
//!    **not truncated** (`"truncated": false` — i.e. this really is every
//!    path in the repo, not a partial listing), then searched case-
//!    insensitively for `grafana` and `dashboard`. **Zero matches.** Envoy's
//!    own repository does not vendor a Grafana dashboard anywhere.
//! 3. **grafana.com's public dashboard catalog** (not the envoyproxy/envoy
//!    repository the brief pointed at, so checked only as a fallback): a
//!    dashboard titled "Envoy Clusters" exists there (catalog id `11021`,
//!    downloadable, and it does download successfully). Its own metadata
//!    (`orgName: "mischenkovn"`) shows it is a **third-party community
//!    contribution**, not something published by the Envoy project. Per this
//!    the brief's own instructions — "do NOT invent a dashboard and do NOT fake the
//!    test" — an unverified third party's dashboard is treated the same as
//!    having found nothing: it is not "Envoy's own dashboard", and building
//!    a conformance test against it would risk exactly the kind of
//!    unverified artifact this project has been bitten by before.
//!
//! **Conclusion: no obtainable artifact satisfies the brief's actual
//! acceptance criterion.** This file is the honest fallback the design
//! brief names for exactly this outcome.
//!
//! # What this file asserts instead
//!
//! A small, explicitly-listed set of Prometheus metric family names, taken
//! directly from the instruments [`crate::stats::instruments`] defines
//! today — nothing invented, nothing borrowed from an unverified source. It
//! proves the renderer can produce a scrapeable series for every instrument
//! this registry actually has, which is necessary but **not sufficient**
//! for the brief's real bar. **Do not extend this file as a substitute for
//! the real conformance test** — replace it outright once an authoritative
//! Envoy dashboard (or its extracted PromQL metric list) is obtained, and
//! delete this doc comment's caveats along with it.

use super::prometheus_render::render;
use super::{instruments, StatsControl, WorkerId};

/// One Prometheus metric family name per instrument `crate::stats::instruments`
/// defines, in `envoy_<sanitized instrument name>` form (see
/// `prometheus_render`'s module doc for the naming rule). Update this list
/// whenever an instrument is added or renamed — this test only proves the
/// renderer covers *this* list, not "every instrument that will ever exist".
const EXPECTED_METRIC_FAMILIES: &[&str] = &[
    "envoy_upstream_rq",
    "envoy_downstream_cx_total",
    "envoy_llm_client_token_usage",
    "envoy_upstream_rq_time",
];

/// Resolves and records one measurement against every instrument named in
/// [`EXPECTED_METRIC_FAMILIES`], then asserts the rendered Prometheus output
/// contains each family name — failing with the list of whichever are
/// missing, per the brief.
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
