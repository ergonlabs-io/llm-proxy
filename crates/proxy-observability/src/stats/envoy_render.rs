//! WP-23 increment 3 — renders a [`Registry`] into Envoy's flat `/stats`
//! text format, and nothing else: no Prometheus (increment 4), no OTLP
//! (WP-51). See `docs/wp-23-stats-design-brief.md`'s Decision 4 for the
//! naming rules this module implements.
//!
//! # Name rendering: one-to-many, and some render to nothing
//!
//! Each `(instrument, attrs)` pair the registry has resolved maps to
//! **zero or one** Envoy `/stats` name:
//!
//! | OTel | Envoy `/stats` |
//! |---|---|
//! | `upstream_rq` `{cluster, status_class}` | `cluster.<cluster>.upstream_rq_<class>` |
//! | `upstream_rq` `{cluster}` | `cluster.<cluster>.upstream_rq_total` |
//! | `upstream_rq_time` `{cluster}` | `cluster.<cluster>.upstream_rq_time` |
//! | anything else (e.g. `gen_ai.client.token.usage`) | *(no Envoy equivalent — omitted)* |
//!
//! [`envoy_counter_name`]/[`envoy_histogram_name`] are the only functions
//! that know this table; nothing else in this module inspects an
//! instrument's name. An instrument this table doesn't recognize is
//! **omitted from the output entirely**, never rendered under an invented
//! name — `/stats` is a compatibility surface, and a name Envoy never had
//! is not compatibility (design brief, Decision 4, point 2).
//!
//! This mapping is deliberately independent of any particular `Instrument`
//! const's declared `attribute_keys` — it only looks at the attribute keys
//! actually present on a given resolved handle. That is what lets the same
//! OTel instrument *name* (e.g. `"upstream_rq"`) expand into several Envoy
//! names depending on which attributes a given call site resolved it with
//! (design brief, Decision 4, point 1), without this module needing to
//! know how many attribute-shaped variants of `UPSTREAM_RQ` exist.
//!
//! # Output ordering
//!
//! [`render`] sorts by the **rendered** Envoy name, not by resolve order or
//! OTel instrument name, and produces byte-identical output for two calls
//! against unchanged registry state. Envoy's own `/stats` output is
//! sorted, and an unstable order would make every diff-based test against
//! this one worthless.
//!
//! # The histogram line format — UNVERIFIED, isolated in [`render_histogram_line`]
//!
//! Counters are unambiguous: `name: value`. Envoy's text `/stats`
//! histogram line is not, and **this module could not verify its exact
//! shape.** Before writing [`render_histogram_line`], this repo was
//! searched for an authoritative source, in the order the WP-23 increment-3
//! task asked for:
//!
//! 1. **Vendored protos** (`crates/proxy-api/vendor/envoy/**`): the closest
//!    thing is `envoy/config/metrics/v3/stats.proto`'s
//!    `HistogramBucketSettings`, which is where
//!    [`super::ENVOY_DEFAULT_HISTOGRAM_BUCKETS_MS`] is vendored from — but
//!    that message describes bucket *boundaries* for a **sink config**, not
//!    the admin `/stats` **text rendering**. The admin endpoint's text
//!    output has never been a proto message; it's C++ admin-handler
//!    formatting code, outside anything xDS vendors here.
//! 2. **`testing/corpus`**: no stats fixtures of any kind (searched for
//!    `histogram` and for the literal `P0(`; no hits).
//! 3. **`testing/diffrig`**: runs a real Envoy (v1.38.0, docker-gated), but
//!    its comparisons are all against **config parsing** output
//!    (`configs/*.yaml` diffed against Envoy's own parsed config), never
//!    against the admin surface. No `/stats` output has ever been captured
//!    into this repo, in `testing/diffrig` or anywhere else (searched
//!    repo-wide for `P0(`; no hits).
//! 4. **Any other recorded Envoy output**: none found.
//!
//! **No authoritative reference exists in this repo**, and this module does
//! not invent one by asserting a format from memory either.
//! [`render_histogram_line`] implements a best-effort shape —
//! `P<percentile>(<a>,<b>)` pairs, one per
//! [`ENVOY_STATS_TEXT_PERCENTILES`], each pair nominally
//! `(interval, cumulative)` — but that shape is a recollection, not a
//! confirmed fact, and three things about it are recorded here so a future
//! reader does not have to rediscover them:
//!
//! 1. **The percentile *set* is a clearly-named constant**
//!    ([`ENVOY_STATS_TEXT_PERCENTILES`]), not inlined, so it can be
//!    corrected in one place if it turns out wrong.
//! 2. **The whole line format lives in one named function.** Nothing else
//!    in this module, or in [`render`], knows or assumes anything about a
//!    histogram's rendered shape — an unverified format spread through the
//!    renderer would be a defect that looks right in every test written
//!    against it and fails against real tooling; isolating it here is the
//!    mitigation.
//! 3. Because [`Registry`] has no periodic-flush concept (one running,
//!    cumulative accumulation, not a windowed "since the last flush"
//!    figure), the two numbers in each `P<n>(a,b)` pair are currently
//!    **the same computed percentile value** — a second, deliberate
//!    simplification layered on top of the already-unverified pair format
//!    itself, recorded here rather than silently guessed at.
//!
//! **Nothing in this file proves this format correct.** WP-23 increment
//! 4's Grafana-dashboard conformance test is what will actually exercise
//! real tooling against this output; until that lands, treat this as a
//! labelled, isolated guess, not a fact.

use super::{HistogramHandle, Instrument, Registry};

/// Percentiles Envoy's `/stats` text endpoint is believed to report per
/// histogram, in rendering order. **Part of what this module could not
/// verify** — see the module doc's "UNVERIFIED" section. If a future
/// increment confirms a different set (or drops the `(a,b)` pairing
/// entirely), this is the one place that needs to change.
const ENVOY_STATS_TEXT_PERCENTILES: [(&str, f64); 10] = [
    ("P0", 0.0),
    ("P25", 25.0),
    ("P50", 50.0),
    ("P75", 75.0),
    ("P90", 90.0),
    ("P95", 95.0),
    ("P99", 99.0),
    ("P99.5", 99.5),
    ("P99.9", 99.9),
    ("P100", 100.0),
];

/// Renders `registry`'s current state into Envoy's flat `/stats` text
/// format: `name: value` for every counter/up-down-counter that has an
/// Envoy name (see the module doc's table), and a percentile line (see
/// [`render_histogram_line`]) for every histogram that does — one line per
/// stat, each `\n`-terminated, sorted by rendered name. Instruments with no
/// Envoy equivalent (e.g. `gen_ai.client.token.usage`) contribute no line
/// at all.
///
/// **Reads only.** This walks already-resolved handles and sums
/// already-stored atomics via [`Registry::counters`]/[`Registry::histograms`]/
/// [`Registry::percentile`] — no I/O, no blocking, safe to call from an
/// admin request handler on the control runtime (see
/// `proxy-admin/src/server.rs`'s `/stats` route).
pub fn render(registry: &Registry) -> String {
    let mut lines: Vec<(String, String)> = Vec::new();

    for (instrument, attrs, value) in registry.counters() {
        if let Some(name) = envoy_counter_name(instrument, attrs) {
            lines.push((name, value.to_string()));
        }
    }
    for (handle, instrument, attrs) in registry.histograms() {
        if let Some(name) = envoy_histogram_name(instrument, attrs) {
            lines.push((name, render_histogram_line(registry, handle)));
        }
    }

    // Rule 3 (module doc): sort by the RENDERED name, not resolve order —
    // Envoy's own /stats output is sorted, and an unstable order makes
    // every diff-based test against this function worthless.
    lines.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = String::new();
    for (name, value) in lines {
        out.push_str(&name);
        out.push_str(": ");
        out.push_str(&value);
        out.push('\n');
    }
    out
}

/// Looks up `key` in `attrs`. `Registry` happens to store attrs sorted by
/// key internally, but this module doesn't rely on that — it just searches.
fn attr<'a>(attrs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Maps one resolved counter/up-down-counter `(instrument, attrs)` pair to
/// its Envoy `/stats` name, or `None` if this instrument has no Envoy
/// equivalent — see the module doc's table. Depends only on
/// `instrument.name` and the attribute keys actually present in `attrs`,
/// never on any particular `Instrument` const's declared `attribute_keys`
/// — see the module doc for why that split matters.
fn envoy_counter_name(instrument: &Instrument, attrs: &[(String, String)]) -> Option<String> {
    match instrument.name {
        "upstream_rq" => {
            let cluster = attr(attrs, "cluster")?;
            match attr(attrs, "status_class") {
                Some(class) => Some(format!("cluster.{cluster}.upstream_rq_{class}")),
                None => Some(format!("cluster.{cluster}.upstream_rq_total")),
            }
        }
        // Everything else (gen_ai.*, and any future counter this table
        // hasn't been taught about yet) has no Envoy /stats equivalent —
        // omitted, not invented. See the module doc's Rule 2.
        _ => None,
    }
}

/// The histogram counterpart of [`envoy_counter_name`].
fn envoy_histogram_name(instrument: &Instrument, attrs: &[(String, String)]) -> Option<String> {
    match instrument.name {
        "upstream_rq_time" => {
            let cluster = attr(attrs, "cluster")?;
            Some(format!("cluster.{cluster}.upstream_rq_time"))
        }
        _ => None,
    }
}

/// Renders one histogram handle's `/stats` text line body (everything
/// after `"name: "`). **UNVERIFIED format — read the module doc before
/// trusting this function.** Isolated here, and only here, so correcting
/// it later (once increment 4's Grafana conformance test has actually
/// exercised real tooling against it) touches exactly one function.
fn render_histogram_line(registry: &Registry, handle: HistogramHandle) -> String {
    ENVOY_STATS_TEXT_PERCENTILES
        .iter()
        .map(|(label, p)| {
            // Rendered as (value, value) -- see the module doc's point 3:
            // this registry has no separate "interval since last flush"
            // figure, only the cumulative one.
            let value = registry.percentile(handle, *p);
            format!("{label}({value},{value})")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{instruments, InstrumentKind, WorkerId};

    // ---- 1: a counter renders as `name: value` under its Envoy name ------

    #[test]
    fn counter_renders_as_name_colon_value() {
        let mut registry = Registry::new(1);
        let h = registry.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        registry.incr(WorkerId(0), h, 5);

        let output = render(&registry);
        assert_eq!(output, "cluster.openai.upstream_rq_total: 5\n");
    }

    // ---- 2: attribute expansion produces one-to-many Envoy names ----------

    #[test]
    fn attribute_expansion_produces_one_to_many_envoy_names() {
        // The production UPSTREAM_RQ const (stats.rs) only carries
        // `cluster` today (no call site resolves it with `status_class`
        // yet — that's increment 5's job). Rendering only depends on
        // instrument.name and the attrs actually present on a handle (see
        // this module's doc), so a locally-defined instrument sharing the
        // same OTel name is enough to exercise the status_class expansion
        // rule without touching stats.rs's `instruments` module.
        static UPSTREAM_RQ_BY_CLASS: Instrument = Instrument {
            name: "upstream_rq",
            kind: InstrumentKind::Counter,
            unit: "{request}",
            attribute_keys: &["cluster", "status_class"],
            buckets: None,
        };

        let mut registry = Registry::new(1);
        let ok = registry.resolve(
            &UPSTREAM_RQ_BY_CLASS,
            &[("cluster", "x"), ("status_class", "2xx")],
        );
        let err = registry.resolve(
            &UPSTREAM_RQ_BY_CLASS,
            &[("cluster", "x"), ("status_class", "5xx")],
        );
        registry.incr(WorkerId(0), ok, 3);
        registry.incr(WorkerId(0), err, 1);

        let output = render(&registry);
        assert!(
            output.contains("cluster.x.upstream_rq_2xx: 3\n"),
            "output: {output}"
        );
        assert!(
            output.contains("cluster.x.upstream_rq_5xx: 1\n"),
            "output: {output}"
        );
    }

    // ---- 3: an instrument with no Envoy template is absent -----------------

    #[test]
    fn instrument_with_no_envoy_template_is_absent() {
        let mut registry = Registry::new(1);
        let h = registry.resolve(
            &instruments::GEN_AI_CLIENT_TOKEN_USAGE,
            &[("provider", "openai"), ("type", "input")],
        );
        registry.incr(WorkerId(0), h, 42);

        let output = render(&registry);
        assert!(
            !output.contains("gen_ai"),
            "gen_ai.* has no Envoy /stats equivalent and must be omitted entirely, got: \
             {output:?}"
        );
        assert_eq!(
            output, "",
            "nothing else was resolved, so absence must mean an empty render"
        );
    }

    // ---- 4: output is sorted and stable across repeated renders -----------

    #[test]
    fn output_is_sorted_and_stable_across_repeated_renders() {
        let mut registry = Registry::new(1);
        let zeta = registry.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "zeta")]);
        let alpha = registry.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "alpha")]);
        registry.incr(WorkerId(0), zeta, 1);
        registry.incr(WorkerId(0), alpha, 1);

        let first = render(&registry);
        let second = render(&registry);
        assert_eq!(
            first, second,
            "rendering identical state twice must produce identical output"
        );

        let alpha_pos = first.find("cluster.alpha").expect("alpha line present");
        let zeta_pos = first.find("cluster.zeta").expect("zeta line present");
        assert!(
            alpha_pos < zeta_pos,
            "output must be sorted by rendered name, got: {first}"
        );
    }

    // ---- 5: the histogram line, in its own focused test --------------------

    #[test]
    fn histogram_line_renders_the_chosen_unverified_format() {
        let mut registry = Registry::new(1);
        let h = registry.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
        registry.observe(WorkerId(0), h, 7.0);
        registry.observe(WorkerId(0), h, 800.0);

        let line = render_histogram_line(&registry, h);

        // Structure only -- see the module doc for why the exact numbers
        // are not, and cannot yet be, asserted against any external
        // authority.
        for (label, _) in ENVOY_STATS_TEXT_PERCENTILES {
            assert!(
                line.contains(&format!("{label}(")),
                "missing {label} in histogram line: {line}"
            );
        }
        assert_eq!(
            line.matches('(').count(),
            ENVOY_STATS_TEXT_PERCENTILES.len(),
            "exactly one (a,b) pair per percentile: {line}"
        );

        // Wired end to end through render() too, under its Envoy name.
        let output = render(&registry);
        assert!(
            output.starts_with("cluster.x.upstream_rq_time: "),
            "output: {output}"
        );
    }

    // ---- 8: rendered values are summed across workers, not one shard ------

    /// The ADR-0005 trap, one layer out from `stats.rs`'s own coverage of it:
    /// a renderer that reached for a single shard instead of
    /// `Registry::counters`'s already-summed value would pass every test
    /// above this one.
    #[test]
    fn rendered_value_is_summed_across_workers_not_a_single_shard() {
        let mut registry = Registry::new(2);
        let h = registry.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        registry.incr(WorkerId(0), h, 10);
        registry.incr(WorkerId(1), h, 25);

        let output = render(&registry);
        assert!(
            output.contains("cluster.openai.upstream_rq_total: 35\n"),
            "must render the SUM (35), not one worker's figure (10 or 25): {output}"
        );
        assert!(
            !output.contains(": 10\n"),
            "must not be worker 0's figure alone"
        );
        assert!(
            !output.contains(": 25\n"),
            "must not be worker 1's figure alone"
        );
    }
}
