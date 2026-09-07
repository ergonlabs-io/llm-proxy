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
//! | anything else (e.g. `llm.client.token.usage`) | *(no Envoy equivalent — omitted)* |
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
//! # The histogram line format — CONFIRMED against Envoy's own source, 2026-08-09
//!
//! Increment 3 shipped this as an unverified recollection (`P<n>(a,b)`
//! space-separated pairs) because nothing in this repo could confirm or
//! refute it. Increment 4's research had network access to
//! `envoyproxy/envoy` itself, so this is now settled rather than guessed:
//! fetched directly from `source/common/stats/histogram_impl.cc` and
//! `source/server/admin/stats_render.cc` at commit
//! `d57118924c85fcaa07758dddbb9c5da4e89045af` (`main`, fetched 2026-08-09).
//!
//! `StatsTextRender::generate(..., const Stats::ParentHistogram&)` (in
//! `stats_render.cc`) is the function that decides what a plain `/stats`
//! request (no `histogram_buckets` query parameter — which this proxy does
//! not implement either, so this is the only mode that applies here) prints
//! for a histogram:
//!
//! ```text
//! response.addFragments({name, ": ", histogram.quantileSummary(), "\n"});
//! ```
//!
//! The argument is a **`ParentHistogram`**, and that is the whole subtlety:
//! Envoy has TWO `quantileSummary()` implementations and they produce
//! different strings.
//!
//! - `HistogramStatisticsImpl::quantileSummary()` (in `histogram_impl.cc`)
//!   formats `"P{:g}: {:g}"` and joins with `", "`.
//! - `ParentHistogramImpl::quantileSummary()` (in
//!   `source/common/stats/thread_local_store.cc`) formats
//!   `"P{:g}({},{})"` — the *interval* and *cumulative* quantiles as a pair —
//!   and joins with `" "`.
//!
//! **The admin endpoint calls the second one.** `/stats` renders parent
//! histograms, so the wire format is the parenthesized pair, space-joined:
//!
//! ```text
//! summary.push_back(fmt::format("P{:g}({},{})", 100 * supported_quantiles_ref[i],
//!                               interval_statistics_.computedQuantiles()[i],
//!                               cumulative_statistics_.computedQuantiles()[i]));
//! return absl::StrJoin(summary, " ");
//! ```
//!
//! over the fixed quantile set `{0, 0.25, 0.5, 0.75, 0.90, 0.95, 0.99,
//! 0.995, 0.999, 1}` — i.e. exactly [`ENVOY_STATS_TEXT_PERCENTILES`].
//!
//! **So increment 3's recollection was RIGHT**, both in the pair shape and in
//! the space-joining, and it is confirmed here rather than replaced. An
//! earlier pass at this section read `histogram_impl.cc` alone, concluded the
//! pair shape was wrong, rewrote [`render_histogram_line`] to
//! `P<n>: <value>`, and marked it confirmed — reading a real function in the
//! real repo, just not the one the admin endpoint calls. That is the failure
//! mode worth naming: "checked against the source" is only as good as having
//! checked the right symbol, and a plausible near-miss reads exactly like a
//! confirmation.
//!
//! This registry has no "interval since last flush" figure, only the lifetime
//! one, so both halves of each pair carry the same value. That is a real
//! divergence from Envoy and it is deliberate; a scraper reading the second
//! element gets the right number.
//!
//! One thing the same research DID settle, and it is kept: Envoy's
//! `used() == false` case prints `No recorded values` instead of a percentile
//! line. [`render_histogram_line`] matches it, using this registry's
//! `count == 0` as the equivalent of `!used()`.
//!
//! **One narrower thing remains unconfirmed**, isolated the same way the
//! whole shape used to be: Envoy formats each individual number with C++'s
//! `fmt::format("{:g}", ...)`, which is `printf`'s `%g` — roughly six
//! significant digits, switching to scientific notation outside a threshold
//! range, always trimming trailing zeros. Rust's default `f64` `Display`
//! (used here) instead prints the *shortest string that round-trips exactly*
//! back to the same `f64`, which is a different rule and can disagree with
//! `%g` on values with more than ~6 significant digits (small integers and
//! "nice" decimals like the ones in [`ENVOY_DEFAULT_HISTOGRAM_BUCKETS_MS`]
//! agree under both rules, which is why the existing tests don't catch the
//! difference). Replicating `%g` exactly was judged out of scope for this
//! WP; this is the whole remaining gap, and it is far narrower than "the
//! entire shape might be wrong".

use super::{HistogramHandle, Instrument, Registry};

/// Percentiles Envoy's `/stats` text endpoint reports per histogram, in
/// rendering order. The quantile *set* is confirmed against
/// `HistogramStatisticsImpl::supportedQuantiles()` in Envoy's own
/// `source/common/stats/histogram_impl.cc` — both of Envoy's
/// `quantileSummary()` implementations share this same fixed set. The *line
/// format* this set is rendered into is a different symbol,
/// `ParentHistogramImpl::quantileSummary()` in
/// `source/common/stats/thread_local_store.cc` — see the module doc's
/// "CONFIRMED" section for why that one, specifically, is the one the admin
/// endpoint calls, and for the near-miss with the other `quantileSummary()`
/// that this file's history records.
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
/// Envoy equivalent (e.g. `llm.client.token.usage`) contribute no line
/// at all.
///
/// **Reads only.** This walks already-resolved handles and sums
/// already-stored atomics via [`Registry::counters`]/[`Registry::histograms`]/
/// [`Registry::percentile`] — no I/O, no blocking, safe to call from an
/// admin request handler on the control runtime (see
/// `proxy-admin/src/server.rs`'s `/stats` route).
pub fn render(registry: &Registry) -> String {
    let mut lines: Vec<(String, String)> = Vec::new();

    // Rust note: `counters()`/`histograms()` now hand back owned
    // `Vec<(String, String)>` attrs rather than a slice borrowed from
    // `registry` (see their doc comments -- the underlying data lives
    // behind an `ArcSwap` a concurrent `resolve` could replace), so `&attrs`
    // below is a plain reference to a local, not a reborrow of `registry`.
    for (instrument, attrs, value) in registry.counters() {
        if let Some(name) = envoy_counter_name(instrument, &attrs) {
            lines.push((name, value.to_string()));
        }
    }
    for (handle, instrument, attrs) in registry.histograms() {
        if let Some(name) = envoy_histogram_name(instrument, &attrs) {
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
        // Envoy's listener stat family. **Divergence, deliberate:** Envoy
        // keys these by the listener's ADDRESS by default
        // (`listener.0.0.0.0_80.downstream_cx_total`), falling back to a
        // configured `Listener.stat_prefix` when one is set. This renders the
        // configured listener NAME instead, unconditionally — see
        // internal-docs/envoy-divergences.md for the reasoning. The short version:
        // the attribute this instrument carries IS the name
        // (`DOWNSTREAM_CX_TOTAL.attribute_keys`), the address is not
        // available at the recording site, and a name is stable across a
        // rebind where an address is not.
        //
        // This is "rendered under a different key", not "invented": the stat
        // itself is Envoy's, unlike `llm.*` below. Rule 2 forbids making
        // up a stat that has no Envoy equivalent, not choosing between two
        // real Envoy key schemes.
        "downstream_cx_total" => {
            let listener = attr(attrs, "listener")?;
            Some(format!("listener.{listener}.downstream_cx_total"))
        }
        // Everything else (llm.*, and any future counter this table
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
/// after `"name: "`). **Confirmed shape** — see the module doc's "CONFIRMED"
/// section for the exact Envoy source this was checked against. Still
/// isolated here, and only here, so the one remaining unconfirmed detail
/// (the module doc's `%g`-vs-`Display` note) stays contained to one
/// function if it's ever tightened up further.
fn render_histogram_line(registry: &Registry, handle: HistogramHandle) -> String {
    let snapshot = registry.histogram_snapshot(handle);
    if snapshot.count == 0 {
        // Envoy's own `!used()` branch, in `ParentHistogramImpl`.
        return "No recorded values".to_string();
    }
    ENVOY_STATS_TEXT_PERCENTILES
        .iter()
        .map(|(label, p)| {
            // `P<n>(interval,cumulative)`, space-joined. This registry has no
            // separate "interval since last flush" figure, only the lifetime
            // one, so both fields carry the same value -- a named divergence,
            // not an accident.
            let value = registry.percentile(handle, *p);
            format!("{label}({value},{value})")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{instruments, InstrumentKind, StatsControl, WorkerId};

    // ---- 1: a counter renders as `name: value` under its Envoy name ------

    #[test]
    fn counter_renders_as_name_colon_value() {
        let control = StatsControl::new(1);
        let h = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let registry = control.registry();
        registry.incr(WorkerId(0), h, 5);

        let output = render(&registry);
        assert_eq!(output, "cluster.openai.upstream_rq_total: 5\n");
    }

    // ---- 2: attribute expansion produces one-to-many Envoy names ----------

    #[test]
    fn attribute_expansion_produces_one_to_many_envoy_names() {
        // The production UPSTREAM_RQ const (stats.rs) only carries
        // `cluster` today (no call site resolves it with `status_class`
        // yet — that's increment 6's job). Rendering only depends on
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

        let control = StatsControl::new(1);
        let ok = control.resolve(
            &UPSTREAM_RQ_BY_CLASS,
            &[("cluster", "x"), ("status_class", "2xx")],
        );
        let err = control.resolve(
            &UPSTREAM_RQ_BY_CLASS,
            &[("cluster", "x"), ("status_class", "5xx")],
        );
        let registry = control.registry();
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

    // ---- 2b: the listener family ------------------------------------------

    /// WP-23 increment 6b follow-up: `downstream_cx_total` is a real Envoy
    /// stat, and until this case existed it rendered to nothing on `/stats`
    /// while appearing normally on `/stats/prometheus` -- so the Envoy-text
    /// endpoint silently under-reported. Keyed by listener NAME, which is a
    /// deliberate divergence from Envoy's address-keyed default; see
    /// `envoy_counter_name` and internal-docs/envoy-divergences.md.
    #[test]
    fn downstream_cx_total_renders_under_the_listener_name() {
        let control = StatsControl::new(1);
        let h = control.resolve(
            &instruments::DOWNSTREAM_CX_TOTAL,
            &[("listener", "ingress_http")],
        );
        let registry = control.registry();
        registry.incr(WorkerId(0), h, 3);

        let output = render(&registry);
        assert_eq!(output, "listener.ingress_http.downstream_cx_total: 3\n");
    }

    // ---- 3: an instrument with no Envoy template is absent -----------------

    #[test]
    fn instrument_with_no_envoy_template_is_absent() {
        let control = StatsControl::new(1);
        let h = control.resolve(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", "acme"),
            ],
        );
        let registry = control.registry();
        registry.incr(WorkerId(0), h, 42);

        let output = render(&registry);
        assert!(
            !output.contains("llm_client_token_usage") && !output.contains("llm.client.token.usage"),
            "llm.client.token.usage has no Envoy /stats equivalent and must be omitted entirely, got: \
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
        let control = StatsControl::new(1);
        let zeta = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "zeta")]);
        let alpha = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "alpha")]);
        let registry = control.registry();
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
    fn histogram_line_renders_the_confirmed_pair_format() {
        let control = StatsControl::new(1);
        let h = control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
        let registry = control.registry();
        registry.observe(WorkerId(0), h, 7.0);
        registry.observe(WorkerId(0), h, 800.0);

        let line = render_histogram_line(&registry, h);

        // "P<n>(interval,cumulative)" entries, space-joined -- confirmed
        // against `ParentHistogramImpl::quantileSummary()` in Envoy's own
        // `source/common/stats/thread_local_store.cc`, the symbol the admin
        // endpoint actually calls (see the module doc's "CONFIRMED"
        // section). This registry has no separate interval figure, so both
        // halves of each pair carry the same (percentile) value.
        for (label, p) in ENVOY_STATS_TEXT_PERCENTILES {
            let value = registry.percentile(h, p);
            assert!(
                line.contains(&format!("{label}({value},{value})")),
                "missing {label}({value},{value}) in histogram line: {line}"
            );
        }
        assert_eq!(
            line.matches('(').count(),
            ENVOY_STATS_TEXT_PERCENTILES.len(),
            "exactly one (interval,cumulative) pair per percentile: {line}"
        );
        assert_eq!(
            line.matches(' ').count(),
            ENVOY_STATS_TEXT_PERCENTILES.len() - 1,
            "entries must be joined by a single space, not \", \": {line}"
        );
        assert!(
            !line.contains(": "),
            "the OTHER (HistogramStatisticsImpl) colon-joined shape must not appear -- \
             that symbol is not the one /stats actually calls: {line}"
        );

        // Wired end to end through render() too, under its Envoy name.
        let output = render(&registry);
        assert!(
            output.starts_with("cluster.x.upstream_rq_time: "),
            "output: {output}"
        );
    }

    #[test]
    fn histogram_with_no_observations_renders_no_recorded_values() {
        let control = StatsControl::new(1);
        let h = control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
        let registry = control.registry();

        let line = render_histogram_line(&registry, h);
        assert_eq!(
            line, "No recorded values",
            "matches Envoy's own !histogram.used() branch -- see the module doc"
        );
    }

    // ---- 8: rendered values are summed across workers, not one shard ------

    /// The ADR-0005 trap, one layer out from `stats.rs`'s own coverage of it:
    /// a renderer that reached for a single shard instead of
    /// `Registry::counters`'s already-summed value would pass every test
    /// above this one.
    #[test]
    fn rendered_value_is_summed_across_workers_not_a_single_shard() {
        let control = StatsControl::new(2);
        let h = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let registry = control.registry();
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
