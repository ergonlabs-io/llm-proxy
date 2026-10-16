//! Renders a [`Registry`] into Envoy's flat `/stats` text format. No
//! Prometheus, no OTLP. The naming rules are in `stats.rs` Decision 4.
//!
//! # Name rendering
//!
//! Each resolved `(instrument, attrs)` pair maps to zero or one Envoy name:
//!
//! | OTel | Envoy `/stats` |
//! |---|---|
//! | `upstream_rq` `{cluster, status_class}` | `cluster.<cluster>.upstream_rq_<class>` |
//! | `upstream_rq` `{cluster}` | `cluster.<cluster>.upstream_rq_total` |
//! | `upstream_rq_time` `{cluster}` | `cluster.<cluster>.upstream_rq_time` |
//! | anything else (e.g. `llm.client.token.usage`) | omitted |
//!
//! [`envoy_counter_name`] and [`envoy_histogram_name`] are the only functions
//! that know this table. An unrecognized instrument is omitted, never rendered
//! under an invented name. `/stats` is a compatibility surface.
//!
//! # Output ordering
//!
//! [`render`] sorts by the rendered Envoy name, so output is byte-identical for
//! unchanged state and diff-based tests stay meaningful.
//!
//! # Histogram line format
//!
//! Envoy's admin endpoint renders parent histograms with
//! `ParentHistogramImpl::quantileSummary()` in
//! `source/common/stats/thread_local_store.cc`. Each quantile prints as
//! `P{:g}(interval,cumulative)`, space-joined, over the fixed set
//! [`ENVOY_STATS_TEXT_PERCENTILES`]. The other `quantileSummary()` in
//! `histogram_impl.cc` uses a different shape and is not the one the endpoint
//! calls.
//!
//! This registry keeps only lifetime figures, so both halves of each pair carry
//! the same value. That is a deliberate divergence from Envoy. A histogram with
//! no recorded values prints `No recorded values`, as Envoy does.
//!
//! Known gap: Envoy formats numbers with `%g`, while Rust's `Display` prints
//! the shortest round-trip string. The two can differ for values with more than
//! about six significant digits.

use super::{percentile_of, HistogramHandle, Instrument, Registry};

/// Percentiles Envoy's `/stats` text endpoint reports per histogram, in
/// rendering order. The set matches `HistogramStatisticsImpl::supportedQuantiles()`
/// in Envoy's `source/common/stats/histogram_impl.cc`. See the module doc for the
/// line format.
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

/// Renders `registry` into Envoy's flat `/stats` text format: `name: value` for
/// each counter with an Envoy name, and a percentile line for each histogram
/// with one. Lines are `\n`-terminated and sorted by rendered name.
///
/// Reads only, with no I/O or blocking. It is safe to call from an admin handler.
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
            // `None`: the series was drained after `histograms()` listed it.
            if let Some(line) = render_histogram_line(registry, handle) {
                lines.push((name, line));
            }
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
        "ext_authz" => Some(format!(
            "http.{}.{}",
            attr(attrs, "scope")?,
            attr(attrs, "outcome")?
        )),
        "upstream_rq" => {
            let cluster = attr(attrs, "cluster")?;
            match attr(attrs, "status_class") {
                Some(class) => Some(format!("cluster.{cluster}.upstream_rq_{class}")),
                None => Some(format!("cluster.{cluster}.upstream_rq_total")),
            }
        }
        // Envoy's listener family. **Deliberate divergence:** Envoy keys these by
        // listener address by default, and this renders the listener name
        // instead (`internal-docs/envoy-divergences.md`). The address is not
        // known at the recording site, and a name survives a rebind. The stat
        // itself is Envoy's, so this is a different key, not an invented stat.
        "downstream_cx_total" => {
            let listener = attr(attrs, "listener")?;
            Some(format!("listener.{listener}.downstream_cx_total"))
        }
        "downstream_global_cx_overflow" => {
            let listener = attr(attrs, "listener")?;
            Some(format!("listener.{listener}.downstream_global_cx_overflow"))
        }
        "downstream_cx_transport_socket_connect_timeout" => {
            let listener = attr(attrs, "listener")?;
            Some(format!(
                "listener.{listener}.downstream_cx_transport_socket_connect_timeout"
            ))
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

/// Renders one histogram handle's `/stats` line body (everything after
/// `"name: "`). Every percentile comes from one read, so the line describes one
/// moment.
/// `None` if `handle` went stale.
fn render_histogram_line(registry: &Registry, handle: HistogramHandle) -> Option<String> {
    let (snapshot, boundaries) = registry.histogram_view(handle)?;
    if snapshot.count == 0 {
        // Envoy's own `!used()` branch, in `ParentHistogramImpl`.
        return Some("No recorded values".to_string());
    }
    let line = ENVOY_STATS_TEXT_PERCENTILES
        .iter()
        .map(|(label, p)| {
            // `P<n>(interval,cumulative)`, space-joined. This registry has no
            // separate "interval since last flush" figure, only the lifetime
            // one, so both fields carry the same value -- a named divergence,
            // not an accident.
            let value = percentile_of(&snapshot, boundaries, *p);
            format!("{label}({value},{value})")
        })
        .collect::<Vec<_>>()
        .join(" ");
    Some(line)
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
        // Rendering depends only on the instrument name and the attrs present on
        // the handle, so a local instrument with the same name exercises the
        // `status_class` expansion.
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

    /// `downstream_cx_total` is a real Envoy
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

    /// Envoy's listener stat for a downstream TLS handshake that outlived
    /// `transport_socket_connect_timeout`; the rendered key is the
    /// operator-facing contract.
    #[test]
    fn transport_socket_connect_timeout_renders_under_the_listener_name() {
        let control = StatsControl::new(1);
        let h = control.resolve(
            &instruments::DOWNSTREAM_CX_TRANSPORT_SOCKET_CONNECT_TIMEOUT,
            &[("listener", "ingress_https")],
        );
        let registry = control.registry();
        registry.incr(WorkerId(0), h, 2);

        let output = render(&registry);
        assert_eq!(
            output,
            "listener.ingress_https.downstream_cx_transport_socket_connect_timeout: 2\n"
        );
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

        let line = render_histogram_line(&registry, h).unwrap();

        // "P<n>(interval,cumulative)" entries, space-joined. Both halves carry
        // the same lifetime value; see the module doc.
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

        let line = render_histogram_line(&registry, h).unwrap();
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
