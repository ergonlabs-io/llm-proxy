//! WP-23 increment 4 — renders a [`Registry`] into Prometheus text exposition
//! format. See `docs/wp-23-stats-design-brief.md`'s Decision 4 for the naming
//! rules this module implements, and [`envoy_render`](super::envoy_render)
//! for the sibling renderer this one deliberately does *not* copy the shape
//! of (see "Names vs. labels" below).
//!
//! # Names vs. labels — why this renderer does not expand attribute values
//!
//! [`envoy_render`](super::envoy_render) expands an attribute *value* into a
//! name segment (`upstream_rq` `{cluster, status_class="2xx"}` becomes the
//! name `cluster.<cluster>.upstream_rq_2xx`) because Envoy's flat `/stats`
//! text format has no concept of a label. Prometheus does, so that expansion
//! is not needed here and — per the design brief's Decision 4 — must not be
//! copied over: **every attribute becomes a label**, and the metric name is
//! just the instrument's own (sanitized, `envoy_`-prefixed) name. This is
//! also why, unlike `envoy_render`, this renderer has **no per-instrument
//! name table and omits nothing** — `llm.*` (no Envoy `/stats` text
//! equivalent at all) renders here exactly like `upstream_rq` does, which is
//! the module doc's point 2 for Decision 4: those instruments "exist in
//! Prometheus/OTLP output only".
//!
//! # Name and label sanitization — confirmed against Envoy's own source
//!
//! Verified against `envoyproxy/envoy` commit `d57118924c85fcaa07758dddbb9c5da4e89045af`
//! (`main`, fetched 2026-08-09), `source/server/admin/prometheus_stats.cc`:
//!
//! - **Metric names**: prefixed with `envoy_`, then every character outside
//!   `[a-zA-Z0-9_]` is replaced with `_` (`sanitizeNameInPlace`). Envoy's own
//!   comment notes the `envoy_` prefix already guarantees the result can't
//!   start with a digit, so it does not special-case that — this module's
//!   [`sanitize_metric_name`] still guards it explicitly (see that
//!   function's doc) so the function is correct standing on its own, not
//!   just correct because its one caller happens to always prepend a
//!   letter-starting prefix first.
//! - **Label (tag) names**: exactly the same `[^a-zA-Z0-9_]` -> `_` rule
//!   (`sanitizeNameInPlace` is reused verbatim for tag names in
//!   `formattedTags`) — Prometheus label names allow no `:`, unlike metric
//!   names, so this is a distinct function from the metric-name one despite
//!   the identical character class.
//! - **Label values are escaped, not sanitized**: backslash -> `\\`,
//!   newline -> `\n`, double-quote -> `\"`, applied in exactly that order
//!   (`sanitizeValue`, which cites
//!   <https://github.com/prometheus/common/blob/88f1636b699ae4fb949d292ffb904c205bf542c9/expfmt/text_create.go#L419-L420>
//!   as its own source). Order matters: escaping the backslash first is what
//!   stops the newline/quote escapes from being re-escaped.
//!
//! # `# TYPE` lines, once per family
//!
//! `Counter` -> `counter`, `UpDownCounter` -> `gauge` (Envoy's own C++ code
//! doesn't have an `UpDownCounter` concept — it only ever emits `counter` or
//! `gauge` from its native `Stats::Counter`/`Stats::Gauge` types — but
//! `gauge` is the correct target for a value that can move in both
//! directions, matching the OTel Collector's own Prometheus exporter
//! convention), `Histogram` -> `histogram`. One `# TYPE` line per rendered
//! metric *family* (i.e. per rendered name, before any `_bucket`/`_sum`/
//! `_count` suffix), even when several attribute sets ("series") share that
//! family — confirmed by `TextFormat::generateNumericOutput`/
//! `generateHistogramOutput` in the same source file, both of which call
//! `generateTypeOutput` exactly once before looping over every series.
//!
//! # Histogram bucket lines — cumulative counts, confirmed shape
//!
//! `TextFormat::generateHistogramOutput` (same source file) confirms the
//! exact shape this module produces: `<name>_bucket{<labels>le="<boundary>"} <cumulative>`
//! for each declared boundary in ascending order, then
//! `<name>_bucket{<labels>le="+Inf"} <total count>`, then
//! `<name>_sum{<labels>} <sum>` and `<name>_count{<labels>} <count>` (no
//! `le` label on the last two). [`Registry`] stores **non-cumulative**
//! per-bucket counts (see `stats.rs`'s module doc), so
//! [`render_histogram_series`] computes the running prefix sum itself —
//! Envoy's own `computed_buckets_`/`computedBuckets()` do the equivalent
//! summation on their side before this exact rendering step.
//!
//! # What this module does not do
//!
//! No periodic flush, no `?filter=`/`?histogram_buckets=` query parameters,
//! no protobuf exposition format, no OpenMetrics. All out of scope per the
//! design brief's "what this brief does not decide" and this WP's own
//! increment boundary.

use std::collections::BTreeMap;

use super::{HistogramHandle, Instrument, InstrumentKind, Registry};

/// One resolved attribute set, keys already sanitized into Prometheus label
/// names (values are escaped later, at render time -- see
/// [`escape_label_value`]). Named as a `type` alias purely to keep
/// [`render`]'s grouping maps readable -- clippy's `type_complexity` lint
/// flagged the inline form, the same reason `stats.rs`'s own `ResolveKey`
/// alias exists.
type Labels = Vec<(String, String)>;

/// [`render`]'s grouping map for counters/up-down-counters: rendered metric
/// name -> (the `InstrumentKind` to print in its `# TYPE` line, every
/// resolved series sharing that name as `(labels, summed value)`).
type CounterFamilies = BTreeMap<String, (InstrumentKind, Vec<(Labels, u64)>)>;

/// [`render`]'s grouping map for histograms: rendered metric name -> every
/// resolved histogram handle sharing that name, paired with its instrument
/// (for bucket boundaries) and resolved attrs.
type HistogramFamilies = BTreeMap<String, Vec<(HistogramHandle, &'static Instrument, Labels)>>;

/// The `Content-Type` this crate's renderer's callers (`proxy-admin`'s
/// `/stats/prometheus` route) must answer with.
///
/// Confirmed, not guessed: Envoy's admin server never sets a `Content-Type`
/// for the `/stats/prometheus` handler specifically
/// (`StatsHandler::prometheusRender`, `source/server/admin/stats_handler.cc`)
/// so it falls through to the admin-wide default,
/// `source/server/admin/utils.cc`'s `populateFallbackResponseHeaders`:
/// `Http::Headers::get().ContentTypeValues.TextUtf8`, which
/// `source/common/http/headers.h` defines as exactly this string (modulo the
/// `UTF-8`/`utf-8` casing, which HTTP treats as equivalent). This also
/// matches `proxy-admin`'s own existing `text()` helper, so `/stats/prometheus`
/// can reuse it rather than needing a second response-building path.
pub const CONTENT_TYPE: &str = "text/plain; charset=utf-8";

/// Renders `registry`'s current state into Prometheus text exposition
/// format: a `# TYPE` line per metric family, then one series line per
/// resolved `(instrument, attrs)` pair (or, for histograms, one `_bucket`
/// line per boundary plus `_sum`/`_count`) — see the module doc for the
/// exact rules.
///
/// **Reads only**, same guarantee as [`envoy_render::render`](super::envoy_render::render):
/// no I/O, no blocking, safe to call from an admin request handler.
///
/// Unlike `envoy_render::render`, **every** resolved instrument renders here
/// — there is no "no Envoy equivalent, omit it" case, because there is no
/// per-instrument name table to miss an entry from (see the module doc's
/// "Names vs. labels" section). An empty registry renders `""`.
pub fn render(registry: &Registry) -> String {
    let mut out = String::new();

    // Rust note: `BTreeMap`, not `HashMap` -- keying by the rendered metric
    // name gives us both the "group everything sharing a family" step and a
    // stable (alphabetical) iteration order for free, the same reason
    // `envoy_render::render` explicitly sorts its own output. Multiple
    // instruments could in principle collide on a rendered name; the last
    // insertion's `InstrumentKind` wins for the `# TYPE` line in that
    // (pathological, not expected in practice) case.
    let mut counter_families: CounterFamilies = BTreeMap::new();
    for (instrument, attrs, value) in registry.counters() {
        let name = prometheus_name(instrument);
        let labels = prometheus_labels(&attrs);
        counter_families
            .entry(name)
            .or_insert_with(|| (instrument.kind, Vec::new()))
            .1
            .push((labels, value));
    }
    for (name, (kind, mut series)) in counter_families {
        // Sort series within a family by their (sanitized) labels so two
        // calls against unchanged state render identically -- same
        // motivation as envoy_render's name sort.
        series.sort_by(|a, b| a.0.cmp(&b.0));
        let type_name = match kind {
            InstrumentKind::Counter => "counter",
            InstrumentKind::UpDownCounter => "gauge",
            InstrumentKind::Histogram => {
                unreachable!("Registry::counters() never yields a Histogram handle")
            }
        };
        out.push_str(&format!("# TYPE {name} {type_name}\n"));
        for (labels, value) in series {
            out.push_str(&format_series(&name, &labels, &value.to_string()));
        }
    }

    let mut histogram_families: HistogramFamilies = BTreeMap::new();
    for (handle, instrument, attrs) in registry.histograms() {
        let name = prometheus_name(instrument);
        histogram_families
            .entry(name)
            .or_default()
            .push((handle, instrument, attrs));
    }
    for (name, mut entries) in histogram_families {
        entries.sort_by(|a, b| a.2.cmp(&b.2));
        out.push_str(&format!("# TYPE {name} histogram\n"));
        for (handle, instrument, attrs) in entries {
            let labels = prometheus_labels(&attrs);
            render_histogram_series(&mut out, registry, handle, instrument, &name, &labels);
        }
    }

    out
}

/// `envoy_<sanitized instrument name>` -- see the module doc's "Name and
/// label sanitization" section.
fn prometheus_name(instrument: &Instrument) -> String {
    format!("envoy_{}", sanitize_metric_name(instrument.name))
}

/// Sanitizes every attribute key into a Prometheus label name, leaving
/// values untouched (they are escaped, not sanitized, at render time -- see
/// [`escape_label_value`]).
fn prometheus_labels(attrs: &[(String, String)]) -> Vec<(String, String)> {
    attrs
        .iter()
        .map(|(k, v)| (sanitize_label_name(k), v.clone()))
        .collect()
}

/// Replaces every character outside `[a-zA-Z0-9_]` with `_`, matching
/// Envoy's `sanitizeNameInPlace` (see the module doc). Additionally, if the
/// result would start with a digit, prepends `_` -- Prometheus metric names
/// must match `[a-zA-Z_:][a-zA-Z0-9_:]*`, so a name starting with a digit is
/// invalid. Every real call site here goes through [`prometheus_name`],
/// which always prepends `envoy_` first and so can never actually hit this
/// case (matching Envoy's own reasoning for not checking it) -- this guard
/// exists so the function is correct on its own terms, independent of its
/// only current caller, and so `tests::name_starting_with_digit_is_prefixed`
/// has something real to test.
fn sanitize_metric_name(name: &str) -> String {
    sanitize_leading_digit(sanitize_chars(name, false))
}

/// The label-name counterpart of [`sanitize_metric_name`]: same character
/// class minus `:` (Prometheus label names never allow it, even though
/// metric names do), same leading-digit guard.
fn sanitize_label_name(name: &str) -> String {
    sanitize_leading_digit(sanitize_chars(name, false))
}

/// Shared sanitization core. `allow_colon` exists for documentation clarity
/// at each call site even though both current callers pass `false` --
/// Envoy's own metric names and tag names both exclude `:` in practice (only
/// the *Prometheus spec's* metric-name grammar allows it), so nothing here
/// actually needs the `true` branch yet; it is wired through rather than
/// hard-coded so a future difference between the two doesn't require
/// threading a new parameter through both functions above.
fn sanitize_chars(name: &str, allow_colon: bool) -> String {
    name.chars()
        .map(|c| {
            let ok = c.is_ascii_alphanumeric() || c == '_' || (allow_colon && c == ':');
            if ok {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// If `name` starts with an ASCII digit, prepends `_` so it satisfies
/// Prometheus's "must not start with a digit" rule.
fn sanitize_leading_digit(name: String) -> String {
    match name.chars().next() {
        Some(c) if c.is_ascii_digit() => {
            let mut out = String::with_capacity(name.len() + 1);
            out.push('_');
            out.push_str(&name);
            out
        }
        _ => name,
    }
}

/// Escapes a label *value* (never sanitizes it -- see the module doc for why
/// mangling a value where escaping is called for silently corrupts a
/// series): backslash -> `\\`, newline -> `\n`, double-quote -> `\"`, in
/// that order. Order matters -- escaping the backslash first stops the
/// newline/quote escapes from being re-escaped by a later pass.
fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out
}

/// Renders one series line: `<name>{<label>="<value>",...} <raw_value>\n`,
/// or `<name> <raw_value>\n` with no braces when `labels` is empty --
/// Prometheus's exposition format allows either omitting empty braces or
/// writing `{}`; this renderer omits them, matching the common convention
/// (and Envoy's own output for a series with no tags).
fn format_series(name: &str, labels: &[(String, String)], raw_value: &str) -> String {
    if labels.is_empty() {
        format!("{name} {raw_value}\n")
    } else {
        let label_str = labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{}\"", escape_label_value(v)))
            .collect::<Vec<_>>()
            .join(",");
        format!("{name}{{{label_str}}} {raw_value}\n")
    }
}

/// Renders one histogram handle's `_bucket`/`_sum`/`_count` series under
/// `name` (already `envoy_`-prefixed and sanitized) -- see the module doc's
/// "Histogram bucket lines" section for the confirmed shape this
/// implements.
fn render_histogram_series(
    out: &mut String,
    registry: &Registry,
    handle: HistogramHandle,
    instrument: &Instrument,
    name: &str,
    labels: &[(String, String)],
) {
    let boundaries = instrument
        .buckets
        .expect("a Histogram-kind Instrument always declares buckets -- Registry::resolve_histogram enforces this at resolve time");
    let snapshot = registry.histogram_snapshot(handle);
    let bucket_name = format!("{name}_bucket");

    // `snapshot.bucket_counts` is non-cumulative (stats.rs's module doc) --
    // this prefix sum is the "cumulative" step Envoy's own computedBuckets()
    // performs before this exact rendering step, done here instead because
    // this registry deliberately never stores the cumulative form (see the
    // module doc).
    let mut cumulative: u64 = 0;
    for (i, boundary) in boundaries.iter().enumerate() {
        cumulative = cumulative.wrapping_add(snapshot.bucket_counts[i]);
        let mut bucket_labels = labels.to_vec();
        bucket_labels.push(("le".to_string(), format_bucket_boundary(*boundary)));
        out.push_str(&format_series(
            &bucket_name,
            &bucket_labels,
            &cumulative.to_string(),
        ));
    }
    // The overflow bucket (index == boundaries.len(), see stats.rs's module
    // doc) is Prometheus's own `+Inf` bucket -- rolling it into the running
    // sum here means this final count is, by construction, exactly
    // `snapshot.count` (every non-cumulative bucket, including overflow,
    // has now been added exactly once).
    cumulative = cumulative.wrapping_add(snapshot.bucket_counts[boundaries.len()]);
    let mut inf_labels = labels.to_vec();
    inf_labels.push(("le".to_string(), "+Inf".to_string()));
    out.push_str(&format_series(
        &bucket_name,
        &inf_labels,
        &cumulative.to_string(),
    ));

    out.push_str(&format_series(
        &format!("{name}_sum"),
        labels,
        &format_f64(snapshot.sum),
    ));
    out.push_str(&format_series(
        &format!("{name}_count"),
        labels,
        &snapshot.count.to_string(),
    ));
}

/// Formats one bucket boundary for a Prometheus `le` label. Rust's default
/// `f64` `Display` already produces the shortest round-tripping decimal
/// (`1000.0` -> `"1000"`, `0.5` -> `"0.5"`) with no trailing `.0`, which is
/// exactly the shape every boundary in
/// [`super::ENVOY_DEFAULT_HISTOGRAM_BUCKETS_MS`] needs.
fn format_bucket_boundary(boundary: f64) -> String {
    format_f64(boundary)
}

/// Formats an arbitrary observed `f64` (a histogram's running `sum`) for
/// exposition. Same `Display`-based formatting as [`format_bucket_boundary`]
/// -- see that function's doc.
fn format_f64(value: f64) -> String {
    format!("{value}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{instruments, StatsControl, WorkerId};

    // ---- 1: metric name sanitization, including a leading digit ----------

    #[test]
    fn metric_name_sanitizes_disallowed_characters() {
        assert_eq!(sanitize_metric_name("upstream_rq"), "upstream_rq");
        assert_eq!(
            sanitize_metric_name("llm.client.token.usage"),
            "llm_client_token_usage"
        );
        assert_eq!(sanitize_metric_name("a-b c/d"), "a_b_c_d");
    }

    #[test]
    fn metric_name_starting_with_a_digit_is_prefixed_with_underscore() {
        assert_eq!(sanitize_metric_name("2xx_total"), "_2xx_total");
    }

    #[test]
    fn label_name_sanitizes_disallowed_characters_and_excludes_colon() {
        assert_eq!(sanitize_label_name("status_class"), "status_class");
        assert_eq!(
            sanitize_label_name("gen_ai.provider.name"),
            "gen_ai_provider_name"
        );
        // Unlike metric names, Prometheus label names never allow ':' --
        // this module's sanitize_label_name mangles it like any other
        // disallowed character rather than special-casing it through.
        assert_eq!(sanitize_label_name("a:b"), "a_b");
    }

    // ---- 2: label VALUE escaping -- quote, backslash, newline -----------

    #[test]
    fn label_value_escapes_backslash_quote_and_newline() {
        assert_eq!(escape_label_value(r#"back\slash"#), r#"back\\slash"#);
        assert_eq!(escape_label_value(r#"has "quotes""#), r#"has \"quotes\""#);
        assert_eq!(escape_label_value("line1\nline2"), "line1\\nline2");
        // Order matters: the backslash introduced by escaping the quote must
        // not itself be re-escaped.
        assert_eq!(escape_label_value("\\\n\""), "\\\\\\n\\\"");
    }

    #[test]
    fn label_value_is_escaped_not_sanitized_in_full_output() {
        let control = StatsControl::new(1);
        let h = control.resolve(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("provider", "openai\"evil"),
                ("type", "input"),
                ("tenant", "acme"),
            ],
        );
        let registry = control.registry();
        registry.incr(WorkerId(0), h, 1);

        let output = render(&registry);
        assert!(
            output.contains(r#"provider="openai\"evil""#),
            "value must be escaped (not stripped/mangled) in place: {output}"
        );
    }

    // ---- 3: exactly one # TYPE line per family across multiple series ---

    #[test]
    fn exactly_one_type_line_per_family_across_multiple_label_sets() {
        let control = StatsControl::new(1);
        let a = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let b = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "anthropic")]);
        let registry = control.registry();
        registry.incr(WorkerId(0), a, 1);
        registry.incr(WorkerId(0), b, 1);

        let output = render(&registry);
        assert_eq!(
            output.matches("# TYPE envoy_upstream_rq counter").count(),
            1,
            "expected exactly one TYPE line for the shared family, got: {output}"
        );
        assert!(output.contains(r#"envoy_upstream_rq{cluster="openai"} 1"#));
        assert!(output.contains(r#"envoy_upstream_rq{cluster="anthropic"} 1"#));
    }

    #[test]
    fn counter_and_up_down_counter_render_different_type_lines() {
        static A_GAUGE: Instrument = Instrument {
            name: "connections_open",
            kind: InstrumentKind::UpDownCounter,
            unit: "{connection}",
            attribute_keys: &["listener"],
            buckets: None,
        };

        let control = StatsControl::new(1);
        let counter = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let gauge = control.resolve(&A_GAUGE, &[("listener", "ingress")]);
        let registry = control.registry();
        registry.incr(WorkerId(0), counter, 1);
        registry.add(WorkerId(0), gauge, 3);

        let output = render(&registry);
        assert!(output.contains("# TYPE envoy_upstream_rq counter\n"));
        assert!(output.contains("# TYPE envoy_connections_open gauge\n"));
    }

    // ---- 4: no per-instrument omission -- llm.* renders here -----------

    #[test]
    fn llm_instrument_with_no_envoy_text_equivalent_still_renders_in_prometheus() {
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
            output.contains("envoy_llm_client_token_usage"),
            "Prometheus output must include instruments envoy_render omits: {output}"
        );
        assert!(output.contains(r#"provider="openai""#));
        assert!(output.contains(r#"type="input""#));
    }

    // ---- 5: histograms -- cumulative buckets, +Inf == _count -------------

    #[test]
    fn histogram_buckets_are_cumulative_and_inf_equals_count() {
        let control = StatsControl::new(1);
        let h = control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
        let registry = control.registry();
        registry.observe(WorkerId(0), h, 0.5);
        registry.observe(WorkerId(0), h, 7.0);
        registry.observe(WorkerId(0), h, 800.0);
        registry.observe(WorkerId(0), h, 5_000_000.0); // lands in the overflow (+Inf-only) bucket

        let output = render(&registry);
        assert!(output.contains("# TYPE envoy_upstream_rq_time histogram\n"));

        // le="0.5" must already see the one observation <= 0.5.
        assert!(
            output.contains(r#"envoy_upstream_rq_time_bucket{cluster="x",le="0.5"} 1"#),
            "output: {output}"
        );
        // Every boundary from here up must be >= that cumulative count
        // (monotonic non-decreasing cumulative sequence).
        assert!(
            output.contains(r#"envoy_upstream_rq_time_count{cluster="x"} 4"#),
            "output: {output}"
        );

        let inf_line = extract_value(
            &output,
            r#"envoy_upstream_rq_time_bucket{cluster="x",le="+Inf"} "#,
        );
        let count_value = extract_value(&output, r#"envoy_upstream_rq_time_count{cluster="x"} "#);
        assert_eq!(
            inf_line, count_value,
            "the +Inf bucket must equal _count: {output}"
        );
        assert_eq!(count_value, "4");
    }

    #[test]
    fn histogram_bucket_boundaries_are_ascending_le_labels() {
        let control = StatsControl::new(1);
        let h = control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
        let registry = control.registry();
        registry.observe(WorkerId(0), h, 1.0);

        let output = render(&registry);
        // First declared boundary (0.5) and last (3600000) must both appear
        // as `le` labels, in addition to the synthesized "+Inf".
        assert!(output.contains(r#"le="0.5""#), "output: {output}");
        assert!(output.contains(r#"le="3600000""#), "output: {output}");
        assert!(output.contains(r#"le="+Inf""#), "output: {output}");
    }

    // ---- 6: empty registry renders valid (empty) output ------------------

    #[test]
    fn empty_registry_renders_empty_output_without_panicking() {
        let control = StatsControl::new(1);
        let registry = control.registry();
        assert_eq!(render(&registry), "");
    }

    // ---- 7: summed across workers, not one shard --------------------------

    #[test]
    fn rendered_counter_value_is_summed_across_workers() {
        let control = StatsControl::new(2);
        let h = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let registry = control.registry();
        registry.incr(WorkerId(0), h, 10);
        registry.incr(WorkerId(1), h, 25);

        let output = render(&registry);
        assert!(output.contains(r#"envoy_upstream_rq{cluster="openai"} 35"#));
    }

    /// Pulls the integer/float token immediately following `prefix` in
    /// `output`, up to the next whitespace -- a small test-only helper so
    /// the two histogram assertions above can compare rendered numbers
    /// without hand-parsing the whole line.
    fn extract_value<'a>(output: &'a str, prefix: &str) -> &'a str {
        let start = output.find(prefix).unwrap_or_else(|| {
            panic!("expected to find {prefix:?} in output: {output}");
        }) + prefix.len();
        let rest = &output[start..];
        let end = rest.find(['\n']).unwrap_or(rest.len());
        &rest[..end]
    }
}
