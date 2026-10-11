//! Acceptance, config half: OTLP metric export is
//! configured, validated, and lowered entirely independently of OTLP *trace*
//! export.
//!
//! The load-bearing claim this file exists to pin is the one
//! `docs/telemetry-design.md` §5.3 states: "Configure OTLP metric export
//! independently of trace sampling/export. Disabling traces must not disable
//! metrics." Before this, `ConfigSnapshot::tracing` was the only OTLP field in
//! the IR, so a config with no `tracing` block exported no metrics over OTLP
//! even though the registry they are read from is always populated. Every test
//! here is written to fail if someone merges the two namespaces back together.
//!
//! Same shape as `tests/tracing.rs` (see its module doc): the strict-parse ->
//! PGV -> IR pipeline a hand-written Envoy config goes through, so a config
//! that sets neither surface must be completely unaffected, and every malformed
//! shape is a hard error carrying its full dotted path (AGENTS.md invariant 1), never
//! a silent skip.

use std::time::Duration;

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

fn snapshot_from(yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

fn err_path(err: &ConfigError) -> &str {
    match err {
        ConfigError::UnsupportedField { field_path, .. } => field_path,
        ConfigError::InvalidValue { field_path, .. } => field_path,
        other => panic!("expected a field-scoped error, got: {other}"),
    }
}

const METRICS_PATH: &str = "node.metadata[\"io.llmproxy.metrics\"]";

// ---------------------------------------------------- independence from tracing --

/// The headline case. Metrics configured, tracing entirely absent: metrics
/// MUST lower, and tracing MUST stay off. If the two namespaces ever merge, or
/// if `convert_metrics_metadata` is ever gated on `snapshot.tracing`, this is
/// the test that catches it.
#[test]
fn metrics_lower_with_no_tracing_block_at_all() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert_eq!(
        snapshot.tracing, None,
        "the metrics namespace must not turn tracing on"
    );
    let metrics = snapshot.metrics.expect("metrics must be configured");
    assert_eq!(metrics.otlp_endpoint, "http://localhost:4317");
    assert_eq!(metrics.service_name, "llm-proxy");
    assert_eq!(metrics.export_interval, Duration::from_secs(15));
    assert_eq!(metrics.export_deadline, Duration::from_secs(10));
}

/// The mirror image: tracing configured, metrics absent. Must leave metrics
/// off. A test of the other direction, because "metrics off does not require
/// tracing off" is only half the claim -- turning tracing ON must not
/// accidentally imply metrics on either, since that would make an operator who
/// wanted traces only start paying for full metric snapshots.
#[test]
fn tracing_alone_leaves_metrics_unset() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://localhost:4317"
      sample_ratio: 0.25
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert_eq!(snapshot.metrics, None);
    assert_eq!(
        snapshot.tracing.expect("tracing configured").sample_ratio,
        0.25
    );
}

/// Both configured, in the same `node.metadata`, with DIFFERENT endpoints and
/// service names -- which is the ordinary deployment (metrics and traces
/// usually go to different collectors) and is only expressible because the two
/// are separate structs rather than one block with an enable flag.
#[test]
fn both_surfaces_coexist_with_independent_endpoints() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://traces:4317"
      service_name: "llm-proxy-traces"
    io.llmproxy.metrics:
      otlp_endpoint: "http://metrics:4317"
      service_name: "llm-proxy-metrics"
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let tracing = snapshot.tracing.expect("tracing configured");
    let metrics = snapshot.metrics.expect("metrics configured");
    assert_eq!(tracing.otlp_endpoint, "http://traces:4317");
    assert_eq!(tracing.service_name, "llm-proxy-traces");
    assert_eq!(metrics.otlp_endpoint, "http://metrics:4317");
    assert_eq!(metrics.service_name, "llm-proxy-metrics");
}

// ---------------------------------------------------------------- absence --

/// A bootstrap with no `node` at all -- the overwhelming majority of configs --
/// must come through with BOTH surfaces off, not a guessed default.
#[test]
fn absent_node_leaves_both_surfaces_unset() {
    let snapshot = snapshot_from("static_resources:\n  listeners: []\n").expect("must lower");
    assert_eq!(snapshot.tracing, None);
    assert_eq!(snapshot.metrics, None);
}

/// A `node.metadata` that never sets either namespace (absent, or set only to
/// unrelated keys) must also leave BOTH surfaces off.
#[test]
fn unrelated_node_metadata_leaves_both_surfaces_unset() {
    let yaml = r#"
node:
  id: my-node
  metadata:
    some.other.namespace:
      anything: "goes here"
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert_eq!(snapshot.tracing, None);
    assert_eq!(snapshot.metrics, None);
}

/// A namespace that is present but not an object is a hard error. Silently
/// treating a malformed metrics block as "metrics off" is the exact failure
/// mode AGENTS.md invariant 1 exists to prevent: the operator wrote the block, so
/// something must have been meant by it.
#[test]
fn non_object_namespace_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics: "http://localhost:4317"
"#;
    let err = snapshot_from(yaml).expect_err("a scalar namespace must not load");
    assert_eq!(err_path(&err), METRICS_PATH);
}

// --------------------------------------------------- endpoint and defaults --

/// The full shape, every field explicit.
#[test]
fn full_shape_lowers_with_explicit_interval_and_deadline() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://collector:4317"
      service_name: "my-gateway"
      export_interval: 30
      export_deadline: 5
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert_eq!(
        snapshot.metrics,
        Some(MetricsExportConfig {
            otlp_endpoint: "http://collector:4317".to_string(),
            service_name: "my-gateway".to_string(),
            // A `Struct` number is plain seconds, so `30` means 30s -- and the
            // fractional form below proves the conversion is not integer-only.
            export_interval: Duration::from_secs(30),
            export_deadline: Duration::from_secs(5),
        })
    );
}

/// Sub-second values must survive intact. A `0.5` deadline is a perfectly
/// ordinary thing to want against a fast local collector, and rounding it to
/// zero would make the exporter time out on every single tick.
#[test]
fn fractional_seconds_are_preserved() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://collector:4317"
      export_interval: 2.5
      export_deadline: 0.5
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let metrics = snapshot.metrics.expect("configured");
    assert_eq!(metrics.export_interval, Duration::from_millis(2_500));
    assert_eq!(metrics.export_deadline, Duration::from_millis(500));
}

/// Only `otlp_endpoint` is required; the other three have their own defaults.
#[test]
fn service_name_and_durations_default() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://collector:4317"
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert_eq!(
        snapshot.metrics,
        Some(MetricsExportConfig {
            otlp_endpoint: "http://collector:4317".to_string(),
            service_name: "llm-proxy".to_string(),
            export_interval: Duration::from_secs(15),
            export_deadline: Duration::from_secs(10),
        })
    );
}

/// AGENTS.md invariant 1: a missing endpoint is a hard error naming the exact field,
/// not a namespace silently treated as absent.
#[test]
fn missing_otlp_endpoint_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics: {}
"#;
    let err = snapshot_from(yaml).expect_err("a missing otlp_endpoint must not load");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.otlp_endpoint"));
}

/// An empty string is treated the same as missing -- there is no sensible
/// destination to guess, same as the tracing namespace's identical check.
#[test]
fn empty_otlp_endpoint_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: ""
"#;
    let err = snapshot_from(yaml).expect_err("an empty otlp_endpoint must not load");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.otlp_endpoint"));
}

// ------------------------------------------------------------- durations --

/// An unknown key under the namespace is a hard error. The reflective surface
/// walk cannot see into a `Struct`, so this hand-written parse is the only
/// place AGENTS.md invariant 1 can be enforced for it -- a typo'd `interval:` must not
/// load as "export_interval not set" and then get the default.
#[test]
fn unknown_key_under_the_metrics_namespace_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      interval: 30
"#;
    let err = snapshot_from(yaml).expect_err("an unknown key must not load");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.interval"));
}

/// A `0` interval is rejected rather than read as "export every 0 seconds".
/// `Duration::from_secs_f64(0)` is legal, so nothing downstream would have
/// complained -- the interval would simply be zero and `tokio::time::interval`
/// would panic on the control runtime, taking the whole proxy down. Catching
/// it at config load is the difference between a bad config file and a dead
/// process.
#[test]
fn zero_interval_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_interval: 0
"#;
    let err = snapshot_from(yaml).expect_err("a zero interval must not load");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.export_interval"));
}

/// The P1 review finding: a huge but perfectly FINITE value. `1e100` passes
/// `is_finite`, passes the positivity check, and would reach
/// `Duration::from_secs_f64` -- which PANICS on overflow, not on NaN or
/// infinity alone. That panic aborted config load with exit code 101, turning
/// a typo into a dead process, exactly the class of bug the checks around it
/// exist to prevent. `try_from_secs_f64` must turn it into a dotted-path error
/// instead.
///
/// This test is the regression pin, and it was reproduced against the real
/// binary before the fix (`--mode validate` aborted); after it, config load
/// fails as configuration and the process lives.
#[test]
fn huge_finite_interval_is_a_hard_error_not_a_panic() {
    for huge in ["1.0e100", "1e308", "1.7976931348623157e308"] {
        let yaml = format!(
            r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_interval: {huge}
"#
        );
        let err = snapshot_from(&yaml).expect_err("{huge} must not load and must not panic");
        assert_eq!(
            err_path(&err),
            &format!("{METRICS_PATH}.export_interval"),
            "huge={huge}"
        );
    }
}

/// The same overflow band is reachable through `export_deadline`, and must be
/// rejected there too -- the conversion helper is shared, but the field name in
/// the error has to be the one the operator actually wrote.
#[test]
fn huge_finite_deadline_is_a_hard_error_not_a_panic() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_deadline: 1.0e100
"#;
    let err = snapshot_from(yaml).expect_err("1e100 deadline must not load and must not panic");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.export_deadline"));
}

/// Same reasoning, negative side. `from_secs_f64` PANICS on a negative value
/// rather than returning an error, so this check is what keeps a negative
/// config value from aborting the process at snapshot-build time.
#[test]
fn negative_interval_is_a_hard_error_not_a_panic() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_interval: -5
"#;
    let err = snapshot_from(yaml).expect_err("a negative interval must not load");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.export_interval"));
}

/// A non-finite number. `Struct` numbers are `f64`, so YAML `.inf`/`.nan` reach
/// this parser; `Duration::from_secs_f64` panics on both, and neither is a
/// thing an operator can debug from a proxy log line.
#[test]
fn non_finite_interval_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_interval: .inf
"#;
    let err = snapshot_from(yaml).expect_err("a non-finite interval must not load");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.export_interval"));
}

/// A string where a number belongs. A `"30s"` here is a genuine operator
/// mistake -- this surface is plain seconds -- and it must say so rather than
/// falling back to the default.
#[test]
fn string_interval_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_interval: "30s"
"#;
    let err = snapshot_from(yaml).expect_err("a string interval must not load");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.export_interval"));
}

/// Below the 1s floor. The reason is documented on the constant: a `0.1` typo
/// would otherwise turn the exporter into a busy loop shipping a full
/// cumulative snapshot ten times a second.
#[test]
fn sub_second_interval_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_interval: 0.1
"#;
    let err = snapshot_from(yaml).expect_err("a sub-second interval must not load");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.export_interval"));
}

/// Above the 1h ceiling, for the same reason in the other direction: `86400`
/// (a "once a day" reading of a field the operator may have assumed was
/// milliseconds, or a fat-fingered `60`) would silently disable metric export
/// for a day at a time.
#[test]
fn interval_above_the_ceiling_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_interval: 86400
"#;
    let err = snapshot_from(yaml).expect_err("an over-long interval must not load");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.export_interval"));
}

/// The load-bearing cross-field rule. A deadline at or above the interval is a
/// configuration that cannot do what it looks like it does: every tick's export
/// is abandoned as a timeout before the next one is even due. The error names
/// `export_deadline` because that is the field the operator must change, but
/// the message has to state the relationship or they will simply re-pick a
/// number.
#[test]
fn deadline_at_or_above_the_interval_is_a_hard_error() {
    for deadline in ["10", "11", "3600"] {
        let yaml = format!(
            r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_interval: 10
      export_deadline: {deadline}
"#
        );
        let err = snapshot_from(&yaml).expect_err("deadline >= interval must not load");
        assert_eq!(
            err_path(&err),
            &format!("{METRICS_PATH}.export_deadline"),
            "deadline={deadline}"
        );
    }
}

/// The same rule when the interval is the defaulted one, so a config that sets
/// ONLY `export_deadline: 30` (against a 15s default interval) is caught. This
/// is the case a naive implementation gets wrong by comparing against the
/// default only when the interval was explicitly set.
#[test]
fn deadline_above_the_defaulted_interval_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_deadline: 30
"#;
    let err = snapshot_from(yaml).expect_err("30s deadline vs 15s default must not load");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.export_deadline"));
}

/// Below the 100ms floor: a deadline that tight would expire on a healthy
/// collector over a slow network, turning metric export off entirely while
/// looking correctly configured.
#[test]
fn sub_100ms_deadline_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_interval: 10
      export_deadline: 0.05
"#;
    let err = snapshot_from(yaml).expect_err("a 50ms deadline must not load");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.export_deadline"));
}

/// A zero deadline is a subset of the positive check, but pinned separately
/// because it is the shape an operator reaches for when they mean "give up
/// immediately" -- and a zero `tokio::time::timeout` would expire before the
/// request was even sent, producing an infinite failure loop.
#[test]
fn zero_deadline_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_interval: 10
      export_deadline: 0
"#;
    let err = snapshot_from(yaml).expect_err("a zero deadline must not load");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.export_deadline"));
}

// ------------------------------------------------------------- boundaries --

/// The exact floor and ceiling both load. A bounds check written with `<` or
/// `>` instead of `<=`/`>=` would silently reject a legitimate configuration
/// and nothing else in this file would notice.
#[test]
fn interval_bounds_are_inclusive() {
    for interval in ["1", "3600"] {
        let yaml = format!(
            r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_interval: {interval}
      export_deadline: 0.5
"#
        );
        snapshot_from(&yaml).unwrap_or_else(|err| panic!("{interval}s must load, got: {err}"));
    }
}

/// A non-string `service_name` is rejected with its own path rather than
/// falling back to the default.
#[test]
fn non_string_service_name_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      service_name: 42
"#;
    let err = snapshot_from(yaml).expect_err("a numeric service_name must not load");
    assert_eq!(err_path(&err), &format!("{METRICS_PATH}.service_name"));
}

// --------------------------------------------------- xDS carry-forward --

/// `ConfigSnapshot::with_dynamic_resources` carries `metrics` forward
/// unchanged, exactly as it does `tracing`. Both are bootstrap-scoped (a
/// collector endpoint), not xDS resources, so an LDS/CDS/RDS delivery must not
/// be able to wipe them. Without this in the struct literal, the field would
/// silently become `None` on the first xDS response.
#[test]
fn dynamic_resources_carry_the_metrics_config_forward() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://collector:4317"
static_resources:
  listeners: []
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let carried = snapshot.with_dynamic_resources(
        Default::default(),
        Default::default(),
        Default::default(),
        SnapshotVersion(2),
    );
    assert_eq!(
        carried.metrics, snapshot.metrics,
        "a dynamic-resources assembly must not drop the metrics endpoint"
    );
    assert_eq!(carried.version, SnapshotVersion(2));
}
