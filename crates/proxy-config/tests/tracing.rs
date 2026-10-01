//! WP-51 increment 3 acceptance tests: config surface only.
//!
//! Two front doors, and this file tests both:
//! - `Bootstrap.node.metadata["io.llmproxy.tracing"]` -> `ConfigSnapshot.tracing`
//!   (the carrier the `llmproxy` dialect actually uses -- see
//!   `convert_tracing_metadata` in `lower.rs` for why `Node.metadata`, a real
//!   Envoy field, stands in for the real-but-unmapped
//!   `HttpConnectionManager.tracing.provider`);
//! - `HttpConnectionManager.tracing` itself, which Envoy mode rejects outright
//!   with a dotted path rather than mapping (the tracer extension proto isn't
//!   compiled into the descriptor pool -- see `convert_hcm`'s comment).
//!
//! Everything here is the strict-parse -> PGV -> IR pipeline a hand-written
//! Envoy config goes through, so a config that never sets either surface must
//! be completely unaffected. Every malformed shape is a hard error carrying
//! its full dotted path (ground rule #1), never a silent skip.

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

/// A bootstrap with no `node` at all -- the overwhelming majority of configs
/// today -- must come through with tracing off, not a guessed default.
#[test]
fn absent_node_leaves_tracing_unset() {
    let yaml = r#"
static_resources:
  listeners: []
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert_eq!(snapshot.tracing, None);
}

/// A `node.metadata` that never sets this namespace (including one that's
/// entirely absent, or sets only unrelated keys) must also leave tracing off.
#[test]
fn unrelated_node_metadata_is_left_alone() {
    let yaml = r#"
node:
  id: my-node
  metadata:
    some.other.namespace:
      anything: "goes here"
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert_eq!(snapshot.tracing, None);
}

/// The full shape the dialect emits: all three fields set explicitly.
#[test]
fn full_shape_lowers() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://localhost:4317"
      service_name: "my-gateway"
      sample_ratio: 0.5
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert_eq!(
        snapshot.tracing,
        Some(TracingConfig {
            otlp_endpoint: "http://localhost:4317".to_string(),
            service_name: "my-gateway".to_string(),
            sample_ratio: 0.5,
            export_deadline: std::time::Duration::from_secs(5),
        })
    );
}

/// `service_name` and `sample_ratio` are both optional, with their own
/// defaults -- only `otlp_endpoint` is required.
#[test]
fn service_name_and_sample_ratio_default() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://collector:4317"
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert_eq!(
        snapshot.tracing,
        Some(TracingConfig {
            otlp_endpoint: "http://collector:4317".to_string(),
            service_name: "llm-proxy".to_string(),
            sample_ratio: 1.0,
            export_deadline: std::time::Duration::from_secs(5),
        })
    );
}

/// Ground rule #1: a missing `otlp_endpoint` is a hard error naming the exact
/// field, not a namespace silently treated as absent -- the operator wrote
/// `io.llmproxy.tracing`, so something must have been meant by it.
#[test]
fn missing_otlp_endpoint_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing: {}
"#;
    let err = snapshot_from(yaml).expect_err("a missing otlp_endpoint must not load");
    assert_eq!(
        err_path(&err),
        "node.metadata[\"io.llmproxy.tracing\"].otlp_endpoint"
    );
}

/// An empty string is treated the same as missing -- there is no sensible
/// destination to guess, same as `auth.hmac_secret`'s empty-string check in
/// the dialect.
#[test]
fn empty_otlp_endpoint_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: ""
"#;
    let err = snapshot_from(yaml).expect_err("an empty otlp_endpoint must not load");
    assert_eq!(
        err_path(&err),
        "node.metadata[\"io.llmproxy.tracing\"].otlp_endpoint"
    );
}

/// `sample_ratio` above 1.0 is rejected with its own dotted path.
#[test]
fn sample_ratio_above_one_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://localhost:4317"
      sample_ratio: 1.5
"#;
    let err = snapshot_from(yaml).expect_err("sample_ratio above 1.0 must not load");
    assert_eq!(
        err_path(&err),
        "node.metadata[\"io.llmproxy.tracing\"].sample_ratio"
    );
}

/// `sample_ratio` below 0.0 is rejected too -- the same check, the other
/// direction.
#[test]
fn sample_ratio_below_zero_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://localhost:4317"
      sample_ratio: -0.1
"#;
    let err = snapshot_from(yaml).expect_err("a negative sample_ratio must not load");
    assert_eq!(
        err_path(&err),
        "node.metadata[\"io.llmproxy.tracing\"].sample_ratio"
    );
}

/// An unknown key inside the namespace is a hard error too. The reflective
/// surface walk cannot see into a `Struct`, so this is the only place ground
/// rule #1 can be enforced for it -- a typo'd `endpoint:` must not load as
/// "no otlp_endpoint configured".
#[test]
fn unknown_key_under_the_tracing_namespace_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://localhost:4317"
      endpoint: "http://localhost:4317"
"#;
    let err = snapshot_from(yaml).expect_err("an unknown key must not load");
    assert_eq!(
        err_path(&err),
        "node.metadata[\"io.llmproxy.tracing\"].endpoint"
    );
}

/// `HttpConnectionManager.tracing` -- the real Envoy field -- is rejected
/// outright rather than mapped. Setting a sub-field (`random_sampling` here)
/// is caught by the generic surface walk first, since `Tracing`'s own
/// allow-list entry is `&[]` (nothing mapped) -- naming the specific
/// sub-field rather than the whole block, which is still a full dotted path
/// (ground rule #1), just a more precise one than `convert_hcm`'s own check
/// produces for the bare-block case (see `empty_hcm_tracing_block_is_rejected`
/// below).
#[test]
fn hcm_tracing_field_is_rejected() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          direct_response: { status: 200 }
                tracing:
                  random_sampling: { value: 50 }
"#;
    let err = snapshot_from(yaml).expect_err("HCM tracing must not load in Envoy mode");
    assert_eq!(
        err_path(&err),
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.tracing.random_sampling"
    );
}

/// An empty `tracing: {}` block is rejected too -- presence alone is enough,
/// independent of what (if anything) is set inside it.
#[test]
fn empty_hcm_tracing_block_is_rejected() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          direct_response: { status: 200 }
                tracing: {}
"#;
    let err = snapshot_from(yaml).expect_err("even an empty HCM tracing block must not load");
    assert_eq!(
        err_path(&err),
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.tracing"
    );
}

// ------------------------------------------ WP-51 increment 4: export deadline --

/// The default when the field is absent: 5s, matching the fixed batch
/// interval. Present in the IR so the exporter always has a bounded RPC --
/// a deadline that had to be configured would be a deadline that usually
/// wasn't.
#[test]
fn export_deadline_defaults_to_five_seconds() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://localhost:4317"
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert_eq!(
        snapshot.tracing.expect("configured").export_deadline,
        std::time::Duration::from_secs(5)
    );
}

/// An explicit deadline lowers through.
#[test]
fn export_deadline_lowers_when_set() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://localhost:4317"
      export_deadline: 2
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert_eq!(
        snapshot.tracing.expect("configured").export_deadline,
        std::time::Duration::from_secs(2)
    );
}

/// Below the 100ms floor. A deadline that tight would expire against a healthy
/// collector on a slow network, turning trace export off entirely while
/// looking correctly configured -- the same reasoning as the metric side's
/// identical floor.
#[test]
fn export_deadline_below_the_floor_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://localhost:4317"
      export_deadline: 0.05
"#;
    let err = snapshot_from(yaml).expect_err("a 50ms deadline must not load");
    assert_eq!(
        err_path(&err),
        "node.metadata[\"io.llmproxy.tracing\"].export_deadline"
    );
}

/// Above the 60s ceiling -- the value the exporter module itself publishes as
/// its sane maximum, so loader and exporter cannot drift. A deadline longer
/// than several batch cycles would let a wedged export hold batches in memory
/// across multiple cycles before being abandoned.
#[test]
fn export_deadline_above_the_ceiling_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://localhost:4317"
      export_deadline: 120
"#;
    let err = snapshot_from(yaml).expect_err("a 120s deadline must not load");
    assert_eq!(
        err_path(&err),
        "node.metadata[\"io.llmproxy.tracing\"].export_deadline"
    );
}

/// A non-number deadline is rejected with its own path rather than falling
/// back to the default.
#[test]
fn non_numeric_export_deadline_is_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://localhost:4317"
      export_deadline: "5s"
"#;
    let err = snapshot_from(yaml).expect_err("a string deadline must not load");
    assert_eq!(
        err_path(&err),
        "node.metadata[\"io.llmproxy.tracing\"].export_deadline"
    );
}

/// The huge-finite case the metrics side panicked on before the P1 fix. The
/// trace path shares the same `seconds_to_duration` helper, so it inherits the
/// fix -- this test pins that inheritance, since the two surfaces are easy to
/// assume independent and the panic was originally reproduced only through the
/// metrics field.
#[test]
fn huge_finite_export_deadline_is_a_hard_error_not_a_panic() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://localhost:4317"
      export_deadline: 1.0e100
"#;
    let err = snapshot_from(yaml).expect_err("1e100 must not load and must not panic");
    assert_eq!(
        err_path(&err),
        "node.metadata[\"io.llmproxy.tracing\"].export_deadline"
    );
}

/// An unknown key alongside the new field is still a hard error -- adding
/// `export_deadline` to the accepted set must not have loosened the strict
/// walk for everything else.
#[test]
fn unknown_key_beside_export_deadline_is_still_a_hard_error() {
    let yaml = r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "http://localhost:4317"
      export_deadline: 2
      endpoint: "http://localhost:4317"
"#;
    let err = snapshot_from(yaml).expect_err("an unknown key must not load");
    assert_eq!(
        err_path(&err),
        "node.metadata[\"io.llmproxy.tracing\"].endpoint"
    );
}
