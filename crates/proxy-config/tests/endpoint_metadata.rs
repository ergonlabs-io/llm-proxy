//! WP-56: `LbEndpoint.metadata.filter_metadata["io.llmproxy.endpoint"]` ->
//! `EndpointIR::metadata`. See `EndpointIR::metadata`'s doc comment in
//! `proxy-config/src/ir.rs` for the design this implements: our own
//! namespace lowers to a `BTreeMap<String, String>`, and every other
//! namespace -- `envoy.lb` (Envoy's own LB subset-routing selector) most
//! deliberately -- is refused by dotted path rather than silently ignored,
//! because nothing in this proxy routes on endpoint metadata.
//!
//! The static half (`load_assignment` in a bootstrap file) is covered here;
//! the EDS half (`lower_dynamic_endpoints`) lives alongside its sibling
//! tests in `dynamic_endpoints.rs`.

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

/// No `metadata` at all: an ordinary hand-written endpoint is unaffected.
#[test]
fn absent_metadata_lowers_to_an_empty_map() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      load_assignment:
        cluster_name: c1
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 10.0.0.1, port_value: 8080 }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert!(cluster.endpoints[0].metadata.is_empty());
}

/// `metadata` present with no `filter_metadata` at all: still an empty map,
/// not an error.
#[test]
fn metadata_with_no_filter_metadata_lowers_to_an_empty_map() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      load_assignment:
        cluster_name: c1
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 10.0.0.1, port_value: 8080 }
                metadata: {}
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert!(cluster.endpoints[0].metadata.is_empty());
}

/// The documented shape: `io.llmproxy.endpoint` string fields lower straight
/// into `EndpointIR::metadata`.
#[test]
fn llmproxy_endpoint_namespace_lowers_into_endpoint_metadata() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      load_assignment:
        cluster_name: c1
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 10.0.0.1, port_value: 8080 }
                metadata:
                  filter_metadata:
                    io.llmproxy.endpoint:
                      region: us-east-1
                      rack: "12"
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    let metadata = &cluster.endpoints[0].metadata;
    assert_eq!(
        metadata.get("region").map(String::as_str),
        Some("us-east-1")
    );
    assert_eq!(metadata.get("rack").map(String::as_str), Some("12"));
    assert_eq!(metadata.len(), 2);
}

/// `envoy.lb` is Envoy's own LB subset-routing selector; this proxy
/// implements no subset routing, so it must be refused rather than
/// silently accepted into a map nothing routes on -- and the message must
/// say why, not just that it was refused.
#[test]
fn envoy_lb_namespace_is_refused_with_the_subset_routing_reason() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      load_assignment:
        cluster_name: c1
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 10.0.0.1, port_value: 8080 }
                metadata:
                  filter_metadata:
                    envoy.lb:
                      canary: "true"
"#;
    let err = snapshot_from(yaml).expect_err("envoy.lb must be refused");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].load_assignment.endpoints[0].lb_endpoints[0]\
         .metadata.filter_metadata[\"envoy.lb\"]"
    );
    let ConfigError::UnsupportedField { reason, .. } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert!(
        reason.contains("subset routing"),
        "message must explain envoy.lb is a subset-routing selector, got: {reason}"
    );
}

/// A third namespace, belonging to neither us nor Envoy's `envoy.lb`, is
/// refused by dotted path too -- this map has exactly one consumer.
#[test]
fn an_unknown_third_namespace_is_refused() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      load_assignment:
        cluster_name: c1
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 10.0.0.1, port_value: 8080 }
                metadata:
                  filter_metadata:
                    some.other.namespace:
                      anything: "goes here"
"#;
    let err = snapshot_from(yaml).expect_err("unknown namespace must be refused");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].load_assignment.endpoints[0].lb_endpoints[0]\
         .metadata.filter_metadata[\"some.other.namespace\"]"
    );
}

/// A non-string value under our namespace is a hard error naming its dotted
/// path -- never stringified, since an operator who wrote a number or bool
/// there meant something we would only be guessing at.
#[test]
fn a_non_string_value_in_our_namespace_is_refused() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      load_assignment:
        cluster_name: c1
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 10.0.0.1, port_value: 8080 }
                metadata:
                  filter_metadata:
                    io.llmproxy.endpoint:
                      weight: 5
"#;
    let err = snapshot_from(yaml).expect_err("a non-string value must be refused");
    let ConfigError::InvalidValue { field_path, reason } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(
        field_path,
        "static_resources.clusters[0].load_assignment.endpoints[0].lb_endpoints[0]\
         .metadata.filter_metadata[\"io.llmproxy.endpoint\"].weight"
    );
    assert!(reason.contains("string"), "got: {reason}");
}

/// An `LbEndpoint` field outside the allowlist -- `health_status`, which
/// `allowed_fields("envoy.config.endpoint.v3.LbEndpoint")` in `lower.rs`
/// deliberately does not list -- is still rejected by its exact dotted path.
/// This proves WP-56 widened that allowlist by exactly the one field
/// (`metadata`) it was asked to add.
#[test]
fn an_lb_endpoint_field_still_outside_the_allowlist_is_refused() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      load_assignment:
        cluster_name: c1
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 10.0.0.1, port_value: 8080 }
                health_status: HEALTHY
"#;
    let err = snapshot_from(yaml).expect_err("health_status must still be refused");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].load_assignment.endpoints[0].lb_endpoints[0].health_status"
    );
}
