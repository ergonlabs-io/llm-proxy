//! `Cluster.metadata.filter_metadata["io.llmproxy.provider_auth"]`
//! -> `ClusterConfig.request_headers_to_add`. This is the surface the
//! `llmproxy` dialect uses to smuggle provider credentials onto the CLUSTER
//! (see `ClusterConfig::request_headers_to_add`'s doc comment in
//! `proxy-config/src/ir.rs` for why they can no longer live on the route),
//! since Envoy has no proto field for per-provider auth headers and the
//! dialect lowers through this identical strict-parse -> PGV -> IR pipeline.
//!
//! A hand-written Envoy config that never sets this namespace must be
//! completely unaffected -- covered here alongside the malformed-shape
//! cases, which must all be hard errors (AGENTS.md invariant 1).

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

/// No `metadata` at all: an ordinary hand-written Envoy cluster is unaffected.
#[test]
fn absent_metadata_leaves_request_headers_to_add_empty() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert!(cluster.request_headers_to_add.is_empty());
}

/// `metadata` present, but no `io.llmproxy.provider_auth` namespace: still
/// empty, and a namespace belonging to some other consumer must not trip
/// the surface check (AGENTS.md invariant 1 rejects unknown *fields*, not unknown
/// map entries under an allowed field).
#[test]
fn unrelated_metadata_namespace_is_left_alone() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          some.other.namespace:
            anything: "goes here"
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert!(cluster.request_headers_to_add.is_empty());
}

/// The documented shape: `headers: [{key, value}, ...]`, all lowered to
/// `OverwriteIfExistsOrAdd`.
#[test]
fn provider_auth_headers_lower_to_cluster_request_headers_to_add() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - { key: authorization, value: "Bearer sk-test" }
              - { key: anthropic-version, value: "2023-06-01" }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert_eq!(cluster.request_headers_to_add.len(), 2);
    assert_eq!(cluster.request_headers_to_add[0].key, "authorization");
    assert_eq!(cluster.request_headers_to_add[0].value, "Bearer sk-test");
    assert_eq!(
        cluster.request_headers_to_add[0].action,
        HeaderAppendAction::OverwriteIfExistsOrAdd
    );
    assert_eq!(cluster.request_headers_to_add[1].key, "anthropic-version");
    assert_eq!(cluster.request_headers_to_add[1].value, "2023-06-01");
}

/// `headers` missing entirely under the namespace: an empty (not absent)
/// namespace is treated the same as "no headers".
#[test]
fn provider_auth_with_no_headers_key_is_empty() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth: {}
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert!(cluster.request_headers_to_add.is_empty());
}

/// A sub-key other than `headers` under the namespace is a hard error with
/// its full dotted path -- AGENTS.md invariant 1: a typo here must never silently
/// mean "no auth header".
#[test]
fn unknown_sub_key_under_provider_auth_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers: []
            extra_stuff: true
"#;
    let err = snapshot_from(yaml).expect_err("unknown sub-key must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].extra_stuff"
    );
}

/// `headers` set to something other than a list is a hard error.
#[test]
fn non_list_headers_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers: "not a list"
"#;
    let err = snapshot_from(yaml).expect_err("non-list headers must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].headers"
    );
}

/// A `headers` entry that isn't an object is a hard error.
#[test]
fn non_object_header_entry_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers: ["not an object"]
"#;
    let err = snapshot_from(yaml).expect_err("non-object entry must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].headers[0]"
    );
}

/// A `headers` entry missing `value` is a hard error, not a header with an
/// empty value.
#[test]
fn header_entry_missing_value_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - { key: authorization }
"#;
    let err = snapshot_from(yaml).expect_err("missing value must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].headers[0].value"
    );
}

/// A `headers` entry with a non-string `key` is a hard error.
#[test]
fn header_entry_non_string_key_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - { key: 123, value: "x" }
"#;
    let err = snapshot_from(yaml).expect_err("non-string key must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].headers[0].key"
    );
}

/// A `headers` entry with an unrecognized sub-key (typo'd `keys`, say) is a
/// hard error rather than silently ignoring the typo and emitting no header.
#[test]
fn header_entry_unknown_sub_key_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - { key: authorization, value: "x", extra: "y" }
"#;
    let err = snapshot_from(yaml).expect_err("unknown sub-key must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].headers[0].extra"
    );
}
