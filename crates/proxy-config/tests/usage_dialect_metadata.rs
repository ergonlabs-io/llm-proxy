//! `Cluster.metadata.filter_metadata["io.llmproxy.usage"]` ->
//! `ClusterConfig.usage_dialect`. A known instance of AGENTS.md invariant 6, and the
//! exact sibling of `provider_auth_metadata.rs`: the usage dialect is a
//! property of the provider actually dialled, so it has to ride the cluster
//! rather than the route, and Envoy has no proto field for it -- hence the
//! same `filter_metadata` smuggling channel, under its own namespace.
//!
//! Everything here is the strict-parse -> PGV -> IR pipeline a hand-written
//! Envoy config goes through, so a config that never sets this namespace
//! must be completely unaffected. Every malformed shape is a hard error
//! carrying its full dotted path (AGENTS.md invariant 1), never a silent skip.

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

/// An ordinary hand-written Envoy cluster never sets this namespace, and
/// must come through with no dialect rather than a guessed default --
/// `None` is what tells a later increment "this cluster said nothing", which
/// is different from "this cluster said openai".
#[test]
fn absent_metadata_leaves_the_usage_dialect_unset() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert_eq!(snapshot.clusters["c1"].usage_dialect, None);
    // Unset is never free (AGENTS.md "Fail-open controls").
    assert_eq!(
        snapshot.clusters["c1"].unanswered_usage,
        UnansweredUsage::Input
    );
}

/// A namespace belonging to some other consumer (including the credentials
/// one, which shares this `filter_metadata` map) must not be read as a
/// dialect, and must not trip the surface check.
#[test]
fn unrelated_metadata_namespaces_are_left_alone() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          some.other.namespace:
            anything: "goes here"
          io.llmproxy.provider_auth:
            headers:
              - key: authorization
                value: "Bearer sk-x"
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = &snapshot.clusters["c1"];
    assert_eq!(cluster.usage_dialect, None);
    // ...and the credentials namespace still works, i.e. the two readers
    // genuinely coexist on one cluster rather than one shadowing the other.
    assert_eq!(cluster.request_headers_to_add.len(), 1);
}

/// Both documented values, and the credentials namespace alongside -- the
/// real shape the `llmproxy` dialect emits for every provider.
#[test]
fn both_dialects_lower_and_coexist_with_credentials() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - key: authorization
                value: "Bearer sk-x"
          io.llmproxy.usage:
            dialect: openai
    - name: c2
      metadata:
        filter_metadata:
          io.llmproxy.usage:
            dialect: anthropic
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert_eq!(
        snapshot.clusters["c1"].usage_dialect,
        Some(UsageDialect::OpenAi)
    );
    assert_eq!(snapshot.clusters["c1"].request_headers_to_add.len(), 1);
    assert_eq!(
        snapshot.clusters["c2"].usage_dialect,
        Some(UsageDialect::Anthropic)
    );
}

/// AGENTS.md invariant 1: an unrecognized value is a hard error naming the exact
/// field, not a fallback to openai. A silent fallback here is the
/// wrong-billing bug this whole carrier exists to prevent, just relocated
/// into the loader.
#[test]
fn an_unrecognized_dialect_value_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.usage:
            dialect: gemini
"#;
    let err = snapshot_from(yaml).expect_err("an unknown dialect must not load");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.usage\"].dialect"
    );
}

/// The namespace present but empty: `dialect` is required, because a
/// namespace that says nothing is indistinguishable from a typo'd key.
#[test]
fn a_missing_dialect_key_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.usage: {}
"#;
    let err = snapshot_from(yaml).expect_err("a missing dialect must not load");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.usage\"].dialect"
    );
}

/// Wrong JSON type rather than wrong string -- `google.protobuf.Struct` will
/// happily carry a number here, so the reader has to reject it explicitly.
#[test]
fn a_non_string_dialect_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.usage:
            dialect: 7
"#;
    let err = snapshot_from(yaml).expect_err("a non-string dialect must not load");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.usage\"].dialect"
    );
}

/// An unknown key *inside* this namespace is a hard error too. The
/// reflective surface walk cannot see into a `Struct`, so this is the only
/// place AGENTS.md invariant 1 can be enforced for it -- a typo'd `dialects:` must
/// not load as "no dialect configured".
#[test]
fn an_unknown_key_under_the_usage_namespace_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.usage:
            dialect: openai
            dialects: openai
"#;
    let err = snapshot_from(yaml).expect_err("an unknown key must not load");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.usage\"].dialects"
    );
}

/// AGENTS.md invariant 6, stated as a load error: the dialect must sit on the
/// member that actually serves the request, never on the aggregate that
/// merely selects one. An aggregate rejects `metadata` outright, so a
/// dialect placed there cannot silently do nothing.
#[test]
fn a_usage_dialect_on_an_aggregate_cluster_is_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: agg
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [c1]
      metadata:
        filter_metadata:
          io.llmproxy.usage:
            dialect: openai
    - name: c1
"#;
    let err = snapshot_from(yaml).expect_err("metadata on an aggregate must not load");
    assert_eq!(err_path(&err), "static_resources.clusters[0].metadata");
}

/// `unanswered` sets what an attempt that got no response is charged; each
/// documented value lowers, and omitting it means `input`.
#[test]
fn each_unanswered_value_lowers_to_the_cluster() {
    for (value, expected) in [
        ("none", UnansweredUsage::None),
        ("input", UnansweredUsage::Input),
        ("output_cap", UnansweredUsage::OutputCap),
    ] {
        let yaml = format!(
            r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.usage:
            dialect: openai
            unanswered: {value}
"#
        );
        let snapshot = snapshot_from(&yaml).expect("must lower");
        assert_eq!(
            snapshot.clusters["c1"].unanswered_usage, expected,
            "{value}"
        );
    }
}

/// AGENTS.md invariant 1: an unrecognized `unanswered` value names its field
/// rather than falling back to a default charge.
#[test]
fn an_unrecognized_unanswered_value_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.usage:
            dialect: openai
            unanswered: free
"#;
    let err = snapshot_from(yaml).expect_err("an unknown value must not load");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.usage\"].unanswered"
    );
}
