//! The IR surface for EDS clusters, and nothing else.
//!
//! These tests cover config lowering only: EDS clusters lower to IR, while
//! unsupported fields fail with their dotted paths (AGENTS.md invariant 1).

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

/// Build a minimal bootstrap with one cluster named `eds_cluster` whose body
/// (`type`, `eds_cluster_config`, `load_assignment`, ...) is supplied by the
/// caller.
fn yaml_with_eds_cluster(cluster_body: &str) -> String {
    format!(
        r#"
static_resources:
  clusters:
    - name: eds_cluster
{cluster_body}
"#
    )
}

/// A valid `eds_cluster_config`, delivered over ADS -- the only transport we
/// implement (the ADS client).
const VALID_EDS_CONFIG: &str = r#"
      type: EDS
      eds_cluster_config:
        service_name: real-provider-name
        eds_config:
          ads: {}
          resource_api_version: V3
"#;

/// An `eds_cluster_config` set, delivered over ADS, but with `service_name`
/// left unset.
const EDS_CONFIG_NO_SERVICE_NAME: &str = r#"
      type: EDS
      eds_cluster_config:
        eds_config:
          ads: {}
          resource_api_version: V3
"#;

// ------------------------------------------------------------- the happy path

/// A valid EDS cluster with an explicit `service_name` lowers to
/// `DiscoveryType::Eds`, carries that `service_name` in `eds`, and has no
/// endpoints of its own -- they arrive over EDS, not `load_assignment`.
#[test]
fn a_valid_eds_cluster_with_explicit_service_name_lowers() {
    let yaml = yaml_with_eds_cluster(VALID_EDS_CONFIG);
    let snapshot = snapshot_from(&yaml).expect("a well-formed EDS cluster must load");
    let cluster = snapshot.clusters.get("eds_cluster").expect("cluster");

    assert_eq!(cluster.discovery, DiscoveryType::Eds);
    let eds = cluster
        .eds
        .as_ref()
        .expect("eds must be Some for an EDS cluster");
    assert_eq!(eds.service_name, "real-provider-name");
    assert!(
        cluster.endpoints.is_empty(),
        "an EDS cluster's endpoints are not populated at lowering time"
    );
}

/// Envoy defaults an unset `service_name` to the cluster name.
#[test]
fn eds_cluster_config_with_unset_service_name_defaults_to_the_cluster_name() {
    let yaml = yaml_with_eds_cluster(EDS_CONFIG_NO_SERVICE_NAME);
    let snapshot = snapshot_from(&yaml).expect("a well-formed EDS cluster must load");
    let cluster = snapshot.clusters.get("eds_cluster").expect("cluster");

    let eds = cluster
        .eds
        .as_ref()
        .expect("eds must be Some for an EDS cluster");
    assert_eq!(eds.service_name, "eds_cluster");
}

// ------------------------------------------------------------------ refusals

/// Envoy requires `eds_cluster_config` on an EDS cluster; omitting it is
/// refused at its own dotted path rather than silently building a cluster
/// with no way to ever learn a host.
#[test]
fn eds_cluster_without_eds_cluster_config_is_rejected() {
    let yaml = yaml_with_eds_cluster("      type: EDS\n");
    let err = snapshot_from(&yaml).expect_err("eds_cluster_config is required for type: EDS");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].eds_cluster_config"
    );
}

/// `eds_cluster_config` present but its `eds_config` unset is refused --
/// without it there's no channel to ever ask for endpoints.
#[test]
fn eds_cluster_config_without_eds_config_is_rejected() {
    let yaml = yaml_with_eds_cluster(
        r#"
      type: EDS
      eds_cluster_config:
        service_name: real-provider-name
"#,
    );
    let err = snapshot_from(&yaml).expect_err("eds_cluster_config.eds_config is required");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].eds_cluster_config.eds_config"
    );
}

/// `eds_config` set to anything other than ADS is a different xDS transport
/// we do not implement -- refused naming exactly which specifier was found,
/// the same reasoning `check_ads_source` already applies to
/// `dynamic_resources`'s per-type ConfigSources.
#[test]
fn eds_config_set_to_a_filesystem_source_instead_of_ads_is_rejected() {
    let yaml = yaml_with_eds_cluster(
        r#"
      type: EDS
      eds_cluster_config:
        eds_config:
          path: /etc/envoy/eds.yaml
          resource_api_version: V3
"#,
    );
    let err = snapshot_from(&yaml).expect_err("only ADS-delivered EDS is implemented");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].eds_cluster_config.eds_config.path_config_source.path"
    );
}

/// An EDS cluster that also carries a non-empty `load_assignment` is
/// rejected -- those endpoints would be silently ignored in favour of the
/// EDS-delivered set, AGENTS.md invariant 1's exact shape.
#[test]
fn eds_cluster_with_a_non_empty_load_assignment_is_rejected() {
    let yaml = yaml_with_eds_cluster(
        r#"
      type: EDS
      eds_cluster_config:
        eds_config:
          ads: {}
          resource_api_version: V3
      load_assignment:
        cluster_name: eds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.1, port_value: 443 } }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("load_assignment on an EDS cluster is rejected");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].load_assignment"
    );
}

// ----------------------------------------------------------------- regression

/// A non-EDS cluster's `eds` field stays `None` -- the field is not
/// populated for STATIC/STRICT_DNS/LOGICAL_DNS discovery.
#[test]
fn a_static_cluster_has_no_eds_config() {
    let yaml = r#"
static_resources:
  clusters:
    - name: static_cluster
      type: STATIC
      load_assignment:
        cluster_name: static_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.1, port_value: 443 } }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("static_cluster").expect("cluster");
    assert_eq!(cluster.discovery, DiscoveryType::Static);
    assert!(cluster.eds.is_none());
}
