//! WP-20 increment 1 acceptance tests: the ADS config surface, and nothing
//! else. No client, no gRPC, no networking -- this increment only teaches the
//! loader to accept a bootstrap that points at a control plane, and to refuse
//! every part of that surface it does not implement with a full dotted path.
//!
//! **The refusals are the substance of this file, not an afterthought.** Before
//! this increment, `dynamic_resources` was a strict-mode hard error by name,
//! because `Bootstrap`'s allowed-field list contained only
//! `node`/`admin`/`static_resources` -- ground rule #1 working correctly. The
//! risk in widening that list is trading one honest refusal for several silent
//! drops, so every unimplemented member below has its own test asserting the
//! exact path an operator will see.

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

/// The ADS cluster every valid case below points at.
const XDS_CLUSTER: &str = r#"
  clusters:
    - name: xds_cluster
      type: STATIC
      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 127.0.0.1, port_value: 18000 }
"#;

fn with_ads(dynamic: &str) -> String {
    format!("node:\n  id: proxy-1\n  cluster: proxy-fleet\n{dynamic}static_resources:\n  listeners: []{XDS_CLUSTER}")
}

// ------------------------------------------------------------- the happy path

/// The whole surface, lowered. Asserts every field including the Node identity,
/// which was NOT in the IR before this increment -- `node` was previously read
/// only for `node.metadata`'s tracing key.
#[test]
fn a_full_ads_bootstrap_lowers_to_ads_config() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
  lds_config: { ads: {}, resource_api_version: V3 }
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let snap = snapshot_from(&yaml).expect("a well-formed ADS bootstrap must load");
    let ads = snap.ads.expect("dynamic_resources must lower to Some");
    assert_eq!(ads.cluster, "xds_cluster");
    assert!(ads.lds, "lds_config sets ads, so LDS is subscribed");
    assert!(ads.cds, "cds_config sets ads, so CDS is subscribed");
    assert_eq!(ads.node.id, "proxy-1");
    assert_eq!(ads.node.cluster, "proxy-fleet");
}

/// Subscribing to only one type is legal -- a control plane may serve clusters
/// while listeners stay static.
#[test]
fn cds_only_is_legal_and_leaves_lds_false() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let ads = snapshot_from(&yaml)
        .expect("CDS-only must load")
        .ads
        .unwrap();
    assert!(ads.cds);
    assert!(!ads.lds);
}

/// The back-compat case, and the one that matters most: every config shipped
/// through v0.2.0 has no `dynamic_resources` and must be completely unaffected.
#[test]
fn a_bootstrap_without_dynamic_resources_lowers_to_ads_none() {
    let yaml = format!("static_resources:\n  listeners: []{XDS_CLUSTER}");
    let snap = snapshot_from(&yaml).expect("a static bootstrap must still load");
    assert!(
        snap.ads.is_none(),
        "absent dynamic_resources must be None, never a guessed default"
    );
}

// ---------------------------------------------------------------- refusals --

#[test]
fn rest_api_type_is_refused_naming_api_type() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: REST
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("REST must be refused");
    assert_eq!(err_path(&err), "dynamic_resources.ads_config.api_type");
}

#[test]
fn delta_grpc_api_type_is_refused_naming_wp22() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: DELTA_GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("delta xDS must be refused");
    assert_eq!(err_path(&err), "dynamic_resources.ads_config.api_type");
    assert!(
        format!("{err}").contains("WP-22"),
        "the message must say which work package owns delta: {err}"
    );
}

#[test]
fn cluster_names_is_refused_as_rest_only() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    cluster_names: [xds_cluster]
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("cluster_names must be refused");
    assert_eq!(err_path(&err), "dynamic_resources.ads_config.cluster_names");
}

#[test]
fn two_grpc_services_are_refused_naming_the_count() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
      - envoy_grpc: { cluster_name: xds_cluster }
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("two services must be refused");
    assert_eq!(err_path(&err), "dynamic_resources.ads_config.grpc_services");
    assert!(format!("{err}").contains('2'), "must name the count: {err}");
}

#[test]
fn google_grpc_is_refused_pointing_at_envoy_grpc() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - google_grpc: { target_uri: "127.0.0.1:18000", stat_prefix: ads }
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("google_grpc must be refused");
    assert!(
        err_path(&err).ends_with("google_grpc"),
        "path must name google_grpc, got {}",
        err_path(&err)
    );
}

#[test]
fn rate_limit_settings_is_refused() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    rate_limit_settings: { max_tokens: 10 }
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("rate_limit_settings must be refused");
    assert_eq!(
        err_path(&err),
        "dynamic_resources.ads_config.rate_limit_settings"
    );
}

#[test]
fn set_node_on_first_message_only_is_refused() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    set_node_on_first_message_only: true
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("must be refused");
    assert_eq!(
        err_path(&err),
        "dynamic_resources.ads_config.set_node_on_first_message_only"
    );
}

/// A per-type source that is NOT ADS-backed is a separate transport. Accepting
/// it silently would mean the type is never actually subscribed.
#[test]
fn a_non_ads_per_type_source_is_refused() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
  cds_config:
    resource_api_version: V3
    api_config_source:
      api_type: GRPC
      transport_api_version: V3
      grpc_services:
        - envoy_grpc: { cluster_name: xds_cluster }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("a per-type api_config_source must be refused");
    assert!(
        err_path(&err).starts_with("dynamic_resources.cds_config"),
        "path must name the offending source, got {}",
        err_path(&err)
    );
}

/// EDS needs an IR discovery variant that does not exist; WP-21 owns adding it.
#[test]
fn a_filesystem_source_is_refused_naming_wp22() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
  cds_config: { path: /etc/xds/cds.yaml, resource_api_version: V3 }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("filesystem xDS must be refused");
    assert!(
        format!("{err}").contains("WP-22"),
        "must name the owning work package: {err}"
    );
}

#[test]
fn xdstp_resource_locators_are_refused() {
    let yaml = with_ads(
        r#"dynamic_resources:
  lds_resources_locator: "xdstp://foo/bar"
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("xdstp:// must be refused");
    assert_eq!(err_path(&err), "dynamic_resources.lds_resources_locator");
}

/// `ads_config` with nothing subscribed would open a stream and request
/// nothing -- a config that looks configured and does nothing.
#[test]
fn ads_config_with_no_subscriptions_is_refused() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("no subscriptions must be refused");
    assert_eq!(err_path(&err), "dynamic_resources.ads_config");
}

/// Per-type sources without an `ads_config` to stream them on.
#[test]
fn per_type_sources_without_ads_config_are_refused() {
    let yaml = with_ads(
        r#"dynamic_resources:
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("must be refused");
    assert_eq!(err_path(&err), "dynamic_resources.ads_config");
}

// ------------------------------------------- the cluster-existence check ----

/// The proto is explicit: "The cluster with name `cluster_name` must be
/// statically defined." Without this check the failure would surface as a
/// connection error at runtime instead of a config error at load.
#[test]
fn an_ads_cluster_missing_from_static_resources_is_refused_by_name() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: not_declared }
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("an undeclared ADS cluster must be refused");
    assert_eq!(
        err_path(&err),
        "dynamic_resources.ads_config.grpc_services[0].envoy_grpc.cluster_name"
    );
    assert!(
        format!("{err}").contains("not_declared"),
        "the message must name the missing cluster: {err}"
    );
}

/// The same check, on the path where there are no static resources at all --
/// which would otherwise return early and skip it entirely.
#[test]
fn an_ads_cluster_with_no_static_resources_at_all_is_refused() {
    let yaml = r#"
dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
  cds_config: { ads: {}, resource_api_version: V3 }
"#;
    let err = snapshot_from(yaml).expect_err("no static_resources must be refused");
    assert_eq!(
        err_path(&err),
        "dynamic_resources.ads_config.grpc_services[0].envoy_grpc.cluster_name"
    );
}

/// Reached before our own check: the PGV validation engine (WP-04) already
/// enforces `min_len: 1` on this field from the proto's own constraints, so it
/// fires first and with a different `ConfigError` variant. Asserted on the
/// rendered message rather than the variant, because which layer refuses is an
/// implementation detail -- what an operator needs is the dotted path. The
/// explicit empty-name arm in `convert_ads_grpc_service` is therefore
/// defensive, not load-bearing; it matters only if that field is ever reached
/// from a non-PGV path.
#[test]
fn an_empty_ads_cluster_name_is_refused() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: "" }
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let err = snapshot_from(&yaml).expect_err("an empty cluster name must be refused");
    let rendered = format!("{err}");
    assert!(
        rendered.contains("grpc_services[0].envoy_grpc.cluster_name"),
        "the error must carry the full dotted path, got: {rendered}"
    );
}
