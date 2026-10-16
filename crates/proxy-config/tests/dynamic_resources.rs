//! Tests the ADS bootstrap config surface without starting a client or network
//! connection. Supported fields lower; unsupported fields fail with dotted paths.

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
    assert_eq!(ads.cluster.as_deref(), Some("xds_cluster"));
    assert_eq!(ads.protocol, proxy_config::ir::AdsProtocol::Sotw);
    assert!(ads.lds, "lds_config sets ads, so LDS is subscribed");
    assert!(ads.cds, "cds_config sets ads, so CDS is subscribed");
    assert_eq!(ads.node.id, "proxy-1");
    assert_eq!(ads.node.cluster, "proxy-fleet");
}

#[test]
fn a_filesystem_lds_source_lowers_without_an_ads_cluster() {
    let yaml = r#"dynamic_resources:
  lds_config:
    path: Cargo.toml
    resource_api_version: V3
static_resources:
  listeners: []
"#;
    let ads = snapshot_from(yaml)
        .expect("filesystem source must lower")
        .ads
        .expect("filesystem dynamic resources must produce AdsConfig");
    assert_eq!(ads.cluster, None);
    assert_eq!(ads.cds_source, None);
    assert!(matches!(
        ads.lds_source,
        Some(DiscoverySource::Filesystem(_))
    ));
}

#[test]
fn lds_filesystem_and_cds_ads_sources_can_be_mixed() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
  lds_config: { path: Cargo.toml, resource_api_version: V3 }
  cds_config: { ads: {}, resource_api_version: V3 }
"#,
    );
    let ads = snapshot_from(&yaml)
        .expect("mixed filesystem and ADS sources must lower")
        .ads
        .expect("dynamic resources must be present");
    assert!(matches!(
        ads.lds_source,
        Some(DiscoverySource::Filesystem(_))
    ));
    assert_eq!(ads.cds_source, Some(DiscoverySource::Ads));
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

/// `initial_fetch_timeout` belongs to each ADS-backed `ConfigSource`, not
/// `ads_config`. The shared ADS runtime currently has one startup deadline,
/// so a sole CDS source carries its exact configured value into `AdsConfig`.
#[test]
fn cds_initial_fetch_timeout_lowers_to_ads_config() {
    let yaml = with_ads(
        r#"dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: { cluster_name: xds_cluster }
  cds_config:
    ads: {}
    resource_api_version: V3
    initial_fetch_timeout: 0.200s
"#,
    );
    let ads = snapshot_from(&yaml)
        .expect("CDS initial_fetch_timeout must load")
        .ads
        .unwrap();
    assert_eq!(
        ads.initial_fetch_timeout,
        Some(std::time::Duration::from_millis(200))
    );
}

/// Configs without `dynamic_resources` remain unaffected.
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
fn delta_grpc_api_type_selects_delta_transport() {
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
    let ads = snapshot_from(&yaml)
        .expect("delta xDS must lower")
        .ads
        .unwrap();
    assert_eq!(ads.protocol, proxy_config::ir::AdsProtocol::Delta);
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

/// EDS needs an IR discovery variant that does not exist.
#[test]
fn a_missing_filesystem_source_is_refused_by_full_path() {
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
    assert_eq!(
        err_path(&err),
        "dynamic_resources.cds_config.path_config_source.path"
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

/// PGV rejects the empty name before typed lowering; assert the operator-facing
/// dotted path independent of which validation layer reports it.
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

// --------------------------------------------- ADS transport security (H7) --

/// A bootstrap whose ADS cluster is the SECOND cluster, so the dotted path
/// must carry the right index, dialling `address`, with optional extra
/// cluster YAML (a `transport_socket`) and optional `node.metadata` YAML.
fn ads_transport_bootstrap(address: &str, cluster_extra: &str, metadata: &str) -> String {
    format!(
        r#"node:
  id: proxy-1
{metadata}dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: {{ cluster_name: xds_cluster }}
  cds_config: {{ ads: {{}}, resource_api_version: V3 }}
static_resources:
  listeners: []
  clusters:
    - name: backend
      type: STATIC
      load_assignment:
        cluster_name: backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 10.9.9.9, port_value: 80 }}
    - name: xds_cluster
      type: STRICT_DNS
{cluster_extra}      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: "{address}", port_value: 18000 }}
"#
    )
}

const ADS_TLS: &str = r#"      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: cp.example.com
"#;

const ALLOW_PLAINTEXT: &str = "  metadata:\n    io.llmproxy.ads: { allow_plaintext: true }\n";

/// The ADS channel carries provider credentials, so plaintext is accepted
/// only on loopback, with TLS configured, or with the explicit opt-in;
/// anything else fails load at the ADS cluster's `transport_socket` path
/// (envoy-divergences.md row 32).
#[test]
fn a_plaintext_ads_channel_is_refused_unless_loopback_tls_or_allowed() {
    const REFUSED: Result<bool, &str> = Err("static_resources.clusters[1].transport_socket");
    // (address, cluster extra, metadata, expected allow_plaintext or error path)
    let cases: [(&str, &str, &str, Result<bool, &str>); 8] = [
        ("10.0.0.5", "", "", REFUSED),
        ("cp.example.com", "", "", REFUSED),
        (
            "10.0.0.5",
            "",
            "  metadata:\n    io.llmproxy.ads: { allow_plaintext: false }\n",
            REFUSED,
        ),
        ("127.0.0.1", "", "", Ok(false)),
        ("::1", "", "", Ok(false)),
        ("localhost", "", "", Ok(false)),
        ("cp.example.com", ADS_TLS, "", Ok(false)),
        ("10.0.0.5", "", ALLOW_PLAINTEXT, Ok(true)),
    ];
    for (address, extra, metadata, expected) in cases {
        let yaml = ads_transport_bootstrap(address, extra, metadata);
        let result = snapshot_from(&yaml);
        match expected {
            Ok(allow) => {
                let snap =
                    result.unwrap_or_else(|e| panic!("{address} {extra:?} {metadata:?}: {e}"));
                assert_eq!(snap.ads.expect("ads").allow_plaintext, allow, "{address}");
            }
            Err(path) => {
                let err = result.expect_err(&format!("plaintext to {address} must be refused"));
                assert_eq!(err_path(&err), path, "{address}");
                let rendered = err.to_string();
                assert!(
                    rendered.contains("allow_plaintext") && rendered.contains(address),
                    "the error must name the target and the opt-in, got: {rendered}"
                );
            }
        }
    }
}

/// `node.metadata["io.llmproxy.ads"]` is opaque to the reflective surface
/// walk, so its strictness is enforced by hand: an unknown key, a wrong type,
/// or the key on a bootstrap with no ADS channel each fail with their path
/// (AGENTS.md invariant 1).
#[test]
fn the_ads_metadata_key_is_strict() {
    let cases = [
        (
            ads_transport_bootstrap(
                "10.0.0.5",
                "",
                "  metadata:\n    io.llmproxy.ads: { allow_plaintxt: true }\n",
            ),
            "node.metadata[\"io.llmproxy.ads\"].allow_plaintxt",
        ),
        (
            ads_transport_bootstrap(
                "10.0.0.5",
                "",
                "  metadata:\n    io.llmproxy.ads: { allow_plaintext: \"yes\" }\n",
            ),
            "node.metadata[\"io.llmproxy.ads\"].allow_plaintext",
        ),
        (
            format!(
                "node:\n  id: p\n{ALLOW_PLAINTEXT}static_resources:\n  listeners: []{XDS_CLUSTER}"
            ),
            "node.metadata[\"io.llmproxy.ads\"]",
        ),
    ];
    for (yaml, path) in cases {
        let err = snapshot_from(&yaml).expect_err(path);
        assert_eq!(err_path(&err), path);
    }
}
