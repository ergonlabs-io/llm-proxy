//! Acceptance tests: PGV constraint enforcement with exact field paths.
//!
//! Each case is a config Envoy itself rejects (constraints read from the
//! `validate.rules` annotations in the pinned protos). The diff rig will
//! later assert our messages against real Envoy's, byte for byte where possible.

use proxy_config::{parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

fn expect_validation_failure(yaml: &str, want_path: &str, want_rule: &str) {
    let err = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
        .expect_err("config must fail validation");
    let ConfigError::Validation { field_path, rule } = &err else {
        panic!("expected Validation error, got: {err}");
    };
    assert_eq!(field_path, want_path, "wrong path; rule was: {rule}");
    assert!(
        rule.contains(want_rule),
        "rule `{rule}` should contain `{want_rule}`"
    );
}

/// `Cluster.name` carries `string.min_len 1`: an absent name violates it —
/// PGV rules on plain proto3 scalars apply to the default value.
#[test]
fn cluster_without_name_fails() {
    expect_validation_failure(
        r#"
static_resources:
  clusters:
    - type: STATIC
"#,
        "static_resources.clusters[0].name",
        "at least 1",
    );
}

/// `Cluster.connect_timeout` carries `duration.gt 0s`.
#[test]
fn zero_connect_timeout_fails() {
    expect_validation_failure(
        r#"
static_resources:
  clusters:
    - name: c1
      connect_timeout: 0s
"#,
        "static_resources.clusters[0].connect_timeout",
        "greater than",
    );
}

/// `SocketAddress.port_value` carries `uint32.lte 65535`.
#[test]
fn out_of_range_port_fails() {
    expect_validation_failure(
        r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: { address: 0.0.0.0, port_value: 70000 }
"#,
        "static_resources.listeners[0].address.socket_address.port_value",
        "at most 65535",
    );
}

/// `TcpProxy.cluster_specifier` is a `validate.required` oneof.
#[test]
fn tcp_proxy_without_cluster_fails() {
    expect_validation_failure(
        r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: { address: 0.0.0.0, port_value: 10000 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: ingress
"#,
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.cluster_specifier",
        "required",
    );
}

/// `TcpProxy.stat_prefix` carries `string.min_len 1` — validation reaches
/// INSIDE `typed_config` Anys, like Envoy's recursive validate() calls.
#[test]
fn tcp_proxy_without_stat_prefix_fails() {
    expect_validation_failure(
        r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: { address: 0.0.0.0, port_value: 10000 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                cluster: backend
"#,
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.stat_prefix",
        "at least 1",
    );
}

/// `HttpConnectionManager.stat_prefix` carries `string.min_len 1`.
#[test]
fn hcm_without_stat_prefix_fails() {
    expect_validation_failure(
        &hcm_bootstrap(r#"{ "route_config": { "virtual_hosts": [] } }"#),
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.stat_prefix",
        "at least 1",
    );
}

/// `VirtualHost.domains` carries `repeated.min_items 1`.
#[test]
fn virtual_host_without_domains_fails() {
    expect_validation_failure(
        &hcm_bootstrap(
            r#"{ "stat_prefix": "http",
                 "route_config": { "virtual_hosts": [ { "name": "vh" } ] } }"#,
        ),
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.route_config.virtual_hosts[0].domains",
        "at least 1 item",
    );
}

/// `VirtualHost.name` carries `string.min_len 1`.
#[test]
fn virtual_host_without_name_fails() {
    expect_validation_failure(
        &hcm_bootstrap(
            r#"{ "stat_prefix": "http",
                 "route_config": { "virtual_hosts": [ { "domains": ["*"] } ] } }"#,
        ),
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.route_config.virtual_hosts[0].name",
        "at least 1",
    );
}

/// `RouteMatch.path_specifier` is a `validate.required` oneof.
#[test]
fn route_without_path_specifier_fails() {
    expect_validation_failure(
        &hcm_bootstrap(
            r#"{ "stat_prefix": "http",
                 "route_config": { "virtual_hosts": [
                   { "name": "vh", "domains": ["*"],
                     "routes": [ { "match": {}, "route": { "cluster": "c1" } } ] } ] } }"#,
        ),
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.route_config.virtual_hosts[0].routes[0].match.path_specifier",
        "required",
    );
}

/// `Route.action` is a `validate.required` oneof.
#[test]
fn route_without_action_fails() {
    expect_validation_failure(
        &hcm_bootstrap(
            r#"{ "stat_prefix": "http",
                 "route_config": { "virtual_hosts": [
                   { "name": "vh", "domains": ["*"],
                     "routes": [ { "match": { "prefix": "/" } } ] } ] } }"#,
        ),
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.route_config.virtual_hosts[0].routes[0].action",
        "required",
    );
}

/// `HeaderValue.key` carries `string.min_len 1` — via `request_headers_to_add`.
#[test]
fn empty_header_key_fails() {
    expect_validation_failure(
        &hcm_bootstrap(
            r#"{ "stat_prefix": "http",
                 "route_config": { "virtual_hosts": [
                   { "name": "vh", "domains": ["*"],
                     "routes": [ { "match": { "prefix": "/" },
                                   "route": { "cluster": "c1" },
                                   "request_headers_to_add": [
                                     { "header": { "key": "", "value": "v" } } ] } ] } ] } }"#,
        ),
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.route_config.virtual_hosts[0].routes[0].request_headers_to_add[0].header.key",
        "at least 1",
    );
}

/// `Cluster.lb_policy` carries `enum.defined_only`: unknown enum numbers are
/// rejected. (Sent as proto binary — JSON already rejects unknown enum names.)
#[test]
fn undefined_enum_number_fails() {
    use prost::Message as _;
    use proxy_api::envoy::config::bootstrap::v3::{bootstrap::StaticResources, Bootstrap};
    use proxy_api::envoy::config::cluster::v3::Cluster;

    let bootstrap = Bootstrap {
        static_resources: Some(StaticResources {
            clusters: vec![Cluster {
                name: "c1".into(),
                lb_policy: 999,
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let err = parse_bootstrap(
        &bootstrap.encode_to_vec(),
        ConfigFormat::ProtoBinary,
        StrictMode::Strict,
    )
    .expect_err("undefined enum must fail");
    let ConfigError::Validation { field_path, rule } = &err else {
        panic!("expected Validation error, got: {err}");
    };
    assert_eq!(field_path, "static_resources.clusters[0].lb_policy");
    assert!(rule.contains("not a defined value"), "got rule: {rule}");
}

/// A fully valid config passes validation (no false positives).
#[test]
fn valid_example_config_passes() {
    let yaml = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/tcp-proxy.yaml"
    ))
    .expect("read example");
    parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
        .expect("example must pass PGV validation");
}

/// Validation runs in permissive mode too: only UNKNOWN fields are forgiven,
/// never constraint violations.
#[test]
fn permissive_mode_still_validates() {
    let err = parse_bootstrap(
        b"static_resources: { clusters: [ { name: c1, connect_timeout: 0s } ] }",
        ConfigFormat::Yaml,
        StrictMode::Permissive,
    )
    .expect_err("constraint violations fail even in permissive mode");
    assert!(matches!(err, ConfigError::Validation { .. }), "got: {err}");
}

/// Bootstrap wrapping an HCM listener whose typed_config is the given JSON.
fn hcm_bootstrap(hcm_json: &str) -> String {
    let mut hcm: serde_json::Value = serde_json::from_str(hcm_json).expect("valid HCM json");
    hcm.as_object_mut().expect("object").insert(
        "@type".to_string(),
        "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager".into(),
    );
    serde_json::json!({
        "static_resources": {
            "listeners": [ {
                "name": "l1",
                "address": { "socket_address": { "address": "0.0.0.0", "port_value": 8080 } },
                "filter_chains": [ { "filters": [ {
                    "name": "envoy.filters.network.http_connection_manager",
                    "typed_config": hcm
                } ] } ]
            } ]
        }
    })
    .to_string()
}
