//! WP-33: route metadata carries the `streaming: strict` assertion through
//! strict Envoy parsing into the IR.  The factory-capability check belongs to
//! `proxy-http`; these tests pin this config crate's half of the contract.

use proxy_config::ir::{ConfigSnapshot, NetworkFilterSpec};
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

fn snapshot_from_route(route: &str) -> Result<ConfigSnapshot, ConfigError> {
    let yaml = format!(
        r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: {{ address: 0.0.0.0, port_value: 8080 }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
{route}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
"#
    );
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

fn only_route(snapshot: &ConfigSnapshot) -> &proxy_config::ir::RouteEntry {
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    &hcm.route_table.virtual_hosts[0].routes[0]
}

#[test]
fn strict_streaming_metadata_lowers_to_a_route_assertion() {
    let snapshot = snapshot_from_route(
        r#"                        - match: { prefix: "/" }
                          direct_response: { status: 200 }
                          metadata:
                            filter_metadata:
                              io.llmproxy.streaming:
                                strict: true
"#,
    )
    .expect("strict metadata must load");
    assert!(only_route(&snapshot).streaming_strict);
}

#[test]
fn false_strict_streaming_is_rejected_not_silently_ignored() {
    let err = snapshot_from_route(
        r#"                        - match: { prefix: "/" }
                          direct_response: { status: 200 }
                          metadata:
                            filter_metadata:
                              io.llmproxy.streaming:
                                strict: false
"#,
    )
    .expect_err("false is not a supported assertion value");
    match err {
        ConfigError::InvalidValue { field_path, .. } => assert_eq!(
            field_path,
            "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.route_config.virtual_hosts[0].routes[0].metadata.filter_metadata[\"io.llmproxy.streaming\"].strict"
        ),
        other => panic!("expected an invalid-value error, got {other:?}"),
    }
}
