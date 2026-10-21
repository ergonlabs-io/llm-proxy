//! Virtual-host metadata `io.llmproxy.routing_headers` turns on the routing
//! response headers (`envoy-divergences.md` row 49). Envoy has no such field,
//! so the strict loader lowers the one accepted form onto every route of the
//! virtual host and refuses everything else with its path.

use proxy_config::ir::{ConfigSnapshot, NetworkFilterSpec};
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

const VHOST_PATH: &str = "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.route_config.virtual_hosts[0]";

fn snapshot_with_vhost_metadata(metadata: &str) -> Result<ConfigSnapshot, ConfigError> {
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
                      domains: ["*"]{metadata}
                      routes:
                        - {{ match: {{ prefix: "/a" }}, direct_response: {{ status: 200 }} }}
                        - {{ match: {{ prefix: "/b" }}, direct_response: {{ status: 200 }} }}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
"#
    );
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

fn metadata(body: &str) -> String {
    format!(
        "\n                      metadata:\n                        filter_metadata:\n                          io.llmproxy.routing_headers: {body}"
    )
}

fn route_flags(snapshot: &ConfigSnapshot) -> Vec<bool> {
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    hcm.route_table.virtual_hosts[0]
        .routes
        .iter()
        .map(|route| route.include_routing_headers_in_response)
        .collect()
}

#[test]
fn enabled_reaches_every_route_of_the_vhost_and_absence_keeps_it_off() {
    let on = snapshot_with_vhost_metadata(&metadata("{ enabled: true }")).expect("enabled loads");
    assert_eq!(route_flags(&on), [true, true]);
    let off = snapshot_with_vhost_metadata("").expect("plain vhost");
    assert_eq!(route_flags(&off), [false, false]);
}

/// `false`, another key, a non-boolean and a missing `enabled` are refused
/// with their own path rather than read as "off".
#[test]
fn every_other_shape_is_refused_with_its_path() {
    let key = format!("{VHOST_PATH}.metadata.filter_metadata[\"io.llmproxy.routing_headers\"]");
    for (body, expected) in [
        ("{ enabled: false }", format!("{key}.enabled")),
        ("{ enabled: \"yes\" }", format!("{key}.enabled")),
        ("{}", format!("{key}.enabled")),
        ("{ enabled: true, hosts: true }", format!("{key}.hosts")),
    ] {
        let err = snapshot_with_vhost_metadata(&metadata(body)).expect_err(body);
        let path = match &err {
            ConfigError::InvalidValue { field_path, .. }
            | ConfigError::UnsupportedField { field_path, .. } => field_path.clone(),
            other => panic!("unexpected error {other:?}"),
        };
        assert_eq!(path, expected, "{body}");
    }
}
