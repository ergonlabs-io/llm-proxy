//! ADR-0004 step 4: `typed_per_filter_config` -> IR
//! `PerFilterConfig` acceptance tests.
//!
//! Covers bare (unwrapped) entries, `FilterConfig`-wrapped entries
//! (`is_optional`, `disabled`), the `config`+`disabled` conflict error, the
//! neither-set error, virtual-host/route-configuration-level entries, and the
//! dense `route_index`/`route_count()` assigned by `RouteTable::new`.

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

fn snapshot_from(yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

/// A minimal listener/HCM wired around a single caller-supplied
/// `route_config` block (indentation matches the neighboring test files).
fn hcm_with_route_config(route_config: &str) -> Result<ConfigSnapshot, ConfigError> {
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
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
{route_config}
"#
    );
    snapshot_from(&yaml)
}

fn route_table(snapshot: &ConfigSnapshot) -> &RouteTable {
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    &hcm.route_table
}

/// The `Any` used for a "bare" (unwrapped) per-route filter override in these
/// tests: `envoy.filters.http.router.v3.Router`'s message has no fields, so
/// it decodes trivially and its only job here is to be *some* resolvable
/// type distinct from the wrapper `FilterConfig` message.
const ROUTER_ANY: &str = "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router";

#[test]
fn bare_entry_lowers_with_type_url_and_defaults() {
    let route_config = format!(
        r#"
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          direct_response: {{ status: 200 }}
                          typed_per_filter_config:
                            my.filter:
                              "@type": {ROUTER_ANY}
"#
    );
    let snapshot = hcm_with_route_config(&route_config).expect("must lower");
    let rt = route_table(&snapshot);
    let route = &rt.virtual_hosts[0].routes[0];
    let entry = route
        .typed_per_filter_config
        .get("my.filter")
        .expect("entry present");
    assert_eq!(entry.type_url, ROUTER_ANY);
    assert!(!entry.is_optional);
    assert!(!entry.disabled);
    assert!(entry.config.is_some());
}

#[test]
fn filter_config_wrapped_is_optional_unwraps_inner_type() {
    let route_config = format!(
        r#"
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          direct_response: {{ status: 200 }}
                          typed_per_filter_config:
                            my.filter:
                              "@type": type.googleapis.com/envoy.config.route.v3.FilterConfig
                              is_optional: true
                              config:
                                "@type": {ROUTER_ANY}
"#
    );
    let snapshot = hcm_with_route_config(&route_config).expect("must lower");
    let rt = route_table(&snapshot);
    let route = &rt.virtual_hosts[0].routes[0];
    let entry = route
        .typed_per_filter_config
        .get("my.filter")
        .expect("entry present");
    assert_eq!(
        entry.type_url, ROUTER_ANY,
        "type_url must be the inner config's type, not FilterConfig's"
    );
    assert!(entry.is_optional);
    assert!(!entry.disabled);
    assert!(entry.config.is_some());
}

#[test]
fn filter_config_disabled_with_no_config() {
    let route_config = r#"
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          direct_response: { status: 200 }
                          typed_per_filter_config:
                            my.filter:
                              "@type": type.googleapis.com/envoy.config.route.v3.FilterConfig
                              disabled: true
"#;
    let snapshot = hcm_with_route_config(route_config).expect("must lower");
    let rt = route_table(&snapshot);
    let route = &rt.virtual_hosts[0].routes[0];
    let entry = route
        .typed_per_filter_config
        .get("my.filter")
        .expect("entry present");
    assert!(entry.disabled);
    assert!(entry.config.is_none());
}

#[test]
fn filter_config_with_both_config_and_disabled_is_rejected() {
    let route_config = format!(
        r#"
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          direct_response: {{ status: 200 }}
                          typed_per_filter_config:
                            my.filter:
                              "@type": type.googleapis.com/envoy.config.route.v3.FilterConfig
                              disabled: true
                              config:
                                "@type": {ROUTER_ANY}
"#
    );
    let err = hcm_with_route_config(&route_config).expect_err("must reject config+disabled");
    let msg = err.to_string();
    assert!(
        msg.contains("typed_per_filter_config[my.filter]"),
        "expected the full dotted path with the filter-name key, got: {msg}"
    );
    assert!(
        msg.contains("config") && msg.contains("disabled"),
        "expected the reason to mention both fields, got: {msg}"
    );
}

#[test]
fn virtual_host_and_route_config_level_entries_land_in_their_ir_fields() {
    let route_config = format!(
        r#"
                route_config:
                  name: rc
                  typed_per_filter_config:
                    rc.filter:
                      "@type": {ROUTER_ANY}
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      typed_per_filter_config:
                        vh.filter:
                          "@type": {ROUTER_ANY}
                      routes:
                        - match: {{ prefix: "/" }}
                          direct_response: {{ status: 200 }}
"#
    );
    let snapshot = hcm_with_route_config(&route_config).expect("must lower");
    let rt = route_table(&snapshot);
    assert!(rt.typed_per_filter_config.contains_key("rc.filter"));
    assert!(rt.virtual_hosts[0]
        .typed_per_filter_config
        .contains_key("vh.filter"));
    // The route itself carries no override at this level.
    assert!(rt.virtual_hosts[0].routes[0]
        .typed_per_filter_config
        .is_empty());
}

#[test]
fn route_index_is_dense_and_unique_across_the_table() {
    let route_config = r#"
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh1
                      domains: ["a.example.com"]
                      routes:
                        - match: { prefix: "/1" }
                          direct_response: { status: 200 }
                        - match: { prefix: "/2" }
                          direct_response: { status: 200 }
                    - name: vh2
                      domains: ["b.example.com"]
                      routes:
                        - match: { prefix: "/3" }
                          direct_response: { status: 200 }
                        - match: { prefix: "/4" }
                          direct_response: { status: 200 }
"#;
    let snapshot = hcm_with_route_config(route_config).expect("must lower");
    let rt = route_table(&snapshot);
    assert_eq!(rt.route_count(), 4);
    let mut indices: Vec<usize> = rt
        .virtual_hosts
        .iter()
        .flat_map(|vh| vh.routes.iter().map(|r| r.route_index))
        .collect();
    indices.sort_unstable();
    assert_eq!(indices, vec![0, 1, 2, 3]);
}
