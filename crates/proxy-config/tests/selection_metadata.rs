//! Route metadata `io.llmproxy.selection` turns on latency-aware selection
//! for a weighted route (`envoy-divergences.md` row 48). Envoy has no such
//! field, so the strict loader must lower the one accepted form and refuse
//! everything else with its path rather than ignore it.

use proxy_config::ir::{ConfigSnapshot, ForwardTarget, NetworkFilterSpec, RouteActionIR};
use proxy_config::ir::{ForwardAction, WeightedSelection};
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

const ROUTE_PATH: &str = "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.route_config.virtual_hosts[0].routes[0]";

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
                        - match: {{ prefix: "/" }}
{route}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: a
      connect_timeout: 1s
    - name: b
      connect_timeout: 1s
"#
    );
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

const WEIGHTED: &str = r#"                          route:
                            weighted_clusters:
                              clusters: [{ name: a, weight: 1 }, { name: b, weight: 1 }]"#;

fn selection(snapshot: &ConfigSnapshot) -> WeightedSelection {
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    match &hcm.route_table.virtual_hosts[0].routes[0].action {
        RouteActionIR::Forward(ForwardAction {
            target: ForwardTarget::Weighted(weighted),
            ..
        }) => weighted.selection,
        other => panic!("expected a weighted route, got {other:?}"),
    }
}

fn metadata(body: &str) -> String {
    format!(
        "                          metadata:\n                            filter_metadata:\n                              io.llmproxy.selection: {body}\n"
    )
}

#[test]
fn latency_mode_lowers_and_absence_keeps_the_static_draw() {
    let latency = snapshot_from_route(&format!("{}{WEIGHTED}", metadata("{ mode: latency }")))
        .expect("latency mode must load");
    assert_eq!(selection(&latency), WeightedSelection::Latency);
    let plain = snapshot_from_route(WEIGHTED).expect("plain weighted route");
    assert_eq!(selection(&plain), WeightedSelection::Static);
}

/// Each refused shape names its own dotted path: an unknown key, a mode
/// other than `latency`, a missing mode, and the namespace on a route that
/// has no weighted split for it to change.
#[test]
fn every_other_selection_shape_is_refused_with_its_path() {
    let key = format!("{ROUTE_PATH}.metadata.filter_metadata[\"io.llmproxy.selection\"]");
    let single = r#"                          route: { cluster: a }"#;
    for (route, expected) in [
        (
            format!("{}{WEIGHTED}", metadata("{ mode: latency, floor: 0.2 }")),
            format!("{key}.floor"),
        ),
        (
            format!("{}{WEIGHTED}", metadata("{ mode: static }")),
            format!("{key}.mode"),
        ),
        (
            format!("{}{WEIGHTED}", metadata("{}")),
            format!("{key}.mode"),
        ),
        (
            format!("{}{single}", metadata("{ mode: latency }")),
            key.clone(),
        ),
    ] {
        let err = snapshot_from_route(&route).expect_err(&route);
        let path = match &err {
            ConfigError::InvalidValue { field_path, .. }
            | ConfigError::UnsupportedField { field_path, .. } => field_path.clone(),
            other => panic!("unexpected error {other:?}"),
        };
        assert_eq!(path, expected, "{route}");
    }
}
