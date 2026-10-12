//! Downstream admission limits: HCM `request_headers_timeout` /
//! `request_timeout`, bootstrap `overload_manager`'s
//! `global_downstream_max_connections` monitor, and `Listener.
//! ignore_global_conn_limit`. All are driven through the real YAML -> IR path.
//! Envoy treats unset and `0s` timeouts as disabled; the connection cap must be
//! an explicit positive number.

use std::time::Duration;

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

const MONITOR: &str = "envoy.resource_monitors.global_downstream_max_connections";
const MONITOR_TYPE: &str = "type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig";

fn lower(yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

/// One HTTP listener; `listener_extra` is indented at listener level and
/// `hcm_extra` at HCM level (both 6 / 16 spaces, matching the template).
fn http_yaml(listener_extra: &str, hcm_extra: &str) -> String {
    format!(
        r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: {{ address: 127.0.0.1, port_value: 8080 }}
{listener_extra}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
{hcm_extra}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
                    - name: all
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route: {{ cluster: backend }}
  clusters:
    - name: backend
      type: STATIC
      load_assignment:
        cluster_name: backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: 9000 }}
"#
    )
}

fn hcm_of(s: &ConfigSnapshot) -> &HttpConnectionManagerConfig {
    match &s.listeners["http"].filter_chains[0].filters[0] {
        NetworkFilterSpec::HttpConnectionManager(h) => h,
        other => panic!("expected HCM, got {other:?}"),
    }
}

fn overload_yaml(monitors: &str) -> String {
    format!("overload_manager:\n{monitors}\n")
}

fn monitor_entry(name: &str, max: i64) -> String {
    format!(
        "    - name: {name}\n      typed_config:\n        \"@type\": {MONITOR_TYPE}\n        max_active_downstream_connections: {max}"
    )
}

fn err_path(err: ConfigError) -> String {
    match err {
        ConfigError::InvalidValue { field_path, .. }
        | ConfigError::Validation { field_path, .. }
        | ConfigError::UnsupportedField { field_path, .. }
        | ConfigError::UnknownTypeUrl { field_path, .. } => field_path,
        other => panic!("unexpected error variant: {other}"),
    }
}

// ----------------------------------------------------------- HCM timeouts --

#[test]
fn hcm_timeouts_unset_lower_to_none() {
    let s = lower(&http_yaml("", "")).expect("lowers");
    let hcm = hcm_of(&s);
    assert_eq!(hcm.request_headers_timeout, None);
    assert_eq!(hcm.request_timeout, None);
}

#[test]
fn hcm_timeouts_lower_to_durations() {
    let s = lower(&http_yaml(
        "",
        "                request_headers_timeout: 5s\n                request_timeout: 1.5s",
    ))
    .expect("lowers");
    let hcm = hcm_of(&s);
    assert_eq!(hcm.request_headers_timeout, Some(Duration::from_secs(5)));
    assert_eq!(hcm.request_timeout, Some(Duration::from_millis(1500)));
}

#[test]
fn hcm_timeouts_zero_means_disabled() {
    let s = lower(&http_yaml(
        "",
        "                request_headers_timeout: 0s\n                request_timeout: 0s",
    ))
    .expect("lowers");
    let hcm = hcm_of(&s);
    assert_eq!(hcm.request_headers_timeout, None);
    assert_eq!(hcm.request_timeout, None);
}

#[test]
fn hcm_negative_timeouts_are_rejected_with_path() {
    for field in ["request_headers_timeout", "request_timeout"] {
        let yaml = http_yaml("", &format!("                {field}: -1s"));
        let err = lower(&yaml).expect_err("negative must be rejected");
        assert_eq!(
            err_path(err),
            format!(
                "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.{field}"
            )
        );
    }
}

// -------------------------------------------------- ignore_global_conn_limit --

#[test]
fn ignore_global_conn_limit_defaults_false_and_lowers_true() {
    let off = lower(&http_yaml("", "")).expect("lowers");
    assert!(!off.listeners["http"].ignore_global_conn_limit);
    let on = lower(&http_yaml("      ignore_global_conn_limit: true", "")).expect("lowers");
    assert!(on.listeners["http"].ignore_global_conn_limit);
}

// -------------------------------------------------------- overload_manager --

#[test]
fn max_downstream_connections_unset_is_none() {
    let s = lower(&http_yaml("", "")).expect("lowers");
    assert_eq!(s.max_downstream_connections, None);
}

#[test]
fn global_downstream_max_connections_lowers() {
    let yaml = format!(
        "{}{}",
        overload_yaml(&format!(
            "  resource_monitors:\n{}",
            monitor_entry(MONITOR, 1000)
        )),
        http_yaml("", "")
    );
    let s = lower(&yaml).expect("lowers");
    assert_eq!(s.max_downstream_connections, Some(1000));
}

fn monitors_yaml(entries: &[String]) -> String {
    format!(
        "{}{}",
        overload_yaml(&format!("  resource_monitors:\n{}", entries.join("\n"))),
        http_yaml("", "")
    )
}

#[test]
fn zero_or_negative_max_is_rejected() {
    for max in [0, -5] {
        let err = lower(&monitors_yaml(&[monitor_entry(MONITOR, max)]))
            .expect_err("non-positive must be rejected");
        assert_eq!(
            err_path(err),
            "overload_manager.resource_monitors[0].typed_config.max_active_downstream_connections"
        );
    }
}

#[test]
fn unset_max_is_rejected_as_zero() {
    // Omitted field decodes as 0, which Envoy's `gt: 0` rule rejects.
    let entry =
        format!("    - name: {MONITOR}\n      typed_config:\n        \"@type\": {MONITOR_TYPE}");
    let err = lower(&monitors_yaml(&[entry])).expect_err("must be rejected");
    assert_eq!(
        err_path(err),
        "overload_manager.resource_monitors[0].typed_config.max_active_downstream_connections"
    );
}

#[test]
fn unknown_monitor_name_is_rejected() {
    let err = lower(&monitors_yaml(&[
        monitor_entry(MONITOR, 10),
        monitor_entry("envoy.resource_monitors.fixed_heap", 10),
    ]))
    .expect_err("unknown monitor");
    assert_eq!(err_path(err), "overload_manager.resource_monitors[1].name");
}

#[test]
fn duplicate_monitor_is_rejected() {
    let err = lower(&monitors_yaml(&[
        monitor_entry(MONITOR, 10),
        monitor_entry(MONITOR, 20),
    ]))
    .expect_err("duplicate monitor");
    assert_eq!(err_path(err), "overload_manager.resource_monitors[1]");
}

#[test]
fn wrong_typed_config_is_rejected() {
    let entry = format!(
        "    - name: {MONITOR}\n      typed_config:\n        \"@type\": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
    );
    let err = lower(&monitors_yaml(&[entry])).expect_err("wrong type");
    assert_eq!(
        err_path(err),
        "overload_manager.resource_monitors[0].typed_config"
    );
}

#[test]
fn unsupported_overload_manager_fields_are_rejected() {
    let monitors = format!("  resource_monitors:\n{}", monitor_entry(MONITOR, 10));
    let cases = [
        ("  refresh_interval: 1s", "overload_manager.refresh_interval"),
        (
            "  actions:\n    - name: envoy.overload_actions.stop_accepting_requests\n      triggers:\n        - name: envoy.resource_monitors.global_downstream_max_connections\n          threshold: { value: 0.9 }",
            "overload_manager.actions",
        ),
        (
            "  loadshed_points:\n    - name: envoy.load_shed_points.tcp_listener_accept\n      triggers:\n        - name: envoy.resource_monitors.global_downstream_max_connections\n          threshold: { value: 0.9 }",
            "overload_manager.loadshed_points",
        ),
        (
            "  buffer_factory_config:\n    minimum_account_to_track_power_of_two: 20",
            "overload_manager.buffer_factory_config",
        ),
    ];
    for (extra, path) in cases {
        let yaml = format!(
            "{}{}",
            overload_yaml(&format!("{monitors}\n{extra}")),
            http_yaml("", "")
        );
        let err = lower(&yaml).expect_err(path);
        assert_eq!(err_path(err), path, "case {path}");
    }
}
