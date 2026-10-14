//! HCM `stream_idle_timeout` and `common_http_protocol_options.max_stream_duration`
//! lowering. Driven through the real YAML -> IR path.
//!
//! The two differ on purpose: Envoy defaults `stream_idle_timeout` to 5 minutes
//! when unset (so an unset field must not lower to "disabled"), while
//! `max_stream_duration` is off unless set. Every other field on
//! `common_http_protocol_options` and the route-level `max_stream_duration`
//! stay rejected by dotted path (AGENTS.md invariant 1).

use std::time::Duration;

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

const HCM_PATH: &str = "static_resources.listeners[0].filter_chains[0].filters[0].typed_config";

fn lower(yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

/// One HTTP listener; `hcm_extra` is indented at HCM level (16 spaces) and
/// `route_extra` inside the route action (28 spaces).
fn http_yaml(hcm_extra: &str, route_extra: &str) -> String {
    format!(
        r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: {{ address: 127.0.0.1, port_value: 8080 }}
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
                          route:
                            cluster: backend
{route_extra}
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

fn err_path(err: ConfigError) -> String {
    match err {
        ConfigError::InvalidValue { field_path, .. }
        | ConfigError::Validation { field_path, .. }
        | ConfigError::UnsupportedField { field_path, .. }
        | ConfigError::UnknownField { field_path, .. } => field_path,
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn unset_stream_idle_timeout_takes_envoys_five_minute_default() {
    let s = lower(&http_yaml("", "")).expect("lowers");
    let hcm = hcm_of(&s);
    assert_eq!(hcm.stream_idle_timeout, Some(Duration::from_secs(300)));
    assert_eq!(hcm.max_stream_duration, None);
}

#[test]
fn stream_idle_timeout_and_max_stream_duration_lower_to_durations() {
    let s = lower(&http_yaml(
        "                stream_idle_timeout: 90s\n\
         \x20               common_http_protocol_options:\n\
         \x20                 max_stream_duration: 1800s",
        "",
    ))
    .expect("lowers");
    let hcm = hcm_of(&s);
    assert_eq!(hcm.stream_idle_timeout, Some(Duration::from_secs(90)));
    assert_eq!(hcm.max_stream_duration, Some(Duration::from_secs(1800)));
}

#[test]
fn an_explicit_zero_disables_both() {
    let s = lower(&http_yaml(
        "                stream_idle_timeout: 0s\n\
         \x20               common_http_protocol_options:\n\
         \x20                 max_stream_duration: 0s",
        "",
    ))
    .expect("lowers");
    let hcm = hcm_of(&s);
    assert_eq!(hcm.stream_idle_timeout, None);
    assert_eq!(hcm.max_stream_duration, None);
}

#[test]
fn negative_values_are_rejected_with_path() {
    let err = lower(&http_yaml("                stream_idle_timeout: -1s", ""))
        .expect_err("negative must be rejected");
    assert_eq!(err_path(err), format!("{HCM_PATH}.stream_idle_timeout"));

    let err = lower(&http_yaml(
        "                common_http_protocol_options:\n\
         \x20                 max_stream_duration: -1s",
        "",
    ))
    .expect_err("negative must be rejected");
    assert_eq!(
        err_path(err),
        format!("{HCM_PATH}.common_http_protocol_options.max_stream_duration")
    );
}

/// Only `max_stream_duration` is read from `common_http_protocol_options`; a
/// neighbouring field must fail by name rather than be accepted and ignored.
#[test]
fn other_common_http_protocol_options_are_still_rejected() {
    let err = lower(&http_yaml(
        "                common_http_protocol_options:\n\
         \x20                 idle_timeout: 30s",
        "",
    ))
    .expect_err("idle_timeout is not read by anything");
    assert_eq!(
        err_path(err),
        format!("{HCM_PATH}.common_http_protocol_options.idle_timeout")
    );
}

/// The route-level override is not implemented, so it is refused with its
/// path instead of being parsed and dropped.
#[test]
fn route_level_max_stream_duration_is_rejected() {
    let err = lower(&http_yaml(
        "",
        "                            max_stream_duration:\n\
         \x20                             max_stream_duration: 30s",
    ))
    .expect_err("route max_stream_duration is not implemented");
    assert!(
        err_path(err).ends_with("route.max_stream_duration"),
        "the error must name the route field"
    );
}
