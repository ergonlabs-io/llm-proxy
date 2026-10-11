//! Listener `per_connection_buffer_limit_bytes`: an explicit 0 is rejected at
//! load with its full dotted path (AGENTS.md invariant 1), because the value
//! becomes the HTTP body buffer cap and 0 would reject every request body.
//! Envoy accepts 0; this is a deliberate divergence.

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

fn snapshot_with_limit(limit_line: &str) -> Result<ConfigSnapshot, ConfigError> {
    let yaml = format!(
        r#"
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address: {{ address: 127.0.0.1, port_value: 10000 }}
{limit_line}
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: tcp
                cluster: backend
  clusters:
    - name: backend
      type: STATIC
      load_assignment:
        cluster_name: backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: 8080 }}
"#
    );
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

fn limit_of(snapshot: &ConfigSnapshot) -> u32 {
    snapshot
        .listeners
        .get("ingress")
        .expect("listener")
        .per_connection_buffer_limit_bytes
}

#[test]
fn explicit_zero_is_rejected_with_full_dotted_path() {
    let err = snapshot_with_limit("      per_connection_buffer_limit_bytes: 0")
        .expect_err("0 must be rejected");
    match err {
        ConfigError::InvalidValue { field_path, reason } => {
            assert_eq!(
                field_path,
                "static_resources.listeners[0].per_connection_buffer_limit_bytes"
            );
            assert!(reason.contains("omit the field"), "reason: {reason}");
        }
        other => panic!("expected InvalidValue, got: {other}"),
    }
}

#[test]
fn positive_value_is_accepted_and_lowered() {
    let snapshot =
        snapshot_with_limit("      per_connection_buffer_limit_bytes: 4096").expect("lowers");
    assert_eq!(limit_of(&snapshot), 4096);
}

#[test]
fn unset_lowers_to_one_mib_default() {
    let snapshot = snapshot_with_limit("").expect("lowers");
    assert_eq!(limit_of(&snapshot), 1024 * 1024);
}
