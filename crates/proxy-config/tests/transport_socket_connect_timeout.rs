//! `FilterChain.transport_socket_connect_timeout` lowering: unset stays
//! `None` (the listener applies its own default), an explicit value
//! (including `0s`, meaning no deadline) reaches the IR, and a negative value
//! is rejected with its full dotted path (AGENTS.md invariant 1).

use std::time::Duration;

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

fn snapshot_with(timeout_line: &str) -> Result<ConfigSnapshot, ConfigError> {
    let yaml = format!(
        r#"
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address: {{ address: 127.0.0.1, port_value: 10000 }}
      filter_chains:
        - {timeout_line}
          filters:
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

fn timeout_of(snapshot: &ConfigSnapshot) -> Option<Duration> {
    snapshot.listeners["ingress"].filter_chains[0].transport_socket_connect_timeout
}

#[test]
fn explicit_timeout_lowers_to_the_ir() {
    let s = snapshot_with("transport_socket_connect_timeout: 2.5s").expect("lowers");
    assert_eq!(timeout_of(&s), Some(Duration::from_millis(2500)));
}

#[test]
fn unset_timeout_is_none() {
    let s = snapshot_with("name: plain").expect("lowers");
    assert_eq!(timeout_of(&s), None);
}

#[test]
fn explicit_zero_is_kept_distinct_from_unset() {
    let s = snapshot_with("transport_socket_connect_timeout: 0s").expect("lowers");
    assert_eq!(timeout_of(&s), Some(Duration::ZERO));
}

#[test]
fn negative_timeout_is_rejected_with_the_full_dotted_path() {
    let err = snapshot_with("transport_socket_connect_timeout: -1s").expect_err("negative");
    match err {
        ConfigError::InvalidValue { field_path, .. } => assert_eq!(
            field_path,
            "static_resources.listeners[0].filter_chains[0].transport_socket_connect_timeout"
        ),
        other => panic!("expected InvalidValue, got: {other}"),
    }
}
