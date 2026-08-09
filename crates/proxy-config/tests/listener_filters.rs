//! WP-08 chunk C1 acceptance tests: `Listener.listener_filters` lowering and
//! `tls_inspector` support, including Envoy's auto-injection of a default
//! `tls_inspector` when a filter chain matches on SNI/ALPN/`transport_protocol:
//! tls` but none was configured explicitly.

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
        ConfigError::UnknownTypeUrl { field_path, .. } => field_path,
        // `max_client_hello_size`'s bound is also declared via
        // `(validate.rules)` on the proto, so protovalidate can reject it
        // before our own `256..=16384` check in `lower.rs` ever runs.
        ConfigError::Validation { field_path, .. } => field_path,
        other => panic!("expected a field-scoped error, got: {other}"),
    }
}

/// A single-filter-chain listener wrapper: `listener_filters_yaml` goes at
/// listener level, `match_yaml` inside `filter_chain_match` (may be empty).
fn listener_yaml(listener_filters_yaml: &str, match_yaml: &str) -> String {
    // Rust note: `filter_chain_match.rs` establishes the same column-10
    // indentation trick — whichever key comes right after `- ` fixes the
    // mapping's indent, so every sibling key (`filters:`) must line up
    // with it exactly.
    let filter_chain_chain = if match_yaml.is_empty() {
        "        - filters:\n".to_string()
    } else {
        format!("        - filter_chain_match:\n{match_yaml}\n          filters:\n")
    };
    format!(
        r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: {{ address: 0.0.0.0, port_value: 10000 }}
{listener_filters_yaml}
      filter_chains:
{filter_chain_chain}            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: t
                cluster: c
"#
    )
}

const LISTENER_FILTER_PATH: &str = "static_resources.listeners[0].listener_filters[0]";

// --------------------------------------------------------------- case  1 --

#[test]
fn explicit_tls_inspector_with_max_client_hello_size() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
            max_client_hello_size: 4096"#,
        "",
    );
    let snapshot = snapshot_from(&yaml).expect("must lower");
    let listener = snapshot.listeners.get("l1").expect("listener");
    assert_eq!(listener.listener_filters.len(), 1);
    match &listener.listener_filters[0] {
        ListenerFilterSpec::TlsInspector(cfg) => assert_eq!(cfg.max_client_hello_size, 4096),
    }
}

// --------------------------------------------------------------- case  2 --

#[test]
fn explicit_tls_inspector_defaults_max_client_hello_size() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector"#,
        "",
    );
    let snapshot = snapshot_from(&yaml).expect("must lower");
    let listener = snapshot.listeners.get("l1").expect("listener");
    assert_eq!(listener.listener_filters.len(), 1);
    match &listener.listener_filters[0] {
        ListenerFilterSpec::TlsInspector(cfg) => assert_eq!(cfg.max_client_hello_size, 16384),
    }
}

// --------------------------------------------------------------- case  3 --

#[test]
fn max_client_hello_size_above_16384_is_rejected() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
            max_client_hello_size: 20000"#,
        "",
    );
    let err = snapshot_from(&yaml).expect_err("must reject");
    assert_eq!(
        err_path(&err),
        format!("{LISTENER_FILTER_PATH}.typed_config.max_client_hello_size")
    );
    assert!(err.to_string().contains("16384"), "got: {err}");
}

#[test]
fn max_client_hello_size_below_256_is_rejected() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
            max_client_hello_size: 100"#,
        "",
    );
    let err = snapshot_from(&yaml).expect_err("must reject");
    assert_eq!(
        err_path(&err),
        format!("{LISTENER_FILTER_PATH}.typed_config.max_client_hello_size")
    );
}

// --------------------------------------------------------------- case  4 --

#[test]
fn ja3_fingerprinting_field_is_rejected() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
            enable_ja3_fingerprinting: true"#,
        "",
    );
    let err = snapshot_from(&yaml).expect_err("must reject");
    assert_eq!(
        err_path(&err),
        format!("{LISTENER_FILTER_PATH}.typed_config.enable_ja3_fingerprinting")
    );
}

#[test]
fn initial_read_buffer_size_field_is_rejected() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
            initial_read_buffer_size: 1024"#,
        "",
    );
    let err = snapshot_from(&yaml).expect_err("must reject");
    assert_eq!(
        err_path(&err),
        format!("{LISTENER_FILTER_PATH}.typed_config.initial_read_buffer_size")
    );
}

#[test]
fn close_connection_on_client_hello_parsing_errors_field_is_rejected() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
            close_connection_on_client_hello_parsing_errors: true"#,
        "",
    );
    let err = snapshot_from(&yaml).expect_err("must reject");
    assert_eq!(
        err_path(&err),
        format!(
            "{LISTENER_FILTER_PATH}.typed_config.close_connection_on_client_hello_parsing_errors"
        )
    );
}

// --------------------------------------------------------------- case  5 --

#[test]
fn auto_injects_tls_inspector_for_server_names_match() {
    let yaml = listener_yaml("", "            server_names: [\"example.com\"]");
    let snapshot = snapshot_from(&yaml).expect("must lower");
    let listener = snapshot.listeners.get("l1").expect("listener");
    assert_eq!(listener.listener_filters.len(), 1);
    match &listener.listener_filters[0] {
        ListenerFilterSpec::TlsInspector(cfg) => {
            assert_eq!(cfg.max_client_hello_size, 16384);
        }
    }
}

#[test]
fn auto_injects_tls_inspector_for_application_protocols_match() {
    let yaml = listener_yaml("", "            application_protocols: [\"h2\"]");
    let snapshot = snapshot_from(&yaml).expect("must lower");
    let listener = snapshot.listeners.get("l1").expect("listener");
    assert_eq!(listener.listener_filters.len(), 1);
    assert!(matches!(
        listener.listener_filters[0],
        ListenerFilterSpec::TlsInspector(_)
    ));
}

#[test]
fn auto_injects_tls_inspector_for_transport_protocol_tls_match() {
    let yaml = listener_yaml("", "            transport_protocol: tls");
    let snapshot = snapshot_from(&yaml).expect("must lower");
    let listener = snapshot.listeners.get("l1").expect("listener");
    assert_eq!(listener.listener_filters.len(), 1);
    assert!(matches!(
        listener.listener_filters[0],
        ListenerFilterSpec::TlsInspector(_)
    ));
}

// --------------------------------------------------------------- case  6 --

#[test]
fn plain_listener_gets_no_auto_injected_filters() {
    let yaml = listener_yaml("", "");
    let snapshot = snapshot_from(&yaml).expect("must lower");
    let listener = snapshot.listeners.get("l1").expect("listener");
    assert!(listener.listener_filters.is_empty());
}

// --------------------------------------------------------------- case  7 --

#[test]
fn explicit_tls_inspector_prevents_double_injection() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
            max_client_hello_size: 8192"#,
        "            server_names: [\"example.com\"]",
    );
    let snapshot = snapshot_from(&yaml).expect("must lower");
    let listener = snapshot.listeners.get("l1").expect("listener");
    assert_eq!(listener.listener_filters.len(), 1);
    match &listener.listener_filters[0] {
        ListenerFilterSpec::TlsInspector(cfg) => assert_eq!(cfg.max_client_hello_size, 8192),
    }
}

// --------------------------------------------------------------- case  8 --

#[test]
fn unknown_listener_filter_type_url_is_rejected() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.http_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.http_inspector.v3.HttpInspector"#,
        "",
    );
    // The loader resolves the type URL against the descriptor pool while
    // decoding the YAML `@type` tag into an `Any`, before lowering ever runs;
    // an unregistered extension type therefore surfaces there rather than as
    // our own `UnknownTypeUrl`, but it still names the `typed_config` path.
    let err = snapshot_from(&yaml).expect_err("must reject");
    assert_eq!(
        err_path(&err),
        format!("{LISTENER_FILTER_PATH}.typed_config")
    );
    assert!(err.to_string().contains("http_inspector"), "got: {err}");
}

/// A type URL that *is* registered in the descriptor pool (so it survives the
/// loader's `@type` resolution) but is not `tls_inspector` — this is the case
/// that actually exercises `convert_listener_filters`' own `UnknownTypeUrl`.
#[test]
fn listener_filter_with_wrong_but_known_type_is_rejected() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext"#,
        "",
    );
    let err = snapshot_from(&yaml).expect_err("must reject");
    assert!(
        matches!(err, ConfigError::UnknownTypeUrl { .. }),
        "got: {err}"
    );
    assert_eq!(
        err_path(&err),
        format!("{LISTENER_FILTER_PATH}.typed_config")
    );
}

#[test]
fn two_tls_inspectors_is_rejected_naming_both_indices() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector"#,
        "",
    );
    let err = snapshot_from(&yaml).expect_err("must reject");
    assert!(
        err.to_string().contains("listener_filters[0]"),
        "got: {err}"
    );
    assert!(
        err.to_string().contains("listener_filters[1]"),
        "got: {err}"
    );
}

#[test]
fn listener_filter_missing_typed_config_is_rejected() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.tls_inspector"#,
        "",
    );
    let err = snapshot_from(&yaml).expect_err("must reject");
    assert_eq!(err_path(&err), LISTENER_FILTER_PATH);
}

#[test]
fn filter_disabled_is_rejected_via_surface_walk() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
          filter_disabled:
            any_match: true"#,
        "",
    );
    let err = snapshot_from(&yaml).expect_err("must reject");
    assert_eq!(
        err_path(&err),
        format!("{LISTENER_FILTER_PATH}.filter_disabled")
    );
}

#[test]
fn config_discovery_is_rejected() {
    let yaml = listener_yaml(
        r#"      listener_filters:
        - name: envoy.filters.listener.tls_inspector
          config_discovery:
            config_source:
              ads: {}
            type_urls:
              - type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector"#,
        "",
    );
    let err = snapshot_from(&yaml).expect_err("must reject");
    assert!(
        err_path(&err).starts_with(&format!("{LISTENER_FILTER_PATH}.config_discovery")),
        "got: {err}"
    );
}
