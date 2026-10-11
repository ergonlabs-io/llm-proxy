//! `typed_extension_protocol_options` -> IR `UpstreamProtocol`
//! acceptance tests. Covers HTTP/1 (explicit and default-absent), HTTP/2,
//! and rejection of every unsupported shape the config could take:
//! HTTP/3, `use_downstream_protocol_config`, an unknown map key, and tuning
//! sub-fields inside the h1/h2 selectors (proving the bare-`{}` strictness).

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
        other => panic!("expected a field-scoped error, got: {other}"),
    }
}

/// No `typed_extension_protocol_options` at all: Envoy's HTTP/1.1 default.
#[test]
fn absent_protocol_options_defaults_to_http1() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert_eq!(cluster.upstream_protocol, UpstreamProtocol::Http1);
}

/// `explicit_http_config.http_protocol_options: {}` selects HTTP/1.1.
#[test]
fn explicit_http1_lowers_to_http1() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http_protocol_options: {}
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert_eq!(cluster.upstream_protocol, UpstreamProtocol::Http1);
}

/// `explicit_http_config.http2_protocol_options: {}` selects HTTP/2.
#[test]
fn explicit_http2_lowers_to_http2() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http2_protocol_options: {}
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert_eq!(cluster.upstream_protocol, UpstreamProtocol::Http2);
}

/// HTTP/3 is not implemented; rejected with a dotted path naming it.
#[test]
fn http3_is_rejected_with_path() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http3_protocol_options: {}
"#;
    let err = snapshot_from(yaml).expect_err("http3 must be rejected");
    assert!(
        err_path(&err).contains("http3_protocol_options"),
        "got path: {}",
        err_path(&err)
    );
}

/// `use_downstream_protocol_config` is on the proto but not on our supported
/// surface; the reflective allowlist walk rejects it before typed lowering
/// even runs.
#[test]
fn use_downstream_protocol_config_is_rejected_with_path() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          use_downstream_protocol_config:
            http_protocol_options: {}
"#;
    let err = snapshot_from(yaml).expect_err("use_downstream_protocol_config must be rejected");
    assert!(
        err_path(&err).contains("use_downstream_protocol_config"),
        "got path: {}",
        err_path(&err)
    );
}

/// A map key other than the one extension we implement is rejected, not
/// silently ignored.
#[test]
fn unknown_map_key_is_rejected_with_path() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      typed_extension_protocol_options:
        envoy.some.other.Extension:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http_protocol_options: {}
"#;
    let err = snapshot_from(yaml).expect_err("unknown extension key must be rejected");
    assert!(
        err_path(&err).contains("envoy.some.other.Extension"),
        "got path: {}",
        err_path(&err)
    );
}

/// A tuning sub-field inside `http2_protocol_options` proves the bare-`{}`
/// strictness: only the empty selector is on the supported surface.
#[test]
fn http2_tuning_subfield_is_rejected_with_path() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http2_protocol_options:
              max_concurrent_streams: 100
"#;
    let err = snapshot_from(yaml).expect_err("http2 tuning sub-field must be rejected");
    assert!(
        err_path(&err).contains("max_concurrent_streams"),
        "got path: {}",
        err_path(&err)
    );
}
