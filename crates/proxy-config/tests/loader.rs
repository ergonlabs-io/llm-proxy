//! WP-03 acceptance tests: bootstrap loading with field-path-precise errors.

use proxy_config::{parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

/// The Phase-1 example config, parsed with typed field spot-checks.
#[test]
fn example_config_parses_with_typed_fields() {
    let yaml = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/tcp-proxy.yaml"
    ))
    .expect("read example");

    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
        .expect("example config must load");

    assert!(loaded.warnings.is_empty());
    let sr = loaded.bootstrap.static_resources.expect("static_resources");
    assert_eq!(sr.listeners.len(), 1);
    assert_eq!(sr.listeners[0].name, "ingress_tcp");
    assert_eq!(sr.clusters.len(), 1);
    assert_eq!(sr.clusters[0].name, "backend");

    // "5s" proto3-JSON duration -> prost Duration.
    let timeout = sr.clusters[0]
        .connect_timeout
        .as_ref()
        .expect("connect_timeout");
    assert_eq!((timeout.seconds, timeout.nanos), (5, 0));

    // The tcp_proxy Any is preserved with its type URL for later stages.
    let filter = &sr.listeners[0].filter_chains[0].filters[0];
    assert_eq!(filter.name, "envoy.filters.network.tcp_proxy");
}

#[test]
fn json_format_parses() {
    let json = r#"{
        "static_resources": {
            "clusters": [
                { "name": "c1", "type": "STRICT_DNS", "connect_timeout": "0.250s" }
            ]
        }
    }"#;
    let loaded = parse_bootstrap(json.as_bytes(), ConfigFormat::Json, StrictMode::Strict)
        .expect("json parses");
    let cluster = &loaded.bootstrap.static_resources.unwrap().clusters[0];
    assert_eq!(cluster.name, "c1");
    let t = cluster.connect_timeout.as_ref().unwrap();
    assert_eq!((t.seconds, t.nanos), (0, 250_000_000));
}

#[test]
fn proto_binary_format_parses() {
    use prost::Message as _;
    use proxy_api::envoy::config::bootstrap::v3::Bootstrap;
    use proxy_api::envoy::config::core::v3::Node;

    let original = Bootstrap {
        node: Some(Node {
            id: "n1".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let bytes = original.encode_to_vec();
    let loaded =
        parse_bootstrap(&bytes, ConfigFormat::ProtoBinary, StrictMode::Strict).expect("pb parses");
    assert_eq!(loaded.bootstrap.node.unwrap().id, "n1");
}

/// Ground rule #2: a nested unknown field is rejected, and the error names the
/// FULL dotted path — this is the error-quality bar for the whole project.
#[test]
fn nested_unknown_field_error_carries_full_path() {
    let yaml = r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: { address: 0.0.0.0, port_value: 10000 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              definitely_not_a_field: true
"#;
    let err = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
        .expect_err("unknown nested field must fail");
    let ConfigError::UnknownField { field_path } = &err else {
        panic!("expected UnknownField, got: {err}");
    };
    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filters[0].definitely_not_a_field"
    );
}

/// Permissive mode: same config loads, and every ignored field is reported
/// with its path — nothing is silently dropped.
#[test]
fn permissive_mode_collects_warnings() {
    let yaml = r#"
node: { id: n1, bogus_node_field: 1 }
static_resources:
  clusters:
    - name: c1
      type: STATIC
      made_up_cluster_knob: "hello"
"#;
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Permissive)
        .expect("permissive mode loads despite unknown fields");
    let mut paths: Vec<&str> = loaded
        .warnings
        .iter()
        .map(|w| w.field_path.as_str())
        .collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            "node.bogus_node_field",
            "static_resources.clusters[0].made_up_cluster_knob"
        ]
    );
    // The known fields still made it through.
    assert_eq!(loaded.bootstrap.node.unwrap().id, "n1");
    assert_eq!(
        loaded.bootstrap.static_resources.unwrap().clusters[0].name,
        "c1"
    );
}

/// Type errors (not unknown fields) fail in BOTH modes, with a path.
#[test]
fn invalid_value_fails_even_in_permissive_mode() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      connect_timeout: "not-a-duration"
"#;
    for mode in [StrictMode::Strict, StrictMode::Permissive] {
        let err = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, mode)
            .expect_err("bad duration must fail");
        let ConfigError::InvalidValue { field_path, .. } = &err else {
            panic!("expected InvalidValue, got: {err}");
        };
        assert!(
            field_path.starts_with("static_resources.clusters[0]"),
            "path should locate the cluster, got: {field_path}"
        );
    }
}

#[test]
fn bad_enum_value_reports_path() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: NOT_A_DISCOVERY_TYPE
"#;
    let err = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
        .expect_err("bad enum must fail");
    assert!(
        err.to_string().contains("static_resources.clusters[0]"),
        "got: {err}"
    );
}

#[test]
fn file_format_detection() {
    use std::path::Path;
    assert_eq!(
        ConfigFormat::from_path(Path::new("a.yaml")).unwrap(),
        ConfigFormat::Yaml
    );
    assert_eq!(
        ConfigFormat::from_path(Path::new("a.yml")).unwrap(),
        ConfigFormat::Yaml
    );
    assert_eq!(
        ConfigFormat::from_path(Path::new("a.json")).unwrap(),
        ConfigFormat::Json
    );
    assert_eq!(
        ConfigFormat::from_path(Path::new("a.pb")).unwrap(),
        ConfigFormat::ProtoBinary
    );
    assert!(matches!(
        ConfigFormat::from_path(Path::new("a.pb_text")),
        Err(ConfigError::Unimplemented { field_path, .. }) if field_path == "a.pb_text"
    ));
    assert!(ConfigFormat::from_path(Path::new("a.conf")).is_err());
}

#[test]
fn missing_file_reports_io_error() {
    let err = proxy_config::load_bootstrap_file(
        std::path::Path::new("/nonexistent/bootstrap.yaml"),
        StrictMode::Strict,
    )
    .expect_err("missing file must fail");
    assert!(matches!(err, ConfigError::Io { .. }), "got: {err}");
}
