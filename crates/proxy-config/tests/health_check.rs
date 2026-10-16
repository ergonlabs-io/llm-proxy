//! S6 active health checking: `Cluster.health_checks` -> IR
//! `HealthCheckIR` lowering. Covers the HTTP and TCP happy paths end to end,
//! every rejection AGENTS.md invariant 1 requires (a second check, gRPC/custom
//! checkers, an aggregate cluster, a second `receive` payload), the hex vs.
//! binary `Payload` decoding trap, and `expected_statuses` range expansion.

use std::time::Duration;

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
        // PGV catches missing required fields before typed health-check lowering.
        ConfigError::Validation { field_path, .. } => field_path,
        other => panic!("expected a field-scoped error, got: {other}"),
    }
}

/// An HTTP health check lowers end to end: required fields, jitter/no-traffic
/// defaults, the empty `host` -> `None` convention, and `expected_statuses`
/// range expansion into a flat list.
#[test]
fn http_health_check_lowers_end_to_end() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 2s
          interval: 5s
          unhealthy_threshold: 3
          healthy_threshold: 2
          http_health_check:
            path: /healthz
            expected_statuses:
              - { start: 200, end: 203 }
              - { start: 429, end: 430 }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    let hc = cluster.health_check.as_ref().expect("health_check");

    assert_eq!(hc.timeout, Duration::from_secs(2));
    assert_eq!(hc.interval, Duration::from_secs(5));
    assert_eq!(hc.interval_jitter, Duration::ZERO);
    assert_eq!(hc.unhealthy_threshold, 3);
    assert_eq!(hc.healthy_threshold, 2);
    assert_eq!(hc.no_traffic_interval, Duration::from_secs(60));

    match &hc.kind {
        HealthCheckKindIR::Http {
            path,
            expected_statuses,
            host,
        } => {
            assert_eq!(path, "/healthz");
            assert_eq!(expected_statuses, &vec![200u16, 201, 202, 429]);
            assert_eq!(*host, None);
        }
        other => panic!("expected Http, got {other:?}"),
    }
}

/// `HttpHealthCheck.host`, when set, becomes `Some`.
#[test]
fn http_health_check_host_override_is_some() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 2s
          interval: 5s
          unhealthy_threshold: 3
          healthy_threshold: 2
          http_health_check:
            path: /healthz
            host: upstream.example.com
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    let hc = cluster.health_check.as_ref().expect("health_check");
    match &hc.kind {
        HealthCheckKindIR::Http { host, .. } => {
            assert_eq!(host.as_deref(), Some("upstream.example.com"));
        }
        other => panic!("expected Http, got {other:?}"),
    }
}

/// An empty `expected_statuses` stays empty -- the IR's own "200 only"
/// convention (Envoy's zero-value-means-default), not an error.
#[test]
fn http_health_check_empty_expected_statuses_stays_empty() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 2s
          interval: 5s
          unhealthy_threshold: 3
          healthy_threshold: 2
          http_health_check:
            path: /healthz
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    let hc = cluster.health_check.as_ref().expect("health_check");
    match &hc.kind {
        HealthCheckKindIR::Http {
            expected_statuses, ..
        } => assert!(expected_statuses.is_empty()),
        other => panic!("expected Http, got {other:?}"),
    }
}

/// A TCP health check lowers end to end, including a non-default
/// `interval_jitter` and `no_traffic_interval`.
#[test]
fn tcp_health_check_lowers_end_to_end() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 1s
          interval: 10s
          interval_jitter: 1s
          no_traffic_interval: 30s
          unhealthy_threshold: 1
          healthy_threshold: 1
          tcp_health_check:
            send:
              text: "504F4E47"
            receive:
              - text: "504F4E47"
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    let hc = cluster.health_check.as_ref().expect("health_check");

    assert_eq!(hc.interval_jitter, Duration::from_secs(1));
    assert_eq!(hc.no_traffic_interval, Duration::from_secs(30));
    match &hc.kind {
        HealthCheckKindIR::Tcp { send, expect } => {
            assert_eq!(send, b"PONG");
            assert_eq!(expect, b"PONG");
        }
        other => panic!("expected Tcp, got {other:?}"),
    }
}

/// `Payload.text` is hex-encoded: `504F4E47` represents the bytes `PONG`.
#[test]
fn payload_text_is_hex_decoded_not_raw() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          tcp_health_check:
            send:
              text: "504F4E47"
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    let hc = cluster.health_check.as_ref().expect("health_check");
    match &hc.kind {
        HealthCheckKindIR::Tcp { send, .. } => {
            assert_eq!(send, b"PONG", "must decode hex, not treat as raw text");
            assert_ne!(send.as_slice(), b"504F4E47");
            assert_eq!(send.len(), 4, "8 hex chars decode to 4 bytes, not 8");
        }
        other => panic!("expected Tcp, got {other:?}"),
    }
}

/// `Payload.binary` is raw bytes -- no decoding at all.
#[test]
fn payload_binary_is_raw_bytes() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          tcp_health_check:
            send:
              binary: UE9ORw==
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    let hc = cluster.health_check.as_ref().expect("health_check");
    match &hc.kind {
        HealthCheckKindIR::Tcp { send, .. } => assert_eq!(send, b"PONG"),
        other => panic!("expected Tcp, got {other:?}"),
    }
}

/// Odd-length hex is rejected with the field's own path, not silently
/// truncated or padded.
#[test]
fn odd_length_hex_payload_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          tcp_health_check:
            send:
              text: "ABC"
"#;
    let err = snapshot_from(yaml).expect_err("odd-length hex must be rejected");
    assert!(
        err_path(&err).contains("tcp_health_check.send.text"),
        "got: {}",
        err_path(&err)
    );
}

/// Non-hex characters are rejected with the field's own path.
#[test]
fn invalid_hex_payload_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          tcp_health_check:
            send:
              text: "ZZZZ"
"#;
    let err = snapshot_from(yaml).expect_err("non-hex text must be rejected");
    assert!(
        err_path(&err).contains("tcp_health_check.send.text"),
        "got: {}",
        err_path(&err)
    );
}

/// Two `health_checks` entries: only one implemented -- reject rather than
/// silently run the first and ignore the rest.
#[test]
fn second_health_check_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          tcp_health_check: {}
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          tcp_health_check: {}
"#;
    let err = snapshot_from(yaml).expect_err("a second health check must be rejected");
    assert!(
        err_path(&err).ends_with("health_checks[1]"),
        "got: {}",
        err_path(&err)
    );
}

/// `grpc_health_check` gets its own operator-facing rejection rather than
/// the surface walk's generic "not implemented yet" text.
#[test]
fn grpc_health_check_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          grpc_health_check: {}
"#;
    let err = snapshot_from(yaml).expect_err("grpc_health_check must be rejected");
    assert!(
        err_path(&err).ends_with("grpc_health_check"),
        "got: {}",
        err_path(&err)
    );
    assert!(err.to_string().contains("gRPC"), "got: {err}");
}

/// `custom_health_check` gets its own operator-facing rejection.
#[test]
fn custom_health_check_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          custom_health_check:
            name: some-checker
"#;
    let err = snapshot_from(yaml).expect_err("custom_health_check must be rejected");
    assert!(
        err_path(&err).ends_with("custom_health_check"),
        "got: {}",
        err_path(&err)
    );
    assert!(err.to_string().contains("custom"), "got: {err}");
}

/// No `health_checker` set at all is an error, not a silently-inert check.
#[test]
fn missing_health_checker_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
"#;
    let err = snapshot_from(yaml).expect_err("a health_checker must be required");
    // The PGV oneof-required rule catches this before
    // `convert_health_check` runs (see `err_path`'s `Validation` arm).
    assert!(
        err_path(&err).contains("health_checker"),
        "got: {}",
        err_path(&err)
    );
}

/// A required field left unset -- `timeout` here -- is an error naming its
/// own path, not a silently-defaulted value.
#[test]
fn missing_timeout_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          tcp_health_check: {}
"#;
    let err = snapshot_from(yaml).expect_err("missing timeout must be rejected");
    assert!(
        err_path(&err).contains("timeout"),
        "got: {}",
        err_path(&err)
    );
}

/// A second `receive` payload on a TCP check: the IR carries one `expect`.
#[test]
fn tcp_second_receive_payload_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          tcp_health_check:
            receive:
              - text: "41"
              - text: "42"
"#;
    let err = snapshot_from(yaml).expect_err("a second receive payload must be rejected");
    assert!(
        err_path(&err).ends_with("receive[1]"),
        "got: {}",
        err_path(&err)
    );
}

/// A status range outside `[100, 600)` is rejected with its own path.
#[test]
fn expected_status_range_out_of_bounds_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          http_health_check:
            path: /healthz
            expected_statuses:
              - { start: 50, end: 60 }
"#;
    let err = snapshot_from(yaml).expect_err("range outside [100, 600) must be rejected");
    assert!(
        err_path(&err).ends_with("expected_statuses[0]"),
        "got: {}",
        err_path(&err)
    );
}

/// `end <= start` is rejected -- a reversed or empty range is not a
/// well-formed set of statuses.
#[test]
fn expected_status_range_end_not_after_start_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          http_health_check:
            path: /healthz
            expected_statuses:
              - { start: 300, end: 300 }
"#;
    let err = snapshot_from(yaml).expect_err("end <= start must be rejected");
    assert!(
        err_path(&err).ends_with("expected_statuses[0]"),
        "got: {}",
        err_path(&err)
    );
}

/// `health_checks` on an aggregate cluster is inert -- an aggregate has no
/// hosts of its own to probe -- and gets the same rejection as
/// `load_assignment`/`transport_socket`/etc. do on one.
#[test]
fn aggregate_cluster_with_health_check_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: a
      type: STATIC
      load_assignment:
        cluster_name: a
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.1, port_value: 443 } }
    - name: agg
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: ["a"]
      health_checks:
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          tcp_health_check: {}
"#;
    let err = snapshot_from(yaml).expect_err("health_checks on an aggregate must be rejected");
    assert!(
        err_path(&err).ends_with("health_checks"),
        "got: {}",
        err_path(&err)
    );
}

/// No `health_checks` at all lowers to `None` -- Envoy's own default (no
/// active probing, every host healthy).
#[test]
fn absent_health_checks_is_none() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert!(cluster.health_check.is_none());
}

/// A field on `HttpHealthCheck` outside the supported surface (here,
/// `codec_client_type`) is rejected by the surface walk with the full
/// dotted path, not silently dropped.
#[test]
fn unsupported_http_health_check_field_rejected_with_path() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      health_checks:
        - timeout: 1s
          interval: 10s
          unhealthy_threshold: 1
          healthy_threshold: 1
          http_health_check:
            path: /healthz
            codec_client_type: HTTP2
"#;
    let err = snapshot_from(yaml).expect_err("codec_client_type must be rejected");
    assert!(
        err_path(&err).contains("codec_client_type"),
        "got: {}",
        err_path(&err)
    );
}
