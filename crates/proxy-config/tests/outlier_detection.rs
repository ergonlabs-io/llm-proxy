//! S6 passive outlier detection (WP-19): `Cluster.outlier_detection` -> IR
//! `OutlierDetectionIR` lowering. Covers the full-block happy path, the two
//! silently-wrong-value traps (a present-but-empty block must mean all S6
//! defaults not zeros, and `max_ejection_time` must clamp up to
//! `base_ejection_time`), the percentage-range rejection, the
//! `split_external_local_origin_errors: true` rejection (only `false` is
//! implemented), an unsupported field rejected by the surface walk, the
//! aggregate-cluster rejection, and the absent-block -> `None` default.

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
        ConfigError::Validation { field_path, .. } => field_path,
        other => panic!("expected a field-scoped error, got: {other}"),
    }
}

/// A fully-specified block lowers end to end, every field honored, and the
/// percentage fields land in the IR's `u8`.
#[test]
fn outlier_detection_lowers_end_to_end() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      outlier_detection:
        interval: 7s
        base_ejection_time: 20s
        max_ejection_time: 200s
        max_ejection_percent: 42
        always_eject_one_host: true
        consecutive_5xx: 9
        enforcing_consecutive_5xx: 90
        consecutive_gateway_failure: 4
        enforcing_consecutive_gateway_failure: 55
        success_rate_minimum_hosts: 3
        success_rate_request_volume: 77
        success_rate_stdev_factor: 2100
        enforcing_success_rate: 80
        failure_percentage_threshold: 70
        enforcing_failure_percentage: 60
        failure_percentage_minimum_hosts: 2
        failure_percentage_request_volume: 40
        successful_active_health_check_uneject_host: false
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let od = snapshot
        .clusters
        .get("c1")
        .expect("cluster")
        .outlier_detection
        .as_ref()
        .expect("outlier_detection");

    assert_eq!(od.interval, Duration::from_secs(7));
    assert_eq!(od.base_ejection_time, Duration::from_secs(20));
    assert_eq!(od.max_ejection_time, Duration::from_secs(200));
    assert_eq!(od.max_ejection_percent, 42);
    assert!(od.always_eject_one_host);
    assert_eq!(od.consecutive_5xx, 9);
    assert_eq!(od.enforcing_consecutive_5xx, 90);
    assert_eq!(od.consecutive_gateway_failure, 4);
    assert_eq!(od.enforcing_consecutive_gateway_failure, 55);
    assert_eq!(od.success_rate_min_hosts, 3);
    assert_eq!(od.success_rate_request_volume, 77);
    assert_eq!(od.success_rate_stdev_factor, 2100);
    assert_eq!(od.enforcing_success_rate, 80);
    assert_eq!(od.failure_percentage_threshold, 70);
    assert_eq!(od.enforcing_failure_percentage, 60);
    assert_eq!(od.failure_percentage_min_hosts, 2);
    assert_eq!(od.failure_percentage_request_volume, 40);
    assert!(!od.uneject_on_healthy_active_hc);
}

/// The first silently-wrong-value trap: a present-but-EMPTY block must lower
/// to every S6 default, never the Rust zero value. A zero `max_ejection_percent`
/// or `enforcing_consecutive_5xx` would silently disable ejection.
#[test]
fn empty_block_means_all_defaults_not_zeros() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      outlier_detection: {}
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let od = snapshot
        .clusters
        .get("c1")
        .expect("cluster")
        .outlier_detection
        .as_ref()
        .expect("an empty block is Some(defaults), not None");

    assert_eq!(od, &OutlierDetectionIR::ENVOY_DEFAULT);
    // Spell out the load-bearing non-zero defaults, so a regression to Rust
    // zeros fails here with a legible value rather than only on the struct eq.
    assert_eq!(od.max_ejection_percent, 10, "not 0 -- 0 disables ejection");
    assert_eq!(od.enforcing_consecutive_5xx, 100, "not 0");
    assert_eq!(od.consecutive_5xx, 5, "not 0");
    assert_eq!(od.interval, Duration::from_secs(10));
    assert_eq!(od.max_ejection_time, Duration::from_secs(300));
    assert!(
        od.uneject_on_healthy_active_hc,
        "S6 default true, not false"
    );
}

/// The two enforcing-percent fields Envoy defaults to 0 (tracked, never
/// enforced) must NOT be "helpfully" raised to 100.
#[test]
fn the_two_zero_default_enforcing_fields_stay_zero() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      outlier_detection: {}
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let od = snapshot
        .clusters
        .get("c1")
        .unwrap()
        .outlier_detection
        .as_ref()
        .unwrap();
    assert_eq!(od.enforcing_consecutive_gateway_failure, 0);
    assert_eq!(od.enforcing_failure_percentage, 0);
}

/// The second silently-wrong-value trap: a `max_ejection_time` below
/// `base_ejection_time` is clamped UP to the base. Left unclamped it would
/// silently mean "every ejection lasts `base`, not the configured max".
#[test]
fn max_ejection_time_is_clamped_up_to_base() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      outlier_detection:
        base_ejection_time: 30s
        max_ejection_time: 5s
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let od = snapshot
        .clusters
        .get("c1")
        .unwrap()
        .outlier_detection
        .as_ref()
        .unwrap();
    assert_eq!(
        od.max_ejection_time,
        Duration::from_secs(30),
        "max below base must clamp up to base, not stay at the configured 5s"
    );
}

/// A percentage field above 100 is rejected with its dotted path rather than
/// truncated into the IR's `u8`.
#[test]
fn percentage_above_100_is_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      outlier_detection:
        max_ejection_percent: 150
"#;
    let err = snapshot_from(yaml).expect_err("a percentage over 100 must be rejected");
    assert!(
        err_path(&err).ends_with("outlier_detection.max_ejection_percent"),
        "got: {}",
        err_path(&err)
    );
}

/// Only `split_external_local_origin_errors: false` is implemented; `true`
/// needs a separate local-origin failure axis and is rejected rather than
/// accepted and silently ignored (ground rule #1).
#[test]
fn split_external_local_origin_errors_true_is_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      outlier_detection:
        split_external_local_origin_errors: true
"#;
    let err = snapshot_from(yaml).expect_err("split=true must be rejected");
    assert!(
        err_path(&err).ends_with("outlier_detection.split_external_local_origin_errors"),
        "got: {}",
        err_path(&err)
    );

    // `false` is the default and must lower cleanly.
    let ok = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      outlier_detection:
        split_external_local_origin_errors: false
"#;
    snapshot_from(ok).expect("split=false must lower");
}

/// A field we do not implement (`detect_degraded_hosts`) is rejected by the
/// surface walk with its path -- never silently ignored.
#[test]
fn an_unsupported_outlier_field_is_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      outlier_detection:
        detect_degraded_hosts: true
"#;
    let err = snapshot_from(yaml).expect_err("an unimplemented field must be rejected");
    assert!(
        err_path(&err).contains("detect_degraded_hosts"),
        "got: {}",
        err_path(&err)
    );
}

/// `outlier_detection` on an aggregate cluster is inert -- an aggregate has no
/// hosts of its own to eject -- and gets the same rejection `health_checks`
/// does on one.
#[test]
fn aggregate_cluster_with_outlier_detection_rejected() {
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
      outlier_detection: {}
"#;
    let err = snapshot_from(yaml).expect_err("outlier_detection on an aggregate must be rejected");
    assert!(
        err_path(&err).ends_with("outlier_detection"),
        "got: {}",
        err_path(&err)
    );
}

/// No `outlier_detection` at all lowers to `None` -- Envoy's own default (no
/// passive ejection, every host stays eligible).
#[test]
fn absent_outlier_detection_is_none() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert!(snapshot
        .clusters
        .get("c1")
        .unwrap()
        .outlier_detection
        .is_none());
}
