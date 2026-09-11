//! S5 circuit breaker acceptance tests: `CircuitBreakers`/`Thresholds` proto
//! -> IR lowering. Covers explicit per-priority thresholds, the all-default
//! fallback when `circuit_breakers` is absent, rejection of an unsupported
//! nested field, and rejection of a duplicate priority.

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
        other => panic!("expected a field-scoped error, got: {other}"),
    }
}

/// Explicit DEFAULT and HIGH thresholds lower to their own buckets; fields
/// left unset within each entry fall back to the Envoy defaults.
#[test]
fn explicit_thresholds_per_priority() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      circuit_breakers:
        thresholds:
          - priority: DEFAULT
            max_requests: 5
          - priority: HIGH
            max_requests: 50
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    let cb = cluster.circuit_breakers;

    assert_eq!(cb.default.max_requests, 5);
    assert_eq!(
        cb.default.max_connections,
        CircuitBreakerThresholds::ENVOY_DEFAULT.max_connections
    );
    assert_eq!(
        cb.default.max_pending_requests,
        CircuitBreakerThresholds::ENVOY_DEFAULT.max_pending_requests
    );
    assert_eq!(
        cb.default.max_retries,
        CircuitBreakerThresholds::ENVOY_DEFAULT.max_retries
    );

    assert_eq!(cb.high.max_requests, 50);
    assert_eq!(
        cb.high.max_connections,
        CircuitBreakerThresholds::ENVOY_DEFAULT.max_connections
    );
}

/// No `circuit_breakers` block at all: both buckets get Envoy's documented
/// all-1024 (retries 3) defaults.
#[test]
fn absent_circuit_breakers_uses_envoy_defaults() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    let cb = cluster.circuit_breakers;

    assert_eq!(cb.default, CircuitBreakerThresholds::ENVOY_DEFAULT);
    assert_eq!(cb.high, CircuitBreakerThresholds::ENVOY_DEFAULT);
}

/// A configured retry budget replaces `max_retries`; omitted sub-fields use
/// Envoy's 20% / 3-concurrency defaults rather than becoming zeroes.
#[test]
fn retry_budget_lowers_fractional_percent_and_defaults() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      circuit_breakers:
        thresholds:
          - priority: DEFAULT
            max_retries: 99
            retry_budget:
              budget_percent: { value: 12.5 }
              min_retry_concurrency: 7
          - priority: HIGH
            retry_budget: {}
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cb = snapshot.clusters["c1"].circuit_breakers;
    assert_eq!(
        cb.default.retry_budget,
        Some(RetryBudget {
            budget_percent: 12.5,
            min_retry_concurrency: 7,
        })
    );
    assert_eq!(
        cb.high.retry_budget,
        Some(RetryBudget {
            budget_percent: 20.0,
            min_retry_concurrency: 3,
        })
    );
    assert_eq!(
        cb.default.max_retries, 99,
        "IR retains source for display only"
    );
}

#[test]
fn retry_budget_rejects_out_of_range_percent() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      circuit_breakers:
        thresholds:
          - retry_budget:
              budget_percent: { value: 100.1 }
"#;
    let err = snapshot_from(yaml).expect_err("over-100 percent must fail");
    assert!(err.to_string().contains("budget_percent"), "got: {err}");
}

/// `track_remaining` is not on the supported surface: rejected with a path
/// that names the offending field, not silently dropped (ground rule #1).
#[test]
fn unsupported_nested_field_rejected_with_path() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      circuit_breakers:
        thresholds:
          - priority: DEFAULT
            max_requests: 5
            track_remaining: true
"#;
    let err = snapshot_from(yaml).expect_err("track_remaining must be rejected");
    assert!(
        err_path(&err).contains("circuit_breakers"),
        "got path: {}",
        err_path(&err)
    );
    assert!(
        err_path(&err).contains("track_remaining"),
        "got path: {}",
        err_path(&err)
    );
}

/// Two `thresholds` entries tagged DEFAULT is ambiguous configuration --
/// reject rather than silently pick Envoy's "first wins" behavior.
#[test]
fn duplicate_priority_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      circuit_breakers:
        thresholds:
          - priority: DEFAULT
            max_requests: 5
          - priority: DEFAULT
            max_requests: 10
"#;
    let err = snapshot_from(yaml).expect_err("duplicate DEFAULT priority must be rejected");
    assert!(err.to_string().contains("duplicate"), "got: {err}");
}
