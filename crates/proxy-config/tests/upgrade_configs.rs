//! WP-10 S10 increment 1 acceptance tests: HCM `upgrade_configs` ->
//! `Vec<UpgradeConfig>` (config surface only; the tunnel itself lands in
//! increments 2/3). Strict-parse -> PGV -> IR pipeline, so a config that
//! never sets `upgrade_configs` is completely unaffected, and every malformed
//! shape is a hard error carrying its full dotted path (ground rule #1).

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

fn snapshot_from(yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

/// `upgrade_configs` block (caller-supplied, indented to match) wired into an
/// otherwise-minimal HCM with a match-all direct-response route.
fn hcm_with_upgrade_configs(upgrade_configs: &str) -> Result<ConfigSnapshot, ConfigError> {
    let yaml = format!(
        r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: {{ address: 0.0.0.0, port_value: 8080 }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          direct_response: {{ status: 200 }}
                upgrade_configs:
{upgrade_configs}
"#
    );
    snapshot_from(&yaml)
}

fn upgrade_configs(snapshot: &ConfigSnapshot) -> &[UpgradeConfig] {
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    &hcm.upgrade_configs
}

fn err_path(err: &ConfigError) -> &str {
    match err {
        ConfigError::UnsupportedField { field_path, .. } => field_path,
        ConfigError::InvalidValue { field_path, .. } => field_path,
        other => panic!("expected a field-scoped error, got: {other}"),
    }
}

/// The common case: one `websocket` upgrade, `enabled` unset -> defaults true.
#[test]
fn single_websocket_upgrade_defaults_enabled_true() {
    let yaml = r#"
                  - upgrade_type: websocket
"#;
    let snapshot = hcm_with_upgrade_configs(yaml).expect("must lower");
    assert_eq!(
        upgrade_configs(&snapshot),
        &[UpgradeConfig {
            upgrade_type: "websocket".to_string(),
            enabled: true,
        }]
    );
}

/// `enabled: false` is honored (a type declared-but-disabled at the HCM level;
/// a route may re-enable it later, S10.1).
#[test]
fn enabled_false_is_honored() {
    let yaml = r#"
                  - upgrade_type: websocket
                    enabled: false
"#;
    let snapshot = hcm_with_upgrade_configs(yaml).expect("must lower");
    assert!(!upgrade_configs(&snapshot)[0].enabled);
}

/// Envoy matches `upgrade_type` case-insensitively, so we store it lowercased.
#[test]
fn upgrade_type_is_stored_lowercased() {
    let yaml = r#"
                  - upgrade_type: WebSocket
"#;
    let snapshot = hcm_with_upgrade_configs(yaml).expect("must lower");
    assert_eq!(upgrade_configs(&snapshot)[0].upgrade_type, "websocket");
}

/// Two entries whose types collide case-insensitively are a config error
/// (as in Envoy), at the offending dotted path.
#[test]
fn duplicate_upgrade_type_is_rejected() {
    let yaml = r#"
                  - upgrade_type: websocket
                  - upgrade_type: WEBSOCKET
"#;
    let err = hcm_with_upgrade_configs(yaml).expect_err("duplicate must reject");
    assert!(err_path(&err).ends_with("upgrade_configs[1].upgrade_type"));
}

/// An empty `upgrade_type` is a hard error, not a silently-dropped entry.
#[test]
fn empty_upgrade_type_is_rejected() {
    let yaml = r#"
                  - upgrade_type: ""
"#;
    let err = hcm_with_upgrade_configs(yaml).expect_err("empty type must reject");
    assert!(err_path(&err).ends_with("upgrade_configs[0].upgrade_type"));
}

/// Per-upgrade filter chains (`UpgradeConfig.filters`) are unimplemented (the
/// tunnel is transparent, S10.2 deferred), so setting them is rejected by the
/// surface walk with its dotted path -- never silently ignored.
#[test]
fn per_upgrade_filters_are_rejected() {
    let yaml = r#"
                  - upgrade_type: websocket
                    filters:
                      - name: envoy.filters.http.router
                        typed_config:
                          "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
"#;
    let err = hcm_with_upgrade_configs(yaml).expect_err("per-upgrade filters must reject");
    assert!(err_path(&err).contains("upgrade_configs[0].filters"));
}

/// A config that never sets `upgrade_configs` comes through with none -- the
/// Envoy default (no upgrades), not a guessed one.
#[test]
fn absent_upgrade_configs_is_empty() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          direct_response: { status: 200 }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert!(upgrade_configs(&snapshot).is_empty());
}
