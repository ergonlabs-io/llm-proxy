//! `realtime`: the dialect's switch for WebSocket sessions (ADR-0015) lowers
//! to the listener HCM's `upgrade_configs`, the same capability Envoy mode
//! configures directly (AGENTS.md invariant 5), and survives
//! `--mode translate`.

use proxy_config::ir::{NetworkFilterSpec, UpgradeConfig};
use proxy_config::{ConfigError, ConfigSnapshot};
use proxy_simple_config::{lower_to_loaded, parse_simple_config_with_env, to_envoy_yaml};

fn test_env(name: &str) -> Option<String> {
    (name == "OPENAI_API_KEY").then(|| "sk-test-openai".to_string())
}

fn config(realtime: &str) -> String {
    format!(
        r#"
version: 1
providers:
  openai: {{ api_key: ${{OPENAI_API_KEY}} }}
routes:
  - {{ model: "*", provider: openai }}
{realtime}
"#
    )
}

fn snapshot(text: &str) -> Result<ConfigSnapshot, ConfigError> {
    let config = parse_simple_config_with_env(text, &test_env)?;
    let loaded = lower_to_loaded(&config)?;
    proxy_config::build_snapshot(&loaded)
}

fn upgrade_configs(snapshot: &ConfigSnapshot) -> Vec<UpgradeConfig> {
    let listener = &snapshot.listeners["llmproxy_listener"];
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM");
    };
    hcm.upgrade_configs.clone()
}

fn websocket() -> Vec<UpgradeConfig> {
    vec![UpgradeConfig {
        upgrade_type: "websocket".to_string(),
        enabled: true,
    }]
}

#[test]
fn enabled_realtime_enables_websocket_upgrades_on_the_listener() {
    let text = config("realtime: { enabled: true }");
    assert_eq!(upgrade_configs(&snapshot(&text).unwrap()), websocket());

    let parsed = parse_simple_config_with_env(&text, &test_env).unwrap();
    let (yaml, _) = to_envoy_yaml(&parsed).unwrap();
    let loaded = proxy_config::parse_bootstrap(
        yaml.as_bytes(),
        proxy_config::ConfigFormat::Yaml,
        proxy_config::StrictMode::Strict,
    )
    .expect("translate output must be strict-valid Envoy config");
    assert_eq!(
        upgrade_configs(&proxy_config::build_snapshot(&loaded).unwrap()),
        websocket(),
        "the translated bootstrap configures the same upgrades"
    );
}

/// Absent or disabled: no upgrade type, so every upgrade gets Envoy's 403.
#[test]
fn realtime_absent_or_disabled_allows_no_upgrade() {
    for realtime in ["", "realtime: { enabled: false }"] {
        assert!(
            upgrade_configs(&snapshot(&config(realtime)).unwrap()).is_empty(),
            "{realtime:?}"
        );
    }
}

#[test]
fn an_unknown_realtime_field_is_a_load_error_with_its_path() {
    let err =
        snapshot(&config("realtime: { enabled: true, idle: 5s }")).expect_err("strict config");
    let text = err.to_string();
    assert!(text.contains("realtime") && text.contains("idle"), "{text}");
    let err = snapshot(&config("realtime: {}")).expect_err("enabled is required");
    assert!(err.to_string().contains("enabled"), "{err}");
}
