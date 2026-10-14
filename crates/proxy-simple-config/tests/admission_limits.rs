//! Admission limits in the simple dialect: `listen.max_connections`,
//! `listen.request_headers_timeout`, `listen.request_timeout`. The dialect
//! ships Envoy's edge-proxy defaults (50000 / 10s / 60s) where Envoy mode
//! leaves all three disabled.
//!
//! Fixtures are real YAML lowered through the real pipeline, then built into
//! IR by the real Envoy-mode loader, both directly and via the translate
//! (`to_envoy_yaml`) round trip.

use std::time::Duration;

use proxy_config::ir::NetworkFilterSpec;
use proxy_config::{ConfigError, ConfigSnapshot};
use proxy_simple_config::{lower_to_loaded, parse_simple_config_with_env, to_envoy_yaml};

fn test_env(name: &str) -> Option<String> {
    (name == "OPENAI_API_KEY").then(|| "sk-test-openai".to_string())
}

fn config_with_listen(listen: &str) -> String {
    format!(
        r#"
version: 0
listen: {listen}
providers:
  openai: {{ api_key: ${{OPENAI_API_KEY}} }}
routes:
  - model: "*"
    provider: openai
"#
    )
}

fn snapshot(text: &str) -> Result<ConfigSnapshot, ConfigError> {
    let config = parse_simple_config_with_env(text, &test_env)?;
    let loaded = lower_to_loaded(&config)?;
    proxy_config::build_snapshot(&loaded)
}

/// The same config, but via `--mode translate` output re-parsed as Envoy YAML.
fn snapshot_via_translate(text: &str) -> ConfigSnapshot {
    let config = parse_simple_config_with_env(text, &test_env).unwrap();
    let (yaml, _) = to_envoy_yaml(&config).unwrap();
    let loaded = proxy_config::parse_bootstrap(
        yaml.as_bytes(),
        proxy_config::ConfigFormat::Yaml,
        proxy_config::StrictMode::Strict,
    )
    .expect("translate output must be strict-valid Envoy config");
    proxy_config::build_snapshot(&loaded).unwrap()
}

/// (max connections, headers timeout, request timeout) from the IR.
fn limits(s: &ConfigSnapshot) -> (Option<u64>, Option<Duration>, Option<Duration>) {
    let listener = &s.listeners["llmproxy_listener"];
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM");
    };
    (
        s.max_downstream_connections,
        hcm.request_headers_timeout,
        hcm.request_timeout,
    )
}

fn secs(n: u64) -> Option<Duration> {
    Some(Duration::from_secs(n))
}

#[test]
fn defaults_apply_for_every_listen_shape() {
    for listen in [r#""127.0.0.1:8080""#, r#"{ address: "127.0.0.1:8080" }"#] {
        let text = config_with_listen(listen);
        let expected = (Some(50_000), secs(10), secs(60));
        assert_eq!(limits(&snapshot(&text).unwrap()), expected, "{listen}");
        assert_eq!(limits(&snapshot_via_translate(&text)), expected, "{listen}");
    }
}

#[test]
fn overrides_are_honored() {
    let text = config_with_listen(
        r#"{ address: "127.0.0.1:8080", max_connections: 123, request_headers_timeout: 2s, request_timeout: 5m }"#,
    );
    let expected = (Some(123), secs(2), secs(300));
    assert_eq!(limits(&snapshot(&text).unwrap()), expected);
    assert_eq!(limits(&snapshot_via_translate(&text)), expected);
}

#[test]
fn zero_duration_disables_a_timeout() {
    let text = config_with_listen(
        r#"{ address: "127.0.0.1:8080", request_headers_timeout: 0s, request_timeout: 0s }"#,
    );
    let expected = (Some(50_000), None, None);
    assert_eq!(limits(&snapshot(&text).unwrap()), expected);
    assert_eq!(limits(&snapshot_via_translate(&text)), expected);
}

#[test]
fn zero_max_connections_is_rejected_with_path() {
    let text = config_with_listen(r#"{ address: "127.0.0.1:8080", max_connections: 0 }"#);
    let err = parse_simple_config_with_env(&text, &test_env).unwrap_err();
    assert!(
        matches!(&err, ConfigError::InvalidValue { field_path, .. } if field_path == "listen.max_connections"),
        "got {err}"
    );
}

#[test]
fn malformed_duration_is_rejected() {
    for field in ["request_headers_timeout", "request_timeout"] {
        let text = config_with_listen(&format!(
            r#"{{ address: "127.0.0.1:8080", {field}: "soon" }}"#
        ));
        let err = parse_simple_config_with_env(&text, &test_env).unwrap_err();
        // `listen` is an untagged enum (string | object), so serde reports a
        // bad field inside it at `listen` rather than at the field itself;
        // the same holds for `listen.max_request_body_bytes`.
        assert!(
            matches!(&err, ConfigError::InvalidValue { field_path, .. } if field_path == "listen"),
            "{field}: got {err}"
        );
    }
}

/// (stream idle timeout, max stream duration) from the IR.
fn stream_limits(s: &ConfigSnapshot) -> (Option<Duration>, Option<Duration>) {
    let listener = &s.listeners["llmproxy_listener"];
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM");
    };
    (hcm.stream_idle_timeout, hcm.max_stream_duration)
}

/// The dialect cuts a silent provider after 10 minutes where Envoy mode keeps
/// Envoy's 5 minute default, and imposes no overall stream limit.
#[test]
fn stream_limits_default_to_a_ten_minute_idle_and_no_total() {
    let text = config_with_listen(r#""127.0.0.1:8080""#);
    let expected = (secs(600), None);
    assert_eq!(stream_limits(&snapshot(&text).unwrap()), expected);
    assert_eq!(stream_limits(&snapshot_via_translate(&text)), expected);
}

#[test]
fn stream_limits_overrides_are_honored() {
    let text = config_with_listen(
        r#"{ address: "127.0.0.1:8080", stream_idle_timeout: 90s, max_stream_duration: 30m }"#,
    );
    let expected = (secs(90), secs(1800));
    assert_eq!(stream_limits(&snapshot(&text).unwrap()), expected);
    assert_eq!(stream_limits(&snapshot_via_translate(&text)), expected);
}

#[test]
fn zero_disables_the_stream_limits() {
    let text = config_with_listen(
        r#"{ address: "127.0.0.1:8080", stream_idle_timeout: 0s, max_stream_duration: 0s }"#,
    );
    let expected = (None, None);
    assert_eq!(stream_limits(&snapshot(&text).unwrap()), expected);
    assert_eq!(stream_limits(&snapshot_via_translate(&text)), expected);
}
