//! `listen.max_request_body_bytes`: the dialect's request body limit. It
//! lowers to the listener's `per_connection_buffer_limit_bytes`, the value
//! the filter manager caps every request body at (`413` over it) and the
//! router uses as its retry replay limit.
//!
//! Fixtures are real YAML, lowered through the real pipeline and then built
//! into IR by the real Envoy-mode loader, so a value that only reached the
//! JSON would fail here.

use proxy_config::ConfigError;
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config_with_env, SimpleConfig};

fn test_env(name: &str) -> Option<String> {
    match name {
        "OPENAI_API_KEY" => Some("sk-test-openai".to_string()),
        _ => None,
    }
}

fn parse(text: &str) -> Result<SimpleConfig, ConfigError> {
    parse_simple_config_with_env(text, &test_env)
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

/// The IR listener's limit, after the lowered config goes through the real
/// Envoy-mode loader.
fn ir_limit(text: &str) -> u32 {
    let config = parse(text).expect("config must parse");
    let loaded = lower_to_loaded(&config).expect("must survive strict Envoy parsing");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must lower to IR");
    snapshot
        .listeners
        .get("llmproxy_listener")
        .expect("simple lowering names its listener")
        .per_connection_buffer_limit_bytes
}

#[test]
fn max_request_body_bytes_lowers_to_the_listener_buffer_limit() {
    let text =
        config_with_listen(r#"{ address: "127.0.0.1:8080", max_request_body_bytes: 20971520 }"#);
    let bootstrap = lower(&parse(&text).unwrap()).unwrap().bootstrap;
    assert_eq!(
        bootstrap["static_resources"]["listeners"][0]["per_connection_buffer_limit_bytes"],
        serde_json::json!(20_971_520)
    );
    assert_eq!(ir_limit(&text), 20_971_520);
}

#[test]
fn an_unset_limit_keeps_the_1_mib_default() {
    for listen in [r#""127.0.0.1:8080""#, r#"{ address: "127.0.0.1:8080" }"#] {
        let text = config_with_listen(listen);
        let bootstrap = lower(&parse(&text).unwrap()).unwrap().bootstrap;
        assert!(
            bootstrap["static_resources"]["listeners"][0]
                .get("per_connection_buffer_limit_bytes")
                .is_none(),
            "an unset limit must not be written for {listen}"
        );
        assert_eq!(ir_limit(&text), 1 << 20, "default for {listen}");
    }
}

#[test]
fn a_zero_limit_is_rejected_with_its_path() {
    let text = config_with_listen(r#"{ address: "127.0.0.1:8080", max_request_body_bytes: 0 }"#);
    match parse(&text) {
        Err(ConfigError::InvalidValue { field_path, .. }) => {
            assert_eq!(field_path, "listen.max_request_body_bytes");
        }
        other => panic!("expected InvalidValue at listen.max_request_body_bytes, got {other:?}"),
    }
}

#[test]
fn a_limit_that_does_not_fit_in_u32_is_rejected() {
    let text =
        config_with_listen(r#"{ address: "127.0.0.1:8080", max_request_body_bytes: 4294967296 }"#);
    assert!(parse(&text).is_err(), "a value over u32::MAX must not load");
}
