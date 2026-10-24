//! `models.<name>.max_output_tokens` in the dialect: lowered onto the model's
//! route as the `llmproxy.body_rewrite` per-route override, loaded by the
//! strict Envoy loader, and refused with dialect dotted paths when it is
//! malformed or cannot be honoured.

use proxy_config::ConfigError;
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config_with_env};

fn test_env(name: &str) -> Option<String> {
    match name {
        "OPENAI_API_KEY" => Some("sk-test-openai".to_string()),
        _ => None,
    }
}

fn config(extra: &str, capped: &str) -> String {
    format!(
        r#"
version: 1
providers:
  openai:
    api_key: ${{OPENAI_API_KEY}}
{extra}
routes: []
models:
  a-capped:
    providers: [openai]
{capped}
  b-free:
    providers: [openai]
"#
    )
}

fn routes(text: &str) -> Vec<serde_json::Value> {
    let config = parse_simple_config_with_env(text, &test_env).expect("parse");
    let bootstrap = lower(&config).expect("lower").bootstrap;
    bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        ["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .expect("routes")
        .clone()
}

fn body_rewrite(route: &serde_json::Value) -> &serde_json::Value {
    &route["typed_per_filter_config"]["llmproxy.body_rewrite"]
}

fn load_error(text: &str) -> ConfigError {
    parse_simple_config_with_env(text, &test_env)
        .and_then(|config| lower_to_loaded(&config).map(|_| ()))
        .expect_err("must be refused")
}

#[test]
fn the_cap_lands_on_that_models_route_only() {
    let routes = routes(&config("", "    max_output_tokens: 4096"));
    assert_eq!(body_rewrite(&routes[0])["max_output_tokens"], 4096);
    assert_eq!(body_rewrite(&routes[0])["enabled"], true);
    // Negative: the other model's override carries no cap.
    assert!(body_rewrite(&routes[1]).get("max_output_tokens").is_none());
}

#[test]
fn a_cap_with_usage_reporting_off_keeps_the_usage_splice_off() {
    let extra = "observability:\n  force_usage_reporting: false";
    let routes = routes(&config(extra, "    max_output_tokens: 10"));
    assert_eq!(body_rewrite(&routes[0])["max_output_tokens"], 10);
    assert_eq!(
        body_rewrite(&routes[0])["enabled"],
        false,
        "the override replaces the listener config, so it must not re-enable usage forcing"
    );
    assert!(
        routes[1]["typed_per_filter_config"]
            .get("llmproxy.body_rewrite")
            .is_none(),
        "an uncapped model needs no override when usage forcing is off"
    );
}

#[test]
fn the_strict_loader_accepts_the_lowered_override() {
    let parsed =
        parse_simple_config_with_env(&config("", "    max_output_tokens: 4096"), &test_env)
            .expect("parse");
    let loaded = lower_to_loaded(&parsed).expect("strict load");
    proxy_config::build_snapshot(&loaded).expect("IR");
}

#[test]
fn zero_is_refused_at_the_dialect_path() {
    match load_error(&config("", "    max_output_tokens: 0")) {
        ConfigError::InvalidValue { field_path, .. } => {
            assert_eq!(field_path, "models.a-capped.max_output_tokens")
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn non_integer_and_out_of_range_values_are_refused() {
    for bad in ["-1", "1.5", "\"100\"", "4294967296"] {
        let text = config("", &format!("    max_output_tokens: {bad}"));
        assert!(
            parse_simple_config_with_env(&text, &test_env).is_err(),
            "{bad} must not parse"
        );
    }
}

#[test]
fn combining_with_auto_is_refused() {
    let text = format!(
        "{}\nauto:\n  default: b-free\n",
        config("", "    max_output_tokens: 100")
    );
    match load_error(&text) {
        ConfigError::InvalidValue { field_path, reason } => {
            assert_eq!(field_path, "models.a-capped.max_output_tokens");
            assert!(reason.contains("auto"), "{reason}");
        }
        other => panic!("unexpected {other:?}"),
    }
}
