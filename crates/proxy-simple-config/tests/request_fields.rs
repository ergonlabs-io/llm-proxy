//! `providers.<name>.request_fields` in the dialect: lowered onto the
//! provider's cluster metadata as `request_field_policy` (AGENTS.md
//! invariant 6), accepted by the strict Envoy loader, and refused with
//! dialect dotted paths when malformed.

use proxy_config::ConfigError;
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config_with_env};

fn test_env(name: &str) -> Option<String> {
    match name {
        "OPENAI_API_KEY" => Some("sk-test-openai".to_string()),
        _ => None,
    }
}

const WITH_FALLBACK: &str = r#"
version: 0
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
    request_fields: { deny: [models, route], strip: [plugins] }
  fb1: { type: openai-compatible, base_url: "http://fb1.internal:8000" }
routes:
  - { model: "*", provider: openai, fallbacks: [fb1] }
"#;

fn provider(fields: &str) -> String {
    format!(
        r#"
version: 0
providers:
  openai:
    api_key: ${{OPENAI_API_KEY}}
    request_fields: {fields}
routes:
  - {{ model: "*", provider: openai }}
"#
    )
}

fn load_error(fields: &str) -> ConfigError {
    let result = parse_simple_config_with_env(&provider(fields), &test_env)
        .and_then(|config| lower_to_loaded(&config).map(|_| ()));
    result.expect_err("must be refused")
}

#[test]
fn policy_lands_on_the_provider_cluster_metadata() {
    let config = parse_simple_config_with_env(WITH_FALLBACK, &test_env).expect("parse");
    let bootstrap = lower(&config).expect("lower").bootstrap;
    let clusters = bootstrap["static_resources"]["clusters"]
        .as_array()
        .unwrap();
    let find = |name: &str| clusters.iter().find(|c| c["name"] == name).unwrap();
    let auth = |c: &serde_json::Value| {
        c["metadata"]["filter_metadata"]["io.llmproxy.provider_auth"].clone()
    };
    assert_eq!(
        auth(find("provider:openai"))["request_field_policy"],
        serde_json::json!({ "deny": ["models", "route"], "strip": ["plugins"] })
    );
    // Negative: the provider without the knob carries no policy, so the
    // fallback is not constrained by the primary's.
    assert!(auth(find("provider:fb1"))
        .get("request_field_policy")
        .is_none());
}

#[test]
fn strict_envoy_loader_builds_the_policy_into_the_ir() {
    let config = parse_simple_config_with_env(WITH_FALLBACK, &test_env).expect("parse");
    let loaded = lower_to_loaded(&config).expect("strict load");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("IR");
    let policy = &snapshot.clusters["provider:openai"]
        .provider_runtime
        .as_ref()
        .expect("runtime")
        .request_field_policy;
    assert_eq!(policy.deny, ["models", "route"]);
    assert_eq!(policy.strip, ["plugins"]);
    let fb = &snapshot.clusters["provider:fb1"];
    assert!(fb
        .provider_runtime
        .as_ref()
        .is_none_or(|r| r.request_field_policy.is_empty()));
}

#[test]
fn every_cluster_lowered_from_the_provider_carries_it() {
    // A provider reached by several models still gets one policy per cluster.
    let text = r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY}, request_fields: { deny: [models] } }
models:
  a: { providers: [{ provider: openai, model: a-up }] }
  b: { providers: [{ provider: openai, model: b-up }] }
routes:
  - { model: "*", provider: openai }
"#;
    let config = parse_simple_config_with_env(text, &test_env).expect("parse");
    let snapshot =
        proxy_config::build_snapshot(&lower_to_loaded(&config).expect("load")).expect("IR");
    let with_policy = snapshot
        .clusters
        .values()
        .filter(|c| {
            c.provider_runtime
                .as_ref()
                .is_some_and(|r| !r.request_field_policy.is_empty())
        })
        .count();
    assert!(with_policy >= 1);
    for (name, c) in &snapshot.clusters {
        if name.starts_with("provider:") {
            assert_eq!(
                c.provider_runtime
                    .as_ref()
                    .unwrap()
                    .request_field_policy
                    .deny,
                ["models"],
                "{name}"
            );
        }
    }
}

#[test]
fn unknown_key_under_request_fields_is_refused() {
    let err = parse_simple_config_with_env(&provider("{ allow: [x] }"), &test_env)
        .expect_err("unknown key");
    assert!(err.to_string().contains("allow"), "{err}");
}

#[test]
fn empty_name_is_refused_at_the_dialect_path() {
    match load_error(r#"{ deny: [models, ""] }"#) {
        ConfigError::InvalidValue { field_path, .. } => {
            assert_eq!(field_path, "providers.openai.request_fields.deny[1]")
        }
        other => panic!("unexpected {other:?}"),
    }
    match load_error(r#"{ strip: [""] }"#) {
        ConfigError::InvalidValue { field_path, .. } => {
            assert_eq!(field_path, "providers.openai.request_fields.strip[0]")
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn name_in_both_lists_is_refused_at_the_dialect_path() {
    match load_error("{ deny: [models], strip: [models] }") {
        ConfigError::InvalidValue { field_path, reason } => {
            assert_eq!(field_path, "providers.openai.request_fields.strip[0]");
            assert!(reason.contains("deny"), "{reason}");
        }
        other => panic!("unexpected {other:?}"),
    }
}
