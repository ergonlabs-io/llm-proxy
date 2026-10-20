//! `auth.chargeback_tags` and `auth.keys[].tags` lower to config the real
//! auth filter accepts, errors name dialect paths, and the dialect's copy of
//! the tag rules agrees with `proxy_observability::chargeback`.

use proxy_config::ConfigError;
use proxy_filters::auth_filter::AuthFilterFactory;
use proxy_http::filter::{FactoryContext, HttpFilterFactory};
use proxy_observability::chargeback;
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config_with_env, SimpleConfig};

const DIGEST: &str = "3f2a1e9c7b4d5f6a8e0c2b1d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a";

fn parse(text: &str) -> Result<SimpleConfig, ConfigError> {
    parse_simple_config_with_env(text, &|name| {
        (name == "OPENAI_API_KEY").then(|| "sk-test-openai".to_string())
    })
}

/// A config whose `auth` block ends with `extra` (indented two spaces) and
/// whose one key carries `key_tags` (a YAML flow map, or empty for none).
fn config(key_tags: &str, extra: &str) -> String {
    let tags = if key_tags.is_empty() {
        String::new()
    } else {
        format!(", tags: {key_tags}")
    };
    format!(
        "version: 0\n\
         providers:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         auth:\n  hmac_secret: \"test-operator-secret\"\n  \
         keys:\n    - {{ id: k1, tenant: acme, digest: \"{DIGEST}\"{tags} }}\n{extra}"
    )
}

fn auth_typed_config(config: &SimpleConfig) -> serde_json::Value {
    let lowered = lower(config).expect("must lower");
    lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"]["http_filters"][0]["typed_config"]
        .clone()
}

/// Lowers through the strict loader and builds the real filter from the IR.
fn real_filter_accepts(config: &SimpleConfig) {
    let loaded = lower_to_loaded(config).expect("must lower and strict-validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");
    let listener = snapshot.listeners.values().next().expect("one listener");
    let proxy_config::ir::NetworkFilterSpec::HttpConnectionManager(hcm) =
        &listener.filter_chains[0].filters[0]
    else {
        panic!("expected an HTTP connection manager");
    };
    let typed = hcm
        .http_filters
        .iter()
        .find(|f| f.type_url == proxy_filters::auth_filter::TYPE_URL)
        .and_then(|f| f.config.as_ref())
        .expect("the auth filter's typed_config");
    AuthFilterFactory
        .create(typed, &FactoryContext::default())
        .expect("the real auth filter must accept the lowered tags");
}

fn lowering_error(text: &str) -> (String, String) {
    let config = match parse(text) {
        Ok(config) => config,
        Err(ConfigError::InvalidValue { field_path, reason }) => return (field_path, reason),
        Err(other) => panic!("unexpected parse error {other:?}"),
    };
    match lower(&config) {
        Err(ConfigError::InvalidValue { field_path, reason }) => (field_path, reason),
        Err(other) => panic!("unexpected error {other:?}"),
        Ok(_) => panic!("must be refused:\n{text}"),
    }
}

#[test]
fn tags_lower_to_the_proto_and_the_real_filter_accepts_them() {
    let text = config(
        "{ team: infra, project: search }",
        "  chargeback_tags:\n    from_header: true\n    max_tags: 4\n    max_value_bytes: 32\n    \
         allowed:\n      - key: project\n      - key: team\n        values: [infra, search]\n",
    );
    let config = parse(&text).unwrap();
    let typed = auth_typed_config(&config);
    assert_eq!(
        typed["chargeback_tags"],
        serde_json::json!({
            "allowed": [{"key": "project"}, {"key": "team", "values": ["infra", "search"]}],
            "from_header": true,
            "max_tags": 4,
            "max_value_bytes": 32,
        })
    );
    assert_eq!(
        typed["virtual_keys"][0]["tags"],
        serde_json::json!({"project": "search", "team": "infra"})
    );
    real_filter_accepts(&config);
}

/// Configs without tags lower with no new member, so they are unchanged.
#[test]
fn absent_tags_add_no_member() {
    let typed = auth_typed_config(&parse(&config("", "")).unwrap());
    assert!(typed.get("chargeback_tags").is_none(), "{typed}");
    assert!(typed["virtual_keys"][0].get("tags").is_none(), "{typed}");
    let typed = auth_typed_config(
        &parse(&config(
            "",
            "  chargeback_tags:\n    allowed: [{ key: project }]\n",
        ))
        .unwrap(),
    );
    assert_eq!(
        typed["chargeback_tags"],
        serde_json::json!({"allowed": [{"key": "project"}], "from_header": false})
    );
}

#[test]
fn bad_tag_config_is_refused_naming_the_dialect_path() {
    for (key_tags, extra, path) in [
        ("", "  chargeback_tags:\n    allowed: []\n", "auth.chargeback_tags.allowed"),
        (
            "",
            "  chargeback_tags:\n    allowed: [{ key: Team }]\n",
            "auth.chargeback_tags.allowed[0].key",
        ),
        (
            "",
            "  chargeback_tags:\n    allowed: [{ key: team }, { key: team }]\n",
            "auth.chargeback_tags.allowed[1].key",
        ),
        (
            "",
            "  chargeback_tags:\n    allowed: [{ key: team, values: [] }]\n",
            "auth.chargeback_tags.allowed[0].values",
        ),
        (
            "",
            "  chargeback_tags:\n    max_value_bytes: 4\n    allowed: [{ key: team, values: [toolong] }]\n",
            "auth.chargeback_tags.allowed[0].values[0]",
        ),
        (
            "",
            "  chargeback_tags:\n    max_tags: 0\n    allowed: [{ key: team }]\n",
            "auth.chargeback_tags.max_tags",
        ),
        (
            "",
            "  chargeback_tags:\n    max_value_bytes: 257\n    allowed: [{ key: team }]\n",
            "auth.chargeback_tags.max_value_bytes",
        ),
        ("{ Team: infra }", "", "auth.keys[0].tags"),
        ("{ team: \"in fra\" }", "", "auth.keys[0].tags.team"),
    ] {
        let (field_path, reason) = lowering_error(&config(key_tags, extra));
        assert_eq!(field_path, path, "{reason}");
    }
    // An unknown field is refused by the strict model, with its path.
    match parse(&config(
        "",
        "  chargeback_tags:\n    allowed: [{ key: team }]\n    header: x-cost-tags\n",
    )) {
        Err(ConfigError::UnknownField { field_path, .. }) => {
            assert_eq!(field_path, "auth.chargeback_tags.header")
        }
        other => panic!("expected UnknownField, got {other:?}"),
    }
}

/// The dialect repeats the tag rules so its errors name dialect paths; it
/// must accept exactly what the filter accepts.
#[test]
fn dialect_tag_rules_agree_with_the_filters() {
    assert_eq!(chargeback::MAX_KEY_BYTES, 64);
    assert_eq!(chargeback::MAX_TAGS_CEILING, 32);
    assert_eq!(chargeback::MAX_VALUE_BYTES_CEILING, 256);
    assert_eq!(chargeback::DEFAULT_MAX_VALUE_BYTES, 64);
    let long_key = format!("a{}", "b".repeat(63));
    let too_long_key = format!("a{}", "b".repeat(64));
    for key in [
        "a",
        "team",
        "cost.centre",
        "a-b_c.d9",
        "Team",
        "9team",
        "_x",
        "te am",
        "t=x",
        &long_key,
        &too_long_key,
    ] {
        let text = config(
            "",
            &format!("  chargeback_tags:\n    allowed: [{{ key: \"{key}\" }}]\n"),
        );
        let dialect = parse(&text).and_then(|c| lower(&c).map(|_| ())).is_ok();
        assert_eq!(
            dialect,
            chargeback::validate_key(key).is_ok(),
            "key {key:?}"
        );
    }
    let long_value = "v".repeat(256);
    let too_long_value = "v".repeat(257);
    for value in [
        "infra",
        "a:b/c@d+e-f_g.h",
        "A9",
        "in fra",
        "a,b",
        "a=b",
        "\\\"q\\\"",
        "é",
        &long_value,
        &too_long_value,
    ] {
        let text = config(&format!("{{ team: \"{value}\" }}"), "");
        let dialect = parse(&text).and_then(|c| lower(&c).map(|_| ())).is_ok();
        let tags = [("team".to_string(), value.replace("\\\"", "\""))].into();
        assert_eq!(
            dialect,
            chargeback::validate_key_tags(&tags).is_ok(),
            "value {value:?}"
        );
    }
}
