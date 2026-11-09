//! `auth.declared_policy` lowers onto `Authentication.declared_policy`, the
//! strict loader and the real auth filter accept the result, the schema
//! agrees, and every rejection names its dialect path.

mod schema_support;

use proxy_config::ConfigError;
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config_with_env};
use serde_json::{json, Value};

fn parse(text: &str) -> Result<proxy_simple_config::SimpleConfig, ConfigError> {
    parse_simple_config_with_env(text, &|name| {
        (name == "OPENAI_API_KEY").then(|| "sk-test-openai".to_string())
    })
}

/// A config whose `auth` block holds `body` (already indented four spaces
/// under `declared_policy:`) and `enforce` lines (indented two spaces).
fn config(body: &str, enforce: &str) -> String {
    let enforce = if enforce.is_empty() {
        String::new()
    } else {
        format!("  enforce:\n{enforce}")
    };
    format!(
        "version: 1\n\
         providers:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n  \
         anthropic: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         auth:\n  hmac_secret: \"test-operator-secret\"\n{enforce}  declared_policy:\n{body}"
    )
}

const FULL: &str = "    revision: 7
    tenants:
      - id: acme
        policy:
          access: { only: [\"gpt-4o\", \"claude-*\"] }
          deny: [\"gpt-4o-mini\"]
        budget: { max_usd: \"500.00\", period: monthly, credential_source: platform }
        scoped_budgets:
          - name: openai-cap
            max_usd: 100
            period: daily
            credential_source: tenant
            models: [\"gpt-4o*\"]
            providers: [openai, openai]
            alert_at_percent: [50, 80]
        limits:
          tokens_per_minute: 100000
          requests_per_minute: 600
          tokens_per_day: 5000000
          requests_per_day: 20000
          concurrent_streams: 8
      - id: beta
        policy: { access: all }
      - id: gamma
";

fn lowered_declared(text: &str) -> Value {
    let config = parse(text).expect("must parse");
    let lowered = lower(&config).expect("must lower");
    lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"]["http_filters"][0]["typed_config"]["declared_policy"]
        .clone()
}

/// The lowering error for `text`; fails the test when it lowers.
fn lower_error(text: &str) -> (String, String) {
    let config = parse(text).expect("must parse");
    match lower(&config).expect_err("must be rejected") {
        ConfigError::InvalidValue { field_path, reason } => (field_path, reason),
        other => panic!("expected InvalidValue, got {other:?}"),
    }
}

fn assert_rejected_at(body: &str, enforce: &str, path: &str) -> String {
    let (field_path, reason) = lower_error(&config(body, enforce));
    assert_eq!(field_path, path, "reason: {reason}");
    reason
}

#[test]
fn a_full_declaration_lowers_to_the_proto_json_shape() {
    let declared = lowered_declared(&config(FULL, ""));
    assert_eq!(
        declared,
        json!({
            "revision": 7,
            "tenants": [
                {
                    "id": "acme",
                    "policy": {
                        "only": { "patterns": ["gpt-4o", "claude-*"] },
                        "deny": ["gpt-4o-mini"],
                    },
                    "budget": {
                        "max_usd": "500.00",
                        "period": "monthly",
                        "credential_source": "platform",
                    },
                    "scoped_budgets": [{
                        "name": "openai-cap",
                        "max_usd": "100",
                        "period": "daily",
                        "credential_source": "tenant",
                        "models": ["gpt-4o*"],
                        "providers": ["provider:openai"],
                        "alert_at_percent": [50, 80],
                    }],
                    "limits": {
                        "tokens_per_minute": 100000,
                        "requests_per_minute": 600,
                        "tokens_per_day": 5000000,
                        "requests_per_day": 20000,
                        "concurrent_streams": 8,
                    },
                },
                { "id": "beta", "policy": { "all": {} } },
                { "id": "gamma" },
            ],
        })
    );
}

#[test]
fn the_strict_loader_accepts_the_lowered_declaration() {
    let config = parse(&config(FULL, "")).expect("must parse");
    lower_to_loaded(&config).expect("the proto-level strict load must accept the declaration");
}

#[test]
fn an_empty_tenant_list_and_an_absent_block_differ() {
    let declared = lowered_declared(&config("    revision: 3\n", ""));
    assert_eq!(declared, json!({ "revision": 3, "tenants": [] }));

    let absent = "version: 1\nproviders:\n  openai: { api_key: ${OPENAI_API_KEY} }\n\
                  routes:\n  - { model: \"*\", provider: openai }\n\
                  auth:\n  hmac_secret: \"s\"\n";
    assert!(lowered_declared(absent).is_null());
}

#[test]
fn the_full_example_validates_against_the_schema() {
    let schema = schema_support::schema();
    let validator = schema_support::validator(&schema);
    // Interpolate by hand: the schema sees the document after `${VAR}` expansion.
    let text = config(FULL, "").replace("${OPENAI_API_KEY}", "sk-test");
    let instance: Value =
        serde_json::to_value(serde_yaml::from_str::<serde_yaml::Value>(&text).expect("yaml"))
            .expect("json");
    let errors = schema_support::validation_errors(&validator, &instance);
    assert!(errors.is_empty(), "schema rejected the example: {errors:?}");
}

#[test]
fn unknown_fields_are_rejected_with_the_full_dotted_path() {
    let body = "    revision: 1\n    tenants:\n      - id: acme\n        budget:\n          \
                max_usd: \"1\"\n          period: daily\n          bogus: 1\n";
    match parse(&config(body, "")).expect_err("unknown field") {
        ConfigError::UnknownField { field_path, .. } => {
            assert_eq!(field_path, "auth.declared_policy.tenants[0].budget.bogus");
        }
        other => panic!("expected UnknownField, got {other:?}"),
    }
}

#[test]
fn a_missing_revision_names_its_path() {
    assert_rejected_at("    tenants: []\n", "", "auth.declared_policy.revision");
    assert_rejected_at("    revision: 0\n", "", "auth.declared_policy.revision");
}

#[test]
fn a_duplicate_tenant_id_names_the_second_entry() {
    let reason = assert_rejected_at(
        "    revision: 1\n    tenants:\n      - id: acme\n      - id: other\n      - id: acme\n",
        "",
        "auth.declared_policy.tenants[2].id",
    );
    assert!(reason.contains("index 0"), "{reason}");
}

#[test]
fn bad_tenant_ids_are_rejected() {
    for (id, reason_part) in [
        ("default", "reserved"),
        ("unauthenticated", "reserved"),
        ("\"\"", "empty"),
        ("\"a\\u0007b\"", "control"),
    ] {
        let body = format!("    revision: 1\n    tenants:\n      - id: {id}\n");
        let reason = assert_rejected_at(&body, "", "auth.declared_policy.tenants[0].id");
        assert!(reason.contains(reason_part), "{id}: {reason}");
    }
    let long = "x".repeat(129);
    let body = format!("    revision: 1\n    tenants:\n      - id: {long}\n");
    assert_rejected_at(&body, "", "auth.declared_policy.tenants[0].id");
    let body = "    revision: 1\n    tenants:\n      - policy: { access: all }\n";
    assert_rejected_at(body, "", "auth.declared_policy.tenants[0].id");
}

#[test]
fn an_unknown_provider_names_its_index() {
    let body =
        "    revision: 1\n    tenants:\n      - id: a\n      - id: b\n      - id: c\n        \
                scoped_budgets:\n          - { name: x, max_usd: \"1\", period: daily, \
                providers: [openai, nope] }\n";
    assert_rejected_at(
        body,
        "",
        "auth.declared_policy.tenants[2].scoped_budgets[0].providers[1]",
    );
}

#[test]
fn each_off_toggle_conflicts_with_its_row() {
    let policy = "    revision: 1\n    tenants:\n      - id: a\n        policy: { access: all }\n";
    let budget = "    revision: 1\n    tenants:\n      - id: a\n        \
                  budget: { max_usd: \"1\", period: daily }\n";
    let scoped =
        "    revision: 1\n    tenants:\n      - id: a\n        scoped_budgets:\n          \
                  - { name: x, max_usd: \"1\", period: daily, models: [m] }\n";
    let limits = "    revision: 1\n    tenants:\n      - id: a\n        \
                  limits: { requests_per_day: 1 }\n";
    let cases = [
        (
            policy,
            "    model_policy: false\n",
            "policy",
            "model_policy",
        ),
        (budget, "    spend: false\n", "budget", "spend"),
        (scoped, "    spend: false\n", "scoped_budgets", "spend"),
        (limits, "    limits: false\n", "limits", "limits"),
    ];
    for (body, enforce, field, toggle) in cases {
        let reason = assert_rejected_at(
            body,
            enforce,
            &format!("auth.declared_policy.tenants[0].{field}"),
        );
        assert!(
            reason.contains(&format!("auth.enforce.{toggle}")),
            "{reason}"
        );
    }
}

#[test]
fn a_yaml_float_amount_asks_the_operator_to_quote_it() {
    let body = "    revision: 1\n    tenants:\n      - id: a\n        \
                budget: { max_usd: 12.5, period: daily }\n";
    let reason = assert_rejected_at(body, "", "auth.declared_policy.tenants[0].budget.max_usd");
    assert!(reason.contains("quote"), "{reason}");
}

#[test]
fn bad_amounts_are_rejected_at_their_field() {
    for amount in [
        "\"-1\"",
        "-1",
        "\"1.1234567\"",
        "\"1.\"",
        "\".5\"",
        "\"abc\"",
        "\"\"",
        "\"99999999999999\"",
        "\"1e3\"",
    ] {
        let body = format!(
            "    revision: 1\n    tenants:\n      - id: a\n        \
             budget: {{ max_usd: {amount}, period: daily }}\n"
        );
        assert_rejected_at(&body, "", "auth.declared_policy.tenants[0].budget.max_usd");
    }
}

#[test]
fn an_empty_limits_block_is_rejected() {
    let body = "    revision: 1\n    tenants:\n      - id: a\n        limits: {}\n";
    let reason = assert_rejected_at(body, "", "auth.declared_policy.tenants[0].limits");
    assert!(reason.contains("remove"), "{reason}");
}

#[test]
fn bad_model_patterns_are_rejected_at_their_index() {
    for (policy, path) in [
        (
            "{ access: { only: [\"gpt-4o\", \"*gpt\"] } }",
            "auth.declared_policy.tenants[0].policy.access.only[1]",
        ),
        (
            "{ access: all, deny: [\"a\", \"\"] }",
            "auth.declared_policy.tenants[0].policy.deny[1]",
        ),
        (
            "{ access: { only: [\"a*b*\"] } }",
            "auth.declared_policy.tenants[0].policy.access.only[0]",
        ),
    ] {
        let body =
            format!("    revision: 1\n    tenants:\n      - id: a\n        policy: {policy}\n");
        assert_rejected_at(&body, "", path);
    }
    // `only: []` is legal and grants nothing.
    let body =
        "    revision: 1\n    tenants:\n      - id: a\n        policy: { access: { only: [] } }\n";
    let declared = lowered_declared(&config(body, ""));
    assert_eq!(
        declared["tenants"][0]["policy"],
        json!({ "only": { "patterns": [] } })
    );
}

#[test]
fn scoped_budget_rules_name_the_offending_field() {
    let wrap = |entries: &str| {
        format!("    revision: 1\n    tenants:\n      - id: a\n        scoped_budgets:\n{entries}")
    };
    // One entry line; `fields` is the inside of the flow map.
    let entry = |fields: &str| format!("          - {{ {fields} }}\n");
    let ok = "max_usd: \"1\", period: daily, models: [m]";
    let at = |suffix: &str| format!("auth.declared_policy.tenants[0].scoped_budgets{suffix}");

    let cases: Vec<(String, String)> = vec![
        (entry(&format!("name: \"Bad Name\", {ok}")), at("[0].name")),
        (entry(ok), at("[0].name")),
        (
            entry(&format!("name: x, {ok}")) + &entry(&format!("name: x, {ok}")),
            at("[1].name"),
        ),
        (entry("name: x, max_usd: \"1\", period: daily"), at("[0]")),
        (
            entry(&format!("name: x, {ok}, alert_at_percent: [0]")),
            at("[0].alert_at_percent[0]"),
        ),
        (
            entry(&format!("name: x, {ok}, alert_at_percent: [50, 101]")),
            at("[0].alert_at_percent[1]"),
        ),
        (
            entry(&format!("name: x, {ok}, alert_at_percent: [50, 50]")),
            at("[0].alert_at_percent[1]"),
        ),
        (
            entry("name: x, period: daily, models: [m]"),
            at("[0].max_usd"),
        ),
        (
            entry("name: x, max_usd: \"1\", models: [m]"),
            at("[0].period"),
        ),
        (
            entry("name: x, max_usd: \"1\", period: daily, models: [\"a*b\"]"),
            at("[0].models[0]"),
        ),
    ];
    for (entries, path) in cases {
        assert_rejected_at(&wrap(&entries), "", &path);
    }

    let many: String = (0..33)
        .map(|i| entry(&format!("name: n{i}, {ok}")))
        .collect();
    assert_rejected_at(&wrap(&many), "", &at(""));

    let models = (0..65)
        .map(|i| format!("m{i}"))
        .collect::<Vec<_>>()
        .join(",");
    assert_rejected_at(
        &wrap(&entry(&format!(
            "name: x, max_usd: \"1\", period: daily, models: [{models}]"
        ))),
        "",
        &at("[0].models"),
    );
}
