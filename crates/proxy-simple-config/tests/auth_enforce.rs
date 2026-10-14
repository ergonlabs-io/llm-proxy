//! `auth` turns on tenant model allow-lists and spend budgets. The admin API
//! accepts `PUT /tenants/{id}/policy` and `/budget`, so a dialect chain that
//! lacked `llmproxy.model_authz` / `llmproxy.spend_limit` stored them and
//! enforced nothing. These tests lower real YAML and check the chain, then
//! push it through the strict Envoy loader (which enforces filter order) and
//! the real filter factories.

use proxy_config::ConfigError;
use proxy_filters::auth_filter::AuthFilterFactory;
use proxy_filters::model_authz_filter::ModelAuthzFilterFactory;
use proxy_filters::spend_limit_filter::SpendLimitFilterFactory;
use proxy_http::filter::{FactoryContext, HttpFilterFactory};
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config_with_env, SimpleConfig};

fn parse(text: &str) -> Result<SimpleConfig, ConfigError> {
    parse_simple_config_with_env(text, &|name| match name {
        "OPENAI_API_KEY" => Some("sk-test-openai".to_string()),
        _ => None,
    })
}

const BASE: &str = r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
"#;

/// `BASE` plus an `auth` block, with `extra` appended inside it (indented
/// two spaces by the caller) and `tail` appended at top level.
fn with_auth(extra: &str, tail: &str) -> String {
    format!("{BASE}auth:\n  hmac_secret: \"test-operator-secret\"\n  keys: []\n{extra}{tail}")
}

const PRICING: &str = r#"
pricing:
  price_list:
    version: 2026-09
    effective_from: "2026-09-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: gpt-5
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 1250
            cached_input_nanodollars_per_token: 125
            cache_write_nanodollars_per_token: 1560
            output_nanodollars_per_token: 10000
"#;

fn names(config_text: &str) -> Vec<String> {
    let lowered = lower(&parse(config_text).expect("must parse")).expect("must lower");
    lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"]["http_filters"]
        .as_array()
        .expect("http_filters")
        .iter()
        .map(|f| f["name"].as_str().expect("name").to_string())
        .collect()
}

#[test]
fn auth_lowers_model_authz_and_spend_limit_in_the_required_order() {
    let text = with_auth(
        "",
        &format!("limits:\n  - {{ key: tenant, tokens_per_minute: 100k }}\n{PRICING}"),
    );
    assert_eq!(
        names(&text),
        [
            "llmproxy.auth",
            "llmproxy.body_rewrite",
            "llmproxy.model_authz",
            "llmproxy.token_limit",
            "llmproxy.spend_limit",
            "llmproxy.usage",
            "envoy.filters.http.router",
        ]
    );
}

/// The strict loader runs `check_lane_h_filter_order`; the real factories
/// prove the emitted `typed_config`s (including the cutover enum) parse and
/// that the markers the admin API looks for are registered.
#[test]
fn the_lowered_chain_loads_strictly_and_the_real_factories_accept_it() {
    let config = parse(&with_auth("", PRICING)).expect("must parse");
    let loaded = lower_to_loaded(&config).expect("strict loader must accept the chain");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");
    let listener = snapshot.listeners.values().next().expect("one listener");
    let proxy_config::ir::NetworkFilterSpec::HttpConnectionManager(hcm) =
        &listener.filter_chains[0].filters[0]
    else {
        panic!("expected an HTTP connection manager");
    };
    let config_of = |type_url: &str| {
        hcm.http_filters
            .iter()
            .find(|f| f.type_url == type_url)
            .unwrap_or_else(|| panic!("{type_url} must be in the chain"))
            .config
            .clone()
            .expect("typed_config survives to the IR")
    };

    let ctx = FactoryContext::default();
    AuthFilterFactory
        .create(&config_of(proxy_filters::auth_filter::TYPE_URL), &ctx)
        .expect("auth");
    ModelAuthzFilterFactory
        .create(
            &config_of(proxy_filters::model_authz_filter::TYPE_URL),
            &ctx,
        )
        .expect("model_authz");
    SpendLimitFilterFactory
        .create(
            &config_of(proxy_filters::spend_limit_filter::TYPE_URL),
            &ctx,
        )
        .expect("spend_limit");
    assert!(
        ctx.shared
            .get_across_scopes(proxy_filters::model_authz_filter::TYPE_URL)
            .expect("one scope")
            .is_some(),
        "model_authz registers the marker the admin API checks"
    );
    assert!(ctx
        .shared
        .get_across_scopes(proxy_filters::spend_limit_filter::TYPE_URL)
        .expect("one scope")
        .is_some());
}

#[test]
fn a_config_without_auth_lowers_with_no_new_filters() {
    assert_eq!(
        names(&format!("{BASE}{PRICING}")),
        [
            "llmproxy.body_rewrite",
            "llmproxy.usage",
            "envoy.filters.http.router"
        ]
    );
}

#[test]
fn model_authz_keeps_body_rewrite_in_the_chain_when_usage_forcing_is_off() {
    // model_authz reads the model body_rewrite publishes; without it every
    // request would be refused as model-less.
    let config = BASE.replace(
        "providers:",
        "observability:\n  force_usage_reporting: false\nproviders:",
    );
    let text = format!("{config}auth:\n  hmac_secret: \"s\"\n  keys: []\n");
    let chain = names(&text);
    let body = chain.iter().position(|n| n == "llmproxy.body_rewrite");
    let authz = chain.iter().position(|n| n == "llmproxy.model_authz");
    assert!(
        body.is_some() && authz.is_some() && body < authz,
        "{chain:?}"
    );
    lower_to_loaded(&parse(&text).unwrap()).expect("strict loader accepts it");
}

#[test]
fn enforce_model_policy_false_omits_model_authz_and_warns() {
    let text = with_auth("  enforce: { model_policy: false }\n", PRICING);
    let chain = names(&text);
    assert!(
        !chain.contains(&"llmproxy.model_authz".to_string()),
        "{chain:?}"
    );
    assert!(
        chain.contains(&"llmproxy.spend_limit".to_string()),
        "{chain:?}"
    );
    let lowered = lower(&parse(&text).unwrap()).unwrap();
    assert!(
        lowered
            .warnings
            .iter()
            .any(|w| w.field_path == "auth.enforce.model_policy"
                && w.message.contains("NOT enforced")),
        "{:?}",
        lowered.warnings
    );
    lower_to_loaded(&parse(&text).unwrap()).expect("strict loader accepts it");
}

#[test]
fn enforce_spend_false_omits_spend_limit_and_warns() {
    let text = with_auth("  enforce: { spend: false }\n", PRICING);
    let chain = names(&text);
    assert!(
        !chain.contains(&"llmproxy.spend_limit".to_string()),
        "{chain:?}"
    );
    assert!(
        chain.contains(&"llmproxy.model_authz".to_string()),
        "{chain:?}"
    );
    let lowered = lower(&parse(&text).unwrap()).unwrap();
    assert!(
        lowered
            .warnings
            .iter()
            .any(|w| w.field_path == "auth.enforce.spend" && w.message.contains("NOT enforced")),
        "{:?}",
        lowered.warnings
    );
}

#[test]
fn defaults_enforce_both_and_warn_about_nothing_when_pricing_is_set() {
    let lowered = lower(&parse(&with_auth("", PRICING)).unwrap()).unwrap();
    assert!(
        lowered
            .warnings
            .iter()
            .all(|w| !w.field_path.starts_with("auth.enforce")),
        "{:?}",
        lowered.warnings
    );
}

#[test]
fn spend_enforced_without_pricing_warns_that_budgets_cannot_fire() {
    let lowered = lower(&parse(&with_auth("", "")).unwrap()).unwrap();
    assert!(
        lowered
            .warnings
            .iter()
            .any(|w| w.field_path == "pricing" && w.message.contains("budget")),
        "{:?}",
        lowered.warnings
    );
}

#[test]
fn unknown_key_under_enforce_is_rejected_with_its_dotted_path() {
    let err = parse(&with_auth("  enforce: { model_polcy: false }\n", ""))
        .expect_err("unknown key must fail");
    match err {
        ConfigError::UnknownField { field_path, .. } => {
            assert_eq!(field_path, "auth.enforce.model_polcy");
        }
        other => panic!("expected UnknownField, got {other:?}"),
    }
}
