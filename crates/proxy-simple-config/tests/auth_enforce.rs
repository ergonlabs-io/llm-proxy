//! `auth` turns on tenant model allow-lists and spend budgets. The admin API
//! accepts `PUT /tenants/{id}/policy` and `/budget`, so a dialect chain that
//! lacked `llmproxy.model_authz` / `llmproxy.spend_limit` stored them and
//! enforced nothing. These tests lower real YAML and check the chain, then
//! push it through the strict Envoy loader (which enforces filter order) and
//! the real filter factories.

use proxy_config::ConfigError;
use proxy_filters::auth_filter::AuthFilterFactory;
use proxy_filters::model_authz_filter::ModelAuthzFilterFactory;
use proxy_filters::object_ownership_filter::ObjectOwnershipFilterFactory;
use proxy_filters::spend_limit_filter::SpendLimitFilterFactory;
use proxy_filters::token_limit_filter::TokenLimitFilterFactory;
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
            "llmproxy.object_ownership",
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
    TokenLimitFilterFactory
        .create(
            &config_of(proxy_filters::token_limit_filter::TYPE_URL),
            &ctx,
        )
        .expect("token_limit in policy-only mode, over auth's control plane");
    ObjectOwnershipFilterFactory
        .create(
            &config_of(proxy_filters::object_ownership_filter::TYPE_URL),
            &ctx,
        )
        .expect("object_ownership, over auth's control plane");
    assert!(ctx
        .shared
        .get_across_scopes(proxy_filters::object_ownership_filter::TYPE_URL)
        .expect("one scope")
        .is_some());
    assert!(
        ctx.shared
            .get_across_scopes(proxy_filters::token_limit_filter::TYPE_URL)
            .expect("one scope")
            .is_some(),
        "token_limit registers where the admin API's limits check looks"
    );
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

/// The fail-open opt-out: no filter, and a warning that says what is open.
/// `tenant_object_ownership_e2e.rs` drives the same opt-out at the socket.
#[test]
fn enforce_object_ownership_false_omits_the_filter_and_warns() {
    let text = with_auth("  enforce: { object_ownership: false }\n", PRICING);
    let chain = names(&text);
    assert!(
        !chain.contains(&"llmproxy.object_ownership".to_string()),
        "{chain:?}"
    );
    let lowered = lower(&parse(&text).unwrap()).unwrap();
    assert!(
        lowered
            .warnings
            .iter()
            .any(|w| w.field_path == "auth.enforce.object_ownership"
                && w.message.contains("NOT kept to their tenant")),
        "{:?}",
        lowered.warnings
    );
    lower_to_loaded(&parse(&text).unwrap()).expect("strict loader accepts it");
}

/// The owner TTL of the two stored-output collections (ADR-0013 §6): 30
/// days by default, `auth.stored_output_owner_ttl` when set, and no other
/// collection's owners expire. The strict loader and the real filter
/// factory accept the lowered config.
#[test]
fn stored_output_owner_ttl_lowers_onto_responses_and_chat_completions() {
    let ttls = |extra: &str| {
        let text = with_auth(extra, PRICING);
        let lowered = lower(&parse(&text).expect("must parse")).expect("must lower");
        lower_to_loaded(&parse(&text).unwrap()).expect("strict loader accepts it");
        let filters = lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
            ["filters"][0]["typed_config"]["http_filters"]
            .as_array()
            .expect("http_filters")
            .clone();
        let ownership = filters
            .iter()
            .find(|f| f["name"] == "llmproxy.object_ownership")
            .expect("object_ownership in the chain")["typed_config"]
            .clone();
        ownership["collection"]
            .as_array()
            .expect("collection")
            .iter()
            .map(|c| {
                (
                    c["path"].as_str().unwrap().to_string(),
                    c["owner_ttl_seconds"].as_u64(),
                )
            })
            .collect::<Vec<_>>()
    };
    let month = Some(30 * 24 * 3600);
    let want = |ttl: Option<u64>| {
        vec![
            ("/v1/responses".to_string(), ttl),
            ("/v1/chat/completions".to_string(), ttl),
            ("/v1/threads".to_string(), None),
            ("/v1/fine_tuning/jobs".to_string(), None),
        ]
    };
    assert_eq!(ttls(""), want(month));
    assert_eq!(
        ttls("  stored_output_owner_ttl: 48h\n"),
        want(Some(48 * 3600))
    );

    for (extra, why) in [
        ("  stored_output_owner_ttl: 500ms\n", "whole seconds"),
        ("  stored_output_owner_ttl: 0s\n", "at least 1s"),
        (
            "  stored_output_owner_ttl: 1h\n  enforce: { object_ownership: false }\n",
            "no effect",
        ),
    ] {
        let err = lower(&parse(&with_auth(extra, PRICING)).unwrap()).expect_err(extra);
        let ConfigError::InvalidValue { field_path, reason } = err else {
            panic!("{extra}: {err:?}");
        };
        assert_eq!(field_path, "auth.stored_output_owner_ttl", "{extra}");
        assert!(reason.contains(why), "{extra}: {reason}");
    }
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

/// The lowered `llmproxy.model_authz` typed_config, as JSON.
fn model_authz_config(config_text: &str) -> serde_json::Value {
    let lowered = lower(&parse(config_text).expect("must parse")).expect("must lower");
    lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"]["http_filters"]
        .as_array()
        .expect("http_filters")
        .iter()
        .find(|f| f["name"] == "llmproxy.model_authz")
        .expect("model_authz in the chain")["typed_config"]
        .clone()
}

/// `tenants_without_policy` (review H4): absent and `deny` add no field (the
/// proto's zero value is DENY); `allow` lowers to `ALLOW`, warns at load, and
/// the strict loader accepts it.
#[test]
fn tenants_without_policy_lowers_deny_by_default_and_allow_loudly() {
    for extra in ["", "  enforce: { tenants_without_policy: deny }\n"] {
        let typed = model_authz_config(&with_auth(extra, PRICING));
        assert!(
            typed.get("tenants_without_policy").is_none(),
            "{extra:?}: {typed}"
        );
    }

    let text = with_auth("  enforce: { tenants_without_policy: allow }\n", PRICING);
    assert_eq!(model_authz_config(&text)["tenants_without_policy"], "ALLOW");
    let lowered = lower(&parse(&text).unwrap()).unwrap();
    assert!(
        lowered
            .warnings
            .iter()
            .any(|w| w.field_path == "auth.enforce.tenants_without_policy"),
        "{:?}",
        lowered.warnings
    );
    lower_to_loaded(&parse(&text).unwrap()).expect("strict loader accepts ALLOW");
}

/// `GET /v1/models` lists exact names from both `routes` and `models`, sorted
/// and deduplicated, never a `*` pattern. With model policy enforced the same
/// list reaches `llmproxy.model_authz`, which answers with the caller's subset
/// before the unfiltered catalogue route is reached; the strict loader and the
/// real factory accept it.
#[test]
fn the_model_catalogue_reaches_model_authz_and_the_catalogue_route() {
    let text = r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: gpt-4o, provider: openai }
  - { model: "claude-*", provider: openai }
models:
  text-embedding-3-small: { providers: [openai] }
  gpt-4o: { providers: [openai] }
  "*": { providers: [openai] }
auth:
  hmac_secret: "test-operator-secret"
  keys: []
"#;
    let expected = ["gpt-4o", "text-embedding-3-small"];
    assert_eq!(
        model_authz_config(text)["model_catalog"],
        serde_json::json!(expected)
    );

    let lowered = lower(&parse(text).unwrap()).unwrap();
    let routes = lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .unwrap();
    let catalog_route = routes
        .iter()
        .find(|route| route["name"] == "llmproxy_model_catalog")
        .expect("catalogue route");
    let body: serde_json::Value = serde_json::from_str(
        catalog_route["direct_response"]["body"]["inline_string"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let ids: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, expected);

    let loaded = lower_to_loaded(&parse(text).unwrap()).expect("strict loader accepts it");
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
            .unwrap()
            .config
            .clone()
            .unwrap()
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
        .expect("model_authz accepts the catalogue");
}

/// A config with no exact model name has nothing to list: no catalogue field,
/// no catalogue route.
#[test]
fn a_wildcard_only_config_has_no_model_catalogue() {
    let typed = model_authz_config(&with_auth("", ""));
    assert!(typed.get("model_catalog").is_none(), "{typed}");
}

#[test]
fn tenants_without_policy_with_model_policy_off_is_a_load_error() {
    let text = with_auth(
        "  enforce: { model_policy: false, tenants_without_policy: allow }\n",
        PRICING,
    );
    match lower(&parse(&text).unwrap()) {
        Err(ConfigError::InvalidValue { field_path, .. }) => {
            assert_eq!(field_path, "auth.enforce.tenants_without_policy")
        }
        other => panic!("expected InvalidValue, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn auth_adds_a_policy_only_token_limit_between_auth_and_usage() {
    let text = with_auth("", PRICING);
    let chain = names(&text);
    let auth = chain.iter().position(|n| n == "llmproxy.auth");
    let limit = chain.iter().position(|n| n == "llmproxy.token_limit");
    let usage = chain.iter().position(|n| n == "llmproxy.usage");
    assert!(
        auth.is_some() && limit.is_some() && auth < limit,
        "{chain:?}"
    );
    if usage.is_some() {
        assert!(limit < usage, "{chain:?}");
    }
    let lowered = lower(&parse(&text).unwrap()).unwrap();
    let filters = lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["http_filters"]
        .as_array()
        .unwrap()
        .clone();
    let typed = &filters
        .iter()
        .find(|f| f["name"] == "llmproxy.token_limit")
        .unwrap()["typed_config"];
    assert!(
        typed.get("max_tokens").is_none() && typed.get("fill_rate").is_none(),
        "no static rule without a `limits` entry: {typed}"
    );
    lower_to_loaded(&parse(&text).unwrap()).expect("strict loader accepts it");
}

#[test]
fn enforce_limits_false_omits_token_limit_and_warns() {
    let text = with_auth("  enforce: { limits: false }\n", PRICING);
    let chain = names(&text);
    assert!(
        !chain.contains(&"llmproxy.token_limit".to_string()),
        "{chain:?}"
    );
    let lowered = lower(&parse(&text).unwrap()).unwrap();
    assert!(
        lowered
            .warnings
            .iter()
            .any(|w| w.field_path == "auth.enforce.limits" && w.message.contains("NOT enforced")),
        "{:?}",
        lowered.warnings
    );
}

#[test]
fn a_limits_entry_keeps_one_token_limit_with_its_static_rule() {
    let tail = format!("{PRICING}limits:\n  - {{ key: tenant, tokens_per_minute: 1000 }}\n");
    let text = with_auth("  enforce: { limits: false }\n", &tail);
    let chain = names(&text);
    assert_eq!(
        chain
            .iter()
            .filter(|n| n.as_str() == "llmproxy.token_limit")
            .count(),
        1,
        "{chain:?}"
    );
    let lowered = lower(&parse(&text).unwrap()).unwrap();
    assert!(
        !lowered
            .warnings
            .iter()
            .any(|w| w.field_path == "auth.enforce.limits"),
        "the filter is present, so tenant and key limits are enforced: {:?}",
        lowered.warnings
    );
}
