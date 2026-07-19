//! WP-38 acceptance tests: dialect parsing, env interpolation, semantic
//! validation, and lowering through the full Envoy-mode pipeline
//! (strict parse + PGV validation + IR build).

use proxy_config::ConfigError;
use proxy_simple_config::{
    lower_to_loaded, parse_simple_config_with_env, to_envoy_yaml, MODEL_HEADER,
};

/// Env lookup for tests: FOO_KEY-style names resolve, everything else is unset.
fn test_env(name: &str) -> Option<String> {
    match name {
        "OPENAI_API_KEY" => Some("sk-test-openai".to_string()),
        "ANTHROPIC_API_KEY" => Some("sk-test-anthropic".to_string()),
        _ => None,
    }
}

fn parse(text: &str) -> Result<proxy_simple_config::SimpleConfig, ConfigError> {
    parse_simple_config_with_env(text, &test_env)
}

/// The shipped example config — embedded as `SAMPLE_CONFIG` — parses,
/// lowers, and passes the FULL Envoy-mode pipeline, including PGV validation
/// and IR conversion.
#[test]
fn example_config_lowers_end_to_end() {
    let config = parse(proxy_simple_config::SAMPLE_CONFIG).expect("example must parse");
    let loaded = lower_to_loaded(&config).expect("example must lower and validate");

    // The lowered bootstrap must also build IR (the serve-path contract).
    let snapshot = proxy_config::build_snapshot(&loaded).expect("lowered config must build IR");

    // providers -> clusters, deterministically named.
    let mut names: Vec<_> = snapshot.clusters.keys().cloned().collect();
    names.sort();
    assert_eq!(
        names,
        [
            "provider:anthropic",
            "provider:local-vllm",
            "provider:openai"
        ]
    );

    // openai is https: LOGICAL_DNS + TLS with SNI; local-vllm is plain http.
    let openai = &snapshot.clusters["provider:openai"];
    assert_eq!(openai.endpoints[0].host, "api.openai.com");
    assert_eq!(openai.endpoints[0].port, 443);
    assert_eq!(
        openai.transport_socket.as_ref().unwrap().sni.as_deref(),
        Some("api.openai.com")
    );
    let vllm = &snapshot.clusters["provider:local-vllm"];
    assert_eq!(vllm.endpoints[0].port, 8000);
    assert!(vllm.transport_socket.is_none());

    assert_eq!(snapshot.admin, Some("127.0.0.1:9901".parse().unwrap()));

    // Warnings surface every not-yet-enforced feature (fallbacks, limits, ...).
    assert!(!loaded.warnings.is_empty());
    let all = loaded
        .warnings
        .iter()
        .map(|w| w.field_path.as_str())
        .collect::<Vec<_>>()
        .join(",");
    assert!(all.contains("fallbacks"), "warnings: {all}");
    assert!(all.contains("limits"), "warnings: {all}");
}

/// Model globs lower to the right header matchers on the model header.
#[test]
fn model_globs_lower_to_header_matchers() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "gpt-5", provider: openai }      # exact
  - { model: "gpt-5*", provider: openai }     # prefix
  - { model: "a*b", provider: openai }        # inner glob -> regex
  - { model: "*", provider: openai }          # catch-all: no matcher
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let routes = &lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["route_config"]["virtual_hosts"][0]["routes"];

    let header = |i: usize| &routes[i]["match"]["headers"][0];
    assert_eq!(header(0)["name"], MODEL_HEADER);
    assert_eq!(header(0)["string_match"]["exact"], "gpt-5");
    assert_eq!(header(1)["string_match"]["prefix"], "gpt-5");
    assert_eq!(header(2)["string_match"]["safe_regex"]["regex"], "a.*b");
    assert!(
        routes[3]["match"]["headers"].is_null(),
        "catch-all matches all"
    );
    // A `*` rule exists, so no synthetic 404 route is appended.
    assert_eq!(routes.as_array().unwrap().len(), 4);
}

/// Without a `*` rule, a 404 direct-response backstop is appended.
#[test]
fn missing_catch_all_gets_404_backstop() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "gpt-5*", provider: openai }
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let routes = &lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["route_config"]["virtual_hosts"][0]["routes"];
    let last = routes.as_array().unwrap().last().unwrap();
    assert_eq!(last["direct_response"]["status"], 404);
}

/// Auth headers: Bearer for OpenAI-shaped, x-api-key for Anthropic; always
/// overwrite (client-sent auth never leaks upstream).
#[test]
fn auth_headers_per_provider_type() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
  anthropic: { api_key: ${ANTHROPIC_API_KEY} }
routes:
  - { model: "gpt*", provider: openai }
  - { model: "claude*", provider: anthropic }
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let routes = &lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["route_config"]["virtual_hosts"][0]["routes"];

    let hdr = |i: usize| &routes[i]["request_headers_to_add"][0];
    assert_eq!(hdr(0)["header"]["key"], "authorization");
    assert_eq!(hdr(0)["header"]["value"], "Bearer sk-test-openai");
    assert_eq!(hdr(0)["append_action"], "OVERWRITE_IF_EXISTS_OR_ADD");
    assert_eq!(hdr(1)["header"]["key"], "x-api-key");
    assert_eq!(hdr(1)["header"]["value"], "sk-test-anthropic");
}

/// LLM-safe defaults: total timeout disabled, 90s idle, retries only on
/// certainly-unserved failures.
#[test]
fn llm_safe_route_defaults() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let action = &lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["route_config"]["virtual_hosts"][0]["routes"][0]["route"];
    assert_eq!(action["timeout"], "0s"); // disabled, not 15s
    assert_eq!(action["idle_timeout"], "90s");
    assert_eq!(action["retry_policy"]["num_retries"], 1);
    assert_eq!(
        action["retry_policy"]["retry_on"],
        "connect-failure,refused-stream,reset,retriable-status-codes"
    );
    assert_eq!(action["host_rewrite_literal"], "api.openai.com");
}

/// Unknown fields error with their path — same standard as Envoy mode.
#[test]
fn unknown_field_errors_with_path() {
    let err = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY}, api_keyy: oops }
routes:
  - { model: "*", provider: openai }
"#,
    )
    .expect_err("unknown field must fail");
    let ConfigError::UnknownField { field_path } = &err else {
        panic!("expected UnknownField, got: {err}");
    };
    assert_eq!(field_path, "providers.openai.api_keyy");
}

/// Reserved top-level keys get a dedicated forward-compat error.
#[test]
fn reserved_key_is_rejected_with_explanation() {
    let err = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
clusters: []
"#,
    )
    .expect_err("reserved key must fail");
    let ConfigError::UnsupportedField { field_path, reason } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert_eq!(field_path, "clusters");
    assert!(reason.contains("reserved"), "got: {reason}");
}

#[test]
fn api_key_and_file_are_mutually_exclusive() {
    let err = parse(
        r#"
version: 0
providers:
  openai: { api_key: k, api_key_file: /tmp/f }
routes:
  - { model: "*", provider: openai }
"#,
    )
    .expect_err("both key sources must fail");
    assert!(err.to_string().contains("not both"), "got: {err}");
}

#[test]
fn route_to_unknown_provider_fails() {
    let err = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: nonexistent }
"#,
    )
    .expect_err("unknown provider must fail");
    let ConfigError::InvalidValue { field_path, reason } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "routes[0].provider");
    assert!(
        reason.contains("openai"),
        "should list known providers: {reason}"
    );
}

#[test]
fn unknown_provider_without_base_url_fails() {
    let err = parse(
        r#"
version: 0
providers:
  my-backend: {}
routes:
  - { model: "*", provider: my-backend }
"#,
    )
    .expect_err("no base_url must fail");
    assert!(err.to_string().contains("base_url"), "got: {err}");
}

#[test]
fn missing_env_var_names_the_variable() {
    let err = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${DEFINITELY_NOT_SET_VAR} }
routes:
  - { model: "*", provider: openai }
"#,
    )
    .expect_err("missing env var must fail");
    assert!(
        err.to_string().contains("DEFINITELY_NOT_SET_VAR"),
        "got: {err}"
    );
}

#[test]
fn future_schema_version_is_refused() {
    let err = parse("version: 7\nproviders: { openai: {} }\nroutes: []")
        .expect_err("future version must fail");
    assert!(err.to_string().contains("version 0"), "got: {err}");
}

#[test]
fn token_amounts_and_durations_parse() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY}, connect_timeout: 500ms }
routes:
  - { model: "*", provider: openai, idle_timeout: 5m }
limits:
  - { key: global, tokens_per_minute: 100k, requests_per_minute: 250 }
"#,
    )
    .expect("must parse");
    use proxy_simple_config::model::{LimitKey, TokenAmount};
    assert_eq!(config.limits[0].key, LimitKey::Global);
    assert_eq!(
        config.limits[0].tokens_per_minute,
        Some(TokenAmount(100_000))
    );
    assert_eq!(config.limits[0].requests_per_minute, Some(TokenAmount(250)));
    assert_eq!(
        config.routes[0].idle_timeout.unwrap().0,
        std::time::Duration::from_secs(300)
    );
    assert_eq!(
        config.providers["openai"].connect_timeout.unwrap().0,
        std::time::Duration::from_millis(500)
    );
}

/// `--mode translate` output is valid YAML that Envoy-mode strict parsing
/// accepts round-trip. Uses the full sample config so the round-trip covers
/// every dialect feature the sample exercises (fallbacks, limits, TLS,
/// access logs, ...).
#[test]
fn translate_output_round_trips_through_envoy_mode() {
    let config = proxy_simple_config::sample_config();
    let (yaml, _warnings) = to_envoy_yaml(&config).expect("must translate");
    let loaded = proxy_config::parse_bootstrap(
        yaml.as_bytes(),
        proxy_config::ConfigFormat::Yaml,
        proxy_config::StrictMode::Strict,
    )
    .expect("translate output must be strict-valid Envoy config");
    proxy_config::build_snapshot(&loaded).expect("and must build IR");
}

/// `sample_config()` is self-contained: it needs no real environment
/// variables, and its output lowers and validates on its own, exactly as
/// the crate-level doctest promises.
#[test]
fn sample_config_helper_is_self_contained() {
    let config = proxy_simple_config::sample_config();
    lower_to_loaded(&config).expect("sample_config() output must lower and validate");
}
