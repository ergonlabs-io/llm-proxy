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
    let openai_ts = openai.transport_socket.as_ref().unwrap();
    assert_eq!(openai_ts.sni.as_deref(), Some("api.openai.com"));
    // No `ca_file` configured: the dialect must not fall back to Envoy's
    // "no validation context" default (unverified TLS). It verifies against
    // the platform trust store instead.
    assert!(matches!(
        openai_ts.validation.as_ref().map(|v| &v.ca),
        Some(proxy_config::ir::CaSource::SystemRoots)
    ));
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

/// An `https://` provider with no `ca_file` must still get a validation
/// context — Envoy's raw "no validation context" default means "trust any
/// certificate", which would let a MITM read API keys in flight. The
/// dialect falls back to the platform trust store instead.
#[test]
fn https_provider_without_ca_file_validates_against_system_roots() {
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
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

    let openai = &snapshot.clusters["provider:openai"];
    let ts = openai
        .transport_socket
        .as_ref()
        .expect("https provider must have a transport_socket");
    let validation = ts
        .validation
        .as_ref()
        .expect("no ca_file must still validate against something");
    assert!(matches!(
        validation.ca,
        proxy_config::ir::CaSource::SystemRoots
    ));
    // Chain trust alone is not identity checking (see
    // `proxy-core/tests/upstream_tls.rs`): the dialect must also emit a SAN
    // matcher for the provider's host so a cert for any other domain, even
    // one signed by a trusted public CA, is rejected.
    assert_eq!(validation.san_matchers.len(), 1);
    let m = &validation.san_matchers[0];
    assert!(matches!(m.san_type, proxy_config::ir::SanType::Dns));
    match &m.matcher {
        proxy_config::ir::StringMatcherIR::Exact { value, .. } => {
            assert_eq!(value, "api.openai.com");
        }
        other => panic!("expected an exact DNS matcher, got {other:?}"),
    }
}

/// An `https://` provider with an explicit `ca_file` uses it verbatim
/// (`trusted_ca`), not the system trust store.
#[test]
fn https_provider_with_ca_file_uses_trusted_ca() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY}, ca_file: /etc/ssl/custom-ca.pem }
routes:
  - { model: "*", provider: openai }
"#,
    )
    .expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

    let openai = &snapshot.clusters["provider:openai"];
    let ts = openai.transport_socket.as_ref().unwrap();
    let validation = ts.validation.as_ref().unwrap();
    match &validation.ca {
        proxy_config::ir::CaSource::TrustedCa(proxy_config::ir::DataSourceIR::File(path)) => {
            assert_eq!(path, std::path::Path::new("/etc/ssl/custom-ca.pem"));
        }
        other => panic!("expected TrustedCa(File(..)), got {other:?}"),
    }
    // A custom `ca_file` establishes chain trust but still says nothing
    // about identity: the SAN matcher must be present here too.
    assert_eq!(validation.san_matchers.len(), 1);
    let m = &validation.san_matchers[0];
    assert!(matches!(m.san_type, proxy_config::ir::SanType::Dns));
    match &m.matcher {
        proxy_config::ir::StringMatcherIR::Exact { value, .. } => {
            assert_eq!(value, "api.openai.com");
        }
        other => panic!("expected an exact DNS matcher, got {other:?}"),
    }
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

/// Anthropic rejects every request that lacks `anthropic-version`, so the
/// dialect supplies it automatically. OpenAI providers must NOT get it.
#[test]
fn anthropic_provider_gets_the_required_version_header() {
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

    let keys = |i: usize| -> Vec<String> {
        routes[i]["request_headers_to_add"]
            .as_array()
            .expect("headers must be an array")
            .iter()
            .map(|h| h["header"]["key"].as_str().unwrap().to_string())
            .collect()
    };

    let anthropic = keys(1);
    assert!(
        anthropic.iter().any(|k| k == "anthropic-version"),
        "anthropic provider must get the version header, got {anthropic:?}"
    );
    let openai = keys(0);
    assert!(
        !openai.iter().any(|k| k == "anthropic-version"),
        "openai provider must NOT get an anthropic header, got {openai:?}"
    );
}

/// A user-supplied version wins, and must not be emitted twice. HTTP header
/// names are case-insensitive, so a differently-cased key still counts as an
/// override -- the case that a naive exact-match check would get wrong.
#[test]
fn user_supplied_anthropic_version_overrides_the_default_case_insensitively() {
    let config = parse(
        r#"
version: 0
providers:
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
    extra_headers: { Anthropic-Version: "2099-01-01" }
routes:
  - { model: "claude*", provider: anthropic }
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let headers = lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["route_config"]["virtual_hosts"][0]["routes"][0]
        ["request_headers_to_add"]
        .as_array()
        .expect("headers must be an array")
        .clone();

    let version_headers: Vec<_> = headers
        .iter()
        .filter(|h| {
            h["header"]["key"]
                .as_str()
                .unwrap()
                .eq_ignore_ascii_case("anthropic-version")
        })
        .collect();
    assert_eq!(
        version_headers.len(),
        1,
        "exactly one version header expected, got {version_headers:?}"
    );
    assert_eq!(version_headers[0]["header"]["value"], "2099-01-01");
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

// ------------------------------------------------------------- access logs --

/// Pull the HCM's `typed_config` out of a lowered bootstrap, the same path
/// every other test in this file already indexes into.
fn hcm_typed_config(bootstrap: &serde_json::Value) -> &serde_json::Value {
    &bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
}

#[test]
fn access_logs_stdout_json_lands_on_the_hcm() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  access_logs: { output: stdout, format: json }
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let typed_config = hcm_typed_config(&lowered.bootstrap);
    let entry = &typed_config["access_log"][0];
    assert_eq!(
        entry["typed_config"]["@type"],
        "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog"
    );
    assert_eq!(
        entry["typed_config"]["log_format"]["json_format"]["llm_total_tokens"],
        "%LLM_TOTAL_TOKENS%"
    );
}

#[test]
fn access_logs_file_text_lands_on_the_hcm() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  access_logs: { output: /tmp/x.log, format: text }
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let typed_config = hcm_typed_config(&lowered.bootstrap);
    let entry = &typed_config["access_log"][0];
    assert_eq!(
        entry["typed_config"]["@type"],
        "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog"
    );
    assert_eq!(entry["typed_config"]["path"], "/tmp/x.log");
    let text_format = entry["typed_config"]["log_format"]["text_format"]
        .as_str()
        .expect("text_format must be a string");
    assert!(
        text_format.contains("%LLM_TOTAL_TOKENS%"),
        "got: {text_format}"
    );
}

#[test]
fn access_logs_stderr_selects_the_stderr_sink() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  access_logs: { output: stderr, format: text }
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let typed_config = hcm_typed_config(&lowered.bootstrap);
    let entry = &typed_config["access_log"][0];
    assert_eq!(
        entry["typed_config"]["@type"],
        "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog"
    );
}

/// No `observability` at all: no `access_log` key on the HCM (not even an
/// empty array), and no warning naming the `observability` field path — the
/// stale WP-24 warning this task removes must actually be gone.
#[test]
fn no_observability_emits_no_access_log() {
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
    let typed_config = hcm_typed_config(&lowered.bootstrap);
    assert!(
        typed_config.get("access_log").is_none(),
        "no observability configured must mean no access_log key at all, got {typed_config:?}"
    );
    assert!(
        !lowered
            .warnings
            .iter()
            .any(|w| w.field_path.starts_with("observability")),
        "no observability warning expected, got {:?}",
        lowered.warnings
    );
}

/// The load-bearing check: the emitted `access_log` JSON must not merely be
/// well-shaped, it must actually be *accepted* by the real strict-mode
/// `proxy-config` loader and build IR with exactly one access log entry —
/// for both supported log formats.
#[test]
fn generated_access_log_config_is_accepted_by_the_envoy_loader() {
    for format in ["json", "text"] {
        let config = parse(&format!(
            r#"
version: 0
providers:
  openai: {{ api_key: ${{OPENAI_API_KEY}} }}
routes:
  - {{ model: "*", provider: openai }}
observability:
  access_logs: {{ output: stdout, format: {format} }}
"#,
        ))
        .expect("must parse");
        let loaded = lower_to_loaded(&config)
            .unwrap_or_else(|e| panic!("format {format} must lower and validate: {e}"));
        let snapshot = proxy_config::build_snapshot(&loaded)
            .unwrap_or_else(|e| panic!("format {format} must build IR: {e}"));

        let listener = snapshot
            .listeners
            .values()
            .next()
            .expect("must have exactly one listener");
        let proxy_config::ir::NetworkFilterSpec::HttpConnectionManager(hcm) =
            &listener.filter_chains[0].filters[0]
        else {
            panic!("expected an HTTP connection manager filter for format {format}");
        };
        assert_eq!(
            hcm.access_logs.len(),
            1,
            "expected exactly one access log for format {format}, got {:?}",
            hcm.access_logs
        );
    }
}

// ------------------------------------------------------- WP-33: usage filter --

/// `lower.rs` duplicates the usage filter's type URL as a literal instead of
/// importing it, to keep the data plane out of a config crate's production
/// dependency tree. That trade is only safe if something pins the two
/// together — this is that something.
#[test]
fn usage_filter_type_url_matches_the_filter() {
    // `force_usage_reporting` is off so `http_filters[0]` stays the usage
    // filter; the body-rewrite filter's own type-URL pin lives in
    // `body_rewrite_filter_type_url_matches_the_filter` below.
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  force_usage_reporting: false
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let filters = &lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["http_filters"];

    assert_eq!(
        filters[0]["typed_config"]["@type"],
        proxy_filters::usage_filter::TYPE_URL,
        "the dialect emits a type URL no registered filter factory answers to; \
         this would be a bind-time error on every listener"
    );
    assert_eq!(
        filters[0]["typed_config"]["@type"],
        lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
            ["typed_config"]["route_config"]["virtual_hosts"][0]["routes"][0]
            ["typed_per_filter_config"]["llmproxy.usage"]["@type"],
        "the per-route override must carry the same type URL as the chain entry"
    );
}

/// WP-33 criteria 4 and 5: the usage filter is in the chain ahead of the
/// router, and each route's override names its OWN provider's dialect. A
/// listener-level dialect cannot express this — it is the whole reason the
/// override exists.
#[test]
fn usage_filter_sits_before_the_router_with_per_route_dialects() {
    // `force_usage_reporting` is off here so this test stays scoped to the
    // WP-33 usage filter alone; the body-rewrite filter (WP-45) it would
    // otherwise also emit is covered by its own tests below.
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
  anthropic: { api_key: ${ANTHROPIC_API_KEY} }
routes:
  - { model: "gpt-*", provider: openai }
  - { model: "claude-*", provider: anthropic }
observability:
  force_usage_reporting: false
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let hcm = &lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"]
        [0]["typed_config"];

    // Criterion 4: order matters. The router is terminal — a filter after it
    // is never reached on the encode path.
    let names: Vec<&str> = hcm["http_filters"]
        .as_array()
        .expect("http_filters must be an array")
        .iter()
        .map(|f| f["name"].as_str().expect("filter name must be a string"))
        .collect();
    assert_eq!(names, ["llmproxy.usage", "envoy.filters.http.router"]);

    // Criterion 5: the dialect follows the route, not the listener.
    let routes = &hcm["route_config"]["virtual_hosts"][0]["routes"];
    let dialect =
        |i: usize| routes[i]["typed_per_filter_config"]["llmproxy.usage"]["inline_string"].clone();
    assert_eq!(dialect(0), "openai");
    assert_eq!(dialect(1), "anthropic");
}

/// WP-33 criterion 6: an `openai-compatible` upstream (a `base_url`-only
/// provider, e.g. vLLM/Ollama/TGI) speaks OpenAI's response shape, so it gets
/// the OpenAI dialect — the same `_ =>` fallback `auth_header` uses.
#[test]
fn openai_compatible_provider_gets_the_openai_dialect() {
    let config = parse(
        r#"
version: 0
providers:
  local-vllm: { base_url: "http://127.0.0.1:8000" }
  anthropic: { api_key: ${ANTHROPIC_API_KEY} }
routes:
  - { model: "local-*", provider: local-vllm }
  - { model: "claude-*", provider: anthropic }
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let routes = &lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["route_config"]["virtual_hosts"][0]["routes"];

    assert_eq!(
        routes[0]["typed_per_filter_config"]["llmproxy.usage"]["inline_string"],
        "openai"
    );
    assert_eq!(
        routes[1]["typed_per_filter_config"]["llmproxy.usage"]["inline_string"],
        "anthropic"
    );
}

/// The JSON assertions above only prove the dialect *emits* the override.
/// This proves it survives the full Envoy-mode pipeline — strict parse, PGV,
/// and IR build — and lands on the route the data plane actually reads, with
/// the filter present in the chain (an override naming an absent filter is a
/// hard load error, so this also proves the two names agree).
#[test]
fn per_route_dialect_survives_into_the_ir() {
    // `force_usage_reporting` is off so `http_filters[0]` stays the usage
    // filter, the thing under test here.
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
  anthropic: { api_key: ${ANTHROPIC_API_KEY} }
routes:
  - { model: "gpt-*", provider: openai }
  - { model: "claude-*", provider: anthropic }
observability:
  force_usage_reporting: false
"#,
    )
    .expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

    let listener = snapshot
        .listeners
        .values()
        .next()
        .expect("exactly one listener");
    let proxy_config::ir::NetworkFilterSpec::HttpConnectionManager(hcm) =
        &listener.filter_chains[0].filters[0]
    else {
        panic!("expected an HTTP connection manager");
    };
    assert_eq!(hcm.http_filters[0].name, "llmproxy.usage");

    let routes = &hcm.route_table.virtual_hosts[0].routes;
    for (i, want) in [(0, "openai"), (1, "anthropic")] {
        let per_filter = routes[i]
            .typed_per_filter_config
            .get("llmproxy.usage")
            .unwrap_or_else(|| panic!("route {i} must carry a usage override"));
        assert_eq!(per_filter.type_url, proxy_filters::usage_filter::TYPE_URL);
        assert!(
            !per_filter.disabled,
            "route {i} must not disable the filter"
        );

        // The IR leaves the config undecoded (ground rule #2), so read the
        // dialect back the way the filter's own `parse_per_route` does.
        let msg = per_filter
            .config
            .as_ref()
            .unwrap_or_else(|| panic!("route {i} override must carry a config"));
        let got = msg
            .get_field_by_name("inline_string")
            .expect("DataSource.inline_string")
            .as_str()
            .expect("inline_string must be a string")
            .to_string();
        assert_eq!(got, want, "route {i}");
    }
}

// ------------------------------------------------------- WP-45: body-rewrite filter --

const BASIC_CONFIG: &str = r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
"#;

fn body_rewrite_names(bootstrap: &serde_json::Value) -> Vec<String> {
    hcm_typed_config(bootstrap)["http_filters"]
        .as_array()
        .expect("http_filters must be an array")
        .iter()
        .map(|f| f["name"].as_str().unwrap().to_string())
        .collect()
}

/// `lower.rs` duplicates the body-rewrite filter's type URL as a literal
/// instead of importing it, same trade as the usage filter's. This is the
/// pin that keeps the two from drifting apart.
#[test]
fn body_rewrite_filter_type_url_matches_the_filter() {
    let config = parse(BASIC_CONFIG).expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let filters = &hcm_typed_config(&lowered.bootstrap)["http_filters"];

    assert_eq!(
        filters[0]["typed_config"]["@type"],
        proxy_filters::body_rewrite_filter::TYPE_URL,
        "the dialect emits a type URL no registered filter factory answers to; \
         this would be a bind-time error on every listener"
    );
    assert_eq!(
        filters[0]["typed_config"]["@type"],
        hcm_typed_config(&lowered.bootstrap)["route_config"]["virtual_hosts"][0]["routes"][0]
            ["typed_per_filter_config"]["llmproxy.body_rewrite"]["@type"],
        "the per-route override must carry the same type URL as the chain entry"
    );
}

/// No `observability` block at all: `force_usage_reporting` still defaults
/// to `true`, so the body-rewrite filter is still emitted. This is the case
/// most likely to get the default wrong -- serde's field-level default only
/// covers an explicit-but-empty `observability` block, not an absent one.
#[test]
fn no_observability_block_still_emits_body_rewrite_by_default() {
    let config = parse(BASIC_CONFIG).expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    assert!(
        body_rewrite_names(&lowered.bootstrap).contains(&"llmproxy.body_rewrite".to_string()),
        "the filter must be on by default even with no `observability` block at all"
    );
}

/// An `observability` block that sets only `access_logs` (no
/// `force_usage_reporting` key) must still default the flag to `true`.
#[test]
fn observability_without_the_flag_still_emits_body_rewrite_by_default() {
    let config = parse(&format!(
        "{BASIC_CONFIG}observability:\n  access_logs: {{ output: stdout }}\n"
    ))
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    assert!(
        body_rewrite_names(&lowered.bootstrap).contains(&"llmproxy.body_rewrite".to_string()),
        "an `observability` block present for another reason must not turn the default off"
    );
}

/// `force_usage_reporting: false` leaves no trace of the filter anywhere in
/// the serialized bootstrap -- not the chain, and not any route's
/// `typed_per_filter_config`. Asserted against the whole serialized document
/// so a stray per-route entry can't slip through a narrower check.
#[test]
fn force_usage_reporting_false_leaves_no_trace_of_the_filter() {
    let config = parse(&format!(
        "{BASIC_CONFIG}observability:\n  force_usage_reporting: false\n"
    ))
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let whole = serde_json::to_string(&lowered.bootstrap).unwrap();
    assert!(
        !whole.contains("body_rewrite"),
        "disabling the flag must leave zero trace of the filter, got: {whole}"
    );
    assert!(
        !whole.contains(proxy_filters::body_rewrite_filter::TYPE_URL),
        "disabling the flag must not leave the filter's type URL anywhere, got: {whole}"
    );
}

/// Two-provider config: each route's per-route override carries ITS OWN
/// dialect, not the listener-level default. This is the test that would
/// catch a bug that reuses the listener default for every route.
#[test]
fn body_rewrite_per_route_entries_carry_their_own_dialect() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
  anthropic: { api_key: ${ANTHROPIC_API_KEY} }
routes:
  - { model: "gpt-*", provider: openai }
  - { model: "claude-*", provider: anthropic }
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let routes =
        &hcm_typed_config(&lowered.bootstrap)["route_config"]["virtual_hosts"][0]["routes"];

    let dialect = |i: usize| {
        routes[i]["typed_per_filter_config"]["llmproxy.body_rewrite"]["runtime_key"].clone()
    };
    assert_eq!(dialect(0), "openai");
    assert_eq!(dialect(1), "anthropic");
}

/// The filter is a decode-path filter: it must precede the router in config
/// order, or it never runs at all.
#[test]
fn body_rewrite_filter_sits_before_the_router() {
    let config = parse(BASIC_CONFIG).expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let names = body_rewrite_names(&lowered.bootstrap);
    let body_rewrite_pos = names
        .iter()
        .position(|n| n == "llmproxy.body_rewrite")
        .expect("body_rewrite filter must be present");
    let router_pos = names
        .iter()
        .position(|n| n == "envoy.filters.http.router")
        .expect("router must be present");
    assert!(
        body_rewrite_pos < router_pos,
        "body_rewrite must precede the router, got {names:?}"
    );
}

/// An unknown key inside `observability` is still a strict-mode error with
/// its full dotted path -- adding `force_usage_reporting` must not have
/// loosened `deny_unknown_fields`.
#[test]
fn unknown_observability_key_still_errors_with_path() {
    let err = parse(&format!(
        "{BASIC_CONFIG}observability:\n  force_usage_reportingg: false\n"
    ))
    .expect_err("unknown field must fail");
    let ConfigError::UnknownField { field_path } = &err else {
        panic!("expected UnknownField, got: {err}");
    };
    assert_eq!(field_path, "observability.force_usage_reportingg");
}

/// The body-rewrite counterpart to [`per_route_dialect_survives_into_the_ir`],
/// and it exists for the same reason that one does: the JSON assertions above
/// only prove the dialect *emits* `llmproxy.body_rewrite`, on both the chain
/// and every route, from the same lowering pass. They cannot catch the two
/// names disagreeing, because nothing cross-checks them.
///
/// The full Envoy-mode pipeline does. A `typed_per_filter_config` entry naming
/// a filter that is absent from the chain is a hard build error (that is
/// WP-33's acceptance criterion 3, and `filter_manager::resolve_per_filter_row`
/// is what enforces it), so simply getting through `build_snapshot` with the
/// override attached proves the emitted chain name and the emitted override
/// key agree -- a typo in either one turns this red.
///
/// Note this runs with `force_usage_reporting` at its DEFAULT, unlike the
/// usage-filter tests above which switch it off to stay scoped. Here the
/// default-on path is the point.
#[test]
fn body_rewrite_per_route_config_survives_into_the_ir() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
  anthropic: { api_key: ${ANTHROPIC_API_KEY} }
routes:
  - { model: "gpt-*", provider: openai }
  - { model: "claude-*", provider: anthropic }
"#,
    )
    .expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

    let listener = snapshot
        .listeners
        .values()
        .next()
        .expect("exactly one listener");
    let proxy_config::ir::NetworkFilterSpec::HttpConnectionManager(hcm) =
        &listener.filter_chains[0].filters[0]
    else {
        panic!("expected an HTTP connection manager");
    };
    assert!(
        hcm.http_filters
            .iter()
            .any(|f| f.name == "llmproxy.body_rewrite"),
        "the body-rewrite filter must be in the chain by default; chain was {:?}",
        hcm.http_filters.iter().map(|f| &f.name).collect::<Vec<_>>()
    );

    let routes = &hcm.route_table.virtual_hosts[0].routes;
    for (i, want) in [(0, "openai"), (1, "anthropic")] {
        let per_filter = routes[i]
            .typed_per_filter_config
            .get("llmproxy.body_rewrite")
            .unwrap_or_else(|| panic!("route {i} must carry a body-rewrite override"));
        assert_eq!(
            per_filter.type_url,
            proxy_filters::body_rewrite_filter::TYPE_URL
        );

        // Ground rule #2: the IR leaves the config undecoded, so read the
        // dialect back the way the filter's own `parse_per_route` does --
        // `RuntimeFeatureFlag.runtime_key` carries it.
        let msg = per_filter
            .config
            .as_ref()
            .unwrap_or_else(|| panic!("route {i} override must carry a config"));
        let got = msg
            .get_field_by_name("runtime_key")
            .expect("RuntimeFeatureFlag.runtime_key")
            .as_str()
            .expect("runtime_key must be a string")
            .to_string();
        assert_eq!(got, want, "route {i}");
    }
}
