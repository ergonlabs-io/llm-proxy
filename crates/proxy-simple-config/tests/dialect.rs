//! Acceptance tests: dialect parsing, env interpolation, semantic
//! validation, and lowering through the full Envoy-mode pipeline
//! (strict parse + PGV validation + IR build).

use proxy_config::{ConfigError, ConfigFrontEnd, UNKNOWN_FIELD_DIALECT_HINT};
use proxy_simple_config::{
    lower, lower_to_loaded, parse_simple_config_with_env, to_envoy_yaml, MODEL_HEADER,
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

    // providers -> clusters, deterministically named, plus one aggregate per
    // route that declares `fallbacks`. The example's
    // `gpt-5*` route falls back to `local-vllm`, so it gets
    // `fallback:route-0`.
    let mut names: Vec<_> = snapshot.clusters.keys().cloned().collect();
    names.sort();
    assert_eq!(
        names,
        [
            "fallback:route-0",
            "provider:anthropic",
            "provider:local-vllm",
            "provider:openai"
        ]
    );

    // The aggregate really is one, and its members are in failover order --
    // primary first. Asserting the kind (not just the name) is what proves
    // the dialect emitted something our own strict loader accepted as an
    // aggregate rather than a cluster that merely happens to be called
    // `fallback:...`.
    let aggregate = snapshot
        .clusters
        .get("fallback:route-0")
        .expect("aggregate cluster");
    match &aggregate.kind {
        proxy_config::ir::ClusterKind::Aggregate { members } => assert_eq!(
            members,
            &vec![
                "provider:openai".to_string(),
                "provider:local-vllm".to_string()
            ]
        ),
        other => panic!("expected ClusterKind::Aggregate, got {other:?}"),
    }

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

    // Warnings surface every not-yet-enforced feature (limits, ...).
    assert!(!loaded.warnings.is_empty());
    let all = loaded
        .warnings
        .iter()
        .map(|w| w.field_path.as_str())
        .collect::<Vec<_>>()
        .join(",");
    assert!(all.contains("limits"), "warnings: {all}");
    // `fallbacks` must NOT warn any more: fallback lowering implements it,
    // and this route's chain really does lower to the `fallback:route-0`
    // aggregate asserted above. A warning here would mean the feature had
    // silently regressed to being parsed-and-dropped, which is the state fallback
    // lowering removed.
    assert!(
        !all.contains("fallbacks"),
        "fallbacks are implemented and must not warn; warnings: {all}"
    );
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

#[test]
fn route_streaming_strict_reaches_the_ir_assertion() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - model: "*"
    provider: openai
    streaming: strict
"#,
    )
    .expect("strict streaming config must parse");
    let loaded =
        lower_to_loaded(&config).expect("strict streaming must survive strict Envoy parsing");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must lower to IR");
    let listener = snapshot
        .listeners
        .get("llmproxy_listener")
        .expect("simple lowering names its listener");
    let proxy_config::ir::NetworkFilterSpec::HttpConnectionManager(hcm) =
        &listener.filter_chains[0].filters[0]
    else {
        panic!("simple listener's first network filter must be an HCM");
    };
    let route = &hcm.route_table.virtual_hosts[0].routes[0];
    assert!(
        route.streaming_strict,
        "route metadata must become the IR assertion"
    );
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

/// `protocol: http2` on a provider must reach the IR as
/// `UpstreamProtocol::Http2` on that provider's cluster -- asserted on the
/// IR, not the intermediate JSON, since the JSON being right but the IR
/// being wrong (a drift between this dialect's `HTTP_PROTOCOL_OPTIONS_KEY`
/// and `proxy_config::lower`'s reader) is exactly the failure this test
/// exists to catch. This is the on-ramp to `proxy-http::upstream_pool`'s h2
/// upstream connection cache.
#[test]
fn provider_protocol_http2_reaches_the_ir() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY}, protocol: http2 }
routes:
  - { model: "*", provider: openai }
"#,
    )
    .expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

    assert_eq!(
        snapshot.clusters["provider:openai"].upstream_protocol,
        proxy_config::ir::UpstreamProtocol::Http2,
    );
}

/// Omitting `protocol` entirely must still yield `Http1` -- Envoy's own
/// default for an unconfigured cluster, and the behavior every config
/// predating this field already has.
#[test]
fn provider_protocol_defaults_to_http1() {
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

    assert_eq!(
        snapshot.clusters["provider:openai"].upstream_protocol,
        proxy_config::ir::UpstreamProtocol::Http1,
    );
}

/// An unknown `protocol` value is a load error naming the full dotted path
/// (AGENTS.md invariant 1) -- never a silent fallback to `http1`.
#[test]
fn provider_protocol_bad_value_errors_with_path() {
    let err = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY}, protocol: http3 }
routes:
  - { model: "*", provider: openai }
"#,
    )
    .expect_err("unknown protocol value must fail");
    let ConfigError::InvalidValue { field_path, .. } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "providers.openai.protocol");
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

/// The `io.llmproxy.provider_auth` namespace under a named cluster's
/// `metadata.filter_metadata`, i.e. the exact shape
/// `proxy_config::lower::convert_provider_auth_metadata` reads back out --
/// see `ClusterConfig::request_headers_to_add`'s doc comment for why this
/// lives on the CLUSTER rather than the route.
fn provider_auth_headers<'a>(
    bootstrap: &'a serde_json::Value,
    cluster_name: &str,
) -> &'a [serde_json::Value] {
    let clusters = bootstrap["static_resources"]["clusters"]
        .as_array()
        .expect("clusters must be an array");
    let cluster = clusters
        .iter()
        .find(|c| c["name"] == cluster_name)
        .unwrap_or_else(|| panic!("no cluster named `{cluster_name}`"));
    cluster["metadata"]["filter_metadata"]["io.llmproxy.provider_auth"]["headers"]
        .as_array()
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

/// Auth headers: Bearer for OpenAI-shaped, x-api-key for Anthropic; carried
/// on the provider's CLUSTER, never the route -- a route-level credential
/// would leak the primary provider's key to a fallback's endpoint once one
/// request can reach two providers.
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
    let bootstrap = &lowered.bootstrap;

    // No route carries a credential -- the whole point of this move.
    let routes = &bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"]["route_config"]["virtual_hosts"][0]["routes"];
    for route in routes.as_array().unwrap() {
        assert!(
            route["request_headers_to_add"].is_null(),
            "provider auth must not be on the route: {route}"
        );
    }

    let openai = provider_auth_headers(bootstrap, "provider:openai");
    assert_eq!(openai[0]["key"], "authorization");
    assert_eq!(openai[0]["value"], "Bearer sk-test-openai");

    let anthropic = provider_auth_headers(bootstrap, "provider:anthropic");
    assert_eq!(anthropic[0]["key"], "x-api-key");
    assert_eq!(anthropic[0]["value"], "sk-test-anthropic");

    // Two providers, two clusters: provider A's key must never appear on
    // provider B's cluster -- this is the whole point.
    let openai_values: Vec<_> = openai.iter().map(|h| h["value"].as_str()).collect();
    let anthropic_values: Vec<_> = anthropic.iter().map(|h| h["value"].as_str()).collect();
    assert!(
        !openai_values.contains(&Some("sk-test-anthropic")),
        "anthropic's key leaked onto the openai cluster: {openai:?}"
    );
    assert!(
        !anthropic_values.contains(&Some("sk-test-openai")),
        "openai's key leaked onto the anthropic cluster: {anthropic:?}"
    );
}

/// Anthropic rejects every request that lacks `anthropic-version`, so the
/// dialect supplies it automatically, on the cluster. OpenAI providers must
/// NOT get it.
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
    let bootstrap = &lowered.bootstrap;

    let keys = |cluster_name: &str| -> Vec<String> {
        provider_auth_headers(bootstrap, cluster_name)
            .iter()
            .map(|h| h["key"].as_str().unwrap().to_string())
            .collect()
    };

    let anthropic = keys("provider:anthropic");
    assert!(
        anthropic.iter().any(|k| k == "anthropic-version"),
        "anthropic provider must get the version header, got {anthropic:?}"
    );
    let openai = keys("provider:openai");
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
    let headers = provider_auth_headers(&lowered.bootstrap, "provider:anthropic");

    let version_headers: Vec<_> = headers
        .iter()
        .filter(|h| {
            h["key"]
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
    assert_eq!(version_headers[0]["value"], "2099-01-01");
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
    let ConfigError::UnknownField {
        field_path,
        front_end,
    } = &err
    else {
        panic!("expected UnknownField, got: {err}");
    };
    assert_eq!(field_path, "providers.openai.api_keyy");
    assert_eq!(*front_end, ConfigFrontEnd::Dialect);
    // The dialect is always strict -- `--permissive` does nothing here, so
    // the message must not send the user to try it, and must not name the
    // format it didn't write. Pinned against the real constant.
    assert_eq!(
        err.to_string(),
        format!("unknown field at `{field_path}`: {UNKNOWN_FIELD_DIALECT_HINT}")
    );
    assert!(!err.to_string().contains("--permissive"));
    assert!(!err.to_string().contains("Envoy"));
    assert!(err.to_string().contains("llmproxy-v0.schema.json"));
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

/// The dialect has no custom format, so its two default formats are the only
/// way a dialect user can tell a tenant-credential (BYOK) request from a
/// platform-credential one in the access log.
#[test]
fn default_access_log_formats_carry_the_credential_source() {
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
        let lowered = proxy_simple_config::lower(&config).expect("must lower");
        let log_format =
            &hcm_typed_config(&lowered.bootstrap)["access_log"][0]["typed_config"]["log_format"];
        if format == "json" {
            assert_eq!(
                log_format["json_format"]["llm_credential_source"],
                "%LLM_CREDENTIAL_SOURCE%"
            );
        } else {
            let text = log_format["text_format"].as_str().expect("text_format");
            assert!(
                text.contains("llm_credential_source=\"%LLM_CREDENTIAL_SOURCE%\""),
                "text format must carry the credential source, got {text}"
            );
        }
    }
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
/// stale warning this task removes must actually be gone.
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

// ---------------------------------------------------- tracing --

/// No `observability.tracing` at all -- the overwhelming majority of
/// configs -- must mean no `node` key at all on the lowered bootstrap, and
/// `ConfigSnapshot::tracing` stays `None` all the way through.
#[test]
fn no_tracing_block_emits_no_node_key() {
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
    assert!(
        lowered.bootstrap.get("node").is_none(),
        "no tracing configured must mean no node key at all, got {:?}",
        lowered.bootstrap
    );
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");
    assert_eq!(snapshot.tracing, None);
}

/// The load-bearing check: `observability.tracing` lowers all the way
/// through the real Envoy-mode loader (which rejects the real
/// `HttpConnectionManager.tracing` field outright -- see `convert_hcm`) and
/// into `ConfigSnapshot::tracing`, with the dialect's own defaults applied.
#[test]
fn tracing_block_lowers_end_to_end() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  tracing:
    otlp_endpoint: "http://localhost:4317"
    service_name: "my-gateway"
    sample_ratio: 0.5
"#,
    )
    .expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");
    assert_eq!(
        snapshot.tracing,
        Some(proxy_config::ir::TracingConfig {
            otlp_endpoint: "http://localhost:4317".to_string(),
            service_name: "my-gateway".to_string(),
            sample_ratio: 0.5,
            export_deadline: std::time::Duration::from_secs(5),
        })
    );
}

/// `service_name` and `sample_ratio` both default when omitted -- only
/// `otlp_endpoint` is required.
#[test]
fn tracing_block_defaults_service_name_and_sample_ratio() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  tracing:
    otlp_endpoint: "http://collector:4317"
"#,
    )
    .expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");
    assert_eq!(
        snapshot.tracing,
        Some(proxy_config::ir::TracingConfig {
            otlp_endpoint: "http://collector:4317".to_string(),
            service_name: "llm-proxy".to_string(),
            sample_ratio: 1.0,
            export_deadline: std::time::Duration::from_secs(5),
        })
    );
}

/// AGENTS.md invariant 1: a missing `otlp_endpoint` is a hard error naming the exact
/// field, not a silently-off tracing block -- the operator wrote
/// `observability.tracing`, so something must have been meant by it.
#[test]
fn tracing_block_without_otlp_endpoint_is_a_hard_error() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  tracing: {}
"#,
    )
    .expect("must parse");
    let err = proxy_simple_config::lower(&config)
        .expect_err("a tracing block with no otlp_endpoint must not lower");
    let ConfigError::InvalidValue { field_path, .. } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "observability.tracing.otlp_endpoint");
}

/// An out-of-range `sample_ratio` is rejected with its own dotted path,
/// never silently clamped.
#[test]
fn tracing_block_sample_ratio_out_of_range_is_a_hard_error() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  tracing:
    otlp_endpoint: "http://localhost:4317"
    sample_ratio: 1.5
"#,
    )
    .expect("must parse");
    let err =
        proxy_simple_config::lower(&config).expect_err("sample_ratio above 1.0 must not lower");
    let ConfigError::InvalidValue { field_path, .. } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "observability.tracing.sample_ratio");
}

/// The top-level `tracing:` key stays reserved -- this feature nests under
/// `observability` on purpose (see `RESERVED_KEYS`'s doc in `model.rs`), and
/// this guards against silently un-reserving it while adding the nested
/// block.
#[test]
fn top_level_tracing_key_is_still_reserved() {
    let err = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
tracing:
  otlp_endpoint: "http://localhost:4317"
"#,
    )
    .expect_err("top-level tracing must still be rejected");
    let ConfigError::UnsupportedField { field_path, reason } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert_eq!(field_path, "tracing");
    assert!(reason.contains("reserved"), "got: {reason}");
}

// ------------------------------------------ metric export --

/// No `observability` at all means no `node` key on the lowered bootstrap, and
/// both OTLP surfaces stay `None` all the way through. The metrics mirror of
/// `no_tracing_block_emits_no_node_key`, and the reason both exist is the same:
/// an accidental default here would be an operator's proxy silently shipping
/// telemetry somewhere they did not name.
#[test]
fn no_observability_blocks_emit_no_node_key() {
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
    assert!(
        lowered.bootstrap.get("node").is_none(),
        "no observability configured must mean no node key at all, got {:?}",
        lowered.bootstrap
    );
    let snapshot =
        proxy_config::build_snapshot(&lower_to_loaded(&config).expect("must lower")).expect("IR");
    assert_eq!(snapshot.tracing, None);
    assert_eq!(snapshot.metrics, None);
}

/// The load-bearing case for the whole change: `observability.metrics`
/// lowers all the way through the real Envoy-mode loader into
/// `ConfigSnapshot::metrics` with NO `tracing` block present. Before the split
/// this configuration was inexpressible -- metrics were only ever exported by
/// the task spawned for a `TracingConfig`.
#[test]
fn metrics_block_lowers_end_to_end_with_tracing_absent() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  metrics:
    otlp_endpoint: "http://localhost:4317"
    service_name: "my-gateway"
    export_interval: "30s"
    export_deadline: "5s"
"#,
    )
    .expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

    assert_eq!(
        snapshot.tracing, None,
        "a metrics block must not imply tracing is on"
    );
    assert_eq!(
        snapshot.metrics,
        Some(proxy_config::ir::MetricsExportConfig {
            otlp_endpoint: "http://localhost:4317".to_string(),
            service_name: "my-gateway".to_string(),
            // The dialect's `"30s"` string form must arrive as 30 *seconds*,
            // matching what a raw Envoy config's plain `30` means -- if the two
            // front ends disagreed about the unit, the same number would mean
            // two different intervals depending on which dialect wrote it.
            export_interval: std::time::Duration::from_secs(30),
            export_deadline: std::time::Duration::from_secs(5),
        })
    );
}

/// Both blocks together must land as two sibling keys under ONE
/// `node.metadata`, with neither clobbering the other. This is a real
/// regression target, not a theoretical one: the lowering used to assign
/// `bootstrap["node"]` once per block, so whichever came second would have
/// replaced the first entirely -- silently disabling whichever surface the
/// dialect happened to list first in the file.
#[test]
fn both_observability_blocks_emit_both_metadata_keys() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  tracing:
    otlp_endpoint: "http://traces:4317"
  metrics:
    otlp_endpoint: "http://metrics:4317"
"#,
    )
    .expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

    let tracing = snapshot.tracing.expect("tracing configured");
    let metrics = snapshot.metrics.expect("metrics configured");
    assert_eq!(tracing.otlp_endpoint, "http://traces:4317");
    assert_eq!(metrics.otlp_endpoint, "http://metrics:4317");
}

/// The order-dependence the previous test is really about, pinned directly:
/// `metrics` listed BEFORE `tracing` in the same file must produce the same
/// two-key result. A "whichever is written last wins" bug would pass the
/// tracing-first test above and fail this one.
#[test]
fn metrics_before_tracing_still_keeps_both_blocks() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  metrics:
    otlp_endpoint: "http://metrics:4317"
  tracing:
    otlp_endpoint: "http://traces:4317"
"#,
    )
    .expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");
    assert_eq!(
        snapshot.tracing.expect("tracing").otlp_endpoint,
        "http://traces:4317"
    );
    assert_eq!(
        snapshot.metrics.expect("metrics").otlp_endpoint,
        "http://metrics:4317"
    );
}

/// `service_name` and both durations default when omitted; only `otlp_endpoint`
/// is required.
#[test]
fn metrics_block_defaults_service_name_and_durations() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  metrics:
    otlp_endpoint: "http://collector:4317"
"#,
    )
    .expect("must parse");
    let snapshot = proxy_config::build_snapshot(&lower_to_loaded(&config).expect("must lower"))
        .expect("must build IR");
    let metrics = snapshot.metrics.expect("configured");
    assert_eq!(metrics.service_name, "llm-proxy");
    assert_eq!(metrics.export_interval, std::time::Duration::from_secs(15));
    assert_eq!(metrics.export_deadline, std::time::Duration::from_secs(10));
}

/// AGENTS.md invariant 1: a `metrics` block with no `otlp_endpoint` is a hard error
/// with the operator-facing dialect path -- not a silently-disabled block.
#[test]
fn metrics_block_without_otlp_endpoint_is_a_hard_error() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  metrics: {}
"#,
    )
    .expect("must parse");
    let err = proxy_simple_config::lower(&config)
        .expect_err("a metrics block with no otlp_endpoint must not lower");
    let ConfigError::InvalidValue { field_path, .. } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "observability.metrics.otlp_endpoint");
}

/// An unknown key inside the block is rejected by serde's
/// `deny_unknown_fields`, named against the block's own path rather than the
/// whole file.
#[test]
fn metrics_block_rejects_unknown_keys() {
    let err = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  metrics:
    otlp_endpoint: "http://localhost:4317"
    interval: "30s"
"#,
    )
    .expect_err("an unknown key must not parse");
    let text = err.to_string();
    assert!(
        text.contains("observability.metrics") || text.contains("interval"),
        "error should name the offending field, got: {text}"
    );
}

/// A duration that does not match the dialect's own syntax is rejected at
/// PARSE time, naming the dialect path -- before it can reach the Envoy-mode
/// reader, which would otherwise report a `node.metadata[...]`-rooted path for
/// what is plainly a dialect syntax error.
#[test]
fn metrics_block_rejects_a_malformed_duration() {
    let err = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  metrics:
    otlp_endpoint: "http://localhost:4317"
    export_interval: "30 seconds"
"#,
    )
    .expect_err("a malformed duration must not parse");
    let text = err.to_string();
    assert!(
        text.contains("export_interval"),
        "error should name export_interval, got: {text}"
    );
}

/// The cross-field rule (`export_deadline` must be shorter than
/// `export_interval`) is enforced by the Envoy-mode reader, not reimplemented
/// here -- `lower_metrics`'s doc says why. The error therefore still names a
/// full dotted path, just one rooted at the carrier this dialect lowered
/// through, and it MUST still be an error rather than a config that loads and
/// then times out on every single tick.
#[test]
fn deadline_at_or_above_the_interval_is_rejected_end_to_end() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  metrics:
    otlp_endpoint: "http://localhost:4317"
    export_interval: "10s"
    export_deadline: "10s"
"#,
    )
    .expect("must parse");
    // The rejection lands in `build_snapshot`, not in `lower_to_loaded`: the
    // dialect's own parse and lowering both succeed (they emit the two durations
    // verbatim), and it is the Envoy-mode IR build that owns the cross-field
    // rule. Asserting on the right stage matters -- a test written against
    // `lower_to_loaded` would pass for the wrong reason if the check were ever
    // duplicated into the dialect, and would fail confusingly if it were not.
    let loaded = lower_to_loaded(&config).expect("dialect parse+lower must succeed");
    let err =
        proxy_config::build_snapshot(&loaded).expect_err("deadline >= interval must not build");
    let ConfigError::InvalidValue { field_path, reason } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(
        field_path,
        "node.metadata[\"io.llmproxy.metrics\"].export_deadline"
    );
    assert!(
        reason.contains("export_interval"),
        "the message must state the relationship, got: {reason}"
    );
}

/// A malformed duration reaching the Envoy-mode reader through a path that
/// bypasses the dialect's own parser is still rejected there -- the
/// authoritative check lives in `convert_metrics_metadata`, and this is the
/// test that would catch someone deleting it and trusting the dialect alone.
#[test]
fn the_envoy_mode_reader_enforces_its_own_bounds() {
    // An explicit 30s deadline against the 15s DEFAULT interval, so this
    // exercises the reader's cross-field check against a defaulted value rather
    // than against an explicit one -- the case an implementation that only
    // compares when the interval was supplied would get wrong.
    let yaml = r#"
node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://localhost:4317"
      export_deadline: 30
"#;
    let loaded = proxy_config::parse_bootstrap(
        yaml.as_bytes(),
        proxy_config::ConfigFormat::Yaml,
        proxy_config::StrictMode::Strict,
    )
    .expect("must parse");
    let err = proxy_config::build_snapshot(&loaded)
        .expect_err("a deadline above the defaulted interval must not build");
    let ConfigError::InvalidValue { field_path, .. } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(
        field_path,
        "node.metadata[\"io.llmproxy.metrics\"].export_deadline"
    );
}

// ------------------------------------------------------- usage filter --

/// `lower.rs` duplicates the usage filter's type URL as a literal instead of
/// importing it, to keep the data plane out of a config crate's production
/// dependency tree. That trade is only safe if something pins the two
/// together — this is that something.
#[test]
fn usage_filter_type_url_matches_the_filter() {
    // `force_usage_reporting` is off, but `routes` is non-empty, so
    // `needs_body_rewrite_filter` still inserts the body-rewrite filter
    // (disabled, for consumer B only) ahead of the usage filter --
    // `http_filters[1]` is the usage filter under test here. The
    // body-rewrite filter's own type-URL pin lives in
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
        filters[1]["typed_config"]["@type"],
        proxy_filters::usage_filter::TYPE_URL,
        "the dialect emits a type URL no registered filter factory answers to; \
         this would be a bind-time error on every listener"
    );
    assert_eq!(
        filters[1]["typed_config"]["@type"],
        lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
            ["typed_config"]["route_config"]["virtual_hosts"][0]["routes"][0]
            ["typed_per_filter_config"]["llmproxy.usage"]["@type"],
        "the per-route override must carry the same type URL as the chain entry"
    );
}

/// The usage filter is in the chain ahead of the
/// router, and each route's override names its OWN provider's dialect. A
/// listener-level dialect cannot express this — it is the whole reason the
/// override exists.
#[test]
fn usage_filter_sits_before_the_router_with_per_route_dialects() {
    // `force_usage_reporting` is off, but `routes` is non-empty, so
    // `needs_body_rewrite_filter` still inserts the (disabled) body-rewrite
    // filter ahead of everything else -- it's a decode-path filter and must
    // precede the router in config order regardless of whether consumer A
    // is turned on.
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
    assert_eq!(
        names,
        [
            "llmproxy.body_rewrite",
            "llmproxy.usage",
            "envoy.filters.http.router"
        ]
    );

    // Criterion 5: the dialect follows the route, not the listener.
    let routes = &hcm["route_config"]["virtual_hosts"][0]["routes"];
    let dialect =
        |i: usize| routes[i]["typed_per_filter_config"]["llmproxy.usage"]["dialect"].clone();
    assert_eq!(dialect(0), "openai");
    assert_eq!(dialect(1), "anthropic");
}

/// An `openai-compatible` upstream (a `base_url`-only
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
        routes[0]["typed_per_filter_config"]["llmproxy.usage"]["dialect"],
        "openai"
    );
    assert_eq!(
        routes[1]["typed_per_filter_config"]["llmproxy.usage"]["dialect"],
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
    // `force_usage_reporting` is off, but `routes` is non-empty, so
    // `http_filters[0]` is the (disabled) body-rewrite filter and
    // `http_filters[1]` is the usage filter, the thing under test here.
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
    assert_eq!(hcm.http_filters[0].name, "llmproxy.body_rewrite");
    assert_eq!(hcm.http_filters[1].name, "llmproxy.usage");

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

        // The IR leaves the config undecoded (AGENTS.md invariant 2), so read the
        // dialect back the way the filter's own `parse_per_route` does.
        let msg = per_filter
            .config
            .as_ref()
            .unwrap_or_else(|| panic!("route {i} override must carry a config"));
        let got = msg
            .get_field_by_name("dialect")
            .expect("Usage.dialect")
            .as_str()
            .expect("dialect must be a string")
            .to_string();
        assert_eq!(got, want, "route {i}");
    }
}

// ------------------------------------------------------- body-rewrite filter --

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

/// `force_usage_reporting: false` turns consumer A (the `include_usage`
/// splice) off, but must NOT remove the filter from the chain: `routes` is
/// non-empty (a config with no routes fails semantic validation), so
/// consumer B (body-based model routing) still needs it
/// present. Pins the specific shape that must survive the flag being off:
/// the listener-level entry stays, `enabled` flips to `false`, and no
/// route gets a `typed_per_filter_config` override for it (that override
/// only ever exists to carry consumer A's per-route dialect, so it has
/// nothing to say when consumer A is off).
#[test]
fn force_usage_reporting_false_disables_the_splice_but_keeps_the_filter_for_routing() {
    let config = parse(&format!(
        "{BASIC_CONFIG}observability:\n  force_usage_reporting: false\n"
    ))
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let hcm = hcm_typed_config(&lowered.bootstrap);

    let body_rewrite_entry = hcm["http_filters"]
        .as_array()
        .expect("http_filters must be an array")
        .iter()
        .find(|f| f["name"] == "llmproxy.body_rewrite")
        .expect("the body-rewrite filter must still be in the chain (consumer B needs it)");
    assert_eq!(
        body_rewrite_entry["typed_config"]["enabled"], false,
        "the operator's `force_usage_reporting: false` must reach `enabled`"
    );

    let routes = &hcm["route_config"]["virtual_hosts"][0]["routes"];
    assert!(
        routes[0]["typed_per_filter_config"]["llmproxy.body_rewrite"].is_null(),
        "no per-route override should exist when consumer A is off -- it exists only \
         to carry consumer A's per-route dialect"
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

    let dialect =
        |i: usize| routes[i]["typed_per_filter_config"]["llmproxy.body_rewrite"]["dialect"].clone();
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
    let ConfigError::UnknownField { field_path, .. } = &err else {
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
/// the usage filter's acceptance criterion, and `filter_manager::resolve_per_filter_row`
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

        // AGENTS.md invariant 2: the IR leaves the config undecoded, so read the
        // dialect back the way the filter's own `parse_per_route` does --
        // `BodyRewrite.dialect` carries it.
        let msg = per_filter
            .config
            .as_ref()
            .unwrap_or_else(|| panic!("route {i} override must carry a config"));
        let got = msg
            .get_field_by_name("dialect")
            .expect("BodyRewrite.dialect")
            .as_str()
            .expect("dialect must be a string")
            .to_string();
        assert_eq!(got, want, "route {i}");
    }
}

// ------------------------------------------------------- limits --

fn token_limit_names(bootstrap: &serde_json::Value) -> Vec<String> {
    hcm_typed_config(bootstrap)["http_filters"]
        .as_array()
        .expect("http_filters must be an array")
        .iter()
        .map(|f| f["name"].as_str().unwrap().to_string())
        .collect()
}

fn warning_paths(warnings: &[proxy_config::ConfigWarning]) -> Vec<&str> {
    warnings.iter().map(|w| w.field_path.as_str()).collect()
}

/// The one shape the thin-slice token limiter (`token_limit_filter`)
/// actually enforces: `key: header:authorization` with
/// `tokens_per_minute` set. `100003` is deliberately not a multiple of 60 --
/// `100003 / 60` is not round, so a `fill_rate` formula that used a wrong
/// divisor (e.g. `max_tokens` verbatim, or `/ 60` applied to the wrong
/// value) could not coincidentally produce the right number.
#[test]
fn tokens_per_minute_with_header_authorization_key_emits_the_token_limit_filter() {
    let config = parse(&format!(
        "{BASIC_CONFIG}limits:\n  - key: header:authorization\n    tokens_per_minute: 100003\n"
    ))
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");

    let names = token_limit_names(&lowered.bootstrap);
    assert!(
        names.contains(&"llmproxy.token_limit".to_string()),
        "expected llmproxy.token_limit in {names:?}"
    );

    let filters = &hcm_typed_config(&lowered.bootstrap)["http_filters"];
    let entry = filters
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "llmproxy.token_limit")
        .expect("token_limit filter must be present");
    assert_eq!(
        entry["typed_config"]["@type"],
        proxy_filters::token_limit_filter::TYPE_URL
    );
    assert_eq!(entry["typed_config"]["max_tokens"], 100003);
    let fill_rate = entry["typed_config"]["fill_rate"]
        .as_f64()
        .expect("fill_rate must be a number");
    assert!(
        (fill_rate - 100003.0 / 60.0).abs() < 1e-9,
        "fill_rate must be max_tokens/60 (a 60s window), got {fill_rate}"
    );

    // Must precede `llmproxy.usage` -- S2.1 encoder callbacks run in reverse
    // config order, and this filter's encode-side record needs the usage
    // filter's own encode callback to have already run.
    let limit_pos = names
        .iter()
        .position(|n| n == "llmproxy.token_limit")
        .unwrap();
    let usage_pos = names.iter().position(|n| n == "llmproxy.usage").unwrap();
    assert!(
        limit_pos < usage_pos,
        "llmproxy.token_limit must precede llmproxy.usage, got {names:?}"
    );

    // The one supported limit must not also produce a not-enforced warning.
    let all = warning_paths(&lowered.warnings).join(",");
    assert!(
        !all.contains("limits[0]"),
        "the one supported limit must not also produce a not-enforced warning: {all}"
    );
}

/// `key: global` is not enforced -- the limiter's bucket key is hardcoded to
/// the `authorization` header, never a global bucket.
#[test]
fn global_key_is_not_enforced_and_warns() {
    let config = parse(&format!(
        "{BASIC_CONFIG}limits:\n  - key: global\n    tokens_per_minute: 1000\n"
    ))
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");

    assert!(
        !token_limit_names(&lowered.bootstrap).contains(&"llmproxy.token_limit".to_string()),
        "an unsupported key must never emit the filter"
    );
    let paths = warning_paths(&lowered.warnings);
    assert!(
        paths.contains(&"limits[0].key"),
        "expected a warning naming limits[0].key, got {paths:?}"
    );
}

/// `key: client-ip` is not enforced, for the same reason as `global`.
#[test]
fn client_ip_key_is_not_enforced_and_warns() {
    let config = parse(&format!(
        "{BASIC_CONFIG}limits:\n  - key: client-ip\n    tokens_per_minute: 1000\n"
    ))
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");

    assert!(
        !token_limit_names(&lowered.bootstrap).contains(&"llmproxy.token_limit".to_string()),
        "an unsupported key must never emit the filter"
    );
    let paths = warning_paths(&lowered.warnings);
    assert!(
        paths.contains(&"limits[0].key"),
        "expected a warning naming limits[0].key, got {paths:?}"
    );
}

/// Any header other than `authorization` is not enforced -- the limiter
/// hardcodes the header name.
#[test]
fn header_other_than_authorization_is_not_enforced_and_warns() {
    let config = parse(&format!(
        "{BASIC_CONFIG}limits:\n  - key: header:x-api-key\n    tokens_per_minute: 1000\n"
    ))
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");

    assert!(
        !token_limit_names(&lowered.bootstrap).contains(&"llmproxy.token_limit".to_string()),
        "an unsupported key must never emit the filter"
    );
    let paths = warning_paths(&lowered.warnings);
    assert!(
        paths.contains(&"limits[0].key"),
        "expected a warning naming limits[0].key, got {paths:?}"
    );
}

/// `requests_per_minute` is a request-rate cap, not a token budget -- a
/// different feature the current filter does not implement.
#[test]
fn requests_per_minute_is_not_enforced_and_warns() {
    let config = parse(&format!(
        "{BASIC_CONFIG}limits:\n  - key: header:authorization\n    requests_per_minute: 100\n"
    ))
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");

    // No `tokens_per_minute` at all here, so the filter must not appear.
    assert!(
        !token_limit_names(&lowered.bootstrap).contains(&"llmproxy.token_limit".to_string()),
        "requests_per_minute alone must never emit the filter"
    );
    let paths = warning_paths(&lowered.warnings);
    assert!(
        paths.contains(&"limits[0].requests_per_minute"),
        "expected a warning naming limits[0].requests_per_minute, got {paths:?}"
    );
}

/// `concurrent_sessions` is not enforced yet.
#[test]
fn concurrent_sessions_is_not_enforced_and_warns() {
    let config = parse(&format!(
        "{BASIC_CONFIG}limits:\n  - key: header:authorization\n    concurrent_sessions: 10\n"
    ))
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");

    let paths = warning_paths(&lowered.warnings);
    assert!(
        paths.contains(&"limits[0].concurrent_sessions"),
        "expected a warning naming limits[0].concurrent_sessions, got {paths:?}"
    );
}

/// `models` (per-model scoping) is not enforced by the current thin slice.
#[test]
fn models_scoping_is_not_enforced_and_warns() {
    let config = parse(&format!(
        "{BASIC_CONFIG}limits:\n  - key: header:authorization\n    tokens_per_minute: 500\n    models: [\"gpt-4\"]\n"
    ))
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");

    // The filter must still be emitted for the supported tokens_per_minute
    // part -- `models` is an additional, independently unsupported field,
    // not a reason to drop the whole limit.
    assert!(
        token_limit_names(&lowered.bootstrap).contains(&"llmproxy.token_limit".to_string()),
        "the token part of the limit must still be enforced despite the unsupported `models` field"
    );
    let paths = warning_paths(&lowered.warnings);
    assert!(
        paths.contains(&"limits[0].models"),
        "expected a warning naming limits[0].models, got {paths:?}"
    );
}

/// No `limits` key at all: nothing in the serialized bootstrap ever mentions
/// the token-limit filter, its name, or its type URL.
#[test]
fn no_limits_emits_no_token_limit_filter_anywhere() {
    let config = parse(BASIC_CONFIG).expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let whole = serde_json::to_string(&lowered.bootstrap).unwrap();
    assert!(
        !whole.contains("token_limit"),
        "no limits configured must leave zero trace of the filter, got: {whole}"
    );
}

/// The JSON assertions above only prove the dialect *emits*
/// `llmproxy.token_limit`; they cannot catch the emitted name disagreeing
/// with what the filter registry expects it to be bound to. `build_snapshot`
/// resolving the filter's `type_url` against the real registry is what
/// proves the two agree -- mirrors `per_route_dialect_survives_into_the_ir`
/// and `body_rewrite_per_route_config_survives_into_the_ir` above.
#[test]
fn token_limit_filter_survives_into_the_ir() {
    let config = parse(&format!(
        "{BASIC_CONFIG}limits:\n  - key: header:authorization\n    tokens_per_minute: 6000\n"
    ))
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
    let entry = hcm
        .http_filters
        .iter()
        .find(|f| f.name == "llmproxy.token_limit")
        .expect("llmproxy.token_limit must be in the chain");
    assert_eq!(entry.type_url, proxy_filters::token_limit_filter::TYPE_URL);
}

// -------------------------------------------------------------- models --
//
// The config surface has exactly two nouns: `providers` (the top-level map)
// and `models`. A `models.<name>.providers` entry is a provider reference,
// same as `routes[i].provider` -- either the shorthand string form
// (`provider` or `provider/model`, reusing `ProviderModelRef`) or the object
// form needed whenever `dialect` must be explicit. There is no third noun
// ("backend") anywhere in the config.

/// A `models:` block with two same-dialect providers lowers to an ordered
/// aggregate cluster. The alias is the only client-selectable name; retrying
/// the aggregate reaches the next provider.
#[test]
fn models_multiple_providers_lower_to_ordered_fallback() {
    let config = parse(
        r#"
version: 0
providers:
  primary: { base_url: "https://primary.example", api_key: k }
  secondary: { base_url: "https://secondary.example", api_key: k }
routes:
  - { model: "gpt-*", provider: primary }
models:
  claude-sonnet-4-5:
    providers:
      - { provider: primary, model: claude-sonnet-4-5-primary }
      - { provider: secondary, model: claude-sonnet-4-5-secondary }
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");

    let routes =
        &hcm_typed_config(&lowered.bootstrap)["route_config"]["virtual_hosts"][0]["routes"];
    // routes[0] is the explicit rule; routes[1] is the catalogue alias.
    let model_route = &routes[1];
    assert_eq!(
        model_route["route"]["cluster"],
        "fallback:model-claude-sonnet-4-5"
    );
    assert_eq!(model_route["route"]["retry_policy"]["num_retries"], 1);
    assert_eq!(
        model_route["match"]["headers"][0]["string_match"]["exact"],
        "claude-sonnet-4-5"
    );

    let clusters = &lowered.bootstrap["static_resources"]["clusters"];
    let aggregate = clusters
        .as_array()
        .expect("clusters must be an array")
        .iter()
        .find(|cluster| cluster["name"] == "fallback:model-claude-sonnet-4-5")
        .expect("model aggregate cluster must exist");
    assert_eq!(
        aggregate["cluster_type"]["typed_config"]["clusters"],
        serde_json::json!(["provider:primary", "provider:secondary"])
    );
    assert!(
        lowered.warnings.is_empty(),
        "warnings: {:?}",
        lowered.warnings
    );

    let primary = clusters
        .as_array()
        .expect("clusters must be an array")
        .iter()
        .find(|cluster| cluster["name"] == "provider:primary")
        .expect("primary cluster must exist");
    let secondary = clusters
        .as_array()
        .expect("clusters must be an array")
        .iter()
        .find(|cluster| cluster["name"] == "provider:secondary")
        .expect("secondary cluster must exist");
    for (cluster, upstream_model) in [
        (primary, "claude-sonnet-4-5-primary"),
        (secondary, "claude-sonnet-4-5-secondary"),
    ] {
        assert_eq!(
            cluster["metadata"]["filter_metadata"]["io.llmproxy.provider_auth"]["models"][0],
            serde_json::json!({
                "pattern": "claude-sonnet-4-5",
                "upstream_model": upstream_model,
            })
        );
    }
}

/// A provider entry naming a provider that doesn't exist is a load error
/// with the full dotted path, mirroring `route_to_unknown_provider_fails`.
/// Uses the shorthand string form -- the common case.
#[test]
fn model_provider_entry_unknown_provider_fails() {
    let err = parse(
        r#"
version: 0
providers:
  anthropic: { api_key: ${ANTHROPIC_API_KEY} }
routes:
  - { model: "*", provider: anthropic }
models:
  claude-sonnet-4-5:
    providers:
      - nonexistent
"#,
    )
    .expect_err("unknown provider must fail");
    let ConfigError::InvalidValue { field_path, reason } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "models.claude-sonnet-4-5.providers[0]");
    assert!(
        reason.contains("anthropic"),
        "should list known providers: {reason}"
    );
}

/// An empty `providers` list on a model is a load error.
#[test]
fn model_with_no_providers_fails() {
    let err = parse(
        r#"
version: 0
providers:
  anthropic: { api_key: ${ANTHROPIC_API_KEY} }
routes:
  - { model: "*", provider: anthropic }
models:
  claude-sonnet-4-5:
    providers: []
"#,
    )
    .expect_err("empty providers list must fail");
    let ConfigError::InvalidValue { field_path, reason } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "models.claude-sonnet-4-5.providers");
    assert!(reason.contains("at least one provider"), "got: {reason}");
}

/// Vertex and Bedrock configs lower through the same strict loader as static
/// providers, carrying provider-owned credential and path behavior.
#[test]
fn provider_types_lower_to_runtime_config() {
    for type_name in ["vertex", "bedrock"] {
        let credentials = match type_name {
            "vertex" => "project: test-project\n    location: us-central1\n    publisher: google\n    access_token: token",
            "bedrock" => "region: us-east-1\n    access_key_id: access\n    secret_access_key: secret",
            _ => unreachable!(),
        };
        let models =
            "\nmodels:\n  m1:\n    providers:\n      - { provider: p1, model: m, dialect: anthropic }\n"
                .to_string();
        let config = parse(&format!(
            r#"
version: 0
providers:
  p1:
    type: {type_name}
    base_url: "https://example.com"
    {credentials}
routes:
  - {{ model: "*", provider: p1 }}
{models}"#
        ))
        .unwrap_or_else(|e| panic!("{type_name}: must parse, got {e}"));
        let lowered = proxy_simple_config::lower(&config)
            .unwrap_or_else(|err| panic!("{type_name}: must lower, got {err}"));
        let cluster = lowered.bootstrap["static_resources"]["clusters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|cluster| cluster["name"] == "provider:p1")
            .expect("provider cluster must exist");
        assert!(
            cluster["metadata"]["filter_metadata"]["io.llmproxy.provider_auth"]["scheme"]
                .is_string()
        );
        assert!(
            cluster["metadata"]["filter_metadata"]["io.llmproxy.path_template"]["scheme"]
                .is_string()
        );
    }
}

#[test]
fn vertex_and_bedrock_runtime_settings_survive_ir_lowering() {
    let config = parse(
        r#"
version: 0
providers:
  vertex:
    type: vertex
    base_url: "https://vertex.example.com"
    project: project-a
    location: us-central1
    publisher: anthropic
    access_token: vertex-token
  bedrock:
    type: bedrock
    base_url: "https://bedrock.example.com"
    region: us-east-1
    access_key_id: access-key
    secret_access_key: secret-key
routes:
  - { model: "*", provider: vertex }
models:
  claude-*:
    providers:
      - { provider: vertex, model: claude-upstream, dialect: anthropic }
  bedrock-model:
    providers:
      - { provider: bedrock, model: anthropic.model, dialect: anthropic }
"#,
    )
    .expect("provider config must parse");
    let loaded = lower_to_loaded(&config).expect("provider config must lower");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("provider config must build IR");

    let vertex = snapshot
        .clusters
        .get("provider:vertex")
        .unwrap()
        .provider_runtime
        .as_ref()
        .unwrap();
    assert!(matches!(
        vertex.credential,
        Some(proxy_config::ir::ProviderCredential::VertexOAuth2 { .. })
    ));
    assert!(matches!(
        vertex.path_template,
        Some(proxy_config::ir::ProviderPathTemplate::Vertex { .. })
    ));

    let bedrock = snapshot
        .clusters
        .get("provider:bedrock")
        .unwrap()
        .provider_runtime
        .as_ref()
        .unwrap();
    assert!(matches!(
        bedrock.credential,
        Some(proxy_config::ir::ProviderCredential::BedrockSigV4 { .. })
    ));
    assert!(matches!(
        bedrock.path_template,
        Some(proxy_config::ir::ProviderPathTemplate::Bedrock { .. })
    ));
}

#[test]
fn azure_openai_lowers_auth_and_provider_path_rewrite() {
    let config = parse(
        r#"
version: 0
providers:
  azure:
    type: azure-openai
    base_url: "https://example.openai.azure.com"
    deployment: gpt-4o-prod
    api_version: 2024-10-21
    api_key: azure-key
routes:
  - { model: "*", provider: azure }
"#,
    )
    .expect("Azure config must parse");
    let lowered = lower(&config).expect("Azure config must lower");
    let cluster = lowered.bootstrap["static_resources"]["clusters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|cluster| cluster["name"] == "provider:azure")
        .expect("Azure provider cluster must exist");
    let headers = cluster["metadata"]["filter_metadata"]["io.llmproxy.provider_auth"]["headers"]
        .as_array()
        .unwrap();
    assert!(headers
        .iter()
        .any(|header| header["key"] == "api-key" && header["value"] == "azure-key"));
    assert_eq!(
        cluster["metadata"]["filter_metadata"]["io.llmproxy.path_rewrite"],
        serde_json::json!({
            "match_prefix": "/v1",
            "replacement_prefix": "/openai/deployments/gpt-4o-prod",
            "query": "api-version=2024-10-21",
        })
    );
    let loaded = lower_to_loaded(&config).expect("Azure config must load through Envoy IR");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("Azure config must build IR");
    assert_eq!(
        snapshot.clusters["provider:azure"].request_path_rewrite,
        Some(proxy_config::ir::RequestPathRewrite {
            match_prefix: "/v1".to_string(),
            replacement_prefix: "/openai/deployments/gpt-4o-prod".to_string(),
            query: Some("api-version=2024-10-21".to_string()),
        })
    );
}

#[test]
fn azure_openai_requires_deployment_and_api_version() {
    for (field, config) in [
        (
            "deployment",
            r#"
version: 0
providers:
  azure:
    type: azure-openai
    base_url: "https://example.openai.azure.com"
    api_version: 2024-10-21
routes:
  - { model: "*", provider: azure }
"#,
        ),
        (
            "api_version",
            r#"
version: 0
providers:
  azure:
    type: azure-openai
    base_url: "https://example.openai.azure.com"
    deployment: gpt-4o-prod
routes:
  - { model: "*", provider: azure }
"#,
        ),
    ] {
        let err = parse(config).expect_err("missing Azure field must fail");
        let ConfigError::InvalidValue { field_path, .. } = err else {
            panic!("expected InvalidValue");
        };
        assert_eq!(field_path, format!("providers.azure.{field}"));
    }
}

#[test]
fn azure_openai_rejects_unsafe_path_and_query_values() {
    for (field, deployment, api_version) in [
        ("deployment", "gpt/4o", "2024-10-21"),
        ("api_version", "gpt-4o-prod", "2024-10-21&x=y"),
    ] {
        let config = format!(
            r#"
version: 0
providers:
  azure:
    type: azure-openai
    base_url: "https://example.openai.azure.com"
    deployment: {deployment}
    api_version: {api_version}
routes:
  - {{ model: "*", provider: azure }}
"#
        );
        let err = parse(&config).expect_err("unsafe Azure value must fail");
        let ConfigError::InvalidValue { field_path, .. } = err else {
            panic!("expected InvalidValue");
        };
        assert_eq!(field_path, format!("providers.azure.{field}"));
    }
}

#[test]
fn vertex_and_bedrock_provider_fields_parse() {
    let config = parse(
        r#"
version: 0
providers:
  vertex-us:
    type: vertex
    base_url: "https://vertex.example.com"
    project: test-project
    location: us-central1
    publisher: anthropic
    access_token_file: /run/secrets/vertex-token
  bedrock-us:
    type: bedrock
    base_url: "https://bedrock.example.com"
    region: us-east-1
    access_key_id_file: /run/secrets/aws-access-key
    secret_access_key_file: /run/secrets/aws-secret-key
    session_token: session-token
routes:
  - { model: vertex-model, provider: vertex-us }
  - { model: bedrock-model, provider: bedrock-us }
models:
  vertex-model:
    providers:
      - { provider: vertex-us, dialect: anthropic }
  bedrock-model:
    providers:
      - { provider: bedrock-us, dialect: anthropic }
"#,
    )
    .expect("Vertex and Bedrock provider fields must parse");

    let vertex = &config.providers["vertex-us"];
    assert_eq!(vertex.project.as_deref(), Some("test-project"));
    assert_eq!(vertex.location.as_deref(), Some("us-central1"));
    assert_eq!(vertex.publisher.as_deref(), Some("anthropic"));
    assert_eq!(
        vertex.access_token_file.as_deref(),
        Some("/run/secrets/vertex-token")
    );

    let bedrock = &config.providers["bedrock-us"];
    assert_eq!(bedrock.region.as_deref(), Some("us-east-1"));
    assert_eq!(
        bedrock.access_key_id_file.as_deref(),
        Some("/run/secrets/aws-access-key")
    );
    assert_eq!(
        bedrock.secret_access_key_file.as_deref(),
        Some("/run/secrets/aws-secret-key")
    );
    assert_eq!(bedrock.session_token.as_deref(), Some("session-token"));
}

#[test]
fn vertex_and_bedrock_credentials_require_valid_sources() {
    let assert_field = |config: &str, expected: &str| {
        let err = parse(config).expect_err("invalid provider credential config must fail");
        let ConfigError::InvalidValue { field_path, .. } = err else {
            panic!("expected InvalidValue");
        };
        assert_eq!(field_path, expected);
    };

    assert_field(
        r#"
version: 0
providers:
  vertex:
    type: vertex
    base_url: "https://vertex.example.com"
    location: us-central1
    publisher: google
    access_token: token
routes:
  - { model: "*", provider: vertex }
"#,
        "providers.vertex.project",
    );
    assert_field(
        r#"
version: 0
providers:
  vertex:
    type: vertex
    base_url: "https://vertex.example.com"
    project: project
    location: us-central1
    publisher: google
    access_token: token
    access_token_file: /run/secrets/token
routes:
  - { model: "*", provider: vertex }
"#,
        "providers.vertex.access_token",
    );
    assert_field(
        r#"
version: 0
providers:
  vertex:
    type: vertex
    base_url: "https://vertex.example.com"
    project: project
    location: us-central1
    publisher: google
routes:
  - { model: "*", provider: vertex }
"#,
        "providers.vertex.access_token",
    );
    assert_field(
        r#"
version: 0
providers:
  bedrock:
    type: bedrock
    base_url: "https://bedrock.example.com"
    access_key_id: access
    secret_access_key: secret
routes:
  - { model: "*", provider: bedrock }
"#,
        "providers.bedrock.region",
    );
    assert_field(
        r#"
version: 0
providers:
  bedrock:
    type: bedrock
    base_url: "https://bedrock.example.com"
    region: us-east-1
    secret_access_key: secret
routes:
  - { model: "*", provider: bedrock }
"#,
        "providers.bedrock.access_key_id",
    );
    assert_field(
        r#"
version: 0
providers:
  bedrock:
    type: bedrock
    base_url: "https://bedrock.example.com"
    region: us-east-1
    access_key_id: access
    access_key_id_file: /run/secrets/access
    secret_access_key: secret
routes:
  - { model: "*", provider: bedrock }
"#,
        "providers.bedrock.access_key_id",
    );
    assert_field(
        r#"
version: 0
providers:
  bedrock:
    type: bedrock
    base_url: "https://bedrock.example.com"
    region: us-east-1
    access_key_id: access
routes:
  - { model: "*", provider: bedrock }
"#,
        "providers.bedrock.secret_access_key",
    );
    assert_field(
        r#"
version: 0
providers:
  bedrock:
    type: bedrock
    base_url: "https://bedrock.example.com"
    region: us-east-1
    access_key_id: access
    secret_access_key: secret
    secret_access_key_file: /run/secrets/secret
routes:
  - { model: "*", provider: bedrock }
"#,
        "providers.bedrock.secret_access_key",
    );
    assert_field(
        r#"
version: 0
providers:
  bedrock:
    type: bedrock
    base_url: "https://bedrock.example.com"
    region: us-east-1
    access_key_id: access
    secret_access_key: secret
    session_token: one
    session_token_file: /run/secrets/session
routes:
  - { model: "*", provider: bedrock }
"#,
        "providers.bedrock.session_token",
    );
}

#[test]
fn vertex_and_bedrock_fields_are_rejected_on_other_provider_types() {
    let cases = [
        (
            r#"
version: 0
providers:
  openai:
    project: project
routes:
  - { model: "*", provider: openai }
"#,
            "providers.openai.project",
        ),
        (
            r#"
version: 0
providers:
  openai:
    region: us-east-1
routes:
  - { model: "*", provider: openai }
"#,
            "providers.openai.region",
        ),
        (
            r#"
version: 0
providers:
  vertex:
    type: vertex
    base_url: "https://vertex.example.com"
    project: project
    location: us-central1
    publisher: google
    access_token: token
    region: us-east-1
routes:
  - { model: "*", provider: vertex }
"#,
            "providers.vertex.region",
        ),
        (
            r#"
version: 0
providers:
  bedrock:
    type: bedrock
    base_url: "https://bedrock.example.com"
    region: us-east-1
    access_key_id: access
    secret_access_key: secret
    access_token: token
routes:
  - { model: "*", provider: bedrock }
"#,
            "providers.bedrock.access_token",
        ),
    ];

    for (config, expected) in cases {
        let err = parse(config).expect_err("provider-specific field must be rejected");
        let ConfigError::InvalidValue { field_path, .. } = err else {
            panic!("expected InvalidValue");
        };
        assert_eq!(field_path, expected);
    }
}

/// Vertex/Bedrock serve more than one wire format under one provider type,
/// so a `models:` entry using one MUST set `dialect` explicitly -- and the
/// shorthand string form has nowhere to put it, so it must be rejected
/// telling the user to switch to the object form. Caught at PARSE time
/// (`validate_semantics`), independent of the (also-fatal, but
/// lowering-time) unbuilt-credential-scheme error above.
#[test]
fn model_provider_shorthand_on_ambiguous_provider_type_fails() {
    let err = parse(
        r#"
version: 0
providers:
  vertex-us:
    type: vertex
    base_url: "https://vertex-us.example.com"
    project: test-project
    location: us-central1
    publisher: anthropic
    access_token: token
routes:
  - { model: "*", provider: vertex-us }
models:
  claude-sonnet-4-5:
    providers:
      - vertex-us/claude-sonnet-4-5@20250929
"#,
    )
    .expect_err("the shorthand form on an ambiguous provider type must fail to parse");
    let ConfigError::InvalidValue { field_path, reason } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "models.claude-sonnet-4-5.providers[0]");
    assert!(reason.contains("vertex"), "got: {reason}");
    assert!(
        reason.contains("object form"),
        "should point the user at the fix: {reason}"
    );
}

/// The object-form counterpart: `dialect` omitted is still a load error, at
/// the more specific `.dialect` field path since the object form actually
/// has that field to point at.
#[test]
fn model_provider_object_form_missing_dialect_on_ambiguous_provider_fails() {
    let err = parse(
        r#"
version: 0
providers:
  vertex-us:
    type: vertex
    base_url: "https://vertex-us.example.com"
    project: test-project
    location: us-central1
    publisher: anthropic
    access_token: token
routes:
  - { model: "*", provider: vertex-us }
models:
  claude-sonnet-4-5:
    providers:
      - { provider: vertex-us, model: "claude-sonnet-4-5@20250929" }
"#,
    )
    .expect_err("missing dialect on an ambiguous provider type must fail to parse");
    let ConfigError::InvalidValue { field_path, reason } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "models.claude-sonnet-4-5.providers[0].dialect");
    assert!(reason.contains("vertex"), "got: {reason}");
}

/// `dialect` omitted for `anthropic`/`openai`/`openai-compatible` entries is
/// fine and derives the same string `usage_dialect` would.
#[test]
fn model_provider_dialect_derives_for_unambiguous_provider_types() {
    let config = parse(
        r#"
version: 0
providers:
  anthropic: { api_key: ${ANTHROPIC_API_KEY} }
routes:
  - { model: "*", provider: anthropic }
models:
  claude-sonnet-4-5:
    providers:
      - anthropic
"#,
    )
    .expect("dialect omitted on an unambiguous provider type must parse fine");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let routes =
        &hcm_typed_config(&lowered.bootstrap)["route_config"]["virtual_hosts"][0]["routes"];
    assert_eq!(
        routes[1]["typed_per_filter_config"]["llmproxy.usage"]["dialect"],
        "anthropic"
    );
}

/// An explicit `dialect` on the object form overrides the derived value --
/// proves the field is actually read, not decorative. `nebius` here is
/// openai-compatible, whose derived dialect would be "openai".
#[test]
fn model_provider_explicit_dialect_overrides_derived_value() {
    let config = parse(
        r#"
version: 0
providers:
  nebius: { base_url: "https://api.studio.nebius.ai", api_key: k }
routes:
  - { model: "*", provider: nebius }
models:
  claude-via-nebius:
    providers:
      - { provider: nebius, dialect: anthropic }
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let routes =
        &hcm_typed_config(&lowered.bootstrap)["route_config"]["virtual_hosts"][0]["routes"];
    assert_eq!(
        routes[1]["typed_per_filter_config"]["llmproxy.usage"]["dialect"],
        "anthropic"
    );
}

/// The shorthand string form and the equivalent object form must lower
/// identically -- this is what stops the two forms drifting apart over
/// time, since nothing else in the type system enforces it (an `untagged`
/// enum only guarantees each parses, not that they agree once lowered).
#[test]
fn shorthand_and_object_form_lower_identically() {
    let shorthand = parse(
        r#"
version: 0
providers:
  anthropic: { api_key: ${ANTHROPIC_API_KEY} }
routes:
  - { model: "*", provider: anthropic }
models:
  claude-sonnet-4-5:
    providers:
      - anthropic/claude-sonnet-4-5-20250929
"#,
    )
    .expect("shorthand form must parse");
    let object_form = parse(
        r#"
version: 0
providers:
  anthropic: { api_key: ${ANTHROPIC_API_KEY} }
routes:
  - { model: "*", provider: anthropic }
models:
  claude-sonnet-4-5:
    providers:
      - { provider: anthropic, model: claude-sonnet-4-5-20250929 }
"#,
    )
    .expect("object form must parse");

    let lowered_shorthand = proxy_simple_config::lower(&shorthand).expect("must lower");
    let lowered_object = proxy_simple_config::lower(&object_form).expect("must lower");

    // Compare the ENTIRE lowered bootstrap, not just the route the reference
    // lands on. The claim these two forms make is "same meaning", and a
    // divergence in the cluster, the filter chain, or the per-route dialect
    // would be exactly the kind of drift this test exists to prevent -- and
    // every one of those lives outside `routes[1]`.
    assert_eq!(
        lowered_shorthand.bootstrap, lowered_object.bootstrap,
        "the two spellings of one reference must lower to a byte-identical bootstrap"
    );

    // Both forms name the same "not-yet-substituted upstream model ID"
    // warning at the same path -- the shorthand's `/model` suffix and the
    // object form's `model:` field are the same information.
    assert_eq!(
        warning_paths(&lowered_shorthand.warnings),
        warning_paths(&lowered_object.warnings)
    );
}

/// A `models:`-free config lowers exactly as it did before `models:` existed: the additive
/// field changes nothing about an existing config's output.
#[test]
fn config_without_models_lowers_exactly_as_before() {
    let config = parse(BASIC_CONFIG).expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let routes = hcm_typed_config(&lowered.bootstrap)["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .expect("routes must be an array");
    // BASIC_CONFIG's one `*` rule is a catch-all, so no synthetic 404 route
    // is appended, and an absent `models:` block contributes no implicit
    // routes either -- exactly the one route, unchanged.
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0]["route"]["cluster"], "provider:openai");
}

/// The IR counterpart to the JSON-level tests above, mirroring
/// `per_route_dialect_survives_into_the_ir`: proves a `models:` entry's
/// cluster and dialect survive the full strict-parse -> PGV -> IR pipeline,
/// not just the JSON the dialect happens to emit.
#[test]
fn model_provider_survives_into_the_ir() {
    let config = parse(
        r#"
version: 0
providers:
  anthropic: { api_key: ${ANTHROPIC_API_KEY} }
routes:
  - { model: "gpt-*", provider: anthropic }
models:
  claude-sonnet-4-5:
    providers:
      - anthropic/claude-sonnet-4-5-20250929
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

    // routes[0] is the explicit `gpt-*` rule; routes[1] is the implicit
    // model route built from `claude-sonnet-4-5`'s first provider entry.
    let model_route = &hcm.route_table.virtual_hosts[0].routes[1];
    let proxy_config::ir::RouteActionIR::Forward(forward) = &model_route.action else {
        panic!("expected a Forward action");
    };
    let proxy_config::ir::ForwardTarget::Cluster(cluster) = &forward.target else {
        panic!("expected a Cluster target");
    };
    assert_eq!(cluster.as_str(), "provider:anthropic");

    let per_filter = model_route
        .typed_per_filter_config
        .get("llmproxy.usage")
        .expect("model route must carry a usage override");
    let msg = per_filter
        .config
        .as_ref()
        .expect("override must carry a config");
    let got = msg
        .get_field_by_name("dialect")
        .expect("Usage.dialect")
        .as_str()
        .expect("dialect must be a string")
        .to_string();
    assert_eq!(got, "anthropic");
}

// ---------------------------------------------- wildcards --
//
// `models:` catalogue keys now take `*`, matched exact > longest prefix >
// bare `*` catch-all -- see `lower::model_catalog_order`'s doc for why that
// is one sort rule rather than two, and `lower::classify_model_key` for the
// legal shapes.

/// The full precedence ladder in one config: an exact key, two prefixes of
/// different lengths, and a bare `*` catch-all. Each of four distinct model
/// names exercises exactly one tier, and the tier that wins is read off the
/// target CLUSTER, not just the header matcher -- proving the route that
/// wins is also the route that was meant to.
#[test]
fn model_catalog_precedence_ladder() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
  p-gpt4: { base_url: "https://p-gpt4.example.com" }
  p-gpt: { base_url: "https://p-gpt.example.com" }
  p-catchall: { base_url: "https://p-catchall.example.com" }
routes:
  - { model: "unrelated", provider: openai }
models:
  gpt-4o:
    providers: [openai]
  "gpt-4*":
    providers: [p-gpt4]
  "gpt-*":
    providers: [p-gpt]
  "*":
    providers: [p-catchall]
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let routes = hcm_typed_config(&lowered.bootstrap)["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .expect("routes must be an array");

    // routes[0] is the explicit `routes:` rule; routes[1..] are the four
    // `models:` entries, in precedence order: exact, then longest prefix
    // first. Local catalog discovery precedes the catch-all.
    assert_eq!(routes.len(), 6, "routes: {routes:#?}");
    let m = |i: usize| &routes[i];
    assert_eq!(
        m(1)["match"]["headers"][0]["string_match"]["exact"],
        "gpt-4o"
    );
    assert_eq!(m(1)["route"]["cluster"], "provider:openai");
    assert_eq!(
        m(2)["match"]["headers"][0]["string_match"]["prefix"],
        "gpt-4"
    );
    assert_eq!(m(2)["route"]["cluster"], "provider:p-gpt4");
    assert_eq!(
        m(3)["match"]["headers"][0]["string_match"]["prefix"],
        "gpt-"
    );
    assert_eq!(m(3)["route"]["cluster"], "provider:p-gpt");
    assert!(
        m(5)["match"]["headers"].is_null(),
        "the bare `*` catch-all carries no header matcher: {:?}",
        m(5)
    );
    assert_eq!(m(5)["route"]["cluster"], "provider:p-catchall");
}

/// Two competing prefixes, isolated from the rest of the ladder: the
/// LONGER one wins regardless of catalogue (BTreeMap/YAML) order -- this is
/// the acceptance clause the plan states explicitly ("with both `claude-*`
/// and `claude-sonnet-*` defined, `claude-sonnet-4-5` resolves to the
/// latter").
#[test]
fn longest_matching_prefix_wins_between_two_prefixes() {
    let config = parse(
        r#"
version: 0
providers:
  broad: { base_url: "https://broad.example.com" }
  narrow: { base_url: "https://narrow.example.com" }
routes:
  - { model: "unrelated", provider: broad }
models:
  "claude-*":
    providers: [broad]
  "claude-sonnet-*":
    providers: [narrow]
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let routes = hcm_typed_config(&lowered.bootstrap)["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .expect("routes must be an array");
    // routes[0] explicit, [1] `claude-sonnet-*`, [2] `claude-*`, [3] local
    // catalog discovery, [4] the synthetic 404 (neither prefix is a catch-all, so it's still appended
    // -- unchanged pre-existing behavior, not this test's concern).
    assert_eq!(routes.len(), 5, "routes: {routes:#?}");
    // The longer prefix (`claude-sonnet-`) must be listed FIRST -- Envoy
    // matches first-match-wins, so list order IS precedence order here.
    assert_eq!(
        routes[1]["match"]["headers"][0]["string_match"]["prefix"],
        "claude-sonnet-"
    );
    assert_eq!(routes[1]["route"]["cluster"], "provider:narrow");
    assert_eq!(
        routes[2]["match"]["headers"][0]["string_match"]["prefix"],
        "claude-"
    );
    assert_eq!(routes[2]["route"]["cluster"], "provider:broad");
}

/// A bare `*` catalogue entry serves everything nothing more specific
/// claimed -- proven here against a name that matches neither the exact key
/// nor the one prefix.
#[test]
fn catalog_catch_all_serves_what_nothing_else_matches() {
    let config = parse(
        r#"
version: 0
providers:
  specific: { base_url: "https://specific.example.com" }
  fallback: { base_url: "https://fallback.example.com" }
routes:
  - { model: "unrelated", provider: specific }
models:
  gpt-4o:
    providers: [specific]
  "*":
    providers: [fallback]
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let routes = hcm_typed_config(&lowered.bootstrap)["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .expect("routes must be an array");
    // exact `gpt-4o` first, bare `*` last, no synthetic 404 (the catch-all
    // already covers every remaining request).
    assert_eq!(routes.len(), 4, "routes: {routes:#?}");
    assert_eq!(routes[3]["route"]["cluster"], "provider:fallback");
    assert!(routes[3]["match"]["headers"].is_null());
    assert!(
        !routes.iter().any(|r| r["direct_response"]["status"] == 404),
        "a catch-all model entry must not leave a dead 404 backstop behind it: {routes:#?}"
    );
}

/// Behavior unchanged by wildcard keys: with no `*` anywhere (not
/// in `routes:`, not in `models:`), a name matching nothing still falls
/// through to the synthetic 404 backstop `missing_catch_all_gets_404_backstop`
/// already covers for `routes:` alone -- this pins the same guarantee when
/// the only routing surface configured is `models:`.
#[test]
fn models_only_with_no_catch_all_still_gets_404_backstop() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "unrelated", provider: openai }
models:
  gpt-4o:
    providers: [openai]
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let routes = hcm_typed_config(&lowered.bootstrap)["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .expect("routes must be an array");
    let last = routes.last().expect("at least one route");
    assert_eq!(last["direct_response"]["status"], 404);
}

/// Every shape the plan explicitly names as illegal: a leading `*` that
/// isn't the whole pattern, a mid-string `*`, and a repeated `*`. Each must
/// fail at PARSE time (`validate_semantics`), at the SAME dotted path
/// (`models.<name>`) a shape error on any other `models:` field would use --
/// never silently treated as a literal, and never accepted as
/// `routes[].model`'s wider `safe_regex` grammar would accept it.
#[test]
fn illegal_model_catalog_key_shapes_fail_at_parse_time() {
    for bad in ["*-4o", "gpt-*-mini", "**", "a*b*"] {
        let err = parse(&format!(
            r#"
version: 0
providers:
  openai: {{ api_key: ${{OPENAI_API_KEY}} }}
routes:
  - {{ model: "unrelated", provider: openai }}
models:
  "{bad}":
    providers: [openai]
"#
        ))
        .expect_err(&format!("`{bad}` must be rejected"));
        let ConfigError::InvalidValue { field_path, reason } = &err else {
            panic!("`{bad}`: expected InvalidValue, got: {err}");
        };
        assert_eq!(field_path, &format!("models.{bad}"), "`{bad}`");
        assert!(
            reason.contains('*'),
            "`{bad}`: reason should explain the `*` rule, got {reason}"
        );
    }
}

/// The same catalogue key written twice is a load error naming the
/// duplicate, never a silent "last one wins" -- which is what a plain
/// `BTreeMap` deserialize would otherwise do (see
/// `model::deserialize_model_catalog`'s doc).
#[test]
fn duplicate_model_catalog_key_is_rejected() {
    let err = parse(
        r#"
version: 0
providers:
  a: { base_url: "https://a.example.com" }
  b: { base_url: "https://b.example.com" }
routes:
  - { model: "unrelated", provider: a }
models:
  "gpt-4*":
    providers: [a]
  "gpt-4*":
    providers: [b]
"#,
    )
    .expect_err("a literal duplicate `models:` key must be rejected");
    let ConfigError::InvalidValue { field_path, reason } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "models");
    assert!(
        reason.contains("gpt-4*") && reason.to_lowercase().contains("duplicate"),
        "should name the duplicated key: {reason}"
    );
}

/// Back-compat, restated for wildcard keys: a catalogue of ONLY exact names
/// (no `*` anywhere) lowers in the exact same order as before wildcards
/// existed -- alphabetical, i.e. whatever `BTreeMap`'s key order already
/// was. `model_catalog_order` must be a no-op reshuffle for this case.
#[test]
fn exact_only_catalog_lowers_in_the_same_order_as_before() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "unrelated", provider: openai }
models:
  zeta:
    providers: [openai]
  alpha:
    providers: [openai]
  mid:
    providers: [openai]
"#,
    )
    .expect("must parse");
    let lowered = proxy_simple_config::lower(&config).expect("must lower");
    let routes = hcm_typed_config(&lowered.bootstrap)["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .expect("routes must be an array");
    let names: Vec<&str> = routes[1..4]
        .iter()
        .map(|r| {
            r["match"]["headers"][0]["string_match"]["exact"]
                .as_str()
                .unwrap()
        })
        .collect();
    // Alphabetical -- `BTreeMap`'s natural order, unaffected by the YAML
    // declaration order above (zeta, alpha, mid).
    assert_eq!(names, ["alpha", "mid", "zeta"]);
}

/// **The join between the two crates, which nothing else tests.**
///
/// `proxy-simple-config` writes provider credentials into
/// `Cluster.metadata.filter_metadata["io.llmproxy.provider_auth"]`;
/// `proxy-config::lower::convert_provider_auth_metadata` reads them back out
/// into `ClusterConfig::request_headers_to_add`. The two crates agree on that
/// namespace string only by convention -- each holds its own
/// `PROVIDER_AUTH_METADATA_KEY` constant, and protos never cross the
/// `proxy-config` boundary (AGENTS.md invariant 2), so there is no shared Rust type
/// to pin them together.
///
/// Every other test on either side asserts against the *literal* string, so
/// each crate guards its own half and neither guards the seam. A rename that
/// is self-consistent within one crate -- change the constant, update that
/// crate's tests, both green -- leaves the other side looking for a key
/// nobody emits, and every provider silently loses its credentials. Config
/// parses, validates, lowers, and the API key evaporates: exactly the
/// `request_headers_to_add` P0 that this test guards against.
///
/// Verified by mutation on 2026-08-03: changing only the reader-side constant
/// left all 56 `proxy-simple-config` tests green. This test is what goes red.
/// It asserts on the IR, not on emitted YAML, so it can only pass when both
/// sides genuinely agree.
#[test]
fn provider_credentials_survive_the_dialect_to_ir_round_trip() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: sk-openai-roundtrip }
  anthropic: { type: anthropic, api_key: sk-anthropic-roundtrip }
routes:
  - { model: "gpt-*", provider: openai }
  - { model: "claude-*", provider: anthropic }
"#,
    )
    .expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

    // Rust note: a small helper rather than four near-identical lookups --
    // returns (key, value) pairs so both the presence and the absence
    // assertions below can work off one shape.
    let creds = |cluster: &str| -> Vec<(String, String)> {
        snapshot.clusters[cluster]
            .request_headers_to_add
            .iter()
            .map(|h| (h.key.to_ascii_lowercase(), h.value.clone()))
            .collect()
    };

    let openai = creds("provider:openai");
    assert!(
        openai.contains(&(
            "authorization".to_string(),
            "Bearer sk-openai-roundtrip".to_string()
        )),
        "openai's credential must reach the IR cluster, got {openai:?}"
    );

    let anthropic = creds("provider:anthropic");
    assert!(
        anthropic.contains(&(
            "x-api-key".to_string(),
            "sk-anthropic-roundtrip".to_string()
        )),
        "anthropic's credential must reach the IR cluster, got {anthropic:?}"
    );
    assert!(
        anthropic.iter().any(|(k, _)| k == "anthropic-version"),
        "anthropic's required version header must reach the IR cluster, got {anthropic:?}"
    );

    // The per-provider guarantee, asserted on the IR: neither provider's cluster
    // carries the other's key. Assert the ABSENCE -- checking only that the
    // right key is present passes just as well when both are there, which is
    // precisely the cross-provider leak this assertion exists to prevent.
    assert!(
        !openai
            .iter()
            .any(|(_, v)| v.contains("sk-anthropic-roundtrip")),
        "anthropic's key leaked onto the openai cluster: {openai:?}"
    );
    assert!(
        !anthropic
            .iter()
            .any(|(_, v)| v.contains("sk-openai-roundtrip")),
        "openai's key leaked onto the anthropic cluster: {anthropic:?}"
    );

    // And no route carries a credential any more -- the move is complete,
    // not duplicated. A leftover route-level copy would still reach the
    // fallback's endpoint.
    for table in snapshot.routes.values() {
        for vh in &table.virtual_hosts {
            for route in &vh.routes {
                assert!(
                    route.request_headers_to_add.is_empty(),
                    "provider auth must not remain on route {:?}",
                    route.name
                );
            }
        }
    }
}

// ------------------------------------------------- body-based routing e2e --

/// Drives a REAL request, with a `model`
/// only in the JSON body, through a dialect-lowered config's ENTIRE real
/// pipeline -- lowering, PGV, IR, a real `FilterRegistry` resolving the
/// dialect's `http_filters` to the real `proxy-filters` factories, a real
/// `FilterChainHandler`, a real `ClusterManager`, and a real router --
/// and asserts on which upstream TCP connection was actually dialed.
///
/// This is deliberately NOT a check of the `x-llmproxy-model` header string:
/// `MODEL_HEADER` (this crate) and the header
/// `proxy_filters::body_rewrite_filter` publishes are two independently
/// literal-pinned constants (`proxy-filters` can't depend on this crate --
/// see that filter's module doc). A test asserting on the string would pass
/// even if the two literals drifted apart, as long as each side agreed with
/// itself -- exactly the shape that hid the `io.llmproxy.provider_auth` gap
/// found 2026-08-03. Asserting on which CLUSTER was reached instead requires
/// the whole join -- dialect emits the header matcher, the real filter
/// writes the real header, the real router matches it -- to actually work.
mod body_routing_e2e {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
    use http_body_util::{BodyExt, Full};
    use proxy_cluster::manager::ClusterManager;
    use proxy_cluster::resolver::FakeResolver;
    use proxy_http::filter::{
        FactoryContext, FilterRegistry, RequestHeaders, TerminalFilterInstanceFactory,
    };
    use proxy_http::filter_manager::{ConfiguredHttpFilter, FilterChainHandler};
    use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
    use proxy_http::router::RouterFilterFactory;
    use proxy_http::stat_handles::{RouterStats, StatHandles};
    use proxy_observability::stats::{StatsControl, WorkerId};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::task::LocalSet;

    use proxy_simple_config::lower_to_loaded;

    /// A one-shot upstream that signals `tx` the instant it's dialed and
    /// receives a full request, then answers 200. Two of these (one per
    /// provider) let the test tell "reached A" from "reached B" apart by
    /// which channel fires, not by inspecting anything about the request
    /// itself.
    async fn spawn_marker_upstream() -> (SocketAddr, oneshot::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = tx.send(());
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        });
        (addr, rx)
    }

    /// Build a real, runnable [`FilterChainHandler`] from a dialect-lowered
    /// config's real IR -- the same construction `proxy-core`'s
    /// `build_hcm_handler` does at bind time, minus the parts (TLS certs,
    /// access-log sinks, admin) this test doesn't need.
    async fn build_real_handler(snapshot: &proxy_config::ir::ConfigSnapshot) -> FilterChainHandler {
        let cluster_manager = Arc::new(ClusterManager::with_default_transport(Arc::new(
            FakeResolver::new(),
        )));
        let rejected = cluster_manager
            .update_from_snapshot(&snapshot.clusters)
            .await;
        assert!(
            rejected.is_empty(),
            "no cluster should be rejected: {rejected:?}"
        );

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

        // The REAL registry, with the REAL `proxy-filters` factories --
        // exactly the two filters `proxy-core`'s `filter_registry()`
        // registers.
        let mut registry = FilterRegistry::default();
        registry.register(Arc::new(proxy_filters::usage_filter::UsageFilterFactory));
        registry.register(Arc::new(
            proxy_filters::body_rewrite_filter::BodyRewriteFilterFactory,
        ));

        let factory_ctx = FactoryContext::default();
        let mut filters = Vec::new();
        for f in &hcm.http_filters {
            if f.is_router {
                continue;
            }
            let factory = registry
                .get(&f.type_url)
                .unwrap_or_else(|| panic!("no registered factory for type_url `{}`", f.type_url));
            let config = f
                .config
                .as_ref()
                .expect("lowering only leaves `config: None` on the router filter");
            let instance_factory = factory
                .create(config, &factory_ctx)
                .unwrap_or_else(|e| panic!("filter '{}' config must parse: {e}", f.name));
            filters.push(ConfiguredHttpFilter {
                name: f.name.clone(),
                instance_factory: Arc::from(instance_factory),
                factory: factory.clone(),
            });
        }

        // `RouterFilterFactory` now needs a `RouterStats`
        // to record into -- mirrors `crates/proxy/src/main.rs`'s boot-time
        // construction, resolved for every cluster in this snapshot.
        let stats_control = StatsControl::new(1);
        let stat_handles = Arc::new(StatHandles::build(
            &stats_control,
            snapshot.clusters.keys().map(String::as_str),
        ));
        let router_stats = Arc::new(RouterStats::new(
            stats_control.registry(),
            stat_handles,
            WorkerId(0),
        ));
        let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
            Arc::new(RouterFilterFactory::new(cluster_manager, router_stats));
        FilterChainHandler::new_with_filters(
            filters,
            terminal_factory,
            hcm.route_table.clone(),
            hcm.generate_request_id,
            hcm.use_remote_address,
            hcm.xff_num_trusted_hops,
        )
        .expect("filter chain must build against the real registry")
    }

    fn json_post_request(path: &'static str, body: &'static [u8]) -> HttpRequestParts {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string()).unwrap(),
        );
        HttpRequestParts {
            head: RequestHeaders {
                method: Method::POST,
                uri: Uri::from_static(path),
                headers,
            },
            body: local_boxed(
                Full::new(Bytes::from_static(body))
                    .map_err(|infallible: std::convert::Infallible| match infallible {}),
            ),
            downstream: DownstreamInfo::loopback(),
            on_upgrade: None,
        }
    }

    // Rust note: `flavor = "current_thread"` + an explicit `LocalSet` --
    // same shape as `router_header_mutations.rs`'s tests, for the same
    // reason: `send_upstream_http1` (inside the router terminal this
    // handler drives) spawns a non-`Send` connection driver via
    // `tokio::task::spawn_local`, which needs a `LocalSet` in scope.
    #[tokio::test(flavor = "current_thread")]
    async fn body_based_model_routing_reaches_the_right_provider() {
        LocalSet::new()
            .run_until(async {
                let (addr_a, mut rx_a) = spawn_marker_upstream().await;
                let (addr_b, rx_b) = spawn_marker_upstream().await;

                // Two providers, two model-glob routes -- the second rule is
                // the one under test. Neither provider is `openai`/`anthropic`
                // by name, so both default to the `openai-compatible`
                // (plain-http) dialect and need no TLS setup to reach a local
                // mock upstream.
                let config_text = format!(
                    "version: 0\n\
                     providers:\n\
                     \x20\x20provider-a: {{ base_url: \"http://{addr_a}\" }}\n\
                     \x20\x20provider-b: {{ base_url: \"http://{addr_b}\" }}\n\
                     routes:\n\
                     \x20\x20- {{ model: \"gpt-*\", provider: provider-a }}\n\
                     \x20\x20- {{ model: \"claude-*\", provider: provider-b }}\n"
                );
                let config =
                    proxy_simple_config::parse_simple_config_with_env(&config_text, &|_| None)
                        .expect("must parse");
                let loaded = lower_to_loaded(&config).expect("must lower and validate");
                let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

                let handler = build_real_handler(&snapshot).await;

                // The body names the SECOND provider's model; no
                // `x-llmproxy-model` header is set by the client at all --
                // routing must be entirely body-derived.
                let body = br#"{"model":"claude-3-5-sonnet","messages":[]}"#;
                let resp = handler
                    .handle(json_post_request("/v1/chat/completions", body))
                    .await;
                assert_eq!(resp.head.status, StatusCode::OK);
                let _ = resp.body.collect().await;

                assert!(
                    rx_b.await.is_ok(),
                    "provider B (claude-*) should have been dialed -- the body named a claude model"
                );
                assert!(
                    rx_a.try_recv().is_err(),
                    "provider A (gpt-*) must NOT have been dialed -- the body named a claude \
                     model, not a gpt one"
                );
            })
            .await;
    }
}

// another instance of AGENTS.md invariant 6: the usage dialect on the CLUSTER.

/// The regression test for the defect this carrier was introduced with: the
/// route-level copy resolves through `resolved_dialect` (which honours an
/// explicit `dialect` on a `models` entry), while the first cut of the
/// cluster-level copy derived it from the provider *type* alone. They
/// therefore disagreed for any entry that states a dialect its type would
/// not have implied -- and nothing constrains `dialect` to agree with
/// `type`, so this is reachable today on an ordinary `openai` provider, not
/// only on the still-unbuilt Vertex/Bedrock types where the field is
/// mandatory.
///
/// Asserted on the built IR, not the lowered YAML: `ClusterConfig::usage_dialect`
/// is the carrier the data plane must read (architecture.md §11, finding H2:
/// the forward path does not read it yet), so proving the value survives
/// `metadata.filter_metadata` -> strict loader -> IR is the contract that
/// matters. Checking the YAML alone would pass even if the Envoy-side
/// reader dropped it.
#[test]
fn an_explicit_dialect_reaches_the_cluster_and_not_only_the_route() {
    let config = parse(
        r#"
version: 0
providers:
  myopenai: { type: openai, api_key: k }
models:
  m:
    providers:
      - { provider: myopenai, dialect: anthropic }
routes:
  - { model: "*", provider: myopenai }
"#,
    )
    .expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

    assert_eq!(
        snapshot.clusters["provider:myopenai"].usage_dialect,
        Some(proxy_config::ir::UsageDialect::Anthropic),
        "the cluster must carry the dialect the `models` entry stated, not the one its \
         provider `type` would have implied -- deriving it from the type is what made the \
         two carriers disagree"
    );
}

/// The complement, so the test above cannot pass by simply hardcoding
/// `Anthropic`: with no explicit `dialect` anywhere, the cluster falls back
/// to the type-derived answer.
#[test]
fn with_no_explicit_dialect_the_cluster_falls_back_to_the_provider_type() {
    let config = parse(
        r#"
version: 0
providers:
  myopenai: { type: openai, api_key: k }
  myanthropic: { type: anthropic, api_key: k }
routes:
  - { model: "claude*", provider: myanthropic }
  - { model: "*", provider: myopenai }
"#,
    )
    .expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

    assert_eq!(
        snapshot.clusters["provider:myopenai"].usage_dialect,
        Some(proxy_config::ir::UsageDialect::OpenAi)
    );
    assert_eq!(
        snapshot.clusters["provider:myanthropic"].usage_dialect,
        Some(proxy_config::ir::UsageDialect::Anthropic)
    );
}

/// One cluster cannot carry two dialects, so two `models` entries that
/// resolve the same provider differently is a hard load error naming both
/// paths (AGENTS.md invariant 1) rather than a silent pick of whichever the walk
/// reached first.
#[test]
fn two_model_entries_disagreeing_on_a_providers_dialect_is_a_hard_error() {
    let config = parse(
        r#"
version: 0
providers:
  shared: { type: openai, api_key: k }
models:
  a:
    providers:
      - { provider: shared, dialect: openai }
  b:
    providers:
      - { provider: shared, dialect: anthropic }
routes:
  - { model: "*", provider: shared }
"#,
    )
    .expect("must parse -- the disagreement is a lowering-time error");
    let err = lower_to_loaded(&config)
        .expect_err("a provider used with two different dialects must fail to lower");
    let ConfigError::InvalidValue { field_path, reason } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "models.b.providers[0]");
    assert!(
        reason.contains("models.a.providers[0]"),
        "the error must name the OTHER offending path too, or the user cannot tell what it \
         disagrees with: {reason}"
    );
}

/// The two carriers must not drift apart again: for every provider cluster
/// the example config produces, the dialect on the cluster equals the
/// dialect on the route that selects it.
#[test]
fn both_dialect_carriers_agree_on_the_example_config() {
    let config = parse(proxy_simple_config::SAMPLE_CONFIG).expect("example must parse");
    let loaded = lower_to_loaded(&config).expect("example must lower");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("example must build IR");
    let lowered = proxy_simple_config::lower(&config).expect("example must lower");
    let routes = lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .expect("routes")
        .clone();

    let name_of = |d: proxy_config::ir::UsageDialect| match d {
        proxy_config::ir::UsageDialect::OpenAi => "openai",
        proxy_config::ir::UsageDialect::Anthropic => "anthropic",
    };

    let mut checked = 0;
    for route in &routes {
        let cluster = route["route"]["cluster"]
            .as_str()
            .expect("every example route targets a named cluster");
        let route_dialect = route["typed_per_filter_config"]["llmproxy.usage"]["dialect"]
            .as_str()
            .expect("every route carries a usage dialect");

        // A route targeting an aggregate is the case AGENTS.md invariant 6 is
        // actually about: the route picks the aggregate, but the MEMBER is
        // what gets dialled, so every member must agree with the route's
        // dialect -- otherwise failover silently meters the fallback with
        // the primary's parser. The aggregate itself carries no dialect
        // (`metadata` on an aggregate is a hard load error precisely so it
        // cannot), so this checks through to the members.
        let member_clusters: Vec<&str> = match &snapshot.clusters[cluster].kind {
            proxy_config::ir::ClusterKind::Aggregate { members } => {
                members.iter().map(String::as_str).collect()
            }
            _ => vec![cluster],
        };

        for member in member_clusters {
            let cluster_dialect = name_of(
                snapshot.clusters[member]
                    .usage_dialect
                    .expect("every provider cluster carries a usage dialect"),
            );
            assert_eq!(
                route_dialect, cluster_dialect,
                "route targeting `{cluster}` says `{route_dialect}` but member `{member}` \
                 says `{cluster_dialect}` -- the two carriers have drifted, which is exactly \
                 the wrong-billing failure moving this onto the cluster exists to prevent"
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 4,
        "expected at least 4 (route, cluster) pairs from the example -- three provider \
         routes plus the fallback route's second member; checked {checked}, so this test \
         has gone vacuous"
    );
}

// ---------------------------------------------------------------------------
// `routes:`-surface dialect resolution (the route carrier's half of the
// per-provider dialect work). `models:` got this check when it was added;
// `routes:` did
// not, and a `ProviderModelRef` is `{ provider, model }` with no `dialect`
// field, so a Vertex/Bedrock provider reached through `routes:` silently
// lowered as `openai`.
//
// Why that matters even though `lower()` currently refuses Vertex/Bedrock
// outright (`unbuilt_provider_types_are_hard_load_errors`): the guess is
// wrong the day those types become loadable, and what it produces is not a
// loud failure. The OpenAI usage parser finds no usage object in an
// Anthropic-shaped response, `StreamInfo::llm.usage` stays `None`, and the
// token limiter fails open -- it warns now (AGENTS.md "Fail-open controls") but still admits
// the request uncharged. This is the check that has to exist before either
// type ships, not after.

/// A dialect-ambiguous provider reached only through `routes:`, with no
/// `models:` entry to state its wire format, must be refused by name and
/// path rather than silently answered `openai`.
#[test]
fn a_routes_only_ambiguous_provider_is_rejected_with_its_path() {
    let err = parse(
        r#"
version: 0
providers:
  vertex-us:
    type: vertex
    base_url: "https://vertex-us.example.com"
    project: test-project
    location: us-central1
    publisher: anthropic
    access_token: token
routes:
  - { model: "*", provider: vertex-us }
"#,
    )
    .expect_err("an ambiguous provider with no dialect anywhere must fail");
    let ConfigError::InvalidValue { field_path, reason } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "routes[0].provider");
    assert!(reason.contains("vertex"), "names the type: {reason}");
    assert!(
        reason.contains("models:"),
        "points at the surface that can fix it: {reason}"
    );
}

/// The same rule applies to a fallback, at the fallback's own path -- a
/// fallback is dialled on failover, so a wrong dialect there mis-meters
/// exactly the requests that were already having a bad time.
#[test]
fn a_routes_fallback_to_an_ambiguous_provider_is_rejected_at_its_own_path() {
    let err = parse(
        r#"
version: 0
providers:
  main: { type: anthropic, base_url: "https://a.example.com", api_key: k }
  bedrock-w:
    type: bedrock
    base_url: "https://b.example.com"
    region: us-east-1
    access_key_id: access
    secret_access_key: secret
routes:
  - model: "*"
    provider: main
    fallbacks: [bedrock-w]
"#,
    )
    .expect_err("an ambiguous fallback with no dialect anywhere must fail");
    let ConfigError::InvalidValue { field_path, reason } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "routes[0].fallbacks[0]");
    assert!(reason.contains("bedrock"), "names the type: {reason}");
}

/// The check must NOT make Vertex/Bedrock unusable: `routes:` is
/// unconditionally required, so a blanket rejection would mean no valid
/// config could ever name one. A `models:` entry stating `dialect` is what
/// makes the route reference resolvable, and the route must then be accepted
/// AND carry the stated dialect -- not the `openai` the type would derive.
#[test]
fn a_models_entry_makes_an_ambiguous_routes_provider_resolvable() {
    let config = parse(
        r#"
version: 0
providers:
  vertex-us:
    type: vertex
    base_url: "https://vertex-us.example.com"
    project: test-project
    location: us-central1
    publisher: anthropic
    access_token: token
routes:
  - { model: "*", provider: vertex-us }
models:
  claude-sonnet-4-5:
    providers:
      - { provider: vertex-us, model: "claude-sonnet-4-5@20250929", dialect: anthropic }
"#,
    )
    .expect("a models entry pinning dialect must make this parse");
    let lowered = proxy_simple_config::lower(&config).expect("Vertex must lower");
    let cluster = lowered.bootstrap["static_resources"]["clusters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|cluster| cluster["name"] == "provider:vertex-us")
        .expect("Vertex provider cluster must exist");
    assert_eq!(
        cluster["metadata"]["filter_metadata"]["io.llmproxy.usage"]["dialect"],
        "anthropic"
    );
}

/// An unambiguous type in `routes:` is untouched by any of this -- the type
/// alone states the wire format, so no `models:` entry is needed.
#[test]
fn an_unambiguous_routes_provider_needs_no_models_entry() {
    parse(
        r#"
version: 0
providers:
  main: { type: anthropic, base_url: "https://a.example.com", api_key: k }
routes:
  - { model: "*", provider: main }
"#,
    )
    .expect("an anthropic provider derives its own dialect");
}

// ------------------------------------ tracing export deadline --

/// `observability.tracing.export_deadline` lowers with the dialect's own
/// duration syntax and defaults to 5s when omitted -- the same deadline
/// semantics the metrics block got, since neither exporter may stall forever.
#[test]
fn tracing_export_deadline_lowers_and_defaults() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  tracing:
    otlp_endpoint: "http://localhost:4317"
    export_deadline: "2s"
"#,
    )
    .expect("must parse");
    let snapshot = proxy_config::build_snapshot(&lower_to_loaded(&config).expect("must lower"))
        .expect("must build IR");
    assert_eq!(
        snapshot.tracing.expect("configured").export_deadline,
        std::time::Duration::from_secs(2)
    );

    // And the default, when the key is absent.
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  tracing:
    otlp_endpoint: "http://localhost:4317"
"#,
    )
    .expect("must parse");
    let snapshot = proxy_config::build_snapshot(&lower_to_loaded(&config).expect("must lower"))
        .expect("must build IR");
    assert_eq!(
        snapshot.tracing.expect("configured").export_deadline,
        std::time::Duration::from_secs(5)
    );
}

/// A malformed duration is a parse-time error naming the dialect path, before
/// it can reach the Envoy-mode reader.
#[test]
fn tracing_export_deadline_rejects_a_malformed_duration() {
    let err = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  tracing:
    otlp_endpoint: "http://localhost:4317"
    export_deadline: "5 seconds"
"#,
    )
    .expect_err("a malformed duration must not parse");
    assert!(
        err.to_string().contains("export_deadline"),
        "error should name export_deadline, got: {err}"
    );
}

/// The Envoy-mode reader's own bounds (`100ms..=60s`) apply to the dialect's
/// output too: the lowering forwards plain seconds, and the authoritative
/// reader rejects out-of-band values end to end. `60s` itself must LOAD -- the
/// ceiling is inclusive, same as the interval's bounds. The floor case uses
/// `100ms` rather than a fractional-second string because the dialect's
/// `SimpleDuration` syntax is integer-plus-unit (`^[0-9]+(ms|s|m|h)$`), so
/// `0.05s` is a syntax error at parse time -- which is its own (separate)
/// test, not this one.
#[test]
fn tracing_export_deadline_out_of_band_is_rejected_end_to_end() {
    for (value, expect_ok) in [("100ms", true), ("60s", true), ("120s", false)] {
        let config = parse(&format!(
            r#"
version: 0
providers:
  openai: {{ api_key: ${{OPENAI_API_KEY}} }}
routes:
  - {{ model: "*", provider: openai }}
observability:
  tracing:
    otlp_endpoint: "http://localhost:4317"
    export_deadline: "{value}"
"#
        ))
        .expect("must parse");
        let loaded = lower_to_loaded(&config).expect("dialect parse+lower must succeed");
        let built = proxy_config::build_snapshot(&loaded);
        assert_eq!(
            built.is_ok(),
            expect_ok,
            "export_deadline={value} must {}",
            if expect_ok { "load" } else { "be rejected" }
        );
    }
}

/// A sub-floor deadline expressed in the dialect's own millisecond syntax
/// (`50ms`) reaches the Envoy-mode reader and is rejected there, naming the
/// carrier-rooted path -- the same shape as the metrics side's cross-field
/// error, and the proof that the reader owns the bound rather than the dialect.
#[test]
fn tracing_export_deadline_below_the_floor_is_rejected_end_to_end() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
observability:
  tracing:
    otlp_endpoint: "http://localhost:4317"
    export_deadline: "50ms"
"#,
    )
    .expect("must parse");
    let loaded = lower_to_loaded(&config).expect("dialect parse+lower must succeed");
    let err = proxy_config::build_snapshot(&loaded).expect_err("50ms must not build");
    let ConfigError::InvalidValue { field_path, .. } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(
        field_path,
        "node.metadata[\"io.llmproxy.tracing\"].export_deadline"
    );
}

/// Both default formats carry the served model, so a dialect user can see
/// when the provider billed a different model than the one selected.
#[test]
fn default_access_log_formats_carry_the_served_model() {
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
        let lowered = proxy_simple_config::lower(&config).expect("must lower");
        let log_format =
            &hcm_typed_config(&lowered.bootstrap)["access_log"][0]["typed_config"]["log_format"];
        if format == "json" {
            assert_eq!(
                log_format["json_format"]["llm_served_model"],
                "%LLM_SERVED_MODEL%"
            );
        } else {
            let text = log_format["text_format"].as_str().expect("text_format");
            assert!(
                text.ends_with("llm_served_model=\"%LLM_SERVED_MODEL%\"\n"),
                "text format must end with the served model, got {text}"
            );
        }
    }
}
