//! WP-35 increment 2c acceptance tests: `routes[i].fallbacks` lowers to an
//! `envoy.clusters.aggregate` cluster that the Envoy-mode strict loader
//! actually accepts (`cluster_type` + `lb_policy: CLUSTER_PROVIDED`, and none
//! of the five fields an aggregate forbids), with the route's `cluster`
//! pointed at the aggregate instead of the primary provider directly, the
//! Host header following each MEMBER cluster rather than the route, and
//! `num_retries` enlarged to reach every member of the chain.

use proxy_config::ir::ClusterKind;
use proxy_config::ConfigError;
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config_with_env, SimpleConfig};

fn test_env(name: &str) -> Option<String> {
    match name {
        "OPENAI_API_KEY" => Some("sk-test-openai".to_string()),
        "ANTHROPIC_API_KEY" => Some("sk-test-anthropic".to_string()),
        _ => None,
    }
}

fn parse(text: &str) -> Result<SimpleConfig, ConfigError> {
    parse_simple_config_with_env(text, &test_env)
}

/// A route with one fallback: `openai` (the name-inferred provider) falling
/// over to `fb1`, an explicitly `openai-compatible` provider -- same
/// dialect, different provider, exactly the case the spec calls out as
/// supported.
const ONE_FALLBACK_CONFIG: &str = r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
  fb1: { type: openai-compatible, base_url: http://fb1.internal:8000 }
routes:
  - model: "*"
    provider: openai
    fallbacks: [fb1]
"#;

/// Same as [`ONE_FALLBACK_CONFIG`] but with a second same-dialect fallback,
/// for the tests that need a three-member chain (retry-count floor).
const THREE_MEMBER_CONFIG: &str = r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
  fb1: { type: openai-compatible, base_url: http://fb1.internal:8000 }
  fb2: { type: openai-compatible, base_url: http://fb2.internal:8000 }
routes:
  - model: "*"
    provider: openai
    fallbacks: [fb1, fb2]
    retries: { attempts: 1 }
"#;

/// No `fallbacks:` at all -- the pre-2c shape, kept as a regression fixture.
const NO_FALLBACK_CONFIG: &str = r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - model: "*"
    provider: openai
"#;

/// `openai` (dialect `openai`) falling back to `anthropic` (dialect
/// `anthropic`) -- the cross-dialect case that must be a hard config error.
const CROSS_DIALECT_CONFIG: &str = r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
  anthropic: { api_key: ${ANTHROPIC_API_KEY} }
routes:
  - model: "*"
    provider: openai
    fallbacks: [anthropic]
"#;

fn route_action(bootstrap: &serde_json::Value, index: usize) -> &serde_json::Value {
    &bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        ["route_config"]["virtual_hosts"][0]["routes"][index]["route"]
}

fn clusters(bootstrap: &serde_json::Value) -> &Vec<serde_json::Value> {
    bootstrap["static_resources"]["clusters"]
        .as_array()
        .expect("clusters must be an array")
}

fn find_cluster<'a>(bootstrap: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    clusters(bootstrap)
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("cluster `{name}` must be present"))
}

/// A route with one fallback emits an aggregate cluster whose `clusters`
/// list is `["provider:openai", "provider:fb1"]`, in that order -- listed
/// order is the failover order -- and the aggregate carries exactly the
/// shape `convert_cluster` (proxy-config) requires: `lb_policy:
/// CLUSTER_PROVIDED` and nothing else exotic.
#[test]
fn one_fallback_emits_an_aggregate_with_members_in_order() {
    let config = parse(ONE_FALLBACK_CONFIG).expect("must parse");
    let lowered = lower(&config).expect("must lower");

    let agg = find_cluster(&lowered.bootstrap, "fallback:route-0");
    assert_eq!(agg["lb_policy"], "CLUSTER_PROVIDED");
    assert_eq!(agg["cluster_type"]["name"], "envoy.clusters.aggregate");
    assert_eq!(
        agg["cluster_type"]["typed_config"]["clusters"],
        serde_json::json!(["provider:openai", "provider:fb1"])
    );
    // None of the five fields an aggregate forbids.
    assert!(agg.get("load_assignment").is_none());
    assert!(agg.get("transport_socket").is_none());
    assert!(agg.get("typed_extension_protocol_options").is_none());
    assert!(agg.get("metadata").is_none());
}

/// The route's `cluster` becomes the aggregate name, not `provider:openai`.
#[test]
fn route_with_fallback_targets_the_aggregate_not_the_primary() {
    let config = parse(ONE_FALLBACK_CONFIG).expect("must parse");
    let lowered = lower(&config).expect("must lower");

    let action = route_action(&lowered.bootstrap, 0);
    assert_eq!(action["cluster"], "fallback:route-0");
}

/// Regression: a route with NO fallbacks still targets `provider:{name}`
/// directly, and no aggregate cluster is emitted anywhere in the bootstrap.
#[test]
fn no_fallbacks_is_unchanged() {
    let config = parse(NO_FALLBACK_CONFIG).expect("must parse");
    let lowered = lower(&config).expect("must lower");

    let action = route_action(&lowered.bootstrap, 0);
    assert_eq!(action["cluster"], "provider:openai");

    assert!(
        clusters(&lowered.bootstrap).iter().all(|c| !c["name"]
            .as_str()
            .unwrap_or_default()
            .starts_with("fallback:")),
        "no aggregate cluster should be emitted for a route with no fallbacks"
    );
}

/// Every provider cluster carries a `host` entry in its provider_auth
/// headers, matching its OWN upstream host -- this is what lets the Host
/// header follow whichever member an aggregate actually dials, rather than
/// staying pinned to the primary via the route's `host_rewrite_literal`.
#[test]
fn every_provider_cluster_carries_its_own_host_header() {
    let config = parse(ONE_FALLBACK_CONFIG).expect("must parse");
    let lowered = lower(&config).expect("must lower");

    let expect_host_header = |cluster_name: &str, want_host: &str| {
        let cluster = find_cluster(&lowered.bootstrap, cluster_name);
        let headers = cluster["metadata"]["filter_metadata"]["io.llmproxy.provider_auth"]
            ["headers"]
            .as_array()
            .unwrap_or_else(|| panic!("{cluster_name} must carry provider_auth headers"));
        let host_entry = headers
            .iter()
            .find(|h| h["key"] == "host")
            .unwrap_or_else(|| panic!("{cluster_name} must carry a `host` header entry"));
        assert_eq!(host_entry["value"], want_host, "cluster {cluster_name}");
    };

    expect_host_header("provider:openai", "api.openai.com");
    expect_host_header("provider:fb1", "fb1.internal");
}

/// Cross-dialect fallback (`openai` primary -> `anthropic` fallback) is a
/// hard error naming `routes[0].fallbacks[0]` -- an OpenAI-shaped request
/// body is not valid for Anthropic, and the response would be parsed for
/// tokens by the wrong dialect's parser.
#[test]
fn cross_dialect_fallback_is_rejected() {
    let config = parse(CROSS_DIALECT_CONFIG).expect("must parse");
    let err = lower(&config).expect_err("cross-dialect fallback must be rejected");
    match err {
        ConfigError::InvalidValue { field_path, reason } => {
            assert_eq!(field_path, "routes[0].fallbacks[0]");
            assert!(
                reason.contains("dialect"),
                "expected the reason to explain the dialect mismatch, got: {reason}"
            );
        }
        other => panic!("expected InvalidValue, got: {other}"),
    }
}

/// Same-dialect fallback across different providers (`openai` ->
/// `openai-compatible`) is accepted -- the supported case.
#[test]
fn same_dialect_fallback_across_providers_is_accepted() {
    let config = parse(ONE_FALLBACK_CONFIG).expect("must parse");
    lower(&config).expect("same-dialect fallback across providers must lower");
}

/// `attempted_clusters` makes each retry against an aggregate pick the NEXT
/// member, so a three-member chain (`openai` -> `fb1` -> `fb2`) needs at
/// least 2 retries to ever reach the last one. `retries.attempts: 1` alone
/// is not enough, so `num_retries` must be raised to 2.
#[test]
fn num_retries_is_raised_to_reach_every_member() {
    let config = parse(THREE_MEMBER_CONFIG).expect("must parse");
    let lowered = lower(&config).expect("must lower");

    let action = route_action(&lowered.bootstrap, 0);
    assert_eq!(action["retry_policy"]["num_retries"], 2);
}

/// End-to-end through the real loader: the emitted YAML for a fallback
/// config lowers cleanly via `parse_bootstrap` + `build_snapshot` (what
/// `lower_to_loaded` wraps) to a `ClusterKind::Aggregate` with the right
/// members -- this is what would catch, for example, forgetting
/// `lb_policy: CLUSTER_PROVIDED`.
#[test]
fn fallback_config_lowers_through_the_real_loader_to_an_aggregate() {
    let config = parse(ONE_FALLBACK_CONFIG).expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and strict-validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

    let agg = snapshot
        .clusters
        .get("fallback:route-0")
        .expect("aggregate cluster must be in the snapshot");
    match &agg.kind {
        ClusterKind::Aggregate { members } => {
            assert_eq!(
                members,
                &vec!["provider:openai".to_string(), "provider:fb1".to_string()]
            );
        }
        other => panic!("expected ClusterKind::Aggregate, got {other:?}"),
    }
}
