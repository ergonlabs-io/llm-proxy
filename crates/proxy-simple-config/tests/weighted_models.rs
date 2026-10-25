//! `models.<name>.providers[i].weight` and `providers.<name>.outlier_detection`.
//!
//! A weighted alias lowers to Envoy `weighted_clusters` (S1.5) over one
//! aggregate per provider with a weight above 0, each starting at that
//! provider and keeping the rest of the list as its fallback chain. An alias
//! with no weights lowers exactly as before.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::collections::BTreeMap;

use proxy_config::ir::{ClusterKind, ForwardTarget, NetworkFilterSpec, RouteActionIR};
use proxy_config::ConfigError;
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config, SimpleConfig};
use serde_json::{json, Value};

fn parse(text: &str) -> SimpleConfig {
    parse_simple_config(text).expect("must parse")
}

fn parse_err(text: &str) -> (String, String) {
    let err = match parse_simple_config(text) {
        Ok(config) => lower(&config).expect_err("config must be refused"),
        Err(err) => err,
    };
    match err {
        ConfigError::InvalidValue { field_path, reason } => (field_path, reason),
        other => panic!("expected InvalidValue, got: {other}"),
    }
}

fn cluster<'a>(bootstrap: &'a Value, name: &str) -> &'a Value {
    bootstrap["static_resources"]["clusters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("cluster `{name}` must be present"))
}

fn cluster_names(bootstrap: &Value) -> Vec<String> {
    let mut names: Vec<String> = bootstrap["static_resources"]["clusters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

/// The `route` action of the implicit route for model `m`.
fn model_route_action(bootstrap: &Value) -> &Value {
    let routes = bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"]["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .unwrap();
    &routes
        .iter()
        .find(|r| r["match"]["headers"][0]["string_match"]["exact"] == "m")
        .expect("model route for `m`")["route"]
}

fn two_provider_config(entries: &str) -> String {
    format!(
        r#"
version: 1
providers:
  a: {{ type: openai-compatible, base_url: "http://a.internal:8000" }}
  b: {{ type: openai-compatible, base_url: "http://b.internal:8000" }}
  c: {{ type: openai-compatible, base_url: "http://c.internal:8000" }}
routes: []
models:
  m:
    providers: {entries}
"#
    )
}

/// An alias with no weights keeps its single ordered aggregate and the route
/// that targets it, byte for byte, and no provider cluster gains an
/// `outlier_detection`.
#[test]
fn an_alias_without_weights_lowers_exactly_as_before() {
    let lowered = lower(&parse(&two_provider_config("[a, b/b-upstream]"))).unwrap();
    let bootstrap = &lowered.bootstrap;

    assert_eq!(
        model_route_action(bootstrap),
        &json!({
            "cluster": "fallback:model-m",
            "timeout": "0s",
            "idle_timeout": "90s",
            "host_rewrite_literal": "a.internal",
            "retry_policy": {
                "retry_on": "connect-failure,refused-stream,reset-before-request,retriable-status-codes",
                "num_retries": 1,
                "retriable_status_codes": [429, 500, 502, 503],
            },
        })
    );
    assert_eq!(
        cluster(bootstrap, "fallback:model-m"),
        &json!({
            "name": "fallback:model-m",
            "lb_policy": "CLUSTER_PROVIDED",
            "cluster_type": {
                "name": "envoy.clusters.aggregate",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig",
                    "clusters": ["provider:a", "provider:b"],
                }
            }
        })
    );
    assert_eq!(
        cluster_names(bootstrap),
        ["fallback:model-m", "provider:a", "provider:b", "provider:c"]
    );
    for name in ["provider:a", "provider:b", "provider:c"] {
        assert!(cluster(bootstrap, name).get("outlier_detection").is_none());
    }
}

/// Weights 3/1/0: the route splits over an aggregate per positive-weight
/// provider. Each aggregate starts at its provider and keeps every other entry
/// in list order, so `c` (weight 0) is a fallback in both and never first.
#[test]
fn weights_lower_to_weighted_clusters_over_rotated_aggregates() {
    let lowered = lower(&parse(&two_provider_config(
        "[{ provider: a, weight: 3 }, { provider: b, model: b-upstream, weight: 1 }, { provider: c, weight: 0 }]",
    )))
    .unwrap();
    let bootstrap = &lowered.bootstrap;
    let action = model_route_action(bootstrap);

    assert!(action.get("cluster").is_none());
    assert_eq!(
        action["weighted_clusters"],
        json!({ "clusters": [
            { "name": "fallback:model-m@a", "weight": 3 },
            { "name": "fallback:model-m@b", "weight": 1 },
        ] })
    );
    // Retries still reach every member of whichever chain was picked.
    assert_eq!(action["retry_policy"]["num_retries"], 2);
    assert_eq!(
        cluster(bootstrap, "fallback:model-m@a")["cluster_type"]["typed_config"]["clusters"],
        json!(["provider:a", "provider:b", "provider:c"])
    );
    assert_eq!(
        cluster(bootstrap, "fallback:model-m@b")["cluster_type"]["typed_config"]["clusters"],
        json!(["provider:b", "provider:a", "provider:c"])
    );
    assert_eq!(
        cluster_names(bootstrap),
        [
            "fallback:model-m@a",
            "fallback:model-m@b",
            "provider:a",
            "provider:b",
            "provider:c"
        ]
    );
    // The upstream model ID stays on the member cluster (AGENTS.md invariant
    // 6), so whichever chain serves, provider `b` sends `b-upstream`.
    assert_eq!(
        cluster(bootstrap, "provider:b")["metadata"]["filter_metadata"]
            ["io.llmproxy.provider_auth"]["models"],
        json!([{ "pattern": "m", "upstream_model": "b-upstream" }])
    );
}

/// Through the real loader, every draw the router can make maps to a chain
/// whose first member is the provider the weights say, so the split is
/// exactly 3:1 over the whole draw space. This is the deterministic half of
/// the ratio acceptance; the router draws uniformly per request
/// (`router.rs`), and the binary-level sample is in
/// `testing/diffrig/tests/weighted_e2e.rs`.
#[test]
fn every_draw_starts_at_the_provider_its_weight_owns() {
    let config = parse(&two_provider_config(
        "[{ provider: a, weight: 3 }, { provider: b, weight: 1 }, { provider: c, weight: 0 }]",
    ));
    let loaded = lower_to_loaded(&config).expect("must lower and strict-validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");
    let listener = snapshot.listeners.values().next().unwrap();
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected an HTTP connection manager");
    };
    let weighted = hcm.route_table.virtual_hosts[0]
        .routes
        .iter()
        .find_map(|route| match &route.action {
            RouteActionIR::Forward(forward) => match &forward.target {
                ForwardTarget::Weighted(w) => Some(w),
                _ => None,
            },
            _ => None,
        })
        .expect("the alias route targets weighted clusters");
    assert_eq!(weighted.total_weight, 4);

    let mut first_member: BTreeMap<String, u64> = BTreeMap::new();
    for draw in 0..weighted.total_weight {
        let aggregate = weighted.pick(draw);
        let ClusterKind::Aggregate { members } = &snapshot.clusters[aggregate.as_str()].kind else {
            panic!("`{aggregate}` must be an aggregate");
        };
        assert_eq!(members.len(), 3, "every chain keeps all three providers");
        *first_member.entry(members[0].clone()).or_default() += 1;
    }
    assert_eq!(
        first_member,
        BTreeMap::from([("provider:a".to_string(), 3), ("provider:b".to_string(), 1)])
    );
}

/// A weight on a single-provider alias has nothing to split: it lowers to the
/// provider cluster, as without a weight.
#[test]
fn a_weight_on_a_single_provider_alias_targets_the_provider() {
    let lowered = lower(&parse(&two_provider_config("[{ provider: a, weight: 5 }]"))).unwrap();
    let action = model_route_action(&lowered.bootstrap);
    assert_eq!(action["cluster"], "provider:a");
    assert!(action.get("weighted_clusters").is_none());
}

#[test]
fn a_shorthand_entry_in_a_weighted_list_is_refused() {
    let (path, reason) = parse_err(&two_provider_config("[{ provider: a, weight: 1 }, b]"));
    assert_eq!(path, "models.m.providers[1]");
    assert!(reason.contains("object form"), "{reason}");
}

#[test]
fn an_object_entry_without_a_weight_in_a_weighted_list_is_refused() {
    let (path, reason) = parse_err(&two_provider_config(
        "[{ provider: a }, { provider: b, weight: 1 }]",
    ));
    assert_eq!(path, "models.m.providers[0]");
    assert!(reason.contains("every entry"), "{reason}");
}

#[test]
fn all_zero_weights_are_refused() {
    let (path, reason) = parse_err(&two_provider_config(
        "[{ provider: a, weight: 0 }, { provider: b, weight: 0 }]",
    ));
    assert_eq!(path, "models.m.providers");
    assert!(reason.contains("above 0"), "{reason}");
}

#[test]
fn a_weight_over_the_maximum_is_refused() {
    let (path, _) = parse_err(&two_provider_config(
        "[{ provider: a, weight: 1000001 }, { provider: b, weight: 1 }]",
    ));
    assert_eq!(path, "models.m.providers[0].weight");
}

#[test]
fn a_provider_listed_twice_in_a_weighted_list_is_refused() {
    let (path, reason) = parse_err(&two_provider_config(
        "[{ provider: a, weight: 1 }, { provider: a, weight: 2 }]",
    ));
    assert_eq!(path, "models.m.providers[1]");
    assert!(reason.contains("providers[0]"), "{reason}");
}

/// Weights do not relax AGENTS.md invariant 7: every member of every chain
/// must speak the alias's dialect.
#[test]
fn a_cross_dialect_member_of_a_weighted_alias_is_still_refused() {
    let (path, reason) = parse_err(
        r#"
version: 1
providers:
  openai: { api_key: sk-test }
  anthropic: { api_key: sk-ant-test }
routes: []
models:
  m:
    providers:
      - { provider: openai, weight: 1 }
      - { provider: anthropic, weight: 1 }
"#,
    );
    assert_eq!(path, "models.m.providers[1]");
    assert!(reason.contains("cross-dialect"), "{reason}");
}

fn outlier_config(block: &str) -> String {
    format!(
        r#"
version: 1
providers:
  a:
    type: openai-compatible
    base_url: "http://a.internal:8000"
    outlier_detection: {block}
routes: []
models:
  m: {{ providers: [a] }}
"#
    )
}

/// The dialect block lowers to the consecutive-5xx detector with a 100%
/// ejection cap, since a provider cluster has one host and Envoy's 10%
/// default would round to zero ejectable hosts.
#[test]
fn outlier_detection_lowers_to_the_provider_cluster() {
    let config = parse(&outlier_config(
        "{ consecutive_5xx: 3, base_ejection_time: 10s, max_ejection_time: 2m }",
    ));
    let lowered = lower(&config).unwrap();
    assert_eq!(
        cluster(&lowered.bootstrap, "provider:a")["outlier_detection"],
        json!({
            "consecutive_5xx": 3,
            "base_ejection_time": "10s",
            "max_ejection_time": "120s",
            "max_ejection_percent": 100,
            "enforcing_consecutive_5xx": 100,
            "enforcing_consecutive_gateway_failure": 0,
            "enforcing_success_rate": 0,
            "enforcing_failure_percentage": 0,
        })
    );

    let loaded = lower_to_loaded(&config).expect("must lower and strict-validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");
    let od = snapshot.clusters["provider:a"]
        .outlier_detection
        .as_ref()
        .expect("outlier detection reaches the IR");
    assert_eq!(od.consecutive_5xx, 3);
    assert_eq!(od.max_ejection_percent, 100);
    assert_eq!(od.base_ejection_time, std::time::Duration::from_secs(10));
}

/// An empty block takes the S6 defaults for everything it leaves out.
#[test]
fn an_empty_outlier_detection_block_uses_the_defaults() {
    let config = parse(&outlier_config("{}"));
    let loaded = lower_to_loaded(&config).expect("must lower and strict-validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");
    let od = snapshot.clusters["provider:a"]
        .outlier_detection
        .as_ref()
        .unwrap();
    assert_eq!(od.consecutive_5xx, 5);
    assert_eq!(od.base_ejection_time, std::time::Duration::from_secs(30));
    assert_eq!(od.max_ejection_percent, 100);
}

#[test]
fn outlier_detection_values_that_cannot_eject_are_refused() {
    let (path, _) = parse_err(&outlier_config("{ consecutive_5xx: 0 }"));
    assert_eq!(path, "providers.a.outlier_detection.consecutive_5xx");
    let (path, _) = parse_err(&outlier_config("{ base_ejection_time: 0s }"));
    assert_eq!(path, "providers.a.outlier_detection.base_ejection_time");
    let (path, _) = parse_err(&outlier_config(
        "{ base_ejection_time: 60s, max_ejection_time: 30s }",
    ));
    assert_eq!(path, "providers.a.outlier_detection.max_ejection_time");
}

#[test]
fn an_unknown_outlier_detection_field_is_refused() {
    let err = parse_simple_config(&outlier_config("{ interval: 10s }"))
        .expect_err("unknown field must be refused");
    assert!(err.to_string().contains("interval"), "{err}");
}
