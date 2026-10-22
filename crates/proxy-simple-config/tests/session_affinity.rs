//! `models.<name>.session_affinity` (ADR-0016): lowers to Envoy
//! `weighted_clusters.use_hash_policy` plus a route `hash_policy`, so the
//! dialect and Envoy mode reach the same IR and pick the same member for the
//! same session (AGENTS.md invariant 5).

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use proxy_config::ir::{ForwardTarget, NetworkFilterSpec, RouteActionIR, WeightedClusters};
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};
use proxy_http::route::{weighted_draw, DrawSource, HashIdentity};
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config};
use serde_json::{json, Value};

fn config(auth: bool, providers: &str, affinity: &str) -> String {
    let auth = if auth {
        "auth: { hmac_secret: \"s\", keys: [] }\n"
    } else {
        ""
    };
    format!(
        r#"
version: 0
{auth}providers:
  a: {{ type: openai-compatible, base_url: "http://a.internal:8000" }}
  b: {{ type: openai-compatible, base_url: "http://b.internal:8000" }}
routes: []
models:
  m:
    providers: {providers}
    session_affinity: {affinity}
"#
    )
}

const WEIGHTED: &str = "[{ provider: a, weight: 3 }, { provider: b, weight: 1 }]";

fn model_route_action(bootstrap: &Value) -> Value {
    let routes = bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"]["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .unwrap();
    routes
        .iter()
        .find(|r| r["match"]["headers"][0]["string_match"]["exact"] == "m")
        .expect("model route for `m`")["route"]
        .clone()
}

fn load_error(text: &str) -> (String, String) {
    let err = match parse_simple_config(text) {
        Ok(config) => lower(&config).expect_err("config must be refused"),
        Err(err) => err,
    };
    match err {
        ConfigError::InvalidValue { field_path, reason } => (field_path, reason),
        other => panic!("expected InvalidValue, got: {other}"),
    }
}

#[test]
fn header_and_identity_lower_to_an_envoy_hash_policy() {
    let text = config(
        true,
        WEIGHTED,
        "{ header: X-Session-Affinity, identity: user }",
    );
    let lowered = lower(&parse_simple_config(&text).unwrap()).unwrap();
    let action = model_route_action(&lowered.bootstrap);
    assert_eq!(action["weighted_clusters"]["use_hash_policy"], json!(true));
    assert_eq!(
        action["hash_policy"],
        json!([
            { "header": { "header_name": "x-session-affinity" }, "terminal": true },
            { "filter_state": { "key": "llmproxy.auth.user_id" } },
        ])
    );
}

/// A single-provider alias lowers to its provider cluster: every request
/// already reaches the one member, so there is no hash policy to carry.
#[test]
fn a_single_provider_alias_carries_no_hash_policy() {
    let text = config(false, "[{ provider: a, weight: 1 }]", "{ header: x-s }");
    let lowered = lower(&parse_simple_config(&text).unwrap()).unwrap();
    let action = model_route_action(&lowered.bootstrap);
    assert_eq!(action["cluster"], "provider:a");
    assert!(action.get("hash_policy").is_none());
}

#[test]
fn refused_shapes_name_their_path() {
    for (label, text, path) in [
        (
            "unweighted alias",
            config(false, "[a, b]", "{ header: x-s }"),
            "models.m.session_affinity",
        ),
        (
            "no source",
            config(false, WEIGHTED, "{}"),
            "models.m.session_affinity",
        ),
        (
            "identity without auth",
            config(false, WEIGHTED, "{ identity: key }"),
            "models.m.session_affinity.identity",
        ),
        (
            "invalid header name",
            config(false, WEIGHTED, "{ header: \"x s\" }"),
            "models.m.session_affinity.header",
        ),
    ] {
        assert_eq!(load_error(&text).0, path, "{label}");
    }
}

fn weighted_target(snapshot: &proxy_config::ir::ConfigSnapshot) -> &WeightedClusters {
    let listener = snapshot.listeners.values().next().unwrap();
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected an HTTP connection manager");
    };
    hcm.route_table.virtual_hosts[0]
        .routes
        .iter()
        .find_map(|route| match &route.action {
            RouteActionIR::Forward(forward) => match &forward.target {
                ForwardTarget::Weighted(w) => Some(w),
                _ => None,
            },
            _ => None,
        })
        .expect("a weighted route")
}

/// The card's equivalence: a dialect alias and a hand-written Envoy route with
/// the same members, weights and hash policy pick the same member for every
/// session value, through the production lowering and draw.
#[test]
fn envoy_mode_and_the_dialect_pick_the_same_member() {
    let text = config(false, WEIGHTED, "{ header: x-session-affinity }");
    let loaded = lower_to_loaded(&parse_simple_config(&text).unwrap()).unwrap();
    let dialect = build_snapshot(&loaded).unwrap();

    let envoy_yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            hash_policy: [{ header: { header_name: x-session-affinity } }]
                            weighted_clusters:
                              use_hash_policy: true
                              clusters:
                                - { name: "fallback:model-m@a", weight: 3 }
                                - { name: "fallback:model-m@b", weight: 1 }
"#;
    let envoy = build_snapshot(
        &parse_bootstrap(
            envoy_yaml.as_bytes(),
            ConfigFormat::Yaml,
            StrictMode::Strict,
        )
        .unwrap(),
    )
    .unwrap();

    let (left, right) = (weighted_target(&dialect), weighted_target(&envoy));
    assert_eq!(left.hash_policy, right.hash_policy);
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..1000 {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-session-affinity",
            format!("session-{i}").parse().unwrap(),
        );
        let none = HashIdentity::default();
        let random = || panic!("a session header must never take the random draw");
        let (l, source) = weighted_draw(left, &headers, &none, random);
        let (r, _) = weighted_draw(right, &headers, &none, random);
        assert_eq!(source, DrawSource::Hashed);
        assert_eq!(left.pick(l), right.pick(r), "session-{i}");
        seen.insert(left.pick(l).clone());
    }
    assert_eq!(seen.len(), 2, "both members are reachable");
}
