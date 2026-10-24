//! `models.<name>.selection: latency` lowers to route metadata
//! `io.llmproxy.selection` on the model's weighted route, which Envoy mode
//! reads into the IR (AGENTS.md invariant 5, `envoy-divergences.md` row 48).

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use proxy_config::build_snapshot;
use proxy_config::ir::{ForwardTarget, NetworkFilterSpec, RouteActionIR, WeightedSelection};
use proxy_config::ConfigError;
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config};
use serde_json::{json, Value};

fn config(providers: &str, selection: &str) -> String {
    format!(
        r#"
version: 1
providers:
  a: {{ type: openai-compatible, base_url: "http://a.internal:8000" }}
  b: {{ type: openai-compatible, base_url: "http://b.internal:8000" }}
routes: []
models:
  m:
    providers: {providers}
{selection}"#
    )
}

const WEIGHTED: &str = "[{ provider: a, weight: 3 }, { provider: b, weight: 1 }]";
const LATENCY: &str = "    selection: latency\n";

fn model_route(text: &str) -> Value {
    let bootstrap = lower(&parse_simple_config(text).unwrap())
        .unwrap()
        .bootstrap;
    bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        ["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["match"]["headers"][0]["string_match"]["exact"] == "m")
        .expect("model route for `m`")
        .clone()
}

/// The weighted selection the full dialect -> Envoy -> IR path produces.
fn lowered_selection(text: &str) -> Option<WeightedSelection> {
    let loaded = lower_to_loaded(&parse_simple_config(text).unwrap()).unwrap();
    let snapshot = build_snapshot(&loaded).unwrap();
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
                ForwardTarget::Weighted(w) => Some(w.selection),
                _ => None,
            },
            _ => None,
        })
}

#[test]
fn latency_selection_reaches_the_ir_through_route_metadata() {
    let text = config(WEIGHTED, LATENCY);
    assert_eq!(
        model_route(&text)["metadata"],
        json!({ "filter_metadata": { "io.llmproxy.selection": { "mode": "latency" } } })
    );
    assert_eq!(lowered_selection(&text), Some(WeightedSelection::Latency));

    for default in ["", "    selection: weighted\n"] {
        let text = config(WEIGHTED, default);
        assert!(model_route(&text).get("metadata").is_none(), "{default:?}");
        assert_eq!(lowered_selection(&text), Some(WeightedSelection::Static));
    }
}

/// Without weights there is no split to bias: refused with the field's path
/// rather than accepted and ignored. One weighted provider lowers to a plain
/// cluster with nothing to choose, so it carries no metadata, and the Envoy
/// loader (which refuses the namespace on a non-weighted route) accepts it.
#[test]
fn latency_selection_needs_a_weighted_split() {
    let err = parse_simple_config(&config("[a, b]", LATENCY))
        .expect_err("an unweighted alias must be refused");
    match err {
        ConfigError::InvalidValue { field_path, .. } => {
            assert_eq!(field_path, "models.m.selection")
        }
        other => panic!("expected InvalidValue, got: {other}"),
    }

    let single = config("[{ provider: a, weight: 1 }]", LATENCY);
    assert!(model_route(&single).get("metadata").is_none());
    assert_eq!(lowered_selection(&single), None);
}
