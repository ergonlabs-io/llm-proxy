//! A dialect `routes[].model` glob, end to end: the validator's glob
//! (`proxy-simple-config` `parse.rs`), its lowering to an Envoy header
//! matcher (exact, prefix, or an escaped `safe_regex`), the strict Envoy
//! loader, and the router's route match (`proxy-http` `route.rs`). The
//! validator decides whether `auto:` targets are served; the route table
//! decides where a request goes. If they read a glob differently, a model
//! the validator calls served goes elsewhere, or a regex metacharacter in a
//! model name widens a route.
//!
//! Input: the pattern and the model name, split at the first 0xFF byte.
//!
//! Property: with route 0 `{model: <pattern>, provider: a}` and route 1
//! `{model: "*", provider: b}`, a request for the model reaches `provider:a`
//! exactly when the validator's glob matches it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proxy_config::ir::{ForwardTarget, NetworkFilterSpec, RouteActionIR};
use proxy_http::route::{match_route, RouteMatch, RouteRequest};
use proxy_simple_config::fuzzing::glob_matches;

fuzz_target!(|data: &[u8]| {
    let (pattern, name) = match data.iter().position(|&b| b == 0xFF) {
        Some(at) => (&data[..at], &data[at + 1..]),
        None => (data, &data[..0]),
    };
    let (Ok(pattern), Ok(name)) = (std::str::from_utf8(pattern), std::str::from_utf8(name)) else {
        return;
    };
    // `$` would be read as `${VAR}` interpolation before YAML parsing.
    if pattern.is_empty() || pattern.contains('$') || pattern.len() > 128 {
        return;
    }
    // The model reaches the route match as a header value.
    let Ok(value) = http::HeaderValue::from_str(name) else {
        return;
    };

    let quoted = serde_json::to_string(pattern).expect("a str serializes");
    let text = format!(
        "version: 0\n\
         providers:\n  a: {{ base_url: \"http://a.test:1\" }}\n  b: {{ base_url: \"http://b.test:1\" }}\n\
         routes:\n  - model: {quoted}\n    provider: a\n  - model: \"*\"\n    provider: b\n"
    );
    let env = |_: &str| None;
    let Ok(config) = proxy_simple_config::parse_simple_config_with_env(&text, &env) else {
        return;
    };
    let loaded = proxy_simple_config::lower_to_loaded(&config)
        .unwrap_or_else(|err| panic!("a validated pattern {pattern:?} failed to lower: {err}"));
    let snapshot = proxy_config::build_snapshot(&loaded)
        .unwrap_or_else(|err| panic!("a validated pattern {pattern:?} failed to load: {err}"));
    let listener = snapshot
        .listeners
        .get("llmproxy_listener")
        .expect("the dialect names its listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("the dialect listener's first filter is the HCM");
    };

    let mut headers = http::HeaderMap::new();
    headers.insert(proxy_simple_config::MODEL_HEADER, value);
    let request = RouteRequest {
        authority: "fuzz.test",
        path: "/v1/chat/completions",
        headers: &headers,
    };
    let cluster = match match_route(&hcm.route_table, &request) {
        RouteMatch::Found { route, .. } => match &route.action {
            RouteActionIR::Forward(forward) => match &forward.target {
                ForwardTarget::Cluster(cluster) => Some(cluster.clone()),
                other => panic!("unexpected forward target {other:?}"),
            },
            _ => None,
        },
        _ => None,
    };
    let expected = if glob_matches(pattern, name) {
        "provider:a"
    } else {
        "provider:b"
    };
    assert_eq!(
        cluster.as_deref(),
        Some(expected),
        "pattern {pattern:?}, model {name:?}"
    );
});
