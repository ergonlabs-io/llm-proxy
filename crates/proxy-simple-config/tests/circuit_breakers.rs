//! `providers.<name>.circuit_breakers`: per-provider S5 concurrency ceilings.
//!
//! The block lowers onto the provider cluster's `DEFAULT`-priority thresholds
//! (AGENTS.md invariant 6: never the route). An aggregate in front of
//! configured providers is sized so its own budget never binds before theirs.
//! `crates/proxy/tests/provider_circuit_breaker_e2e.rs` proves the shedding
//! through the real binary.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use proxy_config::ir::{CircuitBreakerThresholds, CircuitBreakers};
use proxy_config::ConfigError;
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config};
use serde_json::{json, Value};

fn config(a_block: &str) -> String {
    format!(
        r#"
version: 0
providers:
  a:
    type: openai-compatible
    base_url: "http://a.internal:8000"
{a_block}
  b: {{ type: openai-compatible, base_url: "http://b.internal:8000" }}
routes:
  - {{ model: "r*", provider: a, fallbacks: [b] }}
models:
  m: {{ providers: [a, b] }}
"#
    )
}

fn circuit_breakers(text: &str) -> std::collections::HashMap<String, CircuitBreakers> {
    let parsed = parse_simple_config(text).expect("must parse");
    let loaded = lower_to_loaded(&parsed).expect("must lower and strict-validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");
    snapshot
        .clusters
        .iter()
        .map(|(name, cluster)| (name.clone(), cluster.circuit_breakers))
        .collect()
}

fn cluster(text: &str, name: &str) -> Value {
    let lowered = lower(&parse_simple_config(text).expect("must parse")).expect("must lower");
    lowered.bootstrap["static_resources"]["clusters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("cluster `{name}` must be present"))
        .clone()
}

fn parse_err(text: &str) -> ConfigError {
    match parse_simple_config(text) {
        Ok(parsed) => lower(&parsed).expect_err("config must be refused"),
        Err(err) => err,
    }
}

/// Unset keeps the Envoy default (1024 each) on every provider and aggregate,
/// and emits no `circuit_breakers` key, so existing configs lower unchanged.
#[test]
fn unset_keeps_the_envoy_default_on_providers_and_aggregates() {
    let text = config("");
    for (name, cb) in circuit_breakers(&text) {
        assert_eq!(cb, CircuitBreakers::default(), "{name}");
        assert_eq!(cb.default.max_requests, 1024, "{name}");
        assert_eq!(cb.default.max_pending_requests, 1024, "{name}");
        assert_eq!(cb.default.max_connections, 1024, "{name}");
    }
    for name in [
        "provider:a",
        "provider:b",
        "fallback:route-0",
        "fallback:model-m",
    ] {
        assert!(
            cluster(&text, name).get("circuit_breakers").is_none(),
            "{name}"
        );
    }
}

/// Each configured field reaches the provider's `DEFAULT` bucket; the fields
/// left out and the `HIGH` bucket keep the defaults, and the other provider is
/// untouched.
#[test]
fn configured_fields_reach_only_that_provider_cluster() {
    let text = config(
        "    circuit_breakers: { max_requests: 4096, max_pending_requests: 8, max_connections: 64 }",
    );
    let breakers = circuit_breakers(&text);
    assert_eq!(
        breakers["provider:a"].default,
        CircuitBreakerThresholds {
            max_requests: 4096,
            max_pending_requests: 8,
            max_connections: 64,
            ..CircuitBreakerThresholds::ENVOY_DEFAULT
        }
    );
    assert_eq!(
        breakers["provider:a"].high,
        CircuitBreakerThresholds::ENVOY_DEFAULT
    );
    assert_eq!(breakers["provider:b"], CircuitBreakers::default());

    let only_requests = circuit_breakers(&config("    circuit_breakers: { max_requests: 2 }"));
    assert_eq!(
        only_requests["provider:a"].default,
        CircuitBreakerThresholds {
            max_requests: 2,
            ..CircuitBreakerThresholds::ENVOY_DEFAULT
        }
    );
}

/// The router checks the routed aggregate's `max_requests` before the dialled
/// member's, so an aggregate left at 1024 would cap a raised provider. Both
/// aggregate shapes (route fallbacks, model lists) get the members' sum, an
/// unset member counting as 1024.
#[test]
fn an_aggregate_is_sized_to_the_sum_of_its_members() {
    let text = config("    circuit_breakers: { max_requests: 5000 }");
    let breakers = circuit_breakers(&text);
    for name in ["fallback:route-0", "fallback:model-m"] {
        assert_eq!(breakers[name].default.max_requests, 6024, "{name}");
        assert_eq!(
            cluster(&text, name)["circuit_breakers"],
            json!({ "thresholds": [{ "max_requests": 6024 }] }),
            "{name}"
        );
    }

    let saturated = circuit_breakers(&config(
        "    circuit_breakers: { max_requests: 4294967295 }",
    ));
    assert_eq!(saturated["fallback:model-m"].default.max_requests, u32::MAX);
}

/// Zero would shed every request; it fails load with the full dotted path.
#[test]
fn zero_fails_with_the_full_dotted_path() {
    for field in ["max_requests", "max_pending_requests", "max_connections"] {
        let err = parse_err(&config(&format!("    circuit_breakers: {{ {field}: 0 }}")));
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, format!("providers.a.circuit_breakers.{field}"));
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }
}

/// Strict mode (AGENTS.md invariant 1): an unknown key fails with its path.
#[test]
fn an_unknown_key_fails_with_the_full_dotted_path() {
    let err = parse_err(&config("    circuit_breakers: { max_retries: 3 }"));
    match err {
        ConfigError::UnknownField { field_path, .. } => {
            assert_eq!(field_path, "providers.a.circuit_breakers.max_retries");
        }
        other => panic!("expected UnknownField, got {other:?}"),
    }
}
