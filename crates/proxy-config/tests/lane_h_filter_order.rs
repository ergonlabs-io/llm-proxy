//! WP-50 increment 2a-ii: Lane-H HTTP filter ordering is a config error, not
//! a doc comment.
//!
//! Two orderings among the Lane-H filters fail **silently** when reversed —
//! every request succeeds, nothing is logged, and the affected filter just
//! reads `None` out of `StreamInfo` forever. That is exactly ground rule #1's
//! failure mode, so `lower::check_lane_h_filter_order` rejects both at config
//! load. These are its acceptance tests.
//!
//! The two rules run in **opposite** directions because decode callbacks run
//! in config order and encode callbacks in reverse (S2.1). That is the single
//! most confusing thing here, and it is why each direction gets its own test
//! rather than one parameterised pair.

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

const AUTH: &str = "type.llmproxy.dev/llmproxy.filters.v0.Authentication";
const TOKEN_LIMIT: &str = "type.llmproxy.dev/envoy.config.core.v3.RateLimitSettings";
const USAGE: &str = "type.llmproxy.dev/envoy.config.core.v3.DataSource";

/// One `http_filters` entry. The configs are the minimum each message needs to
/// decode — this pass only reads `type_url`, never the payload.
fn filter_entry(name: &str, type_url: &str) -> String {
    let body = match type_url {
        AUTH => {
            "\n                      hmac_secret: { inline_string: \"s\" }\n                      virtual_keys: []"
        }
        TOKEN_LIMIT => "\n                      max_tokens: 10\n                      fill_rate: 1.0",
        USAGE => "\n                      inline_string: \"\"",
        other => panic!("unexpected type url {other}"),
    };
    format!(
        r#"                  - name: {name}
                    typed_config:
                      "@type": {type_url}{body}
"#
    )
}

/// A listener whose HCM carries `filters` (already-rendered entries) followed
/// by the mandatory terminal router.
fn snapshot_with_filters(filters: &str) -> Result<ConfigSnapshot, ConfigError> {
    let yaml = format!(
        r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: {{ address: 0.0.0.0, port_value: 8080 }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters:
{filters}                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rt
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          direct_response: {{ status: 200 }}
"#
    );
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

fn chain(order: &[(&str, &str)]) -> Result<ConfigSnapshot, ConfigError> {
    let filters: String = order
        .iter()
        .map(|(name, url)| filter_entry(name, url))
        .collect();
    snapshot_with_filters(&filters)
}

fn expect_invalid(result: Result<ConfigSnapshot, ConfigError>) -> (String, String) {
    match result {
        Err(ConfigError::InvalidValue { field_path, reason }) => (field_path, reason),
        Err(other) => panic!("expected InvalidValue, got {other:?}"),
        Ok(_) => panic!("expected the config to be rejected, but it loaded"),
    }
}

// --- rule 1: auth before token_limit (both decode-side) --------------------

#[test]
fn auth_before_token_limit_is_accepted() {
    chain(&[
        ("llmproxy.auth", AUTH),
        ("llmproxy.token_limit", TOKEN_LIMIT),
    ])
    .expect("auth ahead of the limiter is the correct order");
}

/// **The security-relevant one.** Reversed, the limiter's `decode_headers`
/// runs before the auth filter has written `StreamInfo::auth.tenant`, reads
/// `None`, and falls back to bucketing on the client's `authorization`
/// header — the spoofable key WP-50 exists to remove. Nothing about that
/// failure is visible at runtime.
#[test]
fn token_limit_before_auth_is_rejected_because_the_limiter_would_silently_bucket_on_a_client_header(
) {
    let (field_path, reason) = expect_invalid(chain(&[
        ("llmproxy.token_limit", TOKEN_LIMIT),
        ("llmproxy.auth", AUTH),
    ]));

    // The error names the offending filter's own index (the auth filter, at 1),
    // not the whole list -- an operator needs to be told which line to move.
    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.http_filters[1]"
    );
    assert!(
        reason.contains("llmproxy.auth") && reason.contains("BEFORE"),
        "the reason must name the filter and the required direction: {reason}"
    );
    assert!(
        reason.contains("authorization"),
        "the reason must say what actually goes wrong -- silently bucketing on a \
         client-supplied header -- not merely that the order is wrong: {reason}"
    );
}

// --- rule 2: token_limit before usage (encode-side, so REVERSED) -----------

#[test]
fn token_limit_before_usage_is_accepted() {
    chain(&[
        ("llmproxy.token_limit", TOKEN_LIMIT),
        ("llmproxy.usage", USAGE),
    ])
    .expect("the limiter ahead of the usage filter is the correct order");
}

/// The direction here is the OPPOSITE of what "must run first" suggests,
/// because the limiter's `record` is encode-side and encode runs in reverse
/// config order. Reversed, every request records zero tokens against its
/// budget and the limit never fires.
#[test]
fn usage_before_token_limit_is_rejected_because_the_limiter_would_record_zero_tokens() {
    let (field_path, reason) = expect_invalid(chain(&[
        ("llmproxy.usage", USAGE),
        ("llmproxy.token_limit", TOKEN_LIMIT),
    ]));

    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.http_filters[1]"
    );
    assert!(
        reason.contains("zero tokens"),
        "the reason must state the silent consequence: {reason}"
    );
    assert!(
        reason.contains("REVERSE"),
        "the reason must explain WHY the required order looks backwards, or the \
         operator will read the error as a typo in our validator: {reason}"
    );
}

// --- a rule applies only when both of its filters are present --------------

#[test]
fn each_lane_h_filter_alone_is_a_valid_chain() {
    for (name, url) in [
        ("llmproxy.auth", AUTH),
        ("llmproxy.token_limit", TOKEN_LIMIT),
        ("llmproxy.usage", USAGE),
    ] {
        chain(&[(name, url)])
            .unwrap_or_else(|e| panic!("`{name}` alone must be a valid chain, got {e:?}"));
    }
}

/// A chain with no Lane-H filters at all is the overwhelmingly common case and
/// must not be touched by this pass.
#[test]
fn a_chain_with_no_lane_h_filters_is_unaffected() {
    snapshot_with_filters("").expect("a router-only chain must still load");
}

// --- all three together ----------------------------------------------------

#[test]
fn the_full_lane_h_chain_in_the_one_correct_order_loads() {
    let snapshot = chain(&[
        ("llmproxy.auth", AUTH),
        ("llmproxy.token_limit", TOKEN_LIMIT),
        ("llmproxy.usage", USAGE),
    ])
    .expect("auth -> token_limit -> usage is the only order satisfying both rules");

    // Also pin that the order survived into the IR unchanged: this pass
    // validates, it must never reorder on the operator's behalf. Silently
    // "fixing" a chain would mean the running config differs from the written
    // one, which is the same class of surprise as ignoring a field.
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    let urls: Vec<&str> = hcm
        .http_filters
        .iter()
        .map(|f| f.type_url.as_str())
        .collect();
    assert_eq!(
        urls,
        vec![
            AUTH,
            TOKEN_LIMIT,
            USAGE,
            "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
        ]
    );
}

/// With all three present, the auth rule must still fire even though the
/// token_limit/usage pair is correctly ordered — the two rules are checked
/// independently, and a chain that satisfies one is not thereby excused the
/// other.
#[test]
fn a_chain_satisfying_one_rule_is_still_rejected_for_violating_the_other() {
    let (_, reason) = expect_invalid(chain(&[
        ("llmproxy.token_limit", TOKEN_LIMIT),
        ("llmproxy.usage", USAGE),
        ("llmproxy.auth", AUTH),
    ]));
    assert!(
        reason.contains("llmproxy.auth"),
        "the auth rule must still fire: {reason}"
    );
}
