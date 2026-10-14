//! llmproxy HTTP filter ordering is a config error, not
//! a doc comment.
//!
//! Two orderings among the llmproxy filters fail **silently** when reversed —
//! every request succeeds, nothing is logged, and the affected filter just
//! reads `None` out of `StreamInfo` forever. That is exactly AGENTS.md invariant 1's
//! failure mode, so `lower::check_lane_h_filter_order` rejects both at config
//! load. These are its acceptance tests.
//!
//! The two rules run in **opposite** directions because decode callbacks run
//! in config order and encode callbacks in reverse (S2.1). That is the single
//! most confusing thing here, and it is why each direction gets its own test
//! rather than one parameterised pair.

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

// The type URLs under test are `lower.rs`'s OWN constants, not fresh copies:
// a test that re-declared these literals would pin itself to the filters and
// leave `lower.rs` free to drift from both.
use proxy_config::lower::{
    AUTH_FILTER_TYPE as AUTH, BODY_REWRITE_FILTER_TYPE as BODY_REWRITE,
    LEGACY_BODY_REWRITE_FILTER_TYPE as LEGACY_BODY_REWRITE,
    LEGACY_TOKEN_LIMIT_FILTER_TYPE as LEGACY_TOKEN_LIMIT, LEGACY_USAGE_FILTER_TYPE as LEGACY_USAGE,
    MODEL_AUTHZ_FILTER_TYPE as MODEL_AUTHZ, MODEL_RESOLVER_FILTER_TYPE as MODEL_RESOLVER,
    SPEND_LIMIT_FILTER_TYPE as SPEND_LIMIT, TOKEN_LIMIT_FILTER_TYPE as TOKEN_LIMIT,
    USAGE_FILTER_TYPE as USAGE,
};

/// `lower.rs` cannot import the filters' constants — `proxy-filters` depends
/// on `proxy-config`, so the production dependency cannot point back — and
/// duplicates them as string literals instead. That duplication is only safe
/// if something fails when the two copies drift, which is this test.
///
/// **What drift would actually cost.** `check_lane_h_filter_order` matches on
/// `type_url` equality. Rename a filter's `TYPE_URL` without updating
/// `lower.rs` and the ordering rules stop matching anything: no error, no
/// warning, and every wrongly-ordered chain loads clean again — the exact
/// silent failure the check was written to remove, reintroduced by a rename
/// that looks purely local. A `proxy-filters` dev-dependency is a cheap price
/// for making that impossible.
#[test]
fn the_type_url_literals_in_lower_rs_match_the_filters_that_define_them() {
    assert_eq!(
        AUTH,
        proxy_filters::auth_filter::TYPE_URL,
        "the auth filter's type URL changed; update `AUTH_FILTER_TYPE` in \
         proxy-config/src/lower.rs or the auth-before-token_limit ordering rule \
         silently stops firing"
    );
    assert_eq!(
        TOKEN_LIMIT,
        proxy_filters::token_limit_filter::TYPE_URL,
        "the token limiter's type URL changed; update `TOKEN_LIMIT_FILTER_TYPE` in \
         proxy-config/src/lower.rs or BOTH ordering rules silently stop firing"
    );
    assert_eq!(
        LEGACY_TOKEN_LIMIT,
        proxy_filters::token_limit_filter::LEGACY_TYPE_URL,
        "the legacy token limiter type URL changed; update \
         `LEGACY_TOKEN_LIMIT_FILTER_TYPE` in proxy-config/src/lower.rs or old configs \
         will lose ordering protection during the one-release compatibility window"
    );
    assert_eq!(
        USAGE,
        proxy_filters::usage_filter::TYPE_URL,
        "the usage filter's type URL changed; update `USAGE_FILTER_TYPE` in \
         proxy-config/src/lower.rs or the token_limit-before-usage ordering rule \
         silently stops firing"
    );
    assert_eq!(
        LEGACY_USAGE,
        proxy_filters::usage_filter::LEGACY_TYPE_URL,
        "the legacy usage-filter type URL changed; update LEGACY_USAGE_FILTER_TYPE in \
         proxy-config/src/lower.rs or old configs will lose ordering protection during \
         the one-release compatibility window"
    );
    assert_eq!(
        BODY_REWRITE,
        proxy_filters::body_rewrite_filter::TYPE_URL,
        "the body_rewrite filter's type URL changed; update `BODY_REWRITE_FILTER_TYPE` in \
         proxy-config/src/lower.rs or the body_rewrite-before-model_authz ordering rule \
         silently stops firing"
    );
    assert_eq!(
        LEGACY_BODY_REWRITE,
        proxy_filters::body_rewrite_filter::LEGACY_TYPE_URL,
        "the legacy body_rewrite type URL changed; update LEGACY_BODY_REWRITE_FILTER_TYPE in \
         proxy-config/src/lower.rs or old configs will lose ordering protection during \
         the one-release compatibility window"
    );
    assert_eq!(
        MODEL_AUTHZ,
        proxy_filters::model_authz_filter::TYPE_URL,
        "the model_authz filter's type URL changed; update `MODEL_AUTHZ_FILTER_TYPE` in \
         proxy-config/src/lower.rs or BOTH model_authz ordering rules silently \
         stop firing"
    );
    assert_eq!(
        MODEL_RESOLVER,
        proxy_filters::model_resolver_filter::TYPE_URL,
        "the model_resolver filter's type URL changed; update `MODEL_RESOLVER_FILTER_TYPE` \
         in proxy-config/src/lower.rs or every model_resolver ordering rule silently \
         stops firing"
    );
    assert_eq!(
        SPEND_LIMIT,
        proxy_filters::spend_limit_filter::TYPE_URL,
        "the spend_limit filter's type URL changed; update `SPEND_LIMIT_FILTER_TYPE` in \
         proxy-config/src/lower.rs or BOTH spend_limit ordering rules \
         silently stop firing"
    );
}

/// One `http_filters` entry. The configs are the minimum each message needs to
/// decode — this pass only reads `type_url`, never the payload.
fn filter_entry(name: &str, type_url: &str) -> String {
    let body = match type_url {
        AUTH => {
            "\n                      hmac_secret: { inline_string: \"s\" }\n                      virtual_keys: []"
        }
        TOKEN_LIMIT => "\n                      max_tokens: 10\n                      fill_rate: 1.0",
        LEGACY_TOKEN_LIMIT => "\n                      max_tokens: 10\n                      fill_rate: 1.0",
        USAGE => "\n                      dialect: openai",
        LEGACY_USAGE => "\n                      inline_string: \"\"",
        BODY_REWRITE => "\n                      enabled: true\n                      dialect: openai",
        LEGACY_BODY_REWRITE => "\n                      default_value: true\n                      runtime_key: openai",
        MODEL_AUTHZ => "\n                      policies: []",
        MODEL_RESOLVER => "\n                      rules: { default_model: fast }",
        SPEND_LIMIT => "\n                      pricing: []",
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

#[test]
fn legacy_token_limit_keeps_the_same_ordering_protection() {
    chain(&[
        ("llmproxy.auth", AUTH),
        ("llmproxy.token_limit", LEGACY_TOKEN_LIMIT),
        ("llmproxy.usage", USAGE),
    ])
    .expect("the one-release legacy type keeps the canonical ordering rules");

    let (_, reason) = expect_invalid(chain(&[
        ("llmproxy.token_limit", LEGACY_TOKEN_LIMIT),
        ("llmproxy.auth", AUTH),
    ]));
    assert!(
        reason.contains("authorization"),
        "legacy configs must not lose the security ordering check: {reason}"
    );
}

#[test]
fn canonical_and_legacy_limiters_are_each_checked_when_both_are_configured() {
    let (_, reason) = expect_invalid(chain(&[
        ("llmproxy.auth", AUTH),
        ("llmproxy.token_limit", TOKEN_LIMIT),
        ("llmproxy.usage", USAGE),
        ("llmproxy.token_limit_legacy", LEGACY_TOKEN_LIMIT),
    ]));
    assert!(
        reason.contains("REVERSE"),
        "the legacy entry after usage must still be rejected: {reason}"
    );
}

/// **The security-relevant one.** Reversed, the limiter's `decode_headers`
/// runs before the auth filter has written `StreamInfo::auth.tenant`, reads
/// `None`, and falls back to bucketing on the client's `authorization`
/// header — the spoofable key the auth filter exists to remove. Nothing about that
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

// --- rule 3: auth before model_authz (both decode-side) ----------------

#[test]
fn auth_before_model_authz_is_accepted() {
    chain(&[
        ("llmproxy.auth", AUTH),
        ("llmproxy.model_authz", MODEL_AUTHZ),
    ])
    .expect("auth ahead of model_authz is the correct order");
}

/// Reversed, `model_authz`'s `decode_headers` runs before the auth filter has
/// written `StreamInfo::auth.tenant`, reads `None`, and (per its fail-closed
/// design) refuses every request.
#[test]
fn model_authz_before_auth_is_rejected_because_the_authz_filter_would_see_no_tenant() {
    let (field_path, reason) = expect_invalid(chain(&[
        ("llmproxy.model_authz", MODEL_AUTHZ),
        ("llmproxy.auth", AUTH),
    ]));

    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.http_filters[1]"
    );
    assert!(
        reason.contains("llmproxy.auth") && reason.contains("BEFORE"),
        "the reason must name the filter and the required direction: {reason}"
    );
    assert!(
        reason.contains("no tenant"),
        "the reason must say what actually goes wrong: {reason}"
    );
}

// --- rule 4: body_rewrite before model_authz (both decode-side) ------------

#[test]
fn body_rewrite_before_model_authz_is_accepted() {
    chain(&[
        ("llmproxy.body_rewrite", BODY_REWRITE),
        ("llmproxy.model_authz", MODEL_AUTHZ),
    ])
    .expect("body_rewrite ahead of model_authz is the correct order");
}

#[test]
fn legacy_body_rewrite_keeps_the_same_ordering_protection() {
    chain(&[
        ("llmproxy.body_rewrite", LEGACY_BODY_REWRITE),
        ("llmproxy.model_authz", MODEL_AUTHZ),
    ])
    .expect("the one-release legacy type keeps the canonical ordering rule");

    let (_, reason) = expect_invalid(chain(&[
        ("llmproxy.model_authz", MODEL_AUTHZ),
        ("llmproxy.body_rewrite", LEGACY_BODY_REWRITE),
    ]));
    assert!(
        reason.contains("no model"),
        "legacy configs must not lose model extraction ordering protection: {reason}"
    );
}

/// Reversed, `model_authz`'s `decode_headers` runs before body_rewrite has
/// published `StreamInfo::requested_model`, reads `None`, and refuses every
/// request.
#[test]
fn model_authz_before_body_rewrite_is_rejected_because_the_authz_filter_would_see_no_model() {
    let (field_path, reason) = expect_invalid(chain(&[
        ("llmproxy.model_authz", MODEL_AUTHZ),
        ("llmproxy.body_rewrite", BODY_REWRITE),
    ]));

    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.http_filters[1]"
    );
    assert!(
        reason.contains("llmproxy.body_rewrite") && reason.contains("BEFORE"),
        "the reason must name the filter and the required direction: {reason}"
    );
    assert!(
        reason.contains("no model"),
        "the reason must say what actually goes wrong: {reason}"
    );
}

// --- rule 5: auth before spend_limit (decode-side) -------------------

#[test]
fn auth_before_spend_limit_is_accepted() {
    chain(&[
        ("llmproxy.auth", AUTH),
        ("llmproxy.spend_limit", SPEND_LIMIT),
    ])
    .expect("auth ahead of spend_limit is the correct order");
}

/// Reversed, the spend filter's `decode_headers` runs before the auth filter
/// has written `StreamInfo::auth.tenant`, reads `None`, and treats every
/// request as unlimited -- a ceiling that silently never fires.
#[test]
fn spend_limit_before_auth_is_rejected_because_the_spend_filter_would_see_no_tenant() {
    let (field_path, reason) = expect_invalid(chain(&[
        ("llmproxy.spend_limit", SPEND_LIMIT),
        ("llmproxy.auth", AUTH),
    ]));

    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.http_filters[1]"
    );
    assert!(
        reason.contains("llmproxy.auth") && reason.contains("BEFORE"),
        "the reason must name the filter and the required direction: {reason}"
    );
    assert!(
        reason.contains("unlimited"),
        "the reason must say what actually goes wrong: {reason}"
    );
}

// --- rule 6: spend_limit before usage (encode-side, so REVERSED) -----------

#[test]
fn spend_limit_before_usage_is_accepted() {
    chain(&[
        ("llmproxy.spend_limit", SPEND_LIMIT),
        ("llmproxy.usage", USAGE),
    ])
    .expect("the spend filter ahead of the usage filter is the correct order");
}

/// The direction here is the OPPOSITE of what "must run first" suggests,
/// because the spend filter's `record` is encode-side and encode runs in
/// reverse config order. Reversed, every request is priced as free and a
/// configured ceiling can never be reached.
#[test]
fn usage_before_spend_limit_is_rejected_because_the_spend_filter_would_price_every_request_as_free()
{
    let (field_path, reason) = expect_invalid(chain(&[
        ("llmproxy.usage", USAGE),
        ("llmproxy.spend_limit", SPEND_LIMIT),
    ]));

    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.http_filters[1]"
    );
    assert!(
        reason.contains("priced as free"),
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
        ("llmproxy.body_rewrite", BODY_REWRITE),
        ("llmproxy.model_authz", MODEL_AUTHZ),
        ("llmproxy.spend_limit", SPEND_LIMIT),
    ] {
        chain(&[(name, url)])
            .unwrap_or_else(|e| panic!("`{name}` alone must be a valid chain, got {e:?}"));
    }
}

/// A chain with no llmproxy filters at all is the overwhelmingly common case and
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

// --- model_resolver: after auth and body_rewrite, before model_authz -------

#[test]
fn model_resolver_between_extraction_and_authz_is_accepted() {
    chain(&[
        ("llmproxy.auth", AUTH),
        ("llmproxy.body_rewrite", BODY_REWRITE),
        ("llmproxy.model_resolver", MODEL_RESOLVER),
        ("llmproxy.model_authz", MODEL_AUTHZ),
    ])
    .expect("auth, body_rewrite, model_resolver, model_authz is the correct order");
}

#[test]
fn model_resolver_before_auth_is_rejected_because_every_tenant_would_get_the_default() {
    let (field_path, reason) = expect_invalid(chain(&[
        ("llmproxy.body_rewrite", BODY_REWRITE),
        ("llmproxy.model_resolver", MODEL_RESOLVER),
        ("llmproxy.auth", AUTH),
    ]));

    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.http_filters[2]"
    );
    assert!(
        reason.contains("llmproxy.auth") && reason.contains("llmproxy.model_resolver"),
        "the reason must name both filters: {reason}"
    );
    assert!(
        reason.contains("default model"),
        "the reason must say what actually goes wrong: {reason}"
    );
}

#[test]
fn model_resolver_before_body_rewrite_is_rejected_because_auto_would_reach_the_provider() {
    let (field_path, reason) = expect_invalid(chain(&[
        ("llmproxy.model_resolver", MODEL_RESOLVER),
        ("llmproxy.body_rewrite", BODY_REWRITE),
    ]));

    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.http_filters[1]"
    );
    assert!(
        reason.contains("llmproxy.body_rewrite") && reason.contains("BEFORE"),
        "the reason must name the filter and the required direction: {reason}"
    );
}

#[test]
fn model_authz_before_model_resolver_is_rejected_because_it_would_check_auto() {
    let (field_path, reason) = expect_invalid(chain(&[
        ("llmproxy.body_rewrite", BODY_REWRITE),
        ("llmproxy.model_authz", MODEL_AUTHZ),
        ("llmproxy.model_resolver", MODEL_RESOLVER),
    ]));

    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.http_filters[2]"
    );
    assert!(
        reason.contains("`auto`"),
        "the reason must say what actually goes wrong: {reason}"
    );
}

/// Without body_rewrite the resolver never sees a model, so no ordering rule
/// fires; the chain must still be refused.
#[test]
fn model_resolver_without_body_rewrite_is_rejected() {
    let (field_path, reason) = expect_invalid(chain(&[
        ("llmproxy.auth", AUTH),
        ("llmproxy.model_resolver", MODEL_RESOLVER),
    ]));

    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.http_filters[1]"
    );
    assert!(
        reason.contains("requires `llmproxy.body_rewrite`"),
        "unexpected reason: {reason}"
    );
}

#[test]
fn model_resolver_with_legacy_body_rewrite_is_accepted() {
    chain(&[
        ("llmproxy.body_rewrite", LEGACY_BODY_REWRITE),
        ("llmproxy.model_resolver", MODEL_RESOLVER),
    ])
    .expect("the one-release legacy body_rewrite type satisfies the resolver");
}
