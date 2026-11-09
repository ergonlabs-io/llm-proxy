//! `routes[].retries`: `per_try_timeout`, `on_status` and `max_retry_after`
//! reach the router's retry policy through the full dialect -> Envoy -> IR
//! path, the dialect never gains the `reset` trigger, and every out-of-range
//! or inert value is a load error naming its dotted path (AGENTS.md
//! invariant 1).

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::time::Duration;

use proxy_config::build_snapshot;
use proxy_config::ir::{
    NetworkFilterSpec, RateLimitedBackOff, ResetHeader, ResetHeaderFormat, RetryOn, RouteActionIR,
    RouteEntry,
};
use proxy_config::ConfigError;
use proxy_simple_config::{lower_to_loaded, parse_simple_config};

fn config(route_extra: &str) -> String {
    format!(
        r#"
version: 1
providers:
  openai: {{ type: openai, api_key: sk-a }}
  fb1: {{ type: openai-compatible, base_url: http://fb1.internal:8000 }}
routes:
  - {{ model: "*", provider: openai{route_extra} }}
"#
    )
}

/// The one forwarding route the dialect lowered `text` to, as the router
/// receives it.
fn with_route<T>(text: &str, check: impl FnOnce(&RouteEntry) -> T) -> T {
    let loaded = lower_to_loaded(&parse_simple_config(text).unwrap()).unwrap();
    let snapshot = build_snapshot(&loaded).unwrap();
    let listener = snapshot.listeners.values().next().unwrap();
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected an HTTP connection manager");
    };
    let route = hcm.route_table.virtual_hosts[0]
        .routes
        .iter()
        .find(|route| matches!(route.action, RouteActionIR::Forward(_)))
        .expect("a forwarding route");
    check(route)
}

/// The triggers every dialect route has: never `reset`, `5xx` or
/// `gateway-error`, each of which would resend a request the provider read
/// in full and then reset.
fn assert_no_reset_after_send(retry_on: &RetryOn, case: &str) {
    assert!(retry_on.connect_failure, "{case}");
    assert!(retry_on.refused_stream, "{case}");
    assert!(retry_on.reset_before_request, "{case}");
    assert!(
        !retry_on.reset && !retry_on.five_xx && !retry_on.gateway_error,
        "{case}: {retry_on:?}"
    );
}

#[test]
fn retry_fields_reach_the_routers_retry_policy() {
    let text = config(
        ", retries: { attempts: 2, per_try_timeout: 20s, on_status: [504, 529], \
         max_retry_after: 10s }",
    );
    with_route(&text, |route| {
        let RouteActionIR::Forward(forward) = &route.action else {
            unreachable!()
        };
        let policy = forward.retry_policy.as_ref().expect("retry policy");
        assert_eq!(policy.num_retries, 2);
        assert_eq!(policy.per_try_timeout, Some(Duration::from_secs(20)));
        assert!(policy.retry_on_per_try_timeout);
        assert!(policy.retry_on.retriable_status_codes);
        assert_eq!(policy.retriable_status_codes, vec![504, 529]);
        assert_eq!(
            policy.rate_limited_back_off,
            Some(Box::new(RateLimitedBackOff {
                reset_headers: vec![ResetHeader {
                    name: http::HeaderName::from_static("retry-after"),
                    format: ResetHeaderFormat::Seconds,
                }],
                max_interval: Duration::from_secs(10),
            }))
        );
        assert_no_reset_after_send(&policy.retry_on, "all fields");
    });
}

/// Absent fields keep today's policy: the four default statuses, no
/// per-attempt limit, `Retry-After` ignored.
#[test]
fn absent_retry_fields_keep_the_default_policy() {
    with_route(&config(""), |route| {
        let RouteActionIR::Forward(forward) = &route.action else {
            unreachable!()
        };
        let policy = forward.retry_policy.as_ref().expect("retry policy");
        assert_eq!(policy.retriable_status_codes, vec![429, 500, 502, 503]);
        assert_eq!(policy.per_try_timeout, None);
        assert!(!policy.retry_on_per_try_timeout);
        assert_eq!(policy.rate_limited_back_off, None);
        assert_no_reset_after_send(&policy.retry_on, "defaults");
    });
}

/// The shapes that change what is emitted: an empty `on_status` drops the
/// status trigger; a per-try timeout with no retry left still lowers (a fast
/// 504); a per-try timeout beside `streaming: strict` keeps both route
/// metadata namespaces.
#[test]
fn edge_shapes_of_the_retry_fields_lower_as_documented() {
    with_route(&config(", retries: { on_status: [] }"), |route| {
        let RouteActionIR::Forward(forward) = &route.action else {
            unreachable!()
        };
        let policy = forward.retry_policy.as_ref().expect("retry policy");
        assert!(!policy.retry_on.retriable_status_codes);
        assert!(policy.retriable_status_codes.is_empty());
        assert_no_reset_after_send(&policy.retry_on, "on_status: []");
    });
    with_route(
        &config(", retries: { attempts: 0, per_try_timeout: 5s }"),
        |route| {
            let RouteActionIR::Forward(forward) = &route.action else {
                unreachable!()
            };
            let policy = forward.retry_policy.as_ref().expect("retry policy");
            assert_eq!(policy.num_retries, 0);
            assert_eq!(policy.per_try_timeout, Some(Duration::from_secs(5)));
        },
    );
    with_route(
        &config(", fallbacks: [fb1], streaming: strict, retries: { per_try_timeout: 5s }"),
        |route| {
            let RouteActionIR::Forward(forward) = &route.action else {
                unreachable!()
            };
            let policy = forward.retry_policy.as_ref().expect("retry policy");
            assert!(route.streaming_strict);
            assert!(policy.retry_on_per_try_timeout);
            assert_eq!(policy.num_retries, 1);
        },
    );
}

#[test]
fn out_of_range_or_inert_retry_fields_name_their_dotted_path() {
    for (extra, path) in [
        (
            ", retries: { per_try_timeout: 0s }",
            "routes[0].retries.per_try_timeout",
        ),
        (
            ", retries: { per_try_timeout: 2h }",
            "routes[0].retries.per_try_timeout",
        ),
        (
            ", retries: { per_try_timeout: soon }",
            "routes[0].retries.per_try_timeout",
        ),
        (
            ", retries: { on_status: [399] }",
            "routes[0].retries.on_status[0]",
        ),
        (
            ", retries: { on_status: [500, 600] }",
            "routes[0].retries.on_status[1]",
        ),
        (
            ", retries: { on_status: [503, 503] }",
            "routes[0].retries.on_status[1]",
        ),
        (
            ", retries: { on_status: [70000] }",
            "routes[0].retries.on_status[0]",
        ),
        (
            ", retries: { on_status: [400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, \
             411, 412, 413, 414, 415, 416] }",
            "routes[0].retries.on_status",
        ),
        (
            ", retries: { attempts: 0, on_status: [503] }",
            "routes[0].retries.on_status",
        ),
        (
            ", retries: { max_retry_after: 0s }",
            "routes[0].retries.max_retry_after",
        ),
        (
            ", retries: { max_retry_after: 61s }",
            "routes[0].retries.max_retry_after",
        ),
        (
            ", retries: { attempts: 0, max_retry_after: 5s }",
            "routes[0].retries.max_retry_after",
        ),
        (
            ", fallbacks: [fb1], retries: { max_retry_after: 5s }",
            "routes[0].retries.max_retry_after",
        ),
        (
            ", retries: { on_reset: true }",
            "routes[0].retries.on_reset",
        ),
    ] {
        let err = parse_simple_config(&config(extra)).expect_err(extra);
        let field_path = match &err {
            ConfigError::InvalidValue { field_path, .. }
            | ConfigError::UnknownField { field_path, .. } => field_path.clone(),
            other => panic!("{extra}: unexpected error {other:?}"),
        };
        assert_eq!(field_path, path, "{extra}: {err}");
    }
}
