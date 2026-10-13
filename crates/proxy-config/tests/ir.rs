//! Acceptance tests: proto -> IR conversion.
//!
//! Covers: the Phase-1 example config, S1 domain-precedence pre-computation,
//! route defaults (15s timeout, case-sensitive), weighted-cluster cumulative
//! arrays, retry policy parsing, and — critically — that every proto field
//! outside the supported surface errors with its full path (AGENTS.md invariant 1).

use std::time::Duration;

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

fn snapshot_from(yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

fn hcm_snapshot(route_config: &str) -> ConfigSnapshot {
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
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
{route_config}
"#
    );
    snapshot_from(&yaml).expect("config must lower to IR")
}

/// Like [`hcm_snapshot`], but for configs that are expected to be REJECTED —
/// returns the error instead of panicking, so a test can assert on its field
/// path and reason.
fn hcm_snapshot_err(route_config: &str) -> ConfigError {
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
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
{route_config}
"#
    );
    snapshot_from(&yaml).expect_err("config must be rejected")
}

/// Like [`hcm_snapshot`], but with a caller-supplied `http_filters` block
/// (indented to match) instead of the fixed router-only chain.
fn hcm_snapshot_with_filters(http_filters: &str, route_config: &str) -> ConfigSnapshot {
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
{http_filters}
                route_config:
{route_config}
"#
    );
    snapshot_from(&yaml).expect("config must lower to IR")
}

fn route_table(snapshot: &ConfigSnapshot) -> &RouteTable {
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    &hcm.route_table
}

#[test]
fn hcm_rds_over_ads_lowers_to_a_named_route_dependency() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 127.0.0.1, port_value: 8080 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                rds:
                  route_config_name: ingress-routes
                  config_source:
                    ads: {}
                    resource_api_version: V3
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
"#;
    let snapshot = snapshot_from(yaml).expect("ADS-backed RDS must lower");
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    assert_eq!(hcm.rds_route_config_name.as_deref(), Some("ingress-routes"));
}

/// The Phase-1 example config lowers end to end.
#[test]
fn example_tcp_proxy_config_lowers() {
    let yaml = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/tcp-proxy.yaml"
    ))
    .expect("read example");
    let snapshot = snapshot_from(&yaml).expect("example must lower");

    assert_eq!(snapshot.admin, Some("127.0.0.1:9901".parse().unwrap()));

    let listener = snapshot.listeners.get("ingress_tcp").expect("listener");
    assert_eq!(listener.address, "0.0.0.0:10000".parse().unwrap());
    assert_eq!(listener.per_connection_buffer_limit_bytes, 1024 * 1024); // default 1 MiB
    let NetworkFilterSpec::TcpProxy(tp) = &listener.filter_chains[0].filters[0] else {
        panic!("expected tcp_proxy filter");
    };
    assert_eq!(tp.stat_prefix, "ingress_tcp");
    assert_eq!(tp.cluster, "backend");
    assert_eq!(tp.idle_timeout, Some(Duration::from_secs(3600))); // Envoy default 1h

    let cluster = snapshot.clusters.get("backend").expect("cluster");
    assert_eq!(cluster.discovery, DiscoveryType::Static);
    assert_eq!(cluster.lb_policy, LbPolicy::RoundRobin);
    assert_eq!(cluster.connect_timeout, Duration::from_secs(5));
    assert_eq!(cluster.endpoints.len(), 2);
    assert_eq!(cluster.endpoints[0].host, "127.0.0.1");
    assert_eq!(cluster.endpoints[0].port, 8081);
    assert_eq!(cluster.endpoints[0].weight, 1); // default
    assert_eq!(cluster.endpoints[0].priority, 0);
}

/// S1: exact > longest suffix wildcard > longest prefix wildcard > `*`,
/// case-insensitively — the precedence is pre-computed at build time.
#[test]
fn s1_domain_precedence() {
    let snapshot = hcm_snapshot(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: exact
                      domains: ["api.example.com"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
                    - name: suffix-long
                      domains: ["*.api.example.com"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
                    - name: suffix-short
                      domains: ["*.example.com"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
                    - name: prefix
                      domains: ["example.*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
                    - name: catch-all
                      domains: ["*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#,
    );
    let table = route_table(&snapshot);
    let find = |host: &str| table.find_virtual_host(host).expect("vhost").name.clone();

    assert_eq!(find("api.example.com"), "exact");
    assert_eq!(find("API.EXAMPLE.COM"), "exact"); // case-insensitive
    assert_eq!(find("v1.api.example.com"), "suffix-long"); // longest suffix wins
    assert_eq!(find("foo.example.com"), "suffix-short");
    assert_eq!(find("example.org"), "prefix");
    assert_eq!(find("unrelated.io"), "catch-all");
}

/// Duplicate domains across virtual hosts are a config error, as in Envoy.
#[test]
fn duplicate_domain_is_rejected() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: hcm
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
                    - name: a
                      domains: ["example.com"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
                    - name: b
                      domains: ["EXAMPLE.com"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#;
    let err = snapshot_from(yaml).expect_err("duplicate domain must fail");
    assert!(err.to_string().contains("duplicate domain"), "got: {err}");
}

/// S4 route timeout semantics: absent -> 15s default; explicit 0s -> disabled.
#[test]
fn route_timeout_defaults() {
    let snapshot = hcm_snapshot(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - { match: { prefix: "/default" }, route: { cluster: c } }
                        - { match: { prefix: "/disabled" }, route: { cluster: c, timeout: 0s } }
                        - { match: { prefix: "/custom" }, route: { cluster: c, timeout: 120s } }
"#,
    );
    let table = route_table(&snapshot);
    let routes = &table.virtual_hosts[0].routes;
    let forward = |i: usize| match &routes[i].action {
        RouteActionIR::Forward(f) => f,
        other => panic!("expected forward action, got {other:?}"),
    };
    assert_eq!(forward(0).timeout, Some(Duration::from_secs(15)));
    assert_eq!(forward(1).timeout, None);
    assert_eq!(forward(2).timeout, Some(Duration::from_secs(120)));
    // S1: path matching is case-sensitive unless configured otherwise.
    assert!(routes[0].matcher.case_sensitive);
}

/// Weighted clusters pre-compute the cumulative array; picks are O(log n).
#[test]
fn weighted_clusters_cumulative_array() {
    let snapshot = hcm_snapshot(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            weighted_clusters:
                              clusters:
                                - { name: a, weight: 20 }
                                - { name: b, weight: 30 }
                                - { name: c, weight: 50 }
"#,
    );
    let table = route_table(&snapshot);
    let RouteActionIR::Forward(f) = &table.virtual_hosts[0].routes[0].action else {
        panic!("expected forward");
    };
    let ForwardTarget::Weighted(w) = &f.target else {
        panic!("expected weighted");
    };
    assert_eq!(w.total_weight, 100);
    assert_eq!(
        w.cumulative,
        vec![("a".into(), 20), ("b".into(), 50), ("c".into(), 100)]
    );
    assert_eq!(w.pick(0), "a");
    assert_eq!(w.pick(19), "a");
    assert_eq!(w.pick(20), "b");
    assert_eq!(w.pick(99), "c");
}

/// S3: `num_retries` defaults to 1; `retry_on` tokens parse; unknown tokens
/// are ignored (Envoy parity).
#[test]
fn retry_policy_defaults_and_parsing() {
    let snapshot = hcm_snapshot(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            cluster: c
                            retry_policy:
                              retry_on: "connect-failure,5xx,made-up-token"
                              retriable_status_codes: [429, 503]
"#,
    );
    let table = route_table(&snapshot);
    let RouteActionIR::Forward(f) = &table.virtual_hosts[0].routes[0].action else {
        panic!("expected forward");
    };
    let rp = f.retry_policy.as_ref().expect("retry policy");
    assert_eq!(rp.num_retries, 1); // Envoy default
    assert!(rp.retry_on.connect_failure);
    assert!(rp.retry_on.five_xx);
    assert!(!rp.retry_on.reset);
    assert_eq!(rp.retriable_status_codes, vec![429, 503]);
    // Absent `retry_back_off` / `host_selection_retry_max_attempts` fall
    // back to Envoy's defaults (S3.3 / S3.1).
    assert_eq!(rp.retry_back_off, RetryBackOff::ENVOY_DEFAULT);
    assert_eq!(rp.host_selection_retry_max_attempts, 1);
}

/// Hedging is opt-in and deliberately narrow: it only uses the existing
/// per-try timeout/retry budget rather than accepting an independent retry
/// mechanism that the router could not account for.
#[test]
fn hedge_on_per_try_timeout_lowers_into_the_retry_policy() {
    let snapshot = hcm_snapshot(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            cluster: c
                            retry_policy:
                              retry_on: "5xx"
                              num_retries: 1
                              per_try_timeout: 0.050s
                            hedge_policy:
                              hedge_on_per_try_timeout: true
"#,
    );
    let table = route_table(&snapshot);
    let RouteActionIR::Forward(f) = &table.virtual_hosts[0].routes[0].action else {
        panic!("expected forward");
    };
    let policy = f.retry_policy.as_ref().expect("retry policy");
    assert!(policy.hedge_on_per_try_timeout);
    assert_eq!(policy.per_try_timeout, Some(Duration::from_millis(50)));
}

#[test]
fn hedge_on_per_try_timeout_requires_a_retriable_per_try_policy() {
    let err = hcm_snapshot_err(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            cluster: c
                            hedge_policy:
                              hedge_on_per_try_timeout: true
"#,
    );
    let message = err.to_string();
    assert!(message.contains("hedge_policy.hedge_on_per_try_timeout"));
    assert!(message.contains("retry_policy"));
}

#[test]
fn unsupported_multi_initial_request_hedging_is_rejected() {
    let err = hcm_snapshot_err(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            cluster: c
                            retry_policy:
                              retry_on: "5xx"
                              per_try_timeout: 0.050s
                            hedge_policy:
                              initial_requests: 2
                              hedge_on_per_try_timeout: true
"#,
    );
    let message = err.to_string();
    assert!(message.contains("hedge_policy.initial_requests"));
    assert!(message.contains("default of 1"));
}

/// S3.3: an explicit `retry_back_off` with only `base_interval` set derives
/// `max_interval` as 10x the base.
#[test]
fn retry_back_off_explicit_base_derives_default_max() {
    let snapshot = hcm_snapshot(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            cluster: c
                            retry_policy:
                              retry_on: "5xx"
                              retry_back_off:
                                base_interval: 0.100s
"#,
    );
    let table = route_table(&snapshot);
    let RouteActionIR::Forward(f) = &table.virtual_hosts[0].routes[0].action else {
        panic!("expected forward");
    };
    let rp = f.retry_policy.as_ref().expect("retry policy");
    assert_eq!(rp.retry_back_off.base_interval, Duration::from_millis(100));
    assert_eq!(rp.retry_back_off.max_interval, Duration::from_millis(1000));
}

/// AGENTS.md invariant 1, guarding a gap that actually bit us: route-level
/// `request_headers_to_add` IS lowered (and applied by the
/// router), but Envoy also allows the same field on `VirtualHost` and
/// `RouteConfiguration`, where we model nothing. Those levels must be
/// REJECTED with their field path rather than parsed and dropped — the
/// route-level version spent months lowering into an IR field no runtime code
/// read, which is exactly the failure mode this asserts against.
#[test]
fn virtual_host_level_request_headers_to_add_is_rejected() {
    let err = hcm_snapshot_err(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      request_headers_to_add:
                        - header: { key: x-from-vhost, value: "1" }
                      routes:
                        - match: { prefix: "/" }
                          route: { cluster: c }
"#,
    );
    let msg = err.to_string();
    assert!(
        msg.contains("request_headers_to_add"),
        "error must name the unsupported field, got: {msg}"
    );
}

/// Envoy's built-in `previous_hosts` predicate is lowered
/// with the exact host-selection reattempt count.  The runtime owns the
/// history; config only carries this explicit policy through to it.
#[test]
fn previous_hosts_predicate_and_selection_attempts_are_lowered() {
    let snapshot = hcm_snapshot(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            cluster: c
                            retry_policy:
                              retry_on: "5xx"
                              host_selection_retry_max_attempts: 5
                              retry_host_predicate:
                                - name: envoy.retry_host_predicates.previous_hosts
                                  typed_config:
                                    "@type": type.googleapis.com/envoy.extensions.retry.host.previous_hosts.v3.PreviousHostsPredicate
"#,
    );
    let table = route_table(&snapshot);
    let RouteActionIR::Forward(f) = &table.virtual_hosts[0].routes[0].action else {
        panic!("expected forward");
    };
    let rp = f.retry_policy.as_ref().expect("retry policy");
    assert!(rp.avoid_previous_hosts);
    assert_eq!(rp.host_selection_retry_max_attempts, 5);
}

/// A high reattempt count without a predicate still does nothing, so it stays
/// a strict config error instead of becoming a silently accepted knob.
#[test]
fn host_selection_retry_max_attempts_above_one_without_predicate_is_rejected() {
    let err = hcm_snapshot_err(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            cluster: c
                            retry_policy:
                              retry_on: "5xx"
                              host_selection_retry_max_attempts: 5
"#,
    );
    assert!(err.to_string().contains("previous_hosts"));
}

/// AGENTS.md invariant 1: `envoy-ratelimited` fires on the `x-envoy-ratelimited`
/// response header, which no filter sets yet — so accepting the token would
/// silently never retry anything.
#[test]
fn retry_on_envoy_ratelimited_is_rejected() {
    let err = hcm_snapshot_err(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            cluster: c
                            retry_policy:
                              retry_on: "5xx,envoy-ratelimited"
"#,
    );
    let msg = err.to_string();
    assert!(
        msg.contains("retry_on"),
        "error must name the field path, got: {msg}"
    );
    assert!(
        msg.contains("envoy-ratelimited"),
        "error must name the offending token, got: {msg}"
    );
}

/// S3.3: both `base_interval` and `max_interval` set are lowered verbatim.
#[test]
fn retry_back_off_explicit_base_and_max() {
    let snapshot = hcm_snapshot(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            cluster: c
                            retry_policy:
                              retry_on: "5xx"
                              retry_back_off:
                                base_interval: 0.050s
                                max_interval: 0.500s
"#,
    );
    let table = route_table(&snapshot);
    let RouteActionIR::Forward(f) = &table.virtual_hosts[0].routes[0].action else {
        panic!("expected forward");
    };
    let rp = f.retry_policy.as_ref().expect("retry policy");
    assert_eq!(rp.retry_back_off.base_interval, Duration::from_millis(50));
    assert_eq!(rp.retry_back_off.max_interval, Duration::from_millis(500));
}

/// AGENTS.md invariant 1: an unsupported `retry_policy` sub-field (e.g.
/// `retry_priority`) must error with its full dotted path, not be silently
/// dropped.
#[test]
fn retry_policy_unsupported_subfield_errors_with_path() {
    let yaml = r#"
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
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            cluster: c
                            retry_policy:
                              retry_on: "5xx"
                              host_selection_retry_max_attempts: 2
                              retry_priority:
                                name: envoy.retry_priorities.previous_priorities
"#;
    let err = snapshot_from(yaml).expect_err("unsupported retry_policy field must error");
    let ConfigError::UnsupportedField { field_path, .. } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert!(
        field_path.ends_with("retry_policy.retry_priority"),
        "path was: {field_path}"
    );
}

/// Regex route matches compile at build time and are full-string (safe_regex).
#[test]
fn regex_route_match_compiles_anchored() {
    let snapshot = hcm_snapshot(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { safe_regex: { regex: "/v[0-9]+/chat" } }
                          route: { cluster: c }
"#,
    );
    let table = route_table(&snapshot);
    let matcher = &table.virtual_hosts[0].routes[0].matcher;
    assert!(matcher.path.matches("/v1/chat", true));
    assert!(!matcher.path.matches("/v1/chat/extra", true)); // anchored
    assert!(!matcher.path.matches("prefix/v1/chat", true));
}

/// AGENTS.md invariant 1: a SET proto field outside the supported surface errors
/// with its full dotted path — never silently dropped.
#[test]
fn unsupported_field_errors_with_path() {
    let yaml = r#"
static_resources:
  listeners:
    - name: l1
      transparent: true
      address:
        socket_address: { address: 0.0.0.0, port_value: 10000 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: t
                cluster: c
"#;
    let err = snapshot_from(yaml).expect_err("unsupported field must fail");
    let ConfigError::UnsupportedField { field_path, .. } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert_eq!(field_path, "static_resources.listeners[0].transparent");
}

/// We deliberately ship without RING_HASH/MAGLEV (they need bit-exact
/// parity with Envoy's hashing, or session affinity breaks across a mixed
/// fleet). That has to fail at *config* time: `proxy-cluster` also refuses to
/// build such a cluster, but that happens after startup and merely leaves the
/// cluster absent — every request to it would get a bare 503 with nothing
/// explaining why. Failing here is what makes `make validate` and startup
/// report the real reason.
#[test]
fn unimplemented_lb_policy_errors_at_config_time() {
    for policy in ["RING_HASH", "MAGLEV"] {
        let yaml = format!(
            r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      lb_policy: {policy}
      load_assignment:
        cluster_name: c1
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: 8080 }}
"#
        );
        let err = snapshot_from(&yaml).expect_err("{policy} must be rejected at config time");
        let ConfigError::UnsupportedField { field_path, reason } = &err else {
            panic!("expected UnsupportedField for {policy}, got: {err}");
        };
        assert_eq!(field_path, "static_resources.clusters[0].lb_policy");
        // The message must name the policy — an operator reading only the
        // error should know which setting to change.
        assert!(
            reason.contains(policy),
            "error for {policy} must name the policy, got: {reason}"
        );
    }
}

/// The surface check reaches inside `typed_config` Anys too.
#[test]
fn unsupported_field_inside_any_errors_with_path() {
    let yaml = r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: { address: 0.0.0.0, port_value: 10000 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: t
                cluster: c
                downstream_idle_timeout: 5s
"#;
    let err = snapshot_from(yaml).expect_err("unsupported field must fail");
    let ConfigError::UnsupportedField { field_path, .. } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filters[0].typed_config.downstream_idle_timeout"
    );
}

/// STATIC clusters require IP endpoints; the error suggests the DNS types.
#[test]
fn static_cluster_rejects_hostname_endpoints() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      load_assignment:
        cluster_name: c1
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: api.openai.com, port_value: 443 }
"#;
    let err = snapshot_from(yaml).expect_err("hostname in STATIC cluster must fail");
    assert!(err.to_string().contains("STRICT_DNS"), "got: {err}");
}

/// LOGICAL_DNS clusters accept hostname endpoints and upstream TLS with SNI.
#[test]
fn logical_dns_cluster_with_upstream_tls() {
    let yaml = r#"
static_resources:
  clusters:
    - name: openai
      type: LOGICAL_DNS
      load_assignment:
        cluster_name: openai
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: api.openai.com, port_value: 443 }
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: api.openai.com
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("openai").expect("cluster");
    assert_eq!(
        cluster.discovery,
        DiscoveryType::LogicalDns(DnsRefresh::ENVOY_DEFAULT)
    );
    assert_eq!(cluster.endpoints[0].host, "api.openai.com");
    let tls = cluster.transport_socket.as_ref().expect("tls");
    assert_eq!(tls.sni.as_deref(), Some("api.openai.com"));
    // No validation_context configured: Envoy parity means no server-cert
    // verification at all (not even system roots).
    assert!(tls.validation.is_none());
    assert!(tls.client_certificate.is_none());
    assert_eq!(tls.params.min_version, TlsVersion::V1_2);
    assert_eq!(tls.params.max_version, TlsVersion::V1_2); // upstream TLS_AUTO default
}

/// Redirect and direct-response actions lower with Envoy defaults (301).
#[test]
fn redirect_and_direct_response_actions() {
    let snapshot = hcm_snapshot(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/old" }
                          redirect: { host_redirect: new.example.com }
                        - match: { prefix: "/teapot" }
                          direct_response: { status: 418, body: { inline_string: "short and stout" } }
"#,
    );
    let table = route_table(&snapshot);
    let routes = &table.virtual_hosts[0].routes;
    let RouteActionIR::Redirect(r) = &routes[0].action else {
        panic!("expected redirect");
    };
    assert_eq!(r.host_redirect.as_deref(), Some("new.example.com"));
    assert_eq!(r.response_code, 301); // Envoy default
    let RouteActionIR::DirectResponse { status, body } = &routes[1].action else {
        panic!("expected direct response");
    };
    assert_eq!(*status, 418);
    assert_eq!(body, &Some(DataSourceIR::Inline("short and stout".into())));
}

/// The router must be the last (terminal) HTTP filter.
#[test]
fn hcm_requires_terminal_router() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: hcm
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters: []
                route_config:
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#;
    let err = snapshot_from(yaml).expect_err("missing router must fail");
    assert!(err.to_string().contains("router"), "got: {err}");
}

/// The router must be last, not merely present.
#[test]
fn hcm_router_not_last_is_rejected() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: hcm
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                  - name: envoy.filters.listener.tls_inspector
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
                route_config:
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#;
    let err = snapshot_from(yaml).expect_err("router not last must fail");
    assert!(err.to_string().contains("last"), "got: {err}");
}

/// Exactly one router is allowed, even if it's last.
#[test]
fn hcm_duplicate_router_is_rejected() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: hcm
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#;
    let err = snapshot_from(yaml).expect_err("duplicate router must fail");
    assert!(err.to_string().contains("once"), "got: {err}");
}

/// S9: `generate_request_id` is unset by default and lowers to Envoy's
/// default (`true`); the field must also be accepted by the surface check
/// rather than rejected as an unsupported HCM field (AGENTS.md invariant 1: the
/// allowlist and the IR must agree).
#[test]
fn hcm_generate_request_id_defaults_to_true() {
    let snapshot = hcm_snapshot(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#,
    );
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    assert!(hcm.generate_request_id);
}

/// An explicit `generate_request_id: true` lowers to `true` and is accepted
/// by the surface check.
#[test]
fn hcm_generate_request_id_explicit_true() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: hcm
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                generate_request_id: true
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#;
    let snapshot = snapshot_from(yaml).expect("generate_request_id: true must lower");
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    assert!(hcm.generate_request_id);
}

/// An explicit `generate_request_id: false` lowers to `false` (and is not
/// silently ignored, per AGENTS.md invariant 1).
#[test]
fn hcm_generate_request_id_explicit_false() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: hcm
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                generate_request_id: false
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#;
    let snapshot = snapshot_from(yaml).expect("generate_request_id: false must lower");
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    assert!(!hcm.generate_request_id);
}

/// S9: `use_remote_address` and `xff_num_trusted_hops` lower to the values
/// set on the HCM (not silently dropped, per AGENTS.md invariant 1).
#[test]
fn hcm_use_remote_address_and_trusted_hops_explicit() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: hcm
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                use_remote_address: true
                xff_num_trusted_hops: 2
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#;
    let snapshot = snapshot_from(yaml).expect("use_remote_address/xff_num_trusted_hops must lower");
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    assert!(hcm.use_remote_address);
    assert_eq!(hcm.xff_num_trusted_hops, 2);
}

/// S9: `use_remote_address` and `xff_num_trusted_hops` default to Envoy's
/// defaults (`false` / `0`) when omitted.
#[test]
fn hcm_use_remote_address_and_trusted_hops_default() {
    let snapshot = hcm_snapshot(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#,
    );
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    assert!(!hcm.use_remote_address);
    assert_eq!(hcm.xff_num_trusted_hops, 0);
}

/// `codec_type` is unset by default and lowers to Envoy's default
/// (`AUTO`, proto zero-value) -- must also be accepted by the surface check
/// rather than rejected as an unsupported HCM field (AGENTS.md invariant 1: the
/// allowlist and the IR must agree).
#[test]
fn hcm_codec_type_defaults_to_auto() {
    let snapshot = hcm_snapshot(
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#,
    );
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    assert_eq!(hcm.codec_type, CodecType::Auto);
}

/// `codec_type: HTTP1`/`codec_type: HTTP2` both round-trip through
/// the real loader into the matching IR variant (not silently dropped, per
/// AGENTS.md invariant 1).
#[test]
fn hcm_codec_type_explicit_http1_and_http2_lower() {
    for (proto_value, expected) in [("HTTP1", CodecType::Http1), ("HTTP2", CodecType::Http2)] {
        let yaml = format!(
            r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: {{ address: 0.0.0.0, port_value: 8080 }}
      filter_chains:
        - filters:
            - name: hcm
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                codec_type: {proto_value}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{{ match: {{ prefix: "/" }}, route: {{ cluster: c }} }}]
"#
        );
        let snapshot = snapshot_from(&yaml)
            .unwrap_or_else(|e| panic!("codec_type: {proto_value} must lower: {e}"));
        let listener = snapshot.listeners.get("http").expect("listener");
        let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
        else {
            panic!("expected HCM filter");
        };
        assert_eq!(
            hcm.codec_type, expected,
            "codec_type: {proto_value} should lower to {expected:?}"
        );
    }
}

/// `codec_type: HTTP3` has no IR variant (no QUIC/UDP listener in
/// this proxy -- see `CodecType`'s doc) and must be rejected with its full
/// dotted path, not silently accepted and treated as `AUTO` (AGENTS.md invariant 1
/// applies to values with no implementation, not just unrecognized fields).
#[test]
fn hcm_codec_type_http3_is_rejected_with_path() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: hcm
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                codec_type: HTTP3
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#;
    let err = snapshot_from(yaml).expect_err("codec_type: HTTP3 must be rejected");
    let ConfigError::UnsupportedField { field_path, .. } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert!(
        field_path.ends_with(".codec_type"),
        "expected the dotted path to name codec_type, got: {field_path}"
    );
}

/// A two-filter chain preserves config order and decodes each non-router
/// filter's own `typed_config` (here `tls_inspector`, reused purely as a
/// stand-in for "some non-router HTTP filter with real config" -- lowering
/// doesn't care what an HTTP filter's proto shape means, only that it
/// resolves against the descriptor pool).
#[test]
fn hcm_two_filter_chain_preserves_order_and_decodes_config() {
    let snapshot = hcm_snapshot_with_filters(
        r#"
                  - name: my.filters.stand_in
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
                      max_client_hello_size: 2048
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
"#,
        r#"
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#,
    );
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    assert_eq!(hcm.http_filters.len(), 2);

    let first = &hcm.http_filters[0];
    assert_eq!(first.name, "my.filters.stand_in");
    assert!(!first.is_router);
    assert_eq!(
        first.type_url,
        "type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector"
    );
    let config = first
        .config
        .as_ref()
        .expect("non-router filter must carry decoded config");
    assert!(
        config.has_field_by_name("max_client_hello_size"),
        "expected the decoded config to carry the configured field"
    );

    let second = &hcm.http_filters[1];
    assert_eq!(second.name, "envoy.filters.http.router");
    assert!(second.is_router);
    assert!(second.config.is_none());
}

/// An HTTP filter `typed_config` whose type URL isn't in the descriptor pool
/// is a config error naming both the type URL and the dotted path -- never a
/// silent skip, even though the IR can now hold arbitrary filter config.
#[test]
fn hcm_unknown_http_filter_type_url_is_rejected() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: hcm
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters:
                  - name: mystery
                    typed_config:
                      "@type": type.googleapis.com/does.not.Exist
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#;
    let err = snapshot_from(yaml).expect_err("unknown type_url must fail");
    let msg = err.to_string();
    assert!(msg.contains("does.not.Exist"), "got: {msg}");
    assert!(msg.contains("http_filters[0].typed_config"), "got: {msg}");
}
