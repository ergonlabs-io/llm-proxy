//! WP-05 acceptance tests: proto -> IR conversion.
//!
//! Covers: the Phase-1 example config, S1 domain-precedence pre-computation,
//! route defaults (15s timeout, case-sensitive), weighted-cluster cumulative
//! arrays, retry policy parsing, and — critically — that every proto field
//! outside the supported surface errors with its full path (ground rule #2).

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

fn route_table(snapshot: &ConfigSnapshot) -> &RouteTable {
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    &hcm.route_table
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

/// Ground rule #2: a SET proto field outside the supported surface errors
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
    assert_eq!(cluster.discovery, DiscoveryType::LogicalDns);
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
