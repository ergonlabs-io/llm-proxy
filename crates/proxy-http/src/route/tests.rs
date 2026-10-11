//! Acceptance tests for the route matching engine.
//!
//! Fixtures build real `RouteTable`s through `proxy_config`'s YAML lowering
//! pipeline (the same helper shape as `proxy-config/tests/ir.rs`) rather than
//! constructing `PathMatch`/`HeaderMatchKind` variants by hand: those hold
//! compiled `regex::Regex` values, and `regex` is not a direct dependency of
//! this crate (only of `proxy-config`, which compiles patterns at lowering
//! time) — going through the real config loader keeps this module fully
//! decoupled from the `regex` crate, as intended.

use http::HeaderMap;
use proxy_config::ir::{
    ConfigSnapshot, ForwardTarget, NetworkFilterSpec, RouteActionIR, RouteTable,
};
use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};

use super::*;

fn snapshot_from(route_config: &str) -> ConfigSnapshot {
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
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
        .expect("bootstrap must parse");
    build_snapshot(&loaded).expect("config must lower to IR")
}

/// Owns the snapshot so tests can borrow a `&RouteTable` with a named
/// lifetime, matching the shape callers actually have (an `Arc<ConfigSnapshot>`
/// held alive for the whole request).
struct Fixture {
    snapshot: ConfigSnapshot,
}

impl Fixture {
    fn new(route_config: &str) -> Self {
        Self {
            snapshot: snapshot_from(route_config),
        }
    }

    fn table(&self) -> &RouteTable {
        let listener = self.snapshot.listeners.get("http").expect("listener");
        let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
        else {
            panic!("expected HCM filter");
        };
        &hcm.route_table
    }
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.append(
            http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            http::HeaderValue::from_str(v).unwrap(),
        );
    }
    map
}

fn req<'a>(authority: &'a str, path: &'a str, headers: &'a HeaderMap) -> RouteRequest<'a> {
    RouteRequest {
        authority,
        path,
        headers,
    }
}

// -------------------------------------------------------------- S1.1 vhost --

#[test]
fn vhost_exact_domain_match() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["api.foo.com"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#,
    );
    let hdrs = headers(&[]);
    let r = req("api.foo.com", "/x", &hdrs);
    assert!(matches!(
        match_route(fx.table(), &r),
        RouteMatch::Found { vhost, .. } if vhost.name == "v1"
    ));
}

#[test]
fn vhost_port_is_stripped_before_lookup() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["api.foo.com"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#,
    );
    let hdrs = headers(&[]);
    let r = req("api.foo.com:8443", "/x", &hdrs);
    assert!(matches!(
        match_route(fx.table(), &r),
        RouteMatch::Found { vhost, .. } if vhost.name == "v1"
    ));
}

#[test]
fn vhost_ipv6_literal_port_is_stripped() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["[::1]"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#,
    );
    let hdrs = headers(&[]);
    let r = req("[::1]:8080", "/x", &hdrs);
    assert!(matches!(
        match_route(fx.table(), &r),
        RouteMatch::Found { vhost, .. } if vhost.name == "v1"
    ));
}

#[test]
fn vhost_no_match_is_no_virtual_host() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["api.foo.com"]
                      routes: [{ match: { prefix: "/" }, route: { cluster: c } }]
"#,
    );
    let hdrs = headers(&[]);
    let r = req("unrelated.example", "/x", &hdrs);
    assert!(matches!(
        match_route(fx.table(), &r),
        RouteMatch::NoVirtualHost
    ));
}

#[test]
fn vhost_matches_but_no_route_matches() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["api.foo.com"]
                      routes: [{ match: { prefix: "/only" }, route: { cluster: c } }]
"#,
    );
    let hdrs = headers(&[]);
    let r = req("api.foo.com", "/nope", &hdrs);
    assert!(matches!(
        match_route(fx.table(), &r),
        RouteMatch::NoRoute { vhost } if vhost.name == "v1"
    ));
}

// -------------------------------------------------------------- S1.2 first-match-wins --

#[test]
fn first_match_wins_even_when_second_route_is_more_specific() {
    // The second route (`/foo/bar`, exact) is objectively "more specific"
    // than the first (`/`, prefix) but MUST NOT be selected: S1.2 forbids
    // any specificity re-ordering.
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { prefix: "/" }, route: { cluster: general } }
                        - { match: { path: "/foo/bar" }, route: { cluster: specific } }
"#,
    );
    let hdrs = headers(&[]);
    let r = req("any.host", "/foo/bar", &hdrs);
    let RouteMatch::Found { route, .. } = match_route(fx.table(), &r) else {
        panic!("expected a route match");
    };
    let RouteActionIR::Forward(fwd) = &route.action else {
        panic!("expected forward action");
    };
    let ForwardTarget::Cluster(name) = &fwd.target else {
        panic!("expected cluster target");
    };
    assert_eq!(name, "general");
}

#[test]
fn matching_route_with_dangling_cluster_still_wins() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { prefix: "/" }, route: { cluster: does-not-exist } }
"#,
    );
    let hdrs = headers(&[]);
    let r = req("any.host", "/anything", &hdrs);
    let RouteMatch::Found { route, .. } = match_route(fx.table(), &r) else {
        panic!("expected a route match even with a dangling cluster");
    };
    let RouteActionIR::Forward(fwd) = &route.action else {
        panic!("expected forward action");
    };
    let ForwardTarget::Cluster(name) = &fwd.target else {
        panic!("expected cluster target");
    };
    assert_eq!(name, "does-not-exist");
}

// -------------------------------------------------------------- S1.3 path --

#[test]
fn prefix_matches_including_query_string() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { prefix: "/search?q=" }, route: { cluster: c } }
"#,
    );
    let hdrs = headers(&[]);
    // The literal `?q=` is part of the prefix, so it must be matched against
    // the path WITH the query string still attached.
    let r = req("h", "/search?q=hello", &hdrs);
    assert!(matches!(
        match_route(fx.table(), &r),
        RouteMatch::Found { .. }
    ));

    let r2 = req("h", "/search", &hdrs);
    assert!(matches!(
        match_route(fx.table(), &r2),
        RouteMatch::NoRoute { .. }
    ));
}

#[test]
fn exact_match_strips_query_string() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { path: "/exact" }, route: { cluster: c } }
"#,
    );
    let hdrs = headers(&[]);
    let r = req("h", "/exact?foo=bar", &hdrs);
    assert!(matches!(
        match_route(fx.table(), &r),
        RouteMatch::Found { .. }
    ));

    // Query must not be part of the exact comparison.
    let r2 = req("h", "/exact?", &hdrs);
    assert!(matches!(
        match_route(fx.table(), &r2),
        RouteMatch::Found { .. }
    ));

    let r3 = req("h", "/exactly", &hdrs);
    assert!(matches!(
        match_route(fx.table(), &r3),
        RouteMatch::NoRoute { .. }
    ));
}

#[test]
fn regex_is_a_full_path_anchor_not_a_substring_search() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { safe_regex: { regex: "/foo" } }, route: { cluster: c } }
"#,
    );
    let hdrs = headers(&[]);
    assert!(matches!(
        match_route(fx.table(), &req("h", "/foo", &hdrs)),
        RouteMatch::Found { .. }
    ));
    // Must NOT match as a substring.
    assert!(matches!(
        match_route(fx.table(), &req("h", "/xx/foobar", &hdrs)),
        RouteMatch::NoRoute { .. }
    ));
    assert!(matches!(
        match_route(fx.table(), &req("h", "/foo/bar", &hdrs)),
        RouteMatch::NoRoute { .. }
    ));
}

#[test]
fn regex_full_path_ignores_query() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { safe_regex: { regex: "/foo" } }, route: { cluster: c } }
"#,
    );
    let hdrs = headers(&[]);
    assert!(matches!(
        match_route(fx.table(), &req("h", "/foo?x=1", &hdrs)),
        RouteMatch::Found { .. }
    ));
}

#[test]
fn prefix_case_insensitive_when_configured() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { prefix: "/Api", case_sensitive: false }, route: { cluster: c } }
"#,
    );
    let hdrs = headers(&[]);
    assert!(matches!(
        match_route(fx.table(), &req("h", "/api/x", &hdrs)),
        RouteMatch::Found { .. }
    ));
}

#[test]
fn exact_case_insensitive_when_configured() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { path: "/Api", case_sensitive: false }, route: { cluster: c } }
"#,
    );
    let hdrs = headers(&[]);
    assert!(matches!(
        match_route(fx.table(), &req("h", "/api", &hdrs)),
        RouteMatch::Found { .. }
    ));
}

#[test]
fn case_sensitive_default_true_rejects_mismatched_case() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { path: "/Api" }, route: { cluster: c } }
"#,
    );
    let hdrs = headers(&[]);
    assert!(matches!(
        match_route(fx.table(), &req("h", "/api", &hdrs)),
        RouteMatch::NoRoute { .. }
    ));
}

#[test]
fn case_sensitivity_never_applies_to_regex() {
    // `case_sensitive: false` alongside a regex must have NO effect on the
    // regex evaluation (Envoy semantics, and `ir.rs`'s `PathMatch::matches`
    // already ignores it for regex — this asserts the engine doesn't
    // second-guess that).
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { safe_regex: { regex: "/Foo" }, case_sensitive: false }, route: { cluster: c } }
"#,
    );
    let hdrs = headers(&[]);
    // Lowercase path must NOT match an uppercase-`F` pattern even though
    // case_sensitive is false, because regex ignores that flag entirely.
    assert!(matches!(
        match_route(fx.table(), &req("h", "/foo", &hdrs)),
        RouteMatch::NoRoute { .. }
    ));
    assert!(matches!(
        match_route(fx.table(), &req("h", "/Foo", &hdrs)),
        RouteMatch::Found { .. }
    ));
}

// ------------------------------------------------------------- S1.4 headers --

#[test]
fn header_exact_match() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/", headers: [{ name: "x-h", string_match: { exact: "v" } }] }
                          route: { cluster: c }
"#,
    );
    assert!(matches!(
        match_route(fx.table(), &req("h", "/", &headers(&[("x-h", "v")]))),
        RouteMatch::Found { .. }
    ));
    assert!(matches!(
        match_route(fx.table(), &req("h", "/", &headers(&[("x-h", "other")]))),
        RouteMatch::NoRoute { .. }
    ));
}

#[test]
fn header_prefix_match() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/", headers: [{ name: "x-h", string_match: { prefix: "ab" } }] }
                          route: { cluster: c }
"#,
    );
    assert!(matches!(
        match_route(fx.table(), &req("h", "/", &headers(&[("x-h", "abcdef")]))),
        RouteMatch::Found { .. }
    ));
    assert!(matches!(
        match_route(fx.table(), &req("h", "/", &headers(&[("x-h", "xabc")]))),
        RouteMatch::NoRoute { .. }
    ));
}

#[test]
fn header_suffix_match() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/", headers: [{ name: "x-h", string_match: { suffix: "yz" } }] }
                          route: { cluster: c }
"#,
    );
    assert!(matches!(
        match_route(fx.table(), &req("h", "/", &headers(&[("x-h", "abcxyz")]))),
        RouteMatch::Found { .. }
    ));
    assert!(matches!(
        match_route(fx.table(), &req("h", "/", &headers(&[("x-h", "xyzabc")]))),
        RouteMatch::NoRoute { .. }
    ));
}

#[test]
fn header_regex_match() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/", headers: [{ name: "x-h", string_match: { safe_regex: { regex: "[0-9]+" } } }] }
                          route: { cluster: c }
"#,
    );
    assert!(matches!(
        match_route(fx.table(), &req("h", "/", &headers(&[("x-h", "12345")]))),
        RouteMatch::Found { .. }
    ));
    assert!(matches!(
        match_route(fx.table(), &req("h", "/", &headers(&[("x-h", "12a45")]))),
        RouteMatch::NoRoute { .. }
    ));
}

#[test]
fn header_present_true_and_false() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/present", headers: [{ name: "x-h", present_match: true }] }
                          route: { cluster: present }
                        - match: { prefix: "/absent", headers: [{ name: "x-h", present_match: false }] }
                          route: { cluster: absent }
"#,
    );
    assert!(matches!(
        match_route(
            fx.table(),
            &req("h", "/present", &headers(&[("x-h", "anything")]))
        ),
        RouteMatch::Found { .. }
    ));
    assert!(matches!(
        match_route(fx.table(), &req("h", "/present", &headers(&[]))),
        RouteMatch::NoRoute { .. }
    ));
    assert!(matches!(
        match_route(fx.table(), &req("h", "/absent", &headers(&[]))),
        RouteMatch::Found { .. }
    ));
    assert!(matches!(
        match_route(fx.table(), &req("h", "/absent", &headers(&[("x-h", "x")]))),
        RouteMatch::NoRoute { .. }
    ));
}

#[test]
fn header_matches_if_any_value_of_a_multi_valued_header_matches() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/", headers: [{ name: "x-h", string_match: { exact: "b" } }] }
                          route: { cluster: c }
"#,
    );
    let hdrs = headers(&[("x-h", "a"), ("x-h", "b"), ("x-h", "c")]);
    assert!(matches!(
        match_route(fx.table(), &req("h", "/", &hdrs)),
        RouteMatch::Found { .. }
    ));
}

#[test]
fn all_header_matchers_must_match_and_one_failing_fails_the_route() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                            headers:
                              - { name: "x-a", string_match: { exact: "1" } }
                              - { name: "x-b", string_match: { exact: "2" } }
                          route: { cluster: c }
"#,
    );
    assert!(matches!(
        match_route(
            fx.table(),
            &req("h", "/", &headers(&[("x-a", "1"), ("x-b", "2")]))
        ),
        RouteMatch::Found { .. }
    ));
    // x-b is wrong -> overall AND fails.
    assert!(matches!(
        match_route(
            fx.table(),
            &req("h", "/", &headers(&[("x-a", "1"), ("x-b", "WRONG")]))
        ),
        RouteMatch::NoRoute { .. }
    ));
}

// ----------------------------------------------------------- S1.5 weighted --

#[test]
fn weighted_pick_boundaries() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
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
    let RouteMatch::Found { route, .. } = match_route(fx.table(), &req("h", "/", &headers(&[])))
    else {
        panic!("expected match");
    };
    let RouteActionIR::Forward(fwd) = &route.action else {
        panic!("expected forward action");
    };
    let ForwardTarget::Weighted(w) = &fwd.target else {
        panic!("expected weighted target");
    };
    assert_eq!(w.total_weight, 100);
    // cumulative: a=20, b=50, c=100
    assert_eq!(w.pick(0), "a");
    assert_eq!(w.pick(19), "a");
    assert_eq!(w.pick(20), "b");
    assert_eq!(w.pick(49), "b");
    assert_eq!(w.pick(50), "c");
    assert_eq!(w.pick(99), "c");
}

#[test]
fn weighted_pick_single_entry() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route:
                            weighted_clusters:
                              clusters:
                                - { name: only, weight: 7 }
"#,
    );
    let RouteMatch::Found { route, .. } = match_route(fx.table(), &req("h", "/", &headers(&[])))
    else {
        panic!("expected match");
    };
    let RouteActionIR::Forward(fwd) = &route.action else {
        panic!("expected forward action");
    };
    assert_eq!(select_cluster(&fwd.target, &headers(&[]), 0), Some("only"));
    assert_eq!(select_cluster(&fwd.target, &headers(&[]), 6), Some("only"));
}

// --------------------------------------------------------- select_cluster --

#[test]
fn select_cluster_direct() {
    let target = ForwardTarget::Cluster("direct".to_string());
    assert_eq!(select_cluster(&target, &headers(&[]), 0), Some("direct"));
}

#[test]
fn select_cluster_header_present() {
    let target = ForwardTarget::ClusterHeader("x-cluster".to_string());
    let hdrs = headers(&[("x-cluster", "chosen")]);
    assert_eq!(select_cluster(&target, &hdrs, 0), Some("chosen"));
}

#[test]
fn select_cluster_header_missing() {
    let target = ForwardTarget::ClusterHeader("x-cluster".to_string());
    assert_eq!(select_cluster(&target, &headers(&[]), 0), None);
}

#[test]
fn select_cluster_header_empty() {
    let target = ForwardTarget::ClusterHeader("x-cluster".to_string());
    let hdrs = headers(&[("x-cluster", "")]);
    assert_eq!(select_cluster(&target, &hdrs, 0), None);
}

#[test]
fn select_cluster_header_non_ascii_is_none() {
    // `http::HeaderValue::to_str()` only accepts visible ASCII (32-126) plus
    // tab; any byte >= 127, including UTF-8 multi-byte sequences, makes it
    // fail. `select_cluster` must turn that into `None`, not panic.
    let target = ForwardTarget::ClusterHeader("x-cluster".to_string());
    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        "x-cluster",
        http::HeaderValue::from_bytes("café".as_bytes()).unwrap(),
    );
    assert_eq!(select_cluster(&target, &hdrs, 0), None);
}

#[test]
fn select_cluster_header_invalid_utf8_is_none() {
    let target = ForwardTarget::ClusterHeader("x-cluster".to_string());
    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        "x-cluster",
        http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
    );
    assert_eq!(select_cluster(&target, &hdrs, 0), None);
}

// ------------------------------------------------------- strip_query/port --

#[test]
fn strip_query_variants() {
    assert_eq!(strip_query("/foo"), "/foo");
    assert_eq!(strip_query("/foo?a=1"), "/foo");
    assert_eq!(strip_query("/foo?"), "/foo");
    assert_eq!(strip_query("?a=1"), "");
    assert_eq!(strip_query(""), "");
}

#[test]
fn strip_port_variants() {
    assert_eq!(strip_port("api.foo.com"), "api.foo.com");
    assert_eq!(strip_port("api.foo.com:8443"), "api.foo.com");
    assert_eq!(strip_port("[::1]:8080"), "[::1]");
    assert_eq!(strip_port("[::1]"), "[::1]");
    assert_eq!(strip_port(""), "");
    // Not a valid port (non-digit) -> left alone.
    assert_eq!(strip_port("host:abc"), "host:abc");
    // Trailing colon with nothing after -> left alone (empty "port").
    assert_eq!(strip_port("host:"), "host:");
}

#[test]
fn adversarial_authority_and_path_inputs_match_literally() {
    // Routes are matched on the raw `:path` (S1.3): no percent-decoding, no
    // case folding of non-ASCII, and a dangling-colon authority is left
    // as-is by `strip_port` but still reaches the `*` virtual host.
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { prefix: "/日本語" }, route: { cluster: jp } }
                        - { match: { prefix: "/x" }, route: { cluster: x } }
"#,
    );
    let hdrs = headers(&[]);
    // `Some(cluster)` = first matching route's cluster; `None` = NoRoute.
    let outcome = |authority: &str, path: &str| -> Option<String> {
        match match_route(fx.table(), &req(authority, path, &hdrs)) {
            RouteMatch::Found { route, .. } => {
                let RouteActionIR::Forward(fwd) = &route.action else {
                    panic!("expected forward action");
                };
                let ForwardTarget::Cluster(name) = &fwd.target else {
                    panic!("expected cluster target");
                };
                Some(name.clone())
            }
            RouteMatch::NoRoute { .. } => None,
            RouteMatch::NoVirtualHost => panic!("`*` vhost must catch {authority:?}"),
        }
    };
    // Empty authority and empty path: vhost found, no prefix matches.
    assert_eq!(outcome("", ""), None);
    // Multi-byte UTF-8 prefix matches byte-for-byte.
    assert_eq!(outcome("h", "/日本語/path").as_deref(), Some("jp"));
    // `%`-garbage is not decoded, so it matches nothing.
    assert_eq!(outcome("h", "%%%garbage%%%"), None);
    // Percent-encoded form of a configured prefix does not match it.
    assert_eq!(outcome("h", "/%78"), None);
    // Trailing-colon authority still resolves the catch-all vhost.
    assert_eq!(outcome("h:", "/x").as_deref(), Some("x"));
}

// --------------------------------------------------------- prefix_rewrite --

#[test]
fn apply_prefix_rewrite_preserves_remainder_and_query() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { prefix: "/old" }, route: { cluster: c, prefix_rewrite: "/new" } }
"#,
    );
    let RouteMatch::Found { route, .. } =
        match_route(fx.table(), &req("h", "/old/thing?x=1", &headers(&[])))
    else {
        panic!("expected match");
    };
    let rewritten = apply_prefix_rewrite(&route.matcher, "/new", "/old/thing?x=1");
    assert_eq!(rewritten.as_deref(), Some("/new/thing?x=1"));
}

#[test]
fn apply_prefix_rewrite_on_exact_match_reattaches_query() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { path: "/exact" }, route: { cluster: c, prefix_rewrite: "/rewritten" } }
"#,
    );
    let RouteMatch::Found { route, .. } =
        match_route(fx.table(), &req("h", "/exact?q=1", &headers(&[])))
    else {
        panic!("expected match");
    };
    let rewritten = apply_prefix_rewrite(&route.matcher, "/rewritten", "/exact?q=1");
    assert_eq!(rewritten.as_deref(), Some("/rewritten?q=1"));
}

#[test]
fn apply_prefix_rewrite_none_for_regex_matcher() {
    let fx = Fixture::new(
        r#"
                  name: rt
                  virtual_hosts:
                    - name: v1
                      domains: ["*"]
                      routes:
                        - { match: { safe_regex: { regex: "/foo" } }, route: { cluster: c } }
"#,
    );
    let RouteMatch::Found { route, .. } = match_route(fx.table(), &req("h", "/foo", &headers(&[])))
    else {
        panic!("expected match");
    };
    assert_eq!(apply_prefix_rewrite(&route.matcher, "/new", "/foo"), None);
}
