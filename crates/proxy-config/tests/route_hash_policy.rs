//! ADR-0016: route `hash_policy` with `weighted_clusters.use_hash_policy`.
//! Strict-parse -> PGV -> IR, so every accepted shape reaches the IR and every
//! refused one fails with its full dotted path (AGENTS.md invariant 1),
//! including the Envoy-valid shapes listed in `envoy-divergences.md` row 46.

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

const AUTH_FILTER: &str = r#"                  - name: llmproxy.auth
                    typed_config:
                      "@type": type.llmproxy.dev/llmproxy.filters.v0.Authentication
                      hmac_secret: { inline_string: "s" }
                      virtual_keys: []
"#;

/// One HCM whose single route carries `route` (indented to match), behind
/// the authentication filter when `with_auth`.
fn lower(route: &str, with_auth: bool) -> Result<ConfigSnapshot, ConfigError> {
    let auth = if with_auth { AUTH_FILTER } else { "" };
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
{auth}                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route:
{route}
"#
    );
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

fn weighted(hash_policy: &str, use_hash_policy: &str) -> String {
    format!(
        r#"                            hash_policy: {hash_policy}
                            weighted_clusters:
                              {use_hash_policy}
                              clusters:
                                - {{ name: a, weight: 1 }}
                                - {{ name: b, weight: 1 }}"#
    )
}

fn hash_policy(snapshot: &ConfigSnapshot) -> &[RouteHashPolicy] {
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    let RouteActionIR::Forward(fwd) = &hcm.route_table.virtual_hosts[0].routes[0].action else {
        panic!("expected forward action");
    };
    let ForwardTarget::Weighted(w) = &fwd.target else {
        panic!("expected weighted target");
    };
    &w.hash_policy
}

fn err_path(err: ConfigError) -> String {
    match err {
        ConfigError::UnsupportedField { field_path, .. } => field_path,
        ConfigError::InvalidValue { field_path, .. } => field_path,
        other => panic!("expected a field-scoped error, got: {other}"),
    }
}

const ROUTE: &str = "static_resources.listeners[0].filter_chains[0].filters[0].typed_config\
                     .route_config.virtual_hosts[0].routes[0].route";

#[test]
fn header_and_identity_sources_reach_the_ir() {
    let snapshot = lower(
        &weighted(
            "[{ header: { header_name: X-Session-Affinity }, terminal: true }, \
             { filter_state: { key: llmproxy.auth.key_id } }, \
             { filter_state: { key: llmproxy.auth.user_id } }, \
             { filter_state: { key: llmproxy.auth.tenant } }]",
            "use_hash_policy: true",
        ),
        true,
    )
    .expect("must lower");
    assert_eq!(
        hash_policy(&snapshot),
        &[
            RouteHashPolicy {
                source: HashSource::Header(http::HeaderName::from_static("x-session-affinity")),
                terminal: true,
            },
            RouteHashPolicy {
                source: HashSource::AuthKeyId,
                terminal: false,
            },
            RouteHashPolicy {
                source: HashSource::AuthUserId,
                terminal: false,
            },
            RouteHashPolicy {
                source: HashSource::AuthTenant,
                terminal: false,
            },
        ]
    );
}

/// `use_hash_policy: false` is Envoy's default and keeps the random draw.
#[test]
fn use_hash_policy_false_with_no_hash_policy_is_the_random_draw() {
    let snapshot = lower(&weighted("[]", "use_hash_policy: false"), false).expect("must lower");
    assert!(hash_policy(&snapshot).is_empty());
}

/// Every refused shape, with the path it must name. Several are valid
/// Envoy (row 46): accepting them would silently do nothing here.
#[test]
fn refused_shapes_name_their_path() {
    let header = "[{ header: { header_name: x-s } }]";
    let cases: Vec<(&str, String, bool, String)> = vec![
        (
            "hash_policy without use_hash_policy",
            weighted(header, ""),
            false,
            format!("{ROUTE}.hash_policy"),
        ),
        (
            "hash_policy on a single-cluster route",
            format!("                            hash_policy: {header}\n                            cluster: a"),
            false,
            format!("{ROUTE}.hash_policy"),
        ),
        (
            "use_hash_policy without hash_policy",
            weighted("[]", "use_hash_policy: true"),
            false,
            format!("{ROUTE}.weighted_clusters.use_hash_policy"),
        ),
        (
            "caller-supplied random value",
            weighted("[]", "header_name: x-random"),
            false,
            format!("{ROUTE}.weighted_clusters.header_name"),
        ),
        (
            "cookie",
            weighted("[{ cookie: { name: c } }]", "use_hash_policy: true"),
            false,
            format!("{ROUTE}.hash_policy[0].cookie"),
        ),
        (
            "connection_properties",
            weighted(
                "[{ connection_properties: { source_ip: true } }]",
                "use_hash_policy: true",
            ),
            false,
            format!("{ROUTE}.hash_policy[0].connection_properties"),
        ),
        (
            "query_parameter",
            weighted("[{ query_parameter: { name: q } }]", "use_hash_policy: true"),
            false,
            format!("{ROUTE}.hash_policy[0].query_parameter"),
        ),
        (
            "regex_rewrite",
            weighted(
                "[{ header: { header_name: x-s, regex_rewrite: { pattern: { regex: a }, substitution: b } } }]",
                "use_hash_policy: true",
            ),
            false,
            format!("{ROUTE}.hash_policy[0].header.regex_rewrite"),
        ),
        (
            "unknown filter-state key",
            weighted(
                "[{ filter_state: { key: envoy.network.upstream_server_name } }]",
                "use_hash_policy: true",
            ),
            true,
            format!("{ROUTE}.hash_policy[0].filter_state.key"),
        ),
        (
            "identity source with no authentication filter",
            weighted(
                "[{ filter_state: { key: llmproxy.auth.key_id } }]",
                "use_hash_policy: true",
            ),
            false,
            format!("{ROUTE}.hash_policy"),
        ),
    ];
    for (label, route, with_auth, path) in cases {
        let err = lower(&route, with_auth).expect_err(label);
        assert_eq!(err_path(err), path, "{label}");
    }
}
