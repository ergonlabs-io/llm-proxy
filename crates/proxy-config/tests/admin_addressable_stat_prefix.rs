//! WP-50 3c-ii-a: a duplicate HCM `stat_prefix` is a config error ONLY among
//! chains that configure `llmproxy.auth` -- the only filter an admin
//! endpoint addresses by name today (`SharedFactoryState::get_by_name`,
//! `proxy-admin`'s `/chains/{stat_prefix}/...`). Envoy itself tolerates a
//! duplicate `stat_prefix` everywhere (it merges stats), so a duplicate
//! among chains that register no admin-addressable singleton must stay
//! legal -- see `internal-docs/IMPLEMENTATION_PLAN.md`'s "addressing
//! follows Envoy" and `lower::check_admin_addressable_stat_prefixes`'s doc.

use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

/// One `http_filters` entry for the given filter, followed by the mandatory
/// terminal router -- built directly as YAML text (this test builds two full
/// listeners, one string each, rather than reusing `lane_h_filter_order.rs`'s
/// private helpers, which live in a separate test binary).
fn auth_filter_entry() -> &'static str {
    r#"                  - name: llmproxy.auth
                    typed_config:
                      "@type": type.llmproxy.dev/llmproxy.filters.v0.Authentication
                      hmac_secret: { inline_string: "s" }
                      virtual_keys: []
"#
}

/// One listener -> one filter chain -> one HCM with `stat_prefix` set to
/// `stat_prefix`, optionally preceded by `llmproxy.auth` in its
/// `http_filters` (`with_auth`). `port` and `name` keep two listeners in one
/// bootstrap from colliding on address or name.
fn listener_yaml(name: &str, port: u16, stat_prefix: &str, with_auth: bool) -> String {
    let auth_entry = if with_auth { auth_filter_entry() } else { "" };
    format!(
        r#"    - name: {name}
      address:
        socket_address: {{ address: 0.0.0.0, port_value: {port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: {stat_prefix}
                http_filters:
{auth_entry}                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rt_{name}
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          direct_response: {{ status: 200 }}
"#
    )
}

/// A bootstrap with exactly the two listeners `listener_yaml` describes.
fn two_listener_snapshot(
    stat_prefix_a: &str,
    with_auth_a: bool,
    stat_prefix_b: &str,
    with_auth_b: bool,
) -> Result<proxy_config::ir::ConfigSnapshot, ConfigError> {
    let yaml = format!(
        "static_resources:\n  listeners:\n{}{}",
        listener_yaml("l1", 8080, stat_prefix_a, with_auth_a),
        listener_yaml("l2", 8081, stat_prefix_b, with_auth_b),
    );
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

fn expect_invalid(
    result: Result<proxy_config::ir::ConfigSnapshot, ConfigError>,
) -> (String, String) {
    match result {
        Err(ConfigError::InvalidValue { field_path, reason }) => (field_path, reason),
        Err(other) => panic!("expected InvalidValue, got {other:?}"),
        Ok(_) => panic!("expected the config to be rejected, but it loaded"),
    }
}

/// The narrow rule's positive case: two chains sharing a `stat_prefix`, BOTH
/// configuring `llmproxy.auth`, must be rejected -- `/chains/dup/...` and a
/// future persisted spend row could not tell them apart.
#[test]
fn duplicate_stat_prefix_across_two_auth_chains_is_a_load_error_naming_the_dotted_path() {
    let (field_path, reason) = expect_invalid(two_listener_snapshot("dup", true, "dup", true));

    assert_eq!(
        field_path,
        "static_resources.listeners[1].filter_chains[0].filters[0].typed_config.stat_prefix",
        "the error must name the SECOND occurrence's own dotted path, not just say \"dup\" \
         is bad somewhere"
    );
    assert!(
        reason.contains("dup") && reason.contains("llmproxy.auth"),
        "the reason must name the colliding stat_prefix and explain it's an auth-addressing \
         collision, not merely \"duplicate\": {reason}"
    );
    assert!(
        reason.contains("static_resources.listeners[0]"),
        "the reason must also point back at the FIRST chain that already claimed this \
         stat_prefix, or an operator can't find the collision: {reason}"
    );
}

/// **The narrowness itself.** Two chains sharing a `stat_prefix`, NEITHER
/// configuring `llmproxy.auth`, must still load clean -- Envoy's own
/// tolerance for a duplicate `stat_prefix` (it just merges stats), and
/// nothing here ever addresses either chain by that name.
#[test]
fn duplicate_stat_prefix_across_two_non_auth_chains_still_loads_clean() {
    two_listener_snapshot("dup", false, "dup", false).expect(
        "a duplicate stat_prefix between two chains that configure no admin-addressable \
         singleton must stay legal, exactly as in Envoy",
    );
}

/// One chain configures `llmproxy.auth` under `stat_prefix`, the other does
/// not -- no ambiguity is possible (only the auth chain is ever addressed by
/// name), so this must load clean too.
#[test]
fn duplicate_stat_prefix_where_only_one_side_configures_auth_still_loads_clean() {
    two_listener_snapshot("dup", true, "dup", false).expect(
        "only the auth-configuring chain is ever addressed by stat_prefix; the non-auth \
         chain sharing its name has nothing to collide with",
    );
}

/// Distinct `stat_prefix`es, both configuring `llmproxy.auth` -- the
/// ordinary case this whole increment exists to make addressable -- must
/// load clean.
#[test]
fn distinct_stat_prefixes_across_two_auth_chains_load_clean() {
    two_listener_snapshot("chain-a", true, "chain-b", true)
        .expect("two auth chains with distinct stat_prefixes must not collide");
}
