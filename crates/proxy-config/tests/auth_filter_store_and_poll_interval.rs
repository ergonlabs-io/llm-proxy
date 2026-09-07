//! WP-61: `llmproxy.filters.v0.Authentication`'s `store` oneof
//! (`in_memory`/`persistent`) and its new `poll_interval_seconds` field, both
//! through the real strict-parse -> surface-walk -> IR pipeline.
//!
//! Before this fix, `lower::allowed_fields`'s
//! `"llmproxy.filters.v0.Authentication"` entry listed only `hmac_secret` and
//! `virtual_keys` -- the `store` oneof's members never appeared under their
//! own field names, so any config that set `persistent` was rejected by the
//! surface walk with `UnsupportedField`, making the redb-backed store
//! unreachable through Envoy-mode config even though
//! `auth_filter::parse_store` fully supported it. These tests pin that the
//! fix holds: a config selecting `persistent`, and one setting
//! `poll_interval_seconds`, must both lower cleanly rather than being
//! rejected as an unsupported field.

use proxy_config::{build_snapshot, ir::*, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

fn snapshot_from(yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

/// One listener, one HCM, `llmproxy.auth` configured with whatever
/// `auth_typed_config_extra` adds after `hmac_secret`/`virtual_keys`,
/// followed by the mandatory terminal router.
fn listener_yaml(auth_typed_config_extra: &str) -> String {
    format!(
        r#"static_resources:
  listeners:
    - name: l1
      address:
        socket_address: {{ address: 0.0.0.0, port_value: 8080 }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: st1
                http_filters:
                  - name: llmproxy.auth
                    typed_config:
                      "@type": type.llmproxy.dev/llmproxy.filters.v0.Authentication
                      hmac_secret: {{ inline_string: "s" }}
                      virtual_keys: []
{auth_typed_config_extra}                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rt_l1
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          direct_response: {{ status: 200 }}
"#
    )
}

/// The `llmproxy.auth` `HttpFilterSpec`'s `config` -- the raw
/// [`prost_reflect::DynamicMessage`] `proxy-config` leaves it in (see
/// `HttpFilterSpec::config`'s doc: parsing it further is a filter factory's
/// job, not this crate's), which is what these tests inspect directly since
/// there is no filter-specific IR type for it to have lowered into.
fn auth_config(snapshot: &ConfigSnapshot) -> prost_reflect::DynamicMessage {
    let listener = snapshot
        .listeners
        .get("l1")
        .expect("the fixture defines exactly one listener, named `l1`");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected the HCM to be the first network filter");
    };
    hcm.http_filters[0]
        .config
        .clone()
        .expect("llmproxy.auth always has typed_config")
}

#[test]
fn an_auth_filter_configuring_a_persistent_store_lowers() {
    let yaml = listener_yaml(
        r#"                      persistent:
                        path: /var/lib/llm-proxy/control-plane.redb
"#,
    );
    let snapshot = snapshot_from(&yaml).expect(
        "a config selecting `persistent` must lower cleanly -- before the allowed_fields fix, \
         this was rejected as an UnsupportedField",
    );
    let config = auth_config(&snapshot);
    let persistent = config
        .get_field_by_name("persistent")
        .and_then(|v| v.as_message().cloned())
        .expect("`persistent` must survive the surface walk into the filter's own config");
    assert_eq!(
        persistent
            .get_field_by_name("path")
            .and_then(|v| v.as_str().map(str::to_string)),
        Some("/var/lib/llm-proxy/control-plane.redb".to_string()),
    );
}

#[test]
fn an_auth_filter_setting_poll_interval_seconds_lowers() {
    let yaml = listener_yaml("                      poll_interval_seconds: 90\n");
    let snapshot = snapshot_from(&yaml).expect(
        "a config setting `poll_interval_seconds` must lower cleanly -- before the \
         allowed_fields fix, this was rejected as an UnsupportedField",
    );
    let config = auth_config(&snapshot);
    assert_eq!(
        config
            .get_field_by_name("poll_interval_seconds")
            .and_then(|v| v.as_u32()),
        Some(90),
    );
}
