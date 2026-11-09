//! `llmproxy.auth`'s `declared_policy` through the strict bootstrap pipeline:
//! the surface walk accepts every declared field and rejects an unknown one
//! at its path, and a scoped budget's provider must name a cluster, since a
//! budget on a misspelled one matches no attempt and caps nothing.

use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

fn load(declared: &str) -> Result<(), ConfigError> {
    let yaml = format!(
        r#"static_resources:
  clusters:
    - name: openai
      connect_timeout: 1s
      load_assignment:
        cluster_name: openai
        endpoints:
          - lb_endpoints:
              - endpoint: {{ address: {{ socket_address: {{ address: 127.0.0.1, port_value: 9 }} }} }}
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
                      declared_policy:
{declared}
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rt_l1
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route: {{ cluster: openai }}
"#
    );
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded).map(|_| ())
}

fn tenant(provider: &str, extra: &str) -> String {
    format!(
        r#"                        revision: 1
                        tenants:
                          - id: acme
                            policy: {{ all: {{}}, deny: ["gpt-4o-mini"] }}
                            budget: {{ max_usd: "5", period: monthly }}
                            limits: {{ requests_per_minute: 10, concurrent_streams: 2 }}
                            scoped_budgets:
                              - {{ name: cap, max_usd: "1", period: daily, models: ["gpt-4o*"], providers: [{provider}], alert_at_percent: [50] }}
{extra}"#
    )
}

#[test]
fn every_declared_field_is_accepted_and_providers_must_name_clusters() {
    load(&tenant("openai", "")).expect("a declared block naming a known cluster loads");

    let err = load(&tenant("opnai", "")).expect_err("an unknown cluster is refused");
    let message = err.to_string();
    assert!(
        message.contains(
            "listeners[0].filter_chains[0].filters[0].typed_config.http_filters[0].typed_config\
             .declared_policy.tenants[0].scoped_budgets[0].providers[0]"
        ) && message.contains("unknown cluster `opnai`"),
        "{message}"
    );
}

#[test]
fn an_unknown_declared_field_is_refused_at_its_path() {
    let err = load(&tenant("openai", "                            bogus: 1\n"))
        .expect_err("strict mode refuses an unknown field");
    let message = err.to_string();
    assert!(
        message.contains("declared_policy.tenants[0].bogus")
            || message.contains("declared_policy.tenants[0]") && message.contains("bogus"),
        "{message}"
    );
}
