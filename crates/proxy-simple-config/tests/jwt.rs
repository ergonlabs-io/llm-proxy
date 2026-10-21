//! `auth.jwt` (ADR-0014) lowers to the Envoy-mode `llmproxy.auth`
//! `jwt_providers` a hand-written bootstrap would carry, and every dialect
//! rule fails at its dotted path. Request behaviour is proven on the real
//! binary in `crates/proxy/tests/dialect_jwt_e2e.rs`.

use proxy_config::ConfigError;
use proxy_filters::auth_filter::AuthFilterFactory;
use proxy_http::filter::{FactoryContext, HttpFilterFactory};
use proxy_simple_config::{lower, parse_simple_config_with_env, to_envoy_yaml, SimpleConfig};

fn parse(text: &str) -> Result<SimpleConfig, ConfigError> {
    parse_simple_config_with_env(text, &|name| {
        (name == "OPENAI_API_KEY").then(|| "sk-test-openai".to_string())
    })
}

/// A dialect config with `auth.jwt` set to `jwt` (YAML flow or block text
/// indented for a list item under `jwt:`), and `extra_auth` appended to the
/// `auth` block.
fn dialect(jwt: &str, extra_auth: &str) -> String {
    format!(
        "version: 0\n\
         providers:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         auth:\n  hmac_secret: test-secret\n{extra_auth}  jwt:\n{jwt}"
    )
}

const STATIC_PROVIDER: &str = "    - issuer: https://idp.example
      audience: api://llm-proxy
      jwks:
        keys:
          - { kid: k1, n: sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw, e: AQAB }
      tenant:
        claim: tid
        values: { tid-acme: acme }
      user:
        claim: oid
";

fn http_filters(bootstrap: &serde_json::Value) -> &Vec<serde_json::Value> {
    bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        ["http_filters"]
        .as_array()
        .expect("http_filters must be an array")
}

fn invalid_path(text: &str) -> String {
    let config = match parse(text) {
        Ok(config) => config,
        Err(ConfigError::UnknownField { field_path, .. }) => return field_path,
        Err(other) => panic!("unexpected parse error: {other:?}"),
    };
    match lower(&config).map(|_| ()).expect_err("must be refused") {
        ConfigError::InvalidValue { field_path, .. } => field_path,
        other => panic!("expected InvalidValue, got {other:?}"),
    }
}

/// `--mode translate` output carries exactly the `llmproxy.auth` filter an
/// operator would hand-write in Envoy mode, and the real filter accepts it.
#[test]
fn translate_output_matches_a_hand_written_envoy_mode_auth_filter() {
    // A file-backed secret: translate redacts an inline one, and a
    // hand-written bootstrap would not inline it either.
    let dir = std::env::temp_dir().join(format!("llmproxy-jwt-hmac-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let secret_file = dir.join("hmac");
    std::fs::write(&secret_file, "test-secret").expect("write secret");
    let text = dialect(STATIC_PROVIDER, "  keys: []\n").replace(
        "hmac_secret: test-secret",
        &format!("hmac_secret_file: {}", secret_file.display()),
    );
    let config = parse(&text).expect("must parse");
    let (yaml, warnings) = to_envoy_yaml(&config).expect("must translate");
    assert!(
        !warnings.iter().any(|w| w.field_path == "auth.keys"),
        "an auth block with only JWT providers must not warn about empty keys: {warnings:?}"
    );
    let translated: serde_json::Value = serde_yaml::from_str(&yaml).expect("translate is YAML");

    let hand_written: serde_json::Value = serde_yaml::from_str(&format!(
        r#"
name: llmproxy.auth
typed_config:
  "@type": {type_url}
  hmac_secret: {{ filename: {secret} }}
  virtual_keys: []
  jwt_providers:
    - issuer: https://idp.example
      audience: api://llm-proxy
      tenant_claim: tid
      tenant_values: {{ tid-acme: acme }}
      subject_claim: oid
      keys:
        - kid: k1
          n: sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw
          e: AQAB
"#,
        type_url = proxy_filters::auth_filter::TYPE_URL,
        secret = secret_file.display(),
    ))
    .expect("hand-written fragment is YAML");
    assert_eq!(http_filters(&translated)[0], hand_written);

    let loaded = proxy_config::parse_bootstrap(
        yaml.as_bytes(),
        proxy_config::ConfigFormat::Yaml,
        proxy_config::StrictMode::Strict,
    )
    .expect("translate output must be strict-valid Envoy config");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("and must build IR");
    let listener = snapshot.listeners.values().next().expect("one listener");
    let proxy_config::ir::NetworkFilterSpec::HttpConnectionManager(hcm) =
        &listener.filter_chains[0].filters[0]
    else {
        panic!("expected an HTTP connection manager");
    };
    let typed = hcm
        .http_filters
        .iter()
        .find(|f| f.type_url == proxy_filters::auth_filter::TYPE_URL)
        .and_then(|f| f.config.as_ref())
        .expect("llmproxy.auth carries its typed_config");
    AuthFilterFactory
        .create(typed, &FactoryContext::default())
        .expect("the real auth filter must accept the lowered JWT provider");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Discovery lowers to the URL, whole-second interval and CA filename, and
/// the output is strict-valid. The filter is not built: it would start a
/// refresher against the URL.
#[test]
fn discovery_lowers_interval_and_trusted_ca() {
    let dir = std::env::temp_dir().join(format!("llmproxy-jwt-ca-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let ca = dir.join("ca.pem");
    std::fs::write(
        &ca,
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    )
    .expect("write CA");
    let jwt = format!(
        "    - issuer: https://idp.example
      audience: api://llm-proxy
      jwks:
        discovery_url: https://idp.example/.well-known/openid-configuration
        refresh_interval: 5m
        trusted_ca_file: {}
      tenant: {{ claim: tid, values: {{ tid-acme: acme }} }}
      user: {{ claim: oid }}
",
        ca.display()
    );
    let config = parse(&dialect(&jwt, "")).expect("must parse");
    let lowered = lower(&config).expect("must lower");
    let provider = &http_filters(&lowered.bootstrap)[0]["typed_config"]["jwt_providers"][0];
    assert_eq!(
        provider["discovery_url"],
        "https://idp.example/.well-known/openid-configuration"
    );
    assert_eq!(provider["refresh_interval_seconds"], 300);
    assert_eq!(
        provider["trusted_ca"]["filename"],
        ca.display().to_string().as_str()
    );
    assert!(provider.get("keys").is_none());
    proxy_simple_config::lower_to_loaded(&config).expect("must strict-validate");

    std::fs::write(&ca, "not a certificate").expect("write CA");
    assert_eq!(
        invalid_path(&dialect(&jwt, "")),
        "auth.jwt[0].jwks.trusted_ca_file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every required field and every dialect-only rule (ADR-0014 D1-D7) is
/// refused at its own dotted path.
#[test]
fn each_dialect_rule_is_refused_at_its_dotted_path() {
    let keys = "{ keys: [ { kid: k1, n: AQAB, e: AQAB } ] }";
    let entry = |issuer: &str, audience: &str, jwks: &str, tenant: &str, user: &str| {
        let mut out = String::from("    - ");
        let mut fields = Vec::new();
        for (name, value) in [
            ("issuer", issuer),
            ("audience", audience),
            ("jwks", jwks),
            ("tenant", tenant),
            ("user", user),
        ] {
            if !value.is_empty() {
                fields.push(format!("{name}: {value}"));
            }
        }
        out.push_str(&fields.join("\n      "));
        out.push('\n');
        out
    };
    let tenant = "{ claim: tid, values: { t1: acme } }";
    let user = "{ claim: oid }";
    let ok = |issuer| entry(issuer, "aud", keys, tenant, user);
    let cases: Vec<(String, &str)> = vec![
        (entry("", "aud", keys, tenant, user), "auth.jwt[0].issuer"),
        (
            entry("\"\"", "aud", keys, tenant, user),
            "auth.jwt[0].issuer",
        ),
        (entry("iss", "", keys, tenant, user), "auth.jwt[0].audience"),
        (entry("iss", "aud", "", tenant, user), "auth.jwt[0].jwks"),
        (entry("iss", "aud", keys, "", user), "auth.jwt[0].tenant"),
        (entry("iss", "aud", keys, tenant, ""), "auth.jwt[0].user"),
        (
            entry("iss", "aud", keys, tenant, "{}"),
            "auth.jwt[0].user.claim",
        ),
        (
            entry("iss", "aud", keys, "{ values: { t1: acme } }", user),
            "auth.jwt[0].tenant.claim",
        ),
        (
            entry("iss", "aud", keys, "{ claim: tid }", user),
            "auth.jwt[0].tenant.values",
        ),
        (
            entry("iss", "aud", keys, "{ claim: tid, values: {} }", user),
            "auth.jwt[0].tenant.values",
        ),
        (
            entry(
                "iss",
                "aud",
                keys,
                "{ claim: tid, values: { t1: default } }",
                user,
            ),
            "auth.jwt[0].tenant.values.t1",
        ),
        (
            entry(
                "iss",
                "aud",
                keys,
                "{ claim: tid, values: { t1: \"a:b\" } }",
                user,
            ),
            "auth.jwt[0].tenant.values.t1",
        ),
        (
            entry(
                "iss",
                "aud",
                keys,
                &format!("{{ claim: tid, values: {{ t1: {} }} }}", "a".repeat(84)),
                user,
            ),
            "auth.jwt[0].tenant.values.t1",
        ),
        (entry("iss", "aud", "{}", tenant, user), "auth.jwt[0].jwks"),
        (
            entry(
                "iss",
                "aud",
                "{ discovery_url: \"https://x\", keys: [ { kid: k1, n: AQAB, e: AQAB } ] }",
                tenant,
                user,
            ),
            "auth.jwt[0].jwks",
        ),
        (
            entry(
                "iss",
                "aud",
                "{ discovery_url: \"http://x\" }",
                tenant,
                user,
            ),
            "auth.jwt[0].jwks.discovery_url",
        ),
        (
            entry("iss", "aud", "{ keys: [] }", tenant, user),
            "auth.jwt[0].jwks.keys",
        ),
        (
            entry(
                "iss",
                "aud",
                "{ refresh_interval: 5m, keys: [ { kid: k1, n: AQAB, e: AQAB } ] }",
                tenant,
                user,
            ),
            "auth.jwt[0].jwks.refresh_interval",
        ),
        (
            entry(
                "iss",
                "aud",
                "{ discovery_url: \"https://x\", refresh_interval: 1500ms }",
                tenant,
                user,
            ),
            "auth.jwt[0].jwks.refresh_interval",
        ),
        (
            entry(
                "iss",
                "aud",
                "{ keys: [ { kid: k1, n: AQAB, e: AQAB }, { kid: k1, n: AQAB, e: AQAB } ] }",
                tenant,
                user,
            ),
            "auth.jwt[0].jwks.keys[1].kid",
        ),
        (
            entry(
                "iss",
                "aud",
                "{ keys: [ { kid: k1, n: \"AQ==\", e: AQAB } ] }",
                tenant,
                user,
            ),
            "auth.jwt[0].jwks.keys[0].n",
        ),
        (
            entry(
                "iss",
                "aud",
                "{ keys: [ { kid: k1, n: AQAB } ] }",
                tenant,
                user,
            ),
            "auth.jwt[0].jwks.keys[0].e",
        ),
        (format!("{}{}", ok("iss"), ok("iss")), "auth.jwt[1].issuer"),
        (
            entry(
                "iss",
                "aud",
                keys,
                "{ claim: tid, values: { t1: acme }, map: {} }",
                user,
            ),
            "auth.jwt[0].tenant.map",
        ),
        (
            format!("{}      subject_claim: sub\n", ok("iss")),
            "auth.jwt[0].subject_claim",
        ),
    ];
    for (jwt, expected) in cases {
        assert_eq!(invalid_path(&dialect(&jwt, "")), expected, "config:\n{jwt}");
    }
    // Two issuers are two providers, in order.
    let config = parse(&dialect(&format!("{}{}", ok("a"), ok("b")), "")).expect("must parse");
    let lowered = lower(&config).expect("two distinct issuers lower");
    let providers = &http_filters(&lowered.bootstrap)[0]["typed_config"]["jwt_providers"];
    assert_eq!(providers[0]["issuer"], "a");
    assert_eq!(providers[1]["issuer"], "b");
}

/// The longest tenant the identity bound allows is accepted; one byte more
/// is the case refused above. `jwt:` + `iss` + 2 separators + 36-byte
/// subject leaves 83 bytes of 128.
#[test]
fn the_tenant_length_bound_leaves_room_for_a_uuid_subject() {
    let jwt = format!(
        "    - issuer: iss
      audience: aud
      jwks: {{ keys: [ {{ kid: k1, n: AQAB, e: AQAB }} ] }}
      tenant: {{ claim: tid, values: {{ t1: {} }} }}
      user: {{ claim: oid }}
",
        "a".repeat(83)
    );
    let config = parse(&dialect(&jwt, "")).expect("must parse");
    lower(&config).expect("an 83-byte tenant fits");
}

/// A JWT principal carries its tenant's provider credentials as a virtual key
/// does (ADR-0014 decision 2), so a config with both lowers without a warning
/// at `auth.jwt`.
#[test]
fn jwt_with_tenant_credentials_lowers_without_a_platform_mode_warning() {
    let dir = std::env::temp_dir().join(format!("llmproxy-jwt-kek-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let kek = dir.join("kek");
    std::fs::write(&kek, [7u8; 32]).expect("write key");
    let extra = format!(
        "  store: {{ persistent: {{ path: {} }} }}\n  tenant_credentials: {{ encryption_key_file: {}, encryption_key_id: k1 }}\n",
        dir.join("control.redb").display(),
        kek.display()
    );
    let config = parse(&dialect(STATIC_PROVIDER, &extra)).expect("must parse");
    let lowered = lower(&config).expect("must lower");
    let jwt_warnings: Vec<_> = lowered
        .warnings
        .iter()
        .filter(|w| w.field_path == "auth.jwt")
        .collect();
    assert!(jwt_warnings.is_empty(), "{:?}", lowered.warnings);
    let _ = std::fs::remove_dir_all(&dir);
}
