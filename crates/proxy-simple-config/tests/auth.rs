//! WP-50 increment 2a-iii acceptance tests: the dialect's `auth:` block
//! lowers to a real `llmproxy.auth` `http_filters` entry that
//! `proxy_filters::auth_filter::parse_config` actually accepts, with strict
//! validation -- done entirely in this crate, naming DIALECT paths
//! (`auth.keys[0].digest`) rather than that function's proto paths
//! (`typed_config.virtual_keys[0].digest_hex`), which the operator's
//! document has no `typed_config` to point into.
//!
//! Follows `tests/fallbacks.rs`'s shape: fixtures are real YAML, lowered
//! through the real pipeline, asserted on the resulting bootstrap JSON (or,
//! for the end-to-end case, on the real IR + the real filter factory) rather
//! than on any intermediate representation.

use proxy_config::ConfigError;
use proxy_filters::auth_filter::AuthFilterFactory;
use proxy_http::filter::{FactoryContext, HttpFilterFactory};
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config_with_env, SimpleConfig};

fn test_env(name: &str) -> Option<String> {
    match name {
        "OPENAI_API_KEY" => Some("sk-test-openai".to_string()),
        _ => None,
    }
}

fn parse(text: &str) -> Result<SimpleConfig, ConfigError> {
    parse_simple_config_with_env(text, &test_env)
}

/// The same HMAC-SHA256 `auth_filter::parse_config` / `KeySet::insert`
/// verify against, computed independently here (via `ring` directly, a
/// test-only dependency -- see `Cargo.toml`) rather than through any
/// `proxy-filters` helper, so a fixture exercises the REAL filter instead of
/// asserting against a value nobody checked.
fn digest_hex(secret: &[u8], plaintext: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let digest = ring::hmac::sign(&key, plaintext.as_bytes());
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// A minimal config with no `auth:` block at all -- the pre-WP-50 shape,
/// kept as a regression fixture (test 12).
const NO_AUTH_CONFIG: &str = r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
"#;

/// One valid `auth:` block, computed from `secret`/`digest` at call time so
/// every test can use its own distinct secret without duplicating this
/// scaffolding.
fn config_with_one_key(secret: &str, key_id: &str, tenant: &str, digest: &str) -> String {
    format!(
        "version: 0\n\
         providers:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         auth:\n  hmac_secret: \"{secret}\"\n  keys:\n    - {{ id: \"{key_id}\", tenant: \"{tenant}\", digest: \"{digest}\" }}\n"
    )
}

fn http_filters(bootstrap: &serde_json::Value) -> &Vec<serde_json::Value> {
    bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        ["http_filters"]
        .as_array()
        .expect("http_filters must be an array")
}

// --- 1: a valid `auth:` block lowers, `llmproxy.auth` FIRST in http_filters --

#[test]
fn a_valid_auth_block_lowers_with_llmproxy_auth_first_in_http_filters() {
    let secret = "test-operator-secret";
    let digest = digest_hex(secret.as_bytes(), "llmp_test-key");
    let config = parse(&config_with_one_key(secret, "k1", "acme", &digest)).expect("must parse");
    let lowered = lower(&config).expect("must lower");

    let filters = http_filters(&lowered.bootstrap);
    assert!(
        filters.len() > 1,
        "expected other filters (body-rewrite/usage/router) alongside auth"
    );
    assert_eq!(
        filters[0]["name"], "llmproxy.auth",
        "llmproxy.auth must be the FIRST entry -- ahead of body-rewrite so an \
         unauthenticated request is refused before the body-peek filter buffers it"
    );
}

/// `lower.rs` duplicates the auth filter's type URL as a literal instead of
/// importing it, to keep the data plane out of a config crate's production
/// dependency tree (see `AUTH_FILTER_TYPE_URL`'s doc comment in `lower.rs`).
/// That trade is only safe if something pins the two together -- this is
/// that something, mirroring `dialect.rs`'s
/// `usage_filter_type_url_matches_the_filter`.
#[test]
fn auth_filter_type_url_matches_the_filter() {
    let secret = "test-operator-secret";
    let digest = digest_hex(secret.as_bytes(), "llmp_test-key");
    let config = parse(&config_with_one_key(secret, "k1", "acme", &digest)).expect("must parse");
    let lowered = lower(&config).expect("must lower");
    let filters = http_filters(&lowered.bootstrap);

    assert_eq!(
        filters[0]["typed_config"]["@type"],
        proxy_filters::auth_filter::TYPE_URL,
        "the dialect emits a type URL no registered filter factory answers to; \
         this would be a bind-time error on every listener"
    );
}

// --- 2: lowers through the real Envoy loader, and the REAL filter accepts it --

/// This is what actually proves the dialect's emitted config satisfies
/// `auth_filter::parse_config`, not merely that it looks plausible as JSON:
/// strict-parse + PGV + IR (via `lower_to_loaded` + `build_snapshot`, same as
/// `fallbacks.rs`'s equivalent), then the REAL `AuthFilterFactory::create`
/// against the REAL `DynamicMessage` the IR carries.
#[test]
fn auth_config_lowers_through_the_real_loader_and_the_real_filter_accepts_it() {
    let secret = "test-operator-secret";
    let digest = digest_hex(secret.as_bytes(), "llmp_test-key");
    let config = parse(&config_with_one_key(secret, "k1", "acme", &digest)).expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and strict-validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

    let listener = snapshot
        .listeners
        .values()
        .next()
        .expect("exactly one listener");
    let proxy_config::ir::NetworkFilterSpec::HttpConnectionManager(hcm) =
        &listener.filter_chains[0].filters[0]
    else {
        panic!("expected an HTTP connection manager");
    };
    let auth_entry = hcm
        .http_filters
        .iter()
        .find(|f| f.type_url == proxy_filters::auth_filter::TYPE_URL)
        .expect("llmproxy.auth must be in the IR's http_filters");
    let config = auth_entry
        .config
        .as_ref()
        .expect("the auth filter's typed_config must survive to the IR");

    AuthFilterFactory
        .create(config, &FactoryContext {})
        .expect("the real auth_filter::parse_config must accept the dialect's emitted config");
}

// --- 3: hmac_secret_file lowers to filename and warns; a missing file errors --

#[test]
fn hmac_secret_file_lowers_to_filename_and_warns_and_a_missing_file_errors() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "llm-proxy-simple-config-auth-test-secret-{}",
        std::process::id()
    ));
    std::fs::write(&path, b"test-operator-secret").expect("write temp secret file");

    let digest = digest_hex(b"test-operator-secret", "llmp_test-key");
    let config_text = format!(
        "version: 0\n\
         providers:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         auth:\n  hmac_secret_file: \"{}\"\n  keys:\n    - {{ id: \"k1\", tenant: \"acme\", digest: \"{digest}\" }}\n",
        path.display()
    );
    let config = parse(&config_text).expect("must parse");
    let lowered = lower(&config).expect("must lower");

    assert!(
        lowered
            .warnings
            .iter()
            .any(|w| w.field_path == "auth.hmac_secret_file"
                && w.message
                    == "the key file is read once at startup; hot reload lands with WP-35"),
        "expected the api_key_file-style warning (same wording), got: {:?}",
        lowered.warnings
    );

    let filters = http_filters(&lowered.bootstrap);
    assert_eq!(
        filters[0]["typed_config"]["hmac_secret"],
        serde_json::json!({ "filename": path.display().to_string() })
    );

    std::fs::remove_file(&path).ok();

    let missing = dir.join("llm-proxy-simple-config-auth-test-secret-does-not-exist");
    let config_text = format!(
        "version: 0\n\
         providers:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         auth:\n  hmac_secret_file: \"{}\"\n",
        missing.display()
    );
    let config = parse(&config_text).expect("must parse");
    let err = lower(&config).expect_err("a nonexistent secret file must be rejected");
    match err {
        ConfigError::Io { path: p, .. } => assert_eq!(p, missing.display().to_string()),
        other => panic!("expected Io, got {other:?}"),
    }
}

// --- 4: neither / both secret fields -> error, field_path == "auth" --

#[test]
fn neither_or_both_secret_fields_is_rejected_naming_auth() {
    let neither = parse(
        "version: 0\n\
         providers:\n  openai: { api_key: ${OPENAI_API_KEY} }\n\
         routes:\n  - { model: \"*\", provider: openai }\n\
         auth: {}\n",
    )
    .expect("must parse");
    let err =
        lower(&neither).expect_err("neither hmac_secret nor hmac_secret_file must be rejected");
    match err {
        ConfigError::InvalidValue { field_path, .. } => assert_eq!(field_path, "auth"),
        other => panic!("expected InvalidValue, got {other:?}"),
    }

    let both = parse(
        "version: 0\n\
         providers:\n  openai: { api_key: ${OPENAI_API_KEY} }\n\
         routes:\n  - { model: \"*\", provider: openai }\n\
         auth: { hmac_secret: \"a\", hmac_secret_file: \"/nonexistent\" }\n",
    )
    .expect("must parse");
    let err = lower(&both).expect_err("both hmac_secret and hmac_secret_file must be rejected");
    match err {
        ConfigError::InvalidValue { field_path, .. } => assert_eq!(field_path, "auth"),
        other => panic!("expected InvalidValue, got {other:?}"),
    }
}

// --- 5: each digest-shape failure -> error naming auth.keys[0].digest --

#[test]
fn malformed_digest_variants_are_each_rejected_naming_the_dialect_path() {
    let secret = "test-operator-secret";
    let good_digest = digest_hex(secret.as_bytes(), "llmp_x");

    let bad_digests = [
        good_digest[..good_digest.len() - 1].to_string(), // wrong length
        "z".repeat(64),                                   // non-hex, same length
        good_digest.to_ascii_uppercase(),                 // uppercase
    ];

    for bad in bad_digests {
        let config = parse(&config_with_one_key(secret, "k1", "acme", &bad)).expect("must parse");
        let err = lower(&config).expect_err(&format!("{bad:?} must be rejected"));
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "auth.keys[0].digest")
            }
            other => panic!("expected InvalidValue for {bad:?}, got {other:?}"),
        }
    }
}

/// Not in the acceptance list explicitly, but required by the spec's
/// validation section ("`id` or `tenant` empty -> error on that key's
/// path") -- worth pinning independently of the digest checks above.
#[test]
fn empty_id_or_tenant_is_rejected_naming_that_keys_path() {
    let secret = "test-operator-secret";
    let digest = digest_hex(secret.as_bytes(), "llmp_x");

    let empty_id = parse(&config_with_one_key(secret, "", "acme", &digest)).expect("must parse");
    let err = lower(&empty_id).expect_err("empty id must be rejected");
    match err {
        ConfigError::InvalidValue { field_path, .. } => {
            assert_eq!(field_path, "auth.keys[0].id")
        }
        other => panic!("expected InvalidValue, got {other:?}"),
    }

    let empty_tenant = parse(&config_with_one_key(secret, "k1", "", &digest)).expect("must parse");
    let err = lower(&empty_tenant).expect_err("empty tenant must be rejected");
    match err {
        ConfigError::InvalidValue { field_path, .. } => {
            assert_eq!(field_path, "auth.keys[0].tenant")
        }
        other => panic!("expected InvalidValue, got {other:?}"),
    }
}

// --- 6: duplicate id / duplicate digest -> error naming index 1 --

#[test]
fn duplicate_id_and_duplicate_digest_are_each_rejected_naming_index_1() {
    let secret = "test-operator-secret";
    let digest_a = digest_hex(secret.as_bytes(), "llmp_a");
    let digest_b = digest_hex(secret.as_bytes(), "llmp_b");

    let dup_id = format!(
        "version: 0\n\
         providers:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         auth:\n  hmac_secret: \"{secret}\"\n  keys:\n\
         \x20\x20\x20\x20- {{ id: \"dup\", tenant: \"acme\", digest: \"{digest_a}\" }}\n\
         \x20\x20\x20\x20- {{ id: \"dup\", tenant: \"acme2\", digest: \"{digest_b}\" }}\n"
    );
    let config = parse(&dup_id).expect("must parse");
    let err = lower(&config).expect_err("duplicate id must be rejected");
    match err {
        ConfigError::InvalidValue { field_path, .. } => assert_eq!(field_path, "auth.keys[1].id"),
        other => panic!("expected InvalidValue, got {other:?}"),
    }

    let dup_digest = format!(
        "version: 0\n\
         providers:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         auth:\n  hmac_secret: \"{secret}\"\n  keys:\n\
         \x20\x20\x20\x20- {{ id: \"k1\", tenant: \"acme\", digest: \"{digest_a}\" }}\n\
         \x20\x20\x20\x20- {{ id: \"k2\", tenant: \"acme2\", digest: \"{digest_a}\" }}\n"
    );
    let config = parse(&dup_digest).expect("must parse");
    let err = lower(&config).expect_err("duplicate digest must be rejected");
    match err {
        ConfigError::InvalidValue { field_path, .. } => {
            assert_eq!(field_path, "auth.keys[1].digest")
        }
        other => panic!("expected InvalidValue, got {other:?}"),
    }
}

// --- 7: keys: [] -> legal, but warns --

#[test]
fn empty_keys_lowers_and_warns() {
    let config_text = "version: 0\n\
         providers:\n  openai: { api_key: ${OPENAI_API_KEY} }\n\
         routes:\n  - { model: \"*\", provider: openai }\n\
         auth:\n  hmac_secret: \"test-operator-secret\"\n  keys: []\n";
    let config = parse(config_text).expect("must parse");
    let lowered = lower(&config).expect("empty `keys` is legal");

    assert!(
        lowered.warnings.iter().any(|w| w.field_path == "auth.keys"),
        "expected a warning about empty `auth.keys` (fail closed = refuses everything), got: {:?}",
        lowered.warnings
    );
    let filters = http_filters(&lowered.bootstrap);
    assert!(
        filters.iter().any(|f| f["name"] == "llmproxy.auth"),
        "the filter must still be emitted -- empty keys means it 401s every request, not \
         that it's absent from the chain"
    );
}

// --- 8: no error or warning message anywhere contains the secret or a digest --

#[test]
fn no_error_or_warning_message_contains_the_secret_or_a_digest() {
    let distinctive_secret = "very-distinctive-operator-secret-value";
    let distinctive_digest = digest_hex(distinctive_secret.as_bytes(), "llmp_distinctive-key");

    let mut messages: Vec<String> = Vec::new();

    // Malformed (truncated) digest, secret present too -- a leak has
    // something distinctive to leak.
    let truncated = &distinctive_digest[..distinctive_digest.len() - 1];
    let config = parse(&config_with_one_key(
        distinctive_secret,
        "k1",
        "acme",
        truncated,
    ))
    .expect("must parse");
    messages.push(
        lower(&config)
            .expect_err("malformed digest must be rejected")
            .to_string(),
    );

    // Duplicate digest, using the distinctive digest twice.
    let dup = format!(
        "version: 0\n\
         providers:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         auth:\n  hmac_secret: \"{distinctive_secret}\"\n  keys:\n\
         \x20\x20\x20\x20- {{ id: \"k1\", tenant: \"acme\", digest: \"{distinctive_digest}\" }}\n\
         \x20\x20\x20\x20- {{ id: \"k2\", tenant: \"acme2\", digest: \"{distinctive_digest}\" }}\n"
    );
    let config = parse(&dup).expect("must parse");
    messages.push(
        lower(&config)
            .expect_err("duplicate digest must be rejected")
            .to_string(),
    );

    // A config that only warns (empty keys), still with the distinctive
    // secret present.
    let empty_keys = format!(
        "version: 0\n\
         providers:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         auth:\n  hmac_secret: \"{distinctive_secret}\"\n  keys: []\n"
    );
    let config = parse(&empty_keys).expect("must parse");
    let lowered = lower(&config).expect("empty keys is legal");
    messages.extend(lowered.warnings.iter().map(|w| w.message.clone()));

    assert!(!messages.is_empty());
    for message in &messages {
        assert!(
            !message.contains(distinctive_secret),
            "message must never contain the secret: {message}"
        );
        assert!(
            !message.contains(&distinctive_digest),
            "message must never contain the digest: {message}"
        );
    }
}

// --- 9/10/11: `limits[].key: tenant` and its interaction with `auth:` --

#[test]
fn tenant_key_without_auth_is_rejected() {
    let config = parse(
        r#"
version: 0
providers:
  openai: { api_key: ${OPENAI_API_KEY} }
routes:
  - { model: "*", provider: openai }
limits:
  - { key: tenant, tokens_per_minute: 100k }
"#,
    )
    .expect("must parse");
    let err = lower(&config).expect_err("`key: tenant` without `auth:` must be rejected");
    match err {
        ConfigError::InvalidValue { field_path, .. } => assert_eq!(field_path, "limits[0].key"),
        other => panic!("expected InvalidValue, got {other:?}"),
    }
}

#[test]
fn tenant_key_with_auth_lowers_and_emits_the_token_limit_filter() {
    let secret = "test-operator-secret";
    let digest = digest_hex(secret.as_bytes(), "llmp_test-key");
    let config_text = format!(
        "{}limits:\n  - {{ key: tenant, tokens_per_minute: 100k }}\n",
        config_with_one_key(secret, "k1", "acme", &digest)
    );
    let config = parse(&config_text).expect("must parse");
    let lowered = lower(&config).expect("must lower");

    let filters = http_filters(&lowered.bootstrap);
    assert!(
        filters.iter().any(|f| f["name"] == "llmproxy.token_limit"),
        "the token-limit filter must be emitted for `key: tenant` with `auth:` configured, \
         exactly as `key: header:authorization` does today"
    );
}

#[test]
fn header_authorization_key_with_auth_lowers_and_warns() {
    let secret = "test-operator-secret";
    let digest = digest_hex(secret.as_bytes(), "llmp_test-key");
    let config_text = format!(
        "{}limits:\n  - {{ key: header:authorization, tokens_per_minute: 100k }}\n",
        config_with_one_key(secret, "k1", "acme", &digest)
    );
    let config = parse(&config_text).expect("must parse");
    let lowered = lower(&config).expect("must lower");

    let filters = http_filters(&lowered.bootstrap);
    assert!(
        filters.iter().any(|f| f["name"] == "llmproxy.token_limit"),
        "`header:authorization` is still the one enforced header key even with `auth:` \
         configured -- only the RUNTIME bucket changes, not whether the filter is emitted"
    );
    assert!(
        lowered
            .warnings
            .iter()
            .any(|w| w.field_path == "limits[0].key" && w.message.contains("tenant")),
        "expected a warning steering the operator toward `key: tenant`, got: {:?}",
        lowered.warnings
    );
}

// --- 12: no `auth:` block at all -> unchanged output --

#[test]
fn no_auth_block_leaves_http_filters_unchanged() {
    let config = parse(NO_AUTH_CONFIG).expect("must parse");
    let lowered = lower(&config).expect("must lower");
    let filters = http_filters(&lowered.bootstrap);
    assert!(
        filters.iter().all(|f| f["name"] != "llmproxy.auth"),
        "no `auth:` block must mean no `llmproxy.auth` filter anywhere in the chain"
    );
}
