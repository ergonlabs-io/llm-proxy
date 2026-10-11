//! Acceptance tests for tenant provider credentials in the config dialect
//! (ADR-0007). `providers.<name>.tenant_credentials: true` lowers a
//! `tenant_credential` slot onto the provider's cluster, and
//! `auth.tenant_credentials` lowers the key ring into `llmproxy.auth`.
//!
//! Fixtures are real YAML, lowered through the real pipeline. Assertions are
//! whole values where the shape matters, and the lowered config is checked by
//! the real loader and the real auth filter, the same as `auth.rs`.

use std::path::PathBuf;

use proxy_config::ConfigError;
use proxy_filters::auth_filter::AuthFilterFactory;
use proxy_http::filter::{FactoryContext, HttpFilterFactory};
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config_with_env, SimpleConfig};

/// Namespace key the provider's cluster metadata carries the slot under.
const PROVIDER_AUTH_KEY: &str = "io.llmproxy.provider_auth";

fn test_env(name: &str) -> Option<String> {
    match name {
        "OPENAI_API_KEY" => Some("sk-test-openai".to_string()),
        _ => None,
    }
}

fn parse(text: &str) -> Result<SimpleConfig, ConfigError> {
    parse_simple_config_with_env(text, &test_env)
}

fn lower_text(text: &str) -> Result<serde_json::Value, ConfigError> {
    let config = parse(text)?;
    Ok(lower(&config)?.bootstrap)
}

/// The lowered cluster named `name`, from `static_resources.clusters`.
fn cluster<'a>(bootstrap: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    bootstrap["static_resources"]["clusters"]
        .as_array()
        .expect("clusters must be an array")
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no cluster named {name}"))
}

/// The `io.llmproxy.provider_auth` metadata object on cluster `name`.
fn provider_auth<'a>(bootstrap: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    &cluster(bootstrap, name)["metadata"]["filter_metadata"][PROVIDER_AUTH_KEY]
}

fn http_filters(bootstrap: &serde_json::Value) -> &Vec<serde_json::Value> {
    bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        ["http_filters"]
        .as_array()
        .expect("http_filters must be an array")
}

/// A 32-byte key file with mode 0600, which the auth filter requires. This
/// crate has no `tempfile` dependency, so the name is process- and
/// test-unique by construction (`name` is unique per test).
fn key_file(name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::temp_dir().join(format!(
        "llm-proxy-simple-config-tenant-kek-{name}-{}",
        std::process::id()
    ));
    std::fs::write(&path, [7u8; 32].as_slice()).expect("write key file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod key file");
    path
}

/// Strict load: lowered config passes the proto validation and builds IR.
fn strict_load_accepts(config: &SimpleConfig) -> proxy_config::ConfigSnapshot {
    let loaded = lower_to_loaded(config).expect("must lower and strict-validate");
    proxy_config::build_snapshot(&loaded).expect("must build IR")
}

/// Hands the lowered `llmproxy.auth` typed config to the REAL
/// `AuthFilterFactory::create`, which is what loads the key ring.
fn real_filter_accepts(snapshot: &proxy_config::ConfigSnapshot) {
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
    let typed = auth_entry
        .config
        .as_ref()
        .expect("the auth filter's typed_config must survive to the IR");
    AuthFilterFactory
        .create(typed, &FactoryContext::default())
        .expect("the real auth_filter::parse_config must accept the lowered key ring");
}

/// The `auth:` block for a config whose key ring points at `current` (and
/// optionally one previous key), with the operator HMAC secret. Tenant
/// credentials need the persistent store (ADR-0007), so the block selects one
/// at `{current}.redb`, beside the key file in the temp dir.
fn auth_block(current: &str, previous: Option<(&str, &str)>) -> String {
    let mut block = format!(
        "auth:\n  hmac_secret: \"test-operator-secret\"\n  \
         store:\n    persistent:\n      path: \"{current}.redb\"\n  \
         tenant_credentials:\n    \
         encryption_key_file: \"{current}\"\n    encryption_key_id: \"kek-2026\"\n"
    );
    if let Some((id, file)) = previous {
        block.push_str(&format!(
            "    previous_keys:\n      - {{ id: \"{id}\", file: \"{file}\" }}\n"
        ));
    }
    block
}

// --- 1: each provider type's slot shape, as a whole value --------------------

/// Every header API-key provider type, opted in. The slot names the provider
/// label and the same header and prefix the operator key would use. No
/// operator `api_key` is set, so the only credential headers are the slot's
/// own (which is what a tenant-only provider looks like).
#[test]
fn each_header_api_key_type_gets_its_slot_shape_in_the_cluster_metadata() {
    let key = key_file("slot-shapes");
    let text = format!(
        "version: 0\n\
         providers:\n\
         \x20 openai: {{ type: openai, tenant_credentials: true }}\n\
         \x20 anthropic: {{ type: anthropic, tenant_credentials: true }}\n\
         \x20 compat: {{ type: openai-compatible, base_url: \"https://llm.example.com\", tenant_credentials: true }}\n\
         \x20 openrouter: {{ type: openrouter, tenant_credentials: true }}\n\
         \x20 azure: {{ type: azure-openai, base_url: \"https://azure.example.com\", deployment: dep, api_version: \"2024-06-01\", tenant_credentials: true }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         {auth}",
        auth = auth_block(&key.display().to_string(), None),
    );
    let bootstrap = lower_text(&text).expect("must lower");
    std::fs::remove_file(&key).ok();

    assert_eq!(
        provider_auth(&bootstrap, "provider:openai"),
        &serde_json::json!({
            "headers": [{ "key": "host", "value": "api.openai.com" }],
            "models": [],
            "tenant_credential": {
                "provider": "openai",
                "header": "authorization",
                "prefix": "Bearer ",
            },
        })
    );
    assert_eq!(
        provider_auth(&bootstrap, "provider:anthropic"),
        &serde_json::json!({
            "headers": [
                { "key": "anthropic-version", "value": "2023-06-01" },
                { "key": "host", "value": "api.anthropic.com" },
            ],
            "models": [],
            "tenant_credential": {
                "provider": "anthropic",
                "header": "x-api-key",
                "prefix": "",
            },
        })
    );
    assert_eq!(
        provider_auth(&bootstrap, "provider:compat"),
        &serde_json::json!({
            "headers": [{ "key": "host", "value": "llm.example.com" }],
            "models": [],
            "tenant_credential": {
                "provider": "compat",
                "header": "authorization",
                "prefix": "Bearer ",
            },
        })
    );
    assert_eq!(
        provider_auth(&bootstrap, "provider:openrouter"),
        &serde_json::json!({
            "headers": [{ "key": "host", "value": "openrouter.ai" }],
            "models": [],
            "tenant_credential": {
                "provider": "openrouter",
                "header": "authorization",
                "prefix": "Bearer ",
            },
        })
    );
    assert_eq!(
        provider_auth(&bootstrap, "provider:azure"),
        &serde_json::json!({
            "headers": [{ "key": "host", "value": "azure.example.com" }],
            "models": [],
            "tenant_credential": {
                "provider": "azure",
                "header": "api-key",
                "prefix": "",
            },
        })
    );
}

// --- 2: Vertex and Bedrock cannot opt in -----------------------------------

#[test]
fn vertex_and_bedrock_opt_in_is_rejected_at_the_opt_in_field() {
    let key = key_file("reject-oauth-sigv4");
    let auth = auth_block(&key.display().to_string(), None);
    let cases = [
        (
            "  vertex-us: { type: vertex, base_url: \"https://us-central1-aiplatform.googleapis.com\", project: p, location: us-central1, publisher: google, access_token: tok, tenant_credentials: true }\n",
            "providers.vertex-us.tenant_credentials",
        ),
        (
            "  bedrock-us: { type: bedrock, base_url: \"https://bedrock-runtime.us-east-1.amazonaws.com\", region: us-east-1, access_key_id: AKIAEXAMPLE, secret_access_key: sek, tenant_credentials: true }\n",
            "providers.bedrock-us.tenant_credentials",
        ),
    ];
    for (provider, expected) in cases {
        let text = format!(
            "version: 0\nproviders:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n{provider}\
             routes:\n  - {{ model: \"*\", provider: openai }}\n{auth}"
        );
        match lower_text(&text).expect_err("must be rejected") {
            ConfigError::InvalidValue { field_path, reason } => {
                assert_eq!(field_path, expected);
                assert!(
                    reason.contains("OAuth2 or SigV4"),
                    "reason must name the auth mechanism, got {reason}"
                );
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }
    std::fs::remove_file(&key).ok();
}

// --- 3: opting in needs the key ring ---------------------------------------

#[test]
fn opt_in_without_a_key_ring_is_rejected_at_the_opt_in_field() {
    // An `auth:` block with no `tenant_credentials`, then no `auth:` at all.
    let no_ring =
        "version: 0\nproviders:\n  anthropic: { type: anthropic, tenant_credentials: true }\n\
         routes:\n  - { model: \"*\", provider: anthropic }\n\
         auth:\n  hmac_secret: \"test-operator-secret\"\n";
    let no_auth =
        "version: 0\nproviders:\n  anthropic: { type: anthropic, tenant_credentials: true }\n\
         routes:\n  - { model: \"*\", provider: anthropic }\n";
    for text in [no_ring, no_auth] {
        match lower_text(text).expect_err("must be rejected") {
            ConfigError::InvalidValue { field_path, reason } => {
                assert_eq!(field_path, "providers.anthropic.tenant_credentials");
                assert!(
                    reason.contains("auth.tenant_credentials"),
                    "reason must name the key ring, got {reason}"
                );
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }
}

// --- 4: the key ring lowers into llmproxy.auth, and the real filter loads it

#[test]
fn key_ring_block_lowers_verbatim_into_typed_config_and_the_real_filter_loads_it() {
    let current = key_file("ring-current");
    let previous = key_file("ring-previous");
    let text = format!(
        "version: 0\nproviders:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n{auth}",
        auth = auth_block(
            &current.display().to_string(),
            Some(("kek-2025", &previous.display().to_string())),
        ),
    );
    let config = parse(&text).expect("must parse");
    let lowered = lower(&config).expect("must lower");
    let typed = &http_filters(&lowered.bootstrap)[0]["typed_config"];
    assert_eq!(
        typed["tenant_credentials"],
        serde_json::json!({
            "encryption_key_file": current.display().to_string(),
            "encryption_key_id": "kek-2026",
            "previous_keys": [{
                "id": "kek-2025",
                "file": previous.display().to_string(),
            }],
        })
    );

    let snapshot = strict_load_accepts(&config);
    real_filter_accepts(&snapshot);
    std::fs::remove_file(&current).ok();
    std::fs::remove_file(&previous).ok();
}

/// A key ring with no opted-in provider is allowed and adds no slot anywhere.
#[test]
fn key_ring_without_an_opted_in_provider_adds_no_slot() {
    let key = key_file("ring-no-opt-in");
    let text = format!(
        "version: 0\nproviders:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n{auth}",
        auth = auth_block(&key.display().to_string(), None),
    );
    let bootstrap = lower_text(&text).expect("must lower");
    assert!(provider_auth(&bootstrap, "provider:openai")
        .get("tenant_credential")
        .is_none());
    std::fs::remove_file(&key).ok();
}

// --- 5: required and non-empty checks name their dotted path ---------------

#[test]
fn missing_or_empty_key_ring_fields_are_rejected_at_their_dotted_paths() {
    let key = key_file("ring-required").display().to_string();
    let cases: [(&str, &str, &str); 4] = [
        (
            "auth:\n  hmac_secret: \"s\"\n  tenant_credentials:\n    encryption_key_id: \"kek\"\n",
            "auth.tenant_credentials.encryption_key_file",
            "is required",
        ),
        (
            &format!(
                "auth:\n  hmac_secret: \"s\"\n  tenant_credentials:\n    \
                 encryption_key_file: \"{key}\"\n    encryption_key_id: \"\"\n"
            ),
            "auth.tenant_credentials.encryption_key_id",
            "must not be empty",
        ),
        (
            &format!(
                "auth:\n  hmac_secret: \"s\"\n  tenant_credentials:\n    \
                 encryption_key_file: \"{key}\"\n    encryption_key_id: \"kek\"\n    \
                 previous_keys:\n      - {{ id: \"old\", file: \"\" }}\n"
            ),
            "auth.tenant_credentials.previous_keys[0].file",
            "must not be empty",
        ),
        (
            &format!(
                "auth:\n  hmac_secret: \"s\"\n  tenant_credentials:\n    \
                 encryption_key_file: \"{key}\"\n    encryption_key_id: \"kek\"\n    \
                 previous_keys:\n      - {{ id: \"old\", file: \"{key}\" }}\n      - {{ file: \"{key}\" }}\n"
            ),
            "auth.tenant_credentials.previous_keys[1].id",
            "is required",
        ),
    ];
    for (auth, expected, reason_part) in cases {
        let text = format!(
            "version: 0\nproviders:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
             routes:\n  - {{ model: \"*\", provider: openai }}\n{auth}"
        );
        match lower_text(&text).expect_err("must be rejected") {
            ConfigError::InvalidValue { field_path, reason } => {
                assert_eq!(field_path, expected);
                assert!(reason.contains(reason_part), "got {reason}");
            }
            other => panic!("expected InvalidValue at {expected}, got {other:?}"),
        }
    }
    std::fs::remove_file(&key).ok();
}

// --- 6: unknown fields are rejected with the full dotted path -------------

#[test]
fn unknown_fields_are_rejected_with_the_full_dotted_path_in_both_places() {
    let key = key_file("unknown-fields").display().to_string();

    let provider_typo = format!(
        "version: 0\nproviders:\n  openai: {{ api_key: ${{OPENAI_API_KEY}}, tenant_credential: true }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n{}",
        auth_block(&key, None)
    );
    let ring_typo = format!(
        "version: 0\nproviders:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         auth:\n  hmac_secret: \"s\"\n  tenant_credentials:\n    \
         encryption_key_fil: \"{key}\"\n    encryption_key_id: \"kek\"\n"
    );
    let previous_typo = format!(
        "version: 0\nproviders:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         auth:\n  hmac_secret: \"s\"\n  tenant_credentials:\n    \
         encryption_key_file: \"{key}\"\n    encryption_key_id: \"kek\"\n    \
         previous_keys:\n      - {{ id: \"old\", file: \"{key}\", fil: \"x\" }}\n"
    );

    let cases = [
        (provider_typo, "providers.openai.tenant_credential"),
        (ring_typo, "auth.tenant_credentials.encryption_key_fil"),
        (
            previous_typo,
            "auth.tenant_credentials.previous_keys[0].fil",
        ),
    ];
    for (text, expected) in cases {
        match parse(&text).expect_err("unknown field must be rejected") {
            ConfigError::UnknownField { field_path, .. } => {
                assert_eq!(field_path, expected);
            }
            other => panic!("expected UnknownField at {expected}, got {other:?}"),
        }
    }
    std::fs::remove_file(&key).ok();
}

// --- 7: absent fields lower byte-identically -------------------------------

/// A config with no tenant fields, pinned as whole values. Any drift in the
/// operator path (a stray `tenant_credential` key, an added empty
/// `tenant_credentials` member) fails here.
#[test]
fn absent_tenant_fields_lower_byte_identical_to_the_pre_feature_output() {
    let secret = "test-operator-secret";
    let text = format!(
        "version: 0\nproviders:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n\
         auth:\n  hmac_secret: \"{secret}\"\n  keys: []\n"
    );
    let bootstrap = lower_text(&text).expect("must lower");

    assert_eq!(
        provider_auth(&bootstrap, "provider:openai"),
        &serde_json::json!({
            "headers": [
                { "key": "authorization", "value": "Bearer sk-test-openai" },
                { "key": "host", "value": "api.openai.com" },
            ],
            "models": [],
        })
    );
    assert_eq!(
        http_filters(&bootstrap)[0],
        serde_json::json!({
            "name": "llmproxy.auth",
            "typed_config": {
                "@type": proxy_filters::auth_filter::TYPE_URL,
                "hmac_secret": { "inline_string": secret },
                "virtual_keys": [],
            }
        })
    );
}

// --- 8: the slot and the ring reach the IR the data plane reads -----------

#[test]
fn the_slot_reaches_the_ir_cluster_and_the_ring_reaches_the_filter() {
    let key = key_file("ir-reach");
    let text = format!(
        "version: 0\nproviders:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         \x20 anthropic: {{ type: anthropic, tenant_credentials: true }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n  - {{ model: \"claude-*\", provider: anthropic }}\n{auth}",
        auth = auth_block(&key.display().to_string(), None),
    );
    let config = parse(&text).expect("must parse");
    let snapshot = strict_load_accepts(&config);

    let slot = snapshot.clusters["provider:anthropic"]
        .provider_runtime
        .as_ref()
        .and_then(|runtime| runtime.tenant_credential.clone())
        .expect("anthropic's cluster must carry the tenant credential slot");
    assert_eq!(
        slot,
        proxy_config::ir::TenantCredentialSlot {
            provider: "anthropic".to_string(),
            header: "x-api-key".to_string(),
            value_prefix: String::new(),
            verify_path: None,
        }
    );
    let openai_slot = snapshot.clusters["provider:openai"]
        .provider_runtime
        .as_ref()
        .and_then(|runtime| runtime.tenant_credential.as_ref());
    assert!(
        openai_slot.is_none(),
        "openai did not opt in and must carry no slot"
    );
    real_filter_accepts(&snapshot);
    std::fs::remove_file(&key).ok();
}

// --- 9: `--mode translate` carries both, and round-trips through strict load

#[test]
fn translate_output_carries_the_slot_and_the_ring_and_round_trips() {
    let previous = key_file("translate-previous");
    let current = key_file("translate-current");
    let text = format!(
        "version: 0\nproviders:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         \x20 openrouter: {{ type: openrouter, tenant_credentials: true }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n{auth}",
        auth = auth_block(
            &current.display().to_string(),
            Some(("kek-2025", &previous.display().to_string())),
        ),
    );
    let config = parse(&text).expect("must parse");
    let (yaml, _warnings) = proxy_simple_config::to_envoy_yaml(&config).expect("must translate");

    let doc: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("translate output is YAML");
    let clusters = doc["static_resources"]["clusters"]
        .as_sequence()
        .expect("clusters must be a sequence");
    let openrouter = clusters
        .iter()
        .find(|c| c["name"].as_str() == Some("provider:openrouter"))
        .expect("openrouter cluster");
    assert_eq!(
        openrouter["metadata"]["filter_metadata"]["io.llmproxy.provider_auth"]["tenant_credential"]
            ["header"]
            .as_str(),
        Some("authorization")
    );
    assert_eq!(
        openrouter["metadata"]["filter_metadata"]["io.llmproxy.provider_auth"]["tenant_credential"]
            ["prefix"]
            .as_str(),
        Some("Bearer ")
    );

    let typed = &doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"]["http_filters"][0]["typed_config"];
    assert_eq!(
        typed["tenant_credentials"]["encryption_key_id"].as_str(),
        Some("kek-2026")
    );
    assert_eq!(
        typed["tenant_credentials"]["previous_keys"][0]["id"].as_str(),
        Some("kek-2025")
    );

    let loaded = proxy_config::parse_bootstrap(
        yaml.as_bytes(),
        proxy_config::ConfigFormat::Yaml,
        proxy_config::StrictMode::Strict,
    )
    .expect("translate output must be strict-valid Envoy config");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("and must build IR");
    real_filter_accepts(&snapshot);

    std::fs::remove_file(&current).ok();
    std::fs::remove_file(&previous).ok();
}

// --- 8: tenant credentials require the persistent store --------------------

/// An `auth:` block with a key ring and the given `store:` block (empty for
/// no store at all). Lowering never connects, so the `shared` URL is inert.
fn auth_with_store(store: &str, key: &str) -> String {
    format!(
        "auth:\n  hmac_secret: \"test-operator-secret\"\n{store}  \
         tenant_credentials:\n    encryption_key_file: \"{key}\"\n    \
         encryption_key_id: \"kek-2026\"\n"
    )
}

/// Absent, `in_memory` and `shared` stores are each a load error at
/// `auth.tenant_credentials`, with the reason naming the requirement. The
/// `providers.<name>.tenant_credentials: true` opt-in reaches the same error,
/// because it needs the ring.
#[test]
fn tenant_credentials_without_a_persistent_store_is_rejected_at_the_block() {
    let key = key_file("store-required").display().to_string();
    let stores = [
        ("", "an absent store"),
        ("  store:\n    in_memory: {}\n", "an in_memory store"),
        (
            "  store:\n    shared:\n      url: \"redis://127.0.0.1:6390/0\"\n",
            "a shared store",
        ),
    ];
    for (store, label) in stores {
        let text = format!(
            "version: 0\nproviders:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
             routes:\n  - {{ model: \"*\", provider: openai }}\n{}",
            auth_with_store(store, &key)
        );
        match lower_text(&text).expect_err("must be rejected") {
            ConfigError::InvalidValue { field_path, reason } => {
                assert_eq!(field_path, "auth.tenant_credentials", "{label}");
                assert!(
                    reason.contains("tenant credentials require the persistent store"),
                    "{label}: got {reason}"
                );
            }
            other => panic!("{label}: expected InvalidValue, got {other:?}"),
        }
    }

    let opt_in = format!(
        "version: 0\nproviders:\n  openai: {{ api_key: ${{OPENAI_API_KEY}}, tenant_credentials: true }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n{}",
        auth_with_store("  store:\n    in_memory: {}\n", &key)
    );
    match lower_text(&opt_in).expect_err("an opt-in on an in_memory store must be rejected") {
        ConfigError::InvalidValue { field_path, .. } => {
            assert_eq!(field_path, "auth.tenant_credentials");
        }
        other => panic!("expected InvalidValue, got {other:?}"),
    }
    std::fs::remove_file(&key).ok();
}

/// The persistent store is the one that loads: it lowers, the strict loader
/// accepts it, and the real auth filter opens the ring against it.
#[test]
fn tenant_credentials_with_a_persistent_store_lowers_and_loads() {
    let key = key_file("store-persistent");
    let db = key.with_extension("redb");
    let text = format!(
        "version: 0\nproviders:\n  openai: {{ api_key: ${{OPENAI_API_KEY}} }}\n\
         routes:\n  - {{ model: \"*\", provider: openai }}\n{}",
        auth_with_store(
            &format!(
                "  store:\n    persistent:\n      path: \"{}\"\n",
                db.display()
            ),
            &key.display().to_string(),
        )
    );
    let config = parse(&text).expect("must parse");
    let lowered = lower(&config).expect("a persistent store must lower");
    let typed = &http_filters(&lowered.bootstrap)[0]["typed_config"];
    assert_eq!(
        typed["persistent"]["path"].as_str(),
        Some(db.display().to_string().as_str())
    );
    assert!(typed["tenant_credentials"].is_object());

    let snapshot = strict_load_accepts(&config);
    real_filter_accepts(&snapshot);

    std::fs::remove_file(&key).ok();
    std::fs::remove_file(&db).ok();
}
