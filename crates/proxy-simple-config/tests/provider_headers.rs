//! Provider credential and `extra_headers` values are checked when the config
//! loads. The router cannot send a malformed header, so before this check it
//! dropped the credential on every request and the provider call went out
//! without it. Each source of a value (inline, `api_key_file`, `${ENV}`)
//! fails with its own dotted path, and no error quotes the value.

use proxy_config::ConfigError;
use proxy_simple_config::{lower_to_loaded, parse_simple_config_with_env};

const SECRET: &str = "sk-provider-headers-secret-0001";

/// Parses and lowers through the full Envoy-mode pipeline, as `--config` does.
fn load(text: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<(), ConfigError> {
    let config = parse_simple_config_with_env(text, env)?;
    lower_to_loaded(&config).map(|_| ())
}

fn no_env(_: &str) -> Option<String> {
    None
}

fn openai(provider_body: &str) -> String {
    format!(
        "version: 0\nproviders:\n  openai:\n{provider_body}routes:\n  - {{ model: \"*\", provider: openai }}\n"
    )
}

/// The field path of a load error, after asserting the error never renders
/// the secret.
fn failed_path(result: Result<(), ConfigError>) -> String {
    let err = result.expect_err("the config must not load");
    assert!(
        !err.to_string().contains(SECRET),
        "the error must not render the secret: {err}"
    );
    match err {
        ConfigError::InvalidValue { field_path, .. } => field_path,
        other => panic!("expected InvalidValue, got: {other}"),
    }
}

#[test]
fn an_inline_api_key_with_a_control_character_fails_at_api_key() {
    let text = openai(&format!("    api_key: \"{SECRET}\\u0001\"\n"));
    assert_eq!(
        failed_path(load(&text, &no_env)),
        "providers.openai.api_key"
    );
}

#[test]
fn a_key_file_with_an_embedded_newline_fails_at_api_key_file() {
    let dir =
        std::env::temp_dir().join(format!("llm-proxy-provider-headers-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("key");
    // A trailing newline is trimmed; one inside the value is not.
    std::fs::write(&file, format!("{SECRET}\nsecond-line\n")).unwrap();
    let text = openai(&format!("    api_key_file: {}\n", file.display()));
    let path = failed_path(load(&text, &no_env));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(path, "providers.openai.api_key_file");
}

/// YAML refuses a raw control character anywhere in the file, so an
/// interpolated one never reaches the field. The error names the variable
/// instead of a byte position, and still not the value.
#[test]
fn an_env_value_with_a_control_character_names_the_variable() {
    let text = openai("    api_key: ${PROVIDER_KEY}\n");
    let env = |name: &str| (name == "PROVIDER_KEY").then(|| format!("{SECRET}\u{1}"));
    let err = load(&text, &env).expect_err("the config must not load");
    let message = err.to_string();
    assert!(message.contains("PROVIDER_KEY"), "got: {message}");
    assert!(
        !message.contains(SECRET),
        "the error must not render the secret: {message}"
    );
}

#[test]
fn an_env_sourced_extra_header_name_that_is_not_a_token_fails_at_its_key() {
    let text = openai("    api_key: k\n    extra_headers: { \"${HEADER}\": v }\n");
    let env = |name: &str| (name == "HEADER").then(|| "x org id".to_string());
    assert_eq!(
        failed_path(load(&text, &env)),
        "providers.openai.extra_headers.x org id"
    );
}

#[test]
fn an_extra_header_value_with_a_control_character_fails_at_its_key() {
    let text = openai(&format!(
        "    api_key: k\n    extra_headers: {{ x-api-key-2: \"{SECRET}\\r\\nx-injected: 1\" }}\n"
    ));
    assert_eq!(
        failed_path(load(&text, &no_env)),
        "providers.openai.extra_headers.x-api-key-2"
    );
}

/// `host` is set from `base_url` after `extra_headers`, so a value here would
/// be replaced without a word.
#[test]
fn host_in_extra_headers_is_refused() {
    let text = openai("    extra_headers: { Host: other.example }\n");
    assert_eq!(
        failed_path(load(&text, &no_env)),
        "providers.openai.extra_headers.Host"
    );
}

/// `extra_headers` applies after the key, so the same header there would
/// replace the configured credential.
#[test]
fn the_providers_own_credential_header_in_extra_headers_is_refused() {
    let anthropic = format!(
        "version: 0\nproviders:\n  anthropic:\n    api_key: k\n    extra_headers: {{ X-Api-Key: \"{SECRET}\" }}\nroutes:\n  - {{ model: \"*\", provider: anthropic }}\n"
    );
    assert_eq!(
        failed_path(load(&anthropic, &no_env)),
        "providers.anthropic.extra_headers.X-Api-Key"
    );
    let openai = openai(&format!(
        "    api_key: k\n    extra_headers: {{ authorization: \"Bearer {SECRET}\" }}\n"
    ));
    assert_eq!(
        failed_path(load(&openai, &no_env)),
        "providers.openai.extra_headers.authorization"
    );
}

/// Without a configured key, a credential in `extra_headers` is the only
/// one, so it stays allowed (`CREDENTIAL_HEADER_NAMES` redacts it).
#[test]
fn a_credential_header_in_extra_headers_without_an_api_key_loads() {
    let text = format!(
        "version: 0\nproviders:\n  other:\n    type: openai-compatible\n    base_url: http://127.0.0.1:9\n    extra_headers: {{ authorization: \"Bearer {SECRET}\" }}\nroutes:\n  - {{ model: \"*\", provider: other }}\n"
    );
    load(&text, &no_env).expect("a sole credential in extra_headers must load");
}
