//! `providers.<name>.oauth2_jwt_bearer` in the dialect: it lowers to the
//! `oauth2-jwt-bearer` credential plus a generated token-endpoint cluster with
//! verified TLS, the key file is read and checked at load, and every bad shape
//! fails with its dialect path (AGENTS.md invariant 1).

use std::path::{Path, PathBuf};
use std::time::Duration;

use proxy_config::ir::{ProviderCredential, ProviderPathTemplate, RsaSigningKey};
use proxy_config::ConfigError;
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config_with_env};

/// A PKCS#8 PEM RSA key, generated once per build directory and reused, since
/// RSA key generation takes seconds in a debug build. Never committed.
fn key_file() -> PathBuf {
    use rsa::pkcs8::EncodePrivateKey;
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("oauth2-dialect-key.pem");
    if let Ok(pem) = std::fs::read_to_string(&path) {
        if RsaSigningKey::from_pkcs8_pem(&pem).is_ok() {
            return path;
        }
    }
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("generate RSA key");
    let pem = key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("encode key");
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&tmp, pem.as_bytes()).expect("write key");
    std::fs::rename(&tmp, &path).expect("publish key");
    path
}

fn config(provider_type: &str, extra: &str, oauth2: &str) -> String {
    format!(
        r#"
version: 1
providers:
  vertex:
    type: {provider_type}
    base_url: "https://vertex.example.test"
    project: project-a
    location: us-central1
    publisher: anthropic
{extra}    oauth2_jwt_bearer:
{oauth2}
routes:
  - {{ model: "*", provider: vertex }}
models:
  claude-*:
    providers:
      - {{ provider: vertex, model: claude-upstream, dialect: anthropic }}
"#
    )
}

fn block(key: &Path) -> String {
    format!(
        r#"      token_url: "https://token.example.test/oauth2/token"
      issuer: "svc@example.test"
      subject: "user@example.test"
      private_key_file: "{}"
      scopes: ["scope.a"]
      refresh_before: 10m
      timeout: 5s"#,
        key.display()
    )
}

/// Parse and lower, returning the first error.
fn load(text: &str) -> Result<proxy_config::ConfigSnapshot, ConfigError> {
    let config = parse_simple_config_with_env(text, &|_| None)?;
    let loaded = lower_to_loaded(&config)?;
    proxy_config::build_snapshot(&loaded)
}

#[test]
fn the_block_lowers_to_a_minted_credential_and_a_verified_token_cluster() {
    let key = key_file();
    let text = config("vertex", "", &block(&key));
    let snapshot = load(&text).expect("must load");

    let runtime = snapshot.clusters["provider:vertex"]
        .provider_runtime
        .as_ref()
        .expect("provider runtime");
    let Some(ProviderCredential::OAuth2JwtBearer(oauth2)) = &runtime.credential else {
        panic!(
            "expected an OAuth2JwtBearer credential: {:?}",
            runtime.credential
        );
    };
    assert_eq!(oauth2.token_cluster, "oauth2-token:vertex");
    assert_eq!(oauth2.token_url, "https://token.example.test/oauth2/token");
    assert_eq!(oauth2.subject.as_deref(), Some("user@example.test"));
    assert_eq!(oauth2.refresh_before, Duration::from_secs(600));
    assert_eq!(oauth2.request_timeout, Duration::from_secs(5));
    assert!(matches!(
        runtime.path_template,
        Some(ProviderPathTemplate::Vertex { .. })
    ));
    assert!(snapshot.clusters.contains_key("oauth2-token:vertex"));

    // The token endpoint is verified like a provider: platform roots and a
    // SAN match on its host. A signed assertion must never reach an
    // unverified peer.
    let config = parse_simple_config_with_env(&text, &|_| None).unwrap();
    let bootstrap = lower(&config).unwrap().bootstrap;
    let token_cluster = bootstrap["static_resources"]["clusters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "oauth2-token:vertex")
        .expect("token cluster in the bootstrap");
    let tls = &token_cluster["transport_socket"]["typed_config"];
    assert_eq!(tls["sni"], "token.example.test");
    let validation = &tls["common_tls_context"]["validation_context"];
    assert!(
        validation.get("system_root_certs").is_some(),
        "{validation}"
    );
    assert_eq!(
        validation["match_typed_subject_alt_names"][0]["matcher"]["exact"],
        "token.example.test"
    );
    // The bootstrap carries the key's path, never its contents.
    let pem = std::fs::read_to_string(&key).unwrap();
    assert!(!bootstrap.to_string().contains(pem.lines().nth(1).unwrap()));
}

#[test]
fn bad_blocks_fail_with_their_dialect_path() {
    let key = key_file();
    let not_pem = Path::new(env!("CARGO_TARGET_TMPDIR")).join("oauth2-dialect-not-a-key.pem");
    std::fs::write(&not_pem, "not a key").unwrap();
    let good = block(&key);
    let swap = |from: &str, to: &str| good.replace(from, to);
    let base = "providers.vertex.oauth2_jwt_bearer";
    let cases: Vec<(&str, String, String, String)> = vec![
        (
            "plain http to a remote host",
            String::new(),
            swap("https://token.example.test", "http://token.example.test"),
            format!("{base}.token_url"),
        ),
        (
            "a static token beside it",
            "    access_token: tok\n".into(),
            good.clone(),
            base.to_string(),
        ),
        (
            "unknown field",
            String::new(),
            format!("{good}\n      bogus: 1"),
            format!("{base}.bogus"),
        ),
        (
            "empty scopes",
            String::new(),
            swap(r#"["scope.a"]"#, "[]"),
            format!("{base}.scopes"),
        ),
        (
            "a sub-second timeout",
            String::new(),
            swap("timeout: 5s", "timeout: 500ms"),
            format!("{base}.timeout"),
        ),
        (
            "ca_file for plain http",
            String::new(),
            format!(
                "{}\n      ca_file: /etc/ca.pem",
                swap("https://token.example.test", "http://127.0.0.1:9")
            ),
            format!("{base}.ca_file"),
        ),
        (
            "missing key file",
            String::new(),
            swap(&key.display().to_string(), "/nonexistent/key.pem"),
            format!("{base}.private_key_file"),
        ),
        (
            "a file that is not a key",
            String::new(),
            swap(&key.display().to_string(), &not_pem.display().to_string()),
            format!("{base}.private_key_file"),
        ),
    ];
    for (name, extra, body, path) in cases {
        let err = load(&config("vertex", &extra, &body)).expect_err(name);
        assert!(
            err.to_string().contains(&format!("`{path}`")),
            "{name}: expected the error to name `{path}`, got: {err}"
        );
    }

    let openai = format!(
        r#"
version: 1
providers:
  openai:
    type: openai
    api_key: sk-test
    oauth2_jwt_bearer:
{good}
routes:
  - {{ model: "*", provider: openai }}
"#
    );
    let err = load(&openai).expect_err("non-vertex provider");
    assert!(
        err.to_string()
            .contains("`providers.openai.oauth2_jwt_bearer`: is only valid for vertex providers"),
        "{err}"
    );

    // Plain http is accepted to a loopback token endpoint.
    load(&config(
        "vertex",
        "",
        &swap("https://token.example.test", "http://127.0.0.1:9"),
    ))
    .expect("loopback http token endpoint");
}
