//! The `oauth2-jwt-bearer` provider credential in Envoy mode:
//! `io.llmproxy.provider_auth.oauth2_jwt_bearer` lowers to
//! `ProviderCredential::OAuth2JwtBearer`, the key file is read and checked at
//! load, and every malformed shape fails with its dotted path (AGENTS.md
//! invariant 1).

use std::path::{Path, PathBuf};
use std::time::Duration;

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

/// A PKCS#8 PEM RSA key, generated once per build directory and reused, since
/// RSA key generation takes seconds in a debug build. Never committed.
fn key_file() -> PathBuf {
    use rsa::pkcs8::EncodePrivateKey;
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("oauth2-config-key.pem");
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

fn snapshot_from(yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

/// A provider cluster `p` with the given `oauth2_jwt_bearer` body (YAML, at
/// the block's indentation) and a token cluster `t`.
fn bootstrap(scheme_extra: &str, block: &str) -> String {
    format!(
        r#"
static_resources:
  clusters:
    - name: t
    - name: p
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            scheme: oauth2-jwt-bearer
{scheme_extra}            oauth2_jwt_bearer:
{block}
"#
    )
}

fn valid_block(key: &Path) -> String {
    format!(
        r#"              token_cluster: t
              token_url: "https://token.example.test/token"
              issuer: "svc@example.test"
              private_key_file: "{}"
              scopes: ["scope.a", "scope.b"]"#,
        key.display()
    )
}

#[test]
fn the_block_lowers_to_the_credential_with_generic_defaults() {
    let key = key_file();
    let snapshot = snapshot_from(&bootstrap("", &valid_block(&key))).expect("must lower");
    let cluster = snapshot.clusters.get("p").expect("provider cluster");
    let Some(ProviderCredential::OAuth2JwtBearer(oauth2)) = cluster
        .provider_runtime
        .as_ref()
        .and_then(|r| r.credential.as_ref())
    else {
        panic!("expected an OAuth2JwtBearer credential");
    };
    assert_eq!(oauth2.token_cluster, "t");
    assert_eq!(oauth2.issuer, "svc@example.test");
    assert_eq!(oauth2.scopes, ["scope.a", "scope.b"]);
    assert_eq!(
        oauth2.audience, "https://token.example.test/token",
        "the audience defaults to the token URL"
    );
    assert_eq!(oauth2.subject, None);
    assert_eq!(oauth2.assertion_lifetime, Duration::from_secs(3600));
    assert_eq!(oauth2.refresh_before, Duration::from_secs(300));
    assert_eq!(oauth2.request_timeout, Duration::from_secs(10));

    // The key never renders: not in the IR's Debug, which logs may carry.
    let pem = std::fs::read_to_string(&key).unwrap();
    let rendered = format!("{cluster:?}");
    assert!(!rendered.contains(pem.lines().nth(1).unwrap()));
    assert!(rendered.contains("RsaSigningKey(<redacted>)"));
}

#[test]
fn malformed_blocks_fail_with_their_dotted_path() {
    let key = key_file();
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let not_pem = dir.join("oauth2-not-a-key.pem");
    std::fs::write(&not_pem, "not a key").unwrap();
    let pkcs1 = dir.join("oauth2-pkcs1.pem");
    std::fs::write(
        &pkcs1,
        "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    let base =
        "static_resources.clusters[1].metadata.filter_metadata[\"io.llmproxy.provider_auth\"]";
    let block = valid_block(&key);
    let swap = |from: &str, to: &str| block.replace(from, to);
    let cases: Vec<(&str, String, String, &str)> = vec![
        (
            "unknown field",
            String::new(),
            format!("{block}\n              bogus: 1"),
            "oauth2_jwt_bearer.bogus",
        ),
        (
            "missing token_cluster",
            String::new(),
            swap("              token_cluster: t\n", ""),
            "oauth2_jwt_bearer.token_cluster",
        ),
        (
            "relative token_url",
            String::new(),
            swap("https://token.example.test/token", "/token"),
            "oauth2_jwt_bearer.token_url",
        ),
        (
            "missing key file",
            String::new(),
            swap(&key.display().to_string(), "/nonexistent/key.pem"),
            "oauth2_jwt_bearer.private_key_file",
        ),
        (
            "key file that is not PEM",
            String::new(),
            swap(&key.display().to_string(), &not_pem.display().to_string()),
            "oauth2_jwt_bearer.private_key_file",
        ),
        (
            "PKCS#1 key",
            String::new(),
            swap(&key.display().to_string(), &pkcs1.display().to_string()),
            "oauth2_jwt_bearer.private_key_file",
        ),
        (
            "empty scopes",
            String::new(),
            swap(r#"["scope.a", "scope.b"]"#, "[]"),
            "oauth2_jwt_bearer.scopes",
        ),
        (
            "scope with a space",
            String::new(),
            swap(r#""scope.a""#, r#""scope a""#),
            "oauth2_jwt_bearer.scopes[0]",
        ),
        (
            "fractional seconds",
            String::new(),
            format!("{block}\n              refresh_before_seconds: 1.5"),
            "oauth2_jwt_bearer.refresh_before_seconds",
        ),
        (
            "unknown token cluster",
            String::new(),
            swap("token_cluster: t", "token_cluster: nowhere"),
            "oauth2_jwt_bearer.token_cluster",
        ),
        (
            "its own token cluster",
            String::new(),
            swap("token_cluster: t", "token_cluster: p"),
            "oauth2_jwt_bearer.token_cluster",
        ),
        (
            "a static token beside it",
            "            access_token: tok\n".to_string(),
            block.clone(),
            "access_token",
        ),
        (
            "a tenant credential beside it",
            "            tenant_credential: { provider: x, header: authorization }\n".to_string(),
            block.clone(),
            "tenant_credential",
        ),
    ];
    for (name, extra, body, suffix) in cases {
        let err = snapshot_from(&bootstrap(&extra, &body)).expect_err(name);
        let path = match &err {
            ConfigError::UnsupportedField { field_path, .. }
            | ConfigError::InvalidValue { field_path, .. } => field_path.clone(),
            other => panic!("{name}: expected a field-scoped error, got {other}"),
        };
        assert_eq!(path, format!("{base}.{suffix}"), "{name}: {err}");
    }

    // A missing block entirely names the block.
    let yaml = r#"
static_resources:
  clusters:
    - name: p
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            scheme: oauth2-jwt-bearer
"#;
    let err = snapshot_from(yaml).expect_err("block is required");
    assert!(err.to_string().contains("oauth2_jwt_bearer"), "{err}");
}
