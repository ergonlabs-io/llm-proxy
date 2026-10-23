//! A JWT principal whose tenant stored provider credentials (ADR-0007) is
//! sent upstream with that tenant's credential, exactly as a virtual key for
//! the same tenant is (ADR-0014 decision 2), and across failover each
//! attempt carries only its own provider's credential (AGENTS.md invariant
//! 6).
//!
//! Drives the real `llm-proxy` binary in `--config` mode: two
//! openai-compatible providers with tenant credential slots in one fallback
//! chain, a primary mock that always answers 500 (retriable) and a fallback
//! mock that answers 200, a persistent redb auth store and a 0600
//! key-encryption-key file. Assertions are on the raw request heads the mocks
//! received, so a credential sent on any header is seen.
//!
//! Rust note: same harness shape as `tests/dialect_jwt_e2e.rs` (std threads,
//! ephemeral ports, a `Drop` that kills the proxy). Every wait is bounded, so
//! a hung child fails the test instead of stalling it.

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const ADMIN_TOKEN: &str = "jwt-tenant-credentials-e2e-admin-token";
const ISSUER: &str = "https://idp.test";
const AUDIENCE: &str = "api://llm-proxy";
const KID: &str = "k1";
/// Holds a stored credential for both providers.
const BYOK_TENANT: &str = "acme";
/// Granted every model, holds no credential.
const PLATFORM_TENANT: &str = "beta";

const OPERATOR_PRIMARY: &str = "sk-operator-PRIMARY";
const OPERATOR_FALLBACK: &str = "sk-operator-FALLBACK";
const TENANT_PRIMARY: &str = "sk-tenant-PRIMARY";
const TENANT_FALLBACK: &str = "sk-tenant-FALLBACK";
const KEK: [u8; 32] = *b"e2e-kek-0123456789abcdef-padding";

/// The throwaway test key `tests/dialect_jwt_e2e.rs` signs with, used only to
/// sign test tokens. Embedded rather than generated: `rsa` key generation
/// takes seconds in a debug build.
const TEST_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDYUDpGMnANDY/X
tCa1gvJjkWkkpADwNKTbQlEBnE3vAo9eqFMap4zmNck07baJJjhhUVEoY/FoT5UN
3ZqrTD8ZlmzNhIsChSZ4rWF0vUSme6/sHBYyqCN/xBeJswyDwzgN5OGrcLWXidJP
lJWFfhvlf5gUjpV8S1Z+E1tdGkxQ8wm3I6LKtv7jFaCtuAGULOEf65ZgweSANOoI
CbM62M55d+mgvpCUkxO6jREOpACsrgh2ySJ6e+bGEkV3k6z9GgDMj4vvxAkaKihO
W0gw1aC2rKSXPXMB5Z9WqfefBqSIm+RLs6LTITt2NbyAj0/vmgyu8g89aoSJzSeU
QXi+7zbLAgMBAAECggEAE6i68G1IvLmfpI7QDngKV8fmjTjF3bl9xXA8qiT5T5W6
ekkEVdb7bw1dWMzv5X1j612iFBsn3Knlld8u3Y7uPyuU04V5GBoKJIvmtbQ2hzDq
N08C1MjDgoBLqVfsn78AGwHTDACQKGe+BZMvQZ9z9pgcNhC9VOYImX213yYdiyUD
TKof4glCbRU7jG2GugByNEnMifgE2xZxbgXISNc97zznrokFHTxyxsr7R7/peuvi
Qko4lJRfjn/B6afiL5VAl9mr3IseVHAcYMFDIomdhCC6aiXje8rsY2JTrwgVQmev
ezd6bYJIn9NTPUCQvV9Xw0PqNpbj5Kpd6/m7YmxVeQKBgQD1ST4ntZaEcTJcJpfz
TSO1yYi8QqNTJ/HJm3LfOLDj67jAavDpzT2lGFoMNvnqqgl0pks5p0hxFSudQJOQ
Wl7wE+dpU7VU3ZVUwyHEPhVYl1EluHFSpsyWxSgHNBTJS3BgiRzjfjXmjvxtghrQ
VAQRZGbkh8OVimsZeXA4vrREEwKBgQDhwwQGD44EIg8GBRdWoIdJhXMoAjNzFsaG
Y96K4sdmAmVe42/A+LVqI49cFyVPD1tPIYo29UW4fQuwUDIkGCC+KlYgSzKFAXFI
NqWjVS4uVK+XtEFFjhOsssXEUYnz1OE4Z6aSiDb6o54RGTY2cWk/S9jOHzNz07JC
q3Kn1A7paQKBgDUiobFOeAXG08b8oUwWeNbnipRlxyW7cHhhEVhj2oX1SXd9cyTi
zijWhqNAwZDhNt0rLP6XS20bze/pzk2mFgzh8u5xMMXqnm/XOZhebpdbaDvIodvq
wEUk/o/Y62vTyMtQyI5Lh/ejH/HFDnP0z1DJNDTraCYb7yl8kh/ox/o7AoGADqhZ
t4cFAnGvpgVomYA8qGJYsq1J59v/sbQEO+IzbgUTzdBYbh/3r1d1tFXwXyyxEfcs
gRr1lt/PhXf/eWZzocUf6GLZedc5IqYhpPQf1nQ7Hk9euYRa9Kh6vJ9KpKEaqk3Y
e8UKRMWgup13bpt4aNqkzeUqswd4mGmHPSxAd5kCgYAxv3Bet/w4C6x5FT2zjkug
/B22YsQI9QCRQ/Yo0Qb1vXbvLygOeCQEE8VGqW+J2mj0cMwJay1urDEwxvxrBV3r
S7PF7LBkZeSJ5SRmsa3bOnFZsSOilYDGBMDGTIwbNdZjY/QYxamBIiLVD+QfB5RI
R7gVFiRwVoeAS4UwnrS8NA==
-----END PRIVATE KEY-----
";

#[test]
fn a_byok_jwt_tenant_sends_only_each_providers_own_tenant_key_across_failover() {
    let key = signing_key();
    let dir = scratch_dir();
    let kek = dir.join("credential-kek");
    std::fs::write(&kek, KEK).expect("write kek");
    std::fs::set_permissions(&kek, std::fs::Permissions::from_mode(0o600)).expect("chmod kek");
    let primary = Upstream::spawn(500);
    let fallback = Upstream::spawn(200);
    let proxy = Proxy::start(&dir, &config_text(&primary, &fallback, &dir, &kek, &key));
    for tenant in [BYOK_TENANT, PLATFORM_TENANT] {
        proxy.admin(
            "POST",
            "/tenants",
            &format!(r#"{{"tenant":"{tenant}"}}"#),
            201,
        );
        proxy.admin(
            "PUT",
            &format!("/tenants/{tenant}/policy"),
            r#"{"access":"all"}"#,
            204,
        );
    }
    for (provider, secret) in [("primary", TENANT_PRIMARY), ("fallback", TENANT_FALLBACK)] {
        proxy.admin(
            "PUT",
            &format!("/tenants/{BYOK_TENANT}/provider_credentials/{provider}"),
            &format!(r#"{{"schema_version":1,"api_key":"{secret}","verify":false}}"#),
            200,
        );
    }
    let minted = proxy.admin(
        "POST",
        "/keys",
        &format!(r#"{{"tenant":"{BYOK_TENANT}","key_id":"acme-key"}}"#),
        201,
    );
    let virtual_key = serde_json::from_str::<serde_json::Value>(response_body(&minted))
        .expect("minted key JSON")["key"]
        .as_str()
        .expect("plaintext key")
        .to_string();

    // A BYOK tenant's JWT: the primary attempt carries the tenant's primary
    // key, the fallback attempt the tenant's fallback key, and neither
    // carries the other's key or an operator key alongside.
    let jwt = sign(&key, &claims("tid-acme"));
    let served = chat(&proxy, &format!("Bearer {jwt}"));
    assert!(served.starts_with("HTTP/1.1 200"), "BYOK JWT:\n{served}");
    let (to_primary, to_fallback) = (primary.take(), fallback.take());
    assert_eq!(to_primary.len(), 1, "one primary attempt");
    assert_eq!(to_fallback.len(), 1, "one fallback attempt");
    assert_only_credential(&to_primary[0], TENANT_PRIMARY);
    assert_only_credential(&to_fallback[0], TENANT_FALLBACK);

    // The same tenant's virtual key sends the same credentials: one rule.
    let keyed = chat(&proxy, &format!("Bearer {virtual_key}"));
    assert!(keyed.starts_with("HTTP/1.1 200"), "virtual key:\n{keyed}");
    assert_eq!(
        credential_headers(&primary.take()[0]),
        credential_headers(&to_primary[0])
    );
    assert_eq!(
        credential_headers(&fallback.take()[0]),
        credential_headers(&to_fallback[0])
    );

    // A tenant with no stored credential: the operator keys, as before.
    let platform = chat(
        &proxy,
        &format!("Bearer {}", sign(&key, &claims("tid-beta"))),
    );
    assert!(
        platform.starts_with("HTTP/1.1 200"),
        "platform JWT:\n{platform}"
    );
    assert_only_credential(&primary.take()[0], OPERATOR_PRIMARY);
    assert_only_credential(&fallback.take()[0], OPERATOR_FALLBACK);

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `head` carries `expected` as its bearer credential, on no other
/// credential header, and none of the other three secrets anywhere.
fn assert_only_credential(head: &str, expected: &str) {
    assert_eq!(
        credential_headers(head),
        vec![format!("authorization: Bearer {expected}")],
        "credential headers of:\n{head}"
    );
    for secret in [
        OPERATOR_PRIMARY,
        OPERATOR_FALLBACK,
        TENANT_PRIMARY,
        TENANT_FALLBACK,
    ] {
        if secret != expected {
            assert!(!head.contains(secret), "{secret} was sent in:\n{head}");
        }
    }
}

/// Every header of the three credential shapes ADR-0007 decision 5 clears.
fn credential_headers(head: &str) -> Vec<String> {
    head.lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            let name = name.trim().to_ascii_lowercase();
            ["authorization", "x-api-key", "api-key"]
                .contains(&name.as_str())
                .then(|| format!("{name}: {}", value.trim()))
        })
        .collect()
}

// ------------------------------------------------------------------ helpers --

struct SigningKey {
    pkcs1_der: Vec<u8>,
    n: String,
    e: String,
}

fn signing_key() -> SigningKey {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;

    let private = rsa::RsaPrivateKey::from_pkcs8_pem(TEST_KEY_PEM).expect("test key parses");
    SigningKey {
        pkcs1_der: private.to_pkcs1_der().expect("PKCS#1").as_bytes().to_vec(),
        n: URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
        e: URL_SAFE_NO_PAD.encode(private.e().to_bytes_be()),
    }
}

/// An RS256 token over `claims`, signed with the test key.
fn sign(key: &SigningKey, claims: &serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{KID}"}}"#));
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let message = format!("{header}.{payload}");
    let pair = ring::signature::RsaKeyPair::from_der(&key.pkcs1_der).expect("PKCS#1 DER");
    let mut signature = vec![0u8; pair.public().modulus_len()];
    pair.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        message.as_bytes(),
        &mut signature,
    )
    .expect("RS256 sign");
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn claims(tid: &str) -> serde_json::Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs();
    serde_json::json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
        "tid": tid,
        "oid": "00000000-0000-0000-0000-00000000a11c",
    })
}

fn config_text(
    primary: &Upstream,
    fallback: &Upstream,
    dir: &Path,
    kek: &Path,
    key: &SigningKey,
) -> String {
    format!(
        r#"version: 1
listen: 127.0.0.1:{listen}
admin: 127.0.0.1:{admin}
providers:
  primary:
    type: openai-compatible
    base_url: http://{primary}
    api_key: {OPERATOR_PRIMARY}
    tenant_credentials: true
  fallback:
    type: openai-compatible
    base_url: http://{fallback}
    api_key: {OPERATOR_FALLBACK}
    tenant_credentials: true
routes:
  - {{ model: "*", provider: primary, fallbacks: [fallback] }}
auth:
  hmac_secret: jwt-tenant-credentials-e2e-secret
  store:
    persistent: {{ path: "{db}" }}
  tenant_credentials:
    encryption_key_file: "{kek}"
    encryption_key_id: kek-1
  jwt:
    - issuer: "{ISSUER}"
      audience: "{AUDIENCE}"
      jwks: {{ keys: [ {{ kid: {KID}, n: "{n}", e: "{e}" }} ] }}
      tenant:
        claim: tid
        values: {{ tid-acme: {BYOK_TENANT}, tid-beta: {PLATFORM_TENANT} }}
      user: {{ claim: oid }}
"#,
        listen = free_port(),
        admin = free_port(),
        primary = primary.addr,
        fallback = fallback.addr,
        db = dir.join("control.redb").display(),
        kek = kek.display(),
        n = key.n,
        e = key.e,
    )
}

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-jwt-tenant-credentials-e2e-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// A running proxy. Killed and reaped on drop, so a failed assertion cannot
/// leave a listener behind (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    listen: SocketAddr,
    admin: SocketAddr,
}

impl Proxy {
    fn start(dir: &Path, config: &str) -> Proxy {
        let listen = port_after(config, "listen: 127.0.0.1:");
        let admin = port_after(config, "admin: 127.0.0.1:");
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).expect("write temp config");
        let child = Command::new(BIN)
            .args([
                "--config",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
            ])
            .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn llm-proxy");
        let proxy = Proxy {
            child,
            listen: SocketAddr::from(([127, 0, 0, 1], listen)),
            admin: SocketAddr::from(([127, 0, 0, 1], admin)),
        };
        for addr in [proxy.admin, proxy.listen] {
            assert!(
                wait_for_connectable(addr, STARTUP_TIMEOUT),
                "listener at {addr} did not become connectable in time"
            );
        }
        proxy
    }

    /// An admin call that must answer `status`; returns the whole response.
    fn admin(&self, method: &str, path: &str, body: &str, status: u16) -> String {
        let response = http_request(
            method,
            self.admin,
            path,
            &format!("Bearer {ADMIN_TOKEN}"),
            body,
        );
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{method} {path}:\n{response}"
        );
        response
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn port_after(config: &str, prefix: &str) -> u16 {
    config
        .split(prefix)
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|p| p.parse().ok())
        .expect("config names the listener")
}

fn chat(proxy: &Proxy, authorization: &str) -> String {
    http_request(
        "POST",
        proxy.listen,
        "/v1/chat/completions",
        authorization,
        r#"{"model":"gpt-4o-mini","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
    )
}

fn response_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
}

fn http_request(
    method: &str,
    addr: SocketAddr,
    path: &str,
    authorization: &str,
    body: &str,
) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: proxy.local\r\nAuthorization: {authorization}\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .expect("write request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

fn wait_for_connectable(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Reads one HTTP/1.1 request (head and `Content-Length` body) from
/// `stream`; returns the head, or `None` if the peer went away.
fn read_request(stream: &mut impl Read) -> Option<String> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let content_length: usize = head
        .to_ascii_lowercase()
        .lines()
        .find_map(|l| l.strip_prefix("content-length:").map(str::to_owned))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let mut have = raw.len() - (head_end + 4);
    while have < content_length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => have += n,
        }
    }
    Some(head)
}

/// A mock provider that answers every request with `status` and records
/// each request head.
struct Upstream {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Upstream {
    fn spawn(status: u16) -> Upstream {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
        let addr = listener.local_addr().expect("local addr");
        let heads = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&heads);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let recorded = Arc::clone(&recorded);
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                    let Some(head) = read_request(&mut stream) else {
                        return;
                    };
                    recorded.lock().expect("heads lock").push(head);
                    let body = if status == 200 {
                        r#"{"id":"c","object":"chat.completion","choices":[]}"#
                    } else {
                        r#"{"error":{"message":"mock failure"}}"#
                    };
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                });
            }
        });
        Upstream { addr, heads }
    }

    /// The heads recorded since the last call, in arrival order.
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.heads.lock().expect("heads lock"))
    }
}
