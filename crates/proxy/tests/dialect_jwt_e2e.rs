//! `auth.jwt` (ADR-0014) on the real binary in `--config` mode: a valid
//! token reaches the provider; an expired, wrong-issuer, wrong-audience or
//! unmapped-tenant token gets 401; a validly signed token whose tenant has no
//! grant gets 403 and is never admitted as `default`. The discovery case
//! serves the OIDC document and JWKS from a loopback HTTPS server the test
//! owns, so nothing leaves the machine.
//!
//! Rust note: same harness shape as `tests/tenant_enforcement_e2e.rs` (std
//! threads, ephemeral ports, a `Drop` that kills the proxy). Every wait is
//! bounded, so a hung child fails the test instead of stalling it.

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const ADMIN_TOKEN: &str = "dialect-jwt-e2e-admin-token";
const ISSUER: &str = "https://idp.test";
const AUDIENCE: &str = "api://llm-proxy";
const KID: &str = "k1";
/// Mapped and granted every model.
const GRANTED_TENANT: &str = "acme";
/// Mapped, but no model policy is ever stored for it.
const UNGRANTED_TENANT: &str = "beta";

/// A throwaway 2048-bit RSA key, used only to sign test tokens. Embedded
/// rather than generated: `rsa` key generation takes seconds in a debug build.
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

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
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

/// Valid claims for `issuer`, with `overrides` layered on top.
fn claims(issuer: &str, tid: &str, overrides: serde_json::Value) -> serde_json::Value {
    let mut claims = serde_json::json!({
        "iss": issuer,
        "aud": AUDIENCE,
        "exp": now() + 3600,
        "tid": tid,
        "oid": "00000000-0000-0000-0000-00000000a11c",
    });
    for (k, v) in overrides.as_object().expect("overrides is an object") {
        claims[k] = v.clone();
    }
    claims
}

/// The `auth.jwt` entry shared by both tests; `jwks` is the flow-style
/// `jwks:` value.
fn jwt_entry(issuer: &str, jwks: &str) -> String {
    format!(
        "  jwt:\n\
         \x20   - issuer: \"{issuer}\"\n\
         \x20     audience: \"{AUDIENCE}\"\n\
         \x20     jwks: {jwks}\n\
         \x20     tenant:\n\
         \x20       claim: tid\n\
         \x20       values: {{ tid-acme: {GRANTED_TENANT}, tid-beta: {UNGRANTED_TENANT} }}\n\
         \x20     user: {{ claim: oid }}\n"
    )
}

/// The status line of each case, and whether it reached the provider.
#[test]
fn a_valid_token_reaches_the_provider_and_every_bad_token_is_refused() {
    let key = signing_key();
    let dir = scratch_dir("static");
    let upstream = Upstream::spawn();
    let jwks = format!(
        "{{ keys: [ {{ kid: {KID}, n: \"{}\", e: \"{}\" }} ] }}",
        key.n, key.e
    );
    let proxy = Proxy::start(&dir, &config_text(&upstream, &jwt_entry(ISSUER, &jwks)));
    grant_all_models(&proxy, GRANTED_TENANT);

    let valid = chat(
        &proxy,
        &sign(&key, &claims(ISSUER, "tid-acme", serde_json::json!({}))),
    );
    assert!(valid.starts_with("HTTP/1.1 200"), "valid token:\n{valid}");
    assert_eq!(upstream.hits(), 1, "the valid token reached the provider");

    let refused = [
        (
            "expired",
            claims(
                ISSUER,
                "tid-acme",
                serde_json::json!({ "exp": now() - 3600 }),
            ),
            "HTTP/1.1 401",
        ),
        (
            "wrong issuer",
            claims("https://other-idp.test", "tid-acme", serde_json::json!({})),
            "HTTP/1.1 401",
        ),
        (
            "wrong audience",
            claims(
                ISSUER,
                "tid-acme",
                serde_json::json!({ "aud": "api://someone-else" }),
            ),
            "HTTP/1.1 401",
        ),
        (
            "unmapped tenant claim",
            claims(ISSUER, "tid-unknown", serde_json::json!({})),
            "HTTP/1.1 401",
        ),
        // The reserved tenant cannot be named by a claim value: it is not in
        // `tenant.values`, and lowering refuses it as a target.
        (
            "claim value `default`",
            claims(ISSUER, "default", serde_json::json!({})),
            "HTTP/1.1 401",
        ),
        // Validly signed and mapped, but the tenant has no grant: refused by
        // model policy, not admitted under some other tenant's grant.
        (
            "ungranted tenant",
            claims(ISSUER, "tid-beta", serde_json::json!({})),
            "HTTP/1.1 403",
        ),
    ];
    for (what, claims, expected) in refused {
        let response = chat(&proxy, &sign(&key, &claims));
        assert!(response.starts_with(expected), "{what}:\n{response}");
    }
    assert_eq!(
        upstream.hits(),
        1,
        "no refused token may reach the provider"
    );

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `jwks.discovery_url` with `trusted_ca_file`: the proxy fetches the OIDC
/// document and the JWKS from a loopback HTTPS server, then admits a token
/// signed by the published key.
#[test]
fn discovery_over_https_publishes_the_key_set_and_admits_a_valid_token() {
    let key = signing_key();
    let dir = scratch_dir("discovery");
    let upstream = Upstream::spawn();
    let idp = Idp::spawn(&key, &dir);
    let issuer = format!("https://localhost:{}", idp.port);
    let jwks = format!(
        "{{ discovery_url: \"{issuer}/.well-known/openid-configuration\", trusted_ca_file: \"{}\" }}",
        idp.ca_file.display()
    );
    let proxy = Proxy::start(&dir, &config_text(&upstream, &jwt_entry(&issuer, &jwks)));
    grant_all_models(&proxy, GRANTED_TENANT);

    // Until the first refresh lands every token is refused, so poll.
    let token = sign(&key, &claims(&issuer, "tid-acme", serde_json::json!({})));
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let response = loop {
        let response = chat(&proxy, &token);
        if response.starts_with("HTTP/1.1 200") || Instant::now() >= deadline {
            break response;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "a token signed by the discovered key must be admitted:\n{response}"
    );
    assert!(
        idp.jwks_fetches() >= 1,
        "the JWKS was fetched from the test server"
    );

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

/// The dialect file; `auth_extra` is appended inside the `auth` block.
fn config_text(upstream: &Upstream, auth_extra: &str) -> String {
    format!(
        r#"version: 0
listen: 127.0.0.1:{listen}
admin: 127.0.0.1:{admin}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
routes:
  - {{ model: "*", provider: openai }}
auth:
  hmac_secret: dialect-jwt-e2e-secret
{auth_extra}"#,
        listen = free_port(),
        admin = free_port(),
        upstream = upstream.addr,
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-dialect-jwt-e2e-{tag}-{}",
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
        assert!(
            wait_for_connectable(proxy.admin, STARTUP_TIMEOUT),
            "admin listener at {} did not become connectable in time",
            proxy.admin
        );
        assert!(
            wait_for_connectable(proxy.listen, STARTUP_TIMEOUT),
            "listener at {} did not become connectable in time",
            proxy.listen
        );
        proxy
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

/// Creates `tenant` and grants it every model.
fn grant_all_models(proxy: &Proxy, tenant: &str) {
    let created = http_request(
        "POST",
        proxy.admin,
        "/tenants",
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        &format!(r#"{{"tenant":"{tenant}"}}"#),
    );
    assert!(
        created.starts_with("HTTP/1.1 2"),
        "POST /tenants:\n{created}"
    );
    let put = http_request(
        "PUT",
        proxy.admin,
        &format!("/tenants/{tenant}/policy"),
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        r#"{"access":"all"}"#,
    );
    assert!(put.starts_with("HTTP/1.1 204"), "PUT policy:\n{put}");
}

fn chat(proxy: &Proxy, token: &str) -> String {
    http_request(
        "POST",
        proxy.listen,
        "/v1/chat/completions",
        Some(&format!("Bearer {token}")),
        r#"{"model":"gpt-4o-mini","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
    )
}

fn http_request(
    method: &str,
    addr: SocketAddr,
    path: &str,
    authorization: Option<&str>,
    body: &str,
) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    let auth = authorization
        .map(|a| format!("Authorization: {a}\r\n"))
        .unwrap_or_default();
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: proxy.local\r\n{auth}\
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
/// `stream`; returns the request line, or `None` if the peer went away.
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
    head.lines().next().map(str::to_owned)
}

/// A mock provider that answers every request `200 {}` and counts them.
struct Upstream {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl Upstream {
    fn spawn() -> Upstream {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
        let addr = listener.local_addr().expect("local addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let counter = Arc::clone(&counter);
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                    if read_request(&mut stream).is_none() {
                        return;
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                          Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                    );
                });
            }
        });
        Upstream { addr, hits }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// A loopback HTTPS identity provider: serves the OIDC discovery document
/// and a JWKS holding the test key, under a `localhost` certificate from a
/// CA written to `ca_file`.
struct Idp {
    port: u16,
    ca_file: PathBuf,
    jwks_fetches: Arc<AtomicUsize>,
}

impl Idp {
    fn spawn(key: &SigningKey, dir: &Path) -> Idp {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let mut ca_params = CertificateParams::new(Vec::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().expect("CA key");
        let ca = ca_params.self_signed(&ca_key).expect("self-sign CA");
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf = CertificateParams::new(vec!["localhost".to_string()])
            .expect("leaf params")
            .signed_by(&leaf_key, &ca, &ca_key)
            .expect("sign leaf");
        let ca_file = dir.join("idp-ca.pem");
        std::fs::write(&ca_file, ca.pem()).expect("write CA");

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(leaf.der().to_vec())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
                )
                .expect("server cert"),
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind IdP");
        let port = listener.local_addr().expect("local addr").port();
        let issuer = format!("https://localhost:{port}");
        let discovery = serde_json::json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks"),
        })
        .to_string();
        let jwks = serde_json::json!({
            "keys": [{ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID, "n": key.n, "e": key.e }],
        })
        .to_string();
        let jwks_fetches = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&jwks_fetches);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(tcp) = stream else { continue };
                let (tls, discovery, jwks, counter) = (
                    Arc::clone(&tls),
                    discovery.clone(),
                    jwks.clone(),
                    Arc::clone(&counter),
                );
                std::thread::spawn(move || {
                    let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
                    let Ok(conn) = rustls::ServerConnection::new(tls) else {
                        return;
                    };
                    let mut stream = rustls::StreamOwned::new(conn, tcp);
                    let Some(request_line) = read_request(&mut stream) else {
                        return;
                    };
                    let body = if request_line.contains(" /.well-known/openid-configuration ") {
                        discovery
                    } else if request_line.contains(" /jwks ") {
                        counter.fetch_add(1, Ordering::SeqCst);
                        jwks
                    } else {
                        let _ = stream.write_all(
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        return;
                    };
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                    stream.conn.send_close_notify();
                    let _ = stream.flush();
                });
            }
        });
        Idp {
            port,
            ca_file,
            jwks_fetches,
        }
    }

    fn jwks_fetches(&self) -> usize {
        self.jwks_fetches.load(Ordering::SeqCst)
    }
}
