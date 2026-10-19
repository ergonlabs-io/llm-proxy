//! A Vertex provider whose access token the proxy mints itself with the
//! OAuth2 JWT-bearer grant (ADR-0005, amendment 2026-10-17), through the real
//! `llm-proxy` binary and a dialect config. The token endpoint and the
//! provider are local mocks; the RSA keys are generated for the test run, so
//! no real provider or credential is involved.
//!
//! Rust note: same harness shape as `tests/credential_forwarding_e2e.rs` (std
//! threads, ephemeral ports, a guard that kills the proxy on drop); each
//! `tests/*.rs` file is its own crate, so the helpers are duplicated.

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use proxy_config::ir::RsaSigningKey;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const WAIT: Duration = Duration::from_secs(10);

/// A PKCS#8 PEM RSA key named `name`, generated once per build directory and
/// reused, since RSA key generation takes seconds in a debug build.
fn test_key_pem(name: &str) -> String {
    use rsa::pkcs8::EncodePrivateKey;
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("oauth2-e2e-{name}.pem"));
    if let Ok(pem) = std::fs::read_to_string(&path) {
        if RsaSigningKey::from_pkcs8_pem(&pem).is_ok() {
            return pem;
        }
    }
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("generate RSA key");
    let pem = key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("encode key")
        .to_string();
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&tmp, &pem).expect("write key");
    std::fs::rename(&tmp, &path).expect("publish key");
    pem
}

/// Whether the RS256 JWT `assertion` verifies with `pem`'s public key.
fn signed_by(assertion: &str, pem: &str) -> bool {
    let Some((input, signature)) = assertion.rsplit_once('.') else {
        return false;
    };
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let der = RsaSigningKey::from_pkcs8_pem(pem).unwrap();
    let key = ring::signature::RsaKeyPair::from_pkcs8(der.pkcs8_der()).unwrap();
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        key.public().as_ref(),
    )
    .verify(input.as_bytes(), &signature)
    .is_ok()
}

/// One request as a mock saw it: request line, lowercased headers, body.
#[derive(Clone, Debug)]
struct Seen {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Seen> {
    stream.set_read_timeout(Some(WAIT)).ok()?;
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
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = raw[head_end + 4..].to_vec();
    while body.len() < length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&buf[..n]),
        }
    }
    Some(Seen {
        request_line,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) {
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
}

/// A token endpoint answering from a script whose replies can be swapped
/// mid-test. Every request is recorded.
struct TokenEndpoint {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    replies: Arc<Mutex<Vec<(u16, String)>>>,
}

fn token(access_token: &str) -> (u16, String) {
    (
        200,
        format!(r#"{{"access_token":"{access_token}","expires_in":3600,"token_type":"Bearer"}}"#),
    )
}

impl TokenEndpoint {
    fn spawn(replies: Vec<(u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind token endpoint");
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(replies));
        let (seen_t, replies_t) = (Arc::clone(&seen), Arc::clone(&replies));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(request) = read_request(&mut stream) else {
                    continue;
                };
                let index = {
                    let mut seen = seen_t.lock().unwrap();
                    seen.push(request);
                    seen.len() - 1
                };
                let (status, body) = {
                    let replies = replies_t.lock().unwrap();
                    replies[index.min(replies.len() - 1)].clone()
                };
                respond(&mut stream, status, &body);
            }
        });
        Self {
            addr,
            seen,
            replies,
        }
    }

    fn assertions(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|r| {
                r.body
                    .split_once("&assertion=")
                    .map(|(_, a)| a.to_string())
                    .unwrap_or_default()
            })
            .collect()
    }
}

/// A provider that records each request and answers `200 {}`.
fn spawn_provider() -> (SocketAddr, mpsc::Receiver<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind provider");
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || {
                if let Some(request) = read_request(&mut stream) {
                    let _ = tx.send(request);
                    respond(&mut stream, 200, "{}");
                }
            });
        }
    });
    (addr, rx)
}

struct Proxy {
    child: Child,
    port: u16,
    log: PathBuf,
}

impl Proxy {
    fn spawn(config: &Path, port: u16, log: PathBuf) -> Self {
        let out = std::fs::File::create(&log).expect("create log");
        let child = Command::new(BIN)
            .arg("--config")
            .arg(config)
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .expect("spawn llm-proxy");
        let proxy = Self { child, port, log };
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                Instant::now() < deadline,
                "proxy never listened; log:\n{}",
                proxy.log_text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        proxy
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn sighup(&self) {
        let status = Command::new("kill")
            .args(["-HUP", &self.child.id().to_string()])
            .status()
            .expect("kill -HUP");
        assert!(status.success());
    }

    /// One Messages request; returns the status line and body.
    fn send(&self) -> (String, String) {
        let body =
            r#"{"model":"claude-test","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#;
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        stream.set_read_timeout(Some(WAIT)).unwrap();
        stream
            .write_all(
                format!(
                    "POST /v1/messages HTTP/1.1\r\nHost: proxy.local\r\n\
                     Content-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .unwrap();
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        let response = String::from_utf8_lossy(&response).to_string();
        let status = response.lines().next().unwrap_or_default().to_string();
        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        (status, body)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "oauth2-e2e-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(port: u16, provider: SocketAddr, token: SocketAddr, key: &Path) -> String {
    format!(
        r#"
version: 0
listen: "127.0.0.1:{port}"
providers:
  vertex:
    type: vertex
    base_url: "http://{provider}"
    project: project-a
    location: us-central1
    publisher: anthropic
    oauth2_jwt_bearer:
      token_url: "http://{token}/token"
      issuer: "svc@example.test"
      private_key_file: "{}"
      scopes: ["scope.a"]
routes:
  - {{ model: "*", provider: vertex }}
models:
  claude-*:
    providers:
      - {{ provider: vertex, model: claude-upstream, dialect: anthropic }}
"#,
        key.display()
    )
}

/// The provider receives the token the proxy minted, on the Vertex path, and
/// the log never shows the token or the key.
#[test]
fn a_request_reaches_the_provider_with_the_minted_bearer() {
    let pem = test_key_pem("a");
    let scratch = Scratch::new("bearer");
    let key = scratch.write("key.pem", &pem);
    let tokens = TokenEndpoint::spawn(vec![token("minted-e2e-token-1")]);
    let (provider, received) = spawn_provider();
    let port = free_port();
    let path = scratch.write("llmproxy.yaml", &config(port, provider, tokens.addr, &key));
    let proxy = Proxy::spawn(&path, port, scratch.0.join("proxy.log"));

    let (status, body) = proxy.send();
    assert!(status.contains(" 200 "), "status {status}: {body}");
    let seen = received
        .recv_timeout(WAIT)
        .expect("provider got the request");
    assert_eq!(
        seen.header("authorization"),
        Some("Bearer minted-e2e-token-1")
    );
    assert!(
        seen.request_line.starts_with(
            "POST /v1/projects/project-a/locations/us-central1/publishers/anthropic/models/claude-upstream:"
        ),
        "Vertex path: {}",
        seen.request_line
    );

    let assertions = tokens.assertions();
    assert_eq!(assertions.len(), 1, "one mint at load, none per request");
    assert!(signed_by(&assertions[0], &pem));

    let log = proxy.log_text();
    let key_line = pem.lines().nth(1).expect("PEM body line");
    for secret in ["minted-e2e-token-1", key_line, assertions[0].as_str()] {
        assert!(!log.contains(secret), "the log leaked a secret:\n{log}");
    }
}

/// With no token minted, a request is refused locally with a finite reason
/// and never reaches the provider unauthenticated.
#[test]
fn with_no_token_a_request_fails_closed_without_reaching_the_provider() {
    let pem = test_key_pem("a");
    let scratch = Scratch::new("fail-closed");
    let key = scratch.write("key.pem", &pem);
    let tokens = TokenEndpoint::spawn(vec![(500, r#"{"error":"server_error"}"#.to_string())]);
    let (provider, received) = spawn_provider();
    let port = free_port();
    let path = scratch.write("llmproxy.yaml", &config(port, provider, tokens.addr, &key));
    let proxy = Proxy::spawn(&path, port, scratch.0.join("proxy.log"));

    let (status, body) = proxy.send();
    assert!(status.contains(" 503 "), "status {status}: {body}");
    // The local reply may be chunked; the reason is its whole text.
    assert!(
        body.contains("provider token unavailable"),
        "body: {body:?}"
    );
    assert!(
        received.recv_timeout(Duration::from_millis(500)).is_err(),
        "a request without a token must not reach the provider"
    );
    let log = proxy.log_text();
    assert!(log.contains("OAuth2 token mint failed"), "log:\n{log}");
    assert!(
        log.contains("server_error"),
        "the endpoint's error code is logged:\n{log}"
    );
}

/// A SIGHUP after the key file is replaced re-reads the key, mints with the
/// new key before the reload is published, and later requests carry the new
/// token.
#[test]
fn a_reload_with_a_rotated_key_mints_with_the_new_key() {
    let (old_pem, new_pem) = (test_key_pem("a"), test_key_pem("b"));
    let scratch = Scratch::new("rotate");
    let key = scratch.write("key.pem", &old_pem);
    let tokens = TokenEndpoint::spawn(vec![token("minted-old")]);
    let (provider, received) = spawn_provider();
    let port = free_port();
    let path = scratch.write("llmproxy.yaml", &config(port, provider, tokens.addr, &key));
    let proxy = Proxy::spawn(&path, port, scratch.0.join("proxy.log"));
    let (status, _) = proxy.send();
    assert!(status.contains(" 200 "));
    assert_eq!(
        received.recv_timeout(WAIT).unwrap().header("authorization"),
        Some("Bearer minted-old")
    );

    *tokens.replies.lock().unwrap() = vec![token("minted-old"), token("minted-new")];
    scratch.write("key.pem", &new_pem);
    proxy.sighup();
    let deadline = Instant::now() + WAIT;
    while !proxy.log_text().contains("SIGHUP: config reload succeeded") {
        assert!(
            Instant::now() < deadline,
            "reload never finished:\n{}",
            proxy.log_text()
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let assertions = tokens.assertions();
    assert_eq!(assertions.len(), 2, "one mint per key");
    assert!(
        signed_by(&assertions[1], &new_pem),
        "the reload must sign with the new key"
    );
    assert!(!signed_by(&assertions[1], &old_pem));

    // Workers pick up the published snapshot asynchronously; a fresh
    // connection soon carries the new generation's token.
    let deadline = Instant::now() + WAIT;
    loop {
        let (status, _) = proxy.send();
        assert!(status.contains(" 200 "));
        let auth = received
            .recv_timeout(WAIT)
            .unwrap()
            .header("authorization")
            .map(str::to_string);
        if auth.as_deref() == Some("Bearer minted-new") {
            break;
        }
        assert_eq!(auth.as_deref(), Some("Bearer minted-old"));
        assert!(
            Instant::now() < deadline,
            "no request carried the new token"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
