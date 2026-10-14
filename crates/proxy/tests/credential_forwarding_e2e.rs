//! The downstream virtual key must never reach a provider.
//!
//! `llmproxy.auth` authenticates `Authorization: Bearer llmp_...`. The
//! provider credential is added later, by the selected cluster's
//! `request_headers_to_add` (AGENTS.md invariant 6). For an `openai` provider with an
//! `api_key` that overwrites the client's `Authorization`, but an `anthropic`
//! provider sends its key in `x-api-key`, and a keyless `openai-compatible`
//! provider (Ollama, vLLM) sends nothing -- so unless the auth filter removes
//! the credential it verified, the tenant's virtual key is forwarded to a
//! third party.
//!
//! This drives the real `llm-proxy` binary with a dialect config, one mock
//! upstream per provider type, and asserts on the headers each upstream
//! actually received.
//!
//! Rust note: same harness shape as `tests/stats_e2e.rs` (std threads, no
//! async runtime, ephemeral ports, a `ChildGuard` that kills the proxy on
//! drop); each `tests/*.rs` file is its own crate, so the helpers are
//! duplicated rather than shared.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use proxy_filters::auth::{digest_hex, HmacSecret};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

const HMAC_SECRET: &str = "credential-forwarding-e2e-secret";
const VIRTUAL_KEY: &str = "llmp_credential-forwarding-e2e-key";
const OPENAI_KEY: &str = "sk-openai-provider-key";
const ANTHROPIC_KEY: &str = "sk-ant-provider-key";

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
}

fn wait_for_connectable(addr: (&str, u16), timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One request head as the upstream saw it: lowercased header names, values
/// verbatim.
type ReceivedHeaders = Vec<(String, String)>;

/// A mock provider that records each request's headers on a channel and
/// answers `200` with an empty JSON object.
fn spawn_recording_upstream() -> (SocketAddr, mpsc::Receiver<ReceivedHeaders>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let head_end = loop {
                    if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i;
                    }
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
                let headers: ReceivedHeaders = head
                    .lines()
                    .skip(1)
                    .filter_map(|line| line.split_once(':'))
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                    .collect();
                // Drain the body so the reply never races the request.
                let content_length: usize = headers
                    .iter()
                    .find(|(k, _)| k == "content-length")
                    .and_then(|(_, v)| v.parse().ok())
                    .unwrap_or(0);
                let mut have = raw.len() - (head_end + 4);
                while have < content_length {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => have += n,
                    }
                }
                let _ = tx.send(headers);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                      Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            });
        }
    });
    (addr, rx)
}

fn post(addr: SocketAddr, path: &str, authorization: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set_read_timeout");
    stream
        .write_all(
            format!(
                "POST {path} HTTP/1.1\r\nHost: proxy.local\r\nAuthorization: {authorization}\r\n\
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

fn values<'a>(headers: &'a ReceivedHeaders, name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .collect()
}

#[test]
fn the_virtual_key_never_reaches_any_provider_type() {
    let (openai_addr, openai_rx) = spawn_recording_upstream();
    let (anthropic_addr, anthropic_rx) = spawn_recording_upstream();
    let (ollama_addr, ollama_rx) = spawn_recording_upstream();
    let listen_port = free_port();
    let admin_port = free_port();

    let digest = digest_hex(&HmacSecret::new(HMAC_SECRET.as_bytes()), VIRTUAL_KEY);
    let config = format!(
        r#"version: 0
listen: 127.0.0.1:{listen_port}
admin: 127.0.0.1:{admin_port}
providers:
  openai:
    type: openai
    base_url: http://{openai_addr}
    api_key: {OPENAI_KEY}
  anthropic:
    type: anthropic
    base_url: http://{anthropic_addr}
    api_key: {ANTHROPIC_KEY}
  ollama:
    type: openai-compatible
    base_url: http://{ollama_addr}
routes:
  - {{ model: "gpt-*", provider: openai }}
  - {{ model: "claude-*", provider: anthropic }}
  - {{ model: "llama*", provider: ollama }}
auth:
  hmac_secret: "{HMAC_SECRET}"
  enforce: {{ tenants_without_policy: allow }}
  keys:
    - {{ id: "key-1", tenant: "tenant-a", digest: "{digest}" }}
"#
    );
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-credential-forwarding-e2e-{}-{listen_port}.yaml",
        std::process::id()
    ));
    std::fs::write(&config_path, config).expect("failed to write temp config");

    let _proxy = ChildGuard(
        Command::new(BIN)
            .args([
                "--config",
                config_path.to_str().unwrap(),
                "--concurrency",
                "1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn llm-proxy"),
    );
    assert!(
        wait_for_connectable(("127.0.0.1", listen_port), STARTUP_TIMEOUT),
        "listener at 127.0.0.1:{listen_port} did not become connectable in time"
    );
    let listen_addr: SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    let bearer = format!("Bearer {VIRTUAL_KEY}");

    let cases = [
        ("openai", "/v1/chat/completions", "gpt-4o-mini", &openai_rx),
        (
            "anthropic",
            "/v1/messages",
            "claude-sonnet-4-5",
            &anthropic_rx,
        ),
        ("ollama", "/v1/chat/completions", "llama3", &ollama_rx),
    ];
    // Collected rather than asserted inline, so one run reports every
    // provider type that leaks instead of stopping at the first.
    let mut leaks = Vec::new();
    for (provider, path, model, rx) in cases {
        let body = format!(
            r#"{{"model":"{model}","max_tokens":8,"messages":[{{"role":"user","content":"hi"}}]}}"#
        );
        let response = post(listen_addr, path, &bearer, &body);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "{provider}: expected the proxied request to succeed, got:\n{response}"
        );
        let headers = rx
            .recv_timeout(Duration::from_secs(10))
            .unwrap_or_else(|_| panic!("{provider}: the upstream never received the request"));

        let leaked: Vec<_> = headers
            .iter()
            .filter(|(_, v)| v.contains(VIRTUAL_KEY))
            .map(|(k, _)| k.clone())
            .collect();
        if !leaked.is_empty() {
            leaks.push(format!("{provider} received it in {leaked:?}"));
            continue;
        }

        let authorization = values(&headers, "authorization");
        match provider {
            "openai" => assert_eq!(authorization, [format!("Bearer {OPENAI_KEY}")]),
            "anthropic" => {
                assert_eq!(values(&headers, "x-api-key"), [ANTHROPIC_KEY]);
                assert!(authorization.is_empty(), "{provider}: {authorization:?}");
            }
            _ => assert!(authorization.is_empty(), "{provider}: {authorization:?}"),
        }
    }

    let _ = std::fs::remove_file(&config_path);
    assert!(
        leaks.is_empty(),
        "the downstream virtual key was forwarded upstream: {leaks:?}"
    );
}
