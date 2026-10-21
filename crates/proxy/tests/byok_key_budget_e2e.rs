//! A key budget counts operator spend, and BYOK spend too with
//! `include_byok_in_limit: true` (ADR-0007 amendment 1).
//!
//! Drives the real `llm-proxy` binary in `--config` mode: one priced provider
//! that carries a tenant credential slot, a mock upstream that records the
//! `Authorization` it receives and reports fixed usage, a persistent redb auth
//! store and a 0600 key-encryption-key file. The tenant runs on the operator's
//! key, then on its own key after `PUT .../provider_credentials`, then on the
//! operator's key again after `DELETE`. Two keys of that tenant send the same
//! traffic with budgets of two requests' cost; only the flag differs.
//!
//! Rust note: same harness shape as `tests/jwt_tenant_credentials_e2e.rs`
//! (std threads, ephemeral ports, a `Drop` that kills the proxy). Every wait
//! is bounded, so a hung child fails the test instead of stalling it.

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const ADMIN_TOKEN: &str = "byok-key-budget-e2e-admin-token";
const TENANT: &str = "acme";
const OPERATOR_KEY: &str = "sk-operator-OPERATOR";
const TENANT_KEY: &str = "sk-tenant-BYOK";
const KEK: [u8; 32] = *b"e2e-kek-0123456789abcdef-padding";

/// The mock's usage (6 input, 4 output tokens) at the configured prices
/// (1000 and 2000 nanodollars per token): 14 micro-dollars a request.
/// Each key's budget is two requests' cost.
const BUDGET_USD: &str = "0.000028";

#[test]
fn a_key_budget_counts_byok_spend_only_with_include_byok_in_limit() {
    let dir = scratch_dir();
    let kek = dir.join("credential-kek");
    std::fs::write(&kek, KEK).expect("write kek");
    std::fs::set_permissions(&kek, std::fs::Permissions::from_mode(0o600)).expect("chmod kek");
    let upstream = Upstream::spawn();
    let proxy = Proxy::start(&dir, &config_text(upstream.addr, &dir, &kek));

    proxy.admin(
        "POST",
        "/tenants",
        &format!(r#"{{"tenant":"{TENANT}"}}"#),
        201,
    );
    proxy.admin(
        "PUT",
        &format!("/tenants/{TENANT}/policy"),
        r#"{"access":"all"}"#,
        204,
    );
    let mut keys = Vec::new();
    for (key_id, include_byok_in_limit) in [("counts-byok", true), ("operator-only", false)] {
        let minted = proxy.admin(
            "POST",
            "/keys",
            &format!(r#"{{"tenant":"{TENANT}","key_id":"{key_id}"}}"#),
            201,
        );
        let minted: serde_json::Value =
            serde_json::from_str(response_body(&minted)).expect("mint response is JSON");
        proxy.admin(
            "PUT",
            &format!("/keys/{key_id}/budget"),
            &format!(
                r#"{{"budget":{{"max_usd":"{BUDGET_USD}","period":"daily","include_byok_in_limit":{include_byok_in_limit}}}}}"#
            ),
            204,
        );
        keys.push(format!(
            "Bearer {}",
            minted["key"].as_str().expect("plaintext key")
        ));
    }
    let (counts_byok, operator_only) = (&keys[0], &keys[1]);

    // One request each on the operator's credential: half of each budget.
    for key in [counts_byok, operator_only] {
        assert_eq!(status(&chat(&proxy, key)), 200);
    }
    assert_eq!(
        upstream.take(),
        [OPERATOR_KEY, OPERATOR_KEY].map(|k| format!("Bearer {k}"))
    );

    // The tenant's own key: BYOK spend from here on.
    proxy.admin(
        "PUT",
        &format!("/tenants/{TENANT}/provider_credentials/openai"),
        &format!(r#"{{"schema_version":1,"api_key":"{TENANT_KEY}","verify":false}}"#),
        200,
    );
    for key in [counts_byok, operator_only] {
        assert_eq!(status(&chat(&proxy, key)), 200);
    }
    assert_eq!(
        upstream.take(),
        [TENANT_KEY, TENANT_KEY].map(|k| format!("Bearer {k}")),
        "the second request of each key must be BYOK spend"
    );

    // Operator plus BYOK spend now meets the flagged key's budget.
    let refused = chat(&proxy, counts_byok);
    assert_spend_refusal(&refused);
    // The same traffic on the unflagged key counted only its operator
    // request, and BYOK requests are not held to its budget.
    for _ in 0..2 {
        assert_eq!(status(&chat(&proxy, operator_only)), 200);
    }
    assert_eq!(
        upstream.take(),
        [TENANT_KEY, TENANT_KEY].map(|k| format!("Bearer {k}")),
        "a refused request must not reach the provider"
    );

    // Back on the operator's credential: one more operator request meets
    // the unflagged key's budget, and the next is refused.
    proxy.admin(
        "DELETE",
        &format!("/tenants/{TENANT}/provider_credentials/openai"),
        "",
        204,
    );
    assert_eq!(status(&chat(&proxy, operator_only)), 200);
    let refused = chat(&proxy, operator_only);
    assert_spend_refusal(&refused);
    assert_eq!(upstream.take(), [format!("Bearer {OPERATOR_KEY}")]);

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

/// The spend filter's refusal (`spend_budget_exceeded` in the access log):
/// its body, and the key's ceiling in micro-dollars, which no token limit in
/// this config could report.
fn assert_spend_refusal(response: &str) {
    assert_eq!(status(response), 429, "{response}");
    assert!(
        response.contains("spend budget exceeded"),
        "the refusal names the spend budget: {response}"
    );
    assert!(
        response.contains("x-ratelimit-limit: 28\r\n"),
        "the ceiling is the key's budget: {response}"
    );
}

fn config_text(upstream: SocketAddr, dir: &Path, kek: &Path) -> String {
    format!(
        r#"version: 0
listen: 127.0.0.1:{listen}
admin: 127.0.0.1:{admin}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: {OPERATOR_KEY}
    tenant_credentials: true
routes:
  - {{ model: "*", provider: openai }}
auth:
  hmac_secret: byok-key-budget-e2e-secret
  store:
    persistent: {{ path: "{db}" }}
  tenant_credentials:
    encryption_key_file: "{kek}"
    encryption_key_id: kek-1
pricing:
  price_list:
    version: byok-key-budget-e2e
    effective_from: "2026-01-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: gpt-4o
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 1000
            cached_input_nanodollars_per_token: 1000
            cache_write_nanodollars_per_token: 1000
            output_nanodollars_per_token: 2000
"#,
        listen = free_port(),
        admin = free_port(),
        db = dir.join("control.redb").display(),
        kek = kek.display(),
    )
}

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-byok-key-budget-e2e-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// An OpenAI-shaped upstream that answers every request with fixed usage
/// and records the `Authorization` header each request carried.
struct Upstream {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Upstream {
    fn spawn() -> Upstream {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
        let addr = listener.local_addr().expect("mock address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let record = Arc::clone(&record);
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                    let Some(head) = read_request(&mut stream) else {
                        return;
                    };
                    let authorization = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("authorization")
                                .then(|| value.trim().to_string())
                        })
                        .unwrap_or_default();
                    record.lock().expect("mock lock").push(authorization);
                    let body = r#"{"id":"x","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":6,"completion_tokens":4,"total_tokens":10}}"#;
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                });
            }
        });
        Upstream { addr, seen }
    }

    /// The `Authorization` values received since the last call, in order.
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.seen.lock().expect("mock lock"))
    }
}

/// Reads one request (head and `Content-Length` body) and returns the head.
fn read_request(stream: &mut TcpStream) -> Option<String> {
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
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    let mut have = raw.len() - (head_end + 4);
    while have < length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => have += n,
        }
    }
    Some(head)
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
        r#"{"model":"gpt-4o","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
    )
}

fn status(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line: {response}"))
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
    String::from_utf8_lossy(&response).into_owned()
}

fn wait_for_connectable(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}
