//! The save-time credential probe end to end (ADR-0007 decision 10): the real
//! `llm-proxy` binary with a `--config` dialect file, an OpenRouter-type
//! provider pointed at a mock, and the admin API.
//!
//! The mock answers `GET /api/v1/key` with 200 for one key, 401 for any other
//! key, and 500 for a third key. The test asserts the probe reached the mock
//! with only the candidate key (never the operator key), that a good key is
//! stored with `verified_at`, and that a rejected or unverifiable key is
//! refused with nothing stored.
//!
//! Rust note: same harness shape as `tests/auth_store_e2e.rs` (std threads,
//! ephemeral ports, a guard that kills the child on drop, every wait bounded).

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const ADMIN_TOKEN: &str = "verify-e2e-admin-token";
const HMAC_SECRET: &str = "verify-e2e-hmac-secret";
const TENANT: &str = "tenant-v";
const OPERATOR_KEY: &str = "sk-or-OPERATOR-key";
const GOOD_KEY: &str = "sk-or-GOOD-tenant-key";
const BAD_KEY: &str = "sk-or-BAD-tenant-key";
const FLAKY_KEY: &str = "sk-or-FLAKY-tenant-key";
const VERIFY_PATH: &str = "/api/v1/key";

#[test]
fn the_probe_verifies_a_good_key_and_refuses_a_bad_one() {
    let dir = scratch_dir();
    let (upstream, seen) = spawn_key_endpoint();
    let proxy = Proxy::start(&dir, upstream);
    let cred_path = format!("/tenants/{TENANT}/provider_credentials/openrouter");

    let (status, body) = proxy.admin("POST", "/tenants", &format!(r#"{{"tenant":"{TENANT}"}}"#));
    assert_eq!(status, 201, "{body}");

    // A good key: probed, stored, verified.
    let (status, body) = proxy.admin("PUT", &cred_path, &put_body(GOOD_KEY));
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains(GOOD_KEY), "{body}");
    let stored: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(stored["verified_at"].is_string(), "{body}");
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "one probe: {seen:?}");
        let probe = &seen[0];
        assert!(
            probe.starts_with(&format!(
                "get {} http/1.1",
                VERIFY_PATH.to_ascii_lowercase()
            )),
            "{probe}"
        );
        assert!(
            probe.contains(&format!(
                "authorization: bearer {}",
                GOOD_KEY.to_ascii_lowercase()
            )),
            "{probe}"
        );
        assert!(
            !probe.contains(&OPERATOR_KEY.to_ascii_lowercase()),
            "the operator key reached the probe: {probe}"
        );
    }

    // A rejected key: 422 with the provider's status, and the good key stays.
    let (status, body) = proxy.admin("PUT", &cred_path, &put_body(BAD_KEY));
    assert_eq!(status, 422, "{body}");
    assert!(!body.contains(BAD_KEY), "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"]["type"], "credential_rejected", "{body}");
    assert_eq!(error["error"]["upstream_status"], 401, "{body}");

    // A provider error: 502, and the good key still stays.
    let (status, body) = proxy.admin("PUT", &cred_path, &put_body(FLAKY_KEY));
    assert_eq!(status, 502, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        error["error"]["type"], "credential_verification_unavailable",
        "{body}"
    );
    assert_eq!(error["error"]["upstream_status"], 500, "{body}");

    let (status, body) = proxy.admin(
        "GET",
        &format!("/tenants/{TENANT}/provider_credentials"),
        "",
    );
    assert_eq!(status, 200, "{body}");
    let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let credentials = listed["credentials"].as_array().unwrap();
    assert_eq!(credentials.len(), 1, "{body}");
    assert_eq!(
        credentials[0]["last4"],
        &GOOD_KEY[GOOD_KEY.len() - 4..],
        "a refused key replaced the verified one: {body}"
    );
    assert!(credentials[0]["verified_at"].is_string(), "{body}");

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

fn put_body(key: &str) -> String {
    format!(r#"{{"schema_version":1,"api_key":"{key}"}}"#)
}

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("llm-proxy-verify-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn config_text(dir: &Path, listen: u16, admin: u16, upstream: SocketAddr) -> String {
    let kek = dir.join("kek.bin");
    std::fs::write(&kek, b"verify-e2e-kek-0123456789abcdef!").expect("write kek");
    std::fs::set_permissions(&kek, std::fs::Permissions::from_mode(0o600)).expect("chmod kek");
    format!(
        r#"version: 0
listen: 127.0.0.1:{listen}
admin: 127.0.0.1:{admin}
providers:
  openrouter:
    type: openrouter
    base_url: http://{upstream}
    api_key: {OPERATOR_KEY}
    tenant_credentials: true
    tenant_credential_verify_path: {VERIFY_PATH}
routes:
  - {{ model: "*", provider: openrouter }}
auth:
  hmac_secret: "{HMAC_SECRET}"
  store:
    persistent: {{ path: "{db}" }}
  tenant_credentials:
    encryption_key_file: "{kek}"
    encryption_key_id: "k1"
"#,
        db = dir.join("control.redb").display(),
        kek = kek.display(),
    )
}

/// A running proxy. Killed and reaped on drop (AGENTS.md "Running The
/// Product").
struct Proxy {
    child: Child,
    admin: SocketAddr,
}

impl Proxy {
    fn start(dir: &Path, upstream: SocketAddr) -> Proxy {
        let listen = free_port();
        let admin = free_port();
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config_text(dir, listen, admin, upstream)).expect("write config");
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
            admin: SocketAddr::from(([127, 0, 0, 1], admin)),
        };
        let listen = SocketAddr::from(([127, 0, 0, 1], listen));
        assert!(
            wait_for_connectable(proxy.admin, STARTUP_TIMEOUT),
            "admin listener at {} did not become connectable in time",
            proxy.admin
        );
        assert!(
            wait_for_connectable(listen, STARTUP_TIMEOUT),
            "listener at {listen} did not become connectable in time"
        );
        proxy
    }

    /// One admin request. Returns the status code and the body.
    fn admin(&self, method: &str, path: &str, body: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(self.admin).expect("connect admin");
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("set_read_timeout");
        stream
            .write_all(
                format!(
                    "{method} {path} HTTP/1.1\r\nHost: admin.local\r\n\
                     Authorization: Bearer {ADMIN_TOKEN}\r\n\
                     Content-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .expect("write admin request");
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        let response = String::from_utf8_lossy(&response).to_string();
        let status = response
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no status line in {response:?}"));
        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_string())
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

fn wait_for_connectable(addr: SocketAddr, timeout: Duration) -> bool {
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

/// A mock of OpenRouter's key endpoint. Records each request head
/// (lowercased) and answers by the bearer key: 200 for [`GOOD_KEY`], 500 for
/// [`FLAKY_KEY`], 401 otherwise.
fn spawn_key_endpoint() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let record = record.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&raw).to_string();
                let status = if head.contains(&format!("Bearer {GOOD_KEY}")) {
                    "200 OK"
                } else if head.contains(&format!("Bearer {FLAKY_KEY}")) {
                    "500 Internal Server Error"
                } else {
                    "401 Unauthorized"
                };
                record.lock().unwrap().push(head.to_ascii_lowercase());
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                         Content-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                    )
                    .as_bytes(),
                );
            });
        }
    });
    (addr, seen)
}
