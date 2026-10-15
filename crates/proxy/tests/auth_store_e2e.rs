//! A key minted through the admin API survives a restart when the dialect
//! selects a persistent auth store (`auth.store.persistent`), and does not
//! survive one when the store is left at its in-memory default.
//!
//! Drives the real `llm-proxy` binary with a `--config` dialect file, a mock
//! upstream, and the admin listener. The in-memory case is the negative
//! control: without it, a persistent store that silently fell back to memory
//! would be indistinguishable from one that works.
//!
//! Rust note: same harness shape as `tests/credential_forwarding_e2e.rs` (std
//! threads, no async runtime, ephemeral ports, a `ChildGuard` that kills the
//! proxy on drop). Every wait is bounded by `STARTUP_TIMEOUT` or a socket read
//! timeout, so a hung child fails the test instead of stalling it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const HMAC_SECRET: &str = "auth-store-e2e-secret";
const ADMIN_TOKEN: &str = "auth-store-e2e-admin-token";
const TENANT: &str = "tenant-a";
const KEY_ID: &str = "minted-1";
const MODEL: &str = "gpt-4o-mini";

#[test]
fn a_minted_key_survives_a_restart_with_a_persistent_store() {
    let dir = scratch_dir("persistent");
    let db = dir.join("control.redb");
    let config = config_text(&db, true);

    let minted = {
        let proxy = Proxy::start(&dir, &config);
        let key = mint_key(&proxy);
        assert_authenticates(&proxy, &key, "before the restart");
        key
    };

    // Same config, same redb file, new process: the key must still work.
    let restarted = Proxy::start(&dir, &config);
    assert_authenticates(&restarted, &minted, "after the restart");
    drop(restarted);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_key_policy_survives_a_restart_with_a_persistent_store() {
    let dir = scratch_dir("key-policy-persistent");
    let db = dir.join("control.redb");
    let config = config_text(&db, true);

    let key = {
        let proxy = Proxy::start(&dir, &config);
        let key = mint_key(&proxy);
        let created = http_post(
            proxy.admin,
            "/tenants",
            Some(&format!("Bearer {ADMIN_TOKEN}")),
            "application/json",
            &format!(r#"{{"tenant":"{TENANT}"}}"#),
        );
        assert!(
            created.starts_with("HTTP/1.1 2"),
            "POST /tenants:\n{created}"
        );
        let tenant_policy = http_put(
            proxy.admin,
            &format!("/tenants/{TENANT}/policy"),
            r#"{"access":"all"}"#,
        );
        assert!(
            tenant_policy.starts_with("HTTP/1.1 204"),
            "PUT tenant policy:\n{tenant_policy}"
        );
        let key_policy = http_put(
            proxy.admin,
            &format!("/keys/{KEY_ID}/policy"),
            r#"{"access":{"only":["gpt-4*"]}}"#,
        );
        assert!(
            key_policy.starts_with("HTTP/1.1 204"),
            "PUT key policy:\n{key_policy}"
        );
        key
    };

    let restarted = Proxy::start(&dir, &config);
    let denied = chat_model(&restarted, &key, "claude-3");
    assert!(
        denied.starts_with("HTTP/1.1 403"),
        "key policy must deny claude-3 after restart:\n{denied}"
    );
    let allowed = chat_model(&restarted, &key, "gpt-4o");
    assert!(
        allowed.starts_with("HTTP/1.1 200"),
        "key policy must allow gpt-4o after restart:\n{allowed}"
    );
    drop(restarted);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Negative control: with no `store:` the minted key is lost on restart, so the
/// 401 after restart is the expected outcome here.
#[test]
fn a_minted_key_does_not_survive_a_restart_with_the_in_memory_default() {
    let dir = scratch_dir("in-memory");
    let db = dir.join("control.redb");
    let config = config_text(&db, false);

    let minted = {
        let proxy = Proxy::start(&dir, &config);
        let key = mint_key(&proxy);
        assert_authenticates(&proxy, &key, "before the restart");
        key
    };

    let restarted = Proxy::start(&dir, &config);
    let response = chat(&restarted, &minted);
    assert!(
        response.starts_with("HTTP/1.1 401"),
        "in-memory store kept a minted key across a restart:\n{response}"
    );
    drop(restarted);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

/// The dialect file. `persistent` adds the `auth.store` under test; without it
/// the file is exactly the default the proxy runs with today.
fn config_text(db: &Path, persistent: bool) -> String {
    let store = if persistent {
        format!(
            "  store:\n    persistent: {{ path: \"{}\" }}\n",
            db.display()
        )
    } else {
        String::new()
    };
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
  hmac_secret: "{HMAC_SECRET}"
  enforce: {{ tenants_without_policy: allow }}
{store}"#,
        listen = free_port(),
        admin = free_port(),
        upstream = spawn_ok_upstream(),
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-auth-store-e2e-{tag}-{}",
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
        // The ports are recorded in the config text by `config_text`; read them
        // back from it so `Proxy` talks to the same listeners the child binds.
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
    let rest = config
        .split(prefix)
        .nth(1)
        .expect("config names the listener");
    rest.split_whitespace()
        .next()
        .and_then(|p| p.parse().ok())
        .expect("listener port parses")
}

/// `POST /keys` on the admin listener. Returns the plaintext key, which the
/// response carries exactly once.
fn mint_key(proxy: &Proxy) -> String {
    let body = format!(r#"{{"tenant":"{TENANT}","key_id":"{KEY_ID}"}}"#);
    let response = http_post(
        proxy.admin,
        "/keys",
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        "application/json",
        &body,
    );
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "POST /keys did not mint a key:\n{response}"
    );
    let json = response_body(&response);
    let parsed: serde_json::Value = serde_json::from_str(json).expect("POST /keys returns JSON");
    parsed["key"]
        .as_str()
        .expect("POST /keys returns the plaintext key")
        .to_string()
}

fn chat(proxy: &Proxy, key: &str) -> String {
    chat_model(proxy, key, MODEL)
}

fn chat_model(proxy: &Proxy, key: &str, model: &str) -> String {
    let body = format!(
        r#"{{"model":"{model}","max_tokens":8,"messages":[{{"role":"user","content":"hi"}}]}}"#
    );
    http_post(
        proxy.listen,
        "/v1/chat/completions",
        Some(&format!("Bearer {key}")),
        "application/json",
        &body,
    )
}

fn assert_authenticates(proxy: &Proxy, key: &str, when: &str) {
    let response = chat(proxy, key);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "minted key was refused {when}:\n{response}"
    );
}

fn response_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
}

fn http_post(
    addr: SocketAddr,
    path: &str,
    authorization: Option<&str>,
    content_type: &str,
    body: &str,
) -> String {
    http_request("POST", addr, path, authorization, content_type, body)
}

fn http_put(addr: SocketAddr, path: &str, body: &str) -> String {
    http_request(
        "PUT",
        addr,
        path,
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        "application/json",
        body,
    )
}

fn http_request(
    method: &str,
    addr: SocketAddr,
    path: &str,
    authorization: Option<&str>,
    content_type: &str,
    body: &str,
) -> String {
    let mut stream = TcpStream::connect_timeout(&addr, IO_TIMEOUT).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("set_write_timeout");
    let auth = authorization
        .map(|a| format!("Authorization: {a}\r\n"))
        .unwrap_or_default();
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: proxy.local\r\n{auth}\
                 Content-Type: {content_type}\r\nContent-Length: {}\r\n\
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

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
}

/// A mock provider that answers every request `200` with an empty JSON object.
/// Only the status matters here: the test asserts on the proxy's auth decision,
/// not on the upstream's content.
fn spawn_ok_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
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
                let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
                let content_length: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut have = raw.len() - (head_end + 4);
                while have < content_length {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => have += n,
                    }
                }
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                      Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            });
        }
    });
    addr
}
