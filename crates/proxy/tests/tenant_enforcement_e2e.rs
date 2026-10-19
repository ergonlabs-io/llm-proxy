//! Tenant model allow-lists and spend budgets set through the admin API are
//! enforced on the data plane when the dialect has an `auth` block.
//!
//! This drives the real `llm-proxy` binary through `--config`: mint a key for a
//! tenant, write a policy or budget over the admin listener, and check the next
//! request. The `auth.enforce` opt-out is the negative control: the same write
//! is then refused with 409 instead of being stored and ignored.
//!
//! Rust note: same harness shape as `tests/auth_store_e2e.rs` (std threads,
//! ephemeral ports, a `ChildGuard`-style `Drop` that kills the proxy). Every
//! wait is bounded, so a hung child fails the test instead of stalling it.

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const HMAC_SECRET: &str = "tenant-enforcement-e2e-secret";
const ADMIN_TOKEN: &str = "tenant-enforcement-e2e-admin-token";
const TENANT: &str = "t1";
const KEY_ID: &str = "minted-1";
const MODEL: &str = "gpt-4o-mini";

#[test]
fn an_empty_only_policy_makes_the_next_request_403() {
    let dir = scratch_dir("policy");
    let proxy = Proxy::start(&dir, &config_text(""));
    let key = mint_key(&proxy);
    allow_all_models(&proxy);

    let before = chat(&proxy, &key);
    assert!(
        before.starts_with("HTTP/1.1 200"),
        "before the policy:\n{before}"
    );

    // The tenant must exist before a policy can be set on it.
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

    let put = http_put(
        proxy.admin,
        &format!("/tenants/{TENANT}/policy"),
        r#"{"access":{"only":[]}}"#,
    );
    assert!(put.starts_with("HTTP/1.1 204"), "PUT policy:\n{put}");

    let after = chat(&proxy, &key);
    assert!(
        after.starts_with("HTTP/1.1 403"),
        "an `only: []` policy must deny every model:\n{after}"
    );
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_zero_budget_refuses_the_next_request() {
    let dir = scratch_dir("budget");
    let proxy = Proxy::start(&dir, &config_text(""));
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

    let put = http_put(
        proxy.admin,
        &format!("/tenants/{TENANT}/budget"),
        r#"{"budget":{"max_usd":"0","period":"daily"}}"#,
    );
    assert!(put.starts_with("HTTP/1.1 204"), "PUT budget:\n{put}");

    let after = chat(&proxy, &key);
    assert!(
        after.starts_with("HTTP/1.1 429"),
        "a zero budget must refuse the request:\n{after}"
    );
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Absence of policy is not a grant. A minted key whose tenant has
/// no stored model policy is refused by default; the dialect's
/// `tenants_without_policy: allow` (the fail-open option, warned at load)
/// admits it.
#[test]
fn a_tenant_without_a_policy_is_refused_unless_the_config_allows_it() {
    for (tag, extra, expected) in [
        ("default-deny", "", "HTTP/1.1 403"),
        (
            "allow",
            "  enforce: { tenants_without_policy: allow }\n",
            "HTTP/1.1 200",
        ),
    ] {
        let dir = scratch_dir(tag);
        let proxy = Proxy::start(&dir, &config_text(extra));
        let key = mint_key(&proxy);
        let response = chat(&proxy, &key);
        assert!(response.starts_with(expected), "{tag}:\n{response}");
        drop(proxy);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Offboarding: `DELETE /tenants/{id}` revokes the tenant's keys,
/// so the next request with a key minted for it is 401, not admitted.
#[test]
fn deleting_a_tenant_makes_its_keys_stop_authenticating() {
    let dir = scratch_dir("delete");
    let proxy = Proxy::start(&dir, &config_text(""));
    let key = mint_key(&proxy);
    allow_all_models(&proxy);
    let before = chat(&proxy, &key);
    assert!(
        before.starts_with("HTTP/1.1 200"),
        "before the delete:\n{before}"
    );

    let deleted = http_request(
        "DELETE",
        proxy.admin,
        &format!("/tenants/{TENANT}"),
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        "application/json",
        "",
    );
    assert!(
        deleted.starts_with("HTTP/1.1 204"),
        "DELETE tenant:\n{deleted}"
    );

    let after = chat(&proxy, &key);
    assert!(
        after.starts_with("HTTP/1.1 401"),
        "a deleted tenant's key must not authenticate:\n{after}"
    );
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Negative control: with the filters opted out, the writes are refused rather
/// than stored and ignored.
#[test]
fn opting_out_of_enforcement_makes_the_admin_writes_409() {
    let dir = scratch_dir("opt-out");
    let proxy = Proxy::start(
        &dir,
        &config_text("  enforce: { model_policy: false, spend: false, limits: false }\n"),
    );
    let _key = mint_key(&proxy);
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

    let policy = http_put(
        proxy.admin,
        &format!("/tenants/{TENANT}/policy"),
        r#"{"access":{"only":[]}}"#,
    );
    assert!(policy.starts_with("HTTP/1.1 409"), "PUT policy:\n{policy}");
    assert!(policy.contains("not_enforced") && policy.contains("llmproxy.model_authz"));

    let budget = http_put(
        proxy.admin,
        &format!("/tenants/{TENANT}/budget"),
        r#"{"budget":{"max_usd":"0","period":"daily"}}"#,
    );
    assert!(budget.starts_with("HTTP/1.1 409"), "PUT budget:\n{budget}");
    assert!(budget.contains("not_enforced") && budget.contains("llmproxy.spend_limit"));

    let limits = http_put(
        proxy.admin,
        &format!("/tenants/{TENANT}/limits"),
        r#"{"limits":{"requests_per_minute":0}}"#,
    );
    assert!(limits.starts_with("HTTP/1.1 409"), "PUT limits:\n{limits}");
    assert!(limits.contains("not_enforced"));
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Tenant and key request limits through the dialect's default chain. A key's
/// limit refuses it while its tenant still has room; a sibling key with no
/// limits row is bounded by the tenant alone.
#[test]
fn a_key_limit_narrows_its_tenant_and_a_sibling_keeps_the_tenant_limit() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("limits-narrow");
    let proxy = Proxy::start(&dir, &config_text(""));
    let key1 = mint_key(&proxy);
    let key2 = mint_key_as(&proxy, "minted-2");
    allow_all_models(&proxy);
    create_tenant(&proxy);
    put_ok(
        &proxy,
        &format!("/tenants/{TENANT}/limits"),
        r#"{"limits":{"requests_per_minute":3}}"#,
    );
    put_ok(
        &proxy,
        &format!("/keys/{KEY_ID}/limits"),
        r#"{"limits":{"requests_per_minute":1}}"#,
    );

    assert_admitted(&chat(&proxy, &key1), "key1, first request");
    assert_rate_limited(
        &chat(&proxy, &key1),
        "key1 is over its own limit while the tenant has room",
    );
    assert_admitted(&chat(&proxy, &key2), "key2, tenant request 2 of 3");
    assert_admitted(&chat(&proxy, &key2), "key2, tenant request 3 of 3");
    assert_rate_limited(
        &chat(&proxy, &key2),
        "key2 has no limit of its own but the tenant is spent",
    );
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A key limit above its tenant's never widens it.
#[test]
fn a_key_limit_never_widens_its_tenant() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("limits-widen");
    let proxy = Proxy::start(&dir, &config_text(""));
    let key = mint_key(&proxy);
    allow_all_models(&proxy);
    create_tenant(&proxy);
    put_ok(
        &proxy,
        &format!("/tenants/{TENANT}/limits"),
        r#"{"limits":{"requests_per_minute":1}}"#,
    );
    put_ok(
        &proxy,
        &format!("/keys/{KEY_ID}/limits"),
        r#"{"limits":{"requests_per_minute":100}}"#,
    );

    assert_admitted(&chat(&proxy, &key), "first request");
    assert_rate_limited(
        &chat(&proxy, &key),
        "the key allows 100 but its tenant allows 1",
    );
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Limits are control-plane rows. On the persistent store they survive a
/// restart.
#[test]
fn limits_survive_a_restart_with_a_persistent_store() {
    let dir = scratch_dir("limits-restart");
    let store = dir.join("control.redb");
    let auth_extra = format!(
        "  store:\n    persistent:\n      path: \"{}\"\n",
        store.display()
    );

    let proxy = Proxy::start(&dir, &config_text(&auth_extra));
    let key = mint_key(&proxy);
    allow_all_models(&proxy);
    put_ok(
        &proxy,
        &format!("/keys/{KEY_ID}/limits"),
        r#"{"limits":{"requests_per_minute":0}}"#,
    );
    assert_rate_limited(
        &chat(&proxy, &key),
        "a zero key limit refuses before the restart",
    );
    drop(proxy);

    let proxy = Proxy::start(&dir, &config_text(&auth_extra));
    assert_rate_limited(&chat(&proxy, &key), "the key limit is reloaded from redb");
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

/// The dialect file; `auth_extra` is appended inside the `auth` block.
fn config_text(auth_extra: &str) -> String {
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
{auth_extra}"#,
        listen = free_port(),
        admin = free_port(),
        upstream = spawn_ok_upstream(),
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-tenant-enforcement-e2e-{tag}-{}",
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

/// `PUT /tenants/{TENANT}/policy` granting every model.
fn allow_all_models(proxy: &Proxy) {
    let put = http_put(
        proxy.admin,
        &format!("/tenants/{TENANT}/policy"),
        r#"{"access":"all"}"#,
    );
    assert!(put.starts_with("HTTP/1.1 204"), "PUT policy:\n{put}");
}

fn chat(proxy: &Proxy, key: &str) -> String {
    let body = format!(
        r#"{{"model":"{MODEL}","max_tokens":8,"messages":[{{"role":"user","content":"hi"}}]}}"#
    );
    http_post(
        proxy.listen,
        "/v1/chat/completions",
        Some(&format!("Bearer {key}")),
        "application/json",
        &body,
    )
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

/// `POST /keys` for `key_id` on [`TENANT`]; returns the plaintext key.
fn mint_key_as(proxy: &Proxy, key_id: &str) -> String {
    let response = http_post(
        proxy.admin,
        "/keys",
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        "application/json",
        &format!(r#"{{"tenant":"{TENANT}","key_id":"{key_id}"}}"#),
    );
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "POST /keys:\n{response}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(response_body(&response)).expect("POST /keys returns JSON");
    parsed["key"].as_str().expect("plaintext key").to_string()
}

fn create_tenant(proxy: &Proxy) {
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
}

fn put_ok(proxy: &Proxy, path: &str, body: &str) {
    let put = http_put(proxy.admin, path, body);
    assert!(put.starts_with("HTTP/1.1 204"), "PUT {path}:\n{put}");
}

fn assert_admitted(response: &str, what: &str) {
    assert!(response.starts_with("HTTP/1.1 200"), "{what}:\n{response}");
}

/// A 429 from the limiter itself: the body names the refusing limit, which
/// the mock upstream (always 200) never produces.
fn assert_rate_limited(response: &str, what: &str) {
    assert!(
        response.starts_with("HTTP/1.1 429") && response.contains("request rate exceeded"),
        "{what}:\n{response}"
    );
}

/// Windows are aligned to the minute (ADR-0006 amendment B). A test that
/// counts requests in one window waits out the last few seconds of a minute
/// first, so its requests cannot straddle a boundary.
fn start_away_from_a_window_edge() {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs();
    let into_minute = secs % 60;
    if into_minute >= 50 {
        std::thread::sleep(Duration::from_secs(61 - into_minute));
    }
}
