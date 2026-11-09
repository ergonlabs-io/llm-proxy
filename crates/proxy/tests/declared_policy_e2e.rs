//! Tenant policy declared in a `--config` file, through the real binary and
//! a real SIGHUP:
//! - a declared tenant's model policy and limit are enforced from the first
//!   request, and its budget and scoped budget are in the snapshot the spend
//!   filter reads, with no admin call; removing the tenant from the file and
//!   sending SIGHUP removes its rows;
//! - an admin write to a declared row takes it over: a reload with another
//!   file value leaves it, with exactly one warning naming the entry's
//!   dotted path, until `DELETE /tenants/{id}/override` hands it back;
//! - a reload with an unknown field in the block is refused at its full
//!   dotted path, and the running policy stays.
//!
//! Same harness shape as `tests/auth_reload_e2e.rs`: std threads, ephemeral
//! ports, a child killed on drop, and a stderr reader for log lines.

mod common;

use common::free_port;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const ADMIN_TOKEN: &str = "declared-policy-e2e-admin-token";
const RECONCILED: &str = "declared tenant policy reconciled";
const SHADOWED: &str = "an admin write owns this row";

/// `auth.declared_policy` for one tenant `acme` granted `models`, plus the
/// rows each test needs.
fn acme(revision: u32, models: &str, extra: &str) -> String {
    format!(
        "    revision: {revision}\n    tenants:\n      - id: acme\n        \
         policy: {{ access: {{ only: [{models}] }} }}\n{extra}"
    )
}

#[test]
fn declared_rows_are_enforced_at_start_and_a_sighup_that_drops_them_removes_them() {
    let dir = scratch_dir("lifecycle");
    let ports = Ports::new();
    let rows = "        budget: { max_usd: \"25.50\", period: monthly }\n        \
                scoped_budgets:\n          - { name: openai-cap, max_usd: \"3\", period: daily, providers: [openai] }\n      \
                - id: capped\n        policy: { access: all }\n        limits: { requests_per_minute: 0 }\n";
    let mut proxy = Proxy::start(&dir, &ports.config(&acme(1, "gpt-4o-mini", rows)));
    proxy.wait_for_log(RECONCILED);
    let acme_key = mint_key(&proxy, "acme-key", "acme");
    let capped_key = mint_key(&proxy, "capped-key", "capped");

    assert_eq!(
        chat(&proxy, &acme_key, "gpt-4o-mini"),
        200,
        "the declared grant admits"
    );
    assert_eq!(
        chat(&proxy, &acme_key, "gpt-4o"),
        403,
        "the declared grant is all it admits"
    );
    assert_eq!(
        chat(&proxy, &capped_key, "gpt-4o"),
        429,
        "the declared limit refuses"
    );
    let spend = admin(&proxy, "GET", "/tenants/acme/spend", "");
    assert!(
        spend.contains(r#""budget_micro_usd":25500000"#),
        "the declared budget is in the published snapshot:\n{spend}"
    );
    let scoped = admin(&proxy, "GET", "/tenants/acme/scoped_budgets", "");
    assert!(
        scoped.contains(r#""name":"openai-cap""#) && scoped.contains(r#""provider:openai""#),
        "the declared scoped budget is in the published snapshot:\n{scoped}"
    );

    // Revision 2 drops `capped` and acme's budgets.
    proxy.reload(&ports.config(&acme(2, "gpt-4o-mini", "")));
    proxy.wait_for_log("SIGHUP: config reload succeeded");
    let line = proxy.wait_for_log(RECONCILED);
    assert!(line.contains("revision=2"), "{line}");
    assert_eq!(
        chat(&proxy, &capped_key, "gpt-4o"),
        403,
        "capped's policy and limit rows are gone, so it has no grant at all"
    );
    let spend = admin(&proxy, "GET", "/tenants/acme/spend", "");
    assert!(spend.contains(r#""budget_micro_usd":null"#), "{spend}");
    let scoped = admin(&proxy, "GET", "/tenants/acme/scoped_budgets", "");
    assert!(scoped.contains(r#""budgets":[]"#), "{scoped}");
    assert_eq!(
        chat(&proxy, &acme_key, "gpt-4o-mini"),
        200,
        "acme stays declared"
    );
}

#[test]
fn an_admin_write_shadows_the_file_until_it_is_handed_back() {
    let dir = scratch_dir("shadow");
    let ports = Ports::new();
    let mut proxy = Proxy::start(&dir, &ports.config(&acme(1, "gpt-4o-mini", "")));
    proxy.wait_for_log(RECONCILED);
    let key = mint_key(&proxy, "acme-key", "acme");

    // The operator widens acme by hand.
    admin_expect(
        &proxy,
        "PUT",
        "/tenants/acme/policy",
        r#"{"access":"all"}"#,
        204,
    );
    assert_eq!(chat(&proxy, &key, "gpt-4o"), 200);

    // The file moves acme to another model; the admin row keeps winning.
    proxy.reload(&ports.config(&acme(2, "gpt-4o-nano", "")));
    proxy.wait_for_log("SIGHUP: config reload succeeded");
    proxy.wait_for_log(RECONCILED);
    assert_eq!(
        chat(&proxy, &key, "gpt-4o"),
        200,
        "the admin value is still enforced"
    );
    let path = "auth.declared_policy.tenants[acme].policy";
    let warnings: Vec<&String> = proxy
        .log
        .iter()
        .filter(|line| line.contains(SHADOWED))
        .collect();
    assert_eq!(
        warnings.len(),
        1,
        "exactly one shadow warning, for the one admin-owned row: {warnings:?}"
    );
    assert!(
        warnings[0].contains(path),
        "the warning names {path}: {}",
        warnings[0]
    );

    // Hand-back: the row returns to the file, and the reconcile applies it.
    let body = admin_expect(&proxy, "DELETE", "/tenants/acme/override", "", 200);
    assert!(
        body.contains(r#""handed_back":["policy"]"#) && body.contains(r#""reconcile":"applied""#),
        "{body}"
    );
    assert_eq!(
        chat(&proxy, &key, "gpt-4o"),
        403,
        "the file value applies again"
    );
    assert_eq!(chat(&proxy, &key, "gpt-4o-nano"), 200);
    admin_expect(&proxy, "DELETE", "/tenants/nobody/override", "", 409);
}

#[test]
fn a_reload_with_an_unknown_declared_field_is_refused_at_its_dotted_path() {
    let dir = scratch_dir("strict");
    let ports = Ports::new();
    let mut proxy = Proxy::start(&dir, &ports.config(&acme(1, "gpt-4o-mini", "")));
    proxy.wait_for_log(RECONCILED);
    let key = mint_key(&proxy, "acme-key", "acme");

    proxy.reload(&ports.config(&acme(2, "gpt-4o", "        bogus: 1\n")));
    let failure = proxy.wait_for_log("SIGHUP: config reload failed");
    assert!(
        failure.contains("auth.declared_policy.tenants[0].bogus"),
        "the refusal names the full dotted path: {failure}"
    );
    assert_eq!(
        chat(&proxy, &key, "gpt-4o-mini"),
        200,
        "revision 1 still applies"
    );
    assert_eq!(chat(&proxy, &key, "gpt-4o"), 403);
}

// ------------------------------------------------------------------ helpers --

/// The ports one test's proxy keeps across reloads.
struct Ports {
    listen: u16,
    admin: u16,
    upstream: SocketAddr,
}

impl Ports {
    fn new() -> Ports {
        Ports {
            listen: free_port(),
            admin: free_port(),
            upstream: spawn_ok_upstream(),
        }
    }

    /// The dialect file with `declared` as the `auth.declared_policy` body.
    fn config(&self, declared: &str) -> String {
        format!(
            r#"version: 1
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
  hmac_secret: "declared-policy-e2e-secret"
  declared_policy:
{declared}"#,
            listen = self.listen,
            admin = self.admin,
            upstream = self.upstream,
        )
    }
}

/// `POST /keys` for `tenant`; returns the plaintext key.
fn mint_key(proxy: &Proxy, key_id: &str, tenant: &str) -> String {
    let body = admin_expect(
        proxy,
        "POST",
        "/keys",
        &format!(r#"{{"tenant":"{tenant}","key_id":"{key_id}"}}"#),
        201,
    );
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("POST /keys returns JSON");
    parsed["key"].as_str().expect("plaintext key").to_string()
}

/// An admin call expected to answer 200; returns the body.
fn admin(proxy: &Proxy, method: &str, path: &str, body: &str) -> String {
    admin_expect(proxy, method, path, body, 200)
}

fn admin_expect(proxy: &Proxy, method: &str, path: &str, body: &str, status: u16) -> String {
    let response = http(
        proxy.admin,
        method,
        path,
        &format!("Bearer {ADMIN_TOKEN}"),
        body,
    );
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status}")),
        "{method} {path}: expected {status}, got:\n{response}"
    );
    response
        .split_once("\r\n\r\n")
        .map_or(String::new(), |(_, b)| b.to_string())
}

/// One chat request with `key` for `model`; returns the status code.
fn chat(proxy: &Proxy, key: &str, model: &str) -> u16 {
    let response = http(
        proxy.listen,
        "POST",
        "/v1/chat/completions",
        &format!("Bearer {key}"),
        &format!(
            r#"{{"model":"{model}","max_tokens":8,"messages":[{{"role":"user","content":"hi"}}]}}"#
        ),
    );
    response
        .get(9..12)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line:\n{response}"))
}

fn http(addr: SocketAddr, method: &str, path: &str, authorization: &str, body: &str) -> String {
    let mut stream = TcpStream::connect_timeout(&addr, IO_TIMEOUT).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("write timeout");
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

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-declared-policy-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// A running proxy reading `llmproxy.yaml` in its scratch dir. Killed and
/// reaped on drop (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    path: PathBuf,
    listen: SocketAddr,
    admin: SocketAddr,
    stderr: Receiver<String>,
    /// Lines already matched by `wait_for_log`, so each wait sees only lines
    /// that arrived after the previous one.
    seen: usize,
    log: Vec<String>,
}

impl Proxy {
    fn start(dir: &Path, config: &str) -> Proxy {
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).expect("write config");
        let mut child = Command::new(BIN)
            .args([
                "--config",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
                // The spend recovery journal requires a node id.
                "--service-node",
                "declared-policy-e2e",
            ])
            .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn llm-proxy");
        let stderr = spawn_line_reader(child.stderr.take().expect("stderr is piped"));
        let proxy = Proxy {
            child,
            path,
            listen: SocketAddr::from(([127, 0, 0, 1], port_after(config, "listen: 127.0.0.1:"))),
            admin: SocketAddr::from(([127, 0, 0, 1], port_after(config, "admin: 127.0.0.1:"))),
            stderr,
            seen: 0,
            log: Vec::new(),
        };
        for addr in [proxy.admin, proxy.listen] {
            assert!(
                wait_for_connectable(addr, STARTUP_TIMEOUT),
                "{addr} did not become connectable in time"
            );
        }
        proxy
    }

    fn reload(&mut self, config: &str) {
        std::fs::write(&self.path, config).expect("rewrite config");
        let status = Command::new("kill")
            .args(["-HUP", &self.child.id().to_string()])
            .status()
            .expect("failed to send SIGHUP");
        assert!(status.success(), "kill -HUP failed");
    }

    /// Waits for the next stderr line containing `needle` and returns it,
    /// ANSI-stripped. Panics with the log seen so far on timeout.
    fn wait_for_log(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + RELOAD_TIMEOUT;
        loop {
            while let Ok(line) = self.stderr.try_recv() {
                self.log.push(strip_ansi(&line));
            }
            if let Some(i) = self.log[self.seen..]
                .iter()
                .position(|line| line.contains(needle))
            {
                self.seen += i + 1;
                return self.log[self.seen - 1].clone();
            }
            assert!(
                Instant::now() < deadline,
                "no log line containing {needle:?}; log:\n{}",
                self.log.join("")
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_line_reader(stderr: impl Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if tx.send(line + "\n").is_err() {
                break;
            }
        }
    });
    rx
}

/// Removes `ESC [ ... m` sequences; the formatter colors output even on a pipe.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn port_after(config: &str, prefix: &str) -> u16 {
    config
        .split(prefix)
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|port| port.parse().ok())
        .expect("config names the port")
}

fn wait_for_connectable(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// A provider that answers every request `200 {}`; only the proxy's auth
/// decision matters here.
fn spawn_ok_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
    let addr = listener.local_addr().expect("local addr");
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
