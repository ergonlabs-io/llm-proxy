//! A SIGHUP reload of a `--config` file that changes `auth.hmac_secret`,
//! `auth.keys` or `auth.spend.recovery_journal_path` is refused, and the proxy
//! keeps serving the configuration it started with. A restart applies the
//! change.
//!
//! The auth control plane (store, bootstrap keys, the secret keys are minted
//! with) is built once per serve. Before the refusal existed, a reload that
//! changed the secret installed it for verification only, so every key was
//! refused with 401 while the log said the reload succeeded; a reload that
//! removed a configured key left it authenticating, silently.
//!
//! Drives the real binary. Same harness shape as `tests/auth_store_e2e.rs`
//! (std threads, ephemeral ports, a child killed on drop), plus a stderr
//! reader so the reload's log line can be awaited.

mod common;

use common::free_port;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use proxy_control::auth::{digest_hex, HmacSecret};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const SECRET: &str = "auth-reload-e2e-secret";
const ROTATED_SECRET: &str = "auth-reload-e2e-rotated-secret";
const ADMIN_TOKEN: &str = "auth-reload-e2e-admin-token";
const KEY_1: &str = "llmp_auth-reload-e2e-key-1";
const KEY_2: &str = "llmp_auth-reload-e2e-key-2";
const REFUSED: &str = "SIGHUP: config reload refused";
const SUCCEEDED: &str = "SIGHUP: config reload succeeded";

#[test]
fn a_reload_that_changes_the_hmac_secret_is_refused_and_every_key_keeps_working() {
    let dir = scratch_dir("secret");
    let ports = Ports::new();
    let mut proxy = Proxy::start(&dir, &ports.config(SECRET, &[(KEY_1, false)], ""));
    let minted_before = mint_key(&proxy, "minted-before");

    // The operator re-digests the configured key under the new secret, as a
    // rotation would require.
    proxy.reload(&ports.config(ROTATED_SECRET, &[(KEY_1, false)], ""));
    let refusal = proxy.wait_for_log(REFUSED);
    assert!(
        refusal.contains("auth.hmac_secret"),
        "the refusal must name the field: {refusal}"
    );
    assert!(
        !refusal.contains(SECRET) && !refusal.contains(ROTATED_SECRET),
        "the refusal must not render a secret: {refusal}"
    );

    // Minting and verifying still share the running secret.
    assert_status(&proxy, KEY_1, 200, "the configured key after the refusal");
    assert_status(
        &proxy,
        &minted_before,
        200,
        "a key minted before the refusal",
    );
    let minted_after = mint_key(&proxy, "minted-after");
    assert_status(&proxy, &minted_after, 200, "a key minted after the refusal");
    drop(proxy);

    // A restart applies the new secret to both sides.
    let restarted = Proxy::start(&dir, &ports.config(ROTATED_SECRET, &[(KEY_1, false)], ""));
    assert_status(
        &restarted,
        KEY_1,
        200,
        "the configured key after the restart",
    );
    let minted = mint_key(&restarted, "minted-restarted");
    assert_status(&restarted, &minted, 200, "a key minted after the restart");
    drop(restarted);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_reload_that_removes_or_revokes_a_configured_key_is_refused_until_a_restart() {
    let dir = scratch_dir("keys");
    let ports = Ports::new();
    let both = [(KEY_1, false), (KEY_2, false)];
    let mut proxy = Proxy::start(&dir, &ports.config(SECRET, &both, ""));

    proxy.reload(&ports.config(SECRET, &[(KEY_1, false)], ""));
    let removed = proxy.wait_for_log(REFUSED);
    assert!(
        removed.contains("auth.keys"),
        "the refusal must name the field: {removed}"
    );
    proxy.reload(&ports.config(SECRET, &[(KEY_1, false), (KEY_2, true)], ""));
    let revoked = proxy.wait_for_log(REFUSED);
    assert!(
        revoked.contains("auth.keys"),
        "the refusal must name the field: {revoked}"
    );
    // Refused, so the running key list still holds key 2.
    assert_status(&proxy, KEY_2, 200, "key 2 after the refused reloads");

    // A reload that leaves `auth` alone still applies, and the chain it
    // rebuilds keeps the running keys.
    proxy.reload(&ports.config(
        SECRET,
        &both,
        "  - { model: \"other-*\", provider: openai }\n",
    ));
    proxy.wait_for_log(SUCCEEDED);
    assert_status(&proxy, KEY_1, 200, "key 1 after an unrelated reload");
    assert_status(&proxy, KEY_2, 200, "key 2 after an unrelated reload");
    drop(proxy);

    // The removal takes effect at restart: key 2 is refused, key 1 is not.
    let restarted = Proxy::start(&dir, &ports.config(SECRET, &[(KEY_1, false)], ""));
    assert_status(&restarted, KEY_2, 401, "the removed key after the restart");
    assert_status(&restarted, KEY_1, 200, "the kept key after the restart");
    drop(restarted);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The spend accumulator opens its recovery journal once per serve and
/// outlives a reload, so a reload that moves or drops the journal could only
/// be ignored. It is refused instead, naming the dialect field.
#[test]
fn a_reload_that_changes_the_spend_recovery_journal_is_refused() {
    let dir = scratch_dir("journal");
    let ports = Ports::new();
    let store = dir.join("store.redb");
    let first = dir.join("journal-a.redb");
    let moved = dir.join("journal-b.redb");
    let with_journal = |journal: Option<&Path>, extra_routes: &str| {
        let spend = journal.map_or(String::new(), |path| {
            format!(
                "  spend: {{ recovery_journal_path: \"{}\" }}\n",
                path.display()
            )
        });
        format!(
            "{}  store: {{ persistent: {{ path: \"{}\" }} }}\n{spend}",
            ports.config(SECRET, &[(KEY_1, false)], extra_routes),
            store.display()
        )
    };
    let mut proxy = Proxy::start(&dir, &with_journal(Some(&first), ""));
    assert!(first.exists(), "the journal is opened at startup");

    for (journal, what) in [(Some(moved.as_path()), "moved"), (None, "removed")] {
        proxy.reload(&with_journal(journal, ""));
        let refusal = proxy.wait_for_log(REFUSED);
        assert!(
            refusal.contains("auth.spend.recovery_journal_path"),
            "the refusal of a {what} journal must name the field: {refusal}"
        );
    }
    assert!(
        !moved.exists(),
        "a refused reload must not open the new journal"
    );
    assert_status(&proxy, KEY_1, 200, "the running chain after the refusals");

    // A reload that leaves the journal alone still applies.
    proxy.reload(&with_journal(
        Some(&first),
        "  - { model: \"other-*\", provider: openai }\n",
    ));
    proxy.wait_for_log(SUCCEEDED);
    assert_status(&proxy, KEY_1, 200, "after an unrelated reload");
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

/// The ports one test's proxy keeps across reloads and restarts.
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

    /// The dialect file: `keys` are `(plaintext, revoked)`, digested under
    /// `secret`; `extra_routes` go before the catch-all route.
    fn config(&self, secret: &str, keys: &[(&str, bool)], extra_routes: &str) -> String {
        let hmac = HmacSecret::new(secret.as_bytes());
        let keys: String = keys
            .iter()
            .enumerate()
            .map(|(i, (plaintext, revoked))| {
                format!(
                    "    - {{ id: \"key-{i}\", tenant: \"tenant-a\", digest: \"{}\", \
                     revoked: {revoked} }}\n",
                    digest_hex(&hmac, plaintext)
                )
            })
            .collect();
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
{extra_routes}  - {{ model: "*", provider: openai }}
auth:
  hmac_secret: "{secret}"
  enforce: {{ tenants_without_policy: allow }}
  keys:
{keys}"#,
            listen = self.listen,
            admin = self.admin,
            upstream = self.upstream,
        )
    }
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-auth-reload-e2e-{tag}-{}",
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
                "auth-reload-e2e",
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

/// `POST /keys`; returns the plaintext key the response carries once.
fn mint_key(proxy: &Proxy, key_id: &str) -> String {
    let response = http_post(
        proxy.admin,
        "/keys",
        &format!("Bearer {ADMIN_TOKEN}"),
        &format!(r#"{{"tenant":"tenant-a","key_id":"{key_id}"}}"#),
    );
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "POST /keys did not mint a key:\n{response}"
    );
    let body = response.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    let parsed: serde_json::Value = serde_json::from_str(body).expect("POST /keys returns JSON");
    parsed["key"].as_str().expect("plaintext key").to_string()
}

fn assert_status(proxy: &Proxy, key: &str, status: u16, what: &str) {
    let response = http_post(
        proxy.listen,
        "/v1/chat/completions",
        &format!("Bearer {key}"),
        r#"{"model":"gpt-4o-mini","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
    );
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status}")),
        "{what}: expected {status}, got:\n{response}"
    );
}

fn http_post(addr: SocketAddr, path: &str, authorization: &str, body: &str) -> String {
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
