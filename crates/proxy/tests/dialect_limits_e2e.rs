//! Every dialect `limits[]` key and field is enforced by the real binary.
//!
//! Drives `llm-proxy --config` against std-thread mock upstreams. Each test
//! checks the refusal body and, through the mock's request counter, that a
//! refused request never reached the upstream (AGENTS.md "Coverage").
//!
//! Rust note: the mocks share a counter with the test through
//! `Arc<AtomicUsize>`. `Arc` lets two threads own it; the atomic needs no lock.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const WAIT: Duration = Duration::from_secs(10);

const HMAC_SECRET: &str = "dialect-limits-e2e-secret";
const ADMIN_TOKEN: &str = "dialect-limits-e2e-admin-token";
const TENANT: &str = "t1";

const RATE: &str = "request rate exceeded";
const TOKENS: &str = "token budget exceeded";
const STREAMS: &str = "too many concurrent streams";

#[test]
fn global_requests_per_minute_counts_every_caller() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("global");
    let mock = Mock::start(Duration::ZERO);
    let proxy = Proxy::start(
        &dir,
        &config_text(
            mock.addr,
            "  - { key: global, requests_per_minute: 2 }\n",
            false,
        ),
    );
    assert_admitted(&chat(&proxy, "gpt-4o", &[("authorization", "Bearer a")]));
    assert_admitted(&chat(&proxy, "gpt-4o", &[("authorization", "Bearer b")]));
    assert_eq!(mock.count(), 2);
    let third = chat(&proxy, "gpt-4o", &[("authorization", "Bearer c")]);
    assert_refused(&third, RATE);
    assert_eq!(mock.count(), 2, "the refused request reached the upstream");
    finish(proxy, &dir);
}

#[test]
fn client_ip_requests_per_minute_counts_the_peer() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("client-ip");
    let mock = Mock::start(Duration::ZERO);
    let proxy = Proxy::start(
        &dir,
        &config_text(
            mock.addr,
            "  - { key: client-ip, requests_per_minute: 1 }\n",
            false,
        ),
    );
    assert_admitted(&chat(
        &proxy,
        "gpt-4o",
        &[("x-forwarded-for", "203.0.113.1")],
    ));
    // The dialect trusts no hops: a new x-forwarded-for must not be a new bucket.
    let second = chat(&proxy, "gpt-4o", &[("x-forwarded-for", "203.0.113.2")]);
    assert_refused(&second, RATE);
    assert_eq!(mock.count(), 1, "the refused request reached the upstream");
    finish(proxy, &dir);
}

#[test]
fn tenant_tokens_per_minute_charges_actual_usage() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("tenant-tokens");
    let mock = Mock::start(Duration::ZERO);
    let proxy = Proxy::start(
        &dir,
        &config_text(
            mock.addr,
            "  - { key: tenant, tokens_per_minute: 10 }\n",
            true,
        ),
    );
    let key = mint_key(&proxy, "k1");
    allow_all_models(&proxy);
    let auth = format!("Bearer {key}");
    assert_admitted(&chat(&proxy, "gpt-4o", &[("authorization", &auth)]));
    // The mock reports 10 total tokens, which exactly spends the limit.
    let second = chat(&proxy, "gpt-4o", &[("authorization", &auth)]);
    assert_refused(&second, TOKENS);
    assert_eq!(mock.count(), 1, "the refused request reached the upstream");
    finish(proxy, &dir);
}

#[test]
fn header_key_buckets_per_value_and_skips_a_missing_header() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("header");
    let mock = Mock::start(Duration::ZERO);
    let proxy = Proxy::start(
        &dir,
        &config_text(
            mock.addr,
            "  - { key: \"header:x-api-key\", requests_per_minute: 1 }\n",
            false,
        ),
    );
    assert_admitted(&chat(&proxy, "gpt-4o", &[("x-api-key", "A")]));
    assert_refused(&chat(&proxy, "gpt-4o", &[("x-api-key", "A")]), RATE);
    assert_eq!(mock.count(), 1, "the refused request reached the upstream");
    assert_admitted(&chat(&proxy, "gpt-4o", &[("x-api-key", "B")]));
    // A request without the header is not counted by this rule.
    for _ in 0..3 {
        assert_admitted(&chat(&proxy, "gpt-4o", &[]));
    }
    assert_eq!(mock.count(), 5);
    finish(proxy, &dir);
}

#[test]
fn header_authorization_buckets_per_key_even_with_auth() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("header-authorization");
    let mock = Mock::start(Duration::ZERO);
    let proxy = Proxy::start(
        &dir,
        &config_text(
            mock.addr,
            "  - { key: \"header:authorization\", requests_per_minute: 1 }\n",
            true,
        ),
    );
    let key1 = format!("Bearer {}", mint_key(&proxy, "k1"));
    let key2 = format!("Bearer {}", mint_key(&proxy, "k2"));
    allow_all_models(&proxy);
    assert_admitted(&chat(&proxy, "gpt-4o", &[("authorization", &key1)]));
    assert_refused(&chat(&proxy, "gpt-4o", &[("authorization", &key1)]), RATE);
    assert_eq!(mock.count(), 1, "the refused request reached the upstream");
    // Same tenant, different header value: a per-tenant bucket would refuse.
    assert_admitted(&chat(&proxy, "gpt-4o", &[("authorization", &key2)]));
    assert_eq!(mock.count(), 2);
    finish(proxy, &dir);
}

#[test]
fn concurrent_sessions_holds_a_slot_while_a_response_is_in_flight() {
    let dir = scratch_dir("concurrent");
    let mock = Mock::start(Duration::from_millis(1500));
    let proxy = Proxy::start(
        &dir,
        &config_text(
            mock.addr,
            "  - { key: global, concurrent_sessions: 1 }\n",
            false,
        ),
    );
    let listen = proxy.listen;
    let first = std::thread::spawn(move || send_chat(listen, "gpt-4o", &[]));
    wait_until(|| mock.count() == 1, "the mock to receive request 1");

    let second = chat(&proxy, "gpt-4o", &[]);
    assert_refused(&second, STREAMS);
    assert_eq!(mock.count(), 1, "the refused request reached the upstream");

    assert_admitted(&first.join().expect("request 1 thread"));
    // The slot is released when the response ends; allow the proxy a moment.
    let deadline = Instant::now() + WAIT;
    loop {
        let third = chat(&proxy, "gpt-4o", &[]);
        if third.starts_with("HTTP/1.1 200") {
            break;
        }
        assert!(Instant::now() < deadline, "slot never released:\n{third}");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(mock.count(), 2);
    finish(proxy, &dir);
}

#[test]
fn models_scope_limits_only_matching_models() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("models");
    let mock = Mock::start(Duration::ZERO);
    let proxy = Proxy::start(
        &dir,
        &config_text(
            mock.addr,
            "  - { key: global, requests_per_minute: 1, models: [\"gpt-4*\"] }\n",
            false,
        ),
    );
    assert_admitted(&chat(&proxy, "gpt-4o", &[]));
    assert_refused(&chat(&proxy, "gpt-4o-mini", &[]), RATE);
    assert_eq!(mock.count(), 1, "the refused request reached the upstream");
    assert_admitted(&chat(&proxy, "claude-3", &[]));
    assert_admitted(&chat(&proxy, "claude-3", &[]));
    assert_eq!(mock.count(), 3);
    finish(proxy, &dir);
}

// ------------------------------------------------------------------ helpers --

fn finish(proxy: Proxy, dir: &Path) {
    drop(proxy);
    let _ = std::fs::remove_dir_all(dir);
}

/// The dialect file. `limits` is the indented list body; `auth` adds the
/// `auth` block and the admin listener a test needs to mint keys.
fn config_text(upstream: SocketAddr, limits: &str, auth: bool) -> String {
    let admin = if auth {
        format!(
            "admin: 127.0.0.1:{}\nauth:\n  hmac_secret: \"{HMAC_SECRET}\"\n",
            free_port()
        )
    } else {
        String::new()
    };
    format!(
        r#"version: 0
listen: 127.0.0.1:{listen}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
routes:
  - {{ model: "*", provider: openai }}
{admin}limits:
{limits}"#,
        listen = free_port(),
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-dialect-limits-e2e-{tag}-{}",
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
    admin: Option<SocketAddr>,
}

impl Proxy {
    fn start(dir: &Path, config: &str) -> Proxy {
        let listen = port_after(config, "listen: 127.0.0.1:").expect("listen port");
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
            admin: admin.map(|p| SocketAddr::from(([127, 0, 0, 1], p))),
        };
        for addr in proxy.admin.into_iter().chain([proxy.listen]) {
            assert!(
                wait_for_connectable(addr, STARTUP_TIMEOUT),
                "listener at {addr} did not become connectable in time"
            );
        }
        proxy
    }

    fn admin(&self) -> SocketAddr {
        self.admin.expect("this test configured an admin listener")
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn port_after(config: &str, prefix: &str) -> Option<u16> {
    config
        .split(prefix)
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// `POST /keys` on the admin listener; returns the plaintext key.
fn mint_key(proxy: &Proxy, key_id: &str) -> String {
    let response = http_request(
        "POST",
        proxy.admin(),
        "/keys",
        &[("authorization", &format!("Bearer {ADMIN_TOKEN}"))],
        &format!(r#"{{"tenant":"{TENANT}","key_id":"{key_id}"}}"#),
    );
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "POST /keys did not mint a key:\n{response}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(response_body(&response)).expect("POST /keys returns JSON");
    parsed["key"].as_str().expect("plaintext key").to_string()
}

/// `PUT /tenants/{TENANT}/policy` granting every model. Without it a tenant
/// with no stored policy is refused with 403.
fn allow_all_models(proxy: &Proxy) {
    let put = http_request(
        "PUT",
        proxy.admin(),
        &format!("/tenants/{TENANT}/policy"),
        &[("authorization", &format!("Bearer {ADMIN_TOKEN}"))],
        r#"{"access":"all"}"#,
    );
    assert!(put.starts_with("HTTP/1.1 204"), "PUT policy:\n{put}");
}

fn chat(proxy: &Proxy, model: &str, headers: &[(&str, &str)]) -> String {
    send_chat(proxy.listen, model, headers)
}

fn send_chat(listen: SocketAddr, model: &str, headers: &[(&str, &str)]) -> String {
    http_request(
        "POST",
        listen,
        "/v1/chat/completions",
        headers,
        &format!(
            r#"{{"model":"{model}","max_tokens":8,"messages":[{{"role":"user","content":"hi"}}]}}"#
        ),
    )
}

fn response_body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

fn http_request(
    method: &str,
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    let extra: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: proxy.local\r\n{extra}\
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

/// Polls `condition` until it holds, failing the test after [`WAIT`].
fn wait_until(condition: impl Fn() -> bool, what: &str) {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
}

/// A mock OpenAI upstream that reports 10 total tokens and counts the requests
/// it fully received. `delay` holds each response back, for the concurrency test.
struct Mock {
    addr: SocketAddr,
    received: Arc<AtomicUsize>,
}

impl Mock {
    fn start(delay: Duration) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
        let addr = listener.local_addr().expect("no local addr");
        let received = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&received);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let counter = Arc::clone(&counter);
                std::thread::spawn(move || {
                    if read_request(&mut stream).is_none() {
                        return;
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(delay);
                    let body = r#"{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":6,"completion_tokens":4,"total_tokens":10}}"#;
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
        Mock { addr, received }
    }

    fn count(&self) -> usize {
        self.received.load(Ordering::SeqCst)
    }
}

/// Reads one full request (head and Content-Length body); `None` on error.
fn read_request(stream: &mut TcpStream) -> Option<()> {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
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
    let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
    let content_length: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let mut have = raw.len() - (head_end + 4);
    while have < content_length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => have += n,
        }
    }
    Some(())
}

fn assert_admitted(response: &str) {
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

/// A 429 from the limiter itself: the body names the refusing limit, which
/// the mock upstream (always 200) never produces.
fn assert_refused(response: &str, body: &str) {
    assert!(
        response.starts_with("HTTP/1.1 429") && response.contains(body),
        "expected 429 `{body}`:\n{response}"
    );
}

/// Windows are one minute and epoch-aligned. A test that counts requests in
/// one window waits out the last seconds of a minute so it cannot straddle one.
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
