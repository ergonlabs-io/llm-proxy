//! Two real `llm-proxy` processes on one real Redis enforce one tenant and one
//! key `concurrent_streams` ceiling together, and a replica killed mid-stream
//! releases its slot within the lease TTL (ADR-0006 amendment E).
//!
//! `#[ignore]`d because CI has no Redis, like `control_redis`'s store tests.
//! Run with `make tq-redis`, or:
//!
//!   docker run -d --rm -p 6390:6379 --name llmproxy-test-redis redis:7-alpine
//!   LLM_PROXY_TEST_REDIS=redis://127.0.0.1:6390 \
//!     cargo nextest run -p proxy --run-ignored all -E 'test(redis)'
//!
//! The second process starts after the admin writes made through the first,
//! so it loads them at boot rather than waiting for the policy poll. Each run
//! uses its own Redis namespace.
//!
//! A replica learns the fleet's count only through its own publish, so
//! before asserting a refusal the test polls with a request the mock answers
//! at once: an early admission there frees its slot immediately and cannot
//! disturb the streams the test holds.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a held stream may stay open: far past every wait below.
const HOLD_TIMEOUT: Duration = Duration::from_secs(120);
const WAIT: Duration = Duration::from_secs(20);

/// `DEFAULT_LEASE_TTL` and `DEFAULT_LEASE_PUBLISH_INTERVAL` in
/// `proxy-filters`' `window_counter.rs`.
const LEASE_TTL: Duration = Duration::from_secs(5);
const PUBLISH_INTERVAL: Duration = Duration::from_secs(1);

const HMAC_SECRET: &str = "shared-limits-e2e-secret";
const ADMIN_TOKEN: &str = "shared-limits-e2e-admin-token";
const TENANT: &str = "t1";
const STREAMS: &str = "too many concurrent streams";

/// The mock holds a request for this model until released.
const HELD: &str = "held";
/// The mock answers a request for this model at once.
const FAST: &str = "fast";

#[test]
#[ignore = "needs a real Redis: set LLM_PROXY_TEST_REDIS"]
fn redis_two_processes_share_tenant_and_key_stream_ceilings_and_a_killed_replica_releases() {
    let redis = std::env::var("LLM_PROXY_TEST_REDIS").expect(
        "LLM_PROXY_TEST_REDIS is not set -- start a Redis with `docker run -d --rm \
         -p 6390:6379 --name llmproxy-test-redis redis:7-alpine` and set \
         LLM_PROXY_TEST_REDIS=redis://127.0.0.1:6390",
    );
    let namespace = format!(
        "llmproxy-e2e-streams-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after the epoch")
            .as_nanos()
    );
    let mock = Mock::start();
    let dir_a = scratch_dir("a");
    let dir_b = scratch_dir("b");

    let mut a = Proxy::start(&dir_a, &config_text(mock.addr, &redis, &namespace));
    let k1 = mint_key(&a, "k1");
    let k2 = mint_key(&a, "k2");
    admin_put(
        &a,
        &format!("/tenants/{TENANT}/policy"),
        r#"{"access":"all"}"#,
    );
    admin_put(
        &a,
        &format!("/tenants/{TENANT}/limits"),
        r#"{"limits":{"concurrent_streams":2}}"#,
    );
    admin_put(
        &a,
        "/keys/k1/limits",
        r#"{"limits":{"concurrent_streams":1}}"#,
    );
    let b = Proxy::start(&dir_b, &config_text(mock.addr, &redis, &namespace));
    let (k1, k2) = (format!("Bearer {k1}"), format!("Bearer {k2}"));

    // Key ceiling: k1 holds its one stream on A, so B refuses k1.
    let a_k1 = hold(&a, &k1);
    mock.wait_for_held(1);
    wait_for_refusal(&b, &k1, "B to learn A's k1 stream");
    let before = mock.held();
    assert_refused(&send_chat(b.listen, HELD, &k1, IO_TIMEOUT), STREAMS);
    assert_eq!(
        mock.held(),
        before,
        "the refused stream reached the upstream"
    );

    // Tenant ceiling: k2 has no key limit, so B admits it beside A's k1 and
    // the tenant reaches 2; then A refuses k2.
    let b_k2 = hold(&b, &k2);
    mock.wait_for_held(2);
    wait_for_refusal(&a, &k2, "A to learn B's k2 stream");
    assert_refused(&send_chat(a.listen, HELD, &k2, IO_TIMEOUT), STREAMS);
    assert_eq!(mock.held(), 2, "the refused stream reached the upstream");

    // Kill A while its k1 stream is in flight. Its lease rows are never
    // released; they expire one TTL after A's last publish, and B admits k1
    // again once its own next publish sees that.
    a.kill();
    let killed = Instant::now();
    let deadline = killed + LEASE_TTL + 3 * PUBLISH_INTERVAL + WAIT;
    let released_after = loop {
        let response = send_chat(b.listen, FAST, &k1, IO_TIMEOUT);
        if response.starts_with("HTTP/1.1 200") {
            break killed.elapsed();
        }
        assert_refused(&response, STREAMS);
        assert!(Instant::now() < deadline, "A's slot was never released");
        std::thread::sleep(Duration::from_millis(100));
    };
    eprintln!("a killed replica's k1 slot was released after {released_after:?}");
    assert!(
        released_after <= LEASE_TTL + 2 * PUBLISH_INTERVAL,
        "released after {released_after:?}: more than the lease TTL plus the \
         two publishes that carry it"
    );

    mock.release();
    let _ = a_k1.join();
    assert_admitted(&b_k2.join().expect("B's k2 stream"));
    drop(b);
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// Polls `proxy` with a request the mock answers at once until the limiter
/// refuses it for streams.
fn wait_for_refusal(proxy: &Proxy, auth: &str, what: &str) {
    let deadline = Instant::now() + WAIT;
    loop {
        let response = send_chat(proxy.listen, FAST, auth, IO_TIMEOUT);
        if response.starts_with("HTTP/1.1 429") {
            assert_refused(&response, STREAMS);
            return;
        }
        assert_admitted(&response);
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn hold(proxy: &Proxy, auth: &str) -> std::thread::JoinHandle<String> {
    let (listen, auth) = (proxy.listen, auth.to_string());
    std::thread::spawn(move || send_chat(listen, HELD, &auth, HOLD_TIMEOUT))
}

// ------------------------------------------------------------------ helpers --

fn config_text(upstream: SocketAddr, redis: &str, namespace: &str) -> String {
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
  store:
    shared: {{ url: "{redis}", namespace: "{namespace}" }}
"#,
        listen = free_port(),
        admin = free_port(),
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-shared-limits-e2e-{tag}-{}",
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
        let listen = port_after(config, "listen: 127.0.0.1:").expect("listen port");
        let admin = port_after(config, "admin: 127.0.0.1:").expect("admin port");
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

    /// SIGKILL: no shutdown path runs, as when a replica crashes.
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.kill();
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
        proxy.admin,
        "/keys",
        &[("authorization", &format!("Bearer {ADMIN_TOKEN}"))],
        &format!(r#"{{"tenant":"{TENANT}","key_id":"{key_id}"}}"#),
        IO_TIMEOUT,
    );
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "POST /keys did not mint a key:\n{response}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(response_body(&response)).expect("POST /keys returns JSON");
    parsed["key"].as_str().expect("plaintext key").to_string()
}

fn admin_put(proxy: &Proxy, path: &str, body: &str) {
    let response = http_request(
        "PUT",
        proxy.admin,
        path,
        &[("authorization", &format!("Bearer {ADMIN_TOKEN}"))],
        body,
        IO_TIMEOUT,
    );
    assert!(
        response.starts_with("HTTP/1.1 204"),
        "PUT {path}:\n{response}"
    );
}

fn send_chat(listen: SocketAddr, model: &str, auth: &str, timeout: Duration) -> String {
    http_request(
        "POST",
        listen,
        "/v1/chat/completions",
        &[("authorization", auth)],
        &format!(
            r#"{{"model":"{model}","max_tokens":8,"messages":[{{"role":"user","content":"hi"}}]}}"#
        ),
        timeout,
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
    timeout: Duration,
) -> String {
    let Ok(mut stream) = TcpStream::connect(addr) else {
        return String::new();
    };
    stream
        .set_read_timeout(Some(timeout))
        .expect("set_read_timeout");
    let extra: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    let _ = stream.write_all(
        format!(
            "{method} {path} HTTP/1.1\r\nHost: proxy.local\r\n{extra}\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
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

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
}

/// A mock OpenAI upstream. A request for [`HELD`] is counted and held until
/// [`Mock::release`]; any other model is answered at once.
struct Mock {
    addr: SocketAddr,
    held: Arc<AtomicUsize>,
    released: Arc<AtomicBool>,
}

impl Mock {
    fn start() -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
        let addr = listener.local_addr().expect("no local addr");
        let held = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let (held_count, gate) = (Arc::clone(&held), Arc::clone(&released));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (held_count, gate) = (Arc::clone(&held_count), Arc::clone(&gate));
                std::thread::spawn(move || {
                    let Some(request) = read_request(&mut stream) else {
                        return;
                    };
                    if request.contains(&format!(r#""model":"{HELD}""#)) {
                        held_count.fetch_add(1, Ordering::SeqCst);
                        let deadline = Instant::now() + HOLD_TIMEOUT;
                        while !gate.load(Ordering::SeqCst) && Instant::now() < deadline {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                    }
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
        Mock {
            addr,
            held,
            released,
        }
    }

    fn held(&self) -> usize {
        self.held.load(Ordering::SeqCst)
    }

    fn wait_for_held(&self, n: usize) {
        let deadline = Instant::now() + WAIT;
        while self.held() < n {
            assert!(Instant::now() < deadline, "the mock never held {n} streams");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
    }
}

/// Reads one full request (head and Content-Length body) and returns it as
/// text; `None` on error.
fn read_request(stream: &mut TcpStream) -> Option<String> {
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
    while raw.len() - (head_end + 4) < content_length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    }
    Some(String::from_utf8_lossy(&raw).to_string())
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
