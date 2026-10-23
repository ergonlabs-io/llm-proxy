//! `auth.spend.recovery_journal_path` keeps spend accrued during a store
//! outage across a `kill -9`, driven through the real binary in `--config`
//! mode.
//!
//! The proxy reaches Redis through a forwarder this test controls. With the
//! forwarder down, a request accrues spend the store never confirms; the
//! proxy is killed with SIGKILL, the forwarder comes back, and the proxy
//! restarts. A third process with no journal then reads the key's spend from
//! the store (a budgeted key's row is loaded at boot), so the assertion is on
//! what reached the store, not on the restarted process's memory. The same
//! run without the journal is the negative control: that spend is lost.
//!
//! `#[ignore]`d because CI has no Redis, like `shared_limits_redis_e2e`. Run
//! with `make tq-redis`, or:
//!
//!   docker run -d --rm -p 6390:6379 --name llmproxy-test-redis redis:7-alpine
//!   LLM_PROXY_TEST_REDIS=redis://127.0.0.1:6390 \
//!     cargo nextest run -p proxy --run-ignored all -E 'test(redis)'

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Several spend flush ticks (5 s each by default).
const WAIT: Duration = Duration::from_secs(30);

const HMAC_SECRET: &str = "spend-journal-e2e-secret";
const ADMIN_TOKEN: &str = "spend-journal-e2e-admin-token";
const TENANT: &str = "t1";
const KEY_ID: &str = "k1";
const NODE: &str = "replica-a";

#[test]
#[ignore = "needs a real Redis: set LLM_PROXY_TEST_REDIS"]
fn redis_spend_journal_replays_outage_spend_after_kill_9() {
    let lost = run_outage_then_kill(/* journal */ false);
    assert_eq!(
        lost.stored_after_restart, 0,
        "negative control: without a journal the outage spend ({} micro-USD) must be lost",
        lost.accrued
    );

    let kept = run_outage_then_kill(/* journal */ true);
    assert_eq!(
        kept.stored_after_restart, kept.accrued,
        "the journal must replay the outage spend into the store"
    );
}

struct Outcome {
    /// Spend the first process accrued while the store was unreachable.
    accrued: u64,
    /// That key's spend as a fresh process reads it from the store.
    stored_after_restart: u64,
}

fn run_outage_then_kill(journal: bool) -> Outcome {
    let redis = std::env::var("LLM_PROXY_TEST_REDIS").expect(
        "LLM_PROXY_TEST_REDIS is not set -- start a Redis with `docker run -d --rm \
         -p 6390:6379 --name llmproxy-test-redis redis:7-alpine` and set \
         LLM_PROXY_TEST_REDIS=redis://127.0.0.1:6390",
    );
    let redis_addr = redis
        .strip_prefix("redis://")
        .and_then(|rest| rest.split('/').next())
        .expect("LLM_PROXY_TEST_REDIS is redis://host:port[/db]")
        .to_string();
    let forwarder = Forwarder::start(redis_addr);
    let namespace = format!(
        "llmproxy-e2e-spend-journal-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after the epoch")
            .as_nanos()
    );
    let mock = start_mock();
    let dir = scratch_dir(if journal { "journal" } else { "none" });
    let journal_path = dir.join("spend-journal.redb");
    let journaled = config_text(
        mock,
        forwarder.addr,
        &namespace,
        journal.then_some(journal_path.as_path()),
    );

    let first = Proxy::start(&dir, &journaled);
    first.admin(
        "PUT",
        &format!("/tenants/{TENANT}/policy"),
        r#"{"access":"all"}"#,
        204,
    );
    let minted = first.admin(
        "POST",
        "/keys",
        &format!(r#"{{"tenant":"{TENANT}","key_id":"{KEY_ID}"}}"#),
        201,
    );
    let key: serde_json::Value =
        serde_json::from_str(response_body(&minted)).expect("mint response is JSON");
    let bearer = format!("Bearer {}", key["key"].as_str().expect("plaintext key"));
    // A budget makes the third process load this key's row from the store
    // at boot, which is how the test reads what the store holds.
    first.admin(
        "PUT",
        &format!("/keys/{KEY_ID}/budget"),
        r#"{"budget":{"max_usd":"1000.00","period":"daily"}}"#,
        204,
    );

    forwarder.set_up(false);
    let response = chat(first.listen, &bearer);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let accrued = first.key_spend()["spend_micro_usd"]
        .as_u64()
        .expect("spend_micro_usd");
    assert!(accrued > 0, "the request must accrue spend");
    if journal {
        // The checkpoint is committed before the store write the outage
        // fails. Its gauge sums every journaled row, and the tenant's
        // aggregate row carries the same charge as the key's, so it reads at
        // least the key's accrual.
        wait_until(
            || {
                first.key_spend()["journal_pending_micro_usd"]
                    .as_u64()
                    .is_some_and(|pending| pending >= accrued)
            },
            "the journal checkpoint to hold the outage spend",
        );
    }
    first.kill_9();

    forwarder.set_up(true);
    // A journaled start replays before it serves, so once its listeners
    // accept, the store holds whatever the journal carried.
    let restarted = Proxy::start(&dir, &journaled);
    restarted.kill_9();

    let reader = Proxy::start(&dir, &config_text(mock, forwarder.addr, &namespace, None));
    let stored_after_restart = reader.key_spend()["spend_micro_usd"]
        .as_u64()
        .expect("spend_micro_usd");
    drop(reader);
    let _ = std::fs::remove_dir_all(&dir);
    Outcome {
        accrued,
        stored_after_restart,
    }
}

fn config_text(
    upstream: SocketAddr,
    redis: SocketAddr,
    namespace: &str,
    journal: Option<&Path>,
) -> String {
    let spend = journal.map_or(String::new(), |path| {
        format!(
            "  spend: {{ recovery_journal_path: \"{}\" }}\n",
            path.display()
        )
    });
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
  store: {{ shared: {{ url: "redis://{redis}/0", namespace: "{namespace}" }} }}
  # Only spend is under test; the other store-backed controls stay out of
  # the outage.
  enforce: {{ limits: false, object_ownership: false }}
{spend}pricing:
  price_list:
    version: spend-journal-e2e
    effective_from: "2026-01-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: gpt-4o-mini
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 10000
            cached_input_nanodollars_per_token: 1
            cache_write_nanodollars_per_token: 1
            output_nanodollars_per_token: 100000
"#,
        listen = free_port(),
        admin = free_port(),
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-spend-journal-e2e-{tag}-{}",
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
        let port = |prefix: &str| -> u16 {
            config
                .split(prefix)
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|port| port.parse().ok())
                .unwrap_or_else(|| panic!("no `{prefix}` port in the config"))
        };
        let listen = SocketAddr::from(([127, 0, 0, 1], port("listen: 127.0.0.1:")));
        let admin = SocketAddr::from(([127, 0, 0, 1], port("admin: 127.0.0.1:")));
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).expect("write temp config");
        let child = Command::new(BIN)
            .args([
                "--config",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
                "--service-node",
                NODE,
            ])
            .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn llm-proxy");
        let mut proxy = Proxy {
            child,
            listen,
            admin,
        };
        for addr in [admin, listen] {
            let deadline = Instant::now() + STARTUP_TIMEOUT;
            while TcpStream::connect(addr).is_err() {
                if let Some(status) = proxy.child.try_wait().expect("try_wait") {
                    panic!("llm-proxy exited during startup: {status}");
                }
                assert!(Instant::now() < deadline, "{addr} did not accept in time");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        proxy
    }

    /// SIGKILL: no drain, no final flush.
    fn kill_9(mut self) {
        self.child.kill().expect("SIGKILL llm-proxy");
        self.child.wait().expect("reap llm-proxy");
    }

    fn admin(&self, method: &str, path: &str, body: &str, status: u16) -> String {
        let response = http_request(
            method,
            self.admin,
            path,
            &[("authorization", &format!("Bearer {ADMIN_TOKEN}"))],
            body,
        );
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{method} {path} expected {status}:\n{response}"
        );
        response
    }

    fn key_spend(&self) -> serde_json::Value {
        let response = self.admin("GET", &format!("/keys/{KEY_ID}/spend"), "", 200);
        serde_json::from_str(response_body(&response))
            .unwrap_or_else(|e| panic!("spend response is not JSON ({e}):\n{response}"))
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A TCP forwarder to Redis that the test can take down: while down it
/// closes every open connection and every new one at once, so each store
/// call fails fast.
struct Forwarder {
    addr: SocketAddr,
    up: Arc<AtomicBool>,
    open: Arc<Mutex<Vec<TcpStream>>>,
}

impl Forwarder {
    fn start(redis: String) -> Forwarder {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind forwarder");
        let addr = listener.local_addr().expect("forwarder addr");
        let up = Arc::new(AtomicBool::new(true));
        let open = Arc::new(Mutex::new(Vec::new()));
        let (accept_up, accept_open) = (Arc::clone(&up), Arc::clone(&open));
        std::thread::spawn(move || {
            for client in listener.incoming() {
                let Ok(client) = client else { continue };
                if !accept_up.load(Ordering::SeqCst) {
                    let _ = client.shutdown(Shutdown::Both);
                    continue;
                }
                let Ok(server) = TcpStream::connect(&redis) else {
                    continue;
                };
                let mut open = accept_open.lock().expect("forwarder list lock");
                for stream in [&client, &server] {
                    if let Ok(clone) = stream.try_clone() {
                        open.push(clone);
                    }
                }
                drop(open);
                pipe(&client, &server);
                pipe(&server, &client);
            }
        });
        Forwarder { addr, up, open }
    }

    fn set_up(&self, up: bool) {
        self.up.store(up, Ordering::SeqCst);
        if !up {
            for stream in self.open.lock().expect("forwarder list lock").drain(..) {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }
}

/// Copies `from` to `to` on a thread until either side closes.
fn pipe(from: &TcpStream, to: &TcpStream) {
    let (Ok(mut from), Ok(mut to)) = (from.try_clone(), to.try_clone()) else {
        return;
    };
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut from, &mut to);
        let _ = to.shutdown(Shutdown::Both);
        let _ = from.shutdown(Shutdown::Both);
    });
}

/// A mock OpenAI upstream that answers every request with fixed usage.
fn start_mock() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
    let addr = listener.local_addr().expect("mock addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                if read_request(&mut stream).is_none() {
                    return;
                }
                let body = r#"{"id":"x","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":6,"completion_tokens":4,"total_tokens":10}}"#;
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
    addr
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

fn chat(listen: SocketAddr, bearer: &str) -> String {
    http_request(
        "POST",
        listen,
        "/v1/chat/completions",
        &[("authorization", bearer)],
        r#"{"model":"gpt-4o-mini","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
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

/// Polls `condition` until it holds, failing the test after [`WAIT`].
fn wait_until(condition: impl Fn() -> bool, what: &str) {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}
