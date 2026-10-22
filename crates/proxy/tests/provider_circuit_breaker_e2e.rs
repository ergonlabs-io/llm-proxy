//! `providers.<name>.circuit_breakers.max_requests` is enforced by the real
//! binary, per provider.
//!
//! Drives `llm-proxy --config` against std-thread mock upstreams. The capped
//! provider's mock holds every response until the test opens its gate, so the
//! requests in flight are known exactly and no assertion depends on timing.
//! A shed request answers while the gate is still closed, which also proves
//! the overflow 503 fails fast instead of queueing (S5).
//!
//! Rust note: the gate and counters are `Arc<Atomic*>` shared between the
//! test thread and the mock's threads; atomics need no lock.

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const WAIT: Duration = Duration::from_secs(10);

/// With `max_requests: 2`, two requests in flight to `capped` fill its
/// budget: the third gets the UpstreamOverflow 503 without reaching the
/// upstream, while `open` on the same proxy still serves. Once the two finish,
/// `capped` serves again.
#[test]
fn max_requests_sheds_the_third_concurrent_request_while_another_provider_serves() {
    let dir = scratch_dir("direct");
    let capped = Mock::start(true);
    let open = Mock::start(false);
    let proxy = Proxy::start(
        &dir,
        &config_text(
            capped.addr,
            open.addr,
            "    circuit_breakers: { max_requests: 2 }\n",
            "",
        ),
    );

    let listen = proxy.listen;
    let in_flight: Vec<_> = (0..2)
        .map(|_| std::thread::spawn(move || send_chat(listen, "capped-model")))
        .collect();
    wait_until(
        || capped.count() == 2,
        "both requests to reach the capped mock",
    );

    let third = send_chat(listen, "capped-model");
    assert_overflow(&third);
    assert_eq!(capped.count(), 2, "the shed request reached the upstream");

    assert_ok(&send_chat(listen, "open-model"));
    assert_eq!(open.count(), 1);

    capped.release();
    for request in in_flight {
        assert_ok(&request.join().expect("in-flight request thread"));
    }
    // The permits go back when each response body ends.
    wait_for_ok(listen, "capped-model");
    assert_eq!(capped.count(), 3);
    finish(proxy, &dir);
}

/// A model with a fallback routes through an aggregate. The ceiling of the
/// provider actually dialled still holds: with `capped` full, the next request
/// gets the 503 rather than passing the ceiling, and is not sent to the
/// fallback (Envoy never retries an overflow).
#[test]
fn a_fallback_model_sheds_at_the_dialled_providers_ceiling() {
    let dir = scratch_dir("fallback");
    let capped = Mock::start(true);
    let open = Mock::start(false);
    let proxy = Proxy::start(
        &dir,
        &config_text(
            capped.addr,
            open.addr,
            "    circuit_breakers: { max_requests: 1 }\n",
            "models:\n  chain: { providers: [capped, open] }\n",
        ),
    );

    let listen = proxy.listen;
    let first = std::thread::spawn(move || send_chat(listen, "chain"));
    wait_until(
        || capped.count() == 1,
        "the first request to reach the capped mock",
    );

    assert_overflow(&send_chat(listen, "chain"));
    assert_eq!(
        capped.count(),
        1,
        "the shed request reached the capped upstream"
    );
    assert_eq!(
        open.count(),
        0,
        "the shed request failed over to the fallback"
    );

    capped.release();
    assert_ok(&first.join().expect("in-flight request thread"));
    finish(proxy, &dir);
}

/// A provider that sends `503` headers and then stalls its body must not hold
/// up failover: the fallback answers while the stalled body is still open
/// (without a bound the wait is the 10-minute stream idle timeout, far past
/// the client's read timeout). The stalled connection is closed rather than
/// reused, and `capped`'s single `max_requests` permit comes back, so the
/// next request is served by `capped` itself.
#[test]
fn a_stalled_error_body_does_not_hold_up_failover_or_the_providers_permit() {
    let dir = scratch_dir("stall");
    let capped = StallingMock::start();
    let open = Mock::start(false);
    let proxy = Proxy::start(
        &dir,
        &config_text(
            capped.addr,
            open.addr,
            "    circuit_breakers: { max_requests: 1 }\n",
            "models:\n  chain: { providers: [capped, open] }\n",
        ),
    );

    let first = send_chat(proxy.listen, "chain");
    assert_ok(&first);
    assert_eq!(open.count(), 1, "the fallback did not answer");
    wait_until(
        || capped.stall_ended(),
        "the proxy to close the stalled connection",
    );

    let second = send_chat(proxy.listen, "chain");
    assert_ok(&second);
    assert_eq!(
        capped.connections(),
        2,
        "the second request must reach capped on a new connection"
    );
    assert_eq!(open.count(), 1, "the second request failed over");
    finish(proxy, &dir);
}

// ------------------------------------------------------------------ helpers --

fn finish(proxy: Proxy, dir: &Path) {
    drop(proxy);
    let _ = std::fs::remove_dir_all(dir);
}

/// Two providers: `capped` (with `capped_block` under it) serves
/// `capped-model`, `open` serves `open-model`. `extra` is appended as is.
fn config_text(capped: SocketAddr, open: SocketAddr, capped_block: &str, extra: &str) -> String {
    format!(
        r#"version: 0
listen: 127.0.0.1:{listen}
providers:
  capped:
    type: openai-compatible
    base_url: http://{capped}
{capped_block}  open:
    type: openai-compatible
    base_url: http://{open}
routes:
  - {{ model: capped-model, provider: capped }}
  - {{ model: open-model, provider: open }}
{extra}"#,
        listen = free_port(),
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-provider-cb-e2e-{tag}-{}",
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
}

impl Proxy {
    fn start(dir: &Path, config: &str) -> Proxy {
        let listen: u16 = config
            .split("listen: 127.0.0.1:")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|port| port.parse().ok())
            .expect("listen port");
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).expect("write temp config");
        let child = Command::new(BIN)
            .args([
                "--config",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn llm-proxy");
        let proxy = Proxy {
            child,
            listen: SocketAddr::from(([127, 0, 0, 1], listen)),
        };
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

fn send_chat(listen: SocketAddr, model: &str) -> String {
    let body = format!(
        r#"{{"model":"{model}","max_tokens":8,"messages":[{{"role":"user","content":"hi"}}]}}"#
    );
    let mut stream = TcpStream::connect(listen).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    stream
        .write_all(
            format!(
                "POST /v1/chat/completions HTTP/1.1\r\nHost: proxy.local\r\n\
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

/// Retries until `model` answers 200, failing after [`WAIT`].
fn wait_for_ok(listen: SocketAddr, model: &str) {
    let deadline = Instant::now() + WAIT;
    loop {
        let response = send_chat(listen, model);
        if response.starts_with("HTTP/1.1 200") {
            return;
        }
        assert!(Instant::now() < deadline, "never served again:\n{response}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A mock OpenAI upstream that counts the requests it fully received. When
/// `gated`, every response waits until [`Mock::release`].
struct Mock {
    addr: SocketAddr,
    received: Arc<AtomicUsize>,
    open: Arc<AtomicBool>,
}

impl Mock {
    fn start(gated: bool) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
        let addr = listener.local_addr().expect("no local addr");
        let received = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(AtomicBool::new(!gated));
        let (counter, gate) = (Arc::clone(&received), Arc::clone(&open));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (counter, gate) = (Arc::clone(&counter), Arc::clone(&gate));
                std::thread::spawn(move || {
                    if read_request(&mut stream).is_none() {
                        return;
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    while !gate.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(5));
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
            received,
            open,
        }
    }

    fn count(&self) -> usize {
        self.received.load(Ordering::SeqCst)
    }

    fn release(&self) {
        self.open.store(true, Ordering::SeqCst);
    }
}

impl Drop for Mock {
    /// Frees any response still held, so no mock thread outlives the test.
    fn drop(&mut self) {
        self.release();
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

fn assert_ok(response: &str) {
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

/// The S5 UpstreamOverflow reply: a local 503 carrying `x-envoy-overloaded`,
/// which the mock upstreams (always 200) never produce.
fn assert_overflow(response: &str) {
    assert!(
        response.starts_with("HTTP/1.1 503")
            && response
                .to_ascii_lowercase()
                .contains("x-envoy-overloaded: true"),
        "expected the UpstreamOverflow 503:\n{response}"
    );
}

/// A mock OpenAI upstream whose first connection answers `503` headers and
/// 10 of 100 body bytes, then waits for the proxy to close the connection
/// (the stall ends only then). Later connections answer 200.
struct StallingMock {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    stall_ended: Arc<AtomicBool>,
}

impl StallingMock {
    fn start() -> StallingMock {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
        let addr = listener.local_addr().expect("no local addr");
        let connections = Arc::new(AtomicUsize::new(0));
        let stall_ended = Arc::new(AtomicBool::new(false));
        let (count, ended) = (Arc::clone(&connections), Arc::clone(&stall_ended));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let first = count.fetch_add(1, Ordering::SeqCst) == 0;
                let ended = Arc::clone(&ended);
                std::thread::spawn(move || {
                    if read_request(&mut stream).is_none() {
                        return;
                    }
                    if first {
                        let _ = stream.write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\n\
                              Content-Length: 100\r\n\r\noverloaded",
                        );
                        // No read timeout: this returns only when the proxy
                        // closes the connection.
                        let _ = stream.set_read_timeout(None);
                        let mut buf = [0u8; 64];
                        while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
                        ended.store(true, Ordering::SeqCst);
                        return;
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
        StallingMock {
            addr,
            connections,
            stall_ended,
        }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn stall_ended(&self) -> bool {
        self.stall_ended.load(Ordering::SeqCst)
    }
}
