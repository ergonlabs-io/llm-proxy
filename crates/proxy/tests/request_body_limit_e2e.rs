//! `listen.max_request_body_bytes` end to end: the real `llm-proxy` binary
//! with a `--config` dialect file and a mock upstream.
//!
//! With the limit at 2 MiB, a 1.5 MiB body reaches the upstream whole and a
//! 3 MiB body gets `413` without reaching it. The negative control is the
//! same 1.5 MiB body against the 1 MiB default, which must get `413`:
//! without it, a field that lowered to nothing would pass the first case
//! only if the default were already large enough.
//!
//! Rust note: same harness shape as `tests/auth_store_e2e.rs` (std threads,
//! ephemeral ports, a `Proxy` guard that kills the child on drop). Every wait
//! is bounded by `STARTUP_TIMEOUT` or a socket read timeout.

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const LIMIT: usize = 2 << 20;
const UNDER: usize = 3 << 19; // 1.5 MiB: over the 1 MiB default, under LIMIT.
const OVER: usize = 3 << 20;

#[test]
fn a_raised_limit_admits_a_body_under_it_and_rejects_one_over_it() {
    let dir = scratch_dir("raised");
    let (upstream, received) = spawn_recording_upstream();
    let proxy = Proxy::start(&dir, upstream, Some(LIMIT));

    let response = post_body(proxy.listen, UNDER);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "a {UNDER}-byte body under a {LIMIT}-byte limit was refused:\n{}",
        head_of(&response)
    );
    assert_eq!(
        received.recv_timeout(IO_TIMEOUT).ok(),
        Some(UNDER),
        "the upstream must receive the whole body"
    );

    let response = post_body(proxy.listen, OVER);
    assert!(
        response.starts_with("HTTP/1.1 413"),
        "a {OVER}-byte body over a {LIMIT}-byte limit was not refused with 413:\n{}",
        head_of(&response)
    );
    assert!(
        received.recv_timeout(Duration::from_millis(500)).is_err(),
        "a body over the limit must not reach the upstream"
    );

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Negative control: the same body under the 1 MiB default is refused.
#[test]
fn the_default_limit_rejects_the_same_body() {
    let dir = scratch_dir("default");
    let (upstream, received) = spawn_recording_upstream();
    let proxy = Proxy::start(&dir, upstream, None);

    let response = post_body(proxy.listen, UNDER);
    assert!(
        response.starts_with("HTTP/1.1 413"),
        "a {UNDER}-byte body under the 1 MiB default was not refused with 413:\n{}",
        head_of(&response)
    );
    assert!(
        received.recv_timeout(Duration::from_millis(500)).is_err(),
        "a body over the default must not reach the upstream"
    );

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

fn config_text(listen: u16, admin: u16, upstream: SocketAddr, limit: Option<usize>) -> String {
    let limit = limit
        .map(|l| format!(", max_request_body_bytes: {l}"))
        .unwrap_or_default();
    format!(
        r#"version: 1
listen: {{ address: "127.0.0.1:{listen}"{limit} }}
admin: 127.0.0.1:{admin}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
routes:
  - {{ model: "*", provider: openai }}
"#
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-body-limit-e2e-{tag}-{}",
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
    fn start(dir: &Path, upstream: SocketAddr, limit: Option<usize>) -> Proxy {
        let listen = free_port();
        let admin = free_port();
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config_text(listen, admin, upstream, limit))
            .expect("write temp config");
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
        let admin = SocketAddr::from(([127, 0, 0, 1], admin));
        assert!(
            wait_for_connectable(admin, STARTUP_TIMEOUT),
            "admin listener at {admin} did not become connectable in time"
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

/// POSTs a chat request whose body is `len` bytes of valid JSON.
///
/// The response is read on its own thread while the body is still being
/// written: on a 413 the proxy answers and closes with the rest of the body
/// unread, and a reader that waited for the write to finish could lose the
/// response to the connection reset.
fn post_body(addr: SocketAddr, len: usize) -> String {
    let prefix = br#"{"model":"gpt-4o-mini","max_tokens":8,"messages":[{"role":"user","content":""#;
    let suffix = br#""}]}"#;
    let mut body = Vec::with_capacity(len);
    body.extend_from_slice(prefix);
    body.resize(len - suffix.len(), b'x');
    body.extend_from_slice(suffix);
    assert_eq!(body.len(), len);

    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    let mut reader = stream.try_clone().expect("clone stream");
    let read = std::thread::spawn(move || {
        let mut response = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
            }
        }
        String::from_utf8_lossy(&response).to_string()
    });
    let head = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: proxy.local\r\n\
         Content-Type: application/json\r\nContent-Length: {len}\r\n\
         Connection: close\r\n\r\n"
    );
    // A write error is expected on the 413 path: the proxy stops reading.
    let _ = stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(&body));
    read.join().expect("reader thread")
}

fn head_of(response: &str) -> &str {
    response.split("\r\n\r\n").next().unwrap_or(response)
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

/// A mock provider that reads each whole request, sends the body length it
/// read on the channel, and answers `200` with an empty JSON object.
fn spawn_recording_upstream() -> (SocketAddr, mpsc::Receiver<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let mut raw = Vec::new();
                let mut buf = [0u8; 65536];
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
                let _ = tx.send(have);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                      Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            });
        }
    });
    (addr, rx)
}
