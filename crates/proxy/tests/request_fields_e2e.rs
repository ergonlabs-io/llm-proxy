//! `providers.<name>.request_fields` end to end: the real `llm-proxy` binary
//! with a `--config` dialect file and a mock upstream.
//!
//! A body carrying a denied top-level key gets `400` and never reaches the
//! upstream. The negative control is the same request without that key, which
//! must reach the upstream: without it, a proxy that rejected everything would
//! pass the first case. A `strip` provider forwards the body without the key.
//!
//! Rust note: same harness shape as `tests/request_body_limit_e2e.rs`.

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

#[test]
fn a_denied_field_gets_400_and_never_reaches_the_upstream() {
    let dir = scratch_dir("deny");
    let (upstream, received) = spawn_recording_upstream();
    let proxy = Proxy::start(&dir, upstream, "{ deny: [models] }");

    let denied = post(
        proxy.listen,
        r#"{"model":"gpt-4o-mini","models":["a","b"],"messages":[]}"#,
    );
    assert!(denied.starts_with("HTTP/1.1 400"), "got:\n{denied}");
    assert!(
        denied.contains("request field not permitted: models"),
        "got:\n{denied}"
    );
    assert!(
        received.recv_timeout(Duration::from_millis(500)).is_err(),
        "a denied request must not reach the upstream"
    );

    let allowed = post(proxy.listen, r#"{"model":"gpt-4o-mini","messages":[]}"#);
    assert!(allowed.starts_with("HTTP/1.1 200"), "got:\n{allowed}");
    assert!(received.recv_timeout(IO_TIMEOUT).is_ok());

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_stripped_field_is_removed_before_the_upstream_sees_it() {
    let dir = scratch_dir("strip");
    let (upstream, received) = spawn_recording_upstream();
    let proxy = Proxy::start(&dir, upstream, "{ strip: [plugins] }");

    let response = post(
        proxy.listen,
        r#"{"model":"gpt-4o-mini","plugins":["x"],"messages":[]}"#,
    );
    assert!(response.starts_with("HTTP/1.1 200"), "got:\n{response}");
    let body = received.recv_timeout(IO_TIMEOUT).expect("upstream body");
    assert!(body.contains("gpt-4o-mini"), "body was {body}");
    assert!(!body.contains("plugins"), "body was {body}");

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

fn config_text(listen: u16, admin: u16, upstream: SocketAddr, fields: &str) -> String {
    format!(
        r#"version: 0
listen: "127.0.0.1:{listen}"
admin: 127.0.0.1:{admin}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
    request_fields: {fields}
routes:
  - {{ model: "*", provider: openai }}
"#
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-request-fields-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// POSTs `body` and returns the whole response text.
fn post(addr: SocketAddr, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    let head = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: proxy.local\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).expect("write head");
    stream.write_all(body.as_bytes()).expect("write body");
    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&response).to_string()
}

/// A running proxy. Killed and reaped on drop, so a failed assertion cannot
/// leave a listener behind (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    listen: SocketAddr,
}

impl Proxy {
    fn start(dir: &Path, upstream: SocketAddr, fields: &str) -> Proxy {
        let listen = free_port();
        let admin = free_port();
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config_text(listen, admin, upstream, fields))
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

/// A mock provider that reads each whole request, sends the body it
/// read on the channel, and answers `200` with an empty JSON object.
fn spawn_recording_upstream() -> (SocketAddr, mpsc::Receiver<String>) {
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
                let mut body = raw[head_end + 4..].to_vec();
                while body.len() < content_length {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => body.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&body).to_string());
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                      Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            });
        }
    });
    (addr, rx)
}
