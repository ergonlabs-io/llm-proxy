//! `models.<name>.max_output_tokens` end to end: the real `llm-proxy` binary
//! with a `--config` dialect file and a recording mock upstream.
//!
//! Each case asserts on what the upstream actually received, or that it received
//! nothing. The negative controls are an uncapped model on the same listener and
//! limits at or under the cap, which must reach the upstream byte for byte:
//! without them, a proxy that refused every body would pass the refusal cases.
//!
//! Rust note: same harness shape as `tests/request_fields_e2e.rs`: std
//! threads and sockets with bounded timeouts, ephemeral ports, and a `Drop`
//! guard that kills the child so a failed assertion leaves no listener behind.

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
fn chat_completions_over_the_cap_is_refused_and_the_rest_passes_untouched() {
    let dir = scratch_dir("chat");
    let (upstream, received) = spawn_recording_upstream();
    let proxy = Proxy::start(&dir, upstream);
    let path = "/v1/chat/completions";

    // Over the cap: 400 naming the field and the cap; never reaches upstream.
    for body in [
        r#"{"model":"gpt-capped","max_tokens":9000,"messages":[]}"#,
        r#"{"model":"gpt-capped","max_completion_tokens":9000}"#,
    ] {
        let r = post(proxy.listen, path, body);
        assert!(r.starts_with("HTTP/1.1 400"), "{body} got:\n{r}");
        assert!(r.contains("exceeds the maximum of 100"), "got:\n{r}");
    }
    // A body declared as plain text carries no model for routing to use, so
    // it matches no model route and cannot reach a capped model at all.
    let r = post_typed(
        proxy.listen,
        path,
        "text/plain",
        r#"{"model":"gpt-capped","max_tokens":9000}"#,
    );
    assert!(r.starts_with("HTTP/1.1 404"), "got:\n{r}");
    assert!(
        received.recv_timeout(Duration::from_millis(500)).is_err(),
        "a refused request must not reach the upstream"
    );

    // At or under the cap, and absent: forwarded byte for byte.
    for body in [
        r#"{"model":"gpt-capped","max_tokens":100}"#,
        r#"{"model":"gpt-capped","max_tokens":7}"#,
        r#"{"model":"gpt-capped","messages":[]}"#,
    ] {
        let r = post(proxy.listen, path, body);
        assert!(r.starts_with("HTTP/1.1 200"), "{body} got:\n{r}");
        assert_eq!(received.recv_timeout(IO_TIMEOUT).unwrap(), body);
    }

    // Negative control: a model without a cap is not touched.
    let free = r#"{"model":"gpt-free","max_tokens":9000}"#;
    let r = post(proxy.listen, path, free);
    assert!(r.starts_with("HTTP/1.1 200"), "got:\n{r}");
    assert_eq!(received.recv_timeout(IO_TIMEOUT).unwrap(), free);

    let metrics = get(proxy.admin, "/stats/prometheus");
    assert_eq!(
        counter(&metrics, "llmproxy_router_max_output_tokens_rejected_total"),
        2,
        "{metrics}"
    );

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn responses_path_checks_max_output_tokens() {
    let dir = scratch_dir("responses");
    let (upstream, received) = spawn_recording_upstream();
    let proxy = Proxy::start(&dir, upstream);

    let r = post(
        proxy.listen,
        "/v1/responses",
        r#"{"model":"gpt-capped","max_output_tokens":9000}"#,
    );
    assert!(r.starts_with("HTTP/1.1 400"), "got:\n{r}");
    assert!(r.contains("max_output_tokens"), "got:\n{r}");

    // `max_tokens` is not this path's field, so it is not checked here.
    let ok = r#"{"model":"gpt-capped","max_tokens":9000,"max_output_tokens":100}"#;
    let r = post(proxy.listen, "/v1/responses", ok);
    assert!(r.starts_with("HTTP/1.1 200"), "got:\n{r}");
    assert_eq!(received.recv_timeout(IO_TIMEOUT).unwrap(), ok);

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn messages_path_checks_max_tokens() {
    let dir = scratch_dir("messages");
    let (upstream, received) = spawn_recording_upstream();
    let proxy = Proxy::start(&dir, upstream);

    let r = post(
        proxy.listen,
        "/v1/messages",
        r#"{"model":"claude-capped","max_tokens":9000}"#,
    );
    assert!(r.starts_with("HTTP/1.1 400"), "got:\n{r}");
    assert!(r.contains("max_tokens"), "got:\n{r}");

    let ok = r#"{"model":"claude-capped","max_tokens":100}"#;
    let r = post(proxy.listen, "/v1/messages", ok);
    assert!(r.starts_with("HTTP/1.1 200"), "got:\n{r}");
    assert_eq!(received.recv_timeout(IO_TIMEOUT).unwrap(), ok);

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_ambiguous_limit_is_refused_and_never_reaches_the_upstream() {
    let dir = scratch_dir("refuse");
    let (upstream, received) = spawn_recording_upstream();
    let proxy = Proxy::start(&dir, upstream);
    let path = "/v1/chat/completions";

    for body in [
        r#"{"model":"gpt-capped","max_tokens":1,"max_tokens":9000}"#,
        r#"{"model":"gpt-capped","max_tokens":"9000"}"#,
        r#"{"model":"gpt-capped","max_tokens":-1}"#,
    ] {
        let r = post(proxy.listen, path, body);
        assert!(r.starts_with("HTTP/1.1 400"), "{body} got:\n{r}");
    }
    assert!(
        received.recv_timeout(Duration::from_millis(500)).is_err(),
        "a refused request must not reach the upstream"
    );

    // Negative control: the same malformed limit on an uncapped model is the
    // provider's business and is forwarded.
    let free = r#"{"model":"gpt-free","max_tokens":"9000"}"#;
    let r = post(proxy.listen, path, free);
    assert!(r.starts_with("HTTP/1.1 200"), "got:\n{r}");
    assert_eq!(received.recv_timeout(IO_TIMEOUT).unwrap(), free);

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

fn config_text(listen: u16, admin: u16, upstream: SocketAddr) -> String {
    format!(
        r#"version: 0
listen: "127.0.0.1:{listen}"
admin: 127.0.0.1:{admin}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
  anthropic:
    type: anthropic
    base_url: http://{upstream}
    api_key: sk-ant-upstream-provider-key
routes: []
models:
  gpt-capped:
    providers: [openai]
    max_output_tokens: 100
  gpt-free:
    providers: [openai]
  claude-capped:
    providers: [anthropic]
    max_output_tokens: 100
"#
    )
}

/// GETs `path` from the admin listener.
fn get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect admin");
    stream.set_read_timeout(Some(IO_TIMEOUT)).expect("timeout");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: admin\r\nConnection: close\r\n\r\n"
    )
    .expect("write");
    let mut out = String::new();
    let _ = stream.read_to_string(&mut out);
    out
}

/// The value of the unlabelled Prometheus series whose name ends with `name`.
fn counter(metrics: &str, name: &str) -> u64 {
    metrics
        .lines()
        .find(|l| !l.starts_with('#') && l.contains(name))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-max-output-tokens-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// POSTs `body` to `path` and returns the whole response text.
fn post(addr: SocketAddr, path: &str, body: &str) -> String {
    post_typed(addr, path, "application/json", body)
}

fn post_typed(addr: SocketAddr, path: &str, content_type: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: proxy.local\r\n\
         Content-Type: {content_type}\r\nContent-Length: {}\r\n\
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
    admin: SocketAddr,
}

impl Proxy {
    fn start(dir: &Path, upstream: SocketAddr) -> Proxy {
        let listen = free_port();
        let admin = free_port();
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config_text(listen, admin, upstream)).expect("write temp config");
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
            admin: SocketAddr::from(([127, 0, 0, 1], admin)),
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
