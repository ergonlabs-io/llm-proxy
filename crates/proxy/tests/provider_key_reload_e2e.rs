//! A SIGHUP reload whose `api_key_file` now holds a value the router cannot
//! send is refused, and the proxy keeps sending the previous key. Before the
//! load-time check the reload succeeded and every request went to the
//! provider without its credential.
//!
//! Drives the real binary with the `auth_reload_e2e.rs` harness shape: std
//! threads, ephemeral ports, a child killed on drop, and a stderr reader so
//! the reload's log line can be awaited.

mod common;

use common::free_port;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const KEY_1: &str = "sk-provider-key-reload-1";
const KEY_2: &str = "sk-provider-key-reload-2";
const FAILED: &str = "SIGHUP: config reload failed";

#[test]
fn a_reload_with_an_unsendable_key_file_is_refused_and_the_previous_key_keeps_serving() {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-provider-key-reload-e2e-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let key_file = dir.join("openai.key");
    std::fs::write(&key_file, format!("{KEY_1}\n")).expect("write key file");

    let listen = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let upstream = spawn_echo_upstream();
    let config_path = dir.join("llmproxy.yaml");
    std::fs::write(
        &config_path,
        format!(
            "version: 1\nlisten: {listen}\nproviders:\n  openai:\n    type: openai\n    \
             base_url: http://{upstream}\n    api_key_file: {}\nroutes:\n  - {{ model: \"*\", provider: openai }}\n",
            key_file.display()
        ),
    )
    .expect("write config");

    let mut child = Command::new(BIN)
        .args([
            "--config",
            config_path.to_str().expect("utf-8 path"),
            "--concurrency",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn llm-proxy");
    let stderr = spawn_line_reader(child.stderr.take().expect("stderr is piped"));
    let mut proxy = Proxy {
        child,
        stderr,
        log: Vec::new(),
    };
    assert!(
        wait_for_connectable(listen, STARTUP_TIMEOUT),
        "{listen} did not become connectable in time"
    );
    assert_eq!(upstream_authorization(listen), format!("Bearer {KEY_1}"));

    // A pasted key with a second line: `api_key_file` trims only the end.
    std::fs::write(&key_file, format!("{KEY_2}\nsecond-line\n")).expect("rewrite key file");
    let status = Command::new("kill")
        .args(["-HUP", &proxy.child.id().to_string()])
        .status()
        .expect("failed to send SIGHUP");
    assert!(status.success(), "kill -HUP failed");

    let failed = proxy.wait_for_log(FAILED);
    assert!(
        failed.contains("providers.openai.api_key_file"),
        "the refusal must name the field: {failed}"
    );
    assert!(
        !proxy.log.concat().contains(KEY_2),
        "the log must not render the new key:\n{}",
        proxy.log.concat()
    );
    assert_eq!(
        upstream_authorization(listen),
        format!("Bearer {KEY_1}"),
        "the previous snapshot must keep sending the previous key"
    );
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A running proxy. Killed and reaped on drop (AGENTS.md "Running The
/// Product").
struct Proxy {
    child: Child,
    stderr: Receiver<String>,
    log: Vec<String>,
}

impl Proxy {
    /// Waits for a stderr line containing `needle` and returns it,
    /// ANSI-stripped. Panics with the log seen so far on timeout.
    fn wait_for_log(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + RELOAD_TIMEOUT;
        loop {
            while let Ok(line) = self.stderr.try_recv() {
                self.log.push(strip_ansi(&line));
            }
            if let Some(line) = self.log.iter().find(|line| line.contains(needle)) {
                return line.clone();
            }
            assert!(
                Instant::now() < deadline,
                "no log line containing {needle:?}; log:\n{}",
                self.log.concat()
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

/// Sends one chat completion through the proxy and returns the
/// `authorization` value the provider received, as the echo upstream reports
/// it in the response body.
fn upstream_authorization(listen: SocketAddr) -> String {
    let body = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;
    let mut stream = TcpStream::connect_timeout(&listen, IO_TIMEOUT).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("read timeout");
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
    let response = String::from_utf8_lossy(&response).to_string();
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200, got:\n{response}"
    );
    let body = response.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    let parsed: serde_json::Value = serde_json::from_str(body).expect("echo body is JSON");
    parsed["authorization"]
        .as_str()
        .expect("echo names the header")
        .to_string()
}

/// A provider that answers every request `200` with the `authorization`
/// header it received, so the test sees what went on the wire.
fn spawn_echo_upstream() -> SocketAddr {
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
                let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
                let header = |name: &str| {
                    head.lines().find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case(name)
                            .then(|| value.trim().to_string())
                    })
                };
                let content_length: usize = header("content-length")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let mut have = raw.len() - (head_end + 4);
                while have < content_length {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => have += n,
                    }
                }
                let body =
                    serde_json::json!({ "authorization": header("authorization") }).to_string();
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
