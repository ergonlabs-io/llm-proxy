//! Process signals against the real binary: SIGUSR1 reopens the log files
//! after logrotate renamed them, and SIGTERM stops a proxy that is still
//! waiting at its startup gate.
//!
//! Every signal goes to the spawned `llm-proxy`, never to the test runner.
//! Same harness shape as `tests/empty_response_e2e.rs`: std threads,
//! ephemeral ports, a `Drop` that kills the proxy, every wait bounded.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".
#![cfg(unix)]

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const WAIT_TIMEOUT: Duration = Duration::from_secs(20);

/// logrotate's `create` mode: rename both files, then `postrotate kill -USR1`.
/// Later lines and records must land in new files at the configured paths, the
/// renamed files must keep what was written before, and the process must
/// still be running (SIGUSR1's default disposition terminates it).
#[test]
fn sigusr1_after_a_rename_moves_access_log_and_records_to_new_files() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let upstream = spawn_upstream();
    let listen = free_port();
    let access_log = dir.join("access.log");
    let records = dir.join("records.jsonl");
    let config = dir.join("llmproxy.yaml");
    std::fs::write(
        &config,
        format!(
            r#"version: 1
listen: 127.0.0.1:{listen}
admin: 127.0.0.1:{admin}
providers:
  upstream:
    base_url: http://{upstream}
    api_key: sk-test-upstream
routes:
  - model: "*"
    provider: upstream
observability:
  access_logs: {{ output: "{log}", format: json }}
"#,
            admin = free_port(),
            log = access_log.display(),
        ),
    )
    .unwrap();
    let mut proxy = Proxy::spawn(
        dir,
        &[
            "--config",
            config.to_str().unwrap(),
            "--request-records-file",
            records.to_str().unwrap(),
        ],
    );
    let listen = SocketAddr::from(([127, 0, 0, 1], listen));
    assert!(
        wait_for_connectable(listen, STARTUP_TIMEOUT),
        "proxy never listened on {listen}; stderr:\n{}",
        proxy.stderr()
    );

    let response = chat(listen);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    wait_for_lines(&access_log, 1);
    wait_for_lines(&records, 1);

    let rotated_log = dir.join("access.log.1");
    let rotated_records = dir.join("records.jsonl.1");
    std::fs::rename(&access_log, &rotated_log).unwrap();
    std::fs::rename(&records, &rotated_records).unwrap();
    proxy.signal("-USR1");
    proxy.wait_stderr("SIGUSR1: reopened log files");
    assert!(
        proxy.child.try_wait().unwrap().is_none(),
        "SIGUSR1 must not end the process; stderr:\n{}",
        proxy.stderr()
    );

    let response = chat(listen);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert_eq!(wait_for_lines(&access_log, 1).len(), 1);
    let fresh = wait_for_lines(&records, 1);
    let record: serde_json::Value = serde_json::from_str(&fresh[0]).unwrap();
    assert_eq!(
        record["record_seq"], 2,
        "the second record, in the new file: {record}"
    );
    assert_eq!(
        read_lines(&rotated_log).len(),
        1,
        "the renamed log keeps only the first line"
    );
    assert_eq!(read_lines(&rotated_records).len(), 1);

    proxy.signal("-TERM");
    let status = proxy.wait_exit(WAIT_TIMEOUT);
    assert!(
        status.is_some_and(|s| s.success()),
        "{status:?}; stderr:\n{}",
        proxy.stderr()
    );
}

/// A control plane that accepts the connection and never answers holds the
/// startup gate for `initial_fetch_timeout` (here 300 s). SIGTERM in that
/// window must stop the proxy within the drain budget, not after the gate.
#[test]
fn sigterm_while_the_startup_gate_waits_on_a_silent_control_plane_exits_promptly() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    // Connections complete in the backlog and are never served.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let ads = silent.local_addr().unwrap();
    let listen = free_port();
    let config = dir.join("bootstrap.yaml");
    std::fs::write(
        &config,
        format!(
            r#"
node:
  id: proxy-1
  cluster: proxy-fleet
dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: {{ cluster_name: xds_cluster }}
  cds_config:
    ads: {{}}
    resource_api_version: V3
    initial_fetch_timeout: 300s
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listen} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: ingress
                cluster: xds_cluster
  clusters:
    - name: xds_cluster
      type: STATIC
      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {ip}, port_value: {port} }}
"#,
            ip = ads.ip(),
            port = ads.port(),
        ),
    )
    .unwrap();
    let mut proxy = Proxy::spawn(
        dir,
        &["-c", config.to_str().unwrap(), "--drain-time-s", "5"],
    );
    proxy.wait_stderr("llm-proxy started");
    // The gate holds: no worker has bound the listener.
    assert!(
        TcpStream::connect(("127.0.0.1", listen)).is_err(),
        "the startup gate must still be closed; stderr:\n{}",
        proxy.stderr()
    );

    proxy.signal("-TERM");
    // The drain budget plus the shutdown flushes. Without the fix the proxy
    // ignores the signal until the 300 s gate expires.
    let status = proxy.wait_exit(WAIT_TIMEOUT);
    assert!(
        status.is_some_and(|s| s.success()),
        "SIGTERM during the startup gate must exit cleanly, got {status:?}; stderr:\n{}",
        proxy.stderr()
    );
    assert!(
        TcpStream::connect(("127.0.0.1", listen)).is_err(),
        "no listener was bound on the way out"
    );
    drop(silent);
}

// ------------------------------------------------------------------ helpers --

/// A running proxy, stderr in a file. Killed and reaped on drop, so a failed
/// assertion cannot leave a process behind (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    stderr: PathBuf,
}

impl Proxy {
    fn spawn(dir: &Path, args: &[&str]) -> Proxy {
        let stderr = dir.join("stderr.log");
        let child = Command::new(BIN)
            .args(args)
            .args(["--concurrency", "1"])
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&stderr).unwrap()))
            .spawn()
            .expect("spawn llm-proxy");
        Proxy { child, stderr }
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    fn wait_stderr(&self, needle: &str) {
        let deadline = Instant::now() + WAIT_TIMEOUT;
        while !self.stderr().contains(needle) {
            assert!(
                Instant::now() < deadline,
                "stderr never logged {needle:?}:\n{}",
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn signal(&self, signal: &str) {
        let status = Command::new("kill")
            .arg(signal)
            .arg(self.child.id().to_string())
            .status()
            .expect("run kill");
        assert!(status.success(), "kill {signal} failed");
    }

    fn wait_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
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

fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Waits until `path` holds at least `count` complete lines; both writers
/// batch, so a line appears some time after the response.
fn wait_for_lines(path: &Path, count: usize) -> Vec<String> {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        let lines = read_lines(path);
        if lines.len() >= count {
            return lines;
        }
        assert!(
            Instant::now() < deadline,
            "only {} of {count} lines in {}",
            lines.len(),
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn chat(addr: SocketAddr) -> String {
    let body = r#"{"model":"test-model","messages":[{"role":"user","content":"hi"}]}"#;
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    write!(
        stream,
        "POST /v1/chat/completions HTTP/1.1\r\nHost: test.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

/// Answers every request with one OpenAI-shaped chat completion.
fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let mut head = Vec::new();
                let mut buf = [0u8; 4096];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                // Read the request body too, so closing cannot reset the
                // connection under the response.
                let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let split = text.find("\r\n\r\n").unwrap() + 4;
                let length: usize = text
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                let mut have = head.len() - split;
                while have < length {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => have += n,
                    }
                }
                let body = r#"{"id":"c1","object":"chat.completion","model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    addr
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
