//! A response with no body is a clean completion, not a client hang-up.
//!
//! hyper never polls a response body whose framing is already complete (a
//! `Content-Length: 0` reply, a `204`, the reply to a `HEAD`), so the body that
//! writes the access log and the request record is dropped without ever
//! seeing end-of-stream. Envoy logs that exchange with no response flag. The
//! record must say `complete` with no `DC`, and the access log must render
//! `-`; a metering consumer reads `DC` as a stream the client cut.
//!
//! The negative control is the same request to the same upstream with a
//! two-byte body: only the body length changes between the cases.
//!
//! Rust note: same harness shape as `tests/partial_usage_e2e.rs` (std
//! threads, ephemeral ports, a `Drop` that kills the proxy, every wait bounded).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const RECORD_TIMEOUT: Duration = Duration::from_secs(20);

#[test]
fn a_response_without_a_body_is_recorded_complete_without_dc() {
    // (method, path, status line the client sees, response body bytes)
    let cases = [
        ("GET", "/full", "HTTP/1.1 200", 2),
        ("GET", "/empty", "HTTP/1.1 200", 0),
        ("GET", "/no-content", "HTTP/1.1 204", 0),
        ("HEAD", "/full", "HTTP/1.1 200", 0),
    ];
    let temp = tempfile::tempdir().unwrap();
    let proxy = Proxy::start(temp.path());
    for (index, (method, path, status, bytes)) in cases.into_iter().enumerate() {
        let response = request(proxy.listen, method, path);
        assert!(response.starts_with(status), "{path}:\n{response}");

        let record = proxy.wait_for_records(index + 1).remove(index);
        assert_eq!(record["bytes_response"], bytes, "{path}: {record}");
        assert_eq!(record["termination"], "complete", "{path}: {record}");
        assert_eq!(
            record["response_flags"],
            serde_json::json!([]),
            "{path}: {record}"
        );
        assert!(record["error_category"].is_null(), "{path}: {record}");

        let line = proxy.wait_for_log_lines(index + 1).remove(index);
        assert_eq!(line, format!("{path} {} - {bytes}", &status[9..]), "{path}");
    }
}

struct Proxy {
    child: Child,
    listen: SocketAddr,
    records: PathBuf,
    access_log: PathBuf,
}

impl Proxy {
    fn start(dir: &Path) -> Self {
        let upstream = spawn_upstream();
        let listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let admin = free_port();
        let records = dir.join("records.jsonl");
        let access_log = dir.join("access.log");
        let bootstrap = dir.join("proxy.yaml");
        std::fs::write(
            &bootstrap,
            format!(
                r#"
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin} }}
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listen_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress
                access_log:
                  - name: envoy.access_loggers.file
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                      path: {log}
                      log_format:
                        text_format: "%REQ(:PATH)% %RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_SENT%\n"
                route_config:
                  name: local
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route: {{ cluster: backend }}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: backend
      type: STATIC
      connect_timeout: 1s
      load_assignment:
        cluster_name: backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: {upstream_port} }}
"#,
                listen_port = listen.port(),
                upstream_port = upstream.port(),
                log = access_log.display(),
            ),
        )
        .unwrap();
        let child = Command::new(BIN)
            .arg("-c")
            .arg(&bootstrap)
            .arg("--request-records-file")
            .arg(&records)
            .args(["--concurrency", "1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn llm-proxy");
        let proxy = Self {
            child,
            listen,
            records,
            access_log,
        };
        assert!(
            wait_for_connectable(listen, STARTUP_TIMEOUT),
            "proxy never listened on {listen}"
        );
        proxy
    }

    /// Wait until the records file holds `count` records, and return them.
    fn wait_for_records(&self, count: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + RECORD_TIMEOUT;
        loop {
            let text = std::fs::read_to_string(&self.records).unwrap_or_default();
            let records: Vec<serde_json::Value> = text
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
            if records.len() >= count {
                return records;
            }
            assert!(
                Instant::now() < deadline,
                "only {} of {count} records arrived; file:\n{text}",
                records.len()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Wait until the access log holds `count` lines, and return them.
    fn wait_for_log_lines(&self, count: usize) -> Vec<String> {
        let deadline = Instant::now() + RECORD_TIMEOUT;
        loop {
            let text = std::fs::read_to_string(&self.access_log).unwrap_or_default();
            let lines: Vec<String> = text.lines().map(str::to_owned).collect();
            if lines.len() >= count {
                return lines;
            }
            assert!(
                Instant::now() < deadline,
                "only {} of {count} log lines arrived; log:\n{text}",
                lines.len()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn request(addr: SocketAddr, method: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

/// A mock upstream: `/full` answers 200 with a two-byte body (headers only
/// for `HEAD`), `/empty` 200 with `Content-Length: 0`, and `/no-content` a
/// 204.
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
                let head = String::from_utf8_lossy(&head);
                let response: &[u8] = if head.starts_with("GET /full ") {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                } else if head.starts_with("HEAD /full ") {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n"
                } else if head.starts_with("GET /empty ") {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
                };
                let _ = stream.write_all(response);
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

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve a port");
    listener.local_addr().unwrap().port()
}
