//! `%COMMON_DURATION%` through the real binary: a request goes through the
//! proxy to a provider that waits [`DELAY`] before answering, and the access
//! log line must put that wait between `US_TX_END` and `US_RX_BEG`.
//!
//! The provider keeps its connection open, so the second request reuses it.
//! Envoy repeats a connection's `US_CX_*` points for every request on it
//! (v1.38 `substitution_formatter` docs), so the reused request reports the
//! first request's connect span, and its own `DS_RX_BEG -> US_CX_BEG` renders
//! `-` because the connect happened before the request began.
//!
//! Rust note: same harness shape as `tests/route_idle_timeout_e2e.rs`; each
//! `tests/*.rs` file is its own crate, so the helpers are duplicated.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const LOG_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the provider waits between reading a request and answering it.
const DELAY: Duration = Duration::from_millis(300);

/// The twelve points, in the order the Envoy-mode format renders them.
const POINTS: [&str; 12] = [
    "DS_RX_BEG",
    "DS_RX_END",
    "US_CX_BEG",
    "US_CX_END",
    "US_HS_END",
    "US_TX_BEG",
    "US_TX_END",
    "US_RX_BEG",
    "US_RX_BODY_BEG",
    "US_RX_END",
    "DS_TX_BEG",
    "DS_TX_END",
];

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for_connectable(port: u16) -> bool {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-common-duration-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// A keep-alive HTTP/1.1 provider: for each request on a connection it reads
/// the head and the `Content-Length` body, waits [`DELAY`], and answers
/// `200` with a small JSON body. Returns its address and a count of the
/// connections it accepted.
fn spawn_delayed_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
    let addr = listener.local_addr().expect("local addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            counter.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || serve_keep_alive(stream));
        }
    });
    (addr, accepted)
}

fn serve_keep_alive(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut pending: Vec<u8> = Vec::new();
    loop {
        let head_end = loop {
            if let Some(pos) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            let mut buf = [0u8; 4096];
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => pending.extend_from_slice(&buf[..n]),
            }
        };
        let head = String::from_utf8_lossy(&pending[..head_end]).to_ascii_lowercase();
        let body_len: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        while pending.len() < head_end + body_len {
            let mut buf = [0u8; 4096];
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => pending.extend_from_slice(&buf[..n]),
            }
        }
        pending.drain(..head_end + body_len);
        std::thread::sleep(DELAY);
        let body = br#"{"object":"list","data":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        if stream.write_all(response.as_bytes()).is_err() || stream.write_all(body).is_err() {
            return;
        }
    }
}

/// Send one request on its own client connection and return the raw response.
fn send(listen_port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", listen_port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("read timeout");
    let body = r#"{"model":"m","input":"hi"}"#;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: t.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

/// Wait until `path` holds `count` complete lines, and return them.
fn wait_for_lines(path: &Path, count: usize) -> Vec<String> {
    let deadline = Instant::now() + LOG_TIMEOUT;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text
            .split_inclusive('\n')
            .filter(|l| l.ends_with('\n'))
            .map(|l| l.trim_end().to_string())
            .collect();
        if lines.len() >= count {
            return lines;
        }
        assert!(
            Instant::now() < deadline,
            "only {} of {count} access-log lines arrived; file:\n{text}",
            lines.len()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn spawn_proxy(args: &[&str], listen_port: u16) -> ChildGuard {
    let guard = ChildGuard(
        Command::new(BIN)
            .args(args)
            .args(["--concurrency", "1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn llm-proxy"),
    );
    assert!(
        wait_for_connectable(listen_port),
        "listener on {listen_port} never became connectable"
    );
    guard
}

/// One parsed Envoy-mode line: each point's offset from `DS_RX_BEG` in
/// microseconds (`None` for `-`), then `US_TX_END -> US_RX_BEG` in ms, then
/// the connect span and `DS_RX_BEG -> US_CX_BEG`, both in microseconds.
struct Line {
    offsets: Vec<Option<u64>>,
    wait_ms: Option<u64>,
    connect_us: Option<u64>,
    start_to_connect_us: Option<u64>,
}

fn parse_line(line: &str) -> Line {
    let fields: Vec<Option<u64>> = line
        .split(' ')
        .map(|f| {
            if f == "-" {
                None
            } else {
                Some(
                    f.parse()
                        .unwrap_or_else(|_| panic!("bad field {f:?} in {line:?}")),
                )
            }
        })
        .collect();
    assert_eq!(fields.len(), POINTS.len() + 3, "{line:?}");
    Line {
        offsets: fields[..POINTS.len()].to_vec(),
        wait_ms: fields[POINTS.len()],
        connect_us: fields[POINTS.len() + 1],
        start_to_connect_us: fields[POINTS.len() + 2],
    }
}

fn offset(line: &Line, point: &str) -> Option<u64> {
    line.offsets[POINTS.iter().position(|p| *p == point).unwrap()]
}

#[test]
fn envoy_mode_line_carries_each_phase_and_a_reused_connection_repeats_its_connect() {
    let dir = scratch_dir("envoy");
    let log = dir.join("access.log");
    let (upstream, accepted) = spawn_delayed_upstream();
    let listen = free_port();
    let admin = free_port();

    let mut format: Vec<String> = POINTS
        .iter()
        .map(|p| format!("%COMMON_DURATION(DS_RX_BEG:{p}:us)%"))
        .collect();
    format.push("%COMMON_DURATION(US_TX_END:US_RX_BEG)%".to_string());
    format.push("%COMMON_DURATION(US_CX_BEG:US_CX_END:us)%".to_string());
    format.push("%COMMON_DURATION(DS_RX_BEG:US_CX_BEG:us)%".to_string());
    let format = format.join(" ");

    let config_path = dir.join("bootstrap.yaml");
    let config = format!(
        r#"
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin} }}
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listen} }}
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
                        text_format: "{format}\n"
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route: {{ cluster: delayed, timeout: 0s }}
  clusters:
    - name: delayed
      type: STATIC
      connect_timeout: 2s
      load_assignment:
        cluster_name: delayed
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {ip}, port_value: {port} }}
"#,
        log = log.display(),
        ip = upstream.ip(),
        port = upstream.port(),
    );
    std::fs::write(&config_path, config).expect("write config");
    let _proxy = spawn_proxy(&["-c", config_path.to_str().unwrap()], listen);

    for _ in 0..2 {
        let response = send(listen, "/v1/responses");
        assert!(response.starts_with("HTTP/1.1 200"), "{response:?}");
    }
    let lines = wait_for_lines(&log, 2);
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "the second request must reuse the first connection"
    );
    let first = parse_line(&lines[0]);
    let second = parse_line(&lines[1]);

    // The provider's wait sits between the last byte sent and the first
    // received. A lower bound only: a loaded box can stretch it, never shrink it.
    for (n, line) in [(1, &first), (2, &second)] {
        let wait = line.wait_ms.expect("US_TX_END -> US_RX_BEG must render");
        assert!(
            wait >= DELAY.as_millis() as u64,
            "request {n}: US_TX_END -> US_RX_BEG was {wait} ms, the provider waited {} ms",
            DELAY.as_millis()
        );
    }

    // A fresh plaintext connection: every point but the TLS handshake, in
    // request order. `DS_TX_BEG` (head to the client) comes before the body
    // is read from the provider, since the body streams through.
    for point in POINTS.iter().filter(|p| **p != "US_HS_END") {
        assert!(
            offset(&first, point).is_some(),
            "request 1: {point} missing in {:?}",
            lines[0]
        );
    }
    assert_eq!(
        offset(&first, "US_HS_END"),
        None,
        "plaintext has no handshake"
    );
    assert_eq!(offset(&first, "DS_RX_BEG"), Some(0));
    let order = [
        "DS_RX_BEG",
        "DS_RX_END",
        "US_CX_BEG",
        "US_CX_END",
        "US_TX_BEG",
        "US_TX_END",
        "US_RX_BEG",
        "DS_TX_BEG",
        "US_RX_BODY_BEG",
        "US_RX_END",
        "DS_TX_END",
    ];
    for pair in order.windows(2) {
        assert!(
            offset(&first, pair[0]) <= offset(&first, pair[1]),
            "request 1: {} after {} in {:?}",
            pair[0],
            pair[1],
            lines[0]
        );
    }
    assert!(first.start_to_connect_us.is_some());

    // The reused connection repeats its dial, which happened before this
    // request started: the connect span is the first request's, and the
    // offsets of the connect points from this request's start are negative,
    // which renders `-`.
    assert_eq!(second.connect_us, first.connect_us);
    assert_eq!(second.start_to_connect_us, None);
    assert_eq!(offset(&second, "US_CX_BEG"), None);
    assert_eq!(offset(&second, "US_CX_END"), None);
    for point in [
        "US_TX_BEG",
        "US_TX_END",
        "US_RX_BEG",
        "US_RX_END",
        "DS_TX_END",
    ] {
        assert!(
            offset(&second, point).is_some(),
            "request 2: {point} missing"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The `--config` dialect has no custom format string; its default JSON line
/// carries the phase breakdown, and the provider's wait lands in `us_wait_us`.
#[test]
fn dialect_json_line_carries_the_provider_wait() {
    let dir = scratch_dir("dialect");
    let log = dir.join("access.log");
    let (upstream, _accepted) = spawn_delayed_upstream();
    let listen = free_port();
    let admin = free_port();
    let config_path = dir.join("llmproxy.yaml");
    std::fs::write(
        &config_path,
        format!(
            r#"version: 0
listen: {{ address: "127.0.0.1:{listen}" }}
admin: 127.0.0.1:{admin}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
routes:
  - {{ model: "*", provider: openai }}
observability:
  access_logs: {{ output: {log}, format: json }}
"#,
            log = log.display(),
        ),
    )
    .expect("write config");
    let _proxy = spawn_proxy(&["--config", config_path.to_str().unwrap()], listen);

    let response = send(listen, "/v1/responses");
    assert!(response.starts_with("HTTP/1.1 200"), "{response:?}");
    let lines = wait_for_lines(&log, 1);
    let record: serde_json::Value = serde_json::from_str(&lines[0]).expect("json line");
    let micros = |key: &str| -> Option<u64> {
        let value = record[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} in {record}"));
        (value != "-").then(|| value.parse().unwrap_or_else(|_| panic!("{key}={value}")))
    };
    let wait = micros("us_wait_us").expect("us_wait_us must render");
    assert!(
        wait >= DELAY.as_micros() as u64,
        "us_wait_us was {wait}, the provider waited {} us",
        DELAY.as_micros()
    );
    for key in [
        "ds_rx_us",
        "pre_upstream_us",
        "us_tx_us",
        "resp_head_us",
        "ds_tx_us",
    ] {
        assert!(micros(key).is_some(), "{key} must render in {record}");
    }
    // A reused connection repeats an earlier connect, so the default line
    // carries no connect phase (see `TIMING_PHASES` in the dialect's lower).
    assert!(
        record.get("us_connect_us").is_none(),
        "the default line must not carry a connect phase: {record}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
