//! Trusted hops (envoy-semantics S9, HCM `xff_num_trusted_hops`) end to end:
//! the real `llm-proxy` binary behind a simulated load balancer.
//!
//! The test client stands in for the balancer: every connection comes from
//! 127.0.0.1, and the `x-forwarded-for` it sends is what a balancer would
//! forward (the client's own header with the client's address appended).
//! With one trusted hop, `client-ip` limits, the access log and the request
//! record must all use the rightmost entry; entries left of it are the
//! client's own writing and must never choose a bucket. With zero hops the
//! TCP peer is used whatever the header says.
//!
//! Rust note: same harness shape as `tests/dialect_limits_e2e.rs` (std
//! threads, ephemeral ports, a `Proxy` guard that kills the child on drop).

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const WAIT: Duration = Duration::from_secs(10);

const RATE: &str = "request rate exceeded";

/// Two clients behind the same balancer address get separate buckets.
#[test]
fn one_trusted_hop_gives_each_client_behind_the_balancer_its_own_bucket() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("separate");
    let (upstream, heads) = spawn_upstream();
    let proxy = Proxy::dialect(&dir, upstream, Some(1));

    assert_admitted(&chat(&proxy, &[("x-forwarded-for", "203.0.113.1")]));
    assert_admitted(&chat(&proxy, &[("x-forwarded-for", "203.0.113.2")]));
    assert_refused(&chat(&proxy, &[("x-forwarded-for", "203.0.113.1")]));

    // The edge appends the balancer (the TCP peer) to what it forwards.
    let forwarded: Vec<String> = heads.try_iter().map(|h| xff_of(&h)).collect();
    assert_eq!(
        forwarded,
        ["203.0.113.1, 127.0.0.1", "203.0.113.2, 127.0.0.1"],
        "the refused request must not reach the upstream"
    );
    let logged = wait_for_lines(&dir.join("access.log"), 3);
    assert_eq!(
        json_field(&logged, "client_address"),
        ["203.0.113.1", "203.0.113.2", "203.0.113.1"]
    );
    let records = wait_for_lines(&dir.join("records.jsonl"), 3);
    assert_eq!(
        json_field(&records, "client_address"),
        ["203.0.113.1", "203.0.113.2", "203.0.113.1"]
    );
    proxy.finish(&dir);
}

/// A client that writes its own `x-forwarded-for` with extra entries still
/// lands in the bucket of the address the balancer saw.
#[test]
fn a_spoofed_x_forwarded_for_cannot_choose_its_bucket() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("spoof");
    let (upstream, heads) = spawn_upstream();
    let proxy = Proxy::dialect(&dir, upstream, Some(1));

    assert_admitted(&chat(&proxy, &[("x-forwarded-for", "203.0.113.1")]));
    // The client at 203.0.113.1 sent `x-forwarded-for: 198.51.100.66`; the
    // balancer appended the address it saw.
    let spoofed = chat(&proxy, &[("x-forwarded-for", "198.51.100.66, 203.0.113.1")]);
    assert_refused(&spoofed);
    assert_eq!(
        heads.try_iter().count(),
        1,
        "the spoofed request reached the upstream"
    );

    let logged = wait_for_lines(&dir.join("access.log"), 2);
    assert_eq!(
        json_field(&logged, "client_address"),
        ["203.0.113.1", "203.0.113.1"]
    );
    proxy.finish(&dir);
}

/// Zero hops (the default) is unchanged: the TCP peer is the client, a new
/// `x-forwarded-for` is not a new bucket, and nothing is appended to it.
#[test]
fn zero_trusted_hops_keys_on_the_peer_and_leaves_x_forwarded_for_alone() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("zero");
    let (upstream, heads) = spawn_upstream();
    let proxy = Proxy::dialect(&dir, upstream, None);

    assert_admitted(&chat(&proxy, &[("x-forwarded-for", "203.0.113.1")]));
    assert_refused(&chat(&proxy, &[("x-forwarded-for", "203.0.113.2")]));

    let forwarded: Vec<String> = heads.try_iter().map(|h| xff_of(&h)).collect();
    assert_eq!(forwarded, ["203.0.113.1"]);
    let logged = wait_for_lines(&dir.join("access.log"), 2);
    assert_eq!(
        json_field(&logged, "client_address"),
        ["127.0.0.1", "127.0.0.1"]
    );
    let records = wait_for_lines(&dir.join("records.jsonl"), 2);
    assert_eq!(
        json_field(&records, "client_address"),
        ["127.0.0.1", "127.0.0.1"]
    );
    proxy.finish(&dir);
}

/// S9: `x-envoy-*` request headers are trusted only from an internal source.
/// A request relayed by more than one hop is external, so a client's forged
/// `x-envoy-attempt-count` never reaches the provider. The same headers from
/// an internal source (a private peer, one forwarded entry) pass, which shows
/// the external case is stripped by the S9 rule and not lost on the way.
#[test]
fn an_external_clients_x_envoy_headers_do_not_reach_the_provider() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("x-envoy");
    let (upstream, heads) = spawn_upstream();
    let proxy = Proxy::dialect(&dir, upstream, Some(1));
    let forged = [
        ("x-envoy-attempt-count", "7"),
        ("x-envoy-client-probe", "1"),
    ];

    let external = [("x-forwarded-for", "198.51.100.66, 203.0.113.1")];
    assert_admitted(&chat(&proxy, &[&external[..], &forged[..]].concat()));
    let internal = [("x-forwarded-for", "203.0.113.2")];
    assert_admitted(&chat(&proxy, &[&internal[..], &forged[..]].concat()));

    let seen: Vec<String> = heads.try_iter().collect();
    assert_eq!(seen.len(), 2, "{seen:#?}");
    for (head, kept) in seen.iter().zip([false, true]) {
        for (name, value) in forged {
            assert_eq!(
                head.lines()
                    .any(|line| line.trim_end() == format!("{name}: {value}")),
                kept,
                "{name} {} reach the provider:\n{head}",
                if kept { "must" } else { "must not" }
            );
        }
    }
    proxy.finish(&dir);
}

/// Envoy mode resolves the same address from `use_remote_address` and
/// `xff_num_trusted_hops`, and `%DOWNSTREAM_REMOTE_ADDRESS%` renders it with
/// port 0, as Envoy does for an address taken from `x-forwarded-for`.
#[test]
fn envoy_mode_trusted_hops_key_limits_and_the_access_log() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("envoy");
    let (upstream, heads) = spawn_upstream();
    let proxy = Proxy::envoy(&dir, upstream);

    assert_admitted(&chat(&proxy, &[("x-forwarded-for", "203.0.113.1")]));
    assert_admitted(&chat(&proxy, &[("x-forwarded-for", "203.0.113.2")]));
    assert_refused(&chat(
        &proxy,
        &[("x-forwarded-for", "198.51.100.66, 203.0.113.1")],
    ));
    assert_eq!(heads.try_iter().count(), 2);

    let logged = wait_for_lines(&dir.join("access.log"), 3);
    assert_eq!(logged, ["203.0.113.1:0", "203.0.113.2:0", "203.0.113.1:0"]);
    proxy.finish(&dir);
}

// ------------------------------------------------------------------ helpers --

/// A running proxy. Killed and reaped on drop, so a failed assertion cannot
/// leave a listener behind (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    listen: SocketAddr,
}

impl Proxy {
    /// The dialect with a `client-ip` limit of one request a minute, a JSON
    /// access log and request records, both in `dir`.
    fn dialect(dir: &Path, upstream: SocketAddr, trusted_hops: Option<u32>) -> Proxy {
        let listen = free_port();
        let hops = trusted_hops.map_or(String::new(), |n| format!(", trusted_hops: {n}"));
        let config = format!(
            r#"version: 1
listen: {{ address: "127.0.0.1:{listen}"{hops} }}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
routes:
  - {{ model: "*", provider: openai }}
limits:
  - {{ key: client-ip, requests_per_minute: 1 }}
observability:
  access_logs:
    output: {log}
    format: json
"#,
            log = dir.join("access.log").display(),
        );
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).expect("write temp config");
        let records = dir.join("records.jsonl");
        Proxy::spawn(
            &[
                "--config",
                path.to_str().expect("utf-8 path"),
                "--request-records-file",
                records.to_str().expect("utf-8 path"),
            ],
            listen,
        )
    }

    /// An Envoy bootstrap at the edge behind one trusted hop, with the same
    /// limit and a text access log of `%DOWNSTREAM_REMOTE_ADDRESS%`.
    fn envoy(dir: &Path, upstream: SocketAddr) -> Proxy {
        let listen = free_port();
        let admin = free_port();
        let log = dir.join("access.log");
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
                use_remote_address: true
                xff_num_trusted_hops: 1
                access_log:
                  - name: envoy.access_loggers.file
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                      path: {log}
                      log_format:
                        text_format: "%DOWNSTREAM_REMOTE_ADDRESS%\n"
                route_config:
                  name: local
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route: {{ cluster: backend }}
                http_filters:
                  - name: llmproxy.token_limit
                    typed_config:
                      "@type": type.llmproxy.dev/llmproxy.filters.v0.TokenLimit
                      rules:
                        - {{ key: CLIENT_IP, requests_per_minute: 1 }}
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
            log = log.display(),
            upstream_port = upstream.port(),
        );
        let path = dir.join("envoy.yaml");
        std::fs::write(&path, config).expect("write temp config");
        Proxy::spawn(&["-c", path.to_str().expect("utf-8 path")], listen)
    }

    fn spawn(args: &[&str], listen: u16) -> Proxy {
        let child = Command::new(BIN)
            .args(args)
            .args(["--concurrency", "1"])
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

    fn finish(self, dir: &Path) {
        drop(self);
        let _ = std::fs::remove_dir_all(dir);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-trusted-hops-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn chat(proxy: &Proxy, headers: &[(&str, &str)]) -> String {
    let body = r#"{"model":"gpt-4o","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#;
    let mut stream = TcpStream::connect(proxy.listen).expect("connect");
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
                "POST /v1/chat/completions HTTP/1.1\r\nHost: proxy.local\r\n{extra}\
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

fn assert_admitted(response: &str) {
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

/// A 429 from the limiter itself: the mock upstream always answers 200.
fn assert_refused(response: &str) {
    assert!(
        response.starts_with("HTTP/1.1 429") && response.contains(RATE),
        "expected 429 `{RATE}`:\n{response}"
    );
}

/// A mock OpenAI upstream that sends each request head it receives, lowercased,
/// down the channel.
fn spawn_upstream() -> (SocketAddr, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || {
                let Some(head) = read_request(&mut stream) else {
                    return;
                };
                let _ = tx.send(head);
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
    (addr, rx)
}

/// Reads one full request (head and Content-Length body) and returns the
/// lowercased head; `None` on error.
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
    let mut have = raw.len() - (head_end + 4);
    while have < content_length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => have += n,
        }
    }
    Some(head)
}

/// The `x-forwarded-for` value of a lowercased request head; empty if absent.
fn xff_of(head: &str) -> String {
    head.lines()
        .find_map(|l| l.strip_prefix("x-forwarded-for:"))
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

/// Waits until `path` holds at least `n` lines and returns them.
fn wait_for_lines(path: &Path, n: usize) -> Vec<String> {
    let deadline = Instant::now() + WAIT;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if lines.len() >= n {
            return lines;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {n} lines in {}; have {lines:?}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// One string field from each JSON line.
fn json_field(lines: &[String], key: &str) -> Vec<String> {
    lines
        .iter()
        .map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).expect("a JSON line");
            value[key]
                .as_str()
                .unwrap_or_else(|| panic!("`{key}` missing in {line}"))
                .to_string()
        })
        .collect()
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

/// Windows are one minute and epoch-aligned. A test that counts requests in
/// one window waits out the last seconds of a minute so it cannot straddle one.
fn start_away_from_a_window_edge() {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs();
    let into_minute = secs % 60;
    if into_minute >= 50 {
        std::thread::sleep(Duration::from_secs(61 - into_minute));
    }
}
