//! A cluster-level `usage_dialect` must decide how the usage filter parses the
//! response of the cluster that was actually dialled (AGENTS.md invariant 6),
//! on an ordinary forward and again after failover onto a second member.
//!
//! The request path is `/v1/chat/completions` on purpose: the usage filter
//! lets a `/messages` or `/responses` path pick the dialect itself, so only a
//! path that names no dialect leaves the cluster (or the filter default) in
//! charge of how the body is read.
//!
//! The filter default is `openai` throughout, and every provider body is in
//! the dialect its own cluster declares, so a request that falls back to the
//! filter default parses the Anthropic body as OpenAI and reports no tokens.
//! The failover case also fails if the dialect of the first (failed) attempt
//! is kept instead of the one of the member that answered.
//!
//! Rust note: same harness shape as `tests/stats_e2e.rs` (real binary,
//! ephemeral ports, a guard that kills the proxy on drop); each `tests/*.rs`
//! file is its own crate, so the helpers are duplicated.

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

const ANTHROPIC_BODY: &str =
    r#"{"id":"msg_1","type":"message","usage":{"input_tokens":21,"output_tokens":5}}"#;

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

/// A mock provider answering every request with `200` and `body` as JSON.
fn spawn_upstream(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                // Drain the request head before replying.
                while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                }
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

/// An address nothing listens on, so the connect fails and the route's
/// `connect-failure` retry moves to the next aggregate member.
fn dead_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("local addr")
}

fn static_cluster(name: &str, addr: SocketAddr, dialect: &str) -> String {
    format!(
        r#"
    - name: {name}
      type: STATIC
      connect_timeout: 2s
      metadata:
        filter_metadata:
          io.llmproxy.usage:
            dialect: {dialect}
      load_assignment:
        cluster_name: {name}
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {ip}, port_value: {port} }}
"#,
        ip = addr.ip(),
        port = addr.port()
    )
}

/// Runs one POST through the proxy with `clusters` (YAML list items) routed
/// to `route_cluster`, and returns the access-log line
/// `"<input tokens> <output tokens>"` the usage filter produced.
fn token_line(clusters: &str, route_cluster: &str) -> String {
    let listener_port = free_port();
    let admin_port = free_port();
    let tag = format!("{}-{listener_port}", std::process::id());
    let log_path = std::env::temp_dir().join(format!("llm-proxy-usage-dialect-{tag}.log"));
    let config_path = std::env::temp_dir().join(format!("llm-proxy-usage-dialect-{tag}.yaml"));
    let log_path_str = log_path.display().to_string();

    let config = format!(
        r#"
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin_port} }}
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress
                http_filters:
                  - name: llmproxy.usage
                    typed_config:
                      "@type": type.llmproxy.dev/envoy.config.core.v3.DataSource
                      inline_string: openai
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: {route_cluster}
                            retry_policy:
                              retry_on: connect-failure
                              num_retries: 2
                access_log:
                  - name: envoy.access_loggers.file
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                      path: {log_path_str}
                      log_format:
                        text_format: "%LLM_INPUT_TOKENS% %LLM_OUTPUT_TOKENS%\n"
  clusters:
{clusters}
"#
    );
    std::fs::write(&config_path, config).expect("write config");

    let _proxy = ChildGuard(
        Command::new(BIN)
            .args(["-c", config_path.to_str().unwrap(), "--concurrency", "1"])
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn llm-proxy"),
    );
    assert!(
        wait_for_connectable(listener_port),
        "listener on {listener_port} never became connectable"
    );

    let body = r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
    let mut stream = TcpStream::connect(("127.0.0.1", listener_port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    stream
        .write_all(
            format!(
                "POST /v1/chat/completions HTTP/1.1\r\nHost: t.local\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .expect("write request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200, got:\n{response}"
    );

    // The access log is written when the response body completes, which can
    // land just after the client sees EOF.
    let deadline = Instant::now() + Duration::from_secs(5);
    let line = loop {
        let text = std::fs::read_to_string(&log_path).unwrap_or_default();
        if let Some(line) = text.lines().next() {
            break line.to_string();
        }
        assert!(Instant::now() < deadline, "access log never written");
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&log_path);
    line
}

/// Ordinary forward, no failover, no hedge, no upgrade: the cluster says
/// `anthropic`, the filter default says `openai`, and the cluster wins.
#[test]
fn cluster_usage_dialect_applies_on_a_plain_forward() {
    let clusters = static_cluster("claude", spawn_upstream(ANTHROPIC_BODY), "anthropic");
    assert_eq!(token_line(&clusters, "claude"), "21 5");
}

/// The first member (dead, `openai`) fails to connect and the request falls
/// back to the second (`anthropic`). Usage must be parsed with the dialect of
/// the member that answered, not the failed attempt's and not the filter
/// default.
#[test]
fn cluster_usage_dialect_follows_failover_to_the_dialled_member() {
    let clusters = format!(
        "{}{}{}",
        static_cluster("primary", dead_addr(), "openai"),
        static_cluster("fallback", spawn_upstream(ANTHROPIC_BODY), "anthropic"),
        r#"
    - name: providers
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [primary, fallback]
"#
    );
    assert_eq!(token_line(&clusters, "providers"), "21 5");
}
