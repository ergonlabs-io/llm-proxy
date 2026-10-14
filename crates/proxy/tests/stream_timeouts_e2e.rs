//! HCM `stream_idle_timeout` and `common_http_protocol_options.max_stream_duration`
//! reach the data plane from an Envoy-mode config.
//!
//! The behaviour itself is pinned in `crates/proxy-http/tests/stream_timeouts.rs`;
//! this proves the real binary lowers the fields and hands them to the
//! listener. The upstream accepts and never answers, so the only thing that can
//! end the request is the stream limit under test.
//!
//! Rust note: same harness shape as `tests/stats_e2e.rs` (real binary,
//! ephemeral ports, a guard that kills the proxy on drop); each `tests/*.rs`
//! file is its own crate, so the helpers are duplicated.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
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

/// A provider that reads each request and then holds the connection open
/// without ever answering.
fn spawn_hanging_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            held.push(stream);
        }
    });
    addr
}

/// Boots the proxy with `hcm_extra` (16-space indented HCM fields) in front of
/// the hanging upstream, sends one request and returns the response status
/// line.
fn status_line(hcm_extra: &str) -> String {
    let upstream = spawn_hanging_upstream();
    let listener_port = free_port();
    let admin_port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-stream-timeouts-{}-{listener_port}.yaml",
        std::process::id()
    ));
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
{hcm_extra}
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
                        - match:
                            prefix: "/"
                          route:
                            cluster: hung
                            timeout: 0s
  clusters:
    - name: hung
      type: STATIC
      connect_timeout: 2s
      load_assignment:
        cluster_name: hung
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {ip}, port_value: {port} }}
"#,
        ip = upstream.ip(),
        port = upstream.port()
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

    let mut stream = TcpStream::connect(("127.0.0.1", listener_port)).expect("connect");
    // Backstop only: the proxy must answer long before this.
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("read timeout");
    stream
        .write_all(b"GET /v1/models HTTP/1.1\r\nHost: t.local\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let _ = std::fs::remove_file(&config_path);
    String::from_utf8_lossy(&response)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn hcm_stream_idle_timeout_cuts_a_provider_that_never_answers() {
    assert!(
        status_line("                stream_idle_timeout: 0.5s").starts_with("HTTP/1.1 408"),
        "expected the idle timeout to answer 408"
    );
}

#[test]
fn hcm_max_stream_duration_cuts_a_provider_that_never_answers() {
    let hcm = "                stream_idle_timeout: 0s\n\
               \x20               common_http_protocol_options:\n\
               \x20                 max_stream_duration: 0.5s";
    assert!(
        status_line(hcm).starts_with("HTTP/1.1 504"),
        "expected max_stream_duration to answer 504"
    );
}
