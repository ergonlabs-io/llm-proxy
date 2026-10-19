//! A route `idle_timeout` of `0s` disables the idle timeout for that route's
//! response body; Envoy treats 0 as "off", not as "cut at once". Driven
//! through the real binary so the lowering and the router are both on the
//! path.
//!
//! The provider sends a first chunk, pauses longer than the HCM
//! `stream_idle_timeout`, then sends the rest. With the HCM idle timeout armed
//! the stream is cut in the gap; with a route `idle_timeout: 0s` it must not
//! be (the route value, including 0, wins over the HCM value).
//!
//! Rust note: same harness shape as `tests/stream_timeouts_e2e.rs`; each
//! `tests/*.rs` file is its own crate, so the helpers are duplicated.

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const GAP: Duration = Duration::from_millis(1500);

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

/// Answers with one chunk, pauses for [`GAP`], then sends the final chunk.
fn spawn_pausing_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nfirst\r\n",
                );
                std::thread::sleep(GAP);
                let _ = stream.write_all(b"4\r\nlast\r\n0\r\n\r\n");
            });
        }
    });
    addr
}

/// Boots the proxy with an HCM `stream_idle_timeout` of 0.5s and `route_extra`
/// (28-space indented route fields), sends one request and returns the raw
/// response.
fn response_with_route_fields(route_extra: &str) -> String {
    let upstream = spawn_pausing_upstream();
    let listener_port = free_port();
    let admin_port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-route-idle-{}-{listener_port}.yaml",
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
                stream_idle_timeout: 0.5s
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
                            cluster: pausing
                            timeout: 0s
{route_extra}
  clusters:
    - name: pausing
      type: STATIC
      connect_timeout: 2s
      load_assignment:
        cluster_name: pausing
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
    // Backstop only: the proxy must finish long before this.
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("read timeout");
    stream
        .write_all(b"GET /v1/models HTTP/1.1\r\nHost: t.local\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let _ = std::fs::remove_file(&config_path);
    String::from_utf8_lossy(&response).to_string()
}

#[test]
fn route_idle_timeout_zero_disables_the_idle_timeout_for_the_route() {
    let response = response_with_route_fields("                            idle_timeout: 0s");
    assert!(
        response.contains("first") && response.contains("last"),
        "a route idle_timeout of 0s must let a pause longer than the HCM idle timeout through, got: {response:?}"
    );
}

/// Negative control: without the route field the HCM idle timeout does cut
/// the pause, so the test above passes because of the `0s`, not because the
/// pause is too short to matter.
#[test]
fn without_a_route_idle_timeout_the_hcm_idle_timeout_cuts_the_pause() {
    let response = response_with_route_fields("");
    assert!(
        response.contains("first") && !response.contains("last"),
        "the HCM idle timeout must cut the stream in the pause, got: {response:?}"
    );
}
