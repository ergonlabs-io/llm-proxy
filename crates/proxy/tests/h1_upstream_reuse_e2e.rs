//! HTTP/1.1 upstream connection reuse through the real binary. A provider
//! that frames its response with `Content-Length` must get its connection
//! back for the next request, and a response the client abandons must not.
//!
//! The downstream h1 writer stops polling a response body once it has written
//! `Content-Length` bytes, so the upstream body never yields its terminal
//! `None`. Router unit tests drain bodies with `collect()`, which does poll to
//! `None`, so only a test through the real downstream codec sees this.
//!
//! Rust note: same harness shape as `tests/common_duration_e2e.rs`; each
//! `tests/*.rs` file is its own crate, so the helpers are duplicated.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
/// The declared length of the response the client abandons. Far more than
/// the provider sends, so that response can never end cleanly.
const STALLED_LENGTH: usize = 1 << 20;

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

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-h1-reuse-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// What the provider observed, shared with the test.
#[derive(Default)]
struct Observed {
    accepted: AtomicUsize,
    /// The proxy closed the connection that carried the `/stall` response.
    stall_closed: AtomicBool,
    /// More bytes (a next request) arrived on that connection: it was reused.
    stall_reused: AtomicBool,
}

/// A keep-alive HTTP/1.1 provider. `/stall` answers with a `Content-Length`
/// of [`STALLED_LENGTH`], sends a few bytes and then waits to see whether the
/// proxy closes the connection or sends another request on it; any other path
/// gets a complete `Content-Length` response.
fn spawn_content_length_upstream() -> (SocketAddr, Arc<Observed>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
    let addr = listener.local_addr().expect("local addr");
    let observed = Arc::new(Observed::default());
    let shared = observed.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            shared.accepted.fetch_add(1, Ordering::SeqCst);
            let shared = shared.clone();
            std::thread::spawn(move || serve_keep_alive(stream, &shared));
        }
    });
    (addr, observed)
}

fn serve_keep_alive(mut stream: TcpStream, observed: &Observed) {
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
        let head = String::from_utf8_lossy(&pending[..head_end]).to_string();
        pending.drain(..head_end);
        if head.starts_with("GET /stall ") {
            let _ = stream.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {STALLED_LENGTH}\r\n\r\npartial")
                    .as_bytes(),
            );
            let mut buf = [0u8; 64];
            match stream.read(&mut buf) {
                Ok(0) => observed.stall_closed.store(true, Ordering::SeqCst),
                Ok(_) => observed.stall_reused.store(true, Ordering::SeqCst),
                Err(_) => {}
            }
            return;
        }
        let body = b"complete";
        let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        if stream.write_all(response.as_bytes()).is_err() || stream.write_all(body).is_err() {
            return;
        }
    }
}

/// Boot the proxy in Envoy mode with one plaintext HTTP/1.1 cluster.
fn start_proxy(dir: &std::path::Path, upstream: SocketAddr) -> (ChildGuard, u16) {
    let listen = free_port();
    let admin = free_port();
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
                          route: {{ cluster: provider, timeout: 0s }}
  clusters:
    - name: provider
      type: STATIC
      connect_timeout: 2s
      load_assignment:
        cluster_name: provider
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {ip}, port_value: {port} }}
"#,
        ip = upstream.ip(),
        port = upstream.port(),
    );
    std::fs::write(&config_path, config).expect("write config");
    let guard = ChildGuard(
        Command::new(BIN)
            .args(["-c", config_path.to_str().unwrap(), "--concurrency", "1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn llm-proxy"),
    );
    assert!(
        wait_for_connectable(listen),
        "listener on {listen} never became connectable"
    );
    (guard, listen)
}

/// One complete request on its own client connection.
fn get(listen: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", listen)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("read timeout");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: t.local\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .expect("write request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

#[test]
fn a_content_length_response_returns_its_connection_for_the_next_request() {
    let dir = scratch_dir("reuse");
    let (upstream, observed) = spawn_content_length_upstream();
    let (_proxy, listen) = start_proxy(&dir, upstream);

    for n in 1..=3 {
        let response = get(listen, "/v1/models");
        assert!(
            response.starts_with("HTTP/1.1 200") && response.ends_with("complete"),
            "request {n}: {response:?}"
        );
    }
    assert_eq!(
        observed.accepted.load(Ordering::SeqCst),
        1,
        "three sequential requests must share one upstream connection"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Negative control: a response the client abandons mid-body leaves its
/// connection mid-response, so the next request must dial a new one.
#[test]
fn a_response_the_client_abandons_does_not_return_its_connection() {
    let dir = scratch_dir("abandon");
    let (upstream, observed) = spawn_content_length_upstream();
    let (_proxy, listen) = start_proxy(&dir, upstream);

    let mut stream = TcpStream::connect(("127.0.0.1", listen)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("read timeout");
    stream
        .write_all(b"GET /stall HTTP/1.1\r\nHost: t.local\r\n\r\n")
        .expect("write request");
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&seen).contains("partial") {
        let n = stream.read(&mut buf).expect("read the partial body");
        assert!(n > 0, "proxy closed before the partial body: {seen:?}");
        seen.extend_from_slice(&buf[..n]);
    }
    drop(stream);

    // The proxy notices the disconnect on its own schedule; wait for the
    // provider to see that connection closed rather than sleeping a fixed time.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !observed.stall_closed.load(Ordering::SeqCst) {
        assert!(
            !observed.stall_reused.load(Ordering::SeqCst),
            "the abandoned response's connection was reused"
        );
        assert!(
            Instant::now() < deadline,
            "the proxy never closed the abandoned response's connection"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let response = get(listen, "/v1/models");
    assert!(response.ends_with("complete"), "{response:?}");
    assert!(!observed.stall_reused.load(Ordering::SeqCst));
    assert_eq!(
        observed.accepted.load(Ordering::SeqCst),
        2,
        "the next request must dial a fresh connection"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
