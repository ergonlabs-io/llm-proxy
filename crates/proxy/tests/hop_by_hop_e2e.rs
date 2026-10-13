//! S9 rule 6 (hop-by-hop headers) end to end: the real `llm-proxy` binary
//! with an Envoy bootstrap and a mock h1 upstream.
//!
//! Connection-management headers describe one hop. An upstream's
//! `Connection: close` must not close the client's keep-alive connection,
//! and a client's `Connection: close` must not close the pooled upstream
//! connection. Envoy strips them in both directions
//! (`ConnectionManagerUtility::mutateRequestHeaders` and
//! `mutateResponseHeaders`).
//!
//! Rust note: same harness shape as `tests/request_body_limit_e2e.rs` (std
//! threads, ephemeral ports, a `Proxy` guard that kills the child on drop).
//! Every wait is bounded by `STARTUP_TIMEOUT` or a socket read timeout.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// An upstream that answers every request with `Connection: close` (and a
/// `Keep-Alive` header) and then closes. The client's connection to the
/// proxy must still carry a second request.
#[test]
fn a_downstream_keepalive_connection_survives_an_upstream_connection_close() {
    let dir = scratch_dir("response");
    let (upstream, heads) = spawn_closing_upstream();
    let proxy = Proxy::start(&dir, upstream);

    let mut stream = TcpStream::connect(proxy.listen).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    for attempt in 1..=2 {
        write!(
            stream,
            "GET /v1/models HTTP/1.1\r\nHost: test.local\r\n\r\n"
        )
        .unwrap();
        let head = read_response_head(&mut stream).unwrap_or_else(|| {
            panic!("request {attempt}: the proxy closed the keep-alive connection")
        });
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "request {attempt}: {head}"
        );
        let lower = head.to_ascii_lowercase();
        assert!(
            !lower.contains("\r\nconnection:") && !lower.contains("\r\nkeep-alive:"),
            "request {attempt}: the upstream's connection management reached the client:\n{head}"
        );
    }
    assert_eq!(
        heads.try_iter().count(),
        2,
        "both requests must reach the upstream"
    );

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A client's connection-management headers must not reach the upstream:
/// a forwarded `Connection: close` closes the pooled upstream connection.
/// `TE` keeps only `trailers`. An `Upgrade` header without
/// `Connection: upgrade` is not an upgrade, so it is stripped too.
#[test]
fn client_connection_management_headers_do_not_reach_the_upstream() {
    let dir = scratch_dir("request");
    let (upstream, heads) = spawn_closing_upstream();
    let proxy = Proxy::start(&dir, upstream);

    let mut stream = TcpStream::connect(proxy.listen).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    write!(
        stream,
        "GET /v1/models HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\
         Keep-Alive: timeout=5\r\nProxy-Connection: keep-alive\r\nTE: gzip, trailers\r\n\
         Upgrade: example/1\r\nX-End-To-End: kept\r\n\r\n"
    )
    .unwrap();
    let head = read_response_head(&mut stream).expect("a response");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    let upstream_head = heads.recv_timeout(IO_TIMEOUT).expect("upstream request");
    let lines: Vec<&str> = upstream_head.lines().collect();
    for name in [
        "connection:",
        "keep-alive:",
        "proxy-connection:",
        "upgrade:",
    ] {
        assert!(
            !lines.iter().any(|l| l.starts_with(name)),
            "`{name}` reached the upstream:\n{upstream_head}"
        );
    }
    assert!(
        lines.contains(&"te: trailers"),
        "`te` must be reduced to `trailers`:\n{upstream_head}"
    );
    assert!(
        lines.contains(&"x-end-to-end: kept"),
        "an end-to-end header must pass:\n{upstream_head}"
    );

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

/// Reads one response head (status line and headers). `None` if the
/// connection closed first. Never reads past the head, so a later response
/// on the same connection stays unread; every response here has
/// `content-length: 0`.
fn read_response_head(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 16384, "oversized response head");
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

fn bootstrap(listen: u16, admin: u16, upstream: SocketAddr) -> String {
    let upstream_port = upstream.port();
    format!(
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
"#
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-hop-by-hop-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// A running proxy. Killed and reaped on drop, so a failed assertion cannot
/// leave a listener behind (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    listen: SocketAddr,
}

impl Proxy {
    fn start(dir: &Path, upstream: SocketAddr) -> Proxy {
        let listen = free_port();
        let admin = free_port();
        let path = dir.join("bootstrap.yaml");
        std::fs::write(&path, bootstrap(listen, admin, upstream)).expect("write bootstrap");
        let child = Command::new(BIN)
            .args([
                "-c",
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

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
}

/// A mock upstream that reads one bodiless request per connection, sends its
/// lowercased head on the channel, answers `200` with `Connection: close`
/// and a `Keep-Alive` header, and closes.
fn spawn_closing_upstream() -> (SocketAddr, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || {
                // macOS: an accepted socket can inherit the listener's
                // non-blocking flag; reads below must block.
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&raw).to_ascii_lowercase());
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\
                      Keep-Alive: timeout=5\r\n\r\n",
                );
            });
        }
    });
    (addr, rx)
}
