//! The request-record JSONL file sink (`--request-records-file`) against the
//! real binary: a request that spans SIGTERM is still recorded, and records
//! keep flowing, in order, across a SIGHUP reload on a kept-alive client.
#![cfg(unix)]
mod common;

use common::free_port;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

fn records(path: &std::path::Path) -> Vec<proxy_observability::records::RequestRecord> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn keepalive_connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(2),
    )
    .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
}

fn keepalive_get(stream: &mut TcpStream, path: &str) {
    write!(stream, "GET {path} HTTP/1.1\r\nHost: test.local\r\n\r\n").unwrap();
    // Read exactly one response; never consume bytes from a later response.
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        assert!(response.len() < 16384, "oversized response headers");
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        response.push(byte[0]);
    }
    let headers = String::from_utf8(response).unwrap();
    assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
    assert!(
        headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("content-length: 0")),
        "{headers}"
    );
    assert!(
        !headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("connection: close")),
        "{headers}"
    );
}

fn bootstrap_yaml(listener: u16, admin: u16, upstream: u16) -> String {
    format!(
        r#"
node:
  id: test-proxy
  cluster: test
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin} }}
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener} }}
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
                    socket_address: {{ address: 127.0.0.1, port_value: {upstream} }}
"#
    )
}

/// Upstream that answers only after `release` is set, so a request can span
/// SIGTERM. `arrived` counts requests that reached it.
fn gated_mock(release: Arc<AtomicBool>, arrived: Arc<std::sync::atomic::AtomicUsize>) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let halted = stop.clone();
    let thread = std::thread::spawn(move || {
        while !halted.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let _ = stream.read(&mut [0; 4096]);
                    arrived.fetch_add(1, Ordering::SeqCst);
                    while !release.load(Ordering::SeqCst) && !halted.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => break,
            }
        }
    });
    Mock {
        address,
        stop,
        thread: Some(thread),
    }
}

struct Proxy(Child);
impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Mock {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
fn mock() -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let halted = stop.clone();
    let thread = std::thread::spawn(move || {
        while !halted.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // On macOS an accepted socket inherits the listener's
                    // O_NONBLOCK. Left set, a request that has not arrived yet
                    // reads as WouldBlock, the mock answers and closes with
                    // the request unread, and the kernel resets the
                    // connection under the proxy (UC, 502).
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    // Read the whole head (requests here carry no body) so
                    // dropping `stream` never closes it with request bytes
                    // unread.
                    let mut head = Vec::new();
                    let mut chunk = [0; 4096];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => break,
            }
        }
    });
    Mock {
        address,
        stop,
        thread: Some(thread),
    }
}
fn get(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}
fn wait(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !condition() {
        assert!(Instant::now() < deadline, "integration deadline exceeded");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_request_spanning_sigterm_is_recorded() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("records.jsonl");
    let release = Arc::new(AtomicBool::new(false));
    let arrived = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let upstream = gated_mock(release.clone(), arrived.clone());
    let (listener, admin) = (free_port(), free_port());
    let bootstrap = temp.path().join("proxy.yaml");
    std::fs::write(
        &bootstrap,
        bootstrap_yaml(listener, admin, upstream.address.port()),
    )
    .unwrap();
    let mut proxy = Proxy(
        Command::new(BIN)
            .arg("-c")
            .arg(&bootstrap)
            .args(["--concurrency", "1", "--drain-time-s", "600"])
            .arg("--request-records-file")
            .arg(&file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait(|| {
        assert!(proxy.0.try_wait().unwrap().is_none(), "proxy exited early");
        TcpStream::connect(("127.0.0.1", listener)).is_ok()
            && TcpStream::connect(("127.0.0.1", admin)).is_ok()
    });

    let mut client = TcpStream::connect(("127.0.0.1", listener)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        client,
        "GET /spanning HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    wait(|| arrived.load(Ordering::SeqCst) == 1);

    assert!(Command::new("kill")
        .args(["-TERM", &proxy.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    wait(|| get(admin, "/ready").contains("DRAINING"));
    release.store(true, Ordering::SeqCst);
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    wait(|| proxy.0.try_wait().unwrap().is_some());
    assert!(proxy.0.try_wait().unwrap().unwrap().success());

    let records = records(&file);
    assert_eq!(records.len(), 1, "the drained request must be recorded");
    assert_eq!(records[0].status, Some(200));
}

/// A reload closes HTTP connections accepted under the replaced snapshot
/// (envoy-divergences.md, row 38), so the client reconnects. The file sink is
/// boot-scoped: its writer thread, numbering and instance id carry across.
#[test]
fn request_records_keep_flowing_in_order_across_a_sighup_reload() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("records.jsonl");
    let upstream = mock();
    let (listener, admin) = (free_port(), free_port());
    let bootstrap = temp.path().join("proxy.yaml");
    let log = temp.path().join("proxy.log");
    std::fs::write(
        &bootstrap,
        bootstrap_yaml(listener, admin, upstream.address.port()),
    )
    .unwrap();
    let mut proxy = Proxy(
        Command::new(BIN)
            .arg("-c")
            .arg(&bootstrap)
            .args(["--concurrency", "1", "--drain-time-s", "0"])
            .arg("--request-records-file")
            .arg(&file)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap(),
    );
    wait(|| {
        assert!(
            proxy.0.try_wait().unwrap().is_none(),
            "proxy exited before binding"
        );
        TcpStream::connect(("127.0.0.1", listener)).is_ok()
            && TcpStream::connect(("127.0.0.1", admin)).is_ok()
    });
    let mut downstream = keepalive_connect(listener);
    keepalive_get(&mut downstream, "/first");
    wait(|| records(&file).len() == 1);

    assert!(Command::new("kill")
        .args(["-HUP", &proxy.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    wait(|| {
        std::fs::read_to_string(&log)
            .unwrap()
            .matches("SIGHUP: config reload succeeded")
            .count()
            == 1
    });
    downstream = keepalive_connect(listener);
    keepalive_get(&mut downstream, "/second");
    wait(|| records(&file).len() == 2);
    drop(downstream);
    assert!(Command::new("kill")
        .args(["-TERM", &proxy.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    wait(|| proxy.0.try_wait().unwrap().is_some());

    let records = records(&file);
    assert_eq!(records.len(), 2);
    for (record, seq) in records.iter().zip(1..) {
        // Numbered by the one writer thread in arrival order (ADR-0011
        // decision 2); a reload neither restarts nor gaps the numbering.
        assert_eq!(record.record_seq, Some(seq), "{record:?}");
        assert_eq!(record.instance_id, records[0].instance_id);
        assert_eq!(record.status, Some(200));
        assert_eq!(record.tenant_id, "default");
        assert_eq!(record.selected_cluster.as_deref(), Some("backend"));
        assert_eq!(record.physical_attempt_count, 1);
    }
}
