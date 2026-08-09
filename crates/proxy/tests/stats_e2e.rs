//! WP-23 increment 6a acceptance: real traffic through the real `llm-proxy`
//! binary shows up in `/stats`. This is the load-bearing test for the
//! increment -- an assertion against `Registry::value` (or anything short of
//! the actual `/stats` HTTP response) would pass even if the renderer never
//! saw what the router recorded. See `crates/proxy-http/src/stat_handles.rs`
//! and `crates/proxy-http/src/router.rs` for the recording side; this file
//! only drives the compiled binary and reads its admin surface.
//!
//! Rust note: same shape as `tests/cli.rs` (a separate compiled crate per
//! `tests/*.rs` file, so nothing here is shared with it beyond convention) --
//! `env!("CARGO_BIN_EXE_llm-proxy")`, ephemeral ports via `free_port()`, and
//! `Command::new(BIN).spawn()` rather than any in-process harness, because
//! `crates/proxy` has no `[lib]` target for an integration test to link
//! against: the only way to exercise `main.rs`'s real wiring (the
//! `StatsControl`/`StatHandles`/`RouterStats` construction in `run_serve`/
//! `worker_main`) is to run the actual binary.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

/// Reserves a free ephemeral port and hands back its number -- same
/// "bind to port 0, read it back, drop it" technique as `tests/cli.rs`'s own
/// `free_port`; each `tests/*.rs` file is its own compiled crate, so this
/// isn't shared, just duplicated.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
}

/// How long to wait for the freshly spawned `llm-proxy` to become
/// connectable -- see `tests/cli.rs`'s `STARTUP_TIMEOUT` for why this is a
/// liveness backstop, not a speed assertion.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

fn wait_for_connectable(addr: (&str, u16), timeout: Duration) -> bool {
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

fn spawn_line_reader(
    mut reader: BufReader<impl std::io::Read + Send + 'static>,
) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line.clone()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

fn drain_available_lines(rx: &mpsc::Receiver<String>) -> Vec<String> {
    let mut lines = Vec::new();
    while let Ok(line) = rx.try_recv() {
        lines.push(line);
    }
    lines
}

/// A mock upstream: accepts connections in a loop, forever, answering each
/// with a quick `200 OK` -- what the proxy's `backend` cluster forwards to.
/// Plain `std::net`/`std::thread` (no tokio) since this whole test avoids an
/// async runtime, matching `tests/cli.rs`'s style.
fn spawn_mock_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                // Read whatever the client sent (don't bother parsing it --
                // this mock only cares that a request arrived) before
                // replying, so the reply isn't racing the request on the
                // wire.
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            });
        }
    });
    addr
}

/// Sends a plain `GET <path> HTTP/1.1` with `Connection: close` to `addr` and
/// returns the full response (status line + headers + body) read up to EOF --
/// the server closing the connection (honoring `Connection: close`) is what
/// ends the read, matching hyper's (admin) and this proxy's (listener) own
/// HTTP/1.1 behavior for a closed-connection request.
fn get(addr: SocketAddr, path: &str, host: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set_read_timeout");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read response to EOF");
    String::from_utf8_lossy(&response).to_string()
}

/// The load-bearing WP-23 increment 6a test: two requests through a real
/// `llm-proxy` listener to a real (mock) upstream, then a real HTTP scrape of
/// `/stats` on the real admin server -- and the rendered text must show
/// exactly what happened, not an empty body (the pre-increment-6a gap this
/// closes) and not a fabricated reading.
#[test]
fn served_requests_are_reflected_in_stats() {
    let upstream_addr = spawn_mock_upstream();
    let listener_port = free_port();
    let admin_port = free_port();

    let config_yaml = format!(
        r#"
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin_port} }}

static_resources:
  listeners:
    - name: ingress_http
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: backend
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: backend
      type: STATIC
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {upstream_ip}, port_value: {upstream_port} }}
"#,
        upstream_ip = upstream_addr.ip(),
        upstream_port = upstream_addr.port(),
    );

    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-stats-e2e-test-{}-{}.yaml",
        std::process::id(),
        listener_port
    ));
    std::fs::write(&config_path, config_yaml).expect("failed to write temp config");

    let mut child = Command::new(BIN)
        .args(["-c", config_path.to_str().unwrap(), "--concurrency", "1"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn llm-proxy");

    let stderr = child.stderr.take().expect("child stderr not piped");
    let rx = spawn_line_reader(BufReader::new(stderr));

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "listener at 127.0.0.1:{listener_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&rx)
    );
    let admin_ready = wait_for_connectable(("127.0.0.1", admin_port), STARTUP_TIMEOUT);
    assert!(
        admin_ready,
        "admin at 127.0.0.1:{admin_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&rx)
    );

    // Two real requests through the real router to the real (mock) upstream
    // -- each a fresh h1 connection (connect-per-stream, matching this
    // router's v1 h1 behavior), so this also proves `upstream_rq` counts
    // requests, not connections.
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    for _ in 0..2 {
        let response = get(listener_addr, "/v1/chat/completions", "test.local");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected the proxied request to succeed, got:\n{response}"
        );
    }

    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    let stats_response = get(admin_addr, "/stats", "admin.local");
    assert!(
        stats_response.starts_with("HTTP/1.1 200"),
        "expected /stats to answer 200, got:\n{stats_response}"
    );
    let body = stats_response
        .split("\r\n\r\n")
        .nth(1)
        .expect("response has a body separated from headers by a blank line");
    assert!(
        body.contains("cluster.backend.upstream_rq_total: 2"),
        "expected /stats to report 2 real requests against cluster \"backend\", got body:\n{body}\n\
         (full response: {stats_response})"
    );

    let pid = child.id().to_string();
    let _ = Command::new("kill").arg("-TERM").arg(&pid).status();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_file(&config_path);
}
