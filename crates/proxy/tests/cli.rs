//! Integration tests for the `llm-proxy` binary's CLI surface (WP-06 chunk C):
//! `--mode validate` exit codes and the SIGTERM drain-then-exit sequence.
//!
//! Rust note: `env!("CARGO_BIN_EXE_llm-proxy")` is filled in by cargo at build
//! time for integration tests (anything under `tests/`) -- it expands to the
//! absolute path of the `llm-proxy` binary this crate produces, so we don't
//! have to guess `target/debug/...` ourselves.

use std::io::{BufRead, BufReader, Write as _};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

fn repo_root() -> std::path::PathBuf {
    // `tests/` runs with CARGO_MANIFEST_DIR = crates/proxy.
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn validate_exits_zero_for_a_good_config() {
    let config = repo_root().join("examples/tcp-proxy.yaml");
    let status = Command::new(BIN)
        .args(["-c", config.to_str().unwrap(), "--mode", "validate"])
        .status()
        .expect("failed to run llm-proxy");
    assert!(status.success(), "expected exit 0, got {status:?}");
}

#[test]
fn validate_exits_nonzero_for_a_bad_config() {
    let dir = std::env::temp_dir();
    let bad_path = dir.join(format!("llm-proxy-bad-config-{}.yaml", std::process::id()));
    std::fs::write(&bad_path, "not: valid: yaml: [").expect("failed to write temp config");

    let status = Command::new(BIN)
        .args(["-c", bad_path.to_str().unwrap(), "--mode", "validate"])
        .status()
        .expect("failed to run llm-proxy");

    let _ = std::fs::remove_file(&bad_path);
    assert!(!status.success(), "expected a nonzero exit, got {status:?}");
}

/// Spawns a background thread that reads `reader` line by line and forwards
/// each line over the returned channel until EOF/error.
///
/// Rust note: `BufReader::read_line` blocks, so it has to run on its own
/// thread; the important bit here is that *the caller* owns the returned
/// `Receiver` (and thus decides when the underlying pipe's read end actually
/// closes) rather than a short-lived helper dropping it early. Dropping the
/// receiver -- and with it the reader thread's `ChildStdio` -- while the
/// child process is still writing to that pipe closes the read end out from
/// under it, and the next write earns the child an `EPIPE`. Keeping the
/// channel (and thus the pipe) open for the process's whole lifetime avoids
/// that race, which is why callers hang on to the `Receiver` past the first
/// `wait_for_line` call below.
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

/// How long to wait for a freshly spawned `llm-proxy` process to reach a
/// startup milestone (bind its listener / log "started").
///
/// Deliberately generous: this is wall-clock time for an unoptimized debug
/// binary to start on a machine that, under `make ci`, is simultaneously
/// running every other crate's test binaries. A 5s budget here was observed to
/// pass standalone but flake inside the full gate. The timeout is a
/// liveness backstop, not an assertion about speed -- the test still fails if
/// the process never binds, it just doesn't fail because the box was busy.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Waits (with a timeout) for a line matching `needle` to arrive on `rx`,
/// returning `true` if found. Non-matching lines are discarded.
fn wait_for_line(rx: &mpsc::Receiver<String>, needle: &str, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match rx.recv_timeout(remaining) {
            Ok(line) if line.contains(needle) => return true,
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
}

#[test]
fn sigterm_drains_then_exits_cleanly() {
    let config = repo_root().join("examples/tcp-proxy.yaml");
    let mut child = Command::new(BIN)
        .args([
            "-c",
            config.to_str().unwrap(),
            "--concurrency",
            "2",
            "--drain-time-s",
            "1",
        ])
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn llm-proxy");

    let stderr = child.stderr.take().expect("child stderr not piped");
    // Rust note: `rx` is kept alive for the rest of the test (see
    // `spawn_line_reader`'s doc comment) so the child's stderr pipe stays
    // open across the whole SIGTERM/drain/exit sequence, not just until the
    // startup line shows up.
    let rx = spawn_line_reader(BufReader::new(stderr));
    let found = wait_for_line(&rx, "llm-proxy started", STARTUP_TIMEOUT);
    assert!(found, "startup line did not appear on stderr in time");

    // `Child::kill` sends SIGKILL, not SIGTERM -- shell out to `kill -TERM`
    // to exercise the actual signal our graceful-shutdown path listens for.
    let pid = child.id().to_string();
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(&pid)
        .status()
        .expect("failed to send SIGTERM");
    assert!(status.success(), "kill -TERM failed");

    let exit = child
        .wait_timeout_or_kill(Duration::from_secs(5))
        .expect("llm-proxy did not exit after SIGTERM within timeout");
    assert!(
        exit.success(),
        "expected exit 0 after SIGTERM, got {exit:?}"
    );
}

/// Reserves a free ephemeral port and reserves it long enough to hand back
/// its number.
///
/// Rust note: standard "bind to port 0, read back what the OS picked, then
/// drop it" technique -- there's a small window where another process could
/// grab the same port before `llm-proxy` binds it, but that race is
/// acceptable for a test (and far less likely to collide in CI than the
/// example config's hardcoded port 10000 would be).
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
}

#[test]
fn serve_mode_accepts_connections_on_its_listener() {
    // Reuse the example's shape but swap in an ephemeral-derived port, so
    // this test can't collide with another `llm-proxy` (or itself, run in
    // parallel) bound to the example's fixed port 10000.
    let port = free_port();
    let config_yaml = format!(
        r#"
static_resources:
  listeners:
    - name: ingress_tcp
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: ingress_tcp
                cluster: backend

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
                    socket_address: {{ address: 127.0.0.1, port_value: 8081 }}
"#
    );

    let dir = std::env::temp_dir();
    let config_path = dir.join(format!(
        "llm-proxy-serve-test-{}-{}.yaml",
        std::process::id(),
        port
    ));
    std::fs::write(&config_path, config_yaml).expect("failed to write temp config");

    let mut child = Command::new(BIN)
        .args(["-c", config_path.to_str().unwrap(), "--concurrency", "1"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn llm-proxy");

    let stderr = child.stderr.take().expect("child stderr not piped");
    let rx = spawn_line_reader(BufReader::new(stderr));
    let found = wait_for_line(&rx, "listener bound", STARTUP_TIMEOUT);
    assert!(
        found,
        "listener-bound line did not appear on stderr in time"
    );

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .expect("connecting to the running listener should succeed");
    // A successful write proves the connection is actually live, not just
    // accepted-then-immediately-reset.
    stream
        .write_all(b"ping")
        .expect("write to the accepted connection should succeed");

    let pid = child.id().to_string();
    let _ = Command::new("kill").arg("-TERM").arg(&pid).status();
    let _ = child.wait_timeout_or_kill(Duration::from_secs(5));
    let _ = std::fs::remove_file(&config_path);
}

#[test]
fn serve_mode_fails_startup_when_a_listener_cannot_bind() {
    // Hold a plain (no `SO_REUSEADDR`/`SO_REUSEPORT`) listener on the port
    // `llm-proxy`'s config will ask for, so its worker's own bind -- which
    // does set those options (see `proxy_core::listener`'s module doc) --
    // still collides: `SO_REUSEPORT`-style sharing requires *every* socket
    // on the port to opt in, and this one doesn't. Held for the whole test
    // so the port stays occupied.
    //
    // Platform note: verified this actually fails to bind on macOS (this
    // dev machine) too, not just Linux -- Apple's `SO_REUSEPORT` also
    // requires all sharing sockets to set it, so a plain `std::net::TcpListener`
    // (which sets neither option) blocks the worker's bind either way.
    let held = std::net::TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    let port = held.local_addr().expect("no local addr").port();

    let config_yaml = format!(
        r#"
static_resources:
  listeners:
    - name: ingress_tcp
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: ingress_tcp
                cluster: backend

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
                    socket_address: {{ address: 127.0.0.1, port_value: 8081 }}
"#
    );

    let dir = std::env::temp_dir();
    let config_path = dir.join(format!(
        "llm-proxy-bind-fail-test-{}-{}.yaml",
        std::process::id(),
        port
    ));
    std::fs::write(&config_path, config_yaml).expect("failed to write temp config");

    let mut child = Command::new(BIN)
        .args(["-c", config_path.to_str().unwrap(), "--concurrency", "1"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn llm-proxy");

    let stderr = child.stderr.take().expect("child stderr not piped");
    let rx = spawn_line_reader(BufReader::new(stderr));

    let exit = child
        .wait_timeout_or_kill(Duration::from_secs(10))
        .expect("llm-proxy should exit (not hang) after a fatal initial bind failure");
    assert!(
        !exit.success(),
        "expected a nonzero exit when a listener fails to bind, got {exit:?}"
    );

    let mut saw_bind_failure = false;
    while let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
        if line.contains("failed to bind") {
            saw_bind_failure = true;
            break;
        }
    }
    assert!(
        saw_bind_failure,
        "expected stderr to mention the listener bind failure"
    );

    drop(held);
    let _ = std::fs::remove_file(&config_path);
}

#[test]
fn serve_mode_fails_startup_when_a_listener_has_a_bad_cert() {
    // WP-08 chunk C3: a `transport_socket` whose cert PEM won't parse must
    // fail startup exactly like a socket that won't bind (`initial_bind`'s
    // TLS-build path is fatal, same as its socket-bind path) -- Envoy itself
    // fails a static listener's warm-up on a bad cert.
    let port = free_port();
    let config_yaml = format!(
        r#"
static_resources:
  listeners:
    - name: ingress_tls
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: ingress_tls
                cluster: backend
          transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificates:
                  - certificate_chain: {{ inline_string: "not a real certificate" }}
                    private_key: {{ inline_string: "not a real key" }}

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
                    socket_address: {{ address: 127.0.0.1, port_value: 8081 }}
"#
    );

    let dir = std::env::temp_dir();
    let config_path = dir.join(format!(
        "llm-proxy-bad-cert-test-{}-{}.yaml",
        std::process::id(),
        port
    ));
    std::fs::write(&config_path, config_yaml).expect("failed to write temp config");

    let mut child = Command::new(BIN)
        .args(["-c", config_path.to_str().unwrap(), "--concurrency", "1"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn llm-proxy");

    let stderr = child.stderr.take().expect("child stderr not piped");
    let rx = spawn_line_reader(BufReader::new(stderr));

    let exit = child
        .wait_timeout_or_kill(Duration::from_secs(10))
        .expect("llm-proxy should exit (not hang) after a fatal TLS build failure");
    assert!(
        !exit.success(),
        "expected a nonzero exit when a listener's cert fails to load, got {exit:?}"
    );

    let mut saw_tls_failure = false;
    while let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
        if line.contains("TLS config error") || line.contains("ingress_tls") {
            saw_tls_failure = true;
            break;
        }
    }
    assert!(
        saw_tls_failure,
        "expected stderr to mention the TLS/cert failure"
    );

    let _ = std::fs::remove_file(&config_path);
}

/// Small helper: `std::process::Child` has no built-in "wait with timeout",
/// so poll `try_wait` instead of pulling in an extra crate for one test.
trait WaitTimeoutOrKill {
    fn wait_timeout_or_kill(&mut self, timeout: Duration) -> Option<std::process::ExitStatus>;
}

impl WaitTimeoutOrKill for std::process::Child {
    fn wait_timeout_or_kill(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Ok(Some(status)) = self.try_wait() {
                return Some(status);
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.kill();
                let _ = self.wait();
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
