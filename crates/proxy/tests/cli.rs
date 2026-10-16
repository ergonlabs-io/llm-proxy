//! Integration tests for the `llm-proxy` binary's CLI surface:
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

/// Review M9: `--mode translate` prints the lowered bootstrap, which holds
/// every interpolated secret. By default none reaches stdout; the operator
/// is told how to get them, and `--reveal-secrets` prints them.
#[test]
fn translate_redacts_interpolated_secrets_unless_asked_to_reveal_them() {
    let provider_key = "sk-translate-test-provider-key-0001";
    let header_key = "sk-translate-test-header-key-0002";
    let hmac_secret = "translate-test-hmac-secret-0003";
    let redis_url = "redis://:translate-test-redis-password@127.0.0.1:6379/0";
    let path = std::env::temp_dir().join(format!(
        "llm-proxy-translate-secrets-{}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &path,
        format!(
            "version: 0\n\
             providers:\n  openai: {{ api_key: ${{TRANSLATE_TEST_OPENAI_KEY}} }}\n  \
             other:\n    type: openai-compatible\n    base_url: http://127.0.0.1:9\n    \
             extra_headers: {{ x-api-key: {header_key} }}\n\
             routes:\n  - {{ model: \"gpt-*\", provider: openai }}\n  - {{ model: \"*\", provider: other }}\n\
             auth:\n  hmac_secret: {hmac_secret}\n  store: {{ shared: {{ url: \"{redis_url}\" }} }}\n"
        ),
    )
    .unwrap();
    let translate = |reveal: bool| {
        let mut command = Command::new(BIN);
        command
            .args(["--config", path.to_str().unwrap(), "--mode", "translate"])
            .env("TRANSLATE_TEST_OPENAI_KEY", provider_key);
        if reveal {
            command.arg("--reveal-secrets");
        }
        let output = command.output().expect("failed to run llm-proxy");
        assert!(output.status.success(), "{output:?}");
        (
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap(),
        )
    };
    let secrets = [provider_key, header_key, hmac_secret, redis_url];

    let (stdout, stderr) = translate(false);
    for secret in secrets {
        assert!(
            !stdout.contains(secret),
            "{secret} reached stdout:\n{stdout}"
        );
        assert!(
            !stderr.contains(secret),
            "{secret} reached stderr:\n{stderr}"
        );
    }
    assert!(stdout.contains("[REDACTED]"), "{stdout}");
    assert!(stderr.contains("--reveal-secrets"), "{stderr}");

    let (stdout, _) = translate(true);
    let _ = std::fs::remove_file(&path);
    for secret in secrets {
        assert!(
            stdout.contains(secret),
            "--reveal-secrets must print {secret}"
        );
    }
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

/// Reads child output on a background thread. Callers retain the receiver for
/// the child's lifetime so dropping the pipe cannot cause the child to hit EPIPE.
/// Output is diagnostic only; readiness uses a TCP connection.
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

/// How long to wait for a freshly spawned `llm-proxy` to bind its listener or
/// log "started".
///
/// Deliberately generous. A debug binary under `make ci` shares the machine
/// with every other test binary, and a 5s budget flaked. This is a liveness
/// backstop, not a speed assertion.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Polls until the OS accepts a TCP connection; log lines can precede actual
/// listener readiness.
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

/// Drains whatever lines are already sitting in `rx` without blocking, for
/// use in failure messages (e.g. "here's what the child printed before we
/// gave up").
fn drain_available_lines(rx: &mpsc::Receiver<String>) -> Vec<String> {
    let mut lines = Vec::new();
    while let Ok(line) = rx.try_recv() {
        lines.push(line);
    }
    lines
}

#[test]
fn sigterm_drains_then_exits_cleanly() {
    // Reuse the example's SHAPE, not the example file, with an ephemeral port
    // -- the same swap `serve_mode_accepts_connections_on_its_listener` makes
    // below, and for a sharper reason here.
    //
    // This test used `examples/tcp-proxy.yaml` directly, which binds a fixed
    // `0.0.0.0:10000` and a fixed admin `127.0.0.1:9901`. Anything else
    // holding either one -- another `llm-proxy`, a leftover child from an
    // earlier run, an unrelated service -- broke this test, and **it broke it
    // in the worst available way**: measured 2026-08-08 by holding :10000
    // from another process, the readiness fence below PASSED (it connected to
    // the squatter) and the test then failed much later, at the exit-status
    // assertion, pointing at the drain path rather than at the port. A fence
    // that reports ready when a *different* process is listening is not a
    // fence; it is a false negative generator aimed at whatever code runs
    // next.
    //
    // `free_port()` removes the collision, which also makes the fence mean
    // what its comment below claims. `.config/nextest.toml` still serializes
    // this binary; that serialization was added for this fixed port and could
    // now be relaxed, but that is a separate change with its own risk.
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
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: 8082 }}
"#
    );
    let config = std::env::temp_dir().join(format!(
        "llm-proxy-sigterm-drain-test-{}-{}.yaml",
        std::process::id(),
        port
    ));
    std::fs::write(&config, config_yaml).expect("failed to write temp config");

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

    // Deliberately *not* `wait_for_line(&rx, "llm-proxy started", ..)` here:
    // `run_serve` (crates/proxy/src/main.rs) logs that line before it has
    // confirmed every worker's initial listener bind, and -- more importantly
    // -- before `wait_for_shutdown_signal` makes its (synchronous)
    // `tokio::signal::unix::signal(SIGTERM)` call that actually installs our
    // handler. A SIGTERM delivered in that window hits the default
    // disposition (process-terminate-by-signal) instead of the drain path,
    // which is exactly the kind of failure this test saw once on 2026-07-29:
    // a non-`success()` exit, not a timeout. Polling for the example config's
    // listener (127.0.0.1:10000, examples/tcp-proxy.yaml) to actually accept
    // a connection instead ties readiness to `initial_bind` having completed
    // in every worker, which happens-before `run_serve`'s `wait_for_shutdown_signal`
    // call (see `wait_for_initial_binds` gating it) -- a real readiness fence
    // instead of a log line that can precede it.
    let ready = wait_for_connectable(("127.0.0.1", port), STARTUP_TIMEOUT);
    assert!(
        ready,
        "listener at 127.0.0.1:{port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&rx)
    );

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
    let _ = std::fs::remove_file(&config);
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
    // Readiness is a real TCP connect, not the "listener bound" log line, for
    // the same reason `sigterm_drains_then_exits_cleanly` polls the port: a
    // log line is emitted *around* the bind, not *by* it, so gating on the
    // line can hand back control before the socket is actually accepting --
    // and this test then does the one thing that requires it to be. Observed
    // flaking under parallel test load on 2026-07-31.
    let ready = wait_for_connectable(("127.0.0.1", port), STARTUP_TIMEOUT);
    assert!(
        ready,
        "listener at 127.0.0.1:{port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&rx)
    );

    // A second, fresh connection: `wait_for_connectable` proves the port
    // accepts at least once, this proves the listener keeps accepting and
    // that an accepted connection is actually writable rather than being
    // immediately reset.
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
    // A `transport_socket` whose cert PEM won't parse must
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

/// A dialect config with `auth.store.shared`, listening on an ephemeral port.
/// Nothing here dials the Redis: the refusal comes first.
fn shared_store_dialect_config(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "llm-proxy-shared-node-id-{tag}-{}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &path,
        "version: 0\n\
         listen: 127.0.0.1:0\n\
         providers:\n  openai:\n    type: openai\n    base_url: http://127.0.0.1:9\n    api_key: sk-x\n\
         routes:\n  - { model: \"*\", provider: openai }\n\
         auth:\n  hmac_secret: shared-node-id-secret\n  \
         store: { shared: { url: \"redis://127.0.0.1:1/0\" } }\n",
    )
    .unwrap();
    path
}

/// ADR-0006 addendum "Admission stays local" §5, dialect: `auth.store.shared`
/// without `--service-node` fails validate (and so serve) at the dialect
/// path, naming the flag; the same config with the flag validates.
#[test]
fn dialect_shared_store_without_service_node_is_refused() {
    let path = shared_store_dialect_config("dialect");
    let validate = |service_node: Option<&str>| {
        let mut command = Command::new(BIN);
        command.args(["--config", path.to_str().unwrap(), "--mode", "validate"]);
        if let Some(node) = service_node {
            command.args(["--service-node", node]);
        }
        command.output().expect("failed to run llm-proxy")
    };
    let refused = validate(None);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(stderr.contains("`auth.store.shared`"), "{stderr}");
    assert!(stderr.contains("--service-node"), "{stderr}");
    let accepted = validate(Some("replica-a"));
    assert!(accepted.status.success(), "{accepted:?}");
    let _ = std::fs::remove_file(&path);
}

/// The same refusal in Envoy mode, where it comes from the auth filter's
/// factory as the workers build the chain: serve exits non-zero at startup
/// with the full dotted path, before any listener serves.
#[test]
fn envoy_shared_store_without_a_node_id_fails_serve_at_startup() {
    let dialect = shared_store_dialect_config("envoy-src");
    let translated = Command::new(BIN)
        .args([
            "--config",
            dialect.to_str().unwrap(),
            "--mode",
            "translate",
            "--reveal-secrets",
        ])
        .output()
        .expect("failed to run llm-proxy");
    assert!(translated.status.success(), "{translated:?}");
    let bootstrap = std::env::temp_dir().join(format!(
        "llm-proxy-shared-node-id-envoy-{}.yaml",
        std::process::id()
    ));
    std::fs::write(&bootstrap, &translated.stdout).unwrap();

    let mut child = Command::new(BIN)
        .args(["-c", bootstrap.to_str().unwrap(), "--concurrency", "1"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn llm-proxy");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("serve did not refuse the config within 30s");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).unwrap();
    assert!(!status.success(), "{status:?}");
    assert!(stderr.contains("`typed_config.store.shared`"), "{stderr}");
    assert!(stderr.contains("--service-node"), "{stderr}");
    let _ = std::fs::remove_file(&dialect);
    let _ = std::fs::remove_file(&bootstrap);
}
