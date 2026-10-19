//! SIGHUP config-reload acceptance tests. They drive `reload` in
//! `crates/proxy/src/main.rs`; the downstream publish and reconcile machinery
//! is covered by `proxy-core`'s own unit tests.
//!
//! A broken reload must never take the process down.
//! `sighup_with_a_broken_config_keeps_serving_and_logs_error` is that test.
//!
//! Rust note: each `tests/*.rs` file is its own crate, so helpers are
//! duplicated, and `env!("CARGO_BIN_EXE_llm-proxy")` drives the real binary
//! because `crates/proxy` has no `[lib]` target to link against.

mod common;

use common::free_port;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

/// How long to wait for the freshly spawned `llm-proxy` to become
/// connectable, and (separately) for a reload's log line to show up -- both
/// liveness backstops, not speed assertions, matching `tests/cli.rs`'s
/// `STARTUP_TIMEOUT`.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(10);

fn wait_for_connectable(addr: (&str, u16), timeout: Duration) -> bool {
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

fn spawn_line_reader(
    mut reader: BufReader<impl std::io::Read + Send + 'static>,
) -> Receiver<String> {
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

/// Strips `ESC '[' ... 'm'` ANSI SGR sequences. The tracing formatter colors
/// output even when stderr is a pipe, and it splits field renders such as
/// `version=2` into escape-wrapped spans, so assertions on field values need
/// this first.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Consume through the terminating 'm' of a `\x1b[...m` sequence;
            // anything else after ESC (none, in practice, from this
            // formatter) is passed through unchanged rather than eaten.
            let mut consumed = false;
            let rest: String = chars.clone().collect();
            if let Some(stripped) = rest.strip_prefix('[') {
                if let Some(end) = stripped.find('m') {
                    for _ in 0..=end + 1 {
                        chars.next();
                    }
                    consumed = true;
                }
            }
            if !consumed {
                out.push(c);
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Drains whatever lines are currently buffered in `rx` into `into`,
/// without blocking.
fn drain_into(rx: &Receiver<String>, into: &mut Vec<String>) {
    while let Ok(line) = rx.try_recv() {
        into.push(line);
    }
}

/// Polls (draining into `log`, so later assertions can still see everything
/// that arrived) until some line in `log`, ANSI-stripped, contains `needle`,
/// or `timeout` elapses.
fn wait_for_log_line(
    rx: &Receiver<String>,
    log: &mut Vec<String>,
    needle: &str,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        drain_into(rx, log);
        if log.iter().any(|line| strip_ansi(line).contains(needle)) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn send_sighup(child: &Child) {
    let pid = child.id().to_string();
    let status = Command::new("kill")
        .args(["-HUP", &pid])
        .status()
        .expect("failed to send SIGHUP");
    assert!(status.success(), "kill -HUP failed");
}

fn terminate_and_wait(child: &mut Child) {
    let pid = child.id().to_string();
    let _ = Command::new("kill").args(["-TERM", &pid]).status();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A single `tcp_proxy` listener naming `backend`, on `port`, as a config
/// file body -- the same fixture shape `tests/cli.rs` uses.
fn one_listener_config(port: u16) -> String {
    format!(
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
    )
}

/// Two `tcp_proxy` listeners naming `backend`, on `port_a` and `port_b` --
/// what `one_listener_config(port_a)` reloads into, to prove a SIGHUP
/// actually changes what the running process is doing (a new listener
/// becomes connectable) rather than merely re-reading the same file.
fn two_listener_config(port_a: u16, port_b: u16) -> String {
    format!(
        r#"
static_resources:
  listeners:
    - name: ingress_tcp
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {port_a} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: ingress_tcp
                cluster: backend
    - name: ingress_tcp_2
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {port_b} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: ingress_tcp_2
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
    )
}

/// A single `tcp_proxy` listener on `port`, routed to a cluster named
/// `cluster_name`, plus an `admin` bind on `admin_port` -- the fixture for
/// the `/config_dump`/`/clusters` reload tests below, where the changing
/// piece across a reload is `cluster_name` itself so the admin surface's
/// response body is byte-different before and after, not merely re-served
/// from the same file.
fn config_with_admin(admin_port: u16, port: u16, cluster_name: &str) -> String {
    format!(
        r#"
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin_port} }}

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
                cluster: {cluster_name}

  clusters:
    - name: {cluster_name}
      type: STATIC
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: {cluster_name}
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: 8081 }}
"#
    )
}

/// Sends a plain `GET <path> HTTP/1.1` with `Connection: close` to `addr` and
/// returns the full response (status line + headers + body) read up to EOF --
/// same technique as `tests/stats_e2e.rs`'s own `get` (each `tests/*.rs` file
/// is its own compiled crate, so this is duplicated rather than shared).
fn get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set_read_timeout");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: admin.local\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read response to EOF");
    String::from_utf8_lossy(&response).to_string()
}

struct Harness {
    child: Child,
    log: Vec<String>,
    rx: Receiver<String>,
    config_path: std::path::PathBuf,
}

impl Harness {
    /// Spawns `llm-proxy -c config_path`, waits for `ready_port` to become
    /// connectable, and returns a harness holding everything a test needs
    /// (the child, the config path to overwrite for a reload, and the
    /// growing stderr log).
    fn spawn(config_path: std::path::PathBuf, ready_port: u16) -> Self {
        let child = Command::new(BIN)
            .args(["-c", config_path.to_str().unwrap(), "--concurrency", "1"])
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn llm-proxy");

        let mut child = child;
        let stderr = child.stderr.take().expect("child stderr not piped");
        let rx = spawn_line_reader(BufReader::new(stderr));
        let mut log = Vec::new();

        let ready = wait_for_connectable(("127.0.0.1", ready_port), STARTUP_TIMEOUT);
        drain_into(&rx, &mut log);
        assert!(
            ready,
            "listener at 127.0.0.1:{ready_port} did not become connectable in time \
             (stderr so far: {log:?})"
        );

        Harness {
            child,
            log,
            rx,
            config_path,
        }
    }

    fn rewrite_config(&self, contents: &str) {
        std::fs::write(&self.config_path, contents).expect("failed to rewrite config");
    }

    fn sighup(&self) {
        send_sighup(&self.child);
    }

    fn wait_for_log(&mut self, needle: &str, timeout: Duration) -> bool {
        wait_for_log_line(&self.rx, &mut self.log, needle, timeout)
    }

    fn finish(mut self) {
        terminate_and_wait(&mut self.child);
        let _ = std::fs::remove_file(&self.config_path);
    }
}

/// A failed assertion must not leave the proxy running: an orphan keeps the
/// test binary's output pipe open and hangs `cargo test`.
impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Requirement (test list item 1): SIGHUP with a valid, CHANGED config takes
/// effect -- proved by a listener the original config never had becoming
/// connectable after the reload, not merely by a log line saying so.
#[test]
fn sighup_with_a_valid_changed_config_adds_a_listener() {
    let port_a = free_port();
    let port_b = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-reload-add-listener-{}-{}.yaml",
        std::process::id(),
        port_a
    ));
    std::fs::write(&config_path, one_listener_config(port_a)).expect("write initial config");

    let mut harness = Harness::spawn(config_path, port_a);

    // Sanity: the second listener's port must NOT be serving yet -- otherwise
    // the assertion below (it becomes connectable after the reload) would be
    // vacuously true.
    assert!(
        TcpStream::connect(("127.0.0.1", port_b)).is_err(),
        "port {port_b} must not be listening before the reload"
    );

    harness.rewrite_config(&two_listener_config(port_a, port_b));
    harness.sighup();

    assert!(
        harness.wait_for_log("SIGHUP: config reload succeeded", RELOAD_TIMEOUT),
        "expected a successful-reload log line; stderr so far: {:?}",
        harness.log
    );

    let new_listener_ready = wait_for_connectable(("127.0.0.1", port_b), RELOAD_TIMEOUT);
    assert!(
        new_listener_ready,
        "the listener added by the reload never became connectable; stderr so far: {:?}",
        harness.log
    );
    assert!(
        TcpStream::connect(("127.0.0.1", port_a)).is_ok(),
        "the original listener must still be serving after the reload"
    );

    harness.finish();
}

/// Requirement (test list item 2, and the load-bearing one): SIGHUP with a
/// BROKEN config must never take the process down. The old snapshot keeps
/// serving, and the failure is logged.
#[test]
fn sighup_with_a_broken_config_keeps_serving_and_logs_error() {
    let port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-reload-broken-{}-{}.yaml",
        std::process::id(),
        port
    ));
    std::fs::write(&config_path, one_listener_config(port)).expect("write initial config");

    let mut harness = Harness::spawn(config_path, port);

    harness.rewrite_config("not: valid: yaml: [");
    harness.sighup();

    assert!(
        harness.wait_for_log(
            "SIGHUP: config reload failed; continuing to serve the previous snapshot",
            RELOAD_TIMEOUT
        ),
        "expected an error-level log line naming the reload failure; stderr so far: {:?}",
        harness.log
    );

    // The proxy must still be running and the OLD config must still serve.
    // Both are checked over a settle window, not once: a process mid-exit
    // still reads as alive to one `try_wait`, and its socket can accept
    // briefly after it has decided to die.
    let settle_deadline = Instant::now() + Duration::from_millis(750);
    loop {
        assert!(
            matches!(harness.child.try_wait(), Ok(None)),
            "the process must still be running after a broken reload"
        );
        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_ok(),
            "the original listener must still be serving after a broken reload"
        );
        if Instant::now() >= settle_deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    harness.finish();
}

/// Requirement (test list item 3): SIGHUP with an UNCHANGED config is
/// harmless -- the reload still runs (and still logs success, and still
/// advances the version -- see the next test for that), but nothing about
/// the running proxy breaks.
#[test]
fn sighup_with_an_unchanged_config_is_harmless() {
    let port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-reload-unchanged-{}-{}.yaml",
        std::process::id(),
        port
    ));
    let config_yaml = one_listener_config(port);
    std::fs::write(&config_path, &config_yaml).expect("write initial config");

    let mut harness = Harness::spawn(config_path, port);

    // Rewritten with the SAME content -- a real "operator re-saved the file
    // without changing anything" scenario, not just "no SIGHUP at all".
    harness.rewrite_config(&config_yaml);
    harness.sighup();

    assert!(
        harness.wait_for_log("SIGHUP: config reload succeeded", RELOAD_TIMEOUT),
        "an unchanged config should still reload successfully; stderr so far: {:?}",
        harness.log
    );
    assert!(
        matches!(harness.child.try_wait(), Ok(None)),
        "the process must still be running after a no-op reload"
    );
    assert!(
        TcpStream::connect(("127.0.0.1", port)).is_ok(),
        "the listener must still be serving after a no-op reload"
    );

    harness.finish();
}

/// OTLP trace and metric export start once at boot, so a reload that adds
/// either block is refused by name rather than ignored (AGENTS.md invariant
/// 1). The closing reload of the original file proves the refusals left the
/// process reloadable.
#[test]
fn sighup_that_changes_otlp_export_is_refused_by_name() {
    let port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-reload-otlp-{}-{}.yaml",
        std::process::id(),
        port
    ));
    let original = one_listener_config(port);
    std::fs::write(&config_path, &original).expect("write initial config");
    let mut harness = Harness::spawn(config_path, port);

    let collector = format!("http://127.0.0.1:{}", free_port());
    let tracing = format!(
        "node:\n  metadata:\n    io.llmproxy.tracing:\n      otlp_endpoint: \"{collector}\"\n\
         \x20     service_name: \"reload\"\n{original}"
    );
    let metrics = format!(
        "node:\n  metadata:\n    io.llmproxy.metrics:\n      otlp_endpoint: \"{collector}\"\n\
         \x20     service_name: \"reload\"\n{original}"
    );
    for (config, field) in [
        (tracing, "`observability.tracing`) cannot change on reload"),
        (metrics, "`observability.metrics`) cannot change on reload"),
    ] {
        harness.rewrite_config(&config);
        harness.sighup();
        assert!(
            harness.wait_for_log(field, RELOAD_TIMEOUT),
            "expected the refusal to name {field:?}; stderr so far: {:?}",
            harness.log
        );
    }
    assert!(
        !harness
            .log
            .iter()
            .any(|line| strip_ansi(line).contains("SIGHUP: config reload succeeded")),
        "a refused reload must not also report success; stderr so far: {:?}",
        harness.log
    );

    harness.rewrite_config(&original);
    harness.sighup();
    assert!(
        harness.wait_for_log("SIGHUP: config reload succeeded", RELOAD_TIMEOUT),
        "the original config must still reload; stderr so far: {:?}",
        harness.log
    );
    harness.finish();
}

/// Requirement (test list item 4): the snapshot version strictly advances
/// across reloads, so `config_ping` observers (and `/config_dump`) can tell
/// two snapshots apart even when nothing else about them differs.
#[test]
fn snapshot_version_advances_across_reloads() {
    let port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-reload-version-{}-{}.yaml",
        std::process::id(),
        port
    ));
    let config_yaml = one_listener_config(port);
    std::fs::write(&config_path, &config_yaml).expect("write initial config");

    let mut harness = Harness::spawn(config_path, port);

    harness.rewrite_config(&config_yaml);
    harness.sighup();
    assert!(
        harness.wait_for_log("version=2", RELOAD_TIMEOUT),
        "expected the first reload to publish version 2; stderr so far: {:?}",
        harness.log
    );

    harness.rewrite_config(&config_yaml);
    harness.sighup();
    assert!(
        harness.wait_for_log("version=3", RELOAD_TIMEOUT),
        "expected the second reload to publish version 3, not repeat version 2; \
         stderr so far: {:?}",
        harness.log
    );

    harness.finish();
}

/// Regression guard: a clean SIGTERM exit after a reload must still run the
/// graceful shutdown path. A loop that mishandles the `Shutdown` arm would
/// break this.
#[test]
fn sigterm_after_a_reload_still_drains_and_exits_cleanly() {
    let port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-reload-then-sigterm-{}-{}.yaml",
        std::process::id(),
        port
    ));
    let config_yaml = one_listener_config(port);
    std::fs::write(&config_path, &config_yaml).expect("write initial config");

    let mut harness = Harness::spawn(config_path, port);

    harness.rewrite_config(&config_yaml);
    harness.sighup();
    assert!(
        harness.wait_for_log("SIGHUP: config reload succeeded", RELOAD_TIMEOUT),
        "stderr so far: {:?}",
        harness.log
    );

    let pid = harness.child.id().to_string();
    let status = Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .expect("failed to send SIGTERM");
    assert!(status.success(), "kill -TERM failed");

    let deadline = Instant::now() + Duration::from_secs(5);
    let exit = loop {
        if let Ok(Some(status)) = harness.child.try_wait() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let exit = exit.expect("llm-proxy did not exit after SIGTERM within timeout");
    assert!(
        exit.success(),
        "expected exit 0 after SIGTERM following a reload, got {exit:?}"
    );

    let _ = std::fs::remove_file(&harness.config_path);
}

/// `/config_dump` and `/clusters` must follow a reload. They read through the
/// same `SnapshotHandles` that `ConfigPublisher::publish` updates
/// (`crates/proxy-core/src/runtime.rs`), not a boot-time copy. This test
/// SIGHUPs a config that renames the cluster and checks both endpoints show
/// the new name. A unit test on the handle would miss an admin handler that
/// stopped reading through it.
#[test]
fn sighup_reload_is_reflected_in_config_dump_and_clusters() {
    let port = free_port();
    let admin_port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-reload-admin-dump-{}-{}.yaml",
        std::process::id(),
        port
    ));
    std::fs::write(
        &config_path,
        config_with_admin(admin_port, port, "backend_v1"),
    )
    .expect("write initial config");

    let mut harness = Harness::spawn(config_path, port);
    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    assert!(
        wait_for_connectable(("127.0.0.1", admin_port), STARTUP_TIMEOUT),
        "admin server at {admin_addr} did not become connectable in time; \
         stderr so far: {:?}",
        harness.log
    );

    let dump_before = get(admin_addr, "/config_dump");
    assert!(
        dump_before.contains("backend_v1") && !dump_before.contains("backend_v2"),
        "expected /config_dump to show the boot config's cluster before any reload, got:\n\
         {dump_before}"
    );
    let clusters_before = get(admin_addr, "/clusters");
    assert!(
        clusters_before.contains("backend_v1") && !clusters_before.contains("backend_v2"),
        "expected /clusters to show the boot config's cluster before any reload, got:\n\
         {clusters_before}"
    );

    harness.rewrite_config(&config_with_admin(admin_port, port, "backend_v2"));
    harness.sighup();
    assert!(
        harness.wait_for_log("SIGHUP: config reload succeeded", RELOAD_TIMEOUT),
        "expected a successful-reload log line; stderr so far: {:?}",
        harness.log
    );

    let dump_after = get(admin_addr, "/config_dump");
    assert!(
        dump_after.contains("backend_v2") && !dump_after.contains("backend_v1"),
        "/config_dump must reflect the SIGHUP reload (the admin server's own handle must be \
         republished into, not just the workers'), got:\n{dump_after}"
    );
    let clusters_after = get(admin_addr, "/clusters");
    assert!(
        clusters_after.contains("backend_v2") && !clusters_after.contains("backend_v1"),
        "/clusters must reflect the SIGHUP reload, got:\n{clusters_after}"
    );

    harness.finish();
}

/// Churn drill over the real binary: every reload renames the cluster, and
/// `/stats` must follow the live config -- the previous names' series are gone
/// and the line count stays flat instead of growing by one cluster's series
/// per reload. Counts series lines, not bytes.
#[test]
fn stats_series_follow_the_live_cluster_across_renaming_reloads() {
    let port = free_port();
    let admin_port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-reload-stats-churn-{}-{}.yaml",
        std::process::id(),
        port
    ));
    std::fs::write(
        &config_path,
        config_with_admin(admin_port, port, "churn_v0"),
    )
    .expect("write initial config");

    let mut harness = Harness::spawn(config_path, port);
    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    assert!(
        wait_for_connectable(("127.0.0.1", admin_port), STARTUP_TIMEOUT),
        "admin server did not become connectable; stderr so far: {:?}",
        harness.log
    );

    let series_lines = |body: &str| body.lines().filter(|l| l.contains("churn_v")).count();
    let first = get(admin_addr, "/stats");
    let baseline = series_lines(&first);
    assert!(
        baseline > 0 && first.contains("churn_v0"),
        "the boot cluster must have series (else this test proves nothing):\n{first}"
    );

    for cycle in 1..=5 {
        let name = format!("churn_v{cycle}");
        harness.rewrite_config(&config_with_admin(admin_port, port, &name));
        harness.sighup();
        let needle = format!("version={}", cycle + 1);
        assert!(
            harness.wait_for_log(&needle, RELOAD_TIMEOUT),
            "cycle {cycle}: expected a successful reload; stderr so far: {:?}",
            harness.log
        );
        let body = get(admin_addr, "/stats");
        assert!(
            body.contains(&name),
            "cycle {cycle}: live cluster missing:\n{body}"
        );
        for old in 0..cycle {
            assert!(
                !body.contains(&format!("churn_v{old}."))
                    && !body.contains(&format!("churn_v{old} ")),
                "cycle {cycle}: series of removed cluster churn_v{old} still exported:\n{body}"
            );
        }
        assert_eq!(
            series_lines(&body),
            baseline,
            "cycle {cycle}: series count must follow the live set:\n{body}"
        );
    }

    harness.finish();
}

/// Sanity check on the ANSI stripper itself, since two tests above depend on
/// it to find `version=N` inside colorized log output -- an instrument that
/// lies about matching would make those tests pass for the wrong reason
/// (see AGENTS.md "Build And Test"'s note on validating instruments before reasoning from
/// them).
#[test]
fn strip_ansi_removes_sgr_codes_around_a_field() {
    let colorized = "\u{1b}[3mversion\u{1b}[0m\u{1b}[2m=\u{1b}[0m2";
    assert_eq!(strip_ansi(colorized), "version=2");
}
