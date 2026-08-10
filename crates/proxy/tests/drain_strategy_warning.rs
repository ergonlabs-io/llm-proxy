//! Defect 2 (found writing user documentation, 2026-08-09): `--drain-strategy
//! gradual` and `immediate` behave identically today (`DrainState::
//! drain_close_probability` has no production call site -- see
//! `docs/envoy-divergences.md`'s "Drain strategy" section). Ground rule #1
//! forbids leaving that silent, so `serve` emits a startup `tracing::warn!`
//! instead of wiring up the full per-response close-probability feature
//! (out of scope for a contained fix -- see the same doc section for why).
//! This is the end-to-end proof the warning actually reaches an operator's
//! log, for either `--drain-strategy` value.
//!
//! Rust note: same shape as `tests/reload.rs`/`tests/stats_e2e.rs` -- a
//! separate compiled crate per `tests/*.rs` file, so helpers are duplicated
//! rather than shared, and `env!("CARGO_BIN_EXE_llm-proxy")` +
//! `Command::new(BIN).spawn()` drive the real binary.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
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

fn wait_for_line(rx: &Receiver<String>, needle: &str, timeout: Duration) -> (bool, Vec<String>) {
    let deadline = Instant::now() + timeout;
    let mut log = Vec::new();
    loop {
        while let Ok(line) = rx.try_recv() {
            log.push(line);
        }
        if log.iter().any(|line| line.contains(needle)) {
            return (true, log);
        }
        if Instant::now() >= deadline {
            return (false, log);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

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

/// Runs `llm-proxy serve` with the given `--drain-strategy` value and returns
/// whether the "not enforced" warning showed up on stderr before `SIGTERM`
/// cleans the process up.
fn drain_strategy_warns(strategy: &str) -> (bool, Vec<String>) {
    let port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-drain-strategy-warning-{strategy}-{}-{}.yaml",
        std::process::id(),
        port
    ));
    std::fs::write(&config_path, one_listener_config(port)).expect("write config");

    let mut child = Command::new(BIN)
        .args([
            "-c",
            config_path.to_str().unwrap(),
            "--concurrency",
            "1",
            "--drain-strategy",
            strategy,
        ])
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn llm-proxy");

    let stderr = child.stderr.take().expect("child stderr not piped");
    let rx = spawn_line_reader(BufReader::new(stderr));

    let result = wait_for_line(
        &rx,
        "--drain-strategy is accepted but not enforced during drain",
        STARTUP_TIMEOUT,
    );

    let pid = child.id().to_string();
    let _ = Command::new("kill").args(["-TERM", &pid]).status();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_file(&config_path);

    result
}

#[test]
fn gradual_emits_the_not_enforced_warning() {
    let (found, log) = drain_strategy_warns("gradual");
    assert!(
        found,
        "expected the --drain-strategy inertness warning on stderr for `gradual`; \
         stderr so far: {log:?}"
    );
}

#[test]
fn immediate_emits_the_not_enforced_warning() {
    let (found, log) = drain_strategy_warns("immediate");
    assert!(
        found,
        "expected the --drain-strategy inertness warning on stderr for `immediate` too -- \
         the whole point is that both values are equally unenforced; stderr so far: {log:?}"
    );
}
