//! Drain and readiness acceptance tests against the real binary
//! (`internal-docs/architecture.md` section 8, "Drain"): SIGTERM and
//! `POST /drain_listeners` flip `/ready` to 503 DRAINING and stop accepting at
//! once; a stream in flight finishes untouched; whatever is still open at
//! `--drain-time-s` is cut; a second signal exits promptly; `/ready` is not
//! LIVE before a listener is bound; a second signal also exits promptly while
//! telemetry is being flushed.
//!
//! Every wait is a bounded poll on an observable condition (a response, an
//! exit status, a refused connect). No test asserts how long anything took.
//!
//! Rust note: same shape as `tests/reload.rs` -- one compiled crate per
//! `tests/*.rs` file, so helpers are duplicated rather than shared, and
//! `env!("CARGO_BIN_EXE_llm-proxy")` drives the real binary.

#![cfg(unix)]

mod common;

use common::free_port;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

/// Liveness backstop for every wait, not an expectation of speed.
const WAIT: Duration = Duration::from_secs(30);
const ADMIN_TOKEN: &str = "drain-e2e-token";

fn poll_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Kills and reaps the child on drop, so a failed assertion cannot leak a
/// listening process (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    config_path: std::path::PathBuf,
    data: SocketAddr,
    admin: SocketAddr,
    /// Held for the child's whole life so its stderr pipe never closes under it.
    stderr: std::sync::mpsc::Receiver<String>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config_path);
    }
}

fn spawn_line_reader(
    reader: impl std::io::Read + Send + 'static,
) -> std::sync::mpsc::Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(reader);
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

impl Proxy {
    fn spawn(config: &str, data: u16, admin: u16, drain_time_s: u32, with_token: bool) -> Proxy {
        Self::spawn_with(config, data, admin, drain_time_s, with_token, &[])
    }

    fn spawn_with(
        config: &str,
        data: u16,
        admin: u16,
        drain_time_s: u32,
        with_token: bool,
        extra_args: &[&str],
    ) -> Proxy {
        let config_path = std::env::temp_dir().join(format!(
            "llm-proxy-drain-e2e-{}-{admin}.yaml",
            std::process::id()
        ));
        std::fs::write(&config_path, config).expect("write config");
        let mut command = Command::new(BIN);
        command
            .args([
                "-c",
                config_path.to_str().unwrap(),
                "--concurrency",
                "1",
                "--drain-time-s",
                &drain_time_s.to_string(),
            ])
            .args(extra_args)
            .stderr(Stdio::piped());
        if with_token {
            command.env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN);
        } else {
            command.env_remove("LLMPROXY_ADMIN_TOKEN");
        }
        let mut child = command.spawn().expect("spawn llm-proxy");
        let stderr = spawn_line_reader(child.stderr.take().expect("stderr piped"));
        Proxy {
            child,
            config_path,
            data: SocketAddr::from(([127, 0, 0, 1], data)),
            admin: SocketAddr::from(([127, 0, 0, 1], admin)),
            stderr,
        }
    }

    /// Waits until `/ready` answers 200: the admin server is up, a listener is
    /// bound, and nothing is warming.
    fn wait_ready(&mut self) {
        let admin = self.admin;
        assert!(
            poll_until(WAIT, || http(admin, "GET", "/ready", None)
                .is_some_and(|r| r.starts_with("HTTP/1.1 200"))),
            "/ready never became LIVE"
        );
    }

    fn signal_term(&self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -TERM failed");
    }

    fn wait_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits for a stderr line containing `needle` (lines before it are
    /// consumed). A log line is the only observable edge between the drain and
    /// the telemetry flush that follows it.
    fn wait_log(&self, needle: &str) {
        let deadline = Instant::now() + WAIT;
        let mut seen = String::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.stderr.recv_timeout(left) {
                Ok(line) if line.contains(needle) => return,
                Ok(line) => seen.push_str(&line),
                Err(_) => panic!("never saw log line containing {needle:?}; stderr: {seen}"),
            }
        }
    }

    fn wait_draining(&self) {
        let admin = self.admin;
        assert!(
            poll_until(WAIT, || http(admin, "GET", "/ready", None).is_some_and(
                |r| r.starts_with("HTTP/1.1 503") && r.ends_with("DRAINING")
            )),
            "/ready never reported DRAINING"
        );
    }

    /// New connections are refused once the accept loops are gone. The accept
    /// loops close asynchronously after `/ready` flips, so poll (bounded).
    fn wait_data_refused(&self) {
        let data = self.data;
        assert!(
            poll_until(WAIT, || matches!(
                TcpStream::connect(data),
                Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionRefused
            )),
            "the data listener kept accepting during the drain"
        );
    }
}

/// One-shot request with `Connection: close`; `None` when the connection or
/// read fails. Returns the whole response.
fn http(addr: SocketAddr, method: &str, path: &str, bearer: Option<&str>) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let auth = bearer
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let content_length = if method == "POST" {
        "Content-Length: 0\r\n"
    } else {
        ""
    };
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: admin.local\r\n{auth}{content_length}Connection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    Some(String::from_utf8_lossy(&response).to_string())
}

// ------------------------------------------------------------- SSE upstream --

struct UpstreamState {
    /// Streaming requests that reached the upstream.
    streams: AtomicUsize,
    /// Extra `data: more` events the test has released.
    released: AtomicUsize,
    /// Send `[DONE]` and end the stream.
    finish: AtomicBool,
    stop: AtomicBool,
}

/// Upstream whose SSE stream the test steps by hand. `/idle` answers at once
/// with a short `Content-Length` body (used to park a keep-alive connection).
struct Upstream {
    addr: SocketAddr,
    state: Arc<UpstreamState>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::Relaxed);
    }
}

fn chunk(payload: &str) -> Vec<u8> {
    format!("{:x}\r\n{payload}\r\n", payload.len()).into_bytes()
}

impl Upstream {
    fn spawn() -> Upstream {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let state = Arc::new(UpstreamState {
            streams: AtomicUsize::new(0),
            released: AtomicUsize::new(0),
            finish: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        });
        let accept_state = state.clone();
        std::thread::spawn(move || {
            while !accept_state.stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let state = accept_state.clone();
                        std::thread::spawn(move || serve_upstream(stream, state));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Upstream { addr, state }
    }
}

fn serve_upstream(mut stream: TcpStream, state: Arc<UpstreamState>) {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut head = Vec::new();
    let mut buf = [0u8; 2048];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    if head.starts_with(b"GET /idle ") {
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        return;
    }
    state.streams.fetch_add(1, Ordering::SeqCst);
    let mut out =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_vec();
    out.extend(chunk("data: one\n\n"));
    if stream.write_all(&out).is_err() {
        return;
    }
    while !state.stop.load(Ordering::Relaxed) {
        if state.finish.load(Ordering::SeqCst) {
            let mut end = chunk("data: [DONE]\n\n");
            end.extend_from_slice(b"0\r\n\r\n");
            let _ = stream.write_all(&end);
            return;
        }
        let released = state.released.load(Ordering::SeqCst);
        if released > 0
            && state
                .released
                .compare_exchange(released, released - 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            && stream.write_all(&chunk("data: more\n\n")).is_err()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn bootstrap(data: u16, admin: u16, upstream: u16) -> String {
    format!(
        r#"
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin} }}
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {data} }}
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
                          route: {{ cluster: backend, timeout: 0s }}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: backend
      type: STATIC
      connect_timeout: 2s
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

/// A running proxy in front of a stepped upstream, with one SSE stream open
/// and its first event already received.
struct Fixture {
    proxy: Proxy,
    upstream: Upstream,
    stream: TcpStream,
    seen: String,
}

impl Fixture {
    fn start(drain_time_s: u32, with_token: bool) -> Fixture {
        let upstream = Upstream::spawn();
        let (data, admin) = (free_port(), free_port());
        let mut proxy = Proxy::spawn(
            &bootstrap(data, admin, upstream.addr.port()),
            data,
            admin,
            drain_time_s,
            with_token,
        );
        proxy.wait_ready();
        let mut stream = TcpStream::connect(proxy.data).expect("connect to data listener");
        stream
            .write_all(b"GET /v1/stream HTTP/1.1\r\nHost: t\r\n\r\n")
            .unwrap();
        let mut fixture = Fixture {
            proxy,
            upstream,
            stream,
            seen: String::new(),
        };
        fixture.read_until("data: one");
        fixture
    }

    /// Reads from the stream until `needle` has been seen (bounded).
    fn read_until(&mut self, needle: &str) {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let deadline = Instant::now() + WAIT;
        let mut buf = [0u8; 4096];
        while !self.seen.contains(needle) {
            assert!(
                Instant::now() < deadline,
                "never saw {needle:?}; got {:?}",
                self.seen
            );
            match self.stream.read(&mut buf) {
                Ok(0) => panic!("stream ended before {needle:?}; got {:?}", self.seen),
                Ok(n) => self.seen.push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => panic!("read failed before {needle:?}: {e}; got {:?}", self.seen),
            }
        }
    }

    /// Reads until EOF or a connection error; returns what arrived.
    fn read_to_end_lossy(&mut self) -> String {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let deadline = Instant::now() + WAIT;
        let mut buf = [0u8; 4096];
        loop {
            assert!(Instant::now() < deadline, "stream never ended");
            match self.stream.read(&mut buf) {
                Ok(0) => return std::mem::take(&mut self.seen),
                Ok(n) => self.seen.push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                // A reset is also a cut connection.
                Err(_) => return std::mem::take(&mut self.seen),
            }
        }
    }
}

// ------------------------------------------------------------------- tests --

/// SIGTERM with a long drain window: `/ready` flips at once, new connections
/// are refused, the stream in flight finishes intact, and the process exits 0
/// as soon as the last connection is gone, with an idle keep-alive connection
/// also open (it must not hold the drain for the 600 s window).
#[test]
fn sigterm_drains_in_flight_stream_to_completion_and_exits_early() {
    let mut f = Fixture::start(600, false);

    // Park an idle keep-alive connection: a finished request, socket kept open.
    let mut idle = TcpStream::connect(f.proxy.data).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    idle.write_all(b"GET /idle HTTP/1.1\r\nHost: t\r\n\r\n")
        .unwrap();
    let mut first = Vec::new();
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&first).ends_with("ok") {
        let n = idle.read(&mut buf).unwrap();
        assert_ne!(n, 0, "closed before the idle request's response");
        first.extend_from_slice(&buf[..n]);
    }

    f.proxy.signal_term();
    f.proxy.wait_draining();
    f.proxy.wait_data_refused();
    assert!(
        f.proxy.child.try_wait().unwrap().is_none(),
        "the stream is still open, so the process must still be running"
    );

    // The idle connection is closed by the server at drain start.
    let mut rest = Vec::new();
    idle.read_to_end(&mut rest)
        .expect("server closes the idle keep-alive connection");

    // The stream in flight is untouched and finishes intact.
    f.upstream.state.released.fetch_add(1, Ordering::SeqCst);
    f.read_until("data: more");
    f.upstream.state.finish.store(true, Ordering::SeqCst);
    let body = f.read_to_end_lossy();
    assert!(body.contains("data: [DONE]"), "stream was cut: {body:?}");
    assert!(
        body.ends_with("0\r\n\r\n"),
        "no chunked terminator: {body:?}"
    );

    let status = f.proxy.wait_exit(WAIT).expect(
        "the process must exit once the last connection is gone, not at the 600 s deadline",
    );
    assert!(status.success(), "expected exit 0, got {status:?}");
}

/// A stream that never finishes keeps receiving events after SIGTERM and is
/// cut only when the drain window ends; the process then exits 0.
#[test]
fn a_stream_still_open_at_the_deadline_is_cut_then_the_process_exits_zero() {
    let mut f = Fixture::start(5, false);

    f.proxy.signal_term();
    f.proxy.wait_draining();
    f.upstream.state.released.fetch_add(1, Ordering::SeqCst);
    f.read_until("data: more");

    let status = f
        .proxy
        .wait_exit(WAIT)
        .expect("the process must exit at the drain deadline");
    assert!(status.success(), "expected exit 0, got {status:?}");

    let body = f.read_to_end_lossy();
    assert!(
        !body.contains("[DONE]") && !body.ends_with("0\r\n\r\n"),
        "the stream must be cut, not completed: {body:?}"
    );
}

/// A second SIGTERM while draining exits promptly with a failure status,
/// cutting the stream that a 600 s window would otherwise protect.
#[test]
fn a_second_sigterm_cuts_in_flight_streams_and_exits_nonzero() {
    let mut f = Fixture::start(600, false);

    f.proxy.signal_term();
    f.proxy.wait_draining();
    assert!(f.proxy.child.try_wait().unwrap().is_none());
    f.proxy.signal_term();

    let status = f
        .proxy
        .wait_exit(WAIT)
        .expect("a second signal must end the drain without waiting for the deadline");
    assert_eq!(status.code(), Some(1), "expected exit 1, got {status:?}");
    let body = f.read_to_end_lossy();
    assert!(!body.contains("[DONE]"), "{body:?}");
}

/// `POST /drain_listeners` starts the same drain as SIGTERM but the process
/// keeps running until a signal arrives.
#[test]
fn admin_drain_listeners_drains_without_exiting_until_sigterm() {
    let upstream = Upstream::spawn();
    let (data, admin) = (free_port(), free_port());
    let mut proxy = Proxy::spawn(
        &bootstrap(data, admin, upstream.addr.port()),
        data,
        admin,
        600,
        true,
    );
    proxy.wait_ready();

    let unauthorised = http(proxy.admin, "POST", "/drain_listeners", None).unwrap();
    assert!(
        unauthorised.starts_with("HTTP/1.1 401") || unauthorised.starts_with("HTTP/1.1 403"),
        "the drain endpoint must require the token: {unauthorised}"
    );
    assert!(http(proxy.admin, "GET", "/ready", None)
        .unwrap()
        .starts_with("HTTP/1.1 200"));

    let drained = http(proxy.admin, "POST", "/drain_listeners", Some(ADMIN_TOKEN)).unwrap();
    assert!(drained.starts_with("HTTP/1.1 200"), "{drained}");
    proxy.wait_draining();
    proxy.wait_data_refused();

    // Nothing is in flight, so the drain is already complete; the process must
    // still stay up (bounded observation: it can only cause a false pass).
    assert!(
        proxy.wait_exit(Duration::from_secs(1)).is_none(),
        "an admin drain must not exit the process"
    );
    assert!(http(proxy.admin, "GET", "/ready", None)
        .unwrap()
        .ends_with("DRAINING"));

    proxy.signal_term();
    let status = proxy
        .wait_exit(WAIT)
        .expect("SIGTERM after an admin drain must exit");
    assert!(status.success(), "expected exit 0, got {status:?}");
}

/// M6: a proxy with no listener is never LIVE, however long it runs.
#[test]
fn a_proxy_with_no_listener_never_reports_ready() {
    let admin = free_port();
    let config = format!(
        r#"
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin} }}
static_resources:
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
                    socket_address: {{ address: 127.0.0.1, port_value: 9 }}
"#
    );
    let mut proxy = Proxy::spawn(&config, 0, admin, 1, false);
    let admin_addr = proxy.admin;
    assert!(
        poll_until(WAIT, || http(admin_addr, "GET", "/ready", None).is_some()),
        "admin never came up"
    );
    // Bounded observation across many polls: any 200 is the failure.
    for _ in 0..25 {
        let response = http(admin_addr, "GET", "/ready", None).expect("admin answers");
        assert!(
            response.starts_with("HTTP/1.1 503") && response.ends_with("INITIALIZING"),
            "a proxy that binds nothing must stay INITIALIZING, got: {response}"
        );
        assert!(proxy.child.try_wait().unwrap().is_none(), "proxy exited");
        std::thread::sleep(Duration::from_millis(40));
    }
}

/// A second SIGTERM must also end the post-drain telemetry flush. The metric
/// exporter points at a collector that accepts and never answers, with a 30 s
/// deadline, so the final snapshot would otherwise be waited out for tens of
/// seconds. The observable edge is the "flushing" log line, emitted after the
/// workers are gone and before the first flush step.
#[test]
fn a_second_sigterm_during_the_telemetry_flush_exits_nonzero_promptly() {
    // Accepts connections and holds them open without ever replying.
    let collector = TcpListener::bind("127.0.0.1:0").expect("bind hung collector");
    let collector_port = collector.local_addr().unwrap().port();
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let held_by_thread = held.clone();
    std::thread::spawn(move || {
        for stream in collector.incoming().flatten() {
            held_by_thread.lock().unwrap().push(stream);
        }
    });

    let upstream = Upstream::spawn();
    let (data, admin) = (free_port(), free_port());
    let config = format!(
        r#"node:
  metadata:
    io.llmproxy.metrics:
      otlp_endpoint: "http://127.0.0.1:{collector_port}"
      export_interval: 60
      export_deadline: 30
{}"#,
        bootstrap(data, admin, upstream.addr.port())
    );
    let mut proxy = Proxy::spawn(&config, data, admin, 600, false);
    proxy.wait_ready();

    proxy.signal_term();
    proxy.wait_log("drain finished: flushing");
    proxy.signal_term();

    let status = proxy
        .wait_exit(Duration::from_secs(10))
        .expect("a second signal must abandon the flush, not wait out the 30 s export deadline");
    assert_eq!(status.code(), Some(1), "expected exit 1, got {status:?}");
}

/// `--drain-strategy gradual` reaches the workers. SIGTERM does not close every
/// idle keep-alive connection at once: they close one by one across the first
/// quarter of the 40 s window (about 1.25 s apart here). Once the last is gone,
/// the process exits, long before the deadline would cut anything.
#[test]
fn gradual_drain_closes_idle_keep_alives_on_a_schedule_then_exits_before_the_deadline() {
    const CONNECTIONS: usize = 8;
    let upstream = Upstream::spawn();
    let (data, admin) = (free_port(), free_port());
    let mut proxy = Proxy::spawn_with(
        &bootstrap(data, admin, upstream.addr.port()),
        data,
        admin,
        40,
        false,
        &["--drain-strategy", "gradual"],
    );
    proxy.wait_ready();

    let mut open: Vec<TcpStream> = (0..CONNECTIONS)
        .map(|_| {
            let mut client = TcpStream::connect(proxy.data).expect("connect to data listener");
            client
                .write_all(b"GET /idle HTTP/1.1\r\nHost: t\r\n\r\n")
                .unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut response = Vec::new();
            let mut buf = [0u8; 1024];
            while !response.ends_with(b"ok") {
                let n = client.read(&mut buf).expect("read /idle response");
                assert_ne!(n, 0, "closed before the /idle response");
                response.extend_from_slice(&buf[..n]);
            }
            client.set_nonblocking(true).unwrap();
            client
        })
        .collect();

    // Drops every connection the server has closed; returns how many are gone.
    let reap = |open: &mut Vec<TcpStream>| {
        open.retain_mut(|client| {
            let mut buf = [0u8; 64];
            matches!(client.read(&mut buf), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock)
        });
        CONNECTIONS - open.len()
    };

    proxy.signal_term();
    proxy.wait_draining();
    let mut closed = 0;
    assert!(
        poll_until(WAIT, || {
            closed = reap(&mut open);
            closed > 0
        }),
        "the first scheduled close never came"
    );
    assert!(
        closed < CONNECTIONS,
        "gradual must not close every connection at drain start ({closed} closed)"
    );
    assert!(
        poll_until(WAIT, || reap(&mut open) == CONNECTIONS),
        "{} connections still open {WAIT:?} after the first close",
        open.len()
    );
    let status = proxy
        .wait_exit(WAIT)
        .expect("the process must exit once every connection has closed");
    assert!(status.success(), "{status:?}");
}
