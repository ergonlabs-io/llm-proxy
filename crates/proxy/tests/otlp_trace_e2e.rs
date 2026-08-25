//! WP-51 increments 2 + 3a acceptance: real traffic through the real
//! `llm-proxy` binary produces real distributed-trace spans, propagates a
//! W3C `traceparent` to the upstream leg, and exports the finished spans
//! over a real OTLP/gRPC connection to a collector -- a mock one, but a real
//! `tonic` server implementing the generated `TraceServiceServer`, not a
//! stand-in for the wire protocol.
//!
//! Same rationale and shape as `tests/stats_e2e.rs` (see its module doc):
//! only driving the compiled binary exercises `main.rs`'s real
//! `run_serve`/`worker_main` wiring (the `SpanSink` construction and
//! `otlp::run_exporter` task this WP actually adds), and asserting against
//! `FinishedSpan`/`otlp::map_span` directly (already unit-tested, no
//! network, in `proxy-observability`) would not prove any of it reaches a
//! real collector in the real OTLP wire shape.
//!
//! `#[tokio::test(flavor = "multi_thread")]`, not the default
//! `current_thread`: the mock collector's `tonic` server task and this
//! test's own blocking waits (`wait_for_connectable`, `TcpStream` I/O) both
//! need to make progress concurrently -- see CLAUDE.md rule 14's account of
//! exactly this hazard sinking `diffrig::mock_e2e` under a single-threaded
//! runtime.
//!
//! CLAUDE.md rule 15: every spawned process is a [`ChildGuard`] (killed on
//! `Drop`, so a failing assertion partway through still leaves nothing
//! running), ports are all ephemeral (`free_port`), and nothing here runs
//! the binary in the foreground or skips a timeout.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use proxy_api::opentelemetry::proto::collector::trace::v1::trace_service_server::{
    TraceService, TraceServiceServer,
};
use proxy_api::opentelemetry::proto::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use proxy_api::opentelemetry::proto::trace::v1::span::SpanKind as OtlpSpanKind;
use proxy_api::opentelemetry::proto::trace::v1::status::StatusCode as OtlpStatusCode;
use proxy_api::opentelemetry::proto::trace::v1::Span;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

/// Same technique as `tests/stats_e2e.rs`'s `free_port` / `tests/cli.rs`'s
/// own copy -- each `tests/*.rs` file is its own compiled crate, so this
/// isn't shared, just duplicated.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
}

/// A reserved-then-immediately-dropped port: nothing is listening on it, so
/// a connect attempt gets a real, near-instant ECONNREFUSED -- what the
/// `primary` cluster below needs to force a genuine connect-failure attempt
/// (not a slow timeout) on every run.
fn dead_addr() -> SocketAddr {
    format!("127.0.0.1:{}", free_port()).parse().unwrap()
}

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

/// Kills and reaps a child process on drop -- see `tests/stats_e2e.rs`'s
/// identical type for why (CLAUDE.md rule 15: a hand-run process that
/// outlives its test is a leak, not just a red test).
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The `fallback` cluster's mock upstream: answers every request `200 OK`,
/// AND captures the `traceparent` header value it actually received --
/// this is what proves propagation (`RouterHandler`'s `attempt_head.headers.insert`),
/// not merely that a client span with the right parent got minted. If that
/// injection were dropped, this would instead capture the DOWNSTREAM
/// caller's own inbound `traceparent` (unmodified, since `attempt_head`
/// starts as a clone of it) -- a different value from the child span's, so
/// the mismatch is exactly the WP-51 increment-2 propagation mutation this
/// file's task brief calls out.
fn spawn_capturing_mock_upstream() -> (SocketAddr, Arc<Mutex<Option<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    let captured = Arc::new(Mutex::new(None::<String>));
    let captured_for_thread = captured.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let captured = captured_for_thread.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                for line in request.split("\r\n") {
                    if let Some(value) = line
                        .strip_prefix("traceparent:")
                        .or_else(|| line.strip_prefix("Traceparent:"))
                    {
                        *captured.lock().unwrap() = Some(value.trim().to_string());
                    }
                }
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            });
        }
    });
    (addr, captured)
}

/// Sends `GET <path>` with an explicit `traceparent` header -- the JOIN
/// scenario's inbound header -- and returns the full response. Same shape as
/// `tests/stats_e2e.rs`'s `get`, plus the one extra header this file needs.
fn get_with_traceparent(addr: SocketAddr, path: &str, host: &str, traceparent: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set_read_timeout");
    stream
        .write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: {host}\r\ntraceparent: {traceparent}\r\n\
                 Connection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read response to EOF");
    String::from_utf8_lossy(&response).to_string()
}

/// The mock OTLP collector: a real `TraceServiceServer` recording every span
/// it receives into a shared `Vec`, flattened out of
/// `resource_spans[].scope_spans[].spans` -- this proxy only ever sends one
/// `ResourceSpans`/`ScopeSpans` per batch (see `otlp::flush`), but a real
/// collector has to handle the general (possibly-multiple) shape, so this
/// does too rather than assuming index `[0]`.
#[derive(Clone, Default)]
struct MockCollector {
    spans: Arc<Mutex<Vec<Span>>>,
}

#[tonic::async_trait]
impl TraceService for MockCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        let req = request.into_inner();
        let mut spans = self.spans.lock().expect("mock collector mutex poisoned");
        for resource_spans in req.resource_spans {
            for scope_spans in resource_spans.scope_spans {
                spans.extend(scope_spans.spans);
            }
        }
        Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
    }
}

/// Binds an ephemeral port synchronously (so the caller can embed it in the
/// proxy's config before the collector itself finishes starting -- same
/// "reserve, then let the real server rebind" pattern `free_port` documents
/// elsewhere in this file), then spawns the mock collector on the current
/// (multi-thread) tokio runtime. Returns the collector's shared span buffer
/// and its address.
fn spawn_mock_collector() -> (Arc<Mutex<Vec<Span>>>, SocketAddr) {
    let collector = MockCollector::default();
    let spans = collector.spans.clone();
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector))
            .serve(addr)
            .await;
    });
    (spans, addr)
}

/// Polls `spans` until it holds at least `min_count` entries or `deadline`
/// (wall-clock) passes -- the exporter batches on a 5s interval
/// (`otlp::BATCH_INTERVAL`), so this test's spans arrive in one lump well
/// after the request that produced them completes, not immediately.
async fn wait_for_spans(spans: &Arc<Mutex<Vec<Span>>>, min_count: usize, deadline: Duration) {
    let start = std::time::Instant::now();
    loop {
        if spans.lock().expect("mutex poisoned").len() >= min_count {
            return;
        }
        if start.elapsed() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Writes a bootstrap config: one listener routing to an aggregate cluster
/// `agg` (`primary` then `fallback`, WP-35's failover order) with a retry
/// policy that retries a connect failure, plus (when `otlp_endpoint` is
/// `Some`) the `node.metadata["io.llmproxy.tracing"]` block the `llmproxy`
/// dialect's carrier uses (`convert_tracing_metadata` in `proxy-config`).
fn write_config(
    listener_port: u16,
    admin_port: u16,
    primary_addr: SocketAddr,
    fallback_addr: SocketAddr,
    otlp_endpoint: Option<&str>,
) -> std::path::PathBuf {
    let tracing_block = match otlp_endpoint {
        Some(endpoint) => format!(
            r#"
node:
  metadata:
    io.llmproxy.tracing:
      otlp_endpoint: "{endpoint}"
      service_name: "otlp-trace-e2e"
      sample_ratio: 1.0
"#
        ),
        None => String::new(),
    };

    let config_yaml = format!(
        r#"{tracing_block}
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
                            cluster: agg
                            retry_policy:
                              retry_on: "connect-failure"
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: primary
      type: STATIC
      load_assignment:
        cluster_name: primary
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {primary_ip}, port_value: {primary_port} }}
    - name: fallback
      type: STATIC
      load_assignment:
        cluster_name: fallback
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {fallback_ip}, port_value: {fallback_port} }}
    - name: agg
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [primary, fallback]
"#,
        primary_ip = primary_addr.ip(),
        primary_port = primary_addr.port(),
        fallback_ip = fallback_addr.ip(),
        fallback_port = fallback_addr.port(),
    );

    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-otlp-trace-e2e-test-{}-{}.yaml",
        std::process::id(),
        listener_port
    ));
    std::fs::write(&config_path, config_yaml).expect("failed to write temp config");
    config_path
}

fn spawn_proxy(config_path: &std::path::Path) -> (ChildGuard, mpsc::Receiver<String>) {
    let mut child = Command::new(BIN)
        .args(["-c", config_path.to_str().unwrap(), "--concurrency", "1"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn llm-proxy");
    let stderr = child.stderr.take().expect("child stderr not piped");
    let rx = spawn_line_reader(BufReader::new(stderr));
    (ChildGuard(child), rx)
}

fn terminate(child: &mut ChildGuard) {
    let pid = child.0.id().to_string();
    let _ = Command::new("kill").arg("-TERM").arg(&pid).status();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(_)) = child.0.try_wait() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The load-bearing WP-51 test: a real request through a real aggregate
/// fallback, with a synthetic inbound `traceparent`, produces --
/// - exactly one SERVER span whose trace_id equals the INBOUND trace_id
///   (the JOIN: preserved, not replaced by a fresh root);
/// - exactly two CLIENT spans (`primary`'s connect-failure, `fallback`'s
///   response), both parented to that one SERVER span's span_id and sharing
///   its trace_id (the fallback attempt is a child under the SAME server
///   span, never a new trace);
/// - the `fallback` upstream actually receiving a `traceparent` header equal
///   to the fallback CLIENT span's own context, not the downstream client's
///   original header unchanged (the propagation half, not just emission).
#[tokio::test(flavor = "multi_thread")]
async fn traceparent_join_and_fallback_produce_the_right_span_tree() {
    let (fallback_addr, captured_traceparent) = spawn_capturing_mock_upstream();
    let primary_addr = dead_addr();
    let (spans, collector_addr) = spawn_mock_collector();
    // Give the collector's `tonic::transport::Server` a moment to actually
    // bind before the proxy (whose exporter connects lazily anyway, but
    // there's no reason to race it) starts.
    assert!(
        wait_for_connectable(("127.0.0.1", collector_addr.port()), STARTUP_TIMEOUT),
        "mock OTLP collector never became connectable"
    );

    let listener_port = free_port();
    let admin_port = free_port();
    let config_path = write_config(
        listener_port,
        admin_port,
        primary_addr,
        fallback_addr,
        Some(&format!("http://127.0.0.1:{}", collector_addr.port())),
    );
    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "listener at 127.0.0.1:{listener_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&stderr_rx)
    );

    const INBOUND_TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const INBOUND_TRACE_ID: [u8; 16] = [
        0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47,
        0x36,
    ];

    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let response = get_with_traceparent(
        listener_addr,
        "/v1/chat/completions",
        "test.local",
        INBOUND_TRACEPARENT,
    );
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected the retried request to eventually succeed against `fallback`, got:\n{response}"
    );

    // 1 server span + 2 client spans = 3. The exporter batches on a 5s
    // interval; give it comfortable headroom over that.
    wait_for_spans(&spans, 3, Duration::from_secs(20)).await;
    let collected = spans.lock().expect("mutex poisoned").clone();
    assert_eq!(
        collected.len(),
        3,
        "expected exactly 1 server + 2 client spans, got {}: {collected:#?}",
        collected.len()
    );

    let server_spans: Vec<&Span> = collected
        .iter()
        .filter(|s| s.kind == OtlpSpanKind::Server as i32)
        .collect();
    let client_spans: Vec<&Span> = collected
        .iter()
        .filter(|s| s.kind == OtlpSpanKind::Client as i32)
        .collect();
    assert_eq!(
        server_spans.len(),
        1,
        "expected exactly one SERVER span, got {collected:#?}"
    );
    assert_eq!(
        client_spans.len(),
        2,
        "expected exactly two CLIENT spans (primary's connect-failure + fallback's response), \
         got {collected:#?}"
    );

    let server_span = server_spans[0];
    // The JOIN: the server span's trace_id is the INBOUND one, not a fresh
    // root -- this is exactly what breaks if `FilterChainHandler::handle`'s
    // join used `TraceContext::new_root` instead of `inbound_ctx.child()`.
    assert_eq!(
        server_span.trace_id, INBOUND_TRACE_ID,
        "server span's trace_id must equal the inbound traceparent's trace_id (joined, not \
         replaced)"
    );

    for client_span in &client_spans {
        assert_eq!(
            client_span.trace_id, server_span.trace_id,
            "every client span must share the server span's trace_id"
        );
        assert_eq!(
            client_span.parent_span_id, server_span.span_id,
            "every client span must be parented to the SAME server span -- a retry/fallback is \
             a child under the one server span, never a new trace. This is exactly what breaks \
             if `router::RouterHandler`'s per-attempt `TraceContext::child()` call were dropped."
        );
    }

    // One of the two client spans is the connect-failure against `primary`
    // (status Error), the other is the 200 response from `fallback` (status
    // Ok) -- distinguish them by status rather than assuming order.
    let error_spans = client_spans
        .iter()
        .filter(|s| s.status.as_ref().map(|st| st.code) == Some(OtlpStatusCode::Error as i32))
        .count();
    let ok_spans = client_spans
        .iter()
        .filter(|s| s.status.as_ref().map(|st| st.code) == Some(OtlpStatusCode::Ok as i32))
        .count();
    assert_eq!(
        (error_spans, ok_spans),
        (1, 1),
        "expected one Error client span (primary's connect-failure) and one Ok client span \
         (fallback's 200), got {collected:#?}"
    );

    // The propagation half: what `fallback` actually saw on the wire must
    // be the FALLBACK CLIENT SPAN's own traceparent, not the caller's
    // original header passed through unmodified. Find the Ok (fallback)
    // client span and check its own `to_traceparent()`-equivalent bytes
    // against what the mock upstream captured.
    let fallback_span = client_spans
        .iter()
        .find(|s| s.status.as_ref().map(|st| st.code) == Some(OtlpStatusCode::Ok as i32))
        .expect("checked above that exactly one Ok client span exists");
    let expected_traceparent = format!(
        "00-{}-{}-01",
        hex(&fallback_span.trace_id),
        hex(&fallback_span.span_id)
    );
    let seen = captured_traceparent.lock().expect("mutex poisoned").clone();
    assert_eq!(
        seen,
        Some(expected_traceparent.clone()),
        "the fallback upstream must have received the FALLBACK CLIENT SPAN's own traceparent \
         ({expected_traceparent}), not the downstream caller's original header unchanged -- this \
         is exactly what breaks if the `attempt_head.headers.insert(\"traceparent\", ...)` \
         propagation call in `router::RouterHandler::apply_forward` were dropped"
    );
    assert_ne!(
        seen.as_deref(),
        Some(INBOUND_TRACEPARENT),
        "the fallback upstream received the caller's ORIGINAL traceparent unchanged -- \
         propagation did not happen"
    );

    terminate(&mut child);
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Tracing-OFF configuration (no `node.metadata["io.llmproxy.tracing"]`
/// block at all) must mean the collector receives nothing -- no `SpanSink`
/// is ever built, no `otlp::run_exporter` task ever runs, so there is
/// nothing to connect with in the first place.
#[tokio::test(flavor = "multi_thread")]
async fn tracing_off_sends_nothing_to_the_collector() {
    let (fallback_addr, _captured) = spawn_capturing_mock_upstream();
    let primary_addr = dead_addr();
    let (spans, collector_addr) = spawn_mock_collector();
    assert!(
        wait_for_connectable(("127.0.0.1", collector_addr.port()), STARTUP_TIMEOUT),
        "mock OTLP collector never became connectable"
    );

    let listener_port = free_port();
    let admin_port = free_port();
    let config_path = write_config(listener_port, admin_port, primary_addr, fallback_addr, None);
    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "listener at 127.0.0.1:{listener_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&stderr_rx)
    );

    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let response = get_with_traceparent(
        listener_addr,
        "/v1/chat/completions",
        "test.local",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    );
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected the retried request to eventually succeed against `fallback`, got:\n{response}"
    );

    // Nothing to wait a batch interval FOR -- no exporter task exists at
    // all when tracing is off, so this is a short bounded sanity wait, not
    // a proof by timeout (rule 14: every wait here is bounded).
    tokio::time::sleep(Duration::from_secs(2)).await;
    let collected = spans.lock().expect("mutex poisoned");
    assert!(
        collected.is_empty(),
        "tracing-off config must send nothing to the collector, got: {collected:#?}"
    );
    drop(collected);

    terminate(&mut child);
}
