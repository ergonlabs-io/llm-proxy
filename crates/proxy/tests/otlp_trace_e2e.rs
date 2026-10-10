//! WP-51 increments 2 + 3a + 4 acceptance: real traffic through the real
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
//! need to make progress concurrently -- see AGENTS.md "Build And Test"'s account of
//! exactly this hazard sinking `diffrig::mock_e2e` under a single-threaded
//! runtime.
//!
//! AGENTS.md "Running The Product": every spawned process is a [`ChildGuard`] (killed on
//! `Drop`, so a failing assertion partway through still leaves nothing
//! running), ports are all ephemeral (`free_port`), and nothing here runs
//! the binary in the foreground or skips a timeout.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use proxy_api::opentelemetry::proto::collector::metrics::v1::metrics_service_server::{
    MetricsService, MetricsServiceServer,
};
use proxy_api::opentelemetry::proto::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use proxy_api::opentelemetry::proto::collector::trace::v1::trace_service_server::{
    TraceService, TraceServiceServer,
};
use proxy_api::opentelemetry::proto::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use proxy_api::opentelemetry::proto::metrics::v1::{metric, ResourceMetrics};
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
/// identical type for why (AGENTS.md "Running The Product": a hand-run process that
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

/// A mock upstream that sleeps `delay` before answering every request --
/// everything else identical to [`spawn_capturing_mock_upstream`].
///
/// This exists so a request can be made IN FLIGHT across SIGTERM: the drain
/// sequence waits for connections that are already open (Gradual's close
/// probability ramps over the whole window, and an in-flight request is given
/// its full window), so the request completes after the signal but before the
/// drain finishes -- and its counters must land in the final snapshot.
fn spawn_slow_mock_upstream(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                std::thread::sleep(delay);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            });
        }
    });
    addr
}

/// Sends `GET <path>` with no `traceparent` at all. Same shape as
/// `get_with_traceparent` minus the header -- used by the increment-4 tests,
/// where a `traceparent` would make a failure ambiguous between "the trace
/// export is wrongly on" and "the traceparent join is broken", and the two
/// need to be distinguishable.
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
    // WP-51 increment 3b: same capture, for the parallel `MetricsService`
    // implementation below -- one `ResourceMetrics` per export call, kept
    // whole (rather than flattened like `spans`) because a test needs to
    // read a specific named `Metric` back out of its `scope_metrics`.
    metrics: Arc<Mutex<Vec<ResourceMetrics>>>,
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

#[tonic::async_trait]
impl MetricsService for MockCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportMetricsServiceRequest>,
    ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
        let req = request.into_inner();
        let mut metrics = self.metrics.lock().expect("mock collector mutex poisoned");
        metrics.extend(req.resource_metrics);
        Ok(tonic::Response::new(ExportMetricsServiceResponse::default()))
    }
}

/// Binds an ephemeral port synchronously (so the caller can embed it in the
/// proxy's config before the collector itself finishes starting -- same
/// "reserve, then let the real server rebind" pattern `free_port` documents
/// elsewhere in this file), then spawns the mock collector on the current
/// (multi-thread) tokio runtime. Returns the collector's shared span buffer,
/// its shared `ResourceMetrics` buffer (WP-51 increment 3b), and its
/// address. Both `TraceService` and `MetricsService` are registered on the
/// SAME `tonic` router/port -- exactly what a real OTLP/gRPC collector
/// exposes (one endpoint, multiple services multiplexed by gRPC method
/// path), and what `otlp::run_exporter` connects to: one `Channel`, two
/// clients built from it.
/// Named purely to keep [`spawn_mock_collector`]'s signature readable --
/// clippy's `type_complexity` lint flagged the inline three-tuple form, same
/// reasoning as `stats.rs`'s own `ResolveKey` alias.
type MockCollectorHandles = (
    Arc<Mutex<Vec<Span>>>,
    Arc<Mutex<Vec<ResourceMetrics>>>,
    SocketAddr,
);

fn spawn_mock_collector() -> MockCollectorHandles {
    let collector = MockCollector::default();
    let spans = collector.spans.clone();
    let metrics = collector.metrics.clone();
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector.clone()))
            .add_service(MetricsServiceServer::new(collector))
            .serve(addr)
            .await;
    });
    (spans, metrics, addr)
}

/// Polls `metrics` for a `Sum`-typed `Metric` named `name` whose data points'
/// `AsInt` values total at least `min_total`, or until `deadline` (wall-clock)
/// passes. Returns that `Metric`, cloned, once found.
///
/// Every export the mock collector receives is a FULL, CUMULATIVE snapshot of
/// the registry at that tick, not a delta (`otlp::map_metrics` reads
/// `Registry::counters` fresh on every call) -- and
/// `tokio::time::interval`'s first tick fires immediately (`otlp.rs`'s own
/// doc on `run_exporter`), so the collector's FIRST captured export can
/// easily predate the request this test just sent. Matching on "a `Metric`
/// with this name exists" (as a naive first-found search would) is therefore
/// a race: it can return that too-early, all-zero snapshot. Scanning from the
/// MOST RECENT export backward and requiring the total to clear `min_total`
/// waits out that race instead of merely tolerating it.
async fn wait_for_metric_totaling(
    metrics: &Arc<Mutex<Vec<ResourceMetrics>>>,
    name: &str,
    min_total: i64,
    deadline: Duration,
) -> Option<proxy_api::opentelemetry::proto::metrics::v1::Metric> {
    use proxy_api::opentelemetry::proto::metrics::v1::number_data_point::Value;

    let start = std::time::Instant::now();
    loop {
        {
            let collected = metrics.lock().expect("mutex poisoned");
            for resource_metrics in collected.iter().rev() {
                for scope_metrics in &resource_metrics.scope_metrics {
                    if let Some(found) = scope_metrics.metrics.iter().find(|m| m.name == name) {
                        let total: i64 = match found.data.as_ref() {
                            Some(metric::Data::Sum(sum)) => sum
                                .data_points
                                .iter()
                                .map(|p| match p.value {
                                    Some(Value::AsInt(v)) => v,
                                    _ => 0,
                                })
                                .sum(),
                            _ => 0,
                        };
                        if total >= min_total {
                            return Some(found.clone());
                        }
                    }
                }
            }
        }
        if start.elapsed() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A healthy collector whose `Export` calls sleep `delay` before recording.
///
/// This exists for exactly one test (`a_clean_shutdown_...`), and the delay is
/// what makes that test discriminating. A collector that answers instantly
/// cannot distinguish "the shutdown path awaited its final export" from "the
/// shutdown path signalled and then raced the runtime teardown", because an
/// instant loopback RPC usually wins that race even when nothing is waiting for
/// it. Verified: mutating `main.rs` to signal without awaiting the task left a
/// delay-free version of the test green. With the final export deliberately
/// slower than process exit, only actually waiting for it delivers the
/// snapshot.
type DelayedCollectorHandles = (
    Arc<Mutex<Vec<Span>>>,
    Arc<Mutex<Vec<ResourceMetrics>>>,
    SocketAddr,
);

/// [`spawn_delayed_collector_with_arrivals`] without the arrival log -- the
/// shape the shutdown-delivery test wants (it only checks snapshot CONTENT).
fn spawn_delayed_collector(delay: Duration) -> DelayedCollectorHandles {
    let (spans, metrics, _arrivals, addr) = spawn_delayed_collector_with_arrivals(delay);
    (spans, metrics, addr)
}

/// Wall-clock arrival time of each `ResourceMetrics` the delayed collector has
/// received, in receive order. Exposed so the drain-ordering test can compare
/// "when the final snapshot landed" against "when the in-flight request
/// finished" -- the only reliable discriminator for export-after-drain, since
/// this proxy's counters are dispatch-time (`upstream_rq`) or
/// attempt-except-killed (`upstream_rq_time`; see the test's comment).
/// Handles returned by [`spawn_delayed_collector_with_arrivals`]: span buffer,
/// metric buffer, metric ARRIVAL timestamps (see that function's doc), and the
/// bound address.
type DelayedWithArrivalsHandles = (
    Arc<Mutex<Vec<Span>>>,
    Arc<Mutex<Vec<ResourceMetrics>>>,
    Arc<Mutex<Vec<std::time::Instant>>>,
    SocketAddr,
);

fn spawn_delayed_collector_with_arrivals(delay: Duration) -> DelayedWithArrivalsHandles {
    let collector = DelayedCollector {
        delay,
        spans: Arc::new(Mutex::new(Vec::new())),
        metrics: Arc::new(Mutex::new(Vec::new())),
        arrivals: Arc::new(Mutex::new(Vec::new())),
    };
    let spans = collector.spans.clone();
    let metrics = collector.metrics.clone();
    let arrivals = collector.arrivals.clone();
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector.clone()))
            .add_service(MetricsServiceServer::new(collector))
            .serve(addr)
            .await;
    });
    (spans, metrics, arrivals, addr)
}

#[derive(Clone)]
struct DelayedCollector {
    delay: Duration,
    spans: Arc<Mutex<Vec<Span>>>,
    metrics: Arc<Mutex<Vec<ResourceMetrics>>>,
    arrivals: Arc<Mutex<Vec<std::time::Instant>>>,
}

#[tonic::async_trait]
impl TraceService for DelayedCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        tokio::time::sleep(self.delay).await;
        let mut spans = self.spans.lock().expect("mock collector mutex poisoned");
        for resource_spans in request.into_inner().resource_spans {
            for scope_spans in resource_spans.scope_spans {
                spans.extend(scope_spans.spans);
            }
        }
        Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
    }
}

#[tonic::async_trait]
impl MetricsService for DelayedCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportMetricsServiceRequest>,
    ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
        tokio::time::sleep(self.delay).await;
        self.arrivals
            .lock()
            .expect("mock collector mutex poisoned")
            .push(std::time::Instant::now());
        let mut metrics = self.metrics.lock().expect("mock collector mutex poisoned");
        metrics.extend(request.into_inner().resource_metrics);
        Ok(tonic::Response::new(ExportMetricsServiceResponse::default()))
    }
}

/// A collector that completes the gRPC transport and then never answers an
/// `Export` call -- the "accepted the connection, went silent" case that
/// `export_deadline` exists for.
///
/// A real `tonic` server (so the HTTP/2 handshake genuinely completes and the
/// proxy's `connect_lazy` genuinely succeeds -- a `dead_addr` would only prove
/// the connect-error path), whose `export` implementations park on
/// `std::future::pending()` forever. Returns the bound address.
///
/// This is the one mock here that deliberately leaks a parked task: it is
/// dropped when the test's runtime tears down at the end of the test, and there
/// is no clean way to cancel a `pending()` from outside. It holds no proxy state
/// and no port the next test could collide on (the port is freed by the OS on
/// process exit, and the test binary exits after its own tests).
fn spawn_hanging_collector() -> SocketAddr {
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let collector = HangingCollector;
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(collector.clone()))
            .add_service(MetricsServiceServer::new(collector))
            .serve(addr)
            .await;
    });
    addr
}

#[derive(Clone)]
struct HangingCollector;

#[tonic::async_trait]
impl TraceService for HangingCollector {
    async fn export(
        &self,
        _request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        std::future::pending().await
    }
}

#[tonic::async_trait]
impl MetricsService for HangingCollector {
    async fn export(
        &self,
        _request: tonic::Request<ExportMetricsServiceRequest>,
    ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
        std::future::pending().await
    }
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

/// The two OTLP surfaces under test, as the two INDEPENDENT
/// `node.metadata` namespace keys the `llmproxy` dialect's carriers use
/// (`convert_tracing_metadata` and `convert_metrics_metadata` in
/// `proxy-config`). They are separate arguments rather than one endpoint for
/// both because the whole point of WP-51 increment 4 is that they can differ --
/// see the module doc's "The two exporters are independent" section.
#[derive(Debug, Clone, Default)]
struct OtlpEndpoints {
    /// `io.llmproxy.tracing`'s endpoint, deadline, and sampling ratio.
    traces: Option<TraceBlock>,
    /// `io.llmproxy.metrics`'s endpoint, interval, and deadline.
    metrics: Option<MetricsBlock>,
}

/// One `io.llmproxy.tracing` block's worth of configuration.
///
/// The deadline is per-instance for the same reason `MetricsBlock`'s are: the
/// hung-export test needs to choose it so the relationship to the batch
/// interval is visible at the call site. `1.0s` default keeps every existing
/// test's behavior unchanged (the collector answers instantly there) while
/// bounding any hung attempt to a fraction of the fixed 5s batch interval.
#[derive(Debug, Clone)]
struct TraceBlock {
    endpoint: String,
    deadline_secs: f64,
}

impl TraceBlock {
    /// 1s deadline: comfortably over an instant loopback collector, and a
    /// fraction of the fixed 5s batch interval, so a hung export costs one
    /// bounded timeout rather than holding spans across many batch cycles.
    fn fast(endpoint: String) -> Self {
        TraceBlock {
            endpoint,
            deadline_secs: 1.0,
        }
    }
}

impl From<String> for TraceBlock {
    fn from(endpoint: String) -> Self {
        TraceBlock::fast(endpoint)
    }
}

/// One `io.llmproxy.metrics` block's worth of configuration.
///
/// The interval and deadline are per-instance rather than constants on
/// `OtlpEndpoints` because the deadline test needs to choose both itself (1s
/// interval, 200ms deadline) while every other test wants the fast default pair.
/// Defaulted here so the common case can be written `endpoint.into()`.
#[derive(Debug, Clone)]
struct MetricsBlock {
    endpoint: String,
    interval_secs: f64,
    deadline_secs: f64,
}

impl MetricsBlock {
    /// The fast pairing most tests use: 1s interval, 250ms deadline.
    ///
    /// The interval is at the 1s floor `convert_metrics_metadata` enforces
    /// (`METRICS_EXPORT_INTERVAL_MIN`), not below it -- a sub-second interval is
    /// a config error, so a test cannot use one. That floor is itself a real
    /// constraint on the tests here rather than an inconvenience: a
    /// full cumulative registry snapshot ten times a second is bandwidth an
    /// operator should have to opt into explicitly, and the proxy refusing to be
    /// configured that way is the same check these tests exercise
    /// incidentally.
    ///
    /// 1s is still well below the 15s production default, so it keeps every
    /// assertion in this file to one or two ticks instead of fifteen. The
    /// deadline is 250ms -- under the interval as required, and short enough
    /// that the hung-collector test sees several expiries quickly.
    fn fast(endpoint: String) -> Self {
        MetricsBlock {
            endpoint,
            interval_secs: 1.0,
            deadline_secs: 0.25,
        }
    }
}

impl From<String> for MetricsBlock {
    fn from(endpoint: String) -> Self {
        MetricsBlock::fast(endpoint)
    }
}

impl OtlpEndpoints {
    /// Both surfaces pointed at one collector -- the ordinary deployment, and
    /// the one the pre-split code could express at all.
    fn both(collector: SocketAddr) -> Self {
        let endpoint = format!("http://127.0.0.1:{}", collector.port());
        OtlpEndpoints {
            traces: Some(TraceBlock::fast(endpoint.clone())),
            metrics: Some(MetricsBlock::fast(endpoint)),
        }
    }

    fn traces_only(collector: SocketAddr) -> Self {
        OtlpEndpoints {
            traces: Some(TraceBlock::fast(format!(
                "http://127.0.0.1:{}",
                collector.port()
            ))),
            metrics: None,
        }
    }

    fn metrics_only(collector: SocketAddr) -> Self {
        OtlpEndpoints {
            traces: None,
            metrics: Some(MetricsBlock::fast(format!(
                "http://127.0.0.1:{}",
                collector.port()
            ))),
        }
    }
}

/// Writes a bootstrap config: one listener routing to an aggregate cluster
/// `agg` (`primary` then `fallback`, WP-35's failover order) with a retry
/// policy that retries a connect failure, plus whichever of the two
/// `node.metadata` OTLP blocks `endpoints` names.
///
/// The `export_interval`/`export_deadline` here are short on purpose. The
/// production defaults (15s/10s) would make every metric assertion in this file
/// either a 15-second wait or a race against a snapshot taken before the
/// request under test; 500ms/250ms keeps the tests fast while still exercising
/// the real ticker, the real deadline, and the real cumulative-snapshot
/// semantics. The bounds are validated by `crates/proxy-config`'s own tests,
/// not here.
fn write_config(
    listener_port: u16,
    admin_port: u16,
    primary_addr: SocketAddr,
    fallback_addr: SocketAddr,
    endpoints: OtlpEndpoints,
) -> std::path::PathBuf {
    // Built as a list of already-indented metadata block bodies and joined,
    // rather than string-concatenated with its own `node:` header per block, so
    // a config with BOTH blocks ends up with exactly one `node:` carrying two
    // metadata keys -- which is what `proxy-simple-config`'s merge-then-emit
    // lowering produces, so a bug there and a bug here would look the same.
    let mut metadata = Vec::new();
    if let Some(traces) = endpoints.traces {
        metadata.push(format!(
            r#"    io.llmproxy.tracing:
      otlp_endpoint: "{}"
      service_name: "otlp-trace-e2e"
      sample_ratio: 1.0
      export_deadline: {}"#,
            traces.endpoint, traces.deadline_secs
        ));
    }
    if let Some(metrics) = endpoints.metrics {
        metadata.push(format!(
            r#"    io.llmproxy.metrics:
      otlp_endpoint: "{}"
      service_name: "otlp-metrics-e2e"
      export_interval: {}
      export_deadline: {}"#,
            metrics.endpoint, metrics.interval_secs, metrics.deadline_secs
        ));
    }
    let node_block = build_node_block(&metadata);

    let config_yaml = format!(
        r#"{node_block}
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

    write_temp_config(listener_port, config_yaml)
}

/// Assemble the `node:` YAML from already-indented metadata block bodies, or
/// the empty string when there are none.
///
/// Centralized rather than inlined in `write_config` so the "no `node:` key at
/// all when nothing is configured" case has exactly one implementation. That
/// case is load-bearing: a config that emits an empty `node: {metadata: {}}` is
/// still a valid config, but it stops being a faithful stand-in for the
/// overwhelmingly common no-OTLP deployment, and
/// `crates/proxy-simple-config/tests/dialect.rs` asserts the empty case lowers
/// to *no* node key.
fn build_node_block(metadata_blocks: &[String]) -> String {
    if metadata_blocks.is_empty() {
        return String::new();
    }
    format!("node:\n  metadata:\n{}\n", metadata_blocks.join("\n"))
}

/// Write `config_yaml` to a per-(process, listener-port) temp path and return
/// it. The port is in the name so two tests in the same process never collide,
/// and the process id keeps concurrent `cargo nextest` runs apart.
fn write_temp_config(listener_port: u16, config_yaml: String) -> std::path::PathBuf {
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

/// Sends SIGTERM WITHOUT waiting for the process to exit -- unlike
/// [`terminate`], which signals and then blocks on exit. Needed by the
/// drain-ordering test, which must measure "when the in-flight request
/// finished" independently of "when the process exited": `terminate` would
/// conflate the two and make the arrival-time assertion vacuous.
fn signal_term(child: &mut ChildGuard) {
    let pid = child.0.id().to_string();
    let _ = Command::new("kill").arg("-TERM").arg(&pid).status();
}

/// Waits up to `timeout` for a previously-signalled process to exit; kills it
/// if the deadline passes (the [`ChildGuard`] handles the rest on drop).
fn wait_for_exit(child: &mut ChildGuard, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if matches!(child.0.try_wait(), Ok(Some(_)) | Err(_)) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.0.kill();
            let _ = child.0.wait();
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
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
    let (spans, _metrics, collector_addr) = spawn_mock_collector();
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
        OtlpEndpoints::both(collector_addr),
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

/// Tracing-OFF configuration (no `node.metadata["io.llmproxy.tracing"]` and
/// no `io.llmproxy.metrics` block at all) must mean the collector receives
/// nothing on either signal -- no `SpanSink` is ever built, no exporter task
/// ever runs, so there is nothing to connect with in the first place.
///
/// The metrics half of that assertion is WP-51 increment 4's and is the
/// stricter one: before the split, "no collector traffic" was trivially true
/// because metrics rode inside the trace exporter, so this test could not have
/// distinguished "metrics off" from "metrics configured but broken". Now the
/// two are independent, and this pins that a config naming NEITHER leaves both
/// silent -- while `metrics_export_with_tracing_disabled_exports_metrics` pins
/// that naming one leaves the other running.
#[tokio::test(flavor = "multi_thread")]
async fn no_otlp_surfaces_configured_sends_nothing_to_the_collector() {
    let (fallback_addr, _captured) = spawn_capturing_mock_upstream();
    let primary_addr = dead_addr();
    let (spans, metrics, collector_addr) = spawn_mock_collector();
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
        OtlpEndpoints::default(),
    );
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
    // all when neither surface is configured, so this is a short bounded
    // sanity wait, not a proof by timeout (rule 14: every wait here is
    // bounded). The metric export interval configured in `write_config` is
    // 500ms, so 2s is four full intervals: if a metric export task were
    // wrongly spawned it would have landed at least three times by now.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let collected = spans.lock().expect("mutex poisoned");
    assert!(
        collected.is_empty(),
        "tracing-off config must send no spans to the collector, got: {collected:#?}"
    );
    drop(collected);
    let collected = metrics.lock().expect("mutex poisoned");
    assert!(
        collected.is_empty(),
        "a config naming neither OTLP surface must send no metrics either, got {} exports",
        collected.len()
    );
    drop(collected);

    terminate(&mut child);
}

/// WP-51 increment 3b acceptance, restated for increment 4: the same real
/// proxy, driven by the same real traffic as
/// `traceparent_join_and_fallback_produce_the_right_span_tree` above, also
/// exports OTLP **metrics** to the collector. `upstream_rq`
/// (`RouterStats::record_attempt`) is the counter the served request actually
/// increments: one attempt against `primary` (connect-failure) and one against
/// `fallback` (the 200), so its per-cluster data points should sum to 2 --
/// proving both the wiring (`main.rs`'s `registry.clone()` reaching the metric
/// exporter) and the grouping (`otlp::map_metrics` collapsing the two `cluster`
/// attribute sets into one `Metric`).
///
/// This used to assert that both signals shared ONE `Channel`. They no longer
/// do -- `otlp::metrics_client` builds its own `Endpoint` -- so the mock
/// collector still serves both on one port (a real collector's shape) while
/// the proxy now holds two independent connections to it.
#[tokio::test(flavor = "multi_thread")]
async fn served_traffic_exports_upstream_rq_metric_to_the_collector() {
    let (fallback_addr, _captured) = spawn_capturing_mock_upstream();
    let primary_addr = dead_addr();
    let (_spans, metrics, collector_addr) = spawn_mock_collector();
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
        OtlpEndpoints::both(collector_addr),
    );
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

    // `write_config` sets the metric export interval to 500ms, so this normally
    // resolves in well under a second; the 20s ceiling is headroom for a loaded
    // CI box, and `wait_for_metric_totaling` is itself the real assertion (it
    // scans newest-first and requires the cumulative total to actually reach 2,
    // rather than returning an early all-zero snapshot -- see its doc).
    //
    // `write_config`'s boot snapshot names three clusters (`primary`,
    // `fallback`, and the aggregate `agg` itself -- `StatHandles::build`
    // resolves a handle for every cluster in the snapshot, per its own doc), so
    // `upstream_rq` carries THREE per-cluster data points; only `primary` and
    // `fallback` are ever actually dispatched to (`agg` is a routing target,
    // never dialed itself), so their two attempts are what this waits for.
    let upstream_rq = wait_for_metric_totaling(&metrics, "upstream_rq", 2, Duration::from_secs(20))
        .await
        .expect(
            "expected an \"upstream_rq\" Metric totaling at least 2 to arrive at the mock \
             collector within the wait window -- either the exporter task never got the \
             registry, or map_metrics never ran",
        );

    let sum = match upstream_rq.data.as_ref().expect("Metric.data present") {
        metric::Data::Sum(sum) => sum,
        other => panic!("expected upstream_rq to be Data::Sum, got {other:?}"),
    };
    assert!(
        sum.is_monotonic,
        "upstream_rq is a Counter instrument -- its Sum must be monotonic"
    );

    // Three resolved clusters (`primary`, `fallback`, `agg`), each a
    // DIFFERENT `cluster` attribute value -- so this must be ONE Metric
    // (asserted above by `wait_for_metric_totaling` finding exactly the name
    // "upstream_rq") carrying multiple data points, not one Metric per
    // cluster. This is exactly the grouping `otlp::map_metrics`'s module doc
    // calls out.
    assert_eq!(
        sum.data_points.len(),
        3,
        "expected one data point per resolved cluster (primary, fallback, agg), got {:#?}",
        sum.data_points
    );
    let total: i64 = sum
        .data_points
        .iter()
        .map(|p| match p.value {
            Some(
                proxy_api::opentelemetry::proto::metrics::v1::number_data_point::Value::AsInt(v),
            ) => v,
            other => panic!("expected AsInt, got {other:?}"),
        })
        .sum();
    assert_eq!(
        total, 2,
        "expected exactly 2 total upstream_rq attempts (1 primary + 1 fallback; \"agg\" is \
         never dialed itself), got {total}"
    );

    let cluster_values: Vec<String> = sum
        .data_points
        .iter()
        .flat_map(|p| p.attributes.iter())
        .filter(|kv| kv.key == "cluster")
        .filter_map(|kv| match &kv.value.as_ref()?.value {
            Some(proxy_api::opentelemetry::proto::common::v1::any_value::Value::StringValue(s)) => {
                Some(s.clone())
            }
            _ => None,
        })
        .collect();
    assert!(
        cluster_values.contains(&"primary".to_string())
            && cluster_values.contains(&"fallback".to_string()),
        "expected data points for both \"primary\" and \"fallback\" clusters, got {cluster_values:?}"
    );

    terminate(&mut child);
}

// ------------------------------- WP-51 increment 4: exporter independence --

/// The headline acceptance criterion, stated as a test: **metrics export works
/// with tracing entirely off.** A config naming only `io.llmproxy.metrics`
/// must still export OTLP metrics for real served traffic, and must produce NO
/// spans.
///
/// Before the split this configuration was inexpressible: the only OTLP config
/// in the IR was `tracing`, and the `MetricsServiceClient` was constructed
/// inside the task spawned for it. The regression this pins is therefore not
/// subtle -- it is "someone re-merged the two config fields, or re-gated the
/// metric spawn on `snapshot.tracing`".
///
/// The span half of the assertion matters as much as the metric half: a change
/// that made metrics work by, say, constructing a `SpanSink` unconditionally
/// and exporting its (empty) contents would pass a metrics-only test.
#[tokio::test(flavor = "multi_thread")]
async fn metrics_export_with_tracing_disabled_exports_metrics_and_no_spans() {
    let (fallback_addr, _captured) = spawn_capturing_mock_upstream();
    let primary_addr = dead_addr();
    let (spans, metrics, collector_addr) = spawn_mock_collector();
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
        OtlpEndpoints::metrics_only(collector_addr),
    );
    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "listener at 127.0.0.1:{listener_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&stderr_rx)
    );

    // A plain request, no `traceparent` at all. The header is not what makes
    // tracing off here -- the absent `io.llmproxy.tracing` block is -- but
    // sending it anyway would make this test's failure mode ambiguous (a broken
    // traceparent join vs. a wrongly-enabled span sink would look identical).
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let response = get(listener_addr, "/v1/chat/completions", "test.local");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected the retried request to eventually succeed against `fallback`, got:\n{response}"
    );

    let upstream_rq = wait_for_metric_totaling(&metrics, "upstream_rq", 2, Duration::from_secs(20))
        .await
        .expect(
            "metrics configured with tracing off must still reach the collector -- the metric \
             exporter must be spawned from `snapshot.metrics` alone",
        );
    let sum = match upstream_rq.data.as_ref().expect("Metric.data present") {
        metric::Data::Sum(sum) => sum,
        other => panic!("expected upstream_rq to be Data::Sum, got {other:?}"),
    };
    let total: i64 = sum
        .data_points
        .iter()
        .map(|p| match p.value {
            Some(
                proxy_api::opentelemetry::proto::metrics::v1::number_data_point::Value::AsInt(v),
            ) => v,
            other => panic!("expected AsInt, got {other:?}"),
        })
        .sum();
    assert_eq!(
        total, 2,
        "expected 2 total upstream_rq attempts (1 primary + 1 fallback), got {total}"
    );

    // No spans: no `SpanSink` is built, so there is nothing that could have
    // produced one. Waited out rather than sampled once, because the span batch
    // interval is 5s and a single early check would pass even if spans were
    // being exported on a slower tick.
    tokio::time::sleep(Duration::from_secs(7)).await;
    let collected = spans.lock().expect("mutex poisoned");
    assert!(
        collected.is_empty(),
        "tracing is off, so no spans may be exported even though metrics are -- got {collected:#?}"
    );
    drop(collected);

    terminate(&mut child);
}

/// The mirror image, and the half of the independence claim that is easy to
/// regress by accident: **traces must not imply metrics.** A config naming only
/// `io.llmproxy.tracing` exports spans and NO metrics.
///
/// This is what stops a future "helpfully default metrics on whenever the
/// exporter is running" change from quietly making an operator who wanted
/// traces only start paying for a full cumulative registry snapshot on every
/// interval. The interval is 500ms here, so the 2s wait covers four of them.
#[tokio::test(flavor = "multi_thread")]
async fn tracing_without_metrics_exports_spans_and_no_metrics() {
    let (fallback_addr, captured_traceparent) = spawn_capturing_mock_upstream();
    let primary_addr = dead_addr();
    let (spans, metrics, collector_addr) = spawn_mock_collector();
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
        OtlpEndpoints::traces_only(collector_addr),
    );
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

    // 1 server span + 2 client spans (primary's connect failure, fallback's 200).
    wait_for_spans(&spans, 3, Duration::from_secs(20)).await;
    assert_eq!(
        spans.lock().expect("mutex poisoned").len(),
        3,
        "tracing must still work with metrics unconfigured"
    );
    assert!(
        captured_traceparent
            .lock()
            .expect("mutex poisoned")
            .is_some(),
        "propagation must be unaffected by the metrics/traces split"
    );

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        metrics.lock().expect("mutex poisoned").is_empty(),
        "metrics are unconfigured, so no OTLP metric export may happen -- a config that wanted \
         traces only must not start paying for cumulative registry snapshots"
    );

    terminate(&mut child);
}

/// A **failing** metric export must be counted, not swallowed, and must NOT
/// stop the proxy from forwarding traffic or from serving `/stats`.
///
/// This is the observability-half of the design doc's failure matrix row
/// "Operational collector unavailable -> Forwarding: Continues; Operational
/// outcome: bounded export failures/drops". The failure is provoked by pointing
/// the metrics block at a port nothing is listening on (`dead_addr()`), which
/// is a connect error rather than a hang -- the deadline case is covered
/// separately below.
///
/// The assertion is made against the ADMIN server's `/stats/prometheus` rather
/// than against the collector, because the point is that the failure count is
/// visible *somewhere* when the collector is by definition unreachable. That
/// also proves the two paths are independent: scrape keeps working while OTLP
/// export does not.
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_metric_export_is_counted_and_forwarding_continues() {
    let (fallback_addr, _captured) = spawn_capturing_mock_upstream();
    let primary_addr = dead_addr();
    // Nothing is bound here: every export attempt gets a real, fast
    // ECONNREFUSED, so several ticks fail inside the wait window.
    let dead_collector = dead_addr();

    let listener_port = free_port();
    let admin_port = free_port();
    let config_path = write_config(
        listener_port,
        admin_port,
        primary_addr,
        fallback_addr,
        OtlpEndpoints {
            traces: None,
            metrics: Some(format!("http://127.0.0.1:{}", dead_collector.port()).into()),
        },
    );
    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "listener at 127.0.0.1:{listener_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&stderr_rx)
    );

    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let response = get(listener_addr, "/v1/chat/completions", "test.local");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "an unreachable collector must not affect forwarding, got:\n{response}"
    );

    // Poll the admin server for the failure counter to become non-zero. The
    // proxy logs one warning per failed export, so a bound on the wait is
    // enough -- but polling rather than sleeping a fixed time keeps this fast
    // on a healthy box and still bounded on a slow one.
    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut scrape;
    loop {
        scrape = get(admin_addr, "/stats/prometheus", "admin.local");
        if scrape.contains(r#"envoy_llmproxy_otel_export_failures{signal="metrics"} "#) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    assert!(
        scrape.contains("# TYPE envoy_llmproxy_otel_export_failures counter"),
        "the export-failure instrument must be a counter in Prometheus output, got:\n{scrape}"
    );
    let failures: i64 = scrape
        .lines()
        .find_map(|line| {
            line.strip_prefix(r#"envoy_llmproxy_otel_export_failures{signal="metrics"} "#)?
                .parse()
                .ok()
        })
        .unwrap_or_else(|| {
            panic!(
                "expected a non-zero `llmproxy_otel_export_failures{{signal=\"metrics\"}}` series \
                 after a failed export -- an unreachable collector that is counted nowhere is \
                 indistinguishable from one that is not being exported at all. scrape:\n{scrape}"
            )
        });
    assert!(
        failures >= 1,
        "expected at least one counted metric-export failure, got {failures}"
    );

    // The `traces` signal must stay at zero: the traces exporter was never
    // spawned (no tracing block), so counting a trace failure here would mean
    // the two counters are not actually independent.
    assert!(
        scrape.contains(r#"envoy_llmproxy_otel_export_failures{signal="traces"} 0"#),
        "the traces signal must remain 0 when tracing is unconfigured, got:\n{scrape}"
    );

    // Forwarding still works after the failures, and the counters that prove the
    // request happened are visible on the same scrape -- so an operator can see
    // both "the proxy is serving" and "the collector is unreachable" at once.
    let second = get(listener_addr, "/v1/chat/completions", "test.local");
    assert!(
        second.starts_with("HTTP/1.1 200"),
        "forwarding must continue to work across repeated export failures, got:\n{second}"
    );
    let stats = get(admin_addr, "/stats", "admin.local");
    assert!(
        stats.contains("upstream_rq_total"),
        "the registry must still be populated and scrapeable, got:\n{stats}"
    );

    terminate(&mut child);
}

/// A **hung** collector -- one that accepts the TCP connection and then never
/// answers -- must be bounded by `export_deadline`, counted, and must not wedge
/// the proxy or prevent later ticks.
///
/// The mock collector below is the important piece: it completes the HTTP/2
/// handshake by running a real `tonic` server, then simply never calls `export`
/// (it parks instead of answering). Without the `export_deadline`
/// `tokio::time::timeout` in `flush_metrics`, the first export's `.await` would
/// never return and every subsequent tick would queue behind it forever --
/// which is precisely the failure mode the design doc's §5.3 "separate metric
/// and span scheduling/deadlines" exists to prevent, and the reason the
/// deadline is a config field rather than a constant.
///
/// Asserted through the same admin `/stats/prometheus` path as above, since the
/// collector never answers by construction.
#[tokio::test(flavor = "multi_thread")]
async fn a_hung_collector_is_bounded_by_the_export_deadline() {
    let (fallback_addr, _captured) = spawn_capturing_mock_upstream();
    let primary_addr = dead_addr();
    // Real gRPC server that never answers an Export call.
    let hung_addr = spawn_hanging_collector();

    let listener_port = free_port();
    let admin_port = free_port();
    // A 1s interval with a 200ms deadline: several timeouts must elapse inside
    // any reasonable wait, and the deadline is comfortably under the interval as
    // `convert_metrics_metadata` requires.
    let config_path = write_config(
        listener_port,
        admin_port,
        primary_addr,
        fallback_addr,
        OtlpEndpoints {
            traces: None,
            metrics: Some(MetricsBlock {
                endpoint: format!("http://127.0.0.1:{}", hung_addr.port()),
                interval_secs: 1.0,
                deadline_secs: 0.2,
            }),
        },
    );
    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "listener at 127.0.0.1:{listener_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&stderr_rx)
    );

    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let response = get(listener_addr, "/v1/chat/completions", "test.local");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "a hung collector must not affect forwarding, got:\n{response}"
    );

    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut scrape;
    loop {
        scrape = get(admin_addr, "/stats/prometheus", "admin.local");
        if scrape.contains(r#"envoy_llmproxy_otel_export_failures{signal="metrics"} "#)
            && scrape
                .lines()
                .any(|l| l.starts_with(r#"envoy_llmproxy_otel_export_failures{signal="metrics"} "#))
        {
            let counted: i64 = scrape
                .lines()
                .find_map(|line| {
                    line.strip_prefix(r#"envoy_llmproxy_otel_export_failures{signal="metrics"} "#)?
                        .parse()
                        .ok()
                })
                .unwrap_or(0);
            if counted >= 2 {
                break;
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // TWO or more timeouts is the assertion that matters. One would be
    // consistent with either a working deadline or a single unlucky connect
    // error; repeated expiry is only possible if the first hung export was
    // actually abandoned and the ticker kept running.
    let counted: i64 = scrape
        .lines()
        .find_map(|line| {
            line.strip_prefix(r#"envoy_llmproxy_otel_export_failures{signal="metrics"} "#)?
                .parse()
                .ok()
        })
        .unwrap_or(0);
    assert!(
        counted >= 2,
        "expected at least 2 deadline expiries against a hung collector -- one would be \
         consistent with a single connect error rather than a bounded hung export. got {counted}. \
         scrape:\n{scrape}"
    );

    // And the proxy is still serving after all of them.
    let second = get(listener_addr, "/v1/chat/completions", "test.local");
    assert!(
        second.starts_with("HTTP/1.1 200"),
        "forwarding must survive repeated deadline expiries, got:\n{second}"
    );

    terminate(&mut child);
}

/// `/stats/prometheus` must work with NO OTLP configuration of any kind --
/// neither `tracing` nor `metrics`. Design doc §5.3: "Prometheus scrape remains
/// available without OTLP or tracing."
///
/// This is partly a regression guard on the split itself: the metric exporter's
/// self-instruments (`llmproxy_otel_export_failures`, `llmproxy_otel_spans_
/// dropped`) are resolved at boot **unconditionally**, so this test also proves
/// those series exist in scrape output on a process that has never exported
/// anything. That is deliberate (`MetricExportHealth::resolve`'s doc): a
/// dashboard should not have a series appear mid-incident.
#[tokio::test(flavor = "multi_thread")]
async fn prometheus_scrape_works_with_no_otlp_configured() {
    let (fallback_addr, _captured) = spawn_capturing_mock_upstream();
    let primary_addr = dead_addr();

    let listener_port = free_port();
    let admin_port = free_port();
    let config_path = write_config(
        listener_port,
        admin_port,
        primary_addr,
        fallback_addr,
        OtlpEndpoints::default(),
    );
    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "listener at 127.0.0.1:{listener_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&stderr_rx)
    );

    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let response = get(listener_addr, "/v1/chat/completions", "test.local");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected the retried request to eventually succeed against `fallback`, got:\n{response}"
    );

    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    let scrape = get(admin_addr, "/stats/prometheus", "admin.local");
    assert!(
        scrape.starts_with("HTTP/1.1 200"),
        "/stats/prometheus must answer with no OTLP config, got:\n{scrape}"
    );
    assert!(
        scrape.contains("envoy_upstream_rq"),
        "real traffic must be visible on the scrape, got:\n{scrape}"
    );
    // Both self-instrument series are resolved at boot, so both are present --
    // at zero, which is the honest value for a process that has not exported
    // and dropped nothing.
    assert!(
        scrape.contains(r#"envoy_llmproxy_otel_export_failures{signal="metrics"} 0"#),
        "the metrics self-instrument must exist from the first scrape, got:\n{scrape}"
    );
    assert!(
        scrape.contains(r#"envoy_llmproxy_otel_export_failures{signal="traces"} 0"#),
        "the traces self-instrument must exist from the first scrape, got:\n{scrape}"
    );
    assert!(scrape.contains("# TYPE envoy_llmproxy_otel_spans_dropped counter"));
    assert!(
        scrape.contains("envoy_llmproxy_otel_spans_dropped 0"),
        "the span-drop series must exist from the first scrape, got:\n{scrape}"
    );

    terminate(&mut child);
}

/// Shutdown closes trace producers and waits for the final collector acknowledgement.
#[tokio::test(flavor = "multi_thread")]
async fn a_clean_shutdown_delivers_a_final_trace_batch() {
    let (fallback_addr, _) = spawn_capturing_mock_upstream();
    let (spans, metrics, collector_addr) = spawn_delayed_collector(Duration::from_millis(1_500));
    let listener_port = free_port();
    let config_path = write_config(
        listener_port,
        free_port(),
        dead_addr(),
        fallback_addr,
        OtlpEndpoints {
            traces: Some(TraceBlock {
                endpoint: format!("http://{collector_addr}"),
                deadline_secs: 5.0,
            }),
            metrics: None,
        },
    );
    let (mut child, stderr_rx) = spawn_proxy(&config_path);
    assert!(
        wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT),
        "listener did not start: {:?}",
        drain_available_lines(&stderr_rx)
    );
    let response = get(
        format!("127.0.0.1:{listener_port}").parse().unwrap(),
        "/v1/chat/completions",
        "test.local",
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    // Do not wait for the periodic batch tick: shutdown must close all senders
    // and await the collector's delayed acknowledgement of the remaining spans.
    signal_term(&mut child);
    assert!(wait_for_exit(&mut child, Duration::from_secs(15)));
    assert_eq!(spans.lock().unwrap().len(), 3);
    assert!(metrics.lock().unwrap().is_empty());
}

/// A **clean SIGTERM** must still deliver one final metric snapshot carrying the
/// traffic served so far.
///
/// This is `main.rs`'s shutdown path, and it is the half of the exporter
/// lifecycle the failure tests above cannot reach -- those all `terminate` into
/// a collector that is absent or hung, where no snapshot is expected to survive.
/// Here the collector is healthy, so a snapshot taken after the signal is
/// observable.
///
/// # Why the export interval is 60s and the collector is slow
///
/// Two deliberate constraints, and both were arrived at by watching this test
/// fail to fail. The first version asserted on "a final snapshot was
/// delivered", against a 1s interval and an instant collector -- and mutating
/// `main.rs` to signal the exporter *without awaiting its task* left it green,
/// because the assertion was satisfied by an ordinary tick that had nothing to
/// do with shutdown.
///
/// The interval is 60s so no tick can fire inside the test's lifetime.
/// `tokio::time::interval`'s first tick fires immediately, so the exporter
/// delivers exactly ONE snapshot at startup -- before the request -- then parks
/// for the rest of the test. The only way the collector can come to see
/// `upstream_rq >= 2` is the snapshot the shutdown signal triggers.
///
/// The collector's 1.5s response delay closes the second gap: with an instant
/// collector, the final export can complete in the microseconds between
/// `tx.send(())` and the runtime being dropped, so even the 60s interval is not
/// enough to tell "awaited" from "signalled and raced". A response slower than
/// process exit means the snapshot only arrives if something actually waits.
/// The deadline (5s) is set above that delay on purpose, and below the shutdown
/// budget `main.rs` allows, so the test neither trips the deadline nor hangs.
#[tokio::test(flavor = "multi_thread")]
async fn a_clean_shutdown_delivers_a_final_metric_snapshot() {
    let (fallback_addr, _captured) = spawn_capturing_mock_upstream();
    let primary_addr = dead_addr();
    // Every Export takes 1.5s to answer -- see `spawn_delayed_collector`'s doc
    // for why the delay is the load-bearing part of this test.
    let (spans, metrics, collector_addr) = spawn_delayed_collector(Duration::from_millis(1_500));
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
        OtlpEndpoints {
            traces: None,
            metrics: Some(MetricsBlock {
                endpoint: format!("http://127.0.0.1:{}", collector_addr.port()),
                // 60s interval, well above every wait in this test, so no tick
                // can deliver the served request. The 5s deadline must exceed
                // the collector's 1.5s response time (or the final export would
                // be abandoned as a timeout and there would be nothing to
                // deliver), and the two-deadline shutdown budget remains bounded
                // even if a regular export is still in flight, and is short
                // enough that a genuinely stuck collector cannot hang the test.
                interval_secs: 60.0,
                deadline_secs: 5.0,
            }),
        },
    );
    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "listener at 127.0.0.1:{listener_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&stderr_rx)
    );

    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let response = get(listener_addr, "/v1/chat/completions", "test.local");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected the retried request to eventually succeed against `fallback`, got:\n{response}"
    );

    // Wait for the startup snapshot to land, so "the exporter is running and
    // talking to this collector" is established before the signal. Its contents
    // are not asserted here: it necessarily predates the request. The wait has
    // to clear the collector's 1.5s response delay plus slack.
    let startup_deadline = std::time::Instant::now() + Duration::from_secs(20);
    while metrics.lock().expect("mutex poisoned").is_empty() {
        assert!(
            std::time::Instant::now() < startup_deadline,
            "the exporter never delivered its startup snapshot; stderr so far: {:?}",
            drain_available_lines(&stderr_rx)
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // The served request must NOT already be visible. This is the check that
    // proves the 60s interval really did park the exporter; without it the rest
    // of the test could be satisfied by a stray tick and would prove nothing.
    assert!(
        !collector_saw_upstream_rq_at_least(&metrics, 2),
        "upstream_rq reached 2 before SIGTERM, so the 60s interval did not park the exporter \
         and this test would pass without exercising the shutdown path at all"
    );

    terminate(&mut child);

    assert!(
        spans.lock().expect("mutex poisoned").is_empty(),
        "tracing is unconfigured here, so the shutdown path must not have started a trace \
         export either -- the two halves of the drain stay independent"
    );

    assert!(
        collector_saw_upstream_rq_at_least(&metrics, 2),
        "the final snapshot triggered by SIGTERM never reached the collector. With a 60s export \
         interval the shutdown path is the ONLY thing that can deliver the served request's \
         upstream_rq total, so this means the exporter task was cancelled mid-export instead of \
         being awaited -- main.rs must keep the JoinHandle and wait on it."
    );
}

/// Whether any `ResourceMetrics` the collector has received carries an
/// `upstream_rq` whose per-cluster data points total at least `min_total`.
///
/// Walks the nested `ResourceMetrics`/`ScopeMetrics` shape rather than indexing
/// `[0]`, for the same reason the mock collector itself does (see its doc): a
/// real collector has to handle the general shape, and a test that assumes
/// index `[0]` is asserting that this proxy only ever sends one of each, which
/// is a property of `map_metrics` that has no business being load-bearing here.
fn collector_saw_upstream_rq_at_least(
    metrics: &Arc<Mutex<Vec<ResourceMetrics>>>,
    min_total: i64,
) -> bool {
    metrics.lock().expect("mutex poisoned").iter().any(|rm| {
        rm.scope_metrics.iter().any(|sm| {
            sm.metrics
                .iter()
                .any(|m| m.name == "upstream_rq" && total_of(m) >= min_total)
        })
    })
}

/// A trace collector whose FIRST export hangs forever and whose later exports
/// answer instantly -- the exact shape the trace exporter's deadline exists
/// for.
///
/// The `AtomicU32` counts completed exports, so a test can distinguish "hung"
/// from "answered". Everything else mirrors `MockCollector`.
#[derive(Clone)]
struct HangFirstTraceCollector {
    done: Arc<AtomicU32>,
    received: Arc<AtomicU32>,
    spans: Arc<Mutex<Vec<Span>>>,
    metrics: Arc<Mutex<Vec<ResourceMetrics>>>,
}

impl HangFirstTraceCollector {
    fn new() -> (Self, SocketAddr) {
        let collector = HangFirstTraceCollector {
            done: Arc::new(AtomicU32::new(0)),
            received: Arc::new(AtomicU32::new(0)),
            spans: Arc::new(Mutex::new(Vec::new())),
            metrics: Arc::new(Mutex::new(Vec::new())),
        };
        let addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let server = collector.clone();
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(server.clone()))
                .add_service(MetricsServiceServer::new(server))
                .serve(addr)
                .await;
        });
        (collector, addr)
    }

    fn completed_exports(&self) -> u32 {
        self.done.load(Ordering::SeqCst)
    }
}

#[tonic::async_trait]
impl TraceService for HangFirstTraceCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        let ordinal = self.received.fetch_add(1, Ordering::SeqCst);
        // The FIRST export parks forever -- exactly the "accepted the
        // connection, went silent" collector. Every later export completes
        // normally, so the exporter's next tick must succeed once the deadline
        // has bounded the hung one. (The discriminator is `received`'s ordinal,
        // not `done`: the hung call never completes, so gating on `done == 0`
        // would make EVERY subsequent export hang too, and the test would then
        // measure "exporter never recovers" rather than "one bounded stall".)
        if ordinal == 0 {
            std::future::pending::<()>().await;
        }
        self.done.fetch_add(1, Ordering::SeqCst);
        let mut spans = self.spans.lock().expect("mutex poisoned");
        for resource_spans in request.into_inner().resource_spans {
            for scope_spans in resource_spans.scope_spans {
                spans.extend(scope_spans.spans);
            }
        }
        Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
    }
}

#[tonic::async_trait]
impl MetricsService for HangFirstTraceCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportMetricsServiceRequest>,
    ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
        self.done.fetch_add(1, Ordering::SeqCst);
        let mut metrics = self.metrics.lock().expect("mutex poisoned");
        metrics.extend(request.into_inner().resource_metrics);
        Ok(tonic::Response::new(ExportMetricsServiceResponse::default()))
    }
}

/// A hung TRACE collector must be bounded by `TracingConfig::export_deadline`,
/// the hung batch's spans must be counted into `llmproxy_otel_spans_dropped`,
/// the failure into `llmproxy_otel_export_failures{signal="traces"}`, and
/// forwarding must continue throughout.
///
/// This is the P2 review finding as an executable test: before the deadline
/// existed, the first hung export parked the trace exporter forever, every
/// later batch buffered behind it, the bounded sink filled, and the proxy sat
/// there silently losing spans with NOTHING reporting the loss. Now the hung
/// attempt costs one timeout, the discarded batch's span count (1 server + 2
/// client = 3 here) lands in the ledger the trace exporter itself publishes,
/// and the failure counter names the signal. All three assertions are read
/// from `/stats/prometheus`, which also proves the counters are scrape-visible
/// with no OTLP metric export configured (the review's Prometheus-only case).
///
/// Timeline note: the exporter's first flush attempt happens at the fixed 5s
/// batch tick, the deadline bounds it at 1s, and the poll below allows well
/// over that -- the 40s ceiling is CI headroom, not the expected case.
#[tokio::test(flavor = "multi_thread")]
async fn a_hung_trace_export_is_bounded_and_its_batch_counted_as_dropped() {
    let (fallback_addr, _captured) = spawn_capturing_mock_upstream();
    let primary_addr = dead_addr();
    let (collector, collector_addr) = HangFirstTraceCollector::new();
    assert!(
        wait_for_connectable(("127.0.0.1", collector_addr.port()), STARTUP_TIMEOUT),
        "mock trace collector never became connectable"
    );

    let listener_port = free_port();
    let admin_port = free_port();
    let config_path = write_config(
        listener_port,
        admin_port,
        primary_addr,
        fallback_addr,
        OtlpEndpoints {
            traces: Some(TraceBlock::fast(format!(
                "http://127.0.0.1:{}",
                collector_addr.port()
            ))),
            metrics: None,
        },
    );
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

    // Poll the admin server for BOTH counters to appear. `flush` publishes the
    // ledger after every flush attempt, including the one that timed out, so
    // both series move together within one batch interval of the timeout.
    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    let mut scrape;
    loop {
        scrape = get(admin_addr, "/stats/prometheus", "admin.local");
        let failures = scrape
            .lines()
            .find_map(|l| {
                l.strip_prefix(r#"envoy_llmproxy_otel_export_failures{signal="traces"} "#)?
                    .parse::<i64>()
                    .ok()
            })
            .unwrap_or(0);
        let drops = scrape
            .lines()
            .find_map(|l| {
                l.strip_prefix("envoy_llmproxy_otel_spans_dropped ")?
                    .parse::<i64>()
                    .ok()
            })
            .unwrap_or(0);
        if failures >= 1 && drops >= 3 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let failures = scrape
        .lines()
        .find_map(|l| {
            l.strip_prefix(r#"envoy_llmproxy_otel_export_failures{signal="traces"} "#)?
                .parse::<i64>()
                .ok()
        })
        .unwrap_or(0);
    let drops = scrape
        .lines()
        .find_map(|l| {
            l.strip_prefix("envoy_llmproxy_otel_spans_dropped ")?
                .parse::<i64>()
                .ok()
        })
        .unwrap_or(0);

    assert!(
        failures >= 1,
        "the hung export must be counted as a failure under signal=\"traces\". scrape:\n{scrape}"
    );
    assert!(
        drops >= 3,
        "the hung batch's 3 spans (1 server + 2 client) must be counted as dropped -- a \
         failure counter without the loss total cannot answer the only question an operator \
         asks it. scrape:\n{scrape}"
    );
    // And the hung batch was never delivered, so the collector recorded no
    // spans: the drop counter is telling the truth about real losses, not
    // double-counting a delivery that eventually succeeded.
    assert_eq!(
        collector.spans.lock().expect("mutex poisoned").len(),
        0,
        "the hung batch must not have been recorded -- if it were, the drop counter would be \
         lying"
    );

    // Forwarding continues throughout, and keeps producing exportable spans --
    // which the NEXT flush (after the collector is answering) will deliver,
    // proving the exporter itself recovered.
    let second = get_with_traceparent(
        listener_addr,
        "/v1/chat/completions",
        "test.local",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    );
    assert!(
        second.starts_with("HTTP/1.1 200"),
        "forwarding must survive a hung trace export, got:\n{second}"
    );

    // Wait for a later batch to actually land on the now-answering collector,
    // then confirm the drop count did NOT grow for it.
    let flush_deadline = std::time::Instant::now() + Duration::from_secs(40);
    loop {
        if collector.completed_exports() >= 1
            && !collector.spans.lock().expect("mutex poisoned").is_empty()
        {
            break;
        }
        if std::time::Instant::now() >= flush_deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !collector.spans.lock().expect("mutex poisoned").is_empty(),
        "the exporter must recover and deliver a later batch once the collector answers"
    );
    let drops_after = get(admin_addr, "/stats/prometheus", "admin.local")
        .lines()
        .find_map(|l| {
            l.strip_prefix("envoy_llmproxy_otel_spans_dropped ")?
                .parse::<i64>()
                .ok()
        })
        .unwrap_or(0);
    assert_eq!(
        drops_after, drops,
        "a successfully delivered batch must not be double-counted as dropped"
    );

    terminate(&mut child);
}

/// The final metric snapshot must be taken AFTER the drain finishes, so it
/// includes traffic served during the drain itself.
///
/// This is the P2 review finding as an executable test, and it is
/// discriminating in a way a total-elapsed-time bound cannot be. The earlier
/// ordering fired the final export BEFORE `graceful_shutdown`; under that
/// ordering this test fails at the last assertion, because the "final"
/// snapshot was taken before request 2 ever arrived and permanently shows only
/// 2 of the 4 attempts actually served. Under the corrected ordering the
/// exporter is signalled after the drain returns and its snapshot carries the
/// drain-period request.
///
/// The drain accepts the second request because `Gradual`'s close probability
/// ramps linearly over the (default 600s) drain window -- at the instant after
/// SIGTERM it is still ~0, so a fresh connection is served normally. That is
/// exactly the traffic the old ordering lost.
#[tokio::test(flavor = "multi_thread")]
async fn the_final_snapshot_includes_traffic_served_during_drain() {
    let fallback_addr = spawn_slow_mock_upstream(Duration::from_millis(1_200));
    let primary_addr = dead_addr();
    // A 1.5s collector delay so the final export is a real, awaited RPC rather
    // than a race the loopback usually wins (verified by mutating `main.rs` to
    // signal without awaiting -- a delay-free variant of the shutdown test
    // stayed green). Fast enough that the process still exits inside
    // `terminate`'s 5s kill bound.
    // A 300ms collector delay: short enough that a pre-drain snapshot (built
    // at SIGTERM) arrives well BEFORE the in-flight request finishes, which is
    // what makes the arrival-time assertion below discriminating. The final
    // export is still a real, awaited RPC (verified by mutating `main.rs` to
    // signal without awaiting -- the shutdown-delivery test caught that).
    let (_spans, metrics, arrivals, collector_addr) =
        spawn_delayed_collector_with_arrivals(Duration::from_millis(300));
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
        OtlpEndpoints {
            traces: None,
            metrics: Some(MetricsBlock {
                endpoint: format!("http://127.0.0.1:{}", collector_addr.port()),
                interval_secs: 60.0,
                deadline_secs: 2.0,
            }),
        },
    );
    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "listener at 127.0.0.1:{listener_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&stderr_rx)
    );

    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let first = get(listener_addr, "/v1/chat/completions", "test.local");
    assert!(
        first.starts_with("HTTP/1.1 200"),
        "expected the first request to succeed against `fallback`, got:\n{first}"
    );

    // Start a SECOND request on its own thread, give it time to be in flight
    // (past `primary`'s instant connect-failure, into `fallback`'s 800ms
    // delay), THEN SIGTERM. The drain waits for the in-flight request -- that
    // is the traffic the old pre-drain snapshot ordering permanently lost.
    // Each successful request is one connect-failure attempt against `primary`
    // plus one success against `fallback`, so two requests = 4 total attempts.
    let slow = std::thread::spawn(move || get(listener_addr, "/v1/chat/completions", "test.local"));
    std::thread::sleep(Duration::from_millis(200));
    // SIGTERM without waiting: `terminate` blocks on process exit, which would
    // push `request2_done` past the final snapshot's arrival and make the
    // ordering assertion below vacuous.
    signal_term(&mut child);
    let second = slow
        .join()
        .expect("the in-flight request thread must not panic");
    let request2_done = std::time::Instant::now();
    assert!(
        wait_for_exit(&mut child, Duration::from_secs(20)),
        "the process must exit on its own after the drain; it was killed instead"
    );
    assert!(
        second.starts_with("HTTP/1.1 200"),
        "the drain must let an in-flight request finish (Gradual gives it the window), \
         got:\n{second}"
    );

    // The discriminator is ORDER, not content. This proxy's counters cannot
    // do it: `upstream_rq` increments at attempt DISPATCH (router.rs's
    // `record_attempt` site), so request 2's dispatches are already in the
    // registry while the request is in flight and a pre-drain snapshot carries
    // the same totals -- verified by mutation (moving the final export back
    // before the drain left an `upstream_rq >= 4` assertion green). And
    // `upstream_rq_time` turned out to be unusable too: request 2's in-flight
    // fallback attempt never contributes a duration observation in EITHER
    // ordering (empirically `fallback=1` in both; the attempt is still in
    // flight or killed at snapshot time), so a count-based assertion would
    // either pass under the mutation or fail under the fix.
    //
    // What DOES discriminate is when the final snapshot lands relative to the
    // in-flight request's completion. Under the corrected ordering the
    // exporter is signalled only after the drain returns -- which is after the
    // in-flight request finished -- so the final snapshot ARRIVES after
    // request 2 completed. Under the pre-drain ordering the snapshot is built
    // at SIGTERM, while request 2 still has ~1s of upstream delay left, and
    // with a 300ms collector delay it arrives first. The margin on both sides
    // is ~0.7-1s against a 50ms poll granularity.
    let final_deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let arrived_after = {
            let buf = metrics.lock().expect("mutex poisoned");
            let times = arrivals.lock().expect("arrivals mutex poisoned");
            buf.len() == times.len()
                && times.last().is_some_and(|t| *t > request2_done)
                // ...and the last snapshot actually carries the drain-period
                // request (2 requests x 2 attempts), so an EMPTY final
                // snapshot arriving late cannot satisfy this.
                && buf.last().is_some_and(|rm| {
                    rm.scope_metrics.iter().any(|sm| {
                        sm.metrics
                            .iter()
                            .any(|m| m.name == "upstream_rq" && total_of(m) >= 4)
                    })
                })
        };
        if arrived_after {
            break;
        }
        assert!(
            std::time::Instant::now() < final_deadline,
            "the final snapshot must ARRIVE after the drain-period request completed -- it is \
             taken after the drain finishes, so it both carries that traffic and lands later \
             than it. Under the pre-drain ordering the snapshot is built at SIGTERM and \
             arrives before the in-flight request finishes, missing its completion state -- \
             the exact bug the review flagged. stderr so far: {:?}",
            drain_available_lines(&stderr_rx)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Summed `AsInt` value of a `Sum`-typed metric's data points, or 0 for any
/// other shape. Shared by the shutdown test's "was this data ever delivered"
/// check, which walks nested `ResourceMetrics`/`ScopeMetrics` containers rather
/// than assuming indices.
fn total_of(metric: &proxy_api::opentelemetry::proto::metrics::v1::Metric) -> i64 {
    use proxy_api::opentelemetry::proto::metrics::v1::number_data_point::Value;
    match metric.data.as_ref() {
        Some(metric::Data::Sum(sum)) => sum
            .data_points
            .iter()
            .map(|p| match p.value {
                Some(Value::AsInt(v)) => v,
                _ => 0,
            })
            .sum(),
        _ => 0,
    }
}

/// Both surfaces can point at DIFFERENT collectors in the same config, and each
/// must reach its own. This is the deployment shape the separate `Endpoint`
/// per exporter exists for, and it is only expressible because the two config
/// fields are separate.
#[tokio::test(flavor = "multi_thread")]
async fn traces_and_metrics_can_target_different_collectors() {
    let (fallback_addr, _captured) = spawn_capturing_mock_upstream();
    let primary_addr = dead_addr();
    let (traces_spans, traces_metrics, traces_addr) = spawn_mock_collector();
    let (_other_spans, other_metrics, other_addr) = spawn_mock_collector();
    for addr in [traces_addr, other_addr] {
        assert!(
            wait_for_connectable(("127.0.0.1", addr.port()), STARTUP_TIMEOUT),
            "mock OTLP collector on {addr} never became connectable"
        );
    }

    let listener_port = free_port();
    let admin_port = free_port();
    let config_path = write_config(
        listener_port,
        admin_port,
        primary_addr,
        fallback_addr,
        OtlpEndpoints {
            traces: Some(TraceBlock::fast(format!(
                "http://127.0.0.1:{}",
                traces_addr.port()
            ))),
            metrics: Some(format!("http://127.0.0.1:{}", other_addr.port()).into()),
        },
    );
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

    wait_for_spans(&traces_spans, 3, Duration::from_secs(20)).await;
    assert_eq!(
        traces_spans.lock().expect("mutex poisoned").len(),
        3,
        "the TRACES collector must receive the spans"
    );

    // The metrics collector must receive the metric snapshot...
    wait_for_metric_totaling(&other_metrics, "upstream_rq", 2, Duration::from_secs(20))
        .await
        .expect("the METRICS collector must receive the registry snapshot");

    // ...and the traces collector must NOT, which is the half that proves they
    // really are separate connections rather than one endpoint that happens to
    // be named twice.
    assert!(
        traces_metrics.lock().expect("mutex poisoned").is_empty(),
        "the traces collector must not receive metric snapshots when the endpoints differ"
    );

    terminate(&mut child);
}
