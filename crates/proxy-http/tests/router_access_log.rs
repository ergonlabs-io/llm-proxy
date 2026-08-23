//! WP-24 chunk 3: proves access logs actually emit -- rendered lines land in
//! the configured sink, honoring `AccessLogIR.filter`, and (the mistake this
//! chunk exists to catch) a streamed response's line carries the *final*
//! byte count and a duration covering the whole stream, not just the time to
//! response headers.
//!
//! Relocated (see `proxy_http::access_logging`'s and
//! `proxy_http::filter_manager`'s module docs): access logging now lives on
//! `FilterChainHandler`, one level above the router, not on `RouterHandler`
//! itself -- the router sits INSIDE the encode filter chain, so logging from
//! there could never observe what an encode filter does at end-of-stream.
//! These tests build a `FilterChainHandler` with no configured HTTP filters
//! (nothing here exercises the filter chain itself) wrapping a real
//! `RouterHandler` terminal, and drive requests through the *handler*, not
//! the bare router.
//!
//! Standalone (not `router.rs`'s own `#[cfg(test)]` module), same reasoning
//! as `router_retry.rs`/`router_header_mutations.rs`: a fresh, focused set
//! of upstream/file-reading helpers.
//!
//! Rust note: same shape as `router.rs`'s own tests -- `send_upstream_http1`
//! spawns a non-`Send` connection driver task via `tokio::task::spawn_local`,
//! so every test needs a `LocalSet` on a `current_thread` runtime.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::resolver::FakeResolver;
use proxy_config::ir::{
    AccessLogFilterIR, AccessLogFormat, AccessLogIR, AccessLogSink, ClusterConfig, ClusterKind,
    ClusterName, DiscoveryType, EndpointIR, ForwardAction, ForwardTarget, LbPolicy, PathMatch,
    RouteActionIR, RouteEntry, RouteMatcher, RouteTable, VirtualHostIR,
};
use proxy_http::filter::{RequestHeaders, TerminalFilterInstanceFactory};
use proxy_http::filter_manager::FilterChainHandler;
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
use proxy_http::router::RouterFilterFactory;
use proxy_http::stat_handles::{RouterStats, StatHandles};
use proxy_observability::access_log::parse_format;
use proxy_observability::stats::{StatsControl, WorkerId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::LocalSet;

/// A unique path under the OS temp dir, cleaned up by each test itself --
/// same technique as `proxy_observability::sink`'s own tests.
fn temp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "proxy-http-access-log-test-{}-{}-{}",
        std::process::id(),
        name,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    p
}

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    File::open(path).unwrap().read_to_string(&mut s).unwrap();
    s
}

fn text_logger(path: &Path, format: &str, filter: Option<AccessLogFilterIR>) -> AccessLogIR {
    AccessLogIR {
        sink: AccessLogSink::File {
            path: path.to_string_lossy().into_owned(),
        },
        format: AccessLogFormat::Text(parse_format(format).unwrap()),
        filter,
    }
}

fn prefix_matcher(prefix: &str) -> RouteMatcher {
    RouteMatcher {
        path: PathMatch::Prefix(prefix.to_string()),
        case_sensitive: true,
        headers: Vec::new(),
    }
}

fn forward_to(cluster: &str) -> ForwardAction {
    ForwardAction {
        target: ForwardTarget::Cluster(cluster.to_string()),
        timeout: None,
        idle_timeout: None,
        retry_policy: None,
        host_rewrite_literal: None,
        prefix_rewrite: None,
    }
}

/// WP-23 increment 6a: a fresh, single-worker [`RouterStats`] resolved for
/// exactly `cluster_names` -- what [`RouterFilterFactory::new`] needs,
/// mirroring how `crates/proxy/src/main.rs` builds the real one from the
/// boot config snapshot's cluster names.
fn test_router_stats(cluster_names: &[&str]) -> Arc<RouterStats> {
    let control = StatsControl::new(1);
    let handles = Arc::new(StatHandles::build(&control, cluster_names.iter().copied()));
    Arc::new(RouterStats::new(control.registry(), handles, WorkerId(0)))
}

/// Build a one-route `FilterChainHandler` (no configured HTTP filters, a
/// real `RouterHandler` terminal) forwarding `/v1/` to a cluster named `"up"`
/// at `addr` (when `addr` is `Some`; `None` leaves `"up"` entirely
/// unregistered, for the unknown-cluster/`NC` test), with `access_logs`
/// wired through `FilterChainHandler::new_with_access_logs` -- mirrors
/// `router_retry.rs`'s own `build_router` helper plus the field this file
/// exists to exercise.
async fn build_router(
    addr: Option<SocketAddr>,
    access_logs: Vec<AccessLogIR>,
) -> FilterChainHandler {
    let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
    if let Some(addr) = addr {
        let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
        snapshot.insert(
            "up".to_string(),
            Arc::new(ClusterConfig {
                name: "up".to_string(),
                discovery: DiscoveryType::Static,
                lb_policy: LbPolicy::RoundRobin,
                connect_timeout: Duration::from_secs(5),
                endpoints: vec![EndpointIR {
                    host: addr.ip().to_string(),
                    port: addr.port(),
                    weight: 1,
                    priority: 0,
                }],
                kind: ClusterKind::Endpoints,
                transport_socket: None,
                per_connection_buffer_limit_bytes: 1 << 20,
                circuit_breakers: proxy_config::ir::CircuitBreakers::default(),
                upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
                request_headers_to_add: Vec::new(),
                usage_dialect: None,
                health_check: None,
            }),
        );
        manager.update_from_snapshot(&snapshot).await;
    }

    let route_table = RouteTable::new(
        "test-routes".to_string(),
        vec![VirtualHostIR {
            name: "vh".to_string(),
            domains: vec!["*".to_string()],
            routes: vec![Arc::new(RouteEntry {
                name: None,
                matcher: prefix_matcher("/v1/"),
                action: RouteActionIR::Forward(forward_to("up")),
                request_headers_to_add: Vec::new(),
                typed_per_filter_config: BTreeMap::new(),
                route_index: 0,
            })],
            typed_per_filter_config: BTreeMap::new(),
        }],
        BTreeMap::new(),
    )
    .unwrap();

    let route_table = Arc::new(route_table);
    let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> = Arc::new(
        RouterFilterFactory::new(Arc::new(manager), test_router_stats(&["up"])),
    );
    FilterChainHandler::new_with_access_logs(
        Vec::new(),
        terminal_factory,
        route_table,
        false,
        false,
        0,
        &access_logs,
    )
    .expect("test access-log sinks (temp files/stdout) always open cleanly")
}

fn request(path: &'static str) -> HttpRequestParts {
    request_with_method(Method::GET, path)
}

fn request_with_method(method: Method, path: &'static str) -> HttpRequestParts {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    HttpRequestParts {
        head: RequestHeaders {
            method,
            uri: Uri::from_static(path),
            headers,
        },
        body: local_boxed(
            Full::new(Bytes::new())
                .map_err(|infallible: std::convert::Infallible| match infallible {}),
        ),
        downstream: DownstreamInfo::loopback(),
    }
}

/// A one-shot upstream that answers `200 OK` with a small fixed body,
/// immediately.
async fn spawn_upstream_ok(body: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(body).await;
    });
    addr
}

/// An upstream that streams `frame_count` chunked body frames, each preceded
/// by `gap`, then closes normally -- long enough in total that a log line
/// written at header-flush time (rather than stream-end) would report a
/// duration and byte count from long before the stream actually finished.
async fn spawn_upstream_streaming_slowly(frame_count: usize, gap: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        for _ in 0..frame_count {
            tokio::time::sleep(gap).await;
            stream.write_all(b"5\r\nhello\r\n").await.unwrap();
        }
        stream.write_all(b"0\r\n\r\n").await.unwrap();
    });
    addr
}

#[tokio::test(flavor = "current_thread")]
async fn successful_proxied_request_writes_one_line_with_status_and_path() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream_ok(b"hi").await;
            let path = temp_path("success");
            let handler = build_router(
                Some(addr),
                vec![text_logger(
                    &path,
                    "%RESPONSE_CODE% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%\n",
                    None,
                )],
            )
            .await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);
            resp.body.collect().await.unwrap();

            let logged = read_to_string(&path);
            assert_eq!(logged, "200 /v1/chat/completions\n");

            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

/// The bug this test exists to catch: `%REQ(:METHOD)%` (part of Envoy's OWN
/// default access-log format) used to always render `-` -- no pseudo-header
/// could ever match a real `http::HeaderName`-based lookup -- so every
/// access log this proxy wrote was missing the request method.
#[tokio::test(flavor = "current_thread")]
async fn req_method_pseudo_header_carries_the_real_method_not_a_dash() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream_ok(b"hi").await;
            let path = temp_path("req-method");
            let handler = build_router(
                Some(addr),
                vec![text_logger(&path, "%REQ(:METHOD)%\n", None)],
            )
            .await;

            let resp = handler
                .handle(request_with_method(Method::POST, "/v1/chat/completions"))
                .await;
            assert_eq!(resp.head.status, StatusCode::OK);
            resp.body.collect().await.unwrap();

            let logged = read_to_string(&path);
            assert_eq!(logged, "POST\n");

            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn streamed_response_logs_full_bytes_sent_and_a_duration_covering_the_whole_stream() {
    tokio::time::timeout(Duration::from_secs(5), async {
        LocalSet::new()
            .run_until(async {
                let gap = Duration::from_millis(60);
                let frame_count = 4;
                let addr = spawn_upstream_streaming_slowly(frame_count, gap).await;
                let path = temp_path("streamed");
                let handler = build_router(
                    Some(addr),
                    vec![text_logger(
                        &path,
                        "%RESPONSE_CODE% %BYTES_SENT% %DURATION%\n",
                        None,
                    )],
                )
                .await;

                let resp = handler.handle(request("/v1/chat/completions")).await;
                assert_eq!(resp.head.status, StatusCode::OK);
                let collected = resp.body.collect().await.unwrap().to_bytes();
                // Every frame ("hello", 5 bytes) made it through.
                assert_eq!(collected.len(), 5 * frame_count);

                let logged = read_to_string(&path);
                let mut parts = logged.trim_end().split(' ');
                assert_eq!(parts.next().unwrap(), "200");
                let bytes_sent: u64 = parts.next().unwrap().parse().unwrap();
                let duration_ms: u64 = parts.next().unwrap().parse().unwrap();

                // The bug this test exists to catch: logging at
                // header-flush time would report 0 bytes and ~0ms, not the
                // full stream.
                assert_eq!(
                    bytes_sent,
                    (5 * frame_count) as u64,
                    "bytes_sent must reflect the whole streamed body, not just the headers"
                );
                let min_expected_ms = gap.as_millis() as u64 * frame_count as u64;
                assert!(
                    duration_ms >= min_expected_ms,
                    "duration ({duration_ms}ms) must cover the whole stream (>= {min_expected_ms}ms)"
                );

                std::fs::remove_file(&path).unwrap();
            })
            .await;
    })
    .await
    .expect("should complete well within the test's own guard timeout");
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_cluster_records_and_renders_the_nc_flag() {
    LocalSet::new()
        .run_until(async {
            let path = temp_path("nc-flag");
            // No upstream address registered for cluster "up" at all.
            let handler = build_router(
                None,
                vec![text_logger(
                    &path,
                    "%RESPONSE_CODE% %RESPONSE_FLAGS%\n",
                    None,
                )],
            )
            .await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::SERVICE_UNAVAILABLE);
            resp.body.collect().await.unwrap();

            let logged = read_to_string(&path);
            assert_eq!(logged, "503 NC\n");

            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_request_excluded_by_the_access_log_filter_produces_no_line() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream_ok(b"hi").await;
            let path = temp_path("filtered-out");
            // An empty `ResponseFlag` filter list means "log only if *some*
            // flag fired" (Envoy semantics) -- a plain successful request
            // fires none, so this logger must produce nothing for it.
            let handler = build_router(
                Some(addr),
                vec![text_logger(
                    &path,
                    "%RESPONSE_CODE%\n",
                    Some(AccessLogFilterIR::ResponseFlag(Vec::new())),
                )],
            )
            .await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);
            resp.body.collect().await.unwrap();

            // The sink was still opened (the file exists, created on
            // `FileSink::new`), but no line was ever written to it.
            assert_eq!(read_to_string(&path), "");

            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn two_loggers_on_the_same_file_path_share_one_sink_and_interleave_whole_lines() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream_ok(b"hi").await;
            let path = temp_path("shared-sink");
            // Two independently-configured loggers naming the same file,
            // each with a distinct format -- proves they share one
            // `FileSink` (one `BufWriter`/`Mutex`) rather than each opening
            // their own handle and corrupting each other's writes.
            let handler = build_router(
                Some(addr),
                vec![
                    text_logger(&path, "first %RESPONSE_CODE%\n", None),
                    text_logger(&path, "second %RESPONSE_CODE%\n", None),
                ],
            )
            .await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);
            resp.body.collect().await.unwrap();

            let logged = read_to_string(&path);
            let lines: Vec<&str> = logged.lines().collect();
            assert_eq!(
                lines,
                vec!["first 200", "second 200"],
                "both loggers' lines must land intact, in config order, in the shared file"
            );

            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn no_access_logs_configured_writes_nothing_and_behaves_like_before() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream_ok(b"hi").await;
            let handler = build_router(Some(addr), Vec::new()).await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);
            let collected = resp.body.collect().await.unwrap().to_bytes();
            assert_eq!(collected.as_ref(), b"hi");
        })
        .await;
}
