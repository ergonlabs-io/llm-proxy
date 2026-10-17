//! Verify that access-log lines reach the configured sink, honor filters, and
//! include final byte counts and duration for streamed responses. Logging is
//! attached to `FilterChainHandler`, outside the router, so it observes the
//! encode chain through end-of-stream.
//!
//! Rust note: `send_upstream_http1` uses `spawn_local`, so tests need a
//! `LocalSet` on a current-thread runtime.

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

/// Return a unique temporary path that the test removes afterward.
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
    // Flush queued writes instead of sleeping for the background writer.
    assert!(proxy_observability::sink::flush_all_queued(
        Duration::from_secs(5)
    ));
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

/// Resolve one worker's router stats for the supplied cluster names.
fn test_router_stats(cluster_names: &[&str]) -> Arc<RouterStats> {
    let control = StatsControl::new(1);
    let handles = Arc::new(StatHandles::build(&control, cluster_names.iter().copied()));
    Arc::new(RouterStats::new(control.registry(), handles, WorkerId(0)))
}

/// Build a one-route handler forwarding `/v1/` to `up`. With `addr: None`,
/// the cluster is unregistered for the unknown-cluster test.
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
                // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
                eds: None,
                name: "up".to_string(),
                discovery: DiscoveryType::Static,
                lb_policy: LbPolicy::RoundRobin,
                connect_timeout: Duration::from_secs(5),
                endpoints: vec![EndpointIR {
                    metadata: Default::default(),
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
                request_path_rewrite: None,
                provider_runtime: None,
                usage_dialect: None,
                health_check: None,
                outlier_detection: None,
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
                streaming_strict: false,
                typed_per_filter_config: BTreeMap::new(),
                route_index: 0,
                include_request_attempt_count: false,
                include_attempt_count_in_response: false,
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
        on_upgrade: None,
    }
}

/// Answer once with `200 OK` and a fixed body.
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

/// Stream chunked frames with a delay before each, then close normally.
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

/// Verify `%REQ(:METHOD)%` renders the method despite `:method` being an
/// HTTP pseudo-header rather than a regular `HeaderName`.
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
                // Three `hello` frames contribute 15 response bytes.
                assert_eq!(collected.len(), 5 * frame_count);

                let logged = read_to_string(&path);
                let mut parts = logged.trim_end().split(' ');
                assert_eq!(parts.next().unwrap(), "200");
                let bytes_sent: u64 = parts.next().unwrap().parse().unwrap();
                let duration_ms: u64 = parts.next().unwrap().parse().unwrap();

                // The log must reflect completion of the full stream.
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
                    "%RESPONSE_CODE% %RESPONSE_FLAGS% %RESPONSE_CODE_DETAILS%\n",
                    None,
                )],
            )
            .await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::SERVICE_UNAVAILABLE);
            resp.body.collect().await.unwrap();

            let logged = read_to_string(&path);
            // An unknown cluster is distinct from a registered, unwarmed one;
            // both render as `NC`.
            assert_eq!(logged, "503 NC cluster_not_found\n");

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
            // An empty response-flag filter logs only when a flag fires.
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

            // The sink exists, but the filter prevented any line from being written.
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
            // Both loggers share one sink while retaining distinct formats.
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

/// Render `%COMMON_DURATION(DS_RX_BEG:X:ns)%` for each `X`, `|`-separated, and
/// report which points rendered a value.
fn rendered_points(line: &str, points: &[&str]) -> Vec<(String, bool)> {
    let fields: Vec<&str> = line.trim_end().split('|').collect();
    assert_eq!(fields.len(), points.len(), "{line:?}");
    points
        .iter()
        .zip(fields)
        .map(|(point, field)| {
            assert!(
                field == "-" || field.parse::<u64>().is_ok(),
                "{point}: {field:?}"
            );
            (point.to_string(), field != "-")
        })
        .collect()
}

fn offsets_format(points: &[&str]) -> String {
    let fields: Vec<String> = points
        .iter()
        .map(|p| format!("%COMMON_DURATION(DS_RX_BEG:{p}:ns)%"))
        .collect();
    format!("{}\n", fields.join("|"))
}

const ALL_POINTS: [&str; 12] = [
    "DS_RX_BEG",
    "DS_RX_END",
    "US_CX_BEG",
    "US_CX_END",
    "US_HS_END",
    "US_TX_BEG",
    "US_TX_END",
    "US_RX_BEG",
    "US_RX_BODY_BEG",
    "US_RX_END",
    "DS_TX_BEG",
    "DS_TX_END",
];

/// A local reply never reaches an upstream: every `US_*` point renders `-`,
/// while the downstream points the request did reach still render.
#[tokio::test(flavor = "current_thread")]
async fn a_local_reply_has_downstream_points_and_no_upstream_points() {
    LocalSet::new()
        .run_until(async {
            let path = temp_path("common-duration-local");
            let handler = build_router(
                None,
                vec![text_logger(&path, &offsets_format(&ALL_POINTS), None)],
            )
            .await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::SERVICE_UNAVAILABLE);
            resp.body.collect().await.unwrap();

            let line = read_to_string(&path);
            for (point, present) in rendered_points(&line, &ALL_POINTS) {
                let expected = point.starts_with("DS_");
                assert_eq!(present, expected, "{point} in {line:?}");
            }
            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

/// A provider that dies mid-body: the response head and first body bytes
/// arrived, but neither the upstream nor the downstream stream ended, so
/// `US_RX_END` and `DS_TX_END` render `-`.
#[tokio::test(flavor = "current_thread")]
async fn a_response_cut_mid_body_has_no_rx_end_or_tx_end() {
    LocalSet::new()
        .run_until(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
                    .await;
                // Dropping the stream closes it 93 bytes short.
            });
            let path = temp_path("common-duration-cut");
            let handler = build_router(
                Some(addr),
                vec![text_logger(&path, &offsets_format(&ALL_POINTS), None)],
            )
            .await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);
            assert!(resp.body.collect().await.is_err());

            let line = read_to_string(&path);
            for (point, present) in rendered_points(&line, &ALL_POINTS) {
                let expected = !matches!(point.as_str(), "US_HS_END" | "US_RX_END" | "DS_TX_END");
                assert_eq!(present, expected, "{point} in {line:?}");
            }
            std::fs::remove_file(&path).unwrap();
        })
        .await;
}
