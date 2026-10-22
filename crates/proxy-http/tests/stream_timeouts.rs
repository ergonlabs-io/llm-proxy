//! Exercises HCM stream timeouts against a handler and scripted socket
//! upstream, including stalled and continuously producing responses.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::collections::BTreeMap;
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
    AccessLogFormat, AccessLogIR, AccessLogSink, CircuitBreakerThresholds, CircuitBreakers,
    ClusterConfig, ClusterKind, ClusterName, DiscoveryType, EndpointIR, ForwardAction,
    ForwardTarget, LbPolicy, PathMatch, RouteActionIR, RouteEntry, RouteMatcher, RouteTable,
    VirtualHostIR,
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

/// Bounds handler waits so regressions fail instead of hanging the suite.
const BOUND: Duration = Duration::from_secs(10);

/// What the scripted upstream does once it has read a request head.
#[derive(Clone, Copy)]
enum Script {
    /// Accept and read the request without answering.
    Hang,
    /// Send `chunks` with `gap` between them; optionally stall before ending.
    Stream {
        chunks: u32,
        gap: Duration,
        stall: bool,
    },
}

async fn spawn_upstream(script: Script) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                match script {
                    Script::Hang => std::future::pending::<()>().await,
                    Script::Stream { chunks, gap, stall } => {
                        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                                    Transfer-Encoding: chunked\r\n\r\n";
                        if stream.write_all(head.as_bytes()).await.is_err() {
                            return;
                        }
                        for _ in 0..chunks {
                            if stream.write_all(b"9\r\ndata: x\n\n\r\n").await.is_err() {
                                return;
                            }
                            tokio::time::sleep(gap).await;
                        }
                        if stall {
                            std::future::pending::<()>().await;
                        }
                        let _ = stream.write_all(b"0\r\n\r\n").await;
                    }
                }
            });
        }
    });
    addr
}

struct Limits {
    /// Route `idle_timeout`.
    route_idle: Option<Duration>,
    /// HCM `stream_idle_timeout`.
    idle: Option<Duration>,
    /// HCM `max_stream_duration`.
    max: Option<Duration>,
}

fn temp_path() -> PathBuf {
    // Add a counter because concurrent tests can share a timestamp.
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "proxy-http-stream-timeouts-{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    p
}

fn read_flags(path: &Path) -> Vec<String> {
    assert!(proxy_observability::sink::flush_all_queued(
        Duration::from_secs(5)
    ));
    let mut s = String::new();
    File::open(path).unwrap().read_to_string(&mut s).unwrap();
    s.lines().map(str::to_owned).collect()
}

/// Uses a single-request breaker so leaked permits surface as `503 UO`.
async fn build_handler(addr: SocketAddr, limits: Limits) -> (FilterChainHandler, PathBuf) {
    let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
    let mut snapshot: std::collections::HashMap<ClusterName, Arc<ClusterConfig>> =
        Default::default();
    snapshot.insert(
        "up".to_string(),
        Arc::new(ClusterConfig {
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
            circuit_breakers: CircuitBreakers {
                default: CircuitBreakerThresholds {
                    max_requests: 1,
                    ..CircuitBreakerThresholds::ENVOY_DEFAULT
                },
                high: CircuitBreakerThresholds::ENVOY_DEFAULT,
            },
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

    let route_table = RouteTable::new(
        "test-routes".to_string(),
        vec![VirtualHostIR {
            name: "vh".to_string(),
            domains: vec!["*".to_string()],
            routes: vec![Arc::new(RouteEntry {
                name: None,
                matcher: RouteMatcher {
                    path: PathMatch::Prefix("/".to_string()),
                    case_sensitive: true,
                    headers: Vec::new(),
                },
                action: RouteActionIR::Forward(ForwardAction {
                    target: ForwardTarget::Cluster("up".to_string()),
                    timeout: None,
                    idle_timeout: limits.route_idle,
                    retry_policy: None,
                    host_rewrite_literal: None,
                    prefix_rewrite: None,
                }),
                request_headers_to_add: Vec::new(),
                streaming_strict: false,
                typed_per_filter_config: BTreeMap::new(),
                route_index: 0,
                include_request_attempt_count: false,
                include_attempt_count_in_response: false,
                include_routing_headers_in_response: false,
            })],
            typed_per_filter_config: BTreeMap::new(),
        }],
        BTreeMap::new(),
    )
    .unwrap();

    let control = StatsControl::new(1);
    let handles = Arc::new(StatHandles::build(&control, ["up"]));
    let stats = Arc::new(RouterStats::new(control.registry(), handles, WorkerId(0)));
    let terminal: Arc<dyn TerminalFilterInstanceFactory> =
        Arc::new(RouterFilterFactory::new(Arc::new(manager), stats));
    let log_path = temp_path();
    let handler = FilterChainHandler::new_with_access_logs(
        Vec::new(),
        terminal,
        Arc::new(route_table),
        false,
        false,
        0,
        &[AccessLogIR {
            sink: AccessLogSink::File {
                path: log_path.to_string_lossy().into_owned(),
            },
            format: AccessLogFormat::Text(parse_format("%RESPONSE_FLAGS%\n").unwrap()),
            filter: None,
        }],
    )
    .expect("temp access-log sink opens")
    .with_stream_timeouts(limits.idle, limits.max);
    (handler, log_path)
}

fn request() -> HttpRequestParts {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::GET,
            uri: Uri::from_static("/v1/stream"),
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

/// Returns the status and whether the response body finished cleanly.
async fn drive(handler: &FilterChainHandler) -> (StatusCode, bool) {
    tokio::time::timeout(BOUND, async {
        let resp = handler.handle(request()).await;
        let status = resp.head.status;
        let clean = resp.body.collect().await.is_ok();
        (status, clean)
    })
    .await
    .expect("request must finish within the bound")
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// A hung provider is cut with `408`/`SI`, and its breaker permit is released.
#[tokio::test(flavor = "current_thread")]
async fn a_provider_that_never_answers_is_cut_and_its_permit_released() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream(Script::Hang).await;
            let (handler, log) = build_handler(
                addr,
                Limits {
                    route_idle: None,
                    idle: Some(ms(150)),
                    max: None,
                },
            )
            .await;

            for _ in 0..2 {
                let (status, _) = drive(&handler).await;
                assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
            }
            assert_eq!(read_flags(&log), vec!["SI", "SI"]);
        })
        .await;
}

/// A continuously producing stream outlives the idle timeout without being cut.
#[tokio::test(flavor = "current_thread")]
async fn a_stream_that_keeps_producing_outlives_the_idle_timeout() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream(Script::Stream {
                chunks: 50,
                gap: ms(30),
                stall: false,
            })
            .await;
            let (handler, log) = build_handler(
                addr,
                Limits {
                    route_idle: None,
                    idle: Some(ms(1000)),
                    max: None,
                },
            )
            .await;

            let (status, clean) = drive(&handler).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                clean,
                "an active stream must not be cut by the idle timeout"
            );
            assert_eq!(read_flags(&log), vec!["-"]);
        })
        .await;
}

/// A stream that goes quiet after headers and some chunks is cut with `SI`.
#[tokio::test(flavor = "current_thread")]
async fn a_stream_that_goes_quiet_mid_body_is_cut() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream(Script::Stream {
                chunks: 2,
                gap: ms(10),
                stall: true,
            })
            .await;
            let (handler, log) = build_handler(
                addr,
                Limits {
                    route_idle: None,
                    idle: Some(ms(150)),
                    max: None,
                },
            )
            .await;

            let (status, clean) = drive(&handler).await;
            assert_eq!(status, StatusCode::OK, "headers were already sent");
            assert!(!clean, "the body must end in an error, not a clean finish");
            assert_eq!(read_flags(&log), vec!["SI"]);
        })
        .await;
}

/// Route `idle_timeout` overrides the HCM value for response body gaps.
#[tokio::test(flavor = "current_thread")]
async fn a_route_idle_timeout_overrides_the_hcm_value_for_the_body() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream(Script::Stream {
                chunks: 2,
                gap: ms(300),
                stall: false,
            })
            .await;
            let (handler, _log) = build_handler(
                addr,
                Limits {
                    route_idle: Some(Duration::from_secs(5)),
                    idle: Some(ms(100)),
                    max: None,
                },
            )
            .await;

            let (status, clean) = drive(&handler).await;
            assert_eq!(status, StatusCode::OK);
            assert!(clean, "the route idle_timeout must win over the HCM value");
        })
        .await;
}

/// `max_stream_duration` cuts an active stream with `UMSDR`.
#[tokio::test(flavor = "current_thread")]
async fn max_stream_duration_cuts_a_stream_that_is_still_producing() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream(Script::Stream {
                chunks: 400,
                gap: ms(20),
                stall: false,
            })
            .await;
            let (handler, log) = build_handler(
                addr,
                Limits {
                    route_idle: None,
                    idle: None,
                    max: Some(ms(300)),
                },
            )
            .await;

            let (status, clean) = drive(&handler).await;
            assert_eq!(status, StatusCode::OK);
            assert!(!clean, "an active stream must still be cut at the deadline");
            assert_eq!(read_flags(&log), vec!["UMSDR"]);
        })
        .await;
}

/// Before response headers `max_stream_duration` ends the wait with `504`
/// and `UMSDR`.
#[tokio::test(flavor = "current_thread")]
async fn max_stream_duration_cuts_the_wait_for_headers() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream(Script::Hang).await;
            let (handler, log) = build_handler(
                addr,
                Limits {
                    route_idle: None,
                    idle: None,
                    max: Some(ms(150)),
                },
            )
            .await;

            let (status, _) = drive(&handler).await;
            assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
            assert_eq!(read_flags(&log), vec!["UMSDR"]);
        })
        .await;
}
