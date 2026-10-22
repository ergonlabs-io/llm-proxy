//! The "local 503 response" warning is throttled per (listener, cluster,
//! response flags) (AGENTS.md "Fail-open controls"): a circuit breaker that
//! refuses every request must not write one log line per refusal, while the
//! access log keeps recording every 503.
//!
//! The refusal is real: cluster `"up"` has `max_requests: 0`, so the router
//! answers `503 UO` before it dials anything. Time is tokio's paused clock,
//! so the test advances past the window instead of sleeping.
//!
//! Rust note: `current_thread` with `start_paused` keeps the throttle's
//! per-worker state, the tracing default and the clock on one thread.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
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
    UpstreamProtocol, VirtualHostIR,
};
use proxy_http::filter::{RequestHeaders, TerminalFilterInstanceFactory};
use proxy_http::filter_manager::FilterChainHandler;
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
use proxy_http::router::RouterFilterFactory;
use proxy_http::stat_handles::{RouterStats, StatHandles};
use proxy_observability::access_log::parse_format;
use proxy_observability::stats::{StatsControl, WorkerId};
use tokio::task::LocalSet;

/// A `tracing` writer that appends to a shared buffer.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn warning_lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|line| line.contains("local 503 response"))
            .map(str::to_owned)
            .collect()
    }
}

fn temp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "proxy-http-local-503-log-{}-{}-{}",
        std::process::id(),
        name,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    p
}

async fn circuit_broken_router(access_log: &std::path::Path) -> FilterChainHandler {
    let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
    let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
    snapshot.insert(
        "up".to_string(),
        Arc::new(ClusterConfig {
            eds: None,
            name: "up".to_string(),
            discovery: DiscoveryType::Static,
            lb_policy: LbPolicy::RoundRobin,
            connect_timeout: Duration::from_secs(5),
            // Never dialled: the breaker refuses first.
            endpoints: vec![EndpointIR {
                metadata: Default::default(),
                host: "127.0.0.1".to_string(),
                port: 9,
                weight: 1,
                priority: 0,
            }],
            kind: ClusterKind::Endpoints,
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1 << 20,
            circuit_breakers: CircuitBreakers {
                default: CircuitBreakerThresholds {
                    max_requests: 0,
                    ..CircuitBreakerThresholds::ENVOY_DEFAULT
                },
                high: CircuitBreakerThresholds::ENVOY_DEFAULT,
            },
            upstream_protocol: UpstreamProtocol::Http1,
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
                    path: PathMatch::Prefix("/v1/".to_string()),
                    case_sensitive: true,
                    headers: Vec::new(),
                },
                action: RouteActionIR::Forward(ForwardAction {
                    target: ForwardTarget::Cluster("up".into()),
                    timeout: None,
                    idle_timeout: None,
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
    let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> = Arc::new(
        RouterFilterFactory::new(Arc::new(manager), stats).with_config_context("ingress".into(), 7),
    );
    FilterChainHandler::new_with_access_logs(
        Vec::new(),
        terminal_factory,
        Arc::new(route_table),
        false,
        false,
        0,
        &[AccessLogIR {
            sink: AccessLogSink::File {
                path: access_log.to_string_lossy().into_owned(),
            },
            format: AccessLogFormat::Text(
                parse_format("%RESPONSE_CODE% %RESPONSE_FLAGS%\n").unwrap(),
            ),
            filter: None,
        }],
    )
    .unwrap()
}

fn request() -> HttpRequestParts {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
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

async fn send_503s(handler: &FilterChainHandler, count: usize) {
    for _ in 0..count {
        let resp = handler.handle(request()).await;
        assert_eq!(resp.head.status, StatusCode::SERVICE_UNAVAILABLE);
        resp.body.collect().await.unwrap();
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn circuit_breaker_503s_log_once_per_window_with_suppressed_count() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _default = tracing::subscriber::set_default(subscriber);

    LocalSet::new()
        .run_until(async {
            let path = temp_path("uo");
            let handler = circuit_broken_router(&path).await;

            // A burst inside one window: one line, nothing suppressed yet.
            send_503s(&handler, 500).await;
            let lines = captured.warning_lines();
            assert_eq!(lines.len(), 1, "{lines:#?}");
            assert!(lines[0].contains("WARN"), "{}", lines[0]);
            assert!(lines[0].contains("listener=\"ingress\""), "{}", lines[0]);
            assert!(lines[0].contains("suppressed=0"), "{}", lines[0]);
            assert!(lines[0].contains("UpstreamOverflow"), "{}", lines[0]);

            // The next window's first 503 logs again and reports the 499
            // that were dropped; the rest of that window stays quiet.
            tokio::time::advance(Duration::from_secs(11)).await;
            send_503s(&handler, 100).await;
            let lines = captured.warning_lines();
            assert_eq!(lines.len(), 2, "{lines:#?}");
            assert!(lines[1].contains("suppressed=499"), "{}", lines[1]);

            // The access log is not throttled: every 503 is recorded.
            assert!(proxy_observability::sink::flush_all_queued(
                Duration::from_secs(5)
            ));
            let access = std::fs::read_to_string(&path).unwrap();
            assert_eq!(access.lines().count(), 600);
            assert!(access.lines().all(|line| line == "503 UO"), "{access}");
            std::fs::remove_file(&path).unwrap();
        })
        .await;
}
