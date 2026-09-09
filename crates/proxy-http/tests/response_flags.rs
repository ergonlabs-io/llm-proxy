//! WP-24's remaining acceptance criterion: "every response flag reachable by
//! at least one test." This file drives the REAL condition behind each
//! reachable flag not already covered elsewhere (see the crate-level test
//! files this complements: `router_access_log.rs` for `NC`,
//! `router_retry.rs` for `URX`, and `proxy-filters`'
//! `token_limit_filter.rs` for `RL`) and asserts on the RENDERED
//! `%RESPONSE_FLAGS%` line, not the enum -- the rendering is the contract
//! (see `proxy_observability::flags::render_flags`'s callers).
//!
//! Every test here builds a one-cluster, one-route `FilterChainHandler` with
//! a real access logger and drives an actual failing condition (a refused
//! TCP connect, a hung upstream, a zero-endpoint cluster, ...) through it --
//! never `set_response_flag` called directly. A flag that cannot be driven
//! this way belongs in `internal-docs/envoy-divergences.md`'s response-flags table,
//! not here (see that doc for the full per-flag audit).
//!
//! Rust note: same shape as `router_access_log.rs`/`router.rs`'s own tests
//! -- `send_upstream_http1` spawns a non-`Send` connection driver task via
//! `tokio::task::spawn_local`, so every test needs a `LocalSet` on a
//! `current_thread` runtime.

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
    AccessLogFormat, AccessLogIR, AccessLogSink, CircuitBreakerThresholds, CircuitBreakers,
    ClusterConfig, ClusterKind, ClusterName, DiscoveryType, EdsClusterConfig, EndpointIR,
    ForwardAction, ForwardTarget, LbPolicy, PathMatch, RouteActionIR, RouteEntry, RouteMatcher,
    RouteTable, UpgradeConfig, VirtualHostIR,
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

// --- shared scaffolding (same conventions as `router_access_log.rs`) -------

fn temp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "proxy-http-response-flags-test-{}-{}-{}",
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

fn text_logger(path: &Path, format: &str) -> AccessLogIR {
    AccessLogIR {
        sink: AccessLogSink::File {
            path: path.to_string_lossy().into_owned(),
        },
        format: AccessLogFormat::Text(parse_format(format).unwrap()),
        filter: None,
    }
}

fn prefix_matcher(prefix: &str) -> RouteMatcher {
    RouteMatcher {
        path: PathMatch::Prefix(prefix.to_string()),
        case_sensitive: true,
        headers: Vec::new(),
    }
}

fn forward_to(fwd: ForwardTarget) -> ForwardAction {
    ForwardAction {
        target: fwd,
        timeout: None,
        idle_timeout: None,
        retry_policy: None,
        host_rewrite_literal: None,
        prefix_rewrite: None,
    }
}

fn test_router_stats(cluster_names: &[&str]) -> Arc<RouterStats> {
    let control = StatsControl::new(1);
    let handles = Arc::new(StatHandles::build(&control, cluster_names.iter().copied()));
    Arc::new(RouterStats::new(control.registry(), handles, WorkerId(0)))
}

/// The knobs every test in this file needs to vary: the route's own path
/// matcher (so `NR` can mismatch it), whether/how many endpoints cluster
/// `"up"` has (`UH` needs zero), its circuit breakers (`UO` needs
/// `max_requests: 0`), the forward action (timeouts, for `UT`), and (WP-58)
/// its discovery type -- `Eds` with no `accept_eds_update` ever sent is how a
/// cluster is made to sit registered-but-never-warmed, the real condition
/// behind `cluster_not_warmed` (see `ClusterManager::resolve_cluster`'s doc:
/// an EDS cluster's `initialized` flag is untouched by `update_from_snapshot`,
/// unlike every other discovery type).
struct Scenario {
    route_matcher: RouteMatcher,
    endpoints: Vec<EndpointIR>,
    circuit_breakers: CircuitBreakers,
    fwd: ForwardAction,
    /// `UR` is the only flag here that needs h2: REFUSED_STREAM is a
    /// stream-level reset, and h1 has no such frame.
    protocol: proxy_config::ir::UpstreamProtocol,
    discovery: DiscoveryType,
    eds: Option<EdsClusterConfig>,
    /// WP-58: the upgrade path's own `NoClusterFound`/warming check needs an
    /// enabled upgrade type to ever reach `handle_upgrade` at all -- empty
    /// (the default) is what every non-upgrade test here wants.
    upgrade_configs: Vec<UpgradeConfig>,
}

impl Scenario {
    fn forwarding_to(addr: SocketAddr, fwd: ForwardAction) -> Self {
        Scenario {
            route_matcher: prefix_matcher("/v1/"),
            endpoints: vec![EndpointIR {
                metadata: Default::default(),
                host: addr.ip().to_string(),
                port: addr.port(),
                weight: 1,
                priority: 0,
            }],
            circuit_breakers: CircuitBreakers::default(),
            fwd,
            protocol: proxy_config::ir::UpstreamProtocol::Http1,
            discovery: DiscoveryType::Static,
            eds: None,
            upgrade_configs: Vec::new(),
        }
    }

    /// WP-58: a cluster that's registered but has never completed its first
    /// resolution -- `Eds` discovery, no endpoints, and (crucially) the
    /// caller never calls `ClusterManager::accept_eds_update` on it, so
    /// `is_initialized` stays `false` forever. No live upstream is needed:
    /// every test using this must be refused before any dial is attempted.
    fn warming(fwd: ForwardAction) -> Self {
        Scenario {
            route_matcher: prefix_matcher("/v1/"),
            endpoints: Vec::new(),
            circuit_breakers: CircuitBreakers::default(),
            fwd,
            protocol: proxy_config::ir::UpstreamProtocol::Http1,
            discovery: DiscoveryType::Eds,
            eds: Some(EdsClusterConfig {
                service_name: "up".to_string(),
            }),
            upgrade_configs: Vec::new(),
        }
    }
}

async fn build_router(scenario: Scenario, access_logs: &[AccessLogIR]) -> FilterChainHandler {
    let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
    let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
    snapshot.insert(
        "up".to_string(),
        Arc::new(ClusterConfig {
            eds: scenario.eds,
            name: "up".to_string(),
            discovery: scenario.discovery,
            lb_policy: LbPolicy::RoundRobin,
            connect_timeout: Duration::from_secs(5),
            endpoints: scenario.endpoints,
            kind: ClusterKind::Endpoints,
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1 << 20,
            circuit_breakers: scenario.circuit_breakers,
            upstream_protocol: scenario.protocol,
            request_headers_to_add: Vec::new(),
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
                matcher: scenario.route_matcher,
                action: RouteActionIR::Forward(scenario.fwd),
                request_headers_to_add: Vec::new(),
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

    let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> = Arc::new(
        RouterFilterFactory::new(Arc::new(manager), test_router_stats(&["up"]))
            .with_upgrade_configs(scenario.upgrade_configs),
    );
    FilterChainHandler::new_with_access_logs(
        Vec::new(),
        terminal_factory,
        Arc::new(route_table),
        false,
        false,
        0,
        access_logs,
    )
    .expect("test access-log sinks (temp files) always open cleanly")
}

fn request(path: &'static str) -> HttpRequestParts {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::GET,
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

/// WP-58: a request carrying `Upgrade: websocket` -- routes through
/// `RouterHandler::handle_upgrade` rather than `apply_forward`, which is
/// exactly the bypass this file's warming tests need to rule out. Same shape
/// as `router_upgrade_e2e.rs`'s own `upgrade_request` (duplicated here, same
/// reasoning as that file's doc: each `tests/*.rs` is its own compilation
/// unit).
fn upgrade_request(path: &'static str) -> HttpRequestParts {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(
        http::header::CONNECTION,
        HeaderValue::from_static("Upgrade"),
    );
    let mut synthetic = http::Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(())
        .unwrap();
    let on_upgrade = hyper::upgrade::on(&mut synthetic);
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::GET,
            uri: Uri::from_static(path),
            headers,
        },
        body: local_boxed(
            Full::new(Bytes::new())
                .map_err(|infallible: std::convert::Infallible| match infallible {}),
        ),
        downstream: DownstreamInfo::loopback(),
        on_upgrade: Some(on_upgrade),
    }
}

/// A one-shot upstream that answers `200 OK` immediately -- used only where a
/// test needs SOME live host to prove a sibling condition doesn't also fire.
async fn spawn_upstream_ok() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    });
    addr
}

/// An address nothing is listening on -- bind a listener to grab a genuinely
/// free port, then drop it before returning, so the connect below is
/// refused (`ECONNREFUSED`) rather than landing on some other service.
async fn refused_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// Accepts the connection, reads the request, then answers with bytes that
/// are not a valid HTTP status line at all -- `hyper`'s client fails to
/// parse a response out of this, which is exactly `UpstreamCodecError::Send`
/// (see `codec.rs::send_upstream_http1`), the real condition behind `UC`.
async fn spawn_upstream_garbage_response() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(b"not an http response at all\r\n\r\n")
            .await;
        let _ = stream.shutdown().await;
    });
    addr
}

/// Accepts the connection and reads the request, then never answers --
/// proves the route's own `timeout` (not a connect-level failure) is what
/// ends the request, the real condition behind `UT`.
async fn spawn_hanging_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        std::future::pending::<()>().await;
    });
    addr
}

/// Answers with chunked headers and one body frame, then stalls forever
/// without closing -- the real condition `idle_timeout` (S4, `SI`) exists to
/// bound.
async fn spawn_upstream_that_stalls_mid_body() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await;
        let _ = stream.write_all(b"5\r\nhello\r\n").await;
        std::future::pending::<()>().await;
    });
    addr
}

// --- NR: no route matched --------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn no_route_matched_records_and_renders_the_nr_flag() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream_ok().await;
            let path = temp_path("nr-flag");
            // The only route matches "/v1/"; the request below asks for
            // something else entirely.
            let handler = build_router(
                Scenario::forwarding_to(addr, forward_to(ForwardTarget::Cluster("up".into()))),
                &[text_logger(&path, "%RESPONSE_CODE% %RESPONSE_FLAGS%\n")],
            )
            .await;

            let resp = handler.handle(request("/no-such-route")).await;
            assert_eq!(resp.head.status, StatusCode::NOT_FOUND);
            resp.body.collect().await.unwrap();

            assert_eq!(read_to_string(&path), "404 NR\n");
            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

// --- UH: no healthy upstream host -------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn zero_endpoints_records_and_renders_the_uh_flag() {
    LocalSet::new()
        .run_until(async {
            let path = temp_path("uh-flag");
            let mut scenario = Scenario::forwarding_to(
                // Placeholder address: overwritten to zero endpoints below,
                // so nothing ever actually dials it.
                "127.0.0.1:1".parse().unwrap(),
                forward_to(ForwardTarget::Cluster("up".into())),
            );
            scenario.endpoints = Vec::new();
            let handler = build_router(
                scenario,
                &[text_logger(
                    &path,
                    "%RESPONSE_CODE% %RESPONSE_FLAGS% %RESPONSE_CODE_DETAILS%\n",
                )],
            )
            .await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::SERVICE_UNAVAILABLE);
            resp.body.collect().await.unwrap();

            assert_eq!(
                read_to_string(&path),
                "503 UH no_healthy_upstream\n",
                "WP-58: an initialized cluster whose hosts are all ejected/absent must render \
                 UH + no_healthy_upstream, NOT cluster_not_warmed -- see \
                 `cluster_not_warmed_is_distinguishable_from_all_hosts_ejected` for the direct \
                 comparison"
            );
            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

// --- WP-58: a never-warmed cluster must be distinguishable from UH ----------
//
// `internal-docs/IMPLEMENTATION_PLAN.md`'s WP-21 card: "nothing consults
// `is_initialized` before routing, so an un-initialized cluster still fails a
// request through the same generic `NoHealthyUpstream` path as a cluster
// whose hosts are all ejected". These three tests are the fix's acceptance
// criteria: the warming case renders `NC` (not `UH`) with a
// `cluster_not_warmed` detail, through BOTH `apply_forward` and
// `handle_upgrade` (the bypass risk a check on only one site would leave),
// and is provably distinct from the ejected-hosts case above.

#[tokio::test(flavor = "current_thread")]
async fn cluster_not_warmed_records_and_renders_the_nc_flag_via_forward() {
    LocalSet::new()
        .run_until(async {
            let path = temp_path("warming-flag-forward");
            let scenario = Scenario::warming(forward_to(ForwardTarget::Cluster("up".into())));
            let handler = build_router(
                scenario,
                &[text_logger(
                    &path,
                    "%RESPONSE_CODE% %RESPONSE_FLAGS% %RESPONSE_CODE_DETAILS%\n",
                )],
            )
            .await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::SERVICE_UNAVAILABLE);
            resp.body.collect().await.unwrap();

            assert_eq!(
                read_to_string(&path),
                "503 NC cluster_not_warmed\n",
                "a cluster that exists but never completed its first resolution must render NC \
                 (matching Envoy's real `cluster == nullptr` path for a warming cluster) with a \
                 details string that tells it apart from an unknown cluster or an ejected one"
            );
            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn cluster_not_warmed_records_and_renders_the_nc_flag_via_upgrade() {
    LocalSet::new()
        .run_until(async {
            let path = temp_path("warming-flag-upgrade");
            let mut scenario = Scenario::warming(forward_to(ForwardTarget::Cluster("up".into())));
            scenario.upgrade_configs = vec![UpgradeConfig {
                upgrade_type: "websocket".to_string(),
                enabled: true,
            }];
            let handler = build_router(
                scenario,
                &[text_logger(
                    &path,
                    "%RESPONSE_CODE% %RESPONSE_FLAGS% %RESPONSE_CODE_DETAILS%\n",
                )],
            )
            .await;

            let resp = handler.handle(upgrade_request("/v1/chat")).await;
            assert_eq!(
                resp.head.status,
                StatusCode::SERVICE_UNAVAILABLE,
                "the warming check must fire on the upgrade path too, not just apply_forward -- \
                 an upgrade request is exactly how the check would be bypassed if only one of \
                 the two cluster-lookup sites enforced it"
            );
            resp.body.collect().await.unwrap();

            assert_eq!(read_to_string(&path), "503 NC cluster_not_warmed\n");
            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn cluster_not_warmed_is_distinguishable_from_all_hosts_ejected() {
    LocalSet::new()
        .run_until(async {
            let fmt = "%RESPONSE_CODE% %RESPONSE_FLAGS% %RESPONSE_CODE_DETAILS%\n";

            // The warming case: registered, never resolved.
            let warming_path = temp_path("distinguish-warming");
            let warming_handler = build_router(
                Scenario::warming(forward_to(ForwardTarget::Cluster("up".into()))),
                &[text_logger(&warming_path, fmt)],
            )
            .await;
            let warming_resp = warming_handler
                .handle(request("/v1/chat/completions"))
                .await;
            assert_eq!(warming_resp.head.status, StatusCode::SERVICE_UNAVAILABLE);
            warming_resp.body.collect().await.unwrap();
            let warming_line = read_to_string(&warming_path);
            std::fs::remove_file(&warming_path).unwrap();

            // The ejected case: resolved and initialized, zero healthy hosts.
            let ejected_path = temp_path("distinguish-ejected");
            let mut ejected_scenario = Scenario::forwarding_to(
                "127.0.0.1:1".parse().unwrap(),
                forward_to(ForwardTarget::Cluster("up".into())),
            );
            ejected_scenario.endpoints = Vec::new();
            let ejected_handler =
                build_router(ejected_scenario, &[text_logger(&ejected_path, fmt)]).await;
            let ejected_resp = ejected_handler
                .handle(request("/v1/chat/completions"))
                .await;
            assert_eq!(ejected_resp.head.status, StatusCode::SERVICE_UNAVAILABLE);
            ejected_resp.body.collect().await.unwrap();
            let ejected_line = read_to_string(&ejected_path);
            std::fs::remove_file(&ejected_path).unwrap();

            assert_eq!(warming_line, "503 NC cluster_not_warmed\n");
            assert_eq!(ejected_line, "503 UH no_healthy_upstream\n");
            assert_ne!(
                warming_line, ejected_line,
                "WP-58's whole point: a never-warmed cluster and an all-hosts-ejected cluster \
                 must be distinguishable in the access log, not share one generic path"
            );
        })
        .await;
}

// --- UO: circuit breaker overflow -------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn max_requests_zero_records_and_renders_the_uo_flag() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream_ok().await;
            let path = temp_path("uo-flag");
            let mut scenario =
                Scenario::forwarding_to(addr, forward_to(ForwardTarget::Cluster("up".into())));
            scenario.circuit_breakers = CircuitBreakers {
                default: CircuitBreakerThresholds {
                    max_requests: 0,
                    ..CircuitBreakerThresholds::ENVOY_DEFAULT
                },
                high: CircuitBreakerThresholds::ENVOY_DEFAULT,
            };
            let handler = build_router(
                scenario,
                &[text_logger(&path, "%RESPONSE_CODE% %RESPONSE_FLAGS%\n")],
            )
            .await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::SERVICE_UNAVAILABLE);
            resp.body.collect().await.unwrap();

            assert_eq!(read_to_string(&path), "503 UO\n");
            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

// --- UF: upstream connect failure -------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_refused_connection_records_and_renders_the_uf_flag() {
    LocalSet::new()
        .run_until(async {
            let addr = refused_addr().await;
            let path = temp_path("uf-flag");
            let handler = build_router(
                Scenario::forwarding_to(addr, forward_to(ForwardTarget::Cluster("up".into()))),
                &[text_logger(&path, "%RESPONSE_CODE% %RESPONSE_FLAGS%\n")],
            )
            .await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::SERVICE_UNAVAILABLE);
            resp.body.collect().await.unwrap();

            assert_eq!(read_to_string(&path), "503 UF\n");
            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

// --- UC: upstream codec error -----------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_garbled_upstream_response_records_and_renders_the_uc_flag() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream_garbage_response().await;
            let path = temp_path("uc-flag");
            let handler = build_router(
                Scenario::forwarding_to(addr, forward_to(ForwardTarget::Cluster("up".into()))),
                &[text_logger(&path, "%RESPONSE_CODE% %RESPONSE_FLAGS%\n")],
            )
            .await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::BAD_GATEWAY);
            resp.body.collect().await.unwrap();

            assert_eq!(read_to_string(&path), "502 UC\n");
            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

// --- UT: upstream request timeout -------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_route_timeout_records_and_renders_the_ut_flag() {
    tokio::time::timeout(Duration::from_secs(5), async {
        LocalSet::new()
            .run_until(async {
                let addr = spawn_hanging_upstream().await;
                let path = temp_path("ut-flag");
                let mut fwd = forward_to(ForwardTarget::Cluster("up".into()));
                fwd.timeout = Some(Duration::from_millis(50));
                let handler = build_router(
                    Scenario::forwarding_to(addr, fwd),
                    &[text_logger(&path, "%RESPONSE_CODE% %RESPONSE_FLAGS%\n")],
                )
                .await;

                let resp = handler.handle(request("/v1/chat/completions")).await;
                assert_eq!(resp.head.status, StatusCode::GATEWAY_TIMEOUT);
                resp.body.collect().await.unwrap();

                assert_eq!(read_to_string(&path), "504 UT\n");
                std::fs::remove_file(&path).unwrap();
            })
            .await;
    })
    .await
    .expect("should complete well within the test's own guard timeout");
}

// --- SI: stream idle timeout -------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn an_idle_response_body_records_and_renders_the_si_flag() {
    tokio::time::timeout(Duration::from_secs(5), async {
        LocalSet::new()
            .run_until(async {
                let addr = spawn_upstream_that_stalls_mid_body().await;
                let path = temp_path("si-flag");
                let mut fwd = forward_to(ForwardTarget::Cluster("up".into()));
                fwd.idle_timeout = Some(Duration::from_millis(50));
                let handler = build_router(
                    Scenario::forwarding_to(addr, fwd),
                    &[text_logger(&path, "%RESPONSE_CODE% %RESPONSE_FLAGS%\n")],
                )
                .await;

                let resp = handler.handle(request("/v1/chat/completions")).await;
                // Headers already arrived successfully -- the idle timeout
                // is a body-phase failure, so the STATUS is still 200; only
                // the body stream (and therefore the access log, written at
                // stream end) ever sees the failure.
                assert_eq!(resp.head.status, StatusCode::OK);
                // The body errors out once the idle deadline fires -- the
                // access-log line is still written (see `LoggingBody`'s
                // module doc: it logs regardless of how the stream ends).
                let _ = resp.body.collect().await;

                assert_eq!(read_to_string(&path), "200 SI\n");
                std::fs::remove_file(&path).unwrap();
            })
            .await;
    })
    .await
    .expect("should complete well within the test's own guard timeout");
}

// --- UR: upstream remote reset ----------------------------------------------

/// An h2 upstream that refuses every stream with
/// `RST_STREAM(REFUSED_STREAM)`.
///
/// Raw `h2::server`, not hyper: hyper's server always intends to serve a
/// stream and offers no way to refuse one. Spawned with `spawn_local` because
/// these tests run on a `current_thread` runtime under a `LocalSet`.
async fn spawn_h2_upstream_that_refuses_every_stream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::task::spawn_local(async move {
        loop {
            let Ok((io, _peer)) = listener.accept().await else {
                return;
            };
            tokio::task::spawn_local(async move {
                let Ok(mut conn) = h2::server::handshake(io).await else {
                    return;
                };
                while let Some(accepted) = conn.accept().await {
                    let Ok((_req, mut respond)) = accepted else {
                        return;
                    };
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                }
            });
        }
    });
    addr
}

/// `UR` had no producer at all until the h2 codec learned to decode
/// RST_STREAM reasons -- `PoolError::ResetBeforeHeaders`, the only value
/// `router.rs`'s old `UR` arm matched, is constructed by neither pool, so the
/// flag was dead code (recorded as such in internal-docs/envoy-divergences.md). A
/// refused stream is a deliberate remote reset, which is precisely what Envoy
/// means by `UR`; every other codec failure stays `UC`.
///
/// No retry policy here on purpose: with one, this request would succeed and
/// there would be no flag to render.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_h2_stream_records_and_renders_the_ur_flag() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_h2_upstream_that_refuses_every_stream().await;
            let path = temp_path("ur-flag");
            let mut scenario =
                Scenario::forwarding_to(addr, forward_to(ForwardTarget::Cluster("up".into())));
            scenario.protocol = proxy_config::ir::UpstreamProtocol::Http2;
            let handler = build_router(
                scenario,
                &[text_logger(&path, "%RESPONSE_CODE% %RESPONSE_FLAGS%\n")],
            )
            .await;

            let resp = handler.handle(request("/v1/chat")).await;
            assert_eq!(resp.head.status, StatusCode::BAD_GATEWAY);
            resp.body.collect().await.unwrap();

            assert_eq!(
                read_to_string(&path),
                "502 UR\n",
                "a stream the peer refused is a remote reset, not a codec failure -- `UC` here \
                 would mean the refused-stream decode never reached the router"
            );
            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

/// An h2 upstream that resets every stream with `RST_STREAM(CANCEL)` -- a
/// deliberate reset, but NOT `REFUSED_STREAM`, so it rides in on
/// `UpstreamCodecError::Send` rather than the dedicated `RefusedStream`
/// variant. Same raw-`h2::server` shape as the refuse harness above.
async fn spawn_h2_upstream_that_cancels_every_stream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::task::spawn_local(async move {
        loop {
            let Ok((io, _peer)) = listener.accept().await else {
                return;
            };
            tokio::task::spawn_local(async move {
                let Ok(mut conn) = h2::server::handshake(io).await else {
                    return;
                };
                while let Some(accepted) = conn.accept().await {
                    let Ok((_req, mut respond)) = accepted else {
                        return;
                    };
                    respond.send_reset(h2::Reason::CANCEL);
                }
            });
        }
    });
    addr
}

/// A non-`REFUSED_STREAM` reset (here `CANCEL`) is still a deliberate remote
/// reset -> `UR`, not `UC`. Before `codec::is_remote_reset` landed, only
/// `REFUSED_STREAM` rendered `UR` and every other reset reason fell through to
/// `UC`, mislabelling a peer-initiated reset as a plain connection failure.
/// Flag-only: with no retry policy the reset surfaces as a rendered flag.
#[tokio::test(flavor = "current_thread")]
async fn a_cancelled_h2_stream_records_and_renders_the_ur_flag() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_h2_upstream_that_cancels_every_stream().await;
            let path = temp_path("ur-flag-cancel");
            let mut scenario =
                Scenario::forwarding_to(addr, forward_to(ForwardTarget::Cluster("up".into())));
            scenario.protocol = proxy_config::ir::UpstreamProtocol::Http2;
            let handler = build_router(
                scenario,
                &[text_logger(&path, "%RESPONSE_CODE% %RESPONSE_FLAGS%\n")],
            )
            .await;

            let resp = handler.handle(request("/v1/chat")).await;
            assert_eq!(resp.head.status, StatusCode::BAD_GATEWAY);
            resp.body.collect().await.unwrap();

            assert_eq!(
                read_to_string(&path),
                "502 UR\n",
                "an h2 RST_STREAM(CANCEL) is a remote reset -- `UC` here would mean the router \
                 still treats every non-refused reset reason as a plain connection failure"
            );
            std::fs::remove_file(&path).unwrap();
        })
        .await;
}

// --- DC: downstream connection termination ----------------------------------

/// `DC` was the second flag the WP-24 audit found declared, apparently
/// wired, and unreachable. `access_logging.rs` maps `BodyError::Downstream`
/// to it and has always had a unit test -- but that test **hand-constructs**
/// the error, and nothing in the real pipeline could produce one, because
/// `filter_manager::collect_request` flattened its body error to `()` before
/// any `StreamInfo` existed to flag. A fabricated-condition test is worse
/// than no test: it makes an unreachable path look covered.
///
/// So this test refuses to fabricate anything. It runs the real downstream
/// codec (`serve_http1`) over a real pipe and behaves like a client that dies
/// mid-upload: announce `Content-Length: 100`, send 10 bytes, then close the
/// write half. hyper's `Incoming` surfaces the truncation as an error,
/// `codec.rs` wraps it as `BodyError::Downstream` (the one and only site that
/// constructs it), and the flag must reach the rendered access log.
#[tokio::test(flavor = "current_thread")]
async fn a_client_that_dies_mid_upload_records_and_renders_the_dc_flag() {
    use tokio::io::AsyncWriteExt;

    LocalSet::new()
        .run_until(async {
            let addr = spawn_upstream_ok().await;
            let path = temp_path("dc-flag");
            let handler = build_router(
                Scenario::forwarding_to(addr, forward_to(ForwardTarget::Cluster("up".into()))),
                &[text_logger(&path, "%RESPONSE_CODE% %RESPONSE_FLAGS%\n")],
            )
            .await;

            let (mut client, server) = tokio::io::duplex(64 * 1024);
            let served = tokio::task::spawn_local(async move {
                let _ = proxy_http::codec::serve_http1(
                    server,
                    std::rc::Rc::new(handler) as std::rc::Rc<dyn StreamHandler>,
                    proxy_http::codec::Http1Options { keep_alive: true },
                    std::future::pending::<()>(),
                    DownstreamInfo::loopback(),
                )
                .await;
            });

            // Promise 100 bytes, send 10, then EOF the write half -- the
            // truncation hyper reports as a body error. The read half stays
            // open so the server can still write its 400 rather than failing
            // on a broken pipe, which would be a different condition.
            client
                .write_all(
                    b"POST /v1/chat HTTP/1.1\r\nHost: test.local\r\nContent-Length: 100\r\n\r\n",
                )
                .await
                .unwrap();
            client.write_all(b"0123456789").await.unwrap();
            client.shutdown().await.unwrap();

            let _ = served.await;

            assert_eq!(
                read_to_string(&path),
                "400 DC\n",
                "a client that vanished mid-upload must render DC -- a bare `400` here means \
                 the body error was still being discarded before anything could flag it"
            );
            std::fs::remove_file(&path).unwrap();
        })
        .await;
}
