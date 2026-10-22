//! Verifies route and cluster `request_headers_to_add` mutations on upstream requests.
//!
//! Rust note: `send_upstream_http1` uses `spawn_local`, so tests need a
//! `LocalSet` on a `current_thread` runtime.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::resolver::FakeResolver;
use proxy_config::ir::{
    ClusterConfig, ClusterKind, ClusterName, DiscoveryType, EndpointIR, ForwardAction,
    ForwardTarget, HeaderAppendAction, HeaderMutation, LbPolicy, PathMatch, RouteActionIR,
    RouteEntry, RouteMatcher, RouteTable, VirtualHostIR,
};
use proxy_http::filter::{RequestHeaders, TerminalFilterInstanceFactory};
use proxy_http::filter_manager::FilterChainHandler;
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
use proxy_http::router::RouterFilterFactory;
use proxy_http::stat_handles::{RouterStats, StatHandles};
use proxy_observability::stats::{StatsControl, WorkerId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::LocalSet;

/// Builds router stats for the configured clusters.
fn test_router_stats(cluster_names: &[&str]) -> Arc<RouterStats> {
    let control = StatsControl::new(1);
    let handles = Arc::new(StatHandles::build(&control, cluster_names.iter().copied()));
    Arc::new(RouterStats::new(control.registry(), handles, WorkerId(0)))
}

fn prefix_matcher(prefix: &str) -> RouteMatcher {
    RouteMatcher {
        path: PathMatch::Prefix(prefix.to_string()),
        case_sensitive: true,
        headers: Vec::new(),
    }
}

fn forward_to_up(host_rewrite_literal: Option<String>) -> ForwardAction {
    ForwardAction {
        target: ForwardTarget::Cluster("up".to_string()),
        timeout: None,
        idle_timeout: None,
        retry_policy: None,
        host_rewrite_literal,
        prefix_rewrite: None,
    }
}

fn mutation(key: &str, value: &str, action: HeaderAppendAction) -> HeaderMutation {
    HeaderMutation {
        key: key.to_string(),
        value: value.to_string(),
        action,
    }
}

/// Builds a one-route router with route-level header mutations.
async fn build_router(
    addr: SocketAddr,
    fwd: ForwardAction,
    mutations: Vec<HeaderMutation>,
) -> FilterChainHandler {
    build_router_with_cluster_mutations(addr, fwd, mutations, Vec::new()).await
}

/// Also configures cluster mutations, which are applied per upstream attempt.
async fn build_router_with_cluster_mutations(
    addr: SocketAddr,
    fwd: ForwardAction,
    mutations: Vec<HeaderMutation>,
    cluster_mutations: Vec<HeaderMutation>,
) -> FilterChainHandler {
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
            request_headers_to_add: cluster_mutations,
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
                matcher: prefix_matcher("/v1/"),
                action: RouteActionIR::Forward(fwd),
                request_headers_to_add: mutations,
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

    let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> = Arc::new(
        RouterFilterFactory::new(Arc::new(manager), test_router_stats(&["up"])),
    );
    FilterChainHandler::new(
        Vec::new(),
        terminal_factory,
        Arc::new(route_table),
        false,
        false,
        0,
    )
}

/// A request with no headers beyond the mandatory `Host`.
fn request(path: &'static str) -> HttpRequestParts {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    request_with_headers(path, headers)
}

fn request_with_headers(path: &'static str, headers: HeaderMap) -> HttpRequestParts {
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

/// Accepts one request, returns its raw headers, and responds with 200.
async fn spawn_reflecting_upstream() -> (SocketAddr, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let request_text = String::from_utf8_lossy(&buf).to_string();
        let _ = tx.send(request_text);
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    });
    (addr, rx)
}

/// Counts exact header-line occurrences in the captured request.
fn count_header_line(request_text: &str, needle: &str) -> usize {
    request_text
        .to_ascii_lowercase()
        .lines()
        .filter(|line| line == &needle.to_ascii_lowercase())
        .count()
}

#[tokio::test(flavor = "current_thread")]
async fn configured_authorization_header_reaches_the_upstream() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router(
                addr,
                forward_to_up(None),
                vec![mutation(
                    "Authorization",
                    "Bearer sk-configured",
                    HeaderAppendAction::OverwriteIfExistsOrAdd,
                )],
            )
            .await;

            let resp = router.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap().to_ascii_lowercase();
            assert!(
                upstream_request.contains("authorization: bearer sk-configured"),
                "expected the configured Authorization header on the wire, got: {upstream_request:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn append_if_exists_or_add_keeps_the_existing_value_and_adds_a_second() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router(
                addr,
                forward_to_up(None),
                vec![mutation(
                    "x-tag",
                    "configured",
                    HeaderAppendAction::AppendIfExistsOrAdd,
                )],
            )
            .await;

            let mut headers = HeaderMap::new();
            headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
            headers.insert("x-tag", HeaderValue::from_static("client"));

            let resp = router
                .handle(request_with_headers("/v1/chat/completions", headers))
                .await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap();
            assert_eq!(
                count_header_line(&upstream_request, "x-tag: client"),
                1,
                "the client's original value must survive, got: {upstream_request:?}"
            );
            assert_eq!(
                count_header_line(&upstream_request, "x-tag: configured"),
                1,
                "the configured value must be appended as a second instance, got: {upstream_request:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn append_if_exists_or_add_inserts_when_absent() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router(
                addr,
                forward_to_up(None),
                vec![mutation(
                    "x-tag",
                    "configured",
                    HeaderAppendAction::AppendIfExistsOrAdd,
                )],
            )
            .await;

            let resp = router.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap().to_ascii_lowercase();
            assert!(
                upstream_request.contains("x-tag: configured"),
                "expected the header to be added when absent, got: {upstream_request:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn add_if_absent_does_not_displace_a_client_supplied_value() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router(
                addr,
                forward_to_up(None),
                vec![mutation(
                    "Authorization",
                    "Bearer sk-configured",
                    HeaderAppendAction::AddIfAbsent,
                )],
            )
            .await;

            let mut headers = HeaderMap::new();
            headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
            headers.insert(
                "authorization",
                HeaderValue::from_static("Bearer client-forged"),
            );

            let resp = router
                .handle(request_with_headers("/v1/chat/completions", headers))
                .await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap().to_ascii_lowercase();
            assert!(
                upstream_request.contains("authorization: bearer client-forged"),
                "AddIfAbsent must leave a client-supplied value untouched, got: {upstream_request:?}"
            );
            assert!(
                !upstream_request.contains("sk-configured"),
                "the configured value must not have been inserted alongside the client's, got: {upstream_request:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn add_if_absent_inserts_when_absent() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router(
                addr,
                forward_to_up(None),
                vec![mutation(
                    "Authorization",
                    "Bearer sk-configured",
                    HeaderAppendAction::AddIfAbsent,
                )],
            )
            .await;

            let resp = router.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap().to_ascii_lowercase();
            assert!(
                upstream_request.contains("authorization: bearer sk-configured"),
                "AddIfAbsent must insert when nothing is present, got: {upstream_request:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn overwrite_if_exists_or_add_replaces_a_client_supplied_value() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router(
                addr,
                forward_to_up(None),
                vec![mutation(
                    "Authorization",
                    "Bearer sk-configured",
                    HeaderAppendAction::OverwriteIfExistsOrAdd,
                )],
            )
            .await;

            let mut headers = HeaderMap::new();
            headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
            headers.insert(
                "authorization",
                HeaderValue::from_static("Bearer client-forged"),
            );

            let resp = router
                .handle(request_with_headers("/v1/chat/completions", headers))
                .await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap().to_ascii_lowercase();
            assert!(
                upstream_request.contains("authorization: bearer sk-configured"),
                "OverwriteIfExistsOrAdd must replace a client-supplied value, got: {upstream_request:?}"
            );
            assert!(
                !upstream_request.contains("client-forged"),
                "the client's value must not survive, got: {upstream_request:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn overwrite_if_exists_or_add_inserts_when_absent() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router(
                addr,
                forward_to_up(None),
                vec![mutation(
                    "Authorization",
                    "Bearer sk-configured",
                    HeaderAppendAction::OverwriteIfExistsOrAdd,
                )],
            )
            .await;

            let resp = router.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap().to_ascii_lowercase();
            assert!(
                upstream_request.contains("authorization: bearer sk-configured"),
                "OverwriteIfExistsOrAdd must insert when absent, got: {upstream_request:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn overwrite_if_exists_replaces_an_existing_value() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router(
                addr,
                forward_to_up(None),
                vec![mutation(
                    "x-tag",
                    "configured",
                    HeaderAppendAction::OverwriteIfExists,
                )],
            )
            .await;

            let mut headers = HeaderMap::new();
            headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
            headers.insert("x-tag", HeaderValue::from_static("client"));

            let resp = router
                .handle(request_with_headers("/v1/chat/completions", headers))
                .await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap().to_ascii_lowercase();
            assert!(
                upstream_request.contains("x-tag: configured"),
                "OverwriteIfExists must replace an existing value, got: {upstream_request:?}"
            );
            assert!(
                !upstream_request.contains("x-tag: client"),
                "the client's value must not survive, got: {upstream_request:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn overwrite_if_exists_does_not_insert_when_absent() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router(
                addr,
                forward_to_up(None),
                vec![mutation(
                    "x-tag",
                    "configured",
                    HeaderAppendAction::OverwriteIfExists,
                )],
            )
            .await;

            let resp = router.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap().to_ascii_lowercase();
            assert!(
                !upstream_request.contains("x-tag"),
                "OverwriteIfExists must not insert when absent, got: {upstream_request:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn multiple_mutations_apply_in_config_order() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router(
                addr,
                forward_to_up(None),
                vec![
                    mutation(
                        "authorization",
                        "Bearer first",
                        HeaderAppendAction::OverwriteIfExistsOrAdd,
                    ),
                    mutation(
                        "authorization",
                        "Bearer second",
                        HeaderAppendAction::OverwriteIfExistsOrAdd,
                    ),
                ],
            )
            .await;

            let resp = router.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap().to_ascii_lowercase();
            assert!(
                upstream_request.contains("authorization: bearer second"),
                "the later mutation in config order must win, got: {upstream_request:?}"
            );
            assert!(
                !upstream_request.contains("bearer first"),
                "the earlier mutation's value must not survive, got: {upstream_request:?}"
            );
        })
        .await;
}

/// Route header mutations run after `host_rewrite_literal`, matching Envoy finalization.
#[tokio::test(flavor = "current_thread")]
async fn a_header_mutation_targeting_host_wins_over_host_rewrite_literal() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router(
                addr,
                forward_to_up(Some("rewritten.internal".to_string())),
                vec![mutation(
                    "host",
                    "mutated.internal",
                    HeaderAppendAction::OverwriteIfExistsOrAdd,
                )],
            )
            .await;

            let resp = router.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap().to_ascii_lowercase();
            assert!(
                upstream_request.contains("host: mutated.internal"),
                "expected the header mutation to be the final word over host_rewrite_literal, got: {upstream_request:?}"
            );
            assert!(
                !upstream_request.contains("rewritten.internal"),
                "host_rewrite_literal's value must not survive the later mutation, got: {upstream_request:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn empty_mutation_list_does_not_change_existing_behavior() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router(addr, forward_to_up(None), Vec::new()).await;

            let resp = router.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap();
            assert!(
                upstream_request.starts_with("GET /v1/chat/completions HTTP/1.1"),
                "expected the request line unchanged, got: {upstream_request:?}"
            );
            assert!(
                upstream_request
                    .to_ascii_lowercase()
                    .contains("host: test.local"),
                "expected the original Host header unchanged, got: {upstream_request:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn cluster_level_mutation_reaches_the_upstream() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router_with_cluster_mutations(
                addr,
                forward_to_up(None),
                Vec::new(),
                vec![mutation(
                    "x-api-key",
                    "cluster-secret",
                    HeaderAppendAction::OverwriteIfExistsOrAdd,
                )],
            )
            .await;

            let resp = router.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap().to_ascii_lowercase();
            assert!(
                upstream_request.contains("x-api-key: cluster-secret"),
                "expected the cluster's header mutation on the wire, got: {upstream_request:?}"
            );
        })
        .await;
}

/// Cluster mutations win collisions; the route-level credential must not leak upstream.
#[tokio::test(flavor = "current_thread")]
async fn cluster_level_mutation_overrides_route_level_and_route_value_does_not_leak() {
    LocalSet::new()
        .run_until(async {
            let (addr, rx) = spawn_reflecting_upstream().await;
            let router = build_router_with_cluster_mutations(
                addr,
                forward_to_up(None),
                vec![mutation(
                    "authorization",
                    "Bearer route-primary-key",
                    HeaderAppendAction::OverwriteIfExistsOrAdd,
                )],
                vec![mutation(
                    "authorization",
                    "Bearer cluster-fallback-key",
                    HeaderAppendAction::OverwriteIfExistsOrAdd,
                )],
            )
            .await;

            let resp = router.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);

            let upstream_request = rx.await.unwrap().to_ascii_lowercase();
            assert!(
                upstream_request.contains("authorization: bearer cluster-fallback-key"),
                "expected the cluster's credential to win, got: {upstream_request:?}"
            );
            assert!(
                !upstream_request.contains("route-primary-key"),
                "the route-level (wrong-provider) credential must not leak upstream, got: {upstream_request:?}"
            );
        })
        .await;
}

/// A `tracing` writer that appends to a shared buffer.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The fail-open path (AGENTS.md "Fail-open controls"): a mutation the router
/// cannot send is dropped and the request still goes out with the others.
/// Provider credentials are checked at load, so only an Envoy route mutation
/// reaches here. The first drop logs an error naming the key, never the
/// value; later drops do not repeat it, or the log would grow per request.
#[tokio::test(flavor = "current_thread")]
async fn an_unsendable_mutation_is_dropped_and_logged_once_without_its_value() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _default = tracing::subscriber::set_default(subscriber);

    LocalSet::new()
        .run_until(async {
            for _ in 0..2 {
                let (addr, rx) = spawn_reflecting_upstream().await;
                let router = build_router(
                    addr,
                    forward_to_up(None),
                    vec![
                        mutation(
                            "x-bad",
                            "secret-mutation-value\u{1}",
                            HeaderAppendAction::OverwriteIfExistsOrAdd,
                        ),
                        mutation("x-good", "kept", HeaderAppendAction::OverwriteIfExistsOrAdd),
                    ],
                )
                .await;
                let resp = router.handle(request("/v1/chat/completions")).await;
                assert_eq!(resp.head.status, StatusCode::OK);
                let upstream_request = rx.await.unwrap().to_ascii_lowercase();
                assert_eq!(count_header_line(&upstream_request, "x-good: kept"), 1);
                assert!(
                    !upstream_request.contains("x-bad"),
                    "got: {upstream_request:?}"
                );
            }
        })
        .await;

    let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    let drops: Vec<&str> = log.lines().filter(|l| l.contains("dropping")).collect();
    assert_eq!(drops.len(), 1, "expected one drop line, got:\n{log}");
    assert!(
        drops[0].contains("ERROR") && drops[0].contains("x-bad"),
        "got: {}",
        drops[0]
    );
    assert!(
        !log.contains("secret-mutation-value"),
        "the value must not be logged:\n{log}"
    );
}
