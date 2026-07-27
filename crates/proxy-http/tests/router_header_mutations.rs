//! P0 regression: `RouteEntry::request_headers_to_add` (populated by both
//! config front-ends -- Envoy-mode lowering and the simple dialect's
//! provider-credential injection) has to actually reach the upstream
//! request. Standalone (not `router.rs`'s own `#[cfg(test)]` module) for the
//! same reason as `router_retry.rs`: a fresh, focused set of upstream
//! helpers rather than reusing the existing one-shot ones.
//!
//! Rust note: same shape as `router.rs`'s own tests --
//! `send_upstream_http1` spawns a non-`Send` connection driver task via
//! `tokio::task::spawn_local`, so every test needs a `LocalSet` on a
//! `current_thread` runtime.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::resolver::FakeResolver;
use proxy_config::ir::{
    ClusterConfig, ClusterName, DiscoveryType, EndpointIR, ForwardAction, ForwardTarget,
    HeaderAppendAction, HeaderMutation, LbPolicy, PathMatch, RouteActionIR, RouteEntry,
    RouteMatcher, RouteTable, VirtualHostIR,
};
use proxy_http::filter::RequestHeaders;
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
use proxy_http::router::RouterHandler;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::LocalSet;

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

/// Build a one-cluster, one-route `RouterHandler` forwarding to `addr` under
/// cluster name `"up"`, with `mutations` as the route's
/// `request_headers_to_add` -- mirrors `router.rs`'s own `build_router` test
/// helper, plus the field this file exists to exercise.
async fn build_router(
    addr: SocketAddr,
    fwd: ForwardAction,
    mutations: Vec<HeaderMutation>,
) -> RouterHandler {
    let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
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
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1 << 20,
            circuit_breakers: proxy_config::ir::CircuitBreakers::default(),
            upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
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
            })],
        }],
    )
    .unwrap();

    RouterHandler::new(Arc::new(route_table), Arc::new(manager))
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
        stream_info: None,
        route: None,
    }
}

/// A one-shot "reflecting" upstream: accepts a single connection, reads
/// until the request's header terminator, hands the raw request-line+headers
/// text back over `rx`, then answers 200 -- same shape as `router.rs`'s own
/// `spawn_reflecting_upstream`.
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

/// Count how many times `needle` (a full header line, e.g. `"x-foo: bar"`)
/// appears in `request_text` -- used to distinguish "one value" from
/// "appended as a second instance" for `AppendIfExistsOrAdd`.
fn count_header_line(request_text: &str, needle: &str) -> usize {
    request_text
        .to_ascii_lowercase()
        .lines()
        .filter(|line| line == &needle.to_ascii_lowercase())
        .count()
}

// --- the core regression: a configured Authorization header reaches the upstream ---

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

// --- one test per HeaderAppendAction variant ---

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

// --- ordering / interaction with the S9/S4 rewrites ---

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

/// Pins the ordering decision documented on `apply_request_transforms`: a
/// route-level `request_headers_to_add` entry that targets `host` wins over
/// `host_rewrite_literal`, matching Envoy's `finalizeRequestHeaders` (rewrite
/// first, then header mutations).
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

// --- no-op regression: an empty mutation list behaves exactly as today ---

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
