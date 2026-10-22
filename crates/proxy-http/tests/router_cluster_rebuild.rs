//! Upstream connection reuse across cluster reloads.
//!
//! A cluster that is reloaded with changed settings keeps its name and its
//! endpoint addresses but is rebuilt from scratch: new transport socket (TLS
//! trust roots, client certificate, SNI) and new circuit-breaker gauges. The
//! worker's connection caches are keyed on name, address and protocol, so
//! without something that changes with the rebuild, requests routed to the new
//! build would be sent down a connection the old build negotiated, and counted
//! against a `max_connections` gauge the new build never reads. The converse
//! matters as much: a reload that leaves a cluster alone carries the same
//! build forward, and must not cost it its warm connections. This file drives
//! both through the real router and the real `ClusterManager`, with real
//! sockets on ephemeral ports, because the identity is computed at the router's
//! dial site from the cluster entry it is dialing.
//!
//! Rust note: the h1 upstream codec spawns a non-`Send` connection driver task
//! with `tokio::task::spawn_local`, so the test runs on a `current_thread`
//! runtime inside a `LocalSet`, like the other router tests.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::resolver::FakeResolver;
use proxy_config::ir::{
    ClusterConfig, ClusterKind, ClusterName, DiscoveryType, EndpointIR, ForwardAction,
    ForwardTarget, LbPolicy, PathMatch, RouteActionIR, RouteEntry, RouteMatcher, RouteTable,
    VirtualHostIR,
};
use proxy_http::filter::{RequestHeaders, TerminalFilterInstanceFactory};
use proxy_http::filter_manager::FilterChainHandler;
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
use proxy_http::router::RouterFilterFactory;
use proxy_http::stat_handles::{RouterStats, StatHandles};
use proxy_observability::stats::{StatsControl, WorkerId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::LocalSet;

/// A STATIC, single-endpoint cluster named `"up"`. `connect_timeout` is the
/// setting the test changes to make the manager rebuild it: any difference in
/// the config does.
fn cluster(addr: SocketAddr, connect_timeout: Duration) -> ClusterConfig {
    ClusterConfig {
        eds: None,
        name: "up".to_string(),
        discovery: DiscoveryType::Static,
        lb_policy: LbPolicy::RoundRobin,
        connect_timeout,
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
    }
}

/// Publish `config` as the manager's only cluster, the way a reload does.
async fn publish(manager: &ClusterManager, config: ClusterConfig) {
    let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
    snapshot.insert("up".to_string(), Arc::new(config));
    let rejected = manager.update_from_snapshot(&snapshot).await;
    assert!(rejected.is_empty(), "the cluster builds: {rejected:?}");
}

/// A handler for one configuration generation: the router captures the cluster
/// registry as it is when the handler is built, which is how a downstream
/// connection keeps routing to the builds of the generation it started in.
fn handler_for(manager: &Arc<ClusterManager>) -> FilterChainHandler {
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
    let terminal: Arc<dyn TerminalFilterInstanceFactory> =
        Arc::new(RouterFilterFactory::new(manager.clone(), stats));
    FilterChainHandler::new(Vec::new(), terminal, Arc::new(route_table), false, false, 0)
}

/// An h1 upstream that keeps connections open and answers every bodyless GET,
/// counting the TCP connections it accepts.
async fn spawn_keepalive_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    head.clear();
                    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
                    if stream.write_all(reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, accepted)
}

/// One GET through `handler`, with the body read to its clean end so the
/// connection it used goes back to the cache.
async fn get(handler: &FilterChainHandler) {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    let response = handler
        .handle(HttpRequestParts {
            head: RequestHeaders {
                method: Method::GET,
                uri: Uri::from_static("/v1/models"),
                headers,
            },
            body: local_boxed(
                Full::new(Bytes::new())
                    .map_err(|infallible: std::convert::Infallible| match infallible {}),
            ),
            downstream: DownstreamInfo::loopback(),
            on_upgrade: None,
        })
        .await;
    assert_eq!(response.head.status, StatusCode::OK);
    response
        .body
        .collect()
        .await
        .expect("the body ends cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn connection_reuse_follows_the_cluster_build_across_reloads() {
    LocalSet::new()
        .run_until(async {
            let (addr, accepted) = spawn_keepalive_upstream().await;
            let manager = Arc::new(ClusterManager::with_default_transport(Arc::new(
                FakeResolver::new(),
            )));
            publish(&manager, cluster(addr, Duration::from_secs(5))).await;
            let before = handler_for(&manager);

            get(&before).await;
            get(&before).await;
            assert_eq!(
                accepted.load(Ordering::SeqCst),
                1,
                "control: two requests to one build share one connection, so a second \
                 connection below is down to the rebuild"
            );

            // A reload that leaves this cluster's config alone carries the
            // same build forward, so it must not cost its connections.
            publish(&manager, cluster(addr, Duration::from_secs(5))).await;
            get(&handler_for(&manager)).await;
            assert_eq!(
                accepted.load(Ordering::SeqCst),
                1,
                "a reload that does not change the cluster must keep reusing its connection"
            );

            // The same cluster, name and address unchanged, reloaded with a
            // different setting: the manager builds it afresh.
            publish(&manager, cluster(addr, Duration::from_secs(6))).await;
            let after = handler_for(&manager);

            get(&after).await;
            assert_eq!(
                accepted.load(Ordering::SeqCst),
                2,
                "the rebuilt cluster must dial its own connection instead of riding one \
                 the previous build negotiated"
            );
            get(&after).await;
            assert_eq!(
                accepted.load(Ordering::SeqCst),
                2,
                "the new build then reuses its own connection"
            );

            // A connection that started under the previous generation keeps
            // routing to the previous build, and that build's connection is
            // still there for it.
            get(&before).await;
            assert_eq!(
                accepted.load(Ordering::SeqCst),
                2,
                "the previous generation still reuses its own connection"
            );
        })
        .await;
}
