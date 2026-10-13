//! `LEAST_REQUEST` driven through the real router path: the router holds a
//! `Host::begin_request` guard for every upstream attempt, so each host's
//! in-flight count tracks open requests (headers through body end or drop).
//! Counts are read with a `host_override` pick on the cluster entry, so the
//! tests observe the same `Host` snapshot the load balancer reads and never
//! set a count by hand.
//!
//! Rust note: the router spawns non-`Send` connection drivers with
//! `spawn_local`, so each test runs inside a `LocalSet` on a
//! `current_thread` runtime; the mock upstreams are plain `tokio::spawn`
//! tasks on the same runtime and make progress whenever the test awaits.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::resolver::FakeResolver;
use proxy_cluster::{ClusterEntry, LoadBalancerContext};
use proxy_config::ir::{
    ClusterConfig, ClusterKind, ClusterName, DiscoveryType, EndpointIR, ForwardAction,
    ForwardTarget, LbPolicy, PathMatch, RetryBackOff, RetryOn, RetryPolicyIR, RouteActionIR,
    RouteEntry, RouteMatcher, RouteTable, VirtualHostIR,
};
use proxy_http::filter::{RequestHeaders, TerminalFilterInstanceFactory};
use proxy_http::filter_manager::FilterChainHandler;
use proxy_http::handler::{
    local_boxed, DownstreamInfo, HttpRequestParts, HttpResponseParts, StreamHandler,
};
use proxy_http::router::RouterFilterFactory;
use proxy_http::stat_handles::{RouterStats, StatHandles};
use proxy_observability::stats::{StatsControl, WorkerId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::LocalSet;

const STEP: Duration = Duration::from_secs(5);

struct Harness {
    router: FilterChainHandler,
    entry: Arc<dyn ClusterEntry>,
}

impl Harness {
    /// In-flight count of the host at `addr`, as the load balancer reads it.
    fn count(&self, addr: SocketAddr) -> u64 {
        let ctx = LoadBalancerContext {
            host_override: Some(addr),
            ..Default::default()
        };
        let sel = self.entry.select_host(&ctx).expect("host exists");
        assert_eq!(sel.host.address, addr, "override must resolve to `addr`");
        sel.host.active_request_count()
    }

    async fn send(&self) -> HttpResponseParts {
        tokio::time::timeout(STEP, self.router.handle(request()))
            .await
            .expect("router answers within the step timeout")
    }
}

fn request() -> HttpRequestParts {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat"),
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

async fn build(addrs: &[SocketAddr], retry_policy: Option<RetryPolicyIR>) -> Harness {
    let manager = Arc::new(ClusterManager::with_default_transport(Arc::new(
        FakeResolver::new(),
    )));
    let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
    snapshot.insert(
        "up".to_string(),
        Arc::new(ClusterConfig {
            eds: None,
            name: "up".to_string(),
            discovery: DiscoveryType::Static,
            lb_policy: LbPolicy::LeastRequest,
            connect_timeout: Duration::from_secs(5),
            endpoints: addrs
                .iter()
                .map(|a| EndpointIR {
                    metadata: Default::default(),
                    host: a.ip().to_string(),
                    port: a.port(),
                    weight: 1,
                    priority: 0,
                })
                .collect(),
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
    let entry = manager.cluster("up").expect("cluster built");

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
                    target: ForwardTarget::Cluster("up".to_string()),
                    timeout: None,
                    idle_timeout: None,
                    retry_policy,
                    host_rewrite_literal: None,
                    prefix_rewrite: None,
                }),
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

    let control = StatsControl::new(1);
    let handles = Arc::new(StatHandles::build(&control, ["up"]));
    let stats = Arc::new(RouterStats::new(control.registry(), handles, WorkerId(0)));
    let terminal: Arc<dyn TerminalFilterInstanceFactory> =
        Arc::new(RouterFilterFactory::new(manager, stats));
    Harness {
        router: FilterChainHandler::new(
            Vec::new(),
            terminal,
            Arc::new(route_table),
            false,
            false,
            0,
        ),
        entry,
    }
}

/// Read an upstream request head (these requests have no body).
async fn read_head(stream: &mut tokio::net::TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Upstream that answers headers plus one chunk immediately, then holds the
/// chunked body open until `release` flips to `true`.
async fn spawn_holding_upstream() -> (SocketAddr, tokio::sync::watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (release, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut rx = rx.clone();
            tokio::spawn(async move {
                read_head(&mut stream).await;
                let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
                if stream.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                let _ = rx.wait_for(|released| *released).await;
                let _ = stream.write_all(b"0\r\n\r\n").await;
            });
        }
    });
    (addr, release)
}

/// Upstream that answers a complete 200 to every request.
async fn spawn_fast_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                read_head(&mut stream).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "current_thread")]
async fn streaming_requests_are_counted_and_spread_by_least_request() {
    LocalSet::new()
        .run_until(async {
            let (a, release_a) = spawn_holding_upstream().await;
            let (b, release_b) = spawn_holding_upstream().await;
            let h = build(&[a, b], None).await;

            // With two hosts, power-of-two-choices compares both, so each new
            // request must land on the host with fewer open requests. Uniform
            // random would break the |A - B| <= 1 invariant almost surely
            // over 20 requests; a router that never counts reads 0/0 below.
            let mut open = Vec::new();
            for n in 1..=20u64 {
                let resp = h.send().await;
                assert_eq!(resp.head.status, StatusCode::OK);
                open.push(resp);
                let (ca, cb) = (h.count(a), h.count(b));
                assert_eq!(ca + cb, n, "every open response holds one count");
                assert!(ca.abs_diff(cb) <= 1, "unbalanced: A={ca} B={cb}");
            }

            release_a.send(true).unwrap();
            release_b.send(true).unwrap();
            for resp in open {
                tokio::time::timeout(STEP, resp.body.collect())
                    .await
                    .expect("body completes")
                    .expect("body ok");
            }
            assert_eq!((h.count(a), h.count(b)), (0, 0));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn downstream_dropping_a_streaming_response_releases_the_count() {
    LocalSet::new()
        .run_until(async {
            let (a, _release_a) = spawn_holding_upstream().await;
            let (b, _release_b) = spawn_holding_upstream().await;
            let h = build(&[a, b], None).await;

            let first = h.send().await;
            let second = h.send().await;
            assert_eq!(h.count(a) + h.count(b), 2);

            // Downstream cancels mid-body: the body (and its guard) drops
            // without the upstream ever finishing it.
            drop(first);
            assert_eq!(h.count(a) + h.count(b), 1);
            drop(second);
            assert_eq!((h.count(a), h.count(b)), (0, 0));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_attempt_leaves_no_count_and_the_retry_is_counted() {
    LocalSet::new()
        .run_until(async {
            let closed = {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                listener.local_addr().unwrap()
            };
            let (live, release) = spawn_holding_upstream().await;
            // Enough retries that random picks reach the live host.
            let policy = RetryPolicyIR {
                retry_on: RetryOn::parse("connect-failure"),
                num_retries: 30,
                per_try_timeout: None,
                hedge_on_per_try_timeout: false,
                retriable_status_codes: Vec::new(),
                retry_back_off: RetryBackOff {
                    base_interval: Duration::from_micros(1),
                    max_interval: Duration::from_micros(5),
                },
                host_selection_retry_max_attempts: 1,
                avoid_previous_hosts: false,
            };
            let h = build(&[closed, live], Some(policy)).await;

            let resp = h.send().await;
            assert_eq!(resp.head.status, StatusCode::OK);
            assert_eq!(h.count(closed), 0, "refused attempt must not stay counted");
            assert_eq!(h.count(live), 1, "the retry that succeeded is counted once");

            release.send(true).unwrap();
            tokio::time::timeout(STEP, resp.body.collect())
                .await
                .expect("body completes")
                .expect("body ok");
            assert_eq!((h.count(closed), h.count(live)), (0, 0));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn fast_responses_return_the_count_to_zero() {
    LocalSet::new()
        .run_until(async {
            let a = spawn_fast_upstream().await;
            let b = spawn_fast_upstream().await;
            let h = build(&[a, b], None).await;
            for _ in 0..5 {
                let resp = h.send().await;
                tokio::time::timeout(STEP, resp.body.collect())
                    .await
                    .unwrap()
                    .unwrap();
            }
            assert_eq!((h.count(a), h.count(b)), (0, 0));
        })
        .await;
}
