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
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::rt::TokioIo;
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::resolver::FakeResolver;
use proxy_cluster::{ClusterEntry, LoadBalancerContext};
use proxy_config::ir::{
    ClusterConfig, ClusterKind, ClusterName, DiscoveryType, EndpointIR, ForwardAction,
    ForwardTarget, LbPolicy, PathMatch, RetryBackOff, RetryOn, RetryPolicyIR, RouteActionIR,
    RouteEntry, RouteMatcher, RouteTable, UpgradeConfig, VirtualHostIR,
};
use proxy_http::codec::{serve_http1, Http1Options};
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
        count_of(self.entry.as_ref(), addr)
    }

    async fn send(&self) -> HttpResponseParts {
        tokio::time::timeout(STEP, self.router.handle(request()))
            .await
            .expect("router answers within the step timeout")
    }
}

fn count_of(entry: &dyn ClusterEntry, addr: SocketAddr) -> u64 {
    let ctx = LoadBalancerContext {
        host_override: Some(addr),
        ..Default::default()
    };
    let sel = entry.select_host(&ctx).expect("host exists");
    assert_eq!(sel.host.address, addr, "override must resolve to `addr`");
    sel.host.active_request_count()
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
    build_with(addrs, retry_policy, Vec::new()).await
}

async fn build_with(
    addrs: &[SocketAddr],
    retry_policy: Option<RetryPolicyIR>,
    upgrade_configs: Vec<UpgradeConfig>,
) -> Harness {
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
        Arc::new(RouterFilterFactory::new(manager, stats).with_upgrade_configs(upgrade_configs));
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

fn websocket_enabled() -> Vec<UpgradeConfig> {
    vec![UpgradeConfig {
        upgrade_type: "websocket".to_string(),
        enabled: true,
    }]
}

/// Poll `cond` until true, bounded by `STEP`; no fixed sleep window.
async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    tokio::time::timeout(STEP, async {
        while !cond() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for: {what}"));
}

/// Upstream that answers `101` and echoes raw bytes until the peer closes.
async fn spawn_upgrade_echo_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_head(&mut stream).await;
        let head =
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        if stream.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if stream.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    addr
}

#[tokio::test(flavor = "current_thread")]
async fn an_accepted_upgrade_holds_the_count_for_the_tunnel_lifetime() {
    LocalSet::new()
        .run_until(async {
            let up = spawn_upgrade_echo_upstream().await;
            let h = build_with(&[up], None, websocket_enabled()).await;
            let entry = h.entry.clone();
            // The real codec is needed: only `serve_http1` spawns the tunnel
            // bridge that owns the guard.
            let handler: Rc<dyn StreamHandler> = Rc::new(h.router);

            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            tokio::task::spawn_local(async move {
                let _ = serve_http1(
                    server_io,
                    handler,
                    Http1Options {
                        keep_alive: true,
                        header_read_timeout: None,
                        request_head_limits: Default::default(),
                    },
                    std::future::pending::<()>(),
                    DownstreamInfo::loopback(),
                )
                .await;
            });
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(client_io))
                    .await
                    .expect("client handshake");
            tokio::task::spawn_local(async move {
                let _ = conn.with_upgrades().await;
            });

            let req = http::Request::builder()
                .uri("/v1/chat")
                .header(http::header::HOST, "test.local")
                .header(http::header::UPGRADE, "websocket")
                .header(http::header::CONNECTION, "Upgrade")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let mut response = tokio::time::timeout(STEP, sender.send_request(req))
                .await
                .expect("101 within step")
                .expect("send_request");
            assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
            let upgraded = tokio::time::timeout(STEP, hyper::upgrade::on(&mut response))
                .await
                .expect("upgrade resolves")
                .expect("upgraded stream");
            let mut tunnel = TokioIo::new(upgraded);

            // An echo round trip proves the bridge task is running, so the
            // count below is read while the tunnel owns the guard.
            tunnel.write_all(b"ping").await.unwrap();
            let mut reply = [0u8; 4];
            tokio::time::timeout(STEP, tunnel.read_exact(&mut reply))
                .await
                .expect("echo within step")
                .expect("echo ok");
            assert_eq!(&reply, b"ping");
            assert_eq!(
                count_of(entry.as_ref(), up),
                1,
                "open tunnel holds one count"
            );

            drop(tunnel);
            eventually("tunnel close releases the count", || {
                count_of(entry.as_ref(), up) == 0
            })
            .await;
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_declined_upgrade_holds_the_count_until_the_response_body_ends() {
    LocalSet::new()
        .run_until(async {
            let (up, release) = spawn_holding_upstream().await;
            let h = build_with(&[up], None, websocket_enabled()).await;

            let mut req = request();
            req.head.method = Method::GET;
            req.head
                .headers
                .insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
            req.head.headers.insert(
                http::header::CONNECTION,
                HeaderValue::from_static("Upgrade"),
            );
            // Rust note: a hand-built request never reaches the wire; this only
            // yields the `OnUpgrade` handle the router requires.
            let mut synthetic = http::Request::builder().body(()).unwrap();
            req.on_upgrade = Some(hyper::upgrade::on(&mut synthetic));

            let resp = tokio::time::timeout(STEP, h.router.handle(req))
                .await
                .expect("router answers");
            assert_eq!(resp.head.status, StatusCode::OK, "upstream declined");
            assert_eq!(h.count(up), 1, "declined response body holds the guard");

            release.send(true).unwrap();
            tokio::time::timeout(STEP, resp.body.collect())
                .await
                .expect("body completes")
                .expect("body ok");
            assert_eq!(h.count(up), 0);
        })
        .await;
}

/// Hedged GET: the original attempt (first connection accepted by either
/// upstream) never answers; the hedge on the other host does, once the test
/// has read both counts.
#[tokio::test(flavor = "current_thread")]
async fn a_hedge_counts_each_attempted_host_once_and_releases_both() {
    LocalSet::new()
        .run_until(async {
            let accepted = Arc::new(AtomicUsize::new(0));
            let (go_tx, go_rx) = tokio::sync::watch::channel(false);
            let mut addrs = Vec::new();
            for _ in 0..2 {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                addrs.push(listener.local_addr().unwrap());
                let accepted = accepted.clone();
                let go_rx = go_rx.clone();
                tokio::spawn(async move {
                    loop {
                        let (mut stream, _) = listener.accept().await.unwrap();
                        let attempt = accepted.fetch_add(1, Ordering::SeqCst);
                        let mut go_rx = go_rx.clone();
                        tokio::spawn(async move {
                            read_head(&mut stream).await;
                            if attempt == 0 {
                                // Original: hold the connection until the
                                // proxy cancels it (read sees EOF/reset).
                                let mut b = [0u8; 1];
                                let _ = stream.read(&mut b).await;
                                return;
                            }
                            let _ = go_rx.wait_for(|go| *go).await;
                            let _ = stream
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                                )
                                .await;
                        });
                    }
                });
            }
            let policy = RetryPolicyIR {
                retry_on: RetryOn::parse("5xx"),
                num_retries: 1,
                per_try_timeout: Some(Duration::from_millis(50)),
                hedge_on_per_try_timeout: true,
                retriable_status_codes: Vec::new(),
                retry_back_off: RetryBackOff {
                    base_interval: Duration::from_micros(1),
                    max_interval: Duration::from_micros(5),
                },
                host_selection_retry_max_attempts: 1,
                avoid_previous_hosts: false,
            };
            let h = build(&addrs, Some(policy)).await;
            let mut req = request();
            req.head.method = Method::GET;

            let probe = async {
                eventually("both attempts dispatched", || {
                    accepted.load(Ordering::SeqCst) == 2
                })
                .await;
                // Original is in the hedge task, hedge in the router loop.
                eventually("each attempted host counts exactly one", || {
                    h.count(addrs[0]) == 1 && h.count(addrs[1]) == 1
                })
                .await;
                go_tx.send(true).unwrap();
            };
            let (resp, ()) = tokio::join!(
                async {
                    tokio::time::timeout(STEP, h.router.handle(req))
                        .await
                        .expect("hedge answers")
                },
                probe
            );
            assert_eq!(resp.head.status, StatusCode::OK);
            tokio::time::timeout(STEP, resp.body.collect())
                .await
                .expect("body completes")
                .expect("body ok");
            eventually("winner and cancelled loser both release", || {
                h.count(addrs[0]) == 0 && h.count(addrs[1]) == 0
            })
            .await;
        })
        .await;
}
