//! S10 (WP-10 increment 2b/2c) acceptance tests: the HTTP/1.1 WebSocket
//! TUNNEL, end to end through the real router.
//!
//! `websocket_upgrade_tunnel_echoes_bytes_end_to_end` is the core proof and
//! is the one test in this file that must fail if `codec::bridge_upgrade`
//! (the `tokio::io::copy_bidirectional` spawn in `codec::serve_one`) is
//! removed -- it drives a REAL downstream client through the REAL
//! `proxy_http::serve_http1` codec (not just `FilterChainHandler::handle`
//! called directly, which never reaches `serve_one` and so never spawns the
//! bridge at all) against a mock h1 upstream that answers `101` and then
//! echoes raw bytes.
//!
//! The other two tests (403 gate, upstream declines) only need to prove what
//! `HttpResponseParts` the router itself produces, so they call
//! `FilterChainHandler::handle` directly, same convention as
//! `response_flags.rs`/`router.rs`'s own tests -- there is no tunnel to
//! bridge in either case.

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
use proxy_config::ir::{
    CircuitBreakers, ClusterConfig, ClusterKind, ClusterName, DiscoveryType, EndpointIR,
    ForwardAction, ForwardTarget, LbPolicy, PathMatch, RouteActionIR, RouteEntry, RouteMatcher,
    RouteTable, UpgradeConfig, VirtualHostIR,
};
use proxy_http::codec::{serve_http1, Http1Options};
use proxy_http::filter::{RequestHeaders, TerminalFilterInstanceFactory};
use proxy_http::filter_manager::FilterChainHandler;
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
use proxy_http::router::RouterFilterFactory;
use proxy_http::stat_handles::RouterStats;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::LocalSet;

// --- shared scaffolding (same conventions as `response_flags.rs`/`router.rs`) --

fn test_router_stats(cluster_names: &[&str]) -> Arc<RouterStats> {
    use proxy_http::stat_handles::StatHandles;
    use proxy_observability::stats::{StatsControl, WorkerId};
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

fn forward_to_up() -> ForwardAction {
    ForwardAction {
        target: ForwardTarget::Cluster("up".to_string()),
        timeout: None,
        idle_timeout: None,
        retry_policy: None,
        host_rewrite_literal: None,
        prefix_rewrite: None,
    }
}

/// One-cluster (`"up"`, pointed at `addr`), one-route (`/`, `Forward`)
/// `FilterChainHandler`, with `upgrade_configs` set to `upgrade_configs` --
/// the S10 knob every test in this file varies. Otherwise identical shape to
/// `router.rs`'s own `build_router_with_stats_table` / `response_flags.rs`'s
/// `build_router`, duplicated here because each `tests/*.rs` file is its own
/// compilation unit (see `harness.rs`'s doc in `testing/diffrig` for the same
/// reasoning, in a different crate).
async fn build_router(addr: SocketAddr, upgrade_configs: Vec<UpgradeConfig>) -> FilterChainHandler {
    let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
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
            circuit_breakers: CircuitBreakers::default(),
            upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
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
                matcher: prefix_matcher("/"),
                action: RouteActionIR::Forward(forward_to_up()),
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
            .with_upgrade_configs(upgrade_configs),
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

/// A request carrying (or not) the `Upgrade`/`Connection: Upgrade` header
/// pair -- `on_upgrade` is a synthetic `hyper::upgrade::OnUpgrade` built via
/// `hyper::upgrade::on` on a hand-built (never wire-parsed) request, exactly
/// as `codec::serve_one` would produce for a real one; see this module's
/// doc for why the two direct-`.handle()` tests can use a handle that never
/// resolves (they never await it).
fn upgrade_request(path: &'static str, want_upgrade: bool) -> HttpRequestParts {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    let on_upgrade = if want_upgrade {
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
        Some(hyper::upgrade::on(&mut synthetic))
    } else {
        None
    };
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
        on_upgrade,
    }
}

/// A mock h1 WebSocket upstream: on the first request, answers `101
/// Switching Protocols` + `Upgrade`/`Connection` headers (the handshake
/// shape S10.1 tunnels), then echoes every subsequent byte back verbatim
/// until the peer closes -- what `websocket_upgrade_tunnel_echoes_bytes_end_to_end`
/// drives raw bytes through. `accepted` lets the 403 test assert this was
/// never even dialed.
async fn spawn_upgrade_echo_upstream(accepted: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        accepted.fetch_add(1, Ordering::SeqCst);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let request_text = String::from_utf8_lossy(&buf).to_ascii_lowercase();
        assert!(
            request_text.contains("upgrade: websocket"),
            "expected the router to forward the Upgrade header, got: {request_text:?}"
        );
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\r\n",
            )
            .await
            .unwrap();
        // Raw byte echo, forever -- no WebSocket framing, matching the
        // task's "raw bytes are the point" (mirrors `hyper_spike.rs`
        // finding (e)).
        let mut echo_buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut echo_buf).await.unwrap();
            if n == 0 {
                return;
            }
            stream.write_all(&echo_buf[..n]).await.unwrap();
        }
    });
    addr
}

/// A mock upstream that DECLINES every upgrade request outright: answers a
/// plain `200 OK` instead of `101` -- what
/// `upstream_declining_upgrade_passes_the_response_through` drives.
async fn spawn_upgrade_declining_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nno websocket\n",
            )
            .await;
    });
    addr
}

/// **The core proof.** Drives a REAL downstream client through the REAL
/// `proxy_http::serve_http1` codec (not `FilterChainHandler::handle` called
/// directly -- see this module's doc) against a router whose HCM enables
/// `websocket` in `upgrade_configs`, forwarding to the mock echo upstream
/// above. Asserts the `101` handshake, then a raw byte round-trip through
/// the tunnel -- this is exactly what breaks if `codec::bridge_upgrade`'s
/// `tokio::task::spawn_local` is removed (the client's `write_all`/
/// `read_exact` below would simply hang, since nothing would ever be
/// draining the downstream `Upgraded` stream into the upstream one).
#[tokio::test(flavor = "current_thread")]
async fn websocket_upgrade_tunnel_echoes_bytes_end_to_end() {
    LocalSet::new()
        .run_until(async {
            let accepted = Arc::new(AtomicUsize::new(0));
            let upstream_addr = spawn_upgrade_echo_upstream(accepted.clone()).await;

            let handler: Rc<dyn StreamHandler> = Rc::new(
                build_router(
                    upstream_addr,
                    vec![UpgradeConfig {
                        upgrade_type: "websocket".to_string(),
                        enabled: true,
                    }],
                )
                .await,
            );

            // Serve the downstream side of a `tokio::io::duplex` with the
            // REAL codec, in the background -- same shape
            // `tests/hyper_spike.rs` finding (e) uses for its server half,
            // just through the actual proxy stack instead of a bare
            // `service_fn`. `serve_http1`'s own `.with_upgrades()` (already
            // landed, S10 increment 2a) is what lets the eventual `101`
            // response's `OnUpgrade` resolve at all.
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            tokio::task::spawn_local(async move {
                let _ = serve_http1(
                    server_io,
                    handler,
                    Http1Options { keep_alive: true },
                    async {
                        let _ = shutdown_rx.await;
                    },
                    DownstreamInfo::loopback(),
                )
                .await;
            });

            // The downstream CLIENT, low-level hyper API, `.with_upgrades()`
            // on both the connection AND (below) via `hyper::upgrade::on` --
            // spike finding (e)'s caveat (1): the client side is the one
            // that's easy to forget.
            let io = TokioIo::new(client_io);
            let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io)
                .await
                .expect("client handshake");
            tokio::task::spawn_local(async move {
                let _ = conn.with_upgrades().await;
            });

            let req = http::Request::builder()
                .method("GET")
                .uri("/chat")
                .header(http::header::HOST, "test.local")
                .header(http::header::UPGRADE, "websocket")
                .header(http::header::CONNECTION, "Upgrade")
                .body(Empty::<Bytes>::new())
                .unwrap();

            let mut response = sender.send_request(req).await.expect("send_request");
            assert_eq!(
                response.status(),
                StatusCode::SWITCHING_PROTOCOLS,
                "expected the router to tunnel an allowed, upstream-accepted upgrade"
            );
            assert_eq!(
                response.headers().get(http::header::UPGRADE).unwrap(),
                "websocket"
            );

            let client_upgraded = hyper::upgrade::on(&mut response)
                .await
                .expect("client obtains the upgraded stream once the 101 has been sent");
            let mut client_upgraded = TokioIo::new(client_upgraded);

            const PING: &[u8] = b"ping-through-the-proxy-tunnel";
            client_upgraded
                .write_all(PING)
                .await
                .expect("client writes its half of the tunnel");
            client_upgraded.flush().await.unwrap();

            let mut reply = [0u8; PING.len()];
            client_upgraded.read_exact(&mut reply).await.expect(
                "client reads the bytes echoed back through the proxy's bridge -- \
                     this is what hangs if bridge_upgrade's spawn is removed",
            );
            assert_eq!(
                &reply, PING,
                "the tunnel must round-trip raw bytes byte-for-byte"
            );

            assert_eq!(
                accepted.load(Ordering::SeqCst),
                1,
                "exactly one upstream connection should have been dialed"
            );
        })
        .await;
}

/// S10.1: an `Upgrade: websocket` request against an HCM that does NOT
/// enable `websocket` (empty `upgrade_configs`) is refused with `403`, and
/// the upstream is never dialed at all.
#[tokio::test(flavor = "current_thread")]
async fn disallowed_upgrade_returns_403_and_never_dials_upstream() {
    LocalSet::new()
        .run_until(async {
            let accepted = Arc::new(AtomicUsize::new(0));
            let upstream_addr = spawn_upgrade_echo_upstream(accepted.clone()).await;

            // Empty `upgrade_configs`: the Envoy default, "no upgrades".
            let router = build_router(upstream_addr, Vec::new()).await;

            let resp = router.handle(upgrade_request("/chat", true)).await;
            assert_eq!(resp.head.status, StatusCode::FORBIDDEN);
            assert!(
                resp.upgrade.is_none(),
                "a disallowed upgrade must never produce a tunnel"
            );

            // Give the (would-be) dial every chance to have happened before
            // asserting it didn't -- there is no dial to await here, so a
            // short yield is the honest way to let a wrongly-spawned one
            // surface if the gate were broken.
            tokio::task::yield_now().await;
            assert_eq!(
                accepted.load(Ordering::SeqCst),
                0,
                "a disallowed upgrade must never reach the upstream dial"
            );
        })
        .await;
}

/// S10.1: an `enabled: false` entry is exactly as disallowed as no entry at
/// all -- there is no third state.
#[tokio::test(flavor = "current_thread")]
async fn upgrade_type_present_but_disabled_returns_403() {
    LocalSet::new()
        .run_until(async {
            let accepted = Arc::new(AtomicUsize::new(0));
            let upstream_addr = spawn_upgrade_echo_upstream(accepted.clone()).await;

            let router = build_router(
                upstream_addr,
                vec![UpgradeConfig {
                    upgrade_type: "websocket".to_string(),
                    enabled: false,
                }],
            )
            .await;

            let resp = router.handle(upgrade_request("/chat", true)).await;
            assert_eq!(resp.head.status, StatusCode::FORBIDDEN);
            assert!(resp.upgrade.is_none());
        })
        .await;
}

/// S10.1: when the upstream declines the upgrade (answers something other
/// than `101` -- here a plain `200`), that response is passed straight
/// through to the client with no tunnel, and the request never hangs.
#[tokio::test(flavor = "current_thread")]
async fn upstream_declining_upgrade_passes_the_response_through() {
    LocalSet::new()
        .run_until(async {
            let upstream_addr = spawn_upgrade_declining_upstream().await;
            let router = build_router(
                upstream_addr,
                vec![UpgradeConfig {
                    upgrade_type: "websocket".to_string(),
                    enabled: true,
                }],
            )
            .await;

            let resp = router.handle(upgrade_request("/chat", true)).await;
            assert_eq!(
                resp.head.status,
                StatusCode::OK,
                "the upstream's actual (non-101) response must pass through unmodified"
            );
            assert!(
                resp.upgrade.is_none(),
                "a declined upgrade must never produce a tunnel"
            );

            let body = resp.body.collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"no websocket\n");
        })
        .await;
}
