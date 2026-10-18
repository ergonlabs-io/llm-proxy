//! S10 acceptance tests for HTTP/1.1 WebSocket tunnels through the router.
//! The echo test uses the real codec to exercise `bridge_upgrade`; the 403
//! and upstream-decline tests inspect router responses directly because no
//! tunnel is established.

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

/// One-cluster, one-route handler with the supplied `upgrade_configs`.
/// Each integration-test file is a separate compilation unit, so this helper
/// is local to the file.
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
                matcher: prefix_matcher("/"),
                action: RouteActionIR::Forward(forward_to_up()),
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

/// Build an upgrade request with a synthetic `OnUpgrade` handle, as
/// `codec::serve_one` does for a wire-parsed request.
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

/// Accept a WebSocket handshake, echo bytes until the peer closes, and
/// record whether the upstream was dialed.
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
        // S9 rule 6 strips `Connection`, so the h1 codec must request the
        // protocol switch again.
        let wants_switch = request_text.contains("upgrade: websocket")
            && request_text.contains("connection: upgrade\r\n")
            && !request_text.contains("keep-alive");
        if !wants_switch {
            return;
        }
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade, keep-alive\r\n\
                  Keep-Alive: timeout=5\r\n\r\n",
            )
            .await
            .unwrap();
        // Echo raw tunnel bytes; WebSocket framing is outside this codec test.
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

/// Decline upgrade requests with a plain `200 OK`.
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

/// Exercise the real codec and verify the `101` handshake and raw byte
/// round-trip. This catches a missing `bridge_upgrade` task, which would
/// leave the downstream upgraded stream undrained.
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

            // `.with_upgrades()` lets the `101` response's `OnUpgrade` resolve.
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            tokio::task::spawn_local(async move {
                let _ = serve_http1(
                    server_io,
                    handler,
                    Http1Options {
                        keep_alive: true,
                        header_read_timeout: None,
                        request_head_limits: Default::default(),
                    },
                    async {
                        let _ = shutdown_rx.await;
                    },
                    DownstreamInfo::loopback(),
                )
                .await;
            });

            // The client also needs `.with_upgrades()` for `hyper::upgrade::on`.
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
                .header(http::header::CONNECTION, "keep-alive, Upgrade")
                .header("keep-alive", "timeout=5")
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
            // The client needs `Connection: upgrade` on the 101 response.
            assert_eq!(
                response.headers().get(http::header::CONNECTION).unwrap(),
                "upgrade"
            );
            assert!(!response.headers().contains_key("keep-alive"));

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

            // Let a wrongly spawned upstream request surface before asserting.
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
            let (sink, mut records) = proxy_observability::records::BoundedRecordSink::new(1);
            let router = build_router(
                upstream_addr,
                vec![UpgradeConfig {
                    upgrade_type: "websocket".to_string(),
                    enabled: true,
                }],
            )
            .await
            .with_request_record_sink(Arc::new(sink));

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
            let record = records.try_recv().unwrap();
            assert_eq!(record.attempt_count, 1);
            assert_eq!(record.attempts[0].status, Some(200));
            assert_eq!(record.attempts[0].bytes_response, body.len() as u64);
            assert_eq!(
                record.attempts[0].termination,
                proxy_observability::records::Termination::Complete
            );
        })
        .await;
}
