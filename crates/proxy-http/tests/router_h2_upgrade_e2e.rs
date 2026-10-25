//! S10.2 tests for same-protocol h2 extended CONNECT tunneling and rejection
//! of cross-protocol upgrades. The end-to-end case exercises the real codec,
//! router, and mock upstream; rejection cases assert no upstream dial occurs.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::resolver::FakeResolver;
use proxy_config::ir::{
    CircuitBreakers, ClusterConfig, ClusterKind, ClusterName, DiscoveryType, EndpointIR,
    ForwardAction, ForwardTarget, LbPolicy, PathMatch, RouteActionIR, RouteEntry, RouteMatcher,
    RouteTable, UpgradeConfig, UpstreamProtocol, VirtualHostIR,
};
use proxy_http::codec::serve_http2;
use proxy_http::filter::{RequestHeaders, TerminalFilterInstanceFactory};
use proxy_http::filter_manager::FilterChainHandler;
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
use proxy_http::router::RouterFilterFactory;
use proxy_http::stat_handles::RouterStats;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::LocalSet;

// --- shared scaffolding (same conventions as `router_upgrade_e2e.rs`) --

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

/// One-cluster (`"up"`, pointed at `addr`, protocol `proto`), one-route
/// (`/`, `Forward`) `FilterChainHandler`, with `upgrade_configs` set to
/// `upgrade_configs`. Parameterized over `proto` (unlike
/// `router_upgrade_e2e.rs`'s own always-h1 `build_router`) so this one file
/// can build both the h1- and h2-upstream clusters S10.2's same-protocol
/// enforcement needs to exercise both the allowed h2<->h2 path and the two
/// disallowed cross-protocol combinations.
async fn build_router(
    addr: SocketAddr,
    proto: UpstreamProtocol,
    upgrade_configs: Vec<UpgradeConfig>,
) -> FilterChainHandler {
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
            upstream_protocol: proto,
            request_headers_to_add: Vec::new(),
            request_path_rewrite: None,
            provider_runtime: None,
            usage_dialect: None,
            unanswered_usage: proxy_config::ir::UnansweredUsage::default(),
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
                include_routing_headers_in_response: false,
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

/// A downstream request carrying the H1 upgrade signal (`Upgrade` +
/// `Connection: Upgrade`, `GET`) -- used by the h1-downstream cross-protocol
/// test. `on_upgrade` is a synthetic `hyper::upgrade::OnUpgrade` built on a
/// hand-built (never wire-parsed) request, same convention
/// `router_upgrade_e2e.rs`'s own `upgrade_request` uses -- never awaited
/// here since both cross-protocol tests are rejected before any tunnel is
/// built.
fn h1_upgrade_request(path: &'static str) -> HttpRequestParts {
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
        on_upgrade: Some(hyper::upgrade::on(&mut synthetic)),
    }
}

/// A downstream request carrying the H2 extended-CONNECT signal --
/// `method: CONNECT` plus the synthetic `Upgrade` header
/// `codec::serve_one`'s h2-detection path would have produced (see that
/// call site's Rust note); used by the h2-downstream cross-protocol test.
fn h2_connect_request(path: &'static str) -> HttpRequestParts {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
    let mut synthetic = http::Request::builder()
        .method(Method::CONNECT)
        .uri(path)
        .body(())
        .unwrap();
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::CONNECT,
            uri: Uri::from_static(path),
            headers,
        },
        body: local_boxed(
            Full::new(Bytes::new())
                .map_err(|infallible: std::convert::Infallible| match infallible {}),
        ),
        downstream: DownstreamInfo::loopback(),
        on_upgrade: Some(hyper::upgrade::on(&mut synthetic)),
    }
}

/// A listener that must NEVER be dialed -- S10.2's cross-protocol rejection
/// happens before `pool.new_stream()` runs at all, so `accepted` must stay
/// `0` for the whole test. Deliberately speaks no protocol at all (there is
/// nothing that should ever reach it); it only counts accepts so the tests
/// can assert none happened.
fn spawn_never_dialed_listener() -> (SocketAddr, Arc<AtomicUsize>) {
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_in_task = accepted.clone();
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let addr = std_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let listener = TcpListener::from_std(std_listener).unwrap();
        loop {
            let Ok((_stream, _)) = listener.accept().await else {
                return;
            };
            accepted_in_task.fetch_add(1, Ordering::SeqCst);
        }
    });
    (addr, accepted)
}

/// A mock h2 WebSocket upstream: accepts one connection, opts in to RFC 8441
/// extended CONNECT (`enable_connect_protocol`, mirroring
/// `codec::serve_http2`'s own opt-in), and on a `CONNECT` request carrying
/// `:protocol: websocket` answers `200` then echoes bytes back over the
/// upgraded stream until the client half-closes -- at which point it
/// half-closes its own send direction too (finding (g) caveat (4): an h2
/// CONNECT stream does not end on its own, unlike an h1 Upgrade's
/// connection). `TokioExecutor`/`tokio::spawn` throughout (not
/// `spawn_local`): every body/type this mock touches is `Send`
/// (`Empty<Bytes>`, raw bytes), the identical reasoning
/// `tests/hyper_spike.rs` finding (g) itself documents for its own
/// `#[tokio::test]`-flavor server -- this mock exists purely to stand in for
/// a real h2 origin, not to exercise this crate's `!Send` data-plane types.
async fn spawn_h2_websocket_echo_upstream(accepted: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accepted.fetch_add(1, Ordering::SeqCst);
        let io = TokioIo::new(stream);

        let service = service_fn(
            |mut req: hyper::Request<hyper::body::Incoming>| async move {
                assert_eq!(
                    req.method(),
                    Method::CONNECT,
                    "expected an extended CONNECT"
                );
                let protocol = req.extensions().get::<hyper::ext::Protocol>().cloned();
                assert_eq!(
                    protocol.as_ref().map(|p| p.as_str()),
                    Some("websocket"),
                    "expected the router to forward the :protocol pseudo-header"
                );
                // Same ordering rule as `codec::serve_one`/`hyper_spike.rs`
                // finding (g): `hyper::upgrade::on` must run on the request
                // before this handler returns its response.
                let on_upgrade = hyper::upgrade::on(&mut req);
                tokio::spawn(async move {
                    let upgraded = on_upgrade
                        .await
                        .expect("server obtains the upgraded h2 stream");
                    let mut io = TokioIo::new(upgraded);
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = io
                            .read(&mut buf)
                            .await
                            .expect("server reads the tunnel bytes");
                        if n == 0 {
                            break;
                        }
                        io.write_all(&buf[..n])
                            .await
                            .expect("server echoes the tunnel bytes back");
                    }
                    io.flush().await.unwrap();
                    // Half-close the server -> client direction -- required for
                    // an h2 CONNECT stream specifically (finding (g) caveat (4)):
                    // it does not end on its own the way an h1 Upgrade's
                    // connection close does.
                    io.shutdown()
                        .await
                        .expect("server half-closes its send direction");
                });
                let resp = hyper::Response::builder()
                    .status(StatusCode::OK)
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                Ok::<_, std::convert::Infallible>(resp)
            },
        );

        let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        builder.enable_connect_protocol();
        builder
            .serve_connection(io, service)
            .await
            .expect("mock h2 upstream connection");
    });
    addr
}

/// **The core proof.** Drives a REAL downstream h2 client (extended CONNECT)
/// through the REAL `proxy_http::serve_http2` codec against a router whose
/// HCM enables `websocket` in `upgrade_configs`, forwarding to an h2-upstream
/// cluster pointed at the mock echo upstream above. Asserts the `200` accept,
/// a raw byte round trip through the tunnel, AND that the downstream
/// connection terminates cleanly once both sides half-close -- this is what
/// breaks (hangs) if `codec::bridge_upgrade`'s `tokio::task::spawn_local` is
/// removed, or if `serve_http2`'s `.enable_connect_protocol()` /
/// `serve_one`'s h2-detection were reverted (in which case the server would
/// never even wire up `on_upgrade` for the CONNECT stream in the first
/// place -- `hyper::upgrade::on` on the CLIENT side would then simply never
/// resolve, since the server never sent an upgradeable `200`).
#[tokio::test(flavor = "current_thread")]
async fn h2_websocket_tunnel_echoes_bytes_end_to_end() {
    LocalSet::new()
        .run_until(async {
            let accepted = Arc::new(AtomicUsize::new(0));
            let upstream_addr = spawn_h2_websocket_echo_upstream(accepted.clone()).await;

            let handler: Rc<dyn StreamHandler> = Rc::new(
                build_router(
                    upstream_addr,
                    UpstreamProtocol::Http2,
                    vec![UpgradeConfig {
                        upgrade_type: "websocket".to_string(),
                        enabled: true,
                    }],
                )
                .await,
            );

            // Serve the downstream side of a `tokio::io::duplex` with the
            // REAL codec, in the background -- same shape
            // `router_upgrade_e2e.rs`'s own h1 test uses, `serve_http2`
            // instead of `serve_http1`. `serve_http2`'s own
            // `.enable_connect_protocol()` is what lets an
            // extended CONNECT reach this connection at all.
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let downstream_task = tokio::task::spawn_local(async move {
                serve_http2(
                    server_io,
                    handler,
                    Default::default(),
                    async {
                        let _ = shutdown_rx.await;
                    },
                    DownstreamInfo::loopback(),
                )
                .await
            });

            // The downstream CLIENT, low-level hyper h2 API -- same shape as
            // `tests/hyper_spike.rs` finding (g)'s client half. `Send`
            // throughout (`Empty<Bytes>`), so `tokio::spawn`/`TokioExecutor`
            // are fine here even though this whole test runs inside a
            // `LocalSet` (see `spawn_h2_websocket_echo_upstream`'s own doc
            // for the identical reasoning).
            let io = TokioIo::new(client_io);
            let (mut sender, conn) = hyper::client::conn::http2::handshake::<_, _, Empty<Bytes>>(
                TokioExecutor::new(),
                io,
            )
            .await
            .expect("client handshake");
            tokio::spawn(async move {
                let _ = conn.await;
            });

            let mut req = http::Request::builder()
                .method(Method::CONNECT)
                .uri("https://test.local/chat")
                .header(http::header::HOST, "test.local")
                .body(Empty::<Bytes>::new())
                .unwrap();
            req.extensions_mut()
                .insert(hyper::ext::Protocol::from_static("websocket"));

            let mut response = sender.send_request(req).await.expect("send_request");
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "expected the router to tunnel an allowed, upstream-accepted h2 extended CONNECT \
                 with exactly 200 (finding (g) caveat (1))"
            );

            let client_upgraded = hyper::upgrade::on(&mut response)
                .await
                .expect("client obtains the upgraded h2 stream once the 200 has been sent");
            let mut client_upgraded = TokioIo::new(client_upgraded);

            const PING: &[u8] = b"ping-through-the-h2-proxy-tunnel";
            client_upgraded
                .write_all(PING)
                .await
                .expect("client writes its half of the tunnel");
            client_upgraded.flush().await.unwrap();
            // Half-close the client -> server direction. Required for an h2
            // CONNECT stream specifically (see `spawn_h2_websocket_echo_upstream`'s
            // doc); the read below still works after this (half-close, not a
            // full close).
            client_upgraded
                .shutdown()
                .await
                .expect("client half-closes its send direction");

            let mut reply = [0u8; PING.len()];
            client_upgraded.read_exact(&mut reply).await.expect(
                "client reads the bytes echoed back through the proxy's bridge -- this is what \
                 hangs if bridge_upgrade's spawn (or the h2 CONNECT plumbing) is broken",
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

            // Prove the tunnel -- and this whole downstream connection --
            // actually TERMINATES, not just that bytes moved. An h2 CONNECT
            // stream does not self-close (finding (g) caveat (4)); this
            // connection has one stream, and it is fully bidirectionally
            // closed only once BOTH the client's explicit `.shutdown()`
            // above AND the mock upstream's own explicit `.shutdown()` (in
            // its echo loop) have each propagated through
            // `codec::bridge_upgrade`'s `tokio::io::copy_bidirectional` --
            // which shuts down the opposite side's write half on read EOF,
            // the same mechanism an explicit `.shutdown()` call drives
            // (`AsyncWrite::poll_shutdown`), so no additional explicit
            // shutdown inside `bridge_upgrade` itself was needed for this to
            // work.
            //
            // The join below only asserts `downstream_task` resolves at all
            // within the timeout (a hang would fail it, and nextest's own
            // `terminate-after` is the second line of defense) -- it does
            // NOT require `serve_http2` to return `Ok(())` specifically.
            // Measured empirically: it reliably returns
            // `Err(Connection(BrokenPipe))` instead. That is a real,
            // benign race, not evidence of a bug -- confirmed by instrumenting
            // the CLIENT's own connection future, which resolves `Ok(())`
            // (a clean h2 GOAWAY exchange) *before* this server-side await
            // observes anything: once its one-shot CONNECT tunnel is done,
            // the h2 client closes its whole connection on its own (the
            // same thing this project's OWN upstream h2 client codec does --
            // see `codec::send_upstream_h2_connect`'s doc on dropping
            // `sender`), and `graceful_shutdown` here loses the race to
            // finish writing its own final frames before that peer close
            // reaches this end of the duplex. A real TCP socket would
            // surface the identical race as `ECONNRESET`/`EPIPE`; nothing
            // about it is specific to h2, to this test's duplex transport,
            // or to `bridge_upgrade`.
            let _ = shutdown_tx.send(());
            let _ = tokio::time::timeout(Duration::from_secs(5), downstream_task)
                .await
                .expect(
                    "downstream serve_http2 connection must terminate, not hang -- this is what \
                     proves the h2 CONNECT half-close chain (client shutdown -> bridge_upgrade \
                     -> mock upstream shutdown -> bridge_upgrade -> this connection) actually \
                     completes rather than leaving the stream open forever",
                )
                .expect("downstream task must not panic");
        })
        .await;
}

/// S10.2: an h2 downstream extended CONNECT routed to an H1-UPSTREAM cluster
/// is a disallowed cross-protocol combination -- `502`, no tunnel, and (like
/// `router_upgrade_e2e.rs`'s 403 test) the upstream is never dialed at all:
/// the rejection happens before `pool.new_stream()` runs.
#[tokio::test(flavor = "current_thread")]
async fn h2_downstream_to_h1_upstream_is_rejected_as_cross_protocol() {
    LocalSet::new()
        .run_until(async {
            let (addr, accepted) = spawn_never_dialed_listener();
            let router = build_router(
                addr,
                UpstreamProtocol::Http1,
                vec![UpgradeConfig {
                    upgrade_type: "websocket".to_string(),
                    enabled: true,
                }],
            )
            .await;

            let resp = router.handle(h2_connect_request("/chat")).await;
            assert_eq!(resp.head.status, StatusCode::BAD_GATEWAY);
            assert!(
                resp.upgrade.is_none(),
                "a cross-protocol upgrade must never produce a tunnel"
            );
            let body = resp.body.collect().await.unwrap().to_bytes();
            assert!(
                String::from_utf8_lossy(&body).contains("cross-protocol"),
                "expected the cross-protocol message, got: {body:?}"
            );

            tokio::task::yield_now().await;
            assert_eq!(
                accepted.load(Ordering::SeqCst),
                0,
                "a cross-protocol upgrade must never reach the upstream dial"
            );
        })
        .await;
}

/// S10.2's symmetric case: an h1 downstream `Upgrade` request routed to an
/// H2-UPSTREAM cluster is equally disallowed -- same `502`, no tunnel, no
/// dial.
#[tokio::test(flavor = "current_thread")]
async fn h1_downstream_to_h2_upstream_is_rejected_as_cross_protocol() {
    LocalSet::new()
        .run_until(async {
            let (addr, accepted) = spawn_never_dialed_listener();
            let router = build_router(
                addr,
                UpstreamProtocol::Http2,
                vec![UpgradeConfig {
                    upgrade_type: "websocket".to_string(),
                    enabled: true,
                }],
            )
            .await;

            let resp = router.handle(h1_upgrade_request("/chat")).await;
            assert_eq!(resp.head.status, StatusCode::BAD_GATEWAY);
            assert!(
                resp.upgrade.is_none(),
                "a cross-protocol upgrade must never produce a tunnel"
            );
            let body = resp.body.collect().await.unwrap().to_bytes();
            assert!(
                String::from_utf8_lossy(&body).contains("cross-protocol"),
                "expected the cross-protocol message, got: {body:?}"
            );

            tokio::task::yield_now().await;
            assert_eq!(
                accepted.load(Ordering::SeqCst),
                0,
                "a cross-protocol upgrade must never reach the upstream dial"
            );
        })
        .await;
}
