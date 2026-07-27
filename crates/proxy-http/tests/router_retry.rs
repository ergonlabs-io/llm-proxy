//! WP-14 wiring: `RouterHandler` (S3) actually issuing retried attempts.
//! Standalone (not `router.rs`'s own `#[cfg(test)]` module) because it needs
//! upstreams that count/queue multiple requests, which the existing router
//! tests' one-shot helpers don't need.
//!
//! Rust note: same shape as `router.rs`'s own tests --
//! `send_upstream_http1`/`send_upstream_http2` spawn non-`Send` connection
//! driver tasks via `tokio::task::spawn_local`, so every test needs a
//! `LocalSet` on a `current_thread` runtime.

use std::collections::HashMap;
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
    ClusterConfig, ClusterName, DiscoveryType, EndpointIR, ForwardAction, ForwardTarget, LbPolicy,
    PathMatch, RetryBackOff, RetryOn, RetryPolicyIR, RouteActionIR, RouteEntry, RouteMatcher,
    RouteTable, VirtualHostIR,
};
use proxy_http::filter::RequestHeaders;
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
use proxy_http::router::RouterHandler;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::LocalSet;

/// A near-instant backoff so tests don't spend real wall-clock time on S3.3
/// jitter -- `base_interval`/`max_interval` both tiny, the retry loop's
/// `tokio::time::sleep` still runs, just for microseconds.
fn fast_backoff() -> RetryBackOff {
    RetryBackOff {
        base_interval: Duration::from_micros(1),
        max_interval: Duration::from_micros(5),
    }
}

fn retry_policy(retry_on: &str, num_retries: u32) -> RetryPolicyIR {
    RetryPolicyIR {
        retry_on: RetryOn::parse(retry_on),
        num_retries,
        per_try_timeout: None,
        retriable_status_codes: Vec::new(),
        retry_back_off: fast_backoff(),
        host_selection_retry_max_attempts: 1,
    }
}

fn forward_to_up(retry_policy: Option<RetryPolicyIR>) -> ForwardAction {
    ForwardAction {
        target: ForwardTarget::Cluster("up".to_string()),
        timeout: None,
        idle_timeout: None,
        retry_policy,
        host_rewrite_literal: None,
        prefix_rewrite: None,
    }
}

fn prefix_matcher(prefix: &str) -> RouteMatcher {
    RouteMatcher {
        path: PathMatch::Prefix(prefix.to_string()),
        case_sensitive: true,
        headers: Vec::new(),
    }
}

/// Build a one-cluster, one-route `RouterHandler` forwarding to `addr` under
/// cluster name `"up"` -- mirrors `router.rs`'s own `build_router` test
/// helper.
async fn build_router(addr: SocketAddr, fwd: ForwardAction) -> RouterHandler {
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
                request_headers_to_add: Vec::new(),
            })],
        }],
    )
    .unwrap();

    RouterHandler::new(Arc::new(route_table), Arc::new(manager))
}

fn request_with_body(path: &'static str, body: &'static [u8]) -> HttpRequestParts {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static(path),
            headers,
        },
        body: local_boxed(
            Full::new(Bytes::from_static(body))
                .map_err(|infallible: std::convert::Infallible| match infallible {}),
        ),
        downstream: DownstreamInfo::loopback(),
        stream_info: None,
    }
}

fn request(path: &'static str) -> HttpRequestParts {
    request_with_body(path, b"")
}

/// Read one HTTP/1.1 request off `stream` up through its body (using
/// `Content-Length` if present) and return the raw header text plus the body
/// bytes actually received -- used to assert what the upstream saw, on the
/// wire, across multiple attempts.
async fn read_one_request(stream: &mut tokio::net::TcpStream) -> (String, Bytes) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed before headers arrived");
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let content_length: usize = header_text
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.trim().eq_ignore_ascii_case("content-length"))
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0);

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed before body arrived");
        body.extend_from_slice(&chunk[..n]);
    }
    (header_text, Bytes::from(body))
}

/// An upstream that answers the first `fail_count` requests it accepts with
/// `fail_status` (`Connection: close`) and every request after that with
/// `200 OK` -- used to prove a retry lands on a fresh attempt that
/// eventually succeeds. Also records every request body it saw, in order, so
/// tests can assert the replayed body matches the original.
async fn spawn_upstream_fails_then_succeeds(
    fail_count: usize,
    fail_status: u16,
) -> (
    SocketAddr,
    Arc<AtomicUsize>,
    tokio::sync::mpsc::UnboundedReceiver<Bytes>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_task = count.clone();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let attempt = count_task.fetch_add(1, Ordering::SeqCst);
            let (_headers, body) = read_one_request(&mut stream).await;
            let _ = tx.send(body);
            if attempt < fail_count {
                let _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {fail_status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
            } else {
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        }
    });
    (addr, count, rx)
}

#[tokio::test(flavor = "current_thread")]
async fn a_503_is_retried_and_the_second_attempts_200_is_returned() {
    LocalSet::new()
        .run_until(async {
            let (addr, count, _rx) = spawn_upstream_fails_then_succeeds(1, 503).await;
            let router = build_router(addr, forward_to_up(Some(retry_policy("5xx", 1)))).await;

            let resp = router.handle(request("/v1/chat")).await;
            assert_eq!(resp.head.status, StatusCode::OK);
            assert_eq!(
                count.load(Ordering::SeqCst),
                2,
                "expected exactly 2 attempts"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn retries_stop_at_num_retries_and_return_the_last_failure() {
    LocalSet::new()
        .run_until(async {
            // Every attempt fails: num_retries=2 must yield exactly 3
            // attempts total (the original + 2 retries), and the client sees
            // the final (still-failing) response.
            let (addr, count, _rx) = spawn_upstream_fails_then_succeeds(usize::MAX, 503).await;
            let router = build_router(addr, forward_to_up(Some(retry_policy("5xx", 2)))).await;

            let resp = router.handle(request("/v1/chat")).await;
            assert_eq!(resp.head.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                count.load(Ordering::SeqCst),
                3,
                "expected num_retries + 1 == 3 attempts to reach the upstream"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_connect_failure_is_retried_against_a_live_host() {
    LocalSet::new()
        .run_until(async {
            // Dial a closed port first (nothing listening there), then a
            // real, live upstream -- proved by binding+dropping a listener to
            // get a port that's guaranteed free again.
            let closed_addr = {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                listener.local_addr().unwrap()
            };
            let (live_addr, rx) = spawn_reflecting_ok_upstream().await;

            let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
            let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
            snapshot.insert(
                "up".to_string(),
                Arc::new(ClusterConfig {
                    name: "up".to_string(),
                    discovery: DiscoveryType::Static,
                    lb_policy: LbPolicy::RoundRobin,
                    connect_timeout: Duration::from_secs(5),
                    endpoints: vec![
                        EndpointIR {
                            host: closed_addr.ip().to_string(),
                            port: closed_addr.port(),
                            weight: 1,
                            priority: 0,
                        },
                        EndpointIR {
                            host: live_addr.ip().to_string(),
                            port: live_addr.port(),
                            weight: 1,
                            priority: 0,
                        },
                    ],
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
                        action: RouteActionIR::Forward(forward_to_up(Some(retry_policy(
                            "connect-failure",
                            3,
                        )))),
                        request_headers_to_add: Vec::new(),
                    })],
                }],
            )
            .unwrap();
            let router = RouterHandler::new(Arc::new(route_table), Arc::new(manager));

            // Round-robin over the two endpoints means the closed port isn't
            // guaranteed to be tried first on every LB implementation change,
            // so just assert the request eventually succeeds -- the
            // connect-failure retry is what makes that true at all (a single
            // attempt to the closed port would never reach the live host).
            let resp =
                tokio::time::timeout(Duration::from_secs(2), router.handle(request("/v1/chat")))
                    .await
                    .expect("should complete well within the test's own guard timeout");
            assert_eq!(resp.head.status, StatusCode::OK);
            let _ = rx.await;
        })
        .await;
}

async fn spawn_reflecting_ok_upstream() -> (SocketAddr, tokio::sync::oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        let _ = tx.send(());
    });
    (addr, rx)
}

#[tokio::test(flavor = "current_thread")]
async fn a_status_not_in_retry_on_is_returned_immediately() {
    LocalSet::new()
        .run_until(async {
            // Policy only retries on `connect-failure`; a 503 response is not
            // in that trigger set and must be returned as-is, after exactly
            // one upstream request.
            let (addr, count, _rx) = spawn_upstream_fails_then_succeeds(usize::MAX, 503).await;
            let router = build_router(
                addr,
                forward_to_up(Some(retry_policy("connect-failure", 3))),
            )
            .await;

            let resp = router.handle(request("/v1/chat")).await;
            assert_eq!(resp.head.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(count.load(Ordering::SeqCst), 1);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn no_retry_policy_issues_exactly_one_attempt() {
    LocalSet::new()
        .run_until(async {
            let (addr, count, _rx) = spawn_upstream_fails_then_succeeds(usize::MAX, 503).await;
            let router = build_router(addr, forward_to_up(None)).await;

            let resp = router.handle(request("/v1/chat")).await;
            assert_eq!(resp.head.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(count.load(Ordering::SeqCst), 1);
        })
        .await;
}

// ------------------------------------------------------------ S4.2 --

/// An upstream that accepts connections in a loop; each connection either
/// stalls forever before writing anything (never reaching response headers)
/// or answers a quick `200 OK`, depending on which attempt it is (0-based)
/// -- lets S4.2 tests script "attempt 1 stalls, attempt 2 succeeds fast"
/// against a single `ClusterConfig` with two attempts hitting the same
/// listener.
async fn spawn_upstream_stalls_then_answers(stall_count: usize) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_task = count.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let attempt = count_task.fetch_add(1, Ordering::SeqCst);
            // Rust note: each accepted connection is handled on its own
            // spawned task -- a stalling connection's `pending::<()>().await`
            // below never returns, so without this the *listener's own*
            // accept loop would wedge on the first stall and never reach a
            // second connection at all.
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                if attempt < stall_count {
                    // Hold the accepted connection open without ever
                    // writing a response -- this task just never returns, so
                    // only the router's own per-try timeout can end the
                    // attempt, not the peer.
                    std::future::pending::<()>().await;
                } else {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                }
            });
        }
    });
    (addr, count)
}

fn retry_policy_with_per_try_timeout(
    retry_on: &str,
    num_retries: u32,
    per_try_timeout: Duration,
) -> RetryPolicyIR {
    RetryPolicyIR {
        retry_on: RetryOn::parse(retry_on),
        num_retries,
        per_try_timeout: Some(per_try_timeout),
        retriable_status_codes: Vec::new(),
        retry_back_off: fast_backoff(),
        host_selection_retry_max_attempts: 1,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn per_try_timeout_abandons_a_stalling_attempt_and_the_retry_succeeds() {
    tokio::time::timeout(Duration::from_secs(2), async {
        LocalSet::new()
            .run_until(async {
                // Attempt 0 stalls past the 50ms per-try timeout; attempt 1
                // (the retry) answers immediately.
                let (addr, count) = spawn_upstream_stalls_then_answers(1).await;
                let router = build_router(
                    addr,
                    forward_to_up(Some(retry_policy_with_per_try_timeout(
                        "5xx",
                        1,
                        Duration::from_millis(50),
                    ))),
                )
                .await;

                let resp = router.handle(request("/v1/chat")).await;
                assert_eq!(resp.head.status, StatusCode::OK);
                assert_eq!(
                    count.load(Ordering::SeqCst),
                    2,
                    "expected the stalled attempt plus one retry"
                );
            })
            .await;
    })
    .await
    .expect("the per-try timeout should abandon the stalled attempt well within this guard");
}

#[tokio::test(flavor = "current_thread")]
async fn per_try_timeout_with_no_retry_budget_left_yields_504() {
    tokio::time::timeout(Duration::from_secs(2), async {
        LocalSet::new()
            .run_until(async {
                // num_retries=0: the very first attempt is also the last
                // allowed one, so a per-try timeout on it must surface as a
                // gateway timeout, not a hang and not a retry.
                let (addr, count) = spawn_upstream_stalls_then_answers(usize::MAX).await;
                let router = build_router(
                    addr,
                    forward_to_up(Some(retry_policy_with_per_try_timeout(
                        "5xx",
                        0,
                        Duration::from_millis(50),
                    ))),
                )
                .await;

                let resp = router.handle(request("/v1/chat")).await;
                assert_eq!(resp.head.status, StatusCode::GATEWAY_TIMEOUT);
                assert_eq!(count.load(Ordering::SeqCst), 1);
            })
            .await;
    })
    .await
    .expect("the per-try timeout should fire well within this guard, not hang");
}

#[tokio::test(flavor = "current_thread")]
async fn no_per_try_timeout_preserves_the_slow_but_eventual_success() {
    tokio::time::timeout(Duration::from_secs(2), async {
        LocalSet::new()
            .run_until(async {
                // `per_try_timeout: None` (today's default): an upstream
                // that answers slowly, but well within any sane bound, must
                // still succeed -- nothing new should be timing this out.
                let (addr, rx) = spawn_slow_but_ok_upstream(Duration::from_millis(150)).await;
                let router = build_router(addr, forward_to_up(Some(retry_policy("5xx", 1)))).await;

                let resp = router.handle(request("/v1/chat")).await;
                assert_eq!(resp.head.status, StatusCode::OK);
                let _ = rx.await;
            })
            .await;
    })
    .await
    .expect("should complete well within the test's own guard timeout");
}

#[tokio::test(flavor = "current_thread")]
async fn overall_timeout_wins_over_a_retry_budget_the_per_try_timeout_would_otherwise_allow() {
    tokio::time::timeout(Duration::from_secs(2), async {
        LocalSet::new()
            .run_until(async {
                // Every attempt stalls past its 50ms per-try timeout, so with
                // num_retries=5 the retry loop *could* run for a while (each
                // attempt burning ~50ms + trivial backoff) -- but the route's
                // overall 120ms budget is shorter than that, so the client
                // must see exactly one 504, from the overall-timeout path,
                // not from per-try exhaustion.
                let (addr, _count) = spawn_upstream_stalls_then_answers(usize::MAX).await;
                let mut fwd = forward_to_up(Some(retry_policy_with_per_try_timeout(
                    "5xx",
                    5,
                    Duration::from_millis(50),
                )));
                fwd.timeout = Some(Duration::from_millis(120));
                let router = build_router(addr, fwd).await;

                let resp = router.handle(request("/v1/chat")).await;
                assert_eq!(resp.head.status, StatusCode::GATEWAY_TIMEOUT);
            })
            .await;
    })
    .await
    .expect("the overall timeout must win rather than the request hanging");
}

#[tokio::test(flavor = "current_thread")]
async fn per_try_timeout_is_armed_fresh_for_every_attempt() {
    tokio::time::timeout(Duration::from_secs(2), async {
        LocalSet::new()
            .run_until(async {
                // Both attempts individually take ~35ms to answer -- just
                // under the 50ms per-try limit. If the per-try timer were
                // (incorrectly) armed once at the start of the whole attempt
                // loop instead of fresh per attempt, attempt 2 would inherit
                // attempt 1's already-elapsed time and the combined ~70ms
                // would blow the 50ms budget, timing out. Both attempts
                // proceeding to a final 200 proves the timer resets per
                // attempt.
                let (addr, count) =
                    spawn_upstream_answers_after_delay_then_fails_first(Duration::from_millis(35))
                        .await;
                let router = build_router(
                    addr,
                    forward_to_up(Some(retry_policy_with_per_try_timeout(
                        "5xx",
                        1,
                        Duration::from_millis(50),
                    ))),
                )
                .await;

                let resp = router.handle(request("/v1/chat")).await;
                assert_eq!(resp.head.status, StatusCode::OK);
                assert_eq!(count.load(Ordering::SeqCst), 2);
            })
            .await;
    })
    .await
    .expect("both attempts should complete comfortably within this guard");
}

/// An upstream that, after `delay`, answers its *first* accepted connection
/// with a `503` and every connection after that with a `200` -- both
/// answers come after the same `delay`, so the test above can assert both
/// attempts individually stay under a per-try limit that their *sum* would
/// exceed.
async fn spawn_upstream_answers_after_delay_then_fails_first(
    delay: Duration,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_task = count.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let attempt = count_task.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            tokio::time::sleep(delay).await;
            if attempt == 0 {
                let _ = stream
                    .write_all(b"HTTP/1.1 503 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            } else {
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        }
    });
    (addr, count)
}

/// An upstream that answers a single connection with `200 OK` after `delay`
/// -- used to prove a `per_try_timeout: None` route doesn't spuriously time
/// out an upstream that's merely slow, not stalled.
async fn spawn_slow_but_ok_upstream(
    delay: Duration,
) -> (SocketAddr, tokio::sync::oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        tokio::time::sleep(delay).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        let _ = tx.send(());
    });
    (addr, rx)
}

#[tokio::test(flavor = "current_thread")]
async fn the_replayed_request_carries_the_same_body_as_the_original() {
    LocalSet::new()
        .run_until(async {
            let (addr, count, mut rx) = spawn_upstream_fails_then_succeeds(1, 503).await;
            let router = build_router(addr, forward_to_up(Some(retry_policy("5xx", 1)))).await;

            let resp = router
                .handle(request_with_body("/v1/chat", b"hello retry world"))
                .await;
            assert_eq!(resp.head.status, StatusCode::OK);
            assert_eq!(count.load(Ordering::SeqCst), 2);

            let first_body = rx.recv().await.expect("first attempt reached the upstream");
            let second_body = rx
                .recv()
                .await
                .expect("second attempt reached the upstream");
            assert_eq!(first_body.as_ref(), b"hello retry world");
            assert_eq!(
                second_body.as_ref(),
                b"hello retry world",
                "the replayed attempt must carry the identical body"
            );
        })
        .await;
}
