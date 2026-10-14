//! The aggregate cluster (`ClusterKind::Aggregate`) as a
//! provider-fallback target. This file exists for exactly one guarantee --
//! **credential isolation across failover**: a request that falls over from
//! provider `"a"` to provider `"b"` must carry `"b"`'s credentials, and
//! `"a"`'s must never reach `"b"`'s upstream at all (see
//! `ClusterConfig::request_headers_to_add`'s doc for why a route-level or
//! wrong-cluster credential is a real API-key disclosure to a third party,
//! not just a wrong-header bug).
//!
//! Standalone (not `router.rs`'s own `#[cfg(test)]` module), same reasoning
//! as `router_retry.rs`/`router_header_mutations.rs`: a fresh, focused
//! upstream/cluster-snapshot helper rather than reusing the existing
//! one-shot ones. Modeled closely on `router_header_mutations.rs` (the
//! reflecting upstream that hands back the raw request text) and
//! `router_retry.rs` (the closed-port-for-a-guaranteed-connect-failure
//! trick, and the retry-policy helpers) plus `router_access_log.rs` (reading
//! `StreamInfo::upstream_cluster` back out through a `%UPSTREAM_CLUSTER%`
//! text logger -- there is no other public seam that exposes it).
//!
//! Rust note: same shape as those files' own tests -- `send_upstream_http1`
//! spawns a non-`Send` connection driver task via `tokio::task::spawn_local`,
//! so every test needs a `LocalSet` on a `current_thread` runtime.

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
    AccessLogFormat, AccessLogIR, AccessLogSink, ClusterConfig, ClusterKind, ClusterName,
    DiscoveryType, EndpointIR, ForwardAction, ForwardTarget, HeaderAppendAction, HeaderMutation,
    LbPolicy, PathMatch, RetryBackOff, RetryOn, RetryPolicyIR, RouteActionIR, RouteEntry,
    RouteMatcher, RouteTable, VirtualHostIR,
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
use tokio::sync::oneshot;
use tokio::task::LocalSet;

/// A near-instant backoff so the one retry this file exercises doesn't spend
/// real wall-clock time on S3.3 jitter -- same helper as `router_retry.rs`.
fn fast_backoff() -> RetryBackOff {
    RetryBackOff {
        base_interval: Duration::from_micros(1),
        max_interval: Duration::from_micros(5),
    }
}

/// A fresh, single-worker [`RouterStats`] resolved for
/// exactly `cluster_names` -- what [`RouterFilterFactory::new`] needs,
/// mirroring how `crates/proxy/src/main.rs` builds the real one from the
/// boot config snapshot's cluster names.
fn test_router_stats(cluster_names: &[&str]) -> Arc<RouterStats> {
    let control = StatsControl::new(1);
    let handles = Arc::new(StatHandles::build(&control, cluster_names.iter().copied()));
    Arc::new(RouterStats::new(control.registry(), handles, WorkerId(0)))
}

fn retry_policy(retry_on: &str, num_retries: u32) -> RetryPolicyIR {
    RetryPolicyIR {
        retry_on: RetryOn::parse(retry_on),
        num_retries,
        per_try_timeout: None,
        hedge_on_per_try_timeout: false,
        retriable_status_codes: Vec::new(),
        retry_back_off: fast_backoff(),
        host_selection_retry_max_attempts: 1,
        avoid_previous_hosts: false,
    }
}

/// Forwards to the aggregate cluster `"providers"`, retrying on
/// `connect-failure` -- already a retriable trigger under today's retry
/// engine (S3.2), so this test needs no retry-predicate changes: `"a"`'s
/// closed port fails the connect, the existing retry loop reacts, and the
/// aggregate (the aggregate's own logic) is what decides where the
/// retried attempt goes.
fn forward_to_providers() -> ForwardAction {
    ForwardAction {
        target: ForwardTarget::Cluster("providers".to_string()),
        timeout: None,
        idle_timeout: None,
        retry_policy: Some(retry_policy("connect-failure", 3)),
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

fn mutation(key: &str, value: &str, action: HeaderAppendAction) -> HeaderMutation {
    HeaderMutation {
        key: key.to_string(),
        value: value.to_string(),
        action,
    }
}

/// A STATIC, single-endpoint `Endpoints` cluster carrying `mutations` as its
/// own `request_headers_to_add` -- the per-cluster credential
/// mechanism this test relies on to tell `"a"`'s and `"b"`'s attempts apart.
fn member_cluster(name: &str, addr: SocketAddr, mutations: Vec<HeaderMutation>) -> ClusterConfig {
    ClusterConfig {
        // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
        eds: None,
        name: name.to_string(),
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
        request_headers_to_add: mutations,
        request_path_rewrite: None,
        provider_runtime: None,
        usage_dialect: None,
        health_check: None,
        outlier_detection: None,
    }
}

/// The aggregate cluster `"providers"` over members `["a", "b"]`, in that
/// order -- `discovery`/`endpoints`/`lb_policy`/`transport_socket` are all
/// unused for an aggregate (see `ClusterKind::Aggregate`'s doc) but still
/// need *something* syntactically valid to satisfy `ClusterConfig`'s shape.
fn aggregate_cluster() -> ClusterConfig {
    ClusterConfig {
        // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
        eds: None,
        name: "providers".to_string(),
        discovery: DiscoveryType::Static,
        lb_policy: LbPolicy::RoundRobin,
        connect_timeout: Duration::from_secs(5),
        endpoints: Vec::new(),
        kind: ClusterKind::Aggregate {
            members: vec!["a".to_string(), "b".to_string()],
        },
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

/// A unique path under the OS temp dir for the `%UPSTREAM_CLUSTER%` text
/// logger, same technique as `router_access_log.rs`'s own `temp_path`.
fn temp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "proxy-http-aggregate-test-{}-{}-{}",
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
    // Access-log writes are asynchronous (background writer thread); wait
    // for everything queued so far instead of sleeping.
    assert!(proxy_observability::sink::flush_all_queued(
        Duration::from_secs(5)
    ));
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

/// Builds the one-route `FilterChainHandler` every test in this file drives:
/// a route forwarding `/v1/` to the aggregate `"providers"` over members
/// `["a", "b"]`, where `"a"` points at a closed port (connect failure,
/// guaranteed by binding then dropping a listener so the port is free again)
/// carrying `"a"`'s credential, and `"b"` points at a live reflecting
/// upstream carrying `"b"`'s credential (plus a second header, standing in
/// for e.g. `anthropic-version`). A `%UPSTREAM_CLUSTER%` text logger is
/// always wired so [`stream_info_reports_the_member_that_actually_served`]
/// can read `StreamInfo::upstream_cluster` back out -- there's no other
/// public seam onto it (see `router_access_log.rs`'s module doc).
///
/// Returns the handler, the `oneshot::Receiver` that resolves to whatever
/// raw request text `"b"`'s upstream actually received, and the access-log
/// file's path.
async fn build_router() -> (FilterChainHandler, oneshot::Receiver<String>, PathBuf) {
    let closed_addr = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let (live_addr, rx) = spawn_reflecting_upstream().await;

    let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
    let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
    snapshot.insert(
        "a".to_string(),
        Arc::new(member_cluster(
            "a",
            closed_addr,
            vec![mutation(
                "authorization",
                "bearer key-for-a",
                HeaderAppendAction::OverwriteIfExistsOrAdd,
            )],
        )),
    );
    snapshot.insert(
        "b".to_string(),
        Arc::new(member_cluster(
            "b",
            live_addr,
            vec![
                mutation(
                    "authorization",
                    "bearer key-for-b",
                    HeaderAppendAction::OverwriteIfExistsOrAdd,
                ),
                mutation(
                    "anthropic-version",
                    "2023-06-01",
                    HeaderAppendAction::OverwriteIfExistsOrAdd,
                ),
            ],
        )),
    );
    snapshot.insert("providers".to_string(), Arc::new(aggregate_cluster()));
    manager.update_from_snapshot(&snapshot).await;

    let route_table = RouteTable::new(
        "test-routes".to_string(),
        vec![VirtualHostIR {
            name: "vh".to_string(),
            domains: vec!["*".to_string()],
            routes: vec![Arc::new(RouteEntry {
                name: None,
                matcher: prefix_matcher("/v1/"),
                action: RouteActionIR::Forward(forward_to_providers()),
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

    let log_path = temp_path("upstream-cluster");
    let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
        Arc::new(RouterFilterFactory::new(
            Arc::new(manager),
            test_router_stats(&["a", "b", "providers"]),
        ));
    let handler = FilterChainHandler::new_with_access_logs(
        Vec::new(),
        terminal_factory,
        Arc::new(route_table),
        false,
        false,
        0,
        &[text_logger(&log_path, "%UPSTREAM_CLUSTER%\n")],
    )
    .expect("test access-log sink (temp file) always opens cleanly");

    (handler, rx, log_path)
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

/// A one-shot "reflecting" upstream: accepts a single connection, reads
/// until the request's header terminator, hands the raw request-line+headers
/// text back over `rx`, then answers 200 -- same shape as
/// `router_header_mutations.rs`'s own `spawn_reflecting_upstream`.
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

/// The load-bearing guarantee this whole file exists for: a
/// request that fails over from `"a"` (closed port, connect failure) to
/// `"b"` (live) must carry `"b"`'s credentials -- and `"a"`'s must not
/// appear anywhere in what `"b"` received. Asserting only that `"b"`'s key
/// is present would pass just as well with both keys on the wire, which is
/// exactly the failure mode (a real API-key disclosure to a third party)
/// that matters here -- so the absence of `"a"`'s key is asserted
/// explicitly, over the whole received header block.
#[tokio::test(flavor = "current_thread")]
async fn credential_isolation_across_failover() {
    LocalSet::new()
        .run_until(async {
            let (handler, rx, _log_path) = build_router().await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);
            resp.body.collect().await.unwrap();

            let upstream_request = rx.await.unwrap().to_ascii_lowercase();
            assert!(
                upstream_request.contains("authorization: bearer key-for-b"),
                "expected b's credential on the wire, got: {upstream_request:?}"
            );
            assert!(
                upstream_request.contains("anthropic-version: 2023-06-01"),
                "expected b's second header on the wire too, got: {upstream_request:?}"
            );
            assert!(
                !upstream_request.contains("key-for-a"),
                "a's credential must never reach b's upstream -- a real API-key disclosure to a \
                 third party if it does, got: {upstream_request:?}"
            );
        })
        .await;
}

/// After that same failover, `StreamInfo::upstream_cluster` (surfaced here
/// via `%UPSTREAM_CLUSTER%`) must name `"b"` -- the cluster actually
/// dialed -- not `"providers"` (the routed aggregate, which owns no host)
/// and not `"a"` (the member a retry moved past).
#[tokio::test(flavor = "current_thread")]
async fn stream_info_reports_the_member_that_actually_served() {
    LocalSet::new()
        .run_until(async {
            let (handler, _rx, log_path) = build_router().await;

            let resp = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(resp.head.status, StatusCode::OK);
            resp.body.collect().await.unwrap();

            let logged = read_to_string(&log_path);
            assert_eq!(
                logged, "b\n",
                "expected %UPSTREAM_CLUSTER% to name the member that actually served, got: \
                 {logged:?}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn metadata_keeps_failed_primary_and_actual_fallback_member() {
    LocalSet::new()
        .run_until(async {
            let (handler, _, _) = build_router().await;
            let (sink, mut records) = proxy_observability::records::BoundedRecordSink::new(1);
            let handler = handler.with_request_record_sink(Arc::new(sink));
            let response = handler.handle(request("/v1/chat/completions")).await;
            assert_eq!(response.head.status, StatusCode::OK);
            response.body.collect().await.unwrap();
            let record = records.try_recv().unwrap();
            assert_eq!(record.selected_cluster.as_deref(), Some("b"));
            assert_eq!(record.attempt_count, 2);
            assert_eq!(record.physical_attempt_count, 2);
            assert!(record.selected_provider.is_none());
            assert!(record.user_id.is_none());
            assert!(record.usage.is_none());
            assert!(record.cost.is_none());
            assert_eq!(record.attempts[0].cluster.as_deref(), Some("a"));
            assert_eq!(
                record.attempts[0].termination,
                proxy_observability::records::Termination::UpstreamError
            );
            assert_eq!(record.attempts[0].status, None);
            assert_eq!(record.attempts[1].cluster.as_deref(), Some("b"));
            assert_eq!(record.attempts[1].retry_reason.as_deref(), Some("fallback"));
            assert_eq!(record.attempts[1].status, Some(200));
        })
        .await;
}

/// An upstream that reads one whole request (headers, then `Content-Length`
/// body bytes) before answering 200, and reports the body length it read.
/// Unlike [`spawn_reflecting_upstream`] it never answers with request bytes
/// unread, which on a large body could reset the connection under the
/// router's write.
async fn spawn_body_counting_upstream() -> (SocketAddr, oneshot::Receiver<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        let header_end = loop {
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "upstream closed before the header block ended");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
        let content_length: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .map(|v| v.trim().parse().unwrap())
            .unwrap_or(0);
        while buf.len() - header_end < content_length {
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "upstream closed before the body ended");
            buf.extend_from_slice(&chunk[..n]);
        }
        let _ = tx.send(buf.len() - header_end);
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    });
    (addr, rx)
}

/// S3.4: the retry replay limit is the stream's buffer limit (the listener's
/// `per_connection_buffer_limit_bytes`), not a fixed 1 MiB. With the limit
/// raised to 4 MiB, a 2 MiB body whose first member fails to connect must
/// still fail over and reach the second member whole. A fixed 1 MiB replay
/// limit marks the body unretriable, and the client gets the first member's
/// 503 instead.
#[tokio::test(flavor = "multi_thread")]
async fn a_body_over_1_mib_fails_over_when_the_buffer_limit_allows_it() {
    const BODY_LEN: usize = 2 << 20;
    let closed_addr = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let (live_addr, rx) = spawn_body_counting_upstream().await;
    let (status, received) = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        LocalSet::new().block_on(&rt, async move {
            let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
            let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
            snapshot.insert(
                "a".to_string(),
                Arc::new(member_cluster("a", closed_addr, Vec::new())),
            );
            snapshot.insert(
                "b".to_string(),
                Arc::new(member_cluster("b", live_addr, Vec::new())),
            );
            snapshot.insert("providers".to_string(), Arc::new(aggregate_cluster()));
            manager.update_from_snapshot(&snapshot).await;
            let route_table = RouteTable::new(
                "test-routes".to_string(),
                vec![VirtualHostIR {
                    name: "vh".to_string(),
                    domains: vec!["*".to_string()],
                    routes: vec![Arc::new(RouteEntry {
                        name: None,
                        matcher: prefix_matcher("/v1/"),
                        action: RouteActionIR::Forward(forward_to_providers()),
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
            let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
                Arc::new(RouterFilterFactory::new(
                    Arc::new(manager),
                    test_router_stats(&["a", "b", "providers"]),
                ));
            let handler = FilterChainHandler::new_with_access_logs(
                Vec::new(),
                terminal_factory,
                Arc::new(route_table),
                false,
                false,
                0,
                &[],
            )
            .unwrap()
            .with_buffer_limit(4 << 20);

            let mut headers = HeaderMap::new();
            headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
            let req = HttpRequestParts {
                head: RequestHeaders {
                    method: Method::POST,
                    uri: Uri::from_static("/v1/chat/completions"),
                    headers,
                },
                body: local_boxed(
                    Full::new(Bytes::from(vec![b'x'; BODY_LEN]))
                        .map_err(|infallible: std::convert::Infallible| match infallible {}),
                ),
                downstream: DownstreamInfo::loopback(),
                on_upgrade: None,
            };
            let resp = tokio::time::timeout(Duration::from_secs(10), handler.handle(req))
                .await
                .expect("request bounded");
            let status = resp.head.status;
            resp.body.collect().await.unwrap();
            let received = tokio::time::timeout(Duration::from_secs(10), rx)
                .await
                .ok()
                .and_then(Result::ok);
            (status, received)
        })
    })
    .await
    .unwrap();

    assert_eq!(
        status,
        StatusCode::OK,
        "a 2 MiB body under a 4 MiB limit must fail over to b"
    );
    assert_eq!(received, Some(BODY_LEN), "b must receive the whole body");
}

/// A handler routing `/v1/` to the aggregate `["a", "b"]` over two live
/// upstreams, retrying `retry_on` (and 429 under `retriable-status-codes`) up
/// to `num_retries` times.
async fn build_failover_handler(
    a: SocketAddr,
    b: SocketAddr,
    retry_on: &str,
    num_retries: u32,
) -> FilterChainHandler {
    let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
    let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
    snapshot.insert(
        "a".to_string(),
        Arc::new(member_cluster("a", a, Vec::new())),
    );
    snapshot.insert(
        "b".to_string(),
        Arc::new(member_cluster("b", b, Vec::new())),
    );
    snapshot.insert("providers".to_string(), Arc::new(aggregate_cluster()));
    manager.update_from_snapshot(&snapshot).await;
    let mut fwd = forward_to_providers();
    let mut policy = retry_policy(retry_on, num_retries);
    policy.retriable_status_codes = vec![429];
    fwd.retry_policy = Some(policy);
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
    let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
        Arc::new(RouterFilterFactory::new(
            Arc::new(manager),
            test_router_stats(&["a", "b", "providers"]),
        ));
    FilterChainHandler::new_with_access_logs(
        Vec::new(),
        terminal_factory,
        Arc::new(route_table),
        false,
        false,
        0,
        &[],
    )
    .unwrap()
}

/// Reads one request head, then writes `response` verbatim and, if `endless`,
/// keeps appending chunks until the peer goes away. Resolves to the number of
/// extra bytes written.
async fn spawn_scripted_upstream(
    response: &'static [u8],
    endless: bool,
) -> (SocketAddr, tokio::task::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut chunk).await.unwrap();
            if n == 0 {
                return 0;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        if stream.write_all(response).await.is_err() {
            return 0;
        }
        let mut written = 0;
        if endless {
            let piece = format!("2000\r\n{}\r\n", "x".repeat(0x2000));
            while stream.write_all(piece.as_bytes()).await.is_ok() {
                written += piece.len();
            }
        }
        written
    });
    (addr, task)
}

/// With every aggregate member answering 429 and retries to spare, the client
/// must get the last member's real 429 (status, `retry-after`, body), not a
/// synthesized `503 no healthy upstream`. Member `a`'s answer is distinct so a
/// first-response or mixed-up reply fails too.
#[tokio::test(flavor = "current_thread")]
async fn exhausting_every_member_returns_the_last_upstream_response() {
    LocalSet::new()
        .run_until(async {
            let (a, _) = spawn_scripted_upstream(
                b"HTTP/1.1 429 Too Many Requests\r\nretry-after: 1\r\nContent-Length: 7\r\nConnection: close\r\n\r\na-limit",
                false,
            )
            .await;
            let (b, _) = spawn_scripted_upstream(
                b"HTTP/1.1 429 Too Many Requests\r\nretry-after: 42\r\nContent-Length: 7\r\nConnection: close\r\n\r\nb-limit",
                false,
            )
            .await;
            let handler = build_failover_handler(a, b, "retriable-status-codes", 3).await;

            let resp = tokio::time::timeout(
                Duration::from_secs(10),
                handler.handle(request("/v1/chat/completions")),
            )
            .await
            .expect("request bounded");
            assert_eq!(resp.head.status, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(resp.head.headers["retry-after"], "42");
            let body = tokio::time::timeout(Duration::from_secs(10), resp.body.collect())
                .await
                .expect("body bounded")
                .unwrap()
                .to_bytes();
            assert_eq!(&body[..], b"b-limit");
        })
        .await;
}

/// A failed attempt whose body never ends must not stall or grow the proxy:
/// the drain is capped, the attempt is abandoned (its connection closed, which
/// ends the upstream's writer), and the retry reaches the healthy member.
#[tokio::test(flavor = "current_thread")]
async fn a_failed_attempt_with_an_endless_body_is_abandoned_not_drained() {
    LocalSet::new()
        .run_until(async {
            let (a, a_task) = spawn_scripted_upstream(
                b"HTTP/1.1 500 Internal Server Error\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                true,
            )
            .await;
            let (b, _) = spawn_scripted_upstream(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                false,
            )
            .await;
            let handler = build_failover_handler(a, b, "5xx", 3).await;

            let resp = tokio::time::timeout(
                Duration::from_secs(10),
                handler.handle(request("/v1/chat/completions")),
            )
            .await
            .expect("an unbounded drain of a's body would hang the retry");
            assert_eq!(resp.head.status, StatusCode::OK);
            let body = resp.body.collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"ok");

            let written = tokio::time::timeout(Duration::from_secs(10), a_task)
                .await
                .expect("a's writer must be cut off when the attempt is abandoned")
                .unwrap();
            assert!(written > 0, "the endless body must have started");
        })
        .await;
}
