//! The router refuses a request whose buffered body disagrees with the model
//! the earlier filters routed on, even when the selected cluster has no model
//! rewrite (the case the per-attempt rewrite check never covered).
//!
//! The production writer of `StreamInfo::requested_model` is the body_rewrite
//! filter's prefix scan. A stand-in decode filter writes the same field, so
//! the real router path runs unchanged downstream of it.
//!
//! Rust note: the router spawns non-`Send` connection drivers with
//! `spawn_local`, so these tests run on a `current_thread` runtime inside a
//! `LocalSet`, like `router_aggregate.rs`.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
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
use proxy_http::filter::{
    DecoderCallbacks, FilterHeadersStatus, FilterInstanceFactory, HttpFilter, RequestHeaders,
    TerminalFilterInstanceFactory,
};
use proxy_http::filter_manager::FilterChainHandler;
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
use proxy_http::router::RouterFilterFactory;
use proxy_http::stat_handles::{RouterStats, StatHandles};
use proxy_observability::stats::{StatsControl, WorkerId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::LocalSet;
use tokio::time::timeout;

const BOUND: Duration = Duration::from_secs(10);

struct RoutedModel(&'static str);

impl FilterInstanceFactory for RoutedModel {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(RoutedModelFilter(self.0))
    }
}

struct RoutedModelFilter(&'static str);

impl HttpFilter for RoutedModelFilter {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        cb.stream_info().requested_model = Some(self.0.to_string());
        FilterHeadersStatus::Continue
    }
}

/// Request texts (headers and body) the upstream received.
type Seen = Arc<Mutex<Vec<String>>>;

async fn spawn_upstream() -> (SocketAddr, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let record = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let record = record.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                // Read until the declared body has fully arrived.
                loop {
                    let Ok(n) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_ascii_lowercase();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let want = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if body.len() >= want {
                            break;
                        }
                    }
                }
                record
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).into_owned());
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    (addr, seen)
}

/// One route, `/` -> cluster `up`, which has no provider runtime and so no
/// model rewrite.
async fn build(addr: SocketAddr) -> FilterChainHandler {
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
    let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
        Arc::new(RouterFilterFactory::new(Arc::new(manager), stats));
    FilterChainHandler::new(
        vec![Arc::new(RoutedModel("cheap"))],
        terminal_factory,
        Arc::new(route_table),
        false,
        false,
        0,
    )
}

async fn post(handler: &FilterChainHandler, body: &'static str) -> StatusCode {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    headers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).unwrap(),
    );
    let request = HttpRequestParts {
        head: RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
            headers,
        },
        body: local_boxed(
            Full::new(Bytes::from_static(body.as_bytes()))
                .map_err(|infallible: std::convert::Infallible| match infallible {}),
        ),
        downstream: DownstreamInfo::loopback(),
        on_upgrade: None,
    };
    let resp = timeout(BOUND, handler.handle(request))
        .await
        .expect("router answered within the bound");
    let status = resp.head.status;
    let _ = timeout(BOUND, resp.body.collect()).await;
    status
}

#[tokio::test(flavor = "current_thread")]
async fn escaped_duplicate_model_is_refused_before_reaching_the_upstream() {
    LocalSet::new()
        .run_until(async {
            let (addr, seen) = spawn_upstream().await;
            let handler = build(addr).await;

            // Control: a body that agrees with the routed model is forwarded,
            // so the refusal below is not just a dead upstream.
            let agreeing = post(&handler, r#"{"model":"cheap","messages":[]}"#).await;
            assert_eq!(agreeing, StatusCode::OK);
            assert_eq!(seen.lock().unwrap().len(), 1);

            let spoofed = post(
                &handler,
                r#"{"model":"cheap","model":"expensive","messages":[]}"#,
            )
            .await;
            assert_eq!(spoofed, StatusCode::BAD_REQUEST);
            assert_eq!(
                seen.lock().unwrap().len(),
                1,
                "the spoofed request must never reach the upstream"
            );
        })
        .await;
}

/// With serde_json's `raw_value` feature on, `Value` reads this `model` as the
/// string "cheap", so the router's model check would agree with the route,
/// while the provider gets an object. The filter manager refuses the reserved
/// key before the router reads the body.
#[tokio::test(flavor = "current_thread")]
async fn a_model_hidden_behind_the_serde_raw_value_key_is_refused() {
    LocalSet::new()
        .run_until(async {
            let (addr, seen) = spawn_upstream().await;
            let handler = build(addr).await;

            let agreeing = post(&handler, r#"{"model":"cheap","messages":[]}"#).await;
            assert_eq!(agreeing, StatusCode::OK);
            assert_eq!(seen.lock().unwrap().len(), 1);

            for smuggled in [
                r#"{"model":{"$serde_json::private::RawValue":"\"cheap\""},"messages":[]}"#,
                r#"{"model":{"\u0024serde_json::private::RawValue":"\"cheap\""},"messages":[]}"#,
            ] {
                assert_eq!(
                    post(&handler, smuggled).await,
                    StatusCode::BAD_REQUEST,
                    "{smuggled}"
                );
            }
            assert_eq!(
                seen.lock().unwrap().len(),
                1,
                "a smuggled model must never reach the upstream"
            );
        })
        .await;
}
