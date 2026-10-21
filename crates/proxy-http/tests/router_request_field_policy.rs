//! Per-cluster `request_field_policy` enforcement through the real router,
//! including across aggregate failover (AGENTS.md invariant 6: the policy
//! belongs to the provider actually dialled, never the route).
//!
//! Fixture: route `/v1/` -> aggregate `providers` over `["a", "b"]`. `a`
//! points at a closed port, so every request that reaches it fails to connect
//! and falls over to `b`, a live recording upstream. Each test gives `a` and
//! `b` the policies it needs.
//!
//! Rust note: the router spawns non-`Send` connection drivers, so these tests
//! run on a `current_thread` runtime inside a `LocalSet`.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::resolver::FakeResolver;
use proxy_config::ir::{
    AccessLogFormat, AccessLogIR, AccessLogSink, ClusterConfig, ClusterKind, ClusterName,
    DiscoveryType, EndpointIR, ForwardAction, ForwardTarget, LbPolicy, PathMatch,
    ProviderRuntimeConfig, RequestFieldPolicy, RetryBackOff, RetryOn, RetryPolicyIR, RouteActionIR,
    RouteEntry, RouteMatcher, RouteTable, VirtualHostIR,
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
use tokio::task::LocalSet;
use tokio::time::timeout;

const BOUND: Duration = Duration::from_secs(10);

fn policy(deny: &[&str], strip: &[&str]) -> Option<ProviderRuntimeConfig> {
    if deny.is_empty() && strip.is_empty() {
        return None;
    }
    Some(ProviderRuntimeConfig {
        credential: None,
        path_template: None,
        model_rewrites: Vec::new(),
        request_field_policy: RequestFieldPolicy {
            deny: deny.iter().map(|s| s.to_string()).collect(),
            strip: strip.iter().map(|s| s.to_string()).collect(),
        },
        tenant_credential: None,
    })
}

fn cluster(name: &str, addr: SocketAddr, runtime: Option<ProviderRuntimeConfig>) -> ClusterConfig {
    ClusterConfig {
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
        request_headers_to_add: Vec::new(),
        request_path_rewrite: None,
        provider_runtime: runtime,
        usage_dialect: None,
        health_check: None,
        outlier_detection: None,
    }
}

fn aggregate() -> ClusterConfig {
    let mut c = cluster("providers", "127.0.0.1:1".parse().unwrap(), None);
    c.endpoints = Vec::new();
    c.kind = ClusterKind::Aggregate {
        members: vec!["a".to_string(), "b".to_string()],
    };
    c
}

/// Raw request texts (headers and body) the live upstream received.
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
                loop {
                    let Ok(n) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let want = head
                            .to_ascii_lowercase()
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: ").map(str::to_owned))
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

struct Fixture {
    handler: FilterChainHandler,
    seen: Seen,
    log_path: PathBuf,
}

/// `a` (closed port) and `b` (live recording upstream) with the given runtimes.
async fn build(a: Option<ProviderRuntimeConfig>, b: Option<ProviderRuntimeConfig>) -> Fixture {
    build_with(a, b, false).await
}

/// As [`build`]; with `a_live`, `a` shares the live upstream instead of
/// pointing at a closed port, so a request that reaches `a` is dialled.
async fn build_with(
    a: Option<ProviderRuntimeConfig>,
    b: Option<ProviderRuntimeConfig>,
    a_live: bool,
) -> Fixture {
    let (live, seen) = spawn_upstream().await;
    let closed = if a_live {
        live
    } else {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
    let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
    snapshot.insert("a".to_string(), Arc::new(cluster("a", closed, a)));
    snapshot.insert("b".to_string(), Arc::new(cluster("b", live, b)));
    snapshot.insert("providers".to_string(), Arc::new(aggregate()));
    manager.update_from_snapshot(&snapshot).await;

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
                    target: ForwardTarget::Cluster("providers".to_string()),
                    timeout: None,
                    idle_timeout: None,
                    retry_policy: Some(RetryPolicyIR {
                        retry_on: RetryOn::parse("connect-failure"),
                        num_retries: 3,
                        per_try_timeout: None,
                        hedge_on_per_try_timeout: false,
                        retriable_status_codes: Vec::new(),
                        retry_back_off: RetryBackOff {
                            base_interval: Duration::from_micros(1),
                            max_interval: Duration::from_micros(5),
                        },
                        host_selection_retry_max_attempts: 1,
                        avoid_previous_hosts: false,
                    }),
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

    let mut log_path = std::env::temp_dir();
    log_path.push(format!(
        "proxy-http-field-policy-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let control = StatsControl::new(1);
    let handles = Arc::new(StatHandles::build(&control, ["a", "b", "providers"]));
    let stats = Arc::new(RouterStats::new(control.registry(), handles, WorkerId(0)));
    let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
        Arc::new(RouterFilterFactory::new(Arc::new(manager), stats));
    let handler = FilterChainHandler::new_with_access_logs(
        Vec::new(),
        terminal_factory,
        Arc::new(route_table),
        false,
        false,
        0,
        &[AccessLogIR {
            sink: AccessLogSink::File {
                path: log_path.to_string_lossy().into_owned(),
            },
            format: AccessLogFormat::Text(parse_format("%RESPONSE_CODE_DETAILS%\n").unwrap()),
            filter: None,
        }],
    )
    .expect("temp-file access log opens");
    Fixture {
        handler,
        seen,
        log_path,
    }
}

/// POST `body`; returns the status and the local reply body text.
async fn post(handler: &FilterChainHandler, body: &'static str) -> (StatusCode, String) {
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
    let text = timeout(BOUND, resp.body.collect())
        .await
        .expect("body within the bound")
        .map(|c| String::from_utf8_lossy(&c.to_bytes()).into_owned())
        .unwrap_or_default();
    (status, text)
}

fn code_details(path: &PathBuf) -> String {
    assert!(proxy_observability::sink::flush_all_queued(BOUND));
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Header block and body of the single request the upstream saw.
fn only_request(seen: &Seen) -> (String, String) {
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "expected exactly one upstream request");
    let (head, body) = seen[0].split_once("\r\n\r\n").unwrap();
    (head.to_string(), body.to_string())
}

#[tokio::test(flavor = "current_thread")]
async fn deny_is_a_local_400_and_the_upstream_is_never_dialled() {
    LocalSet::new()
        .run_until(async {
            // `a` is the first pick and denies; `b` is live and has no
            // policy. If the deny were treated as a failure, the request
            // would fail over and reach `b`.
            let f = build_with(policy(&["models"], &[]), None, true).await;
            let (status, text) = post(&f.handler, r#"{"model":"m","models":["m","x"]}"#).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(text.contains("models"), "body must name the field: {text}");
            assert!(
                f.seen.lock().unwrap().is_empty(),
                "a denied request must not fail over to another provider"
            );
            assert!(code_details(&f.log_path).contains("request_field_not_permitted"));
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn escaped_denied_key_is_refused() {
    LocalSet::new()
        .run_until(async {
            let f = build_with(policy(&["models"], &[]), None, true).await;
            let (status, _) = post(&f.handler, r#"{"model":"m","models":["x"]}"#).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(f.seen.lock().unwrap().is_empty());
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_stricter_fallback_refuses_after_a_failed_primary() {
    LocalSet::new()
        .run_until(async {
            // `a` has no policy and fails to connect; the fallback `b` denies.
            let f = build(None, policy(&["route"], &[])).await;
            let (status, _) = post(&f.handler, r#"{"model":"m","route":"x"}"#).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(f.seen.lock().unwrap().is_empty());

            // Control: the same cluster forwards a body without the key.
            let (status, _) = post(&f.handler, r#"{"model":"m"}"#).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(f.seen.lock().unwrap().len(), 1);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn strip_applies_to_the_fallback_that_is_dialled_not_the_primary() {
    LocalSet::new()
        .run_until(async {
            let f = build(None, policy(&[], &["plugins"])).await;
            let (status, _) = post(
                &f.handler,
                r#"{"model":"m","plugins":[{"id":"web"}],"messages":[1]}"#,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let (head, body) = only_request(&f.seen);
            assert!(!body.contains("plugins"), "stripped key leaked: {body}");
            let value: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(value, serde_json::json!({"model":"m","messages":[1]}));
            assert!(
                head.to_ascii_lowercase()
                    .contains(&format!("content-length: {}", body.len())),
                "Content-Length must match the stripped body: {head}"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_cluster_without_a_policy_forwards_the_body_byte_identical() {
    LocalSet::new()
        .run_until(async {
            let f = build(None, None).await;
            let body = "{ \"model\" : \"m\",\n \"models\":[\"x\"],  \"plugins\":[] }";
            let (status, _) = post(&f.handler, body).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(only_request(&f.seen).1, body);
        })
        .await;
}
