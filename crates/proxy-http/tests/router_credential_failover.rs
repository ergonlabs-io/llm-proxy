//! A provider credential that cannot be applied fails the request over to
//! the next aggregate member (owner decision 2026-10-20,
//! `internal-docs/envoy-divergences.md` row 43). The failure here is a real
//! Bedrock SigV4 signing error: an access key id that cannot go into an
//! `authorization` header. Config does not reject it, so production reaches
//! it, and the signer has already written `x-amz-*` headers when it fails.
//! The OAuth2 token-unavailable case runs through the binary in
//! `crates/proxy/tests/oauth2_token_e2e.rs`.
//!
//! Rust note: connection drivers use `spawn_local`, so tests need a `LocalSet`
//! on a current-thread runtime.

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
    ForwardTarget, HeaderAppendAction, HeaderMutation, LbPolicy, PathMatch, ProviderCredential,
    ProviderRuntimeConfig, RouteActionIR, RouteEntry, RouteMatcher, RouteTable, VirtualHostIR,
};
use proxy_http::filter::{RequestHeaders, TerminalFilterInstanceFactory};
use proxy_http::filter_manager::FilterChainHandler;
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
use proxy_http::router::RouterFilterFactory;
use proxy_http::stat_handles::{RouterStats, StatHandles};
use proxy_observability::records::{BoundedRecordSink, CredentialSource, RequestRecord};
use proxy_observability::stats::{instruments, Registry, StatsControl, WorkerId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::LocalSet;

const PRIMARY_SESSION_TOKEN: &str = "primary-session-token";

const OUTCOMES: [&str; 4] = [
    instruments::PROVIDER_CREDENTIAL_UNAVAILABLE,
    instruments::PROVIDER_CREDENTIAL_FAILED,
    instruments::PROVIDER_CREDENTIAL_UNAVAILABLE_FAILOVER,
    instruments::PROVIDER_CREDENTIAL_FAILED_FAILOVER,
];

/// Request heads an upstream received, one string per request.
type Seen = Arc<Mutex<Vec<String>>>;

/// Answers every request `200` and records its head. Connections that send
/// nothing are accepted and dropped, so a dial without a request is not
/// counted as one.
async fn spawn_upstream() -> (SocketAddr, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let recorded = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let recorded = recorded.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                recorded
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).to_ascii_lowercase());
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    (addr, seen)
}

/// A Bedrock credential whose access key id holds a newline, so the signed
/// `authorization` value is not a valid header and signing fails after the
/// `x-amz-*` headers are written.
fn broken_bedrock() -> ProviderRuntimeConfig {
    ProviderRuntimeConfig {
        credential: Some(ProviderCredential::BedrockSigV4 {
            region: "us-east-1".to_string(),
            access_key_id: "AKIA\nBROKEN".to_string(),
            secret_access_key: "primary-secret".to_string(),
            session_token: Some(PRIMARY_SESSION_TOKEN.to_string()),
        }),
        path_template: None,
        model_rewrites: Vec::new(),
        request_field_policy: Default::default(),
        tenant_credential: None,
    }
}

fn header(key: &str, value: &str) -> HeaderMutation {
    HeaderMutation {
        key: key.to_string(),
        value: value.to_string(),
        action: HeaderAppendAction::OverwriteIfExistsOrAdd,
    }
}

fn member(
    name: &str,
    addr: SocketAddr,
    headers: Vec<HeaderMutation>,
    runtime: Option<ProviderRuntimeConfig>,
) -> ClusterConfig {
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
        request_headers_to_add: headers,
        request_path_rewrite: None,
        provider_runtime: runtime,
        usage_dialect: None,
        health_check: None,
        outlier_detection: None,
    }
}

fn aggregate() -> ClusterConfig {
    ClusterConfig {
        endpoints: Vec::new(),
        kind: ClusterKind::Aggregate {
            members: vec!["a".to_string(), "b".to_string()],
        },
        ..member(
            "providers",
            "127.0.0.1:1".parse().unwrap(),
            Vec::new(),
            None,
        )
    }
}

struct Fixture {
    handler: FilterChainHandler,
    registry: Arc<Registry>,
    records: tokio::sync::mpsc::Receiver<RequestRecord>,
}

/// Routes `/v1/` to `target` with no retry policy, so any second attempt is
/// the credential failover itself.
async fn build(clusters: Vec<ClusterConfig>, target: &str) -> Fixture {
    let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
    let snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = clusters
        .into_iter()
        .map(|cluster| (cluster.name.clone(), Arc::new(cluster)))
        .collect();
    let names: Vec<&str> = snapshot.keys().map(String::as_str).collect();
    let control = StatsControl::new(1);
    let handles = Arc::new(StatHandles::build(&control, names.iter().copied()));
    let registry = control.registry();
    let stats = Arc::new(RouterStats::new(registry.clone(), handles, WorkerId(0)));
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
                    target: ForwardTarget::Cluster(target.to_string()),
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
    let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
        Arc::new(RouterFilterFactory::new(Arc::new(manager), stats));
    let (sink, records) = BoundedRecordSink::new(1);
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
    .with_request_record_sink(Arc::new(sink));
    Fixture {
        handler,
        registry,
        records,
    }
}

async fn send(fixture: &Fixture) -> (StatusCode, String) {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    let request = HttpRequestParts {
        head: RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/messages"),
            headers,
        },
        body: local_boxed(
            Full::new(Bytes::from_static(b"{}"))
                .map_err(|infallible: std::convert::Infallible| match infallible {}),
        ),
        downstream: DownstreamInfo::loopback(),
        on_upgrade: None,
    };
    let response = tokio::time::timeout(Duration::from_secs(10), fixture.handler.handle(request))
        .await
        .expect("request bounded");
    let status = response.head.status;
    let body = response.body.collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn credential_count(registry: &Registry, cluster: &str, outcome: &str) -> u64 {
    let handle = registry.resolve_capped(
        &instruments::PROVIDER_CREDENTIAL_REQUESTS,
        &[("cluster", cluster), ("outcome", outcome)],
        usize::MAX,
        &[],
    );
    registry.value(handle)
}

/// Every `(cluster, outcome)` series is zero except those in `expected`,
/// which are one.
fn assert_credential_counts(registry: &Registry, expected: &[(&str, &str)]) {
    for cluster in ["a", "b", "providers"] {
        for outcome in OUTCOMES {
            let want = u64::from(expected.contains(&(cluster, outcome)));
            assert_eq!(
                credential_count(registry, cluster, outcome),
                want,
                "provider_credential_requests({cluster}, {outcome})"
            );
        }
    }
}

/// Invariant 6 negative assertion: the fallback carries its own key and
/// nothing the failed primary wrote, neither its static header nor the
/// SigV4 headers the signer set before it failed.
#[tokio::test(flavor = "current_thread")]
async fn a_bedrock_signing_failure_fails_over_with_only_the_fallbacks_credential() {
    LocalSet::new()
        .run_until(async {
            let (a_addr, a_seen) = spawn_upstream().await;
            let (b_addr, b_seen) = spawn_upstream().await;
            let mut fixture = build(
                vec![
                    member(
                        "a",
                        a_addr,
                        vec![header("x-api-key", "key-for-a")],
                        Some(broken_bedrock()),
                    ),
                    member(
                        "b",
                        b_addr,
                        vec![header("authorization", "Bearer key-for-b")],
                        None,
                    ),
                    aggregate(),
                ],
                "providers",
            )
            .await;

            let (status, _) = send(&fixture).await;
            assert_eq!(status, StatusCode::OK);

            assert!(a_seen.lock().unwrap().is_empty(), "nothing is sent to a");
            let b_requests = b_seen.lock().unwrap().clone();
            assert_eq!(b_requests.len(), 1);
            let b_request = &b_requests[0];
            assert!(
                b_request.contains("authorization: bearer key-for-b"),
                "b's credential on the wire: {b_request:?}"
            );
            for primary in [
                "key-for-a",
                "x-amz-",
                "aws4-hmac-sha256",
                "akia",
                PRIMARY_SESSION_TOKEN,
            ] {
                assert!(
                    !b_request.contains(primary),
                    "the primary's credential ({primary}) reached the fallback: {b_request:?}"
                );
            }

            assert_credential_counts(
                &fixture.registry,
                &[("a", instruments::PROVIDER_CREDENTIAL_FAILED_FAILOVER)],
            );

            // The record charges the member actually dialled; the failed
            // primary attempt never reached the credential step.
            let record = fixture.records.try_recv().expect("one request record");
            assert_eq!(record.selected_cluster.as_deref(), Some("b"));
            assert_eq!(record.attempts.len(), 2);
            assert_eq!(record.attempts[0].cluster.as_deref(), Some("a"));
            assert_eq!(record.attempts[0].credential_source, None);
            assert_eq!(record.attempts[1].cluster.as_deref(), Some("b"));
            assert_eq!(
                record.attempts[1].credential_source,
                Some(CredentialSource::Platform)
            );
        })
        .await;
}

/// With every member's credential broken, the request keeps the local 503.
/// The primary counts as a failover, the last member as a refusal.
#[tokio::test(flavor = "current_thread")]
async fn when_every_members_credential_fails_the_request_gets_the_local_503() {
    LocalSet::new()
        .run_until(async {
            let (a_addr, a_seen) = spawn_upstream().await;
            let (b_addr, b_seen) = spawn_upstream().await;
            let fixture = build(
                vec![
                    member("a", a_addr, Vec::new(), Some(broken_bedrock())),
                    member("b", b_addr, Vec::new(), Some(broken_bedrock())),
                    aggregate(),
                ],
                "providers",
            )
            .await;

            let (status, body) = send(&fixture).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body, "provider credential failure");
            assert!(a_seen.lock().unwrap().is_empty());
            assert!(b_seen.lock().unwrap().is_empty());
            assert_credential_counts(
                &fixture.registry,
                &[
                    ("a", instruments::PROVIDER_CREDENTIAL_FAILED_FAILOVER),
                    ("b", instruments::PROVIDER_CREDENTIAL_FAILED),
                ],
            );
        })
        .await;
}

/// A plain cluster has no member to fail over to: one refusal, one count.
#[tokio::test(flavor = "current_thread")]
async fn a_plain_cluster_with_a_broken_credential_answers_the_local_503() {
    LocalSet::new()
        .run_until(async {
            let (a_addr, a_seen) = spawn_upstream().await;
            let fixture = build(
                vec![member("a", a_addr, Vec::new(), Some(broken_bedrock()))],
                "a",
            )
            .await;

            let (status, body) = send(&fixture).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body, "provider credential failure");
            assert!(a_seen.lock().unwrap().is_empty());
            assert_credential_counts(
                &fixture.registry,
                &[("a", instruments::PROVIDER_CREDENTIAL_FAILED)],
            );
        })
        .await;
}
