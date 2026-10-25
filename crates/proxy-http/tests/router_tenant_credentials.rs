//! Exercise the router's per-attempt tenant credentials (ADR-0007). A stand-in
//! decode filter writes `StreamInfo::tenant_credentials`; live recording
//! upstreams verify credential isolation, including across failover.
//!
//! Rust note: router drivers use `spawn_local`; tests use a local runtime and
//! bound each router await with `tokio::time::timeout`.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::resolver::FakeResolver;
use proxy_config::ir::{
    AccessLogFormat, AccessLogIR, AccessLogSink, ClusterConfig, ClusterKind, ClusterName,
    DiscoveryType, EndpointIR, ForwardAction, ForwardTarget, HeaderAppendAction, HeaderMutation,
    LbPolicy, PathMatch, ProviderRuntimeConfig, RetryBackOff, RetryOn, RetryPolicyIR,
    RouteActionIR, RouteEntry, RouteMatcher, RouteTable, TenantCredentialSlot, UpgradeConfig,
    VirtualHostIR,
};
use proxy_credentials::{CredentialSource, TenantCredential, TenantCredentialSet, TenantSecret};
use proxy_http::filter::{
    DecoderCallbacks, FilterHeadersStatus, FilterInstanceFactory, HttpFilter, RequestHeaders,
    TerminalFilterInstanceFactory,
};
use proxy_http::filter_manager::FilterChainHandler;
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
use proxy_http::router::RouterFilterFactory;
use proxy_http::stat_handles::{RouterStats, StatHandles};
use proxy_observability::access_log::parse_format;
use proxy_observability::records::{BoundedRecordSink, RequestRecord, Termination};
use proxy_observability::stats::{instruments, Registry, StatsControl, WorkerId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::LocalSet;
use tokio::time::timeout;

const BOUND: Duration = Duration::from_secs(10);

// --- stand-in for the auth filter -------------------------------------------

struct InstallTenantCredentials(Arc<TenantCredentialSet>);

impl FilterInstanceFactory for InstallTenantCredentials {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(InstallTenantCredentialsFilter(self.0.clone()))
    }
}

struct InstallTenantCredentialsFilter(Arc<TenantCredentialSet>);

impl HttpFilter for InstallTenantCredentialsFilter {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        cb.stream_info().tenant_credentials = Some(self.0.clone());
        FilterHeadersStatus::Continue
    }
}

fn tenant_set(entries: Vec<(&str, Option<&str>)>) -> TenantCredentialSet {
    TenantCredentialSet::new(
        entries
            .into_iter()
            .map(|(provider, secret)| {
                let credential = match secret {
                    Some(secret) => TenantCredential::Usable(TenantSecret::new(secret.to_owned())),
                    None => TenantCredential::Unusable,
                };
                (provider.to_owned(), credential)
            })
            .collect(),
    )
}

// --- recording upstream -----------------------------------------------------

/// Lowercased raw requests received by one upstream.
type Seen = Arc<Mutex<Vec<String>>>;

/// Record request headers and respond with `status` (including upgrade
/// headers for 101).
async fn spawn_upstream(status: u16) -> (SocketAddr, Seen) {
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
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                record
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).to_ascii_lowercase());
                let reply = if status == 101 {
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                        .to_string()
                } else {
                    format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                };
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    (addr, seen)
}

fn requests(seen: &Seen) -> Vec<String> {
    seen.lock().unwrap().clone()
}

// --- cluster fixtures -------------------------------------------------------

/// Configure a member's operator credential and optional tenant slot.
fn member(
    name: &str,
    addr: SocketAddr,
    operator_header: &str,
    slot: Option<(&str, &str, &str)>,
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
        request_headers_to_add: vec![HeaderMutation {
            key: operator_header.to_string(),
            value: format!("operator-key-for-{name}"),
            action: HeaderAppendAction::OverwriteIfExistsOrAdd,
        }],
        request_path_rewrite: None,
        provider_runtime: slot.map(|(provider, header, prefix)| ProviderRuntimeConfig {
            credential: None,
            path_template: None,
            model_rewrites: Vec::new(),
            request_field_policy: Default::default(),
            tenant_credential: Some(TenantCredentialSlot {
                provider: provider.to_string(),
                header: header.to_string(),
                value_prefix: prefix.to_string(),
                verify_path: None,
            }),
        }),
        usage_dialect: None,
        unanswered_usage: proxy_config::ir::UnansweredUsage::default(),
        health_check: None,
        outlier_detection: None,
    }
}

fn aggregate(members: &[&str]) -> ClusterConfig {
    let mut config = member(
        "providers",
        "127.0.0.1:1".parse().unwrap(),
        "x-unused",
        None,
    );
    config.kind = ClusterKind::Aggregate {
        members: members.iter().map(|m| m.to_string()).collect(),
    };
    config.endpoints = Vec::new();
    config.request_headers_to_add = Vec::new();
    config
}

struct Fixture {
    handler: FilterChainHandler,
    records: mpsc::Receiver<RequestRecord>,
    /// Registry used to inspect tenant-credential counters.
    registry: Arc<Registry>,
}

/// Build `/` -> `target`, optionally installing the stand-in tenant filter.
async fn build(
    clusters: Vec<ClusterConfig>,
    target: &str,
    tenant: Option<TenantCredentialSet>,
    retry_on: Option<&str>,
) -> Fixture {
    build_with_access_logs(clusters, target, tenant, retry_on, &[]).await
}

/// Build the handler with access loggers for inspecting rendered `StreamInfo`.
async fn build_with_access_logs(
    clusters: Vec<ClusterConfig>,
    target: &str,
    tenant: Option<TenantCredentialSet>,
    retry_on: Option<&str>,
    access_logs: &[AccessLogIR],
) -> Fixture {
    let names: Vec<String> = clusters.iter().map(|c| c.name.clone()).collect();
    let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
    let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
    for cluster in clusters {
        snapshot.insert(cluster.name.clone(), Arc::new(cluster));
    }
    manager.update_from_snapshot(&snapshot).await;

    let retry_policy = retry_on.map(|retry_on| RetryPolicyIR {
        retry_on: RetryOn::parse(retry_on),
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
    });
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
                    target: ForwardTarget::Cluster(target.to_string()),
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

    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let control = StatsControl::new(1);
    let handles = Arc::new(StatHandles::build(&control, name_refs.iter().copied()));
    let registry = control.registry();
    let stats = Arc::new(RouterStats::new(registry.clone(), handles, WorkerId(0)));
    let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> = Arc::new(
        RouterFilterFactory::new(Arc::new(manager), stats).with_upgrade_configs(vec![
            UpgradeConfig {
                upgrade_type: "websocket".to_string(),
                enabled: true,
            },
        ]),
    );
    let filters: Vec<Arc<dyn FilterInstanceFactory>> = match tenant {
        Some(set) => vec![Arc::new(InstallTenantCredentials(Arc::new(set)))],
        None => Vec::new(),
    };
    let handler = FilterChainHandler::new_with_access_logs(
        filters,
        terminal_factory,
        Arc::new(route_table),
        false,
        false,
        0,
        access_logs,
    )
    .expect("test access-log sink (temp file) always opens cleanly");
    let (sink, records) = BoundedRecordSink::new(4);
    Fixture {
        handler: handler.with_request_record_sink(Arc::new(sink)),
        records,
        registry,
    }
}

/// Return a unique temporary path for a file access logger.
fn temp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "proxy-http-tenant-credentials-test-{}-{}-{}",
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
    // Flush queued writes instead of sleeping for the background writer.
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

fn request(upgrade: bool) -> HttpRequestParts {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    let on_upgrade = if upgrade {
        headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("Upgrade"),
        );
        let mut synthetic = http::Request::builder()
            .method(Method::GET)
            .uri("/chat")
            .body(())
            .unwrap();
        Some(hyper::upgrade::on(&mut synthetic))
    } else {
        None
    };
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::GET,
            uri: Uri::from_static("/chat"),
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

/// Send one request and return its status and body.
async fn send(fixture: &Fixture, upgrade: bool) -> (StatusCode, String) {
    let resp = timeout(BOUND, fixture.handler.handle(request(upgrade)))
        .await
        .expect("router answered within the bound");
    let status = resp.head.status;
    let body = timeout(BOUND, resp.body.collect())
        .await
        .expect("body within the bound")
        .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
        .unwrap_or_default();
    (status, body)
}

/// Possible provider labels, including `-` when a refusal has no slot.
const CREDENTIAL_PROVIDERS: [&str; 3] = ["openai", "anthropic", "-"];
const CREDENTIAL_OUTCOMES: [&str; 3] = [
    instruments::TENANT_CREDENTIAL_APPLIED,
    instruments::TENANT_CREDENTIAL_MISSING,
    instruments::TENANT_CREDENTIAL_UNUSABLE,
];

/// Read a series through `resolve_capped`, reusing an existing handle.
fn credential_requests(registry: &Registry, provider: &str, outcome: &str) -> u64 {
    let handle = registry.resolve_capped(
        &instruments::TENANT_CREDENTIAL_REQUESTS,
        &[("provider", provider), ("outcome", outcome)],
        usize::MAX,
        &[],
    );
    registry.value(handle)
}

/// Assert that only `expected` has a count of 1; `None` requires all zeroes.
fn assert_credential_counts(registry: &Registry, expected: Option<(&str, &str)>) {
    for provider in CREDENTIAL_PROVIDERS {
        for outcome in CREDENTIAL_OUTCOMES {
            let want = u64::from(expected == Some((provider, outcome)));
            assert_eq!(
                credential_requests(registry, provider, outcome),
                want,
                "tenant_credential_requests({provider}, {outcome})"
            );
        }
    }
}

fn only_record(fixture: &mut Fixture) -> RequestRecord {
    fixture.records.try_recv().expect("one request record")
}

fn assert_no_operator_key(texts: &[String]) {
    for text in texts {
        assert!(
            !text.contains("operator-key"),
            "operator credential reached an upstream in tenant mode: {text:?}"
        );
    }
}

// --- tests ------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn tenant_key_replaces_operator_key_for_each_header_shape() {
    for (header, prefix, expected) in [
        (
            "authorization",
            "Bearer ",
            "authorization: bearer tenant-secret",
        ),
        ("x-api-key", "", "x-api-key: tenant-secret"),
        ("api-key", "", "api-key: tenant-secret"),
    ] {
        LocalSet::new()
            .run_until(async {
                let (addr, seen) = spawn_upstream(200).await;
                let mut fixture = build(
                    vec![member("up", addr, header, Some(("openai", header, prefix)))],
                    "up",
                    Some(tenant_set(vec![("openai", Some("tenant-secret"))])),
                    None,
                )
                .await;
                let (status, _) = send(&fixture, false).await;
                assert_eq!(status, StatusCode::OK);
                assert_credential_counts(&fixture.registry, Some(("openai", "applied")));

                let got = requests(&seen);
                assert_eq!(got.len(), 1);
                assert!(got[0].contains(expected), "{header}: {:?}", got[0]);
                assert_eq!(
                    got[0].matches(&format!("\r\n{header}:")).count(),
                    1,
                    "{header} must appear exactly once: {:?}",
                    got[0]
                );
                assert_no_operator_key(&got);

                let record = only_record(&mut fixture);
                assert_eq!(record.credential_source, Some(CredentialSource::Tenant));
                assert_eq!(
                    record.attempts[0].credential_source,
                    Some(CredentialSource::Tenant)
                );
            })
            .await;
    }
}

/// Skip ineligible A and send the first attempt to B, the eligible member.
async fn ineligible_first_member_is_never_dialled(a_slot: Option<(&str, &str, &str)>) {
    LocalSet::new()
        .run_until(async {
            let (a_addr, a_seen) = spawn_upstream(200).await;
            let (b_addr, b_seen) = spawn_upstream(200).await;
            let mut fixture = build(
                vec![
                    member("a", a_addr, "authorization", a_slot),
                    member(
                        "b",
                        b_addr,
                        "authorization",
                        Some(("anthropic", "authorization", "Bearer ")),
                    ),
                    aggregate(&["a", "b"]),
                ],
                "providers",
                Some(tenant_set(vec![("anthropic", Some("tenant-secret"))])),
                None,
            )
            .await;
            let (status, _) = send(&fixture, false).await;
            assert_eq!(status, StatusCode::OK);

            assert!(requests(&a_seen).is_empty(), "a must never be dialled");
            let b = requests(&b_seen);
            assert_eq!(b.len(), 1);
            assert!(b[0].contains("authorization: bearer tenant-secret"));
            assert_no_operator_key(&b);

            let record = only_record(&mut fixture);
            assert_eq!(record.selected_cluster.as_deref(), Some("b"));
            assert_eq!(record.physical_attempt_count, 1);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn aggregate_skips_member_without_a_slot() {
    ineligible_first_member_is_never_dialled(None).await;
}

#[tokio::test(flavor = "current_thread")]
async fn aggregate_skips_member_whose_provider_the_tenant_lacks() {
    ineligible_first_member_is_never_dialled(Some(("openai", "authorization", "Bearer "))).await;
}

#[tokio::test(flavor = "current_thread")]
async fn aggregate_with_no_eligible_member_is_403_and_dials_nothing() {
    LocalSet::new()
        .run_until(async {
            let (a_addr, a_seen) = spawn_upstream(200).await;
            let (b_addr, b_seen) = spawn_upstream(200).await;
            let mut fixture = build(
                vec![
                    member(
                        "a",
                        a_addr,
                        "authorization",
                        Some(("openai", "authorization", "Bearer ")),
                    ),
                    member("b", b_addr, "authorization", None),
                    aggregate(&["a", "b"]),
                ],
                "providers",
                Some(tenant_set(vec![("anthropic", Some("tenant-secret"))])),
                None,
            )
            .await;
            let (status, body) = send(&fixture, false).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_credential_counts(&fixture.registry, Some(("openai", "missing")));
            // The router's refusal is a local reply, not a completed exchange.
            assert_eq!(
                only_record(&mut fixture).termination,
                Termination::LocalReply
            );
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json["error"]["type"], "tenant_credential_missing");
            assert!(
                json["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("openai"),
                "message names the provider involved: {body}"
            );
            assert!(!body.contains("tenant-secret"));
            assert!(requests(&a_seen).is_empty());
            assert!(requests(&b_seen).is_empty());
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn aggregate_with_no_healthy_host_stays_503_in_tenant_mode() {
    LocalSet::new()
        .run_until(async {
            // Eligibility does not make an endpoint healthy.
            let (addr, _seen) = spawn_upstream(200).await;
            let mut b = member(
                "b",
                addr,
                "authorization",
                Some(("anthropic", "authorization", "Bearer ")),
            );
            b.endpoints = Vec::new();
            let fixture = build(
                vec![b, aggregate(&["b"])],
                "providers",
                Some(tenant_set(vec![("anthropic", Some("tenant-secret"))])),
                None,
            )
            .await;
            let (status, body) = send(&fixture, false).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body, "no healthy upstream");
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn plain_cluster_without_matching_slot_is_403_without_dialling() {
    // Refusals are labeled by the missing slot's provider, or `-` if absent.
    for (slot, expected) in [
        (None, ("-", instruments::TENANT_CREDENTIAL_MISSING)),
        (
            Some(("openai", "authorization", "Bearer ")),
            ("openai", instruments::TENANT_CREDENTIAL_MISSING),
        ),
    ] {
        LocalSet::new()
            .run_until(async {
                let (addr, seen) = spawn_upstream(200).await;
                let fixture = build(
                    vec![member("up", addr, "authorization", slot)],
                    "up",
                    Some(tenant_set(vec![("anthropic", Some("tenant-secret"))])),
                    None,
                )
                .await;
                let (status, body) = send(&fixture, false).await;
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert!(body.contains("tenant_credential_missing"));
                assert!(requests(&seen).is_empty());
                assert_credential_counts(&fixture.registry, Some(expected));
            })
            .await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn unusable_credential_fails_closed_with_503_and_no_credential_sent() {
    LocalSet::new()
        .run_until(async {
            let (addr, seen) = spawn_upstream(200).await;
            let fixture = build(
                vec![member(
                    "up",
                    addr,
                    "authorization",
                    Some(("anthropic", "authorization", "Bearer ")),
                )],
                "up",
                Some(tenant_set(vec![("anthropic", None)])),
                None,
            )
            .await;
            let (status, body) = send(&fixture, false).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body, "provider credential failure");
            // No upstream received an operator credential.
            assert!(requests(&seen).is_empty());
            assert_credential_counts(
                &fixture.registry,
                Some(("anthropic", instruments::TENANT_CREDENTIAL_UNUSABLE)),
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn upstream_401_with_tenant_credential_is_one_attempt_and_passed_through() {
    LocalSet::new()
        .run_until(async {
            let (a_addr, a_seen) = spawn_upstream(401).await;
            let (b_addr, b_seen) = spawn_upstream(200).await;
            let slot = Some(("anthropic", "authorization", "Bearer "));
            let mut fixture = build(
                vec![
                    member("a", a_addr, "authorization", slot),
                    member("b", b_addr, "authorization", slot),
                    aggregate(&["a", "b"]),
                ],
                "providers",
                Some(tenant_set(vec![("anthropic", Some("tenant-secret"))])),
                Some("5xx,gateway-error,retriable-4xx,connect-failure,reset"),
            )
            .await;
            let (status, _) = send(&fixture, false).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(requests(&a_seen).len(), 1);
            assert!(requests(&b_seen).is_empty(), "no fallback after a 401");
            assert_no_operator_key(&requests(&a_seen));
            assert_eq!(only_record(&mut fixture).physical_attempt_count, 1);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn platform_mode_keeps_operator_credential_and_records_platform_source() {
    // No filter and an empty credential set both mean platform mode.
    for tenant in [None, Some(tenant_set(Vec::new()))] {
        LocalSet::new()
            .run_until(async {
                let (a_addr, a_seen) = spawn_upstream(200).await;
                let (b_addr, b_seen) = spawn_upstream(200).await;
                let mut fixture = build(
                    vec![
                        // Platform mode ignores slots: A is first and wins.
                        member(
                            "a",
                            a_addr,
                            "authorization",
                            Some(("openai", "authorization", "Bearer ")),
                        ),
                        member("b", b_addr, "authorization", None),
                        aggregate(&["a", "b"]),
                    ],
                    "providers",
                    tenant,
                    None,
                )
                .await;
                let (status, _) = send(&fixture, false).await;
                assert_eq!(status, StatusCode::OK);
                assert_credential_counts(&fixture.registry, None);
                let a = requests(&a_seen);
                assert_eq!(a.len(), 1);
                assert!(a[0].contains("authorization: operator-key-for-a"));
                assert!(requests(&b_seen).is_empty());

                let record = only_record(&mut fixture);
                assert_eq!(record.credential_source, Some(CredentialSource::Platform));
                assert_eq!(
                    record.attempts[0].credential_source,
                    Some(CredentialSource::Platform)
                );
            })
            .await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn access_log_renders_the_credential_source_the_router_chose() {
    // Cover successful tenant mode, refused tenant mode, and platform mode.
    let cases = [
        (
            "tenant",
            Some(tenant_set(vec![("openai", Some("tenant-secret"))])),
            StatusCode::OK,
            "tenant\n",
        ),
        (
            "refused",
            Some(tenant_set(vec![("anthropic", Some("tenant-secret"))])),
            StatusCode::FORBIDDEN,
            "-\n",
        ),
        ("platform", None, StatusCode::OK, "platform\n"),
    ];
    for (name, tenant, expected_status, expected) in cases {
        LocalSet::new()
            .run_until(async {
                let (addr, _seen) = spawn_upstream(200).await;
                let log_path = temp_path(name);
                let fixture = build_with_access_logs(
                    vec![member(
                        "up",
                        addr,
                        "authorization",
                        Some(("openai", "authorization", "Bearer ")),
                    )],
                    "up",
                    tenant,
                    None,
                    &[text_logger(&log_path, "%LLM_CREDENTIAL_SOURCE%\n")],
                )
                .await;
                let (status, _) = send(&fixture, false).await;
                assert_eq!(status, expected_status, "{name}");
                assert_eq!(read_to_string(&log_path), expected, "{name}");
                let _ = std::fs::remove_file(&log_path);
            })
            .await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn websocket_upgrade_applies_the_tenant_credential() {
    LocalSet::new()
        .run_until(async {
            let (addr, seen) = spawn_upstream(101).await;
            let fixture = build(
                vec![member(
                    "up",
                    addr,
                    "authorization",
                    Some(("anthropic", "authorization", "Bearer ")),
                )],
                "up",
                Some(tenant_set(vec![("anthropic", Some("tenant-secret"))])),
                None,
            )
            .await;
            // The synthetic `OnUpgrade` never resolves; inspect the upstream.
            let _ = timeout(BOUND, fixture.handler.handle(request(true))).await;
            assert_credential_counts(&fixture.registry, Some(("anthropic", "applied")));
            let got = requests(&seen);
            assert_eq!(got.len(), 1);
            assert!(got[0].contains("upgrade: websocket"));
            assert!(got[0].contains("authorization: bearer tenant-secret"));
            assert_no_operator_key(&got);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn websocket_upgrade_without_a_matching_credential_is_403() {
    LocalSet::new()
        .run_until(async {
            let (addr, seen) = spawn_upstream(101).await;
            let fixture = build(
                vec![member(
                    "up",
                    addr,
                    "authorization",
                    Some(("openai", "authorization", "Bearer ")),
                )],
                "up",
                Some(tenant_set(vec![("anthropic", Some("tenant-secret"))])),
                None,
            )
            .await;
            let (status, body) = send(&fixture, true).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert!(body.contains("tenant_credential_missing"));
            assert!(requests(&seen).is_empty());
            assert_credential_counts(&fixture.registry, Some(("openai", "missing")));
        })
        .await;
}

/// Keep both operator and tenant credentials off the wire while preserving
/// a non-credential static header (ADR-0007 decision 5).
#[tokio::test(flavor = "current_thread")]
async fn operator_credential_on_a_different_header_than_the_slot_is_removed() {
    for (operator_header, slot_header, prefix, expected, absent) in [
        (
            "authorization",
            "x-api-key",
            "",
            "x-api-key: tenant-secret",
            "\r\nauthorization:",
        ),
        (
            "x-api-key",
            "authorization",
            "Bearer ",
            "authorization: bearer tenant-secret",
            "\r\nx-api-key:",
        ),
    ] {
        LocalSet::new()
            .run_until(async {
                let (addr, seen) = spawn_upstream(200).await;
                let mut cluster = member(
                    "up",
                    addr,
                    operator_header,
                    Some(("openai", slot_header, prefix)),
                );
                cluster.request_headers_to_add.push(HeaderMutation {
                    key: "anthropic-version".to_string(),
                    value: "2023-06-01".to_string(),
                    action: HeaderAppendAction::OverwriteIfExistsOrAdd,
                });
                let fixture = build(
                    vec![cluster],
                    "up",
                    Some(tenant_set(vec![("openai", Some("tenant-secret"))])),
                    None,
                )
                .await;
                let (status, _) = send(&fixture, false).await;
                assert_eq!(status, StatusCode::OK);

                let got = requests(&seen);
                assert_eq!(got.len(), 1);
                assert!(got[0].contains(expected), "{:?}", got[0]);
                assert!(
                    !got[0].contains(absent),
                    "operator header {operator_header} must be removed: {:?}",
                    got[0]
                );
                assert_no_operator_key(&got);
                assert!(
                    got[0].contains("anthropic-version: 2023-06-01"),
                    "non-credential static headers still sent: {:?}",
                    got[0]
                );
            })
            .await;
    }
}

/// After A returns 503, B must receive only its own tenant key. Neither
/// operator key nor A's tenant key may reach B.
#[tokio::test(flavor = "current_thread")]
async fn tenant_credentials_are_isolated_across_failover() {
    // Request text is lowercased by the recorder.
    const OPERATOR_KEYS: [&str; 2] = ["operator-key-a", "operator-key-b"];
    LocalSet::new()
        .run_until(async {
            let (a_addr, a_seen) = spawn_upstream(503).await;
            let (b_addr, b_seen) = spawn_upstream(200).await;
            let mut a = member(
                "a",
                a_addr,
                "authorization",
                Some(("openai", "authorization", "Bearer ")),
            );
            a.request_headers_to_add[0].value = "Bearer operator-key-A".to_string();
            // The removal step must strip B's separate operator header.
            let mut b = member(
                "b",
                b_addr,
                "authorization",
                Some(("anthropic", "x-api-key", "")),
            );
            b.request_headers_to_add[0].value = "Bearer operator-key-B".to_string();
            let mut fixture = build(
                vec![a, b, aggregate(&["a", "b"])],
                "providers",
                Some(tenant_set(vec![
                    ("openai", Some("tenant-key-A")),
                    ("anthropic", Some("tenant-key-B")),
                ])),
                Some("5xx"),
            )
            .await;
            let (status, _) = send(&fixture, false).await;
            assert_eq!(status, StatusCode::OK);

            // Fail over from A to B.
            let a_got = requests(&a_seen);
            let b_got = requests(&b_seen);
            assert_eq!(a_got.len(), 1, "A dialled exactly once: {a_got:?}");
            assert_eq!(b_got.len(), 1, "B dialled exactly once: {b_got:?}");

            // A receives only its own tenant key.
            assert!(
                a_got[0].contains("authorization: bearer tenant-key-a"),
                "A must carry its tenant key: {:?}",
                a_got[0]
            );
            for needle in OPERATOR_KEYS.iter().chain(["tenant-key-b"].iter()) {
                assert!(
                    !a_got[0].contains(needle),
                    "{needle} must not reach A: {:?}",
                    a_got[0]
                );
            }

            // B receives its own key only, on `x-api-key`.
            assert!(
                b_got[0].contains("x-api-key: tenant-key-b"),
                "B must carry its tenant key: {:?}",
                b_got[0]
            );
            assert!(
                !b_got[0].contains("\r\nauthorization:"),
                "B must not carry any authorization header (its operator key sits there): {:?}",
                b_got[0]
            );
            for needle in OPERATOR_KEYS.iter().chain(["tenant-key-a"].iter()) {
                assert!(
                    !b_got[0].contains(needle),
                    "{needle} must not reach B: {:?}",
                    b_got[0]
                );
            }

            // Each member applied its own provider credential once.
            let applied = instruments::TENANT_CREDENTIAL_APPLIED;
            for provider in CREDENTIAL_PROVIDERS {
                for outcome in CREDENTIAL_OUTCOMES {
                    let want = u64::from(
                        outcome == applied && (provider == "openai" || provider == "anthropic"),
                    );
                    assert_eq!(
                        credential_requests(&fixture.registry, provider, outcome),
                        want,
                        "tenant_credential_requests({provider}, {outcome})"
                    );
                }
            }

            let record = only_record(&mut fixture);
            assert_eq!(record.selected_cluster.as_deref(), Some("b"));
            assert_eq!(record.physical_attempt_count, 2);
            assert_eq!(record.credential_source, Some(CredentialSource::Tenant));
            let last = record.attempts.last().expect("at least one attempt");
            assert_eq!(last.cluster.as_deref(), Some("b"));
            assert_eq!(last.credential_source, Some(CredentialSource::Tenant));
        })
        .await;
}
