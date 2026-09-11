//! Wiring tests: real HTTP requests over a real socket (port 0), not
//! hand-called handler functions -- the wiring is the part that breaks.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1 as client_http1;
use hyper::{HeaderMap, Request, StatusCode};
use hyper_util::rt::TokioIo;
use proxy_config::ir::{
    ClusterConfig, ClusterKind, CodecType, ConfigSnapshot, DiscoveryType, EndpointIR,
    FilterChainMatch, FilterChainSpec, ForwardAction, ForwardTarget, HeaderAppendAction,
    HeaderMutation, HttpConnectionManagerConfig, HttpFilterSpec, LbPolicy, ListenerConfig,
    NetworkFilterSpec, PathMatch, RouteActionIR, RouteEntry, RouteMatcher, RouteTable,
    SnapshotVersion, UpstreamProtocol, VirtualHostIR,
};
use proxy_core::runtime::SnapshotHandles;
use proxy_filters::auth::{
    AuthError, AuthOutcome, Authenticator, HmacSecret, KeySet, TenantId, VirtualKeyAuthenticator,
};
use proxy_filters::auth_filter;
use proxy_filters::control::{ControlPlane, InMemoryControlPlaneStore};
use proxy_filters::model_authz::ModelAccess;
use proxy_filters::spend::{Charge, MicroUsd, Period};
use proxy_http::filter::SharedFactoryState;
use proxy_observability::stats::{
    instruments, prometheus_render, Registry, StatsControl, WorkerId,
};
use tokio::net::TcpStream;

use crate::dump::{LiveCluster, LiveEndpoint};
use crate::server::{
    serve, AdminRuntime, AdminServer, ClusterStateProvider, Readiness, ReadinessProbe,
};

/// The HMAC secret every write-API test's `ControlPlane` and matching
/// [`VirtualKeyAuthenticator`] are built with -- arbitrary, but shared
/// between the two so a plaintext key minted through the admin API actually
/// verifies when a test re-derives its digest.
const TEST_HMAC_SECRET: &[u8] = b"admin-write-api-test-secret";

/// The bearer token every write-API test that needs one configures --
/// distinctive enough that a wrong-token test can pick something else
/// entirely without risk of an accidental match.
const ADMIN_TOKEN: &str = "test-admin-token-9f3c";

/// The literal secret this module never expects to see anywhere in a
/// `/config_dump` response body -- distinctive enough that a partial/prefix
/// match can't accidentally pass the assertion.
const SENTINEL_API_KEY: &str = "sk-live-SENTINEL-9f3c7d2a1b6e4488a02c";

/// A snapshot with one listener -> one filter chain -> an HTTP connection
/// manager whose sole route injects `SENTINEL_API_KEY` via
/// `request_headers_to_add`, exactly how the dialect injects provider auth
/// (`authorization: Bearer <key>`).
fn snapshot_with_secret() -> Arc<ConfigSnapshot> {
    let route = Arc::new(RouteEntry {
        name: Some("default".to_string()),
        matcher: RouteMatcher {
            path: PathMatch::Prefix("/".to_string()),
            case_sensitive: true,
            headers: vec![],
        },
        action: RouteActionIR::Forward(ForwardAction {
            target: ForwardTarget::Cluster("upstream".to_string()),
            timeout: Some(Duration::from_secs(15)),
            idle_timeout: None,
            retry_policy: None,
            host_rewrite_literal: None,
            prefix_rewrite: None,
        }),
        request_headers_to_add: vec![HeaderMutation {
            key: "authorization".to_string(),
            value: format!("Bearer {SENTINEL_API_KEY}"),
            action: HeaderAppendAction::OverwriteIfExistsOrAdd,
        }],
        typed_per_filter_config: BTreeMap::new(),
        route_index: 0,
        include_request_attempt_count: false,
        include_attempt_count_in_response: false,
        streaming_strict: false,
    });
    let vhost = VirtualHostIR {
        name: "default".to_string(),
        domains: vec!["*".to_string()],
        routes: vec![route],
        typed_per_filter_config: BTreeMap::new(),
    };
    let route_table =
        Arc::new(RouteTable::new("local_route".to_string(), vec![vhost], BTreeMap::new()).unwrap());

    let hcm = HttpConnectionManagerConfig {
        stat_prefix: "ingress".to_string(),
        route_table,
        rds_route_config_name: None,
        http_filters: vec![HttpFilterSpec {
            name: "envoy.filters.http.router".to_string(),
            type_url: "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
                .to_string(),
            config: None,
            is_router: true,
        }],
        codec_type: CodecType::Auto,
        generate_request_id: true,
        use_remote_address: false,
        xff_num_trusted_hops: 0,
        access_logs: vec![],
        upgrade_configs: vec![],
    };

    let listener = ListenerConfig {
        name: "listener_0".to_string(),
        address: "127.0.0.1:0".parse().unwrap(),
        filter_chains: vec![FilterChainSpec {
            name: Some("default".to_string()),
            match_criteria: FilterChainMatch::default(),
            transport_socket: None,
            filters: vec![NetworkFilterSpec::HttpConnectionManager(hcm)],
        }],
        default_filter_chain: None,
        listener_filters: vec![],
        per_connection_buffer_limit_bytes: 1024 * 1024,
        tcp_backlog_size: None,
        bind_to_port: true,
    };

    let cluster = ClusterConfig {
        // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
        eds: None,
        name: "upstream".to_string(),
        discovery: DiscoveryType::Static,
        lb_policy: LbPolicy::RoundRobin,
        connect_timeout: Duration::from_secs(5),
        endpoints: vec![EndpointIR {
            metadata: Default::default(),
            host: "10.0.0.5".to_string(),
            port: 8080,
            weight: 1,
            priority: 0,
        }],
        kind: ClusterKind::Endpoints,
        transport_socket: None,
        per_connection_buffer_limit_bytes: 1024 * 1024,
        circuit_breakers: Default::default(),
        upstream_protocol: UpstreamProtocol::Http1,
        request_headers_to_add: Vec::new(),
        usage_dialect: None,
        health_check: None,
        outlier_detection: None,
    };

    Arc::new(ConfigSnapshot {
        listeners: HashMap::from([(listener.name.clone(), Arc::new(listener))]),
        clusters: HashMap::from([(cluster.name.clone(), Arc::new(cluster))]),
        routes: HashMap::new(),
        secrets: HashMap::new(),
        admin: Some("127.0.0.1:9901".parse().unwrap()),
        tracing: None,
        // WP-20 increment 1: this fixture is a static-config snapshot, which
        // is what `None` means -- no control plane is involved.
        ads: None,
        version: SnapshotVersion(1),
    })
}

/// Starts an admin server on port 0 over `snapshot`, with no WP-23 stats
/// registry wired -- the default for every test that isn't specifically
/// about `/stats`. See [`start_with_registry`] for the `/stats`-focused
/// tests. Returns the server (kept alive for the caller) and its bound
/// address.
async fn start(snapshot: Arc<ConfigSnapshot>) -> (AdminServer, SocketAddr) {
    start_with_registry(snapshot, None).await
}

/// [`start`], but with an explicit (possibly `Some`) WP-23 stats registry --
/// what `/stats`'s own tests need to exercise both the wired and unwired
/// cases. No `SharedFactoryState` singleton and no admin token -- what every
/// read-only test needs, and (see test 10 in this file) also what proves
/// reads are unaffected by the write API's gate.
async fn start_with_registry(
    snapshot: Arc<ConfigSnapshot>,
    registry: Option<Arc<Registry>>,
) -> (AdminServer, SocketAddr) {
    start_full(
        snapshot,
        registry,
        Arc::new(SharedFactoryState::default()),
        None,
    )
    .await
}

/// [`start`], but with an explicit [`ReadinessProbe`] -- what WP-21 increment
/// 3's `/ready` tests need. No registry, no `SharedFactoryState`, no admin
/// token: the same "only the one thing this test is about" shape as
/// [`start_with_registry`].
async fn start_with_readiness(
    snapshot: Arc<ConfigSnapshot>,
    readiness: ReadinessProbe,
) -> (AdminServer, SocketAddr) {
    start_full_with_readiness(
        snapshot,
        None,
        Arc::new(SharedFactoryState::default()),
        None,
        Some(readiness),
    )
    .await
}

/// The full [`serve`] parameter set MINUS `readiness` -- what every write-API
/// test needs to supply a real `ControlPlane` (via `factory_state`) and/or a
/// bearer token. Kept as its own (unchanged-signature) function rather than
/// adding a fifth parameter here, so the ~30 existing call sites that predate
/// WP-21 increment 3 don't all need touching for a param none of them cares
/// about -- see [`start_full_with_readiness`] for the one that does.
async fn start_full(
    snapshot: Arc<ConfigSnapshot>,
    registry: Option<Arc<Registry>>,
    factory_state: Arc<SharedFactoryState>,
    admin_token: Option<String>,
) -> (AdminServer, SocketAddr) {
    start_full_with_readiness(snapshot, registry, factory_state, admin_token, None).await
}

/// The full [`serve`] parameter set, including `readiness` -- see
/// [`start_full`]'s doc for why that one stays four params.
async fn start_full_with_readiness(
    snapshot: Arc<ConfigSnapshot>,
    registry: Option<Arc<Registry>>,
    factory_state: Arc<SharedFactoryState>,
    admin_token: Option<String>,
    readiness: Option<ReadinessProbe>,
) -> (AdminServer, SocketAddr) {
    // Rust note: `SnapshotHandles::register` both builds the handle and
    // enrolls it, the same path production code (`WorkerPool::spawn`, and
    // `start_admin` in `crates/proxy/src/main.rs`) goes through -- there is
    // no other way to obtain a `WorkerConfigHandle` from outside `proxy-core`.
    let config = SnapshotHandles::new().register(snapshot);
    let server = serve(
        "127.0.0.1:0".parse().unwrap(),
        AdminRuntime {
            config,
            registry,
            started_at: Instant::now(),
            factory_state,
            admin_token,
            readiness,
            cluster_state: None,
        },
    )
    .await
    .expect("admin server bind");
    let addr = server.local_addr();
    (server, addr)
}

/// Starts the real HTTP admin socket with a caller-controlled live host-set
/// provider. This is the same injected seam production uses, without making
/// these admin tests depend on `proxy-cluster`.
async fn start_with_cluster_state(
    snapshot: Arc<ConfigSnapshot>,
    cluster_state: ClusterStateProvider,
) -> (AdminServer, SocketAddr) {
    let config = SnapshotHandles::new().register(snapshot);
    let server = serve(
        "127.0.0.1:0".parse().unwrap(),
        AdminRuntime {
            config,
            registry: None,
            started_at: Instant::now(),
            factory_state: Arc::new(SharedFactoryState::default()),
            admin_token: None,
            readiness: None,
            cluster_state: Some(cluster_state),
        },
    )
    .await
    .expect("admin server bind");
    let addr = server.local_addr();
    (server, addr)
}

/// Registers a real [`ControlPlane`] into `factory_state` under
/// `(scope, auth_filter::TYPE_URL)` AND, since WP-50 3c-ii-a, the matching
/// `(stat_prefix, auth_filter::TYPE_URL)` name-index slot -- the exact shape
/// a worker's `AuthFilterFactory::create` produces for a real `llmproxy.auth`
/// filter (see that factory's own doc for the `get_or_try_init` singleton
/// dance this mirrors). Returns the `ControlPlane`'s own published-snapshot
/// handle, so a test can `.load()` it directly to check what a
/// mint/revoke/policy write actually published -- exactly what
/// `crate::control`'s own tests do from inside that crate.
fn register_control_plane(
    factory_state: &Arc<SharedFactoryState>,
    scope: &str,
    stat_prefix: &str,
    hmac_secret: &[u8],
) -> Arc<arc_swap::ArcSwap<proxy_filters::control::ControlPlaneSnapshot>> {
    let control_plane = ControlPlane::new(
        Box::new(InMemoryControlPlaneStore::default()),
        HmacSecret::new(hmac_secret),
        KeySet::new(),
    )
    .expect("an empty store must not fail ControlPlane::new");
    let handle = control_plane.handle();
    factory_state
        .get_or_try_init(scope, stat_prefix, auth_filter::TYPE_URL, || {
            Ok(Arc::new(control_plane) as Arc<dyn std::any::Any + Send + Sync>)
        })
        .expect("inserting the test ControlPlane singleton must not fail");
    handle
}

/// Builds a [`SharedFactoryState`] with a single real [`ControlPlane`]
/// registered under [`TEST_CHAIN_SCOPE`]/[`TEST_CHAIN_STAT_PREFIX`] -- what
/// every single-chain write test uses (the unscoped alias resolves it
/// unambiguously; the scoped form resolves it by name).
fn factory_state_with_control_plane() -> (
    Arc<SharedFactoryState>,
    Arc<arc_swap::ArcSwap<proxy_filters::control::ControlPlaneSnapshot>>,
) {
    let factory_state = Arc::new(SharedFactoryState::default());
    let handle = register_control_plane(
        &factory_state,
        TEST_CHAIN_SCOPE,
        TEST_CHAIN_STAT_PREFIX,
        TEST_HMAC_SECRET,
    );
    (factory_state, handle)
}

/// Registers a real [`SpendAccumulator`] into `factory_state` under
/// `(scope, spend_limit_filter::TYPE_URL)` and its `stat_prefix` name index
/// -- WP-50 3c-iv's stand-in for what `SpendLimitFilterFactory::create`
/// registers in production. Wraps the accumulator in
/// [`SharedSpendLimitState::for_test`], the SAME wrapper type production
/// registers (see that constructor's own doc for why a bare
/// `Arc<SpendAccumulator>` here would make the admin server's downcast
/// silently miss), rather than driving the whole
/// `SpendLimitFilterFactory::create`/HCM-build machinery just to get one.
///
/// Uses its own fresh, private [`InMemoryControlPlaneStore`] -- independent
/// of whatever store the `ControlPlane` registered at the same scope uses.
/// That is a deliberate simplification for these admin-wiring tests (which
/// exercise gating/resolution/response shape, not `spend_limit_filter`'s own
/// "flushes into the operator's store" property, already covered by that
/// module's own tests): [`SpendAccumulator::report`]/`record` never touch
/// the `ControlPlane`'s store at all, so nothing here depends on the two
/// being the same store.
fn register_spend_accumulator(
    factory_state: &Arc<SharedFactoryState>,
    scope: &str,
    stat_prefix: &str,
    default_period: Period,
) -> Arc<proxy_filters::spend::SpendAccumulator> {
    let accumulator = Arc::new(proxy_filters::spend::SpendAccumulator::new(
        stat_prefix.to_string(),
        Arc::new(InMemoryControlPlaneStore::default()),
        default_period,
        "test-node".to_string(),
    ));
    factory_state
        .get_or_try_init(
            scope,
            stat_prefix,
            proxy_filters::spend_limit_filter::TYPE_URL,
            || {
                Ok(Arc::new(
                    proxy_filters::spend_limit_filter::SharedSpendLimitState::for_test(Arc::clone(
                        &accumulator,
                    )),
                ) as Arc<dyn std::any::Any + Send + Sync>)
            },
        )
        .expect("inserting the test spend accumulator singleton must not fail");
    accumulator
}

/// [`factory_state_with_control_plane`], plus a real [`SpendAccumulator`]
/// registered at the SAME [`TEST_CHAIN_SCOPE`]/[`TEST_CHAIN_STAT_PREFIX`] --
/// what every single-chain spend-read test uses.
fn factory_state_with_control_plane_and_spend(
    default_period: Period,
) -> (
    Arc<SharedFactoryState>,
    Arc<arc_swap::ArcSwap<proxy_filters::control::ControlPlaneSnapshot>>,
    Arc<proxy_filters::spend::SpendAccumulator>,
) {
    let (factory_state, handle) = factory_state_with_control_plane();
    let accumulator = register_spend_accumulator(
        &factory_state,
        TEST_CHAIN_SCOPE,
        TEST_CHAIN_STAT_PREFIX,
        default_period,
    );
    (factory_state, handle, accumulator)
}

/// The single chain scope every `factory_state_with_control_plane` test
/// registers into -- arbitrary, standing in for `build_hcm_handler`'s own
/// `context` string; only the ambiguity/scoped-addressing tests below
/// register a SECOND, different scope.
const TEST_CHAIN_SCOPE: &str = "listener 'test' filter_chains[0]";

/// The `stat_prefix` matching [`TEST_CHAIN_SCOPE`]'s registration -- WP-50
/// 3c-ii-a's external name for the same chain.
const TEST_CHAIN_STAT_PREFIX: &str = "test-chain";

/// A [`VirtualKeyAuthenticator`] over `handle`, built with the same
/// [`TEST_HMAC_SECRET`] every test's [`ControlPlane`] uses -- what every
/// mint/revoke test uses to prove a write actually reached the published
/// snapshot, the same way `crate::control`'s own tests do.
fn test_authenticator(
    handle: Arc<arc_swap::ArcSwap<proxy_filters::control::ControlPlaneSnapshot>>,
) -> VirtualKeyAuthenticator {
    VirtualKeyAuthenticator::new(HmacSecret::new(TEST_HMAC_SECRET), handle)
}

fn headers_with_bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        hyper::header::AUTHORIZATION,
        hyper::header::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers
}

/// A hyper/1 client request carrying a body and an optional bearer token --
/// the write-API counterpart of [`get`]/[`get_with_content_type`]. Returns
/// (status, response headers, body).
async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: &str,
) -> (StatusCode, HeaderMap, String) {
    let stream = TcpStream::connect(addr).await.expect("connect");
    let io = TokioIo::new(stream);
    let (mut sender, conn) = client_http1::handshake(io).await.expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost")
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let req = builder
        .body(Full::<Bytes>::from(body.as_bytes().to_vec()))
        .unwrap();
    let resp = sender.send_request(req).await.expect("send_request");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body_bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        headers,
        String::from_utf8(body_bytes.to_vec()).expect("utf8 body"),
    )
}

/// A minimal hyper/1 client request over a fresh connection -- returns
/// (status, body).
async fn get(addr: SocketAddr, path: &str) -> (StatusCode, String) {
    let (status, _content_type, body) = get_with_content_type(addr, path).await;
    (status, body)
}

/// [`get`], but also returns the response's `content-type` header (empty
/// string if absent) -- what the `/stats/prometheus` tests need to pin the
/// exposition-format content type.
async fn get_with_content_type(addr: SocketAddr, path: &str) -> (StatusCode, String, String) {
    let stream = TcpStream::connect(addr).await.expect("connect");
    let io = TokioIo::new(stream);
    let (mut sender, conn) = client_http1::handshake(io).await.expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", "localhost")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.expect("send_request");
    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().expect("ascii header value").to_string())
        .unwrap_or_default();
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        content_type,
        String::from_utf8(body.to_vec()).expect("utf8 body"),
    )
}

#[tokio::test]
async fn ready_returns_live() {
    let (_server, addr) = start(snapshot_with_secret()).await;
    let (status, body) = get(addr, "/ready").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "LIVE");
}

/// WP-21 increment 3: no probe wired keeps the pre-existing behavior --
/// `200 "LIVE"` -- rather than inventing a new failure mode for a caller
/// (like [`start`]/[`ready_returns_live`] above) that never had a
/// `ClusterManager` to ask. This test asserts the SAME thing via the
/// explicit-`None` path through [`start_full`] instead of [`start`], so a
/// future change to [`start`]'s defaults can't silently stop covering it.
#[tokio::test]
async fn ready_with_no_probe_wired_stays_live() {
    let (_server, addr) = start_full_with_readiness(
        snapshot_with_secret(),
        None,
        Arc::new(SharedFactoryState::default()),
        None,
        None,
    )
    .await;
    let (status, body) = get(addr, "/ready").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "LIVE");
}

#[tokio::test]
async fn ready_reports_live_when_the_probe_says_so() {
    let probe: ReadinessProbe = Arc::new(|| Readiness::Live);
    let (_server, addr) = start_with_readiness(snapshot_with_secret(), probe).await;
    let (status, body) = get(addr, "/ready").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "LIVE");
}

#[tokio::test]
async fn ready_returns_503_initializing_when_the_probe_says_so() {
    let probe: ReadinessProbe = Arc::new(|| Readiness::Initializing {
        warming: vec!["still-warming".to_string()],
    });
    let (_server, addr) = start_with_readiness(snapshot_with_secret(), probe).await;
    let (status, body) = get(addr, "/ready").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, "INITIALIZING");
}

#[tokio::test]
async fn config_dump_is_valid_json() {
    let (_server, addr) = start(snapshot_with_secret()).await;
    let (status, body) = get(addr, "/config_dump").await;
    assert_eq!(status, StatusCode::OK);
    let _: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
}

/// The important one: the sentinel API key must never appear anywhere in
/// `/config_dump`, while the header name it was injected under does.
#[tokio::test]
async fn config_dump_redacts_the_api_key() {
    let (_server, addr) = start(snapshot_with_secret()).await;
    let (status, body) = get(addr, "/config_dump").await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        !body.contains(SENTINEL_API_KEY),
        "the raw API key leaked into /config_dump: {body}"
    );
    assert!(
        !body.contains("Bearer "),
        "the header value leaked (even without the key) into /config_dump: {body}"
    );
    assert!(
        body.contains("authorization"),
        "the header NAME should still be visible so an operator can debug auth: {body}"
    );
    assert!(
        body.contains("[redacted]"),
        "expected the redaction marker in /config_dump: {body}"
    );
}

#[tokio::test]
async fn clusters_lists_name_endpoints_and_discovery_type() {
    let (_server, addr) = start(snapshot_with_secret()).await;
    let (status, body) = get(addr, "/clusters").await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let clusters = value.as_array().expect("array");
    assert_eq!(clusters.len(), 1);
    let cluster = &clusters[0];
    assert_eq!(cluster["name"], "upstream");
    assert_eq!(cluster["discovery"], "STATIC");
    let endpoints = cluster["endpoints"].as_array().expect("endpoints array");
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0]["host"], "10.0.0.5");
    assert_eq!(endpoints[0]["port"], 8080);
}

/// `/clusters` is a runtime endpoint view, not a second spelling of the
/// snapshot's configured `EndpointIR`s. In particular, a DNS/EDS IP can be
/// present even when no literal endpoint was declared in the snapshot.
#[tokio::test]
async fn clusters_renders_live_hosts_with_safe_endpoint_fields() {
    let live: ClusterStateProvider = Arc::new(|_snapshot| {
        vec![LiveCluster {
            name: "upstream".to_string(),
            initialized: true,
            endpoints: vec![LiveEndpoint {
                host: "192.0.2.44".to_string(),
                port: 9443,
                hostname: Some("inference.internal".to_string()),
                weight: 7,
                priority: 2,
                health_flags: "/failed_outlier_check".to_string(),
                metadata: BTreeMap::from([
                    ("engine".to_string(), "vllm".to_string()),
                    ("node_id".to_string(), "gpu-a7".to_string()),
                ]),
            }],
        }]
    });
    let (_server, addr) = start_with_cluster_state(snapshot_with_secret(), live).await;
    let (status, body) = get(addr, "/clusters").await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let endpoint = &value[0]["endpoints"][0];
    assert_eq!(endpoint["host"], "192.0.2.44");
    assert_eq!(endpoint["port"], 9443);
    assert_eq!(endpoint["hostname"], "inference.internal");
    assert_eq!(endpoint["weight"], 7);
    assert_eq!(endpoint["priority"], 2);
    assert_eq!(endpoint["health_flags"], "/failed_outlier_check");
    assert_eq!(endpoint["metadata"]["node_id"], "gpu-a7");
    assert_eq!(value[0]["initialized"], true);
    assert!(
        !body.contains(SENTINEL_API_KEY),
        "route credentials must not enter the live endpoint allowlist: {body}"
    );
}

/// The provider is queried on every poll. This is the external property that
/// proves a DNS refresh / EDS push is visible without restarting admin or
/// rebuilding its config handle.
#[tokio::test]
async fn clusters_re_reads_live_hosts_on_every_poll() {
    let hosts = Arc::new(Mutex::new(vec![LiveCluster {
        name: "upstream".to_string(),
        initialized: true,
        endpoints: vec![LiveEndpoint {
            host: "192.0.2.10".to_string(),
            port: 443,
            hostname: None,
            weight: 1,
            priority: 0,
            health_flags: String::new(),
            metadata: BTreeMap::new(),
        }],
    }]));
    let state = hosts.clone();
    let live: ClusterStateProvider =
        Arc::new(move |_snapshot| state.lock().expect("test state mutex").clone());
    let (_server, addr) = start_with_cluster_state(snapshot_with_secret(), live).await;

    let (_, first) = get(addr, "/clusters").await;
    assert!(first.contains("192.0.2.10"));
    hosts.lock().expect("test state mutex")[0].endpoints[0].host = "192.0.2.11".to_string();
    let (_, second) = get(addr, "/clusters").await;
    assert!(
        second.contains("192.0.2.11"),
        "updated live host missing: {second}"
    );
    assert!(
        !second.contains("192.0.2.10"),
        "stale host remained: {second}"
    );
}

#[tokio::test]
async fn server_info_reports_version_and_uptime() {
    let (_server, addr) = start(snapshot_with_secret()).await;
    let (status, body) = get(addr, "/server_info").await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert!(value["uptime_seconds"].as_u64().is_some());
}

#[tokio::test]
async fn unknown_path_is_404_and_names_available_endpoints() {
    let (_server, addr) = start(snapshot_with_secret()).await;
    let (status, body) = get(addr, "/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("/ready"));
    assert!(body.contains("/config_dump"));
    assert!(body.contains("/clusters"));
    assert!(body.contains("/server_info"));
}

/// When this admin server instance was never handed a WP-23 stats registry
/// (`start`'s default -- most tests in this file don't care about `/stats`),
/// the route must 404 honestly rather than fabricate an empty `200`: an
/// operator who trusts an empty `/stats` believes there is no traffic. Also
/// pins that this is a documented `404`, not a panic -- reaching this
/// `assert_eq!` at all is already proof the handler didn't panic.
#[tokio::test]
async fn stats_is_404_when_no_registry_is_wired() {
    let (_server, addr) = start(snapshot_with_secret()).await;
    let (status, body) = get(addr, "/stats").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("WP-23"));
}

/// WP-23 increment 3: once a registry *is* wired, `/stats` renders it --
/// `200`, with the Envoy-named, `name: value` body `envoy_render::render`
/// produces.
#[tokio::test]
async fn stats_returns_200_with_the_rendered_body_when_a_registry_is_wired() {
    let control = StatsControl::new(1);
    let h = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
    let registry = control.registry();
    registry.incr(WorkerId(0), h, 7);

    let (_server, addr) = start_with_registry(snapshot_with_secret(), Some(registry)).await;
    let (status, body) = get(addr, "/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "cluster.openai.upstream_rq_total: 7\n");
}

/// The ADR-0005 trap, exercised one more layer out (through a real admin
/// HTTP request, not just a direct `render()` call): the rendered figure
/// must be the SUM across worker shards, not one worker's own figure --
/// a scrape handler that reached for a shard instead of the registry's
/// summed read would pass every test above this one.
#[tokio::test]
async fn stats_body_is_the_summed_value_across_workers() {
    let control = StatsControl::new(2);
    let h = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
    let registry = control.registry();
    registry.incr(WorkerId(0), h, 10);
    registry.incr(WorkerId(1), h, 25);

    let (_server, addr) = start_with_registry(snapshot_with_secret(), Some(registry)).await;
    let (status, body) = get(addr, "/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body, "cluster.openai.upstream_rq_total: 35\n",
        "must be the SUM (35), not either worker's own figure (10 or 25)"
    );
}

/// WP-23 increment 4: same honest-404 rule as `/stats` itself when no
/// registry is wired.
#[tokio::test]
async fn stats_prometheus_is_404_when_no_registry_is_wired() {
    let (_server, addr) = start(snapshot_with_secret()).await;
    let (status, body) = get(addr, "/stats/prometheus").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("WP-23"));
}

/// WP-23 increment 4: once a registry is wired, `/stats/prometheus` renders
/// Prometheus text exposition format with the confirmed `envoy_`-prefixed
/// name, and the response's `content-type` must be exactly
/// `prometheus_render::CONTENT_TYPE` -- tying the two together so they can't
/// drift independently.
#[tokio::test]
async fn stats_prometheus_returns_200_with_content_type_and_rendered_body() {
    let control = StatsControl::new(1);
    let h = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
    let registry = control.registry();
    registry.incr(WorkerId(0), h, 7);

    let (_server, addr) = start_with_registry(snapshot_with_secret(), Some(registry)).await;
    let (status, content_type, body) = get_with_content_type(addr, "/stats/prometheus").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type, prometheus_render::CONTENT_TYPE);
    assert!(
        body.contains("# TYPE envoy_upstream_rq counter\n"),
        "body: {body}"
    );
    assert!(
        body.contains(r#"envoy_upstream_rq{cluster="openai"} 7"#),
        "body: {body}"
    );
}

/// The ADR-0005 trap, one more layer out for the Prometheus route too.
#[tokio::test]
async fn stats_prometheus_body_is_the_summed_value_across_workers() {
    let control = StatsControl::new(2);
    let h = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
    let registry = control.registry();
    registry.incr(WorkerId(0), h, 10);
    registry.incr(WorkerId(1), h, 25);

    let (_server, addr) = start_with_registry(snapshot_with_secret(), Some(registry)).await;
    let (status, body) = get(addr, "/stats/prometheus").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"envoy_upstream_rq{cluster="openai"} 35"#),
        "must be the SUM (35), not either worker's own figure (10 or 25): {body}"
    );
}

/// The mutating endpoints Envoy names (`/quitquitquit`, `/drain_listeners`,
/// `/logging`) are not part of this API at all -- unlike `/keys`/`/tenants`
/// below, they must not accidentally work.
#[tokio::test]
async fn mutating_endpoints_are_404() {
    let (_server, addr) = start(snapshot_with_secret()).await;
    for path in ["/quitquitquit", "/drain_listeners", "/logging"] {
        let (status, _) = get(addr, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "path {path} should 404");
    }
}

// --- WP-50 increment 3b-ii, W4: the admin write API + bearer gate ---------

/// Rule 17: the fail-CLOSED path gets its own test. `LLMPROXY_ADMIN_TOKEN`
/// unset (here: `serve`'s `admin_token` is `None`) must refuse the write
/// with 403 -- and, just as important, must not have minted anything: a
/// gate that logs a refusal but performs the write anyway is not a gate.
#[tokio::test]
async fn post_keys_with_no_admin_token_configured_is_forbidden_and_mints_nothing() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(snapshot_with_secret(), None, factory_state, None).await;

    let (status, _headers, body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"t1","key_id":"k1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body.contains("LLMPROXY_ADMIN_TOKEN"),
        "403 body should name the env var an operator needs to set: {body}"
    );

    // Nothing must have been minted. `KeySet` exposes no public way to name
    // an entry (by design -- see its doc), but its `Debug` impl deliberately
    // publishes only the COUNT ("never a digest"), which is exactly enough
    // to prove the store side of this gate stayed closed.
    let debug = format!("{:?}", handle.load().keys);
    assert!(
        debug.contains("len: 0"),
        "a refused write (no admin token configured) must not mint a key: {debug}"
    );
}

/// Token IS configured, but the request carries no `authorization` header at
/// all -> 401, with the RFC 7235 challenge.
#[tokio::test]
async fn write_without_authorization_header_is_401_with_www_authenticate_challenge() {
    let (factory_state, _handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, headers, _body) = request(
        addr,
        "POST",
        "/keys",
        None,
        r#"{"tenant":"t1","key_id":"k1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers.get(hyper::header::WWW_AUTHENTICATE),
        Some(&hyper::header::HeaderValue::from_static("Bearer")),
        "a 401 must carry the RFC 7235 challenge"
    );
}

/// Token IS configured; the request presents a DIFFERENT token -> 401.
#[tokio::test]
async fn write_with_wrong_token_is_401() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, _body) = request(
        addr,
        "POST",
        "/keys",
        Some("definitely-not-the-configured-token"),
        r#"{"tenant":"t1","key_id":"k1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The status alone would still pass if the gate answered 401 AFTER
    // performing the write. Same reasoning as the fail-closed test above:
    // assert the store stayed untouched, not just that the caller was told
    // "no".
    let debug = format!("{:?}", handle.load().keys);
    assert!(
        debug.contains("len: 0"),
        "a write refused for a wrong bearer token must not mint a key: {debug}"
    );
}

/// Token is configured and correct, but nothing has been registered into the
/// shared factory state yet (the boot-race / no-auth-filter case) -> 503.
#[tokio::test]
async fn write_with_correct_token_but_no_control_plane_registered_is_503() {
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        Arc::new(SharedFactoryState::default()),
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, _body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"t1","key_id":"k1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// Token is configured and correct, and a `ControlPlane` IS registered --
/// under TWO different chain scopes, standing in for two listeners that each
/// configure `llmproxy.auth`. The admin API has no chain of its own to
/// disambiguate by, so this must be a loud, explicit error naming the
/// ambiguity, never a silent pick of one of the two -- see
/// `resolve_control_plane`'s doc for why guessing here is exactly the class
/// of bug this task exists to close.
#[tokio::test]
async fn write_with_two_registered_control_planes_is_an_explicit_error_not_a_guess() {
    let factory_state = Arc::new(SharedFactoryState::default());
    register_control_plane(
        &factory_state,
        "listener 'a' filter_chains[0]",
        "chain-a",
        b"scope-a-secret",
    );
    register_control_plane(
        &factory_state,
        "listener 'b' filter_chains[0]",
        "chain-b",
        b"scope-b-secret",
    );

    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"t1","key_id":"k1"}"#,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "two llmproxy.auth-configured chains must be an explicit error, not the 503 the \
         genuinely-not-ready case gets and not a 2xx that silently wrote into one of them"
    );
    assert!(
        body.contains("listener 'a' filter_chains[0]")
            && body.contains("listener 'b' filter_chains[0]"),
        "the error must name every ambiguous scope, not just say \"ambiguous\": {body}"
    );
}

/// **WP-50 3c-ii-a's centrepiece.** Two chains, distinct `stat_prefix`es,
/// each with its OWN `ControlPlane` -- exactly the shape `resolve_control_plane`
/// (the unscoped path) refuses to guess between. Minting through
/// `/chains/chain-a/keys` must land in chain a's `ControlPlane` and be
/// invisible to chain b's: this is the property `get_by_name` exists to
/// give the admin server, as opposed to `get_across_scopes`, which cannot
/// tell the two apart at all.
#[tokio::test]
async fn scoped_write_lands_in_the_named_chains_control_plane_and_not_the_others() {
    let factory_state = Arc::new(SharedFactoryState::default());
    let handle_a = register_control_plane(
        &factory_state,
        "listener 'a' filter_chains[0]",
        "chain-a",
        TEST_HMAC_SECRET,
    );
    let handle_b = register_control_plane(
        &factory_state,
        "listener 'b' filter_chains[0]",
        "chain-b",
        TEST_HMAC_SECRET,
    );

    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "POST",
        "/chains/chain-a/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a"}"#,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "scoped mint into chain-a: {body}"
    );
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let plaintext = value["key"].as_str().expect("key field is a string");

    let auth_a = test_authenticator(handle_a);
    match auth_a.authenticate(&headers_with_bearer(plaintext)) {
        AuthOutcome::Authenticated(principal) => {
            assert_eq!(principal.tenant.as_str(), "tenant-a");
        }
        other => panic!(
            "the key minted through /chains/chain-a/keys must authenticate against chain-a's \
             own ControlPlane; got Rejected={} NoCredential={}",
            matches!(other, AuthOutcome::Rejected(_)),
            matches!(other, AuthOutcome::NoCredential)
        ),
    }

    let auth_b = test_authenticator(handle_b);
    assert!(
        !matches!(
            auth_b.authenticate(&headers_with_bearer(plaintext)),
            AuthOutcome::Authenticated(_)
        ),
        "a key minted into chain-a's ControlPlane must NOT authenticate against chain-b's -- \
         a pass here means the scoped write landed in the wrong chain"
    );
}

/// An unknown `stat_prefix` is a 404 naming the segment that matched no
/// registered chain -- never a 503 (this is not a boot race: some chain IS
/// registered, just not the one named) and never a silent fall-through to
/// the unscoped resolution.
#[tokio::test]
async fn scoped_write_with_unknown_stat_prefix_is_404() {
    let factory_state = Arc::new(SharedFactoryState::default());
    register_control_plane(
        &factory_state,
        "listener 'a' filter_chains[0]",
        "chain-a",
        TEST_HMAC_SECRET,
    );

    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "POST",
        "/chains/no-such-chain/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"t1","key_id":"k1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body.contains("no-such-chain"),
        "the 404 must name the unresolved stat_prefix: {body}"
    );
}

/// The mint flow, correctly authorized: 201, a non-empty plaintext `key`
/// returned exactly once, and the key actually authenticates through the
/// `ControlPlane`'s published snapshot afterward.
#[tokio::test]
async fn post_keys_mints_a_key_that_authenticates_and_returns_plaintext_once() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["key_id"], "key-a");
    assert_eq!(value["tenant"], "tenant-a");
    let plaintext = value["key"].as_str().expect("key field is a string");
    assert!(!plaintext.is_empty(), "the minted key must not be empty");

    let authenticator = test_authenticator(handle);
    let headers = headers_with_bearer(plaintext);
    match authenticator.authenticate(&headers) {
        AuthOutcome::Authenticated(principal) => {
            assert_eq!(principal.tenant.as_str(), "tenant-a");
            assert_eq!(principal.key_id.as_str(), "key-a");
        }
        other => panic!(
            "the minted key must authenticate against the published snapshot; got \
             Rejected={} NoCredential={}",
            matches!(other, AuthOutcome::Rejected(_)),
            matches!(other, AuthOutcome::NoCredential)
        ),
    }
}

/// The important one, same shape as `config_dump_redacts_the_api_key` above:
/// a minted plaintext key must never leak back out through a READ endpoint.
#[tokio::test]
async fn config_dump_and_clusters_never_leak_a_minted_plaintext_key() {
    let (factory_state, _handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let plaintext = value["key"].as_str().unwrap().to_string();

    for path in ["/config_dump", "/clusters"] {
        let (status, body) = get(addr, path).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !body.contains(&plaintext),
            "the minted plaintext key leaked into {path}: {body}"
        );
    }
}

/// `DELETE /keys/{id}` -> 204, and the revoked key stops authenticating
/// through the republished snapshot.
#[tokio::test]
async fn delete_keys_revokes_and_snapshot_reflects_it() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let plaintext = value["key"].as_str().unwrap().to_string();

    let authenticator = test_authenticator(handle);
    let headers = headers_with_bearer(&plaintext);
    assert!(matches!(
        authenticator.authenticate(&headers),
        AuthOutcome::Authenticated(_)
    ));

    let (status, _headers, _body) =
        request(addr, "DELETE", "/keys/key-a", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    match authenticator.authenticate(&headers) {
        AuthOutcome::Rejected(AuthError::RevokedKey) => {}
        other => panic!(
            "a revoked key must be rejected after republish; got Authenticated={}",
            matches!(other, AuthOutcome::Authenticated(_))
        ),
    }
}

/// `POST /tenants` -> 201, `DELETE /tenants/{id}` -> 204. `ControlPlaneSnapshot`
/// itself carries no tenant list (see `proxy_filters::control`'s own tests
/// for the same limitation, from inside that crate) -- a policy attached to
/// the tenant is the one per-tenant fact the published snapshot does expose,
/// so it stands in here as the observable signal that both writes actually
/// reached the store and were republished.
#[tokio::test]
async fn post_and_delete_tenants_are_reflected_in_the_snapshot() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "POST",
        "/tenants",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-x"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["tenant"], "tenant-x");

    let (status, _headers, _body) = request(
        addr,
        "PUT",
        "/tenants/tenant-x/policy",
        Some(ADMIN_TOKEN),
        r#"{"access":"all"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        handle.load().policies.contains_key("tenant-x"),
        "the policy PUT right after tenant creation must be visible in the snapshot"
    );

    let (status, _headers, _body) =
        request(addr, "DELETE", "/tenants/tenant-x", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        !handle.load().policies.contains_key("tenant-x"),
        "delete_tenant must remove the tenant's policy from the republished snapshot too"
    );
}

/// `PUT /tenants/{id}/policy` with both `"all"` and `{"only": [...]}`, plus
/// the load-bearing case: an EMPTY `only: []` must stay `Only(vec![])`, not
/// collapse to `All` -- see `ModelAccess`'s own doc for why that would be a
/// silent privilege escalation. Mutation pin C targets this assertion.
#[tokio::test]
async fn put_policy_all_and_only_are_reflected_and_empty_only_stays_only() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, _body) = request(
        addr,
        "PUT",
        "/tenants/tenant-all/policy",
        Some(ADMIN_TOKEN),
        r#"{"access":"all"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        handle
            .load()
            .policies
            .get("tenant-all")
            .unwrap()
            .model_access,
        ModelAccess::All
    );

    let (status, _headers, _body) = request(
        addr,
        "PUT",
        "/tenants/tenant-only/policy",
        Some(ADMIN_TOKEN),
        r#"{"access":{"only":["gpt-4*"]}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        handle
            .load()
            .policies
            .get("tenant-only")
            .unwrap()
            .model_access,
        ModelAccess::Only(vec![proxy_filters::model_authz::ModelPattern::new(
            "gpt-4*"
        )])
    );

    let (status, _headers, _body) = request(
        addr,
        "PUT",
        "/tenants/tenant-empty/policy",
        Some(ADMIN_TOKEN),
        r#"{"access":{"only":[]}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        handle
            .load()
            .policies
            .get("tenant-empty")
            .unwrap()
            .model_access,
        ModelAccess::Only(vec![]),
        "an empty `only: []` must deny every model (Only(vec![])), NOT collapse to All"
    );
}

// --- PUT /tenants/{id}/budget (WP-50 increment 3c-iii-a) --------------------

/// Sets a budget, reads it back through the published snapshot, then clears
/// it (`{"budget": null}`) and confirms it is gone -- the round trip for
/// both directions of the endpoint's one request shape.
#[tokio::test]
async fn put_budget_sets_reads_back_and_clears() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":{"max_usd":"500.00","period":"monthly"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "set: {body}");

    let budget = handle
        .load()
        .policies
        .get("tenant-a")
        .and_then(|p| p.budget)
        .expect("the budget PUT must be visible in the republished snapshot");
    assert_eq!(budget.max_micros, MicroUsd::from_micros(500_000_000));
    assert_eq!(budget.period, Period::Monthly);

    let (status, _headers, body) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":null}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "clear: {body}");
    assert!(
        handle
            .load()
            .policies
            .get("tenant-a")
            .and_then(|p| p.budget)
            .is_none(),
        "{{\"budget\": null}} must clear the tenant's budget"
    );
}

/// Setting a budget must not clobber an already-set model-access policy for
/// the same tenant, and vice versa -- both directions, exercised through the
/// real HTTP endpoints rather than `ControlPlane` directly.
#[tokio::test]
async fn put_budget_and_put_policy_do_not_clobber_each_other() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, _body) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/policy",
        Some(ADMIN_TOKEN),
        r#"{"access":{"only":["gpt-4*"]}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _headers, _body) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":{"max_usd":"10.00","period":"daily"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let policy = handle
        .load()
        .policies
        .get("tenant-a")
        .expect("tenant must exist")
        .clone();
    assert_eq!(
        policy.model_access,
        ModelAccess::Only(vec![proxy_filters::model_authz::ModelPattern::new(
            "gpt-4*"
        )]),
        "PUT .../budget must not clobber the tenant's already-set policy"
    );
    assert!(policy.budget.is_some());
}

/// A malformed `max_usd` (not a valid decimal `parse_micro_usd` accepts) is a
/// 400 naming the problem, never a silently-truncated or silently-zeroed
/// budget.
#[tokio::test]
async fn put_budget_with_a_malformed_max_usd_is_400() {
    let (factory_state, _handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":{"max_usd":"not-a-number","period":"daily"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// The scoped form lands in the named chain's `ControlPlane` and not
/// another's -- same shape as `scoped_write_lands_in_the_named_chains_control_plane_and_not_the_others`,
/// restated for the budget endpoint.
#[tokio::test]
async fn scoped_put_budget_lands_in_the_named_chains_control_plane_and_not_the_others() {
    let factory_state = Arc::new(SharedFactoryState::default());
    let handle_a = register_control_plane(
        &factory_state,
        "listener 'a' filter_chains[0]",
        "chain-a",
        TEST_HMAC_SECRET,
    );
    let handle_b = register_control_plane(
        &factory_state,
        "listener 'b' filter_chains[0]",
        "chain-b",
        TEST_HMAC_SECRET,
    );

    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "PUT",
        "/chains/chain-a/tenants/tenant-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":{"max_usd":"1.00","period":"daily"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    assert!(
        handle_a
            .load()
            .policies
            .get("tenant-a")
            .and_then(|p| p.budget)
            .is_some(),
        "the scoped budget write must land in chain-a's own ControlPlane"
    );
    assert!(
        handle_b
            .load()
            .policies
            .get("tenant-a")
            .and_then(|p| p.budget)
            .is_none(),
        "a budget set through /chains/chain-a/... must NOT appear in chain-b's ControlPlane"
    );
}

/// An unknown `stat_prefix` is a 404 naming the segment, matching every
/// other scoped write endpoint.
#[tokio::test]
async fn scoped_put_budget_with_unknown_stat_prefix_is_404() {
    let factory_state = Arc::new(SharedFactoryState::default());
    register_control_plane(
        &factory_state,
        "listener 'a' filter_chains[0]",
        "chain-a",
        TEST_HMAC_SECRET,
    );

    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "PUT",
        "/chains/no-such-chain/tenants/tenant-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":{"max_usd":"1.00","period":"daily"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body.contains("no-such-chain"),
        "the 404 must name the unresolved stat_prefix: {body}"
    );
}

// --- GET /tenants/{id}/spend (WP-50 increment 3c-iv) ------------------------
//
// A READ, gated exactly like a write -- see `lib.rs`'s module doc for why.
// These tests exercise the SAME three gates the write-API tests above do,
// restated for this endpoint, plus its own two-singleton resolution and
// response shape.

/// Unit test for the rendering helper itself: `spend_usd` must render EXACTLY
/// from the integer, including a value whose fractional part has leading
/// zeros a naive divide-and-cast would drop.
#[test]
fn render_micro_usd_renders_exactly_from_the_integer() {
    use crate::server::render_micro_usd;
    assert_eq!(render_micro_usd(0), "0.000000");
    assert_eq!(
        render_micro_usd(1_234),
        "0.001234",
        "leading zeros after the decimal point must survive"
    );
    assert_eq!(render_micro_usd(1_000_000), "1.000000");
    assert_eq!(render_micro_usd(500_000_000), "500.000000");
    assert_eq!(render_micro_usd(1_000_001), "1.000001");
}

/// No admin token configured -> 403, exactly like every write endpoint --
/// this is a GET, but it renders per-tenant financial data, so it is gated
/// like a write (see `lib.rs`'s module doc). Pinned by mutation Pin A (skip
/// the bearer gate for the spend read).
#[tokio::test]
async fn spend_read_with_no_admin_token_configured_is_forbidden() {
    let (factory_state, _handle, _accumulator) =
        factory_state_with_control_plane_and_spend(Period::Monthly);
    let (_server, addr) = start_full(snapshot_with_secret(), None, factory_state, None).await;

    let (status, body) = get(addr, "/tenants/tenant-a/spend").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the spend read must be refused exactly like a write when no token is configured: \
         {body}"
    );
}

/// A wrong bearer token -> 401, matching every write endpoint's gate.
#[tokio::test]
async fn spend_read_with_wrong_token_is_401() {
    let (factory_state, _handle, _accumulator) =
        factory_state_with_control_plane_and_spend(Period::Monthly);
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "GET",
        "/tenants/tenant-a/spend",
        Some("definitely-not-the-configured-token"),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

/// A `ControlPlane` IS registered, but no `llmproxy.spend_limit` accumulator
/// is -- 503, naming the missing filter, matching the shape of the existing
/// missing-`ControlPlane` 503 elsewhere in this file (never a fourth status
/// code for "half configured").
#[tokio::test]
async fn spend_read_with_no_accumulator_registered_is_503() {
    let (factory_state, _handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "GET",
        "/tenants/tenant-a/spend",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(
        body.contains("llmproxy.spend_limit"),
        "the 503 must name what's missing: {body}"
    );
}

/// A tenant that has never spent reports zeros, not an error -- an operator
/// asking about a tenant that hasn't made a request yet gets a valid, boring
/// answer.
#[tokio::test]
async fn spend_read_on_a_tenant_that_never_spent_is_zeros_not_an_error() {
    let (factory_state, _handle, _accumulator) =
        factory_state_with_control_plane_and_spend(Period::Monthly);
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "GET",
        "/tenants/tenant-never-spent/spend",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["spend_micro_usd"], 0);
    assert_eq!(value["spend_usd"], "0.000000");
    assert_eq!(value["unpriced_requests"], 0);
    assert_eq!(value["budget_micro_usd"], serde_json::Value::Null);
    assert_eq!(value["remaining_micro_usd"], serde_json::Value::Null);
}

/// The spend read carries this replica's reconciliation state (WP-62,
/// ADR-0006 §5). Filters hold no handle to the stats registry, so this
/// endpoint IS the surface for `spend_reconciliation_age_seconds` and the
/// count of admissions made while stale -- if these keys are missing, the
/// numbers exist nowhere an operator can reach them, and a spend figure
/// read during a store outage looks exactly like a healthy one.
///
/// Pinned by mutation: delete the three keys from the `json!` body.
#[tokio::test]
async fn spend_read_reports_the_replicas_reconciliation_state() {
    let (factory_state, _handle, _accumulator) =
        factory_state_with_control_plane_and_spend(Period::Monthly);
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "GET",
        "/tenants/tenant-a/spend",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    // A fresh accumulator inside the default 60-second bound: not expired,
    // nothing admitted while stale. The point of the assertion is that the
    // keys are PRESENT and typed, which `is_number`/`is_boolean` say and a
    // missing key (rendering as JSON null) does not.
    assert!(
        value["reconciliation_age_seconds"].is_number(),
        "the age must be reported as a number, not omitted: {body}"
    );
    assert_eq!(
        value["reconciliation_expired"],
        serde_json::Value::Bool(false)
    );
    assert_eq!(value["unreconciled_admissions"], 0);
}

/// A tenant with no configured budget is unlimited: `budget_micro_usd` and
/// `remaining_micro_usd` render `null`, never a fabricated ceiling, even
/// though the tenant HAS spent something.
#[tokio::test]
async fn spend_read_on_an_unlimited_tenant_has_null_budget_fields() {
    let (factory_state, _handle, accumulator) =
        factory_state_with_control_plane_and_spend(Period::Monthly);
    accumulator.record_now(
        &TenantId::new("tenant-a"),
        Period::Monthly,
        Charge::Priced(MicroUsd::from_micros(4_200)),
        Some("cluster-a"),
        Some("m"),
    );
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "GET",
        "/tenants/tenant-a/spend",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["spend_micro_usd"], 4_200);
    assert_eq!(value["budget_micro_usd"], serde_json::Value::Null);
    assert_eq!(value["remaining_micro_usd"], serde_json::Value::Null);
}

/// A budgeted tenant reports the correct `remaining_micro_usd`, and it
/// SATURATES at zero rather than wrapping once spend exceeds the budget --
/// the check/record split (`spend_limit_filter`'s own module doc) means the
/// request that crosses a ceiling is always admitted, so live spend CAN
/// legitimately exceed the configured budget. Pinned by mutation Pin B
/// (`remaining` computed by wrapping subtraction instead of saturating).
#[tokio::test]
async fn spend_read_on_a_budgeted_tenant_reports_remaining_and_saturates_at_zero() {
    let (factory_state, _handle, accumulator) =
        factory_state_with_control_plane_and_spend(Period::Monthly);
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":{"max_usd":"10.00","period":"monthly"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Under budget: $4 of $10.
    accumulator.record_now(
        &TenantId::new("tenant-a"),
        Period::Monthly,
        Charge::Priced(MicroUsd::from_micros(4_000_000)),
        Some("cluster-a"),
        Some("m"),
    );
    let (status, _headers, body) = request(
        addr,
        "GET",
        "/tenants/tenant-a/spend",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["budget_micro_usd"], 10_000_000);
    assert_eq!(value["remaining_micro_usd"], 6_000_000);

    // Push spend PAST the budget -- remaining must saturate at 0, never wrap
    // around to a huge positive number.
    accumulator.record_now(
        &TenantId::new("tenant-a"),
        Period::Monthly,
        Charge::Priced(MicroUsd::from_micros(20_000_000)),
        Some("cluster-a"),
        Some("m"),
    );
    let (status, _headers, body) = request(
        addr,
        "GET",
        "/tenants/tenant-a/spend",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["spend_micro_usd"], 24_000_000);
    assert_eq!(
        value["remaining_micro_usd"], 0,
        "remaining must saturate at zero, not wrap, once spend exceeds the budget: {value}"
    );
}

/// Unpriced requests are reported: the count AND the distinct `(cluster,
/// model)` pairs -- the design brief's discoverability requirement (an
/// unconfigured price costs zero, but the gap must stay visible).
#[tokio::test]
async fn spend_read_reports_unpriced_requests_and_pairs() {
    let (factory_state, _handle, accumulator) =
        factory_state_with_control_plane_and_spend(Period::Monthly);
    accumulator.record_now(
        &TenantId::new("tenant-a"),
        Period::Monthly,
        Charge::Unpriced,
        Some("cluster-a"),
        Some("some-model"),
    );
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "GET",
        "/tenants/tenant-a/spend",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["unpriced_requests"], 1);
    assert_eq!(
        value["unpriced_pairs"],
        serde_json::json!([["cluster-a", "some-model"]])
    );
    assert_eq!(value["unpriced_pairs_truncated"], false);
}

/// The scoped form returns the NAMED chain's spend and not another chain's --
/// mirrors `scoped_put_budget_lands_in_the_named_chains_control_plane_and_not_the_others`,
/// restated for the spend read.
#[tokio::test]
async fn scoped_spend_read_returns_the_named_chains_spend_and_not_the_others() {
    let factory_state = Arc::new(SharedFactoryState::default());
    register_control_plane(
        &factory_state,
        "listener 'a' filter_chains[0]",
        "chain-a",
        TEST_HMAC_SECRET,
    );
    register_control_plane(
        &factory_state,
        "listener 'b' filter_chains[0]",
        "chain-b",
        TEST_HMAC_SECRET,
    );
    let accumulator_a = register_spend_accumulator(
        &factory_state,
        "listener 'a' filter_chains[0]",
        "chain-a",
        Period::Monthly,
    );
    let accumulator_b = register_spend_accumulator(
        &factory_state,
        "listener 'b' filter_chains[0]",
        "chain-b",
        Period::Monthly,
    );
    accumulator_a.record_now(
        &TenantId::new("tenant-a"),
        Period::Monthly,
        Charge::Priced(MicroUsd::from_micros(1_000_000)),
        Some("cluster-a"),
        Some("m"),
    );
    accumulator_b.record_now(
        &TenantId::new("tenant-a"),
        Period::Monthly,
        Charge::Priced(MicroUsd::from_micros(9_000_000)),
        Some("cluster-a"),
        Some("m"),
    );

    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "GET",
        "/chains/chain-a/tenants/tenant-a/spend",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(
        value["spend_micro_usd"], 1_000_000,
        "the scoped read must return chain-a's own spend, not chain-b's: {value}"
    );
}

/// An unknown `stat_prefix` is a 404, matching every other scoped endpoint --
/// the `ControlPlane` gate (shared with every write route) refuses before
/// this endpoint's own accumulator resolution is ever reached.
#[tokio::test]
async fn scoped_spend_read_with_unknown_stat_prefix_is_404() {
    let factory_state = Arc::new(SharedFactoryState::default());
    register_control_plane(
        &factory_state,
        "listener 'a' filter_chains[0]",
        "chain-a",
        TEST_HMAC_SECRET,
    );
    register_spend_accumulator(
        &factory_state,
        "listener 'a' filter_chains[0]",
        "chain-a",
        Period::Monthly,
    );

    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(
        addr,
        "GET",
        "/chains/no-such-chain/tenants/tenant-a/spend",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body.contains("no-such-chain"),
        "the 404 must name the unresolved stat_prefix: {body}"
    );
}

/// READ endpoints stay unaffected by the write API's gate: with NO admin
/// token configured at all, `/ready` and `/config_dump` behave exactly as
/// the read-only increment's own tests already prove.
#[tokio::test]
async fn reads_work_with_no_admin_token_configured() {
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        Arc::new(SharedFactoryState::default()),
        None,
    )
    .await;

    let (status, body) = get(addr, "/ready").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "LIVE");

    let (status, body) = get(addr, "/config_dump").await;
    assert_eq!(status, StatusCode::OK);
    let _: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
}

/// Malformed JSON, an unknown field, and a missing/empty required string all
/// answer 400, matching ground rule #1 (a silently ignored field is a P0 in
/// a security-write API too).
#[tokio::test]
async fn bad_bodies_are_400() {
    let (factory_state, _handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, _body) =
        request(addr, "POST", "/keys", Some(ADMIN_TOKEN), "not json at all").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "malformed JSON");

    let (status, _headers, _body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"t1","key_id":"k1","unexpected_field":"x"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown field");

    let (status, _headers, _body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"key_id":"k1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "missing tenant");

    let (status, _headers, _body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"","key_id":"k1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "empty tenant");
}

/// A body over the admin write cap (`MAX_ADMIN_BODY_BYTES`, 64 KiB) must 413
/// rather than being buffered without bound.
#[tokio::test]
async fn oversized_body_is_413() {
    let (factory_state, _handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let oversized = "x".repeat(70 * 1024);
    let (status, _headers, _body) =
        request(addr, "POST", "/keys", Some(ADMIN_TOKEN), &oversized).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

/// A wrong method on a recognized write path (`/keys` only accepts `POST`)
/// answers 405, not the generic 404 an unknown path gets.
#[tokio::test]
async fn wrong_method_on_write_path_is_405() {
    let (factory_state, _handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _body) = get(addr, "/keys").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}
