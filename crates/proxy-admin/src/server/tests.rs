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
    HeaderMatch, HeaderMatchKind, HeaderMutation, HttpConnectionManagerConfig, HttpFilterSpec,
    LbPolicy, ListenerConfig, NetworkFilterSpec, PathMatch, RouteActionIR, RouteEntry,
    RouteMatcher, RouteTable, SnapshotVersion, UpstreamProtocol, VirtualHostIR,
};
use proxy_core::lifecycle::LifecycleState;
use proxy_core::runtime::SnapshotHandles;
use proxy_filters::auth::{
    AuthError, AuthOutcome, Authenticator, HmacSecret, KeyId, KeySet, TenantId,
    VirtualKeyAuthenticator,
};
use proxy_filters::auth_filter;
use proxy_filters::body_rewrite_filter::MODEL_HEADER_NAME;
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
    serve, AdminRuntime, AdminServer, ClusterStateProvider, Readiness, ReadinessProbe, UiAssets,
};

async fn mint_policy_test_key(addr: SocketAddr) {
    let (status, _, body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn put_key_policy_updates_snapshot_and_key_listing() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    mint_policy_test_key(addr).await;
    let (status, _, body) = request(
        addr,
        "PUT",
        "/keys/key-a/policy",
        Some(ADMIN_TOKEN),
        r#"{"access":{"only":["gpt-4*"]},"deny":["gpt-4-old"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let access = handle.load().key_policies[&KeyId::new("key-a")].clone();
    assert!(access.permits("gpt-4o"));
    assert!(!access.permits("gpt-4-old"));
    let (status, _, body) = request(addr, "GET", "/keys", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        value["keys"][0]["policy"],
        serde_json::json!({"access":{"only":["gpt-4*"]},"deny":["gpt-4-old"]})
    );
}

#[tokio::test]
async fn put_key_policy_unknown_key_is_404_and_stores_nothing() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    let (status, _, _) = request(
        addr,
        "PUT",
        "/keys/missing/policy",
        Some(ADMIN_TOKEN),
        r#"{"access":"all"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(handle.load().key_policies.is_empty());
}

#[tokio::test]
async fn scoped_put_key_policy_updates_named_chain() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    mint_policy_test_key(addr).await;
    let (status, _, body) = request(
        addr,
        "PUT",
        "/chains/test-chain/keys/key-a/policy",
        Some(ADMIN_TOKEN),
        r#"{"access":{"only":["gpt-4*"]}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(handle
        .load()
        .key_policies
        .contains_key(&KeyId::new("key-a")));
    let (status, _, body) = request(
        addr,
        "GET",
        "/chains/test-chain/keys",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        value["keys"][0]["policy"],
        serde_json::json!({"access":{"only":["gpt-4*"]}})
    );
}

#[tokio::test]
async fn put_key_policy_without_model_authz_is_409_and_stores_nothing() {
    let factory_state = Arc::new(SharedFactoryState::default());
    let handle = register_control_plane(
        &factory_state,
        TEST_CHAIN_SCOPE,
        TEST_CHAIN_STAT_PREFIX,
        TEST_HMAC_SECRET,
    );
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    mint_policy_test_key(addr).await;
    let (status, _, body) = request(
        addr,
        "PUT",
        "/keys/key-a/policy",
        Some(ADMIN_TOKEN),
        r#"{"access":"all"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
        "not_enforced"
    );
    assert!(handle.load().key_policies.is_empty());
}

#[tokio::test]
async fn put_key_policy_all_lists_as_inherit_equivalent_all() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    mint_policy_test_key(addr).await;
    let (status, _, body) = request(
        addr,
        "PUT",
        "/keys/key-a/policy",
        Some(ADMIN_TOKEN),
        r#"{"access":"all"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        handle.load().key_policies[&KeyId::new("key-a")],
        ModelAccess::All
    );
    let (status, _, body) = request(addr, "GET", "/keys", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        value["keys"][0]["policy"],
        serde_json::json!({"access":"all"})
    );
}

#[tokio::test]
async fn put_key_policy_invalid_pattern_is_400_and_stores_nothing() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    mint_policy_test_key(addr).await;
    let (status, _, _) = request(
        addr,
        "PUT",
        "/keys/key-a/policy",
        Some(ADMIN_TOKEN),
        r#"{"access":{"only":["gpt-*-bad"]}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(handle.load().key_policies.is_empty());
}

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
            ext_authz: None,
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
        request_headers_timeout: None,
        request_timeout: None,
        stream_idle_timeout: None,
        max_stream_duration: None,
    };

    let listener = ListenerConfig {
        name: "listener_0".to_string(),
        address: "127.0.0.1:0".parse().unwrap(),
        filter_chains: vec![FilterChainSpec {
            transport_socket_connect_timeout: None,
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
        ignore_global_conn_limit: false,
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
        request_path_rewrite: None,
        provider_runtime: None,
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
        // Metric export is a separate IR field from trace
        // export precisely so the two are independently configurable; these
        // admin-server fixtures exercise neither, and a snapshot literal is
        // exhaustive by design, so a new root field has to be named here. This
        // is the same hazard `ir.rs`'s `with_dynamic_resources` doc describes
        // from the other side: the compile error is the cheap half, and
        // `tests/ir_readership.rs` is what would have caught a field that was
        // named here but never read.
        metrics: None,
        #[cfg(unix)]
        end_user_capture: None,
        end_user_capture_configured: false,
        ledger: None,
        traces: None,
        // This fixture is a static-config snapshot, which
        // is what `None` means -- no control plane is involved.
        ads: None,
        max_downstream_connections: None,
        version: SnapshotVersion(1),
    })
}

/// A snapshot built ONLY for `GET /models`: one listener whose HCM inlines a
/// route table of [`MODEL_HEADER_NAME`] matchers, plus one RDS-delivered
/// table -- the two route sources `dump::models_from_snapshot` walks -- and
/// one path-only route that must NOT be reported (it serves every model and
/// names none, so reporting an entry for it would invent a model the config
/// never mentioned).
///
/// Deliberately cluster-free: nothing `/models` reads touches clusters, and a
/// fixture carrying them would imply the endpoint reports on them when it
/// does not.
fn snapshot_with_model_routes() -> Arc<ConfigSnapshot> {
    fn model_route(
        name: &str,
        kind: Option<HeaderMatchKind>,
        route_index: usize,
    ) -> Arc<RouteEntry> {
        Arc::new(RouteEntry {
            name: Some(name.to_string()),
            matcher: RouteMatcher {
                path: PathMatch::Prefix("/".to_string()),
                case_sensitive: true,
                headers: kind
                    .map(|kind| {
                        vec![HeaderMatch {
                            name: MODEL_HEADER_NAME.to_string(),
                            kind,
                        }]
                    })
                    .unwrap_or_default(),
            },
            action: RouteActionIR::Forward(ForwardAction {
                target: ForwardTarget::Cluster("upstream".to_string()),
                timeout: None,
                idle_timeout: None,
                retry_policy: None,
                host_rewrite_literal: None,
                prefix_rewrite: None,
            }),
            request_headers_to_add: vec![],
            typed_per_filter_config: BTreeMap::new(),
            route_index,
            include_request_attempt_count: false,
            include_attempt_count_in_response: false,
            streaming_strict: false,
        })
    }

    fn table(name: &str, routes: Vec<Arc<RouteEntry>>) -> Arc<RouteTable> {
        Arc::new(
            RouteTable::new(
                name.to_string(),
                vec![VirtualHostIR {
                    name: "default".to_string(),
                    domains: vec!["*".to_string()],
                    routes,
                    typed_per_filter_config: BTreeMap::new(),
                }],
                BTreeMap::new(),
            )
            .expect("one vhost with domain `*` cannot collide"),
        )
    }

    // The HCM-inlined source: an exact model, a prefix model, and a route
    // that matches on the path alone.
    let inlined = table(
        "local_route",
        vec![
            model_route(
                "model-gpt-4o",
                Some(HeaderMatchKind::Exact {
                    value: "gpt-4o".to_string(),
                    ignore_case: false,
                }),
                0,
            ),
            model_route(
                "model-claude",
                Some(HeaderMatchKind::Prefix {
                    value: "claude-3".to_string(),
                    ignore_case: false,
                }),
                1,
            ),
            model_route("chat-completions", None, 2),
        ],
    );
    // The RDS source: one more exact model, so a pass here proves the walk
    // covers `ConfigSnapshot::routes` and not only the HCM's own table.
    let rds = table(
        "rds_route",
        vec![model_route(
            "model-o3-mini",
            Some(HeaderMatchKind::Exact {
                value: "o3-mini".to_string(),
                ignore_case: false,
            }),
            0,
        )],
    );

    let hcm = HttpConnectionManagerConfig {
        stat_prefix: "ingress".to_string(),
        route_table: inlined,
        rds_route_config_name: None,
        http_filters: vec![HttpFilterSpec {
            ext_authz: None,
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
        request_headers_timeout: None,
        request_timeout: None,
        stream_idle_timeout: None,
        max_stream_duration: None,
    };
    let listener = ListenerConfig {
        name: "listener_0".to_string(),
        address: "127.0.0.1:0".parse().unwrap(),
        filter_chains: vec![FilterChainSpec {
            transport_socket_connect_timeout: None,
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
        ignore_global_conn_limit: false,
    };

    Arc::new(ConfigSnapshot {
        listeners: HashMap::from([(listener.name.clone(), Arc::new(listener))]),
        clusters: HashMap::new(),
        routes: HashMap::from([("rds_route".to_string(), rds)]),
        secrets: HashMap::new(),
        admin: None,
        tracing: None,
        // See the other snapshot fixture in this file.
        metrics: None,
        #[cfg(unix)]
        end_user_capture: None,
        end_user_capture_configured: false,
        ledger: None,
        traces: None,
        ads: None,
        max_downstream_connections: None,
        version: SnapshotVersion(1),
    })
}

/// Starts an admin server on port 0 over `snapshot`, with no stats
/// registry wired -- the default for every test that isn't specifically
/// about `/stats`. See [`start_with_registry`] for the `/stats`-focused
/// tests. Returns the server (kept alive for the caller) and its bound
/// address.
async fn start(snapshot: Arc<ConfigSnapshot>) -> (AdminServer, SocketAddr) {
    start_with_registry(snapshot, None).await
}

/// [`start`], but with an explicit (possibly `Some`) stats registry --
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

/// [`start`], but with an explicit [`ReadinessProbe`] -- what the `/ready` tests
/// need. No registry, no `SharedFactoryState`, no admin
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
/// the readiness parameter don't all need touching for a param none of them cares
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
            ui: None,
            lifecycle: None,
            credential_probe: None,
            capture_agent: None,
            ledger: None,
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
            ui: None,
            lifecycle: None,
            credential_probe: None,
            capture_agent: None,
            ledger: None,
        },
    )
    .await
    .expect("admin server bind");
    let addr = server.local_addr();
    (server, addr)
}

/// Registers a real [`ControlPlane`] into `factory_state` under
/// `(scope, auth_filter::TYPE_URL)` AND the matching
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
    register_model_authz_marker(&factory_state, TEST_CHAIN_SCOPE, TEST_CHAIN_STAT_PREFIX);
    (factory_state, handle)
}

/// Registers the presence marker `ModelAuthzFilterFactory::create` registers,
/// so policy writes are accepted on this chain.
fn register_model_authz_marker(
    factory_state: &Arc<SharedFactoryState>,
    scope: &str,
    stat_prefix: &str,
) {
    factory_state
        .get_or_try_init(
            scope,
            stat_prefix,
            proxy_filters::model_authz_filter::TYPE_URL,
            || {
                Ok(
                    Arc::new(proxy_filters::model_authz_filter::ModelAuthzEnforced)
                        as Arc<dyn std::any::Any + Send + Sync>,
                )
            },
        )
        .expect("inserting the model_authz marker must not fail");
}

/// Registers a real [`SpendAccumulator`] into `factory_state` under
/// `(scope, spend_limit_filter::TYPE_URL)` and its `stat_prefix` name index
/// -- the stand-in for what `SpendLimitFilterFactory::create`
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

/// The `stat_prefix` matching [`TEST_CHAIN_SCOPE`]'s registration -- the
/// external name for the same chain.
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

/// No probe wired keeps the pre-existing behavior --
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

/// When this admin server instance was never handed a stats registry
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
    assert!(body.contains("stats registry"));
}

/// Once a registry *is* wired, `/stats` renders it --
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

/// Same honest-404 rule as `/stats` itself when no
/// registry is wired.
#[tokio::test]
async fn stats_prometheus_is_404_when_no_registry_is_wired() {
    let (_server, addr) = start(snapshot_with_secret()).await;
    let (status, body) = get(addr, "/stats/prometheus").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("stats registry"));
}

/// Once a registry is wired, `/stats/prometheus` renders
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

/// The Envoy admin endpoints we deliberately do not implement
/// (`/quitquitquit`, `/logging`, `/listeners`; see envoy-divergences.md)
/// must not accidentally work, so adding one has to be a decision. Probed
/// with a wired lifecycle and a valid token, the most permissive setup.
#[tokio::test]
async fn unimplemented_envoy_admin_endpoints_are_404() {
    let (_server, addr, _state) = start_lifecycle(Some(ADMIN_TOKEN)).await;
    for path in ["/quitquitquit", "/logging", "/listeners"] {
        for method in ["GET", "POST"] {
            let (status, _, _) = request(addr, method, path, Some(ADMIN_TOKEN), "").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path} should 404");
        }
    }
}

/// Starts an admin server whose `/ready` probe reads the same
/// [`LifecycleState`] the lifecycle endpoints write -- the production wiring
/// shape (the binary builds the probe), so tests prove the shared-state
/// contract at the HTTP boundary.
async fn start_lifecycle(
    admin_token: Option<&str>,
) -> (AdminServer, SocketAddr, Arc<LifecycleState>) {
    let state = Arc::new(LifecycleState::new());
    let probe_state = Arc::clone(&state);
    let probe: ReadinessProbe = Arc::new(move || {
        if probe_state.out_of_rotation() {
            Readiness::Draining
        } else {
            Readiness::Live
        }
    });
    let config = SnapshotHandles::new().register(snapshot_with_secret());
    let server = serve(
        "127.0.0.1:0".parse().unwrap(),
        AdminRuntime {
            config,
            registry: None,
            started_at: Instant::now(),
            factory_state: Arc::new(SharedFactoryState::default()),
            admin_token: admin_token.map(str::to_string),
            readiness: Some(probe),
            cluster_state: None,
            ui: None,
            lifecycle: Some(Arc::clone(&state)),
            credential_probe: None,
            capture_agent: None,
            ledger: None,
        },
    )
    .await
    .expect("admin server bind");
    let addr = server.local_addr();
    (server, addr, state)
}

async fn ready(addr: SocketAddr) -> (StatusCode, String) {
    get(addr, "/ready").await
}

#[tokio::test]
async fn healthcheck_fail_and_ok_toggle_ready() {
    let (_server, addr, state) = start_lifecycle(Some(ADMIN_TOKEN)).await;
    assert_eq!(ready(addr).await, (StatusCode::OK, "LIVE".to_string()));

    let (status, _, body) = request(addr, "POST", "/healthcheck/fail", Some(ADMIN_TOKEN), "").await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "OK"));
    assert_eq!(
        ready(addr).await,
        (StatusCode::SERVICE_UNAVAILABLE, "DRAINING".to_string())
    );
    assert!(
        !state.is_draining(),
        "a health-check failure is not a drain"
    );

    let (status, _, body) = request(addr, "POST", "/healthcheck/ok", Some(ADMIN_TOKEN), "").await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "OK"));
    assert_eq!(ready(addr).await, (StatusCode::OK, "LIVE".to_string()));
}

#[tokio::test]
async fn drain_listeners_is_one_way_and_idempotent() {
    let (_server, addr, state) = start_lifecycle(Some(ADMIN_TOKEN)).await;

    // Two calls: the second is also 200, not an error.
    for _ in 0..2 {
        let (status, _, body) =
            request(addr, "POST", "/drain_listeners", Some(ADMIN_TOKEN), "").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "OK"));
    }
    assert_eq!(
        ready(addr).await,
        (StatusCode::SERVICE_UNAVAILABLE, "DRAINING".to_string())
    );

    // /healthcheck/ok must not reopen a drained process.
    let (status, _, _) = request(addr, "POST", "/healthcheck/ok", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        ready(addr).await,
        (StatusCode::SERVICE_UNAVAILABLE, "DRAINING".to_string())
    );

    assert!(state.is_draining());
    tokio::time::timeout(Duration::from_secs(5), state.drain_requested())
        .await
        .expect("the signal loop's wake-up must fire");
}

/// Fail-closed gate for the lifecycle writes: no token configured -> 403,
/// wrong token -> 401, wrong verb -> 405, and in every case the state is
/// untouched (asserting the negative: a gate that answers 403 after acting
/// would still pass a status-only check).
#[tokio::test]
async fn lifecycle_writes_refused_by_the_gate_change_nothing() {
    for (configured, presented, method, expected) in [
        (None, Some(ADMIN_TOKEN), "POST", StatusCode::FORBIDDEN),
        (
            Some(ADMIN_TOKEN),
            Some("wrong-token"),
            "POST",
            StatusCode::UNAUTHORIZED,
        ),
        (Some(ADMIN_TOKEN), None, "POST", StatusCode::UNAUTHORIZED),
        (
            Some(ADMIN_TOKEN),
            Some(ADMIN_TOKEN),
            "GET",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ] {
        let (_server, addr, state) = start_lifecycle(configured).await;
        for path in ["/healthcheck/fail", "/healthcheck/ok", "/drain_listeners"] {
            let (status, _, _) = request(addr, method, path, presented, "").await;
            assert_eq!(
                status, expected,
                "{method} {path} configured={configured:?}"
            );
        }
        assert_eq!(ready(addr).await, (StatusCode::OK, "LIVE".to_string()));
        assert!(!state.is_draining());
        assert!(!state.out_of_rotation());
    }
}

#[tokio::test]
async fn drain_listeners_query_flags_are_strict() {
    for (query, expected, drains) in [
        ("?inboundonly&graceful", StatusCode::OK, true),
        ("?graceful", StatusCode::OK, true),
        ("?bogus", StatusCode::BAD_REQUEST, false),
        ("?graceful&bogus=1", StatusCode::BAD_REQUEST, false),
    ] {
        let (_server, addr, state) = start_lifecycle(Some(ADMIN_TOKEN)).await;
        let path = format!("/drain_listeners{query}");
        let (status, _, body) = request(addr, "POST", &path, Some(ADMIN_TOKEN), "").await;
        assert_eq!(status, expected, "{query}: {body}");
        if !drains {
            assert!(
                body.contains("bogus"),
                "400 must name the parameter: {body}"
            );
        }
        assert_eq!(state.is_draining(), drains, "{query}");
    }
}

/// With no lifecycle wired (the admin server used standalone) the endpoints
/// are an honest 404, not a 200 that did nothing.
#[tokio::test]
async fn lifecycle_writes_without_a_wired_lifecycle_are_404() {
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        Arc::new(SharedFactoryState::default()),
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    for path in ["/healthcheck/fail", "/healthcheck/ok", "/drain_listeners"] {
        let (status, _, _) = request(addr, "POST", path, Some(ADMIN_TOKEN), "").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

// --- The admin write API + bearer gate ------------------------------------

/// AGENTS.md "Fail-open controls": the fail-CLOSED path gets its own test. `LLMPROXY_ADMIN_TOKEN`
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
/// of bug this design rules out.
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

/// **The scoped-route centrepiece.** Two chains, distinct `stat_prefix`es,
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

/// An id one byte over the bound is a 400 naming the field; exactly at the
/// bound mints. Request records cannot carry longer ids without truncation.
#[tokio::test]
async fn post_keys_enforces_the_128_byte_principal_id_bound() {
    let (factory_state, _handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    let mint = |tenant: String, key_id: String| async move {
        request(
            addr,
            "POST",
            "/keys",
            Some(ADMIN_TOKEN),
            &format!(r#"{{"tenant":"{tenant}","key_id":"{key_id}"}}"#),
        )
        .await
    };

    let (status, _, body) = mint("t".repeat(129), "key-a".into()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("tenant") && body.contains("128"), "{body}");
    let (status, _, body) = mint("tenant-a".into(), "k".repeat(129)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("key_id") && body.contains("128"), "{body}");
    let (status, _, body) = mint("t".repeat(128), "k".repeat(128)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
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
        Some(ModelAccess::All)
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
        Some(ModelAccess::Only(vec![
            proxy_filters::model_authz::ModelPattern::new("gpt-4*")
        ]))
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
        Some(ModelAccess::Only(vec![])),
        "an empty `only: []` must deny every model (Only(vec![])), NOT collapse to All"
    );
}

#[tokio::test]
async fn put_policy_deny_overrides_allow_and_is_visible_in_snapshot() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    let (status, _, _) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/policy",
        Some(ADMIN_TOKEN),
        r#"{"access":{"only":["gpt-*"]},"deny":["gpt-5*"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let snapshot = handle.load();
    let access = snapshot.policies["tenant-a"].model_access.as_ref().unwrap();
    assert!(access.permits("gpt-4o"));
    assert!(!access.permits("gpt-5-mini"));

    let (status, _, _) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/policy",
        Some(ADMIN_TOKEN),
        r#"{"access":"all","deny":["gpt-*-mini"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// --- PUT /tenants/{id}/budget -----------------------------------------------

/// Sets a budget, reads it back through the published snapshot, then clears
/// it (`{"budget": null}`) and confirms it is gone -- the round trip for
/// both directions of the endpoint's one request shape.
#[tokio::test]
async fn put_budget_sets_reads_back_and_clears() {
    let (factory_state, handle, _spend) = factory_state_with_control_plane_and_spend(Period::Daily);
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

/// Key budgets are attached to the stable public `key_id`, independent of
/// its tenant's other keys. This covers the real admin route and published
/// snapshot used by spend enforcement.
#[tokio::test]
async fn put_key_budget_sets_and_clears_the_stable_key_policy() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _, body) = request(
        addr,
        "POST",
        "/tenants",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, _, body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, _, body) = request(
        addr,
        "PUT",
        "/keys/key-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":{"max_usd":"3.00","period":"daily"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        handle.load().key_budgets[&KeyId::new("key-a")].max_micros,
        MicroUsd::from_micros(3_000_000),
    );

    let (status, _, body) = request(
        addr,
        "PUT",
        "/keys/key-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":null}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(!handle.load().key_budgets.contains_key(&KeyId::new("key-a")));
}

/// Key spend reads use the same stable public `key_id` as key-budget writes,
/// and do not expose another key belonging to the same tenant.
#[tokio::test]
async fn key_spend_read_reports_only_the_requested_key_ledger() {
    let (factory_state, handle, accumulator) =
        factory_state_with_control_plane_and_spend(Period::Monthly);
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _, body) = request(
        addr,
        "POST",
        "/tenants",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    for key_id in ["key-a", "key-b"] {
        let (status, _, body) = request(
            addr,
            "POST",
            "/keys",
            Some(ADMIN_TOKEN),
            &format!(r#"{{"tenant":"tenant-a","key_id":"{key_id}"}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    accumulator.record_key_now(
        &KeyId::new("key-a"),
        Period::Monthly,
        Charge::Priced(MicroUsd::from_micros(4_200)),
        Some("cluster-a"),
        Some("model-a"),
    );
    accumulator.record_key_now(
        &KeyId::new("key-b"),
        Period::Monthly,
        Charge::Priced(MicroUsd::from_micros(9_900)),
        Some("cluster-a"),
        Some("model-a"),
    );

    let (status, _, body) = request(addr, "GET", "/keys/key-a/spend", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["key_id"], "key-a");
    assert_eq!(value["tenant"], "tenant-a");
    assert_eq!(value["spend_micro_usd"], 4_200);
    assert_eq!(
        handle.load().key_tenants[&KeyId::new("key-b")],
        TenantId::new("tenant-a")
    );
}

/// Setting a budget must not clobber an already-set model-access policy for
/// the same tenant, and vice versa -- both directions, exercised through the
/// real HTTP endpoints rather than `ControlPlane` directly.
#[tokio::test]
async fn put_budget_and_put_policy_do_not_clobber_each_other() {
    let (factory_state, handle, _spend) = factory_state_with_control_plane_and_spend(Period::Daily);
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
        Some(ModelAccess::Only(vec![
            proxy_filters::model_authz::ModelPattern::new("gpt-4*")
        ])),
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
    for (scope, name) in [
        ("listener 'a' filter_chains[0]", "chain-a"),
        ("listener 'b' filter_chains[0]", "chain-b"),
    ] {
        register_spend_accumulator(&factory_state, scope, name, Period::Daily);
    }

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

// --- GET /tenants/{id}/spend ------------------------------------------------
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

/// The spend read carries this replica's reconciliation state (ADR-0006
/// §5). Filters hold no handle to the stats registry, so this
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
/// model)` pairs -- discoverability matters (an unconfigured price costs
/// zero, but the gap must stay visible).
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
/// the read-only tests already prove.
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
/// answer 400, matching AGENTS.md invariant 1 (a silently ignored field is a P0 in
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

/// A wrong method on a recognized write path answers 405, not the generic
/// 404 an unknown path gets.
///
/// `GET /keys` is the gated LIST endpoint, so the wrong-method probe is
/// `DELETE /keys` (no id -- the mint
/// shape only accepts POST) instead. The listing's own behavior is covered
/// by the `get_keys_*` tests below.
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

    let (status, _headers, _body) = request(addr, "DELETE", "/keys", None, "").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

/// `GET /keys` with no keys yet: a well-formed empty list, not a 404 and not
/// an error -- this is the shape the admin UI's Overview renders before
/// anyone has minted anything.
#[tokio::test]
async fn get_keys_with_no_keys_is_an_empty_list() {
    let (factory_state, _handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;

    let (status, _headers, body) = request(addr, "GET", "/keys", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["count"], 0);
    assert_eq!(value["keys"], serde_json::json!([]));
}

/// The listing itself: two tenants, one revoked key, one budgeted key --
/// sorted by `(tenant, key_id)`, with ownership/revocation/ceiling rendered
/// -- and, above all, NO plaintext of a minted key anywhere in the body.
#[tokio::test]
async fn get_keys_lists_tenant_revocation_and_budget_without_a_plaintext() {
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
    let minted: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let plaintext = minted["key"].as_str().expect("key field").to_string();

    let (status, _headers, _body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-b","key_id":"key-b"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // key-a revoked, key-b budgeted -- so both non-default columns are
    // exercised, and neither state may be reported for the wrong row.
    let (status, _headers, _body) =
        request(addr, "DELETE", "/keys/key-a", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _headers, _body) = request(
        addr,
        "PUT",
        "/keys/key-b/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":{"max_usd":"12.50","period":"daily"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _headers, body) = request(addr, "GET", "/keys", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains(&plaintext),
        "the minted plaintext leaked into the key listing: {body}"
    );

    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["count"], 2);
    let keys = value["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 2);

    assert_eq!(keys[0]["key_id"], "key-a");
    assert_eq!(keys[0]["tenant"], "tenant-a");
    assert!(
        keys[0]["policy"].is_null(),
        "a key with no policy inherits its tenant"
    );
    assert_eq!(
        keys[0]["revoked"], true,
        "a revoked key stays listable -- \
        hiding it would hide exactly what an operator came to audit"
    );
    assert!(
        keys[0]["budget"].is_null(),
        "no budget configured is `null` (unlimited), never a fabricated zero: {}",
        keys[0]["budget"]
    );

    assert_eq!(keys[1]["key_id"], "key-b");
    assert_eq!(keys[1]["tenant"], "tenant-b");
    assert_eq!(keys[1]["revoked"], false);
    assert_eq!(keys[1]["budget"]["max_usd"], "12.500000");
    assert_eq!(keys[1]["budget"]["max_micro_usd"], 12_500_000u64);
    assert_eq!(keys[1]["budget"]["period"], "daily");
}

/// Gate 1 on the listing: token not configured at all -> 403 naming the env
/// var. Same fail-closed rule as the writes -- unset never means open.
#[tokio::test]
async fn get_keys_with_no_admin_token_configured_is_forbidden() {
    let (factory_state, _handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(snapshot_with_secret(), None, factory_state, None).await;

    let (status, _headers, body) = request(addr, "GET", "/keys", None, "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body.contains("LLMPROXY_ADMIN_TOKEN"),
        "the403 must name the env var that would enable the endpoint: {body}"
    );
}

/// Gate 2 on the listing: token configured, wrong one presented -> 401 with
/// the RFC 7235 challenge.
#[tokio::test]
async fn get_keys_with_wrong_token_is_401_with_challenge() {
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
        "GET",
        "/keys",
        Some("definitely-not-the-configured-token"),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers.get(hyper::header::WWW_AUTHENTICATE),
        Some(&hyper::header::HeaderValue::from_static("Bearer")),
        "a 401 must carry the RFC 7235 challenge"
    );
}

/// Gate 3 on the listing: two `llmproxy.auth`-configured chains mean the
/// unscoped `GET /keys` cannot tell which one's inventory is meant. Loud,
/// explicit error naming both scopes -- never a silent pick, exactly as the
/// writes already behave.
#[tokio::test]
async fn get_keys_with_two_control_planes_is_an_explicit_error_not_a_guess() {
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

    let (status, _headers, body) = request(addr, "GET", "/keys", Some(ADMIN_TOKEN), "").await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "two llmproxy.auth-configured chains must be an explicit error, not a listing \
         silently drawn from one of them: {body}"
    );
    assert!(
        body.contains("listener 'a' filter_chains[0]")
            && body.contains("listener 'b' filter_chains[0]"),
        "the error must name every ambiguous scope: {body}"
    );
}

/// The scoped listing answers for exactly the chain it names: key minted into
/// chain-a is visible at `/chains/chain-a/keys` and absent from chain-b's.
#[tokio::test]
async fn scoped_get_keys_reads_only_the_named_chains_inventory() {
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
        "/chains/chain-a/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _headers, body) =
        request(addr, "GET", "/chains/chain-a/keys", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["count"], 1);
    assert_eq!(value["keys"][0]["key_id"], "key-a");

    let (status, _headers, body) =
        request(addr, "GET", "/chains/chain-b/keys", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(
        value["count"], 0,
        "chain-b's inventory must not show chain-a's key: {body}"
    );

    // An unknown stat_prefix is a 404 naming it -- operator error, not a
    // boot race, and never a fall-through to the ambiguous unscoped path.
    let (status, _headers, body) = request(
        addr,
        "GET",
        "/chains/no-such-chain/keys",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("no-such-chain"), "404 must name it: {body}");
}

/// `GET /models`: the model patterns the loaded config routes on, from BOTH
/// route sources (the HCM-inlined table and the RDS-delivered one), with the
/// path-only route excluded -- and ungated, proven by the fixture standing up
/// a server with no admin token configured at all.
#[tokio::test]
async fn get_models_lists_model_header_patterns_and_skips_path_only_routes() {
    let (_server, addr) = start(snapshot_with_model_routes()).await;

    let (status, body) = get(addr, "/models").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "config-shaped reads are ungated: {body}"
    );
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["header"], MODEL_HEADER_NAME);

    let models = value["models"].as_array().expect("models array");
    let rendered: Vec<(&str, &str, &str, &str)> = models
        .iter()
        .map(|m| {
            (
                m["model"].as_str().expect("model"),
                m["match"].as_str().expect("match"),
                m["route"].as_str().expect("route"),
                m["route_table"].as_str().expect("route_table"),
            )
        })
        .collect();
    // Sorted by pattern (the inventory is sorted, so a caller can diff it),
    // with the prefix matcher reconstructed back into the glob an operator
    // wrote (`claude-3` -> `claude-3*`).
    assert_eq!(
        rendered,
        vec![
            ("claude-3*", "prefix", "model-claude", "local_route"),
            ("gpt-4o", "exact", "model-gpt-4o", "local_route"),
            ("o3-mini", "exact", "model-o3-mini", "rds_route"),
        ]
    );
    assert!(
        !body.contains("chat-completions"),
        "a path-only route names no model and must not be reported as one: {body}"
    );
}

/// Starts the real HTTP admin socket with an in-`temp_dir` UI bundle: an
/// `index.html` plus one hashed asset, exercising the same
/// [`UiAssets::load_from_dir`] production (`start_admin`) uses rather than a
/// hand-built map that could drift from the loader.
async fn start_with_ui_from_fixture() -> (AdminServer, SocketAddr, std::path::PathBuf) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static FIXTURE_SEQ: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "llmproxy-admin-ui-test-{}-{}",
        std::process::id(),
        FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(dir.join("assets")).expect("fixture dir");
    std::fs::write(dir.join("index.html"), "<html>ui-index-marker</html>").expect("index");
    std::fs::write(dir.join("assets").join("app.js"), "console.log(1)").expect("asset");

    let ui = UiAssets::load_from_dir(&dir).expect("fixture loads");
    let config = SnapshotHandles::new().register(snapshot_with_secret());
    let server = serve(
        "127.0.0.1:0".parse().unwrap(),
        AdminRuntime {
            config,
            registry: None,
            started_at: Instant::now(),
            factory_state: Arc::new(SharedFactoryState::default()),
            admin_token: None,
            readiness: None,
            cluster_state: None,
            ui: Some(Arc::new(ui)),
            lifecycle: None,
            credential_probe: None,
            capture_agent: None,
            ledger: None,
        },
    )
    .await
    .expect("admin server bind");
    let addr = server.local_addr();
    (server, addr, dir)
}

#[tokio::test]
async fn ui_serves_index_at_both_paths() {
    let (_server, addr, _dir) = start_with_ui_from_fixture().await;
    for path in ["/ui", "/ui/"] {
        let (status, content_type, body) = get_with_content_type(addr, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(
            content_type.starts_with("text/html"),
            "{path}: {content_type}"
        );
        assert!(body.contains("ui-index-marker"), "{path}");
    }
}

#[tokio::test]
async fn ui_serves_hashed_asset_with_js_content_type() {
    let (_server, addr, _dir) = start_with_ui_from_fixture().await;
    let (status, content_type, body) = get_with_content_type(addr, "/ui/assets/app.js").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.starts_with("text/javascript"),
        "{content_type}"
    );
    assert!(body.contains("console.log(1)"));
}

#[tokio::test]
async fn ui_falls_back_to_index_for_unknown_subpath() {
    let (_server, addr, _dir) = start_with_ui_from_fixture().await;
    let (status, _content_type, body) = get_with_content_type(addr, "/ui/tenants/acme").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("ui-index-marker"));
}

#[tokio::test]
async fn ui_rejects_non_get_with_405() {
    let (_server, addr, _dir) = start_with_ui_from_fixture().await;
    let (status, _headers, _body) = request(addr, "POST", "/ui", None, "").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn ui_does_not_shadow_api_or_prefix_siblings() {
    let (_server, addr, _dir) = start_with_ui_from_fixture().await;
    let (status, _body) = get(addr, "/config_dump").await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = get(addr, "/uix").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("available endpoints"), "{body}");
}

#[tokio::test]
async fn ui_absent_is_a_hinted_404() {
    let (_server, addr) = start(snapshot_with_secret()).await;
    let (status, body) = get(addr, "/ui").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("LLMPROXY_ADMIN_UI_DIR"), "{body}");
}

#[tokio::test]
async fn ui_load_requires_index_html() {
    let dir = std::env::temp_dir().join(format!(
        "llmproxy-admin-ui-test-empty-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let err = UiAssets::load_from_dir(&dir).expect_err("no index.html must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    std::fs::remove_dir(&dir).ok();
}

#[tokio::test]
async fn key_rotation_conflicts_and_api_version_are_explicit() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    let body = r#"{"schema_version":2,"tenant":"tenant-a","key_id":"stable"}"#;
    let (status, _, first) = request(addr, "POST", "/keys", Some(ADMIN_TOKEN), body).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let first: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(first["schema_version"], 2);
    let (status, _, second) = request(addr, "POST", "/keys", Some(ADMIN_TOKEN), body).await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    let second: serde_json::Value = serde_json::from_str(&second).unwrap();
    assert_ne!(first["key"], second["key"]);
    let authenticator = test_authenticator(handle);
    assert!(matches!(
        authenticator.authenticate(&headers_with_bearer(second["key"].as_str().unwrap())),
        AuthOutcome::Authenticated(_)
    ));
    assert!(matches!(
        authenticator.authenticate(&headers_with_bearer(first["key"].as_str().unwrap())),
        AuthOutcome::Rejected(AuthError::UnknownKey)
    ));
    for body in [
        r#"{"schema_version":99,"tenant":"tenant-a","key_id":"new"}"#,
        r#"{"schema_version":1,"tenant":"tenant-a","key_id":"new"}"#,
    ] {
        assert_eq!(
            request(addr, "POST", "/keys", Some(ADMIN_TOKEN), body)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        request(
            addr,
            "POST",
            "/keys",
            Some(ADMIN_TOKEN),
            r#"{"tenant":"tenant-b","key_id":"stable"}"#
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(
            addr,
            "PUT",
            "/keys/stable/budget",
            Some(ADMIN_TOKEN),
            r#"{"schema_version":99,"budget":null}"#
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            addr,
            "PUT",
            "/keys/stable/budget",
            Some(ADMIN_TOKEN),
            r#"{"schema_version":2,"budget":{"max_usd":"1.00","period":"daily"}}"#
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(addr, "DELETE", "/keys/stable", Some(ADMIN_TOKEN), "")
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(addr, "POST", "/keys", Some(ADMIN_TOKEN), body)
            .await
            .0,
        StatusCode::CONFLICT
    );
}

mod admin_rate_limit;
mod budget_scope;
mod capture_spool;
mod credentials;
mod ledger;
mod limits;
mod pricing;
mod tenant_budget_cutover;
mod trace_export;
