//! Wiring tests: real HTTP requests over a real socket (port 0), not
//! hand-called handler functions -- the wiring is the part that breaks.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
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
    AuthError, AuthOutcome, Authenticator, HmacSecret, KeySet, VirtualKeyAuthenticator,
};
use proxy_filters::auth_filter;
use proxy_filters::control::{ControlPlane, InMemoryControlPlaneStore};
use proxy_filters::model_authz::ModelAccess;
use proxy_http::filter::SharedFactoryState;
use proxy_observability::stats::{
    instruments, prometheus_render, Registry, StatsControl, WorkerId,
};
use tokio::net::TcpStream;

use crate::server::{serve, AdminServer};

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
        name: "upstream".to_string(),
        discovery: DiscoveryType::Static,
        lb_policy: LbPolicy::RoundRobin,
        connect_timeout: Duration::from_secs(5),
        endpoints: vec![EndpointIR {
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

/// The full [`serve`] parameter set -- what the write-API tests need to
/// supply a real `ControlPlane` (via `factory_state`) and/or a bearer token.
async fn start_full(
    snapshot: Arc<ConfigSnapshot>,
    registry: Option<Arc<Registry>>,
    factory_state: Arc<SharedFactoryState>,
    admin_token: Option<String>,
) -> (AdminServer, SocketAddr) {
    // Rust note: `SnapshotHandles::register` both builds the handle and
    // enrolls it, the same path production code (`WorkerPool::spawn`, and
    // `start_admin` in `crates/proxy/src/main.rs`) goes through -- there is
    // no other way to obtain a `WorkerConfigHandle` from outside `proxy-core`.
    let config = SnapshotHandles::new().register(snapshot);
    let server = serve(
        "127.0.0.1:0".parse().unwrap(),
        config,
        registry,
        Instant::now(),
        factory_state,
        admin_token,
    )
    .await
    .expect("admin server bind");
    let addr = server.local_addr();
    (server, addr)
}

/// Builds a [`SharedFactoryState`] with a real [`ControlPlane`] already
/// registered under `auth_filter::TYPE_URL` -- the exact shape a worker's
/// `AuthFilterFactory::create` produces on the first call for a real
/// `llmproxy.auth` filter (see that factory's own doc for the
/// `get_or_try_init` singleton dance this mirrors). Returns the state and
/// the `ControlPlane`'s own published-snapshot handle, so a test can
/// `.load()` it directly to check what a mint/revoke/policy write actually
/// published -- exactly what `crate::control`'s own tests do from inside
/// that crate.
fn factory_state_with_control_plane() -> (
    Arc<SharedFactoryState>,
    Arc<arc_swap::ArcSwap<proxy_filters::control::ControlPlaneSnapshot>>,
) {
    let control_plane = ControlPlane::new(
        Box::new(InMemoryControlPlaneStore::default()),
        HmacSecret::new(TEST_HMAC_SECRET),
        KeySet::new(),
    )
    .expect("an empty store must not fail ControlPlane::new");
    let handle = control_plane.handle();
    let factory_state = Arc::new(SharedFactoryState::default());
    factory_state
        .get_or_try_init(auth_filter::TYPE_URL, || {
            Ok(Arc::new(control_plane) as Arc<dyn std::any::Any + Send + Sync>)
        })
        .expect("inserting the test ControlPlane singleton must not fail");
    (factory_state, handle)
}

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
