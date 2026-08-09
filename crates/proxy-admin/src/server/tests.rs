//! Wiring tests: real HTTP requests over a real socket (port 0), not
//! hand-called handler functions -- the wiring is the part that breaks.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper::client::conn::http1 as client_http1;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use proxy_config::ir::{
    ClusterConfig, ClusterKind, ConfigSnapshot, DiscoveryType, EndpointIR, FilterChainMatch,
    FilterChainSpec, ForwardAction, ForwardTarget, HeaderAppendAction, HeaderMutation,
    HttpConnectionManagerConfig, HttpFilterSpec, LbPolicy, ListenerConfig, NetworkFilterSpec,
    PathMatch, RouteActionIR, RouteEntry, RouteMatcher, RouteTable, SnapshotVersion,
    UpstreamProtocol, VirtualHostIR,
};
use proxy_core::WorkerConfigHandle;
use proxy_observability::stats::{instruments, Registry, StatsControl, WorkerId};
use tokio::net::TcpStream;

use crate::server::{serve, AdminServer};

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
        generate_request_id: true,
        use_remote_address: false,
        xff_num_trusted_hops: 0,
        access_logs: vec![],
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
    };

    Arc::new(ConfigSnapshot {
        listeners: HashMap::from([(listener.name.clone(), Arc::new(listener))]),
        clusters: HashMap::from([(cluster.name.clone(), Arc::new(cluster))]),
        routes: HashMap::new(),
        secrets: HashMap::new(),
        admin: Some("127.0.0.1:9901".parse().unwrap()),
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
/// cases.
async fn start_with_registry(
    snapshot: Arc<ConfigSnapshot>,
    registry: Option<Arc<Registry>>,
) -> (AdminServer, SocketAddr) {
    let config = Arc::new(WorkerConfigHandle::new(snapshot));
    let server = serve(
        "127.0.0.1:0".parse().unwrap(),
        config,
        registry,
        Instant::now(),
    )
    .await
    .expect("admin server bind");
    let addr = server.local_addr();
    (server, addr)
}

/// A minimal hyper/1 client request over a fresh connection -- returns
/// (status, body).
async fn get(addr: SocketAddr, path: &str) -> (StatusCode, String) {
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
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8(body.to_vec()).expect("utf8 body"))
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

/// The mutating endpoints are explicitly out of scope for this increment;
/// they must not accidentally work.
#[tokio::test]
async fn mutating_endpoints_are_404() {
    let (_server, addr) = start(snapshot_with_secret()).await;
    for path in ["/quitquitquit", "/drain_listeners", "/logging"] {
        let (status, _) = get(addr, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "path {path} should 404");
    }
}
