//! `llmproxy.model_resolver` end to end: an Envoy-mode bootstrap YAML is
//! lowered through the real strict loader, the real `body_rewrite` and
//! `model_resolver` factories run ahead of the real router, and a mock
//! upstream per cluster captures the request body it actually received.
//!
//! What this owns that unit tests cannot: the join between the resolver
//! (`StreamInfo::resolved_model`), header routing on `x-llmproxy-model`, and the
//! router's body rewrite plus content-length fix-up. Per-provider mapping lives
//! on the cluster (`io.llmproxy.provider_auth` `models`), so the same alias
//! must reach each provider under that provider's own name.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::resolver::FakeResolver;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};
use proxy_http::filter::{
    FactoryContext, FilterRegistry, RequestHeaders, TerminalFilterInstanceFactory,
};
use proxy_http::filter_manager::{ConfiguredHttpFilter, FilterChainHandler};
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
use proxy_http::router::RouterFilterFactory;
use proxy_http::stat_handles::{RouterStats, StatHandles};
use proxy_observability::stats::{StatsControl, WorkerId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::LocalSet;

/// What an upstream saw: the declared `Content-Length` and the body bytes.
struct Captured {
    content_length: usize,
    body: Vec<u8>,
}

impl Captured {
    fn model(&self) -> String {
        let json: serde_json::Value =
            serde_json::from_slice(&self.body).expect("upstream body must be JSON");
        json["model"]
            .as_str()
            .expect("upstream body must carry a string `model`")
            .to_string()
    }
}

/// One-shot upstream: reads headers plus `Content-Length` body bytes, hands
/// them back through the channel, answers 200. The channel stays empty if the
/// upstream is never dialed.
async fn spawn_capturing_upstream() -> (SocketAddr, oneshot::Receiver<Captured>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let (header_end, content_length) = loop {
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "upstream connection closed before headers ended");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map(|v| v.trim().parse::<usize>().unwrap())
                    .expect("request must carry content-length");
                break (pos + 4, len);
            }
        };
        while buf.len() < header_end + content_length {
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "upstream connection closed mid-body");
            buf.extend_from_slice(&chunk[..n]);
        }
        let _ = tx.send(Captured {
            content_length,
            body: buf[header_end..header_end + content_length].to_vec(),
        });
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    });
    (addr, rx)
}

struct Upstreams {
    fast: oneshot::Receiver<Captured>,
    smart: oneshot::Receiver<Captured>,
    auto: oneshot::Receiver<Captured>,
}

/// `resolver_rules` is the YAML body of the resolver's `rules:` mapping.
async fn build_handler(resolver_rules: &str) -> (FilterChainHandler, Upstreams) {
    let (addr_fast, fast) = spawn_capturing_upstream().await;
    let (addr_smart, smart) = spawn_capturing_upstream().await;
    let (addr_auto, auto) = spawn_capturing_upstream().await;

    let cluster = |name: &str, addr: SocketAddr, models: &str| {
        format!(
            r#"
    - name: {name}
      type: STATIC
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            models: {models}
      load_assignment:
        cluster_name: {name}
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {ip}, port_value: {port} }}
"#,
            ip = addr.ip(),
            port = addr.port(),
        )
    };
    let route = |model: &str, cluster: &str| {
        format!(
            r#"
                        - match:
                            prefix: "/"
                            headers:
                              - name: x-llmproxy-model
                                string_match: {{ exact: "{model}" }}
                          route: {{ cluster: {cluster} }}
"#
        )
    };
    let yaml = format!(
        r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: {{ address: 127.0.0.1, port_value: 0 }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: test
                http_filters:
                  - name: llmproxy.body_rewrite
                    typed_config:
                      "@type": type.llmproxy.dev/llmproxy.filters.v0.BodyRewrite
                      enabled: true
                      dialect: openai
                  - name: llmproxy.model_resolver
                    typed_config:
                      "@type": type.llmproxy.dev/llmproxy.filters.v0.ModelResolver
                      rules: {resolver_rules}
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
{routes}
  clusters:
{clusters}
"#,
        routes = [
            route("fast", "cluster_fast"),
            route("smart", "cluster_smart"),
            route("auto", "cluster_auto"),
        ]
        .concat(),
        clusters = [
            cluster("cluster_fast", addr_fast, "[]"),
            cluster(
                "cluster_smart",
                addr_smart,
                r#"[{ pattern: smart, upstream_model: provider-smart-v2 }]"#
            ),
            cluster("cluster_auto", addr_auto, "[]"),
        ]
        .concat(),
    );

    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
        .expect("bootstrap YAML must parse");
    let snapshot = build_snapshot(&loaded).expect("bootstrap YAML must lower");

    let cluster_manager = Arc::new(ClusterManager::with_default_transport(Arc::new(
        FakeResolver::new(),
    )));
    let rejected = cluster_manager
        .update_from_snapshot(&snapshot.clusters)
        .await;
    assert!(
        rejected.is_empty(),
        "no cluster may be rejected: {rejected:?}"
    );

    let listener = snapshot.listeners.values().next().expect("one listener");
    let proxy_config::ir::NetworkFilterSpec::HttpConnectionManager(hcm) =
        &listener.filter_chains[0].filters[0]
    else {
        panic!("expected an HTTP connection manager");
    };

    let mut registry = FilterRegistry::default();
    registry.register(Arc::new(
        proxy_filters::body_rewrite_filter::BodyRewriteFilterFactory,
    ));
    registry.register(Arc::new(
        proxy_filters::model_resolver_filter::ModelResolverFilterFactory,
    ));
    let factory_ctx = FactoryContext::default();
    let mut filters = Vec::new();
    for f in hcm.http_filters.iter().filter(|f| !f.is_router) {
        let factory = registry
            .get(&f.type_url)
            .unwrap_or_else(|| panic!("no factory for `{}`", f.type_url));
        let config = f.config.as_ref().expect("non-router filter has config");
        let instance_factory = factory
            .create(config, &factory_ctx)
            .unwrap_or_else(|e| panic!("filter '{}' config must parse: {e}", f.name));
        filters.push(ConfiguredHttpFilter {
            name: f.name.clone(),
            instance_factory: Arc::from(instance_factory),
            factory: factory.clone(),
        });
    }

    let stats_control = StatsControl::new(1);
    let stat_handles = Arc::new(StatHandles::build(
        &stats_control,
        snapshot.clusters.keys().map(String::as_str),
    ));
    let router_stats = Arc::new(RouterStats::new(
        stats_control.registry(),
        stat_handles,
        WorkerId(0),
    ));
    let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> =
        Arc::new(RouterFilterFactory::new(cluster_manager, router_stats));
    let handler = FilterChainHandler::new_with_filters(
        filters,
        terminal_factory,
        hcm.route_table.clone(),
        hcm.generate_request_id,
        hcm.use_remote_address,
        hcm.xff_num_trusted_hops,
    )
    .expect("filter chain must build");
    (handler, Upstreams { fast, smart, auto })
}

fn json_post_request(body: &'static [u8]) -> HttpRequestParts {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("test.local"));
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).unwrap(),
    );
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
            headers,
        },
        body: local_boxed(
            Full::new(Bytes::from_static(body))
                .map_err(|infallible: std::convert::Infallible| match infallible {}),
        ),
        downstream: DownstreamInfo::loopback(),
        on_upgrade: None,
    }
}

/// Send `body`, return the downstream status.
async fn send(handler: &FilterChainHandler, body: &'static [u8]) -> StatusCode {
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        handler.handle(json_post_request(body)),
    )
    .await
    .expect("request must complete");
    let status = resp.head.status;
    let _ = resp.body.collect().await;
    status
}

/// The body the upstream received, with its framing checked: the router must
/// have fixed `content-length` to the rewritten length.
async fn received(rx: oneshot::Receiver<Captured>) -> Captured {
    let captured = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("upstream must be dialed")
        .expect("upstream task must report");
    assert_eq!(
        captured.content_length,
        captured.body.len(),
        "content-length must match the body the upstream received"
    );
    captured
}

fn assert_not_dialed(rx: &mut oneshot::Receiver<Captured>, which: &str) {
    assert!(
        rx.try_recv().is_err(),
        "cluster {which} must not have been dialed"
    );
}

// Rust note: current_thread + LocalSet because the router's upstream
// connection driver is spawned with `spawn_local`, which is not `Send`.
#[tokio::test(flavor = "current_thread")]
async fn auto_resolved_to_an_unmapped_alias_reaches_its_provider_as_the_alias() {
    LocalSet::new()
        .run_until(async {
            let (handler, mut up) = build_handler("{ default_model: fast }").await;
            let status = send(&handler, br#"{"model":"auto","messages":[]}"#).await;
            assert_eq!(status, StatusCode::OK);

            let got = received(up.fast).await;
            assert_eq!(got.model(), "fast", "the provider must not see `auto`");
            assert_not_dialed(&mut up.smart, "smart");
            assert_not_dialed(&mut up.auto, "auto");
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn auto_resolved_to_a_mapped_alias_reaches_its_provider_as_the_upstream_model() {
    LocalSet::new()
        .run_until(async {
            let (handler, mut up) = build_handler("{ default_model: smart }").await;
            let status = send(&handler, br#"{"model":"auto","messages":[]}"#).await;
            assert_eq!(status, StatusCode::OK);

            let got = received(up.smart).await;
            assert_eq!(got.model(), "provider-smart-v2");
            assert_not_dialed(&mut up.fast, "fast");
            assert_not_dialed(&mut up.auto, "auto");
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_concrete_model_is_routed_unchanged() {
    LocalSet::new()
        .run_until(async {
            // The default points at the other provider, so a resolver that
            // fired on a concrete model would be visible as a wrong dial.
            let (handler, mut up) = build_handler("{ default_model: smart }").await;
            let status = send(&handler, br#"{"model":"fast","messages":[]}"#).await;
            assert_eq!(status, StatusCode::OK);

            let got = received(up.fast).await;
            assert_eq!(got.model(), "fast");
            assert_not_dialed(&mut up.smart, "smart");
            assert_not_dialed(&mut up.auto, "auto");
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn auto_with_no_rule_is_refused_with_400_and_dials_nothing() {
    LocalSet::new()
        .run_until(async {
            let (handler, mut up) = build_handler("{}").await;
            let status = send(&handler, br#"{"model":"auto","messages":[]}"#).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);

            assert_not_dialed(&mut up.fast, "fast");
            assert_not_dialed(&mut up.smart, "smart");
            assert_not_dialed(&mut up.auto, "auto");
        })
        .await;
}
