//! Acceptance tests for the dialect's `auto:` block: it lowers to an
//! `llmproxy.model_resolver` filter in the right chain position, passes the
//! strict Envoy loader, rejects bad configs naming the DIALECT field path, and
//! (end to end, real filters + router + mock upstreams) resolves a request
//! for `auto` to the right provider under that provider's own model name.
//!
//! Helpers are duplicated from `dialect.rs`, `auth.rs` and
//! `model_resolver_routing.rs` on purpose: the crate keeps no shared test
//! scaffolding.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::resolver::FakeResolver;
use proxy_config::ConfigError;
use proxy_http::filter::{
    FactoryContext, FilterRegistry, RequestHeaders, TerminalFilterInstanceFactory,
};
use proxy_http::filter_manager::{ConfiguredHttpFilter, FilterChainHandler};
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamHandler};
use proxy_http::router::RouterFilterFactory;
use proxy_http::stat_handles::{RouterStats, StatHandles};
use proxy_observability::stats::{StatsControl, WorkerId};
use proxy_simple_config::{lower, lower_to_loaded, parse_simple_config_with_env, SimpleConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::LocalSet;

fn parse(text: &str) -> Result<SimpleConfig, ConfigError> {
    parse_simple_config_with_env(text, &|_| None)
}

/// Same HMAC-SHA256 the auth filter verifies against (see `auth.rs`).
fn digest_hex(secret: &[u8], plaintext: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let digest = ring::hmac::sign(&key, plaintext.as_bytes());
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn hcm_typed_config(bootstrap: &serde_json::Value) -> &serde_json::Value {
    &bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
}

fn filter_names(bootstrap: &serde_json::Value) -> Vec<String> {
    hcm_typed_config(bootstrap)["http_filters"]
        .as_array()
        .expect("http_filters must be an array")
        .iter()
        .map(|f| f["name"].as_str().unwrap_or_default().to_string())
        .collect()
}

const SECRET: &str = "test-operator-secret";

/// `auth:` block with one key per tenant; the plaintext key is
/// `llmp_<tenant>-key`. Neither tenant has a stored model policy, so the
/// block opts them in with `tenants_without_policy: allow`; these tests are
/// about resolution, not model grants.
fn auth_block() -> String {
    let acme = digest_hex(SECRET.as_bytes(), "llmp_acme-key");
    let globex = digest_hex(SECRET.as_bytes(), "llmp_globex-key");
    format!(
        "auth:\n  hmac_secret: \"{SECRET}\"\n  enforce: {{ tenants_without_policy: allow }}\n  keys:\n    \
         - {{ id: \"k1\", tenant: \"acme\", digest: \"{acme}\" }}\n    \
         - {{ id: \"k2\", tenant: \"globex\", digest: \"{globex}\" }}\n"
    )
}

/// Catalogue config with the given extra top-level YAML appended.
fn config_with(extra: &str) -> String {
    format!(
        "version: 0\n\
         providers:\n  a: {{ base_url: \"http://127.0.0.1:1\" }}\n  b: {{ base_url: \"http://127.0.0.1:2\" }}\n\
         models:\n  fast: {{ providers: [a] }}\n  smart: {{ providers: [{{ provider: b, model: provider-smart-v2 }}] }}\n\
         routes: []\n\
         {extra}"
    )
}

/// `config_with(extra)` plus a `models` entry literally named `auto`.
fn config_with_model_named_auto(extra: &str) -> String {
    config_with(extra).replacen(
        "routes: []\n",
        "  auto: { providers: [a] }\nroutes: []\n",
        1,
    )
}

// --- 1: type URL pin + filter order ------------------------------------------

#[test]
fn model_resolver_lowers_with_pinned_type_url_in_chain_order() {
    let text = config_with(&format!(
        "{}auto:\n  default: fast\n  tenants:\n    acme: smart\n",
        auth_block()
    ));
    let lowered = lower(&parse(&text).expect("must parse")).expect("must lower");

    let names = filter_names(&lowered.bootstrap);
    let pos = |name: &str| {
        names
            .iter()
            .position(|n| n == name)
            .unwrap_or_else(|| panic!("`{name}` missing from {names:?}"))
    };
    assert!(pos("llmproxy.auth") < pos("llmproxy.model_resolver"));
    assert!(pos("llmproxy.body_rewrite") < pos("llmproxy.model_resolver"));
    assert!(pos("llmproxy.model_resolver") < pos("llmproxy.usage"));

    let entry =
        &hcm_typed_config(&lowered.bootstrap)["http_filters"][pos("llmproxy.model_resolver")];
    assert_eq!(
        entry["typed_config"]["@type"],
        proxy_filters::model_resolver_filter::TYPE_URL,
        "lower.rs duplicates this literal; this pins the two together"
    );
    assert_eq!(entry["typed_config"]["rules"]["default_model"], "fast");
    assert_eq!(
        entry["typed_config"]["rules"]["tenants"],
        serde_json::json!([{ "tenant": "acme", "model": "smart" }])
    );
}

// --- 2: strict Envoy load ----------------------------------------------------

#[test]
fn auto_config_lowers_through_the_strict_loader_and_builds_ir() {
    for extra in [
        "auto:\n  default: fast\n".to_string(),
        format!(
            "{}auto:\n  default: fast\n  tenants:\n    acme: smart\n",
            auth_block()
        ),
    ] {
        let config = parse(&config_with(&extra)).expect("must parse");
        let loaded = lower_to_loaded(&config).expect("must lower and strict-validate");
        let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");
        let listener = snapshot.listeners.values().next().expect("one listener");
        let proxy_config::ir::NetworkFilterSpec::HttpConnectionManager(hcm) =
            &listener.filter_chains[0].filters[0]
        else {
            panic!("expected an HTTP connection manager");
        };
        assert!(
            hcm.http_filters
                .iter()
                .any(|f| f.type_url == proxy_filters::model_resolver_filter::TYPE_URL),
            "resolver must survive to the IR"
        );
    }
}

// --- 3: no `auto:` block -----------------------------------------------------

#[test]
fn without_an_auto_block_no_resolver_is_emitted_and_a_model_named_auto_is_accepted() {
    let text = config_with_model_named_auto("");
    let config = parse(&text).expect("must parse");
    let lowered = lower(&config).expect("a model named `auto` is ordinary without the block");
    assert!(!filter_names(&lowered.bootstrap).contains(&"llmproxy.model_resolver".to_string()));
    lower_to_loaded(&config).expect("must strict-validate");
}

// --- 4: validation field paths -----------------------------------------------

#[test]
fn each_invalid_auto_config_names_its_field_path() {
    let with_routes = |extra: &str| {
        format!(
            "version: 0\nproviders:\n  a: {{ base_url: \"http://127.0.0.1:1\" }}\n\
             routes:\n  - {{ model: \"gpt-*\", provider: a }}\n{extra}"
        )
    };
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "empty block",
            config_with("auto: {}\n"),
            "auto",
        ),
        (
            "tenants without auth",
            config_with("auto:\n  tenants:\n    acme: fast\n"),
            "auto.tenants",
        ),
        (
            "empty tenant key",
            config_with(&format!("{}auto:\n  tenants:\n    \"\": fast\n", auth_block())),
            "auto.tenants",
        ),
        (
            "models.auto reserved",
            config_with_model_named_auto("auto:\n  default: fast\n"),
            "models.auto",
        ),
        (
            "routes[i].model reserved",
            with_routes("auto:\n  default: gpt-4\n").replace(
                "routes:\n  - { model: \"gpt-*\", provider: a }\n",
                "routes:\n  - { model: \"gpt-*\", provider: a }\n  - { model: auto, provider: a }\n",
            ),
            "routes[1].model",
        ),
        (
            "empty default",
            config_with("auto:\n  default: \"\"\n"),
            "auto.default",
        ),
        (
            "default is auto",
            config_with("auto:\n  default: auto\n"),
            "auto.default",
        ),
        (
            "default is a pattern",
            with_routes("auto:\n  default: \"gpt-*\"\n"),
            "auto.default",
        ),
        (
            "default unserved",
            with_routes("auto:\n  default: claude-3\n"),
            "auto.default",
        ),
        (
            "tenant target unserved",
            config_with(&format!("{}auto:\n  tenants:\n    acme: nope\n", auth_block())),
            "auto.tenants.acme",
        ),
        (
            "tenant target is auto",
            config_with(&format!("{}auto:\n  tenants:\n    acme: auto\n", auth_block())),
            "auto.tenants.acme",
        ),
    ];
    for (name, text, expected) in cases {
        let err = parse(&text)
            .and_then(|c| lower(&c).map(|_| ()))
            .expect_err(name);
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, expected, "case `{name}`")
            }
            other => panic!("case `{name}`: expected InvalidValue, got {other:?}"),
        }
    }
}

/// A literal duplicate tenant is a parse error, not last-one-wins.
#[test]
fn duplicate_auto_tenant_is_a_parse_error() {
    let text = config_with(&format!(
        "{}auto:\n  tenants:\n    acme: fast\n    acme: smart\n",
        auth_block()
    ));
    let err = parse(&text).expect_err("duplicate tenant must not parse");
    assert!(
        err.to_string()
            .contains("duplicate `auto.tenants` entry `acme`"),
        "got: {err}"
    );
}

// --- 7: access-log formats ---------------------------------------------------

#[test]
fn default_access_log_formats_carry_the_resolved_model() {
    for (format, needle) in [
        ("text", "%LLM_RESOLVED_MODEL%"),
        ("json", "llm_resolved_model"),
    ] {
        let text = config_with(&format!(
            "observability:\n  access_logs: {{ output: stdout, format: {format} }}\n"
        ));
        let lowered = lower(&parse(&text).expect("must parse")).expect("must lower");
        let entry = &hcm_typed_config(&lowered.bootstrap)["access_log"][0];
        assert!(
            entry.to_string().contains(needle),
            "{format} format must contain `{needle}`: {entry}"
        );
    }
}

// --- E2E ---------------------------------------------------------------------

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

/// One-shot upstream that hands back the body it received and answers 200.
/// The channel stays empty if the upstream is never dialed.
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

/// Build a real handler (real auth, body_rewrite, model_resolver, usage and
/// router) from a dialect config. `extra` is the `auto:` (and `auth:`) YAML.
async fn build_handler(
    extra: &str,
) -> (
    FilterChainHandler,
    oneshot::Receiver<Captured>,
    oneshot::Receiver<Captured>,
) {
    let (addr_a, rx_a) = spawn_capturing_upstream().await;
    let (addr_b, rx_b) = spawn_capturing_upstream().await;
    let text = format!(
        "version: 0\n\
         providers:\n  a: {{ base_url: \"http://{addr_a}\" }}\n  b: {{ base_url: \"http://{addr_b}\" }}\n\
         models:\n  fast: {{ providers: [a] }}\n  smart: {{ providers: [{{ provider: b, model: provider-smart-v2 }}] }}\n\
         routes: []\n\
         {extra}"
    );
    let config = parse(&text).expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");

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
    registry.register(Arc::new(proxy_filters::usage_filter::UsageFilterFactory));
    registry.register(Arc::new(
        proxy_filters::body_rewrite_filter::BodyRewriteFilterFactory,
    ));
    registry.register(Arc::new(
        proxy_filters::model_resolver_filter::ModelResolverFilterFactory,
    ));
    registry.register(Arc::new(proxy_filters::auth_filter::AuthFilterFactory));
    // `auth` makes the dialect enforce tenant model policy and budgets.
    registry.register(Arc::new(
        proxy_filters::model_authz_filter::ModelAuthzFilterFactory,
    ));
    registry.register(Arc::new(
        proxy_filters::spend_limit_filter::SpendLimitFilterFactory,
    ));
    // ...and tenant and key rate limits.
    registry.register(Arc::new(
        proxy_filters::token_limit_filter::TokenLimitFilterFactory,
    ));
    let factory_ctx = FactoryContext::default();
    let mut filters = Vec::new();
    for f in hcm.http_filters.iter().filter(|f| !f.is_router) {
        let factory = registry
            .get(&f.type_url)
            .unwrap_or_else(|| panic!("no registered factory for `{}`", f.type_url));
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
    (handler, rx_a, rx_b)
}

fn json_post_request(body: &'static [u8], bearer: Option<&str>) -> HttpRequestParts {
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
    if let Some(key) = bearer {
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {key}")).unwrap(),
        );
    }
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

async fn send(handler: &FilterChainHandler, bearer: Option<&str>) -> StatusCode {
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        handler.handle(json_post_request(
            br#"{"model":"auto","messages":[]}"#,
            bearer,
        )),
    )
    .await
    .expect("request must complete");
    let status = resp.head.status;
    let _ = resp.body.collect().await;
    status
}

async fn received(rx: oneshot::Receiver<Captured>) -> Captured {
    let captured = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("upstream must be dialed")
        .expect("upstream task must report");
    assert_eq!(captured.content_length, captured.body.len());
    captured
}

fn assert_not_dialed(rx: &mut oneshot::Receiver<Captured>, which: &str) {
    assert!(
        rx.try_recv().is_err(),
        "provider {which} must not be dialed"
    );
}

// Rust note: current_thread + LocalSet because the router spawns a non-`Send`
// upstream connection driver with `spawn_local`.
#[tokio::test(flavor = "current_thread")]
async fn e2e_auto_without_auth_reaches_the_default_model() {
    LocalSet::new()
        .run_until(async {
            let (handler, rx_a, mut rx_b) = build_handler("auto:\n  default: fast\n").await;
            assert_eq!(send(&handler, None).await, StatusCode::OK);
            assert_eq!(received(rx_a).await.model(), "fast");
            assert_not_dialed(&mut rx_b, "b");
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_auto_with_auth_resolves_per_tenant() {
    LocalSet::new()
        .run_until(async {
            let extra = format!(
                "{}auto:\n  default: fast\n  tenants:\n    acme: smart\n",
                auth_block()
            );

            // acme has a rule: provider B, under B's own upstream model name.
            let (handler, mut rx_a, rx_b) = build_handler(&extra).await;
            assert_eq!(send(&handler, Some("llmp_acme-key")).await, StatusCode::OK);
            assert_eq!(received(rx_b).await.model(), "provider-smart-v2");
            assert_not_dialed(&mut rx_a, "a");

            // globex has none: falls back to the default, provider A.
            let (handler, rx_a, mut rx_b) = build_handler(&extra).await;
            assert_eq!(
                send(&handler, Some("llmp_globex-key")).await,
                StatusCode::OK
            );
            assert_eq!(received(rx_a).await.model(), "fast");
            assert_not_dialed(&mut rx_b, "b");
        })
        .await;
}
