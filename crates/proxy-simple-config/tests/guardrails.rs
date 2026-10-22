//! The dialect `guardrails:` block: strict parsing with dialect paths, its
//! lowering to `llmproxy.guardrail` in chain order, and the default and
//! per-tenant checks end to end. The end-to-end tests run the real auth,
//! body_rewrite, model_authz, guardrail, spend and usage filters and the real
//! router against a mock provider and real HTTP check services, so a denial
//! is proven by what the provider never received.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

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
use tokio::sync::mpsc;
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

const SECRET: &str = "test-operator-secret";

/// `auth:` with one key per tenant; the plaintext key is `llmp_<tenant>-key`.
/// Neither tenant has a stored model policy, so the block opts them in; these
/// tests are about checks, not model grants.
fn auth_block() -> String {
    let acme = digest_hex(SECRET.as_bytes(), "llmp_acme-key");
    let globex = digest_hex(SECRET.as_bytes(), "llmp_globex-key");
    format!(
        "auth:\n  hmac_secret: \"{SECRET}\"\n  enforce: {{ tenants_without_policy: allow }}\n  keys:\n    \
         - {{ id: \"k1\", tenant: \"acme\", digest: \"{acme}\" }}\n    \
         - {{ id: \"k2\", tenant: \"globex\", digest: \"{globex}\" }}\n"
    )
}

/// A check block in flow style. `failure_mode` is spliced verbatim.
fn check(url: &str, failure_mode: &str) -> String {
    format!(
        "{{ http: {{ url: \"{url}\", timeout: 2s, max_body_bytes: 4096 }}, failure_mode: {failure_mode} }}"
    )
}

fn config_with(upstream: &str, extra: &str) -> String {
    format!(
        "version: 0\n\
         providers:\n  a: {{ base_url: \"http://{upstream}\" }}\n\
         routes:\n  - {{ model: \"*\", provider: a }}\n\
         {extra}"
    )
}

fn filters(bootstrap: &serde_json::Value) -> &Vec<serde_json::Value> {
    bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        ["http_filters"]
        .as_array()
        .expect("http_filters must be an array")
}

// --- lowering -----------------------------------------------------------------

#[test]
fn guardrails_lower_with_the_pinned_type_url_in_chain_order() {
    let text = config_with(
        "127.0.0.1:1",
        &format!(
            "{}auto:\n  default: gpt-4o\nlimits:\n  - {{ key: tenant, tokens_per_minute: 1000 }}\n\
             guardrails:\n  default: {}\n  tenants:\n    acme: {}\n",
            auth_block(),
            check("http://127.0.0.1:9/check", "closed"),
            check("https://guard.example/acme?token=t", "open"),
        ),
    );
    let bootstrap = lower(&parse(&text).expect("must parse"))
        .expect("must lower")
        .bootstrap;
    let filters = filters(&bootstrap);
    let names: Vec<&str> = filters
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    let at = |name: &str| names.iter().position(|n| *n == name).unwrap();
    let guardrail = at("llmproxy.guardrail");
    for before in [
        "llmproxy.auth",
        "llmproxy.body_rewrite",
        "llmproxy.model_resolver",
        "llmproxy.model_authz",
    ] {
        assert!(at(before) < guardrail, "{before} must precede: {names:?}");
    }
    for after in [
        "llmproxy.token_limit",
        "llmproxy.spend_limit",
        "llmproxy.usage",
    ] {
        assert!(guardrail < at(after), "{after} must follow: {names:?}");
    }
    let typed = &filters[guardrail]["typed_config"];
    assert_eq!(typed["@type"], proxy_filters::guardrail_filter::TYPE_URL);
    assert_eq!(
        typed["default_check"],
        serde_json::json!({
            "http": { "uri": "http://127.0.0.1:9/check", "timeout_ms": 2000, "max_body_bytes": 4096 },
            "failure_mode": "FAIL_CLOSED",
        })
    );
    assert_eq!(typed["tenants"][0]["tenant"], "acme");
    assert_eq!(typed["tenants"][0]["check"]["failure_mode"], "FAIL_OPEN");
    assert_eq!(
        typed["tenants"][0]["check"]["http"]["uri"],
        "https://guard.example/acme?token=t"
    );

    // The strict Envoy-mode loader accepts what the dialect emits.
    let loaded = lower_to_loaded(&parse(&text).unwrap()).expect("strict load");
    proxy_config::build_snapshot(&loaded).expect("must build IR");
}

#[test]
fn without_a_guardrails_block_no_guardrail_is_emitted() {
    let bootstrap = lower(&parse(&config_with("127.0.0.1:1", "")).unwrap())
        .unwrap()
        .bootstrap;
    assert!(filters(&bootstrap)
        .iter()
        .all(|f| f["name"] != "llmproxy.guardrail"));
}

#[test]
fn the_default_access_log_formats_carry_the_guardrail_outcome() {
    let text = config_with(
        "127.0.0.1:1",
        "observability:\n  access_logs: { output: stdout, format: json }\n",
    );
    let bootstrap = lower(&parse(&text).unwrap()).unwrap().bootstrap;
    assert!(bootstrap.to_string().contains("%LLM_GUARDRAIL%"));
    let text = config_with(
        "127.0.0.1:1",
        "observability:\n  access_logs: { output: stdout, format: text }\n",
    );
    let bootstrap = lower(&parse(&text).unwrap()).unwrap().bootstrap;
    assert!(bootstrap
        .to_string()
        .contains(r#"guardrail=\"%LLM_GUARDRAIL%\""#));
}

// --- strict errors ----------------------------------------------------------------

#[test]
fn each_invalid_guardrails_block_names_its_dialect_path() {
    let ok = check("http://127.0.0.1:9/check", "closed");
    let auth = auth_block();
    let cases: Vec<(String, &str)> = vec![
        ("guardrails: {}\n".into(), "guardrails.default"),
        (
            format!("guardrails:\n  default: {ok}\n  tenants:\n    acme: {ok}\n"),
            "guardrails.tenants",
        ),
        (
            format!("{auth}guardrails:\n  default: {ok}\n  tenants:\n    \"\": {ok}\n"),
            "guardrails.tenants",
        ),
        (
            "guardrails:\n  default: { failure_mode: closed }\n".into(),
            "guardrails.default",
        ),
        (
            "guardrails:\n  default: { http: { url: \"http://h/c\", timeout: 1s, max_body_bytes: 1 } }\n"
                .into(),
            "guardrails.default.failure_mode",
        ),
        (
            format!("guardrails:\n  default: {}\n", check("ftp://h/c", "closed")),
            "guardrails.default.http.url",
        ),
        (
            format!("guardrails:\n  default: {}\n", check("http://u:p@h/c", "closed")),
            "guardrails.default.http.url",
        ),
        (
            format!("guardrails:\n  default: {}\n", check("http:///c", "closed")),
            "guardrails.default.http.url",
        ),
        (
            "guardrails:\n  default: { http: { url: \"http://h/c\", max_body_bytes: 1 }, failure_mode: open }\n"
                .into(),
            "guardrails.default.http.timeout",
        ),
        (
            "guardrails:\n  default: { http: { url: \"http://h/c\", timeout: 0ms, max_body_bytes: 1 }, failure_mode: open }\n"
                .into(),
            "guardrails.default.http.timeout",
        ),
        (
            "guardrails:\n  default: { http: { url: \"http://h/c\", timeout: 1s, max_body_bytes: 0 }, failure_mode: open }\n"
                .into(),
            "guardrails.default.http.max_body_bytes",
        ),
        (
            format!(
                "{auth}guardrails:\n  default: {ok}\n  tenants:\n    acme: {}\n",
                check("http://h/c", "sideways")
            ),
            "guardrails.tenants.acme.failure_mode",
        ),
        (
            format!(
                "{auth}guardrails:\n  default: {ok}\n  tenants:\n    acme: {{ failure_mode: open }}\n"
            ),
            "guardrails.tenants.acme",
        ),
    ];
    for (extra, path) in cases {
        let err = parse(&config_with("127.0.0.1:1", &extra))
            .err()
            .unwrap_or_else(|| panic!("must not load:\n{extra}"));
        let field_path = match &err {
            ConfigError::InvalidValue { field_path, .. } => field_path,
            other => panic!("expected InvalidValue for\n{extra}\ngot {other:?}"),
        };
        assert_eq!(field_path, path, "{extra}\n{err:?}");
    }
}

#[test]
fn an_unknown_field_is_rejected_with_its_dotted_path() {
    let ok = check("http://127.0.0.1:9/check", "closed");
    let auth = auth_block();
    for (extra, path) in [
        (
            format!("guardrails:\n  default: {ok}\n  redact: true\n"),
            "guardrails.redact",
        ),
        (
            "guardrails:\n  default: { http: { url: \"http://h/c\", timeout: 1s, max_body_bytes: 1, retries: 2 }, failure_mode: open }\n"
                .to_string(),
            "guardrails.default.http.retries",
        ),
        (
            format!(
                "{auth}guardrails:\n  default: {ok}\n  tenants:\n    acme: {{ grpc: {{}}, failure_mode: open }}\n"
            ),
            "guardrails.tenants.acme.grpc",
        ),
    ] {
        match parse(&config_with("127.0.0.1:1", &extra)) {
            Err(ConfigError::UnknownField { field_path, .. }) => {
                assert_eq!(field_path, path, "{extra}")
            }
            other => panic!("expected UnknownField for\n{extra}\ngot {other:?}"),
        }
    }
}

#[test]
fn a_duplicate_tenant_is_a_parse_error() {
    let ok = check("http://127.0.0.1:9/check", "closed");
    let err = parse(&config_with(
        "127.0.0.1:1",
        &format!(
            "{}guardrails:\n  default: {ok}\n  tenants:\n    acme: {ok}\n    acme: {ok}\n",
            auth_block()
        ),
    ))
    .unwrap_err();
    assert!(
        format!("{err:?}").contains("duplicate `guardrails.tenants` entry `acme`"),
        "{err:?}"
    );
}

// --- end to end ---------------------------------------------------------------------

/// A provider that answers every request and reports each body it received.
async fn spawn_provider() -> (SocketAddr, mpsc::UnboundedReceiver<Vec<u8>>) {
    spawn_server(|_| {
        let body = r#"{"id":"x","object":"chat.completion","model":"gpt-4o","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
        body.to_string()
    })
    .await
}

/// A check that denies a body containing `needle` and allows any other.
async fn spawn_check(needle: &'static str) -> (SocketAddr, mpsc::UnboundedReceiver<Vec<u8>>) {
    spawn_server(move |payload| {
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap();
        if doc["body"].as_str().unwrap_or_default().contains(needle) {
            format!(r#"{{"decision":"deny","reason":"contains {needle}"}}"#)
        } else {
            r#"{"decision":"allow"}"#.to_string()
        }
    })
    .await
}

/// An HTTP/1.1 server answering 200 with `answer(body)` per request and
/// reporting every body on the channel; an empty channel proves it was never
/// asked.
async fn spawn_server(
    answer: impl Fn(&[u8]) -> String + Clone + Send + 'static,
) -> (SocketAddr, mpsc::UnboundedReceiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let tx = tx.clone();
            let answer = answer.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head_end, length) = loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
                        let length = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (i + 4, length);
                    }
                };
                while buf.len() < head_end + length {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let body = buf[head_end..head_end + length].to_vec();
                let reply = answer(&body);
                let _ = tx.send(body);
                let _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                            reply.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    (addr, rx)
}

/// A real handler from a dialect config: every filter the dialect emits, then
/// the router.
async fn build_handler(text: &str) -> FilterChainHandler {
    let config = parse(text).expect("must parse");
    let loaded = lower_to_loaded(&config).expect("must lower and validate");
    let snapshot = proxy_config::build_snapshot(&loaded).expect("must build IR");
    let cluster_manager = Arc::new(ClusterManager::with_default_transport(Arc::new(
        FakeResolver::new(),
    )));
    let rejected = cluster_manager
        .update_from_snapshot(&snapshot.clusters)
        .await;
    assert!(rejected.is_empty(), "{rejected:?}");
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
    registry.register(Arc::new(proxy_filters::auth_filter::AuthFilterFactory));
    registry.register(Arc::new(
        proxy_filters::model_authz_filter::ModelAuthzFilterFactory,
    ));
    registry.register(Arc::new(
        proxy_filters::spend_limit_filter::SpendLimitFilterFactory,
    ));
    registry.register(Arc::new(
        proxy_filters::token_limit_filter::TokenLimitFilterFactory,
    ));
    registry.register(Arc::new(
        proxy_filters::object_ownership_filter::ObjectOwnershipFilterFactory,
    ));
    registry.register(Arc::new(
        proxy_filters::guardrail_filter::GuardrailFilterFactory,
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
    assert!(
        filters.iter().any(|f| f.name == "llmproxy.guardrail"),
        "the chain under test must contain the guardrail"
    );

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
    FilterChainHandler::new_with_filters(
        filters,
        terminal_factory,
        hcm.route_table.clone(),
        hcm.generate_request_id,
        hcm.use_remote_address,
        hcm.xff_num_trusted_hops,
    )
    .expect("filter chain must build")
}

/// A chat request whose prompt is `prompt`; headers are the same for every
/// prompt, so only the body can trigger a denial.
async fn chat(handler: &FilterChainHandler, key: &str, prompt: &str) -> (StatusCode, String) {
    let body = Bytes::from(format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{prompt}"}}]}}"#
    ));
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
    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {key}")).unwrap(),
    );
    let request = HttpRequestParts {
        head: RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
            headers,
        },
        body: local_boxed(
            Full::new(body).map_err(|infallible: std::convert::Infallible| match infallible {}),
        ),
        downstream: DownstreamInfo::loopback(),
        on_upgrade: None,
    };
    let resp = tokio::time::timeout(Duration::from_secs(10), handler.handle(request))
        .await
        .expect("request must complete");
    let status = resp.head.status;
    let body = resp.body.collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// Every body the server has reported so far.
fn drain(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(body) = rx.try_recv() {
        out.push(String::from_utf8_lossy(&body).into_owned());
    }
    out
}

// Rust note: current_thread + LocalSet because the router spawns a non-`Send`
// upstream connection driver with `spawn_local`.
#[tokio::test(flavor = "current_thread")]
async fn e2e_the_default_and_a_tenant_override_each_deny_on_body_content() {
    LocalSet::new()
        .run_until(async {
            let (provider, mut provider_rx) = spawn_provider().await;
            let (default_check, mut default_rx) = spawn_check("forbidden").await;
            let (acme_check, mut acme_rx) = spawn_check("acme-secret").await;
            let text = config_with(
                &provider.to_string(),
                &format!(
                    "{}guardrails:\n  default: {}\n  tenants:\n    acme: {}\n",
                    auth_block(),
                    check(&format!("http://{default_check}/check"), "closed"),
                    check(&format!("http://{acme_check}/check"), "closed"),
                ),
            );
            let handler = build_handler(&text).await;

            // globex has no entry: the default check denies `forbidden`.
            let (status, body) = chat(&handler, "llmp_globex-key", "say forbidden").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            assert!(body.contains("contains forbidden"), "{body}");
            assert!(
                drain(&mut provider_rx).is_empty(),
                "a denied request is never dialled"
            );
            let seen = drain(&mut default_rx);
            assert_eq!(seen.len(), 1);
            let payload: serde_json::Value = serde_json::from_str(&seen[0]).unwrap();
            assert_eq!(payload["tenant"], "globex");
            assert_eq!(payload["requested_model"], "gpt-4o");
            assert!(payload["body"].as_str().unwrap().contains("say forbidden"));
            assert!(drain(&mut acme_rx).is_empty());

            // ...and allows the acme-only phrase, which reaches the provider.
            let (status, body) = chat(&handler, "llmp_globex-key", "acme-secret").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(drain(&mut provider_rx).len(), 1);
            assert_eq!(drain(&mut default_rx).len(), 1);

            // acme's override replaces the default: `forbidden` passes...
            let (status, body) = chat(&handler, "llmp_acme-key", "say forbidden").await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(drain(&mut provider_rx).len(), 1);
            assert!(
                drain(&mut default_rx).is_empty(),
                "acme never uses the default"
            );
            assert_eq!(drain(&mut acme_rx).len(), 1);

            // ...and its own phrase is denied before any provider is dialled.
            let (status, body) = chat(&handler, "llmp_acme-key", "the acme-secret").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            assert!(body.contains("contains acme-secret"), "{body}");
            assert!(
                drain(&mut provider_rx).is_empty(),
                "a denied request is never dialled"
            );
            assert_eq!(drain(&mut acme_rx).len(), 1);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_an_unauthenticated_request_is_refused_before_the_check_sees_it() {
    LocalSet::new()
        .run_until(async {
            let (provider, mut provider_rx) = spawn_provider().await;
            let (check_addr, mut check_rx) = spawn_check("never").await;
            let text = config_with(
                &provider.to_string(),
                &format!(
                    "{}guardrails:\n  default: {}\n",
                    auth_block(),
                    check(&format!("http://{check_addr}/check"), "closed"),
                ),
            );
            let handler = build_handler(&text).await;

            let (status, _) = chat(&handler, "llmp_nobody-key", "hello").await;

            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert!(
                drain(&mut check_rx).is_empty(),
                "no prompt is disclosed unauthenticated"
            );
            assert!(drain(&mut provider_rx).is_empty());
        })
        .await;
}
