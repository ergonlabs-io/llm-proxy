//! Exercises provider failover, attempt accounting, and credential isolation
//! through the real binary and dialect config.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, send_json_collect_sse, ProxyProcess, ScratchDir,
    READY_TIMEOUT,
};
use diffrig::upstreams::{OpenAiConfig, OpenAiUpstream};
use serde_json::json;
use serde_json::Value;

// ------------------------------------------------------------------ config --

/// Bounds client waits so a stalled request fails instead of hanging the suite.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

const PRIMARY_KEY: &str = "key-primary";
const STANDBY_KEY: &str = "key-standby";
const STANDBY_RESPONSE_TEXT: &str = "standby served this completion";
const CLIENT_KEY: &str = "llmp_fallback-billing-key";
const CLIENT_KEY_ID: &str = "fallback-billing-key";
const HMAC_SECRET: &str = "fallback-billing-hmac-secret";
const ADMIN_TOKEN: &str = "fallback-billing-admin-token";

/// Renders a same-dialect fallback config. `127.1` and `127.0.0.1` both
/// resolve to loopback here but remain distinct host strings, allowing the test
/// to verify per-member Host rewriting. The shorthand may not resolve on all
/// platforms; preserve distinct loopback host strings if changing it.
fn dialect_config(listener_port: u16, primary_port: u16, standby_port: u16) -> String {
    format!(
        r#"
version: 0
listen: "127.0.0.1:{listener_port}"
providers:
  primary:
    base_url: "http://127.0.0.1:{primary_port}"
    api_key: "{PRIMARY_KEY}"
  standby:
    base_url: "http://127.1:{standby_port}"
    api_key: "{STANDBY_KEY}"
routes:
  - model: "gpt-*"
    provider: primary
    fallbacks: [standby]
models:
  gpt-4o-mini:
    providers:
      - {{ provider: primary, model: primary-upstream-model }}
      - {{ provider: standby, model: standby-upstream-model }}
"#
    )
}

fn digest_hex(secret: &str, plaintext_key: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let digest = ring::hmac::sign(&key, plaintext_key.as_bytes());
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn billing_dialect_config(
    listener_port: u16,
    admin_port: u16,
    primary_port: u16,
    standby_port: u16,
    access_log: &Path,
) -> String {
    let digest = digest_hex(HMAC_SECRET, CLIENT_KEY);
    format!(
        r#"
version: 0
listen: "127.0.0.1:{listener_port}"
admin: "127.0.0.1:{admin_port}"
auth:
  hmac_secret: "{HMAC_SECRET}"
  enforce: {{ tenants_without_policy: allow }}
  keys:
    - {{ id: "{CLIENT_KEY_ID}", tenant: tenant-a, digest: "{digest}" }}
providers:
  openai:
    base_url: "http://127.0.0.1:{primary_port}"
    api_key: "{PRIMARY_KEY}"
  standby:
    base_url: "http://127.1:{standby_port}"
    api_key: "{STANDBY_KEY}"
routes:
  - model: "gpt-*"
    provider: openai
    fallbacks: [standby]
models:
  gpt-4o-mini:
    providers:
      - {{ provider: openai, model: primary-upstream-model }}
      - {{ provider: standby, model: standby-upstream-model }}
pricing:
  price_list:
    version: fallback-card
    effective_from: "2026-01-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: primary-upstream-model
        tier_mode: whole_request
        tiers:
          - {{ input_nanodollars_per_token: 1000000000, cached_input_nanodollars_per_token: 0, cache_write_nanodollars_per_token: 0, output_nanodollars_per_token: 1000000000 }}
      - provider_type: openai-compatible
        model: standby-upstream-model
        tier_mode: whole_request
        tiers:
          - {{ input_nanodollars_per_token: 2000000000, cached_input_nanodollars_per_token: 0, cache_write_nanodollars_per_token: 0, output_nanodollars_per_token: 3000000000 }}
observability:
  force_usage_reporting: true
  access_logs:
    output: "{}"
    format: text
"#,
        access_log.display()
    )
}

// ----------------------------------------------------------------- helpers --

/// Every request 429s, and only `PRIMARY_KEY` is accepted -- so a request
/// that somehow reaches this mock with the standby's key would also be
/// rejected before `forced_error` is even relevant, though `forced_error` is
/// checked first (see `handle_openai`) and so is what a real failover
/// actually observes here.
fn primary_config() -> OpenAiConfig {
    OpenAiConfig {
        model: "gpt-mock".to_string(),
        response_text: "primary's text -- must never reach the client".to_string(),
        ttft: Duration::from_millis(1),
        inter_token_delay: Duration::from_millis(1),
        require_api_key: Some(PRIMARY_KEY.to_string()),
        forced_error: Some((429, "mock upstream is rate limited".to_string())),
        cached_tokens: 0,
    }
}

/// Serves normally, and only accepts `STANDBY_KEY` -- a request carrying the
/// primary's key (a credential-isolation leak) would 401 here, which is why
/// the leak "shows up twice" per the acceptance criteria: once as this
/// 401, and once in Test 2's explicit negative assertion.
fn standby_config() -> OpenAiConfig {
    OpenAiConfig {
        model: "gpt-mock".to_string(),
        response_text: STANDBY_RESPONSE_TEXT.to_string(),
        ttft: Duration::from_millis(1),
        inter_token_delay: Duration::from_millis(1),
        require_api_key: Some(STANDBY_KEY.to_string()),
        forced_error: None,
        cached_tokens: 0,
    }
}

/// Spawn `primary` (429s every request) and `standby` (serves normally)
/// plus the real proxy wired to both via the dialect's `fallbacks:`. Guards
/// are returned so the caller controls drop order (proxy first, then the
/// mocks), same convention as `mock_e2e.rs::spawn_suite`.
async fn spawn_suite(
    label: &str,
) -> (
    SocketAddr,
    OpenAiUpstream,
    OpenAiUpstream,
    ScratchDir,
    ProxyProcess,
) {
    let primary = OpenAiUpstream::spawn(primary_config())
        .await
        .expect("spawn primary mock");
    let standby = OpenAiUpstream::spawn(standby_config())
        .await
        .expect("spawn standby mock");

    let scratch = ScratchDir::new(label);
    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_yaml = dialect_config(listener_port, primary.addr().port(), standby.addr().port());
    let config_path = scratch.write("llmproxy.yaml", &config_yaml);

    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyProcess::spawn(&bin, &config_path, &scratch.path().join("proxy.log"));
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);

    (listener_addr, primary, standby, scratch, proxy)
}

async fn spawn_billing_suite(
    label: &str,
) -> (
    SocketAddr,
    SocketAddr,
    OpenAiUpstream,
    OpenAiUpstream,
    PathBuf,
    ScratchDir,
    ProxyProcess,
) {
    let primary = OpenAiUpstream::spawn(primary_config())
        .await
        .expect("spawn primary mock");
    let standby = OpenAiUpstream::spawn(standby_config())
        .await
        .expect("spawn standby mock");
    let scratch = ScratchDir::new(label);
    let listener_port = free_port();
    let admin_port = free_port();
    let listener_addr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let admin_addr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    let access_log = scratch.path().join("access.log");
    let dialect = billing_dialect_config(
        listener_port,
        admin_port,
        primary.port(),
        standby.port(),
        &access_log,
    );
    let simple = proxy_simple_config::parse_simple_config(&dialect).expect("parse billing config");
    let mut bootstrap = proxy_simple_config::lower(&simple)
        .expect("lower billing config")
        .bootstrap;

    bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"]["access_log"][0]["typed_config"]["log_format"] = json!({
        "text_format": "%UPSTREAM_CLUSTER% %LLM_INPUT_TOKENS% %LLM_OUTPUT_TOKENS% %LLM_LIST_COST% %LLM_KEY_ID% %LLM_TENANT% %LLM_USER_ID% %LLM_REQUESTED_MODEL% %LLM_SELECTED_MODEL% %LLM_RATE_CARD_VERSION% %RESPONSE_CODE%\n"
    });

    let config_yaml = serde_yaml::to_string(&bootstrap).expect("serialize bootstrap");
    let config_path = scratch.write("envoy.yaml", &config_yaml);
    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyProcess::spawn_envoy_with_env(
        &bin,
        &config_path,
        &scratch.path().join("proxy.log"),
        &[("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)],
    );
    proxy.wait_until_ready(admin_addr, READY_TIMEOUT);
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);
    (
        listener_addr,
        admin_addr,
        primary,
        standby,
        access_log,
        scratch,
        proxy,
    )
}

async fn admin_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &Value,
) -> diffrig::harness::RawResponse {
    let bearer = format!("Bearer {ADMIN_TOKEN}");
    tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json(addr, method, path, &[("authorization", &bearer)], body),
    )
    .await
    .expect("admin request timed out")
}

fn read_access_log(path: &Path) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Some(line) = text.lines().find(|line| !line.trim().is_empty()) {
                return line.to_string();
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no access-log line appeared at {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn chat_request_body() -> serde_json::Value {
    json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi there"}],
    })
}

/// Send one non-streaming chat completion through the proxy, bounded by
/// [`CLIENT_TIMEOUT`] so a stuck failover fails this test instead of hanging
/// the suite.
async fn send_chat_request(listener_addr: SocketAddr) -> diffrig::harness::RawResponse {
    tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json(
            listener_addr,
            "POST",
            "/v1/chat/completions",
            &[("x-llmproxy-model", "gpt-4o-mini")],
            &chat_request_body(),
        ),
    )
    .await
    .expect("client request timed out -- failover hung instead of completing or failing")
}

/// Send a streaming chat completion through the fallback chain. The helper
/// collects SSE events incrementally, so the acceptance test below proves the
/// selected standby response remains streamable after the primary 429s.
async fn send_streaming_chat_request(
    listener_addr: SocketAddr,
) -> (u16, Vec<diffrig::harness::TimedEvent>) {
    let body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi there"}],
        "stream": true,
    });
    let (status, _headers, events) = tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json_collect_sse(
            listener_addr,
            "POST",
            "/v1/chat/completions",
            &[("x-llmproxy-model", "gpt-4o-mini")],
            &body,
        ),
    )
    .await
    .expect("streaming client request timed out -- fallback hung");
    (status, events)
}

// -------------------------------------------------------------------- tests --

/// The primary 429s, the proxy fails over to the standby within policy, and
/// the client sees a normal 200 carrying the STANDBY's canned response --
/// never the primary's text, never the 429 itself. Attempt accounting is
/// exact: each upstream is dialed exactly once, proving there is no
/// double-dialling of either member.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failover_completes_the_request_on_the_standby_when_primary_429s() {
    let (listener_addr, primary, standby, scratch, proxy) = spawn_suite("failover-completes").await;

    let res = send_chat_request(listener_addr).await;

    assert_eq!(
        res.status, 200,
        "expected the standby's 200 after failover, got {}: {}",
        res.status, res.body
    );
    let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json");
    assert_eq!(
        parsed["choices"][0]["message"]["content"], STANDBY_RESPONSE_TEXT,
        "expected the standby's canned response, got a different body (primary's text or an \
         error envelope) -- full response: {parsed}"
    );

    assert_eq!(
        primary.log.requests().len(),
        1,
        "primary must be tried exactly once before failing over"
    );
    assert_eq!(
        standby.log.requests().len(),
        1,
        "standby must serve exactly once -- attempt accounting exact, no double-dialling"
    );

    drop(proxy);
    primary.shutdown().await;
    standby.shutdown().await;
    drop(scratch);
}

/// The credential-isolation criterion, which its own acceptance text
/// marks as "not optional": a request that fails over from the primary to
/// the standby must carry the STANDBY's `Authorization` and must NOT carry
/// the PRIMARY's. The negative is asserted explicitly and separately from
/// the positive -- a positive-only check ("the standby's key is present")
/// passes just as well if both keys were sent, which is exactly the leak
/// this criterion exists to catch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failover_carries_the_standbys_credential_and_never_the_primarys() {
    let (listener_addr, primary, standby, scratch, proxy) =
        spawn_suite("failover-credentials").await;

    let res = send_chat_request(listener_addr).await;
    assert_eq!(
        res.status, 200,
        "sanity: failover must succeed before credentials can be inspected, got {}: {}",
        res.status, res.body
    );

    let requests = standby.log.requests();
    let received = requests
        .last()
        .expect("standby must have received a request");

    // Positive: the standby's OWN key arrived.
    assert!(
        received
            .headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("authorization")
                && v == &format!("Bearer {STANDBY_KEY}")),
        "expected `authorization: Bearer {STANDBY_KEY}` at the standby, got: {:?}",
        received.headers
    );

    // Negative, asserted explicitly and separately, per the acceptance
    // criteria: the PRIMARY's key must appear nowhere -- not in
    // `authorization`, not smuggled into any other header -- in what the
    // standby received. Note `standby_config`'s `require_api_key` already
    // fails a leaked-primary-key request with 401 (so the `assert_eq!(res.status,
    // 200, ...)` sanity check above would already have caught it), but this
    // assertion states the property directly and survives someone removing
    // `require_api_key` from the fixture later.
    let leaked = received
        .headers
        .iter()
        .any(|(_, v)| v.contains(PRIMARY_KEY));
    assert!(
        !leaked,
        "the primary's key (`{PRIMARY_KEY}`) leaked into a header the standby received: {:?}",
        received.headers
    );

    let body = standby
        .bodies
        .bodies()
        .last()
        .cloned()
        .expect("standby must have received a parsed chat body");
    assert_eq!(
        body["model"], "standby-upstream-model",
        "fallback must rewrite the logical alias to the selected provider's model: {body}"
    );

    drop(proxy);
    primary.shutdown().await;
    standby.shutdown().await;
    drop(scratch);
}

/// `host_rewrite_literal` on the route is set from the
/// PRIMARY (the route has no way to know which member will actually serve a
/// given attempt), so the per-cluster header mutation is what corrects the
/// `Host` header to the member that actually dialled -- here, `standby`.
/// Without that correction, a failover would silently carry the primary's
/// Host to the standby.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failover_rewrites_host_to_the_member_that_served() {
    let (listener_addr, primary, standby, scratch, proxy) =
        spawn_suite("failover-host-rewrite").await;

    let res = send_chat_request(listener_addr).await;
    assert_eq!(
        res.status, 200,
        "sanity: failover must succeed before the Host header can be inspected, got {}: {}",
        res.status, res.body
    );

    let requests = standby.log.requests();
    let received = requests
        .last()
        .expect("standby must have received a request");
    let host = received
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str());

    // The standby's OWN host (`dialect_config`'s doc comment explains why
    // `127.1` and `127.0.0.1` are used as two distinguishable strings that
    // both reach the same loopback mocks).
    assert_eq!(
        host,
        Some("127.1"),
        "expected the standby's own host (`127.1`) on the request it received, got: {:?}",
        received.headers
    );
    // Asserted explicitly and separately, same reasoning as Test 2's
    // credential negative: a route-level rewrite that was never corrected
    // per attempted member would still carry the PRIMARY's host here.
    assert_ne!(
        host,
        Some("127.0.0.1"),
        "the primary's host leaked into the request the standby received -- \
         host_rewrite_literal was never corrected per attempted member"
    );

    drop(proxy);
    primary.shutdown().await;
    standby.shutdown().await;
    drop(scratch);
}

/// Acceptance seam: a primary 429 must fail over before any
/// response bytes are emitted, and the selected standby must still deliver a
/// genuine multi-frame SSE response. This guards the no-restart-after-stream
/// boundary while the existing auth/spend E2E covers key attribution.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failover_preserves_streaming_on_the_selected_standby() {
    let (listener_addr, primary, standby, scratch, proxy) = spawn_suite("failover-streaming").await;

    let (status, events) = send_streaming_chat_request(listener_addr).await;

    assert_eq!(status, 200, "standby streaming response: {status}");
    assert!(
        events.len() >= 3,
        "expected a role frame, content frame, and terminal frame from standby; got {}",
        events.len()
    );
    assert!(
        events.iter().any(|event| event
            .data
            .contains(STANDBY_RESPONSE_TEXT.split_whitespace().next().unwrap())),
        "standby response text must appear in the streamed events: {:?}",
        events.iter().map(|event| &event.data).collect::<Vec<_>>()
    );
    assert_eq!(primary.log.requests().len(), 1);
    assert_eq!(standby.log.requests().len(), 1);
    assert_eq!(standby.bodies.bodies()[0]["stream"], true);

    drop(proxy);
    primary.shutdown().await;
    standby.shutdown().await;
    drop(scratch);
}

/// Joined acceptance: the authenticated key survives a
/// primary 429, the streamed standby usage is charged to that stable key at
/// the standby cluster's price, and the immutable list-price record uses the
/// selected provider's rate-card entry/version.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_streaming_fallback_charges_the_key_at_the_standby_price() {
    let (listener, admin, primary, standby, access_log, scratch, proxy) =
        spawn_billing_suite("fallback-billing").await;

    let budget = admin_request(
        admin,
        "PUT",
        &format!("/keys/{CLIENT_KEY_ID}/budget"),
        &json!({ "budget": { "max_usd": "100.00", "period": "daily" } }),
    )
    .await;
    assert_eq!(budget.status, 204, "set key budget: {}", budget.body);

    let body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi there"}],
        "stream": true,
    });
    let bearer = format!("Bearer {CLIENT_KEY}");
    let (status, _, events) = tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json_collect_sse(
            listener,
            "POST",
            "/v1/chat/completions",
            &[
                ("authorization", &bearer),
                ("x-llmproxy-model", "gpt-4o-mini"),
            ],
            &body,
        ),
    )
    .await
    .expect("authenticated streaming fallback timed out");
    assert_eq!(status, 200);
    assert!(events.iter().any(|event| event.data.contains("standby")));
    assert_eq!(primary.log.requests().len(), 1);
    assert_eq!(standby.log.requests().len(), 1);
    assert_eq!(
        standby.bodies.bodies()[0]["model"],
        "standby-upstream-model"
    );

    let spend = admin_request(
        admin,
        "GET",
        &format!("/keys/{CLIENT_KEY_ID}/spend"),
        &json!({}),
    )
    .await;
    assert_eq!(spend.status, 200, "read key spend: {}", spend.body);
    let spend_json: Value = serde_json::from_str(&spend.body).expect("spend JSON");
    assert_eq!(
        spend_json["spend_micro_usd"], 16_000_000,
        "2 input tokens at $2/token plus 4 standby output tokens at $3/token"
    );

    let line = read_access_log(&access_log);
    let fields: Vec<_> = line.split_whitespace().collect();
    let card = fields.get(9).expect("immutable rate-card version");
    let digest = card
        .strip_prefix("fallback-card+")
        .expect("configured card name and content digest");
    assert_eq!(digest.len(), 12);
    assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        line,
        format!(
            "provider:standby 2 4 16000000000 {CLIENT_KEY_ID} tenant-a {CLIENT_KEY_ID} gpt-4o-mini standby-upstream-model {card} 200"
        ),
        "selected cluster, terminal token usage, immutable list cost, and the key as the user"
    );

    drop(proxy);
    primary.shutdown().await;
    standby.shutdown().await;
    drop(scratch);
}

// ------------------------------------------------- reload during a retry --

const STANDBY_V2_KEY: &str = "key-replacement";
const STANDBY_V1_TEXT: &str = "standby generation one";
const STANDBY_V2_TEXT: &str = "standby generation two";
const RELOAD_TIMEOUT: Duration = Duration::from_secs(10);

/// The fallback chain with the standby's endpoint, key and upstream model
/// passed in, so a reload can replace all three at once.
fn reload_config(
    listener_port: u16,
    primary_port: u16,
    standby_port: u16,
    standby_key: &str,
    standby_model: &str,
) -> String {
    format!(
        r#"
version: 0
listen: "127.0.0.1:{listener_port}"
providers:
  primary:
    base_url: "http://127.0.0.1:{primary_port}"
    api_key: "{PRIMARY_KEY}"
  standby:
    base_url: "http://127.0.0.1:{standby_port}"
    api_key: "{standby_key}"
routes:
  - model: "gpt-*"
    provider: primary
    fallbacks: [standby]
models:
  gpt-4o-mini:
    providers:
      - {{ provider: primary, model: primary-upstream-model }}
      - {{ provider: standby, model: {standby_model} }}
"#
    )
}

fn standby_generation(key: &str, text: &str) -> OpenAiConfig {
    OpenAiConfig {
        require_api_key: Some(key.to_string()),
        response_text: text.to_string(),
        ..standby_config()
    }
}

/// A primary that answers 429 to every request, but holds the first one
/// until the test releases it. That parks one request between its primary
/// attempt and its failover for as long as the test needs.
struct GatedPrimary {
    addr: SocketAddr,
    arrived: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl GatedPrimary {
    async fn spawn() -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gated primary");
        let addr = listener.local_addr().expect("gated primary addr");
        let arrived = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let seen = Arc::new(AtomicUsize::new(0));
        let (arrived_task, release_task) = (Arc::clone(&arrived), Arc::clone(&release));
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let (arrived, release, seen) = (
                    Arc::clone(&arrived_task),
                    Arc::clone(&release_task),
                    Arc::clone(&seen),
                );
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let (arrived, release, seen) = (
                                Arc::clone(&arrived),
                                Arc::clone(&release),
                                Arc::clone(&seen),
                            );
                            async move {
                                use http_body_util::BodyExt;
                                let _ = req.into_body().collect().await;
                                if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                                    // `notify_one` stores a permit, so neither side
                                    // can miss the other's signal.
                                    arrived.notify_one();
                                    release.notified().await;
                                }
                                let body =
                                    r#"{"error":{"message":"rate limited","type":"rate_limit"}}"#;
                                Ok::<_, std::convert::Infallible>(
                                    hyper::Response::builder()
                                        .status(429)
                                        .header("content-type", "application/json")
                                        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
                                        .expect("static 429 response"),
                                )
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            addr,
            arrived,
            release,
            task,
        }
    }
}

impl Drop for GatedPrimary {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn carries_bearer(headers: &[(String, String)], key: &str) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("authorization") && value == &format!("Bearer {key}")
    })
}

fn mentions(headers: &[(String, String)], key: &str) -> bool {
    headers.iter().any(|(_, value)| value.contains(key))
}

/// A SIGHUP that replaces the standby's endpoint, key and upstream model
/// while a request sits between its primary attempt and its failover. The
/// request fails over within the routing generation its connection was built
/// with: the old standby, with the old standby's key and model, and nothing
/// from the new generation. Mixing generations would send the new key to the
/// old endpoint, or the old key or model to the new one.
///
/// The order is fixed by signals, not sleeps: the request is parked at the
/// primary before the reload, and is released only after a fresh request has
/// been served by the new standby. That fresh request is the negative
/// control: it proves the new generation was live while the parked request
/// retried, so the old-generation answer is not a reload that never applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_during_failover_keeps_the_retry_on_its_own_generation() {
    let primary = GatedPrimary::spawn().await;
    let standby_v1 = OpenAiUpstream::spawn(standby_generation(STANDBY_KEY, STANDBY_V1_TEXT))
        .await
        .expect("spawn first standby");
    let standby_v2 = OpenAiUpstream::spawn(standby_generation(STANDBY_V2_KEY, STANDBY_V2_TEXT))
        .await
        .expect("spawn second standby");

    let scratch = ScratchDir::new("failover-reload");
    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_path = scratch.write(
        "llmproxy.yaml",
        &reload_config(
            listener_port,
            primary.addr.port(),
            standby_v1.addr().port(),
            STANDBY_KEY,
            "standby-upstream-model",
        ),
    );
    let mut proxy = ProxyProcess::spawn(
        &resolve_llm_proxy_bin(),
        &config_path,
        &scratch.path().join("proxy.log"),
    );
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);

    let parked = tokio::spawn(send_chat_request(listener_addr));
    tokio::time::timeout(CLIENT_TIMEOUT, primary.arrived.notified())
        .await
        .expect("the first request never reached the primary");

    scratch.write(
        "llmproxy.yaml",
        &reload_config(
            listener_port,
            primary.addr.port(),
            standby_v2.addr().port(),
            STANDBY_V2_KEY,
            "standby-upstream-model-v2",
        ),
    );
    proxy.sighup();
    proxy.wait_for_log("SIGHUP: config reload succeeded", RELOAD_TIMEOUT);

    // Workers pick up a published snapshot asynchronously, so a connection
    // opened right after the log line may still be built on the old one.
    let deadline = std::time::Instant::now() + RELOAD_TIMEOUT;
    loop {
        let res = send_chat_request(listener_addr).await;
        assert_eq!(res.status, 200, "fresh request: {}", res.body);
        if res.body.contains(STANDBY_V2_TEXT) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no fresh connection reached the new standby after the reload"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        !parked.is_finished(),
        "the parked request must still be waiting on the primary"
    );
    let v1_before = standby_v1.log.requests().len();
    let v2_before = standby_v2.log.requests().len();

    primary.release.notify_one();
    let res = tokio::time::timeout(CLIENT_TIMEOUT, parked)
        .await
        .expect("the parked request never completed")
        .expect("parked request task");

    assert_eq!(res.status, 200, "parked request: {}", res.body);
    let parsed: Value = serde_json::from_str(&res.body).expect("valid json");
    assert_eq!(
        parsed["choices"][0]["message"]["content"], STANDBY_V1_TEXT,
        "the retry must fail over to its own generation's standby"
    );
    assert_eq!(
        standby_v2.log.requests().len(),
        v2_before,
        "the retry must not dial the new generation's standby"
    );
    let v1_requests = standby_v1.log.requests();
    assert_eq!(v1_requests.len(), v1_before + 1, "one failover attempt");
    let received = &v1_requests.last().unwrap().headers;
    assert!(
        carries_bearer(received, STANDBY_KEY),
        "old standby must get its own key: {received:?}"
    );
    assert!(
        !mentions(received, STANDBY_V2_KEY) && !mentions(received, PRIMARY_KEY),
        "no other key may reach the old standby: {received:?}"
    );
    assert_eq!(
        standby_v1.bodies.bodies().last().unwrap()["model"],
        "standby-upstream-model",
        "the retry must use its own generation's upstream model"
    );
    for request in standby_v2.log.requests() {
        assert!(
            !mentions(&request.headers, STANDBY_KEY),
            "the old standby's key reached the new standby: {:?}",
            request.headers
        );
    }
    assert!(standby_v2
        .bodies
        .bodies()
        .iter()
        .all(|body| body["model"] == "standby-upstream-model-v2"));

    drop(proxy);
    drop(primary);
    standby_v1.shutdown().await;
    standby_v2.shutdown().await;
    drop(scratch);
}

/// One downstream HTTP/1.1 connection kept open across requests, so a test
/// can hold a connection accepted before a reload.
struct KeptAliveConnection {
    sender: hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
    /// Resolves when the connection ends.
    driver: tokio::task::JoinHandle<()>,
}

impl KeptAliveConnection {
    async fn open(addr: SocketAddr) -> Self {
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to proxy");
        let (sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .expect("http1 handshake");
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        Self { sender, driver }
    }

    async fn send_chat(&mut self) -> diffrig::harness::RawResponse {
        use http_body_util::BodyExt;
        let request = hyper::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("host", "proxy")
            .header("content-type", "application/json")
            .header("x-llmproxy-model", "gpt-4o-mini")
            .body(http_body_util::Full::new(bytes::Bytes::from(
                chat_request_body().to_string(),
            )))
            .expect("build request");
        let exchange = async {
            // hyper's http1 client goes back to ready only after its connection
            // task has finished the previous exchange; sending before that
            // fails with `Canceled, "connection was not ready"`.
            self.sender.ready().await.expect("connection ready");
            let response = self
                .sender
                .send_request(request)
                .await
                .expect("send request");
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or_default().to_string()))
                .collect();
            let body = response
                .into_body()
                .collect()
                .await
                .expect("collect body")
                .to_bytes();
            diffrig::harness::RawResponse {
                status,
                headers,
                body: String::from_utf8_lossy(&body).to_string(),
            }
        };
        tokio::time::timeout(CLIENT_TIMEOUT, exchange)
            .await
            .expect("kept-alive request timed out")
    }
}

/// [`reload_config`] with `request_headers_timeout` disabled. That timer also
/// closes an idle keep-alive connection (envoy-divergences.md, row 16), which
/// would close the pre-reload connection whether or not the reload did.
fn keepalive_reload_config(
    listener_port: u16,
    primary_port: u16,
    standby_port: u16,
    standby_key: &str,
    standby_model: &str,
) -> String {
    let short = format!("listen: \"127.0.0.1:{listener_port}\"");
    let config = reload_config(
        listener_port,
        primary_port,
        standby_port,
        standby_key,
        standby_model,
    );
    assert!(
        config.contains(&short),
        "reload_config changed its listen line"
    );
    config.replace(
        &short,
        &format!(
            "listen: {{ address: \"127.0.0.1:{listener_port}\", request_headers_timeout: 0s }}"
        ),
    )
}

/// A SIGHUP that rotates the standby's key (and replaces its endpoint and
/// upstream model) while an idle keep-alive connection accepted before the
/// reload stays open. The proxy must close that connection, so the client's
/// next request goes out on a new connection with the new key, and the old
/// key is never sent again. A connection that kept its accept-time generation
/// would keep using a rotated or revoked provider key for as long as the
/// client held it open.
///
/// The close is awaited before anything else is sent, so no request races
/// the reload. A request already in flight at the reload finishes on its own
/// generation; `a_reload_during_failover_keeps_the_retry_on_its_own_generation`
/// covers that.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_closes_kept_alive_connections_so_a_rotated_key_is_not_sent() {
    let primary = OpenAiUpstream::spawn(primary_config())
        .await
        .expect("spawn primary");
    let standby_v1 = OpenAiUpstream::spawn(standby_generation(STANDBY_KEY, STANDBY_V1_TEXT))
        .await
        .expect("spawn first standby");
    let standby_v2 = OpenAiUpstream::spawn(standby_generation(STANDBY_V2_KEY, STANDBY_V2_TEXT))
        .await
        .expect("spawn second standby");

    let scratch = ScratchDir::new("keepalive-reload");
    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_path = scratch.write(
        "llmproxy.yaml",
        &keepalive_reload_config(
            listener_port,
            primary.addr().port(),
            standby_v1.addr().port(),
            STANDBY_KEY,
            "standby-upstream-model",
        ),
    );
    let mut proxy = ProxyProcess::spawn(
        &resolve_llm_proxy_bin(),
        &config_path,
        &scratch.path().join("proxy.log"),
    );
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);

    let mut kept = KeptAliveConnection::open(listener_addr).await;
    let before = kept.send_chat().await;
    assert_eq!(before.status, 200, "first request: {}", before.body);
    assert!(before.body.contains(STANDBY_V1_TEXT), "{}", before.body);
    // The negative control: with no reload the connection stays usable.
    let again = kept.send_chat().await;
    assert!(again.body.contains(STANDBY_V1_TEXT), "{}", again.body);
    let v1_before = standby_v1.log.requests().len();

    scratch.write(
        "llmproxy.yaml",
        &keepalive_reload_config(
            listener_port,
            primary.addr().port(),
            standby_v2.addr().port(),
            STANDBY_V2_KEY,
            "standby-upstream-model-v2",
        ),
    );
    proxy.sighup();
    proxy.wait_for_log("SIGHUP: config reload succeeded", RELOAD_TIMEOUT);

    tokio::time::timeout(RELOAD_TIMEOUT, &mut kept.driver)
        .await
        .expect("the proxy kept the pre-reload connection open")
        .expect("connection driver task");
    assert!(kept.sender.is_closed());

    // The client's next request, on the connection it must now open.
    let mut reconnected = KeptAliveConnection::open(listener_addr).await;
    let after = reconnected.send_chat().await;

    assert_eq!(
        after.status, 200,
        "request after the reload: {}",
        after.body
    );
    assert!(after.body.contains(STANDBY_V2_TEXT), "{}", after.body);
    assert_eq!(
        standby_v1.log.requests().len(),
        v1_before,
        "the old standby (old key) was dialled after the reload"
    );
    let v2_requests = standby_v2.log.requests();
    assert_eq!(v2_requests.len(), 1, "one request to the new standby");
    let received = &v2_requests[0].headers;
    assert!(
        carries_bearer(received, STANDBY_V2_KEY),
        "the new standby must get the rotated key: {received:?}"
    );
    assert!(
        !mentions(received, STANDBY_KEY),
        "the rotated-out key reached the new standby: {received:?}"
    );
    assert_eq!(
        standby_v2.bodies.bodies()[0]["model"],
        "standby-upstream-model-v2",
        "the request after the reload must use the new upstream model"
    );

    drop(reconnected);
    drop(proxy);
    primary.shutdown().await;
    standby_v1.shutdown().await;
    standby_v2.shutdown().await;
    drop(scratch);
}
