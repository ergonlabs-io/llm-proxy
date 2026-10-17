//! Exercises provider failover, attempt accounting, and credential isolation
//! through the real binary and dialect config.

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
            "provider:standby 2 4 16000000000 {CLIENT_KEY_ID} tenant-a - gpt-4o-mini standby-upstream-model {card} 200"
        ),
        "selected cluster, terminal token usage, and immutable list cost"
    );

    drop(proxy);
    primary.shutdown().await;
    standby.shutdown().await;
    drop(scratch);
}
