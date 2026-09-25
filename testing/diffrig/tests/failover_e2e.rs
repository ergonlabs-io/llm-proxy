//! v0.1.0 ship-gate drill (third and last clause): "the proxy fails over
//! from one provider to another without dropping the request", per WP-35's
//! own acceptance criteria -- primary 429s, fallback within policy, exact
//! attempt accounting, and a credential-isolation test that is not optional
//! (see below). This is the end-to-end version: the real `llm-proxy`
//! binary, a real `llmproxy` dialect config with `fallbacks:`, real HTTP
//! over sockets. `crates/proxy-http/tests/router_aggregate.rs` covers the
//! same behavior at the router-unit level; this file proves it survives the
//! whole pipeline (dialect lowering, the strict Envoy loader, and the real
//! router) wired together.
//!
//! Structural sibling of `mock_e2e.rs`: same `dialect_config`/`spawn_suite`
//! shape, same shared machinery from `diffrig::harness`. Read that file
//! first if this one is unfamiliar.

use std::net::SocketAddr;
use std::time::Duration;

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, send_json_collect_sse, ProxyProcess, ScratchDir,
    READY_TIMEOUT,
};
use diffrig::upstreams::{OpenAiConfig, OpenAiUpstream};
use serde_json::json;

// ------------------------------------------------------------------ config --

/// How long the client waits for a response before failing the test outright
/// instead of hanging the whole suite. `mock_e2e.rs`/`tls_e2e.rs` send
/// unwrapped requests, and an unbounded wait there was the reason a hang in
/// eight tests turned a 79s workspace run into 656-863s (see
/// `ProxyProcess::wait_until_ready`'s doc comment) -- do not repeat that here.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

const PRIMARY_KEY: &str = "key-primary";
const STANDBY_KEY: &str = "key-standby";
const STANDBY_RESPONSE_TEXT: &str = "standby served this completion";

/// Render the dialect (`llmproxy-v0`) config: one listener, one route whose
/// provider is `primary` with `fallbacks: [standby]`. Neither provider is
/// named `openai`/`anthropic`, so both default to `openai-compatible`
/// (`Provider::effective_type`) -- same dialect on both sides, the only
/// shape a fallback chain is allowed to mix
/// (`crates/proxy-simple-config/tests/fallbacks.rs::cross_dialect_fallback_is_rejected`).
///
/// `standby`'s `base_url` deliberately addresses the upstream as `127.1`
/// (the old BSD numbers-and-dots shorthand for `127.0.0.1`), where
/// `primary`'s uses the canonical `127.0.0.1` -- both are numeric literals
/// the platform resolver expands locally with no DNS query and no
/// `/etc/hosts` dependency (unlike the hostname `localhost`, which this
/// machine's resolver returns as `::1` FIRST -- an early version of this
/// test used `localhost` and failed with "upstream connect failure" because
/// the standby mock only binds IPv4), so both land on the exact loopback
/// address the mocks are actually bound to. But `"127.1"` fails Rust's
/// `IpAddr::from_str` (`lower.rs::provider_upstream` checks that to choose
/// STATIC vs. LOGICAL_DNS discovery), so it is carried through as a literal
/// STRING distinct from `"127.0.0.1"` -- which is exactly what makes Test
/// 3's Host-header assertion mean anything: with both providers addressed
/// identically, a route-level rewrite pinned to the primary and a correctly
/// per-member-corrected one would be indistinguishable on the wire.
///
/// **Portability caveat, verified on macOS only.** The `127.1` shorthand is
/// resolved here by the platform's `getaddrinfo`, and glibc has tightened its
/// numeric-address parsing over the years (rejecting non-canonical dotted
/// forms in some versions). If this test ever fails on Linux with an upstream
/// connect error, THIS is why -- the fix is to find another pair of literals
/// that both reach the mock while remaining textually distinct, not to weaken
/// the assertion. The property under test (a per-attempt Host correction)
/// needs two distinguishable host strings; it does not care which two.
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
/// the leak "shows up twice" per the WP-35 acceptance criteria: once as this
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

/// WP-35's credential-isolation criterion, which its own acceptance text
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

/// WP-35 increment 2c: `host_rewrite_literal` on the route is set from the
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

/// WP-64/WP-65 acceptance seam: a primary 429 must fail over before any
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
