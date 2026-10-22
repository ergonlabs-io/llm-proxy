//! Exercises the admin API and data plane through a real proxy process and sockets.
//! The admin token is set only in the child environment. Requests are bounded and
//! tests use ephemeral ports because worktrees share machine ports (AGENTS.md "Build And Test").
//!
//! The filter chain follows `check_lane_h_filter_order`. Each exchange costs
//! $1.00: the mock receives one input token and returns one output token, each
//! priced at 500,000 micro-dollars.
//!
//! `a_tenant_policy_write_changes_model_authorization_live` also records a known
//! defect: model authorization currently denies requests in a real filter chain.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, ProxyProcess, RawResponse, ScratchDir,
    READY_TIMEOUT,
};
use diffrig::upstreams::{OpenAiConfig, OpenAiUpstream};
use serde_json::{json, Value};

// ------------------------------------------------------------------ config --

/// Bounds each data-plane or admin request.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`admin_request_retrying`] will retry a `503` "not initialized
/// yet" boot-race response before giving up -- see that function's doc.
const BOOT_RACE_TIMEOUT: Duration = Duration::from_secs(5);

/// Test-only HMAC secret; tests verify minted plaintext keys, not this value.
const HMAC_SECRET: &str = "wp-50-admin-e2e-hmac-secret-never-reused-elsewhere";

/// `LLMPROXY_ADMIN_TOKEN`'s configured value for tests that need the write
/// API enabled.
const ADMIN_TOKEN: &str = "wp-50-admin-e2e-bearer-token-never-reused-elsewhere";
/// A syntactically fine, definitely-wrong bearer token -- exercises Gate 2
/// (`admin/src/server.rs`'s `handle`) without ever matching [`ADMIN_TOKEN`].
const WRONG_ADMIN_TOKEN: &str = "wp-50-admin-e2e-WRONG-bearer-token";

/// Provider credential injected by cluster metadata (AGENTS.md invariant 6).
const PROVIDER_KEY: &str = "sk-real-provider-credential-admin-e2e";

/// A model priced (see the module doc) and, in
/// [`a_tenant_policy_write_changes_model_authorization_live`], the one
/// pattern a restrictive tenant policy allows.
const MODEL_ALLOWED: &str = "gpt-allowed";
/// Priced identically to [`MODEL_ALLOWED`], but never named in that test's
/// allow-list -- the model a restrictive policy must refuse.
const MODEL_DENIED: &str = "gpt-denied";

/// The mock upstream: requires the PROVIDER credential (never a virtual key
/// or the admin token) and always replies with the single-word completion
/// `"ok"`, per the module doc's token math.
fn upstream_config() -> OpenAiConfig {
    OpenAiConfig {
        model: "gpt-mock".to_string(),
        response_text: "ok".to_string(),
        ttft: Duration::from_millis(1),
        inter_token_delay: Duration::from_millis(1),
        require_api_key: Some(PROVIDER_KEY.to_string()),
        forced_error: None,
        cached_tokens: 0,
    }
}

fn chat_request_body(model: &str) -> Value {
    json!({
        "model": model,
        "messages": [{"role": "user", "content": "hi"}],
    })
}

/// Renders the test bootstrap. The filter order satisfies
/// `check_lane_h_filter_order`; virtual keys are minted through the admin API.
/// `with_model_authz` enables the filter for the policy test, which documents
/// its current decode-phase defect.
fn single_chain_config(
    listener_port: u16,
    admin_port: u16,
    upstream_port: u16,
    with_model_authz: bool,
) -> String {
    let model_authz_filter = if with_model_authz {
        r#"          - name: llmproxy.model_authz
            typed_config:
              '@type': type.llmproxy.dev/llmproxy.filters.v0.ModelAuthz
              policies: []
"#
    } else {
        ""
    };
    format!(
        r#"
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin_port} }}
static_resources:
  clusters:
  - connect_timeout: 5s
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: provider:p1
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: {upstream_port}
    metadata:
      filter_metadata:
        io.llmproxy.provider_auth:
          headers:
          - key: authorization
            value: Bearer {PROVIDER_KEY}
          - key: host
            value: 127.0.0.1
    name: provider:p1
    type: STATIC
  listeners:
  - address:
      socket_address:
        address: 127.0.0.1
        port_value: {listener_port}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          http_filters:
          - name: llmproxy.auth
            typed_config:
              '@type': type.llmproxy.dev/llmproxy.filters.v0.Authentication
              hmac_secret:
                inline_string: "{HMAC_SECRET}"
              virtual_keys: []
          - name: llmproxy.body_rewrite
            typed_config:
              '@type': type.llmproxy.dev/envoy.config.core.v3.RuntimeFeatureFlag
              default_value: true
              runtime_key: openai
{model_authz_filter}          - name: llmproxy.spend_limit
            typed_config:
              '@type': type.llmproxy.dev/llmproxy.filters.v0.SpendLimit
              # Tests here set tenant budgets at runtime; the admin API refuses
              # that unless the filter sets the cutover, because the next start
              # would otherwise refuse the stored budget.
              legacy_tenant_budget_cutover: START_KEYS_FRESH
          - name: llmproxy.usage
            typed_config:
              '@type': type.llmproxy.dev/llmproxy.filters.v0.Usage
              dialect: openai
              # $0.50 per token in and out on provider:p1.
              pricing_json: '{{"price_list":{{"effective_from":"2026-01-01T00:00:00Z","entries":[{{"provider_type":"p1","model":"{MODEL_ALLOWED}","tier_mode":"whole_request","tiers":[{{"input_nanodollars_per_token":500000000,"cached_input_nanodollars_per_token":0,"cache_write_nanodollars_per_token":0,"output_nanodollars_per_token":500000000}}]}},{{"provider_type":"p1","model":"{MODEL_DENIED}","tier_mode":"whole_request","tiers":[{{"input_nanodollars_per_token":500000000,"cached_input_nanodollars_per_token":0,"cache_write_nanodollars_per_token":0,"output_nanodollars_per_token":500000000}}]}}]}},"providers":{{"provider:p1":"p1"}}}}'
          - name: envoy.filters.http.router
            typed_config:
              '@type': type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          route_config:
            name: llmproxy_routes
            virtual_hosts:
            - domains:
              - '*'
              name: llmproxy
              routes:
              - match:
                  prefix: /
                route:
                  cluster: provider:p1
                  host_rewrite_literal: 127.0.0.1
                  idle_timeout: 90s
                  retry_policy:
                    num_retries: 1
                    retriable_status_codes:
                    - 429
                    - 500
                    - 502
                    - 503
                    retry_on: connect-failure,refused-stream,reset,retriable-status-codes
                  timeout: 0s
                typed_per_filter_config:
                  llmproxy.body_rewrite:
                    '@type': type.llmproxy.dev/envoy.config.core.v3.RuntimeFeatureFlag
                    default_value: true
                    runtime_key: openai
                  llmproxy.usage:
                    '@type': type.llmproxy.dev/llmproxy.filters.v0.Usage
                    dialect: openai
          stat_prefix: llmproxy
    name: llmproxy_listener
"#
    )
}

/// Renders two auth chains with separate scopes for scoped/unscoped API checks.
/// Both listeners share one cluster and mock upstream.
fn two_chain_config(
    listener_a_port: u16,
    listener_b_port: u16,
    admin_port: u16,
    upstream_port: u16,
) -> String {
    format!(
        r#"
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin_port} }}
static_resources:
  clusters:
  - connect_timeout: 5s
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: provider:p1
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: {upstream_port}
    metadata:
      filter_metadata:
        io.llmproxy.provider_auth:
          headers:
          - key: authorization
            value: Bearer {PROVIDER_KEY}
          - key: host
            value: 127.0.0.1
    name: provider:p1
    type: STATIC
  listeners:
  - address:
      socket_address:
        address: 127.0.0.1
        port_value: {listener_a_port}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          http_filters:
          - name: llmproxy.auth
            typed_config:
              '@type': type.llmproxy.dev/llmproxy.filters.v0.Authentication
              hmac_secret:
                inline_string: "{HMAC_SECRET}"
              virtual_keys: []
          - name: envoy.filters.http.router
            typed_config:
              '@type': type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          route_config:
            name: chain_a_routes
            virtual_hosts:
            - domains:
              - '*'
              name: chain_a
              routes:
              - match:
                  prefix: /
                route:
                  cluster: provider:p1
                  host_rewrite_literal: 127.0.0.1
                  timeout: 0s
          stat_prefix: chain-a
    name: chain_a_listener
  - address:
      socket_address:
        address: 127.0.0.1
        port_value: {listener_b_port}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          http_filters:
          - name: llmproxy.auth
            typed_config:
              '@type': type.llmproxy.dev/llmproxy.filters.v0.Authentication
              hmac_secret:
                inline_string: "{HMAC_SECRET}"
              virtual_keys: []
          - name: envoy.filters.http.router
            typed_config:
              '@type': type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          route_config:
            name: chain_b_routes
            virtual_hosts:
            - domains:
              - '*'
              name: chain_b
              routes:
              - match:
                  prefix: /
                route:
                  cluster: provider:p1
                  host_rewrite_literal: 127.0.0.1
                  timeout: 0s
          stat_prefix: chain-b
    name: chain_b_listener
"#
    )
}

// ----------------------------------------------------------------- helpers --

/// Starts the proxy and mock upstream, setting the admin token only in the child
/// environment. Returns addresses and resource guards.
async fn spawn_suite(
    label: &str,
    admin_token: Option<&str>,
    with_model_authz: bool,
) -> (
    SocketAddr,
    SocketAddr,
    OpenAiUpstream,
    ScratchDir,
    ProxyProcess,
) {
    let upstream = OpenAiUpstream::spawn(upstream_config())
        .await
        .expect("spawn mock upstream");

    let scratch = ScratchDir::new(label);
    let listener_port = free_port();
    let admin_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    let config_yaml =
        single_chain_config(listener_port, admin_port, upstream.port(), with_model_authz);
    let config_path = scratch.write("envoy.yaml", &config_yaml);

    let envs: Vec<(&str, &str)> = admin_token
        .map(|token| vec![("LLMPROXY_ADMIN_TOKEN", token)])
        .unwrap_or_default();

    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyProcess::spawn_envoy_with_env(
        &bin,
        &config_path,
        &scratch.path().join("proxy.log"),
        &envs,
    );
    // The admin listener binds before workers, so it is ready first.
    proxy.wait_until_ready(admin_addr, READY_TIMEOUT);
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);

    (listener_addr, admin_addr, upstream, scratch, proxy)
}

/// Spawns the mock upstream plus the real proxy against [`two_chain_config`],
/// for [`the_admin_api_requires_a_scope_when_multiple_auth_chains_exist`]
/// only. `LLMPROXY_ADMIN_TOKEN` is always set -- that test's subject is
/// scoped-vs-unscoped addressing, not the token gate, which the other tests
/// in this file already cover.
async fn spawn_two_chain_suite(
    label: &str,
) -> (
    SocketAddr,
    SocketAddr,
    SocketAddr,
    OpenAiUpstream,
    ScratchDir,
    ProxyProcess,
) {
    let upstream = OpenAiUpstream::spawn(upstream_config())
        .await
        .expect("spawn mock upstream");

    let scratch = ScratchDir::new(label);
    let listener_a_port = free_port();
    let listener_b_port = free_port();
    let admin_port = free_port();
    let listener_a_addr: SocketAddr = format!("127.0.0.1:{listener_a_port}").parse().unwrap();
    let listener_b_addr: SocketAddr = format!("127.0.0.1:{listener_b_port}").parse().unwrap();
    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    let config_yaml = two_chain_config(
        listener_a_port,
        listener_b_port,
        admin_port,
        upstream.port(),
    );
    let config_path = scratch.write("envoy.yaml", &config_yaml);

    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyProcess::spawn_envoy_with_env(
        &bin,
        &config_path,
        &scratch.path().join("proxy.log"),
        &[("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)],
    );
    proxy.wait_until_ready(admin_addr, READY_TIMEOUT);
    proxy.wait_until_ready(listener_a_addr, READY_TIMEOUT);
    proxy.wait_until_ready(listener_b_addr, READY_TIMEOUT);

    (
        listener_a_addr,
        listener_b_addr,
        admin_addr,
        upstream,
        scratch,
        proxy,
    )
}

/// Send one chat-completion request through the DATA PLANE, bounded by
/// [`CLIENT_TIMEOUT`] -- see `auth_e2e.rs`'s identical helper.
async fn send_chat_request(addr: SocketAddr, headers: &[(&str, &str)], model: &str) -> RawResponse {
    tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json(
            addr,
            "POST",
            "/v1/chat/completions",
            headers,
            &chat_request_body(model),
        ),
    )
    .await
    .expect(
        "data-plane request timed out -- an auth/authz/spend decision hung instead of completing",
    )
}

/// Sends an admin request with an optional bearer token, bounded by the timeout.
async fn admin_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &Value,
) -> RawResponse {
    let bearer = token.map(|t| format!("Bearer {t}"));
    let mut headers: Vec<(&str, &str)> = Vec::new();
    if let Some(bearer) = &bearer {
        headers.push(("authorization", bearer.as_str()));
    }
    tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json(addr, method, path, &headers, body),
    )
    .await
    .expect("admin request timed out -- an admin write hung instead of completing")
}

/// Retries only the boot-race 503 until the control plane is available.
async fn admin_request_retrying(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &Value,
) -> RawResponse {
    let deadline = Instant::now() + BOOT_RACE_TIMEOUT;
    loop {
        let res = admin_request(addr, method, path, token, body).await;
        let is_boot_race = res.status == 503 && res.body.contains("not initialized yet");
        if !is_boot_race || Instant::now() >= deadline {
            return res;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn parse_json(body: &str) -> Value {
    serde_json::from_str(body)
        .unwrap_or_else(|err| panic!("expected a JSON response body, got {body:?}: {err}"))
}

// -------------------------------------------------------------------- tests --

/// 1a. The gate is wired at all: with `LLMPROXY_ADMIN_TOKEN` UNSET in the
/// spawned process, a write endpoint returns 403 and the body names the env
/// var an operator must set. This is the fail-CLOSED path getting its own
/// test (AGENTS.md "Fail-open controls") -- nothing about "admin write endpoints are
/// disabled" is visible anywhere else in this suite.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_write_endpoints_are_forbidden_when_the_token_env_var_is_unset() {
    let (_listener_addr, admin_addr, upstream, scratch, proxy) =
        spawn_suite("admin-token-unset", None, false).await;

    let res = admin_request(
        admin_addr,
        "POST",
        "/tenants",
        None,
        &json!({ "tenant": "tenant-a" }),
    )
    .await;

    assert_eq!(
        res.status, 403,
        "an admin write must be refused when LLMPROXY_ADMIN_TOKEN was never set, got {}: {}",
        res.status, res.body
    );
    assert!(
        res.body.contains("LLMPROXY_ADMIN_TOKEN"),
        "the 403 body must name the env var an operator needs to set, got: {}",
        res.body
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

/// 1b. With `LLMPROXY_ADMIN_TOKEN` set, a wrong bearer token gets 401; the
/// correct one succeeds. Both against the SAME running process, so this is
/// also proof the gate distinguishes "disabled" (1a) from "enabled, wrong
/// credential" from "enabled, right credential" -- three different reasons a
/// write could fail or succeed, never conflated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_write_endpoints_401_on_wrong_token_then_succeed_on_correct_token() {
    let (_listener_addr, admin_addr, upstream, scratch, proxy) =
        spawn_suite("admin-token-wrong-then-right", Some(ADMIN_TOKEN), false).await;

    let wrong = admin_request(
        admin_addr,
        "POST",
        "/tenants",
        Some(WRONG_ADMIN_TOKEN),
        &json!({ "tenant": "tenant-a" }),
    )
    .await;
    assert_eq!(
        wrong.status, 401,
        "a wrong bearer token must be refused, got {}: {}",
        wrong.status, wrong.body
    );
    assert!(
        wrong.headers.iter().any(
            |(name, value)| name.eq_ignore_ascii_case("www-authenticate")
                && value.eq_ignore_ascii_case("Bearer")
        ),
        "a 401 must carry the RFC 7235 www-authenticate challenge, got: {:?}",
        wrong.headers
    );

    let ok = admin_request_retrying(
        admin_addr,
        "POST",
        "/tenants",
        Some(ADMIN_TOKEN),
        &json!({ "tenant": "tenant-a" }),
    )
    .await;
    assert_eq!(
        ok.status, 201,
        "the correct bearer token must be admitted, got {}: {}",
        ok.status, ok.body
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

/// 2. A key minted THROUGH ADMIN authenticates a real data-plane request end
/// to end; a well-formed key that was never minted is rejected. This is the
/// wiring assertion no unit test can make -- it needs the plaintext admin
/// mints to actually flow into the SAME `ControlPlane` the running auth
/// filter reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_minted_key_authenticates_traffic_and_an_unminted_key_is_rejected() {
    let (listener_addr, admin_addr, upstream, scratch, proxy) =
        spawn_suite("admin-mint-key", Some(ADMIN_TOKEN), false).await;

    let tenant = admin_request_retrying(
        admin_addr,
        "POST",
        "/tenants",
        Some(ADMIN_TOKEN),
        &json!({ "tenant": "tenant-a" }),
    )
    .await;
    assert_eq!(
        tenant.status, 201,
        "sanity: tenant creation must succeed before a key can be minted for it, got {}: {}",
        tenant.status, tenant.body
    );

    let minted = admin_request_retrying(
        admin_addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        &json!({ "tenant": "tenant-a", "key_id": "laptop" }),
    )
    .await;
    assert_eq!(
        minted.status, 201,
        "minting a key must succeed, got {}: {}",
        minted.status, minted.body
    );
    let minted_key = parse_json(&minted.body)["key"]
        .as_str()
        .expect("POST /keys must return the plaintext key exactly once")
        .to_string();

    let admitted = send_chat_request(
        listener_addr,
        &[("authorization", &format!("Bearer {minted_key}"))],
        MODEL_ALLOWED,
    )
    .await;
    assert_eq!(
        admitted.status, 200,
        "a key minted through the admin API must authenticate a real request, got {}: {}",
        admitted.status, admitted.body
    );
    assert_eq!(
        upstream.log.requests().len(),
        1,
        "the admitted request must actually have reached the upstream"
    );

    let denied = send_chat_request(
        listener_addr,
        &[("authorization", "Bearer llmp_this-key-was-never-minted")],
        MODEL_ALLOWED,
    )
    .await;
    assert_eq!(
        denied.status, 401,
        "a well-formed but never-minted key must be refused, got {}: {}",
        denied.status, denied.body
    );
    assert_eq!(
        upstream.log.requests().len(),
        1,
        "the refused request must never have reached the upstream"
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

/// 3. `DELETE /keys/{id}` takes effect on the VERY NEXT request -- no
/// reload, no restart. Mints a key, uses it once successfully, revokes it
/// through admin, then re-sends the IDENTICAL request and asserts it is now
/// refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_a_key_takes_effect_on_the_very_next_request() {
    let (listener_addr, admin_addr, upstream, scratch, proxy) =
        spawn_suite("admin-revoke-key", Some(ADMIN_TOKEN), false).await;

    let minted = admin_request_retrying(
        admin_addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        &json!({ "tenant": "tenant-a", "key_id": "revoke-me" }),
    )
    .await;
    assert_eq!(
        minted.status, 201,
        "minting a key must succeed, got {}: {}",
        minted.status, minted.body
    );
    let minted_key = parse_json(&minted.body)["key"]
        .as_str()
        .expect("POST /keys must return the plaintext key")
        .to_string();
    let headers = [("authorization", format!("Bearer {minted_key}"))];
    let header_pairs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();

    let before = send_chat_request(listener_addr, &header_pairs, MODEL_ALLOWED).await;
    assert_eq!(
        before.status, 200,
        "sanity: the key must authenticate before it is revoked, got {}: {}",
        before.status, before.body
    );
    assert_eq!(upstream.log.requests().len(), 1);

    let revoked = admin_request_retrying(
        admin_addr,
        "DELETE",
        "/keys/revoke-me",
        Some(ADMIN_TOKEN),
        &json!({}),
    )
    .await;
    assert_eq!(
        revoked.status, 204,
        "revoking an existing key must succeed with 204, got {}: {}",
        revoked.status, revoked.body
    );

    let after = send_chat_request(listener_addr, &header_pairs, MODEL_ALLOWED).await;
    assert_eq!(
        after.status, 401,
        "the SAME key must be refused on the very next request after revocation, with no \
         reload and no restart -- got {}: {}",
        after.status, after.body
    );
    assert_eq!(
        upstream.log.requests().len(),
        1,
        "the revoked, refused request must never have reached the upstream"
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

/// 4. A policy write should affect the next request without reload. This test
/// currently exposes a decode-phase defect: `model_authz` reads
/// `requested_model` during `decode_headers`, before `body_rewrite` writes it
/// during `decode_data`. Filter phases run globally, so changing filter order
/// cannot resolve this dependency. Unit tests miss it because their callbacks
/// set the model directly instead of driving the real filter manager.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tenant_policy_write_changes_model_authorization_live() {
    let (listener_addr, admin_addr, upstream, scratch, proxy) =
        spawn_suite("admin-tenant-policy", Some(ADMIN_TOKEN), true).await;

    admin_request_retrying(
        admin_addr,
        "POST",
        "/tenants",
        Some(ADMIN_TOKEN),
        &json!({ "tenant": "tenant-a" }),
    )
    .await;
    let minted = admin_request_retrying(
        admin_addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        &json!({ "tenant": "tenant-a", "key_id": "policy-key" }),
    )
    .await;
    assert_eq!(
        minted.status, 201,
        "sanity: minting must succeed: {}",
        minted.body
    );
    let minted_key = parse_json(&minted.body)["key"]
        .as_str()
        .expect("POST /keys must return the plaintext key")
        .to_string();
    let headers = [("authorization", format!("Bearer {minted_key}"))];
    let header_pairs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();

    // No policy stored yet: the tenant is refused (a tenant without a model
    // policy is denied by default).
    let unconfigured = send_chat_request(listener_addr, &header_pairs, MODEL_DENIED).await;
    assert_eq!(
        unconfigured.status, 403,
        "with no policy stored, the tenant must be refused (default deny), got {}: {}",
        unconfigured.status, unconfigured.body
    );

    // Baseline: an `all` policy permits every model -- including the one the
    // policy write below is about to deny. Asserting this first is what
    // proves the LATER denial is caused by the write, not by something else
    // about this model name.
    let all = admin_request_retrying(
        admin_addr,
        "PUT",
        "/tenants/tenant-a/policy",
        Some(ADMIN_TOKEN),
        &json!({ "access": "all" }),
    )
    .await;
    assert_eq!(all.status, 204, "PUT all policy: {}", all.body);
    let baseline = send_chat_request(listener_addr, &header_pairs, MODEL_DENIED).await;
    assert_eq!(
        baseline.status, 200,
        "sanity: an `all` policy must permit every model, got {}: {}",
        baseline.status, baseline.body
    );

    let policy = admin_request_retrying(
        admin_addr,
        "PUT",
        "/tenants/tenant-a/policy",
        Some(ADMIN_TOKEN),
        &json!({ "access": { "only": [MODEL_ALLOWED] } }),
    )
    .await;
    assert_eq!(
        policy.status, 204,
        "setting a tenant's policy must succeed, got {}: {}",
        policy.status, policy.body
    );

    let denied = send_chat_request(listener_addr, &header_pairs, MODEL_DENIED).await;
    assert_eq!(
        denied.status, 403,
        "the VERY NEXT request for a now-denied model must be refused, with no reload -- \
         got {}: {}",
        denied.status, denied.body
    );

    let allowed = send_chat_request(listener_addr, &header_pairs, MODEL_ALLOWED).await;
    assert_eq!(
        allowed.status, 200,
        "a model the new policy DOES allow must still be permitted, got {}: {}",
        allowed.status, allowed.body
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_policy_narrows_its_tenant_grant_and_never_widens_it() {
    let (listener, admin, upstream, scratch, proxy) =
        spawn_suite("admin-key-policy", Some(ADMIN_TOKEN), true).await;

    let tenant = admin_request_retrying(
        admin,
        "POST",
        "/tenants",
        Some(ADMIN_TOKEN),
        &json!({ "tenant": "tenant-a" }),
    )
    .await;
    assert_eq!(tenant.status, 201, "POST /tenants: {}", tenant.body);

    let mut keys = Vec::new();
    for id in ["k1", "k2", "k3"] {
        let minted = admin_request_retrying(
            admin,
            "POST",
            "/keys",
            Some(ADMIN_TOKEN),
            &json!({ "tenant": "tenant-a", "key_id": id }),
        )
        .await;
        assert_eq!(minted.status, 201, "POST /keys for {id}: {}", minted.body);
        keys.push(format!(
            "Bearer {}",
            parse_json(&minted.body)["key"]
                .as_str()
                .expect("POST /keys returns the plaintext key")
        ));
    }

    for (path, policy) in [
        (
            "/tenants/tenant-a/policy",
            json!({ "access": { "only": ["gpt-4*", "claude-a"] } }),
        ),
        (
            "/keys/k1/policy",
            json!({ "access": { "only": ["gpt-4o"] } }),
        ),
        (
            "/keys/k2/policy",
            json!({ "access": { "only": ["claude-b"] } }),
        ),
    ] {
        let response = admin_request_retrying(admin, "PUT", path, Some(ADMIN_TOKEN), &policy).await;
        assert_eq!(response.status, 204, "PUT {path}: {}", response.body);
    }

    let listed = admin_request_retrying(admin, "GET", "/keys", Some(ADMIN_TOKEN), &json!({})).await;
    assert_eq!(listed.status, 200, "GET /keys: {}", listed.body);
    let listing = parse_json(&listed.body);
    let entries = listing["keys"].as_array().expect("GET /keys returns keys");
    let k1 = entries
        .iter()
        .find(|key| key["key_id"] == "k1")
        .expect("K1 listed");
    let k3 = entries
        .iter()
        .find(|key| key["key_id"] == "k3")
        .expect("K3 listed");
    assert_eq!(k1["policy"], json!({ "access": { "only": ["gpt-4o"] } }));
    assert_eq!(k3["policy"], Value::Null);

    let admitted = send_chat_request(listener, &[("authorization", &keys[0])], "gpt-4o").await;
    assert_eq!(admitted.status, 200, "K1 gpt-4o: {}", admitted.body);
    assert_eq!(upstream.log.requests().len(), 1);

    let denied = send_chat_request(listener, &[("authorization", &keys[0])], "claude-a").await;
    assert_eq!(denied.status, 403, "K1 claude-a: {}", denied.body);
    assert_eq!(
        upstream.log.requests().len(),
        1,
        "K1 denial reached upstream"
    );

    let denied = send_chat_request(listener, &[("authorization", &keys[1])], "claude-b").await;
    assert_eq!(denied.status, 403, "K2 claude-b: {}", denied.body);
    assert_eq!(
        upstream.log.requests().len(),
        1,
        "K2 denial reached upstream"
    );

    let inherited = send_chat_request(listener, &[("authorization", &keys[2])], "claude-a").await;
    assert_eq!(inherited.status, 200, "K3 claude-a: {}", inherited.body);
    assert_eq!(upstream.log.requests().len(), 2);

    let all = admin_request_retrying(
        admin,
        "PUT",
        "/keys/k1/policy",
        Some(ADMIN_TOKEN),
        &json!({ "access": "all" }),
    )
    .await;
    assert_eq!(all.status, 204, "PUT K1 all: {}", all.body);
    let now_admitted =
        send_chat_request(listener, &[("authorization", &keys[0])], "claude-a").await;
    assert_eq!(
        now_admitted.status, 200,
        "K1 claude-a after PUT: {}",
        now_admitted.body
    );
    assert_eq!(upstream.log.requests().len(), 3);

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

/// 5. A $1.50 budget admits two $1 exchanges, then refuses the third; spend
/// reporting and rate-limit headers use micro-dollars.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tenant_budget_aggregates_multiple_keys_and_enforces_both_scopes() {
    let (listener, admin, upstream, scratch, proxy) =
        spawn_suite("admin-tenant-budget", Some(ADMIN_TOKEN), false).await;
    assert_eq!(
        admin_request_retrying(
            admin,
            "POST",
            "/tenants",
            Some(ADMIN_TOKEN),
            &json!({"tenant":"aggregate-tenant"})
        )
        .await
        .status,
        201
    );
    let mut credentials = Vec::new();
    for id in ["aggregate-a", "aggregate-b"] {
        let minted = admin_request_retrying(
            admin,
            "POST",
            "/keys",
            Some(ADMIN_TOKEN),
            &json!({"tenant":"aggregate-tenant","key_id":id}),
        )
        .await;
        assert_eq!(minted.status, 201);
        credentials.push(format!(
            "Bearer {}",
            parse_json(&minted.body)["key"].as_str().unwrap()
        ));
        assert_eq!(
            admin_request_retrying(
                admin,
                "PUT",
                &format!("/keys/{id}/budget"),
                Some(ADMIN_TOKEN),
                &json!({"budget":{"max_usd":"1.50","period":"monthly"}})
            )
            .await
            .status,
            204
        );
    }
    assert_eq!(
        admin_request_retrying(
            admin,
            "PUT",
            "/tenants/aggregate-tenant/budget",
            Some(ADMIN_TOKEN),
            &json!({"budget":{"max_usd":"1.50","period":"daily"}})
        )
        .await
        .status,
        204
    );
    for credential in &credentials {
        assert_eq!(
            send_chat_request(
                listener,
                &[("authorization", credential.as_str())],
                MODEL_ALLOWED
            )
            .await
            .status,
            200
        );
    }
    assert_eq!(
        send_chat_request(
            listener,
            &[("authorization", credentials[0].as_str())],
            MODEL_ALLOWED
        )
        .await
        .status,
        429
    );
    for (path, expected) in [
        ("/tenants/aggregate-tenant/spend", 2_000_000),
        ("/keys/aggregate-a/spend", 1_000_000),
        ("/keys/aggregate-b/spend", 1_000_000),
    ] {
        let report =
            admin_request_retrying(admin, "GET", path, Some(ADMIN_TOKEN), &json!({})).await;
        assert_eq!(report.status, 200);
        assert_eq!(parse_json(&report.body)["spend_micro_usd"], expected);
    }
    assert_eq!(
        admin_request_retrying(
            admin,
            "PUT",
            "/tenants/aggregate-tenant/budget",
            Some(ADMIN_TOKEN),
            &json!({"budget":null})
        )
        .await
        .status,
        204
    );
    assert_eq!(
        send_chat_request(
            listener,
            &[("authorization", credentials[0].as_str())],
            MODEL_ALLOWED
        )
        .await
        .status,
        200
    );
    assert_eq!(
        send_chat_request(
            listener,
            &[("authorization", credentials[0].as_str())],
            MODEL_ALLOWED
        )
        .await
        .status,
        429,
        "clearing tenant ceiling must not clear key spend or ceiling"
    );
    drop(proxy);
    drop(scratch);
    drop(upstream);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_budget_write_is_enforced_live_and_reported_via_admin_spend() {
    let (listener_addr, admin_addr, upstream, scratch, proxy) =
        spawn_suite("admin-budget", Some(ADMIN_TOKEN), false).await;

    admin_request_retrying(
        admin_addr,
        "POST",
        "/tenants",
        Some(ADMIN_TOKEN),
        &json!({ "tenant": "tenant-a" }),
    )
    .await;
    let minted = admin_request_retrying(
        admin_addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        &json!({ "tenant": "tenant-a", "key_id": "budget-key" }),
    )
    .await;
    assert_eq!(
        minted.status, 201,
        "sanity: minting must succeed: {}",
        minted.body
    );
    let minted_key = parse_json(&minted.body)["key"]
        .as_str()
        .expect("POST /keys must return the plaintext key")
        .to_string();
    let headers = [("authorization", format!("Bearer {minted_key}"))];
    let header_pairs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();

    let budget = admin_request_retrying(
        admin_addr,
        "PUT",
        "/keys/budget-key/budget",
        Some(ADMIN_TOKEN),
        &json!({ "budget": { "max_usd": "1.50", "period": "daily" } }),
    )
    .await;
    assert_eq!(
        budget.status, 204,
        "setting a tenant's budget must succeed, got {}: {}",
        budget.status, budget.body
    );

    let first = send_chat_request(listener_addr, &header_pairs, MODEL_ALLOWED).await;
    assert_eq!(
        first.status, 200,
        "sanity: the first $1.00 exchange must be admitted under a $1.50 budget, got {}: {}",
        first.status, first.body
    );
    let second = send_chat_request(listener_addr, &header_pairs, MODEL_ALLOWED).await;
    assert_eq!(
        second.status, 200,
        "sanity: the second $1.00 exchange (total $2.00 spend, checked against $1.50 BEFORE \
         this request's own cost is known) must still be admitted, got {}: {}",
        second.status, second.body
    );
    let third = send_chat_request(listener_addr, &header_pairs, MODEL_ALLOWED).await;
    assert_eq!(
        third.status, 429,
        "the third exchange must be refused once accrued spend ($2.00) is at or over the \
         $1.50 ceiling, got {}: {}",
        third.status, third.body
    );
    let header_value = |name: &str| -> String {
        third
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| {
                panic!(
                    "expected header `{name}` on a 429, got: {:?}",
                    third.headers
                )
            })
    };
    assert_eq!(
        header_value("x-ratelimit-limit"),
        "1500000",
        "x-ratelimit-limit must report the configured ceiling in MICRO-DOLLARS, not dollars \
         or a request count"
    );
    assert_eq!(
        header_value("x-ratelimit-remaining"),
        "0",
        "x-ratelimit-remaining must saturate at 0 once spend has crossed the ceiling, never \
         wrap around to a huge positive number"
    );

    let spend = admin_request_retrying(
        admin_addr,
        "GET",
        "/keys/budget-key/spend",
        Some(ADMIN_TOKEN),
        &json!({}),
    )
    .await;
    assert_eq!(
        spend.status, 200,
        "GET .../spend must succeed under the admin token, got {}: {}",
        spend.status, spend.body
    );
    let spend_json = parse_json(&spend.body);
    assert_eq!(
        spend_json["spend_micro_usd"], 2_000_000,
        "reported spend must equal the cost of the two ADMITTED exchanges only ($1.00 each) \
         -- the denied third request must not have been recorded, got: {spend_json}"
    );
    assert_eq!(
        spend_json["budget_micro_usd"], 1_500_000,
        "the reported budget must echo back the configured $1.50 ceiling in micro-dollars, \
         got: {spend_json}"
    );
    assert_eq!(
        spend_json["remaining_micro_usd"], 0,
        "remaining must saturate at 0, matching the 429's own x-ratelimit-remaining, got: \
         {spend_json}"
    );

    // Spend data is gated even on GET; with the gate enabled, missing credentials
    // produce 401 rather than the disabled-gate 403.
    let unauthenticated_spend_read = admin_request(
        admin_addr,
        "GET",
        "/keys/budget-key/spend",
        None,
        &json!({}),
    )
    .await;
    assert_eq!(
        unauthenticated_spend_read.status, 401,
        "GET .../spend is financial data and must be gated exactly like a write, got {}: {}",
        unauthenticated_spend_read.status, unauthenticated_spend_read.body
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

/// 6. With multiple auth chains, unscoped writes are ambiguous; scoped writes
/// address each chain independently, and keys do not cross-authenticate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_admin_api_requires_a_scope_when_multiple_auth_chains_exist() {
    let (listener_a_addr, listener_b_addr, admin_addr, upstream, scratch, proxy) =
        spawn_two_chain_suite("admin-scoped-addressing").await;

    let ambiguous = admin_request_retrying(
        admin_addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        &json!({ "tenant": "t", "key_id": "unscoped" }),
    )
    .await;
    assert_eq!(
        ambiguous.status, 500,
        "the UNSCOPED write API must refuse, never guess, when more than one chain \
         configures llmproxy.auth -- got {}: {}",
        ambiguous.status, ambiguous.body
    );
    // Ambiguity reports internal chain scopes; scoped routes use `stat_prefix`.
    assert!(
        ambiguous.body.contains("chain_a_listener") && ambiguous.body.contains("chain_b_listener"),
        "the refusal must name every ambiguous chain, got: {}",
        ambiguous.body
    );
    assert!(
        ambiguous.body.contains("2 filter chains"),
        "the refusal must say how many chains collided, got: {}",
        ambiguous.body
    );
    assert!(
        ambiguous.body.contains("/chains/"),
        "the refusal must point the caller at the scoped form, got: {}",
        ambiguous.body
    );

    let mint_a = admin_request_retrying(
        admin_addr,
        "POST",
        "/chains/chain-a/keys",
        Some(ADMIN_TOKEN),
        &json!({ "tenant": "t", "key_id": "key-a" }),
    )
    .await;
    assert_eq!(
        mint_a.status, 201,
        "the SCOPED write API must resolve chain-a unambiguously, got {}: {}",
        mint_a.status, mint_a.body
    );
    let key_a = parse_json(&mint_a.body)["key"]
        .as_str()
        .expect("POST /chains/chain-a/keys must return the plaintext key")
        .to_string();

    let mint_b = admin_request_retrying(
        admin_addr,
        "POST",
        "/chains/chain-b/keys",
        Some(ADMIN_TOKEN),
        &json!({ "tenant": "t", "key_id": "key-b" }),
    )
    .await;
    assert_eq!(
        mint_b.status, 201,
        "the SCOPED write API must resolve chain-b unambiguously, got {}: {}",
        mint_b.status, mint_b.body
    );
    let key_b = parse_json(&mint_b.body)["key"]
        .as_str()
        .expect("POST /chains/chain-b/keys must return the plaintext key")
        .to_string();

    let a_on_a = send_chat_request(
        listener_a_addr,
        &[("authorization", &format!("Bearer {key_a}"))],
        MODEL_ALLOWED,
    )
    .await;
    assert_eq!(
        a_on_a.status, 200,
        "a key minted for chain-a must authenticate against chain-a's own listener, got \
         {}: {}",
        a_on_a.status, a_on_a.body
    );

    let b_on_b = send_chat_request(
        listener_b_addr,
        &[("authorization", &format!("Bearer {key_b}"))],
        MODEL_ALLOWED,
    )
    .await;
    assert_eq!(
        b_on_b.status, 200,
        "a key minted for chain-b must authenticate against chain-b's own listener, got \
         {}: {}",
        b_on_b.status, b_on_b.body
    );

    let a_on_b = send_chat_request(
        listener_b_addr,
        &[("authorization", &format!("Bearer {key_a}"))],
        MODEL_ALLOWED,
    )
    .await;
    assert_eq!(
        a_on_b.status, 401,
        "a key minted for chain-a must NOT authenticate against chain-b's listener -- \
         cross-chain leakage would be exactly the `SharedFactoryState` type_url-only-key \
         defect (`df0ae8c`) recurring. Got {}: {}",
        a_on_b.status, a_on_b.body
    );

    let b_on_a = send_chat_request(
        listener_a_addr,
        &[("authorization", &format!("Bearer {key_b}"))],
        MODEL_ALLOWED,
    )
    .await;
    assert_eq!(
        b_on_a.status, 401,
        "a key minted for chain-b must NOT authenticate against chain-a's listener, got \
         {}: {}",
        b_on_a.status, b_on_a.body
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}
