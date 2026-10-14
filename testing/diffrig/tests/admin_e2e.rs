//! End-to-end acceptance drill for the admin WRITE API -- closes the coverage
//! gap that the admin API had never run against the real binary (nothing
//! outside unit tests set `LLMPROXY_ADMIN_TOKEN`). Four of the five defects
//! found when it was first wired (`SharedFactoryState` keyed on `type_url` alone, a
//! per-worker token-limit store, and two more) were wiring bugs a unit test
//! against a `TestCallbacks`/in-process double could not see, because they
//! only exist once a real binary boots real workers around a real socket.
//! This file is that drill: it spawns the REAL `llm-proxy` process with
//! `LLMPROXY_ADMIN_TOKEN` set in ITS environment (never this test process's
//! own -- see [`diffrig::harness::ProxyProcess::spawn_envoy_with_env`]),
//! points it at a mock upstream, and drives both the admin HTTP surface and
//! the data plane over real sockets.
//!
//! # NOT `local_openai_smoke.rs`, deliberately
//!
//! That file is `#[ignore]`d behind a local Ollama -- and AGENTS.md "Coverage"
//! records, from the last time this happened, that an `#[ignore]`d file is
//! exactly how an entire observability surface stayed untested while 1141
//! other tests stayed green. This drill needs no live provider (the mock
//! upstream in `diffrig::upstreams` is enough for every case below), so it
//! runs in the default `make tq` suite, same as `auth_e2e.rs`.
//!
//! # Structural sibling of `auth_e2e.rs` -- read that file first if unfamiliar
//!
//! Same harness, same `spawn_suite` shape, same timeout discipline (every
//! request wrapped in `tokio::time::timeout`), same reason
//! (`ProxyProcess::wait_until_ready` blocks the calling thread, so every test
//! needs `#[tokio::test(flavor = "multi_thread", ...)]` or the mock upstream
//! spawned onto the same runtime freezes -- see that function's doc for the
//! 656-863s incident this guards against).
//!
//! # Ephemeral ports, always
//!
//! Every port here (listener, admin, upstream) comes from
//! [`diffrig::harness::free_port`] at test-run time, never a hardcoded value
//! from `examples/*.yaml` -- AGENTS.md "Build And Test" records a fixed-port test as a
//! real cross-suite collision, and rule 15 records that a git worktree does
//! NOT isolate ports from a concurrently running agent on the same machine.
//!
//! # Filter order, restated for this chain
//!
//! `proxy_config::lower::check_lane_h_filter_order` requires `llmproxy.auth`
//! before `llmproxy.model_authz` and before `llmproxy.spend_limit` (both
//! decode-side), `llmproxy.body_rewrite` before `llmproxy.model_authz` (the
//! model comes from the request body), and `llmproxy.spend_limit` before
//! `llmproxy.usage` (spend's `record` is encode-side, which runs in REVERSE
//! config order). [`single_chain_config`] orders them
//! auth -> body_rewrite -> model_authz -> spend_limit -> usage -> router,
//! satisfying every rule at once.
//!
//! # Pricing, and the token math every priced test depends on
//!
//! Every chat request here sends the single-word message `"hi"` (1 token)
//! and the mock upstream always replies with the single-word completion
//! `"ok"` (1 token) -- see `auth_e2e.rs`'s module doc for why this is exactly
//! reproducible. [`single_chain_config`] prices [`MODEL_ALLOWED`] and
//! [`MODEL_DENIED`] on cluster `provider:p1` at `"500000.00"` per million
//! input AND output tokens (cached/cache-creation at `"0.00"`), so one
//! admitted exchange costs exactly `500_000 + 500_000 = 1_000_000`
//! micro-dollars ($1.00) -- the number [`a_budget_write_is_enforced_live_and_reported_via_admin_spend`]
//! is built around.
//!
//! # One test in this file is RED on purpose
//!
//! [`a_tenant_policy_write_changes_model_authorization_live`] documents a
//! real, previously-unknown defect this drill found (`llmproxy.model_authz`
//! denies every request in a real filter chain, unconditionally -- see that
//! function's doc for the full analysis) rather than silently working
//! around it. Per this task's own instructions, a test that demonstrates a
//! real bug precisely is the correct outcome, not a regression to chase out
//! of this file.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, ProxyProcess, RawResponse, ScratchDir,
    READY_TIMEOUT,
};
use diffrig::upstreams::{OpenAiConfig, OpenAiUpstream};
use serde_json::{json, Value};

// ------------------------------------------------------------------ config --

/// How long a single client request (data-plane or admin) waits before
/// failing the test outright instead of hanging the whole suite -- see
/// `auth_e2e.rs`'s identical constant for the incident this guards against.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`admin_request_retrying`] will retry a `503` "not initialized
/// yet" boot-race response before giving up -- see that function's doc.
const BOOT_RACE_TIMEOUT: Duration = Duration::from_secs(5);

/// The operator secret naming every `Authentication` filter's HMAC key in
/// this file. Real only for the lifetime of one test process -- never a
/// value any of these tests read back out to verify (the whole point of the
/// admin API is that a client sees only the plaintext keys IT mints, never
/// this secret).
const HMAC_SECRET: &str = "wp-50-admin-e2e-hmac-secret-never-reused-elsewhere";

/// `LLMPROXY_ADMIN_TOKEN`'s configured value for tests that need the write
/// API enabled.
const ADMIN_TOKEN: &str = "wp-50-admin-e2e-bearer-token-never-reused-elsewhere";
/// A syntactically fine, definitely-wrong bearer token -- exercises Gate 2
/// (`admin/src/server.rs`'s `handle`) without ever matching [`ADMIN_TOKEN`].
const WRONG_ADMIN_TOKEN: &str = "wp-50-admin-e2e-WRONG-bearer-token";

/// The credential the CLUSTER injects via `io.llmproxy.provider_auth`
/// metadata (AGENTS.md invariant 6: per-provider credentials belong on the cluster,
/// never the route) -- restated from `auth_e2e.rs`.
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

/// Renders a single-listener Envoy bootstrap: one `admin` surface, one
/// cluster (`provider:p1`), one listener whose `http_filters` chain is
/// `llmproxy.auth -> llmproxy.body_rewrite -> llmproxy.model_authz ->
/// llmproxy.spend_limit -> llmproxy.usage -> envoy.filters.http.router` --
/// see the module doc for why this order is the only one
/// `check_lane_h_filter_order` accepts.
///
/// `virtual_keys` is deliberately EMPTY: every credential exercised against
/// this config is minted through the admin API at test run time, not
/// pre-configured -- this is the whole point of the drill (see the top-level
/// module doc).
///
/// `with_model_authz` gates whether `llmproxy.model_authz` is in the chain
/// at all. It defaults OFF for every test but
/// [`a_tenant_policy_write_changes_model_authorization_live`] -- see that
/// function's own doc for a KNOWN, REAL defect this drill found:
/// `llmproxy.model_authz`'s decode-time check runs in the SAME header phase
/// as `llmproxy.body_rewrite`'s `decode_headers`, which never holds the
/// request -- the model it publishes onto `StreamInfo::requested_model` is
/// only written later, in the trailing DATA phase, which
/// `crates/proxy-http/src/filter_manager.rs::drive_decode` runs strictly
/// after every filter's header phase has already completed.
/// `llmproxy.model_authz` therefore denies every request it ever sees in a
/// real chain, unconditionally, regardless of policy -- see that test for
/// the full analysis and the demonstration.
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
              pricing:
              - cluster: provider:p1
                models:
                - model: {MODEL_ALLOWED}
                  input_per_million: "500000.00"
                  output_per_million: "500000.00"
                  cached_per_million: "0.00"
                  cache_creation_per_million: "0.00"
                - model: {MODEL_DENIED}
                  input_per_million: "500000.00"
                  output_per_million: "500000.00"
                  cached_per_million: "0.00"
                  cache_creation_per_million: "0.00"
          - name: llmproxy.usage
            typed_config:
              '@type': type.llmproxy.dev/envoy.config.core.v3.DataSource
              inline_string: openai
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
                    '@type': type.llmproxy.dev/envoy.config.core.v3.DataSource
                    inline_string: openai
          stat_prefix: llmproxy
    name: llmproxy_listener
"#
    )
}

/// Renders a bootstrap with TWO independent listeners, each its own HCM
/// (`stat_prefix` `chain-a`/`chain-b`), each configuring its OWN
/// `llmproxy.auth` -- for
/// [`the_admin_api_requires_a_scope_when_multiple_auth_chains_exist`]. No
/// `llmproxy.model_authz`/`llmproxy.spend_limit`/`llmproxy.body_rewrite`/
/// `llmproxy.usage` on either chain: that test only exercises auth
/// resolution and scoped/unscoped addressing, so the minimal chain that
/// satisfies `check_lane_h_filter_order` (which only fires when BOTH halves
/// of a rule are present) is `llmproxy.auth -> envoy.filters.http.router`.
/// Both listeners route to the SAME cluster/mock upstream -- nothing about
/// this test needs two upstreams, only two independently-scoped
/// `ControlPlane`s.
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

/// Spawns the mock upstream plus the real proxy against
/// [`single_chain_config`], with `LLMPROXY_ADMIN_TOKEN` set to `admin_token`
/// in the CHILD's environment only when `Some` (see
/// `ProxyProcess::spawn_envoy_with_env`'s doc for why never
/// `std::env::set_var` here). Returns the data-plane and admin addresses
/// alongside the guards the caller must hold (and drop, in order) for the
/// rest of the test. `with_model_authz` is forwarded to
/// [`single_chain_config`] -- see that function's doc.
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
    // The admin server binds BEFORE the worker pool spawns (`main.rs`'s
    // `run_serve`, see `start_admin`'s doc), so waiting on it first can only
    // make this call return sooner, never later, than waiting on the
    // data-plane listener.
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

/// Send one request against the ADMIN surface, bounded by [`CLIENT_TIMEOUT`].
/// `token`, when `Some`, is sent as `Authorization: Bearer <token>`; `None`
/// sends no `Authorization` header at all (the Gate-1 "unset token" case
/// tests this on the SERVER side; this is the client sending nothing, which
/// is the normal shape of that case).
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

/// [`admin_request`], but retried while the response is exactly the
/// documented boot-race `503` (`proxy_admin::server`'s `resolve_control_plane`
/// doc: "a request that lands before any worker's `create()` has run finds
/// nothing here yet"). `start_admin` binds the admin port before the worker
/// pool spawns (see `main.rs`), so in practice this never loops more than
/// once by the time `wait_until_ready` has already proven the DATA-PLANE
/// listener is up -- built anyway so a slow CI box cannot turn a real,
/// self-resolving race into a flaky failure. A response that ISN'T that
/// specific 503 (including every other status this file asserts on) is
/// returned immediately, unretried.
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

/// 4. `PUT /tenants/{id}/policy` changes model authorization for the VERY
/// NEXT request, with no reload. Sends the same (denied) model twice --
/// once before the policy write (permitted, the default-open
/// baseline) and once after (refused) -- then confirms the allowed model
/// still passes under the new, restrictive policy.
///
/// # KNOWN DEFECT, found by this test, NOT fixed here -- see the task report
///
/// This test is RED, and stays red: the very first assertion (the
/// default-open baseline, before any policy write) already fails --
/// `llmproxy.model_authz` denies EVERY authenticated request with a real
/// model, unconditionally, in a real filter chain. Reported precisely rather
/// than silently patched (see this crate's task scope). In short:
///
/// `ModelAuthzFilterInstance::decode_headers`
/// (`crates/proxy-filters/src/model_authz_filter.rs`) reads
/// `StreamInfo::requested_model`, which only `BodyRewriteFilterInstance::decode_data`
/// (`crates/proxy-filters/src/body_rewrite_filter.rs`) ever writes.
/// `BodyRewriteFilterInstance::decode_headers` always returns
/// `FilterHeadersStatus::Continue` (never holds the request), so per
/// `drive_decode`'s two-phase design
/// (`crates/proxy-http/src/filter_manager.rs`): first EVERY filter's
/// `decode_headers` runs, in order, all the way to the terminal; only
/// afterward does a SECOND, trailing pass deliver `decode_data` to filters
/// that still owe it, again in order. `llmproxy.model_authz` has no
/// `decode_data` of its own -- its ONLY check is in `decode_headers` -- so
/// it always runs, and always denies (`requested_model: None`), during the
/// FIRST pass, strictly before `llmproxy.body_rewrite`'s `decode_data` (the
/// second pass) has ever set the field it depends on. No filter ORDERING
/// fixes this: any position after `llmproxy.body_rewrite` still puts
/// `model_authz`'s header-phase read before body_rewrite's data-phase write,
/// because the two phases are global (across every filter), not per-filter.
///
/// `crates/proxy-config/src/lower.rs`'s `check_lane_h_filter_order` (and its
/// module doc) states the opposite -- "decode callbacks run in config
/// order" -- treating `decode_headers` and `decode_data` as one combined,
/// per-filter sequence. That is true for a filter whose OWN
/// `decode_headers` holds the request (`llmproxy.auth`/`llmproxy.token_limit`
/// both do, effectively, by resolving everything they need directly from
/// headers with no data dependency), but not for two filters split across
/// the header/data boundary the way `body_rewrite`/`model_authz` are.
///
/// This also explains why no test caught it before now:
/// `model_authz_filter.rs`'s own unit tests use a hand-rolled
/// `TestCallbacks` whose `set_requested_model` writes the field directly,
/// bypassing `drive_decode` entirely -- so they encode "if the model were
/// already known, would the policy check be right", never "does a real
/// chain make the model known in time". This file is the first place
/// `llmproxy.model_authz` has ever run inside the real `filter_manager.rs`
/// pointer machine.
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
    // policy is denied by default, review H4).
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

/// 5. `PUT /keys/{id}/budget` is enforced live against real priced
/// traffic, and `GET /keys/{id}/spend` (admin-gated despite being a GET
/// -- financial data) reports spend consistent with what was actually sent.
///
/// Per the module doc's token math, one admitted exchange against
/// [`MODEL_ALLOWED`] costs exactly 1,000,000 micro-dollars ($1.00). A budget
/// of `"1.50"` (1,500,000 micro-dollars) therefore admits exactly two
/// exchanges and refuses the third with `429` + `x-ratelimit-*` headers IN
/// MICRO-DOLLARS (`spend_limit_filter`'s convention, not a token/request
/// count).
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

    // The financial-data gate applies here too, despite this being a GET --
    // see `handle_get_spend`'s doc for why. Confirmed directly rather than
    // assumed from the write-endpoint tests above. `LLMPROXY_ADMIN_TOKEN` IS
    // configured for this process (unlike
    // `admin_write_endpoints_are_forbidden_when_the_token_env_var_is_unset`'s
    // 403), so presenting no bearer at all lands on Gate 2 ("enabled, no
    // credential presented"), which is a 401, not a 403 -- the SAME
    // distinction that test's own doc draws between "disabled" and
    // "enabled, wrong/missing credential".
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

/// 6. Scoped vs. unscoped addressing. With TWO `llmproxy.auth`-configured
/// filter chains live, the UNSCOPED admin API cannot tell which
/// `ControlPlane` a write means and refuses explicitly (never guesses,
/// AGENTS.md "Fail-open controls"'s shape); the SCOPED `/chains/{stat_prefix}/...` form
/// is always correct, addresses each chain independently, and a key minted
/// on one chain does NOT authenticate against the other -- proving the
/// `df0ae8c` fix (`SharedFactoryState` keyed on `(chain scope, type_url)`,
/// not `type_url` alone) stays fixed end to end.
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
    // The refusal names each ambiguous filter chain by its internal `scope`
    // (listener name + filter_chains index -- `SharedFactoryState`'s doc:
    // `scope` is positional/internal, distinct from the operator-chosen
    // `stat_prefix` this test's OWN chains are named with), not by
    // `stat_prefix` -- the unscoped resolver has no name to give, only the
    // fact that more than one chain collided. `resolve_control_plane`'s doc
    // in `crates/proxy-admin/src/server.rs` is normative for this.
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
