//! End-to-end acceptance test: proves the downstream
//! authentication filter (`crates/proxy-filters/src/auth_filter.rs`) works
//! inside the REAL filter manager, driving a REAL `llm-proxy` process, over a
//! real socket -- not just against the `TestCallbacks` double its unit tests
//! use.
//!
//! Structural sibling of `failover_e2e.rs`: same harness, same `spawn_suite`
//! shape, same timeout discipline (every request wrapped in
//! `tokio::time::timeout` -- see that file's module doc for why a hang here
//! once turned a 79s workspace run into 656-863s). Read `failover_e2e.rs`
//! first if this one is unfamiliar.
//!
//! # Envoy mode (`-c`), not the dialect (`--config`)
//!
//! `llmproxy.auth` has no dialect (`llmproxy.yaml`) surface yet -- see
//! `ProxyProcess::spawn_envoy`'s doc comment. This suite hands the proxy a
//! hand-written Envoy bootstrap document instead, built from a
//! verified-working base (`llm-proxy --config <dialect> --mode translate`
//! against a simple OpenAI-provider dialect config) with `llmproxy.auth`
//! inserted as the FIRST `http_filters` entry.
//!
//! # Why the digests are computed, never hardcoded
//!
//! [`digest_hex`] recomputes `hex(HMAC-SHA256(secret, plaintext_key))` at
//! test-run time, the same way `auth_filter::VirtualKeyAuthenticator`
//! verifies a presented key. A hardcoded digest would silently stop matching
//! the day anything about the derivation changed, and this suite would still
//! "pass" -- by 401ing every request, including the ones meant to succeed.
//!
//! # The token math Test 7 depends on
//!
//! Every chat request in this file sends the single-word message `"hi"`
//! (1 token) and the mock upstream always replies with the single-word
//! completion `"ok"` (1 token, per `OpenAiConfig::response_text`), so every
//! successful exchange costs exactly 2 tokens against
//! `LimitOn::Total` (`crates/proxy-filters/src/token_limit.rs`). Test 7's
//! budget of 2 is chosen to be exhausted by exactly one exchange.

use std::net::SocketAddr;
use std::time::Duration;

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, ProxyProcess, RawResponse, ScratchDir,
    READY_TIMEOUT,
};
use diffrig::upstreams::{OpenAiConfig, OpenAiUpstream};
use serde_json::json;

// ------------------------------------------------------------------ config --

/// How long the client waits for a response before failing the test outright
/// instead of hanging the whole suite -- see `failover_e2e.rs`'s identical
/// constant for the incident this guards against.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// The operator secret that keys every virtual-key digest in this file. Real
/// only for the lifetime of one test process.
const HMAC_SECRET: &str = "wp-50-e2e-test-hmac-secret-never-reused-elsewhere";

const KEY_LIVE: &str = "llmp_e2e-live-key";
const KEY_LIVE_2: &str = "llmp_e2e-live-key-2";
const KEY_REVOKED: &str = "llmp_e2e-revoked-key";
/// Well-formed (`llmp_`-prefixed) but never configured -- exercises the
/// "credential presented, unknown" path, distinct from "no credential at
/// all" (see [`AuthOutcome::NoCredential`] vs. `Rejected(UnknownKey)` in
/// `crates/proxy-filters/src/auth.rs`).
const UNKNOWN_KEY: &str = "llmp_e2e-never-configured";

/// The credential the CLUSTER injects via `io.llmproxy.provider_auth`
/// metadata (AGENTS.md invariant 6: per-provider credentials belong on the cluster,
/// never the route). Test 5 asserts the upstream sees exactly this and never
/// a virtual key.
const PROVIDER_KEY: &str = "sk-real-provider-credential-e2e";

/// A budget generous enough that no test besides Test 7 can accidentally
/// exhaust it.
const AMPLE_MAX_TOKENS: u32 = 1_000;
const AMPLE_FILL_RATE: f64 = 100.0;

/// `hex(HMAC-SHA256(secret, plaintext_key))`, computed exactly the way
/// `auth_filter::VirtualKeyAuthenticator` verifies a presented key -- see
/// this file's module doc for why this must never be a hardcoded literal.
fn digest_hex(secret: &str, plaintext_key: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let digest = ring::hmac::sign(&key, plaintext_key.as_bytes());
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Render the Envoy-mode bootstrap this suite loads with `-c`: one cluster
/// (`provider:p1`, carrying the PROVIDER credential via
/// `io.llmproxy.provider_auth` metadata) and one listener whose
/// `http_filters` puts `llmproxy.auth` FIRST -- before `llmproxy.body_rewrite`
/// (so an unauthenticated request is refused before the body-peek filter
/// ever buffers its body) and before `llmproxy.token_limit`
/// (`proxy_config::lower::check_lane_h_filter_order` ENFORCES this second
/// ordering at load time: reversed, the limiter would silently fall back to
/// bucketing on the client-supplied `authorization` header instead of the
/// tenant this filter resolves).
///
/// Parameterised on the listener/upstream ports and the token-limit budget
/// (Test 7 needs its own tiny one; every other test gets [`AMPLE_MAX_TOKENS`]
/// / [`AMPLE_FILL_RATE`]). The three virtual-key digests are always computed
/// fresh via [`digest_hex`].
fn envoy_config(listener_port: u16, upstream_port: u16, max_tokens: u32, fill_rate: f64) -> String {
    let key_live_digest = digest_hex(HMAC_SECRET, KEY_LIVE);
    let key_revoked_digest = digest_hex(HMAC_SECRET, KEY_REVOKED);
    let key_live_2_digest = digest_hex(HMAC_SECRET, KEY_LIVE_2);

    format!(
        r#"
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
              virtual_keys:
                - key_id: key-live
                  tenant: tenant-a
                  digest_hex: {key_live_digest}
                  revoked: false
                - key_id: key-revoked
                  tenant: tenant-a
                  digest_hex: {key_revoked_digest}
                  revoked: true
                - key_id: key-live-2
                  tenant: tenant-a
                  digest_hex: {key_live_2_digest}
                  revoked: false
          - name: llmproxy.body_rewrite
            typed_config:
              '@type': type.llmproxy.dev/envoy.config.core.v3.RuntimeFeatureFlag
              default_value: true
              runtime_key: openai
          - name: llmproxy.token_limit
            typed_config:
              # Compatibility fixture: real-binary coverage for the
              # one-release decoder of the old borrowed token-limit type.
              '@type': type.llmproxy.dev/envoy.config.core.v3.RateLimitSettings
              fill_rate: {fill_rate}
              max_tokens: {max_tokens}
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

// ----------------------------------------------------------------- helpers --

/// The mock upstream: requires the PROVIDER credential (never a virtual
/// key -- Test 5 checks this directly) and always replies with the
/// single-word completion `"ok"`, per this file's module doc on the token
/// math Test 7 depends on.
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

fn chat_request_body() -> serde_json::Value {
    json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi"}],
    })
}

/// Spawn the mock upstream plus the real proxy in Envoy mode, wired together
/// via [`envoy_config`]. Guards are returned so the caller controls drop
/// order (proxy first, then the mock), same convention as
/// `failover_e2e.rs::spawn_suite`.
async fn spawn_suite(
    label: &str,
    max_tokens: u32,
    fill_rate: f64,
) -> (SocketAddr, OpenAiUpstream, ScratchDir, ProxyProcess) {
    let upstream = OpenAiUpstream::spawn(upstream_config())
        .await
        .expect("spawn mock upstream");

    let scratch = ScratchDir::new(label);
    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_yaml = envoy_config(listener_port, upstream.port(), max_tokens, fill_rate);
    let config_path = scratch.write("envoy.yaml", &config_yaml);

    let bin = resolve_llm_proxy_bin();
    let mut proxy =
        ProxyProcess::spawn_envoy(&bin, &config_path, &scratch.path().join("proxy.log"));
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);

    (listener_addr, upstream, scratch, proxy)
}

/// Send one chat-completion request through the proxy, bounded by
/// [`CLIENT_TIMEOUT`] so a stuck auth/limit decision fails this test instead
/// of hanging the suite.
async fn send_chat_request(addr: SocketAddr, headers: &[(&str, &str)]) -> RawResponse {
    tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json(
            addr,
            "POST",
            "/v1/chat/completions",
            headers,
            &chat_request_body(),
        ),
    )
    .await
    .expect("client request timed out -- an auth/limit decision hung instead of completing")
}

// -------------------------------------------------------------------- tests --

/// 1. A valid virtual key reaches the upstream and returns 200. Asserting
/// the upstream actually received a request (not just a 200) is the point --
/// a bare status code doesn't distinguish "forwarded" from "some other local
/// reply".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_valid_virtual_key_reaches_the_upstream_and_returns_200() {
    let (addr, upstream, scratch, proxy) =
        spawn_suite("auth-valid-key", AMPLE_MAX_TOKENS, AMPLE_FILL_RATE).await;

    let res = send_chat_request(addr, &[("authorization", &format!("Bearer {KEY_LIVE}"))]).await;

    assert_eq!(
        res.status, 200,
        "expected the request to be admitted and forwarded, got {}: {}",
        res.status, res.body
    );
    assert_eq!(
        upstream.log.requests().len(),
        1,
        "the upstream must actually have been dialled -- a bare 200 wouldn't distinguish \
         \"forwarded\" from \"some other local reply\""
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

/// Review M9: the access log never carries a credential, even when the
/// operator's format names the header. An admitted request's key is stripped
/// by `llmproxy.auth` before the log renders, but a refused one keeps it (an
/// unknown key may be a typo of a real one), and a provider key a client sends
/// in `x-api-key` is never stripped. So the renderer redacts credential
/// headers; this drives it through the real binary, for an admitted request
/// and a refused one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_access_log_never_renders_the_virtual_key_or_a_provider_key() {
    let upstream = OpenAiUpstream::spawn(upstream_config())
        .await
        .expect("spawn mock upstream");
    let scratch = ScratchDir::new("auth-access-log-redaction");
    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let log_path = scratch.path().join("access.log");
    let access_log = format!(
        r#"          access_log:
          - name: envoy.access_loggers.file
            typed_config:
              '@type': type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
              path: {}
              log_format:
                text_format: "status=%RESPONSE_CODE% auth=%REQ(authorization)% api_key=%REQ(X-Api-Key)% fallback=%REQ(missing?authorization)%\n"
          http_filters:
"#,
        log_path.display()
    );
    let config_yaml = envoy_config(
        listener_port,
        upstream.port(),
        AMPLE_MAX_TOKENS,
        AMPLE_FILL_RATE,
    )
    .replacen("          http_filters:\n", &access_log, 1);
    let config_path = scratch.write("envoy.yaml", &config_yaml);
    let mut proxy = ProxyProcess::spawn_envoy(
        &resolve_llm_proxy_bin(),
        &config_path,
        &scratch.path().join("proxy.log"),
    );
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);

    let provider_key = "sk-client-sent-provider-key";
    for key in [KEY_LIVE, "llmp_unknown-key"] {
        let bearer = format!("Bearer {key}");
        send_chat_request(
            listener_addr,
            &[("authorization", &bearer), ("x-api-key", provider_key)],
        )
        .await;
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let log = loop {
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        if log.lines().count() >= 2 || std::time::Instant::now() >= deadline {
            break log;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(log.lines().count(), 2, "one line per request:\n{log}");
    assert!(
        log.contains("status=200") && log.contains("status=401"),
        "{log}"
    );
    for (status, expected) in [
        ("200", "auth=- api_key=[REDACTED] fallback=-"),
        (
            "401",
            "auth=[REDACTED] api_key=[REDACTED] fallback=[REDACTED]",
        ),
    ] {
        let line = log
            .lines()
            .find(|line| line.starts_with(&format!("status={status} ")))
            .unwrap_or_else(|| panic!("no {status} line:\n{log}"));
        assert!(
            line.ends_with(expected),
            "a credential header renders as present, never its value: {line}"
        );
    }
    assert!(
        !log.contains("llmp_") && !log.contains(provider_key),
        "no credential may reach the access log:\n{log}"
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

/// 2. An unknown `llmp_`-prefixed key gets 401, AND the upstream is never
/// contacted. The second half is the real assertion: a filter that 401s only
/// AFTER forwarding would still bill the provider.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_key_gets_401_and_the_upstream_is_never_contacted() {
    let (addr, upstream, scratch, proxy) =
        spawn_suite("auth-unknown-key", AMPLE_MAX_TOKENS, AMPLE_FILL_RATE).await;

    let res = send_chat_request(addr, &[("authorization", &format!("Bearer {UNKNOWN_KEY}"))]).await;

    assert_eq!(
        res.status, 401,
        "expected an unknown key to be refused, got {}: {}",
        res.status, res.body
    );
    assert_eq!(
        upstream.log.requests().len(),
        0,
        "an unknown key must never reach the upstream -- a filter that 401s only after \
         forwarding would still bill the provider"
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

/// 3. A revoked key gets 401, upstream not contacted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_key_gets_401_and_the_upstream_is_never_contacted() {
    let (addr, upstream, scratch, proxy) =
        spawn_suite("auth-revoked-key", AMPLE_MAX_TOKENS, AMPLE_FILL_RATE).await;

    let res = send_chat_request(addr, &[("authorization", &format!("Bearer {KEY_REVOKED}"))]).await;

    assert_eq!(
        res.status, 401,
        "expected a revoked key to be refused, got {}: {}",
        res.status, res.body
    );
    assert_eq!(
        upstream.log.requests().len(),
        0,
        "a revoked key must never reach the upstream"
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

/// 4. No `authorization` header at all gets 401, upstream not contacted --
/// fail closed. This is the case a "let it through if there's no credential"
/// refactor would break.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_authorization_header_gets_401_and_the_upstream_is_never_contacted() {
    let (addr, upstream, scratch, proxy) =
        spawn_suite("auth-no-header", AMPLE_MAX_TOKENS, AMPLE_FILL_RATE).await;

    let res = send_chat_request(addr, &[]).await;

    assert_eq!(
        res.status, 401,
        "an absent credential must be refused, not admitted -- fail closed. got {}: {}",
        res.status, res.body
    );
    assert_eq!(
        upstream.log.requests().len(),
        0,
        "an unauthenticated request must never reach the upstream"
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

/// 5. The upstream sees the PROVIDER credential, never the virtual key. This
/// is an acceptance criterion and AGENTS.md invariant 6: a per-provider credential belongs
/// on the cluster (the member actually dialled), never the route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_upstream_sees_the_provider_credential_never_the_virtual_key() {
    let (addr, upstream, scratch, proxy) = spawn_suite(
        "auth-credential-isolation",
        AMPLE_MAX_TOKENS,
        AMPLE_FILL_RATE,
    )
    .await;

    let res = send_chat_request(addr, &[("authorization", &format!("Bearer {KEY_LIVE}"))]).await;
    assert_eq!(
        res.status, 200,
        "sanity: the request must succeed before credentials can be inspected, got {}: {}",
        res.status, res.body
    );

    let requests = upstream.log.requests();
    let received = requests
        .last()
        .expect("upstream must have received a request");

    // Positive: the PROVIDER's own key arrived.
    assert!(
        received
            .headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("authorization")
                && v == &format!("Bearer {PROVIDER_KEY}")),
        "expected `authorization: Bearer {PROVIDER_KEY}` at the upstream, got: {:?}",
        received.headers
    );

    // Negative, asserted explicitly and separately (same reasoning as
    // `failover_e2e.rs`'s credential-isolation test): the virtual key must
    // appear nowhere in what the upstream received -- not in
    // `authorization`, not smuggled into any other header.
    let leaked = received.headers.iter().any(|(_, v)| v.contains(KEY_LIVE));
    assert!(
        !leaked,
        "the virtual key (`{KEY_LIVE}`) leaked into a header the upstream received: {:?}",
        received.headers
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

/// 6. All three failure modes are byte-identical on the wire (status, body,
/// headers). The unit test (`auth_filter::tests`) already asserts this
/// against a `TestCallbacks` double; this asserts it after the local reply
/// has been through the REAL encoder chain, which is where a divergence
/// would actually appear.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_three_failure_modes_are_byte_identical_on_the_wire() {
    let (addr, upstream, scratch, proxy) =
        spawn_suite("auth-identical-401s", AMPLE_MAX_TOKENS, AMPLE_FILL_RATE).await;

    let no_credential = send_chat_request(addr, &[]).await;
    let unknown =
        send_chat_request(addr, &[("authorization", &format!("Bearer {UNKNOWN_KEY}"))]).await;
    let revoked =
        send_chat_request(addr, &[("authorization", &format!("Bearer {KEY_REVOKED}"))]).await;

    for (name, res) in [
        ("no-credential", &no_credential),
        ("unknown", &unknown),
        ("revoked", &revoked),
    ] {
        assert_eq!(res.status, 401, "{name}: status must be 401");
        // `respond_with_local_reply` (`crates/proxy-http/src/filter_manager.rs`)
        // appends a trailing newline to every local-reply body on the wire,
        // so the encoded body is `"unauthorized\n"`, not the bare
        // `"unauthorized"` the filter passes to `send_local_reply` -- this
        // is exactly the kind of divergence a unit test against
        // `TestCallbacks` (which never runs the real encoder chain) cannot
        // see, and the reason this test exists at the e2e layer.
        assert_eq!(res.body, "unauthorized\n", "{name}: body must be identical");
    }

    // Rust note: sort each response's headers before comparing so the
    // assertion doesn't depend on wire order (which this codec happens to
    // keep stable, but the PROPERTY under test is "the same set of headers",
    // not "the same order"). `date` is excluded: it is per-response by
    // design, so two replies straddling a second boundary legitimately
    // differ. Its presence and IMF-fixdate shape are asserted separately so
    // excluding it from the comparison does not stop covering it.
    for (name, res) in [
        ("no-credential", &no_credential),
        ("unknown", &unknown),
        ("revoked", &revoked),
    ] {
        let dates: Vec<&str> = res
            .headers
            .iter()
            .filter(|(n, _)| n == "date")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(dates.len(), 1, "{name}: expected exactly one date header");
        // IMF-fixdate (RFC 9110 5.6.7), e.g. "Sun, 06 Nov 1994 08:49:37 GMT".
        assert!(
            dates[0].len() == 29 && dates[0].ends_with(" GMT"),
            "{name}: date header {:?} is not IMF-fixdate",
            dates[0]
        );
    }
    let sorted = |res: &RawResponse| {
        let mut headers: Vec<_> = res
            .headers
            .iter()
            .filter(|(n, _)| n != "date")
            .cloned()
            .collect();
        headers.sort();
        headers
    };
    assert_eq!(
        sorted(&no_credential),
        sorted(&unknown),
        "no-credential and unknown-key responses carry different headers"
    );
    assert_eq!(
        sorted(&unknown),
        sorted(&revoked),
        "unknown-key and revoked-key responses carry different headers"
    );

    assert_eq!(
        upstream.log.requests().len(),
        0,
        "none of these three refused requests should ever reach the upstream"
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

/// 7. Two different virtual keys on the same tenant share ONE token budget.
///
/// **This is the v0.1.0 ship-gate clause "a token-based rate limit is
/// enforced", proven end to end.** The limiter is keyed on
/// `StreamInfo::auth.tenant`, an identity the CALLER cannot choose, so two
/// keys belonging to the same tenant draw from the same bucket. Keying on the
/// client's raw `authorization` header (`hash_credential(...)`) would make the
/// limit advisory by construction: a second, distinct header value would get a
/// fresh budget. This test is the only place in the suite that would catch a
/// regression back to keying on the raw header.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_virtual_keys_on_the_same_tenant_share_one_token_budget() {
    // A budget of 2 is exhausted by exactly one exchange -- see this file's
    // module doc for the "hi" (1 token) + "ok" (1 token) = 2 total accounting.
    // An hour-long window: windows are aligned to the epoch (ADR-0006
    // amendment B), so a short one could roll over between the two requests
    // and hand the second a fresh budget.
    let (addr, upstream, scratch, proxy) =
        spawn_suite("auth-shared-tenant-budget", 2, 2.0 / 3600.0).await;

    let first = send_chat_request(addr, &[("authorization", &format!("Bearer {KEY_LIVE}"))]).await;
    assert_eq!(
        first.status, 200,
        "sanity: the first exchange (key-live) must be admitted before the budget is \
         exhausted, got {}: {}",
        first.status, first.body
    );

    let second =
        send_chat_request(addr, &[("authorization", &format!("Bearer {KEY_LIVE_2}"))]).await;
    assert_eq!(
        second.status, 429,
        "a SECOND live key belonging to the SAME tenant must be denied once the tenant's \
         shared budget is exhausted -- got {}: {}. Previously this second, distinct \
         `authorization` header value would have drawn a fresh budget instead of sharing \
         the exhausted one.",
        second.status, second.body
    );

    assert_eq!(
        upstream.log.requests().len(),
        1,
        "the denied second request must never reach the upstream -- only the first, \
         admitted exchange should have dialled it"
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}

// ------------------------------------- the dialect path, with a secret FILE --

/// Render an `llmproxy-v0` **dialect** config (the surface real operators
/// write) with an `auth:` block whose secret comes from a FILE.
///
/// `secret_path` is written by the caller into the scratch dir; the dialect
/// lowers `hmac_secret_file` to the proto's `filename` specifier and
/// deliberately does NOT inline the contents, so the running proxy opens this
/// path itself at listener-bind time.
fn dialect_config(listener_port: u16, upstream_port: u16, secret_path: &std::path::Path) -> String {
    let key_live_digest = digest_hex(HMAC_SECRET, KEY_LIVE);
    format!(
        r#"
version: 0
listen: 127.0.0.1:{listener_port}
auth:
  hmac_secret_file: {secret_file}
  enforce: {{ tenants_without_policy: allow }}
  keys:
    - id: alice-laptop
      tenant: acme
      digest: {key_live_digest}
providers:
  p1:
    base_url: http://127.0.0.1:{upstream_port}
    api_key: {PROVIDER_KEY}
routes:
  - model: "*"
    provider: p1
"#,
        secret_file = secret_path.display(),
    )
}

/// **The dialect surface authenticates a real request, end to end.**
///
/// Every other test in this file hands the proxy a hand-written Envoy
/// bootstrap. The dialect tests in `proxy-simple-config` go the other way:
/// they prove an `auth:` block lowers and that the result satisfies
/// `auth_filter::parse_config`. Neither covers the join — a real operator's
/// `llmproxy.yaml`, consumed by the real binary, authenticating over a
/// socket — and that join is **not** covered by transitivity, for one
/// specific reason:
///
/// **`hmac_secret_file` lowers to a `filename`, not to the file's contents.**
/// The dialect reads the file once at load time purely to validate it, then
/// throws the bytes away and emits the *path*. The running proxy opens that
/// path again itself, later, at listener-bind time
/// (`auth_filter::parse_hmac_secret`). Nothing before this test ever executed
/// that second read: the Envoy-mode suite above uses `inline_string`, and the
/// dialect unit tests stop at the lowered JSON. A path that resolved during
/// lowering but not at bind time — a relative path against a different cwd,
/// a permissions difference, a file removed in between — would pass every
/// other test in this repository and fail every real request with a 401.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dialect_config_with_a_secret_file_authenticates_a_real_request() {
    let upstream = OpenAiUpstream::spawn(upstream_config())
        .await
        .expect("spawn mock upstream");

    let scratch = ScratchDir::new("auth-dialect-secret-file");
    // No trailing newline: `auth_filter::parse_hmac_secret` must key the HMAC
    // on exactly these bytes, and a stray `\n` would change every digest --
    // the same trap the documented `openssl` one-liner warns about (`printf
    // %s`, never a here-string).
    let secret_path = scratch.write("auth-secret", HMAC_SECRET);

    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_yaml = dialect_config(listener_port, upstream.port(), &secret_path);
    let config_path = scratch.write("llmproxy.yaml", &config_yaml);

    let bin = resolve_llm_proxy_bin();
    // `spawn`, not `spawn_envoy`: this is the `--config` dialect path, which
    // is exactly what `spawn_envoy`'s doc says to prefer once an `auth:`
    // block exists. It now does.
    let mut proxy = ProxyProcess::spawn(&bin, &config_path, &scratch.path().join("proxy.log"));
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);

    // A configured key authenticates and reaches the upstream.
    let ok = send_chat_request(
        listener_addr,
        &[("authorization", &format!("Bearer {KEY_LIVE}"))],
    )
    .await;
    assert_eq!(
        ok.status, 200,
        "a key configured through the DIALECT must authenticate against a secret the proxy \
         read from `hmac_secret_file` at bind time, got {}: {}",
        ok.status, ok.body
    );
    assert_eq!(
        upstream.log.requests().len(),
        1,
        "the authenticated request must have reached the upstream"
    );

    // And the fail-closed half, so a config that 200s everything (i.e. one
    // where the auth filter silently never got emitted) cannot pass this
    // test on the strength of the assertion above.
    let denied = send_chat_request(
        listener_addr,
        &[("authorization", &format!("Bearer {UNKNOWN_KEY}"))],
    )
    .await;
    assert_eq!(
        denied.status, 401,
        "an unconfigured key must be refused by the dialect-lowered filter too, got {}: {}",
        denied.status, denied.body
    );
    assert_eq!(
        upstream.log.requests().len(),
        1,
        "the refused request must not have reached the upstream"
    );

    drop(proxy);
    upstream.shutdown().await;
    drop(scratch);
}
