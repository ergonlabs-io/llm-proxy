//! **v0.1.0 live ship-gate drill.** `internal-docs/MILESTONES.md` holds v0.1.0 at
//! `current`, not `shipped`, for one reason: its clauses are verified only
//! against mock upstreams (`auth_e2e.rs`, `failover_e2e.rs`). v0.0.1 did not
//! ship on code-complete either -- it shipped on `live_smoke.rs`, a live run
//! against real OpenAI/Anthropic endpoints, actually executed and recorded.
//! This file is that drill for v0.1.0's two clauses that have no live
//! evidence yet: a token-based rate limit enforced against a **real**
//! provider's usage report, and failover that **reaches** a real provider.
//! (The third clause, token counts/TTFT/TPOT, already has live coverage --
//! every request `live_smoke.rs` sends produces a real usage block.)
//!
//! Structural sibling of `live_smoke.rs`: same `#[ignore]` discipline, same
//! "fail loudly naming the missing env var, never skip" rule, same cost
//! warnings. Read that file first if this one is unfamiliar. The assertions
//! below reuse the shape of two mock-based drills: the budget test mirrors
//! `auth_e2e.rs::two_virtual_keys_on_the_same_tenant_share_one_token_budget`,
//! and the credential-swap test mirrors its five single-key auth tests.
//!
//! ## How to run
//!
//! ```sh
//! OPENAI_API_KEY=sk-... cargo test -p diffrig --test live_gate_v0_1_0 -- --ignored
//! ```
//!
//! `OPENAI_API_KEY` must be set. Every test that needs it fails loudly,
//! naming the variable, rather than silently passing or skipping -- a green
//! "skip" here would be exactly the false confidence this gate exists to
//! rule out (`live_smoke.rs` states the same reasoning; it applies unchanged).
//!
//! **This bills your account.** Every prompt is one line and every
//! `max_tokens` is in the single digits or teens, but the file still makes
//! **3 real calls** against OpenAI's production endpoint:
//! - Test 1 (token budget): 1 billable call. The first of its two requests is
//!   admitted and reaches OpenAI; the second is denied by the limiter before
//!   any upstream dial (see the test's own comment for why this is exact,
//!   not probabilistic).
//! - Test 2 (auth + credential swap): 1 billable call. The valid virtual key
//!   reaches OpenAI; the unknown key is refused before routing and never
//!   dials out (also see the test's comment) -- which is why running this
//!   file repeatedly is cheap.
//! - Test 3 (failover): 1 billable call. The primary is a closed local port,
//!   not a second real provider, so the single real call is the fallback
//!   attempt that lands after failover.
//!
//! ## What Test 3 does and does not prove
//!
//! A real provider cannot be forced to fail on demand, so there is no way to
//! build this test against two live endpoints. The primary here is a closed
//! `127.0.0.1` port -- nothing listening, a real connect failure, one of the
//! two retriable failure modes the failover chain is built to fail over on. This
//! proves *failover reaches a real provider*: the request that lands at
//! OpenAI genuinely went through the aggregate-cluster failover mechanism,
//! not a route pointed at OpenAI directly. It does **not** prove *failover
//! between two real providers* -- that both members behave correctly when
//! both are real endpoints is not something this test can arrange, and it
//! isn't the gap this drill exists to close: `failover_e2e.rs` already
//! proves the primary-side mechanics (attempt accounting, credential
//! isolation, host-rewrite-per-member) against two mocks, verified and
//! mutation-tested. What no test before this one proved is that the fallback
//! LEG of that chain is a real dial that a real provider answers.
//!
//! ## Harness
//!
//! `diffrig::harness` (the real `llm-proxy` binary, dialect config, polled
//! listener readiness, plain-file captured stdout/stderr) exactly as
//! `live_smoke.rs` uses it -- see that file's module doc for why no `ca_file`
//! override is needed against `https://api.openai.com`. `${OPENAI_API_KEY}`
//! is interpolated by the dialect at load time (`parse.rs::interpolate_env`),
//! so the real key is never written to disk by this test.
//!
//! ## Why every request is `x-llmproxy-model`-free
//!
//! Earlier e2e files set an `x-llmproxy-model` header explicitly. That became
//! redundant once `body_rewrite_filter` started deriving the routing header
//! from the request body's own `model` field (and stripping any
//! client-supplied one, since trusting a client header for routing would let a
//! client route itself around a fallback chain), so
//! every request below routes on `"model"` in its JSON body alone, the same
//! way `auth_e2e.rs` already does.

use std::net::SocketAddr;
use std::time::Duration;

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, ProxyProcess, RawResponse, ScratchDir,
    READY_TIMEOUT,
};
use serde_json::json;

// ------------------------------------------------------------------ config --

/// Real endpoints are slower than the in-process mocks the rest of this test
/// suite talks to -- `auth_e2e.rs`'s equivalent constant is 10s, which is
/// tuned for a loopback mock answering in single-digit milliseconds. 30s
/// gives OpenAI's real public API (plus whatever the proxy itself adds)
/// generous headroom while still turning an actually-hung request into a
/// named test failure instead of eating the whole suite's wall clock.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

const OPENAI_MODEL: &str = "gpt-4o-mini";

/// Fail loudly, naming the variable, rather than silently skipping -- see
/// `live_smoke.rs`'s identical helper and module-doc reasoning.
fn require_env(var: &str) {
    if std::env::var(var).is_err() {
        panic!(
            "{var} is not set; this ship-gate test needs a real API key -- \
             run as `{var}=... cargo test -p diffrig --test live_gate_v0_1_0 -- --ignored`"
        );
    }
}

/// One small real chat-completion body: a one-line prompt and a tiny
/// `max_tokens`, per this file's cost budget.
fn chat_body(max_tokens: u32, prompt: &str) -> serde_json::Value {
    json!({
        "model": OPENAI_MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    })
}

/// Send one chat-completion request through the proxy, bounded by
/// [`CLIENT_TIMEOUT`] so a stuck request fails this test instead of hanging
/// the suite.
async fn send_chat_request(
    addr: SocketAddr,
    headers: &[(&str, &str)],
    max_tokens: u32,
) -> RawResponse {
    tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json(
            addr,
            "POST",
            "/v1/chat/completions",
            headers,
            &chat_body(max_tokens, "Reply with exactly one short word."),
        ),
    )
    .await
    .expect("client request timed out against the real OpenAI API")
}

/// Spawn the real proxy (dialect mode) against `config_yaml`, whose listener
/// is already bound to `listener_port`. Guards are returned so the caller
/// controls drop order, same convention as `live_smoke.rs`/`auth_e2e.rs`.
fn spawn_live_proxy(
    label: &str,
    listener_port: u16,
    config_yaml: &str,
) -> (SocketAddr, ScratchDir, ProxyProcess) {
    let scratch = ScratchDir::new(label);
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_path = scratch.write("llmproxy.yaml", config_yaml);

    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyProcess::spawn(&bin, &config_path, &scratch.path().join("proxy.log"));
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);
    (listener_addr, scratch, proxy)
}

// ============================================================ test 1: limits =

/// Dialect config: one real `openai` provider plus a `limits:` block bucketed
/// on the client's own `authorization` header, budget `10`. No `auth:` block
/// -- the header here is only the limiter's bucket key, not a credential; the
/// real provider credential is injected by the cluster (ground rule #6), so
/// whatever the client puts in `authorization` never reaches OpenAI.
fn token_budget_config(listener_port: u16) -> String {
    format!(
        r#"
version: 0
listen: "127.0.0.1:{listener_port}"
providers:
  openai:
    api_key: ${{OPENAI_API_KEY}}
routes:
  - model: "gpt-*"
    provider: openai
limits:
  - key: header:authorization
    tokens_per_minute: 10
"#
    )
}

/// **The clause with no live evidence, and the part a mock cannot prove**:
/// the limiter records tokens parsed out of a REAL provider's usage block,
/// not a value the test controls.
///
/// Why a budget of `10` is deterministic, not flaky -- `token_limit_filter`
/// (see also `auth_e2e.rs`'s Test 7) checks the budget BEFORE a request and
/// records actual usage AFTER it completes. The bucket starts empty, so the
/// first request is always admitted regardless of what it ends up costing.
/// Any real chat completion -- even one word, even `max_tokens: 8` -- costs
/// more than 10 tokens once the prompt, the model's reply, and OpenAI's own
/// bookkeeping are all counted, so the second request is always denied. This
/// does not depend on OpenAI's exact token accounting for any particular
/// prompt, only on a real completion costing more than 10 tokens in total --
/// true by a wide margin for any request this file could plausibly send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "hits the real OpenAI API and bills tokens; run with --ignored"]
async fn a_token_budget_is_enforced_against_a_real_providers_usage_report() {
    require_env("OPENAI_API_KEY");

    let listener_port = free_port();
    let config = token_budget_config(listener_port);
    let (addr, scratch, proxy) = spawn_live_proxy("live-gate-token-budget", listener_port, &config);

    let bucket_key = [("authorization", "Bearer live-gate-token-budget-bucket")];

    let first = send_chat_request(addr, &bucket_key, 8).await;
    assert_eq!(
        first.status, 200,
        "the first request must always be admitted -- the budget starts empty regardless of \
         cost, got {}: {}",
        first.status, first.body
    );

    let second = send_chat_request(addr, &bucket_key, 8).await;
    assert_eq!(
        second.status, 429,
        "a second request against the same bucket must be denied once the first real \
         completion's usage (necessarily > 10 tokens) exhausted the budget of 10, got {}: {}",
        second.status, second.body
    );
    for header in [
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    ] {
        assert!(
            second
                .headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case(header)),
            "expected `{header}` on the 429 response, got: {:?}",
            second.headers
        );
    }

    drop(proxy);
    drop(scratch);
}

// =============================================================== test 2: auth =

const HMAC_SECRET: &str = "llm-proxy-v0-1-0-live-gate-hmac-secret-never-reused-elsewhere";
const KEY_LIVE: &str = "llmp_live-gate-key";
/// Well-formed (`llmp_`-prefixed) but never configured -- same "credential
/// presented, unknown" shape `auth_e2e.rs`'s `UNKNOWN_KEY` exercises.
const UNKNOWN_KEY: &str = "llmp_live-gate-never-configured";

/// `hex(HMAC-SHA256(secret, plaintext_key))`, computed the same way
/// `auth_filter::VirtualKeyAuthenticator` verifies a presented key -- see
/// `auth_e2e.rs`'s identical helper for why this must never be a hardcoded
/// literal (it would silently stop matching the day the derivation changed,
/// and this drill would "pass" by 401ing the request meant to succeed).
fn digest_hex(secret: &str, plaintext_key: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let digest = ring::hmac::sign(&key, plaintext_key.as_bytes());
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Dialect config: the same real `openai` provider, plus an `auth:` block
/// with one virtual key. The secret is delivered via `hmac_secret_file`
/// (a path into the scratch dir), not inlined as `${VAR}` -- unlike the
/// OpenAI API key, this secret has no reason to come from the operator's
/// environment (it never leaves this test process), and a file read at
/// listener-bind time is the path `auth_e2e.rs`'s own dialect test already
/// verified end to end, so reusing it here needs no new trust. It also
/// sidesteps mutating process-wide environment state from within a test
/// body, which `std::env::set_var` would require for the `${VAR}` route.
fn auth_swap_config(listener_port: u16, upstream_secret_path: &std::path::Path) -> String {
    let key_live_digest = digest_hex(HMAC_SECRET, KEY_LIVE);
    format!(
        r#"
version: 0
listen: "127.0.0.1:{listener_port}"
auth:
  hmac_secret_file: {secret_file}
  keys:
    - id: live-gate-vk
      tenant: live-gate
      digest: {key_live_digest}
providers:
  openai:
    api_key: ${{OPENAI_API_KEY}}
routes:
  - model: "gpt-*"
    provider: openai
"#,
        secret_file = upstream_secret_path.display(),
    )
}

/// Authentication in front of a real provider, and the credential swap.
///
/// Three things this test proves:
/// - the virtual key authenticates and the request returns 200 from the real
///   OpenAI API;
/// - **that 200 IS the proof of credential replacement.** There is no mock
///   here to inspect the upstream's received headers, and none is needed: if
///   the proxy had forwarded the client's virtual key (`llmp_...`, never a
///   valid OpenAI credential) upstream instead of substituting the real
///   provider key, OpenAI would reject it outright. A real 200 is only
///   obtainable if ground rule #6's swap actually happened on this request.
/// - an unknown `llmp_`-prefixed key returns 401. This case makes no upstream
///   call at all -- the auth filter runs and refuses the request before
///   routing ever selects a cluster to dial -- which is why running this
///   file repeatedly costs nothing extra beyond the two calls the other two
///   tests make.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "hits the real OpenAI API and bills tokens; run with --ignored"]
async fn a_virtual_key_authenticates_and_proves_the_credential_swap_against_a_real_provider() {
    require_env("OPENAI_API_KEY");

    let scratch = ScratchDir::new("live-gate-auth-swap");
    // No trailing newline -- `auth_filter::parse_hmac_secret` keys the HMAC
    // on exactly these bytes, same caveat `auth_e2e.rs`'s dialect test notes.
    let secret_path = scratch.write("auth-secret", HMAC_SECRET);

    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config = auth_swap_config(listener_port, &secret_path);
    let config_path = scratch.write("llmproxy.yaml", &config);

    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyProcess::spawn(&bin, &config_path, &scratch.path().join("proxy.log"));
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);

    let authenticated = send_chat_request(
        listener_addr,
        &[("authorization", &format!("Bearer {KEY_LIVE}"))],
        8,
    )
    .await;
    assert_eq!(
        authenticated.status, 200,
        "expected the virtual key to authenticate and the swapped-credential request to reach \
         the real OpenAI API, got {}: {}",
        authenticated.status, authenticated.body
    );
    let parsed: serde_json::Value = serde_json::from_str(&authenticated.body)
        .expect("OpenAI response body must be well-formed JSON");
    assert!(
        parsed["choices"][0]["message"]["content"]
            .as_str()
            .is_some_and(|c| !c.trim().is_empty()),
        "expected non-empty assistant content from the real API, got: {parsed}"
    );

    let refused = send_chat_request(
        listener_addr,
        &[("authorization", &format!("Bearer {UNKNOWN_KEY}"))],
        8,
    )
    .await;
    assert_eq!(
        refused.status, 401,
        "an unknown key must be refused before any upstream dial, got {}: {}",
        refused.status, refused.body
    );

    drop(proxy);
    drop(scratch);
}

// =========================================================== test 3: failover =

const CLOSED_PORT_KEY: &str = "unused-primary-key-nothing-listens-here";

/// Dialect config: `primary` addresses a closed local port (nothing
/// listening -- a real connect failure) and `fallback` addresses the real
/// `https://api.openai.com`. Neither is named `openai`/`anthropic`, so both
/// default to `openai-compatible` (`Provider::effective_type`) -- same
/// dialect on both sides, the only shape a fallback chain accepts
/// (`crates/proxy-simple-config/tests/fallbacks.rs::cross_dialect_fallback_is_rejected`).
/// No explicit `retries:` needed: `lower.rs`'s default retry policy already
/// includes `connect-failure` and sizes `num_retries` to reach every
/// configured member.
fn failover_config(listener_port: u16, closed_port: u16) -> String {
    format!(
        r#"
version: 0
listen: "127.0.0.1:{listener_port}"
providers:
  primary:
    base_url: "http://127.0.0.1:{closed_port}"
    api_key: "{CLOSED_PORT_KEY}"
  fallback:
    base_url: "https://api.openai.com"
    api_key: ${{OPENAI_API_KEY}}
routes:
  - model: "gpt-*"
    provider: primary
    fallbacks: [fallback]
"#
    )
}

/// Failover reaches a real provider. The primary is a closed local port, so
/// every attempt against it fails to connect -- a retriable failure
/// (`retry_on: connect-failure`) -- and the router must fail over to
/// `fallback`, whose base URL is the real OpenAI endpoint. See this file's
/// module doc ("What Test 3 does and does not prove") for what this test
/// does and does not establish: it proves the FALLBACK leg of the chain is a
/// real dial a real provider answers, not that two real providers can fail
/// over between each other -- forcing a real provider to fail on demand
/// isn't something a test can arrange, and the primary-side mechanics
/// (attempt accounting, credential isolation, per-member host rewrite) are
/// already covered against two mocks by `failover_e2e.rs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "hits the real OpenAI API and bills tokens; run with --ignored"]
async fn failover_reaches_a_real_provider_when_the_primary_cannot_be_connected_to() {
    require_env("OPENAI_API_KEY");

    // Rust note: reserve a port and drop the listener immediately (same
    // `free_port` used for the proxy's own listener), so nothing is bound
    // there when the proxy tries to connect -- a real connect failure rather
    // than a request the local OS itself never even attempts.
    let closed_port = free_port();
    let listener_port = free_port();
    let config = failover_config(listener_port, closed_port);
    let (addr, scratch, proxy) = spawn_live_proxy("live-gate-failover", listener_port, &config);

    let res = send_chat_request(addr, &[], 16).await;

    assert_eq!(
        res.status, 200,
        "expected the request to fail over from the closed primary and reach the real OpenAI \
         API via the fallback, got {}: {}",
        res.status, res.body
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&res.body).expect("OpenAI response body must be well-formed JSON");
    assert_eq!(
        parsed["model"]
            .as_str()
            .map(|m| m.starts_with(OPENAI_MODEL)),
        Some(true),
        "expected the model field to echo the requested model, got: {}",
        parsed["model"]
    );
    assert!(
        parsed["choices"][0]["message"]["content"]
            .as_str()
            .is_some_and(|c| !c.trim().is_empty()),
        "expected non-empty assistant content from the real fallback, got: {parsed}"
    );

    drop(proxy);
    drop(scratch);
}
