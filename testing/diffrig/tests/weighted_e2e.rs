//! Weighted, health-aware selection among a `models` alias's providers,
//! through the real binary.
//!
//! `models.<name>.providers[i].weight` lowers to Envoy `weighted_clusters`
//! over one aggregate per weighted provider (S1.5); `outlier_detection` on a
//! provider ejects it, and an aggregate passes an ejected member over. These
//! tests drive both through the dialect (`--config`), and the billing test
//! runs the lowered bootstrap in Envoy mode (`-c`), so both front-ends reach
//! the same behaviour (AGENTS.md invariant 5).

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, send_json_collect_sse, ProxyProcess, RawResponse,
    ScratchDir, READY_TIMEOUT,
};
use diffrig::upstreams::{OpenAiConfig, OpenAiUpstream, RecordedRequest};
use serde_json::{json, Value};

/// Bounds each client wait so a stalled request fails the test instead of
/// hanging the suite. Not an assertion on timing.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

const KEY_A: &str = "key-provider-a";
const KEY_B: &str = "key-provider-b";
const KEY_C: &str = "key-provider-c";

fn upstream(key: &str, forced_error: Option<u16>) -> OpenAiConfig {
    OpenAiConfig {
        model: "gpt-mock".to_string(),
        response_text: format!("served by {key}"),
        ttft: Duration::from_millis(1),
        inter_token_delay: Duration::from_millis(1),
        require_api_key: Some(key.to_string()),
        forced_error: forced_error.map(|status| (status, "mock upstream failure".to_string())),
        cached_tokens: 0,
    }
}

async fn spawn_upstream(key: &str, forced_error: Option<u16>) -> OpenAiUpstream {
    OpenAiUpstream::spawn(upstream(key, forced_error))
        .await
        .expect("spawn mock upstream")
}

/// Starts the proxy on a dialect config. `{listen}` in `body` is replaced by
/// the listener address.
fn spawn_proxy(label: &str, body: &str) -> (SocketAddr, ScratchDir, ProxyProcess) {
    let scratch = ScratchDir::new(label);
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config = body.replace("{listen}", &addr.to_string());
    let path = scratch.write("llmproxy.yaml", &config);
    let mut proxy = ProxyProcess::spawn(
        &resolve_llm_proxy_bin(),
        &path,
        &scratch.path().join("proxy.log"),
    );
    proxy.wait_until_ready(addr, READY_TIMEOUT);
    (addr, scratch, proxy)
}

async fn chat(addr: SocketAddr, model: &str) -> RawResponse {
    tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json(
            addr,
            "POST",
            "/v1/chat/completions",
            &[("x-llmproxy-model", model)],
            &json!({ "model": model, "messages": [{ "role": "user", "content": "hi" }] }),
        ),
    )
    .await
    .expect("client request timed out")
}

fn carries_bearer(request: &RecordedRequest, key: &str) -> bool {
    request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("authorization") && value == &format!("Bearer {key}")
    })
}

fn mentions(request: &RecordedRequest, key: &str) -> bool {
    request.headers.iter().any(|(_, value)| value.contains(key))
}

/// Weights 3:1 over 2000 requests. The router draws the split uniformly per
/// request (`router.rs`, `ForwardTarget::Weighted`); there is no per-worker
/// rotation state, so the split is the same with any `--concurrency` and the
/// only deviation is sampling. Provider `a`'s count is Binomial(2000, 0.75):
/// mean 1500, standard deviation 19.4. The tolerance is +-120 (about 6.2
/// standard deviations, a 75% +- 6% share), which a correct split misses
/// with probability below 1e-9. The exact mapping of draws to providers is
/// pinned deterministically by
/// `proxy-simple-config/tests/weighted_models.rs::every_draw_starts_at_the_provider_its_weight_owns`.
///
/// The same run asserts the model property: every request reaches a member
/// of the alias with that member's own upstream model ID and key, and a
/// provider outside the alias gets nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_split_follows_the_weights_and_every_request_gets_the_aliass_model() {
    const N: usize = 2000;
    let a = spawn_upstream(KEY_A, None).await;
    let b = spawn_upstream(KEY_B, None).await;
    let c = spawn_upstream(KEY_C, None).await;
    let config = format!(
        r#"
version: 1
listen: "{{listen}}"
providers:
  a: {{ type: openai-compatible, base_url: "http://127.0.0.1:{}", api_key: {KEY_A} }}
  b: {{ type: openai-compatible, base_url: "http://127.0.0.1:{}", api_key: {KEY_B} }}
  c: {{ type: openai-compatible, base_url: "http://127.0.0.1:{}", api_key: {KEY_C} }}
routes: []
models:
  gpt-alias:
    providers:
      - {{ provider: a, model: a-upstream-model, weight: 3 }}
      - {{ provider: b, model: b-upstream-model, weight: 1 }}
  other-model:
    providers: [c/c-upstream-model]
"#,
        a.port(),
        b.port(),
        c.port()
    );
    let (addr, scratch, proxy) = spawn_proxy("weighted-split", &config);

    for i in 0..N {
        let res = chat(addr, "gpt-alias").await;
        assert_eq!(res.status, 200, "request {i}: {}", res.body);
    }

    let a_count = a.log.requests().len();
    let b_count = b.log.requests().len();
    assert_eq!(a_count + b_count, N, "each request dialled exactly once");
    assert!(
        a_count.abs_diff(1500) <= 120,
        "provider a served {a_count} of {N}; weights 3:1 expect 1500 +- 120"
    );
    assert!(
        c.log.requests().is_empty(),
        "a provider outside the alias was dialled"
    );

    for (upstream, key, other_key, model) in [
        (&a, KEY_A, KEY_B, "a-upstream-model"),
        (&b, KEY_B, KEY_A, "b-upstream-model"),
    ] {
        for body in upstream.bodies.bodies() {
            assert_eq!(
                body["model"], model,
                "a member served another model: {body}"
            );
        }
        for request in upstream.log.requests() {
            assert!(carries_bearer(&request, key));
            assert!(!mentions(&request, other_key), "{:?}", request.headers);
        }
    }

    drop(proxy);
    drop(scratch);
    for upstream in [a, b, c] {
        upstream.shutdown().await;
    }
}

/// Weights `b: 1, a: 0` make every request start at `b`, so the order is
/// deterministic. `b` answers every request with 500 and is ejected after
/// one (`consecutive_5xx: 1`) for 300 s, longer than any test run. The first
/// request fails over to `a`. After that, `b` must get no traffic at all:
/// without the aggregate's healthy preference, `b`'s own panic pick would
/// keep dialling it, and each request would still reach `a` on retry, so only
/// `b`'s request count shows the difference.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ejected_provider_gets_no_weighted_traffic() {
    let a = spawn_upstream(KEY_A, None).await;
    let b = spawn_upstream(KEY_B, Some(500)).await;
    let config = format!(
        r#"
version: 1
listen: "{{listen}}"
providers:
  a: {{ type: openai-compatible, base_url: "http://127.0.0.1:{}", api_key: {KEY_A} }}
  b:
    type: openai-compatible
    base_url: "http://127.0.0.1:{}"
    api_key: {KEY_B}
    outlier_detection: {{ consecutive_5xx: 1, base_ejection_time: 300s }}
routes: []
models:
  gpt-alias:
    providers:
      - {{ provider: a, weight: 0 }}
      - {{ provider: b, weight: 1 }}
"#,
        a.port(),
        b.port()
    );
    let (addr, scratch, proxy) = spawn_proxy("weighted-ejection", &config);

    let first = chat(addr, "gpt-alias").await;
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(b.log.requests().len(), 1, "the weighted pick tried b first");
    assert_eq!(a.log.requests().len(), 1, "and failed over to a");

    for i in 0..20 {
        let res = chat(addr, "gpt-alias").await;
        assert_eq!(res.status, 200, "request {i}: {}", res.body);
    }
    assert_eq!(
        b.log.requests().len(),
        1,
        "ejected b received weighted traffic"
    );
    assert_eq!(a.log.requests().len(), 21);

    drop(proxy);
    drop(scratch);
    a.shutdown().await;
    b.shutdown().await;
}

/// After the ejection ends, the weighted pick reaches `b` again. `b`'s mock
/// fails only its first request; its ejection is 1 s. The loop sends
/// requests until `b` serves one; the deadline is a hang guard, not a timing
/// assertion, and every request on the way must succeed through `a`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ejected_provider_gets_weighted_traffic_again_after_it_recovers() {
    use diffrig::upstreams::{Action, FailScript, FlakyUpstream};

    let a = spawn_upstream(KEY_A, None).await;
    let b = FlakyUpstream::spawn(FailScript::new(vec![
        Action::Respond(500),
        Action::Respond(200),
    ]))
    .await
    .expect("spawn flaky upstream");
    let config = format!(
        r#"
version: 1
listen: "{{listen}}"
providers:
  a: {{ type: openai-compatible, base_url: "http://127.0.0.1:{}", api_key: {KEY_A} }}
  b:
    type: openai-compatible
    base_url: "http://127.0.0.1:{}"
    outlier_detection: {{ consecutive_5xx: 1, base_ejection_time: 1s }}
routes: []
models:
  gpt-alias:
    providers:
      - {{ provider: a, weight: 0 }}
      - {{ provider: b, weight: 1 }}
"#,
        a.port(),
        b.addr().port()
    );
    let (addr, scratch, proxy) = spawn_proxy("weighted-recovery", &config);

    let first = chat(addr, "gpt-alias").await;
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(b.log.requests().len(), 1);

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while b.log.requests().len() < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "b never received traffic again after its 1 s ejection"
        );
        let res = chat(addr, "gpt-alias").await;
        assert_eq!(res.status, 200, "{}", res.body);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    drop(proxy);
    drop(scratch);
    a.shutdown().await;
    b.shutdown().await;
}

/// With every provider of the alias down, the request still walks the whole
/// chain and the client gets the last provider's own answer, as an
/// unweighted alias does (review M4), not a synthesized 503.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fully_down_weighted_alias_returns_the_exhausted_chain_answer() {
    let a = spawn_upstream(KEY_A, Some(503)).await;
    let b = spawn_upstream(KEY_B, Some(503)).await;
    let config = format!(
        r#"
version: 1
listen: "{{listen}}"
providers:
  a:
    type: openai-compatible
    base_url: "http://127.0.0.1:{}"
    api_key: {KEY_A}
    outlier_detection: {{ consecutive_5xx: 1, base_ejection_time: 300s }}
  b:
    type: openai-compatible
    base_url: "http://127.0.0.1:{}"
    api_key: {KEY_B}
    outlier_detection: {{ consecutive_5xx: 1, base_ejection_time: 300s }}
routes: []
models:
  gpt-alias:
    providers:
      - {{ provider: a, weight: 1 }}
      - {{ provider: b, weight: 1 }}
"#,
        a.port(),
        b.port()
    );
    let (addr, scratch, proxy) = spawn_proxy("weighted-all-down", &config);

    // The first request ejects both. The rest run with both ejected.
    for i in 1..=4 {
        let res = chat(addr, "gpt-alias").await;
        assert_eq!(res.status, 503, "request {i}: {}", res.body);
        assert!(
            res.body.contains("mock upstream failure"),
            "request {i} got a synthesized answer, not the provider's: {}",
            res.body
        );
        assert_eq!(
            a.log.requests().len() + b.log.requests().len(),
            2 * i,
            "request {i} must try both providers once"
        );
    }

    drop(proxy);
    drop(scratch);
    a.shutdown().await;
    b.shutdown().await;
}

// ------------------------------------------------------------- billing --

fn billing_config(listen: SocketAddr, openai_port: u16, standby_port: u16, log: &Path) -> String {
    format!(
        r#"
version: 1
listen: "{listen}"
providers:
  openai:
    base_url: "http://127.0.0.1:{openai_port}"
    api_key: "{KEY_A}"
  standby:
    type: openai-compatible
    base_url: "http://127.1:{standby_port}"
    api_key: "{KEY_B}"
routes: []
models:
  gpt-alias:
    providers:
      - {{ provider: openai, model: openai-upstream-model, weight: 0 }}
      - {{ provider: standby, model: standby-upstream-model, weight: 1 }}
pricing:
  price_list:
    version: weighted-card
    effective_from: "2026-01-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: openai-upstream-model
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
        log.display()
    )
}

fn read_access_log_line(path: &Path) -> String {
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

/// The weighted pick is `standby` (weight 1), which 429s; the request fails
/// over to `openai` (weight 0). The fallback attempt carries `openai`'s key
/// and not `standby`'s, the weighted attempt carries `standby`'s and not
/// `openai`'s (the `credential_isolation_across_failover` pattern), and the
/// request is charged at `openai`'s rate card for `openai`'s upstream model.
/// Runs the lowered bootstrap in Envoy mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failover_after_a_weighted_pick_isolates_credentials_and_charges_the_dialled_provider() {
    let openai = spawn_upstream(KEY_A, None).await;
    let standby = spawn_upstream(KEY_B, Some(429)).await;
    let scratch = ScratchDir::new("weighted-billing");
    let listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let access_log = scratch.path().join("access.log");
    let dialect = billing_config(listen, openai.port(), standby.port(), &access_log);
    let simple = proxy_simple_config::parse_simple_config(&dialect).expect("parse");
    let mut bootstrap = proxy_simple_config::lower(&simple)
        .expect("lower")
        .bootstrap;
    bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"]["access_log"][0]["typed_config"]["log_format"] = json!({
        "text_format": "%UPSTREAM_CLUSTER% %LLM_INPUT_TOKENS% %LLM_OUTPUT_TOKENS% %LLM_LIST_COST% %LLM_REQUESTED_MODEL% %LLM_SELECTED_MODEL% %RESPONSE_CODE%\n"
    });
    let config_path = scratch.write(
        "envoy.yaml",
        &serde_yaml::to_string(&bootstrap).expect("serialize"),
    );
    let mut proxy = ProxyProcess::spawn_envoy(
        &resolve_llm_proxy_bin(),
        &config_path,
        &scratch.path().join("proxy.log"),
    );
    proxy.wait_until_ready(listen, READY_TIMEOUT);

    let (status, _, events) = tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json_collect_sse(
            listen,
            "POST",
            "/v1/chat/completions",
            &[("x-llmproxy-model", "gpt-alias")],
            &json!({
                "model": "gpt-alias",
                "messages": [{ "role": "user", "content": "hi there" }],
                "stream": true,
            }),
        ),
    )
    .await
    .expect("weighted failover timed out");
    assert_eq!(status, 200);
    assert!(events.iter().any(|event| event.data.contains(KEY_A)));

    let weighted = standby.log.requests();
    let fallback = openai.log.requests();
    assert_eq!(weighted.len(), 1, "the weighted pick dialled standby once");
    assert_eq!(fallback.len(), 1, "and failed over to openai once");
    assert!(carries_bearer(&weighted[0], KEY_B));
    assert!(!mentions(&weighted[0], KEY_A), "{:?}", weighted[0].headers);
    assert!(carries_bearer(&fallback[0], KEY_A));
    assert!(
        !mentions(&fallback[0], KEY_B),
        "the weighted pick's key followed the request to the fallback: {:?}",
        fallback[0].headers
    );
    let fallback_body: Value = openai.bodies.bodies()[0].clone();
    assert_eq!(fallback_body["model"], "openai-upstream-model");

    // 2 input + 3 output tokens (the mock streams one token per word of
    // `served by key-provider-a`) at openai's $1/token = $5; standby's card
    // would charge 2 * $2 + 3 * $3 = $13.
    assert_eq!(
        read_access_log_line(&access_log),
        "provider:openai 2 3 5000000000 gpt-alias openai-upstream-model 200"
    );

    drop(proxy);
    drop(scratch);
    openai.shutdown().await;
    standby.shutdown().await;
}
