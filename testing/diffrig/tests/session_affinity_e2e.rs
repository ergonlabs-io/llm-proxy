//! Session affinity on a weighted `models` alias, through the real binary
//! (ADR-0016). `session_affinity` lowers to Envoy
//! `weighted_clusters.use_hash_policy` plus a route `hash_policy`; the hash,
//! not a random draw, picks the first provider.
//!
//! The hash is deterministic, so the expected member of every session is
//! computed here from the documented mapping, xxHash64 (seed 0) of the value
//! modulo the total weight over cumulative weights in list order, and the
//! per-provider counts are asserted exactly. That also proves the binary uses
//! that mapping, which a tolerance would not.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, ProxyProcess, RawResponse, ScratchDir,
    READY_TIMEOUT,
};
use diffrig::upstreams::{OpenAiConfig, OpenAiUpstream, RecordedRequest};
use serde_json::json;
use xxhash_rust::xxh64::xxh64;

/// Bounds each client wait so a stalled request fails the test instead of
/// hanging the suite. Not an assertion on timing.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

const KEY_A: &str = "key-provider-a";
const KEY_B: &str = "key-provider-b";
const SESSION_HEADER: &str = "x-session-affinity";
const HEADER_ONLY: &str = "{ header: x-session-affinity }";
const HMAC_SECRET: &str = "session-affinity-e2e-hmac-secret";

async fn spawn_upstream(key: &str, forced_error: Option<u16>) -> OpenAiUpstream {
    OpenAiUpstream::spawn(OpenAiConfig {
        model: "gpt-mock".to_string(),
        response_text: format!("served by {key}"),
        ttft: Duration::from_millis(1),
        inter_token_delay: Duration::from_millis(1),
        require_api_key: Some(key.to_string()),
        forced_error: forced_error.map(|status| (status, "mock upstream failure".to_string())),
        cached_tokens: 0,
    })
    .await
    .expect("spawn mock upstream")
}

struct Proxy {
    addr: SocketAddr,
    admin: SocketAddr,
    _process: ProxyProcess,
    _scratch: ScratchDir,
}

/// Starts the proxy on a dialect config. `{listen}` and `{admin}` in `body`
/// are replaced by the listener and admin addresses.
fn spawn_proxy(label: &str, body: &str) -> Proxy {
    let scratch = ScratchDir::new(label);
    let addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let admin: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let config = body
        .replace("{listen}", &addr.to_string())
        .replace("{admin}", &admin.to_string());
    let path = scratch.write("llmproxy.yaml", &config);
    let mut process = ProxyProcess::spawn(
        &resolve_llm_proxy_bin(),
        &path,
        &scratch.path().join("proxy.log"),
    );
    process.wait_until_ready(addr, READY_TIMEOUT);
    Proxy {
        addr,
        admin,
        _process: process,
        _scratch: scratch,
    }
}

/// A two-provider weighted alias with `session_affinity: {affinity}`, both
/// providers ejected after one 5xx; `extra` is spliced in at the top level.
fn alias_config(
    a: &OpenAiUpstream,
    b: &OpenAiUpstream,
    weights: (u32, u32),
    affinity: &str,
    extra: &str,
) -> String {
    format!(
        r#"
version: 0
listen: "{{listen}}"
admin: "{{admin}}"
{extra}
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
      - {{ provider: a, weight: {} }}
      - {{ provider: b, weight: {} }}
    session_affinity: {affinity}
"#,
        a.port(),
        b.port(),
        weights.0,
        weights.1,
    )
}

async fn chat(addr: SocketAddr, headers: &[(&str, &str)]) -> RawResponse {
    let mut headers = headers.to_vec();
    headers.push(("x-llmproxy-model", "gpt-alias"));
    tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json(
            addr,
            "POST",
            "/v1/chat/completions",
            &headers,
            &json!({ "model": "gpt-alias", "messages": [{ "role": "user", "content": "hi" }] }),
        ),
    )
    .await
    .expect("client request timed out")
}

/// True when the documented mapping sends `value` to provider `a`.
fn pins_to_a(value: &str, weights: (u32, u32)) -> bool {
    xxh64(value.as_bytes(), 0) % u64::from(weights.0 + weights.1) < u64::from(weights.0)
}

fn carries_bearer(request: &RecordedRequest, key: &str) -> bool {
    request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("authorization") && value == &format!("Bearer {key}")
    })
}

fn mentions(request: &RecordedRequest, key: &str) -> bool {
    request.headers.iter().any(|(_, value)| value.contains(key))
}

/// `llmproxy_router_session_affinity_total{outcome}` from the admin
/// listener's Prometheus page (rendered with the `envoy_` stats prefix).
fn affinity_count(admin: SocketAddr, outcome: &str) -> u64 {
    let mut stream = TcpStream::connect(admin).expect("connect admin");
    stream.set_read_timeout(Some(CLIENT_TIMEOUT)).unwrap();
    write!(
        stream,
        "GET /stats/prometheus HTTP/1.1\r\nHost: admin\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut page = String::new();
    stream.read_to_string(&mut page).unwrap();
    let series = format!("outcome=\"{outcome}\"");
    page.lines()
        .find(|l| {
            !l.starts_with('#')
                && l.contains("llmproxy_router_session_affinity_total{")
                && l.contains(&series)
        })
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// 50 requests carrying one session value all reach the provider that value
/// maps to; 50 distinct values on 1:1 and on 3:1 split exactly as the mapping
/// says, and both providers are reached. Every hashed pick is counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_session_reaches_one_provider_and_sessions_split_by_weight() {
    for weights in [(1, 1), (3, 1)] {
        let a = spawn_upstream(KEY_A, None).await;
        let b = spawn_upstream(KEY_B, None).await;
        let proxy = spawn_proxy(
            "affinity-split",
            &alias_config(&a, &b, weights, HEADER_ONLY, ""),
        );

        for i in 0..50 {
            let res = chat(proxy.addr, &[(SESSION_HEADER, "conversation-1")]).await;
            assert_eq!(res.status, 200, "request {i}: {}", res.body);
        }
        let (a_count, b_count) = (a.log.requests().len(), b.log.requests().len());
        let expected = if pins_to_a("conversation-1", weights) {
            (50, 0)
        } else {
            (0, 50)
        };
        assert_eq!((a_count, b_count), expected, "weights {weights:?}");

        let mut expected_a = 0;
        for i in 0..50 {
            let session = format!("session-{i}");
            expected_a += usize::from(pins_to_a(&session, weights));
            let res = chat(proxy.addr, &[(SESSION_HEADER, &session)]).await;
            assert_eq!(res.status, 200, "{session}: {}", res.body);
        }
        let a_split = a.log.requests().len() - a_count;
        let b_split = b.log.requests().len() - b_count;
        assert_eq!(
            (a_split, b_split),
            (expected_a, 50 - expected_a),
            "weights {weights:?}"
        );
        assert!(
            a_split > 0 && b_split > 0,
            "both providers serve some sessions"
        );
        assert_eq!(affinity_count(proxy.admin, "hashed"), 100);

        drop(proxy);
        a.shutdown().await;
        b.shutdown().await;
    }
}

/// A session pinned to `b` while `b` fails: its first request reaches `b`
/// (the pin), fails over inside `b`'s aggregate to `a`, and ejects `b`; the
/// rest of that session goes to `a` only. The fallback request carries `a`'s
/// key and never `b`'s (AGENTS.md invariant 6, asserted as the negative).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ejecting_the_pinned_provider_moves_the_session_with_only_the_fallback_key() {
    let weights = (1, 1);
    let session = (0..)
        .map(|i| format!("pinned-to-b-{i}"))
        .find(|s| !pins_to_a(s, weights))
        .unwrap();
    let a = spawn_upstream(KEY_A, None).await;
    let b = spawn_upstream(KEY_B, Some(500)).await;
    let proxy = spawn_proxy(
        "affinity-eject",
        &alias_config(&a, &b, weights, HEADER_ONLY, ""),
    );

    let res = chat(proxy.addr, &[(SESSION_HEADER, &session)]).await;
    assert_eq!(res.status, 200, "{}", res.body);
    assert_eq!(b.log.requests().len(), 1, "the session was pinned to b");
    assert_eq!(a.log.requests().len(), 1, "and failed over to a");

    for i in 0..10 {
        let res = chat(proxy.addr, &[(SESSION_HEADER, &session)]).await;
        assert_eq!(res.status, 200, "request {i}: {}", res.body);
    }
    assert_eq!(
        b.log.requests().len(),
        1,
        "an ejected provider gets no more of the session"
    );
    assert_eq!(a.log.requests().len(), 11);
    for request in a.log.requests() {
        assert!(carries_bearer(&request, KEY_A), "{:?}", request.headers);
        assert!(!mentions(&request, KEY_B), "{:?}", request.headers);
    }

    drop(proxy);
    a.shutdown().await;
    b.shutdown().await;
}

fn digest_hex(plaintext_key: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, HMAC_SECRET.as_bytes());
    ring::hmac::sign(&key, plaintext_key.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// With no session header, `identity: key` pins each virtual key: every
/// request of a key reaches the provider its key id maps to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_header_each_virtual_key_keeps_its_provider() {
    let weights = (1, 1);
    let ids: Vec<String> = (0..6).map(|i| format!("vk-{i}")).collect();
    let keys: String = ids
        .iter()
        .map(|id| {
            format!(
                "    - {{ id: {id}, tenant: acme, digest: \"{}\" }}\n",
                digest_hex(&format!("llmp_plain-{id}"))
            )
        })
        .collect();
    // Tenant model policy is not under test; without a stored policy it
    // denies by default.
    let auth = format!(
        "auth:\n  hmac_secret: \"{HMAC_SECRET}\"\n  enforce: {{ model_policy: false }}\n  keys:\n{keys}"
    );
    let a = spawn_upstream(KEY_A, None).await;
    let b = spawn_upstream(KEY_B, None).await;
    let proxy = spawn_proxy(
        "affinity-key",
        &alias_config(
            &a,
            &b,
            weights,
            "{ header: x-session-affinity, identity: key }",
            &auth,
        ),
    );

    for id in &ids {
        let (a_before, b_before) = (a.log.requests().len(), b.log.requests().len());
        let bearer = format!("Bearer llmp_plain-{id}");
        for _ in 0..5 {
            let res = chat(proxy.addr, &[("authorization", &bearer)]).await;
            assert_eq!(res.status, 200, "{id}: {}", res.body);
        }
        let served = (
            a.log.requests().len() - a_before,
            b.log.requests().len() - b_before,
        );
        let expected = if pins_to_a(id, weights) {
            (5, 0)
        } else {
            (0, 5)
        };
        assert_eq!(served, expected, "{id}");
    }

    drop(proxy);
    a.shutdown().await;
    b.shutdown().await;
}

/// With `session_affinity` set but no header and no `auth` filling an
/// identity, nothing hashes: the pick is today's random draw (both providers
/// reached over 200 requests; all on one side has probability 2^-199) and
/// every pick counts as `unhashed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_session_value_keeps_the_random_weighted_pick() {
    let a = spawn_upstream(KEY_A, None).await;
    let b = spawn_upstream(KEY_B, None).await;
    let proxy = spawn_proxy(
        "affinity-random",
        &alias_config(&a, &b, (1, 1), HEADER_ONLY, ""),
    );

    for i in 0..200 {
        let res = chat(proxy.addr, &[]).await;
        assert_eq!(res.status, 200, "request {i}: {}", res.body);
    }
    assert!(!a.log.requests().is_empty() && !b.log.requests().is_empty());
    assert_eq!(a.log.requests().len() + b.log.requests().len(), 200);
    assert_eq!(affinity_count(proxy.admin, "unhashed"), 200);
    assert_eq!(affinity_count(proxy.admin, "hashed"), 0);

    drop(proxy);
    a.shutdown().await;
    b.shutdown().await;
}
