//! `observability.routing_headers`: the response names the provider that
//! served it, the attempt count and the providers tried, through the real
//! binary (`envoy-divergences.md` row 49).

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::net::SocketAddr;
use std::time::Duration;

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, send_json_collect_sse, ProxyProcess, ScratchDir,
    READY_TIMEOUT,
};
use diffrig::upstreams::{OpenAiConfig, OpenAiUpstream};
use serde_json::json;

/// Bounds each client wait so a stalled request fails the test instead of
/// hanging the suite. Not an assertion on timing.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

const KEY_A: &str = "key-provider-a";
const KEY_B: &str = "key-provider-b";
const ROUTING_HEADERS: [&str; 3] = [
    "x-llmproxy-provider",
    "x-envoy-attempt-count",
    "x-llmproxy-providers-tried",
];

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

/// A two-provider model, `a` first; `a` answers 503, so every request fails
/// over to `b` on its second attempt.
fn spawn_proxy(
    label: &str,
    a: u16,
    b: u16,
    routing_headers: bool,
) -> (SocketAddr, ScratchDir, ProxyProcess) {
    let scratch = ScratchDir::new(label);
    let listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let observability = if routing_headers {
        "observability: { routing_headers: true }\n"
    } else {
        ""
    };
    let config = format!(
        r#"
version: 1
listen: "{listen}"
providers:
  a: {{ type: openai-compatible, base_url: "http://127.0.0.1:{a}", api_key: {KEY_A} }}
  b: {{ type: openai-compatible, base_url: "http://127.0.0.1:{b}", api_key: {KEY_B} }}
routes: []
models:
  gpt-alias:
    providers: [a, b]
{observability}"#
    );
    let path = scratch.write("llmproxy.yaml", &config);
    let mut proxy = ProxyProcess::spawn(
        &resolve_llm_proxy_bin(),
        &path,
        &scratch.path().join("proxy.log"),
    );
    proxy.wait_until_ready(listen, READY_TIMEOUT);
    (listen, scratch, proxy)
}

fn body(stream: bool) -> serde_json::Value {
    json!({
        "model": "gpt-alias",
        "stream": stream,
        "messages": [{ "role": "user", "content": "hi" }],
    })
}

/// The response heads of one plain and one streaming request after a
/// failover from `a` to `b`.
async fn failover_heads(addr: SocketAddr) -> Vec<Vec<(String, String)>> {
    let headers = [("x-llmproxy-model", "gpt-alias")];
    let plain = tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json(addr, "POST", "/v1/chat/completions", &headers, &body(false)),
    )
    .await
    .expect("plain request timed out");
    assert_eq!(plain.status, 200, "{}", plain.body);
    let (status, streamed, events) = tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json_collect_sse(addr, "POST", "/v1/chat/completions", &headers, &body(true)),
    )
    .await
    .expect("streaming request timed out");
    assert_eq!(status, 200);
    assert!(events.iter().any(|event| event.data.contains(KEY_B)));
    vec![plain.headers, streamed]
}

fn header<'a>(head: &'a [(String, String)], name: &str) -> Option<&'a str> {
    head.iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// With the switch on, a plain and a streaming response each name the
/// fallback provider, two attempts, and both providers in the order tried.
/// No value carries either provider's key or an upstream host or port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failover_names_the_fallback_provider_and_both_attempts() {
    let a = spawn_upstream(KEY_A, Some(503)).await;
    let b = spawn_upstream(KEY_B, None).await;
    let (addr, scratch, proxy) = spawn_proxy("routing-headers-on", a.port(), b.port(), true);

    for head in failover_heads(addr).await {
        assert_eq!(
            header(&head, "x-llmproxy-provider"),
            Some("provider:b"),
            "{head:?}"
        );
        assert_eq!(
            header(&head, "x-envoy-attempt-count"),
            Some("2"),
            "{head:?}"
        );
        assert_eq!(
            header(&head, "x-llmproxy-providers-tried"),
            Some("provider:a,provider:b"),
            "{head:?}"
        );
        for name in ROUTING_HEADERS {
            let value = header(&head, name).unwrap();
            for secret in [
                KEY_A.to_string(),
                KEY_B.to_string(),
                "127.0.0.1".to_string(),
                a.port().to_string(),
                b.port().to_string(),
            ] {
                assert!(
                    !value.contains(&secret),
                    "{name}: {value} discloses {secret}"
                );
            }
        }
    }
    assert_eq!(a.log.requests().len(), 2, "each request tried a first");
    assert_eq!(b.log.requests().len(), 2);

    drop(proxy);
    drop(scratch);
    a.shutdown().await;
    b.shutdown().await;
}

/// Off by default: the same failover sets none of the headers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_the_switch_no_routing_header_is_set() {
    let a = spawn_upstream(KEY_A, Some(503)).await;
    let b = spawn_upstream(KEY_B, None).await;
    let (addr, scratch, proxy) = spawn_proxy("routing-headers-off", a.port(), b.port(), false);

    for head in failover_heads(addr).await {
        for name in ROUTING_HEADERS {
            assert_eq!(header(&head, name), None, "{name} in {head:?}");
        }
    }
    assert_eq!(
        b.log.requests().len(),
        2,
        "the failover itself still happened"
    );

    drop(proxy);
    drop(scratch);
    a.shutdown().await;
    b.shutdown().await;
}

/// Both providers refuse the connection, so the proxy answers with its own
/// 503. The answer lists both attempts but names no serving provider: no
/// provider served it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_reply_lists_the_attempts_but_names_no_provider() {
    // Nothing listens on either port.
    let (addr, scratch, proxy) =
        spawn_proxy("routing-headers-local", free_port(), free_port(), true);

    let res = tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json(
            addr,
            "POST",
            "/v1/chat/completions",
            &[("x-llmproxy-model", "gpt-alias")],
            &body(false),
        ),
    )
    .await
    .expect("request timed out");
    assert_eq!(res.status, 503, "{}", res.body);
    assert_eq!(
        header(&res.headers, "x-llmproxy-provider"),
        None,
        "{:?}",
        res.headers
    );
    assert_eq!(header(&res.headers, "x-envoy-attempt-count"), Some("2"));
    assert_eq!(
        header(&res.headers, "x-llmproxy-providers-tried"),
        Some("provider:a,provider:b")
    );

    drop(proxy);
    drop(scratch);
}
