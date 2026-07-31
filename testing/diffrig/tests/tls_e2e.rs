//! Hermetic end-to-end proof (WP-26 / the MVP north-star's P3 milestone):
//! the real `llm-proxy` binary, booted from a dialect (`llmproxy.yaml`)
//! config, proxies real HTTP/1.1 requests over a real TLS connection
//! (self-signed cert, genuine SNI + certificate verification) to the
//! in-process OpenAI/Anthropic mocks in `diffrig::upstreams` -- including
//! SSE responses that genuinely stream through rather than getting buffered
//! whole.
//!
//! **Boot strategy / hermetic DNS / binary resolution**: see
//! `diffrig::harness`'s doc comment -- this file just uses that shared
//! machinery (`ProxyProcess`, `ScratchDir`, `send_json`,
//! `send_json_collect_sse`) rather than keeping a private copy.
//!
//! Providers are addressed by a `*.localhost` hostname (e.g.
//! `llmproxy-openai.test.localhost`, never bare `localhost` itself -- see
//! [`MockTls`]'s doc comment for why that distinction matters here). Per RFC
//! 6761, every resolver this workspace runs on (macOS's mDNSResponder,
//! Linux's systemd-resolved / glibc NSS) answers any `*.localhost` name with
//! the loopback addresses without a network round-trip or an `/etc/hosts`
//! edit, which is what keeps this hermetic without needing root to edit
//! system DNS config.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, send_json_collect_sse, ProxyProcess, ScratchDir,
    READY_TIMEOUT,
};
use diffrig::upstreams::{
    AnthropicConfig, AnthropicUpstream, MockTls, OpenAiConfig, OpenAiUpstream,
};
use serde_json::json;

// ------------------------------------------------------------------ config --

/// Render the dialect (`llmproxy-v0`) config for this test: one listener,
/// an `openai` provider and an `anthropic` provider (named exactly that so
/// the dialect infers their type without an explicit `type:` field), each
/// pointed at a TLS mock upstream with its own `ca_file`. Routing matches
/// the `x-llmproxy-model` request header (see
/// `crates/proxy-simple-config/src/lower.rs`'s `MODEL_HEADER`) against a
/// `gpt-*`/`claude-*` glob.
#[allow(clippy::too_many_arguments)]
fn dialect_config(
    listener_port: u16,
    openai_host: &str,
    openai_port: u16,
    openai_ca_file: &Path,
    anthropic_host: &str,
    anthropic_port: u16,
    anthropic_ca_file: &Path,
) -> String {
    format!(
        r#"
version: 0
listen: "127.0.0.1:{listener_port}"
providers:
  openai:
    base_url: "https://{openai_host}:{openai_port}"
    api_key: "test-openai-key"
    ca_file: "{openai_ca_file}"
  anthropic:
    base_url: "https://{anthropic_host}:{anthropic_port}"
    api_key: "test-anthropic-key"
    ca_file: "{anthropic_ca_file}"
routes:
  - model: "gpt-*"
    provider: openai
  - model: "claude-*"
    provider: anthropic
"#,
        openai_ca_file = openai_ca_file.display(),
        anthropic_ca_file = anthropic_ca_file.display(),
    )
}

// ----------------------------------------------------------------- helpers --

fn base_openai_config() -> OpenAiConfig {
    OpenAiConfig {
        model: "gpt-mock".to_string(),
        response_text: "alpha beta gamma".to_string(),
        ttft: Duration::from_millis(150),
        inter_token_delay: Duration::from_millis(150),
        require_api_key: Some("test-openai-key".to_string()),
        forced_error: None,
        cached_tokens: 0,
    }
}

fn base_anthropic_config() -> AnthropicConfig {
    AnthropicConfig {
        model: "claude-mock".to_string(),
        response_text: "delta epsilon zeta".to_string(),
        ttft: Duration::from_millis(150),
        inter_token_delay: Duration::from_millis(150),
        require_api_key: Some("test-anthropic-key".to_string()),
        forced_error: None,
        cache_read_tokens: 0,
        cache_creation_tokens: 0,
    }
}

// -------------------------------------------------------------------- tests --

/// The acceptance test: real bytes cross a real TLS connection from the
/// proxy to two mock upstreams, driven purely through the dialect config --
/// non-streaming and streaming, both providers, with the auth headers the
/// dialect injects actually observed at the upstream.
#[tokio::test]
async fn upstream_tls_end_to_end_proxies_both_providers_with_real_streaming() {
    let openai_host = "llmproxy-openai.test.localhost";
    let anthropic_host = "llmproxy-anthropic.test.localhost";
    let openai_tls = MockTls::new(openai_host);
    let anthropic_tls = MockTls::new(anthropic_host);

    let openai_upstream = OpenAiUpstream::spawn_tls(base_openai_config(), &openai_tls)
        .await
        .expect("spawn TLS openai mock");
    let anthropic_upstream = AnthropicUpstream::spawn_tls(base_anthropic_config(), &anthropic_tls)
        .await
        .expect("spawn TLS anthropic mock");

    let scratch = ScratchDir::new("positive");
    let openai_ca_file = scratch.write("openai-ca.pem", &openai_tls.ca_pem);
    let anthropic_ca_file = scratch.write("anthropic-ca.pem", &anthropic_tls.ca_pem);

    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_yaml = dialect_config(
        listener_port,
        openai_host,
        openai_upstream.port(),
        &openai_ca_file,
        anthropic_host,
        anthropic_upstream.port(),
        &anthropic_ca_file,
    );
    let config_path = scratch.write("llmproxy.yaml", &config_yaml);

    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyProcess::spawn(&bin, &config_path, &scratch.path().join("proxy.log"));
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);

    // --- OpenAI: non-streaming ---------------------------------------------
    let body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi there"}],
    });
    let res = send_json(
        listener_addr,
        "POST",
        "/v1/chat/completions",
        &[("x-llmproxy-model", "gpt-4o-mini")],
        &body,
    )
    .await;
    assert_eq!(res.status, 200, "openai non-streaming body: {}", res.body);
    assert!(
        res.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.contains("application/json")),
        "expected a JSON content-type forwarded from the upstream, got: {:?}",
        res.headers
    );
    let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json");
    assert_eq!(parsed["object"], "chat.completion");
    assert_eq!(
        parsed["choices"][0]["message"]["content"],
        "alpha beta gamma"
    );

    // The dialect must have injected `authorization: Bearer <api_key>` and
    // it must have actually arrived at the upstream.
    let requests = openai_upstream.log.requests();
    let last = requests.last().expect("openai mock received a request");
    assert!(
        last.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("authorization") && v == "Bearer test-openai-key"),
        "expected `authorization: Bearer test-openai-key` at the upstream, got: {:?}",
        last.headers
    );

    // --- OpenAI: streaming actually streams ---------------------------------
    let stream_body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });
    let (status, _headers, events) = send_json_collect_sse(
        listener_addr,
        "POST",
        "/v1/chat/completions",
        &[("x-llmproxy-model", "gpt-4o-mini")],
        &stream_body,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        events.len() >= 2,
        "expected multiple SSE frames, got {}",
        events.len()
    );
    let first = &events[0];
    let last_event = events.last().expect("at least one event");
    assert!(
        first.data.contains("\"role\":\"assistant\""),
        "expected the role-delta chunk first, got: {}",
        first.data
    );
    assert_eq!(
        last_event.data, "data: [DONE]",
        "expected the stream to terminate with [DONE]"
    );
    // The mock's schedule: TTFT (150ms) gates the first frame; two more
    // 150ms inter-token delays separate the following content chunks. A
    // proxy that buffered the whole response before forwarding it would
    // deliver every frame at ~the same, late instant -- these two bounds
    // together rule that out: the first frame must show up close to TTFT
    // (not close to the total), and the gap to the last frame must be
    // consistent with the real per-token pacing actually having elapsed
    // between frames as they were forwarded.
    assert!(
        first.at < Duration::from_millis(400),
        "first SSE frame arrived suspiciously late ({:?}); proxy may be buffering",
        first.at
    );
    assert!(
        last_event.at.saturating_sub(first.at) >= Duration::from_millis(250),
        "first and last SSE frames arrived too close together ({:?} vs {:?}); \
         proxy may be buffering the whole response instead of streaming it",
        first.at,
        last_event.at
    );

    // --- Anthropic: non-streaming -------------------------------------------
    let body = json!({
        "model": "claude-3-mock",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi there"}],
    });
    let res = send_json(
        listener_addr,
        "POST",
        "/v1/messages",
        &[("x-llmproxy-model", "claude-3-mock")],
        &body,
    )
    .await;
    assert_eq!(
        res.status, 200,
        "anthropic non-streaming body: {}",
        res.body
    );
    let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json");
    assert_eq!(parsed["type"], "message");
    assert_eq!(parsed["content"][0]["text"], "delta epsilon zeta");

    let requests = anthropic_upstream.log.requests();
    let last = requests.last().expect("anthropic mock received a request");
    assert!(
        last.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("x-api-key") && v == "test-anthropic-key"),
        "expected `x-api-key: test-anthropic-key` at the upstream, got: {:?}",
        last.headers
    );
    // The dialect injects a default `anthropic-version` when the user
    // doesn't set one (`DEFAULT_ANTHROPIC_VERSION` in `lower.rs`).
    assert!(
        last.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("anthropic-version") && v == "2023-06-01"),
        "expected a default `anthropic-version: 2023-06-01` at the upstream, got: {:?}",
        last.headers
    );

    // --- Anthropic: streaming actually streams -------------------------------
    let stream_body = json!({
        "model": "claude-3-mock",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });
    let (status, _headers, events) = send_json_collect_sse(
        listener_addr,
        "POST",
        "/v1/messages",
        &[("x-llmproxy-model", "claude-3-mock")],
        &stream_body,
    )
    .await;
    assert_eq!(status, 200);
    let first = &events[0];
    let last_event = events.last().expect("at least one event");
    assert!(
        first.data.contains("event: message_start"),
        "expected `message_start` first, got: {}",
        first.data
    );
    assert!(
        last_event.data.contains("event: message_stop"),
        "expected `message_stop` last, got: {}",
        last_event.data
    );
    assert!(
        first.at < Duration::from_millis(400),
        "first Anthropic SSE frame arrived suspiciously late ({:?})",
        first.at
    );
    assert!(
        last_event.at.saturating_sub(first.at) >= Duration::from_millis(250),
        "Anthropic SSE frames arrived too close together ({:?} vs {:?}); proxy may be buffering",
        first.at,
        last_event.at
    );

    drop(proxy);
    openai_upstream.shutdown().await;
    anthropic_upstream.shutdown().await;
}

/// Verification actually verifies: pointing `ca_file` at a CA unrelated to
/// the one that signed the upstream's certificate must fail the TLS
/// handshake, and the client must see a 503 (the router's upstream-connect
/// local reply) -- never a 200. Without this test, the suite above cannot
/// distinguish "TLS was verified" from "TLS was skipped".
#[tokio::test]
async fn wrong_ca_file_fails_the_handshake_and_the_client_gets_503_not_200() {
    let openai_host = "llmproxy-openai-negative.test.localhost";
    let real_tls = MockTls::new(openai_host);
    // A second, unrelated CA -- never used to sign anything the mock
    // upstream actually presents.
    let unrelated_ca = MockTls::new("unrelated.test.localhost");

    let openai_upstream = OpenAiUpstream::spawn_tls(base_openai_config(), &real_tls)
        .await
        .expect("spawn TLS openai mock");

    let scratch = ScratchDir::new("negative");
    let wrong_ca_file = scratch.write("wrong-ca.pem", &unrelated_ca.ca_pem);
    // Only one provider is needed for this test; `anthropic` still has to be
    // present because the dialect's route table needs at least one
    // resolvable provider per referenced route, so point it at the same
    // (working) mock -- it's simply never exercised below.
    let anthropic_ca_file = scratch.write("anthropic-ca.pem", &real_tls.ca_pem);

    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_yaml = dialect_config(
        listener_port,
        openai_host,
        openai_upstream.port(),
        &wrong_ca_file,
        openai_host,
        openai_upstream.port(),
        &anthropic_ca_file,
    );
    let config_path = scratch.write("llmproxy.yaml", &config_yaml);

    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyProcess::spawn(&bin, &config_path, &scratch.path().join("proxy.log"));
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);

    let body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi there"}],
    });
    let res = send_json(
        listener_addr,
        "POST",
        "/v1/chat/completions",
        &[("x-llmproxy-model", "gpt-4o-mini")],
        &body,
    )
    .await;
    assert_eq!(
        res.status, 503,
        "a certificate signed by an untrusted CA must be rejected (503), got {}: {}",
        res.status, res.body
    );
    assert_ne!(
        res.status, 200,
        "TLS verification must not have been silently skipped"
    );

    drop(proxy);
    openai_upstream.shutdown().await;
}
