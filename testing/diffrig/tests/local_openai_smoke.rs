//! Smoke test: the real `llm-proxy` binary against a locally running
//! OpenAI-compatible server (Ollama), over real HTTP.
//!
//! This sits between two tiers. `mock_e2e.rs` uses our own mocks, which share
//! our reading of the wire format, so a wrong assumption can pass in both
//! places. `live_smoke.rs` uses the real providers but costs money. Ollama is
//! a third-party implementation, so a disagreement with our extractor is a
//! real signal.
//!
//! Ollama serves both the OpenAI and Anthropic surfaces. Both dialects are
//! covered, streaming and not, plus a real upstream-TLS hop.
//!
//! It does not cover public-root certificate trust, real DNS, HTTP/2
//! upstreams, or production error shapes. `live_smoke.rs` is still needed for
//! those.
//!
//! ## The load-bearing assertion
//!
//! Token counts. Ollama emits a genuine `usage` block, so the usage filter is
//! checked against numbers we did not choose. The access log must agree with
//! what the upstream reported. A mock proves the extractor can read a body we
//! wrote. This proves it can read one we did not write.
//! didn't.
//!
//! ## How to run
//!
//! ```sh
//! ollama serve                     # if not already running
//! ollama pull gemma3:270m          # ~290 MB
//! cargo test -p diffrig --test local_openai_smoke -- --ignored
//! ```
//!
//! `#[ignore]`d because it needs a running Ollama on the default port, which
//! CI does not have. It fails loudly naming the missing dependency rather
//! than skipping -- a skipped test reporting success is the exact failure
//! mode this project has been bitten by before.

use std::net::SocketAddr;
use std::time::Duration;

use diffrig::upstreams::{spawn_tls_passthrough, MockTls};

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, send_json_collect_sse, ProxyProcess, ScratchDir,
    TimedEvent, READY_TIMEOUT,
};
use serde_json::json;

/// Where Ollama listens by default.
const OLLAMA_BASE_URL: &str = "http://127.0.0.1:11434";

/// Smallest model that still produces real tokens (~290 MB). Chosen for
/// speed: this test asserts on token *counts* and streaming *timing*, never
/// on what the model actually says, so capability is irrelevant.
const OLLAMA_MODEL: &str = "gemma3:270m";

/// A local model on CPU is far slower to first token than a hosted one, and
/// the tiny model still has to load into memory on first call.
const LOCAL_TIMEOUT: Duration = Duration::from_secs(120);

// ------------------------------------------------------------------ config --

/// The dialect config: one provider named `openai` -- so it gets
/// `ProviderType::OpenAi`, and therefore the OpenAI request/response
/// handling and the `openai` usage dialect -- but with an explicit
/// `base_url` pointing at Ollama instead of the name-inferred
/// `https://api.openai.com`.
///
/// That combination is the whole point: it is exactly the "openai-compatible
/// upstream" shape a user running vLLM/Ollama/TGI would write, and it is the
/// path `lower.rs`'s `usage_dialect` fallback (`_ => "openai"`) exists to
/// serve.
///
/// `api_key` is a dummy: Ollama ignores `Authorization`, but the dialect
/// only injects the header when a key is configured, and we want the
/// credential-injection path exercised rather than skipped.
fn dialect_config(
    listener_port: u16,
    access_log_path: &str,
    base_url: &str,
    ca_file: Option<&str>,
) -> String {
    // `ca_file` is only emitted for the https variant. Note what the dialect
    // does with it beyond chain trust: it also emits a DNS-exact SAN matcher
    // for the provider host, so the leaf must actually be issued for the name
    // in `base_url`. A cert for the wrong name fails even under our own CA --
    // which is the point, and was one of the two upstream-verification holes
    let ca_line = ca_file
        .map(|path| format!("\n    ca_file: \"{path}\""))
        .unwrap_or_default();
    // Both providers point at the same Ollama, which serves OpenAI and
    // Anthropic surfaces. This is a per-route dialect test against a
    // third-party server. Route order matters (S1: first match wins). The
    // `claude-*` route is listed before the catch-all.
    format!(
        r#"
version: 0
listen: "127.0.0.1:{listener_port}"
providers:
  openai:
    base_url: "{base_url}"
    api_key: "ollama-ignores-this"{ca_line}
  anthropic:
    base_url: "{base_url}"
    api_key: "ollama-ignores-this"{ca_line}
routes:
  - model: "claude-*"
    provider: anthropic
  - model: "*"
    provider: openai
observability:
  access_logs:
    output: "{access_log_path}"
    format: json
"#
    )
}

/// Fail loudly, naming the dependency, rather than skipping. Mirrors
/// `live_smoke.rs`'s `require_env`: inside an explicitly `--ignored`-requested
/// run, an absent dependency is a real failure.
fn require_ollama() {
    let probe = std::process::Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "5",
            &format!("{OLLAMA_BASE_URL}/api/tags"),
        ])
        .output();
    let running = probe.map(|o| o.status.success() && !o.stdout.is_empty());
    if !matches!(running, Ok(true)) {
        panic!(
            "no Ollama server reachable at {OLLAMA_BASE_URL} -- this test needs one. \
             Start it with `ollama serve` and `ollama pull {OLLAMA_MODEL}`, then rerun \
             `cargo test -p diffrig --test local_openai_smoke -- --ignored`"
        );
    }
}

fn spawn_proxy(label: &str) -> (SocketAddr, std::path::PathBuf, ScratchDir, ProxyProcess) {
    spawn_proxy_against(label, OLLAMA_BASE_URL, None)
}

fn spawn_proxy_against(
    label: &str,
    base_url: &str,
    ca_pem: Option<&str>,
) -> (SocketAddr, std::path::PathBuf, ScratchDir, ProxyProcess) {
    let scratch = ScratchDir::new(label);
    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let access_log = scratch.path().join("access.log");
    let ca_path = ca_pem.map(|pem| scratch.write("upstream-ca.pem", pem));
    // Rust note: bound to a local first. Chaining
    // `.map(|p| p.to_string_lossy().into_owned()).as_deref()` would borrow a
    // temporary `String` that is dropped at the end of the statement.
    let ca_path_str = ca_path.as_ref().map(|p| p.to_string_lossy().into_owned());
    let config_path = scratch.write(
        "llmproxy.yaml",
        &dialect_config(
            listener_port,
            &access_log.to_string_lossy(),
            base_url,
            ca_path_str.as_deref(),
        ),
    );

    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyProcess::spawn(&bin, &config_path, &scratch.path().join("proxy.log"));
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);
    (listener_addr, access_log, scratch, proxy)
}

/// Read the single JSON access-log line the proxy wrote for this request.
///
/// Access logs are emitted at stream end, and the proxy writes them from its
/// own process, so a brief poll is needed rather than an immediate read --
/// the client seeing the last response byte does not guarantee the log line
/// has hit the filesystem yet.
fn read_access_log_line(path: &std::path::Path) -> serde_json::Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Some(line) = text.lines().find(|l| !l.trim().is_empty()) {
                return serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("access-log line is not valid JSON ({e}): {line}"));
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no access-log line appeared at {} within 5s",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Read exactly `want` JSON access-log lines, polling until they all appear.
///
/// Requiring the count up front is deliberate: a test that reads whatever
/// happens to be on disk can pass against a single line when it meant to
/// compare two, which would make the dual-dialect assertion vacuous.
fn read_access_log_lines(path: &std::path::Path, want: usize) -> Vec<serde_json::Value> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            let lines: Vec<_> = text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    serde_json::from_str(l)
                        .unwrap_or_else(|e| panic!("access-log line is not valid JSON ({e}): {l}"))
                })
                .collect();
            if lines.len() >= want {
                return lines;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "expected {want} access-log lines at {} within 10s",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Pull the JSON payload out of one SSE frame. Anthropic puts an `event:` line
/// before the `data:` line, so the frame must be scanned for `data:` rather
/// than assuming it comes first.
fn sse_json(event: &TimedEvent) -> Option<serde_json::Value> {
    let data = event.data.lines().find_map(|l| l.strip_prefix("data:"))?;
    serde_json::from_str(data.trim()).ok()
}

/// `json_format` values are command-operator format strings, so EVERY value
/// renders as a JSON string -- `"200"`, not `200`. Absent values render as
/// the literal `"-"`. Parse accordingly; a type-assert on a number here
/// silently fails for the wrong reason.
fn numeric_field(line: &serde_json::Value, key: &str) -> Option<i64> {
    line.get(key)?.as_str()?.parse::<i64>().ok()
}

// -------------------------------------------------------------------- tests --

/// Proves: a non-streaming completion round-trips through the proxy to a
/// third-party OpenAI-compatible server, AND the usage filter extracts the
/// token counts that server independently reported into the access log.
#[tokio::test]
#[ignore = "needs a local Ollama server; run with --ignored"]
async fn non_streaming_round_trip_extracts_third_party_token_counts() {
    require_ollama();
    let (listener_addr, access_log, scratch, proxy) = spawn_proxy("ollama-non-streaming");

    let body = json!({
        "model": OLLAMA_MODEL,
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with exactly one short word."}],
    });
    let res = tokio::time::timeout(
        LOCAL_TIMEOUT,
        send_json(
            listener_addr,
            "POST",
            "/v1/chat/completions",
            &[("x-llmproxy-model", OLLAMA_MODEL)],
            &body,
        ),
    )
    .await
    .expect("Ollama did not answer within the local timeout");

    assert_eq!(
        res.status, 200,
        "expected 200 through the proxy, got {}: {}",
        res.status, res.body
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&res.body).expect("response body must be well-formed JSON");
    let content = parsed["choices"][0]["message"]["content"]
        .as_str()
        .expect("choices[0].message.content must be a string");
    assert!(
        !content.trim().is_empty(),
        "expected non-empty assistant content, got: {parsed}"
    );

    // The upstream's own numbers -- chosen by Ollama, not by us.
    let upstream_input = parsed["usage"]["prompt_tokens"]
        .as_i64()
        .expect("Ollama must report usage.prompt_tokens");
    let upstream_output = parsed["usage"]["completion_tokens"]
        .as_i64()
        .expect("Ollama must report usage.completion_tokens");

    // ...and what the proxy independently extracted on the way past. These
    // agreeing is the assertion a mock cannot make, because a mock's usage
    // block is one we wrote to match what we already believed.
    let line = read_access_log_line(&access_log);
    assert_eq!(
        numeric_field(&line, "llm_input_tokens"),
        Some(upstream_input),
        "access log disagrees with the upstream's own prompt_tokens (line: {line})"
    );
    assert_eq!(
        numeric_field(&line, "llm_output_tokens"),
        Some(upstream_output),
        "access log disagrees with the upstream's own completion_tokens (line: {line})"
    );
    assert_eq!(numeric_field(&line, "response_code"), Some(200));

    drop(proxy);
    drop(scratch);
}

/// Proves: a streamed completion delivers incremental SSE frames as they are
/// produced, and the usage filter recovers token counts from the FINAL SSE
/// frame -- a different code path (`SseUsageScanner`) from the JSON one
/// above, on a stream this project did not generate.
#[tokio::test]
#[ignore = "needs a local Ollama server; run with --ignored"]
async fn streaming_delivers_incremental_frames_and_extracts_usage_from_the_stream() {
    require_ollama();
    let (listener_addr, access_log, scratch, proxy) = spawn_proxy("ollama-streaming");

    let body = json!({
        "model": OLLAMA_MODEL,
        "max_tokens": 32,
        "messages": [{"role": "user", "content": "Count from one to five, one number per word."}],
        "stream": true,
        // Without this, an OpenAI-compatible server omits usage from the
        // stream entirely -- there would be nothing for the filter to find,
        // and the test would be asserting on the wrong thing.
        "stream_options": {"include_usage": true},
    });
    let (status, headers, events) = tokio::time::timeout(
        LOCAL_TIMEOUT,
        send_json_collect_sse(
            listener_addr,
            "POST",
            "/v1/chat/completions",
            &[("x-llmproxy-model", OLLAMA_MODEL)],
            &body,
        ),
    )
    .await
    .expect("Ollama did not finish streaming within the local timeout");

    assert_eq!(status, 200);
    assert!(
        headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.contains("text/event-stream")),
        "expected `content-type: text/event-stream`, got: {headers:?}"
    );
    assert!(
        events.len() > 1,
        "expected more than one SSE frame, got {}",
        events.len()
    );
    assert_eq!(
        events.last().expect("at least one event").data.trim(),
        "data: [DONE]",
        "expected the stream to terminate with `data: [DONE]`"
    );

    // Real streaming means frames arrive at distinct times. A buffered
    // response lands every frame at once at the end. Asserting on the spread
    // of arrival times does not depend on where TTFT sits, which matters for a
    // small local model where model load dominates.
    let first_at = events[0].at;
    let total = events.last().expect("at least one event").at;
    let distinct_arrivals = events
        .iter()
        .map(|e| e.at.as_millis())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    assert!(
        distinct_arrivals >= 3,
        "all {} SSE frames arrived at {distinct_arrivals} distinct instant(s) (first {first_at:?}, \
         last {total:?}) -- that is a buffered response replayed as SSE, not a live stream",
        events.len()
    );

    // Ollama puts usage in the penultimate frame (the one before [DONE]),
    // with an empty `choices` array. Pull its numbers out and require the
    // proxy's SSE scanner to have found the same ones.
    let upstream_usage = events
        .iter()
        .filter_map(sse_json)
        .find(|v| v.get("usage").is_some_and(|u| !u.is_null()))
        .expect("the stream must carry a usage frame given stream_options.include_usage");
    let upstream_input = upstream_usage["usage"]["prompt_tokens"]
        .as_i64()
        .expect("usage.prompt_tokens in the stream");
    let upstream_output = upstream_usage["usage"]["completion_tokens"]
        .as_i64()
        .expect("usage.completion_tokens in the stream");

    let line = read_access_log_line(&access_log);
    assert_eq!(
        numeric_field(&line, "llm_input_tokens"),
        Some(upstream_input),
        "SSE scanner disagrees with the stream's own prompt_tokens (line: {line})"
    );
    assert_eq!(
        numeric_field(&line, "llm_output_tokens"),
        Some(upstream_output),
        "SSE scanner disagrees with the stream's own completion_tokens (line: {line})"
    );

    // TTFT is only meaningful on a streamed response, and it is the metric
    // It is the TTFT metric, so assert it is populated and sane rather than "-".
    let ttft = numeric_field(&line, "llm_ttft_ms")
        .unwrap_or_else(|| panic!("llm_ttft_ms must be populated for a stream (line: {line})"));
    assert!(
        ttft >= 0 && (ttft as f64) <= total.as_secs_f64() * 1000.0,
        "llm_ttft_ms {ttft} is outside the stream's own {total:?} duration (line: {line})"
    );

    drop(proxy);
    drop(scratch);
}

/// The same third-party round trip over real upstream TLS. This covers the
/// handshake, SNI, chain verification against a configured CA, and the
/// DNS-exact SAN check. The TLS front is a plain `copy_bidirectional` pump, not
/// an HTTP reverse proxy. Re-framing the request would reintroduce our own
/// framing into a test meant to use foreign framing.
#[tokio::test]
#[ignore = "needs a local Ollama server; run with --ignored"]
async fn tls_round_trip_to_a_third_party_upstream_extracts_token_counts() {
    require_ollama();

    // Never bare `localhost`: the dialect emits a DNS-exact SAN matcher on the
    // provider host, and this asserts a real hostname check rather than the
    // loopback name resolvers special-case. `*.localhost` resolves to loopback
    // per RFC 6761 with no /etc/hosts edit (see tls_e2e.rs).
    let tls = MockTls::new("ollama.test.localhost");
    let ollama: SocketAddr = "127.0.0.1:11434".parse().unwrap();
    let front = spawn_tls_passthrough(&tls, ollama)
        .await
        .expect("TLS front binds");

    let base_url = format!("https://{}:{}", tls.dns_name, front.port);
    let (listener_addr, access_log, scratch, proxy) =
        spawn_proxy_against("ollama-tls", &base_url, Some(&tls.ca_pem));

    let body = json!({
        "model": OLLAMA_MODEL,
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with exactly one short word."}],
    });
    let res = tokio::time::timeout(
        LOCAL_TIMEOUT,
        send_json(
            listener_addr,
            "POST",
            "/v1/chat/completions",
            &[("x-llmproxy-model", OLLAMA_MODEL)],
            &body,
        ),
    )
    .await
    .expect("Ollama did not answer over TLS within the local timeout");

    assert_eq!(
        res.status, 200,
        "expected 200 through the proxy over TLS, got {}: {}",
        res.status, res.body
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&res.body).expect("response body must be well-formed JSON");
    assert!(
        !parsed["choices"][0]["message"]["content"]
            .as_str()
            .expect("choices[0].message.content must be a string")
            .trim()
            .is_empty(),
        "expected non-empty assistant content, got: {parsed}"
    );

    // Usage still extracted correctly with a TLS hop in the middle -- i.e. the
    // encode-side filter sees decrypted bytes, and the handshake did not
    // disturb chunk boundaries in a way the scanner cares about.
    let upstream_input = parsed["usage"]["prompt_tokens"]
        .as_i64()
        .expect("Ollama must report usage.prompt_tokens");
    let upstream_output = parsed["usage"]["completion_tokens"]
        .as_i64()
        .expect("Ollama must report usage.completion_tokens");

    let line = read_access_log_line(&access_log);
    assert_eq!(
        numeric_field(&line, "llm_input_tokens"),
        Some(upstream_input),
        "access log disagrees with the upstream's own prompt_tokens over TLS (line: {line})"
    );
    assert_eq!(
        numeric_field(&line, "llm_output_tokens"),
        Some(upstream_output),
        "access log disagrees with the upstream's own completion_tokens over TLS (line: {line})"
    );
    assert_eq!(numeric_field(&line, "response_code"), Some(200));

    drop(proxy);
    drop(scratch);
    front.shutdown().await;
}

/// The negative case, and the one that makes the positive case mean
/// something: a CA that did not issue the upstream's certificate must fail
/// the handshake, and the client must see a 503 rather than a 200.
///
/// Without this, `ca_file` could be ignored entirely and the test above would
/// still pass. That is not hypothetical -- two upstream-verification holes
/// were found in this dialect on 2026-07-25, one of which meant "accept any
/// server certificate".
#[tokio::test]
#[ignore = "needs a local Ollama server; run with --ignored"]
async fn a_ca_that_did_not_issue_the_cert_fails_the_handshake() {
    require_ollama();

    let serving = MockTls::new("ollama.test.localhost");
    // Same name, different CA: only the trust chain differs, so a failure here
    // can only be chain verification -- not a name mismatch.
    let unrelated = MockTls::new("ollama.test.localhost");
    let ollama: SocketAddr = "127.0.0.1:11434".parse().unwrap();
    let front = spawn_tls_passthrough(&serving, ollama)
        .await
        .expect("TLS front binds");

    let base_url = format!("https://{}:{}", serving.dns_name, front.port);
    let (listener_addr, _access_log, scratch, proxy) =
        spawn_proxy_against("ollama-tls-wrong-ca", &base_url, Some(&unrelated.ca_pem));

    let body = json!({
        "model": OLLAMA_MODEL,
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with exactly one short word."}],
    });
    let res = tokio::time::timeout(
        LOCAL_TIMEOUT,
        send_json(
            listener_addr,
            "POST",
            "/v1/chat/completions",
            &[("x-llmproxy-model", OLLAMA_MODEL)],
            &body,
        ),
    )
    .await
    .expect("proxy did not answer within the local timeout");

    assert_eq!(
        res.status, 503,
        "an untrusted upstream certificate must fail the handshake and surface as 503, \
         got {}: {} -- a 200 here would mean certificate verification was skipped entirely",
        res.status, res.body
    );

    drop(proxy);
    drop(scratch);
    front.shutdown().await;
}

// ------------------------------------------------- Anthropic-compatible tier --

/// Header value that routes to the `anthropic` provider (see `dialect_config`).
/// The BODY model stays `gemma3:270m` -- routing matches the
/// `x-llmproxy-model` header today, and the body model is what Ollama serves.
const ANTHROPIC_ROUTE_MODEL: &str = "claude-gemma";

/// Proves: the Anthropic dialect, end to end, against a third-party server.
///
/// This was the last row of the coverage table with mocks-only support.
/// Ollama also speaks the Anthropic Messages API, so `/v1/messages`, the
/// `content[].text` response shape, and `usage.{input,output}_tokens` all get
/// exercised against a body we did not write. It also proves the dialect's
/// Anthropic-specific request path: `x-api-key` rather than `Bearer`, plus
/// the auto-injected `anthropic-version` header.
#[tokio::test]
#[ignore = "needs a local Ollama server; run with --ignored"]
async fn anthropic_non_streaming_round_trip_extracts_third_party_token_counts() {
    require_ollama();
    let (listener_addr, access_log, scratch, proxy) = spawn_proxy("ollama-anthropic");

    let body = json!({
        "model": OLLAMA_MODEL,
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with exactly one short word."}],
    });
    let res = tokio::time::timeout(
        LOCAL_TIMEOUT,
        send_json(
            listener_addr,
            "POST",
            "/v1/messages",
            &[("x-llmproxy-model", ANTHROPIC_ROUTE_MODEL)],
            &body,
        ),
    )
    .await
    .expect("Ollama did not answer within the local timeout");

    assert_eq!(
        res.status, 200,
        "expected 200 from the Anthropic-compatible endpoint, got {}: {}",
        res.status, res.body
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&res.body).expect("response body must be well-formed JSON");
    assert_eq!(
        parsed["type"], "message",
        "expected an Anthropic-shaped response, got: {parsed}"
    );
    assert!(
        !parsed["content"][0]["text"]
            .as_str()
            .expect("content[0].text must be a string")
            .trim()
            .is_empty(),
        "expected non-empty text content, got: {parsed}"
    );

    // Anthropic names its buckets differently from OpenAI. The extractor
    // reading these correctly is exactly what the per-route dialect decides.
    let upstream_input = parsed["usage"]["input_tokens"]
        .as_i64()
        .expect("Ollama must report usage.input_tokens");
    let upstream_output = parsed["usage"]["output_tokens"]
        .as_i64()
        .expect("Ollama must report usage.output_tokens");

    let line = read_access_log_line(&access_log);
    assert_eq!(
        numeric_field(&line, "llm_input_tokens"),
        Some(upstream_input),
        "access log disagrees with the upstream's own input_tokens (line: {line})"
    );
    assert_eq!(
        numeric_field(&line, "llm_output_tokens"),
        Some(upstream_output),
        "access log disagrees with the upstream's own output_tokens (line: {line})"
    );

    drop(proxy);
    drop(scratch);
}

/// Proves: the Anthropic SSE shape streams and meters correctly.
///
/// A different event grammar from OpenAI's -- named `event:` lines, usage
/// split across `message_start` (input) and `message_delta` (output), and no
/// `[DONE]` sentinel. Note there is NO opt-in equivalent to
/// `stream_options.include_usage` here: Anthropic reports usage
/// unconditionally, which is why forced usage reporting is scoped to the
/// OpenAI dialect only. This test is what makes that claim checkable rather
/// than asserted.
#[tokio::test]
#[ignore = "needs a local Ollama server; run with --ignored"]
async fn anthropic_streaming_extracts_usage_split_across_start_and_delta() {
    require_ollama();
    let (listener_addr, access_log, scratch, proxy) = spawn_proxy("ollama-anthropic-stream");

    let body = json!({
        "model": OLLAMA_MODEL,
        "max_tokens": 32,
        "messages": [{"role": "user", "content": "Count from one to five, one number per word."}],
        "stream": true,
    });
    let (status, headers, events) = tokio::time::timeout(
        LOCAL_TIMEOUT,
        send_json_collect_sse(
            listener_addr,
            "POST",
            "/v1/messages",
            &[("x-llmproxy-model", ANTHROPIC_ROUTE_MODEL)],
            &body,
        ),
    )
    .await
    .expect("Ollama did not finish streaming within the local timeout");

    assert_eq!(status, 200);
    assert!(
        headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.contains("text/event-stream")),
        "expected `content-type: text/event-stream`, got: {headers:?}"
    );
    assert!(
        events.len() > 1,
        "expected more than one SSE frame, got {}",
        events.len()
    );

    // Same spread-based streaming check as the OpenAI case: buffering would
    // land every frame in one instant at the end.
    let distinct_arrivals = events
        .iter()
        .map(|e| e.at.as_millis())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    assert!(
        distinct_arrivals >= 3,
        "all {} Anthropic SSE frames arrived at {distinct_arrivals} distinct instant(s) -- \
         that is a buffered response replayed as SSE, not a live stream",
        events.len()
    );

    // `message_delta` carries the final, authoritative usage for both buckets.
    let delta = events
        .iter()
        .filter_map(sse_json)
        .find(|v| v["type"] == "message_delta")
        .expect("an Anthropic stream must carry a message_delta frame");
    let upstream_input = delta["usage"]["input_tokens"]
        .as_i64()
        .expect("message_delta.usage.input_tokens");
    let upstream_output = delta["usage"]["output_tokens"]
        .as_i64()
        .expect("message_delta.usage.output_tokens");

    let line = read_access_log_line(&access_log);
    assert_eq!(
        numeric_field(&line, "llm_input_tokens"),
        Some(upstream_input),
        "SSE scanner disagrees with message_delta's input_tokens (line: {line})"
    );
    assert_eq!(
        numeric_field(&line, "llm_output_tokens"),
        Some(upstream_output),
        "SSE scanner disagrees with message_delta's output_tokens (line: {line})"
    );

    drop(proxy);
    drop(scratch);
}

/// Proves acceptance criterion 7 against a third-party server: **one proxy, one
/// config, both dialects, correct numbers for each.**
///
/// The existing dialect unit tests prove the right `inline_string` is emitted
/// per route; QA-1 proves the counts land against our mocks. This proves it
/// where the response bodies were written by someone else. A listener-level
/// dialect cannot pass this: whichever one it picked would be wrong for the
/// other route, and -- the failure mode that matters -- the OpenAI parser on
/// an Anthropic body reports nothing rather than erroring, so the log would
/// show `"-"` instead of a loud failure.
#[tokio::test]
#[ignore = "needs a local Ollama server; run with --ignored"]
async fn both_dialects_meter_correctly_from_one_proxy_and_one_config() {
    require_ollama();
    let (listener_addr, access_log, scratch, proxy) = spawn_proxy("ollama-both-dialects");

    let make_body = || {
        json!({
            "model": OLLAMA_MODEL,
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "Reply with exactly one short word."}],
        })
    };

    let openai = tokio::time::timeout(
        LOCAL_TIMEOUT,
        send_json(
            listener_addr,
            "POST",
            "/v1/chat/completions",
            &[("x-llmproxy-model", OLLAMA_MODEL)],
            &make_body(),
        ),
    )
    .await
    .expect("OpenAI-route request timed out");
    assert_eq!(openai.status, 200, "openai route: {}", openai.body);

    let anthropic = tokio::time::timeout(
        LOCAL_TIMEOUT,
        send_json(
            listener_addr,
            "POST",
            "/v1/messages",
            &[("x-llmproxy-model", ANTHROPIC_ROUTE_MODEL)],
            &make_body(),
        ),
    )
    .await
    .expect("Anthropic-route request timed out");
    assert_eq!(anthropic.status, 200, "anthropic route: {}", anthropic.body);

    let openai_json: serde_json::Value = serde_json::from_str(&openai.body).expect("openai JSON");
    let anthropic_json: serde_json::Value =
        serde_json::from_str(&anthropic.body).expect("anthropic JSON");

    // Correlate log lines by path, since the dialect's JSON format carries no
    // model field yet (same correlation QA-1 uses, and for the same reason).
    let lines = read_access_log_lines(&access_log, 2);
    let by_path = |want: &str| -> serde_json::Value {
        lines
            .iter()
            .find(|l| l["path"] == want)
            .unwrap_or_else(|| panic!("no access-log line for {want} among {lines:?}"))
            .clone()
    };

    let oai_line = by_path("/v1/chat/completions");
    assert_eq!(
        numeric_field(&oai_line, "llm_input_tokens"),
        openai_json["usage"]["prompt_tokens"].as_i64(),
        "openai route metered with the wrong dialect (line: {oai_line})"
    );

    let ant_line = by_path("/v1/messages");
    assert_eq!(
        numeric_field(&ant_line, "llm_input_tokens"),
        anthropic_json["usage"]["input_tokens"].as_i64(),
        "anthropic route metered with the wrong dialect (line: {ant_line})"
    );
    assert_eq!(
        numeric_field(&ant_line, "llm_output_tokens"),
        anthropic_json["usage"]["output_tokens"].as_i64(),
        "anthropic route metered with the wrong dialect (line: {ant_line})"
    );

    drop(proxy);
    drop(scratch);
}
