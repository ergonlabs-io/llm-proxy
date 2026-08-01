//! **Third-party smoke test**: the real `llm-proxy` binary against a real,
//! locally-running OpenAI-compatible server (Ollama), over real HTTP.
//!
//! ## Why this exists, and what it is NOT
//!
//! This sits in the gap between two tiers we already have:
//!
//! - `mock_e2e.rs` drives the proxy against **our own** in-process mocks.
//!   Those mocks encode our understanding of the provider wire format, so
//!   they agree with the proxy by construction: any assumption baked into
//!   the proxy is baked into the mock too, and the pair can be wrong
//!   together without a single test going red.
//! - `live_smoke.rs` drives it against **api.openai.com / api.anthropic.com**
//!   with real keys. That is the v0.0.1 ship gate.
//!
//! This file drives it against a **third-party implementation nobody here
//! wrote**, for free, with no network egress. That kills the shared-blind-spot
//! problem above -- Ollama's `/v1/chat/completions` was written by people who
//! read OpenAI's spec independently of us, so a disagreement between it and
//! our extractor is a genuine signal.
//!
//! **It does not close the v0.0.1 ship gate and must never be described as
//! doing so.** What it still cannot see: TLS to a public cert chain, real
//! chunk boundaries and header casing from OpenAI's edge, rate-limit and
//! error response shapes, and every undocumented quirk of a production
//! endpoint. `live_smoke.rs` remains the only test that closes the gate.
//!
//! ## The load-bearing assertion
//!
//! Token counts. Ollama emits a genuine `usage` block -- in the JSON body
//! when non-streaming, and (given `stream_options.include_usage`) in the
//! final SSE frame when streaming. So this exercises the WP-33 usage filter
//! end to end against numbers **we did not choose**: the proxy's access log
//! must agree with what the upstream independently reported. A mock proves
//! the extractor can read a body we wrote; this proves it can read one we
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

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, send_json_collect_sse, ProxyProcess, ScratchDir,
    READY_TIMEOUT,
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
fn dialect_config(listener_port: u16, access_log_path: &str) -> String {
    format!(
        r#"
version: 0
listen: "127.0.0.1:{listener_port}"
providers:
  openai:
    base_url: "{OLLAMA_BASE_URL}"
    api_key: "ollama-ignores-this"
routes:
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
    let scratch = ScratchDir::new(label);
    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let access_log = scratch.path().join("access.log");
    let config_path = scratch.write(
        "llmproxy.yaml",
        &dialect_config(listener_port, &access_log.to_string_lossy()),
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
        events.last().expect("at least one event").data,
        "data: [DONE]",
        "expected the stream to terminate with `data: [DONE]`"
    );

    // Real streaming, not a buffered response replayed as SSE at the end.
    //
    // `live_smoke.rs` tests this as "first frame lands before 80% of total",
    // which works against a hosted model where generation dominates. It is
    // the WRONG test here and produced a false failure on the first run: a
    // 270M model answers so fast that model load and prompt eval dominate,
    // so the first frame legitimately arrives at ~81% of a ~250ms stream.
    // High TTFT with a short tail is still streaming.
    //
    // What buffering actually looks like is every frame landing in the same
    // instant at the end, so assert on SPREAD instead: distinct arrival
    // times across frames. That discriminates the thing we care about
    // without assuming anything about where TTFT sits.
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
        .filter_map(|e| {
            serde_json::from_str::<serde_json::Value>(e.data.trim_start_matches("data: ")).ok()
        })
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
    // v0.1.0's gate names -- assert it is populated and sane rather than "-".
    let ttft = numeric_field(&line, "llm_ttft_ms")
        .unwrap_or_else(|| panic!("llm_ttft_ms must be populated for a stream (line: {line})"));
    assert!(
        ttft >= 0 && (ttft as f64) <= total.as_secs_f64() * 1000.0,
        "llm_ttft_ms {ttft} is outside the stream's own {total:?} duration (line: {line})"
    );

    drop(proxy);
    drop(scratch);
}
