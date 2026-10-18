//! A stream cut mid-flight is still metered: the real `llm-proxy` binary in
//! `--config` mode, a mock upstream that streams SSE, and three ways to cut
//! the stream after response headers (review C3): the client drops the
//! connection, the provider resets it, and a stream timer fires. A fourth cut,
//! the drain deadline at shutdown, must still be recorded before exit. A client
//! that leaves before response headers is pinned as a known divergence.
//!
//! The request record (`--request-records-file`) must say `completeness:
//! partial`, carry the upstream response id, mark the token counts and cost as
//! estimates, and the tenant's spend must have been charged that estimate. The
//! negative control is a stream that ends cleanly: `complete`, the provider's
//! own counts, a `list` cost, charged once. A proxy that never recorded the
//! abort, or that charged the clean stream twice, fails one or the other.
//! Every cut is checked on all four surfaces it must reach: the request
//! record, the JSON access log (completeness and response flag), the tenant's
//! spend, and the tenant's token window (`GET /v1/usage`).
//!
//! The same harness, a minted key writing request records, also pins which
//! user a record names.
//!
//! Rust note: same harness shape as `tests/tenant_enforcement_e2e.rs` (std
//! threads, ephemeral ports, a `Drop` that kills the proxy, every wait bounded).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const RECORD_TIMEOUT: Duration = Duration::from_secs(20);

/// Requests the mock provider received with the `silent` marker, and how many
/// of those the proxy then hung up. Only the pre-headers test sends `silent`.
static UPSTREAM_SILENT: AtomicUsize = AtomicUsize::new(0);
static UPSTREAM_HUNG_UP: AtomicUsize = AtomicUsize::new(0);

const HMAC_SECRET: &str = "partial-usage-e2e-secret";
const ADMIN_TOKEN: &str = "partial-usage-e2e-admin-token";
const TENANT: &str = "t1";
const MODEL: &str = "gpt-4o-mini";

/// Nanodollars per token on the test rate card. Multiples of 1000, so the
/// spend accumulator's micro-dollar figure is exact.
const INPUT_NANO: u64 = 10_000;
const OUTPUT_NANO: u64 = 100_000;

/// The text in every mock frame is this many bytes, so one frame is one
/// estimated output token.
const FRAME_TEXT: &str = "abcd";

#[test]
fn an_abandoned_stream_is_recorded_partial_estimated_and_charged() {
    let dir = scratch_dir("abort");
    let proxy = Proxy::start(&dir, NO_TIMERS);
    let key = mint_key(&proxy);

    // Clean stream first: complete, provider counts, charged once.
    let clean_body = chat_body("clean");
    let response = post_to_end(proxy.listen, &key, &clean_body);
    assert!(response.starts_with("HTTP/1.1 200"), "got:\n{response}");
    let clean = proxy.wait_for_records(1).remove(0);
    assert_eq!(clean["usage"]["completeness"], "complete", "{clean}");
    assert_eq!(clean["usage"]["provenance"], "provider", "{clean}");
    assert_eq!(clean["usage"]["input_estimated"], false, "{clean}");
    assert_eq!(clean["usage"]["output_estimated"], false, "{clean}");
    assert_eq!(clean["cost"]["kind"], "list", "{clean}");
    assert_eq!(
        clean["cost"]["amount"],
        11 * INPUT_NANO + 5 * OUTPUT_NANO,
        "{clean}"
    );
    assert_eq!(clean["upstream_response_id"], "chatcmpl-clean", "{clean}");
    assert_eq!(
        clean["upstream_usage"],
        serde_json::json!({"prompt_tokens": 11, "completion_tokens": 5}),
        "the provider's usage object is embedded as JSON, not a string"
    );
    let clean_micros = (11 * INPUT_NANO + 5 * OUTPUT_NANO) / 1000;
    assert_eq!(
        proxy.spend_micros(),
        clean_micros,
        "a clean stream is charged exactly once"
    );
    assert_eq!(
        proxy.window_tokens(&key),
        11 + 5,
        "a clean stream moves the token window exactly once"
    );
    let clean_line = proxy.wait_for_chat_log_lines(1).remove(0);
    assert_eq!(
        clean_line["llm_usage_completeness"], "complete",
        "{clean_line}"
    );
    assert_eq!(clean_line["response_flags"], "-", "{clean_line}");

    // Abandoned stream: read the first frames, then drop the connection.
    let abort_body = chat_body("abort");
    abort_after_two_frames(proxy.listen, &key, &abort_body);
    let partial = proxy.wait_for_records(2).remove(1);
    assert_eq!(partial["usage"]["completeness"], "partial", "{partial}");
    assert_eq!(partial["usage"]["provenance"], "estimate", "{partial}");
    assert_eq!(partial["usage"]["input_estimated"], true, "{partial}");
    assert_eq!(partial["usage"]["output_estimated"], true, "{partial}");
    assert_eq!(
        partial["upstream_response_id"], "chatcmpl-abort",
        "{partial}"
    );
    assert!(partial["upstream_usage"].is_null(), "{partial}");
    // The client left: the remote side closed, unlike a drain-deadline cut.
    assert_eq!(
        partial["error_category"], "downstream_remote_disconnect",
        "{partial}"
    );

    // 4 bytes per token, rounded up, from the request size and the frames the
    // proxy had streamed. The client read two frames; the proxy may have
    // forwarded more before it noticed the disconnect.
    let input = partial["usage"]["input_tokens"].as_u64().unwrap();
    let output = partial["usage"]["output_tokens"].as_u64().unwrap();
    // The request size is the body the proxy forwarded (`bytes_request`), which
    // is larger than what the client sent when the proxy adds usage reporting.
    assert!(partial["bytes_request"].as_u64().unwrap() >= abort_body.len() as u64);
    assert_eq!(
        input,
        partial["bytes_request"].as_u64().unwrap().div_ceil(4),
        "{partial}"
    );
    assert!(
        output >= 2,
        "at least the two frames the client read: {partial}"
    );
    assert_eq!(partial["cost"]["kind"], "estimate", "{partial}");
    let estimate_nano = input * INPUT_NANO + output * OUTPUT_NANO;
    assert_eq!(partial["cost"]["amount"], estimate_nano, "{partial}");

    assert_eq!(
        proxy.spend_micros(),
        clean_micros + estimate_nano / 1000,
        "the abandoned stream's estimate is charged to the tenant"
    );
    assert_eq!(
        proxy.window_tokens(&key),
        11 + 5 + input + output,
        "the abandoned stream's estimate moves the token window once"
    );
    let line = proxy.wait_for_chat_log_lines(2).remove(1);
    assert_eq!(line["llm_usage_completeness"], "partial", "{line}");
    assert_eq!(line["llm_cost_kind"], "estimate", "{line}");
    assert_eq!(line["llm_output_tokens"], output.to_string(), "{line}");
    assert_eq!(line["response_flags"], "DC", "{line}");

    let stats = http_get(proxy.admin, "/stats/prometheus", None);
    assert!(
        stats.contains("envoy_llmproxy_usage_partial_total{") && stats.contains("} 1\n"),
        "partial counter missing from export:\n{stats}"
    );
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The provider resets the connection after two frames (no terminating
/// chunk): the stream ends with an upstream error, not a client hang-up.
#[test]
fn an_upstream_reset_mid_stream_is_recorded_partial_and_charged_once() {
    let dir = scratch_dir("reset");
    let proxy = Proxy::start(&dir, NO_TIMERS);
    let key = mint_key(&proxy);
    let response = post_to_end(proxy.listen, &key, &chat_body("reset"));
    assert!(response.starts_with("HTTP/1.1 200"), "got:\n{response}");
    assert_cut_charged_once(&proxy, &key, "UC");
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The provider sends two frames and then nothing, so a timer cuts the stream
/// after response headers. Each timer has its own cut path: the route's
/// `idle_timeout` (flag `SI`) and the listener's `max_stream_duration` (flag
/// `UMSDR`). The listener's `stream_idle_timeout` is not a case: every
/// dialect route carries an `idle_timeout` (default 90s), which takes over
/// the gap between response chunks once headers arrive.
#[test]
fn a_timeout_mid_stream_is_recorded_partial_and_charged_once() {
    let cases = [
        (
            "route-idle",
            Timers {
                route: ", idle_timeout: 1s",
                listen: "",
            },
            "SI",
        ),
        (
            "duration",
            Timers {
                route: "",
                listen: ", max_stream_duration: 1s",
            },
            "UMSDR",
        ),
    ];
    for (tag, timers, flag) in cases {
        let dir = scratch_dir(tag);
        let proxy = Proxy::start(&dir, timers);
        let key = mint_key(&proxy);
        let response = post_to_end(proxy.listen, &key, &chat_body("stall"));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "{tag}: got:\n{response}"
        );
        assert_cut_charged_once(&proxy, &key, flag);
        drop(proxy);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The drain deadline cuts a stream that is still flowing: SIGTERM with a
/// one-second `--drain-time-s` against a provider that streams for ten.
/// Stopping the workers drops the stream's response body, which writes the
/// record, and metadata delivery is flushed after that, so the record reaches
/// the records file before exit as a partial estimate. A shutdown that exited
/// without stopping the workers would leave the request unrecorded and
/// unbilled. The cut is `downstream_disconnect` / `DC`, as Envoy flags either
/// side's close, with details `downstream_local_disconnect` (ADR-0011).
#[test]
fn a_stream_cut_at_the_drain_deadline_is_recorded_partial_before_exit() {
    let dir = scratch_dir("drain");
    let mut proxy = Proxy::start_with_args(&dir, NO_TIMERS, &["--drain-time-s", "1"]);
    let key = mint_key(&proxy);
    let body = chat_body("abort");
    let mut stream = read_two_frames(proxy.listen, &key, &body);

    let status = Command::new("kill")
        .args(["-TERM", &proxy.child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(status.success(), "kill -TERM failed");

    // The stream ends without the terminating chunk: the deadline cut it.
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);
    let rest = String::from_utf8_lossy(&rest);
    assert!(
        !rest.contains("0\r\n\r\n"),
        "the stream must be cut, not completed: {rest:?}"
    );
    let deadline = Instant::now() + RECORD_TIMEOUT;
    let exit = loop {
        if let Some(exit) = proxy.child.try_wait().expect("try_wait") {
            break exit;
        }
        assert!(Instant::now() < deadline, "the proxy never exited");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(exit.success(), "a deadline drain exits zero: {exit:?}");

    // The process is gone, so whatever the file holds is final.
    let records = proxy.wait_for_records(1);
    assert_eq!(records.len(), 1, "{records:?}");
    let record = &records[0];
    assert_eq!(record["upstream_response_id"], "chatcmpl-abort", "{record}");
    assert_eq!(record["termination"], "downstream_disconnect", "{record}");
    assert_eq!(
        record["response_flags"],
        serde_json::json!(["DC"]),
        "{record}"
    );
    // Envoy's flag for either side's close; the details say this side cut it.
    assert_eq!(
        record["error_category"], "downstream_local_disconnect",
        "{record}"
    );
    assert_eq!(record["usage"]["completeness"], "partial", "{record}");
    assert_eq!(record["usage"]["provenance"], "estimate", "{record}");
    assert_eq!(record["cost"]["kind"], "estimate", "{record}");
    let input = record["usage"]["input_tokens"].as_u64().unwrap();
    let output = record["usage"]["output_tokens"].as_u64().unwrap();
    assert_eq!(
        input,
        record["bytes_request"].as_u64().unwrap().div_ceil(4),
        "{record}"
    );
    assert!(
        output >= 2,
        "at least the two frames the client read: {record}"
    );
    assert_eq!(
        record["cost"]["amount"],
        input * INPUT_NANO + output * OUTPUT_NANO,
        "{record}"
    );
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Pins `envoy-divergences.md` row 34: a client that hangs up while the
/// request still waits for response headers drops the filter chain's future,
/// so no `on_stream_complete`, no access log line, no record and no charge.
/// Envoy logs this stream (code 0, flag `DC`). When the divergence is fixed,
/// this test fails and should assert the logged line instead.
#[test]
fn a_client_disconnect_before_response_headers_is_not_logged_or_charged() {
    let dir = scratch_dir("preheaders");
    let proxy = Proxy::start(&dir, NO_TIMERS);
    let key = mint_key(&proxy);
    let mut stream = TcpStream::connect(proxy.listen).expect("connect");
    stream
        .write_all(chat_request(&key, &chat_body("silent")).as_bytes())
        .unwrap();
    wait_until("the request reaches the provider", || {
        UPSTREAM_SILENT.load(Ordering::SeqCst) == 1
    });
    drop(stream);
    // The proxy closing its upstream connection means the stream is gone:
    // anything it would log or record has been written by now.
    wait_until("the proxy hangs up on the provider", || {
        UPSTREAM_HUNG_UP.load(Ordering::SeqCst) == 1
    });

    // A clean request afterwards proves the sinks are live.
    let response = post_to_end(proxy.listen, &key, &chat_body("clean"));
    assert!(response.starts_with("HTTP/1.1 200"), "got:\n{response}");
    let records = proxy.wait_for_records(1);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["upstream_response_id"], "chatcmpl-clean");
    let lines = proxy.wait_for_chat_log_lines(1);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["response_flags"], "-", "{lines:?}");
    assert_eq!(
        proxy.spend_micros(),
        (11 * INPUT_NANO + 5 * OUTPUT_NANO) / 1000,
        "only the clean request is charged"
    );
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

fn wait_until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + IO_TIMEOUT;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The only request on `proxy` was cut after exactly two frames: its record,
/// access log line, spend and token window all carry the same partial
/// estimate, charged once, and the log names the cut with `flag`.
fn assert_cut_charged_once(proxy: &Proxy, key: &str, flag: &str) {
    let record = proxy.wait_for_records(1).remove(0);
    assert_eq!(record["usage"]["completeness"], "partial", "{record}");
    assert_eq!(record["usage"]["provenance"], "estimate", "{record}");
    assert_eq!(record["cost"]["kind"], "estimate", "{record}");
    let input = record["usage"]["input_tokens"].as_u64().unwrap();
    let output = record["usage"]["output_tokens"].as_u64().unwrap();
    assert_eq!(
        input,
        record["bytes_request"].as_u64().unwrap().div_ceil(4),
        "{record}"
    );
    // Exactly the two frames the provider sent before the cut.
    assert_eq!(output, 2, "{record}");
    let estimate_nano = input * INPUT_NANO + output * OUTPUT_NANO;
    assert_eq!(record["cost"]["amount"], estimate_nano, "{record}");

    let line = proxy.wait_for_chat_log_lines(1).remove(0);
    assert_eq!(line["llm_usage_completeness"], "partial", "{line}");
    assert_eq!(line["llm_cost_kind"], "estimate", "{line}");
    assert_eq!(line["llm_input_tokens"], input.to_string(), "{line}");
    assert_eq!(line["llm_output_tokens"], output.to_string(), "{line}");
    assert_eq!(line["response_flags"], flag, "{line}");

    assert_eq!(
        proxy.spend_micros(),
        estimate_nano / 1000,
        "the cut stream's estimate is charged to the tenant once"
    );
    assert_eq!(
        proxy.window_tokens(key),
        input + output,
        "the cut stream's estimate moves the token window once"
    );
}

/// The record and the access log name the user bound to the presented key
/// (the key is the user), even when the body's `user` field names someone
/// else: that field is the caller's to write. No metric carries either value
/// as a label (AGENTS.md "Policy Domains").
#[test]
fn the_record_names_the_keys_user_not_the_bodys_user_field() {
    let dir = scratch_dir("identity");
    let proxy = Proxy::start(&dir, NO_TIMERS);
    let key = mint_key(&proxy);

    let body = format!(
        r#"{{"model":"{MODEL}","stream":true,"user":"someone-else","messages":[{{"role":"user","content":"clean"}}]}}"#
    );
    let response = post_to_end(proxy.listen, &key, &body);
    assert!(response.starts_with("HTTP/1.1 200"), "got:\n{response}");

    let record = proxy.wait_for_records(1).remove(0);
    assert_eq!(record["user_id"], "minted-1", "{record}");
    let line = proxy.wait_for_chat_log_lines(1).remove(0);
    assert_eq!(line["llm_user_id"], "minted-1", "{line}");

    let metrics = http_get(proxy.admin, "/stats/prometheus", None);
    assert!(metrics.starts_with("HTTP/1.1 200"), "{metrics}");
    // The dialect's one HCM exports the in-flight gauge under its prefix.
    assert!(
        metrics.contains("envoy_downstream_rq_active{scope=\"llmproxy\"} "),
        "{metrics}"
    );
    for user in ["minted-1", "someone-else"] {
        assert!(
            !metrics.contains(user),
            "{user} reached a metric:\n{metrics}"
        );
    }
}

// ------------------------------------------------------------------ helpers --

fn chat_body(marker: &str) -> String {
    format!(
        r#"{{"model":"{MODEL}","stream":true,"messages":[{{"role":"user","content":"{marker}"}}]}}"#
    )
}

/// The dialect file: auth (so spend is charged to a tenant), a per-tenant
/// token limit (so the token window is metered), a rate card, and a JSON
/// access log. `timers` are appended to the listener and the catch-all route.
fn config_text(
    listen: u16,
    admin: u16,
    upstream: SocketAddr,
    access_log: &Path,
    timers: Timers,
) -> String {
    let Timers {
        route: route_extra,
        listen: listen_extra,
    } = timers;
    format!(
        r#"version: 0
listen: {{ address: "127.0.0.1:{listen}"{listen_extra} }}
admin: 127.0.0.1:{admin}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
routes:
  - {{ model: "*", provider: openai{route_extra} }}
auth:
  hmac_secret: "{HMAC_SECRET}"
  # The tenant holds no model policy; this test is about metering, not access.
  enforce: {{ tenants_without_policy: allow }}
pricing:
  price_list:
    version: partial-e2e
    effective_from: "2026-01-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: {MODEL}
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: {INPUT_NANO}
            cached_input_nanodollars_per_token: 1
            cache_write_nanodollars_per_token: 1
            output_nanodollars_per_token: {OUTPUT_NANO}
limits:
  - {{ key: tenant, tokens_per_minute: 1000000 }}
observability:
  access_logs: {{ output: {log}, format: json }}
"#,
        log = access_log.display(),
    )
}

/// Extra YAML flow-map entries (each starting `, `) for the listener and the
/// catch-all route, so a test can arm one stream timer.
#[derive(Clone, Copy)]
struct Timers {
    route: &'static str,
    listen: &'static str,
}

const NO_TIMERS: Timers = Timers {
    route: "",
    listen: "",
};

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-partial-usage-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// A running proxy. Killed and reaped on drop, so a failed assertion cannot
/// leave a listener behind (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    listen: SocketAddr,
    admin: SocketAddr,
    records: PathBuf,
    access_log: PathBuf,
}

impl Proxy {
    fn start(dir: &Path, timers: Timers) -> Proxy {
        Proxy::start_with_args(dir, timers, &[])
    }

    fn start_with_args(dir: &Path, timers: Timers, extra: &[&str]) -> Proxy {
        let listen = free_port();
        let admin = free_port();
        let upstream = spawn_streaming_upstream();
        let path = dir.join("llmproxy.yaml");
        let records = dir.join("records.jsonl");
        let access_log = dir.join("access.log");
        std::fs::write(
            &path,
            config_text(listen, admin, upstream, &access_log, timers),
        )
        .expect("write temp config");
        let child = Command::new(BIN)
            .args([
                "--config",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
                "--request-records-file",
                records.to_str().expect("utf-8 path"),
            ])
            .args(extra)
            .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn llm-proxy");
        let proxy = Proxy {
            child,
            listen: SocketAddr::from(([127, 0, 0, 1], listen)),
            admin: SocketAddr::from(([127, 0, 0, 1], admin)),
            records,
            access_log,
        };
        for addr in [proxy.admin, proxy.listen] {
            assert!(
                wait_for_connectable(addr, STARTUP_TIMEOUT),
                "{addr} did not become connectable in time"
            );
        }
        proxy
    }

    /// Wait until the records file holds `count` complete lines for chat
    /// requests (not the `GET /v1/usage` reads), and return them. Bounded: a
    /// record that never arrives fails the test.
    fn wait_for_records(&self, count: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + RECORD_TIMEOUT;
        loop {
            let text = std::fs::read_to_string(&self.records).unwrap_or_default();
            let records: Vec<serde_json::Value> = text
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .filter(|record| record["method"] == "POST")
                .collect();
            if records.len() >= count {
                return records;
            }
            assert!(
                Instant::now() < deadline,
                "only {} of {count} records arrived; file:\n{text}",
                records.len()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Wait until the access log holds `count` lines for chat requests, and
    /// return them. Bounded like `wait_for_records`.
    fn wait_for_chat_log_lines(&self, count: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + RECORD_TIMEOUT;
        loop {
            let text = std::fs::read_to_string(&self.access_log).unwrap_or_default();
            let lines: Vec<serde_json::Value> = text
                .lines()
                .filter(|line| line.contains("/v1/chat/completions"))
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
            if lines.len() >= count {
                return lines;
            }
            assert!(
                Instant::now() < deadline,
                "only {} of {count} chat log lines arrived; log:\n{text}",
                lines.len()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Tokens in the tenant's current token-limit window, from the tenant's
    /// own `GET /v1/usage` (answered by the limiter, never proxied).
    fn window_tokens(&self, key: &str) -> u64 {
        let response = http_get(self.listen, "/v1/usage", Some(&format!("Bearer {key}")));
        let body = response.split_once("\r\n\r\n").map_or("", |(_, b)| b);
        // Chunked or not: the chunk-size lines fall outside the braces.
        let body = match (body.find('{'), body.rfind('}')) {
            (Some(start), Some(end)) if start < end => &body[start..=end],
            _ => body,
        };
        let json: serde_json::Value = serde_json::from_str(body)
            .unwrap_or_else(|e| panic!("usage response is not JSON ({e}):\n{response}"));
        // The limiter reports weighted counts as floats.
        let used: f64 = json["routes"]
            .as_array()
            .unwrap_or_else(|| panic!("no routes:\n{response}"))
            .iter()
            .filter_map(|r| r["used"].as_f64())
            .sum();
        used as u64
    }

    /// The tenant's charged spend, in micro-dollars, from the admin API.
    fn spend_micros(&self) -> u64 {
        let response = http_get(
            self.admin,
            &format!("/tenants/{TENANT}/spend"),
            Some(&format!("Bearer {ADMIN_TOKEN}")),
        );
        let body = response.split_once("\r\n\r\n").map_or("", |(_, b)| b);
        let json: serde_json::Value = serde_json::from_str(body)
            .unwrap_or_else(|e| panic!("spend response is not JSON ({e}):\n{response}"));
        json["spend_micro_usd"].as_u64().expect("spend_micro_usd")
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn mint_key(proxy: &Proxy) -> String {
    let body = format!(r#"{{"tenant":"{TENANT}","key_id":"minted-1"}}"#);
    let response = http_request(
        "POST",
        proxy.admin,
        "/keys",
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        &body,
    );
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "POST /keys:\n{response}"
    );
    let json: serde_json::Value =
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).expect("JSON");
    json["key"].as_str().expect("plaintext key").to_string()
}

fn chat_request(key: &str, body: &str) -> String {
    format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: proxy.local\r\n\
         Authorization: Bearer {key}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn post_to_end(addr: SocketAddr, key: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream
        .write_all(chat_request(key, body).as_bytes())
        .unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

/// Send the request, read until two SSE frames have arrived, then drop the
/// connection without reading the rest.
fn abort_after_two_frames(addr: SocketAddr, key: &str, body: &str) {
    drop(read_two_frames(addr, key, body));
}

/// Send the request and read until two SSE frames have arrived; the
/// connection stays open for the caller.
fn read_two_frames(addr: SocketAddr, key: &str, body: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream
        .write_all(chat_request(key, body).as_bytes())
        .unwrap();
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + IO_TIMEOUT;
    while String::from_utf8_lossy(&seen).matches("data: ").count() < 2 {
        assert!(Instant::now() < deadline, "never saw two frames");
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => panic!("stream ended before two frames"),
            Ok(n) => seen.extend_from_slice(&buf[..n]),
        }
    }
    assert!(
        String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 200"),
        "got:\n{}",
        String::from_utf8_lossy(&seen)
    );
    stream
}

fn http_get(addr: SocketAddr, path: &str, authorization: Option<&str>) -> String {
    http_request("GET", addr, path, authorization, "")
}

fn http_request(
    method: &str,
    addr: SocketAddr,
    path: &str,
    authorization: Option<&str>,
    body: &str,
) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    let auth = authorization
        .map(|a| format!("Authorization: {a}\r\n"))
        .unwrap_or_default();
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: proxy.local\r\n{auth}\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

fn wait_for_connectable(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
}

fn chunk(data: &str) -> Vec<u8> {
    format!("{:x}\r\n{data}\r\n", data.len()).into_bytes()
}

fn frame(id: &str) -> String {
    format!(
        "data: {{\"id\":\"chatcmpl-{id}\",\"choices\":[{{\"delta\":{{\"content\":\"{FRAME_TEXT}\"}}}}]}}\n\n"
    )
}

/// A mock provider streaming chat-completions SSE. A request whose body names
/// `abort` gets a frame every 50 ms until the proxy closes the connection (a
/// write error), so it is still streaming when the client leaves. `reset`
/// gets two frames and then a closed connection without the terminating
/// chunk; `stall` gets two frames and then silence. Any other request gets
/// three frames, a final usage frame, `[DONE]`, and a clean end.
fn spawn_streaming_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || serve_stream(&mut stream));
        }
    });
    addr
}

fn serve_stream(stream: &mut TcpStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    let head_end = loop {
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
    let content_length: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    while raw.len() < head_end + 4 + content_length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    }
    let body = String::from_utf8_lossy(&raw[head_end + 4..]).to_string();
    let abort = body.contains("abort");
    let reset = body.contains("reset");
    let stall = body.contains("stall");
    let id = if abort { "abort" } else { "clean" };
    if body.contains("silent") {
        // Never answer; count the request, then wait (bounded by the read
        // timeout) for the proxy to hang up and count that.
        UPSTREAM_SILENT.fetch_add(1, Ordering::SeqCst);
        if matches!(stream.read(&mut buf), Ok(0)) {
            UPSTREAM_HUNG_UP.fetch_add(1, Ordering::SeqCst);
        }
        return;
    }
    let send = |stream: &mut TcpStream, bytes: &[u8]| stream.write_all(bytes).is_ok();
    if !send(
        stream,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
          Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
    ) {
        return;
    }
    if abort {
        // Bounded: at most ~10 s of frames even if the proxy never hangs up.
        for _ in 0..200 {
            if !send(stream, &chunk(&frame(id))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        return;
    }
    if reset || stall {
        for _ in 0..2 {
            send(stream, &chunk(&frame(id)));
        }
        let _ = stream.flush();
        if stall {
            // Longer than the route's 1 s idle timeout; bounded.
            std::thread::sleep(IO_TIMEOUT);
        } else {
            std::thread::sleep(Duration::from_millis(200));
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        return;
    }
    for _ in 0..3 {
        send(stream, &chunk(&frame(id)));
    }
    send(
        stream,
        &chunk("data: {\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":5}}\n\n"),
    );
    send(stream, &chunk("data: [DONE]\n\n"));
    send(stream, b"0\r\n\r\n");
}
