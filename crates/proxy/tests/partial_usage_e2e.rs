//! A stream the client abandons is still metered: the real `llm-proxy` binary
//! in `--config` mode, a mock upstream that streams SSE slowly, and a client
//! that reads the first frames and then drops the connection.
//!
//! The request record (`--request-records-file`) must say `completeness:
//! partial`, carry the upstream response id, mark the token counts and cost as
//! estimates, and the tenant's spend must have been charged that estimate. The
//! negative control is a stream that ends cleanly: `complete`, the provider's
//! own counts, a `list` cost, charged once. A proxy that never recorded the
//! abort, or that charged the clean stream twice, fails one or the other.
//!
//! Rust note: same harness shape as `tests/tenant_enforcement_e2e.rs` (std
//! threads, ephemeral ports, a `Drop` that kills the proxy, every wait bounded).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const RECORD_TIMEOUT: Duration = Duration::from_secs(20);

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
    let proxy = Proxy::start(&dir);
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

    let stats = http_get(proxy.admin, "/stats/prometheus", None);
    assert!(
        stats.contains("envoy_llmproxy_usage_partial_total{") && stats.contains("} 1\n"),
        "partial counter missing from export:\n{stats}"
    );
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

fn chat_body(marker: &str) -> String {
    format!(
        r#"{{"model":"{MODEL}","stream":true,"messages":[{{"role":"user","content":"{marker}"}}]}}"#
    )
}

/// The dialect file: auth (so spend is charged to a tenant) and a rate card.
fn config_text(listen: u16, admin: u16, upstream: SocketAddr) -> String {
    format!(
        r#"version: 0
listen: 127.0.0.1:{listen}
admin: 127.0.0.1:{admin}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
routes:
  - {{ model: "*", provider: openai }}
auth:
  hmac_secret: "{HMAC_SECRET}"
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
"#
    )
}

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
}

impl Proxy {
    fn start(dir: &Path) -> Proxy {
        let listen = free_port();
        let admin = free_port();
        let upstream = spawn_streaming_upstream();
        let path = dir.join("llmproxy.yaml");
        let records = dir.join("records.jsonl");
        std::fs::write(&path, config_text(listen, admin, upstream)).expect("write temp config");
        let child = Command::new(BIN)
            .args([
                "--config",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
                "--request-records-file",
                records.to_str().expect("utf-8 path"),
            ])
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
        };
        for addr in [proxy.admin, proxy.listen] {
            assert!(
                wait_for_connectable(addr, STARTUP_TIMEOUT),
                "{addr} did not become connectable in time"
            );
        }
        proxy
    }

    /// Wait until the records file holds `count` complete lines, and return
    /// them. Bounded: a record that never arrives fails the test.
    fn wait_for_records(&self, count: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + RECORD_TIMEOUT;
        loop {
            let text = std::fs::read_to_string(&self.records).unwrap_or_default();
            let records: Vec<serde_json::Value> = text
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
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
    drop(stream);
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
/// write error), so it is still streaming when the client leaves. Any other
/// request gets three frames, a final usage frame, `[DONE]`, and a clean end.
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
    let id = if abort { "abort" } else { "clean" };
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
