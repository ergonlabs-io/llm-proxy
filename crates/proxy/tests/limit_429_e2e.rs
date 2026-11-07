//! The 429 the proxy's own limits send, through the real binary.
//!
//! One test per cause (`request_limit_exceeded`, `token_limit_exceeded`,
//! `concurrency_limit_exceeded`, `spend_budget_exceeded`) checks the status,
//! the JSON body, the stable code and every header a client or SDK reads. The
//! body follows the client's API: a `.../messages` request gets Anthropic's
//! error shape, everything else OpenAI's. A last test records what a client
//! receives when every provider of a failover chain answers 429 itself.
//!
//! Rust note: same harness shape as `tests/dialect_limits_e2e.rs` (std
//! threads, ephemeral ports, a `Drop` that kills the proxy).

mod common;

use common::free_port;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const WAIT: Duration = Duration::from_secs(10);

const HMAC_SECRET: &str = "limit-429-e2e-secret";
const ADMIN_TOKEN: &str = "limit-429-e2e-admin-token";
const TENANT: &str = "t1";

#[test]
fn a_request_limit_429_names_the_requests_dimension() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("requests");
    let mock = Mock::ok(Duration::ZERO);
    let proxy = Proxy::start(
        &dir,
        &config(mock.addr, "  - { key: global, requests_per_minute: 1 }\n"),
    );
    assert_eq!(chat(&proxy, &[]).status, 200);

    let refused = chat(&proxy, &[]);
    assert_eq!(refused.status, 429, "{refused:?}");
    assert_eq!(refused.header("content-type"), "application/json");
    assert_openai_error(&refused, "request_limit_exceeded", "request rate exceeded");
    let retry = refused.retry_after();
    assert!((1..=60).contains(&retry), "a per-minute wait: {retry}");
    assert_eq!(refused.header("x-should-retry"), "true");
    for (suffixed, unsuffixed) in [
        ("x-ratelimit-limit-requests", "x-ratelimit-limit"),
        ("x-ratelimit-remaining-requests", "x-ratelimit-remaining"),
        ("x-ratelimit-reset-requests", "x-ratelimit-reset"),
    ] {
        // The unsuffixed set is deprecated but still sent for one minor release.
        assert_eq!(refused.header(suffixed), refused.header(unsuffixed));
    }
    assert_eq!(refused.header("x-ratelimit-limit-requests"), "1");
    assert_eq!(refused.header("x-ratelimit-remaining-requests"), "0");
    assert_eq!(
        refused.header("x-ratelimit-reset-requests"),
        retry.to_string()
    );
    assert!(
        refused.headers.keys().all(|n| !n.ends_with("-tokens")),
        "a request refusal must not name the tokens dimension: {:?}",
        refused.headers
    );
    assert_eq!(mock.count(), 1, "the refused request reached the upstream");
    finish(proxy, &dir);
}

#[test]
fn a_token_limit_429_names_the_tokens_dimension() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("tokens");
    let mock = Mock::ok(Duration::ZERO);
    let proxy = Proxy::start(
        &dir,
        &auth_config(
            mock.addr,
            "  - { key: tenant, tokens_per_minute: 10 }\n",
            "",
        ),
    );
    let auth = format!("Bearer {}", setup_tenant(&proxy));
    assert_eq!(chat(&proxy, &[("authorization", &auth)]).status, 200);

    // The mock reports 10 total tokens, which spends the whole limit.
    let refused = chat(&proxy, &[("authorization", &auth)]);
    assert_eq!(refused.status, 429, "{refused:?}");
    assert_openai_error(&refused, "token_limit_exceeded", "token budget exceeded");
    let retry = refused.retry_after();
    assert!((1..=60).contains(&retry), "a per-minute wait: {retry}");
    assert_eq!(refused.header("x-should-retry"), "true");
    assert_eq!(refused.header("x-ratelimit-limit-tokens"), "10");
    assert_eq!(refused.header("x-ratelimit-remaining-tokens"), "0");
    assert_eq!(
        refused.header("x-ratelimit-reset-tokens"),
        retry.to_string()
    );
    assert_eq!(refused.header("x-ratelimit-limit"), "10");
    assert!(
        refused.headers.keys().all(|n| !n.ends_with("-requests")),
        "a token refusal must not name the requests dimension: {:?}",
        refused.headers
    );
    assert_eq!(mock.count(), 1, "the refused request reached the upstream");
    finish(proxy, &dir);
}

#[test]
fn a_concurrency_429_has_a_code_and_no_dimension_headers() {
    let dir = scratch_dir("streams");
    let mock = Mock::ok(Duration::from_millis(1500));
    let proxy = Proxy::start(
        &dir,
        &config(mock.addr, "  - { key: global, concurrent_sessions: 1 }\n"),
    );
    let listen = proxy.listen;
    let first = std::thread::spawn(move || send_chat(listen, "/v1/chat/completions", &[]));
    wait_until(|| mock.count() == 1, "the mock to receive request 1");

    let refused = chat(&proxy, &[]);
    assert_eq!(refused.status, 429, "{refused:?}");
    assert_openai_error(
        &refused,
        "concurrency_limit_exceeded",
        "too many concurrent streams",
    );
    let retry = refused.retry_after();
    assert_eq!(
        refused.header("x-should-retry"),
        if retry > 60 { "false" } else { "true" }
    );
    assert!(
        refused
            .headers
            .keys()
            .all(|n| !n.ends_with("-requests") && !n.ends_with("-tokens")),
        "a stream refusal has no counted dimension: {:?}",
        refused.headers
    );
    assert_eq!(mock.count(), 1, "the refused request reached the upstream");
    assert_eq!(first.join().expect("request 1 thread").status, 200);
    finish(proxy, &dir);
}

#[test]
fn a_spend_429_carries_budget_headers_in_usd_and_no_ratelimit_headers() {
    let dir = scratch_dir("spend");
    let mock = Mock::ok(Duration::ZERO);
    // The mock reports 6 input and 4 output tokens: 14 micro-dollars a request.
    let proxy = Proxy::start(&dir, &auth_config(mock.addr, "", PRICING));
    let key = setup_tenant(&proxy);
    let put = admin(
        &proxy,
        "PUT",
        "/keys/k1/budget",
        r#"{"budget":{"max_usd":"0.000010","period":"daily"}}"#,
    );
    assert_eq!(put.status, 204, "{put:?}");
    let auth = format!("Bearer {key}");
    assert_eq!(chat(&proxy, &[("authorization", &auth)]).status, 200);

    // Spend is recorded as the response ends; allow the proxy a moment.
    let deadline = Instant::now() + WAIT;
    let refused = loop {
        let next = chat(&proxy, &[("authorization", &auth)]);
        if next.status == 429 {
            break next;
        }
        assert!(Instant::now() < deadline, "never refused: {next:?}");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_openai_error(&refused, "spend_budget_exceeded", "spend budget exceeded");
    assert_eq!(refused.header("x-llmproxy-budget-limit-usd"), "0.000010");
    assert_eq!(
        refused.header("x-llmproxy-budget-remaining-usd"),
        "0.000000"
    );
    let reset = refused.header("x-llmproxy-budget-reset");
    assert_eq!(reset, refused.retry_after().to_string());
    // A daily budget resets at the next UTC midnight: over a minute away
    // except in that last minute.
    let wait = refused.retry_after();
    assert_eq!(
        refused.header("x-should-retry"),
        if wait > 60 { "false" } else { "true" }
    );
    assert!(
        refused
            .headers
            .keys()
            .all(|n| !n.starts_with("x-ratelimit")),
        "a spend refusal must not borrow the request/token names: {:?}",
        refused.headers
    );
    finish(proxy, &dir);
}

#[test]
fn a_messages_request_gets_the_anthropic_error_shape() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("anthropic");
    let mock = Mock::ok(Duration::ZERO);
    let proxy = Proxy::start(
        &dir,
        &config(mock.addr, "  - { key: global, requests_per_minute: 1 }\n"),
    );
    assert_eq!(send_chat(proxy.listen, "/v1/messages", &[]).status, 200);

    let refused = send_chat(proxy.listen, "/v1/messages", &[]);
    assert_eq!(refused.status, 429, "{refused:?}");
    assert_eq!(refused.header("content-type"), "application/json");
    let body = refused.json();
    assert_eq!(body["type"], "error", "{body}");
    assert_eq!(body["error"]["type"], "rate_limit_error", "{body}");
    assert_eq!(body["error"]["message"], "request rate exceeded", "{body}");
    assert_eq!(body["error"]["code"], "request_limit_exceeded", "{body}");
    assert!(
        body.get("code").is_none(),
        "the Anthropic shape keeps `code` inside `error`: {body}"
    );
    finish(proxy, &dir);
}

/// Records, and so pins, what a client receives when every provider of a
/// failover chain answers 429: today the proxy passes the last provider's
/// response through unchanged, including its own rate-limit headers. A
/// tenant therefore sees the limits of the platform's account with that
/// provider. Changing that is an owner decision; this test fails when it
/// changes so the change is deliberate.
#[test]
fn a_failover_chain_that_all_answers_429_passes_the_last_providers_headers_through() {
    let dir = scratch_dir("failover");
    let first = Mock::rate_limited("111");
    let second = Mock::rate_limited("222");
    let proxy = Proxy::start(&dir, &failover_config(first.addr, second.addr, ""));

    let response = send_model(proxy.listen, "/v1/chat/completions", "chain", &[]);
    assert_eq!(response.status, 429, "{response:?}");
    let seen = (
        first.count(),
        second.count(),
        response.headers.get("x-ratelimit-limit-requests").cloned(),
        response.headers.get("retry-after").cloned(),
        response.body.clone(),
    );
    assert_eq!(
        seen,
        (
            1,
            1,
            Some("222".to_string()),
            Some("17".to_string()),
            r#"{"error":"provider-rate-limited"}"#.to_string()
        ),
        "every member was tried, and the client got the last member's 429 verbatim"
    );
    finish(proxy, &dir);
}

#[test]
fn a_key_with_requests_per_day_3_admits_three_and_refuses_the_fourth() {
    start_away_from_a_day_edge();
    let dir = scratch_dir("daily-requests");
    let mock = Mock::ok(Duration::ZERO);
    let proxy = Proxy::start(&dir, &auth_config(mock.addr, "", ""));
    let key = setup_tenant(&proxy);
    let put = admin(
        &proxy,
        "PUT",
        "/keys/k1/limits",
        r#"{"limits":{"requests_per_day":3}}"#,
    );
    assert_eq!(put.status, 204, "{put:?}");
    let auth = format!("Bearer {key}");

    for n in 1..=3 {
        assert_eq!(
            chat(&proxy, &[("authorization", &auth)]).status,
            200,
            "request {n}"
        );
    }
    let refused = chat(&proxy, &[("authorization", &auth)]);
    assert_eq!(refused.status, 429, "{refused:?}");
    assert_openai_error(
        &refused,
        "request_limit_exceeded",
        "request rate exceeded (daily limit)",
    );
    // The wait is to the next UTC midnight: over a minute away, since the
    // test started away from the day's edge.
    let wait = refused.retry_after();
    assert!((61..=86_400).contains(&wait), "{wait}");
    assert_eq!(refused.header("x-should-retry"), "false");
    assert_eq!(refused.header("x-ratelimit-limit-requests"), "3");
    assert_eq!(refused.header("x-ratelimit-remaining-requests"), "0");
    assert_eq!(mock.count(), 3, "the refused request reached the upstream");
    finish(proxy, &dir);
}

/// `tokens_per_day` charges the usage the provider that answered reported,
/// here the second member of a chain whose first member is down.
#[test]
fn a_daily_token_limit_charges_the_provider_that_answered_after_failover() {
    start_away_from_a_day_edge();
    let dir = scratch_dir("daily-tokens-failover");
    let first = Mock::unavailable();
    let second = Mock::ok(Duration::ZERO);
    let extra = format!(
        "admin: 127.0.0.1:{}\nauth:\n  hmac_secret: \"{HMAC_SECRET}\"\n\
         limits:\n  - {{ key: tenant, tokens_per_day: 15 }}\n",
        free_port()
    );
    let proxy = Proxy::start(&dir, &failover_config(first.addr, second.addr, &extra));
    let key = setup_tenant(&proxy);
    let auth = format!("Bearer {key}");

    // Each answer reports 10 tokens: 10 is under 15, 20 is over.
    for n in 1..=2 {
        let r = send_model(
            proxy.listen,
            "/v1/chat/completions",
            "chain",
            &[("authorization", &auth)],
        );
        assert_eq!(r.status, 200, "request {n}: {r:?}");
    }
    assert_eq!(second.count(), 2, "the second member answered both");
    let refused = send_model(
        proxy.listen,
        "/v1/chat/completions",
        "chain",
        &[("authorization", &auth)],
    );
    assert_eq!(refused.status, 429, "{refused:?}");
    assert_openai_error(
        &refused,
        "token_limit_exceeded",
        "token budget exceeded (daily limit)",
    );
    assert_eq!(refused.header("x-ratelimit-limit-tokens"), "15");
    assert_eq!(refused.header("x-should-retry"), "false");
    finish(proxy, &dir);
}

/// With a persistent store the day's count is written beside the keys, so a
/// restarted proxy still refuses. (With `in_memory` the keys and counts are
/// gone after a restart, which the docs state.)
#[test]
fn a_daily_count_survives_a_restart_with_a_persistent_store() {
    start_away_from_a_day_edge();
    let dir = scratch_dir("daily-restart");
    let mock = Mock::ok(Duration::ZERO);
    let store = format!(
        "  store:\n    persistent: {{ path: \"{}\" }}\n",
        dir.join("control.redb").display()
    );
    let config = auth_config_with_store(mock.addr, "", "", &store);
    let proxy = Proxy::start(&dir, &config);
    let key = setup_tenant(&proxy);
    let put = admin(
        &proxy,
        "PUT",
        "/keys/k1/limits",
        r#"{"limits":{"requests_per_day":2}}"#,
    );
    assert_eq!(put.status, 204, "{put:?}");
    let auth = format!("Bearer {key}");
    for n in 1..=2 {
        assert_eq!(
            chat(&proxy, &[("authorization", &auth)]).status,
            200,
            "request {n}"
        );
    }
    // Counts reach the store on the flush interval (one second by default).
    std::thread::sleep(Duration::from_secs(3));
    drop(proxy);

    let proxy = Proxy::start(&dir, &config);
    let deadline = Instant::now() + WAIT;
    let refused = loop {
        let r = chat(&proxy, &[("authorization", &auth)]);
        if r.status == 429 {
            break r;
        }
        assert!(Instant::now() < deadline, "the day's count was lost: {r:?}");
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_openai_error(
        &refused,
        "request_limit_exceeded",
        "request rate exceeded (daily limit)",
    );
    finish(proxy, &dir);
}

// ------------------------------------------------------------------ helpers --

const PRICING: &str = r#"pricing:
  price_list:
    version: limit-429-e2e
    effective_from: "2026-01-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: gpt-4o
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 1000
            cached_input_nanodollars_per_token: 1000
            cache_write_nanodollars_per_token: 1000
            output_nanodollars_per_token: 2000
"#;

fn config(upstream: SocketAddr, limits: &str) -> String {
    format!(
        r#"version: 1
listen: 127.0.0.1:{listen}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
routes:
  - {{ model: "*", provider: openai }}
limits:
{limits}"#,
        listen = free_port(),
    )
}

/// A config with `auth` (so keys can be minted) and, optionally, `limits` and
/// extra top-level blocks such as [`PRICING`].
fn auth_config(upstream: SocketAddr, limits: &str, extra: &str) -> String {
    auth_config_with_store(upstream, limits, extra, "")
}

/// [`auth_config`] with `store` (indented `auth` members) after `hmac_secret`.
fn auth_config_with_store(upstream: SocketAddr, limits: &str, extra: &str, store: &str) -> String {
    let limits = if limits.is_empty() {
        String::new()
    } else {
        format!("limits:\n{limits}")
    };
    format!(
        r#"version: 1
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
{store}{limits}{extra}"#,
        listen = free_port(),
        admin = free_port(),
    )
}

fn failover_config(first: SocketAddr, second: SocketAddr, extra: &str) -> String {
    format!(
        r#"version: 1
listen: 127.0.0.1:{listen}
providers:
  first: {{ type: openai, base_url: "http://{first}", api_key: sk-first }}
  second: {{ type: openai, base_url: "http://{second}", api_key: sk-second }}
routes:
  - {{ model: "unused", provider: first }}
models:
  chain: {{ providers: [first, second] }}
{extra}"#,
        listen = free_port(),
    )
}

fn assert_openai_error(response: &Response, code: &str, message: &str) {
    let body = response.json();
    assert_eq!(body["error"]["code"], code, "{body}");
    assert_eq!(body["error"]["message"], message, "{body}");
    assert_eq!(body["error"]["type"], "rate_limit_error", "{body}");
    assert!(
        body.get("type").is_none(),
        "the OpenAI shape has no top-level `type`: {body}"
    );
}

fn finish(proxy: Proxy, dir: &Path) {
    drop(proxy);
    let _ = std::fs::remove_dir_all(dir);
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-limit-429-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// A running proxy, killed and reaped on drop (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    listen: SocketAddr,
    admin: Option<SocketAddr>,
}

impl Proxy {
    fn start(dir: &Path, config: &str) -> Proxy {
        let listen = port_after(config, "listen: 127.0.0.1:").expect("listen port");
        let admin = port_after(config, "admin: 127.0.0.1:");
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).expect("write temp config");
        let child = Command::new(BIN)
            .args([
                "--config",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
            ])
            .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn llm-proxy");
        let proxy = Proxy {
            child,
            listen: SocketAddr::from(([127, 0, 0, 1], listen)),
            admin: admin.map(|p| SocketAddr::from(([127, 0, 0, 1], p))),
        };
        for addr in proxy.admin.into_iter().chain([proxy.listen]) {
            assert!(
                wait_for_connectable(addr, STARTUP_TIMEOUT),
                "listener at {addr} did not become connectable in time"
            );
        }
        proxy
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn port_after(config: &str, prefix: &str) -> Option<u16> {
    config
        .split(prefix)
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Grants the tenant every model and mints key `k1`; returns its plaintext.
fn setup_tenant(proxy: &Proxy) -> String {
    let policy = admin(
        proxy,
        "PUT",
        &format!("/tenants/{TENANT}/policy"),
        r#"{"access":"all"}"#,
    );
    assert_eq!(policy.status, 204, "{policy:?}");
    let minted = admin(
        proxy,
        "POST",
        "/keys",
        &format!(r#"{{"tenant":"{TENANT}","key_id":"k1"}}"#),
    );
    assert_eq!(minted.status, 201, "{minted:?}");
    minted.json()["key"]
        .as_str()
        .expect("plaintext key")
        .to_string()
}

fn admin(proxy: &Proxy, method: &str, path: &str, body: &str) -> Response {
    let addr = proxy.admin.expect("this test configured an admin listener");
    request(
        method,
        addr,
        path,
        &[("authorization", &format!("Bearer {ADMIN_TOKEN}"))],
        body,
    )
}

fn chat(proxy: &Proxy, headers: &[(&str, &str)]) -> Response {
    send_chat(proxy.listen, "/v1/chat/completions", headers)
}

fn send_chat(listen: SocketAddr, path: &str, headers: &[(&str, &str)]) -> Response {
    send_model(listen, path, "gpt-4o", headers)
}

fn send_model(listen: SocketAddr, path: &str, model: &str, headers: &[(&str, &str)]) -> Response {
    request(
        "POST",
        listen,
        path,
        headers,
        &format!(
            r#"{{"model":"{model}","max_tokens":8,"messages":[{{"role":"user","content":"hi"}}]}}"#
        ),
    )
}

/// A parsed HTTP/1.1 response. Header names are lower-cased.
#[derive(Debug)]
struct Response {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

impl Response {
    fn parse(raw: &str) -> Response {
        let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
        let mut lines = head.lines();
        let status = lines
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no status line in:\n{raw}"));
        let headers: HashMap<String, String> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        let chunked = headers
            .get("transfer-encoding")
            .is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
        let body = if chunked {
            dechunk(body)
        } else {
            body.to_string()
        };
        Response {
            status,
            headers,
            body,
        }
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .unwrap_or_else(|| panic!("no `{name}` header in {self:?}"))
    }

    fn retry_after(&self) -> u64 {
        self.header("retry-after")
            .parse()
            .expect("retry-after is a number of seconds")
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("body is JSON ({e}): {self:?}"))
    }
}

/// Decodes a chunked body (no trailers, no extensions).
fn dechunk(mut raw: &str) -> String {
    let mut out = String::new();
    while let Some((size, rest)) = raw.split_once("\r\n") {
        let size = usize::from_str_radix(size.trim(), 16).expect("hex chunk size");
        if size == 0 {
            break;
        }
        out.push_str(&rest[..size]);
        raw = &rest[size + 2..];
    }
    out
}

fn request(
    method: &str,
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Response {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    let extra: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: proxy.local\r\n{extra}\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .expect("write request");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    Response::parse(&String::from_utf8_lossy(&raw))
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

fn wait_until(condition: impl Fn() -> bool, what: &str) {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A mock upstream that counts the requests it fully received. `ok` answers
/// 200 with 10 total tokens after `delay`; `rate_limited` answers 429 with
/// its own rate-limit headers, marked by `limit`.
struct Mock {
    addr: SocketAddr,
    received: Arc<AtomicUsize>,
}

impl Mock {
    fn ok(delay: Duration) -> Mock {
        let body = r#"{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":6,"completion_tokens":4,"total_tokens":10}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        Mock::start(delay, response)
    }

    /// Answers `503`, which a failover chain retries on its next member.
    fn unavailable() -> Mock {
        Mock::start(
            Duration::ZERO,
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n"
                .to_string(),
        )
    }

    fn rate_limited(limit: &str) -> Mock {
        let body = r#"{"error":"provider-rate-limited"}"#;
        let response = format!(
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n\
             x-ratelimit-limit-requests: {limit}\r\nretry-after: 17\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        Mock::start(Duration::ZERO, response)
    }

    fn start(delay: Duration, response: String) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
        let addr = listener.local_addr().expect("no local addr");
        let received = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&received);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let counter = Arc::clone(&counter);
                let response = response.clone();
                std::thread::spawn(move || {
                    if read_request(&mut stream).is_none() {
                        return;
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(delay);
                    let _ = stream.write_all(response.as_bytes());
                });
            }
        });
        Mock { addr, received }
    }

    fn count(&self) -> usize {
        self.received.load(Ordering::SeqCst)
    }
}

/// Reads one full request (head and Content-Length body); `None` on error.
fn read_request(stream: &mut TcpStream) -> Option<()> {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
    let content_length: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let mut have = raw.len() - (head_end + 4);
    while have < content_length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => have += n,
        }
    }
    Some(())
}

/// Windows are one minute and epoch-aligned. A test that counts requests in
/// one window waits out the last seconds of a minute so it cannot straddle one.
fn start_away_from_a_window_edge() {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs();
    let into_minute = secs % 60;
    if into_minute >= 50 {
        std::thread::sleep(Duration::from_secs(61 - into_minute));
    }
}

/// Daily windows end at UTC midnight. A test that expects a wait of more than
/// a minute must not start in the last minutes of the UTC day.
fn start_away_from_a_day_edge() {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs();
    let into_day = secs % 86_400;
    if into_day >= 86_400 - 120 {
        std::thread::sleep(Duration::from_secs(86_400 - into_day + 1));
    }
}
