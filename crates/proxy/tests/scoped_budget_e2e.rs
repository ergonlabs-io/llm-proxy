//! Scoped budgets through the real binary in `--config` mode: a budget
//! narrowed by provider is charged for the provider that served after
//! failover, never the primary, and a spent one closes its provider so the
//! request fails over; a budget narrowed by model refuses only that model.
//!
//! Two OpenAI-compatible mock upstreams stand in for the providers. Each
//! records how many requests it received; the primary can be told to answer
//! 503, which the route's fallback chain treats as a failure. Spend is read
//! back through `GET /tenants/{id}/scoped_budgets`, the admin surface an
//! operator uses.
//!
//! Rust note: same harness shape as `tests/byok_key_budget_e2e.rs` (std
//! threads, ephemeral ports, a `Drop` that kills the proxy). Every wait is
//! bounded.

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const ADMIN_TOKEN: &str = "scoped-budget-e2e-admin-token";
const TENANT: &str = "acme";

/// The mock's usage (6 input, 4 output tokens) at the configured prices
/// (1000 and 2000 nanodollars per token) costs 14 micro-dollars.
const REQUEST_MICROS: u64 = 14;

#[test]
fn provider_budgets_charge_the_member_dialled_and_model_budgets_refuse_only_their_model() {
    let dir = scratch_dir();
    let primary = Upstream::spawn();
    let fallback = Upstream::spawn();
    let proxy = Proxy::start(&dir, &config_text(primary.addr, fallback.addr, &dir));
    let key = setup_tenant(&proxy);

    // A budget on each provider, roomy, with an alert at half of the
    // fallback's ceiling (two requests' cost).
    put_scoped_budgets(
        &proxy,
        r#"[
          {"name":"primary-cap","max_usd":"1.00","period":"daily","providers":["primary"]},
          {"name":"fallback-cap","max_usd":"0.000028","period":"daily","providers":["fallback"],
           "alert_at_percent":[50]}
        ]"#,
    );

    // Failover: the primary answers 503, the fallback serves.
    primary.fail.store(true, Ordering::SeqCst);
    assert_eq!(status(&chat(&proxy, &key, "gpt-4o")), 200);
    assert_eq!(
        (primary.hits(), fallback.hits()),
        (1, 1),
        "the request must have failed over"
    );
    let spend = scoped_spend(&proxy);
    assert_eq!(
        spend["fallback-cap"], REQUEST_MICROS,
        "the member that served is charged"
    );
    assert_eq!(
        spend["primary-cap"], 0,
        "the primary answered 503 and must not be charged: {spend:?}"
    );

    // The fallback budget is now half spent, which the gauge reports per
    // tenant and budget, with no user or key label.
    let line = wait_for_metric(&proxy, r#"budget="fallback-cap""#);
    assert!(
        line.contains(r#"tenant="acme""#) && line.ends_with(" 50"),
        "the gauge reads 50 percent for the fallback budget: {line}"
    );
    assert!(
        !line.contains("user") && !line.contains("key"),
        "no user or key label: {line}"
    );

    // A second failover spends the fallback budget. The next request tries
    // the failing primary, and its fallback is closed: the client gets the
    // primary's answer, as from any fallback chain with nothing left.
    assert_eq!(status(&chat(&proxy, &key, "gpt-4o")), 200);
    assert_eq!(fallback.hits(), 2);
    let failed = chat(&proxy, &key, "gpt-4o");
    assert_eq!(status(&failed), 503, "{failed}");
    assert_eq!(
        fallback.hits(),
        2,
        "a closed provider is never dialled: {failed}"
    );

    // With the primary healthy again, the closed fallback does not matter.
    primary.fail.store(false, Ordering::SeqCst);
    assert_eq!(status(&chat(&proxy, &key, "gpt-4o")), 200);
    assert_eq!(fallback.hits(), 2);

    // A spent primary budget closes the primary: the request fails over to
    // the fallback without dialling the primary at all.
    put_scoped_budgets(
        &proxy,
        r#"[{"name":"primary-cap","max_usd":"0","period":"daily","providers":["primary"]}]"#,
    );
    let primary_before = primary.hits();
    assert_eq!(status(&chat(&proxy, &key, "gpt-4o")), 200);
    assert_eq!(
        (primary.hits(), fallback.hits()),
        (primary_before, 3),
        "the closed primary is skipped and the fallback serves"
    );

    // Both providers closed: nothing can be dialled, so the router sends the
    // spend filter's 429 for the first spent budget.
    put_scoped_budgets(
        &proxy,
        r#"[
          {"name":"primary-cap","max_usd":"0","period":"daily","providers":["primary"]},
          {"name":"fallback-cap","max_usd":"0","period":"daily","providers":["fallback"]}
        ]"#,
    );
    let (p, f) = (primary.hits(), fallback.hits());
    assert_scoped_refusal(&chat(&proxy, &key, "gpt-4o"), "primary-cap");
    assert_eq!(
        (primary.hits(), fallback.hits()),
        (p, f),
        "a request with every provider closed reaches none"
    );
    // A route straight to the closed primary, with no fallback, is refused
    // before any pick.
    assert_scoped_refusal(&chat(&proxy, &key, "solo-1"), "primary-cap");
    assert_eq!(primary.hits(), p, "the closed primary is never dialled");

    // A spent model budget refuses its model only, whatever the provider.
    put_scoped_budgets(
        &proxy,
        r#"[{"name":"gpt-4o-cap","max_usd":"0","period":"daily","models":["gpt-4o*"]}]"#,
    );
    let (p, f) = (primary.hits(), fallback.hits());
    assert_scoped_refusal(&chat(&proxy, &key, "gpt-4o-mini"), "gpt-4o-cap");
    assert_eq!(
        (primary.hits(), fallback.hits()),
        (p, f),
        "a refused request reaches no provider"
    );
    assert_eq!(
        status(&chat(&proxy, &key, "gpt-5")),
        200,
        "another model is not held to the gpt-4o budget"
    );

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

fn setup_tenant(proxy: &Proxy) -> String {
    proxy.admin(
        "POST",
        "/tenants",
        &format!(r#"{{"tenant":"{TENANT}"}}"#),
        201,
    );
    proxy.admin(
        "PUT",
        &format!("/tenants/{TENANT}/policy"),
        r#"{"access":"all"}"#,
        204,
    );
    let minted = proxy.admin(
        "POST",
        "/keys",
        &format!(r#"{{"tenant":"{TENANT}","key_id":"scoped"}}"#),
        201,
    );
    let minted: serde_json::Value =
        serde_json::from_str(response_body(&minted)).expect("mint response is JSON");
    format!("Bearer {}", minted["key"].as_str().expect("plaintext key"))
}

fn put_scoped_budgets(proxy: &Proxy, budgets: &str) {
    proxy.admin(
        "PUT",
        &format!("/tenants/{TENANT}/scoped_budgets"),
        &format!(r#"{{"budgets":{budgets}}}"#),
        204,
    );
}

/// Each scoped budget's live spend this period, by name.
fn scoped_spend(proxy: &Proxy) -> std::collections::HashMap<String, u64> {
    let response = proxy.admin("GET", &format!("/tenants/{TENANT}/scoped_budgets"), "", 200);
    let body: serde_json::Value =
        serde_json::from_str(response_body(&response)).expect("scoped budgets are JSON");
    body["budgets"]
        .as_array()
        .expect("a budgets array")
        .iter()
        .map(|b| {
            (
                b["name"].as_str().expect("name").to_owned(),
                b["spend_micro_usd"].as_u64().expect("spend"),
            )
        })
        .collect()
}

/// The `llmproxy_spend_budget_utilization` sample whose labels contain
/// `labels`, once the flusher has published it.
fn wait_for_metric(proxy: &Proxy, labels: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let response = proxy.admin("GET", "/stats/prometheus", "", 200);
        if let Some(line) = response_body(&response).lines().find(|line| {
            line.contains("llmproxy_spend_budget_utilization{") && line.contains(labels)
        }) {
            if !line.ends_with(" 0") {
                return line.to_owned();
            }
        }
        assert!(
            Instant::now() < deadline,
            "no llmproxy_spend_budget_utilization sample with {labels}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn assert_scoped_refusal(response: &str, name: &str) {
    assert_eq!(status(response), 429, "{response}");
    assert!(
        response.contains("spend budget exceeded"),
        "the refusal names the spend budget: {response}"
    );
    assert!(
        response.contains("x-llmproxy-budget-scope: scoped\r\n")
            && response.contains(&format!("x-llmproxy-budget-name: {name}\r\n")),
        "the refusal names the scoped budget {name}: {response}"
    );
    assert!(
        !response.contains("x-ratelimit-"),
        "a spend refusal sends no x-ratelimit-* headers: {response}"
    );
}

fn config_text(primary: SocketAddr, fallback: SocketAddr, dir: &Path) -> String {
    format!(
        r#"version: 1
listen: 127.0.0.1:{listen}
admin: 127.0.0.1:{admin}
providers:
  primary:
    type: openai-compatible
    base_url: http://{primary}
  fallback:
    type: openai-compatible
    base_url: http://{fallback}
routes:
  - model: "solo-*"
    provider: primary
  - model: "*"
    provider: primary
    fallbacks: [fallback]
auth:
  hmac_secret: scoped-budget-e2e-secret
  store:
    persistent: {{ path: "{db}" }}
pricing:
  price_list:
    version: scoped-budget-e2e
    effective_from: "2026-01-01T00:00:00Z"
    entries:
{entries}
"#,
        listen = free_port(),
        admin = free_port(),
        db = dir.join("control.redb").display(),
        entries = ["gpt-4o", "gpt-4o-mini", "gpt-5"]
            .iter()
            .map(|model| format!(
                "      - provider_type: openai-compatible
        model: {model}
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 1000
            cached_input_nanodollars_per_token: 1000
            cache_write_nanodollars_per_token: 1000
            output_nanodollars_per_token: 2000"
            ))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-scoped-budget-e2e-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// An OpenAI-shaped upstream that answers with fixed usage, or 503 while
/// `fail` is set, and counts the requests it received.
struct Upstream {
    addr: SocketAddr,
    fail: Arc<AtomicBool>,
    hits: Arc<AtomicUsize>,
}

impl Upstream {
    fn spawn() -> Upstream {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
        let addr = listener.local_addr().expect("mock address");
        let fail = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(AtomicUsize::new(0));
        let (fail_in, hits_in) = (Arc::clone(&fail), Arc::clone(&hits));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (fail, hits) = (Arc::clone(&fail_in), Arc::clone(&hits_in));
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                    let Some(model) = read_request_model(&mut stream) else {
                        return;
                    };
                    hits.fetch_add(1, Ordering::SeqCst);
                    let response = if fail.load(Ordering::SeqCst) {
                        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\
                         Connection: close\r\n\r\n"
                            .to_owned()
                    } else {
                        let body = format!(
                            r#"{{"id":"x","object":"chat.completion","model":"{model}","choices":[{{"index":0,"message":{{"role":"assistant","content":"ok"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":6,"completion_tokens":4,"total_tokens":10}}}}"#
                        );
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    };
                    let _ = stream.write_all(response.as_bytes());
                });
            }
        });
        Upstream { addr, fail, hits }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// Reads one request and returns the `model` its JSON body names.
fn read_request_model(stream: &mut TcpStream) -> Option<String> {
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
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    while raw.len() < head_end + 4 + length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    }
    let body: serde_json::Value = serde_json::from_slice(&raw[head_end + 4..]).ok()?;
    Some(body["model"].as_str().unwrap_or("unknown").to_owned())
}

/// A running proxy. Killed and reaped on drop, so a failed assertion cannot
/// leave a listener behind (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    listen: SocketAddr,
    admin: SocketAddr,
}

impl Proxy {
    fn start(dir: &Path, config: &str) -> Proxy {
        let listen = port_after(config, "listen: 127.0.0.1:");
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
            admin: SocketAddr::from(([127, 0, 0, 1], admin)),
        };
        for addr in [proxy.admin, proxy.listen] {
            assert!(
                wait_for_connectable(addr, STARTUP_TIMEOUT),
                "listener at {addr} did not become connectable in time"
            );
        }
        proxy
    }

    fn admin(&self, method: &str, path: &str, body: &str, status: u16) -> String {
        let response = http_request(
            method,
            self.admin,
            path,
            &format!("Bearer {ADMIN_TOKEN}"),
            body,
        );
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{method} {path}:\n{response}"
        );
        response
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn port_after(config: &str, prefix: &str) -> u16 {
    config
        .split(prefix)
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|p| p.parse().ok())
        .expect("config names the listener")
}

fn chat(proxy: &Proxy, authorization: &str, model: &str) -> String {
    http_request(
        "POST",
        proxy.listen,
        "/v1/chat/completions",
        authorization,
        &format!(
            r#"{{"model":"{model}","max_tokens":8,"messages":[{{"role":"user","content":"hi"}}]}}"#
        ),
    )
}

fn status(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line: {response}"))
}

fn response_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
}

fn http_request(
    method: &str,
    addr: SocketAddr,
    path: &str,
    authorization: &str,
    body: &str,
) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: proxy.local\r\nAuthorization: {authorization}\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .expect("write request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).into_owned()
}

fn wait_for_connectable(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}
