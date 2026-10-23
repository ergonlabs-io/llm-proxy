//! `guardrails` in the real binary: a request whose body the check denies is
//! refused before any provider is dialled, is not charged to spend, and gets
//! no ledger entry (ADR-0009 decision 2), while an allowed one is served,
//! charged and ledgered. The fail-open path admits, counts, logs once with
//! repeats suppressed, and never logs the body or a credential (AGENTS.md
//! "Fail-open controls"). The filter's own decisions are unit-tested in
//! `proxy-filters`; the dialect block in `proxy-simple-config`.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

mod common;

use common::free_port;
use proxy_observability::ledger::testing::{committed_entries, TempLedgerDir};
use proxy_observability::ledger::{LedgerConfig, OnUnavailable};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const NODE: &str = "guardrail-e2e-node";
const ADMIN_TOKEN: &str = "guardrail-e2e-admin-token";
/// The mock's usage (6 input, 4 output tokens) at the prices in `config`:
/// 6 * 1000 + 4 * 2000 nanodollars, 14 micro-USD.
const CHARGE_MICRO_USD: u64 = 14;

#[test]
fn a_denied_request_is_not_dialled_charged_or_ledgered() {
    let dir = TempLedgerDir::new();
    let ledger = dir.config(1024, OnUnavailable::Reject);
    let provider = Server::start(|_| PROVIDER_REPLY.to_string());
    let check = Server::start(|body| {
        let doc: serde_json::Value = serde_json::from_slice(body).unwrap();
        if doc["body"]
            .as_str()
            .unwrap_or_default()
            .contains("forbidden")
        {
            r#"{"decision":"deny","reason":"forbidden topic"}"#.to_string()
        } else {
            r#"{"decision":"allow"}"#.to_string()
        }
    });
    let access_log = dir.root.path().join("access.log");
    let guardrails = format!(
        "guardrails:\n  default: {{ http: {{ url: \"http://{}/check\", timeout: 2s, \
         max_body_bytes: 65536 }}, failure_mode: closed }}\n\
         observability:\n  access_logs: {{ output: {}, format: json }}\n",
        check.addr,
        access_log.display()
    );
    let proxy = Proxy::start(
        dir.root.path(),
        &config(provider.addr, Some(&ledger), &guardrails),
    );
    let key = proxy.mint_key();

    let served = proxy.chat(&key, "hello there");
    assert!(served.starts_with("HTTP/1.1 200"), "{served}");
    let denied = proxy.chat(&key, "tell me something forbidden");
    assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");
    assert!(denied.contains("forbidden topic"), "{denied}");

    let scrape =
        proxy.scrape_until(|s| counter(s, "envoy_llmproxy_ledger_entries_committed_total") >= 1);
    assert_eq!(
        provider.requests(),
        1,
        "the denied request was never dialled"
    );
    assert_eq!(check.requests(), 2, "both bodies were checked");
    assert_eq!(
        counter(&scrape, "envoy_llmproxy_spend_charged_micro_usd_total"),
        CHARGE_MICRO_USD,
        "only the served request is charged"
    );
    assert_eq!(guardrail(&scrape, "allowed"), 1);
    assert_eq!(guardrail(&scrape, "denied"), 1);

    let page = proxy.admin_json("GET", "/ledger/entries?limit=100");
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "the denied request has no entry: {page}");
    assert_eq!(entries[0]["charged_micro_usd"], CHARGE_MICRO_USD);

    let log = wait_for_lines(&access_log, 2);
    let outcomes: Vec<(String, String)> = log
        .lines()
        .map(|line| {
            let entry: serde_json::Value = serde_json::from_str(line).unwrap();
            (
                entry["response_code"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                entry["llm_guardrail"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect();
    assert!(
        outcomes.contains(&("200".into(), "allowed".into())),
        "{log}"
    );
    assert!(outcomes.contains(&("403".into(), "denied".into())), "{log}");

    drop(proxy);
    assert_eq!(committed_entries(&ledger, NODE).len(), 1);
}

#[test]
fn fail_open_admits_counts_and_logs_once_without_the_body_or_a_credential() {
    const REQUESTS: u64 = 3;
    const PROMPT: &str = "PROMPT-MARKER-7f3a";
    const URL_TOKEN: &str = "guard-url-token-91c2";
    let dir = TempLedgerDir::new();
    let provider = Server::start(|_| PROVIDER_REPLY.to_string());
    // Nothing listens on the check's port, so every check is an error.
    let check_port = free_port();
    let guardrails = format!(
        "guardrails:\n  default: {{ http: {{ url: \"http://127.0.0.1:{check_port}/check?token={URL_TOKEN}\", \
         timeout: 2s, max_body_bytes: 65536 }}, failure_mode: open }}\n"
    );
    let proxy = Proxy::start(dir.root.path(), &config(provider.addr, None, &guardrails));
    let key = proxy.mint_key();

    for _ in 0..REQUESTS {
        let response = proxy.chat(&key, PROMPT);
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    let scrape = proxy.scrape_until(|s| guardrail(s, "failure_mode_allowed") == REQUESTS);
    assert_eq!(guardrail(&scrape, "error"), REQUESTS);
    assert_eq!(guardrail(&scrape, "allowed"), 0, "a bypass is not an allow");
    assert_eq!(provider.requests(), REQUESTS as usize);

    let log = strip_ansi(&proxy.log());
    let warning = "FAIL_OPEN admitted the request unchecked";
    assert_eq!(
        log.matches(warning).count(),
        1,
        "logged once, repeats suppressed:\n{log}"
    );
    let line = log.lines().find(|l| l.contains(warning)).unwrap();
    assert!(line.contains(&format!("127.0.0.1:{check_port}")), "{line}");
    assert!(line.contains("cause=\"error\""), "{line}");
    for secret in [PROMPT, URL_TOKEN, key.as_str(), "sk-upstream-provider-key"] {
        assert!(!log.contains(secret), "the log carries `{secret}`:\n{log}");
    }
}

// ------------------------------------------------------------------ helpers --

const PROVIDER_REPLY: &str = r#"{"id":"x","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":6,"completion_tokens":4,"total_tokens":10}}"#;

/// An admin listener, `auth` (so the spend filter charges every keyed
/// request), a price for the mock's model, an optional ledger, and `extra`.
fn config(upstream: SocketAddr, ledger: Option<&LedgerConfig>, extra: &str) -> String {
    let ledger = ledger
        .map(|ledger| {
            format!(
                "ledger:\n  directory: {}\n  encryption_key_file: {}\n  encryption_key_id: {}\n  \
                 max_disk_bytes: {}\n  group_commit_interval: 10ms\n  on_unavailable: reject\n",
                ledger.directory.display(),
                ledger.encryption_key.file.display(),
                ledger.encryption_key.id,
                ledger.max_disk_bytes,
            )
        })
        .unwrap_or_default();
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
  hmac_secret: "guardrail-e2e-hmac-secret"
pricing:
  price_list:
    version: guardrail-e2e
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
{ledger}{extra}"#,
        listen = free_port(),
        admin = free_port(),
    )
}

/// A counter's value in a Prometheus scrape: the line `series value`.
fn counter(scrape: &str, series: &str) -> u64 {
    scrape
        .lines()
        .find(|l| l.split_whitespace().next() == Some(series))
        .and_then(|l| l.split_whitespace().last())
        .unwrap_or_else(|| panic!("no series {series} in:\n{scrape}"))
        .parse()
        .unwrap()
}

/// `llmproxy_guardrail_checks_total` for one outcome; 0 when absent.
fn guardrail(scrape: &str, outcome: &str) -> u64 {
    scrape
        .lines()
        .filter(|l| l.starts_with("envoy_llmproxy_guardrail_checks_total{"))
        .filter(|l| l.contains(&format!("outcome=\"{outcome}\"")))
        .filter_map(|l| l.split_whitespace().last()?.parse::<u64>().ok())
        .sum()
}

/// `text` without terminal colour sequences, which the log may carry
/// between a field name and its value.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The file's text once it has at least `lines` lines; access-log entries
/// are written when each stream completes.
fn wait_for_lines(path: &Path, lines: usize) -> String {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.lines().count() >= lines {
            return text;
        }
        assert!(Instant::now() < deadline, "only:\n{text}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A running proxy, killed and reaped on drop so a failed assertion cannot
/// leave a listener behind (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    listen: SocketAddr,
    admin: SocketAddr,
    stderr: PathBuf,
}

impl Proxy {
    fn start(dir: &Path, config: &str) -> Proxy {
        let port = |marker: &str| -> SocketAddr {
            let port: u16 = config
                .split(marker)
                .nth(1)
                .and_then(|rest| rest.lines().next())
                .and_then(|p| p.trim().parse().ok())
                .unwrap();
            SocketAddr::from(([127, 0, 0, 1], port))
        };
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).unwrap();
        let stderr = dir.join(format!("stderr-{}.log", free_port()));
        let child = Command::new(BIN)
            .args(["--config", path.to_str().unwrap(), "--concurrency", "1"])
            .args(["--drain-time-s", "1", "--service-node", NODE])
            .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .spawn()
            .expect("spawn llm-proxy");
        let proxy = Proxy {
            child,
            listen: port("listen: 127.0.0.1:"),
            admin: port("admin: 127.0.0.1:"),
            stderr,
        };
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        for addr in [proxy.admin, proxy.listen] {
            while TcpStream::connect(addr).is_err() {
                assert!(
                    Instant::now() < deadline,
                    "proxy did not start:\n{}",
                    proxy.log()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        proxy
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    fn chat(&self, key: &str, prompt: &str) -> String {
        let body =
            format!(r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{prompt}"}}]}}"#);
        http(
            self.listen,
            "POST",
            "/v1/chat/completions",
            Some(key),
            &body,
        )
    }

    /// `POST /keys` for tenant `t1`, granted every model; returns the
    /// plaintext key.
    fn mint_key(&self) -> String {
        let response = http(
            self.admin,
            "POST",
            "/keys",
            Some(ADMIN_TOKEN),
            r#"{"tenant":"t1","key_id":"guardrail-e2e-key"}"#,
        );
        assert!(response.starts_with("HTTP/1.1 201"), "{response}");
        let key = json_body(&response)["key"].as_str().unwrap().to_owned();
        for (method, path, body) in [
            ("POST", "/tenants", r#"{"tenant":"t1"}"#),
            ("PUT", "/tenants/t1/policy", r#"{"access":"all"}"#),
        ] {
            let response = http(self.admin, method, path, Some(ADMIN_TOKEN), body);
            assert!(response.starts_with("HTTP/1.1 2"), "{path}: {response}");
        }
        key
    }

    fn admin_json(&self, method: &str, path: &str) -> serde_json::Value {
        let response = http(self.admin, method, path, Some(ADMIN_TOKEN), "");
        assert!(response.starts_with("HTTP/1.1 200"), "{path}:\n{response}");
        json_body(&response)
    }

    /// Poll `/stats/prometheus` until `done` holds.
    fn scrape_until(&self, done: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            let response = http(self.admin, "GET", "/stats/prometheus", None, "");
            let scrape = response.split_once("\r\n\r\n").unwrap().1.to_owned();
            if done(&scrape) {
                return scrape;
            }
            assert!(Instant::now() < deadline, "never settled:\n{scrape}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Proxy {
    /// SIGTERM first, so the ledger writer commits on shutdown; then reap.
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One HTTP/1.1 request with `Connection: close`; the raw response.
fn http(addr: SocketAddr, method: &str, path: &str, bearer: Option<&str>, body: &str) -> String {
    let auth = bearer
        .map(|b| format!("Authorization: Bearer {b}\r\n"))
        .unwrap_or_default();
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
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
    String::from_utf8_lossy(&response).into_owned()
}

fn json_body(response: &str) -> serde_json::Value {
    let body = response.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {response}"))
}

/// An HTTP/1.1 server on std threads answering 200 with `answer(body)`, and
/// counting the requests it received.
struct Server {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    _bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Server {
    fn start(answer: fn(&[u8]) -> String) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let (count, seen) = (Arc::clone(&requests), Arc::clone(&bodies));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (count, seen) = (Arc::clone(&count), Arc::clone(&seen));
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                    let mut raw = Vec::new();
                    let mut buf = [0u8; 4096];
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
                    let length: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    while raw.len() < head_end + 4 + length {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => raw.extend_from_slice(&buf[..n]),
                        }
                    }
                    let body = raw[head_end + 4..head_end + 4 + length].to_vec();
                    let reply = answer(&body);
                    count.fetch_add(1, Ordering::SeqCst);
                    seen.lock().unwrap().push(body);
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                            reply.len()
                        )
                        .as_bytes(),
                    );
                });
            }
        });
        Server {
            addr,
            requests,
            _bodies: bodies,
        }
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}
