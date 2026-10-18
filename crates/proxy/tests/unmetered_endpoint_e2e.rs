//! Endpoints a spend budget or token limit cannot count are refused where
//! one binds the request, and proxied silently where none does (ADR-0010
//! decision 1, phase 1).
//!
//! This drives the real `llm-proxy` binary through `--config` with no model
//! policy, so no `model_authz` 403 can stand in for the refusal: a request
//! that names a model reaches the `*` route unless the spend or token filter
//! refuses it. Each refusal is checked three ways: 403 with
//! `endpoint_not_metered` in the access log, the
//! `llmproxy_unmetered_endpoint_refused_total` series, and a mock provider
//! that never saw the request.
//!
//! Rust note: same harness shape as `tests/tenant_enforcement_e2e.rs` (std
//! threads, ephemeral ports, a `Drop` that kills the proxy). Every wait is
//! bounded, so a hung child fails the test instead of stalling it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const LOG_TIMEOUT: Duration = Duration::from_secs(10);

const HMAC_SECRET: &str = "unmetered-endpoint-e2e-secret";
const ADMIN_TOKEN: &str = "unmetered-endpoint-e2e-admin-token";
const TENANT: &str = "t1";
const KEY_ID: &str = "minted-1";
const DETAILS: &str = "endpoint_not_metered";
const SERIES: &str = "envoy_llmproxy_unmetered_endpoint_refused_total{";

/// One client request: method, path, body, and the classifier's label for it.
struct Call {
    method: &'static str,
    path: &'static str,
    body: &'static str,
    endpoint: &'static str,
}

const IMAGES: &[Call] = &[
    Call {
        method: "POST",
        path: "/v1/images/generations",
        body: r#"{"model":"gpt-image-1","prompt":"a cat"}"#,
        endpoint: "image_generation",
    },
    Call {
        method: "POST",
        path: "/v1/images/edits",
        body: r#"{"model":"gpt-image-1","prompt":"a hat"}"#,
        endpoint: "image_edit",
    },
];

const AUDIO: &[Call] = &[
    Call {
        method: "POST",
        path: "/v1/audio/speech",
        body: r#"{"model":"tts-1","input":"hello","voice":"alloy"}"#,
        endpoint: "speech",
    },
    Call {
        method: "POST",
        path: "/v1/audio/transcriptions",
        body: r#"{"model":"whisper-1"}"#,
        endpoint: "transcription",
    },
    Call {
        method: "POST",
        path: "/v1/audio/translations",
        body: r#"{"model":"whisper-1"}"#,
        endpoint: "translation",
    },
];

/// The probe that found the bypass added `"model"` to a batch body so the
/// `*` route took it; that injection must not help.
const BATCH_AND_FILES: &[Call] = &[
    Call {
        method: "POST",
        path: "/v1/batches",
        body: r#"{"model":"gpt-4o-mini","input_file_id":"file_1","endpoint":"/v1/chat/completions","completion_window":"24h"}"#,
        endpoint: "unmetered",
    },
    Call {
        method: "POST",
        path: "/v1/files",
        body: r#"{"model":"gpt-4o-mini","purpose":"batch"}"#,
        endpoint: "unmetered",
    },
    Call {
        method: "GET",
        path: "/v1/batches/batch_1",
        body: "",
        endpoint: "unmetered",
    },
];

#[test]
fn images_are_refused_under_every_binding_control() {
    refused_under_every_binding_control("images", IMAGES);
}

#[test]
fn audio_is_refused_under_every_binding_control() {
    refused_under_every_binding_control("audio", AUDIO);
}

#[test]
fn batches_and_files_are_refused_under_every_binding_control() {
    refused_under_every_binding_control("batch", BATCH_AND_FILES);
}

/// The negative case: with no budget and no limit, every one of these
/// endpoints is proxied, nothing is counted, and nothing is logged.
#[test]
fn without_a_budget_or_limit_every_endpoint_is_proxied_silently() {
    let dir = scratch_dir("no-budget");
    let upstream = Upstream::spawn();
    let proxy = Proxy::start(&dir, &config_text(&dir, upstream.addr, CATCH_ALL, ""));
    let key = mint_key(&proxy);
    create_tenant(&proxy);
    let log_mark = proxy.stderr_len();

    let calls: Vec<&Call> = IMAGES.iter().chain(AUDIO).chain(BATCH_AND_FILES).collect();
    for call in &calls {
        let response = send(&proxy, &key, call);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "{} {} without a budget:\n{response}",
            call.method,
            call.path
        );
    }
    assert_eq!(
        upstream.hits(),
        calls.len(),
        "every request reached the provider"
    );
    assert_eq!(proxy.access_log_refusals(calls.len()), 0);
    assert!(
        !scrape(&proxy).contains(SERIES),
        "nothing was refused, so no refusal series exists"
    );
    proxy.assert_no_warning_since(log_mark);
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Free endpoints pass under both controls without a missing-usage warning,
/// although their responses carry no usage. A metered endpoint naming an
/// unknown model still gets the synthetic 404. An unmetered POST that names
/// no model, on a config with no `*` route, would also have reached that 404
/// at headers time; it is refused instead, because the route chosen then is
/// provisional.
#[test]
fn free_endpoints_pass_under_a_budget_and_a_limit_without_warning() {
    let dir = scratch_dir("free");
    let upstream = Upstream::spawn();
    let proxy = Proxy::start(
        &dir,
        &config_text(
            &dir,
            upstream.addr,
            "  - { model: gpt-4o-mini, provider: openai }\n",
            "",
        ),
    );
    let key = mint_key(&proxy);
    create_tenant(&proxy);
    put_ok(
        &proxy,
        &format!("/tenants/{TENANT}/budget"),
        r#"{"budget":{"max_usd":"100","period":"daily"}}"#,
    );
    put_ok(
        &proxy,
        &format!("/tenants/{TENANT}/limits"),
        r#"{"limits":{"tokens_per_minute":1000000}}"#,
    );
    let log_mark = proxy.stderr_len();

    for call in [
        Call {
            method: "GET",
            path: "/v1/models",
            body: "",
            endpoint: "free",
        },
        Call {
            method: "GET",
            path: "/v1/usage",
            body: "",
            endpoint: "free",
        },
        Call {
            method: "POST",
            path: "/v1/messages/count_tokens",
            body: r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#,
            endpoint: "free",
        },
    ] {
        let response = send(&proxy, &key, &call);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "{} {} is free:\n{response}",
            call.method,
            call.path
        );
    }
    let free_hits = upstream.hits();
    assert!(free_hits >= 1, "count_tokens reached the provider");

    let unknown = send(
        &proxy,
        &key,
        &Call {
            method: "POST",
            path: "/v1/chat/completions",
            body: r#"{"model":"no-such-model","messages":[{"role":"user","content":"hi"}]}"#,
            endpoint: "chat_completions",
        },
    );
    assert!(
        unknown.starts_with("HTTP/1.1 404") && !unknown.contains("cannot be metered"),
        "an unknown model on a metered endpoint keeps the synthetic 404:\n{unknown}"
    );

    let batch = send(
        &proxy,
        &key,
        &Call {
            method: "POST",
            path: "/v1/batches",
            body: r#"{"input_file_id":"file_1","completion_window":"24h"}"#,
            endpoint: "unmetered",
        },
    );
    assert_refused(&batch, "a model-less batch with no `*` route");
    assert_eq!(upstream.hits(), free_hits, "neither request was dialled");
    assert_eq!(proxy.access_log_refusals(5), 1);

    proxy.assert_no_warning_since(log_mark);
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A model-scoped token limit binds only once the body has named the model,
/// so it refuses at the end of the body. An image for a model outside the
/// scope is bound by nothing and passes.
#[test]
fn a_model_scoped_token_limit_refuses_an_image_for_a_model_in_scope() {
    let dir = scratch_dir("scoped");
    let upstream = Upstream::spawn();
    let limits =
        "limits:\n  - { key: tenant, tokens_per_minute: 1000000, models: [\"gpt-image-*\"] }\n";
    let proxy = Proxy::start(&dir, &config_text(&dir, upstream.addr, CATCH_ALL, limits));
    let key = mint_key(&proxy);
    create_tenant(&proxy);

    assert_refused(
        &send(&proxy, &key, &IMAGES[0]),
        "an image in the rule's scope",
    );
    assert_eq!(upstream.hits(), 0);
    assert_eq!(
        refusals(&scrape(&proxy), "image_generation", "token_limit"),
        1
    );

    let outside = send(
        &proxy,
        &key,
        &Call {
            method: "POST",
            path: "/v1/images/generations",
            body: r#"{"model":"other-image-model","prompt":"a cat"}"#,
            endpoint: "image_generation",
        },
    );
    assert!(
        outside.starts_with("HTTP/1.1 200"),
        "an image outside the rule's scope:\n{outside}"
    );
    assert_eq!(upstream.hits(), 1);
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Send each call under a tenant budget, then a key budget, then a tenant
/// token limit, each alone. Every call is refused before it is dialled, and
/// once the last control is cleared the same calls pass.
fn refused_under_every_binding_control(tag: &str, calls: &[Call]) {
    let dir = scratch_dir(tag);
    let upstream = Upstream::spawn();
    let proxy = Proxy::start(&dir, &config_text(&dir, upstream.addr, CATCH_ALL, ""));
    let key = mint_key(&proxy);
    create_tenant(&proxy);

    let tenant_budget = format!("/tenants/{TENANT}/budget");
    let key_budget = format!("/keys/{KEY_ID}/budget");
    let tenant_limits = format!("/tenants/{TENANT}/limits");
    let budget = r#"{"budget":{"max_usd":"100","period":"daily"}}"#;
    let steps: [(&str, &str, &str, &str); 3] = [
        (
            "a tenant budget",
            &tenant_budget,
            budget,
            r#"{"budget":null}"#,
        ),
        ("a key budget", &key_budget, budget, r#"{"budget":null}"#),
        (
            "a tenant token limit",
            &tenant_limits,
            r#"{"limits":{"tokens_per_minute":1000000}}"#,
            r#"{"limits":null}"#,
        ),
    ];
    for (what, path, set, clear) in steps {
        put_ok(&proxy, path, set);
        for call in calls {
            let response = send(&proxy, &key, call);
            assert_refused(
                &response,
                &format!("{} {} under {what}", call.method, call.path),
            );
        }
        put_ok(&proxy, path, clear);
    }
    assert_eq!(
        upstream.hits(),
        0,
        "no refused request reached the provider"
    );
    assert_eq!(proxy.access_log_refusals(3 * calls.len()), 3 * calls.len());

    let scrape = scrape(&proxy);
    for endpoint in calls.iter().map(|c| c.endpoint) {
        let per_class = calls.iter().filter(|c| c.endpoint == endpoint).count() as u64;
        assert_eq!(
            refusals(&scrape, endpoint, "spend"),
            2 * per_class,
            "{endpoint}"
        );
        assert_eq!(
            refusals(&scrape, endpoint, "token_limit"),
            per_class,
            "{endpoint}"
        );
    }

    // With every control cleared the same requests are proxied, so each
    // refusal above came from the control, not from the request.
    for call in calls {
        let response = send(&proxy, &key, call);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "{} {} once every control is cleared:\n{response}",
            call.method,
            call.path
        );
    }
    assert_eq!(upstream.hits(), calls.len());
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

const CATCH_ALL: &str = "  - { model: \"*\", provider: openai }\n";

/// The dialect file. No model policy, so `model_authz` is not in the chain.
fn config_text(dir: &Path, upstream: SocketAddr, routes: &str, extra: &str) -> String {
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
{routes}auth:
  hmac_secret: "{HMAC_SECRET}"
  enforce: {{ model_policy: false }}
observability:
  access_logs: {{ output: "{log}", format: json }}
{extra}"#,
        listen = free_port(),
        admin = free_port(),
        log = dir.join("access.log").display(),
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-unmetered-endpoint-e2e-{tag}-{}",
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
    dir: PathBuf,
}

impl Proxy {
    fn start(dir: &Path, config: &str) -> Proxy {
        let listen = port_after(config, "listen: 127.0.0.1:");
        let admin = port_after(config, "admin: 127.0.0.1:");
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).expect("write temp config");
        let stderr = std::fs::File::create(dir.join("stderr.log")).expect("create stderr log");
        let child = Command::new(BIN)
            .args([
                "--config",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
            ])
            .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("failed to spawn llm-proxy");
        let proxy = Proxy {
            child,
            listen: SocketAddr::from(([127, 0, 0, 1], listen)),
            admin: SocketAddr::from(([127, 0, 0, 1], admin)),
            dir: dir.to_path_buf(),
        };
        assert!(
            wait_for_connectable(proxy.admin, STARTUP_TIMEOUT),
            "admin listener at {} did not become connectable in time",
            proxy.admin
        );
        assert!(
            wait_for_connectable(proxy.listen, STARTUP_TIMEOUT),
            "listener at {} did not become connectable in time",
            proxy.listen
        );
        proxy
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(self.dir.join("stderr.log")).unwrap_or_default()
    }

    /// Where the proxy's log stands now; load-time warnings (no model policy)
    /// come before it.
    fn stderr_len(&self) -> usize {
        self.stderr().len()
    }

    /// The proxy logs to stderr synchronously, before the response ends, so
    /// a warning a request caused is already written when this runs.
    fn assert_no_warning_since(&self, mark: usize) {
        let log = self.stderr();
        let since = &log[mark.min(log.len())..];
        assert!(
            !since.lines().any(|line| line.contains("WARN")),
            "no warning was expected, got:\n{since}"
        );
    }

    /// Access-log entries whose response code details are the refusal, once
    /// the log holds at least `lines` entries: the file sink batches writes,
    /// so the test waits for every request it sent to be logged.
    fn access_log_refusals(&self, lines: usize) -> usize {
        let path = self.dir.join("access.log");
        let deadline = std::time::Instant::now() + LOG_TIMEOUT;
        let entries: Vec<serde_json::Value> = loop {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let entries: Vec<serde_json::Value> = text
                .split_inclusive('\n')
                .filter(|line| line.ends_with('\n'))
                .map(|line| serde_json::from_str(line).expect("a JSON access-log line"))
                .collect();
            if entries.len() >= lines {
                break entries;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "only {} of {lines} access-log lines arrived:\n{text}",
                entries.len()
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        entries
            .iter()
            .filter(|entry| entry["response_code_details"] == DETAILS)
            .inspect(|entry| {
                assert!(
                    entry["response_code"].to_string().contains("403"),
                    "{entry}"
                )
            })
            .count()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn port_after(config: &str, prefix: &str) -> u16 {
    let rest = config
        .split(prefix)
        .nth(1)
        .expect("config names the listener");
    rest.split_whitespace()
        .next()
        .and_then(|p| p.parse().ok())
        .expect("listener port parses")
}

/// The 403 the controls send, distinguished from any other 403 by its body.
fn assert_refused(response: &str, what: &str) {
    assert!(
        response.starts_with("HTTP/1.1 403") && response.contains("cannot be metered"),
        "{what} must be refused as unmetered:\n{response}"
    );
}

fn scrape(proxy: &Proxy) -> String {
    let response = http_request(
        "GET",
        proxy.admin,
        "/stats/prometheus",
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        "text/plain",
        "",
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    response
}

/// The refusal counter's value for one `endpoint` and `control`, 0 when the
/// series does not exist.
fn refusals(scrape: &str, endpoint: &str, control: &str) -> u64 {
    scrape
        .lines()
        .filter(|line| line.starts_with(SERIES))
        .filter(|line| {
            line.contains(&format!("endpoint=\"{endpoint}\""))
                && line.contains(&format!("control=\"{control}\""))
        })
        .filter_map(|line| line.split_whitespace().last()?.parse::<u64>().ok())
        .sum()
}

/// `POST /keys` on the admin listener. Returns the plaintext key.
fn mint_key(proxy: &Proxy) -> String {
    let response = http_request(
        "POST",
        proxy.admin,
        "/keys",
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        "application/json",
        &format!(r#"{{"tenant":"{TENANT}","key_id":"{KEY_ID}"}}"#),
    );
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "POST /keys:\n{response}"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(response_body(&response)).expect("POST /keys returns JSON");
    parsed["key"].as_str().expect("plaintext key").to_string()
}

fn create_tenant(proxy: &Proxy) {
    let created = http_request(
        "POST",
        proxy.admin,
        "/tenants",
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        "application/json",
        &format!(r#"{{"tenant":"{TENANT}"}}"#),
    );
    assert!(
        created.starts_with("HTTP/1.1 2"),
        "POST /tenants:\n{created}"
    );
}

fn put_ok(proxy: &Proxy, path: &str, body: &str) {
    let put = http_request(
        "PUT",
        proxy.admin,
        path,
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        "application/json",
        body,
    );
    assert!(put.starts_with("HTTP/1.1 204"), "PUT {path}:\n{put}");
}

fn send(proxy: &Proxy, key: &str, call: &Call) -> String {
    http_request(
        call.method,
        proxy.listen,
        call.path,
        Some(&format!("Bearer {key}")),
        "application/json",
        call.body,
    )
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
    authorization: Option<&str>,
    content_type: &str,
    body: &str,
) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    let auth = authorization
        .map(|a| format!("Authorization: {a}\r\n"))
        .unwrap_or_default();
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: proxy.local\r\n{auth}\
                 Content-Type: {content_type}\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .expect("write request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

fn wait_for_connectable(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
}

/// A mock provider that answers every request `200 {}` (no usage) and counts
/// the requests it read, which is what proves a refusal was never dialled.
struct Upstream {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl Upstream {
    fn spawn() -> Upstream {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
        let addr = listener.local_addr().expect("no local addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&hits);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let counted = Arc::clone(&counted);
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
                    counted.fetch_add(1, Ordering::SeqCst);
                    let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
                    let content_length: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    let mut have = raw.len() - (head_end + 4);
                    while have < content_length {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => have += n,
                        }
                    }
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                          Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                    );
                });
            }
        });
        Upstream { addr, hits }
    }

    /// Requests counted so far. The proxy reads the upstream response only
    /// after the mock read the request head, so a request whose response the
    /// client already holds is counted.
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}
