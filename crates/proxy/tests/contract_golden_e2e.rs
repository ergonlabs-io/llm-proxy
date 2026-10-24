//! Contract tests for the `--config` surfaces operators build dashboards and
//! scripts on: the metric and label names `/stats/prometheus` renders, the
//! admin route table, and the JSON access-log keys. Each is read from the real
//! `llm-proxy` binary after served traffic and compared with a golden file in
//! `tests/golden/` (see `common/golden.rs`). The CLI flag list is the fourth
//! surface; its test is in `src/main.rs`, since it reads clap's definition.
//!
//! To regenerate after an intended change: `make golden`, then review the
//! golden diff. Never regenerate to make a red test green without that review.
//!
//! The scenario switches on what a dialect deployment commonly runs: auth with
//! a minted key, a tenant with policy and budgets, a key budget, a token limit,
//! pricing, a fallback model (the primary answers 503), the billing ledger,
//! trace export for an opted-in tenant, a non-streamed and a streamed chat
//! completion, and one unauthenticated request. Families that appear only
//! under other conditions are named in each golden file's header as not
//! covered.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".
#![cfg(unix)]

mod common;
#[path = "common/golden.rs"]
mod golden;

use common::free_port;
use proxy_observability::ledger::testing::TempLedgerDir;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(20);

const ADMIN_TOKEN: &str = "contract-golden-admin-token";
const TENANT: &str = "t1";
const KEY_ID: &str = "contract-key";
const MODEL: &str = "chat";
const UPSTREAM_MODEL: &str = "gpt-4o";

const METRICS_HEADER: &str = "\
Metric families rendered by GET /stats/prometheus, one line per family and
distinct label-name set: `<name> <type> [<label>,...]`. Label values are not
part of the contract. Histograms list `_bucket`/`_sum`/`_count` under the
family name, without `le`.

Produced by contract_golden_e2e.rs from the --config dialect after served
traffic (auth, tenant and key budgets, token limit, pricing, fallback, ledger,
trace export, non-streamed and streamed chat, one 401).

NOT COVERED: a family renders only once something records into it, so the
families below exist in the code but this scenario never reaches them. They
are not yet stable surface:
  llmproxy_control_plane_load_{duration,payload_bytes,rows} (Redis auth store)
  llmproxy_realtime_usage_missing_total (realtime/WebSocket sessions)
  llmproxy_guardrail_checks_total (guardrails)
  llmproxy_chargeback_tags_dropped_total (chargeback tags)
  llmproxy_tenant_credential_requests_total,
  llmproxy_provider_credential_requests_total (tenant/minted credentials)
  llmproxy_router_max_output_tokens_rejected_total (max_output_tokens)
  llmproxy_router_session_affinity_total (session affinity)
  llmproxy_trace_segments_uploaded_total, llmproxy_trace_upload_failures_total
  (trace upload to S3)
  llmproxy_unmetered_endpoint_refused_total (unmetered endpoints)
  ext_authz (Envoy mode only)
A label that only another outcome would add is not covered, and neither is
Envoy mode (-c, xDS).
Regenerate with `make golden`; review every changed line.";

const ROUTES_HEADER: &str = "\
Admin routes: `<path> <METHOD>,...`, the methods the admin router answers
on that path (not 404 \"unknown admin endpoint\" and not 405). Paths come from
the router's own endpoint list in its 404 body; `{id}`-style segments are
probed with sample values. Paths matched on path alone answer every method.
Methods probed: GET, POST, PUT, DELETE.

Produced by contract_golden_e2e.rs against the --config dialect binary with
LLMPROXY_ADMIN_TOKEN unset, so every gated route refuses with 403 and no probe
changes state. Response bodies and status codes are not covered here.
NOT COVERED: `/ui/<asset>` paths and the `/` redirect (present only when the
admin UI bundle is loaded), query parameters, and request/response bodies.
Regenerate with `make golden`; review every changed line.";

const ACCESS_LOG_HEADER: &str = "\
Keys of each `observability.access_logs.format: json` line, one key per line.
Produced by contract_golden_e2e.rs from the same served traffic as the metrics
golden; every line carries the same keys. Values are not covered.
NOT COVERED: the `text` format string, and lines written for realtime
sessions.
Regenerate with `make golden`; review every changed line.";

#[test]
fn golden_prometheus_metric_names() {
    let scenario = Scenario::run("metrics");
    let families: BTreeSet<String> = render_families(&scenario.scrape).into_iter().collect();
    golden::check("prometheus_metrics.golden", METRICS_HEADER, &families);
    scenario.finish();
}

#[test]
fn golden_access_log_json_keys() {
    let scenario = Scenario::run("access-log");
    let lines = scenario.proxy.access_log_lines();
    let mut sets: BTreeMap<BTreeSet<String>, Vec<String>> = BTreeMap::new();
    for line in &lines {
        let keys = line
            .as_object()
            .unwrap_or_else(|| panic!("access-log line is not an object: {line}"))
            .keys()
            .cloned()
            .collect();
        sets.entry(keys).or_default().push(line["path"].to_string());
    }
    assert_eq!(
        sets.len(),
        1,
        "every JSON access-log line must carry the same keys; key sets by path: {sets:#?}"
    );
    let keys = sets.into_keys().next().expect("one key set");
    golden::check("access_log_json_keys.golden", ACCESS_LOG_HEADER, &keys);
    scenario.finish();
}

#[test]
fn golden_admin_routes() {
    let dir = scratch_dir("routes");
    let ledger = TempLedgerDir::new();
    let upstream = Mock::start(Reply::Chat);
    let proxy = Proxy::spawn(
        &dir,
        &config_text(&dir, &ledger, upstream.addr, upstream.addr),
        None,
    );

    let probe = request("GET", proxy.admin, "/contract-golden-unknown", None, "");
    let body = response_body(&probe);
    let list = body
        .split_once("available endpoints: ")
        .map(|(_, list)| list)
        .unwrap_or_else(|| panic!("404 body lists no endpoints:\n{probe}"));
    // Entries may carry a query or a description: keep the path only. A
    // description's own commas leave fragments that do not start with `/`.
    let paths: BTreeSet<&str> = list
        .split(", ")
        .filter(|entry| entry.starts_with('/'))
        .map(|entry| entry.split(['?', ' ']).next().unwrap_or(entry))
        .collect();

    let mut routes = BTreeSet::new();
    for path in paths {
        let concrete = path
            .replace("{stat_prefix}", "contract-chain")
            .replace("{id}", "contract-id")
            .replace("{object_id}", "file-contract")
            .replace("{provider}", "backup");
        let accepted: Vec<&str> = ["GET", "POST", "PUT", "DELETE"]
            .into_iter()
            .filter(|method| {
                let response = request(method, proxy.admin, &concrete, None, "");
                let routed = !response.starts_with("HTTP/1.1 405")
                    && !response_body(&response).starts_with("unknown admin endpoint");
                assert!(
                    !response.starts_with("HTTP/1.1 2") || !gated(path),
                    "{method} {concrete} succeeded without the admin token:\n{response}"
                );
                routed
            })
            .collect();
        let methods = if accepted.is_empty() {
            "-".to_string()
        } else {
            accepted.join(",")
        };
        routes.insert(format!("{path} {methods}"));
    }
    golden::check("admin_routes.golden", ROUTES_HEADER, &routes);
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Paths whose handlers sit behind the admin token. A 2xx on one without the
/// token would mean the probe changed state, which this test must not do.
fn gated(path: &str) -> bool {
    !matches!(
        path,
        "/ready"
            | "/config_dump"
            | "/clusters"
            | "/models"
            | "/server_info"
            | "/stats"
            | "/stats/prometheus"
            | "/pricing"
            | "/chains/{stat_prefix}/pricing"
    )
}

// ------------------------------------------------------------------ scenario --

struct Scenario {
    dir: PathBuf,
    proxy: Proxy,
    scrape: String,
    _ledger: TempLedgerDir,
    _mocks: (Mock, Mock),
}

impl Scenario {
    fn run(tag: &str) -> Scenario {
        let dir = scratch_dir(tag);
        let ledger = TempLedgerDir::new();
        let primary = Mock::start(Reply::Unavailable);
        let backup = Mock::start(Reply::Chat);
        let config = config_text(&dir, &ledger, primary.addr, backup.addr);
        let proxy = Proxy::spawn(&dir, &config, Some(ADMIN_TOKEN));

        admin_ok(
            &proxy,
            "POST",
            "/tenants",
            &format!(r#"{{"tenant":"{TENANT}"}}"#),
        );
        admin_ok(
            &proxy,
            "PUT",
            &format!("/tenants/{TENANT}/policy"),
            r#"{"access":"all"}"#,
        );
        let key = mint_key(&proxy);
        let budget = r#"{"budget":{"max_usd":"10.00","period":"daily"}}"#;
        admin_ok(&proxy, "PUT", &format!("/tenants/{TENANT}/budget"), budget);
        admin_ok(&proxy, "PUT", &format!("/keys/{KEY_ID}/budget"), budget);
        admin_ok(
            &proxy,
            "PUT",
            &format!("/tenants/{TENANT}/trace_export"),
            r#"{"schema_version":1,"enabled":true}"#,
        );

        let auth = format!("Bearer {key}");
        let plain =
            format!(r#"{{"model":"{MODEL}","messages":[{{"role":"user","content":"hello"}}]}}"#);
        let streamed = format!(
            r#"{{"model":"{MODEL}","stream":true,"messages":[{{"role":"user","content":"hello"}}]}}"#
        );
        for body in [&plain, &streamed] {
            let response = request(
                "POST",
                proxy.listen,
                "/v1/chat/completions",
                Some(&auth),
                body,
            );
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        }
        let anonymous = request("POST", proxy.listen, "/v1/chat/completions", None, &plain);
        assert!(anonymous.starts_with("HTTP/1.1 401"), "{anonymous}");

        proxy.wait_for_access_log_lines(3);
        let scrape = proxy.settled_scrape();
        Scenario {
            dir,
            proxy,
            scrape,
            _ledger: ledger,
            _mocks: (primary, backup),
        }
    }

    fn finish(self) {
        let Scenario { dir, proxy, .. } = self;
        drop(proxy);
        let _ = std::fs::remove_dir_all(dir);
    }
}

fn config_text(
    dir: &Path,
    ledger: &TempLedgerDir,
    primary: SocketAddr,
    backup: SocketAddr,
) -> String {
    let ledger = ledger.config(1024, proxy_observability::ledger::OnUnavailable::Reject);
    format!(
        r#"version: 1
listen: 127.0.0.1:{listen}
admin: 127.0.0.1:{admin}
providers:
  primary: {{ type: openai, base_url: "http://{primary}", api_key: sk-primary }}
  backup: {{ type: openai, base_url: "http://{backup}", api_key: sk-backup }}
routes:
  - {{ model: chat-direct, provider: backup }}
models:
  {MODEL}: {{ providers: [primary/{UPSTREAM_MODEL}, backup/{UPSTREAM_MODEL}] }}
auth:
  hmac_secret: "contract-golden-hmac-secret"
pricing:
  price_list:
    version: contract-golden
    effective_from: "2026-01-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: {UPSTREAM_MODEL}
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 1000
            cached_input_nanodollars_per_token: 1000
            cache_write_nanodollars_per_token: 1000
            output_nanodollars_per_token: 2000
limits:
  - {{ key: tenant, tokens_per_minute: 1000000 }}
ledger:
  directory: {ledger_dir}
  encryption_key_file: {ledger_key}
  encryption_key_id: {ledger_key_id}
  max_disk_bytes: {ledger_disk}
  group_commit_interval: 10ms
observability:
  access_logs: {{ output: {access_log}, format: json }}
  traces:
    directory: "{traces}"
    max_disk_bytes: 1073741824
    max_open_segments: 4
"#,
        listen = free_port(),
        admin = free_port(),
        ledger_dir = ledger.directory.display(),
        ledger_key = ledger.encryption_key.file.display(),
        ledger_key_id = ledger.encryption_key.id,
        ledger_disk = ledger.max_disk_bytes,
        access_log = dir.join("access.log").display(),
        traces = dir.join("traces").display(),
    )
}

/// One golden line per metric family and distinct label-name set, from a
/// Prometheus text scrape.
fn render_families(scrape: &str) -> Vec<String> {
    let mut kinds: BTreeMap<String, String> = BTreeMap::new();
    let mut lines = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in scrape.lines() {
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut parts = rest.split_whitespace();
            let (Some(name), Some(kind)) = (parts.next(), parts.next()) else {
                panic!("malformed TYPE line: {line}");
            };
            kinds.insert(name.to_string(), kind.to_string());
            current = Some((name.to_string(), kind.to_string()));
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (family, kind) = current
            .clone()
            .unwrap_or_else(|| panic!("sample before any TYPE line: {line}"));
        let series = line.split(['{', ' ']).next().unwrap_or_default();
        assert!(
            series.starts_with(&family),
            "sample {series} does not belong to family {family} declared before it"
        );
        let mut labels = label_names(line);
        if kind == "histogram" {
            labels.retain(|label| label != "le");
        }
        let line = if labels.is_empty() {
            format!("{family} {kind}")
        } else {
            format!("{family} {kind} {}", labels.join(","))
        };
        lines.push(line);
    }
    lines
}

/// The label names of one sample line, sorted. Values are skipped with their
/// escapes, so a `,` or `"` inside a value cannot split a label.
fn label_names(line: &str) -> Vec<String> {
    let Some(start) = line.find('{') else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut chars = line[start + 1..].chars();
    let mut name = String::new();
    while let Some(c) = chars.next() {
        match c {
            '=' => {
                assert_eq!(chars.next(), Some('"'), "unquoted label value in {line}");
                let mut escaped = false;
                for v in chars.by_ref() {
                    match (escaped, v) {
                        (false, '\\') => escaped = true,
                        (false, '"') => break,
                        _ => escaped = false,
                    }
                }
                names.push(std::mem::take(&mut name));
            }
            ',' => {}
            '}' => break,
            c => name.push(c),
        }
    }
    names.sort();
    names
}

// ------------------------------------------------------------------- helpers --

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-contract-golden-{tag}-{}",
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
    access_log: PathBuf,
}

impl Proxy {
    fn spawn(dir: &Path, config: &str, admin_token: Option<&str>) -> Proxy {
        let listen = port_after(config, "listen: 127.0.0.1:");
        let admin = port_after(config, "admin: 127.0.0.1:");
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).expect("write temp config");
        let stderr = std::fs::File::create(dir.join("stderr.log")).expect("create stderr log");
        let mut command = Command::new(BIN);
        command
            .args([
                "--config",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
                "--service-node",
                "contract-node",
            ])
            .env_remove("LLMPROXY_ADMIN_TOKEN")
            .env_remove("LLMPROXY_ADMIN_UI_DIR")
            .stdout(Stdio::null())
            .stderr(stderr);
        if let Some(token) = admin_token {
            command.env("LLMPROXY_ADMIN_TOKEN", token);
        }
        let child = command.spawn().expect("failed to spawn llm-proxy");
        let proxy = Proxy {
            child,
            listen: SocketAddr::from(([127, 0, 0, 1], listen)),
            admin: SocketAddr::from(([127, 0, 0, 1], admin)),
            access_log: dir.join("access.log"),
        };
        for addr in [proxy.admin, proxy.listen] {
            assert!(
                wait_for_connectable(addr, STARTUP_TIMEOUT),
                "{addr} did not become connectable in time; stderr:\n{}",
                std::fs::read_to_string(dir.join("stderr.log")).unwrap_or_default()
            );
        }
        proxy
    }

    fn access_log_lines(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.access_log)
            .unwrap_or_default()
            .lines()
            .map(|line| {
                serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("access-log line is not JSON ({e}): {line}"))
            })
            .collect()
    }

    fn wait_for_access_log_lines(&self, count: usize) {
        let deadline = Instant::now() + SETTLE_TIMEOUT;
        while self.access_log_lines().len() < count {
            assert!(
                Instant::now() < deadline,
                "expected {count} access-log lines; got {:#?}",
                self.access_log_lines()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// A scrape whose family lines match the scrape before it, so counters
    /// written after the response (ledger commits, connection teardown) have
    /// landed before the comparison.
    fn settled_scrape(&self) -> String {
        let deadline = Instant::now() + SETTLE_TIMEOUT;
        let mut previous = self.scrape();
        loop {
            std::thread::sleep(Duration::from_millis(300));
            let next = self.scrape();
            if render_families(&next) == render_families(&previous) {
                return next;
            }
            assert!(
                Instant::now() < deadline,
                "/stats/prometheus families did not settle"
            );
            previous = next;
        }
    }

    fn scrape(&self) -> String {
        let response = request("GET", self.admin, "/stats/prometheus", None, "");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        response_body(&response).to_string()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn port_after(config: &str, marker: &str) -> u16 {
    let rest = &config[config.find(marker).expect("marker in config") + marker.len()..];
    rest.split_whitespace()
        .next()
        .and_then(|port| port.parse().ok())
        .expect("port after marker")
}

fn admin_ok(proxy: &Proxy, method: &str, path: &str, body: &str) {
    let response = request(
        method,
        proxy.admin,
        path,
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        body,
    );
    assert!(
        response.starts_with("HTTP/1.1 2"),
        "{method} {path}:\n{response}"
    );
}

/// `POST /keys` for [`KEY_ID`] on [`TENANT`]; returns the plaintext key.
fn mint_key(proxy: &Proxy) -> String {
    let response = request(
        "POST",
        proxy.admin,
        "/keys",
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        &format!(r#"{{"tenant":"{TENANT}","key_id":"{KEY_ID}"}}"#),
    );
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "POST /keys:\n{response}"
    );
    let json: serde_json::Value = serde_json::from_str(response_body(&response)).unwrap();
    json["key"].as_str().expect("plaintext key").to_string()
}

fn response_body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

fn request(
    method: &str,
    addr: SocketAddr,
    path: &str,
    authorization: Option<&str>,
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
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
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

#[derive(Clone, Copy)]
enum Reply {
    /// `503`, which the dialect's fallback retries on the next member.
    Unavailable,
    /// An OpenAI chat completion with usage; server-sent events when the
    /// request asked for a stream.
    Chat,
}

/// A mock provider. The accept thread lives for the test process; the
/// listener is dropped with it.
struct Mock {
    addr: SocketAddr,
}

impl Mock {
    fn start(reply: Reply) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock provider");
        let addr = listener.local_addr().expect("local addr");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                std::thread::spawn(move || serve(stream, reply));
            }
        });
        Mock { addr }
    }
}

fn serve(mut stream: TcpStream, reply: Reply) {
    // On macOS an accepted socket inherits the listener's O_NONBLOCK; the
    // reads below rely on the timeout instead.
    let _ = stream.set_nonblocking(false);
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
    let content_length: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let mut body = raw[head_end + 4..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&buf[..n]),
        }
    }
    let streamed = serde_json::from_slice::<serde_json::Value>(&body)
        .is_ok_and(|v| v["stream"] == serde_json::Value::Bool(true));
    let usage = serde_json::json!({"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7});
    let response = match (reply, streamed) {
        (Reply::Unavailable, _) => {
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string()
        }
        (Reply::Chat, false) => {
            let json = serde_json::json!({
                "id": "chatcmpl-contract",
                "object": "chat.completion",
                "model": UPSTREAM_MODEL,
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": "hi"}}],
                "usage": usage,
            })
            .to_string();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{json}",
                json.len()
            )
        }
        (Reply::Chat, true) => {
            let chunk = serde_json::json!({
                "id": "chatcmpl-contract", "object": "chat.completion.chunk",
                "model": UPSTREAM_MODEL,
                "choices": [{"index": 0, "delta": {"content": "hi"}}],
            });
            let last = serde_json::json!({
                "id": "chatcmpl-contract", "object": "chat.completion.chunk",
                "model": UPSTREAM_MODEL, "choices": [], "usage": usage,
            });
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n\
                 data: {chunk}\n\ndata: {last}\n\ndata: [DONE]\n\n"
            )
        }
    };
    let _ = stream.write_all(response.as_bytes());
}
