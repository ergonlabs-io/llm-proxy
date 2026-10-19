//! Trace export end to end (ADR-0008): the real `llm-proxy` binary with the
//! dialect's `observability.traces`, tenants opted in and out over the admin
//! API, and the sealed segments read back as a consumer would.
//!
//! Same harness shape as `tests/tenant_enforcement_e2e.rs`: std threads,
//! ephemeral ports, a child killed on drop, every wait bounded. The proxy is
//! stopped with SIGTERM so the exporter seals its segments.

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const ADMIN_TOKEN: &str = "trace-export-e2e-admin-token";
const OPTED_IN: &str = "opted-in-tenant";
const OTHER: &str = "other-tenant";

/// Only the opted-in tenant's request is captured, it carries the body the
/// client sent and the response it got, the other tenant produces no trace
/// and no log line, and an opt-out through the admin API stops capture for
/// the next request without any routing change.
#[test]
fn only_an_opted_in_tenant_is_traced_and_an_opt_out_stops_it() {
    let dir = scratch_dir("opt-in");
    let traces = dir.join("traces");
    let proxy = Proxy::start(&dir, &config_text(&traces));

    for tenant in [OPTED_IN, OTHER] {
        admin(
            &proxy,
            "POST",
            "/tenants",
            &format!(r#"{{"tenant":"{tenant}"}}"#),
            "201",
        );
        admin(
            &proxy,
            "PUT",
            &format!("/tenants/{tenant}/policy"),
            r#"{"access":"all"}"#,
            "204",
        );
    }
    let opted_key = mint_key(&proxy, OPTED_IN);
    let other_key = mint_key(&proxy, OTHER);
    admin(
        &proxy,
        "PUT",
        &format!("/tenants/{OPTED_IN}/trace_export"),
        r#"{"schema_version":1,"enabled":true}"#,
        "204",
    );

    let first = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"first"}]}"#;
    assert!(chat(&proxy, &opted_key, first).starts_with("HTTP/1.1 200"));
    let other = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"other"}]}"#;
    assert!(chat(&proxy, &other_key, other).starts_with("HTTP/1.1 200"));

    admin(
        &proxy,
        "PUT",
        &format!("/tenants/{OPTED_IN}/trace_export"),
        r#"{"schema_version":1,"enabled":false}"#,
        "204",
    );
    let after = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"after"}]}"#;
    assert!(chat(&proxy, &opted_key, after).starts_with("HTTP/1.1 200"));

    let log = proxy.stop();
    let lines = read_segments(&traces);
    assert_eq!(lines.len(), 1, "exactly the first request: {lines:#?}");
    let line = &lines[0];
    assert_eq!(line["record"]["tenant_id"], OPTED_IN);
    assert_eq!(line["instance_id"], "node-a");
    assert_eq!(line["event_id"], line["record"]["event_id"]);
    assert_eq!(line["capture"]["state"], "complete");
    assert_eq!(
        line["request"]["body"],
        serde_json::from_str::<serde_json::Value>(first).unwrap(),
        "the body the client sent"
    );
    assert_eq!(line["response"]["status"], 200);
    assert_eq!(
        line["response"]["body"],
        serde_json::json!({"id": "resp-1"})
    );
    assert!(
        !log.lines()
            .any(|l| l.contains(OTHER) && l.to_ascii_lowercase().contains("trace")),
        "a tenant that did not opt in produces no trace log line:\n{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The emergency switch closes capture for an opted-in tenant at once.
#[test]
fn the_emergency_switch_stops_capture() {
    let dir = scratch_dir("gate");
    let traces = dir.join("traces");
    let proxy = Proxy::start(&dir, &config_text(&traces));
    admin(
        &proxy,
        "POST",
        "/tenants",
        &format!(r#"{{"tenant":"{OPTED_IN}"}}"#),
        "201",
    );
    admin(
        &proxy,
        "PUT",
        &format!("/tenants/{OPTED_IN}/policy"),
        r#"{"access":"all"}"#,
        "204",
    );
    let key = mint_key(&proxy, OPTED_IN);
    admin(
        &proxy,
        "PUT",
        &format!("/tenants/{OPTED_IN}/trace_export"),
        r#"{"schema_version":1,"enabled":true}"#,
        "204",
    );
    admin(
        &proxy,
        "POST",
        "/traces/capture",
        r#"{"disabled":true,"expected_generation":0}"#,
        "200",
    );
    let body = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"x"}]}"#;
    assert!(chat(&proxy, &key, body).starts_with("HTTP/1.1 200"));
    proxy.stop();
    assert!(read_segments(&traces).is_empty());
    assert!(
        traces.join(".capture-disabled").exists(),
        "the disable is persisted"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

fn config_text(traces: &Path) -> String {
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
  hmac_secret: "trace-export-e2e-secret"
observability:
  traces:
    directory: "{traces}"
    max_disk_bytes: 1073741824
    max_open_segments: 4
"#,
        listen = free_port(),
        admin = free_port(),
        upstream = spawn_upstream(),
        traces = traces.display(),
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-trace-export-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

struct Proxy {
    child: Option<Child>,
    listen: SocketAddr,
    admin: SocketAddr,
    log: PathBuf,
}

impl Proxy {
    fn start(dir: &Path, config: &str) -> Proxy {
        let listen = port_after(config, "listen: 127.0.0.1:");
        let admin = port_after(config, "admin: 127.0.0.1:");
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).expect("write temp config");
        let log = dir.join("proxy.log");
        let out = std::fs::File::create(&log).expect("create log");
        let child = Command::new(BIN)
            .args([
                "--config",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
                "--service-node",
                "node-a",
                "--drain-time-s",
                "1",
            ])
            .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(out.try_clone().expect("clone log"))
            .stderr(out)
            .spawn()
            .expect("failed to spawn llm-proxy");
        let proxy = Proxy {
            child: Some(child),
            listen: SocketAddr::from(([127, 0, 0, 1], listen)),
            admin: SocketAddr::from(([127, 0, 0, 1], admin)),
            log,
        };
        assert!(
            wait_for_connectable(proxy.admin, STARTUP_TIMEOUT)
                && wait_for_connectable(proxy.listen, STARTUP_TIMEOUT),
            "proxy did not start:\n{}",
            std::fs::read_to_string(&proxy.log).unwrap_or_default()
        );
        proxy
    }

    /// SIGTERM, then wait (bounded) for a clean exit, which seals segments.
    /// Returns everything the process logged.
    fn stop(mut self) -> String {
        let mut child = self.child.take().expect("running");
        let status = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success());
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                assert!(status.success(), "proxy exited with {status}");
                break;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("proxy did not exit after SIGTERM");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Every line of every sealed segment under `dir`.
fn read_segments(dir: &Path) -> Vec<serde_json::Value> {
    let mut lines = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries {
            let path = entry.expect("dir entry").path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                stack.push(path);
            } else if !name.starts_with('.') && name.ends_with(".jsonl.gz") {
                let mut text = String::new();
                flate2::read::MultiGzDecoder::new(std::fs::File::open(&path).unwrap())
                    .read_to_string(&mut text)
                    .unwrap();
                lines.extend(text.lines().map(|l| serde_json::from_str(l).unwrap()));
            }
        }
    }
    lines
}

fn admin(proxy: &Proxy, method: &str, path: &str, body: &str, status: &str) {
    let response = http(
        method,
        proxy.admin,
        path,
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        body,
    );
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status}")),
        "{method} {path}:\n{response}"
    );
}

fn mint_key(proxy: &Proxy, tenant: &str) -> String {
    let response = http(
        "POST",
        proxy.admin,
        "/keys",
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        &format!(r#"{{"tenant":"{tenant}","key_id":"key-{tenant}"}}"#),
    );
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "POST /keys:\n{response}"
    );
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or("");
    let parsed: serde_json::Value = serde_json::from_str(body).expect("JSON");
    parsed["key"].as_str().expect("plaintext key").to_string()
}

fn chat(proxy: &Proxy, key: &str, body: &str) -> String {
    http(
        "POST",
        proxy.listen,
        "/v1/chat/completions",
        Some(&format!("Bearer {key}")),
        body,
    )
}

fn http(method: &str, addr: SocketAddr, path: &str, auth: Option<&str>, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(IO_TIMEOUT)).expect("timeout");
    let auth = auth
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

fn port_after(config: &str, prefix: &str) -> u16 {
    config
        .split(prefix)
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|p| p.parse().ok())
        .expect("listener port")
}

fn wait_for_connectable(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// A provider that answers every request `200` with a small JSON body.
fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
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
                      Content-Length: 15\r\nConnection: close\r\n\r\n{\"id\":\"resp-1\"}",
                );
            });
        }
    });
    addr
}
