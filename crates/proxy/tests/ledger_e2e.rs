//! The billing ledger (ADR-0009) in the real binary: a dialect `ledger`
//! block opens the writer at boot, served requests reach the encrypted spool,
//! shutdown commits what is queued, a restart opens a later epoch, and the
//! things that must stop the proxy do. Consumers pull and acknowledge entries
//! over the admin API, and the two reconciliation counters (ADR-0009 decision
//! 7) agree, or differ by exactly what `admit` served unledgered. Admission
//! and the writer themselves are tested in `proxy-core` and
//! `proxy-observability`; the admin endpoints' contract in `proxy-admin`.

mod common;

use common::free_port;
use proxy_observability::ledger::testing::{committed_entries, TempLedgerDir};
use proxy_observability::ledger::{LedgerConfig, OnUnavailable};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const NODE: &str = "ledger-e2e-node";
const ADMIN_TOKEN: &str = "ledger-e2e-admin-token";
/// The mock's usage (6 input, 4 output tokens) at the prices in
/// `billing_config`: 6 * 1000 + 4 * 2000 nanodollars, 14 micro-USD.
const CHARGE_MICRO_USD: u64 = 14;
/// The per-image price for `gpt-image-1` at 1024x1024 in `billing_config`.
/// An example value, not a provider's rate.
const IMAGE_NANODOLLARS: u64 = 40_000_000;

#[test]
fn served_requests_are_committed_and_a_restart_opens_a_later_epoch() {
    let dir = TempLedgerDir::new();
    let ledger = dir.config(1024, OnUnavailable::Reject);
    let upstream = mock_upstream();
    let config = config_text(&ledger, upstream, "");

    let mut proxy = Proxy::start(dir.root.path(), &config, Some(NODE));
    for _ in 0..2 {
        assert!(proxy.chat().starts_with("HTTP/1.1 200"));
    }
    proxy.terminate();
    let first = committed_entries(&ledger, NODE);
    assert_eq!(
        first.iter().map(|e| e.seq).collect::<Vec<_>>(),
        [0, 1],
        "shutdown commits every entry handed over"
    );
    assert!(first.iter().all(|e| e.instance_id == NODE));

    let mut proxy = Proxy::start(dir.root.path(), &config, Some(NODE));
    assert!(proxy.chat().starts_with("HTTP/1.1 200"));
    proxy.terminate();
    let all = committed_entries(&ledger, NODE);
    assert_eq!(all.len(), 3);
    assert_eq!(all[2].seq, 0);
    assert!(all[2].epoch > all[0].epoch, "{all:?}");
}

/// The instance id is the node id; without one the proxy refuses to start
/// rather than writing under a per-boot identity.
#[test]
fn a_ledger_without_a_node_id_stops_startup() {
    let dir = TempLedgerDir::new();
    let ledger = dir.config(1024, OnUnavailable::Reject);
    let config = config_text(&ledger, mock_upstream(), "");
    let stderr = Proxy::fails(dir.root.path(), &config, None);
    assert!(
        stderr.contains("node.metadata[\"io.llmproxy.ledger\"]")
            && stderr.contains("requires a configured node id"),
        "{stderr}"
    );
}

/// A key file the proxy cannot use stops startup with the field's path.
#[test]
fn a_missing_key_file_stops_startup_naming_the_field() {
    let dir = TempLedgerDir::new();
    let ledger = dir.config(1024, OnUnavailable::Reject);
    std::fs::remove_file(&ledger.encryption_key.file).unwrap();
    let config = config_text(&ledger, mock_upstream(), "");
    let stderr = Proxy::fails(dir.root.path(), &config, Some(NODE));
    assert!(
        stderr.contains("node.metadata[\"io.llmproxy.ledger\"].encryption_key_file"),
        "{stderr}"
    );
}

/// The writer is opened once at boot, so a reload that changes the ledger is
/// refused whole, loudly, and the proxy keeps serving with the old ledger.
#[test]
fn a_reload_that_changes_the_ledger_is_refused() {
    let dir = TempLedgerDir::new();
    let ledger = dir.config(1024, OnUnavailable::Reject);
    let upstream = mock_upstream();
    let config = config_text(&ledger, upstream, "");
    let mut proxy = Proxy::start(dir.root.path(), &config, Some(NODE));
    let changed = config.replace("on_unavailable: reject", "on_unavailable: admit");
    assert_ne!(changed, config);
    std::fs::write(dir.root.path().join("llmproxy.yaml"), changed).unwrap();
    proxy.sighup();
    proxy.wait_for_log("cannot change on reload");
    assert!(proxy.chat().starts_with("HTTP/1.1 200"));
    proxy.terminate();
    assert_eq!(committed_entries(&ledger, NODE).len(), 1);
}

/// Under load with nothing lost, every micro-USD charged to spend is in a
/// committed entry: the two counters are equal. A consumer pulls every entry
/// over the admin API and acknowledges them, after which none is returned.
#[test]
fn spend_and_ledger_counters_agree_and_entries_are_pulled_and_acknowledged() {
    const THREADS: usize = 4;
    const PER_THREAD: usize = 5;
    const TOTAL: u64 = (THREADS * PER_THREAD) as u64;
    let dir = TempLedgerDir::new();
    let ledger = dir.config(1024, OnUnavailable::Reject);
    let config = billing_config(&ledger, mock_upstream(), "reject", 1024);
    let proxy = Proxy::start(dir.root.path(), &config, Some(NODE));
    let key = proxy.mint_key();
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                for _ in 0..PER_THREAD {
                    let response = proxy.chat_as(Some(&key));
                    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
                }
            });
        }
    });
    let scrape = proxy
        .scrape_until(|s| counter(s, "envoy_llmproxy_ledger_entries_committed_total") == TOTAL);
    let charged = counter(&scrape, "envoy_llmproxy_spend_charged_micro_usd_total");
    assert_eq!(
        charged,
        TOTAL * CHARGE_MICRO_USD,
        "every request was charged"
    );
    assert_eq!(
        counter(
            &scrape,
            "envoy_llmproxy_ledger_spend_written_micro_usd_total"
        ),
        charged
    );

    let page = proxy.admin_json("GET", "/ledger/entries?limit=1000");
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len() as u64, TOTAL);
    assert!(entries.iter().all(|e| e["instance_id"] == NODE
        && e["charged_micro_usd"] == CHARGE_MICRO_USD
        && !e["charged_scopes"].as_array().unwrap().is_empty()));
    let through = page["next_after"].as_u64().unwrap();
    let ack = proxy.admin_json("POST", &format!("/ledger/ack?through={through}"));
    assert_eq!(ack["acknowledged_through"], through);
    let after = proxy.admin_json("GET", "/ledger/entries");
    assert_eq!(after["entries"].as_array().unwrap().len(), 0, "{after}");
}

/// ADR-0010 phase 2: an image generation under a tenant spend budget is
/// admitted, charged at the dialled provider's per-image price for the
/// images the response returned, and its ledger entry carries that charge
/// and the images it bought.
#[test]
fn an_image_generation_under_a_tenant_budget_is_charged_and_ledgered() {
    let dir = TempLedgerDir::new();
    let ledger = dir.config(1024, OnUnavailable::Reject);
    let config = billing_config(&ledger, mock_upstream(), "reject", 1024);
    let proxy = Proxy::start(dir.root.path(), &config, Some(NODE));
    let key = proxy.mint_key();
    let budget = http(
        proxy.admin(),
        "PUT",
        "/tenants/t1/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":{"max_usd":"100","period":"daily"}}"#,
    );
    assert!(budget.starts_with("HTTP/1.1 204"), "{budget}");

    let response = http(
        proxy.listen,
        "POST",
        "/v1/images/generations",
        Some(&key),
        r#"{"model":"gpt-image-1","prompt":"a cat","n":2,"size":"1024x1024"}"#,
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    let charge = 2 * IMAGE_NANODOLLARS / 1000;
    let scrape =
        proxy.scrape_until(|s| counter(s, "envoy_llmproxy_ledger_entries_committed_total") == 1);
    assert_eq!(
        counter(&scrape, "envoy_llmproxy_spend_charged_micro_usd_total"),
        charge
    );
    let page = proxy.admin_json("GET", "/ledger/entries");
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{page}");
    let entry = &entries[0];
    assert_eq!(entry["charged_micro_usd"], charge, "{entry}");
    assert!(
        entry["charged_scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|scope| scope["scope"] == "tenant"),
        "the tenant budget was charged: {entry}"
    );
    let text = entry.to_string();
    for needle in [
        r#""images":2"#,
        r#""image_size":"1024x1024""#,
        r#""endpoint":"image_generation""#,
        r#""price_basis":"images""#,
    ] {
        assert!(text.contains(needle), "no {needle} in {entry}");
    }
}

/// Under `admit`, a request with no slot is served unledgered. Its charge is
/// in the spend counter and not in the ledger, so the two counters differ by
/// exactly the charges of the unledgered requests.
#[test]
fn under_admit_the_counters_differ_by_exactly_the_unledgered_charges() {
    const THREADS: usize = 6;
    const PER_THREAD: usize = 3;
    const TOTAL: u64 = (THREADS * PER_THREAD) as u64;
    let dir = TempLedgerDir::new();
    let ledger = dir.config(1, OnUnavailable::Admit);
    // One slot and a slow upstream, so concurrent requests find none.
    let upstream = mock_upstream_with_delay(Duration::from_millis(100));
    let config = billing_config(&ledger, upstream, "admit", 1);
    let proxy = Proxy::start(dir.root.path(), &config, Some(NODE));
    let key = proxy.mint_key();
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                for _ in 0..PER_THREAD {
                    let response = proxy.chat_as(Some(&key));
                    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
                }
            });
        }
    });
    let scrape = proxy.scrape_until(|s| {
        counter(s, "envoy_llmproxy_ledger_entries_committed_total") + unledgered(s) == TOTAL
    });
    let unledgered = unledgered(&scrape);
    assert!(
        unledgered > 0,
        "no request found every slot held:\n{scrape}"
    );
    let charged = counter(&scrape, "envoy_llmproxy_spend_charged_micro_usd_total");
    let written = counter(
        &scrape,
        "envoy_llmproxy_ledger_spend_written_micro_usd_total",
    );
    assert_eq!(charged, TOTAL * CHARGE_MICRO_USD);
    assert_eq!(charged - written, unledgered * CHARGE_MICRO_USD);
}

// ------------------------------------------------------------------ helpers --

/// A ledger, an admin listener, an `auth` block (so the spend filter charges
/// every keyed request) and a price for the mock's model.
fn billing_config(
    ledger: &LedgerConfig,
    upstream: SocketAddr,
    on_unavailable: &str,
    max_reservations: usize,
) -> String {
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
  hmac_secret: "ledger-e2e-hmac-secret"
pricing:
  price_list:
    version: ledger-e2e
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
      - provider_type: openai
        model: gpt-image-1
        basis: images
        image_prices:
          - {{ size: "1024x1024", nanodollars_per_image: {IMAGE_NANODOLLARS} }}
ledger:
  directory: {directory}
  encryption_key_file: {key}
  encryption_key_id: {key_id}
  max_disk_bytes: {disk}
  max_reservations: {max_reservations}
  group_commit_interval: 10ms
  on_unavailable: {on_unavailable}
"#,
        listen = free_port(),
        admin = free_port(),
        directory = ledger.directory.display(),
        key = ledger.encryption_key.file.display(),
        key_id = ledger.encryption_key.id,
        disk = ledger.max_disk_bytes,
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

/// `llmproxy_ledger_unledgered_total`, summed over its reasons.
fn unledgered(scrape: &str) -> u64 {
    scrape
        .lines()
        .filter(|l| l.starts_with("envoy_llmproxy_ledger_unledgered_total{"))
        .filter_map(|l| l.split_whitespace().last()?.parse::<u64>().ok())
        .sum()
}

fn config_text(ledger: &LedgerConfig, upstream: SocketAddr, extra: &str) -> String {
    format!(
        r#"version: 0
listen: 127.0.0.1:{listen}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
routes:
  - {{ model: "*", provider: openai }}
ledger:
  directory: {directory}
  encryption_key_file: {key}
  encryption_key_id: {key_id}
  max_disk_bytes: {disk}
  group_commit_interval: 10ms
  on_unavailable: reject
{extra}"#,
        listen = free_port(),
        directory = ledger.directory.display(),
        key = ledger.encryption_key.file.display(),
        key_id = ledger.encryption_key.id,
        disk = ledger.max_disk_bytes,
    )
}

/// A running proxy, killed and reaped on drop so a failed assertion cannot
/// leave a listener behind (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    listen: SocketAddr,
    admin: Option<SocketAddr>,
    stderr: std::path::PathBuf,
}

impl Proxy {
    fn spawn(dir: &Path, config: &str, node: Option<&str>) -> (Child, std::path::PathBuf) {
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).unwrap();
        let stderr = dir.join(format!("stderr-{}.log", free_port()));
        let mut command = Command::new(BIN);
        command
            .args(["--config", path.to_str().unwrap(), "--concurrency", "1"])
            .args(["--drain-time-s", "1"])
            .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&stderr).unwrap());
        if let Some(node) = node {
            command.args(["--service-node", node]);
        }
        (command.spawn().expect("spawn llm-proxy"), stderr)
    }

    fn start(dir: &Path, config: &str, node: Option<&str>) -> Proxy {
        let port = |marker: &str| -> Option<SocketAddr> {
            let port: u16 = config
                .split(marker)
                .nth(1)?
                .lines()
                .next()?
                .trim()
                .parse()
                .ok()?;
            Some(SocketAddr::from(([127, 0, 0, 1], port)))
        };
        let (child, stderr) = Self::spawn(dir, config, node);
        let proxy = Proxy {
            child,
            listen: port("listen: 127.0.0.1:").unwrap(),
            admin: port("admin: 127.0.0.1:"),
            stderr,
        };
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        for addr in proxy.admin.into_iter().chain([proxy.listen]) {
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

    /// Runs a proxy that must exit non-zero on its own; returns its stderr.
    fn fails(dir: &Path, config: &str, node: Option<&str>) -> String {
        let (mut child, stderr) = Self::spawn(dir, config, node);
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the proxy kept running");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(!status.success());
        std::fs::read_to_string(stderr).unwrap()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    fn wait_for_log(&self, needle: &str) {
        let deadline = Instant::now() + IO_TIMEOUT;
        while !self.log().contains(needle) {
            assert!(
                Instant::now() < deadline,
                "no `{needle}` in:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .args([name, &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn sighup(&self) {
        self.signal("-HUP");
    }

    /// SIGTERM and wait for a clean exit, so the writer's shutdown ran.
    fn terminate(&mut self) {
        self.signal("-TERM");
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "exit {status}:\n{}", self.log());
                return;
            }
            assert!(Instant::now() < deadline, "did not exit:\n{}", self.log());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn chat(&self) -> String {
        self.chat_as(None)
    }

    fn chat_as(&self, key: Option<&str>) -> String {
        let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
        http(self.listen, "POST", "/v1/chat/completions", key, body)
    }

    fn admin(&self) -> SocketAddr {
        self.admin.expect("this test configured an admin listener")
    }

    /// `POST /keys` for tenant `t1`, granted every model; returns the
    /// plaintext key.
    fn mint_key(&self) -> String {
        let response = http(
            self.admin(),
            "POST",
            "/keys",
            Some(ADMIN_TOKEN),
            r#"{"tenant":"t1","key_id":"ledger-e2e-key"}"#,
        );
        assert!(response.starts_with("HTTP/1.1 201"), "{response}");
        let key = json_body(&response)["key"].as_str().unwrap().to_owned();
        let tenant = http(
            self.admin(),
            "POST",
            "/tenants",
            Some(ADMIN_TOKEN),
            r#"{"tenant":"t1"}"#,
        );
        assert!(tenant.starts_with("HTTP/1.1 2"), "{tenant}");
        let policy = http(
            self.admin(),
            "PUT",
            "/tenants/t1/policy",
            Some(ADMIN_TOKEN),
            r#"{"access":"all"}"#,
        );
        assert!(policy.starts_with("HTTP/1.1 204"), "{policy}");
        key
    }

    /// A bearer-gated admin call that must answer 200; its JSON body.
    fn admin_json(&self, method: &str, path: &str) -> serde_json::Value {
        let response = http(self.admin(), method, path, Some(ADMIN_TOKEN), "");
        assert!(response.starts_with("HTTP/1.1 200"), "{path}:\n{response}");
        json_body(&response)
    }

    /// Poll `/stats/prometheus` until `done` holds; the entries commit
    /// asynchronously, within a group-commit interval.
    fn scrape_until(&self, done: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            let response = http(self.admin(), "GET", "/stats/prometheus", None, "");
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
    fn drop(&mut self) {
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

fn mock_upstream() -> SocketAddr {
    mock_upstream_with_delay(Duration::ZERO)
}

/// An OpenAI-shaped upstream on a std thread that answers every request,
/// each after `delay`.
fn mock_upstream_with_delay(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
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
                let length: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut have = raw.len() - (head_end + 4);
                while have < length {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => have += n,
                    }
                }
                std::thread::sleep(delay);
                let image = r#"{"created":1,"data":[{"b64_json":"QUJD"},{"b64_json":"REVG"}]}"#;
                let chat = r#"{"id":"x","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":6,"completion_tokens":4,"total_tokens":10}}"#;
                let body = if head.starts_with("post /v1/images/generations") {
                    image
                } else {
                    chat
                };
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            });
        }
    });
    addr
}
