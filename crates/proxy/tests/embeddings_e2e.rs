//! `/v1/embeddings` is metered like a generation, and `GET /v1/models` lists
//! only what the caller may use: the real `llm-proxy` binary in `--config`
//! mode against std-thread mock providers.
//!
//! An embeddings response reports `usage.prompt_tokens` and no output tokens.
//! The proxy must read it into the access log, the tenant's token window, and
//! the tenant and key spend, priced at the rate card entry of the provider
//! that actually served the request: the primary member of the model's
//! fallback list fails, so the charge must be at the fallback's price, not the
//! primary's. Token limits (a dialect `limits` rule scoped to the model, and a
//! key limit written through the admin API) must refuse the next embeddings
//! request once the first one spent the window, without reaching the provider.
//!
//! `GET /v1/models` is answered by the proxy from the configured catalogue,
//! filtered by the tenant grant intersected with the key policy, and never
//! forwarded.
//!
//! Rust note: same harness shape as `tests/partial_usage_e2e.rs` (std threads,
//! ephemeral ports, a `Drop` that kills the proxy, every wait bounded).

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const LOG_TIMEOUT: Duration = Duration::from_secs(20);

const HMAC_SECRET: &str = "embeddings-e2e-secret";
const ADMIN_TOKEN: &str = "embeddings-e2e-admin-token";
const TENANT: &str = "t1";
const KEY_ID: &str = "minted-1";

/// The client-facing model, and the upstream model each provider serves it as.
const MODEL: &str = "embed";
const PRIMARY_MODEL: &str = "text-embedding-3-large";
const BACKUP_MODEL: &str = "text-embedding-3-small";

/// `usage.prompt_tokens` in every mock embeddings response.
const PROMPT_TOKENS: u64 = 12;

/// Nanodollars per input token on each provider's rate card entry. Multiples
/// of 1000, so the micro-dollar spend is exact. The output price is nonzero
/// so a response metered with output tokens would show in the charge.
const PRIMARY_INPUT_NANO: u64 = 130_000;
const BACKUP_INPUT_NANO: u64 = 20_000;
const OUTPUT_NANO: u64 = 1_000_000;

const TOKENS_REFUSED: &str = "token budget exceeded";

#[test]
fn an_embeddings_request_is_metered_and_charged_at_the_serving_providers_card() {
    let dir = scratch_dir("metered");
    let primary = Mock::start(Reply::Unavailable);
    let backup = Mock::start(Reply::Embeddings);
    let proxy = Proxy::start(
        &dir,
        &Setup {
            primary: Some(primary.addr),
            backup: backup.addr,
            limits: "  - { key: tenant, tokens_per_minute: 1000000 }\n",
            tenants_without_policy: "allow",
        },
    );
    let key = mint_key(&proxy, KEY_ID);
    create_tenant(&proxy);
    put_ok(
        &proxy,
        &format!("/tenants/{TENANT}/budget"),
        r#"{"budget":{"max_usd":"1.00","period":"daily"}}"#,
    );
    put_ok(
        &proxy,
        &format!("/keys/{KEY_ID}/budget"),
        r#"{"budget":{"max_usd":"1.00","period":"daily"}}"#,
    );

    let response = embeddings(&proxy, &key);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert_eq!(primary.requests().len(), 1, "the primary was tried first");
    let served = backup.requests();
    assert_eq!(served.len(), 1, "the fallback served the request");
    assert_eq!(served[0].path, "/v1/embeddings");
    assert_eq!(
        served[0].model.as_deref(),
        Some(BACKUP_MODEL),
        "the fallback member's model rewrite applies"
    );

    // Input only, at the fallback's input price. The primary's price, or an
    // output charge, would give another number.
    let charge_nano = PROMPT_TOKENS * BACKUP_INPUT_NANO;
    assert_eq!(
        proxy.spend_micros(&format!("/tenants/{TENANT}/spend")),
        charge_nano / 1000,
        "the tenant is charged at the serving provider's card"
    );
    assert_eq!(
        proxy.spend_micros(&format!("/keys/{KEY_ID}/spend")),
        charge_nano / 1000,
        "the key is charged the same request"
    );
    assert_eq!(
        proxy.window_tokens(&key),
        PROMPT_TOKENS,
        "the tenant's token window counts the embeddings input"
    );

    let line = proxy.wait_for_log_line("/v1/embeddings");
    assert_eq!(
        line["llm_input_tokens"],
        PROMPT_TOKENS.to_string(),
        "{line}"
    );
    assert_eq!(line["llm_output_tokens"], "0", "{line}");
    assert_eq!(
        line["llm_total_tokens"],
        PROMPT_TOKENS.to_string(),
        "{line}"
    );
    assert_eq!(line["llm_requested_model"], MODEL, "{line}");
    assert_eq!(line["llm_tenant"], TENANT, "{line}");
    assert_eq!(line["llm_key_id"], KEY_ID, "{line}");
    assert_eq!(
        line["llm_list_cost_nanodollars"],
        charge_nano.to_string(),
        "{line}"
    );
    finish(proxy, &dir);
}

/// A dialect rule scoped to the embeddings model counts its input tokens: the
/// first request spends the window, the second is refused before the provider.
#[test]
fn a_models_scoped_token_limit_refuses_the_next_embeddings_request() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("models-limit");
    let backup = Mock::start(Reply::Embeddings);
    let proxy = Proxy::start(
        &dir,
        &Setup {
            primary: None,
            backup: backup.addr,
            limits: &format!("  - {{ key: tenant, tokens_per_minute: 10, models: [{MODEL}] }}\n"),
            tenants_without_policy: "allow",
        },
    );
    let key = mint_key(&proxy, KEY_ID);
    assert_admitted(&embeddings(&proxy, &key));
    let refused = embeddings(&proxy, &key);
    assert_refused(&refused, TOKENS_REFUSED);
    assert_eq!(
        backup.requests().len(),
        1,
        "the refused request reached the provider"
    );
    finish(proxy, &dir);
}

/// A key token limit written through the admin API counts embeddings input.
#[test]
fn a_key_token_limit_refuses_the_next_embeddings_request() {
    start_away_from_a_window_edge();
    let dir = scratch_dir("key-limit");
    let backup = Mock::start(Reply::Embeddings);
    let proxy = Proxy::start(
        &dir,
        &Setup {
            primary: None,
            backup: backup.addr,
            limits: "",
            tenants_without_policy: "allow",
        },
    );
    let key = mint_key(&proxy, KEY_ID);
    put_ok(
        &proxy,
        &format!("/keys/{KEY_ID}/limits"),
        r#"{"limits":{"tokens_per_minute":10}}"#,
    );
    assert_admitted(&embeddings(&proxy, &key));
    assert_refused(&embeddings(&proxy, &key), TOKENS_REFUSED);
    assert_eq!(backup.requests().len(), 1);
    finish(proxy, &dir);
}

/// `GET /v1/models` lists the catalogue entries the caller may use: the tenant
/// grant, narrowed by the key's own policy. A sibling key with no policy sees
/// the whole grant, a tenant with no policy sees nothing, an unauthenticated
/// caller is refused, and no listing reaches a provider.
#[test]
fn models_lists_only_what_the_caller_may_use_and_is_never_forwarded() {
    let dir = scratch_dir("models");
    let backup = Mock::start(Reply::Embeddings);
    let proxy = Proxy::start(
        &dir,
        &Setup {
            primary: None,
            backup: backup.addr,
            limits: "",
            tenants_without_policy: "deny",
        },
    );
    let narrowed = mint_key(&proxy, KEY_ID);
    let sibling = mint_key(&proxy, "minted-2");

    assert!(
        list_models(&proxy, Some(&narrowed)).is_empty(),
        "a tenant without a policy may use nothing, so it lists nothing"
    );

    create_tenant(&proxy);
    put_ok(
        &proxy,
        &format!("/tenants/{TENANT}/policy"),
        r#"{"access":{"only":["embed","gpt-4o"]}}"#,
    );
    put_ok(
        &proxy,
        &format!("/keys/{KEY_ID}/policy"),
        r#"{"access":{"only":["embed","chat-mini"]}}"#,
    );

    assert_eq!(
        list_models(&proxy, Some(&sibling)),
        ["embed", "gpt-4o"],
        "a key without a policy lists its tenant's grant"
    );
    assert_eq!(
        list_models(&proxy, Some(&narrowed)),
        ["embed"],
        "the key policy narrows the grant; chat-mini is not granted to the tenant"
    );

    let anonymous = get(proxy.listen, "/v1/models", None);
    assert!(anonymous.starts_with("HTTP/1.1 401"), "{anonymous}");

    // The listing agrees with enforcement for the same key.
    assert_admitted(&embeddings(&proxy, &narrowed));
    assert!(
        backup.requests().iter().all(|r| r.path != "/v1/models"),
        "a listing was forwarded: {:?}",
        backup.requests()
    );
    finish(proxy, &dir);
}

/// Without `auth` there is no caller to filter for: the catalogue is the
/// whole configured list, still answered locally.
#[test]
fn models_without_auth_lists_the_whole_catalogue() {
    let dir = scratch_dir("models-open");
    let backup = Mock::start(Reply::Embeddings);
    let listen = free_port();
    let admin = free_port();
    let config = format!(
        r#"version: 0
listen: 127.0.0.1:{listen}
admin: 127.0.0.1:{admin}
providers:
  backup: {{ type: openai, base_url: "http://{backup}", api_key: sk-backup }}
routes:
  - {{ model: chat-mini, provider: backup }}
  - {{ model: "gpt-*", provider: backup }}
models:
  {MODEL}: {{ providers: [backup/{BACKUP_MODEL}] }}
  gpt-4o: {{ providers: [backup] }}
"#,
        backup = backup.addr,
    );
    let proxy = Proxy::spawn(&dir, &config, listen, admin);
    assert_eq!(list_models(&proxy, None), ["chat-mini", "embed", "gpt-4o"]);
    assert!(backup.requests().is_empty(), "{:?}", backup.requests());
    finish(proxy, &dir);
}

// ------------------------------------------------------------------ helpers --

struct Setup<'a> {
    /// A first provider for the model, tried before `backup`. `None` serves
    /// the model from `backup` alone.
    primary: Option<SocketAddr>,
    backup: SocketAddr,
    /// `limits:` entries, each line indented two spaces.
    limits: &'a str,
    /// `auth.enforce.tenants_without_policy`.
    tenants_without_policy: &'a str,
}

/// The dialect file: an embeddings model served by one or two providers, two
/// other exact names (`gpt-4o` and the route `chat-mini`) so the catalogue has
/// something to filter, auth, a rate card per upstream model, and a JSON
/// access log.
fn config_text(listen: u16, admin: u16, access_log: &Path, setup: &Setup) -> String {
    let (providers, members) = match setup.primary {
        Some(primary) => (
            format!(
                "  primary: {{ type: openai, base_url: \"http://{primary}\", api_key: sk-primary }}\n"
            ),
            format!("primary/{PRIMARY_MODEL}, backup/{BACKUP_MODEL}"),
        ),
        None => (String::new(), format!("backup/{BACKUP_MODEL}")),
    };
    let limits = if setup.limits.is_empty() {
        String::new()
    } else {
        format!("limits:\n{}", setup.limits)
    };
    format!(
        r#"version: 0
listen: 127.0.0.1:{listen}
admin: 127.0.0.1:{admin}
providers:
{providers}  backup: {{ type: openai, base_url: "http://{backup}", api_key: sk-backup }}
routes:
  - {{ model: chat-mini, provider: backup }}
models:
  {MODEL}: {{ providers: [{members}] }}
  gpt-4o: {{ providers: [backup] }}
auth:
  hmac_secret: "{HMAC_SECRET}"
  enforce: {{ tenants_without_policy: {twp} }}
pricing:
  price_list:
    version: embeddings-e2e
    effective_from: "2026-01-01T00:00:00Z"
    entries:
{primary_entry}{backup_entry}{limits}observability:
  access_logs: {{ output: {log}, format: json }}
"#,
        backup = setup.backup,
        twp = setup.tenants_without_policy,
        primary_entry = price_entry(PRIMARY_MODEL, PRIMARY_INPUT_NANO),
        backup_entry = price_entry(BACKUP_MODEL, BACKUP_INPUT_NANO),
        log = access_log.display(),
    )
}

fn price_entry(model: &str, input_nano: u64) -> String {
    format!(
        "      - provider_type: openai\n        model: {model}\n        tier_mode: whole_request\n        \
         tiers:\n          - input_nanodollars_per_token: {input_nano}\n            \
         cached_input_nanodollars_per_token: 1\n            \
         cache_write_nanodollars_per_token: 1\n            \
         output_nanodollars_per_token: {OUTPUT_NANO}\n"
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-embeddings-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn finish(proxy: Proxy, dir: &Path) {
    drop(proxy);
    let _ = std::fs::remove_dir_all(dir);
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
    fn start(dir: &Path, setup: &Setup) -> Proxy {
        let listen = free_port();
        let admin = free_port();
        let config = config_text(listen, admin, &dir.join("access.log"), setup);
        Proxy::spawn(dir, &config, listen, admin)
    }

    fn spawn(dir: &Path, config: &str, listen: u16, admin: u16) -> Proxy {
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
            access_log: dir.join("access.log"),
        };
        for addr in [proxy.admin, proxy.listen] {
            assert!(
                wait_for_connectable(addr, STARTUP_TIMEOUT),
                "{addr} did not become connectable in time"
            );
        }
        proxy
    }

    /// The first access-log line for `path`. Bounded: a line that never
    /// arrives fails the test.
    fn wait_for_log_line(&self, path: &str) -> serde_json::Value {
        let deadline = Instant::now() + LOG_TIMEOUT;
        loop {
            let text = std::fs::read_to_string(&self.access_log).unwrap_or_default();
            if let Some(line) = text
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .find(|line| line["path"] == path)
            {
                return line;
            }
            assert!(
                Instant::now() < deadline,
                "no access-log line for {path}; log:\n{text}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Tokens in the tenant's current token window, from its own
    /// `GET /v1/usage` (answered by the limiter, never proxied).
    fn window_tokens(&self, key: &str) -> u64 {
        let response = get(self.listen, "/v1/usage", Some(&format!("Bearer {key}")));
        let json = json_body(&response);
        let used: f64 = json["routes"]
            .as_array()
            .unwrap_or_else(|| panic!("no routes:\n{response}"))
            .iter()
            .filter_map(|r| r["used"].as_f64())
            .sum();
        used as u64
    }

    /// `spend_micro_usd` from an admin spend read (`/tenants/{id}/spend` or
    /// `/keys/{id}/spend`).
    fn spend_micros(&self, path: &str) -> u64 {
        let response = get(self.admin, path, Some(&format!("Bearer {ADMIN_TOKEN}")));
        json_body(&response)["spend_micro_usd"]
            .as_u64()
            .unwrap_or_else(|| panic!("spend_micro_usd in:\n{response}"))
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `POST /keys` for `key_id` on [`TENANT`]; returns the plaintext key.
fn mint_key(proxy: &Proxy, key_id: &str) -> String {
    let response = request(
        "POST",
        proxy.admin,
        "/keys",
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        &format!(r#"{{"tenant":"{TENANT}","key_id":"{key_id}"}}"#),
    );
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "POST /keys:\n{response}"
    );
    json_body(&response)["key"]
        .as_str()
        .expect("plaintext key")
        .to_string()
}

fn create_tenant(proxy: &Proxy) {
    let response = request(
        "POST",
        proxy.admin,
        "/tenants",
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        &format!(r#"{{"tenant":"{TENANT}"}}"#),
    );
    assert!(
        response.starts_with("HTTP/1.1 2"),
        "POST /tenants:\n{response}"
    );
}

fn put_ok(proxy: &Proxy, path: &str, body: &str) {
    let response = request(
        "PUT",
        proxy.admin,
        path,
        Some(&format!("Bearer {ADMIN_TOKEN}")),
        body,
    );
    assert!(
        response.starts_with("HTTP/1.1 204"),
        "PUT {path}:\n{response}"
    );
}

fn embeddings(proxy: &Proxy, key: &str) -> String {
    request(
        "POST",
        proxy.listen,
        "/v1/embeddings",
        Some(&format!("Bearer {key}")),
        &format!(r#"{{"model":"{MODEL}","input":["the quick brown fox","jumps"]}}"#),
    )
}

/// `GET /v1/models` as `key` (or anonymously); asserts the 200 list shape and
/// returns the IDs in order.
fn list_models(proxy: &Proxy, key: Option<&str>) -> Vec<String> {
    let authorization = key.map(|key| format!("Bearer {key}"));
    let response = get(proxy.listen, "/v1/models", authorization.as_deref());
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let json = json_body(&response);
    assert_eq!(json["object"], "list", "{response}");
    json["data"]
        .as_array()
        .unwrap_or_else(|| panic!("no data:\n{response}"))
        .iter()
        .map(|entry| entry["id"].as_str().expect("id").to_string())
        .collect()
}

fn assert_admitted(response: &str) {
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

/// A 429 from the limiter itself: the body names the refusing limit, which
/// the mock provider never produces.
fn assert_refused(response: &str, body: &str) {
    assert!(
        response.starts_with("HTTP/1.1 429") && response.contains(body),
        "expected 429 `{body}`:\n{response}"
    );
}

/// The JSON body of a response, chunked or not: chunk-size lines fall outside
/// the outermost braces.
fn json_body(response: &str) -> serde_json::Value {
    let body = response.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    let body = match (body.find('{'), body.rfind('}')) {
        (Some(start), Some(end)) if start < end => &body[start..=end],
        _ => body,
    };
    serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON ({e}):\n{response}"))
}

fn get(addr: SocketAddr, path: &str, authorization: Option<&str>) -> String {
    request("GET", addr, path, authorization, "")
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
    let content = if body.is_empty() {
        String::new()
    } else {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
    };
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: proxy.local\r\n{auth}{content}\
                 Connection: close\r\n\r\n{body}"
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

/// Windows are aligned to the minute (ADR-0006 amendment B). A test that
/// counts tokens in one window waits out the last few seconds of a minute
/// first, so its requests cannot straddle a boundary.
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

#[derive(Clone, Copy)]
enum Reply {
    /// `503`, which the dialect's fallback retries on the next member.
    Unavailable,
    /// An OpenAI embeddings response echoing the request's model.
    Embeddings,
}

/// One request a mock provider received.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    model: Option<String>,
}

/// A mock provider that records every request it receives.
struct Mock {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Mock {
    fn start(reply: Reply) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock provider");
        let addr = listener.local_addr().expect("no local addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let log = Arc::clone(&log);
                std::thread::spawn(move || serve(stream, reply, &log));
            }
        });
        Mock { addr, seen }
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn serve(mut stream: TcpStream, reply: Reply, log: &Mutex<Vec<Seen>>) {
    // The accepted socket may inherit non-blocking mode on macOS; reads below
    // rely on the timeout instead.
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
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let path = head
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let content_length: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().to_string())
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = raw[head_end + 4..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&buf[..n]),
        }
    }
    let model = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["model"].as_str().map(str::to_string));
    log.lock().unwrap().push(Seen {
        path,
        model: model.clone(),
    });
    let response = match reply {
        Reply::Unavailable => {
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string()
        }
        Reply::Embeddings => {
            let json = serde_json::json!({
                "object": "list",
                "data": [
                    {"object": "embedding", "index": 0, "embedding": [0.25, -0.5]},
                    {"object": "embedding", "index": 1, "embedding": [0.125, 0.75]},
                ],
                "model": model.unwrap_or_default(),
                "usage": {"prompt_tokens": PROMPT_TOKENS, "total_tokens": PROMPT_TOKENS},
            })
            .to_string();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{json}",
                json.len()
            )
        }
    };
    let _ = stream.write_all(response.as_bytes());
}
