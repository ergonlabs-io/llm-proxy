//! Hermetic end-to-end proof (WP-26 / the MVP north-star's P3 milestone):
//! the real `llm-proxy` binary, booted from a dialect (`llmproxy.yaml`)
//! config, proxies real HTTP/1.1 requests over a real TLS connection
//! (self-signed cert, genuine SNI + certificate verification) to the
//! in-process OpenAI/Anthropic mocks in `diffrig::upstreams` -- including
//! SSE responses that genuinely stream through rather than getting buffered
//! whole.
//!
//! **Boot strategy**: spawns the built `llm-proxy` binary as a child process
//! against a temp config file and polls its listener socket until it accepts
//! connections. This proves the real startup path (CLI parsing, dialect
//! lowering, `ClusterManager`/listener bring-up) end to end, not a
//! library-level stand-in -- see `resolve_llm_proxy_bin` for how the binary
//! is located (and, for a standalone `cargo test -p diffrig`, built) so this
//! file has no ordering dependency on another crate's test run.
//!
//! **Hermetic DNS**: providers are addressed by a `*.localhost` hostname
//! (e.g. `llmproxy-openai.test.localhost`, never bare `localhost` itself --
//! see [`MockTls`]'s doc comment for why that distinction matters here). Per
//! RFC 6761, every resolver this workspace runs on (macOS's mDNSResponder,
//! Linux's systemd-resolved / glibc NSS) answers any `*.localhost` name with
//! the loopback addresses without a network round-trip or an `/etc/hosts`
//! edit, which is what keeps this hermetic without needing root to edit
//! system DNS config.

use std::net::{SocketAddr, TcpStream as StdTcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bytes::Bytes;
use diffrig::upstreams::{
    AnthropicConfig, AnthropicUpstream, MockTls, OpenAiConfig, OpenAiUpstream,
};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::net::TcpStream;

// --------------------------------------------------------- llm-proxy binary --

/// Find the `llm-proxy` binary (crate `proxy`'s `[[bin]]`) next to this test
/// binary in `target/<profile>/`, building it first if this is a standalone
/// `cargo test -p diffrig` run that never built crate `proxy`.
fn resolve_llm_proxy_bin() -> PathBuf {
    let bin_name = if cfg!(windows) {
        "llm-proxy.exe"
    } else {
        "llm-proxy"
    };

    // Rust note: `cargo test` builds this integration test into
    // `target/<profile>/deps/tls_e2e-<hash>`; every workspace binary
    // (including `llm-proxy`) lands one directory up, at `target/<profile>/`.
    let exe = std::env::current_exe().expect("current_exe should resolve");
    let mut dir = exe
        .parent()
        .expect("test binary path has a parent dir")
        .to_path_buf();
    if dir.file_name().and_then(|n| n.to_str()) == Some("deps") {
        dir.pop();
    }

    let candidate = dir.join(bin_name);

    // ALWAYS rebuild -- do not short-circuit on "the file is already there".
    //
    // This bit us for real: `cargo test -p diffrig` alone never rebuilds
    // sibling crate `proxy` (diffrig depends on its *binary* at runtime, not
    // on it as a library), so an early return on `candidate.is_file()` runs
    // this end-to-end test against whatever `llm-proxy` was last built --
    // possibly from before the fix under test. A router bug was fixed, this
    // test still failed, and the binary was the stale part. A test that can
    // silently validate an old artifact is worse than no test, so we pay a
    // no-op `cargo build` (fast when nothing changed) on every run.
    //
    // No network is needed: every dependency is already resolved in
    // `Cargo.lock` (and fetched, since building diffrig itself required it).
    let is_release = dir.file_name().and_then(|n| n.to_str()) == Some("release");
    let mut build = Command::new("cargo");
    build.args(["build", "-p", "proxy", "--bin", "llm-proxy"]);
    if is_release {
        build.arg("--release");
    }
    let status = build.status().expect("invoke `cargo build -p proxy`");
    assert!(status.success(), "`cargo build -p proxy` failed");

    assert!(
        candidate.is_file(),
        "llm-proxy binary still missing at {} after building it",
        candidate.display()
    );
    candidate
}

/// Reserve an ephemeral loopback port, then free it -- same technique
/// `crates/proxy-core/tests/upstream_tls.rs` uses, needed here so the
/// dialect config can name the listener's port ahead of the child process
/// binding it.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

// ----------------------------------------------------------- proxy process --

/// A running `llm-proxy` child process, killed on drop so a failing
/// assertion (which unwinds past the rest of a test body) never leaks a
/// listening process into the next test.
struct ProxyProcess {
    child: Child,
    log_path: PathBuf,
}

impl ProxyProcess {
    /// Spawn `llm-proxy --config config_path`, with stdout/stderr captured
    /// to a file (not a pipe -- a pipe can fill up and deadlock the child if
    /// nobody drains it; a plain file has no such limit) so a startup
    /// failure can be diagnosed.
    fn spawn(bin: &Path, config_path: &Path, log_path: &Path) -> Self {
        let log_file = std::fs::File::create(log_path).expect("create proxy log file");
        let log_file_err = log_file.try_clone().expect("clone log file handle");
        let child = Command::new(bin)
            .arg("--config")
            .arg(config_path)
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .spawn()
            .expect("spawn llm-proxy");
        Self {
            child,
            log_path: log_path.to_path_buf(),
        }
    }

    /// Poll `addr` until it accepts a TCP connection, or panic (with the
    /// process's captured log) after `timeout`. Also fails fast if the
    /// child has already exited -- a listener that will never come up
    /// should not eat the whole timeout budget.
    fn wait_until_ready(&mut self, addr: SocketAddr, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!(
                    "llm-proxy exited early ({status}) before its listener came up; log:\n{}",
                    std::fs::read_to_string(&self.log_path).unwrap_or_default()
                );
            }
            if StdTcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "llm-proxy's listener at {addr} never came up within {timeout:?}; log:\n{}",
                    std::fs::read_to_string(&self.log_path).unwrap_or_default()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A scratch directory for one test's config/CA files, removed on drop.
/// Rust note: hand-rolled rather than pulling in the `tempfile` crate --
/// this workspace doesn't depend on it anywhere, and a PID+timestamp-suffixed
/// dir under `std::env::temp_dir()` is enough to avoid collisions between
/// concurrently-running tests in this file.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "diffrig-tls-e2e-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write scratch file");
        path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// -------------------------------------------------------------- HTTP client --
//
// A minimal hyper HTTP/1.1 client -- one request per connection, no pooling
// -- same shape as `openai::tests::test_support`/`anthropic::tests::test_support`
// (each lives in its own crate-internal `#[cfg(test)]` module and can't be
// shared with this separate integration-test binary, hence the duplication).

struct RawResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

async fn send_json(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    json_body: &serde_json::Value,
) -> RawResponse {
    let stream = TcpStream::connect(addr).await.expect("connect to proxy");
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake(io).await.expect("http1 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let req = builder
        .body(Full::new(Bytes::from(json_body.to_string())))
        .expect("build request");

    let res = sender.send_request(req).await.expect("send request");
    let status = res.status().as_u16();
    let response_headers = res
        .headers()
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body_bytes = res
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    RawResponse {
        status,
        headers: response_headers,
        body: String::from_utf8_lossy(&body_bytes).to_string(),
    }
}

/// One SSE event as observed by the client (the `data:`/`event:` block with
/// the trailing blank line stripped), timestamped relative to when the
/// request was sent -- this timing is the whole point of the streaming
/// assertions below.
struct TimedEvent {
    at: Duration,
    data: String,
}

async fn send_json_collect_sse(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    json_body: &serde_json::Value,
) -> (u16, Vec<TimedEvent>) {
    let stream = TcpStream::connect(addr).await.expect("connect to proxy");
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake(io).await.expect("http1 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let req = builder
        .body(Full::new(Bytes::from(json_body.to_string())))
        .expect("build request");

    let started = Instant::now();
    let res = sender.send_request(req).await.expect("send request");
    let status = res.status().as_u16();
    let mut body = res.into_body();

    let mut events = Vec::new();
    let mut pending = String::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("frame read ok");
        if let Some(data) = frame.data_ref() {
            pending.push_str(&String::from_utf8_lossy(data));
            while let Some(pos) = pending.find("\n\n") {
                let event = pending[..pos].to_string();
                pending = pending.split_off(pos + 2);
                events.push(TimedEvent {
                    at: started.elapsed(),
                    data: event,
                });
            }
        }
    }
    (status, events)
}

// ------------------------------------------------------------------ config --

/// Render the dialect (`llmproxy-v0`) config for this test: one listener,
/// an `openai` provider and an `anthropic` provider (named exactly that so
/// the dialect infers their type without an explicit `type:` field), each
/// pointed at a TLS mock upstream with its own `ca_file`. Routing matches
/// the `x-llmproxy-model` request header (see
/// `crates/proxy-simple-config/src/lower.rs`'s `MODEL_HEADER`) against a
/// `gpt-*`/`claude-*` glob.
#[allow(clippy::too_many_arguments)]
fn dialect_config(
    listener_port: u16,
    openai_host: &str,
    openai_port: u16,
    openai_ca_file: &Path,
    anthropic_host: &str,
    anthropic_port: u16,
    anthropic_ca_file: &Path,
) -> String {
    format!(
        r#"
version: 0
listen: "127.0.0.1:{listener_port}"
providers:
  openai:
    base_url: "https://{openai_host}:{openai_port}"
    api_key: "test-openai-key"
    ca_file: "{openai_ca_file}"
  anthropic:
    base_url: "https://{anthropic_host}:{anthropic_port}"
    api_key: "test-anthropic-key"
    ca_file: "{anthropic_ca_file}"
routes:
  - model: "gpt-*"
    provider: openai
  - model: "claude-*"
    provider: anthropic
"#,
        openai_ca_file = openai_ca_file.display(),
        anthropic_ca_file = anthropic_ca_file.display(),
    )
}

const READY_TIMEOUT: Duration = Duration::from_secs(10);

// ----------------------------------------------------------------- helpers --

fn base_openai_config() -> OpenAiConfig {
    OpenAiConfig {
        model: "gpt-mock".to_string(),
        response_text: "alpha beta gamma".to_string(),
        ttft: Duration::from_millis(150),
        inter_token_delay: Duration::from_millis(150),
        require_api_key: Some("test-openai-key".to_string()),
        forced_error: None,
        cached_tokens: 0,
    }
}

fn base_anthropic_config() -> AnthropicConfig {
    AnthropicConfig {
        model: "claude-mock".to_string(),
        response_text: "delta epsilon zeta".to_string(),
        ttft: Duration::from_millis(150),
        inter_token_delay: Duration::from_millis(150),
        require_api_key: Some("test-anthropic-key".to_string()),
        forced_error: None,
        cache_read_tokens: 0,
        cache_creation_tokens: 0,
    }
}

// -------------------------------------------------------------------- tests --

/// The acceptance test: real bytes cross a real TLS connection from the
/// proxy to two mock upstreams, driven purely through the dialect config --
/// non-streaming and streaming, both providers, with the auth headers the
/// dialect injects actually observed at the upstream.
#[tokio::test]
async fn upstream_tls_end_to_end_proxies_both_providers_with_real_streaming() {
    let openai_host = "llmproxy-openai.test.localhost";
    let anthropic_host = "llmproxy-anthropic.test.localhost";
    let openai_tls = MockTls::new(openai_host);
    let anthropic_tls = MockTls::new(anthropic_host);

    let openai_upstream = OpenAiUpstream::spawn_tls(base_openai_config(), &openai_tls)
        .await
        .expect("spawn TLS openai mock");
    let anthropic_upstream = AnthropicUpstream::spawn_tls(base_anthropic_config(), &anthropic_tls)
        .await
        .expect("spawn TLS anthropic mock");

    let scratch = ScratchDir::new("positive");
    let openai_ca_file = scratch.write("openai-ca.pem", &openai_tls.ca_pem);
    let anthropic_ca_file = scratch.write("anthropic-ca.pem", &anthropic_tls.ca_pem);

    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_yaml = dialect_config(
        listener_port,
        openai_host,
        openai_upstream.port(),
        &openai_ca_file,
        anthropic_host,
        anthropic_upstream.port(),
        &anthropic_ca_file,
    );
    let config_path = scratch.write("llmproxy.yaml", &config_yaml);

    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyProcess::spawn(&bin, &config_path, &scratch.path().join("proxy.log"));
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);

    // --- OpenAI: non-streaming ---------------------------------------------
    let body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi there"}],
    });
    let res = send_json(
        listener_addr,
        "POST",
        "/v1/chat/completions",
        &[("x-llmproxy-model", "gpt-4o-mini")],
        &body,
    )
    .await;
    assert_eq!(res.status, 200, "openai non-streaming body: {}", res.body);
    assert!(
        res.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v.contains("application/json")),
        "expected a JSON content-type forwarded from the upstream, got: {:?}",
        res.headers
    );
    let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json");
    assert_eq!(parsed["object"], "chat.completion");
    assert_eq!(
        parsed["choices"][0]["message"]["content"],
        "alpha beta gamma"
    );

    // The dialect must have injected `authorization: Bearer <api_key>` and
    // it must have actually arrived at the upstream.
    let requests = openai_upstream.log.requests();
    let last = requests.last().expect("openai mock received a request");
    assert!(
        last.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("authorization") && v == "Bearer test-openai-key"),
        "expected `authorization: Bearer test-openai-key` at the upstream, got: {:?}",
        last.headers
    );

    // --- OpenAI: streaming actually streams ---------------------------------
    let stream_body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });
    let (status, events) = send_json_collect_sse(
        listener_addr,
        "POST",
        "/v1/chat/completions",
        &[("x-llmproxy-model", "gpt-4o-mini")],
        &stream_body,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        events.len() >= 2,
        "expected multiple SSE frames, got {}",
        events.len()
    );
    let first = &events[0];
    let last_event = events.last().expect("at least one event");
    assert!(
        first.data.contains("\"role\":\"assistant\""),
        "expected the role-delta chunk first, got: {}",
        first.data
    );
    assert_eq!(
        last_event.data, "data: [DONE]",
        "expected the stream to terminate with [DONE]"
    );
    // The mock's schedule: TTFT (150ms) gates the first frame; two more
    // 150ms inter-token delays separate the following content chunks. A
    // proxy that buffered the whole response before forwarding it would
    // deliver every frame at ~the same, late instant -- these two bounds
    // together rule that out: the first frame must show up close to TTFT
    // (not close to the total), and the gap to the last frame must be
    // consistent with the real per-token pacing actually having elapsed
    // between frames as they were forwarded.
    assert!(
        first.at < Duration::from_millis(400),
        "first SSE frame arrived suspiciously late ({:?}); proxy may be buffering",
        first.at
    );
    assert!(
        last_event.at.saturating_sub(first.at) >= Duration::from_millis(250),
        "first and last SSE frames arrived too close together ({:?} vs {:?}); \
         proxy may be buffering the whole response instead of streaming it",
        first.at,
        last_event.at
    );

    // --- Anthropic: non-streaming -------------------------------------------
    let body = json!({
        "model": "claude-3-mock",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi there"}],
    });
    let res = send_json(
        listener_addr,
        "POST",
        "/v1/messages",
        &[("x-llmproxy-model", "claude-3-mock")],
        &body,
    )
    .await;
    assert_eq!(
        res.status, 200,
        "anthropic non-streaming body: {}",
        res.body
    );
    let parsed: serde_json::Value = serde_json::from_str(&res.body).expect("valid json");
    assert_eq!(parsed["type"], "message");
    assert_eq!(parsed["content"][0]["text"], "delta epsilon zeta");

    let requests = anthropic_upstream.log.requests();
    let last = requests.last().expect("anthropic mock received a request");
    assert!(
        last.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("x-api-key") && v == "test-anthropic-key"),
        "expected `x-api-key: test-anthropic-key` at the upstream, got: {:?}",
        last.headers
    );
    // The dialect injects a default `anthropic-version` when the user
    // doesn't set one (`DEFAULT_ANTHROPIC_VERSION` in `lower.rs`).
    assert!(
        last.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("anthropic-version") && v == "2023-06-01"),
        "expected a default `anthropic-version: 2023-06-01` at the upstream, got: {:?}",
        last.headers
    );

    // --- Anthropic: streaming actually streams -------------------------------
    let stream_body = json!({
        "model": "claude-3-mock",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });
    let (status, events) = send_json_collect_sse(
        listener_addr,
        "POST",
        "/v1/messages",
        &[("x-llmproxy-model", "claude-3-mock")],
        &stream_body,
    )
    .await;
    assert_eq!(status, 200);
    let first = &events[0];
    let last_event = events.last().expect("at least one event");
    assert!(
        first.data.contains("event: message_start"),
        "expected `message_start` first, got: {}",
        first.data
    );
    assert!(
        last_event.data.contains("event: message_stop"),
        "expected `message_stop` last, got: {}",
        last_event.data
    );
    assert!(
        first.at < Duration::from_millis(400),
        "first Anthropic SSE frame arrived suspiciously late ({:?})",
        first.at
    );
    assert!(
        last_event.at.saturating_sub(first.at) >= Duration::from_millis(250),
        "Anthropic SSE frames arrived too close together ({:?} vs {:?}); proxy may be buffering",
        first.at,
        last_event.at
    );

    drop(proxy);
    openai_upstream.shutdown().await;
    anthropic_upstream.shutdown().await;
}

/// Verification actually verifies: pointing `ca_file` at a CA unrelated to
/// the one that signed the upstream's certificate must fail the TLS
/// handshake, and the client must see a 503 (the router's upstream-connect
/// local reply) -- never a 200. Without this test, the suite above cannot
/// distinguish "TLS was verified" from "TLS was skipped".
#[tokio::test]
async fn wrong_ca_file_fails_the_handshake_and_the_client_gets_503_not_200() {
    let openai_host = "llmproxy-openai-negative.test.localhost";
    let real_tls = MockTls::new(openai_host);
    // A second, unrelated CA -- never used to sign anything the mock
    // upstream actually presents.
    let unrelated_ca = MockTls::new("unrelated.test.localhost");

    let openai_upstream = OpenAiUpstream::spawn_tls(base_openai_config(), &real_tls)
        .await
        .expect("spawn TLS openai mock");

    let scratch = ScratchDir::new("negative");
    let wrong_ca_file = scratch.write("wrong-ca.pem", &unrelated_ca.ca_pem);
    // Only one provider is needed for this test; `anthropic` still has to be
    // present because the dialect's route table needs at least one
    // resolvable provider per referenced route, so point it at the same
    // (working) mock -- it's simply never exercised below.
    let anthropic_ca_file = scratch.write("anthropic-ca.pem", &real_tls.ca_pem);

    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_yaml = dialect_config(
        listener_port,
        openai_host,
        openai_upstream.port(),
        &wrong_ca_file,
        openai_host,
        openai_upstream.port(),
        &anthropic_ca_file,
    );
    let config_path = scratch.write("llmproxy.yaml", &config_yaml);

    let bin = resolve_llm_proxy_bin();
    let mut proxy = ProxyProcess::spawn(&bin, &config_path, &scratch.path().join("proxy.log"));
    proxy.wait_until_ready(listener_addr, READY_TIMEOUT);

    let body = json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hi there"}],
    });
    let res = send_json(
        listener_addr,
        "POST",
        "/v1/chat/completions",
        &[("x-llmproxy-model", "gpt-4o-mini")],
        &body,
    )
    .await;
    assert_eq!(
        res.status, 503,
        "a certificate signed by an untrusted CA must be rejected (503), got {}: {}",
        res.status, res.body
    );
    assert_ne!(
        res.status, 200,
        "TLS verification must not have been silently skipped"
    );

    drop(proxy);
    openai_upstream.shutdown().await;
}
