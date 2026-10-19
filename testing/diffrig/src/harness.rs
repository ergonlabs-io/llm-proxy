//! Shared harness for spawning the real proxy and sending HTTP/1.1 JSON or SSE
//! requests from multiple integration-test binaries.
//!
//! Rust note: shared helpers belong in the library target because each
//! integration-test file is a separate crate.

use std::net::{SocketAddr, TcpStream as StdTcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

// --------------------------------------------------------- llm-proxy binary --

/// Find the `llm-proxy` binary (crate `proxy`'s `[[bin]]`) next to this test
/// binary in `target/<profile>/`, building it first if this is a standalone
/// `cargo test -p diffrig` run that never built crate `proxy`.
pub fn resolve_llm_proxy_bin() -> PathBuf {
    // Rust note: `OnceLock` shares one build result across concurrent callers;
    // the binary is still rebuilt during this run to avoid stale artifacts.
    static BIN: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BIN.get_or_init(build_llm_proxy_bin).clone()
}

fn build_llm_proxy_bin() -> PathBuf {
    let bin_name = if cfg!(windows) {
        "llm-proxy.exe"
    } else {
        "llm-proxy"
    };

    // Rust note: `cargo test` builds an integration test binary into
    // `target/<profile>/deps/<name>-<hash>`; every workspace binary
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

    // `diffrig` depends on the proxy binary at runtime, so cargo test may
    // leave a stale sibling binary. Rebuild to ensure the test exercises the
    // current source.
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

/// A loopback port that is free now, for a config to name before the child
/// process binds it.
///
/// The port comes from 20000-32767, below the kernel's ephemeral range
/// (Linux 32768-60999, macOS 49152-65535). A port from bind-to-0 is in that
/// range, so between the probe and the child's bind any outgoing connection
/// (the test's own, or the proxy's to a mock upstream) can take it as its
/// source port, and the child fails with "Address already in use". Ports
/// below the range are never handed out that way. The start point varies by
/// process and call so parallel test binaries spread out; a port another
/// process holds fails the probe and the next one is tried.
pub fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU32, Ordering};
    const LOW: u32 = 20_000;
    const SPAN: u32 = 32_768 - LOW;
    static CALLS: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let call = CALLS.fetch_add(1, Ordering::Relaxed);
    let start = std::process::id()
        .wrapping_mul(7919)
        .wrapping_add(nanos)
        .wrapping_add(call.wrapping_mul(104_729));
    for step in 0..SPAN {
        let port = (LOW + (start.wrapping_add(step) % SPAN)) as u16;
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free loopback port in {LOW}-32767");
}

/// How long [`ProxyProcess::wait_until_ready`] callers should wait by
/// default before giving up on the listener coming up.
pub const READY_TIMEOUT: Duration = Duration::from_secs(10);

// ----------------------------------------------------------- proxy process --

/// A running `llm-proxy` child process, killed on drop so a failing
/// assertion (which unwinds past the rest of a test body) never leaks a
/// listening process into the next test.
pub struct ProxyProcess {
    child: Child,
    log_path: PathBuf,
}

impl ProxyProcess {
    /// Spawn `llm-proxy --config config_path` (dialect mode), with
    /// stdout/stderr captured to a file (not a pipe -- a pipe can fill up
    /// and deadlock the child if nobody drains it; a plain file has no such
    /// limit) so a startup failure can be diagnosed.
    pub fn spawn(bin: &Path, config_path: &Path, log_path: &Path) -> Self {
        Self::spawn_with_flag(bin, "--config", config_path, log_path, &[])
    }

    /// Spawn `llm-proxy -c config_path` (Envoy mode), otherwise identical to
    /// [`Self::spawn`].
    ///
    /// Use Envoy mode for filters not exposed by the simple dialect, such as
    /// `llmproxy.auth` in `http_filters`.
    pub fn spawn_envoy(bin: &Path, config_path: &Path, log_path: &Path) -> Self {
        Self::spawn_with_flag(bin, "-c", config_path, log_path, &[])
    }

    /// Set environment variables only on the child process; changing the
    /// test process environment would race concurrent tests.
    pub fn spawn_envoy_with_env(
        bin: &Path,
        config_path: &Path,
        log_path: &Path,
        envs: &[(&str, &str)],
    ) -> Self {
        Self::spawn_with_flag(bin, "-c", config_path, log_path, envs)
    }

    // Rust note: shared body for `spawn`/`spawn_envoy`/`spawn_envoy_with_env`
    // -- only the flag name and the extra env vars differ, so both are
    // parameters rather than three near-identical `Command` builders.
    fn spawn_with_flag(
        bin: &Path,
        flag: &str,
        config_path: &Path,
        log_path: &Path,
        envs: &[(&str, &str)],
    ) -> Self {
        let log_file = std::fs::File::create(log_path).expect("create proxy log file");
        let log_file_err = log_file.try_clone().expect("clone log file handle");
        let mut command = Command::new(bin);
        command
            .arg(flag)
            .arg(config_path)
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err));
        for (key, value) in envs {
            command.env(key, value);
        }
        let child = command.spawn().expect("spawn llm-proxy");
        Self {
            child,
            log_path: log_path.to_path_buf(),
        }
    }

    /// Poll `addr` until it accepts a TCP connection, or panic (with the
    /// process's captured log) after `timeout`. Also fails fast if the
    /// child has already exited -- a listener that will never come up
    /// should not eat the whole timeout budget.
    ///
    /// This blocks the calling thread, so async callers must use a
    /// multi-threaded runtime; a current-thread runtime would also freeze the
    /// spawned mock upstreams.
    ///
    /// ```ignore
    /// #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    /// ```
    pub fn wait_until_ready(&mut self, addr: SocketAddr, timeout: Duration) {
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

    /// Ask the proxy to reload its config file. Shells out to `kill` because
    /// the workspace denies `unsafe`, which rules out calling `libc::kill`.
    pub fn sighup(&self) {
        let status = Command::new("kill")
            .args(["-HUP", &self.child.id().to_string()])
            .status()
            .expect("run kill -HUP");
        assert!(status.success(), "kill -HUP {} failed", self.child.id());
    }

    /// Poll the captured log until a line contains `needle`, or panic with
    /// the log after `timeout`. ANSI color codes are stripped first, because
    /// the tracing formatter colors output even when it goes to a file.
    ///
    /// Blocks the calling thread, like [`Self::wait_until_ready`].
    pub fn wait_for_log(&self, needle: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let log = strip_ansi(&std::fs::read_to_string(&self.log_path).unwrap_or_default());
            if log.contains(needle) {
                return;
            }
            if Instant::now() >= deadline {
                panic!("log line {needle:?} never appeared within {timeout:?}; log:\n{log}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Removes `ESC [ ... m` color sequences.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
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
/// concurrently-running tests.
pub struct ScratchDir(PathBuf);

impl ScratchDir {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "diffrig-e2e-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn write(&self, name: &str, contents: &str) -> PathBuf {
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
// A minimal hyper HTTP/1.1 client -- one request per connection, no pooling.

pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub async fn send_json(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    json_body: &serde_json::Value,
) -> RawResponse {
    send_json_optional(addr, method, path, headers, Some(json_body)).await
}

/// Send a JSON request while preserving whether the caller supplied a body.
/// Envoy rejects a bodyless-method request carrying an unsolicited JSON body,
/// so replay clients must not synthesize `{}` for GET/HEAD scenarios.
pub async fn send_json_optional(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    json_body: Option<&serde_json::Value>,
) -> RawResponse {
    let stream = TcpStream::connect(addr).await.expect("connect to proxy");
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake(io).await.expect("http1 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder().method(method).uri(path);
    if json_body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = match json_body {
        Some(body) => Either::Left(Full::new(Bytes::from(body.to_string()))),
        None => Either::Right(Empty::new()),
    };
    let req = builder.body(body).expect("build request");

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
/// assertions that use it.
pub struct TimedEvent {
    pub at: Duration,
    pub data: String,
}

/// Send a JSON request and incrementally collect its response as SSE events,
/// returning the status, response headers, and the timestamped events.
pub async fn send_json_collect_sse(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    json_body: &serde_json::Value,
) -> (u16, Vec<(String, String)>, Vec<TimedEvent>) {
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
    let response_headers = res
        .headers()
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
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
    (status, response_headers, events)
}
