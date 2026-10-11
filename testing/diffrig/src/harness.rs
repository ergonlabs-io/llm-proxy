//! Shared end-to-end test harness: spawning the real `llm-proxy` binary
//! against a dialect config, waiting for its listener to come up, and a
//! minimal HTTP/1.1 client (plain JSON request/response, plus incremental
//! SSE collection with per-event timestamps).
//!
//! Rust note: this lives in the library (`src/`) rather than a `tests/`
//! helper module because each file under `testing/diffrig/tests/` is its own
//! separate compilation unit (a standalone integration-test crate) — there is
//! no way for `tests/tls_e2e.rs` to `mod`-include code from
//! `tests/live_smoke.rs` or vice versa. Only code that lives in the crate's
//! *library* target (what `src/lib.rs` declares) can be `use diffrig::...`'d
//! from more than one integration-test binary, which is why this machinery
//! was extracted here instead of staying duplicated in both files.

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
    // Rust note: `OnceLock` runs the initializer exactly once per PROCESS and
    // blocks any concurrent caller until it finishes, so every test in this
    // binary gets the same freshly-built path.
    //
    // This memoization is a pure win, not a weakening of the guarantee below.
    // Without it every test shelled out to `cargo build` independently: with
    // tests running in parallel they then contended on cargo's build-directory
    // lock ("Blocking waiting for file lock on build directory"), so N tests
    // paid N builds AND serialized on the lock. `mock_e2e.rs` spent 42s of a
    // 61s workspace test run doing this for 6 tests. The anti-stale-binary
    // property is unchanged: the build still happens during THIS run, before
    // any test uses the binary -- just once instead of once per test.
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
pub fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
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
    /// This exists because some filters (e.g. the auth filter, as of this
    /// writing) have no dialect (`llmproxy.yaml`) surface yet --
    /// `--config` only understands the fields `proxy-simple-config` knows
    /// how to lower, so a test that needs `llmproxy.auth` in `http_filters`
    /// must hand the proxy a real Envoy bootstrap document instead. Prefer
    /// [`Self::spawn`] once a dialect `auth:` block lands; it exercises the
    /// same lowering path real users hit and needs no hand-written YAML.
    pub fn spawn_envoy(bin: &Path, config_path: &Path, log_path: &Path) -> Self {
        Self::spawn_with_flag(bin, "-c", config_path, log_path, &[])
    }

    /// Same as [`Self::spawn_envoy`], plus `envs` set in the CHILD's
    /// environment only (via `Command::env`, never `std::env::set_var` --
    /// that call is process-global and would race every other test binary
    /// running concurrently in this workspace). Used by the admin write API
    /// drill (`admin_e2e.rs`), which must set
    /// `LLMPROXY_ADMIN_TOKEN` for the spawned proxy without touching this
    /// test process's own environment.
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
    /// **This function BLOCKS the calling thread** (`std::thread::sleep`, and
    /// a blocking `connect_timeout`), and callers are `async fn`s. Any test
    /// calling it must therefore use a **multi-threaded** runtime:
    ///
    /// ```ignore
    /// #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    /// ```
    ///
    /// Plain `#[tokio::test]` is a `current_thread` runtime -- ONE thread. The
    /// mock upstreams are `tokio::spawn`ed onto that same runtime, so blocking
    /// here freezes them: the proxy waits on upstreams that cannot be polled
    /// by the only thread that could poll them, and the test hangs. Measured
    /// 2026-08-07, that was the cause of 8 tests (6 in `mock_e2e`, 2 in
    /// `tls_e2e`) intermittently hanging and turning a 79s workspace run into
    /// 656-863s. Nothing bounded it, because no request in those tests is
    /// wrapped in `tokio::time::timeout`.
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
