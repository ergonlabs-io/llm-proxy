//! Provider file and batch IDs belong to the tenant that created them
//! (`llmproxy.object_ownership`). Every tenant reaches the provider through
//! the proxy's one provider account, so the provider sees a single namespace
//! of IDs; only the proxy can keep tenant B away from tenant A's objects.
//!
//! These drive the real `llm-proxy` binary through `--config` with two
//! tenants, each holding a minted key. The mock provider records every
//! request it receives, so "the provider is never dialled" is asserted at the
//! socket rather than inferred from a status.
//!
//! Every probe carries `{"model": ...}` in a JSON body. Without one,
//! `llmproxy.model_authz` refuses the request for want of a model, which
//! hid this hole rather than closing it: with the body, the requests used to
//! reach the provider and return the other tenant's objects.
//!
//! Rust note: same harness shape as `tests/tenant_enforcement_e2e.rs` (std
//! threads, ephemeral ports, a `Drop` that kills the proxy). Every wait is
//! bounded, so a hung child fails the test instead of stalling it.

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Backstop for a store write the proxy makes off the request path.
const STORE_WAIT: Duration = Duration::from_secs(10);

const HMAC_SECRET: &str = "tenant-object-ownership-e2e-secret";
const ADMIN_TOKEN: &str = "tenant-object-ownership-e2e-admin-token";
const TENANT_A: &str = "tenant-a";
const TENANT_B: &str = "tenant-b";
const FILE_ID: &str = "file-owned-by-a";
const BATCH_ID: &str = "batch_owned_by_a";
/// The file the provider creates when the batch completes.
const OUTPUT_FILE_ID: &str = "file-output-of-a";
const MODEL_BODY: &str = r#"{"model":"gpt-4o-mini"}"#;

/// The dialect with model policy enforced (the default) and with it off, so
/// the refusal is shown to come from ownership and not from model_authz.
const CHAINS: [(&str, &str); 2] = [
    ("default", ""),
    ("model-policy-off", "  enforce: { model_policy: false }\n"),
];

/// Requests that name tenant A's objects, as (method, path).
fn object_requests() -> Vec<(&'static str, String)> {
    vec![
        ("GET", format!("/v1/files/{FILE_ID}")),
        ("GET", format!("/v1/files/{FILE_ID}/content")),
        ("GET", format!("/v1/batches/{BATCH_ID}")),
        ("POST", format!("/v1/batches/{BATCH_ID}/cancel")),
        ("DELETE", format!("/v1/files/{FILE_ID}")),
    ]
}

/// Tenant B gets 404 for tenant A's file and batch on get, content, cancel
/// and delete, for a batch or chat that names A's file, and for the lists;
/// none of it reaches the provider. An ID no tenant owns is refused the same
/// way. Tenant A still reaches its own objects, so the 404s are ownership
/// and not a blanket refusal.
#[test]
fn another_tenants_files_and_batches_are_refused_before_the_provider_is_dialled() {
    for (tag, extra) in CHAINS {
        let run = Run::start(tag, extra);
        let (key_a, key_b) = (&run.key_a, &run.key_b);
        if tag == "default" {
            // model_authz refuses a multipart upload, which has no model, so
            // this chain gets A's file the way an object created before
            // ownership was recorded does: an operator assigns it.
            run.assign(TENANT_A, FILE_ID);
        } else {
            run.create_file(key_a);
        }
        run.create_batch(key_a);

        for (method, path) in object_requests().into_iter().chain([
            ("GET", "/v1/files".to_string()),
            ("GET", "/v1/batches".to_string()),
        ]) {
            run.assert_refused(
                method,
                &path,
                key_b,
                MODEL_BODY,
                &format!("[{tag}] tenant B"),
            );
        }
        let steal = format!(
            r#"{{"model":"gpt-4o-mini","input_file_id":"{FILE_ID}","endpoint":"/v1/chat/completions","completion_window":"24h"}}"#
        );
        run.assert_refused(
            "POST",
            "/v1/batches",
            key_b,
            &steal,
            &format!("[{tag}] B's batch over A's file"),
        );
        let chat = format!(
            r#"{{"model":"gpt-4o-mini","messages":[{{"role":"user","content":[{{"type":"file","file":{{"file_id":"{FILE_ID}"}}}}]}}]}}"#
        );
        run.assert_refused(
            "POST",
            "/v1/chat/completions",
            key_b,
            &chat,
            &format!("[{tag}] B's chat over A's file"),
        );
        run.assert_refused(
            "GET",
            "/v1/files/file-nobody-owns",
            key_a,
            MODEL_BODY,
            &format!("[{tag}] an unknown ID"),
        );
        run.assert_refused(
            "GET",
            "/v1/files",
            key_a,
            MODEL_BODY,
            &format!("[{tag}] A's list"),
        );

        for (method, path) in object_requests() {
            run.assert_served(
                method,
                &path,
                key_a,
                MODEL_BODY,
                &format!("[{tag}] tenant A"),
            );
        }
        run.assert_served(
            "POST",
            "/v1/chat/completions",
            key_a,
            &chat,
            &format!("[{tag}] A's chat"),
        );
    }
}

/// The provider creates a batch's output file when the batch completes.
/// Reading the batch records that file for the batch's owner, so the owner
/// can fetch its results and nobody else can.
#[test]
fn a_batchs_output_file_belongs_to_the_batchs_owner() {
    let run = Run::start("output", "");
    run.assign(TENANT_A, FILE_ID);
    run.create_batch(&run.key_a);
    let content = format!("/v1/files/{OUTPUT_FILE_ID}/content");
    run.assert_refused(
        "GET",
        &content,
        &run.key_a,
        MODEL_BODY,
        "before the batch is read",
    );
    run.assert_served(
        "GET",
        &format!("/v1/batches/{BATCH_ID}"),
        &run.key_a,
        MODEL_BODY,
        "A reads its batch",
    );
    run.assert_served(
        "GET",
        &content,
        &run.key_a,
        MODEL_BODY,
        "A fetches its output",
    );
    run.assert_refused(
        "GET",
        &content,
        &run.key_b,
        MODEL_BODY,
        "B fetches A's output",
    );
}

/// Owners live in the control-plane store: with a persistent store they
/// survive a restart, and the restarted proxy has no cached owner to fall
/// back on.
#[test]
fn ownership_survives_a_restart_with_a_persistent_store() {
    let dir = scratch_dir("restart");
    let store = dir.join("control.redb");
    let extra = format!(
        "  store:\n    persistent:\n      path: \"{}\"\n",
        store.display()
    );
    let upstream = MockProvider::spawn();
    let config = config_text(upstream.addr, &extra);
    let mut run = Run::start_with(dir.clone(), upstream, &config, None);
    run.assign(TENANT_A, FILE_ID);
    run.create_batch(&run.key_a);
    // The owner is written to the store just after the create's response.
    run.wait_until_stored(TENANT_A, BATCH_ID);

    run.proxy = None;
    run.proxy = Some(Proxy::start(&dir, &config, None));
    let batch = format!("/v1/batches/{BATCH_ID}");
    run.assert_served("GET", &batch, &run.key_a, MODEL_BODY, "A after a restart");
    run.assert_refused("GET", &batch, &run.key_b, MODEL_BODY, "B after a restart");
}

/// Two replicas on one Redis: an object created through one is the creator's
/// on the other at once (owners are read on a miss, not on the policy poll),
/// and refused to the other tenant there.
#[test]
#[ignore = "needs a real Redis: set LLM_PROXY_TEST_REDIS"]
fn redis_ownership_recorded_on_one_replica_is_enforced_on_another() {
    let redis = std::env::var("LLM_PROXY_TEST_REDIS").expect(
        "LLM_PROXY_TEST_REDIS is not set -- start a Redis with `docker run -d --rm \
         -p 6390:6379 --name llmproxy-test-redis redis:7-alpine` and set \
         LLM_PROXY_TEST_REDIS=redis://127.0.0.1:6390",
    );
    let namespace = format!(
        "llmproxy-e2e-objects-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after the epoch")
            .as_nanos()
    );
    let extra =
        format!("  store:\n    shared: {{ url: \"{redis}\", namespace: \"{namespace}\" }}\n");
    let upstream = MockProvider::spawn();
    let dir_b = scratch_dir("replica-b");
    let config_a = config_text(upstream.addr, &extra);
    let mut run = Run::start_with(
        scratch_dir("replica-a"),
        upstream,
        &config_a,
        Some("replica-a"),
    );
    // Keys and policies reach replica B at its boot load; the objects below
    // are created after B is up, so B can only learn their owner from the
    // store.
    let replica_b = Proxy::start(
        &dir_b,
        &config_text(run.upstream.addr, &extra),
        Some("replica-b"),
    );
    run.assign(TENANT_A, FILE_ID);
    run.create_batch(&run.key_a);
    run.wait_until_stored(TENANT_A, BATCH_ID);

    let replica_a = run.proxy.replace(replica_b);
    let batch = format!("/v1/batches/{BATCH_ID}");
    run.assert_served("GET", &batch, &run.key_a, MODEL_BODY, "A on replica B");
    run.assert_refused("GET", &batch, &run.key_b, MODEL_BODY, "B on replica B");
    drop(replica_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// The fail-open opt-out: with `auth.enforce.object_ownership: false` the
/// filter is absent, tenant B reaches tenant A's batch, and the load says so.
#[test]
fn opting_out_leaves_ids_open_and_warns_at_load() {
    let run = Run::start("opt-out", "  enforce: { object_ownership: false }\n");
    let stderr = std::fs::read_to_string(run.dir.join("stderr.log")).unwrap_or_default();
    assert!(
        stderr.contains("auth.enforce.object_ownership") && stderr.contains("NOT kept"),
        "the opt-out must warn at load:\n{stderr}"
    );
    run.assert_served(
        "GET",
        &format!("/v1/batches/{BATCH_ID}"),
        &run.key_b,
        MODEL_BODY,
        "B with ownership off",
    );
}

// ------------------------------------------------------------------ helpers --

/// One proxy over one mock provider, with a key and, where model policy is
/// enforced, an all-models policy for each tenant.
struct Run {
    dir: PathBuf,
    upstream: MockProvider,
    proxy: Option<Proxy>,
    key_a: String,
    key_b: String,
}

impl Run {
    fn start(tag: &str, auth_extra: &str) -> Run {
        let upstream = MockProvider::spawn();
        let config = config_text(upstream.addr, auth_extra);
        Run::start_with(scratch_dir(tag), upstream, &config, None)
    }

    /// `node` is the replica's `--service-node`, which a shared store needs.
    fn start_with(dir: PathBuf, upstream: MockProvider, config: &str, node: Option<&str>) -> Run {
        let proxy = Proxy::start(&dir, config, node);
        let key_a = mint_key(&proxy, TENANT_A, "key-a");
        let key_b = mint_key(&proxy, TENANT_B, "key-b");
        // With model policy off the admin API refuses a policy (409): there
        // is nothing to grant.
        let policies = !config.contains("model_policy: false");
        for tenant in [TENANT_A, TENANT_B].into_iter().filter(|_| policies) {
            admin(
                &proxy,
                "PUT",
                &format!("/tenants/{tenant}/policy"),
                r#"{"access":"all"}"#,
                "204",
            );
        }
        Run {
            dir,
            upstream,
            proxy: Some(proxy),
            key_a,
            key_b,
        }
    }

    fn proxy(&self) -> &Proxy {
        self.proxy.as_ref().expect("a running proxy")
    }

    /// Assigns an object no tenant owns to `tenant` over the admin API.
    fn assign(&self, tenant: &str, object: &str) {
        admin(
            self.proxy(),
            "PUT",
            &format!("/tenants/{tenant}/objects/{object}"),
            "",
            "204",
        );
    }

    /// Waits, at most [`STORE_WAIT`], until the store records `tenant` as
    /// the owner of `object`, as the admin API reads it.
    fn wait_until_stored(&self, tenant: &str, object: &str) {
        let deadline = std::time::Instant::now() + STORE_WAIT;
        let path = format!("/tenants/{tenant}/objects/{object}");
        loop {
            let response = http_request(
                "GET",
                self.proxy().admin,
                &path,
                ADMIN_TOKEN,
                "application/json",
                "",
            );
            if response.starts_with("HTTP/1.1 200") {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the owner of {object} never reached the store:\n{response}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn create_file(&self, key: &str) {
        let response = http_request(
            "POST",
            self.proxy().listen,
            "/v1/files",
            key,
            "multipart/form-data; boundary=b",
            "--b\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nbatch\r\n--b--\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "file create:\n{response}"
        );
        assert_eq!(self.upstream.take(), ["POST /v1/files"]);
    }

    fn create_batch(&self, key: &str) {
        let body = format!(
            r#"{{"model":"gpt-4o-mini","input_file_id":"{FILE_ID}","endpoint":"/v1/chat/completions","completion_window":"24h"}}"#
        );
        self.assert_served("POST", "/v1/batches", key, &body, "batch create");
    }

    /// 404 with no provider ID in the body, and nothing reached the provider.
    fn assert_refused(&self, method: &str, path: &str, key: &str, body: &str, who: &str) {
        let response = http_request(
            method,
            self.proxy().listen,
            path,
            key,
            "application/json",
            body,
        );
        let reached = self.upstream.take();
        assert!(
            response.starts_with("HTTP/1.1 404"),
            "{who}: {method} {path} must be 404:\n{response}"
        );
        assert!(
            reached.is_empty(),
            "{who}: {method} {path} must not reach the provider, which saw {reached:?}"
        );
        for id in [FILE_ID, BATCH_ID, OUTPUT_FILE_ID] {
            assert!(
                !response_body(&response).contains(id),
                "{who}: {method} {path} leaked {id}:\n{response}"
            );
        }
    }

    /// 200 from the provider, which saw exactly this request.
    fn assert_served(&self, method: &str, path: &str, key: &str, body: &str, who: &str) {
        let response = http_request(
            method,
            self.proxy().listen,
            path,
            key,
            "application/json",
            body,
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "{who}: {method} {path} must be served:\n{response}"
        );
        assert_eq!(self.upstream.take(), [format!("{method} {path}")], "{who}");
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        self.proxy = None;
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn config_text(upstream: SocketAddr, auth_extra: &str) -> String {
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
  hmac_secret: "{HMAC_SECRET}"
{auth_extra}"#,
        listen = free_port(),
        admin = free_port(),
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-tenant-object-ownership-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// A running proxy. Killed and reaped on drop, so a failed assertion cannot
/// leave a listener behind (AGENTS.md "Running The Product"). Its stderr
/// goes to `stderr.log` in its directory.
struct Proxy {
    child: Child,
    listen: SocketAddr,
    admin: SocketAddr,
}

impl Proxy {
    fn start(dir: &Path, config: &str, node: Option<&str>) -> Proxy {
        let listen = port_after(config, "listen: 127.0.0.1:");
        let admin = port_after(config, "admin: 127.0.0.1:");
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).expect("write temp config");
        let stderr = std::fs::File::create(dir.join("stderr.log")).expect("stderr log");
        let mut command = Command::new(BIN);
        command.args([
            "--config",
            path.to_str().expect("utf-8 path"),
            "--concurrency",
            "1",
        ]);
        if let Some(node) = node {
            command.args(["--service-node", node]);
        }
        let child = command
            .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::null())
            .stderr(stderr)
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
        .expect("listener port parses")
}

/// `POST /keys` for `key_id` on `tenant`; returns the plaintext key.
fn mint_key(proxy: &Proxy, tenant: &str, key_id: &str) -> String {
    let response = admin(
        proxy,
        "POST",
        "/keys",
        &format!(r#"{{"tenant":"{tenant}","key_id":"{key_id}"}}"#),
        "201",
    );
    let parsed: serde_json::Value =
        serde_json::from_str(response_body(&response)).expect("POST /keys returns JSON");
    parsed["key"].as_str().expect("plaintext key").to_string()
}

/// An admin request that must answer `status`.
fn admin(proxy: &Proxy, method: &str, path: &str, body: &str, status: &str) -> String {
    let response = http_request(
        method,
        proxy.admin,
        path,
        ADMIN_TOKEN,
        "application/json",
        body,
    );
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status}")),
        "{method} {path}:\n{response}"
    );
    response
}

fn response_body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, b)| b)
}

fn http_request(
    method: &str,
    addr: SocketAddr,
    path: &str,
    bearer: &str,
    content_type: &str,
    body: &str,
) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: proxy.local\r\n\
                 Authorization: Bearer {bearer}\r\n\
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

/// A mock provider with one account every tenant shares: it records
/// `METHOD path` for every request and answers creates with the fixed IDs,
/// a batch read with the completed batch, lists with every ID, and anything
/// else with a bare object.
struct MockProvider {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
}

impl MockProvider {
    fn spawn() -> MockProvider {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
        let addr = listener.local_addr().expect("no local addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let log = Arc::clone(&log);
                std::thread::spawn(move || serve(stream, &log));
            }
        });
        MockProvider { addr, seen }
    }

    /// Requests seen since the last call. The mock records a request before
    /// it answers, and the proxy answers only after the provider does, so a
    /// dialled request is already recorded.
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.seen.lock().expect("mock log"))
    }
}

fn serve(mut stream: TcpStream, log: &Mutex<Vec<String>>) {
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
    let request_line = head.lines().next().unwrap_or("").to_string();
    let content_length: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().to_string())
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut have = raw.len() - (head_end + 4);
    while have < content_length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => have += n,
        }
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    log.lock()
        .expect("mock log")
        .push(format!("{method} {path}"));
    let batch = format!("/v1/batches/{BATCH_ID}");
    let body = match (method.as_str(), path.as_str()) {
        ("POST", "/v1/files") => format!(r#"{{"id":"{FILE_ID}","object":"file"}}"#),
        ("POST", "/v1/batches") => format!(
            r#"{{"id":"{BATCH_ID}","object":"batch","input_file_id":"{FILE_ID}","output_file_id":null}}"#
        ),
        ("GET", p) if p == batch => format!(
            r#"{{"id":"{BATCH_ID}","object":"batch","status":"completed","input_file_id":"{FILE_ID}","output_file_id":"{OUTPUT_FILE_ID}"}}"#
        ),
        ("GET", "/v1/files") => format!(
            r#"{{"object":"list","data":[{{"id":"{FILE_ID}"}},{{"id":"{OUTPUT_FILE_ID}"}}]}}"#
        ),
        ("GET", "/v1/batches") => {
            format!(r#"{{"object":"list","data":[{{"id":"{BATCH_ID}"}}]}}"#)
        }
        _ => r#"{"object":"probe"}"#.to_string(),
    };
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
}
