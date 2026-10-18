//! Provider objects outside `/v1/files` and the batch endpoints, which
//! `llmproxy.object_ownership` does not cover yet. Every tenant reaches the
//! provider through the proxy's one provider account, so these IDs share one
//! namespace too: tenant B can read, change or delete tenant A's response,
//! stored completion, upload, vector store, fine-tuning job, assistant,
//! thread, container and conversation, or feed them to a model by reference.
//!
//! Each test states the behavior that keeps tenants apart: tenant B is
//! refused before the provider is dialled, and tenant A still reaches its own
//! objects. They are ignored because the proxy does not do that yet; run
//! them with `--run-ignored only` to reproduce the leaks. Each one reports
//! every request that got through, not only the first.
//!
//! Every probe carries a granted `model` in a JSON body, so a refusal cannot
//! come from `llmproxy.model_authz` for want of a model (see
//! `tenant_object_ownership_e2e.rs`).
//!
//! Rust note: the harness is the one in `tenant_object_ownership_e2e.rs`
//! (std threads, ephemeral ports, a `Drop` that kills the proxy); integration
//! test files do not share modules here.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const HMAC_SECRET: &str = "tenant-object-reach-e2e-secret";
const ADMIN_TOKEN: &str = "tenant-object-reach-e2e-admin-token";
const TENANT_A: &str = "tenant-a";
const TENANT_B: &str = "tenant-b";
const MODEL: &str = "gpt-4o-mini";
const MODEL_BODY: &str = r#"{"model":"gpt-4o-mini"}"#;

// Tenant A's objects, as the mock provider issues them.
const FILE_ID: &str = "file-owned-by-a";
const RESPONSE_ID: &str = "resp_a";
const STREAMED_RESPONSE_ID: &str = "resp_a_streamed";
const COMPLETION_ID: &str = "chatcmpl-a";
const UPLOAD_ID: &str = "upload_a";
/// The file a completed upload creates, nested at `file.id`.
const UPLOADED_FILE_ID: &str = "file-from-upload-a";
const VECTOR_STORE_ID: &str = "vs_a";
const FINE_TUNE_ID: &str = "ftjob-a";
/// The model and result file a finished fine-tuning job names.
const FINE_TUNED_MODEL: &str = "ft:gpt-4o-mini:org::a";
const RESULT_FILE_ID: &str = "file-ft-result-a";
const ASSISTANT_ID: &str = "asst_a";
const THREAD_ID: &str = "thread_a";
const CONTAINER_ID: &str = "cntr_a";
const CONVERSATION_ID: &str = "conv_a";

/// Responses, and every way to reach one: by path, and by
/// `previous_response_id`. One is created as JSON and one as an SSE stream,
/// whose ID arrives in the first event. `/v1/responses/input_tokens` is a
/// sibling endpoint, not a response ID, and must stay open to the owner.
#[test]
#[ignore = "reproduces an open cross-tenant leak: run with --run-ignored only"]
fn another_tenants_responses_are_refused() {
    let run = Run::start("responses");
    run.create(
        "/v1/responses",
        &run.key_a,
        &format!(r#"{{"model":"{MODEL}","input":"hi"}}"#),
    );
    run.create(
        "/v1/responses",
        &run.key_a,
        &format!(r#"{{"model":"{MODEL}","input":"hi","stream":true}}"#),
    );
    let mut probes = Vec::new();
    for id in [RESPONSE_ID, STREAMED_RESPONSE_ID] {
        probes.extend([
            get(format!("/v1/responses/{id}")),
            get(format!("/v1/responses/{id}/input_items")),
            post(format!("/v1/responses/{id}/cancel"), MODEL_BODY.into()),
            post(
                "/v1/responses".into(),
                format!(r#"{{"model":"{MODEL}","input":"and?","previous_response_id":"{id}"}}"#),
            ),
            delete(format!("/v1/responses/{id}")),
        ]);
    }
    run.verdict(
        &probes,
        &[
            get(format!("/v1/responses/{RESPONSE_ID}")),
            get(format!("/v1/responses/{STREAMED_RESPONSE_ID}")),
            post(
                "/v1/responses".into(),
                format!(
                    r#"{{"model":"{MODEL}","input":"and?","previous_response_id":"{RESPONSE_ID}"}}"#
                ),
            ),
            post(
                "/v1/responses/input_tokens".into(),
                format!(r#"{{"model":"{MODEL}","input":"x"}}"#),
            ),
        ],
    );
}

/// Chat completions created with `store: true` are listed, read, updated
/// and deleted under the same path that creates them.
#[test]
#[ignore = "reproduces an open cross-tenant leak: run with --run-ignored only"]
fn another_tenants_stored_chat_completions_are_refused() {
    let run = Run::start("chat-completions");
    run.create(
        "/v1/chat/completions",
        &run.key_a,
        &format!(
            r#"{{"model":"{MODEL}","store":true,"messages":[{{"role":"user","content":"hi"}}]}}"#
        ),
    );
    let id = COMPLETION_ID;
    run.verdict(
        &[
            get("/v1/chat/completions".into()),
            get(format!("/v1/chat/completions/{id}")),
            get(format!("/v1/chat/completions/{id}/messages")),
            post(
                format!("/v1/chat/completions/{id}"),
                format!(r#"{{"model":"{MODEL}","metadata":{{"k":"v"}}}}"#),
            ),
            delete(format!("/v1/chat/completions/{id}")),
        ],
        &[get(format!("/v1/chat/completions/{id}"))],
    );
}

/// An upload is driven by part, complete and cancel calls on its ID, and
/// the completed upload creates a file whose ID is nested at `file.id`. The
/// owner must reach that file; tenant B must not.
#[test]
#[ignore = "reproduces an open cross-tenant leak: run with --run-ignored only"]
fn another_tenants_uploads_are_refused_and_the_completed_file_is_the_owners() {
    let run = Run::start("uploads");
    run.create("/v1/uploads",
        &run.key_a,
        &format!(
            r#"{{"model":"{MODEL}","purpose":"batch","filename":"a.jsonl","bytes":1,"mime_type":"text/jsonl"}}"#
        ),
    );
    let id = UPLOAD_ID;
    let complete = post(
        format!("/v1/uploads/{id}/complete"),
        format!(r#"{{"model":"{MODEL}","part_ids":["part_a"]}}"#),
    );
    run.verdict(
        &[
            post(format!("/v1/uploads/{id}/parts"), MODEL_BODY.into()),
            complete.clone(),
            post(format!("/v1/uploads/{id}/cancel"), MODEL_BODY.into()),
            get(format!("/v1/files/{UPLOADED_FILE_ID}/content")),
        ],
        &[
            complete,
            get(format!("/v1/files/{UPLOADED_FILE_ID}")),
            get(format!("/v1/files/{UPLOADED_FILE_ID}/content")),
        ],
    );
}

/// Vector stores by path, and by `vector_store_ids` in a request that
/// attaches a store to a model.
#[test]
#[ignore = "reproduces an open cross-tenant leak: run with --run-ignored only"]
fn another_tenants_vector_stores_are_refused() {
    let run = Run::start("vector-stores");
    run.create("/v1/vector_stores", &run.key_a, MODEL_BODY);
    let id = VECTOR_STORE_ID;
    let search = format!(
        r#"{{"model":"{MODEL}","input":"q","tools":[{{"type":"file_search","vector_store_ids":["{id}"]}}]}}"#
    );
    run.verdict(
        &[
            get("/v1/vector_stores".into()),
            get(format!("/v1/vector_stores/{id}")),
            post(format!("/v1/vector_stores/{id}"), MODEL_BODY.into()),
            post(
                format!("/v1/vector_stores/{id}/search"),
                format!(r#"{{"model":"{MODEL}","query":"q"}}"#),
            ),
            get(format!("/v1/vector_stores/{id}/files")),
            post(format!("/v1/vector_stores/{id}/file_batches"), MODEL_BODY.into()),
            delete(format!("/v1/vector_stores/{id}")),
            post("/v1/responses".into(), search.clone()),
            post(
                "/v1/assistants".into(),
                format!(
                    r#"{{"model":"{MODEL}","tool_resources":{{"file_search":{{"vector_store_ids":["{id}"]}}}}}}"#
                ),
            ),
        ],
        &[get(format!("/v1/vector_stores/{id}")), post("/v1/responses".into(), search)],
    );
}

/// Fine-tuning jobs by path; another tenant's file by `training_file`; and
/// the job's outputs: its result file belongs to the job's owner, and so
/// does the model it produced.
#[test]
#[ignore = "reproduces an open cross-tenant leak: run with --run-ignored only"]
fn another_tenants_fine_tuning_jobs_are_refused() {
    let run = Run::start("fine-tuning");
    run.assign(TENANT_A, FILE_ID);
    run.create(
        "/v1/fine_tuning/jobs",
        &run.key_a,
        &format!(r#"{{"model":"{MODEL}","training_file":"{FILE_ID}"}}"#),
    );
    let id = FINE_TUNE_ID;
    run.verdict(
        &[
            get("/v1/fine_tuning/jobs".into()),
            get(format!("/v1/fine_tuning/jobs/{id}")),
            get(format!("/v1/fine_tuning/jobs/{id}/events")),
            get(format!("/v1/fine_tuning/jobs/{id}/checkpoints")),
            post(format!("/v1/fine_tuning/jobs/{id}/cancel"), MODEL_BODY.into()),
            post(
                "/v1/fine_tuning/jobs".into(),
                format!(r#"{{"model":"{MODEL}","training_file":"{FILE_ID}"}}"#),
            ),
            get(format!("/v1/files/{RESULT_FILE_ID}/content")),
            post(
                "/v1/chat/completions".into(),
                format!(r#"{{"model":"{FINE_TUNED_MODEL}","messages":[{{"role":"user","content":"hi"}}]}}"#),
            ),
        ],
        // Reading the job comes first: it is what names the result file.
        &[
            get(format!("/v1/fine_tuning/jobs/{id}")),
            get(format!("/v1/files/{RESULT_FILE_ID}/content")),
        ],
    );
}

/// Assistants and threads by path, and by `assistant_id` in a run.
/// `/v1/threads/runs` creates a thread and runs it; `runs` is not a thread
/// ID, and the owner must still reach it.
#[test]
#[ignore = "reproduces an open cross-tenant leak: run with --run-ignored only"]
fn another_tenants_assistants_and_threads_are_refused() {
    let run = Run::start("assistants");
    run.create("/v1/assistants", &run.key_a, MODEL_BODY);
    run.create("/v1/threads", &run.key_a, MODEL_BODY);
    let (asst, thread) = (ASSISTANT_ID, THREAD_ID);
    let run_with = format!(r#"{{"model":"{MODEL}","assistant_id":"{asst}"}}"#);
    run.verdict(
        &[
            get("/v1/assistants".into()),
            get(format!("/v1/assistants/{asst}")),
            post(format!("/v1/assistants/{asst}"), MODEL_BODY.into()),
            delete(format!("/v1/assistants/{asst}")),
            get(format!("/v1/threads/{thread}")),
            get(format!("/v1/threads/{thread}/messages")),
            post(format!("/v1/threads/{thread}/messages"), MODEL_BODY.into()),
            post(format!("/v1/threads/{thread}/runs"), run_with.clone()),
            delete(format!("/v1/threads/{thread}")),
            post("/v1/threads/runs".into(), run_with.clone()),
        ],
        &[
            get(format!("/v1/assistants/{asst}")),
            get(format!("/v1/threads/{thread}/messages")),
            post(format!("/v1/threads/{thread}/runs"), run_with.clone()),
            post("/v1/threads/runs".into(), run_with),
        ],
    );
}

/// Containers by path, and by `container` in a code interpreter tool.
#[test]
#[ignore = "reproduces an open cross-tenant leak: run with --run-ignored only"]
fn another_tenants_containers_are_refused() {
    let run = Run::start("containers");
    run.create("/v1/containers", &run.key_a, MODEL_BODY);
    let id = CONTAINER_ID;
    let tool = format!(
        r#"{{"model":"{MODEL}","input":"run","tools":[{{"type":"code_interpreter","container":"{id}"}}]}}"#
    );
    run.verdict(
        &[
            get("/v1/containers".into()),
            get(format!("/v1/containers/{id}")),
            get(format!("/v1/containers/{id}/files")),
            get(format!("/v1/containers/{id}/files/cfile_1/content")),
            delete(format!("/v1/containers/{id}")),
            post("/v1/responses".into(), tool.clone()),
        ],
        &[
            get(format!("/v1/containers/{id}/files")),
            post("/v1/responses".into(), tool),
        ],
    );
}

/// Conversations by path, and by `conversation` in a response request.
#[test]
#[ignore = "reproduces an open cross-tenant leak: run with --run-ignored only"]
fn another_tenants_conversations_are_refused() {
    let run = Run::start("conversations");
    run.create("/v1/conversations", &run.key_a, MODEL_BODY);
    let id = CONVERSATION_ID;
    let respond = format!(r#"{{"model":"{MODEL}","input":"and?","conversation":"{id}"}}"#);
    run.verdict(
        &[
            get(format!("/v1/conversations/{id}")),
            get(format!("/v1/conversations/{id}/items")),
            post(format!("/v1/conversations/{id}/items"), MODEL_BODY.into()),
            delete(format!("/v1/conversations/{id}")),
            post("/v1/responses".into(), respond.clone()),
        ],
        &[
            get(format!("/v1/conversations/{id}/items")),
            post("/v1/responses".into(), respond),
        ],
    );
}

// ------------------------------------------------------------------ helpers --

/// One request: method, path, JSON body.
#[derive(Clone)]
struct Probe(&'static str, String, String);

fn get(path: String) -> Probe {
    Probe("GET", path, MODEL_BODY.into())
}

fn delete(path: String) -> Probe {
    Probe("DELETE", path, MODEL_BODY.into())
}

fn post(path: String, body: String) -> Probe {
    Probe("POST", path, body)
}

/// One proxy over one mock provider, with a key and an all-models policy for
/// each tenant.
struct Run {
    dir: PathBuf,
    upstream: MockProvider,
    proxy: Proxy,
    key_a: String,
    key_b: String,
}

impl Run {
    fn start(tag: &str) -> Run {
        let upstream = MockProvider::spawn();
        let dir = scratch_dir(tag);
        let proxy = Proxy::start(&dir, &config_text(upstream.addr));
        let key_a = mint_key(&proxy, TENANT_A, "key-a");
        let key_b = mint_key(&proxy, TENANT_B, "key-b");
        for tenant in [TENANT_A, TENANT_B] {
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
            proxy,
            key_a,
            key_b,
        }
    }

    /// Assigns an object no tenant owns to `tenant` over the admin API.
    fn assign(&self, tenant: &str, object: &str) {
        admin(
            &self.proxy,
            "PUT",
            &format!("/tenants/{tenant}/objects/{object}"),
            "",
            "204",
        );
    }

    /// A create (a POST) by tenant A that must reach the provider and succeed.
    fn create(&self, path: &str, key: &str, body: &str) {
        let (status, reached) = self.send(&Probe("POST", path.into(), body.into()), key);
        assert!(
            status.starts_with("HTTP/1.1 200") && reached == [format!("POST {path}")],
            "A's create POST {path} must be served: {status}; provider saw {reached:?}"
        );
    }

    fn send(&self, probe: &Probe, key: &str) -> (String, Vec<String>) {
        let Probe(method, path, body) = probe;
        let response = http_request(method, self.proxy.listen, path, key, body);
        let status = response.lines().next().unwrap_or("").to_string();
        (status, self.upstream.take())
    }

    /// Tenant A's `owner` requests run first and must be served; then each of
    /// tenant B's `probes` must get 404 without reaching the provider. Fails
    /// once, listing every request that went the wrong way.
    fn verdict(&self, probes: &[Probe], owner: &[Probe]) {
        let mut wrong = Vec::new();
        for probe in owner {
            let (status, reached) = self.send(probe, &self.key_a);
            if !status.starts_with("HTTP/1.1 200") || reached.is_empty() {
                wrong.push(format!(
                    "A {} {} not served: {status}; provider saw {reached:?}",
                    probe.0, probe.1
                ));
            }
        }
        for probe in probes {
            let (status, reached) = self.send(probe, &self.key_b);
            if !status.starts_with("HTTP/1.1 404") || !reached.is_empty() {
                wrong.push(format!(
                    "B {} {} {}: {status}; provider saw {reached:?}",
                    probe.0,
                    probe.1,
                    if probe.2 == MODEL_BODY { "" } else { &probe.2 }
                ));
            }
        }
        assert!(wrong.is_empty(), "\n{}\n", wrong.join("\n"));
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        self.proxy.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn config_text(upstream: SocketAddr) -> String {
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
  hmac_secret: "{HMAC_SECRET}"
"#,
        listen = free_port(),
        admin = free_port(),
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-tenant-object-reach-e2e-{tag}-{}",
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
}

impl Proxy {
    fn start(dir: &Path, config: &str) -> Proxy {
        let listen = port_after(config, "listen: 127.0.0.1:");
        let admin = port_after(config, "admin: 127.0.0.1:");
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).expect("write temp config");
        let stderr = std::fs::File::create(dir.join("stderr.log")).expect("stderr log");
        let child = Command::new(BIN)
            .args([
                "--config",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
            ])
            .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .expect("failed to spawn llm-proxy");
        let mut proxy = Proxy {
            child,
            listen: SocketAddr::from(([127, 0, 0, 1], listen)),
            admin: SocketAddr::from(([127, 0, 0, 1], admin)),
        };
        for addr in [proxy.admin, proxy.listen] {
            if !wait_for_connectable(addr, STARTUP_TIMEOUT) {
                proxy.stop();
                panic!("listener at {addr} did not become connectable in time");
            }
        }
        proxy
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop();
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
    let body = response.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    let parsed: serde_json::Value = serde_json::from_str(body).expect("POST /keys returns JSON");
    parsed["key"].as_str().expect("plaintext key").to_string()
}

/// An admin request that must answer `status`.
fn admin(proxy: &Proxy, method: &str, path: &str, body: &str, status: &str) -> String {
    let response = http_request(method, proxy.admin, path, ADMIN_TOKEN, body);
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status}")),
        "{method} {path}:\n{response}"
    );
    response
}

fn http_request(method: &str, addr: SocketAddr, path: &str, bearer: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: proxy.local\r\n\
                 Authorization: Bearer {bearer}\r\n\
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

/// A mock provider with one account every tenant shares. It records
/// `METHOD path` for every request, answers each create with tenant A's
/// fixed ID in the shape that endpoint returns it, and anything else with a
/// bare object.
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

/// The JSON response a create returns, or for a read that names derived
/// objects, the read's response.
fn json_answer(method: &str, path: &str) -> Option<String> {
    let usage = r#""usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}"#;
    let body = match (method, path) {
        ("POST", "/v1/responses") => format!(
            r#"{{"id":"{RESPONSE_ID}","object":"response","status":"completed","output":[],"usage":{{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}}"#
        ),
        ("POST", "/v1/chat/completions") => format!(
            r#"{{"id":"{COMPLETION_ID}","object":"chat.completion","model":"{MODEL}","choices":[],{usage}}}"#
        ),
        ("POST", "/v1/uploads") => {
            format!(r#"{{"id":"{UPLOAD_ID}","object":"upload","status":"pending"}}"#)
        }
        ("POST", p) if p == format!("/v1/uploads/{UPLOAD_ID}/complete") => format!(
            r#"{{"id":"{UPLOAD_ID}","object":"upload","status":"completed","file":{{"id":"{UPLOADED_FILE_ID}","object":"file"}}}}"#
        ),
        ("POST", "/v1/vector_stores") => {
            format!(r#"{{"id":"{VECTOR_STORE_ID}","object":"vector_store"}}"#)
        }
        ("POST", "/v1/fine_tuning/jobs") => format!(
            r#"{{"id":"{FINE_TUNE_ID}","object":"fine_tuning.job","status":"queued","training_file":"{FILE_ID}","fine_tuned_model":null,"result_files":[]}}"#
        ),
        ("GET", p) if p == format!("/v1/fine_tuning/jobs/{FINE_TUNE_ID}") => format!(
            r#"{{"id":"{FINE_TUNE_ID}","object":"fine_tuning.job","status":"succeeded","training_file":"{FILE_ID}","fine_tuned_model":"{FINE_TUNED_MODEL}","result_files":["{RESULT_FILE_ID}"]}}"#
        ),
        ("POST", "/v1/assistants") => {
            format!(r#"{{"id":"{ASSISTANT_ID}","object":"assistant"}}"#)
        }
        ("POST", "/v1/threads") => format!(r#"{{"id":"{THREAD_ID}","object":"thread"}}"#),
        ("POST", "/v1/containers") => {
            format!(r#"{{"id":"{CONTAINER_ID}","object":"container"}}"#)
        }
        ("POST", "/v1/conversations") => {
            format!(r#"{{"id":"{CONVERSATION_ID}","object":"conversation"}}"#)
        }
        _ => return None,
    };
    Some(body)
}

/// A streamed response's events: the ID is in the first one.
fn streamed_response() -> String {
    let created = format!(
        r#"{{"type":"response.created","response":{{"id":"{STREAMED_RESPONSE_ID}","object":"response","status":"in_progress"}}}}"#
    );
    let completed = format!(
        r#"{{"type":"response.completed","response":{{"id":"{STREAMED_RESPONSE_ID}","object":"response","status":"completed","usage":{{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}}}}"#
    );
    format!(
        "event: response.created\ndata: {created}\n\n\
         event: response.completed\ndata: {completed}\n\n"
    )
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
    let mut body = raw[head_end + 4..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&buf[..n]),
        }
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    log.lock()
        .expect("mock log")
        .push(format!("{method} {path}"));
    let streamed = String::from_utf8_lossy(&body).contains(r#""stream":true"#);
    let (content_type, answer) = if streamed && method == "POST" && path == "/v1/responses" {
        ("text/event-stream", streamed_response())
    } else {
        (
            "application/json",
            json_answer(&method, &path).unwrap_or_else(|| r#"{"object":"probe"}"#.to_string()),
        )
    };
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{answer}",
            answer.len()
        )
        .as_bytes(),
    );
}
