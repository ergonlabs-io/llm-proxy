//! Realtime (WebSocket) sessions through the real `llm-proxy` binary and the
//! `--config` dialect's `realtime` block (ADR-0015): the listener's filter
//! chain decides at upgrade time, the session is metered from its
//! `response.done` events and logged once at its close, a concurrent-session
//! limit holds its slot for the session's life, and drain closes an open
//! session with code 1001.
//!
//! The mock provider speaks just enough RFC 6455 to play a realtime server:
//! it answers each client text frame with `response.created` and a
//! `response.done` carrying usage, and answers a Close with a Close.
//!
//! Rust note: same harness shape as `tests/unmetered_endpoint_e2e.rs` (std
//! threads, ephemeral ports, a `Drop` that kills the proxy). Every wait is
//! bounded, so a hung child fails the test instead of stalling it.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

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

const HMAC_SECRET: &str = "realtime-e2e-secret";
const ADMIN_TOKEN: &str = "realtime-e2e-admin-token";
const TENANT: &str = "t1";
const KEY_ID: &str = "minted-1";
const PROVIDER_KEY: &str = "sk-upstream-provider-key";
/// The client-facing model and the provider's own name for it.
const MODEL: &str = "voice";
const UPSTREAM_MODEL: &str = "gpt-realtime-2026";

/// The usage the mock reports per response: 10 input tokens (6 audio) and
/// 5 output tokens (3 audio).
const DONE: &str = r#"{"type":"response.done","response":{"status":"completed","usage":{"total_tokens":15,"input_tokens":10,"output_tokens":5,"input_token_details":{"text_tokens":4,"audio_tokens":6},"output_token_details":{"text_tokens":2,"audio_tokens":3}}}}"#;
/// `DONE` at the rate card in `config_text`: 4 * 1000 + 6 * 4000 input,
/// 2 * 2000 + 3 * 8000 output, in nanodollars. Example values.
const DONE_NANODOLLARS: u64 = 4 * 1000 + 6 * 4000 + 2 * 2000 + 3 * 8000;

/// A session is admitted at upgrade time, the provider sees its own model
/// and key (never the client's), the session counts as one active request
/// until it closes, and its one access-log line, written at the close,
/// carries the summed usage and its cost at the audio rates.
#[test]
fn a_realtime_session_is_metered_from_its_events_and_logged_at_its_close() {
    let dir = scratch_dir("metered");
    let upstream = RealtimeUpstream::spawn();
    let proxy = Proxy::start(&dir, &config_text(&dir, upstream.addr, ""));
    let key = mint_key(&proxy);
    create_tenant(&proxy);
    put_ok(
        &proxy,
        &format!("/tenants/{TENANT}/policy"),
        r#"{"access":"all"}"#,
    );
    put_ok(
        &proxy,
        &format!("/tenants/{TENANT}/budget"),
        r#"{"budget":{"max_usd":"100","period":"daily"}}"#,
    );

    let mut session = Ws::open(&proxy, Some(&key), MODEL).expect("session admitted");
    assert_eq!(session.read_event()["type"], "session.created");
    for _ in 0..2 {
        session.send_text(r#"{"type":"response.create"}"#);
        assert_eq!(session.read_event()["type"], "response.created");
        assert_eq!(session.read_event()["type"], "response.done");
    }
    assert!(
        scrape(&proxy).contains("envoy_downstream_rq_active{scope=\"llmproxy\"} 1"),
        "an open session is an active request (envoy-divergences.md row 39)"
    );
    assert!(
        access_log(&dir).is_empty(),
        "nothing is logged while the session is open"
    );

    session.close();
    let entry = wait_for_entry(&dir, |entry| entry["response_code"] == "101");
    assert_eq!(entry["llm_input_tokens"], "20", "{entry}");
    assert_eq!(entry["llm_output_tokens"], "10", "{entry}");
    assert_eq!(entry["llm_input_audio_tokens"], "12", "{entry}");
    assert_eq!(entry["llm_output_audio_tokens"], "6", "{entry}");
    assert_eq!(entry["llm_usage_completeness"], "complete", "{entry}");
    assert_eq!(entry["llm_requested_model"], MODEL, "{entry}");
    assert_eq!(entry["llm_selected_model"], UPSTREAM_MODEL, "{entry}");
    assert_eq!(
        entry["llm_list_cost_nanodollars"],
        (2 * DONE_NANODOLLARS).to_string(),
        "{entry}"
    );

    let heads = upstream.heads();
    assert_eq!(heads.len(), 1);
    let head = &heads[0];
    assert!(
        head.starts_with(&format!("get /v1/realtime?model={UPSTREAM_MODEL} ")),
        "the provider is asked for its own model:\n{head}"
    );
    assert!(
        head.contains(&format!("authorization: bearer {PROVIDER_KEY}")),
        "{head}"
    );
    assert!(
        !head.contains(&key.to_ascii_lowercase()),
        "client key leaked:\n{head}"
    );
    assert!(
        !head.contains("sec-websocket-extensions"),
        "the compression offer is removed:\n{head}"
    );
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The negative test: an upgrade without credentials, or for a model the
/// tenant may not use, is refused with an HTTP status at upgrade time and
/// never reaches the provider.
#[test]
fn a_refused_upgrade_never_reaches_the_provider() {
    let dir = scratch_dir("refused");
    let upstream = RealtimeUpstream::spawn();
    let proxy = Proxy::start(&dir, &config_text(&dir, upstream.addr, ""));
    let key = mint_key(&proxy);
    create_tenant(&proxy);
    put_ok(
        &proxy,
        &format!("/tenants/{TENANT}/policy"),
        r#"{"access":{"only":["some-other-model"]}}"#,
    );

    let no_key = Ws::open(&proxy, None, MODEL).expect_err("no credentials");
    assert!(no_key.starts_with("HTTP/1.1 401"), "{no_key}");
    let bad_key = Ws::open(&proxy, Some("llmp_not-a-key"), MODEL).expect_err("unknown key");
    assert!(bad_key.starts_with("HTTP/1.1 401"), "{bad_key}");
    let disallowed = Ws::open(&proxy, Some(&key), MODEL).expect_err("disallowed model");
    assert!(disallowed.starts_with("HTTP/1.1 403"), "{disallowed}");
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        upstream.heads().is_empty(),
        "no refusal reached the provider"
    );
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `limits[].concurrent_sessions` holds a slot for the session's whole life:
/// the session over the limit is refused with 429 before it is dialled, and
/// a slot frees when a session closes.
#[test]
fn a_concurrent_session_limit_refuses_the_session_over_it() {
    let dir = scratch_dir("limit");
    let upstream = RealtimeUpstream::spawn();
    let proxy = Proxy::start(
        &dir,
        &config_text(
            &dir,
            upstream.addr,
            "limits:\n  - { key: global, concurrent_sessions: 1 }\n",
        ),
    );
    let key = mint_key(&proxy);
    create_tenant(&proxy);
    put_ok(
        &proxy,
        &format!("/tenants/{TENANT}/policy"),
        r#"{"access":"all"}"#,
    );

    let mut first = Ws::open(&proxy, Some(&key), MODEL).expect("first session");
    assert_eq!(first.read_event()["type"], "session.created");
    let over = Ws::open(&proxy, Some(&key), MODEL).expect_err("over the limit");
    assert!(over.starts_with("HTTP/1.1 429"), "{over}");
    assert_eq!(
        upstream.heads().len(),
        1,
        "the refused session was not dialled"
    );

    first.close();
    // The slot is released when the closed session's stream completes.
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut again = loop {
        match Ws::open(&proxy, Some(&key), MODEL) {
            Ok(session) => break session,
            Err(head) if head.starts_with("HTTP/1.1 429") && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(head) => panic!("the slot was not released:\n{head}"),
        }
    };
    assert_eq!(again.read_event()["type"], "session.created");
    again.close();
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// SIGTERM starts the drain: an open session gets a Close frame with code
/// 1001 instead of a reset at the drain deadline, and is still logged once,
/// with what it used.
#[test]
fn drain_closes_an_open_session_with_1001() {
    let dir = scratch_dir("drain");
    let upstream = RealtimeUpstream::spawn();
    let mut proxy = Proxy::start(&dir, &config_text(&dir, upstream.addr, ""));
    let key = mint_key(&proxy);
    create_tenant(&proxy);
    put_ok(
        &proxy,
        &format!("/tenants/{TENANT}/policy"),
        r#"{"access":"all"}"#,
    );

    let mut session = Ws::open(&proxy, Some(&key), MODEL).expect("session admitted");
    assert_eq!(session.read_event()["type"], "session.created");
    session.send_text(r#"{"type":"response.create"}"#);
    assert_eq!(session.read_event()["type"], "response.created");
    assert_eq!(session.read_event()["type"], "response.done");

    proxy.sigterm();
    let (opcode, payload) = session.read_frame();
    assert_eq!(opcode, 0x8, "a Close frame");
    assert_eq!(
        &payload[..2],
        &1001u16.to_be_bytes(),
        "code 1001, going away"
    );
    session.close_after_server_close();

    let entry = wait_for_entry(&dir, |entry| entry["response_code"] == "101");
    assert_eq!(entry["llm_input_tokens"], "10", "{entry}");
    assert_eq!(
        entry["llm_list_cost_nanodollars"],
        DONE_NANODOLLARS.to_string(),
        "{entry}"
    );
    assert!(
        proxy.wait_exit(IO_TIMEOUT),
        "the drain finished once the session closed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// --- harness ------------------------------------------------------------------

fn config_text(dir: &Path, upstream: SocketAddr, extra: &str) -> String {
    format!(
        r#"version: 1
listen: 127.0.0.1:{listen}
admin: 127.0.0.1:{admin}
realtime: {{ enabled: true }}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: {PROVIDER_KEY}
models:
  {MODEL}:
    providers: [openai/{UPSTREAM_MODEL}]
routes: []
auth:
  hmac_secret: "{HMAC_SECRET}"
pricing:
  price_list:
    version: realtime-e2e
    effective_from: "2026-01-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: {UPSTREAM_MODEL}
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 1000
            cached_input_nanodollars_per_token: 100
            cache_write_nanodollars_per_token: 1000
            output_nanodollars_per_token: 2000
            audio_input_nanodollars_per_token: 4000
            audio_output_nanodollars_per_token: 8000
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
        "llm-proxy-realtime-e2e-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn access_log(dir: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(dir.join("access.log"))
        .unwrap_or_default()
        .split_inclusive('\n')
        .filter(|line| line.ends_with('\n'))
        .map(|line| serde_json::from_str(line).expect("a JSON access-log line"))
        .collect()
}

/// The file sink batches writes, so wait for the entry to land.
fn wait_for_entry(dir: &Path, wanted: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        if let Some(entry) = access_log(dir).into_iter().find(&wanted) {
            return entry;
        }
        assert!(
            Instant::now() < deadline,
            "the session's access-log entry never arrived:\n{:?}",
            access_log(dir)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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
        let stderr = std::fs::File::create(dir.join("stderr.log")).expect("create stderr log");
        let child = Command::new(BIN)
            .args([
                "--config",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
                "--drain-time-s",
                "30",
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

    fn sigterm(&self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success());
    }

    fn wait_exit(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
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
        .expect("config names the listener")
}

fn scrape(proxy: &Proxy) -> String {
    let response = admin_request(proxy, "GET", "/stats/prometheus", "");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    response
}

/// `POST /keys` on the admin listener. Returns the plaintext key.
fn mint_key(proxy: &Proxy) -> String {
    let response = admin_request(
        proxy,
        "POST",
        "/keys",
        &format!(r#"{{"tenant":"{TENANT}","key_id":"{KEY_ID}"}}"#),
    );
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "POST /keys:\n{response}"
    );
    let body = response.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    let parsed: serde_json::Value = serde_json::from_str(body).expect("POST /keys returns JSON");
    parsed["key"].as_str().expect("plaintext key").to_string()
}

fn create_tenant(proxy: &Proxy) {
    let created = admin_request(
        proxy,
        "POST",
        "/tenants",
        &format!(r#"{{"tenant":"{TENANT}"}}"#),
    );
    assert!(
        created.starts_with("HTTP/1.1 2"),
        "POST /tenants:\n{created}"
    );
}

fn put_ok(proxy: &Proxy, path: &str, body: &str) {
    let put = admin_request(proxy, "PUT", path, body);
    assert!(put.starts_with("HTTP/1.1 204"), "PUT {path}:\n{put}");
}

fn admin_request(proxy: &Proxy, method: &str, path: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(proxy.admin).expect("connect admin");
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: admin.local\r\n\
                 Authorization: Bearer {ADMIN_TOKEN}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .expect("write admin request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
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

/// Read a response head up to its blank line, byte by byte so no frame byte
/// after it is consumed.
fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).to_string()
}

/// One frame: its opcode and unmasked payload.
fn read_frame(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).ok()?;
    let mut len = u64::from(head[1] & 0x7f);
    if len == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext).ok()?;
        len = u64::from(u16::from_be_bytes(ext));
    } else if len == 127 {
        let mut ext = [0u8; 8];
        stream.read_exact(&mut ext).ok()?;
        len = u64::from_be_bytes(ext);
    }
    let mask = if head[1] & 0x80 != 0 {
        let mut mask = [0u8; 4];
        stream.read_exact(&mut mask).ok()?;
        Some(mask)
    } else {
        None
    };
    let mut payload = vec![0u8; usize::try_from(len).ok()?];
    stream.read_exact(&mut payload).ok()?;
    if let Some(mask) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Some((head[0] & 0x0f, payload))
}

/// An unmasked (server) or masked (client) final frame.
fn frame(opcode: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    let mask_bit = if masked { 0x80 } else { 0 };
    if payload.len() < 126 {
        out.push(mask_bit | payload.len() as u8);
    } else {
        out.push(mask_bit | 126);
        out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    }
    if masked {
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        out.extend_from_slice(&mask);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    } else {
        out.extend_from_slice(payload);
    }
    out
}

/// A client session through the proxy.
#[derive(Debug)]
struct Ws {
    stream: TcpStream,
}

impl Ws {
    /// Open a session, or return the refusal's response head.
    fn open(proxy: &Proxy, key: Option<&str>, model: &str) -> Result<Ws, String> {
        let mut stream = TcpStream::connect(proxy.listen).expect("connect listener");
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        let auth = key
            .map(|k| format!("Authorization: Bearer {k}\r\n"))
            .unwrap_or_default();
        stream
            .write_all(
                format!(
                    "GET /v1/realtime?model={model} HTTP/1.1\r\nHost: proxy.local\r\n{auth}\
                     Upgrade: websocket\r\nConnection: Upgrade\r\n\
                     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
                     Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
                )
                .as_bytes(),
            )
            .expect("write upgrade request");
        let head = read_head(&mut stream);
        if head.starts_with("HTTP/1.1 101") {
            Ok(Ws { stream })
        } else {
            Err(head)
        }
    }

    fn send_text(&mut self, text: &str) {
        self.stream
            .write_all(&frame(0x1, text.as_bytes(), true))
            .expect("send text frame");
    }

    fn read_frame(&mut self) -> (u8, Vec<u8>) {
        read_frame(&mut self.stream).expect("a frame from the proxy")
    }

    fn read_event(&mut self) -> serde_json::Value {
        let (opcode, payload) = self.read_frame();
        assert_eq!(opcode, 0x1, "a text event");
        serde_json::from_slice(&payload).expect("a JSON event")
    }

    /// The client starts the closing handshake and waits for the end.
    fn close(mut self) {
        self.stream
            .write_all(&frame(0x8, &1000u16.to_be_bytes(), true))
            .expect("send Close");
        let mut rest = Vec::new();
        let _ = self.stream.read_to_end(&mut rest);
    }

    /// The client answers the server's Close and waits for the end.
    fn close_after_server_close(mut self) {
        self.stream
            .write_all(&frame(0x8, &1001u16.to_be_bytes(), true))
            .expect("answer Close");
        let mut rest = Vec::new();
        let _ = self.stream.read_to_end(&mut rest);
    }
}

/// A minimal realtime provider. Records each upgrade request head,
/// lowercased.
struct RealtimeUpstream {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
}

impl RealtimeUpstream {
    fn spawn() -> RealtimeUpstream {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock provider");
        let addr = listener.local_addr().unwrap();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&heads);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let recorded = Arc::clone(&recorded);
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
                    let head = read_head(&mut stream).to_ascii_lowercase();
                    if head.is_empty() {
                        return;
                    }
                    recorded.lock().unwrap().push(head);
                    let _ = stream.write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                          Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                    );
                    let _ = stream.write_all(&frame(
                        0x1,
                        br#"{"type":"session.created","session":{}}"#,
                        false,
                    ));
                    while let Some((opcode, _)) = read_frame(&mut stream) {
                        match opcode {
                            0x1 => {
                                let mut out = frame(0x1, br#"{"type":"response.created"}"#, false);
                                out.extend(frame(0x1, DONE.as_bytes(), false));
                                if stream.write_all(&out).is_err() {
                                    return;
                                }
                            }
                            0x8 => {
                                let _ =
                                    stream.write_all(&frame(0x8, &1000u16.to_be_bytes(), false));
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                                return;
                            }
                            _ => {}
                        }
                    }
                });
            }
        });
        RealtimeUpstream { addr, heads }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}
