//! HTTP/2 request header limits at the real socket boundary: the `llm-proxy`
//! binary with a `--config` dialect file, a prior-knowledge h2 client, and a
//! mock upstream that records every request it receives.
//!
//! Envoy measures an h2 header list as name plus value per field,
//! pseudo-headers included, and resets an over-limit stream with
//! INTERNAL_ERROR instead of answering `431`. The connection stays up. Each
//! case asserts what the client gets and whether anything reached the
//! upstream.
//!
//! Rust note: the `h2` crate is the client because it sends exactly the
//! header list it is given (no added `user-agent` or `content-length`) and
//! reports the RST_STREAM reason, which a hyper client folds into a generic
//! error. Same process harness as `tests/h1_framing_e2e.rs`.

mod common;

use common::free_port;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use bytes::Bytes;
use h2::client::SendRequest;
use h2::Reason;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for an upstream request that must not happen. A late
/// event only makes the test pass falsely, never fail falsely.
const QUIET: Duration = Duration::from_millis(500);

const BODY: &str = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;
const AUTHORITY: &str = "proxy.local";
const PATH: &str = "/v1/chat/completions";
/// The pseudo-headers every request here carries, as Envoy sizes them:
/// `:method POST`, `:scheme http`, `:authority proxy.local` and
/// `:path /v1/chat/completions`.
const PSEUDO_LEN: usize = (7 + 4) + (7 + 4) + (10 + 11) + (5 + 20);
const PSEUDO_COUNT: usize = 4;

/// With neither `max_request_headers_kb` nor `max_request_headers_count` set,
/// Envoy's defaults apply on HTTP/2 too: 60 KiB and 100 headers.
#[test]
fn h2_request_head_limits_default_to_60_kib_and_100_headers() {
    let dir = scratch_dir("default");
    let (upstream, received) = spawn_upstream();
    let proxy = Proxy::start(&dir, upstream, "");
    assert_h2_head_limits(&proxy, &received, 60 * 1024, 100);
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Configured limits replace the defaults on HTTP/2, upward too.
#[test]
fn configured_h2_request_head_limits_are_enforced() {
    let dir = scratch_dir("configured");
    let (upstream, received) = spawn_upstream();
    let proxy = Proxy::start(
        &dir,
        upstream,
        "max_request_headers_kb: 96, max_request_headers_count: 120",
    );
    assert_h2_head_limits(&proxy, &received, 96 * 1024, 120);
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A list at each limit reaches the upstream. One byte or one field over has
/// its stream reset with INTERNAL_ERROR, and the next request on the same
/// connection is still served. Past h2's own `SETTINGS_MAX_HEADER_LIST_SIZE`
/// the h2 library answers `431` itself, and far past it closes the
/// connection; neither is Envoy's reset (`internal-docs/envoy-divergences.md`)
/// but neither reaches the upstream.
fn assert_h2_head_limits(
    proxy: &Proxy,
    received: &mpsc::Receiver<String>,
    max_bytes: usize,
    max_headers: usize,
) {
    run(async {
        let mut client = connect(proxy.listen).await;
        let cases = [
            ("list at the size limit", sized(max_bytes), Ok(200)),
            (
                "list one byte over the size limit",
                sized(max_bytes + 1),
                Err(Reason::INTERNAL_ERROR),
            ),
            ("fields at the count limit", counted(max_headers), Ok(200)),
            (
                "one field over the count limit",
                counted(max_headers + 1),
                Err(Reason::INTERNAL_ERROR),
            ),
            // Envoy leaves `cookie` crumbs out of the count; the proxy counts
            // them (`internal-docs/envoy-divergences.md`).
            (
                "cookie crumbs over the count limit",
                cookies(max_headers + 1),
                Err(Reason::INTERNAL_ERROR),
            ),
            (
                "list over h2's advertised list size",
                sized(max_bytes + 32 * max_headers + 1),
                Ok(431),
            ),
        ];
        for (name, fields, expected) in cases {
            let got = send(&mut client, &fields).await;
            assert_eq!(got, expected, "{name}");
            let upstream = received.recv_timeout(if expected == Ok(200) {
                IO_TIMEOUT
            } else {
                QUIET
            });
            match (expected, upstream) {
                (Ok(200), Ok(head)) => assert!(
                    fields
                        .iter()
                        .all(|(n, v)| n == "cookie" || head.contains(&format!("{n}: {v}"))),
                    "{name}: the upstream did not get every field:\n{head}"
                ),
                (Ok(200), Err(_)) => panic!("{name}: the request did not reach the upstream"),
                (_, Ok(head)) => panic!("{name}: a refused list reached the upstream:\n{head}"),
                (_, Err(_)) => {}
            }
        }

        let got = send(&mut client, &sized(max_bytes * 8)).await;
        assert_eq!(
            got,
            Err(Reason::ENHANCE_YOUR_CALM),
            "a list far over h2's list size closes the connection"
        );
        if let Ok(head) = received.recv_timeout(QUIET) {
            panic!("a list far over the limit reached the upstream:\n{head}");
        }
    });
}

/// The base fields plus one `x-pad` field sized so the whole list, as Envoy
/// measures it, is exactly `len` bytes.
fn sized(len: usize) -> Vec<(String, String)> {
    let mut fields = base_fields();
    let used = PSEUDO_LEN + list_len(&fields) + "x-pad".len();
    let pad = len.checked_sub(used).expect("limit below the base list");
    fields.push(("x-pad".into(), "a".repeat(pad)));
    assert_eq!(PSEUDO_LEN + list_len(&fields), len, "padding arithmetic");
    fields
}

/// Exactly `count` fields, pseudo-headers included.
fn counted(count: usize) -> Vec<(String, String)> {
    let mut fields = base_fields();
    let fillers = count - PSEUDO_COUNT - fields.len();
    fields.extend((0..fillers).map(|i| (format!("x-h{i}"), "v".into())));
    assert_eq!(PSEUDO_COUNT + fields.len(), count, "count arithmetic");
    fields
}

/// Exactly `count` fields, the fillers sent as separate `cookie` crumbs.
fn cookies(count: usize) -> Vec<(String, String)> {
    let mut fields = base_fields();
    let crumbs = count - PSEUDO_COUNT - fields.len();
    fields.extend((0..crumbs).map(|i| ("cookie".into(), format!("c{i}=v"))));
    fields
}

fn base_fields() -> Vec<(String, String)> {
    vec![
        ("content-type".into(), "application/json".into()),
        ("content-length".into(), BODY.len().to_string()),
    ]
}

fn list_len(fields: &[(String, String)]) -> usize {
    fields.iter().map(|(n, v)| n.len() + v.len()).sum()
}

// ------------------------------------------------------------------ client --

fn run<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("client runtime")
        .block_on(fut)
}

async fn connect(addr: SocketAddr) -> SendRequest<Bytes> {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to the proxy");
    let (client, conn) = h2::client::handshake(tcp).await.expect("h2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

/// Send one POST with `fields` and the body. `Ok` is the response status;
/// `Err` is the reason the stream or connection was closed.
async fn send(client: &mut SendRequest<Bytes>, fields: &[(String, String)]) -> Result<u16, Reason> {
    let mut req = http::Request::builder()
        .method("POST")
        .uri(format!("http://{AUTHORITY}{PATH}"));
    for (name, value) in fields {
        req = req.header(name, value);
    }
    let req = req.body(()).expect("valid request");
    let ready = tokio::time::timeout(IO_TIMEOUT, client.clone().ready())
        .await
        .expect("client ready in time")
        .map_err(|e| e.reason().expect("ready error has a reason"))?;
    *client = ready;
    let (response, mut body) = client
        .send_request(req, false)
        .map_err(|e| e.reason().expect("send error has a reason"))?;
    // The stream may already be reset; the response carries the reason.
    let _ = body.send_data(Bytes::from_static(BODY.as_bytes()), true);
    let response = tokio::time::timeout(IO_TIMEOUT, response)
        .await
        .expect("response or reset in time");
    match response {
        Ok(response) => Ok(response.status().as_u16()),
        Err(e) => Err(e.reason().unwrap_or_else(|| panic!("no reason: {e}"))),
    }
}

// ---------------------------------------------------------------- upstream --

/// An HTTP/1.1 upstream that sends each request head it reads, lowercased and
/// CRLF-joined, then answers `200`.
fn spawn_upstream() -> (SocketAddr, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || {
                // macOS: an accepted socket can inherit the listener's
                // non-blocking flag; reads below must block.
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let mut writer = stream.try_clone().expect("clone upstream stream");
                let mut reader = BufReader::new(stream);
                loop {
                    let mut head = Vec::new();
                    loop {
                        let mut line = String::new();
                        match reader.read_line(&mut line) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                        let line = line.trim_end_matches(['\r', '\n']).to_ascii_lowercase();
                        if line.is_empty() {
                            break;
                        }
                        head.push(line);
                    }
                    let len = head
                        .iter()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let mut body = vec![0; len];
                    if reader.read_exact(&mut body).is_err() {
                        return;
                    }
                    let _ = tx.send(head.join("\r\n"));
                    let reply = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                  Content-Length: 2\r\n\r\n{}";
                    if writer.write_all(reply).is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, rx)
}

// ------------------------------------------------------------------- proxy --

/// `listen_extra` is spliced into the `listen` object, after `address`.
fn config_text(listen: u16, admin: u16, upstream: SocketAddr, listen_extra: &str) -> String {
    let listen_extra = if listen_extra.is_empty() {
        String::new()
    } else {
        format!(", {listen_extra}")
    };
    format!(
        r#"version: 0
listen: {{ address: "127.0.0.1:{listen}"{listen_extra} }}
admin: 127.0.0.1:{admin}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
routes:
  - {{ model: "*", provider: openai }}
"#
    )
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-h2-head-limits-e2e-{tag}-{}",
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
}

impl Proxy {
    fn start(dir: &Path, upstream: SocketAddr, listen_extra: &str) -> Proxy {
        let listen = free_port();
        let admin = free_port();
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config_text(listen, admin, upstream, listen_extra))
            .expect("write temp config");
        let child = Command::new(BIN)
            .args([
                "--config",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn llm-proxy");
        let proxy = Proxy {
            child,
            listen: SocketAddr::from(([127, 0, 0, 1], listen)),
        };
        let admin = SocketAddr::from(([127, 0, 0, 1], admin));
        assert!(
            wait_for_connectable(admin, STARTUP_TIMEOUT),
            "admin listener at {admin} did not become connectable in time"
        );
        assert!(
            wait_for_connectable(proxy.listen, STARTUP_TIMEOUT),
            "listener at {} did not become connectable in time",
            proxy.listen
        );
        proxy
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
