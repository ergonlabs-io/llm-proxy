//! HTTP/1.1 request framing at the real socket boundary: the `llm-proxy`
//! binary with a `--config` dialect file, a raw TCP client, and a strict mock
//! upstream that records every request it parses.
//!
//! The proxy is the first parser on an internet-facing hop. Every case
//! asserts two things: what the client gets, and what reaches the upstream.
//! A request whose framing is ambiguous (RFC 9112 section 6.3) must be
//! refused before it is dialled, and a request that is accepted must reach
//! the upstream with exactly one framing header and the body the proxy
//! decoded, so the upstream cannot split the bytes differently.
//!
//! Rust note: same harness shape as `tests/request_body_limit_e2e.rs` (std
//! threads, ephemeral ports, a `Proxy` guard that kills the child on drop).
//! Every wait is bounded by `STARTUP_TIMEOUT` or a socket read timeout.

mod common;

use common::free_port;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for something that must not happen (an upstream request
/// or a downstream close). A late event only makes the test pass falsely,
/// never fail falsely.
const QUIET: Duration = Duration::from_millis(500);

const BODY: &str = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;

/// Requests with ambiguous or malformed framing. Each gets `400` and a
/// closed connection, and never reaches the upstream, not even as a head.
#[test]
fn ambiguous_or_malformed_framing_is_refused_before_the_upstream() {
    let dir = scratch_dir("refused");
    let (upstream, received) = spawn_strict_upstream();
    let proxy = Proxy::start(&dir, upstream);

    let chunked = chunked(BODY);
    let len = BODY.len();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        // Content-Length shorter than the chunked body: an upstream that
        // honours the forwarded Content-Length reads a truncated body.
        (
            "content-length then transfer-encoding",
            head_with(&format!(
                "Content-Length: {}\r\nTransfer-Encoding: chunked\r\n",
                len - 10
            ))
            .into_iter()
            .chain(chunked.clone())
            .collect(),
        ),
        (
            "two different content-length headers",
            head_with(&format!(
                "Content-Length: {len}\r\nContent-Length: {}\r\n",
                len + 1
            ))
            .into_iter()
            .chain(BODY.bytes())
            .collect(),
        ),
        (
            "content-length list",
            request(
                &format!("Content-Length: {len}, {len}\r\n"),
                BODY.as_bytes(),
            ),
        ),
        (
            "signed content-length",
            request(&format!("Content-Length: +{len}\r\n"), BODY.as_bytes()),
        ),
        (
            "negative content-length",
            request("Content-Length: -1\r\n", BODY.as_bytes()),
        ),
        (
            "hex content-length",
            request("Content-Length: 0x10\r\n", BODY.as_bytes()),
        ),
        (
            "transfer-encoding not ending in chunked",
            request("Transfer-Encoding: chunked, identity\r\n", &chunked),
        ),
        (
            "unknown transfer-encoding",
            request("Transfer-Encoding: xchunked\r\n", &chunked),
        ),
        (
            "second transfer-encoding header not chunked",
            request(
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n",
                &chunked,
            ),
        ),
        (
            "space before the colon",
            request("Transfer-Encoding : chunked\r\n", &chunked),
        ),
        (
            "obsolete line folding",
            request("X-Fold: a\r\n Transfer-Encoding: chunked\r\n", &chunked),
        ),
        (
            "vertical tab in the value",
            request("Transfer-Encoding:\x0bchunked\r\n", &chunked),
        ),
        (
            "bare cr in a header value",
            request(
                &format!("X-Cr: a\rb\r\nContent-Length: {len}\r\n"),
                BODY.as_bytes(),
            ),
        ),
        (
            "transfer-encoding on http/1.0",
            b"POST /v1/chat/completions HTTP/1.0\r\nHost: proxy.local\r\n\
              Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                .iter()
                .copied()
                .chain(chunked.clone())
                .collect(),
        ),
        (
            "chunk size not hex",
            chunked_request(b"zz\r\nhello\r\n0\r\n\r\n"),
        ),
        (
            "chunk size overflows u64",
            chunked_request(b"10000000000000000\r\nhello\r\n0\r\n\r\n"),
        ),
        (
            "chunk size with a sign",
            chunked_request(b"-5\r\nhello\r\n0\r\n\r\n"),
        ),
        (
            "chunk data longer than its size",
            chunked_request(b"3\r\nhello\r\n0\r\n\r\n"),
        ),
        (
            "chunk size line ends in bare lf",
            chunked_request(b"5\nhello\r\n0\r\n\r\n"),
        ),
        (
            "chunk extension with a bare cr",
            chunked_request(b"5;a\rb\r\nhello\r\n0\r\n\r\n"),
        ),
    ];

    for (name, raw) in cases {
        let mut stream = connect(proxy.listen);
        stream.write_all(&raw).expect("write request");
        let reply = read_response(&mut stream).unwrap_or_else(|| panic!("{name}: no response"));
        assert_eq!(reply.status, 400, "{name}:\n{}", reply.head);
        assert!(
            is_closed(&mut stream),
            "{name}: the connection must close after a framing error"
        );
        if let Ok(event) = received.recv_timeout(QUIET) {
            panic!("{name}: a refused request reached the upstream:\n{event:?}");
        }
    }

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Requests whose framing is legal but unusual. Each is accepted, and the
/// upstream sees one framing header and exactly the decoded body.
#[test]
fn accepted_framing_reaches_the_upstream_normalized() {
    let dir = scratch_dir("normalized");
    let (upstream, received) = spawn_strict_upstream();
    let proxy = Proxy::start(&dir, upstream);

    let len = BODY.len();
    let (first, rest) = BODY.split_at(10);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("chunked", chunked_request(&chunked(BODY))),
        (
            "chunked in upper case",
            request("Transfer-Encoding: CHUNKED\r\n", &chunked(BODY)),
        ),
        (
            // hyper drops a Content-Length that follows Transfer-Encoding
            // before the proxy sees the head; see envoy-divergences.md.
            "transfer-encoding then content-length",
            request(
                &format!(
                    "Transfer-Encoding: chunked\r\nContent-Length: {}\r\n",
                    len - 10
                ),
                &chunked(BODY),
            ),
        ),
        (
            "two equal content-length headers",
            request(
                &format!("Content-Length: {len}\r\nContent-Length: {len}\r\n"),
                BODY.as_bytes(),
            ),
        ),
        (
            "chunk extensions and two chunks",
            chunked_request(
                format!(
                    "{:x};name=value\r\n{first}\r\n{:x};flag\r\n{rest}\r\n0\r\n\r\n",
                    first.len(),
                    rest.len()
                )
                .as_bytes(),
            ),
        ),
        (
            "chunked with a trailer",
            chunked_request(format!("{:x}\r\n{BODY}\r\n0\r\nX-Trailer: t\r\n\r\n", len).as_bytes()),
        ),
        (
            "bare lf line endings in the head",
            format!(
                "POST /v1/chat/completions HTTP/1.1\nHost: proxy.local\n\
                 Content-Type: application/json\nContent-Length: {len}\n\n{BODY}"
            )
            .into_bytes(),
        ),
    ];

    for (name, raw) in cases {
        let mut stream = connect(proxy.listen);
        stream.write_all(&raw).expect("write request");
        let reply = read_response(&mut stream).unwrap_or_else(|| panic!("{name}: no response"));
        assert_eq!(reply.status, 200, "{name}:\n{}", reply.head);
        let event = received
            .recv_timeout(IO_TIMEOUT)
            .unwrap_or_else(|_| panic!("{name}: nothing reached the upstream"));
        assert_single_framing(name, &event);
        assert_eq!(
            event.body.as_deref(),
            Ok(BODY.as_bytes()),
            "{name}: the upstream must read exactly the decoded body"
        );
        if let Ok(extra) = received.recv_timeout(QUIET) {
            panic!("{name}: one request reached the upstream twice:\n{extra:?}");
        }
    }

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Three requests in one write: a Content-Length body whose content looks
/// like a request line, a chunked body, and a bodiless GET. Each reaches the
/// upstream separately and in order, and the responses come back in order.
#[test]
fn pipelined_requests_are_split_on_their_own_framing() {
    let dir = scratch_dir("pipelined");
    let (upstream, received) = spawn_strict_upstream();
    let proxy = Proxy::start(&dir, upstream);

    let smuggle = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"}]}"#;
    let mut raw = request(
        &format!("Content-Length: {}\r\n", smuggle.len()),
        smuggle.as_bytes(),
    );
    raw.extend(chunked_request(&chunked(BODY)));
    raw.extend_from_slice(b"GET /v1/models HTTP/1.1\r\nHost: proxy.local\r\n\r\n");

    let mut stream = connect(proxy.listen);
    stream.write_all(&raw).expect("write pipeline");
    for n in 1..=3 {
        let reply = read_response(&mut stream).unwrap_or_else(|| panic!("response {n} missing"));
        assert_eq!(reply.status, 200, "response {n}:\n{}", reply.head);
    }

    let mut events = Vec::new();
    for n in 1..=3 {
        events.push(
            received
                .recv_timeout(IO_TIMEOUT)
                .unwrap_or_else(|_| panic!("upstream request {n} missing")),
        );
    }
    assert!(
        events[0].head.starts_with("post /v1/chat/completions "),
        "{:?}",
        events[0]
    );
    assert_eq!(events[0].body.as_deref(), Ok(smuggle.as_bytes()));
    assert!(
        events[1].head.starts_with("post /v1/chat/completions "),
        "{:?}",
        events[1]
    );
    assert_eq!(events[1].body.as_deref(), Ok(BODY.as_bytes()));
    assert!(
        events[2].head.starts_with("get /v1/models "),
        "{:?}",
        events[2]
    );
    for event in &events {
        assert_single_framing("pipelined", event);
    }
    if let Ok(extra) = received.recv_timeout(QUIET) {
        panic!("a fourth request reached the upstream:\n{extra:?}");
    }

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `Expect: 100-continue`: the proxy answers `100 Continue` itself when it
/// is ready for the body, forwards the body once the client sends it, and
/// does not forward the expectation (Envoy's default without
/// `proxy_100_continue`). A client that never sends the body gets no
/// request to the upstream.
#[test]
fn expect_100_continue_is_answered_by_the_proxy() {
    let dir = scratch_dir("continue");
    let (upstream, received) = spawn_strict_upstream();
    let proxy = Proxy::start(&dir, upstream);

    let mut stream = connect(proxy.listen);
    let head = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: proxy.local\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Expect: 100-continue\r\n\r\n",
        BODY.len()
    );
    stream.write_all(head.as_bytes()).expect("write head");
    let interim = read_head(&mut stream).expect("an interim response");
    assert!(
        interim.starts_with("HTTP/1.1 100"),
        "expected 100 Continue:\n{interim}"
    );
    assert!(
        received.recv_timeout(QUIET).is_err(),
        "the upstream must not be dialled before the body arrives"
    );
    stream.write_all(BODY.as_bytes()).expect("write body");
    let reply = read_response(&mut stream).expect("a final response");
    assert_eq!(reply.status, 200, "{}", reply.head);
    let event = received.recv_timeout(IO_TIMEOUT).expect("upstream request");
    assert_eq!(event.body.as_deref(), Ok(BODY.as_bytes()));
    assert!(
        !event.head.lines().any(|l| l.starts_with("expect:")),
        "the expectation must not be forwarded:\n{}",
        event.head
    );

    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// With neither `max_request_headers_kb` nor `max_request_headers_count` set,
/// Envoy's defaults apply: 60 KiB for the raw head and 100 headers.
#[test]
fn request_head_limits_default_to_60_kib_and_100_headers() {
    let dir = scratch_dir("head-default");
    let (upstream, received) = spawn_strict_upstream();
    let proxy = Proxy::start(&dir, upstream);
    assert_head_limits(&proxy, &received, 60 * 1024, 100);
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Configured limits replace the defaults, upward too: a head and a header
/// count that the defaults refuse are accepted.
#[test]
fn configured_request_head_limits_are_enforced() {
    let dir = scratch_dir("head-configured");
    let (upstream, received) = spawn_strict_upstream();
    let proxy = Proxy::start_with(
        &dir,
        upstream,
        "max_request_headers_kb: 96, max_request_headers_count: 120",
    );
    assert_head_limits(&proxy, &received, 96 * 1024, 120);
    drop(proxy);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A head at each limit reaches the upstream. One byte or one header over
/// gets `431`, the connection closes, and nothing reaches the upstream, not
/// even the head. A head far over the limit is refused by hyper's read
/// buffer before it is parsed, and must get the same answer.
fn assert_head_limits(
    proxy: &Proxy,
    received: &mpsc::Receiver<UpstreamRequest>,
    max_bytes: usize,
    max_headers: usize,
) {
    let cases = [
        ("head at the size limit", sized_request(max_bytes), 200),
        (
            "head one byte over the size limit",
            sized_request(max_bytes + 1),
            431,
        ),
        (
            "head far over the size limit",
            sized_request(max_bytes * 8),
            431,
        ),
        (
            "headers at the count limit",
            counted_request(max_headers),
            200,
        ),
        (
            "one header over the count limit",
            counted_request(max_headers + 1),
            431,
        ),
    ];
    for (name, raw, status) in cases {
        let mut stream = connect(proxy.listen);
        // The proxy may answer and close before the whole head is written.
        let _ = stream.write_all(&raw);
        let reply = read_response(&mut stream).unwrap_or_else(|| panic!("{name}: no response"));
        assert_eq!(reply.status, status, "{name}:\n{}", reply.head);
        if status == 200 {
            let event = received
                .recv_timeout(IO_TIMEOUT)
                .unwrap_or_else(|_| panic!("{name}: the request did not reach the upstream"));
            assert_eq!(event.body.as_deref(), Ok(BODY.as_bytes()), "{name}");
        } else {
            if let Ok(event) = received.recv_timeout(QUIET) {
                panic!("{name}: a refused head reached the upstream:\n{event:?}");
            }
            assert!(is_closed(&mut stream), "{name}: the connection must close");
        }
    }
}

/// A request whose head is exactly `len` bytes, padded by one header.
fn sized_request(len: usize) -> Vec<u8> {
    let framing = format!("Content-Length: {}\r\n", BODY.len());
    let base = head_with(&format!("{framing}X-Pad: \r\n")).len();
    let pad = "a".repeat(len.checked_sub(base).expect("limit below the base head"));
    let extra = format!("{framing}X-Pad: {pad}\r\n");
    assert_eq!(head_with(&extra).len(), len, "padding arithmetic");
    request(&extra, BODY.as_bytes())
}

/// A request with exactly `count` header lines: `head_with`'s Host and
/// Content-Type, Content-Length, and fillers.
fn counted_request(count: usize) -> Vec<u8> {
    let fillers: String = (3..count).map(|i| format!("X-H{i}: v\r\n")).collect();
    let extra = format!("{fillers}Content-Length: {}\r\n", BODY.len());
    let raw = request(&extra, BODY.as_bytes());
    let head = String::from_utf8_lossy(&raw);
    let lines = head.split("\r\n\r\n").next().unwrap().lines().count();
    assert_eq!(lines - 1, count, "header count arithmetic");
    raw
}

// ------------------------------------------------------------------ helpers --

/// One request the mock upstream parsed. `body` is `Err` when the framing
/// was ambiguous to a strict parser or the connection closed mid-body.
#[derive(Debug)]
struct UpstreamRequest {
    /// Lowercased request line and headers, CRLF-joined.
    head: String,
    body: Result<Vec<u8>, String>,
}

fn assert_single_framing(name: &str, event: &UpstreamRequest) {
    let framing = event
        .head
        .lines()
        .filter(|l| l.starts_with("content-length:") || l.starts_with("transfer-encoding:"))
        .count();
    let has_body = !event.body.as_ref().map(Vec::is_empty).unwrap_or(false);
    assert!(
        framing == usize::from(has_body),
        "{name}: the upstream request must carry exactly one framing header:\n{}",
        event.head
    );
}

/// A POST head with the given extra header lines, terminated.
fn head_with(extra: &str) -> Vec<u8> {
    format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: proxy.local\r\n\
         Content-Type: application/json\r\n{extra}\r\n"
    )
    .into_bytes()
}

fn request(extra: &str, body: &[u8]) -> Vec<u8> {
    let mut raw = head_with(extra);
    raw.extend_from_slice(body);
    raw
}

fn chunked_request(body: &[u8]) -> Vec<u8> {
    request("Transfer-Encoding: chunked\r\n", body)
}

fn chunked(body: &str) -> Vec<u8> {
    format!("{:x}\r\n{body}\r\n0\r\n\r\n", body.len()).into_bytes()
}

fn connect(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    stream
}

struct Reply {
    status: u16,
    head: String,
}

/// Reads one response head. `None` if the connection closed first.
fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 16384, "oversized response head");
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// Reads one whole response, skipping no interim responses. `None` if the
/// connection closed before a head arrived.
fn read_response(stream: &mut TcpStream) -> Option<Reply> {
    let head = read_head(stream)?;
    let status = head
        .get(9..12)
        .and_then(|s| s.parse().ok())
        .expect("status code");
    let lower = head.to_ascii_lowercase();
    if let Some(len) = lower
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        let mut body = vec![0; len];
        stream.read_exact(&mut body).expect("response body");
    } else if lower.contains("\r\ntransfer-encoding: chunked") {
        let mut reader = std::io::BufReader::new(&mut *stream);
        read_chunked(&mut reader).expect("chunked response body");
    }
    Some(Reply { status, head })
}

/// True when the peer closes the connection within `QUIET`.
fn is_closed(stream: &mut TcpStream) -> bool {
    // macOS fails `setsockopt` with EINVAL once the peer has reset the
    // connection, which is a close.
    if stream.set_read_timeout(Some(QUIET)).is_err() {
        return true;
    }
    let mut buf = [0u8; 64];
    match stream.read(&mut buf) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
    }
}

/// Strict RFC 9112 chunked decoding: CRLF only, hex sizes, extensions
/// ignored, trailers read and discarded.
fn read_chunked(reader: &mut impl std::io::BufRead) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let line = read_crlf_line(reader)?;
        let size = line.split(';').next().unwrap_or("");
        let size =
            usize::from_str_radix(size, 16).map_err(|_| format!("bad chunk size {line:?}"))?;
        if size == 0 {
            while !read_crlf_line(reader)?.is_empty() {}
            return Ok(body);
        }
        let mut chunk = vec![0; size + 2];
        reader
            .read_exact(&mut chunk)
            .map_err(|e| format!("chunk data: {e}"))?;
        if !chunk.ends_with(b"\r\n") {
            return Err("chunk data not followed by CRLF".into());
        }
        body.extend_from_slice(&chunk[..size]);
    }
}

fn read_crlf_line(reader: &mut impl std::io::BufRead) -> Result<String, String> {
    let mut line = Vec::new();
    reader
        .read_until(b'\n', &mut line)
        .map_err(|e| e.to_string())?;
    if !line.ends_with(b"\r\n") {
        return Err(format!("line not CRLF-terminated: {line:?}"));
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line).map_err(|e| e.to_string())
}

/// A strict keep-alive mock provider. For each request on each connection
/// it reads the head, rejects ambiguous framing (both headers, several
/// Content-Length lines, a Transfer-Encoding that is not exactly `chunked`),
/// reads the body by its framing, sends what it saw on the channel, and
/// answers `200` with an empty JSON object.
fn spawn_strict_upstream() -> (SocketAddr, mpsc::Receiver<UpstreamRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
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
                let mut reader = std::io::BufReader::new(stream);
                loop {
                    let mut head = Vec::new();
                    loop {
                        match read_crlf_line(&mut reader) {
                            Ok(line) if line.is_empty() && head.is_empty() => continue,
                            Ok(line) if line.is_empty() => break,
                            Ok(line) => head.push(line.to_ascii_lowercase()),
                            Err(_) => return,
                        }
                    }
                    let lengths: Vec<&str> = head
                        .iter()
                        .filter_map(|l| l.strip_prefix("content-length:"))
                        .map(str::trim)
                        .collect();
                    let encodings: Vec<&str> = head
                        .iter()
                        .filter_map(|l| l.strip_prefix("transfer-encoding:"))
                        .map(str::trim)
                        .collect();
                    let body = match (lengths.as_slice(), encodings.as_slice()) {
                        ([], []) => Ok(Vec::new()),
                        ([], ["chunked"]) => read_chunked(&mut reader),
                        ([len], []) => match len.parse::<usize>() {
                            Ok(len) => {
                                let mut body = vec![0; len];
                                reader
                                    .read_exact(&mut body)
                                    .map(|()| body)
                                    .map_err(|e| format!("short body: {e}"))
                            }
                            Err(_) => Err(format!("bad content-length {len:?}")),
                        },
                        _ => Err("ambiguous framing".into()),
                    };
                    let ok = body.is_ok();
                    let _ = tx.send(UpstreamRequest {
                        head: head.join("\r\n"),
                        body,
                    });
                    if !ok {
                        return;
                    }
                    if writer
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                              Content-Length: 2\r\n\r\n{}",
                        )
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    (addr, rx)
}

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
        "llm-proxy-h1-framing-e2e-{tag}-{}",
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
    fn start(dir: &Path, upstream: SocketAddr) -> Proxy {
        Proxy::start_with(dir, upstream, "")
    }

    /// Like [`Proxy::start`], with extra fields on the `listen` object.
    fn start_with(dir: &Path, upstream: SocketAddr, listen_extra: &str) -> Proxy {
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
