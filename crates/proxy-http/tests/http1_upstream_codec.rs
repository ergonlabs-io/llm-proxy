//! Standalone tests for the upstream HTTP/1.1 codec
//! (`proxy_http::codec::send_upstream_http1`), the client-side mirror of
//! `tests/http1_codec.rs`. Each test stands up a trivial "upstream" server
//! (this crate's own `serve_http1` + a stub `StreamHandler`, over a real
//! localhost `TcpListener`) and drives `send_upstream_http1` against it as
//! the "downstream-facing" client under test.
//!
//! `send_upstream_http1` spawns its connection-driving future with
//! `tokio::task::spawn_local`, so every test needs a running `LocalSet` --
//! provided here via `#[tokio::test(flavor = "current_thread")]` +
//! `LocalSet::run_until`, per the module doc on `send_upstream_http1`.

use std::rc::Rc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full};
use proxy_http::codec::{
    handshake_upstream_http1, send_upstream_http1, serve_http1, Http1Options, UpstreamCodecError,
};
use proxy_http::filter::RequestHeaders;
use proxy_http::handler::{
    local_boxed,
    stub::{EchoHandler, FixedResponseHandler},
    DownstreamInfo, HttpRequestParts, StreamBody, StreamHandler,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::LocalSet;

/// Bind a real localhost listener and serve one accepted connection with
/// `handler` via the downstream codec -- used here purely as a convenient,
/// already-tested stand-in for a real upstream origin server.
async fn spawn_upstream(handler: Rc<dyn StreamHandler>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::task::spawn_local(async move {
        let (io, _peer) = listener.accept().await.expect("accept");
        serve_http1(
            io,
            handler,
            Http1Options {
                keep_alive: true,
                header_read_timeout: None,
                request_head_limits: Default::default(),
            },
            std::future::pending(),
            DownstreamInfo::loopback(),
        )
        .await
        .expect("upstream connection");
    });

    addr
}

#[tokio::test(flavor = "current_thread")]
async fn get_returns_fixed_response() {
    LocalSet::new()
        .run_until(async {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::HeaderName::from_static("x-upstream"),
                http::HeaderValue::from_static("yes"),
            );
            let handler: Rc<dyn StreamHandler> = Rc::new(FixedResponseHandler {
                status: StatusCode::OK,
                headers,
                body: Bytes::from_static(b"hello from upstream"),
            });
            let addr = spawn_upstream(handler).await;

            let io = TcpStream::connect(addr).await.expect("connect");
            let body: StreamBody = local_boxed(
                Empty::<Bytes>::new()
                    .map_err(|infallible: std::convert::Infallible| match infallible {}),
            );
            let req = HttpRequestParts {
                head: RequestHeaders {
                    method: Method::GET,
                    uri: Uri::from_static("/"),
                    headers: HeaderMap::new(),
                },
                body,
                downstream: DownstreamInfo::loopback(),
                on_upgrade: None,
            };

            let response = send_upstream_http1(
                io,
                req,
                Http1Options {
                    keep_alive: true,
                    header_read_timeout: None,
                    request_head_limits: Default::default(),
                },
            )
            .await
            .expect("send_upstream_http1");
            assert_eq!(response.head.status, StatusCode::OK);
            assert_eq!(
                response
                    .head
                    .headers
                    .get("x-upstream")
                    .map(|v| v.as_bytes()),
                Some(&b"yes"[..])
            );
            let bytes = response
                .body
                .collect()
                .await
                .expect("collect body")
                .to_bytes();
            assert_eq!(&bytes[..], b"hello from upstream");
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn post_body_is_streamed_and_echoed_back() {
    LocalSet::new()
        .run_until(async {
            let handler: Rc<dyn StreamHandler> = Rc::new(EchoHandler);
            let addr = spawn_upstream(handler).await;

            let io = TcpStream::connect(addr).await.expect("connect");
            let payload = Bytes::from(
                vec![b'x'; 4096]
                    .into_iter()
                    .chain(vec![b'y'; 8192])
                    .collect::<Vec<u8>>(),
            );
            let body: StreamBody = local_boxed(
                Full::new(payload.clone())
                    .map_err(|infallible: std::convert::Infallible| match infallible {}),
            );
            let req = HttpRequestParts {
                head: RequestHeaders {
                    method: Method::POST,
                    uri: Uri::from_static("/"),
                    headers: HeaderMap::new(),
                },
                body,
                downstream: DownstreamInfo::loopback(),
                on_upgrade: None,
            };

            let response = send_upstream_http1(
                io,
                req,
                Http1Options {
                    keep_alive: true,
                    header_read_timeout: None,
                    request_head_limits: Default::default(),
                },
            )
            .await
            .expect("send_upstream_http1");
            assert_eq!(response.head.status, StatusCode::OK);
            let bytes = response
                .body
                .collect()
                .await
                .expect("collect body")
                .to_bytes();
            assert_eq!(bytes, payload);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn connect_to_nothing_yields_handshake_error() {
    LocalSet::new()
        .run_until(async {
            // Bind then immediately drop the listener so the port is
            // guaranteed closed on this host, then connect straight to it --
            // no listener has ever accepted here, so the handshake itself
            // (rather than any hyper-level parsing) fails deterministically.
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            drop(listener);

            let connect_result = TcpStream::connect(addr).await;
            // On most platforms this fails at the TCP level (connection
            // refused) before we ever get to `send_upstream_http1`; only
            // exercise the codec's error path if the connect itself
            // succeeded (observed on some sandboxed/CI networking setups).
            if let Ok(io) = connect_result {
                let body: StreamBody = local_boxed(
                    Empty::<Bytes>::new()
                        .map_err(|infallible: std::convert::Infallible| match infallible {}),
                );
                let req = HttpRequestParts {
                    head: RequestHeaders {
                        method: Method::GET,
                        uri: Uri::from_static("/"),
                        headers: HeaderMap::new(),
                    },
                    body,
                    downstream: DownstreamInfo::loopback(),
                    on_upgrade: None,
                };
                let result = send_upstream_http1(
                    io,
                    req,
                    Http1Options {
                        keep_alive: true,
                        header_read_timeout: None,
                        request_head_limits: Default::default(),
                    },
                )
                .await;
                assert!(matches!(
                    result,
                    Err(UpstreamCodecError::Handshake(_)) | Err(UpstreamCodecError::Send(_))
                ));
            }
        })
        .await;
}

/// Serve one raw HTTP/1.1 response, written byte for byte, so the test
/// controls framing (`content-length` or chunked) and how the body is split
/// across writes.
async fn spawn_raw_upstream(head: String, body_writes: Vec<Vec<u8>>) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::task::spawn_local(async move {
        let (mut io, _peer) = listener.accept().await.expect("accept");
        // The request is a bodyless GET; read until its head ends.
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = io.read(&mut buf).await.expect("read request");
            assert!(n > 0, "client closed before sending its request head");
            request.extend_from_slice(&buf[..n]);
        }
        io.write_all(head.as_bytes()).await.expect("write head");
        for write in body_writes {
            io.write_all(&write).await.expect("write body");
            io.flush().await.expect("flush");
            tokio::task::yield_now().await;
        }
        io.flush().await.expect("flush");
    });
    addr
}

/// Send a GET through `handshake_upstream_http1`, the builder the router's
/// h1 connection cache uses, and collect the whole response.
async fn get_through_pooled_h1_client(addr: std::net::SocketAddr) -> (http::HeaderMap, Bytes) {
    let io = TcpStream::connect(addr).await.expect("connect");
    let (mut sender, _conn_task) = handshake_upstream_http1(io).await.expect("handshake");
    let body: StreamBody = local_boxed(
        Empty::<Bytes>::new().map_err(|infallible: std::convert::Infallible| match infallible {}),
    );
    let request = http::Request::get("/").body(body).expect("valid request");
    let response = tokio::time::timeout(Duration::from_secs(10), async {
        let response = sender.send_request(request).await.expect("send_request");
        let (parts, incoming) = response.into_parts();
        let bytes = incoming.collect().await.expect("collect body").to_bytes();
        (parts.headers, bytes)
    })
    .await
    .expect("response within 10s");
    response
}

/// Deterministic, non-repeating-at-buffer-size content, so a dropped,
/// duplicated or reordered buffer-sized span changes the bytes compared.
fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[tokio::test(flavor = "current_thread")]
async fn a_body_larger_than_the_read_buffer_arrives_intact() {
    LocalSet::new()
        .run_until(async {
            // One byte past the usage filter's `MAX_JSON_BODY_BYTES` (1 MiB),
            // the largest non-streaming body the proxy reads whole, sent in
            // one write so the client reads it at full socket speed.
            let body = patterned((1 << 20) + 1);
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                body.len()
            );
            let addr = spawn_raw_upstream(head, vec![body.clone()]).await;

            let (_headers, received) = get_through_pooled_h1_client(addr).await;
            assert!(
                received[..] == body[..],
                "body changed in transit: sent {} bytes, received {}",
                body.len(),
                received.len()
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn an_sse_event_larger_than_the_read_buffer_arrives_intact() {
    LocalSet::new()
        .run_until(async {
            // A 256 KiB event in a single chunk between two small ones: the
            // chunk is many read buffers long, so the decoder must hand it
            // over across reads.
            let mut big_event = b"data: ".to_vec();
            big_event.extend(patterned(256 * 1024).iter().map(|b| b'a' + b % 26));
            big_event.extend_from_slice(b"\n\n");
            let events: Vec<Vec<u8>> = vec![
                b"data: {\"first\":true}\n\n".to_vec(),
                big_event,
                b"data: [DONE]\n\n".to_vec(),
            ];
            let mut writes: Vec<Vec<u8>> = events
                .iter()
                .map(|event| {
                    let mut chunk = format!("{:x}\r\n", event.len()).into_bytes();
                    chunk.extend_from_slice(event);
                    chunk.extend_from_slice(b"\r\n");
                    chunk
                })
                .collect();
            writes.push(b"0\r\n\r\n".to_vec());
            let head = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
                        transfer-encoding: chunked\r\n\r\n"
                .to_string();
            let addr = spawn_raw_upstream(head, writes).await;

            let (_headers, received) = get_through_pooled_h1_client(addr).await;
            let expected = events.concat();
            assert!(
                received[..] == expected[..],
                "event stream changed in transit: sent {} bytes, received {}",
                expected.len(),
                received.len()
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_response_head_at_envoys_default_h1_limit_is_accepted() {
    LocalSet::new()
        .run_until(async {
            // hyper refuses a response head that does not fit its read
            // buffer, so the buffer bound is also the upstream head limit.
            // Envoy's default limit for an HTTP/1 response head is 80 KiB
            // (`max_response_headers_kb` unset); a head just under it must
            // pass.
            let filler = "v".repeat(1000);
            let mut head = String::from("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n");
            while head.len() + 1020 < 80 * 1024 {
                let n = head.len();
                head.push_str(&format!("x-filler-{n}: {filler}\r\n"));
            }
            head.push_str("\r\n");
            assert!(
                head.len() > 79 * 1024 && head.len() <= 80 * 1024,
                "head must sit just under 80 KiB; built {} bytes",
                head.len()
            );
            // Written in 1 KiB pieces: hyper checks its bound only between
            // reads, so a head that lands in one read would skip the check.
            let mut writes: Vec<Vec<u8>> =
                head.as_bytes().chunks(1024).map(<[u8]>::to_vec).collect();
            writes.push(b"ok".to_vec());
            let addr = spawn_raw_upstream(String::new(), writes).await;

            let (headers, received) = get_through_pooled_h1_client(addr).await;
            assert!(headers.len() > 50, "got {} headers", headers.len());
            assert_eq!(&received[..], b"ok");
        })
        .await;
}
