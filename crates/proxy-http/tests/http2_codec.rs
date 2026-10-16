//! Tests the downstream HTTP/2 codec with an in-memory client. The codec is
//! `!Send` (ADR-0003), so tests use a local runtime. Multiplexing tests verify
//! that concurrent streams do not share per-stream state.

use std::cell::RefCell;
use std::convert::Infallible;
use std::future::Future;
use std::rc::Rc;
use std::time::Duration;

use bytes::Bytes;
use futures::stream;
use http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use http_body_util::{BodyExt, Empty, Full, StreamBody as HttpStreamBody};
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
use proxy_http::codec::serve_http2;
use proxy_http::filter::{RequestHeaders, ResponseHeaders};
use proxy_http::handler::{
    local_boxed,
    stub::{EchoHandler, FixedResponseHandler},
    DownstreamInfo, HttpRequestParts, HttpResponseParts, StreamBody, StreamHandler,
};
use tokio::io::duplex;
use tokio::task::LocalSet;
use tokio::time::Instant;

/// Run a future locally because the codec and handler are `!Send`.
fn run_local<F: Future<Output = ()>>(fut: F) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = LocalSet::new();
    local.block_on(&rt, fut);
}

/// A pending shutdown future for tests that do not exercise drain.
fn never_shutdown() -> impl Future<Output = ()> {
    std::future::pending()
}

#[test]
fn get_returns_fixed_response_over_h2() {
    run_local(async {
        let (client_io, server_io) = duplex(64 * 1024);

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-custom"),
            HeaderValue::from_static("yes"),
        );
        let handler: Rc<dyn StreamHandler> = Rc::new(FixedResponseHandler {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"hello world"),
        });

        tokio::task::spawn_local(async move {
            serve_http2(
                server_io,
                handler,
                never_shutdown(),
                DownstreamInfo::loopback(),
            )
            .await
            .expect("server connection");
        });

        let io = TokioIo::new(client_io);
        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake::<_, Empty<Bytes>>(io)
            .await
            .expect("h2 client handshake");
        tokio::task::spawn_local(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let mut response = sender.send_request(req).await.expect("send_request");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-custom").map(|v| v.as_bytes()),
            Some(&b"yes"[..])
        );
        let body = response
            .body_mut()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        assert_eq!(&body[..], b"hello world");
    });
}

#[test]
fn post_body_is_echoed_back_over_h2() {
    run_local(async {
        let (client_io, server_io) = duplex(64 * 1024);

        let handler: Rc<dyn StreamHandler> = Rc::new(EchoHandler);

        tokio::task::spawn_local(async move {
            serve_http2(
                server_io,
                handler,
                never_shutdown(),
                DownstreamInfo::loopback(),
            )
            .await
            .expect("server connection");
        });

        let io = TokioIo::new(client_io);
        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake::<_, Full<Bytes>>(io)
            .await
            .expect("h2 client handshake");
        tokio::task::spawn_local(async move {
            let _ = conn.await;
        });

        // Verify that the codec reassembles the chunks without changing bytes.
        let payload = Bytes::from(
            vec![b'a'; 1024]
                .into_iter()
                .chain(vec![b'b'; 2048])
                .collect::<Vec<u8>>(),
        );
        let req = Request::builder()
            .method("POST")
            .uri("http://localhost/")
            .body(Full::new(payload.clone()))
            .unwrap();
        let mut response = sender.send_request(req).await.expect("send_request");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .body_mut()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        assert_eq!(body, payload);
    });
}

/// Yield one response chunk immediately and another after a delay, verifying
/// that HTTP/2 flushes headers and the first chunk before body completion.
struct SlowChunkedHandler {
    pause: Duration,
}

impl StreamHandler for SlowChunkedHandler {
    fn handle<'a>(
        &'a self,
        _req: HttpRequestParts,
    ) -> std::pin::Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
            let pause = self.pause;
            tokio::task::spawn_local(async move {
                tx.send(Ok(Frame::data(Bytes::from_static(b"first-chunk-"))))
                    .await
                    .unwrap();
                tokio::time::sleep(pause).await;
                tx.send(Ok(Frame::data(Bytes::from_static(b"second-chunk"))))
                    .await
                    .unwrap();
            });
            let stream = stream::poll_fn(move |cx| rx.poll_recv(cx));
            let body: StreamBody = local_boxed(
                HttpStreamBody::new(stream).map_err(|infallible: Infallible| match infallible {}),
            );
            HttpResponseParts {
                head: ResponseHeaders {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                },
                body,
                upgrade: None,
            }
        })
    }
}

#[test]
fn streamed_response_arrives_incrementally_over_h2_not_buffered() {
    run_local(async {
        let (client_io, server_io) = duplex(64 * 1024);

        let handler: Rc<dyn StreamHandler> = Rc::new(SlowChunkedHandler {
            pause: Duration::from_millis(200),
        });

        tokio::task::spawn_local(async move {
            serve_http2(
                server_io,
                handler,
                never_shutdown(),
                DownstreamInfo::loopback(),
            )
            .await
            .expect("server connection");
        });

        let io = TokioIo::new(client_io);
        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake::<_, Empty<Bytes>>(io)
            .await
            .expect("h2 client handshake");
        tokio::task::spawn_local(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method("GET")
            .uri("http://localhost/")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let t_start = Instant::now();
        let mut response = sender.send_request(req).await.expect("send_request");
        assert_eq!(response.status(), StatusCode::OK);

        let first_frame = response
            .body_mut()
            .frame()
            .await
            .expect("stream not ended")
            .expect("frame ok");
        let elapsed = t_start.elapsed();
        assert_eq!(
            first_frame.into_data().ok().as_deref(),
            Some(&b"first-chunk-"[..])
        );
        assert!(
            elapsed < Duration::from_millis(150),
            "head+first-chunk took {elapsed:?}, expected well under the 200ms pause"
        );

        let t_before_second = Instant::now();
        let second_frame = response
            .body_mut()
            .frame()
            .await
            .expect("stream not ended")
            .expect("frame ok");
        assert_eq!(
            second_frame.into_data().ok().as_deref(),
            Some(&b"second-chunk"[..])
        );
        assert!(t_before_second.elapsed() >= Duration::from_millis(150));
    });
}

/// Capture the request headers received by the handler.
struct CapturingHandler {
    captured: Rc<RefCell<Option<RequestHeaders>>>,
}

impl StreamHandler for CapturingHandler {
    fn handle<'a>(
        &'a self,
        req: HttpRequestParts,
    ) -> std::pin::Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move {
            *self.captured.borrow_mut() = Some(req.head.clone());
            let _ = req.body.collect().await;
            let mut headers = HeaderMap::new();
            headers.insert(
                HeaderName::from_static("x-response-custom"),
                HeaderValue::from_static("also-yes"),
            );
            let body: StreamBody = local_boxed(
                Full::new(Bytes::from_static(b"ok"))
                    .map_err(|infallible: Infallible| match infallible {}),
            );
            HttpResponseParts {
                head: ResponseHeaders {
                    status: StatusCode::OK,
                    headers,
                },
                body,
                upgrade: None,
            }
        })
    }
}

/// Verify that HTTP/2 `:authority` reaches the handler and ordinary headers
/// round-trip intact. HTTP/2 carries authority as a pseudo-header, not `Host`.
#[test]
fn request_and_response_headers_survive_intact_and_authority_reaches_routing() {
    run_local(async {
        let (client_io, server_io) = duplex(64 * 1024);

        let captured = Rc::new(RefCell::new(None));
        let handler: Rc<dyn StreamHandler> = Rc::new(CapturingHandler {
            captured: captured.clone(),
        });

        tokio::task::spawn_local(async move {
            serve_http2(
                server_io,
                handler,
                never_shutdown(),
                DownstreamInfo::loopback(),
            )
            .await
            .expect("server connection");
        });

        let io = TokioIo::new(client_io);
        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake::<_, Empty<Bytes>>(io)
            .await
            .expect("h2 client handshake");
        tokio::task::spawn_local(async move {
            let _ = conn.await;
        });

        // Hyper derives `:authority` from the absolute URI; this request has
        // no `Host` header.
        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/authority-test")
            .header("x-request-custom", "req-yes")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender.send_request(req).await.expect("send_request");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-response-custom")
                .map(|v| v.as_bytes()),
            Some(&b"also-yes"[..])
        );

        let head = captured
            .borrow_mut()
            .take()
            .expect("handler should have been called");
        assert_eq!(
            head.uri.authority().map(|a| a.as_str()),
            Some("example.com"),
            ":authority should reach the handler via the request URI, same place routing reads it from"
        );
        assert_eq!(head.uri.path(), "/authority-test");
        assert_eq!(
            head.headers.get("x-request-custom").map(|v| v.as_bytes()),
            Some(&b"req-yes"[..]),
            "ordinary request headers should survive intact over h2"
        );
    });
}

/// Delay responses by `x-delay-ms` and echo each stream's `x-stream-id` and
/// body, allowing the multiplexing test to detect cross-stream state leaks.
struct StreamTaggedHandler;

impl StreamHandler for StreamTaggedHandler {
    fn handle<'a>(
        &'a self,
        req: HttpRequestParts,
    ) -> std::pin::Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move {
            let stream_id = req
                .head
                .headers
                .get("x-stream-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("?")
                .to_string();
            let delay_ms: u64 = req
                .head
                .headers
                .get("x-delay-ms")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            // Keep the body and stream ID local across the delay; concurrent
            // streams must not overwrite either value.
            let request_body = req.body.collect().await.expect("collect").to_bytes();
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;

            let response_text = format!(
                "stream={stream_id}:body={}",
                String::from_utf8_lossy(&request_body)
            );
            let body: StreamBody = local_boxed(
                Full::new(Bytes::from(response_text))
                    .map_err(|infallible: Infallible| match infallible {}),
            );
            HttpResponseParts {
                head: ResponseHeaders {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                },
                body,
                upgrade: None,
            }
        })
    }
}

/// Send concurrent streams on one connection and complete them in reverse
/// order. Each response must retain its own stream ID and body.
#[test]
fn several_concurrent_streams_get_their_own_response_without_crosstalk() {
    run_local(async {
        let (client_io, server_io) = duplex(64 * 1024);

        let handler: Rc<dyn StreamHandler> = Rc::new(StreamTaggedHandler);

        tokio::task::spawn_local(async move {
            serve_http2(
                server_io,
                handler,
                never_shutdown(),
                DownstreamInfo::loopback(),
            )
            .await
            .expect("server connection");
        });

        let io = TokioIo::new(client_io);
        let (sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake::<_, Full<Bytes>>(io)
            .await
            .expect("h2 client handshake");
        tokio::task::spawn_local(async move {
            let _ = conn.await;
        });

        // (stream ID, delay, body), ordered so responses finish c, b, a.
        let streams = [
            ("a", 200u64, "payload-a"),
            ("b", 100, "payload-b"),
            ("c", 0, "payload-c"),
        ];

        let t_start = Instant::now();
        let mut sends = Vec::new();
        for (id, delay_ms, payload) in streams {
            let mut sender = sender.clone();
            let req = Request::builder()
                .method("POST")
                .uri("http://localhost/")
                .header("x-stream-id", id)
                .header("x-delay-ms", delay_ms.to_string())
                .body(Full::new(Bytes::from_static(payload.as_bytes())))
                .unwrap();
            // Rust note: spawn each request so all three are in flight
            // concurrently on the connection.
            sends.push((
                id,
                delay_ms,
                tokio::task::spawn_local(async move {
                    let mut response = sender.send_request(req).await.expect("send_request");
                    assert_eq!(response.status(), StatusCode::OK);
                    let body = response
                        .body_mut()
                        .collect()
                        .await
                        .expect("collect body")
                        .to_bytes();
                    (String::from_utf8_lossy(&body).into_owned(), Instant::now())
                }),
            ));
        }

        let mut completions = Vec::new();
        for (id, delay_ms, handle) in sends {
            let (body, completed_at) = handle.await.expect("stream task should not panic");
            assert_eq!(
                body,
                format!("stream={id}:body=payload-{id}"),
                "stream {id}'s response must carry exactly its own id and body, not another stream's"
            );
            completions.push((id, delay_ms, completed_at));
        }

        // Completion order must be c, b, a to prove stream interleaving.
        completions.sort_by_key(|(_, delay_ms, _)| *delay_ms);
        for pair in completions.windows(2) {
            let (earlier_id, _, earlier_at) = pair[0];
            let (later_id, _, later_at) = pair[1];
            assert!(
                earlier_at <= later_at,
                "stream {earlier_id} (shorter delay) should complete no later than stream {later_id} (longer delay), got {earlier_at:?} > {later_at:?}"
            );
        }
        let _ = t_start.elapsed();
    });
}
