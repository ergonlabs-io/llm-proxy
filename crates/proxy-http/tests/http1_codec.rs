//! WP-10 chunk B -- standalone tests for the downstream HTTP/1.1 codec
//! (`proxy_http::codec::serve_http1`) and the `StreamHandler` seam, driven
//! over an in-memory `tokio::io::duplex` pipe with a hyper low-level client
//! on the other end (mirroring the technique `tests/hyper_spike.rs`
//! established). The codec is `!Send` (ADR-0003), so every test runs on a
//! `LocalSet` via `#[tokio::test(flavor = "current_thread")]` + `run_local`.

use std::convert::Infallible;
use std::future::Future;
use std::rc::Rc;
use std::time::Duration;

use bytes::Bytes;
use futures::stream;
use http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use http_body_util::{BodyExt, Empty, Full, StreamBody as HttpStreamBody};
use hyper::body::Frame;
use hyper_util::rt::TokioIo;
use proxy_http::codec::{serve_http1, Http1Options};
use proxy_http::filter::ResponseHeaders;
use proxy_http::handler::{
    local_boxed,
    stub::{EchoHandler, FixedResponseHandler},
    DownstreamInfo, HttpRequestParts, HttpResponseParts, StreamBody, StreamHandler,
};
use tokio::io::duplex;
use tokio::task::LocalSet;
use tokio::time::Instant;

/// Run `fut` to completion on a fresh current-thread runtime + `LocalSet` --
/// the codec (and `Rc<dyn StreamHandler>`) is `!Send`, so it can't run on the
/// default multi-threaded test runtime.
fn run_local<F: Future<Output = ()>>(fut: F) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = LocalSet::new();
    local.block_on(&rt, fut);
}

/// A no-op shutdown future that never resolves -- for tests that don't
/// exercise drain.
fn never_shutdown() -> impl Future<Output = ()> {
    std::future::pending()
}

#[test]
fn get_returns_fixed_response() {
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
            serve_http1(
                server_io,
                handler,
                Http1Options { keep_alive: true },
                never_shutdown(),
                DownstreamInfo::loopback(),
            )
            .await
            .expect("server connection");
        });

        let io = TokioIo::new(client_io);
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io)
            .await
            .expect("client handshake");
        tokio::task::spawn_local(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "localhost")
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
fn post_body_is_echoed_back() {
    run_local(async {
        let (client_io, server_io) = duplex(64 * 1024);

        let handler: Rc<dyn StreamHandler> = Rc::new(EchoHandler);

        tokio::task::spawn_local(async move {
            serve_http1(
                server_io,
                handler,
                Http1Options { keep_alive: true },
                never_shutdown(),
                DownstreamInfo::loopback(),
            )
            .await
            .expect("server connection");
        });

        let io = TokioIo::new(client_io);
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io)
            .await
            .expect("client handshake");
        tokio::task::spawn_local(async move {
            let _ = conn.await;
        });

        // Multi-chunk payload: `Full` sends it as one frame at the hyper
        // client-body level, but the assertion is on the *reassembled*
        // bytes, which is what matters for "the echo round-trips correctly".
        let payload = Bytes::from(
            vec![b'a'; 1024]
                .into_iter()
                .chain(vec![b'b'; 2048])
                .collect::<Vec<u8>>(),
        );
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("host", "localhost")
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

/// A handler whose response body yields one chunk immediately, sleeps, then
/// yields a second chunk and ends -- the SSE-shaped early-flush fixture,
/// mirroring `hyper_spike.rs` test (a) but through the full seam (codec +
/// `StreamHandler`) instead of hyper's raw API.
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
            }
        })
    }
}

#[test]
fn early_flush_streaming_head_and_first_chunk_arrive_before_pause_elapses() {
    run_local(async {
        let (client_io, server_io) = duplex(64 * 1024);

        let handler: Rc<dyn StreamHandler> = Rc::new(SlowChunkedHandler {
            pause: Duration::from_millis(200),
        });

        tokio::task::spawn_local(async move {
            serve_http1(
                server_io,
                handler,
                Http1Options { keep_alive: true },
                never_shutdown(),
                DownstreamInfo::loopback(),
            )
            .await
            .expect("server connection");
        });

        let io = TokioIo::new(client_io);
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io)
            .await
            .expect("client handshake");
        tokio::task::spawn_local(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "localhost")
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

#[test]
fn keep_alive_true_serves_two_requests_on_one_connection() {
    run_local(async {
        let (client_io, server_io) = duplex(64 * 1024);

        let handler: Rc<dyn StreamHandler> = Rc::new(FixedResponseHandler {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"ok"),
        });

        tokio::task::spawn_local(async move {
            serve_http1(
                server_io,
                handler,
                Http1Options { keep_alive: true },
                never_shutdown(),
                DownstreamInfo::loopback(),
            )
            .await
            .expect("server connection");
        });

        let io = TokioIo::new(client_io);
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io)
            .await
            .expect("client handshake");
        tokio::task::spawn_local(async move {
            let _ = conn.await;
        });

        for _ in 0..2 {
            let req = Request::builder()
                .method("GET")
                .uri("/")
                .header("host", "localhost")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let response = sender
                .send_request(req)
                .await
                .expect("request served on shared connection");
            assert_eq!(response.status(), StatusCode::OK);
        }
    });
}

#[test]
fn keep_alive_false_closes_connection_after_one_response() {
    run_local(async {
        let (client_io, server_io) = duplex(64 * 1024);

        let handler: Rc<dyn StreamHandler> = Rc::new(FixedResponseHandler {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"ok"),
        });

        let server_conn = tokio::task::spawn_local(async move {
            serve_http1(
                server_io,
                handler,
                Http1Options { keep_alive: false },
                never_shutdown(),
                DownstreamInfo::loopback(),
            )
            .await
        });

        let io = TokioIo::new(client_io);
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io)
            .await
            .expect("client handshake");
        let client_conn = tokio::task::spawn_local(conn);

        let req = Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "localhost")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender
            .send_request(req)
            .await
            .expect("first request is served in full");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(http::header::CONNECTION)
                .map(|v| v.as_bytes()),
            Some(&b"close"[..])
        );

        server_conn
            .await
            .unwrap()
            .expect("connection ends cleanly after the one request");
        client_conn
            .await
            .unwrap()
            .expect("client side observes a clean connection close");

        let req2 = Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "localhost")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert!(sender.send_request(req2).await.is_err());
    });
}

/// A handler that holds the response open briefly (simulating an in-flight
/// request still being served when drain fires), then completes.
struct SlowHandler {
    delay: Duration,
}

impl StreamHandler for SlowHandler {
    fn handle<'a>(
        &'a self,
        _req: HttpRequestParts,
    ) -> std::pin::Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            let body: StreamBody = local_boxed(
                Full::new(Bytes::from_static(b"done"))
                    .map_err(|infallible: Infallible| match infallible {}),
            );
            HttpResponseParts {
                head: ResponseHeaders {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                },
                body,
            }
        })
    }
}

#[test]
fn drain_completes_in_flight_request_then_closes() {
    run_local(async {
        let (client_io, server_io) = duplex(64 * 1024);

        let handler: Rc<dyn StreamHandler> = Rc::new(SlowHandler {
            delay: Duration::from_millis(150),
        });
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown = async move {
            let _ = shutdown_rx.await;
        };

        let server_conn = tokio::task::spawn_local(async move {
            serve_http1(
                server_io,
                handler,
                Http1Options { keep_alive: true },
                shutdown,
                DownstreamInfo::loopback(),
            )
            .await
        });

        let io = TokioIo::new(client_io);
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io)
            .await
            .expect("client handshake");
        let client_conn = tokio::task::spawn_local(conn);

        let req = Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "localhost")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let send = tokio::task::spawn_local(async move { sender.send_request(req).await });

        // Give the request time to reach the server and start being handled,
        // then fire shutdown mid-flight.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(());

        let response = send
            .await
            .unwrap()
            .expect("in-flight request completes despite mid-flight shutdown");
        assert_eq!(response.status(), StatusCode::OK);

        server_conn
            .await
            .unwrap()
            .expect("connection closes cleanly after graceful shutdown drains it");
        client_conn.await.unwrap().ok();
    });
}
