//! WP-10 chunk A -- hyper 1.x capability spike.
//!
//! This is *not* the WP-10 codec. It is a bounded, throwaway de-risking
//! exercise: four `#[tokio::test]`s, each proving (or disproving) one
//! capability the real downstream/upstream HTTP codec will need, driven
//! through the same **low-level** connection API the codec will use
//! (`hyper::server::conn::{http1,http2}::Builder`,
//! `hyper::client::conn::{http1,http2}`) rather than the high-level
//! `hyper_util` auto server/client. Every test runs entirely in-process over
//! a `tokio::io::duplex` pipe wrapped in `hyper_util::rt::TokioIo`.
//!
//! # Findings (drives the WP-10 codec design)
//!
//! | # | Capability                                   | Verdict            | API used                                                                                       | Caveats / fallback |
//! |---|-----------------------------------------------|--------------------|--------------------------------------------------------------------------------------------------|---------------------|
//! | a | Headers + first body chunk flush before body completes | **Works cleanly** | `http_body_util::StreamBody` over a `futures::stream::poll_fn` wrapping a `tokio::sync::mpsc::Receiver`; `SendRequest::send_request` resolves as soon as the head arrives, independent of `Incoming::frame()` on the body | None. This is exactly the SSE first-token-early requirement. |
//! | b | Trailers stream both ways (request and response) | **Works cleanly**, verified on h2 | `http_body::Frame::trailers(HeaderMap)` to write; `http_body_util::BodyExt::collect()` + `Collected::trailers()` to read (also `Frame::is_trailers()`/`into_trailers()` for frame-by-frame reading) | Only exercised on h2 here (gRPC's actual transport); h1 chunked trailers are a separate, lower-priority code path we did not spike -- flag as a follow-up if h1 trailers become a requirement. |
//! | c | h2 RST_STREAM surfaces as a distinct, inspectable error | **Works cleanly** | Body `poll_frame` yields `Err(h2::Error::from(h2::Reason::CANCEL))` server-side; hyper wraps it and the *cause* is discoverable client-side via `std::error::Error::source(&hyper_err).and_then(|s| s.downcast_ref::<h2::Error>())`, exposing `h2::Error::reason()` / `is_reset()` | `h2::Error::reason()`/`is_reset()`/`is_remote()` are public on the `h2` crate (pinned as a plain, non-workspace dev-dependency matching hyper's transitive version) but `hyper::Error` itself has no public `h2_reason()` accessor -- callers must walk `source()` themselves, exactly as hyper does internally. The retry engine (S3) can drive off this. |
//! | d | h1 keep-alive can be disabled per-connection (for drain) | **Works cleanly** | `hyper::server::conn::http1::Builder::keep_alive(false)` -- a `Builder` is already a fresh, per-accepted-connection value in the intended server loop, so this is naturally a per-connection knob, not a process-global one. Hyper also auto-inserts `Connection: close` on the response (see `fix_keep_alive`/`enforce_version` in `hyper::proto::h1::conn`) and the `Connection` future for that peer resolves `Ok(())` once the one in-flight request is served | An alternative, coarser-grained mechanism is `Connection::graceful_shutdown()` (drains in-flight requests but immediately rejects a next request on the *same* connection); `keep_alive(false)` was simpler to prove per-connection intent for a fresh connection and is what this spike exercises. |
//!
//! Net: no fallback to `httparse` + raw `h2` is needed for any of the four
//! capabilities; hyper 1.x's low-level `conn` API supports all of them
//! directly.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::duplex;
use tokio::time::Instant;

/// (a) Response headers (and the first body chunk) must reach the client
/// before the server has produced its *final* chunk -- the SSE
/// first-token-early requirement.
#[tokio::test]
async fn a_headers_and_first_chunk_flush_before_full_body() {
    let (client_io, server_io) = duplex(64 * 1024);

    // A body that yields one chunk immediately, pauses (simulating slow LLM
    // token generation), then yields a second chunk and ends.
    //
    // Rust note: `tokio::sync::mpsc::Receiver` doesn't implement `Stream`
    // itself (that's what the separate `tokio-stream` crate is for); we
    // avoid that extra dependency here by wrapping its `poll_recv` method
    // directly with `futures::stream::poll_fn`.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
    let server_produced_all_chunks = tokio::spawn(async move {
        tx.send(Ok(Frame::data(Bytes::from_static(b"first-chunk-"))))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        tx.send(Ok(Frame::data(Bytes::from_static(b"second-chunk"))))
            .await
            .unwrap();
        // Dropping `tx` here ends the stream (the receiver observes `None`).
    });
    let stream = futures::stream::poll_fn(move |cx| rx.poll_recv(cx));
    let body = StreamBody::new(stream);
    // Rust note: `service_fn` needs an `Fn`, but our test only ever serves
    // one request on this connection, so a `Mutex<Option<_>>` we `.take()`
    // once is a simple way to move a one-shot value into a callable that the
    // trait requires to be (unboundedly) re-callable.
    let body = Mutex::new(Some(body));

    let service = service_fn(move |_req: Request<Incoming>| {
        let body = body.lock().unwrap().take().expect("service called once");
        let resp = Response::builder()
            .status(StatusCode::OK)
            .body(body)
            .unwrap();
        std::future::ready(Ok::<_, Infallible>(resp))
    });

    tokio::spawn(async move {
        let io = TokioIo::new(server_io);
        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .await
            .expect("server connection");
    });

    let io = TokioIo::new(client_io);
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io)
        .await
        .expect("client handshake");
    tokio::spawn(async move {
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
    let elapsed_to_first_chunk = t_start.elapsed();
    assert_eq!(
        first_frame.into_data().ok().as_deref(),
        Some(&b"first-chunk-"[..])
    );

    // Head + first chunk must arrive well before the server's artificial
    // 200ms pause elapses -- i.e. hyper is not buffering the whole body
    // before writing anything.
    assert!(
        elapsed_to_first_chunk < Duration::from_millis(100),
        "head+first-chunk took {elapsed_to_first_chunk:?}, expected well under \
         the server's 200ms inter-chunk pause"
    );

    // Draining the rest of the body takes until the server's delayed second
    // chunk arrives -- proving the early arrival above wasn't just "the
    // whole exchange happened to be fast".
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

    assert!(response.body_mut().frame().await.is_none());
    server_produced_all_chunks.await.unwrap();
}

/// (b) Trailers on both an outgoing request body and an outgoing response
/// body are readable on the other end, over h2.
#[tokio::test]
async fn b_trailers_flow_both_ways_over_h2() {
    let (client_io, server_io) = duplex(64 * 1024);

    // Rust note: `Arc<Mutex<..>>` is how the server handler (an `Fn`, called
    // from inside hyper) hands data back out to the test's assertions below
    // -- interior mutability shared across the closure boundary.
    let seen_request_trailers: Arc<Mutex<Option<HeaderMap>>> = Arc::new(Mutex::new(None));
    let seen_request_trailers_in_service = seen_request_trailers.clone();

    let service = service_fn(move |req: Request<Incoming>| {
        let seen = seen_request_trailers_in_service.clone();
        async move {
            let collected = req
                .into_body()
                .collect()
                .await
                .expect("collect request body+trailers");
            *seen.lock().unwrap() = collected.trailers().cloned();

            let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
            tokio::spawn(async move {
                tx.send(Ok(Frame::data(Bytes::from_static(b"resp-body"))))
                    .await
                    .unwrap();
                let mut trailers = HeaderMap::new();
                trailers.insert(
                    HeaderName::from_static("x-response-trailer"),
                    HeaderValue::from_static("resp-trailer-value"),
                );
                tx.send(Ok(Frame::trailers(trailers))).await.unwrap();
            });
            let body = StreamBody::new(futures::stream::poll_fn(move |cx| rx.poll_recv(cx)));

            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(body)
                    .unwrap(),
            )
        }
    });

    tokio::spawn(async move {
        let io = TokioIo::new(server_io);
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(io, service)
            .await
            .expect("server connection");
    });

    let io = TokioIo::new(client_io);
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake::<_, _, StreamBody<_>>(TokioExecutor::new(), io)
            .await
            .expect("client handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let (req_tx, mut req_rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
    tokio::spawn(async move {
        req_tx
            .send(Ok(Frame::data(Bytes::from_static(b"req-body"))))
            .await
            .unwrap();
        let mut trailers = HeaderMap::new();
        trailers.insert(
            HeaderName::from_static("x-request-trailer"),
            HeaderValue::from_static("req-trailer-value"),
        );
        req_tx.send(Ok(Frame::trailers(trailers))).await.unwrap();
    });
    let req_body = StreamBody::new(futures::stream::poll_fn(move |cx| req_rx.poll_recv(cx)));

    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("host", "localhost")
        .body(req_body)
        .unwrap();

    let response = sender.send_request(req).await.expect("send_request");
    assert_eq!(response.status(), StatusCode::OK);
    let collected = response
        .into_body()
        .collect()
        .await
        .expect("collect response body+trailers");

    let response_trailers = collected.trailers().expect("response carried trailers");
    assert_eq!(
        response_trailers.get("x-response-trailer").unwrap(),
        "resp-trailer-value"
    );

    // By the time the response is fully collected, the server must already
    // have observed the request trailers (it awaited `collect()` on the
    // request body before ever building the response).
    let request_trailers = seen_request_trailers
        .lock()
        .unwrap()
        .clone()
        .expect("server observed request trailers");
    assert_eq!(
        request_trailers.get("x-request-trailer").unwrap(),
        "req-trailer-value"
    );
}

/// (c) An h2 stream reset (RST_STREAM) must surface as a distinct,
/// inspectable error -- not collapse into an opaque IO error -- so the
/// retry engine (S3) can drive off it.
#[tokio::test]
async fn c_h2_rst_stream_is_a_distinct_error() {
    let (client_io, server_io) = duplex(64 * 1024);

    let service = service_fn(|_req: Request<Incoming>| async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, h2::Error>>(4);
        tokio::spawn(async move {
            tx.send(Ok(Frame::data(Bytes::from_static(b"partial"))))
                .await
                .unwrap();
            // Give the data frame time to actually reach the client before
            // the reset -- without this, both frames can be queued and
            // flushed to the wire in the same poll, and (legitimately, per
            // HTTP/2 semantics) the peer's h2 stack is free to discard a
            // just-arrived DATA frame for a stream it's also resetting.
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Abort the stream with an explicit RST_STREAM(CANCEL) instead
            // of completing it normally. hyper turns a body-stream `Err`
            // into a real RST_STREAM (see hyper::proto::h2::PipeToSendStream
            // / SendStreamExt::on_user_err), using the `h2::Reason` carried
            // by the error when the error *is* an `h2::Error`.
            tx.send(Err(h2::Error::from(h2::Reason::CANCEL)))
                .await
                .unwrap();
        });
        let body = StreamBody::new(futures::stream::poll_fn(move |cx| rx.poll_recv(cx)));
        Ok::<_, Infallible>(
            Response::builder()
                .status(StatusCode::OK)
                .body(body)
                .unwrap(),
        )
    });

    tokio::spawn(async move {
        let io = TokioIo::new(server_io);
        // The body error above legitimately surfaces as a connection/stream
        // error on the server side too; we only assert on what the *client*
        // observes below, which is what a proxy acting as an h2 client to
        // an upstream would see.
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(io, service)
            .await;
    });

    let io = TokioIo::new(client_io);
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake::<_, _, Empty<Bytes>>(TokioExecutor::new(), io)
            .await
            .expect("client handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("/")
        .header("host", "localhost")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let mut response = sender.send_request(req).await.expect("send_request");

    // The partial chunk before the reset arrives fine...
    let first = response
        .body_mut()
        .frame()
        .await
        .expect("stream not ended")
        .expect("frame ok");
    assert!(first.is_data());

    // ...but the reset surfaces as a distinct, downcastable `h2::Error` --
    // not just "the connection died" -- so retry logic can tell "upstream
    // reset the stream" apart from a generic IO error.
    let err = response
        .body_mut()
        .frame()
        .await
        .expect("reset surfaces as a completed poll, not a hang")
        .expect_err("expected the reset to surface as an error, not a clean end-of-stream");

    let h2_err = std::error::Error::source(&err)
        .and_then(|src| src.downcast_ref::<h2::Error>())
        .expect("hyper::Error must chain to the underlying h2::Error");
    assert!(h2_err.is_reset());
    assert_eq!(h2_err.reason(), Some(h2::Reason::CANCEL));
}

/// (d) h1 keep-alive can be disabled per-connection, so drain can serve the
/// in-flight request on a connection and then close it without affecting
/// any other connection.
#[tokio::test]
async fn d_h1_keep_alive_disabled_per_connection() {
    let (client_io, server_io) = duplex(64 * 1024);

    let service = service_fn(|_req: Request<Incoming>| async move {
        Ok::<_, Infallible>(
            Response::builder()
                .status(StatusCode::OK)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
    });

    let server_conn = tokio::spawn(async move {
        let io = TokioIo::new(server_io);
        // A `Builder` is a fresh, cheap value created per accepted
        // connection in a real server loop, so `keep_alive(false)` is
        // naturally a per-connection knob -- exactly what drain needs.
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder.keep_alive(false);
        builder.serve_connection(io, service).await
    });

    let io = TokioIo::new(client_io);
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io)
        .await
        .expect("client handshake");
    let client_conn = tokio::spawn(conn);

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
    // Hyper itself inserts `Connection: close` once keep-alive is disabled
    // for the connection (see `fix_keep_alive`/`enforce_version` in
    // `hyper::proto::h1::conn`), so the client can tell -- without us having
    // to set the header ourselves -- that this specific connection will not
    // be reused.
    assert_eq!(
        response
            .headers()
            .get(http::header::CONNECTION)
            .map(|v| v.as_bytes()),
        Some(&b"close"[..])
    );

    // The server-side `Connection` future resolves on its own right after
    // serving the one request -- it does not idle waiting for a second
    // request -- because keep-alive was disabled for this connection.
    server_conn
        .await
        .unwrap()
        .expect("connection ends cleanly after the one request");
    client_conn
        .await
        .unwrap()
        .expect("client side observes a clean connection close");

    // And a second request on the same `SendRequest` handle now fails,
    // because the connection is gone -- proving the close was real, not
    // just an advisory header.
    let req2 = Request::builder()
        .method("GET")
        .uri("/")
        .header("host", "localhost")
        .body(Empty::<Bytes>::new())
        .unwrap();
    assert!(sender.send_request(req2).await.is_err());
}
