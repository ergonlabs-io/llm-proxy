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
//! | e | HTTP/1.1 Upgrade (WebSocket-shaped `101` handshake) hands both peers a raw bidirectional stream, on both the server *and* client low-level APIs, and coexists with the drain `select!`/`graceful_shutdown` shape | **Works cleanly, with two "must-call-`.with_upgrades()`" caveats** | Server: `hyper::server::conn::http1::Builder::serve_connection(io, service).with_upgrades()`. Client: `hyper::client::conn::http1::handshake(io)` gives `(SendRequest, Connection)`, and that `Connection` *also* needs `.with_upgrades()`. Both sides call `hyper::upgrade::on(&mut req_or_resp)` to get an `OnUpgrade` future that resolves to `hyper::upgrade::Upgraded`, wrapped in `hyper_util::rt::TokioIo` to get back a plain `AsyncRead + AsyncWrite`. | **(1)** `.with_upgrades()` is required on **both** ends, not just the server -- easy to miss since only the server side is commonly documented. Skip it on either side and `Dispatched::Upgrade` takes the `pending.manual()` path (`hyper::proto::Pending::manual`, `src/upgrade.rs`) instead of `pending.fulfill(..)`, so `hyper::upgrade::on(..).await` resolves to an `Err` ("upgrades cannot be used with `Connection::without_upgrades`" case) rather than the raw stream, on whichever side forgot it. **(2)** `.with_upgrades()` returns a *different type* (`UpgradeableConnection<T, S>`, distinct from the plain `Connection<T, S>`) but with an identical API surface for the drain path: it still implements `Future<Output = crate::Result<()>>` and has its own inherent `graceful_shutdown(self: Pin<&mut Self>)`, so `tokio::pin!` + `tokio::select!` + `.as_mut().graceful_shutdown()` -- the exact shape `serve_http1` (`codec.rs`) uses -- needed no changes at all; only the local variable's type changes, not the pattern. **(3)** Ordering: `hyper::upgrade::on` must be called on the request (server) / response (client) *before* it is otherwise consumed or the 101 response is returned -- it removes an `OnUpgrade` value hyper already stashed in the message's `Extensions` during parsing (server: set because the request carried `Upgrade`+HTTP/1.1; client: set once the `101` response is parsed), it does not manufacture one after the fact. **(4)** No extra Cargo feature was needed -- the workspace's existing `["http1","http2","client","server"]` hyper features are sufficient; `hyper::upgrade` is compiled in whenever any of `client`/`server` is paired with `http1`/`http2`. |
//!
//! Net: no fallback to `httparse` + raw `h2` is needed for any of the five
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
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
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

/// (e) An HTTP/1.1 Upgrade (the WebSocket handshake shape: `101 Switching
/// Protocols` plus `Upgrade`/`Connection` headers) hands *both* peers a raw
/// bidirectional byte stream via the low-level `conn` API, and a server
/// connection built with `.with_upgrades()` still fits the exact
/// `tokio::pin!` + `tokio::select!` + `graceful_shutdown()` drain shape
/// `serve_http1` (`codec.rs`) depends on.
#[tokio::test]
async fn e_h1_upgrade_tunnels_bidirectionally() {
    const CLIENT_MSG: &[u8] = b"ping-through-the-tunnel";
    const SERVER_MSG: &[u8] = b"pong-back-through-the-tunnel";

    let (client_io, server_io) = duplex(64 * 1024);

    // Fires once the dispatcher has actually parsed a request head and
    // invoked the service -- i.e. once the connection is provably no longer
    // *idle* -- so the drain signal below lands mid-request rather than
    // before any request has arrived. `hyper::proto::h1::Conn::
    // disable_keep_alive` closes an *idle* connection outright instead of
    // draining it, so firing this any earlier would race the client's
    // request off the wire before the upgrade ever happens.
    //
    // Rust note: a `Mutex<Option<_>>` we `.take()` once, same reason as
    // finding (a) above -- the sender only needs to fire once, but
    // `service_fn` requires an (unboundedly re-callable) `Fn`.
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_tx = Mutex::new(Some(shutdown_tx));

    let service = service_fn(move |mut req: Request<Incoming>| {
        if let Some(tx) = shutdown_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
        // Rust note: `hyper::upgrade::on` must be called on the request (or
        // its parts) *before* this handler returns its response -- it pulls
        // an `OnUpgrade` value hyper already stashed in the request's
        // `Extensions` while parsing (because the request carried
        // `Upgrade` + HTTP/1.1), it doesn't manufacture one afterwards.
        let on_upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let upgraded = on_upgrade
                .await
                .expect("server obtains the upgraded stream");
            let mut io = TokioIo::new(upgraded);
            let mut buf = [0u8; CLIENT_MSG.len()];
            io.read_exact(&mut buf)
                .await
                .expect("server reads the client's tunnel bytes");
            assert_eq!(&buf, CLIENT_MSG);
            io.write_all(SERVER_MSG)
                .await
                .expect("server writes its reply over the same tunnel");
            io.flush().await.unwrap();
        });

        let resp = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::CONNECTION, "Upgrade")
            .body(Empty::<Bytes>::new())
            .unwrap();
        std::future::ready(Ok::<_, Infallible>(resp))
    });

    let server_conn = tokio::spawn(async move {
        let io = TokioIo::new(server_io);
        // `.with_upgrades()` is REQUIRED: a plain `serve_connection` (no
        // `.with_upgrades()`) still parses the request and sends the `101`
        // fine, but the spawned task's `on_upgrade.await` above would
        // resolve to an error instead of the `Upgraded` stream --
        // `proto::Dispatched::Upgrade` takes the `Pending::manual()` path
        // rather than fulfilling it. See finding (e) caveat (1).
        let conn = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .with_upgrades();
        // Same pinning `serve_http1` uses: `UpgradeableConnection` is a
        // distinct type from the plain `Connection` (and is likewise
        // `!Unpin`, wrapping the same self-referential dispatcher state),
        // but exposes the identical `Future` + `graceful_shutdown(Pin<&mut
        // Self>)` surface, so `.with_upgrades()` changes nothing about this
        // pin/select!/graceful_shutdown pattern -- see finding (e) caveat
        // (2).
        tokio::pin!(conn);

        tokio::select! {
            result = &mut conn => {
                result.expect("connection completes on its own if the drain signal loses the race");
            }
            _ = &mut shutdown_rx => {
                conn.as_mut().graceful_shutdown();
            }
        }

        // `graceful_shutdown` only *requests* the drain (mirrors finding
        // (d)/`serve_http1`); the in-flight request/response -- and here,
        // the upgrade handoff that follows it -- still has to be driven to
        // completion by continuing to poll.
        conn.await.expect(
            "a .with_upgrades() connection completes after graceful_shutdown, \
             still handing off the upgrade rather than dropping it",
        );
    });

    let io = TokioIo::new(client_io);
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(io)
        .await
        .expect("client handshake");
    // The low-level CLIENT connection needs `.with_upgrades()` too, for the
    // identical reason as the server above -- without it,
    // `hyper::upgrade::on(&mut response)` below would resolve to an error
    // instead of the `Upgraded` stream. See finding (e) caveat (1); this is
    // the one easy to miss, since only the server side is commonly
    // documented.
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("/")
        .header("host", "localhost")
        .header(http::header::UPGRADE, "websocket")
        .header(http::header::CONNECTION, "Upgrade")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let mut response = sender.send_request(req).await.expect("send_request");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(
        response.headers().get(http::header::UPGRADE).unwrap(),
        "websocket"
    );

    let client_upgraded = hyper::upgrade::on(&mut response)
        .await
        .expect("client obtains the upgraded stream");
    let mut client_upgraded = TokioIo::new(client_upgraded);

    // Bytes flow both ways over the tunnel, after the 101 -- the actual
    // capability finding (e) exists to prove. No WebSocket framing library
    // is involved; raw bytes are the point.
    client_upgraded
        .write_all(CLIENT_MSG)
        .await
        .expect("client writes its half of the tunnel");
    client_upgraded.flush().await.unwrap();

    let mut reply = [0u8; SERVER_MSG.len()];
    client_upgraded
        .read_exact(&mut reply)
        .await
        .expect("client reads the server's reply over the same tunnel");
    assert_eq!(&reply, SERVER_MSG);

    server_conn.await.unwrap();
}
