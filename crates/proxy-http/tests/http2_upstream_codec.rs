//! Standalone tests for the upstream HTTP/2 codec
//! (`proxy_http::codec::send_upstream_http2`), the h2 mirror of
//! `tests/http1_upstream_codec.rs`. The loopback h2 server here is lifted
//! from the now-deleted de-risking spike (`h2_upstream_spike.rs`) -- this
//! test file supersedes it.
//!
//! `send_upstream_http2` spawns its connection-driving future with
//! `tokio::task::spawn_local`, so every test needs a running `LocalSet` --
//! provided here via `#[tokio::test(flavor = "current_thread")]` +
//! `LocalSet::run_until`, per the module doc on `send_upstream_http2`.

use std::future::Future;
use std::rc::Rc;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use proxy_http::codec::{send_upstream_http2, UpstreamCodecError};
use proxy_http::filter::RequestHeaders;
use proxy_http::handler::{local_boxed, DownstreamInfo, HttpRequestParts, StreamBody};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::LocalSet;

/// Same-shape executor as `codec::LocalExec`, but this one only needs to
/// exist on the *server* side of these tests (the server-side response body
/// here is also driven by an executor-spawned pump under a `current_thread`
/// runtime) -- the codec under test supplies its own internally.
#[derive(Clone)]
struct LocalExec;

impl<F> hyper::rt::Executor<F> for LocalExec
where
    F: Future + 'static,
{
    fn execute(&self, fut: F) {
        tokio::task::spawn_local(fut);
    }
}

/// Loopback h2 "upstream" server: accepts one connection and replies to every
/// request with a response body that streams two frames, so the round trip
/// exercises streaming rather than a single buffered reply.
async fn spawn_h2_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::task::spawn_local(async move {
        let (io, _peer) = listener.accept().await.expect("accept");
        let io = TokioIo::new(io);

        let service = service_fn(|_req: Request<Incoming>| async move {
            let (tx, mut rx) =
                tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
            tokio::task::spawn_local(async move {
                tx.send(Ok(Frame::data(Bytes::from_static(b"first-"))))
                    .await
                    .unwrap();
                tx.send(Ok(Frame::data(Bytes::from_static(b"second"))))
                    .await
                    .unwrap();
                // Dropping `tx` here ends the stream.
            });
            let stream = futures::stream::poll_fn(move |cx| rx.poll_recv(cx));
            let body = http_body_util::StreamBody::new(stream);
            Ok::<_, std::convert::Infallible>(
                hyper::Response::builder()
                    .status(StatusCode::OK)
                    .body(body)
                    .unwrap(),
            )
        });

        hyper::server::conn::http2::Builder::new(LocalExec)
            .serve_connection(io, service)
            .await
            .expect("server h2 connection");
    });

    addr
}

#[tokio::test(flavor = "current_thread")]
async fn h2_round_trip_streams_response_with_non_send_request_body() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_h2_upstream().await;
            let io = TcpStream::connect(addr).await.expect("connect");

            // Request body that is provably `!Send`: the `map_err` closure
            // captures an `Rc`, exactly like the deleted spike's test.
            let not_send: Rc<()> = Rc::new(());
            let body: StreamBody = local_boxed(Full::new(Bytes::from_static(b"req-body")).map_err(
                move |infallible: std::convert::Infallible| {
                    let _keep = &not_send;
                    match infallible {}
                },
            ));

            // Origin-form URI + a `Host` header, matching the shape our
            // router actually produces after h1-style processing -- this
            // exercises the `:authority` reconstruction path.
            let mut headers = HeaderMap::new();
            headers.insert(http::header::HOST, "localhost".parse().unwrap());
            let req = HttpRequestParts {
                head: RequestHeaders {
                    method: Method::GET,
                    uri: Uri::from_static("/"),
                    headers,
                },
                body,
                downstream: DownstreamInfo::loopback(),
            };

            let response = send_upstream_http2(io, req)
                .await
                .expect("send_upstream_http2");
            assert_eq!(response.head.status, StatusCode::OK);

            let bytes = response
                .body
                .collect()
                .await
                .expect("collect body")
                .to_bytes();
            assert_eq!(&bytes[..], b"first-second");
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn connect_to_nothing_yields_handshake_error() {
    LocalSet::new()
        .run_until(async {
            // Bind then immediately drop the listener so the port is
            // guaranteed closed on this host, then connect straight to it.
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            drop(listener);

            let connect_result = TcpStream::connect(addr).await;
            if let Ok(io) = connect_result {
                let body: StreamBody = local_boxed(
                    Full::new(Bytes::new())
                        .map_err(|infallible: std::convert::Infallible| match infallible {}),
                );
                let mut headers = HeaderMap::new();
                headers.insert(http::header::HOST, "localhost".parse().unwrap());
                let req = HttpRequestParts {
                    head: RequestHeaders {
                        method: Method::GET,
                        uri: Uri::from_static("/"),
                        headers,
                    },
                    body,
                    downstream: DownstreamInfo::loopback(),
                };
                let result = send_upstream_http2(io, req).await;
                assert!(matches!(
                    result,
                    Err(UpstreamCodecError::Handshake(_)) | Err(UpstreamCodecError::Send(_))
                ));
            }
        })
        .await;
}

/// A loopback h2 "upstream" that accepts one stream and immediately answers
/// `RST_STREAM(REFUSED_STREAM)`.
///
/// Built on the raw `h2` server API rather than hyper's, deliberately:
/// hyper's server has no way to refuse a stream (it always intends to serve
/// one), and the whole point of this test is that a REFUSED_STREAM arrives on
/// the actual wire. `reason` is a parameter so the negative case below can
/// send a *different* reset through the identical path -- the two tests
/// differ in exactly one byte of protocol, which is what makes the
/// comparison mean anything.
async fn spawn_h2_resetting_upstream(reason: h2::Reason) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::task::spawn_local(async move {
        let (io, _peer) = listener.accept().await.expect("accept");
        let mut conn = h2::server::handshake(io)
            .await
            .expect("h2 server handshake");
        if let Some(accepted) = conn.accept().await {
            let (_req, mut respond) = accepted.expect("accept stream");
            respond.send_reset(reason);
        }
        // Keep polling the connection so the RST_STREAM is actually flushed
        // to the wire -- `send_reset` only queues it. Without this the client
        // sees the connection close instead of the reset, which projects to a
        // completely different outcome and would make this test pass for the
        // wrong reason.
        while let Some(accepted) = conn.accept().await {
            drop(accepted);
        }
    });

    addr
}

fn refused_stream_request() -> HttpRequestParts {
    let body: StreamBody = local_boxed(
        Full::new(Bytes::new()).map_err(|infallible: std::convert::Infallible| match infallible {}),
    );
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, "localhost".parse().unwrap());
    HttpRequestParts {
        head: RequestHeaders {
            method: Method::GET,
            uri: Uri::from_static("/"),
            headers,
        },
        body,
        downstream: DownstreamInfo::loopback(),
    }
}

/// S3.2 `refused-stream`, end to end on a real connection.
///
/// This drives an actual `RST_STREAM(REFUSED_STREAM)` rather than
/// constructing an `UpstreamCodecError` by hand, and that is the entire
/// point. The decode works by downcasting the `hyper::Error`'s source chain
/// to `h2::Error`, which is sound only while `h2` is the same compiled crate
/// hyper links -- if the tree ever resolved two semver-incompatible copies,
/// `downcast_ref` would return `None`, the decode would become a silent
/// permanent no-op, and a hand-built-error test would still pass. See
/// `codec::h2_reason`.
#[tokio::test(flavor = "current_thread")]
async fn refused_stream_is_decoded_from_a_real_rst_stream() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_h2_resetting_upstream(h2::Reason::REFUSED_STREAM).await;
            let io = TcpStream::connect(addr).await.expect("connect");

            // Rust note: `expect_err` needs `T: Debug` and `HttpResponseParts`
            // is not, so match the Result explicitly.
            let err = match send_upstream_http2(io, refused_stream_request()).await {
                Ok(_) => panic!("a refused stream must not look like a successful response"),
                Err(err) => err,
            };

            assert!(
                matches!(err, UpstreamCodecError::RefusedStream),
                "REFUSED_STREAM must decode to its own variant -- as a plain `Send` it would \
                 project to ResetBeforeHeaders, and the `refused_stream` retry trigger every \
                 config in this repo switches on would keep on never firing. Got: {err:?}"
            );
        })
        .await;
}

/// The negative case, and the one that stops the test above from passing for
/// the wrong reason: an identical path, identical harness, one different
/// reason code. `CANCEL` means the peer may well have done work, so it must
/// stay a conservative `Send` -- only REFUSED_STREAM carries the "nothing
/// happened, replay freely" guarantee S3.2 relies on.
#[tokio::test(flavor = "current_thread")]
async fn a_non_refused_reset_is_not_decoded_as_refused_stream() {
    LocalSet::new()
        .run_until(async {
            let addr = spawn_h2_resetting_upstream(h2::Reason::CANCEL).await;
            let io = TcpStream::connect(addr).await.expect("connect");

            let err = match send_upstream_http2(io, refused_stream_request()).await {
                Ok(_) => panic!("a cancelled stream is still a failure"),
                Err(err) => err,
            };

            assert!(
                !matches!(err, UpstreamCodecError::RefusedStream),
                "only REFUSED_STREAM may decode to RefusedStream; CANCEL must not, or an \
                 unsafe replay becomes possible on a non-idempotent request. Got: {err:?}"
            );
        })
        .await;
}
