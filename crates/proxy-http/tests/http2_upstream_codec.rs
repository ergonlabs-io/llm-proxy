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
