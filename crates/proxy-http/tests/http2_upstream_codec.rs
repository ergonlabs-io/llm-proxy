//! Tests for the upstream HTTP/2 codec, including streaming and wire-level
//! reset handling. The codec uses `spawn_local`, so tests run inside a `LocalSet`.

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

/// Executor for the test server's local connection driver.
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

/// Loopback server that returns a two-frame streaming response.
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

            // Capturing `Rc` makes the request body provably `!Send`.
            let not_send: Rc<()> = Rc::new(());
            let body: StreamBody = local_boxed(Full::new(Bytes::from_static(b"req-body")).map_err(
                move |infallible: std::convert::Infallible| {
                    let _keep = &not_send;
                    match infallible {}
                },
            ));

            // Origin-form plus Host exercises `:authority` reconstruction.
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
                on_upgrade: None,
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
            // Dropping the listener leaves this ephemeral port closed.
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
                    on_upgrade: None,
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

/// Raw h2 server that resets a stream; hyper's server API cannot send this reset.
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
        // `send_reset` only queues the frame; polling flushes it before close.
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
        on_upgrade: None,
    }
}

/// S3.2 refusal handling over a real connection, exercising Hyper's h2 error downcast.
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

/// CANCEL may arrive after work was done, so unlike REFUSED_STREAM it remains a send error.
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
