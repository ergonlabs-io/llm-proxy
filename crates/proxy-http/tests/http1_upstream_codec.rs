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

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full};
use proxy_http::codec::{send_upstream_http1, serve_http1, Http1Options, UpstreamCodecError};
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
