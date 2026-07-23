//! WP-10 chunk B -- the downstream HTTP/1.1 codec: drives one accepted
//! connection as HTTP/1.1, converting each request into
//! [`crate::handler::HttpRequestParts`], handing it to a
//! [`crate::handler::StreamHandler`], and streaming the returned
//! [`crate::handler::HttpResponseParts`] back incrementally (headers flush
//! before the body completes -- see `tests/hyper_spike.rs` finding (a), the
//! SSE first-token-early requirement this whole codec exists to preserve).
//!
//! Scope: downstream h1 only. h2 downstream, HTTP upgrades (Appendix S10),
//! and the *upstream* (proxy-to-origin) codec are later WP-10 chunks. Wiring
//! this into `proxy-core`'s listener (so an `http_connection_manager` filter
//! chain actually serves traffic) is a deliberately deferred integration
//! chunk -- this module is tested standalone, over an in-memory pipe, in
//! `tests/http1_codec.rs`.

use std::future::Future;
use std::rc::Rc;

use http::{Request, Response};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::filter::{RequestHeaders, ResponseHeaders};
use crate::handler::{
    local_boxed, BodyError, DownstreamInfo, HttpRequestParts, HttpResponseParts, StreamBody,
    StreamHandler,
};

/// Per-connection h1 options. Room to grow (header/body size limits) as
/// later chunks need them.
pub struct Http1Options {
    /// Forwarded straight to `hyper::server::conn::http1::Builder::keep_alive`
    /// (spike finding (d): this is a per-connection knob, exactly what drain
    /// needs -- disable it on a connection about to be drained rather than
    /// flipping a process-global setting).
    pub keep_alive: bool,
}

/// Connection-level codec failures -- distinct from a per-request handler
/// error (a handler is expected to turn its own failures into an HTTP
/// response, e.g. a 5xx, not propagate them here).
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("http/1.1 connection error: {0}")]
    Connection(#[source] hyper::Error),
}

/// Serve one accepted downstream connection as HTTP/1.1 until the peer
/// closes it, `shutdown` fires (see below), or a connection-level error
/// occurs.
///
/// Generic over `IO` so this same function serves both plaintext
/// `TcpStream`s and (once WP-08's TLS termination is wired to HTTP
/// listeners) TLS-terminated streams.
///
/// `shutdown` is the drain signal (mirrors `proxy-core`'s
/// `tokio::sync::watch`-based drain elsewhere in the workspace, but this
/// crate takes any future so it stays decoupled from that machinery). When
/// it resolves, the connection is told to gracefully shut down: finish
/// serving any in-flight request, then refuse to accept a next one on this
/// connection and return -- matching spike finding (d)'s description of
/// `graceful_shutdown`.
pub async fn serve_http1<IO>(
    io: IO,
    handler: Rc<dyn StreamHandler>,
    options: Http1Options,
    shutdown: impl Future<Output = ()>,
    downstream: DownstreamInfo,
) -> Result<(), CodecError>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let io = TokioIo::new(io);

    // Rust note: `service_fn` requires an `Fn`, so the closure below only
    // ever *borrows* `handler` (via `.clone()` of the `Rc`, a pointer bump)
    // rather than consuming it -- it's called once per request on this
    // connection, an unbounded number of times. `downstream` is `Copy`, so
    // each invocation gets its own duplicate rather than a shared borrow.
    let service = service_fn(move |req: Request<Incoming>| {
        let handler = handler.clone();
        async move { Ok::<_, std::convert::Infallible>(serve_one(&*handler, req, downstream).await) }
    });

    let mut builder = hyper::server::conn::http1::Builder::new();
    builder.keep_alive(options.keep_alive);
    let conn = builder.serve_connection(io, service);

    // Rust note: `tokio::pin!` puts `conn` on the stack and shadows it with a
    // `Pin<&mut _>` -- required because `graceful_shutdown` (below) takes
    // `Pin<&mut Connection<..>>`, and a hyper `Connection` is itself `!Unpin`
    // in general (it holds internal self-referential-ish state), so it can't
    // just be passed around by value once we need to call methods on a
    // pinned reference to it.
    tokio::pin!(conn);
    tokio::pin!(shutdown);

    tokio::select! {
        result = &mut conn => {
            return result.map_err(CodecError::Connection);
        }
        _ = &mut shutdown => {
            conn.as_mut().graceful_shutdown();
        }
    }

    // `graceful_shutdown` only *requests* the shutdown; the connection must
    // keep being polled to actually drain the in-flight request (if any) and
    // then finish. Spike finding (d): after this, hyper serves out anything
    // already in flight, then closes without accepting a next request.
    conn.await.map_err(CodecError::Connection)
}

/// Upstream (proxy-to-origin) connection-level codec failures. Distinct from
/// [`CodecError`] (which is downstream-only): the router (later WP) maps
/// these to pool errors / response flags, but this module has no notion of
/// either -- it only ever returns its own typed error.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamCodecError {
    #[error("http/1.1 client handshake failed: {0}")]
    Handshake(#[source] hyper::Error),
    #[error("http/1.1 upstream connection error: {0}")]
    Connection(#[source] hyper::Error),
    #[error("http/1.1 send_request failed: {0}")]
    Send(#[source] hyper::Error),
}

/// Send one request upstream over `io` as HTTP/1.1 and return the response,
/// head-first with a streaming body -- the client-side mirror of
/// `serve_http1`/`serve_one`.
///
/// Generic over `IO` for the same reason `serve_http1` is: this same function
/// drives both plaintext `TcpStream`s and (once upstream TLS origination
/// exists) TLS-wrapped streams.
pub async fn send_upstream_http1<IO>(
    io: IO,
    req: HttpRequestParts,
    options: Http1Options,
) -> Result<HttpResponseParts, UpstreamCodecError>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let io = TokioIo::new(io);

    // Rust note: unlike the downstream server `Builder` (which has a
    // `keep_alive` knob controlling whether *it* offers a next request slot),
    // hyper's client `Builder` has no such method -- client-side keep-alive
    // is negotiated per-request via the `Connection` header, not a
    // connection-wide setting. So `options.keep_alive` is threaded through by
    // setting `Connection: close` on the outgoing request below when it's
    // `false`, rather than on this builder.
    let builder = hyper::client::conn::http1::Builder::new();
    let (mut sender, conn) = builder
        .handshake::<_, StreamBody>(io)
        .await
        .map_err(UpstreamCodecError::Handshake)?;

    // Rust note: like the downstream `Connection`, the client `Connection`
    // future must be polled for the handshake/request/response machinery to
    // make progress at all -- hyper's low-level client API doesn't spawn it
    // for you. It's `!Send` here because the `StreamBody` it drives (via
    // `sender.send_request`) is deliberately `!Send` (ADR-0003), so we can't
    // hand it to `tokio::spawn` (which requires `Send + 'static` futures);
    // `tokio::task::spawn_local` is the `!Send`-friendly equivalent, but it
    // requires a `LocalSet` to be running on this task -- the worker runtime
    // already provides one (as `serve_http1`'s call sites do), and tests
    // calling this function must supply one too (see
    // `tests/http1_upstream_codec.rs`). We keep the `JoinHandle` only to
    // surface a `Connection` error if the caller wants it; for v1 a detached
    // connection task (dropped `JoinHandle`) is an acceptable simplification
    // -- the connection is torn down when `sender`/the response body are
    // dropped either way.
    let conn_task = tokio::task::spawn_local(conn);

    let RequestHeaders {
        method,
        uri,
        headers,
    } = req.head;
    let mut headers = headers;
    if !options.keep_alive {
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("close"),
        );
    }
    let mut builder = Request::builder().method(method).uri(uri);
    // Rust note: mirrors `build_response`'s wholesale `HeaderMap` swap --
    // `Request::builder()` starts with an empty map, so replace it rather
    // than re-inserting each header individually.
    *builder.headers_mut().expect("builder not yet finalized") = headers;
    let request = builder
        .body(req.body)
        .expect("method/uri were already valid; building can't fail here");

    let response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(send_err) => {
            // The request failed to go out (or the response head failed to
            // arrive); prefer surfacing that specific error over whatever the
            // detached connection task did or didn't do.
            conn_task.abort();
            return Err(UpstreamCodecError::Send(send_err));
        }
    };

    let (parts, incoming) = response.into_parts();
    let head = ResponseHeaders {
        status: parts.status,
        headers: parts.headers,
    };
    // Rust note: same adaptation `serve_one` does for the downstream request
    // body, but tagged `BodyError::Upstream` since this body is read on the
    // proxy-to-origin side of the seam.
    let body: StreamBody = local_boxed(incoming.map_err(|e| BodyError::Upstream(Box::new(e))));

    Ok(HttpResponseParts { head, body })
}

/// Convert one `hyper::Request<Incoming>` into [`HttpRequestParts`], hand it
/// to `handler`, and convert the resulting [`HttpResponseParts`] back into a
/// `hyper::Response<StreamBody>`.
async fn serve_one(
    handler: &dyn StreamHandler,
    req: Request<Incoming>,
    downstream: DownstreamInfo,
) -> Response<StreamBody> {
    let (parts, incoming) = req.into_parts();
    let head = RequestHeaders {
        method: parts.method,
        uri: parts.uri,
        headers: parts.headers,
    };
    // Rust note: `BodyExt::map_err` adapts `Incoming`'s error type
    // (`hyper::Error`) to our `BodyError`, then `local_boxed` erases the
    // concrete (now-adapted) body type into `StreamBody` -- this is the one
    // and only place downstream `Incoming` is named; everything past this
    // point (the handler, and the rest of this crate) only ever sees
    // `StreamBody`.
    let body: StreamBody = local_boxed(incoming.map_err(|e| BodyError::Downstream(Box::new(e))));

    let response = handler
        .handle(HttpRequestParts {
            head,
            body,
            downstream,
        })
        .await;
    build_response(response)
}

/// Convert [`HttpResponseParts`] into a `hyper::Response<StreamBody>`. Split
/// out for testability and to keep `serve_one` focused on the request side.
fn build_response(parts: HttpResponseParts) -> Response<StreamBody> {
    let HttpResponseParts {
        head: ResponseHeaders { status, headers },
        body,
    } = parts;
    let mut builder = Response::builder().status(status);
    // Rust note: `Response::builder().status(..)` starts with a fresh, empty
    // `HeaderMap`; swap it wholesale for the one the handler produced rather
    // than re-inserting each entry one at a time.
    *builder.headers_mut().expect("builder not yet finalized") = headers;
    builder
        .body(body)
        .expect("status was already a valid http::StatusCode; building can't fail here")
}
