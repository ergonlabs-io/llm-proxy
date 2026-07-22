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
    local_boxed, BodyError, HttpRequestParts, HttpResponseParts, StreamBody, StreamHandler,
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
) -> Result<(), CodecError>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let io = TokioIo::new(io);

    // Rust note: `service_fn` requires an `Fn`, so the closure below only
    // ever *borrows* `handler` (via `.clone()` of the `Rc`, a pointer bump)
    // rather than consuming it -- it's called once per request on this
    // connection, an unbounded number of times.
    let service = service_fn(move |req: Request<Incoming>| {
        let handler = handler.clone();
        async move { Ok::<_, std::convert::Infallible>(serve_one(&*handler, req).await) }
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

/// Convert one `hyper::Request<Incoming>` into [`HttpRequestParts`], hand it
/// to `handler`, and convert the resulting [`HttpResponseParts`] back into a
/// `hyper::Response<StreamBody>`.
async fn serve_one(handler: &dyn StreamHandler, req: Request<Incoming>) -> Response<StreamBody> {
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

    let response = handler.handle(HttpRequestParts { head, body }).await;
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
