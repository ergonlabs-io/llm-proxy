//! The downstream HTTP/1.1 codec: drives one accepted
//! connection as HTTP/1.1, converting each request into
//! [`crate::handler::HttpRequestParts`], handing it to a
//! [`crate::handler::StreamHandler`], and streaming the returned
//! [`crate::handler::HttpResponseParts`] back incrementally (headers flush
//! before the body completes -- see `tests/hyper_spike.rs` finding (a), the
//! SSE first-token-early requirement this whole codec exists to preserve).
//!
//! Scope: downstream h1 and h2 (`serve_http1`/`serve_http2`), plus the
//! upstream (proxy-to-origin) h1/h2 codecs (`send_upstream_http1`/
//! `send_upstream_http2`). HTTP upgrades (envoy-semantics.md S10) are layered on
//! top of these (see `serve_one`'s upgrade path). `serve_http2` itself is transport-agnostic -- HTTP/2 framing (and
//! its client connection preface, RFC 9113 S3.4) is identical whether the
//! bytes arrived over an ALPN-negotiated TLS stream or plaintext "prior
//! knowledge" h2c, so this module needed no change to serve the latter; it's
//! `proxy-core`'s listener that decides *whether* to call `serve_http2` at
//! all for a given connection (ALPN for TLS, a preface peek for plaintext --
//! see `HttpConnectionManagerConfig::codec_type` and its dispatch). The h1
//! `Upgrade: h2c` mechanism remains out of scope. This module is tested
//! standalone, over an in-memory pipe, in `tests/http1_codec.rs` and
//! `tests/http2_codec.rs`.

use std::future::Future;
use std::rc::Rc;
use std::time::Duration;

use http::{Request, Response};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::filter::{RequestHeaders, ResponseHeaders};
use crate::handler::{
    local_boxed, BodyError, DownstreamInfo, HttpRequestParts, HttpResponseParts, StreamBody,
    StreamHandler, UpgradeTunnel,
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
/// `TcpStream`s and (once TLS termination is wired to HTTP
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
    // Rust note: `Send` here is a new addition (S10),
    // required by hyper's own `Connection::with_upgrades` bound below -- NOT
    // a reversal of ADR-0003's "the data plane never hops threads" (that's
    // about the `!Send` service/body/filter state this function's `handler`
    // and `StreamBody` still carry, untouched here). `IO` itself is just the
    // raw byte stream (`TcpStream`, a TLS-terminated stream, or a test
    // `tokio::io::duplex` half) -- every concrete type this crate ever
    // instantiates it with already is `Send`, so this only narrows what
    // *could* be passed in, not what actually is.
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
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
    // Rust note: `.with_upgrades()` wraps the `Connection` future so that, if
    // `serve_one` pulled an `OnUpgrade` handle out of a request (below), that
    // handle actually resolves once hyper finishes writing the 101 response
    // and hands the raw duplex stream over. Without it, `hyper::upgrade::on`
    // still returns a handle, but it never completes (spike finding (e)).
    // Per the spike, this only changes `conn`'s concrete type
    // (`UpgradeableConnection` instead of `Connection`) -- it keeps the same
    // `Future` + `graceful_shutdown(Pin<&mut Self>)` surface, so nothing below
    // this line changes.
    let conn = builder.serve_connection(io, service).with_upgrades();

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

/// Serve one accepted downstream connection as HTTP/2 until the peer closes
/// it, `shutdown` fires, or a connection-level error occurs -- the h2 mirror
/// of `serve_http1`.
///
/// Divergence from `serve_http1`: there is no `Http2Options`/`keep_alive`
/// parameter. HTTP/2 multiplexes many streams over one connection with no
/// per-request `Connection: close` concept, so there is no per-connection
/// keep-alive knob to thread through (same reasoning `send_upstream_http2`'s
/// doc comment gives for dropping it on the client side).
///
/// Per-stream isolation: `hyper::server::conn::http2::Builder` requires an
/// [`hyper::rt::Executor`] and uses it to spawn each h2 stream's
/// `service_fn` call as its own task (see `H2Stream` in hyper's internals) --
/// concurrent streams are NOT driven cooperatively inside one poll of this
/// function's `Connection` future. That's what makes concurrency real rather
/// than serialized, and why this reuses [`LocalExec`] (ADR-0003: those spawned
/// tasks are `!Send`, so a `Send`-requiring executor like
/// `hyper_util::rt::TokioExecutor` can't be used -- same rationale as the
/// upstream h2 client above). Each spawned stream task calls `serve_one`
/// fresh, which builds a new `HttpRequestParts`/hands the handler a new
/// `HttpRequestParts` -- `handler.handle()` in turn builds a fresh
/// `FilterManager` per call (see `FilterChainHandler::handle`'s doc comment),
/// so two concurrent streams on this connection never share a `StreamInfo` or
/// filter-chain instance.
///
/// Transport-agnostic (see the module doc): driven over an
/// already-ALPN-negotiated `h2` TLS stream, or over a plaintext connection
/// `proxy-core`'s listener detected as h2 prior-knowledge by peeking for the
/// client connection preface -- either way this function reads the same
/// framing starting with that same preface, so it needed no h2c-specific
/// code. The h1 `Upgrade: h2c` mechanism (a *different* connection starting
/// out speaking h1) remains out of scope.
pub async fn serve_http2<IO>(
    io: IO,
    handler: Rc<dyn StreamHandler>,
    shutdown: impl Future<Output = ()>,
    downstream: DownstreamInfo,
) -> Result<(), CodecError>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let io = TokioIo::new(io);

    // Rust note: same shape as `serve_http1`'s `service` closure -- see its
    // comment for why `.clone()`-ing the `Rc` (not moving `handler`) is
    // correct here, once per stream, for an unbounded number of streams.
    let service = service_fn(move |req: Request<Incoming>| {
        let handler = handler.clone();
        async move { Ok::<_, std::convert::Infallible>(serve_one(&*handler, req, downstream).await) }
    });

    let mut builder = hyper::server::conn::http2::Builder::new(LocalExec);
    // S10.2: the ONLY opt-in an h2 server needs to
    // accept an RFC 8441 extended CONNECT at all -- unlike h1's
    // `.with_upgrades()`, there is no separate per-connection "allow
    // upgrades" builder method; this alone advertises
    // `SETTINGS_ENABLE_CONNECT_PROTOCOL` to the peer and makes hyper stash an
    // `OnUpgrade` (plus the `:protocol` pseudo-header as a `hyper::ext::
    // Protocol` extension) on a `:method CONNECT` request, exactly as
    // `tests/hyper_spike.rs` finding (g) proved. Without it, a peer sending
    // `:protocol` is a protocol violation the h2 layer is entitled to reject.
    builder.enable_connect_protocol();
    let conn = builder.serve_connection(io, service);

    // Rust note: same `tokio::pin!` + `graceful_shutdown` shape as
    // `serve_http1` -- see its comments for why pinning is required and what
    // `graceful_shutdown` does and doesn't do on its own.
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
    /// h2-only failure: the request had neither an absolute-form URI nor a
    /// `Host` header to derive `:authority` from. Not reachable by
    /// `send_upstream_http1` (h1 has no `:authority` pseudo-header).
    #[error("request has no authority: URI is origin-form and no Host header was present")]
    MissingAuthority,
    /// h2-only: the peer answered with `RST_STREAM(REFUSED_STREAM)`, which
    /// means it did no work on this stream at all. Its own variant rather
    /// than a `Send` in disguise because S3.2 treats it as *always* safe to
    /// retry -- even a non-idempotent request, and even a body that has
    /// already been written -- which no other send failure is. Produced only
    /// by [`send_on_http2`]; `send_upstream_http1` cannot reach it (h1 has no
    /// stream-level reset).
    #[error("upstream refused the h2 stream (RST_STREAM: REFUSED_STREAM)")]
    RefusedStream,
}

/// Pull the h2 stream-error reason out of a `hyper::Error`, if there is one.
///
/// hyper wraps the underlying `h2::Error` rather than exposing it, so the
/// only route to the reason code is walking the `source()` chain and
/// downcasting -- the technique proven in `tests/hyper_spike.rs`'s capability
/// (c) before any of this was built on it.
///
/// **This is only sound because `h2` is the same compiled crate hyper uses.**
/// `downcast_ref` compares `TypeId`s; two semver-incompatible copies of h2 in
/// the tree are two different types, and this would return `None` forever
/// with no error anywhere -- a silent, permanent no-op. That is why
/// `crates/proxy-http/Cargo.toml` says not to make h2 a workspace dependency
/// with an independent version, and why the test that covers this drives a
/// real RST_STREAM instead of constructing an `UpstreamCodecError` by hand.
///
/// Rust note: the chain is walked rather than checking only the immediate
/// source, because how deeply hyper nests its cause is an implementation
/// detail that has changed across hyper versions.
fn h2_reason(err: &hyper::Error) -> Option<h2::Reason> {
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(err);
    while let Some(cause) = source {
        if let Some(h2_err) = cause.downcast_ref::<h2::Error>() {
            return h2_err.reason();
        }
        source = cause.source();
    }
    None
}

/// Does `err` represent an explicit REMOTE RESET by the upstream (Envoy `UR`),
/// as opposed to a connection that merely terminated (`UC`) or a local /
/// handshake failure?
///
/// An h2 peer that answers with a `RST_STREAM` -- for ANY reason, not only
/// `REFUSED_STREAM` -- has deliberately reset the stream, which is exactly
/// what `UR` means. [`UpstreamCodecError::RefusedStream`] already has its own
/// variant (it carries an extra unconditional-retry guarantee no other reset
/// does), but every OTHER reason (`CANCEL`, `INTERNAL_ERROR`, ...) is folded
/// into [`Send`](UpstreamCodecError::Send)/[`Connection`](UpstreamCodecError::Connection)
/// with the h2 reason still recoverable via [`h2_reason`] -- which is what
/// this reads. A `Send`/`Connection` error with NO h2 reason is a plain
/// connection close (a FIN / broken pipe, or an h1 termination that has no
/// stream-level reset at all) and stays `UC`; a `Handshake` failure and a
/// local `MissingAuthority` are not remote resets either.
///
/// Flag-only: this does not change retry classification. A reset before
/// headers is already retriable under S3.2's `reset`
/// ([`AttemptOutcome::from_codec_error`](crate::retry::AttemptOutcome::from_codec_error)
/// maps `Send`/`Connection` to `ResetBeforeHeaders` regardless); this only
/// decides whether the rendered response flag is `UR` or `UC`.
pub fn is_remote_reset(err: &UpstreamCodecError) -> bool {
    match err {
        UpstreamCodecError::RefusedStream => true,
        UpstreamCodecError::Send(e) | UpstreamCodecError::Connection(e) => h2_reason(e).is_some(),
        UpstreamCodecError::Handshake(_) | UpstreamCodecError::MissingAuthority => false,
    }
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

    Ok(HttpResponseParts {
        head,
        body,
        upgrade: None,
    })
}

/// Send one HTTP/1.1 request upstream as an **Upgrade** -- the client-side
/// half of the S10 tunnel. Like [`send_upstream_http1`]
/// (builds a client `Connection` from scratch, sends `req`, returns head-first
/// with a streaming body) with two differences: the `Connection` is built
/// with `.with_upgrades()` (spike finding (e): required on the CLIENT side
/// too, or `hyper::upgrade::on` below silently never resolves), and the
/// return value ALSO carries the upstream's own [`hyper::upgrade::OnUpgrade`]
/// handle whenever the response is `101 Switching Protocols` -- `None` for
/// any other status, meaning the upstream declined the upgrade and this is
/// just an ordinary response to pass through.
///
/// No [`Http1Options`]/keep-alive parameter, unlike `send_upstream_http1`:
/// this never goes through `crate::upstream_pool::H1ConnCache` -- `router.rs`'s
/// upgrade path dials `io` fresh via `pool.new_stream()` specifically so this
/// call never touches that cache. An upgraded connection is consumed whole by
/// the tunnel (or, on a non-101 response, simply dropped once its response
/// body is drained) and must never be handed back for a future request to
/// reuse.
pub async fn send_upstream_http1_upgrade<IO>(
    io: IO,
    req: HttpRequestParts,
) -> Result<(HttpResponseParts, Option<hyper::upgrade::OnUpgrade>), UpstreamCodecError>
where
    // Rust note: same `Send` bound `serve_http1`'s `IO` carries, and for the
    // identical reason -- required by `Connection::with_upgrades()` below,
    // not a reversal of ADR-0003 (see `serve_http1`'s own Rust note for the
    // full reasoning; every concrete `IO` this crate instantiates this with
    // already is `Send`).
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);

    let builder = hyper::client::conn::http1::Builder::new();
    let (mut sender, conn) = builder
        .handshake::<_, StreamBody>(io)
        .await
        .map_err(UpstreamCodecError::Handshake)?;

    // Rust note: same "why `spawn_local`, why the `JoinHandle` is only used
    // to `.abort()` on a send failure, never otherwise awaited" reasoning as
    // `send_upstream_http1`'s own `conn_task` -- see its comment. The only
    // difference here is `.with_upgrades()`, which changes the future's
    // concrete type (`UpgradeableConnection`, not `Connection`) but not this
    // shape at all -- same as the server side (spike finding (e) caveat (2)).
    let conn_task = tokio::task::spawn_local(conn.with_upgrades());

    let RequestHeaders {
        method,
        uri,
        headers,
    } = req.head;
    let mut builder = Request::builder().method(method).uri(uri);
    *builder.headers_mut().expect("builder not yet finalized") = headers;
    let request = builder
        .body(req.body)
        .expect("method/uri were already valid; building can't fail here");

    let mut response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(send_err) => {
            conn_task.abort();
            return Err(UpstreamCodecError::Send(send_err));
        }
    };

    // Rust note: `hyper::upgrade::on` must run before `response.into_parts()`
    // below consumes `response` (and the `Extensions` it stashed the
    // `OnUpgrade` in while parsing) -- same ordering rule
    // `codec::serve_one`'s own call documents, and spike finding (e)'s
    // caveat (3). Gated on the status, not called unconditionally: on
    // anything other than `101` hyper never populated an `OnUpgrade` at all
    // (the response wasn't an upgrade handshake), so there'd be nothing for
    // this to pull out.
    let on_upgrade = if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
        Some(hyper::upgrade::on(&mut response))
    } else {
        None
    };

    let (parts, incoming) = response.into_parts();
    let head = ResponseHeaders {
        status: parts.status,
        headers: parts.headers,
    };
    let body: StreamBody = local_boxed(incoming.map_err(|e| BodyError::Upstream(Box::new(e))));

    Ok((
        HttpResponseParts {
            head,
            body,
            // The router (`route_and_forward`/`handle_upgrade`) is what
            // pairs `on_upgrade` above with the DOWNSTREAM `OnUpgrade` into
            // an `UpgradeTunnel` -- this function only ever hands both halves
            // back separately, since it has no view of the downstream side.
            upgrade: None,
        },
        on_upgrade,
    ))
}

/// Handshake a fresh HTTP/1.1 client connection over `io` and spawn its
/// connection-driving task, returning the request sender AND that task's
/// `JoinHandle` -- the "dial" half of what `send_upstream_http1` does in one
/// shot, split out so `crate::upstream_pool::H1ConnCache` can
/// hold a handshaken connection alive **between** requests, handing the very
/// same connection to the next lease instead of every request handshaking
/// (and tearing down) its own. h1 has no multiplexing, so unlike
/// [`handshake_upstream_http2`]'s sender (cloned out to many *concurrent*
/// requests), this connection's `SendRequest` is only ever leased to one
/// request at a time -- see `H1ConnCache`'s doc for the full reuse rule.
///
/// Divergence from `handshake_upstream_http2`, which drops its `JoinHandle`:
/// this one is returned rather than detached. The h2 cache never needs to
/// end a connection's task itself -- dropping every clone of its
/// `SendRequest` is enough to let hyper wind the connection down on its own.
/// `H1ConnCache` needs to tear a specific IDLE connection down on demand (a
/// dead one found while scanning for something to reuse, or a live one that
/// just finished a response but turned out not to be safe to reuse) without
/// waiting for that to happen naturally, so the caller needs the handle to
/// call `.abort()` on.
///
/// Rust note: the task's own `Result<(), hyper::Error>` output is folded into
/// `()` right here (spawning an `async move { let _ = conn.await; }` block,
/// rather than `conn` itself) purely so the return type is the plain
/// `JoinHandle<()>` this module's callers actually want -- nothing downstream
/// of this function reads a connection-level error today, the same
/// simplification `send_upstream_http1`'s own already-dropped `JoinHandle`
/// makes; a connection error still surfaces to whichever request was in
/// flight when it happened, via that request's own `send_request` failing.
pub async fn handshake_upstream_http1<IO>(
    io: IO,
) -> Result<
    (
        hyper::client::conn::http1::SendRequest<StreamBody>,
        tokio::task::JoinHandle<()>,
    ),
    UpstreamCodecError,
>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let io = TokioIo::new(io);

    let builder = hyper::client::conn::http1::Builder::new();
    let (sender, conn) = builder
        .handshake::<_, StreamBody>(io)
        .await
        .map_err(UpstreamCodecError::Handshake)?;

    // Rust note: same `spawn_local` reasoning as `send_upstream_http1`'s own
    // `conn_task` -- the `Connection` future is `!Send` because it drives our
    // deliberately `!Send` `StreamBody` (ADR-0003) -- but unlike that
    // function, the handle is kept (see this function's doc for why).
    let conn_task = tokio::task::spawn_local(async move {
        let _ = conn.await;
    });

    Ok((sender, conn_task))
}

/// Rust note: h2's hyper client needs an `Executor` to drive the internal
/// future that pumps frames out of the *request body* onto the h2 connection
/// (hyper's `H2ClientFuture`). That future is `!Send` whenever the request
/// body `B` is `!Send` -- which ours (`StreamBody`) deliberately is
/// (ADR-0003) -- but `hyper_util::rt::TokioExecutor` spawns via
/// `tokio::spawn`, which requires `Send + 'static` futures, so it can't be
/// used here. `LocalExec` is the minimal fix: implement `hyper::rt::Executor`
/// by calling `tokio::task::spawn_local` instead. See
/// `tests/h2_upstream_spike.rs` (now deleted; superseded by this codec + its
/// test) for the traced-through justification. `Clone` is required because
/// hyper's internal bounds on the executor type demand it.
#[derive(Clone)]
struct LocalExec;

impl<F> hyper::rt::Executor<F> for LocalExec
where
    F: Future + 'static,
{
    fn execute(&self, fut: F) {
        // Rust note: the future's output is discarded, matching
        // `TokioExecutor`'s own `execute` (which also drops what
        // `tokio::spawn` returns) -- hyper only needs the side effects (driving
        // the h2 connection/body pump), not a result.
        tokio::task::spawn_local(fut);
    }
}

/// Handshake a fresh HTTP/2 client connection over `io` and spawn its
/// connection-driving task, returning the request sender -- the "dial" half
/// of what `send_upstream_http2` used to do in one shot, split out so `crate::upstream_pool::UpstreamConnCache` can handshake once
/// per `ConnKey` and hand clones of the resulting sender to many requests,
/// instead of every request handshaking its own connection.
///
/// Rust note: same `spawn_local` + dropped `JoinHandle` shape
/// `send_upstream_http1` uses, and for the same reason (the `Connection`
/// future is `!Send`, since it drives our deliberately `!Send` `StreamBody`,
/// ADR-0003). Detaching it here used to mean "the connection tears down once
/// `sender`/the response body are dropped" (v1, connect-per-stream); now that
/// a cache can hold `sender` far longer than one request, this task simply
/// lives exactly as long as whatever holds `sender` does -- that's what makes
/// reuse work, not a leak, as long as the holder eventually drops it (the
/// cache's `clear`/`invalidate`, or the process exiting).
pub async fn handshake_upstream_http2<IO>(
    io: IO,
) -> Result<hyper::client::conn::http2::SendRequest<StreamBody>, UpstreamCodecError>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let io = TokioIo::new(io);

    let builder = hyper::client::conn::http2::Builder::new(LocalExec);
    let (sender, conn) = builder
        .handshake::<_, StreamBody>(io)
        .await
        .map_err(UpstreamCodecError::Handshake)?;

    tokio::task::spawn_local(conn);

    Ok(sender)
}

/// Send one request over an already-handshaken HTTP/2 `sender` and return the
/// response, head-first with a streaming body -- the part of
/// `send_upstream_http2` that doesn't care whether `sender` was just produced
/// by `handshake_upstream_http2` or came out of a
/// `crate::upstream_pool::UpstreamConnCache`. hyper's h2 `SendRequest` is
/// `Clone` and multiplexes concurrent requests over the one underlying
/// connection internally, so a cached caller passes in a clone, never the
/// cache's own copy.
pub async fn send_on_http2(
    mut sender: hyper::client::conn::http2::SendRequest<StreamBody>,
    req: HttpRequestParts,
) -> Result<HttpResponseParts, UpstreamCodecError> {
    let RequestHeaders {
        method,
        uri,
        headers,
    } = req.head;

    // h2 gotcha: every h2 request needs `:scheme` and `:authority`
    // pseudo-headers. hyper's h2 client derives them from the request URI --
    // our router builds origin-form (path-only) URIs after h1-style
    // processing, which carry neither. Reconstruct an absolute URI from the
    // `Host` header (scheme `http`, since this codec only ever runs over a
    // plaintext `IO`) so hyper can populate them. Verified empirically
    // (`tests/http2_upstream_codec.rs`): passing the origin-form URI as-is
    // makes the h2 client reject the request before it's ever sent -- the
    // absolute-URI reconstruction below is what makes the round trip work.
    let uri = if uri.authority().is_some() {
        uri
    } else {
        let host = headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .ok_or(UpstreamCodecError::MissingAuthority)?;
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        format!("http://{host}{path_and_query}")
            .parse::<http::Uri>()
            .map_err(|_| UpstreamCodecError::MissingAuthority)?
    };

    let mut builder = Request::builder().method(method).uri(uri);
    *builder.headers_mut().expect("builder not yet finalized") = headers;
    let request = builder
        .body(req.body)
        .expect("method/uri were already valid; building can't fail here");

    let response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(send_err) => {
            // S3.2 `refused-stream`: REFUSED_STREAM is the one reset the peer
            // can send that carries a guarantee -- it did no work on this
            // stream, so replaying is safe unconditionally. Every other
            // reason (CANCEL, INTERNAL_ERROR, a plain connection error)
            // stays a `Send` and gets the ordinary, conservative treatment.
            if h2_reason(&send_err) == Some(h2::Reason::REFUSED_STREAM) {
                return Err(UpstreamCodecError::RefusedStream);
            }
            return Err(UpstreamCodecError::Send(send_err));
        }
    };

    let (parts, incoming) = response.into_parts();
    let head = ResponseHeaders {
        status: parts.status,
        headers: parts.headers,
    };
    let body: StreamBody = local_boxed(incoming.map_err(|e| BodyError::Upstream(Box::new(e))));

    Ok(HttpResponseParts {
        head,
        body,
        upgrade: None,
    })
}

/// Send one request upstream over `io` as HTTP/2 and return the response,
/// head-first with a streaming body -- the h2 mirror of
/// `send_upstream_http1`. Dial-then-send in one call, composed from
/// `handshake_upstream_http2` + `send_on_http2`; kept for
/// callers (and the existing standalone tests) that don't need connection
/// reuse. The router's real forwarding path calls the two split functions
/// directly through `crate::upstream_pool::UpstreamConnCache` instead, so a
/// concurrent request to the same upstream can reuse the connection this
/// function would otherwise dial fresh every time.
///
/// Divergence from `send_upstream_http1`: there is no `Http2Options`/
/// `keep_alive` parameter. HTTP/2 is multiplexed over one connection; there is
/// no per-request `Connection: close` concept, so we never set (or need) that
/// header.
///
/// Generic over `IO` for the same reason `send_upstream_http1` is.
pub async fn send_upstream_http2<IO>(
    io: IO,
    req: HttpRequestParts,
) -> Result<HttpResponseParts, UpstreamCodecError>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let sender = handshake_upstream_http2(io).await?;
    send_on_http2(sender, req).await
}

/// Send one WebSocket-tunnel request upstream over `io` as an **h2 extended
/// CONNECT** (RFC 8441 S4) -- the h2 mirror of
/// [`send_upstream_http1_upgrade`], and `router.rs`'s h2 counterpart to
/// [`send_upstream_http1_upgrade`] on the same S10.2 tunnel path. Like that
/// function: dials nothing itself (`handshake_upstream_http2` does), sends
/// one request, and returns the response head-first ALONGSIDE the upstream's
/// own [`hyper::upgrade::OnUpgrade`] handle whenever the response is the h2
/// accept status -- exactly `200`, not any `2xx` (finding (g) caveat (1): the
/// h2 CLIENT is stricter than the SERVER side here). `None` for any other
/// status, meaning the upstream declined the extended CONNECT and this is
/// just an ordinary response to pass through.
///
/// Never touches `crate::upstream_pool::UpstreamConnCache`, for the same
/// reason `send_upstream_http1_upgrade` never touches `H1ConnCache`: an
/// upgraded/tunneled connection is consumed whole and must never be handed
/// back for a future request to reuse. `router.rs`'s upgrade path dials `io`
/// fresh via `pool.new_stream()` specifically so this call never touches
/// that cache.
pub async fn send_upstream_h2_connect<IO>(
    io: IO,
    req: HttpRequestParts,
) -> Result<(HttpResponseParts, Option<hyper::upgrade::OnUpgrade>), UpstreamCodecError>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let mut sender = handshake_upstream_http2(io).await?;

    let RequestHeaders {
        method: _,
        uri,
        mut headers,
    } = req.head;

    // Rust note: the inverse of `serve_one`'s normalization -- that call
    // site synthesizes an `Upgrade: <protocol>` header from the h2
    // `:protocol` pseudo-header so the router's gate can read it uniformly;
    // this is where it gets turned back INTO the real wire mechanism (the
    // `:protocol` pseudo-header, sent via a `hyper::ext::Protocol` request
    // Extension -- see below). h1's hop-by-hop `Upgrade`/`Connection`
    // headers have no h2 analog at all, so both are stripped rather than
    // forwarded: sending them as ordinary h2 headers would be inert at best
    // and could confuse a strict peer at worst. `.remove` (not `.get`) is
    // what does the stripping -- it both reads and deletes in one call.
    let protocol = headers
        .remove(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok().map(str::to_string))
        .unwrap_or_else(|| "websocket".to_string());
    headers.remove(http::header::CONNECTION);

    // h2 gotcha, same as `send_on_http2`: every h2 request needs `:scheme`
    // and `:authority` pseudo-headers, which hyper derives from the request
    // URI -- reconstruct an absolute URI from `Host` when the router handed
    // us an origin-form (path-only) one. See `send_on_http2`'s own comment
    // for the empirical justification.
    let uri = if uri.authority().is_some() {
        uri
    } else {
        let host = headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .ok_or(UpstreamCodecError::MissingAuthority)?;
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        format!("http://{host}{path_and_query}")
            .parse::<http::Uri>()
            .map_err(|_| UpstreamCodecError::MissingAuthority)?
    };

    let mut builder = Request::builder().method(http::Method::CONNECT).uri(uri);
    *builder.headers_mut().expect("builder not yet finalized") = headers;
    let mut request = builder
        .body(req.body)
        .expect("method/uri were already valid; building can't fail here");
    // Rust note: `hyper::ext::Protocol::from` (a `&str` impl), not
    // `::from_static` -- `protocol` is a runtime `String` recovered from the
    // synthetic `Upgrade` header above, not a compile-time constant, unlike
    // `tests/hyper_spike.rs` finding (g)'s hand-built test request.
    request
        .extensions_mut()
        .insert(hyper::ext::Protocol::from(protocol.as_str()));

    let mut response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(send_err) => {
            // Same S3.2 `refused-stream` reasoning `send_on_http2` documents:
            // REFUSED_STREAM is the one reset that's unconditionally safe to
            // retry.
            if h2_reason(&send_err) == Some(h2::Reason::REFUSED_STREAM) {
                return Err(UpstreamCodecError::RefusedStream);
            }
            return Err(UpstreamCodecError::Send(send_err));
        }
    };

    // Finding (g) caveat (1): the h2 CLIENT only wires the response up as an
    // upgrade for status EXACTLY `200` -- not `is_success()`/any `2xx`, the
    // way the SERVER side treats acceptance. Gate identically here so
    // `on_upgrade` is `None` in precisely the cases hyper itself would never
    // resolve it.
    let on_upgrade = if response.status() == http::StatusCode::OK {
        Some(hyper::upgrade::on(&mut response))
    } else {
        None
    };

    let (parts, incoming) = response.into_parts();
    let head = ResponseHeaders {
        status: parts.status,
        headers: parts.headers,
    };
    let body: StreamBody = local_boxed(incoming.map_err(|e| BodyError::Upstream(Box::new(e))));

    Ok((
        HttpResponseParts {
            head,
            body,
            // Same reasoning as `send_upstream_http1_upgrade`'s own `upgrade:
            // None` -- pairing this with the DOWNSTREAM `OnUpgrade` into an
            // `UpgradeTunnel` is `router.rs`'s job, not this function's.
            upgrade: None,
        },
        on_upgrade,
    ))
}

/// Does this request ask for a protocol upgrade -- a non-empty `Upgrade`
/// header AND a `Connection` header whose comma-separated tokens include
/// `upgrade` (case-insensitive, per RFC 9110 S7.6.1: `Connection` is a
/// comma-separated list of tokens, not a single value)?
///
/// Both headers are required: `Upgrade` alone names the desired protocol but
/// doesn't ask hop-by-hop-ly for the switch, and `Connection: upgrade` alone
/// (with no `Upgrade` header) names nothing to switch to.
fn request_wants_upgrade(headers: &http::HeaderMap) -> bool {
    if !headers.contains_key(http::header::UPGRADE) {
        return false;
    }
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

/// Convert one `hyper::Request<Incoming>` into [`HttpRequestParts`], hand it
/// to `handler`, and convert the resulting [`HttpResponseParts`] back into a
/// `hyper::Response<StreamBody>`.
async fn serve_one(
    handler: &dyn StreamHandler,
    mut req: Request<Incoming>,
    downstream: DownstreamInfo,
) -> Response<StreamBody> {
    // Rust note: `hyper::upgrade::on` doesn't itself *detect* an upgrade --
    // it only *removes* the `OnUpgrade` handle hyper already stashed in the
    // request's `Extensions` while parsing. Calling it unconditionally would
    // still type-check and still hand back a handle, but on a request that
    // never asked for (or gets) an accept response that handle would simply
    // never resolve -- so the two checks below gate this to the requests
    // where it can. Must run before `req.into_parts()` below: that consumes
    // `req`, taking the `Extensions` (and any `OnUpgrade`/`hyper::ext::
    // Protocol` inside them) with it.
    //
    // S10.2: a SECOND, distinct way a request can ask
    // for an upgrade, alongside the h1 `request_wants_upgrade` check above --
    // an h2 RFC 8441 extended CONNECT. h2 has no `Upgrade`/`Connection`
    // headers at all (h1's hop-by-hop mechanism has no h2 analog); instead
    // the desired protocol arrives as a `:protocol` PSEUDO-HEADER, which
    // hyper surfaces as a `hyper::ext::Protocol` request Extension rather
    // than a real header (`tests/hyper_spike.rs` finding (g)). `serve_http2`
    // (this connection's builder) only reaches this state at all once
    // `.enable_connect_protocol()` has been set -- see its own comment.
    let h2_protocol = req.extensions().get::<hyper::ext::Protocol>().cloned();
    let is_h2_connect = req.method() == http::Method::CONNECT && h2_protocol.is_some();
    let on_upgrade = (request_wants_upgrade(req.headers()) || is_h2_connect)
        .then(|| hyper::upgrade::on(&mut req));

    let (parts, incoming) = req.into_parts();
    let mut headers = parts.headers;
    // Rust note: normalize the h2 `:protocol` pseudo-header into a
    // SYNTHETIC `Upgrade: <protocol>` header on the request head we hand the
    // router, purely so `router.rs`'s existing `is_upgrade_allowed`/
    // `requested_upgrade_type` gate (which reads the `Upgrade` header) works
    // UNCHANGED for both h1 and h2 -- one code path serving two wire
    // representations of "what upgrade type is this?" `parts.method` is left
    // as `CONNECT`, not rewritten to anything h1-shaped: that is deliberately
    // the signal `router::RouterHandler::handle_upgrade` reads to tell an h2
    // upgrade from an h1 one (a real client would never send a bare
    // `Upgrade` header alongside `CONNECT`), so the router can enforce
    // same-protocol tunneling without re-deriving "was this h2" from the
    // (feature-gated, connection-local) `hyper::ext::Protocol` type itself.
    if let Some(protocol) = h2_protocol {
        if let Ok(value) = http::HeaderValue::from_str(protocol.as_str()) {
            headers.insert(http::header::UPGRADE, value);
        }
    }
    let head = RequestHeaders {
        method: parts.method,
        uri: parts.uri,
        headers,
    };
    // Rust note: `BodyExt::map_err` adapts `Incoming`'s error type
    // (`hyper::Error`) to our `BodyError`, then `local_boxed` erases the
    // concrete (now-adapted) body type into `StreamBody` -- this is the one
    // and only place downstream `Incoming` is named; everything past this
    // point (the handler, and the rest of this crate) only ever sees
    // `StreamBody`.
    let body: StreamBody = local_boxed(incoming.map_err(|e| BodyError::Downstream(Box::new(e))));

    let mut response = handler
        .handle(HttpRequestParts {
            head,
            body,
            downstream,
            on_upgrade,
        })
        .await;

    // S10: the router's `101` path is the only
    // producer of `response.upgrade` -- every other response leaves it
    // `None`. Pull it out (`Option::take`, leaving `None` behind) BEFORE
    // handing `response` to `build_response` below, which only knows about
    // `head`/`body`: `HttpResponseParts` carries no `Drop` impl, so this
    // partial move is sound, and it's what lets the tunnel handles survive
    // past that call.
    let upgrade = response.upgrade.take();

    let built = build_response(response);

    // Rust note: the bridging work is a task, not an `.await` right here --
    // and that ordering is load-bearing, not a style choice. Each side's
    // `OnUpgrade` only resolves once ITS OWN peer has finished processing the
    // `101`: hyper resolves the downstream one only after it has actually
    // written `built` (the response this function is about to return) out
    // to the client, and this function hasn't returned it yet. Awaiting the
    // tunnel inline here, before `return built`, would deadlock every
    // upgrade: `built` would never be sent, so `downstream` would never
    // resolve, so this `.await` would hang forever. Spawning lets hyper
    // finish writing `built` (the caller -- `serve_http1`'s `Connection`
    // future -- drives that) while this task waits on both halves
    // independently in the background.
    if let Some(UpgradeTunnel {
        downstream,
        upstream,
        cb_guard,
    }) = upgrade
    {
        tokio::task::spawn_local(bridge_upgrade(downstream, upstream, cb_guard));
    }

    built
}

/// Envoy's HCM `stream_idle_timeout` default (S10) -- this is a FIXED
/// default for now, not yet wired to that IR field; see `pump_with_idle_timeout`'s
/// doc for the tear-down semantics it drives.
const WEBSOCKET_TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// S10: await both halves of an established upgrade
/// handshake and copy raw bytes between them until either side closes --
/// the actual WebSocket-agnostic tunnel `serve_one` exists to set up. Spawned
/// (never awaited inline) by `serve_one`; see its Rust note for why.
///
/// `cb_guard` rides along purely to be held alive (never read -- see
/// `UpgradeTunnel::cb_guard`'s doc) for exactly this function's duration: it
/// represents the S5 `max_connections` slot the router's dial acquired for
/// this physical connection, and that connection is alive for as long as
/// this tunnel is running.
async fn bridge_upgrade(
    downstream: hyper::upgrade::OnUpgrade,
    upstream: hyper::upgrade::OnUpgrade,
    _cb_guard: Option<proxy_cluster::CbGuard>,
) {
    // Rust note: `tokio::try_join!` polls both futures concurrently and
    // resolves as soon as either errors, or once both have resolved
    // successfully -- exactly what's needed here: each side's `OnUpgrade` is
    // independent (see `serve_one`'s note on why they resolve at different,
    // peer-driven times), and there's nothing useful this tunnel can do with
    // only one of the two raw streams in hand.
    let (downstream, upstream) = match tokio::try_join!(downstream, upstream) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::debug!(error = %err, "upgrade tunnel: failed to obtain one or both upgraded streams");
            return;
        }
    };
    let downstream = TokioIo::new(downstream);
    let upstream = TokioIo::new(upstream);
    pump_with_idle_timeout(downstream, upstream, WEBSOCKET_TUNNEL_IDLE_TIMEOUT).await;
    // `_cb_guard` drops here, releasing the `max_connections` slot exactly
    // when the physical connection this tunnel owned is actually done with.
}

/// Bidirectional byte pump between `a` and `b` (the two WebSocket/upgrade
/// tunnel ends), with an IDLE timeout: it tears down once no byte has moved
/// in EITHER direction for `idle_timeout`, rather than living forever until
/// a peer closes (`copy_bidirectional`, which this replaces, has no idle
/// awareness at all). A healthy connection with periodic ping/pong keepalive
/// traffic resets the timer just like any other byte, so this only trips a
/// genuinely stalled tunnel.
///
/// Split out from `bridge_upgrade` so it's testable directly against
/// `tokio::io::duplex` pairs, without needing a real hyper upgrade.
async fn pump_with_idle_timeout<A, B>(mut a: A, mut b: B, idle_timeout: Duration)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut a_to_b_buf = [0u8; 8192];
    let mut b_to_a_buf = [0u8; 8192];
    // Rust note: once a direction hits EOF (a clean close), its read half is
    // done for good -- `_done` latches that so the loop stops polling that
    // side's `read` (a `select!` branch guard below) while the other
    // direction keeps draining normally.
    let mut a_to_b_done = false;
    let mut b_to_a_done = false;
    let (mut a_to_b_bytes, mut b_to_a_bytes) = (0u64, 0u64);

    // Rust note: `tokio::pin!` + `Sleep::reset` is the idiomatic way to run
    // ONE timer across many loop iterations without allocating a fresh
    // `sleep()` future each time -- `select!` re-polls the same pinned
    // `Sleep` every iteration, and any branch that observes real activity
    // pushes its deadline forward with `.reset(..)` instead of replacing it.
    // That's what makes this an IDLE timeout (resets on activity) rather
    // than a fixed total-duration one.
    let deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(deadline);

    loop {
        if a_to_b_done && b_to_a_done {
            break;
        }

        tokio::select! {
            result = a.read(&mut a_to_b_buf), if !a_to_b_done => {
                match result {
                    Ok(0) => {
                        a_to_b_done = true;
                        // Clean EOF from `a`: half-close `b`'s write side so
                        // its peer sees the same close, then keep draining
                        // whatever `b` still has in flight -- the same
                        // clean-close behavior `copy_bidirectional` gives.
                        if let Err(err) = b.shutdown().await {
                            tracing::debug!(error = %err, "upgrade tunnel: half-close after downstream EOF failed");
                        }
                    }
                    Ok(n) => {
                        if let Err(err) = b.write_all(&a_to_b_buf[..n]).await {
                            tracing::debug!(error = %err, "upgrade tunnel: downstream->upstream write failed");
                            break;
                        }
                        if let Err(err) = b.flush().await {
                            tracing::debug!(error = %err, "upgrade tunnel: downstream->upstream flush failed");
                            break;
                        }
                        a_to_b_bytes += n as u64;
                        deadline.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                    }
                    Err(err) => {
                        tracing::debug!(error = %err, "upgrade tunnel: downstream read failed");
                        break;
                    }
                }
            }
            result = b.read(&mut b_to_a_buf), if !b_to_a_done => {
                match result {
                    Ok(0) => {
                        b_to_a_done = true;
                        if let Err(err) = a.shutdown().await {
                            tracing::debug!(error = %err, "upgrade tunnel: half-close after upstream EOF failed");
                        }
                    }
                    Ok(n) => {
                        if let Err(err) = a.write_all(&b_to_a_buf[..n]).await {
                            tracing::debug!(error = %err, "upgrade tunnel: upstream->downstream write failed");
                            break;
                        }
                        if let Err(err) = a.flush().await {
                            tracing::debug!(error = %err, "upgrade tunnel: upstream->downstream flush failed");
                            break;
                        }
                        b_to_a_bytes += n as u64;
                        deadline.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                    }
                    Err(err) => {
                        tracing::debug!(error = %err, "upgrade tunnel: upstream read failed");
                        break;
                    }
                }
            }
            () = &mut deadline => {
                tracing::debug!(idle_timeout = ?idle_timeout, "upgrade tunnel: idle timeout, tearing down");
                break;
            }
        }
    }

    tracing::debug!(
        down_to_up = a_to_b_bytes,
        up_to_down = b_to_a_bytes,
        "upgrade tunnel closed"
    );
}

/// Convert [`HttpResponseParts`] into a `hyper::Response<StreamBody>`. Split
/// out for testability and to keep `serve_one` focused on the request side.
fn build_response(parts: HttpResponseParts) -> Response<StreamBody> {
    let HttpResponseParts {
        head: ResponseHeaders { status, headers },
        body,
        // S10: already `.take()`n by `serve_one` above (see its comment) --
        // this function only ever builds head+body into a hyper `Response`.
        upgrade: _,
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http::HeaderMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{pump_with_idle_timeout, request_wants_upgrade};

    #[test]
    fn upgrade_plus_connection_upgrade_is_true() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(http::header::CONNECTION, "Upgrade".parse().unwrap());
        assert!(request_wants_upgrade(&headers));
    }

    #[test]
    fn keep_alive_only_is_false() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(http::header::CONNECTION, "keep-alive".parse().unwrap());
        assert!(!request_wants_upgrade(&headers));
    }

    /// RFC 9110 S7.6.1: `Connection` is a comma-separated list of tokens, not
    /// a single value -- a real client may send `Connection: keep-alive,
    /// Upgrade` rather than `Connection: Upgrade` alone.
    #[test]
    fn multi_token_connection_header_is_true() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(
            http::header::CONNECTION,
            "keep-alive, Upgrade".parse().unwrap(),
        );
        assert!(request_wants_upgrade(&headers));
    }

    #[test]
    fn no_upgrade_header_is_false() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONNECTION, "Upgrade".parse().unwrap());
        assert!(!request_wants_upgrade(&headers));
    }

    #[test]
    fn case_insensitive_on_both_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(http::header::CONNECTION, "UPGRADE".parse().unwrap());
        assert!(request_wants_upgrade(&headers));

        let mut headers = HeaderMap::new();
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(http::header::CONNECTION, "upgrade".parse().unwrap());
        assert!(request_wants_upgrade(&headers));
    }

    #[test]
    fn no_headers_at_all_is_false() {
        assert!(!request_wants_upgrade(&HeaderMap::new()));
    }

    /// A stalled tunnel -- nothing written on either side -- must be torn
    /// down once `idle_timeout` elapses with no activity at all, rather than
    /// living forever (the `copy_bidirectional` behavior this pump
    /// replaces).
    #[tokio::test]
    async fn idle_tunnel_is_torn_down_after_idle_window() {
        let (down, _down_test) = tokio::io::duplex(1024);
        let (up, _up_test) = tokio::io::duplex(1024);
        let idle = Duration::from_millis(100);

        // Rust note: bound the assertion with `tokio::time::timeout` so a
        // regression that makes the pump hang fails THIS test instead of
        // hanging the suite. A few multiples of `idle` covers scheduling
        // jitter without masking a real "never tears down" bug.
        tokio::time::timeout(idle * 5, pump_with_idle_timeout(down, up, idle))
            .await
            .expect("idle tunnel must be torn down by the idle timeout, not hang forever");
    }

    /// ANY byte in EITHER direction resets the idle timer -- a tunnel
    /// carrying periodic traffic (e.g. WebSocket ping/pong) must not be torn
    /// down mid-conversation just because more time than `idle_timeout` has
    /// passed since the tunnel opened.
    #[tokio::test]
    async fn activity_resets_idle_timer() {
        let (down, mut down_test) = tokio::io::duplex(1024);
        let (up, mut up_test) = tokio::io::duplex(1024);
        let idle = Duration::from_millis(100);

        let pump = tokio::spawn(pump_with_idle_timeout(down, up, idle));

        // One byte every ~40ms for ~280ms: strictly more than `idle` (100ms)
        // has elapsed since the tunnel opened by the time this loop ends, so
        // a timer that reset on a fixed schedule (rather than on real
        // activity) would already have torn the pump down.
        let sent: Vec<u8> = (0u8..7).collect();
        for &byte in &sent {
            down_test
                .write_all(&[byte])
                .await
                .expect("write to downstream test end");
            down_test.flush().await.expect("flush downstream test end");
            tokio::time::sleep(Duration::from_millis(40)).await;
        }

        assert!(
            !pump.is_finished(),
            "pump must not tear down while the tunnel is still active"
        );

        // Everything sent downstream->upstream must have been forwarded
        // byte-for-byte before any teardown.
        let mut received = vec![0u8; sent.len()];
        tokio::time::timeout(Duration::from_secs(1), up_test.read_exact(&mut received))
            .await
            .expect("timed out reading forwarded bytes")
            .expect("read forwarded bytes");
        assert_eq!(received, sent);

        // No more activity now: the pump must go idle and tear itself down
        // within roughly `idle` of the last byte.
        tokio::time::timeout(idle * 5, pump)
            .await
            .expect("pump must tear down once activity stops")
            .expect("pump task must not panic");
    }

    /// The normal EOF-driven close path must still work, and finish
    /// promptly on its own -- not merely because the idle timer eventually
    /// caught up. `idle` here is deliberately much larger than a clean close
    /// should ever take, so a short bound on the final await proves this.
    #[tokio::test]
    async fn clean_close_finishes_promptly_not_via_idle_timer() {
        let (down, mut down_test) = tokio::io::duplex(1024);
        let (up, mut up_test) = tokio::io::duplex(1024);
        let idle = Duration::from_secs(10);

        let pump = tokio::spawn(pump_with_idle_timeout(down, up, idle));

        down_test
            .write_all(b"hello")
            .await
            .expect("write before close");
        down_test.flush().await.expect("flush before close");
        down_test
            .shutdown()
            .await
            .expect("shutdown downstream test end");

        // The in-flight bytes must still be delivered before the close is
        // processed.
        let mut received = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(1), up_test.read_exact(&mut received))
            .await
            .expect("timed out reading in-flight bytes")
            .expect("read in-flight bytes");
        assert_eq!(&received, b"hello");

        // The pump half-closes `up`'s write side once `down` hits EOF
        // (mirroring TCP half-close propagation), so `up_test`'s own read
        // sees EOF too.
        let mut eof_probe = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(1), up_test.read(&mut eof_probe))
            .await
            .expect("timed out waiting for propagated half-close")
            .expect("read after propagated half-close");
        assert_eq!(n, 0, "downstream EOF must propagate to the upstream side");

        // Close the other direction too -- what a real WebSocket close
        // handshake looks like end to end (both peers close).
        up_test
            .shutdown()
            .await
            .expect("shutdown upstream test end");

        tokio::time::timeout(Duration::from_millis(500), pump)
            .await
            .expect("clean close must finish promptly, not wait for the idle timer")
            .expect("pump task must not panic");
    }
}
