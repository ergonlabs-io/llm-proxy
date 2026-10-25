//! HTTP codecs for downstream and upstream HTTP/1.1 and HTTP/2 connections.
//! Request and response bodies stream incrementally so response headers reach
//! clients before long LLM response bodies complete. Upgrades follow Envoy S10.
//! HTTP/2 framing is the same over TLS and prior-knowledge plaintext; listener
//! dispatch decides when to use it. HTTP/1.1 `Upgrade: h2c` is unsupported.

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::{Request, Response};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::filter::{RequestHeaders, ResponseHeaders};
use crate::handler::{
    local_boxed, BodyError, DownstreamInfo, HttpRequestParts, HttpResponseParts, StreamBody,
    StreamHandler, UpgradeTunnel,
};

/// Per-connection h1 options.
pub struct Http1Options {
    /// Forwarded straight to `hyper::server::conn::http1::Builder::keep_alive`
    /// (spike finding (d): this is a per-connection knob, exactly what drain
    /// needs -- disable it on a connection about to be drained rather than
    /// flipping a process-global setting).
    pub keep_alive: bool,
    /// Downstream only (ignored by `send_upstream_http1`): HCM
    /// `request_headers_timeout`. `None` disables the timeout, as Envoy does
    /// when the field is unset or 0s.
    ///
    /// hyper starts this timer when it begins waiting for the next request
    /// head, including on a new or idle keep-alive connection, whereas Envoy
    /// starts it on the first header byte; on expiry hyper closes the
    /// connection without a 408. Both are recorded in
    /// `internal-docs/envoy-divergences.md`.
    pub header_read_timeout: Option<std::time::Duration>,
    /// Downstream only: the request head limits. Over either gets `431` and
    /// the request never reaches the handler.
    pub request_head_limits: RequestHeadLimits,
}

/// HCM `max_request_headers_kb` and `common_http_protocol_options.
/// max_headers_count`, enforced by both downstream codecs. [`Default`] is
/// Envoy's default: 60 KiB and 100 headers.
///
/// On HTTP/1, Envoy's parser counts the raw head: request line, header lines
/// and the blank line. hyper hands over a parsed head, so the size check
/// measures the head as it would be written canonically (`name: value` with
/// one space and CRLF line ends). That equals the raw size for a
/// conventionally formatted request and differs only by optional whitespace
/// around values (`internal-docs/envoy-divergences.md`).
///
/// On HTTP/2, Envoy counts the decoded header list: name plus value of every
/// field, pseudo-headers included, with no per-field overhead. The count
/// includes the pseudo-headers too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestHeadLimits {
    /// The largest request head accepted, in bytes.
    pub max_bytes: usize,
    /// The most header lines a request head may carry.
    pub max_headers: usize,
}

impl Default for RequestHeadLimits {
    fn default() -> Self {
        Self {
            max_bytes: 60 * 1024,
            max_headers: 100,
        }
    }
}

/// How far past [`RequestHeadLimits::max_bytes`] hyper's read buffer may grow
/// while a head is still incomplete. hyper's own buffer check depends on how
/// the head arrives in reads, so it cannot enforce an exact limit; it only
/// bounds memory, and must never refuse a head the exact check would pass.
/// A head that is still incomplete holds fewer bytes than its raw size, so
/// any slack keeps hyper from refusing a head at the limit. One initial read
/// buffer (8 KiB, also hyper's minimum `max_buf_size`) is enough.
const HEAD_BUFFER_SLACK: usize = 8 * 1024;

/// Connection-level codec failures -- distinct from a per-request handler
/// error (a handler is expected to turn its own failures into an HTTP
/// response, e.g. a 5xx, not propagate them here).
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("http/1.1 connection error: {0}")]
    Connection(#[source] hyper::Error),
}

/// Serve an HTTP/1.1 connection until peer close, shutdown, or connection error.
/// Shutdown drains the current request and prevents another from starting.
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
    let tunnels = UpgradeTunnels::default();
    let service_tunnels = tunnels.clone();
    let limits = options.request_head_limits;
    let service = service_fn(move |req: Request<Incoming>| {
        let handler = handler.clone();
        let tunnels = service_tunnels.clone();
        async move {
            // Checked before `serve_one`, so an oversized head never reaches
            // a filter or the upstream. Envoy treats it as a protocol error
            // and closes the connection.
            if request_head_len(&req) > limits.max_bytes {
                return Ok(closing_response(
                    http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                ));
            }
            Ok::<_, std::convert::Infallible>(serve_one(&*handler, req, downstream, &tunnels).await)
        }
    });

    let mut builder = hyper::server::conn::http1::Builder::new();
    builder.keep_alive(options.keep_alive);
    // hyper answers `431` itself for more headers than this, before the
    // service runs. Its count matches Envoy's: header lines, Host included.
    builder.max_headers(limits.max_headers);
    builder.max_buf_size(limits.max_bytes + HEAD_BUFFER_SLACK);
    // hyper only runs `header_read_timeout` when a `Timer` is installed, and
    // with a timer installed it defaults the timeout to 30s. Setting the
    // value explicitly on every connection, `None` included, keeps Envoy's
    // "disabled unless configured" default instead of hyper's.
    builder.timer(hyper_util::rt::TokioTimer::new());
    builder.header_read_timeout(options.header_read_timeout);
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

    let mut shutting_down = false;
    let result = tokio::select! {
        result = &mut conn => result,
        _ = &mut shutdown => {
            shutting_down = true;
            tunnels.drain.start();
            conn.as_mut().graceful_shutdown();
            // `graceful_shutdown` only *requests* the shutdown; the
            // connection must keep being polled to actually drain the
            // in-flight request (if any) and then finish. Spike finding (d):
            // after this, hyper serves out anything already in flight, then
            // closes without accepting a next request.
            conn.as_mut().await
        }
    };

    // An upgrade makes `conn` resolve as soon as hyper hands the raw IO to
    // the tunnel task, while that tunnel is still live. The caller's
    // connection accounting (proxy-core's drain registry) ends when this
    // function returns, and envoy-semantics.md S10.5 counts upgraded streams
    // as active for drain, so return only once every tunnel has closed. A
    // drain that starts while a tunnel is open still reaches it.
    tunnels.wait_idle_or_drain(shutdown, shutting_down).await;
    result.map_err(CodecError::Connection)
}

/// Serve an HTTP/2 connection until peer close, shutdown, or connection error.
/// Streams run as worker-local tasks, each with its own filter manager.
/// A request over `limits` has its stream reset and never reaches the handler.
pub async fn serve_http2<IO>(
    io: IO,
    handler: Rc<dyn StreamHandler>,
    limits: RequestHeadLimits,
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
    let tunnels = UpgradeTunnels::default();
    let service_tunnels = tunnels.clone();
    let service = service_fn(move |req: Request<Incoming>| {
        let handler = handler.clone();
        let tunnels = service_tunnels.clone();
        async move {
            // Envoy checks as each field is decoded and resets the stream
            // with INTERNAL_ERROR, not a `431`, and keeps the connection.
            // A service error makes hyper send that same reset.
            let (len, count) = h2_header_list_len(&req);
            if len > limits.max_bytes || count > limits.max_headers {
                return Err(HeaderListTooLarge);
            }
            Ok(serve_one(&*handler, req, downstream, &tunnels).await)
        }
    });

    let mut builder = hyper::server::conn::http2::Builder::new(LocalExec);
    builder.max_header_list_size(h2_header_list_bound(limits));
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

    let mut shutting_down = false;
    let result = tokio::select! {
        result = &mut conn => result,
        _ = &mut shutdown => {
            shutting_down = true;
            tunnels.drain.start();
            conn.as_mut().graceful_shutdown();
            conn.as_mut().await
        }
    };

    // Same drain contract as `serve_http1`'s tail. An h2 tunnel's bytes ride
    // this connection, so it normally ends no later than `conn`; waiting
    // keeps "returned" meaning "no tunnel left" on both codecs.
    tunnels.wait_idle_or_drain(shutdown, shutting_down).await;
    result.map_err(CodecError::Connection)
}

/// The service error that resets an HTTP/2 stream whose header list is over
/// [`RequestHeadLimits`]. hyper resets with INTERNAL_ERROR, as Envoy does.
#[derive(Debug, thiserror::Error)]
#[error("request header list over the configured limits")]
struct HeaderListTooLarge;

/// `SETTINGS_MAX_HEADER_LIST_SIZE` for a downstream h2 connection. h2 counts
/// 32 bytes of overhead per field (RFC 9113 section 6.5.2) that Envoy does
/// not, and answers a list at or over the setting with `431` and
/// REFUSED_STREAM itself. So the setting sits above anything the exact check
/// in [`serve_http2`] passes: it only bounds memory, and a list far over the
/// limit gets h2's `431`, or past four times the setting h2's GOAWAY, instead
/// of Envoy's reset (`internal-docs/envoy-divergences.md`).
fn h2_header_list_bound(limits: RequestHeadLimits) -> u32 {
    let bound = limits
        .max_bytes
        .saturating_add(limits.max_headers.saturating_mul(32))
        .saturating_add(1);
    u32::try_from(bound).unwrap_or(u32::MAX)
}

/// The decoded size and field count of an h2 request's header list as Envoy
/// measures them: name plus value per field, pseudo-headers included. hyper
/// folds the pseudo-headers into the method, URI and extensions, so they are
/// rebuilt from there. Envoy leaves `cookie` crumbs out of both until the
/// list is complete; they are counted here, so the limit bounds them too
/// (`internal-docs/envoy-divergences.md`).
fn h2_header_list_len<B>(req: &Request<B>) -> (usize, usize) {
    let uri = req.uri();
    let protocol = req.extensions().get::<hyper::ext::Protocol>();
    let pseudo = [
        Some(":method".len() + req.method().as_str().len()),
        uri.scheme_str().map(|s| ":scheme".len() + s.len()),
        uri.authority()
            .map(|a| ":authority".len() + a.as_str().len()),
        uri.path_and_query()
            .map(|pq| ":path".len() + pq.as_str().len()),
        protocol.map(|p| ":protocol".len() + p.as_str().len()),
    ];
    let (mut len, mut count) = (0, 0);
    for size in pseudo.into_iter().flatten() {
        len += size;
        count += 1;
    }
    for (name, value) in req.headers() {
        len += name.as_str().len() + value.len();
        count += 1;
    }
    (len, count)
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
    /// A pooled connection failed while waiting to take the request, before
    /// any of it was written: S3.2's `reset-before-request` case.
    #[error("upstream connection closed before the request was sent: {0}")]
    NotReady(#[source] hyper::Error),
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
/// maps `Send`/`Connection`/`NotReady` to a reset regardless); this only
/// decides whether the rendered response flag is `UR` or `UC`.
pub fn is_remote_reset(err: &UpstreamCodecError) -> bool {
    match err {
        UpstreamCodecError::RefusedStream => true,
        UpstreamCodecError::Send(e)
        | UpstreamCodecError::Connection(e)
        | UpstreamCodecError::NotReady(e) => h2_reason(e).is_some(),
        UpstreamCodecError::Handshake(_) | UpstreamCodecError::MissingAuthority => false,
    }
}

/// Did the upstream break the protocol (a malformed status line, header,
/// or version) rather than reset or close the connection? Envoy reports the
/// first as `UPE` with a `502` and the second as `UC`/`UR` with a `503`
/// ("upstream connect error or disconnect/reset before headers"); see
/// `router::codec_error_reply`. A remote h2 reset is never a protocol error
/// here, whatever its reason code: [`is_remote_reset`] is checked first.
pub fn is_protocol_error(err: &UpstreamCodecError) -> bool {
    match err {
        UpstreamCodecError::Send(e)
        | UpstreamCodecError::Connection(e)
        | UpstreamCodecError::NotReady(e) => e.is_parse(),
        UpstreamCodecError::Handshake(_)
        | UpstreamCodecError::MissingAuthority
        | UpstreamCodecError::RefusedStream => false,
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
    let io = TokioIo::new(UpstreamReadCap { inner: io });

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
    // S10: `serve_one` strips `connection` from an upgrade request (S9 rule
    // 6) and keeps only `upgrade`; this is the h1 wire, so ask for the
    // switch hop-by-hop again here, the inverse of `send_upstream_h2_connect`
    // turning `upgrade` into `:protocol`.
    let mut headers = headers;
    headers.insert(
        http::header::CONNECTION,
        http::HeaderValue::from_static("upgrade"),
    );
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
    let io = TokioIo::new(UpstreamReadCap { inner: io });

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

/// The most bytes one read from an HTTP/1 upstream hands to hyper. Below
/// hyper's initial 8 KiB read buffer, so the buffer never grows.
const UPSTREAM_H1_MAX_READ: usize = 4096;

/// Caps each read from an HTTP/1 upstream at [`UPSTREAM_H1_MAX_READ`] bytes.
///
/// hyper doubles an h1 read buffer after any read that fills it. A streamed
/// LLM response mostly arrives in small reads, but a burst (the socket backs
/// up while the downstream is slow) grows the buffer well past what the
/// stream needs. In a 1000-stream heap profile, capping reads cut the
/// upstream read buffers' peak from about 14 KiB to about 6 KiB per stream,
/// at no measurable CPU cost. hyper's own knobs cannot do this:
/// `max_buf_size` and `read_buf_exact_size` also limit the response head,
/// which must keep accepting what Envoy accepts (80 KiB by default for
/// HTTP/1).
///
/// Only the read size changes. A larger body or SSE event arrives over more
/// reads, and a response head still accumulates across reads up to hyper's
/// own limit.
struct UpstreamReadCap<IO> {
    inner: IO,
}

impl<IO: AsyncRead + Unpin> AsyncRead for UpstreamReadCap<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() <= UPSTREAM_H1_MAX_READ {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        // Rust note: a `ReadBuf` over a prefix of `buf` needs initialized
        // memory unless built with `unsafe` (denied workspace-wide), and
        // zeroing that prefix on every read costs measurable CPU. Read into
        // a per-thread scratch buffer, zeroed once, and copy only what
        // arrived. Workers are single-threaded and this does not re-enter.
        READ_SCRATCH.with_borrow_mut(|scratch| {
            let mut limited = ReadBuf::new(&mut scratch[..]);
            std::task::ready!(Pin::new(&mut self.inner).poll_read(cx, &mut limited))?;
            buf.put_slice(limited.filled());
            Poll::Ready(Ok(()))
        })
    }
}

thread_local! {
    static READ_SCRATCH: std::cell::RefCell<Box<[u8]>> =
        std::cell::RefCell::new(vec![0; UPSTREAM_H1_MAX_READ].into_boxed_slice());
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for UpstreamReadCap<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    // hyper picks its write strategy from this, so it must pass through.
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
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

/// Handshake an HTTP/2 client connection and spawn its driver. The returned
/// sender can be cloned for requests sharing a cached connection.
///
/// Rust note: same `spawn_local` + dropped `JoinHandle` shape
/// `send_upstream_http1` uses, and for the same reason (the `Connection`
/// future is `!Send`, since it drives our deliberately `!Send` `StreamBody`,
/// ADR-0003). Detaching it here used to mean "the connection tears down once
/// `sender`/the response body are dropped" (v1, connect-per-stream); now that
/// a cache can hold `sender` far longer than one request, this task simply
/// lives exactly as long as whatever holds `sender` does -- that's what makes
/// reuse work, not a leak, as long as the holder eventually drops it (the
/// cache's `clear`/`invalidate`, the periodic sweep dropping a closed or
/// idle-expired entry, the socket being dropped by the peer or an error, or
/// the process exiting).
pub async fn handshake_upstream_http2<IO>(
    io: IO,
) -> Result<hyper::client::conn::http2::SendRequest<StreamBody>, UpstreamCodecError>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
{
    // A request's HEADERS and DATA leave in two writes, even when the body is
    // buffered: `h2` keeps a new stream "pending open" until the connection
    // task writes its HEADERS, and hyper's body pump waits for send capacity,
    // which only an open stream gets. Holding the flush for one scheduler
    // turn so the pump can queue DATA saves that write, but was measured to
    // add about 2 ms to median latency at 1k rps on these `LocalSet` workers.
    // Sending the body in the same turn needs `h2` driven directly, not hyper.
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
    tunnels: &UpgradeTunnels,
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

    // RFC 9112 section 6.3: a request with both `Transfer-Encoding` and
    // `Content-Length` is a smuggling vector. hyper decodes it as chunked but
    // keeps a `Content-Length` that precedes `Transfer-Encoding`; hop-by-hop
    // sanitization then strips only `Transfer-Encoding`, so the upstream
    // would frame the decoded body by the client's stale length. Refuse it
    // and close, as Envoy does unless `allow_chunked_length` is set. hyper
    // drops a `Content-Length` that follows `Transfer-Encoding`, so that
    // order never reaches here (envoy-divergences.md).
    if req.headers().contains_key(http::header::TRANSFER_ENCODING)
        && req.headers().contains_key(http::header::CONTENT_LENGTH)
    {
        return closing_response(http::StatusCode::BAD_REQUEST);
    }

    let (parts, incoming) = req.into_parts();
    let mut headers = parts.headers;
    // HCM with `proxy_100_continue` false (S2.6): hyper answers
    // `100 Continue` to the h1 client itself when the body is first polled,
    // so the expectation is met at this hop. Forwarding it would ask the
    // upstream to answer it again, and one that does not support it may 417.
    let expects_continue = headers
        .get(http::header::EXPECT)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"100-continue"));
    if expects_continue {
        headers.remove(http::header::EXPECT);
    }
    // S9 rule 6, request direction, before any filter sees the head (Envoy
    // `mutateRequestHeaders`). hyper has already read `Connection: close`
    // to decide this downstream connection's fate; forwarding it would
    // close the pooled upstream connection too.
    if on_upgrade.is_some() {
        crate::headers::sanitize_upgrade_hop_by_hop(&mut headers);
    } else {
        crate::headers::sanitize_hop_by_hop(&mut headers);
    }
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

    // S9 rule 6, response direction, after the filter chain (Envoy
    // `mutateResponseHeaders`): the upstream's connection management
    // (`connection: close`, `keep-alive`, its framing) describes the
    // upstream hop, never this one. hyper re-adds `connection: close`
    // itself when it is closing this connection (drain, an unread body).
    // An h1 `101` keeps `upgrade` and re-synthesizes `connection: upgrade`,
    // which the client needs to complete the handshake.
    if upgrade.is_some() && response.head.status == http::StatusCode::SWITCHING_PROTOCOLS {
        crate::headers::sanitize_upgrade_hop_by_hop(&mut response.head.headers);
        response.head.headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("upgrade"),
        );
    } else {
        crate::headers::sanitize_hop_by_hop(&mut response.head.headers);
    }

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
        active_request,
        upstream_payload,
        websocket,
    }) = upgrade
    {
        // S10.2: the response body is what the tunnel writes to the client
        // after the `101`; hyper gets an empty one for the handshake.
        let (head, body) = built.into_parts();
        let built = Response::from_parts(head, empty_body());
        tunnels.spawn(bridge_upgrade(
            downstream,
            upstream,
            crate::tunnel::TunnelParts {
                payload: upstream_payload,
                body,
                websocket,
                drain: tunnels.drain.clone(),
                idle_timeout: WEBSOCKET_TUNNEL_IDLE_TIMEOUT,
            },
            (cb_guard, active_request),
        ));
        return built;
    }

    built
}

/// Upgrade tunnels one downstream connection has spawned and that are still
/// running. `serve_http1`/`serve_http2` wait on it before returning, so a
/// caller that holds a per-connection guard across the codec call (the
/// listener's drain registry) keeps counting the connection while its tunnel
/// is live.
///
/// Rust note: `!Send` (`Rc`/`Cell`) for the same reason as proxy-core's
/// `ConnectionRegistry` -- one connection, one worker thread (ADR-0003).
#[derive(Clone, Default)]
struct UpgradeTunnels {
    inner: Rc<UpgradeTunnelsInner>,
    /// Started when the connection's shutdown future resolves; every tunnel
    /// on the connection watches it (a WebSocket sends Close 1001).
    drain: crate::tunnel::DrainSignal,
}

#[derive(Default)]
struct UpgradeTunnelsInner {
    live: Cell<usize>,
    idle: Notify,
}

/// Decrements [`UpgradeTunnels`]' count on drop, so a tunnel task that is
/// dropped without finishing (runtime teardown) still releases its slot.
struct UpgradeTunnelSlot(Rc<UpgradeTunnelsInner>);

impl Drop for UpgradeTunnelSlot {
    fn drop(&mut self) {
        let remaining = self.0.live.get() - 1;
        self.0.live.set(remaining);
        if remaining == 0 {
            self.0.idle.notify_waiters();
        }
    }
}

impl UpgradeTunnels {
    fn spawn(&self, tunnel: impl Future<Output = ()> + 'static) {
        self.inner.live.set(self.inner.live.get() + 1);
        let slot = UpgradeTunnelSlot(self.inner.clone());
        tokio::task::spawn_local(async move {
            let _slot = slot;
            tunnel.await;
        });
    }

    /// [`Self::wait_idle`], starting the tunnels' drain if `shutdown`
    /// resolves first. `already` says the caller saw it resolve, so it is
    /// not polled again.
    async fn wait_idle_or_drain(
        &self,
        shutdown: std::pin::Pin<&mut impl Future<Output = ()>>,
        already: bool,
    ) {
        if !already {
            tokio::select! {
                () = self.wait_idle() => return,
                () = shutdown => self.drain.start(),
            }
        }
        self.wait_idle().await;
    }

    async fn wait_idle(&self) {
        // Rust note: same check-then-`notified()` shape as proxy-core's
        // `ConnectionRegistry::wait_empty`, and race-free for the same
        // reason: on a current-thread runtime no slot can drop between the
        // check and the first poll that registers this waiter.
        while self.inner.live.get() != 0 {
            self.inner.idle.notified().await;
        }
    }
}

/// Envoy's HCM `stream_idle_timeout` default (S10) -- this is a FIXED
/// default for now, not yet wired to that IR field; see `crate::tunnel::run`
/// for the tear-down semantics it drives.
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
    parts: crate::tunnel::TunnelParts,
    _cb_guard: (
        Option<proxy_cluster::CbGuard>,
        Option<proxy_cluster::ActiveRequestGuard>,
    ),
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
    crate::tunnel::run(TokioIo::new(downstream), TokioIo::new(upstream), parts).await;
    // `_cb_guard` drops here, releasing the `max_connections` slot exactly
    // when the physical connection this tunnel owned is actually done with.
}

/// The codec-level `400` for a request whose framing is ambiguous.
/// `connection: close` makes hyper close the connection after writing it,
/// so no byte of the unread body is parsed as a next request.
/// An empty local reply that closes the connection, for a request the codec
/// refuses before the handler sees it.
fn closing_response(status: http::StatusCode) -> Response<StreamBody> {
    let body = local_boxed(http_body_util::Empty::<bytes::Bytes>::new().map_err(|e| match e {}));
    Response::builder()
        .status(status)
        .header(http::header::CONNECTION, "close")
        .header(http::header::CONTENT_LENGTH, "0")
        .body(body)
        .expect("static status and headers are valid")
}

/// An empty response body: the `101`'s, whose real body the tunnel writes.
fn empty_body() -> StreamBody {
    local_boxed(http_body_util::Empty::<bytes::Bytes>::new().map_err(|e| match e {}))
}

/// The size of `req`'s head written canonically: request line, one
/// `name: value` line per header, and the blank line. See
/// [`RequestHeadLimits`] for how this relates to the raw bytes.
fn request_head_len<B>(req: &Request<B>) -> usize {
    const CRLF: usize = 2;
    // `HTTP/1.1` and `HTTP/1.0` are both 8 bytes.
    const VERSION: usize = 8;
    let uri = req.uri();
    // An origin-form target is exactly its path and query. The other forms
    // (absolute, authority, `*`) are rare enough to pay for a render.
    let target = match (uri.scheme(), uri.path_and_query()) {
        (None, Some(pq)) => pq.as_str().len(),
        _ => uri.to_string().len(),
    };
    let request_line = req.method().as_str().len() + 1 + target + 1 + VERSION + CRLF;
    let headers: usize = req
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + 2 + value.len() + CRLF)
        .sum();
    request_line + headers + CRLF
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
    use http::HeaderMap;

    use super::request_wants_upgrade;

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
}
