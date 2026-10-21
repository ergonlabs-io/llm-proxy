//! The `StreamHandler` seam: the boundary between the
//! downstream HTTP codec ([`crate::codec`]) and whatever produces a response
//! for a request. This is **provisional**: the filter manager
//! implements (and may still refine) this trait behind the S2 iteration state
//! machine (envoy-semantics.md S2). [`stub`] provides
//! two concrete handlers ([`stub::FixedResponseHandler`],
//! [`stub::EchoHandler`]) that exercise the seam end-to-end for the codec's
//! own tests.

use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;

use crate::filter::{RequestHeaders, ResponseHeaders};

/// A body read failure, downstream (reading the request) or upstream
/// (reading/producing the response) of the seam. Boxed so it can wrap
/// whatever the concrete body implementation (hyper's `Incoming`, a stub's
/// channel, etc.) actually produces, without coupling this module to any of
/// them.
#[derive(Debug, thiserror::Error)]
pub enum BodyError {
    #[error("failed to read request body: {0}")]
    Downstream(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("failed to read response body: {0}")]
    Upstream(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Boxed streaming body with data and optional trailer frames. It is `!Send`
/// so worker-local filter state can remain in the stream; hyper's connection
/// runs on that same worker (ADR-0003).
pub type StreamBody = Pin<Box<dyn hyper::body::Body<Data = Bytes, Error = BodyError>>>;

/// Box and pin a concrete body into a [`StreamBody`].
///
/// Rust note: this is a plain `Box::pin` rather than `BodyExt::boxed()`
/// because `boxed()` returns `http_body_util::combinators::BoxBody`, which
/// requires the body to be `Send + Sync` -- exactly the bound `StreamBody`
/// exists to avoid. `Box::pin` erases the concrete type into `Pin<Box<dyn
/// Body<..>>>` without adding any auto-trait requirements beyond what `B`
/// already has.
pub fn local_boxed<B>(body: B) -> StreamBody
where
    B: hyper::body::Body<Data = Bytes, Error = BodyError> + 'static,
{
    Box::pin(body)
}

/// Parsed request head, streaming body, connection context, and optional
/// downstream upgrade. The router reads shared request state from callbacks.
pub struct HttpRequestParts {
    pub head: RequestHeaders,
    pub body: StreamBody,
    pub downstream: DownstreamInfo,
    /// S10: the downstream connection's pending HTTP upgrade, if this
    /// request asked for one (`Upgrade` + `Connection: upgrade`). Extracted by
    /// `codec::serve_one` via `hyper::upgrade::on` before the request body is
    /// taken, and carried here so the router can pair it with
    /// the upstream's own `OnUpgrade` and tunnel between them.
    /// `None` for a normal request, and for every internally-synthesised
    /// request (a router's upstream request has no downstream upgrade).
    pub on_upgrade: Option<hyper::upgrade::OnUpgrade>,
}

/// Downstream (client-facing) connection provenance, captured when the
/// connection was accepted and carried alongside the request through the
/// handler chain. The HCM reads it to apply XFF / x-forwarded-proto (S9)
/// before filters run. `Copy` so it threads cheaply and can be duplicated
/// onto a derived upstream request.
#[derive(Debug, Clone, Copy)]
pub struct DownstreamInfo {
    /// The immediate socket peer (the other end of the accepted connection).
    pub remote: std::net::SocketAddr,
    /// Whether this connection was TLS-terminated (drives x-forwarded-proto).
    pub is_tls: bool,
}

impl DownstreamInfo {
    /// A loopback placeholder for tests and for internally-synthesized
    /// requests (e.g. a router's upstream request) that have no real
    /// downstream peer. Rust note: `SocketAddr` has no `Default`, so this is
    /// an explicit, honestly-named stand-in rather than a silent zero value.
    pub fn loopback() -> Self {
        Self {
            remote: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            is_tls: false,
        }
    }
}

/// A response to write back: head (reusing [`crate::filter::ResponseHeaders`])
/// plus its streaming body.
pub struct HttpResponseParts {
    pub head: ResponseHeaders,
    pub body: StreamBody,
    /// S10: set only by the router's own `101`
    /// path (`router::RouterHandler::handle_upgrade`) once the upstream has
    /// answered `101` -- every other constructor of this struct sets `None`.
    /// `codec::serve_one` is the one place this is read: it must be pulled
    /// out BEFORE the head/body are handed to `build_response` (which only
    /// knows about those two fields), and the actual bridging has to happen
    /// in a task spawned AFTER the `101` response is returned to hyper -- see
    /// that call site's Rust note for why the ordering is load-bearing, not
    /// incidental.
    pub upgrade: Option<UpgradeTunnel>,
}

/// The pair of raw byte-stream handles a completed `101` handshake hands
/// back -- one per side of the tunnel `codec::serve_one` bridges with
/// `tokio::io::copy_bidirectional`. Neither handle is usable yet at the
/// point this is constructed: each `OnUpgrade` only resolves once its own
/// peer has actually finished writing/processing the `101` (downstream:
/// once hyper has sent our `101` response out; upstream: already resolved
/// by the time the router builds this, since the upstream's `101` was
/// already read to get here -- but kept as an `OnUpgrade`, not an already
/// -awaited `Upgraded`, so both sides are handled uniformly by the one
/// `tokio::try_join!` in `serve_one`).
pub struct UpgradeTunnel {
    /// The downstream (client-facing) half -- `HttpRequestParts::on_upgrade`,
    /// relayed through `StreamInfo::on_upgrade` (see that field's doc) and
    /// `.take()`n by the router once it decides to tunnel.
    pub downstream: hyper::upgrade::OnUpgrade,
    /// The upstream (origin-facing) half, returned by
    /// `codec::send_upstream_http1_upgrade` alongside the `101` response
    /// that triggered this whole struct's construction.
    pub upstream: hyper::upgrade::OnUpgrade,
    /// The S5 `max_connections` slot the router's `pool.new_stream()` dial
    /// acquired for this physical connection (see
    /// `proxy_cluster::UpstreamStream::cb_guard`'s doc: "must live exactly
    /// as long as the physical connection does"). An upgraded connection is
    /// never returned to a cache -- there is no `H1ReuseBody`/`IdleH1Conn`
    /// to carry it for the tunnel's whole lifetime the way a pooled h1
    /// response would -- so it rides here instead, and
    /// `codec::bridge_upgrade` holds it until `copy_bidirectional` returns.
    /// `None` only when the dial had no real budget to acquire against (see
    /// that same doc).
    pub cb_guard: Option<proxy_cluster::CbGuard>,
    /// The upstream host's in-flight count for `LEAST_REQUEST`, held for the
    /// tunnel's whole life like `cb_guard`. `None` only where no host was
    /// selected.
    pub active_request: Option<proxy_cluster::ActiveRequestGuard>,
    /// S10.2: the sending half of the `101` response's body. The tunnel
    /// feeds the upstream's post-`101` bytes in here, so they pass through
    /// the encode filter chain as ordinary data callbacks, and writes what
    /// the chain emits to the client. Dropping it ends the response body,
    /// which is when the stream's encode end-of-stream, access log and
    /// request record run.
    pub upstream_payload: UpgradePayloadSender,
    /// The upgrade type is `websocket`, so the tunnel may speak RFC 6455
    /// framing toward the client (a Close frame on drain, envoy-semantics.md
    /// S10.5). Any other upgrade type stays an opaque byte stream.
    pub websocket: bool,
}

/// How many upstream reads may wait in an [`UpgradePayloadSender`] before
/// the tunnel stops reading the upstream: backpressure, not buffering.
const UPGRADE_PAYLOAD_DEPTH: usize = 4;

/// The tunnel's end of an [`upgrade_payload_channel`].
pub struct UpgradePayloadSender(tokio::sync::mpsc::Sender<Bytes>);

impl UpgradePayloadSender {
    /// Queue one upstream read for the encode chain. Waits while the chain
    /// is [`UPGRADE_PAYLOAD_DEPTH`] reads behind. `Err` means the response
    /// body is gone (the stream was torn down), so the tunnel should stop.
    pub async fn send(&self, chunk: Bytes) -> Result<(), UpgradePayloadClosed> {
        self.0.send(chunk).await.map_err(|_| UpgradePayloadClosed)
    }
}

/// The response body behind an [`UpgradePayloadSender`] was dropped.
#[derive(Debug)]
pub struct UpgradePayloadClosed;

/// A bounded channel whose receiving half is a [`StreamBody`]: the body of an
/// accepted upgrade's response. It yields each chunk sent as one data frame
/// and ends cleanly once the sender is dropped.
pub fn upgrade_payload_channel() -> (UpgradePayloadSender, StreamBody) {
    let (tx, rx) = tokio::sync::mpsc::channel(UPGRADE_PAYLOAD_DEPTH);
    (
        UpgradePayloadSender(tx),
        local_boxed(UpgradePayloadBody(rx)),
    )
}

struct UpgradePayloadBody(tokio::sync::mpsc::Receiver<Bytes>);

impl hyper::body::Body for UpgradePayloadBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BodyError>>> {
        self.0
            .poll_recv(cx)
            .map(|chunk| chunk.map(|bytes| Ok(hyper::body::Frame::data(bytes))))
    }
}

/// One per HTTP connection manager instance. The codec calls `handle` once
/// per downstream request; the returned response (head + streaming body) is
/// written back incrementally as it's produced (see `codec`'s early-flush
/// handling). Trailers ride the `StreamBody`'s final frame, both ways -- there
/// is no separate trailer field.
///
/// Rust note: this is worker-local / `!Send` (ADR-0003: the data plane never
/// hops threads), so implementations may freely use `Rc`/`RefCell` internally
/// -- do not add a `Send` bound here. `handle` returns a boxed, pinned future
/// (`Pin<Box<dyn Future<...>>>`) instead of being declared `async fn` in the
/// trait: `async fn` in traits desugars to an *anonymous* associated type,
/// which makes the trait not object-safe (you can't build a vtable when the
/// return type depends on the concrete `Self`). We need trait objects here --
/// `Rc<dyn StreamHandler>` -- because which handler runs is decided by
/// listener config, not known at compile time. Boxing the future by hand is
/// the standard workaround until `async fn` in trait objects lands upstream.
pub trait StreamHandler {
    fn handle<'a>(
        &'a self,
        req: HttpRequestParts,
    ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>>;
}

pub mod stub {
    //! Concrete [`super::StreamHandler`]s used to smoke-test the codec
    //! end-to-end (real routing/filtering lives in the filter manager and router). These are plain
    //! fixtures, not test-only mocks -- kept here (rather than under
    //! `#[cfg(test)]`) so other crates can reuse them too.

    use std::future::Future;
    use std::pin::Pin;

    use bytes::Bytes;
    use http::{HeaderMap, StatusCode};
    use http_body_util::{BodyExt, Full};

    use super::{local_boxed, HttpRequestParts, HttpResponseParts, StreamBody, StreamHandler};
    use crate::filter::ResponseHeaders;

    /// Always returns the same fixed status/headers/body, ignoring (and
    /// fully draining) the request body -- proves the basic request/response
    /// path through the seam.
    pub struct FixedResponseHandler {
        pub status: StatusCode,
        pub headers: HeaderMap,
        pub body: Bytes,
    }

    impl StreamHandler for FixedResponseHandler {
        fn handle<'a>(
            &'a self,
            req: HttpRequestParts,
        ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
            Box::pin(async move {
                // Drain (and discard) the request body so the downstream
                // connection isn't left with unread bytes -- mirrors what a
                // real handler that never reads the body must still do.
                let _ = req.body.collect().await;

                let body: StreamBody = local_boxed(
                    Full::new(self.body.clone())
                        .map_err(|infallible: std::convert::Infallible| match infallible {}),
                );
                HttpResponseParts {
                    head: ResponseHeaders {
                        status: self.status,
                        headers: self.headers.clone(),
                    },
                    body,
                    upgrade: None,
                }
            })
        }
    }

    /// Streams the request body straight back as the response body (status
    /// 200) -- proves bidirectional streaming through the seam: the response
    /// is produced by forwarding the request body's frames as they arrive,
    /// not by buffering it first.
    pub struct EchoHandler;

    impl StreamHandler for EchoHandler {
        fn handle<'a>(
            &'a self,
            req: HttpRequestParts,
        ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
            Box::pin(async move {
                // `req.body` is already a `StreamBody` (`BoxBody<Bytes,
                // BodyError>`), i.e. exactly the type we need to hand back --
                // no re-wrapping needed, just move it into the response.
                HttpResponseParts {
                    head: ResponseHeaders {
                        status: StatusCode::OK,
                        headers: HeaderMap::new(),
                    },
                    body: req.body,
                    upgrade: None,
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};

    use super::{local_boxed, StreamBody};

    /// The property this seam's hand-rolled [`StreamBody`] alias exists for:
    /// a body capturing `!Send` state must be storable in it.
    ///
    /// Without this test, swapping `StreamBody` back to
    /// `http_body_util::combinators::BoxBody` would still compile every other
    /// test in the workspace, while silently making streaming a response
    /// through the (`!Send`, ADR-0003) filter chain impossible to express.
    /// Here `Rc` stands in for the per-stream filter state a streaming body
    /// owns.
    #[test]
    fn stream_body_can_hold_non_send_state() {
        let not_send: Rc<u8> = Rc::new(7);
        // Rust note: the `map_err` closure captures `not_send` (an `Rc`), which
        // makes the whole body `!Send`. That `local_boxed` accepts it at all is
        // the assertion -- a compile-time proof. Swapping `StreamBody` back to
        // `BoxBody`/`UnsyncBoxBody` fails to compile right here.
        let body: StreamBody = local_boxed(Full::new(Bytes::from_static(b"x")).map_err(
            move |infallible: std::convert::Infallible| {
                let _keep = &not_send;
                match infallible {}
            },
        ));
        assert!(!body.is_end_stream());
    }

    /// The payload body yields each chunk the tunnel sends, in order, and
    /// ends only once the sender is dropped: that end is what runs the
    /// stream's encode end-of-stream, so it must not come early or never.
    #[tokio::test]
    async fn upgrade_payload_body_yields_sent_chunks_then_ends_when_the_sender_drops() {
        let (tx, mut body) = super::upgrade_payload_channel();
        let feed = async move {
            tx.send(Bytes::from_static(b"one"))
                .await
                .expect("body alive");
            tx.send(Bytes::from_static(b"two"))
                .await
                .expect("body alive");
        };
        let read = async {
            let mut seen = Vec::new();
            while let Some(frame) = body.frame().await {
                seen.push(frame.expect("payload frames never error").into_data().ok());
            }
            seen
        };
        let ((), seen) = tokio::join!(feed, read);
        assert_eq!(
            seen,
            vec![
                Some(Bytes::from_static(b"one")),
                Some(Bytes::from_static(b"two"))
            ]
        );
    }

    /// A dropped body tells the tunnel to stop feeding it.
    #[tokio::test]
    async fn sending_to_a_dropped_payload_body_fails() {
        let (tx, body) = super::upgrade_payload_channel();
        drop(body);
        assert!(tx.send(Bytes::from_static(b"x")).await.is_err());
    }
}
