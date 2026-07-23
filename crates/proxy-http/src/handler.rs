//! WP-10 chunk B -- the `StreamHandler` seam: the boundary between the
//! downstream HTTP codec ([`crate::codec`]) and whatever produces a response
//! for a request. This is **provisional**: WP-11's filter manager will
//! implement (and likely refine) this trait behind the S2 iteration state
//! machine described in IMPLEMENTATION_PLAN.md. Until then, [`stub`] provides
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

/// A streaming HTTP body (request or response), boxed. Carries data frames
/// and a final optional trailers frame, per the `http_body` model. Boxing
/// (rather than naming a concrete type) is what lets this module -- and
/// [`StreamHandler`] implementors -- stay decoupled from hyper's `Incoming`
/// body type (ground rule-adjacent: the codec is the only place that talks
/// hyper).
///
/// Deliberately **not** `Send` (ADR-0003: the data plane never hops threads).
/// `http_body_util::combinators::BoxBody` requires `Send + Sync`, and its
/// `UnsyncBoxBody` variant still requires `Send` -- so neither can hold `!Send`
/// per-stream filter state (e.g. a `Box<dyn HttpFilter>` owning `Rc`/`RefCell`)
/// inside a streaming body, which is exactly what streaming a response through
/// the filter chain needs (WP-11). This hand-rolled alias drops both bounds;
/// hyper's http1 server only requires `B: Body + 'static`, not `B: Send`.
///
/// NOTE(WP-10 h2 chunk): this was verified against hyper's **http1** server
/// bounds. Re-check the http2 path's bounds before wiring h2 downstream -- if
/// it demands `B: Send`, the streaming filter pump needs a different shape
/// (a spawn_local'd pump owning the filters, feeding a channel-backed body).
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

/// A fully parsed request: head (reusing [`crate::filter::RequestHeaders`])
/// plus its streaming body.
pub struct HttpRequestParts {
    pub head: RequestHeaders,
    pub body: StreamBody,
    pub downstream: DownstreamInfo,
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
    //! end-to-end (real routing/filtering is WP-11/12/13). These are plain
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
    /// will own in WP-11 chunk 3.
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
}
