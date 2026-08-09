//! S5 `max_requests`: rides a circuit-breaker guard alongside the upstream
//! response body so the budget stays claimed for the *entire* response
//! stream, not just until headers arrive -- LLM streaming keeps a request
//! active far longer than time-to-headers. See `router.rs`'s module doc for
//! how this composes with the S4 idle timeout (`idle::IdleTimeoutBody`),
//! which this wraps outermost.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Body, Frame};

use crate::handler::{BodyError, StreamBody};

/// A [`Body`] combinator that just delegates to `inner`, holding `_guard`
/// for as long as the body itself is alive so its `Drop` (releasing the
/// circuit-breaker slot) fires exactly when the response stream is fully
/// consumed or abandoned.
///
/// Rust note: same no-`unsafe` shape as [`super::idle::IdleTimeoutBody`] --
/// `inner` is a [`StreamBody`] (`Pin<Box<dyn Body<..>>>`, `Unpin` because
/// the box owns the pin) and `_guard` is a plain owned value (`Unpin` for
/// any `G: Unpin`, which every concrete guard we use satisfies), so
/// `self.get_mut()` safely projects to `&mut self.inner` without a manual
/// pin projection. Generic over `G` (rather than concretely
/// `proxy_cluster::CbGuard`) so this module doesn't need a `proxy-cluster`
/// dependency just to name the guard's type.
pub(super) struct GuardedBody<G> {
    inner: StreamBody,
    _guard: G,
}

impl<G> GuardedBody<G> {
    pub(super) fn new(inner: StreamBody, guard: G) -> Self {
        Self {
            inner,
            _guard: guard,
        }
    }
}

impl<G: Unpin + 'static> Body for GuardedBody<G> {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // Rust note: `self` is `Unpin` (see the struct doc), so `get_mut`
        // gives a plain `&mut Self` and we can reach `&mut self.inner`
        // without `unsafe`.
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}
