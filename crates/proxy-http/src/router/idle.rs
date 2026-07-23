//! S4 route `idle_timeout` (response direction): wraps the upstream
//! response's [`StreamBody`] so that a gap of more than `idle` between body
//! frames resets the stream with a [`BodyError::Upstream`] rather than
//! letting a stalled upstream (e.g. a wedged token stream) hang the
//! downstream connection forever. See `router.rs`'s module doc for how this
//! composes with the route `timeout` (which only bounds time-to-headers).

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame};

use crate::handler::{BodyError, StreamBody};

/// The error surfaced through `BodyError::Upstream` when `poll_frame` has
/// gone `idle` seconds without a frame from the inner body.
#[derive(Debug)]
pub(super) struct IdleTimeoutError {
    idle: Duration,
}

impl fmt::Display for IdleTimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "upstream response idle timeout after {:?}", self.idle)
    }
}

impl Error for IdleTimeoutError {}

/// A [`Body`] combinator that resets an idle timer on every frame produced
/// by `inner`, and fails the stream once `idle` elapses without one.
///
/// Rust note: `inner` is a [`StreamBody`] (already `Pin<Box<dyn Body<..>>>`,
/// which is `Unpin` regardless of what it boxes -- the box itself owns the
/// pin), and `sleep` is a `Pin<Box<tokio::time::Sleep>>` for the same
/// reason. Both fields are therefore `Unpin`, so `IdleTimeoutBody` as a
/// whole is `Unpin` too: `poll_frame` can use `self.get_mut()` to reach
/// `&mut self.inner`/`&mut self.sleep` directly instead of needing a manual
/// (`unsafe`) pin projection -- `unsafe` is denied workspace-wide, so this
/// field shape is what makes the safe projection possible.
pub(super) struct IdleTimeoutBody {
    inner: StreamBody,
    idle: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl IdleTimeoutBody {
    pub(super) fn new(inner: StreamBody, idle: Duration) -> Self {
        Self {
            inner,
            sleep: Box::pin(tokio::time::sleep(idle)),
            idle,
        }
    }
}

impl Body for IdleTimeoutBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // Rust note: `self` is `Unpin` (see the struct doc), so `get_mut`
        // gives a plain `&mut Self` -- no `unsafe` needed to reach the
        // fields below.
        let this = self.get_mut();

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // A frame arrived: the upstream is alive, so push the
                // deadline back out to a full `idle` window from now.
                this.sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + this.idle);
                Poll::Ready(Some(Ok(frame)))
            }
            // Errors and end-of-stream pass through unchanged -- the idle
            // timer only matters while we're still waiting on more frames.
            ready @ (Poll::Ready(Some(Err(_))) | Poll::Ready(None)) => ready,
            Poll::Pending => match this.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    Poll::Ready(Some(Err(BodyError::Upstream(Box::new(IdleTimeoutError {
                        idle: this.idle,
                    })))))
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}
