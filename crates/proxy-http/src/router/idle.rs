//! S4 route `idle_timeout` wraps the upstream response body and fails with
//! [`BodyError::Upstream`] when no frame arrives within `idle`.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame};

use crate::handler::{BodyError, StreamBody};

/// Distinguishes an upstream idle timeout (SI) from a connection failure (UC)
/// when `access_logging::LoggingBody` downcasts the upstream error.
#[derive(Debug)]
pub(crate) struct IdleTimeoutError {
    idle: Duration,
}

impl fmt::Display for IdleTimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "upstream response idle timeout after {:?}", self.idle)
    }
}

impl Error for IdleTimeoutError {}

/// Resets the idle timer on each frame and fails the stream when it expires.
///
/// Rust note: `inner` is a [`StreamBody`] (already `Pin<Box<dyn Body<..>>>`,
/// which is `Unpin` regardless of what it boxes -- the box itself owns the
/// pin), and `sleep` is a `Pin<Box<tokio::time::Sleep>>` for the same
/// reason. Both fields are therefore `Unpin`, so `IdleTimeoutBody` as a
/// whole is `Unpin` too: `poll_frame` can use `self.get_mut()` to reach
/// `&mut self.inner`/`&mut self.sleep` directly instead of needing a manual
/// (`unsafe`) pin projection -- `unsafe` is denied workspace-wide, so this
/// field shape is what makes the safe projection possible.
pub(crate) struct IdleTimeoutBody {
    inner: StreamBody,
    idle: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl IdleTimeoutBody {
    pub(crate) fn new(inner: StreamBody, idle: Duration) -> Self {
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
        // Rust note: `Unpin` permits safe field access through `get_mut`.
        let this = self.get_mut();

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // Start a fresh idle window after each frame.
                this.sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + this.idle);
                Poll::Ready(Some(Ok(frame)))
            }
            // The idle timer only applies while waiting for another frame.
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

/// Lets `LoggingBody` classify an HCM `max_stream_duration` cut as UMSDR.
#[derive(Debug)]
pub(crate) struct MaxStreamDurationError;

impl fmt::Display for MaxStreamDurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stream exceeded max_stream_duration")
    }
}

impl Error for MaxStreamDurationError {}

/// Fails the stream at `deadline`, even if frames are still arriving.
///
/// The deadline is checked before the inner body is polled: a body that is
/// always ready would otherwise never yield to the timer.
pub(crate) struct MaxDurationBody {
    inner: StreamBody,
    sleep: Pin<Box<tokio::time::Sleep>>,
    fired: bool,
}

impl MaxDurationBody {
    pub(crate) fn new(inner: StreamBody, deadline: std::time::Instant) -> Self {
        Self {
            inner,
            sleep: Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
                deadline,
            ))),
            fired: false,
        }
    }
}

impl Body for MaxDurationBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.fired {
            return Poll::Ready(None);
        }
        if this.inner.is_end_stream() {
            return Pin::new(&mut this.inner).poll_frame(cx);
        }
        if this.sleep.as_mut().poll(cx).is_ready() {
            this.fired = true;
            return Poll::Ready(Some(Err(BodyError::Upstream(Box::new(
                MaxStreamDurationError,
            )))));
        }
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.fired || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}
