//! Body wrappers that stamp an attempt's `%COMMON_DURATION%` points as hyper
//! polls the request and response bodies.
//!
//! "Sent" and "received" mean handed to or taken from the upstream codec, the
//! same layer Envoy's router records them at, not the socket.

use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use proxy_observability::access_log::TimePoint;

use crate::handler::{local_boxed, BodyError, StreamBody};
use crate::stream_info::UpstreamTiming;

/// Wraps `body` so `end` is marked once it ends cleanly, and `first_data`
/// (when given) at its first data frame.
///
/// An end is either the terminal `None` or a frame after which the body
/// reports `is_end_stream()`: hyper stops polling a body whose framing says
/// it is complete, so the terminal `None` may never come. A body that is
/// already empty is marked at once, because hyper never polls it at all. An
/// error frame is not an end, so a failed body leaves `end` unset and it
/// renders `-`.
pub(super) fn timed(
    body: StreamBody,
    timing: Rc<UpstreamTiming>,
    first_data: Option<TimePoint>,
    end: TimePoint,
) -> StreamBody {
    if body.is_end_stream() {
        timing.mark(end);
    }
    local_boxed(TimedBody {
        inner: body,
        timing,
        first_data,
        end,
    })
}

struct TimedBody {
    inner: StreamBody,
    timing: Rc<UpstreamTiming>,
    first_data: Option<TimePoint>,
    end: TimePoint,
}

impl Body for TimedBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        // Rust note: every field is `Unpin` (`StreamBody` is a pinned box), so
        // `get_mut` is a safe projection, as in `guarded::GuardedBody`.
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_frame(cx);
        match &poll {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(point), true) = (this.first_data, frame.is_data()) {
                    this.timing.mark(point);
                }
                if this.inner.is_end_stream() {
                    this.timing.mark(this.end);
                }
            }
            Poll::Ready(None) => this.timing.mark(this.end),
            Poll::Ready(Some(Err(_))) | Poll::Pending => {}
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn body_of(chunks: &[&'static str]) -> StreamBody {
        let frames: Vec<Result<Frame<Bytes>, BodyError>> = chunks
            .iter()
            .map(|c| Ok(Frame::data(Bytes::from_static(c.as_bytes()))))
            .collect();
        local_boxed(http_body_util::StreamBody::new(futures::stream::iter(
            frames,
        )))
    }

    #[tokio::test]
    async fn marks_first_data_then_end() {
        let timing = Rc::new(UpstreamTiming::default());
        let mut body = timed(
            body_of(&["a", "b"]),
            timing.clone(),
            Some(TimePoint::UsRxBodyBeg),
            TimePoint::UsRxEnd,
        );
        assert_eq!(timing.points().get(TimePoint::UsRxBodyBeg), None);
        body.frame().await.unwrap().unwrap();
        let first = timing.points().get(TimePoint::UsRxBodyBeg);
        assert!(first.is_some());
        assert_eq!(timing.points().get(TimePoint::UsRxEnd), None);
        body.frame().await.unwrap().unwrap();
        assert_eq!(timing.points().get(TimePoint::UsRxBodyBeg), first);
        assert!(body.frame().await.is_none());
        let end = timing.points().get(TimePoint::UsRxEnd).expect("end marked");
        assert!(first.unwrap() <= end);
    }

    /// hyper never polls an empty body, so its end is the moment it is
    /// wrapped; it has no first data byte.
    #[test]
    fn an_empty_body_ends_at_once_with_no_first_data() {
        let timing = Rc::new(UpstreamTiming::default());
        let empty = local_boxed(http_body_util::Empty::<Bytes>::new().map_err(|e| match e {}));
        let _body = timed(
            empty,
            timing.clone(),
            Some(TimePoint::UsRxBodyBeg),
            TimePoint::UsRxEnd,
        );
        assert!(timing.points().get(TimePoint::UsRxEnd).is_some());
        assert_eq!(timing.points().get(TimePoint::UsRxBodyBeg), None);
    }

    /// A body with exact framing is done after its last frame, before any
    /// terminal `None`, which hyper's h1 writer never asks for.
    #[tokio::test]
    async fn a_body_that_reports_its_end_is_marked_without_a_terminal_none() {
        let timing = Rc::new(UpstreamTiming::default());
        let full = local_boxed(
            http_body_util::Full::new(Bytes::from_static(b"x")).map_err(|e| match e {}),
        );
        let mut body = timed(full, timing.clone(), None, TimePoint::UsTxEnd);
        assert_eq!(timing.points().get(TimePoint::UsTxEnd), None);
        body.frame().await.unwrap().unwrap();
        assert!(timing.points().get(TimePoint::UsTxEnd).is_some());
    }

    #[tokio::test]
    async fn an_error_frame_is_not_an_end() {
        let timing = Rc::new(UpstreamTiming::default());
        let frames: Vec<Result<Frame<Bytes>, BodyError>> =
            vec![Err(BodyError::Upstream("reset".into()))];
        let failing = local_boxed(http_body_util::StreamBody::new(futures::stream::iter(
            frames,
        )));
        let mut body = timed(failing, timing.clone(), None, TimePoint::UsRxEnd);
        assert!(body.frame().await.unwrap().is_err());
        assert_eq!(timing.points().get(TimePoint::UsRxEnd), None);
    }
}
