//! Observes upstream entity bytes at the request/send and response/read
//! boundaries. It retains no body bytes and changes no frames.
use crate::{
    handler::{BodyError, StreamBody},
    stream_info::AttemptInfo,
};
use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use proxy_observability::records::Termination;
use std::{
    cell::RefCell,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

pub(crate) struct AttemptGuard(pub Option<Rc<RefCell<AttemptInfo>>>);
impl AttemptGuard {
    pub fn finish(&self, reason: Termination) {
        if let Some(a) = &self.0 {
            a.borrow_mut().finish(reason);
        }
    }
}
impl Drop for AttemptGuard {
    fn drop(&mut self) {
        self.finish(Termination::Unknown);
    }
}

pub(crate) struct AttemptBody {
    inner: StreamBody,
    info: Rc<RefCell<AttemptInfo>>,
    response: bool,
    done: bool,
}
impl AttemptBody {
    pub fn new(inner: StreamBody, info: Rc<RefCell<AttemptInfo>>, response: bool) -> Self {
        if response && inner.is_end_stream() {
            info.borrow_mut().finish(Termination::Complete);
        }
        Self {
            inner,
            info,
            response,
            done: false,
        }
    }
}
impl Body for AttemptBody {
    type Data = Bytes;
    type Error = BodyError;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(ref frame) = poll {
            let mut info = this.info.borrow_mut();
            match frame {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        if this.response {
                            info.bytes_response =
                                info.bytes_response.saturating_add(data.len() as u64);
                        } else {
                            info.bytes_request = info
                                .bytes_request
                                .map(|n| n.saturating_add(data.len() as u64));
                        }
                    }
                    if this.inner.is_end_stream() {
                        this.done = true;
                        if this.response {
                            info.finish(Termination::Complete);
                        }
                    }
                }
                Some(Err(err)) => {
                    this.done = true;
                    if this.response {
                        let reason = match err {
                            BodyError::Downstream(_) => Termination::DownstreamDisconnect,
                            BodyError::Upstream(source)
                                if source
                                    .downcast_ref::<crate::router::idle::IdleTimeoutError>()
                                    .is_some() =>
                            {
                                Termination::Timeout
                            }
                            _ => Termination::UpstreamError,
                        };
                        info.finish(reason);
                    }
                }
                None => {
                    this.done = true;
                    if this.response {
                        info.finish(Termination::Complete);
                    }
                }
            }
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
impl Drop for AttemptBody {
    fn drop(&mut self) {
        if self.response && !self.done {
            self.info
                .borrow_mut()
                .finish(Termination::DownstreamDisconnect);
        }
    }
}
