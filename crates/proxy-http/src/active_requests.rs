//! Envoy's `downstream_rq_active` HCM gauge: requests in flight on one HTTP
//! connection manager.
//!
//! [`ActiveRequestHandler`] wraps an HCM's [`StreamHandler`]. A request counts
//! from the moment the codec hands it to the HCM until its response body is
//! dropped (written out, or cut), so a streaming response counts for its whole stream, and a
//! request abandoned before response headers (its future dropped) stops
//! counting at once. The count is taken at the HCM boundary rather than inside
//! the filter chain so that every path out of the chain (local reply, router
//! response, a dropped future) passes the same guard.

use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use proxy_observability::stats::{instruments, Handle, Registry, WorkerId};

use crate::handler::{BodyError, HttpRequestParts, HttpResponseParts, StreamBody, StreamHandler};

/// Ceiling on distinct `scope` series. `scope` is an operator-written
/// `stat_prefix`, so the ceiling only guards a pathological config.
const SCOPE_CEILING: usize = 1024;

/// One HCM's `downstream_rq_active` series on one worker.
#[derive(Clone)]
pub struct ActiveRequests {
    registry: Arc<Registry>,
    handle: Handle,
    worker: WorkerId,
}

impl ActiveRequests {
    /// Resolves the series for the HCM whose `stat_prefix` is `scope`.
    /// Control-side: takes the registry's lock.
    pub fn new(registry: Arc<Registry>, worker: WorkerId, scope: &str) -> Self {
        let handle = registry.resolve_capped(
            &instruments::DOWNSTREAM_RQ_ACTIVE,
            &[("scope", scope)],
            SCOPE_CEILING,
            &[("scope", "overflow")],
        );
        Self {
            registry,
            handle,
            worker,
        }
    }

    fn enter(&self) -> ActiveGuard {
        self.registry.add(self.worker, self.handle, 1);
        ActiveGuard(self.clone())
    }
}

/// Holds one unit of the gauge and gives it back when dropped.
struct ActiveGuard(ActiveRequests);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.registry.add(self.0.worker, self.0.handle, -1);
    }
}

/// Counts every request that `inner` handles in `downstream_rq_active`.
pub struct ActiveRequestHandler {
    inner: Rc<dyn StreamHandler>,
    active: ActiveRequests,
}

impl ActiveRequestHandler {
    pub fn new(inner: Rc<dyn StreamHandler>, active: ActiveRequests) -> Self {
        Self { inner, active }
    }
}

impl StreamHandler for ActiveRequestHandler {
    fn handle<'a>(
        &'a self,
        req: HttpRequestParts,
    ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        // Taken before the inner future exists, so a future the codec drops
        // before it is first polled still gives the unit back.
        let guard = self.active.enter();
        let response = self.inner.handle(req);
        Box::pin(async move {
            let mut parts = response.await;
            parts.body = Box::pin(GuardedBody {
                inner: parts.body,
                _guard: guard,
            });
            parts
        })
    }
}

/// A response body that holds an [`ActiveGuard`]. hyper drops the body once it
/// has written the last frame, and a cut stream (a client disconnect, a timer,
/// the drain deadline) drops it unfinished, so both release the unit.
struct GuardedBody {
    inner: StreamBody,
    _guard: ActiveGuard,
}

impl Body for GuardedBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        // Rust note: `GuardedBody` is `Unpin` (both fields are), so
        // `Pin<&mut Self>` derefs to `&mut Self` without any projection.
        self.inner.as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
