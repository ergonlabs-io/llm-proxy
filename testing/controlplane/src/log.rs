//! Request log: every `DiscoveryRequest` a [`crate::server::ScriptedAds`]
//! receives, in arrival order, classified as Initial/Ack/Nack the way
//! WP-20's client-behavior tests need to assert against.

use std::sync::{Arc, Mutex};

use proxy_api::envoy::service::discovery::v3::DiscoveryRequest;

/// A stream's request, as classified by the SotW ACK/NACK rhythm
/// (<https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol>):
/// the first request for a stream carries no `response_nonce`; subsequent
/// requests ACK (no `error_detail`) or NACK (`error_detail` set) the most
/// recent response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Initial,
    Ack,
    Nack,
}

/// One recorded `DiscoveryRequest`, trimmed to the fields tests care about.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    /// Which `StreamAggregatedResources` stream this request arrived on.
    /// Monotonic across the server's lifetime, first stream is `1` (see
    /// `RequestLog::next_stream_id`), so a reconnect (drop stream N, open
    /// stream N+1) is visible in the log without inspecting timing.
    pub stream_id: u64,
    pub type_url: String,
    pub version_info: String,
    pub response_nonce: String,
    /// `Some` iff the request's `error_detail` was set, i.e. a NACK.
    pub error_detail: Option<String>,
    pub resource_names: Vec<String>,
    /// `(node.id, node.cluster)` iff the request carried a `node`.
    ///
    /// Per the xDS protocol (and Envoy's own `GrpcMuxImpl`) a client sends
    /// its node identity on the FIRST request of a stream and omits it from
    /// every request after, so this is `Some` on at most one recorded request
    /// per `stream_id` -- and a reconnect must produce another one. Recorded
    /// as the two fields tests assert on rather than the whole `Node` message,
    /// matching how the rest of this struct is trimmed.
    pub node: Option<(String, String)>,
}

impl RecordedRequest {
    fn from_proto(stream_id: u64, req: &DiscoveryRequest) -> Self {
        Self {
            stream_id,
            type_url: req.type_url.clone(),
            version_info: req.version_info.clone(),
            response_nonce: req.response_nonce.clone(),
            error_detail: req
                .error_detail
                .as_ref()
                .map(|status| status.message.clone()),
            resource_names: req.resource_names.clone(),
            node: req.node.as_ref().map(|n| (n.id.clone(), n.cluster.clone())),
        }
    }

    /// Classify per the SotW rhythm: NACK beats "no nonce yet" (a client
    /// could in principle NACK immediately after connecting to reject a
    /// cached response, though that never happens for `ScriptedAds`' own
    /// self-tests).
    ///
    /// This still reads correctly across a reconnect: per S8 a reconnecting
    /// client re-sends its subscriptions with the last-ACKed `version_info`
    /// but an empty `response_nonce` (there is no prior nonce on the new
    /// stream to echo), so it classifies as `Initial` again even though
    /// `version_info` is non-empty. Distinguishing "first request on a
    /// fresh stream" from "first request ever" is what `stream_id` is for,
    /// not `kind()` — a test asserting reconnect-resync should check both.
    pub fn kind(&self) -> RequestKind {
        if self.error_detail.is_some() {
            RequestKind::Nack
        } else if self.response_nonce.is_empty() {
            RequestKind::Initial
        } else {
            RequestKind::Ack
        }
    }
}

/// The mutable state behind a [`RequestLog`]: the requests seen so far, plus
/// the counter that hands out `stream_id`s. Both live behind the same lock
/// because a stream's very first request needs the id assigned before it
/// can be pushed.
#[derive(Debug)]
struct Inner {
    requests: Vec<RecordedRequest>,
    next_stream_id: u64,
}

impl Default for Inner {
    fn default() -> Self {
        // First stream is 1, not 0, purely so log/test output reads as
        // "stream 1" rather than "stream 0" — no other significance.
        Self {
            requests: Vec::new(),
            next_stream_id: 1,
        }
    }
}

/// Thread-safe, cloneable handle onto every stream's recorded requests.
///
/// Rust note: `Arc<Mutex<..>>` is the standard "shared, mutable, from
/// multiple tasks" shape — the gRPC handler task appends to it while test
/// code reads a snapshot from a different task/thread. `Mutex` (not
/// `tokio::sync::Mutex`) is fine here because we never hold the lock across
/// an `.await`.
#[derive(Debug, Clone, Default)]
pub struct RequestLog {
    inner: Arc<Mutex<Inner>>,
}

impl RequestLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hands out the next `stream_id`, for `ScriptedAds` to assign once per
    /// accepted stream (never per request).
    pub(crate) fn next_stream_id(&self) -> u64 {
        let mut inner = self.inner.lock().expect("request log mutex poisoned");
        let id = inner.next_stream_id;
        inner.next_stream_id += 1;
        id
    }

    pub(crate) fn record(&self, stream_id: u64, req: &DiscoveryRequest) {
        self.inner
            .lock()
            .expect("request log mutex poisoned")
            .requests
            .push(RecordedRequest::from_proto(stream_id, req));
    }

    /// A snapshot of everything recorded so far, in arrival order.
    pub fn snapshot(&self) -> Vec<RecordedRequest> {
        self.inner
            .lock()
            .expect("request log mutex poisoned")
            .requests
            .clone()
    }
}
