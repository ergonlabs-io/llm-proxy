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
    pub type_url: String,
    pub version_info: String,
    pub response_nonce: String,
    /// `Some` iff the request's `error_detail` was set, i.e. a NACK.
    pub error_detail: Option<String>,
    pub resource_names: Vec<String>,
}

impl RecordedRequest {
    fn from_proto(req: &DiscoveryRequest) -> Self {
        Self {
            type_url: req.type_url.clone(),
            version_info: req.version_info.clone(),
            response_nonce: req.response_nonce.clone(),
            error_detail: req
                .error_detail
                .as_ref()
                .map(|status| status.message.clone()),
            resource_names: req.resource_names.clone(),
        }
    }

    /// Classify per the SotW rhythm: NACK beats "no nonce yet" (a client
    /// could in principle NACK immediately after connecting to reject a
    /// cached response, though that never happens for `ScriptedAds`' own
    /// self-tests).
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

/// Thread-safe, cloneable handle onto a stream's recorded requests.
///
/// Rust note: `Arc<Mutex<..>>` is the standard "shared, mutable, from
/// multiple tasks" shape — the gRPC handler task appends to it while test
/// code reads a snapshot from a different task/thread. `Mutex` (not
/// `tokio::sync::Mutex`) is fine here because we never hold the lock across
/// an `.await`.
#[derive(Debug, Clone, Default)]
pub struct RequestLog {
    inner: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl RequestLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record(&self, req: &DiscoveryRequest) {
        self.inner
            .lock()
            .expect("request log mutex poisoned")
            .push(RecordedRequest::from_proto(req));
    }

    /// A snapshot of everything recorded so far, in arrival order.
    pub fn snapshot(&self) -> Vec<RecordedRequest> {
        self.inner
            .lock()
            .expect("request log mutex poisoned")
            .clone()
    }
}
