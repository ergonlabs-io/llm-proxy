//! WP-20 increment 3a: the ADS gRPC request/response pump.
//!
//! This module owns exactly one thing: driving a single
//! `StreamAggregatedResources` bidi stream so that
//! [`crate::subscription::SubscriptionState`] sees every response and its
//! returned [`crate::subscription::Request`] reaches the wire. Everything
//! else is deliberately out of this increment's scope:
//!
//! - **Validation is injected, not implemented.** [`Validator`] is a plain
//!   callback the caller supplies. Real validation (WP-03/04 field-path
//!   errors against the IR) is increment 4's job; pulling `proxy-config` in
//!   here would make every transport test a config test, and this crate's
//!   whole point (per its own `Cargo.toml` comment) is staying free of that
//!   edge until then.
//! - **Applying resources is increment 4's job too.** The response's
//!   `resources` field is never read here -- only `type_url`, `version_info`
//!   and `nonce`, which is all [`SubscriptionState::on_response`] needs.
//! - **Reconnect and backoff are increment 3b.** [`AdsClient::run_once`]
//!   drives ONE stream and returns when the server ends it (or the stream
//!   errors); it does not retry, and it does not call
//!   [`SubscriptionState::reset_stream`] -- that is the caller's job on the
//!   next call, once increment 3b exists to make one.

use std::pin::Pin;
use std::task::{Context, Poll};

use proxy_api::envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use proxy_api::envoy::service::discovery::v3::{DiscoveryRequest, DiscoveryResponse};
use proxy_api::google::rpc::Status as RpcStatus;
use tokio::sync::mpsc;
use tonic::transport::Channel;

use crate::subscription::{Request, SubscriptionState, Verdict};

/// Decides the verdict for one `DiscoveryResponse`.
///
/// Rust note: a plain boxed `FnMut` rather than a custom trait -- there is
/// only one operation and no state a trait would let a caller name that a
/// closure's captures cannot already hold, so a trait would be ceremony
/// around a closure. `FnMut` (not `Fn`) because a real validator will want
/// to accumulate state across calls (e.g. increment 4's IR builder); `Send`
/// because it runs inside a `tokio::spawn`-able future.
pub type Validator = Box<dyn FnMut(&DiscoveryResponse) -> Verdict + Send>;

/// Errors from pumping one ADS stream. None of these are retried here --
/// reconnecting on any of them is increment 3b's job. This type only reports
/// what went wrong on the stream that just ended.
#[derive(Debug, thiserror::Error)]
pub enum AdsError {
    /// The stream itself failed (transport error, or the server closed it
    /// with a non-OK status).
    #[error("ADS stream error: {0}")]
    Stream(#[from] tonic::Status),

    /// A `DiscoveryResponse` named a `type_url` no [`SubscriptionState`] this
    /// client was constructed with covers. Never silently ignored -- this is
    /// as much a "field this build cannot handle" as any config field is.
    #[error("ADS response for type_url `{0}`, which no subscribed SubscriptionState covers")]
    UnknownTypeUrl(String),

    /// The outbound request channel's receiver was dropped -- i.e. the gRPC
    /// stream ended -- while a request was still queued to send on it.
    #[error("ADS outbound request channel closed while the stream was still open")]
    OutboundClosed,
}

/// Wraps an `mpsc::Receiver<DiscoveryRequest>` as the `Stream` tonic's
/// generated client wants for the outbound half of the bidi stream.
///
/// Rust note: same shape as `testing/controlplane`'s own private
/// `OutboundStream` (see its `tests/ads_selftest.rs`), duplicated rather than
/// shared -- neither crate depends on the other, and the type is a few
/// lines. `poll_next` delegates straight to `Receiver::poll_recv`, which
/// already does the real work of registering the waker.
struct OutboundStream(mpsc::Receiver<DiscoveryRequest>);

impl futures::Stream for OutboundStream {
    type Item = DiscoveryRequest;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<DiscoveryRequest>> {
        self.0.poll_recv(cx)
    }
}

/// Converts one subscription-state [`Request`] into the wire
/// `DiscoveryRequest`. `Option::unwrap_or_default` turns "no version/nonce
/// yet" into the proto's own empty-string convention -- S8's first request
/// of a stream carries `""`, not an absent field.
fn to_proto(req: &Request) -> DiscoveryRequest {
    DiscoveryRequest {
        type_url: req.type_url.clone(),
        version_info: req.version_info.clone().unwrap_or_default(),
        response_nonce: req.response_nonce.clone().unwrap_or_default(),
        resource_names: req.resource_names.clone(),
        error_detail: req.error_detail.clone().map(|message| RpcStatus {
            // S8 does not spec a code -- only the field's presence marks a
            // NACK, and nothing here reads `code` back. INVALID_ARGUMENT is
            // simply a reasonable value to put on the wire.
            code: 3,
            message,
            details: vec![],
        }),
        ..Default::default()
    }
}

/// One ADS client: the per-type subscription state this proxy holds, driven
/// over a single gRPC stream at a time by [`AdsClient::run_once`].
pub struct AdsClient {
    states: Vec<SubscriptionState>,
}

impl AdsClient {
    pub fn new(states: Vec<SubscriptionState>) -> Self {
        Self { states }
    }

    /// The current per-type state. Mostly for tests -- production callers
    /// drive everything through [`AdsClient::run_once`].
    pub fn states(&self) -> &[SubscriptionState] {
        &self.states
    }

    /// Opens `StreamAggregatedResources` on `client`, sends the initial
    /// request for every subscription for which
    /// [`SubscriptionState::has_nothing_to_request`] is false, then pumps:
    /// for each `DiscoveryResponse`, hands `(version_info, nonce, Verdict)`
    /// to the matching `SubscriptionState` and sends back the `Request` it
    /// returns. Returns `Ok(())` once the server ends the stream cleanly.
    ///
    /// Reconnecting is NOT this function's job -- a caller that wants to
    /// reconnect calls this again with a freshly connected `client` (that is
    /// increment 3b).
    pub async fn run_once(
        &mut self,
        client: &mut AggregatedDiscoveryServiceClient<Channel>,
        mut validate: Validator,
    ) -> Result<(), AdsError> {
        // Rust note: bounded so a client that never reads applies
        // backpressure rather than growing memory unboundedly -- 16 matches
        // `testing/controlplane`'s own choice of bound for the same reason.
        let (tx, rx) = mpsc::channel::<DiscoveryRequest>(16);
        let response = client
            .stream_aggregated_resources(OutboundStream(rx))
            .await?;
        let mut inbound = response.into_inner();

        for state in &self.states {
            if state.has_nothing_to_request() {
                // S8 / this crate's own doc: an empty name subscription
                // renders identically to a wildcard on the wire and would
                // ask for every resource of the type. Skip it outright
                // rather than send a request nobody meant.
                continue;
            }
            tx.send(to_proto(&state.initial_request()))
                .await
                .map_err(|_| AdsError::OutboundClosed)?;
        }

        loop {
            let Some(resp) = inbound.message().await? else {
                return Ok(());
            };

            let state = self
                .states
                .iter_mut()
                .find(|s| s.type_url() == resp.type_url.as_str())
                .ok_or_else(|| AdsError::UnknownTypeUrl(resp.type_url.clone()))?;

            let verdict = validate(&resp);
            let next = state.on_response(&resp.version_info, &resp.nonce, verdict);
            tx.send(to_proto(&next))
                .await
                .map_err(|_| AdsError::OutboundClosed)?;
        }
    }
}
