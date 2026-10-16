//! The ADS gRPC request/response pump, and the reconnect loop around it.
//!
//! This module drives one `StreamAggregatedResources` bidi stream, so that
//! [`crate::subscription::SubscriptionState`] sees every response and its
//! `Request` reaches the wire.
//!
//! - **Verdicts and applying are injected.** [`ResponseHandler`] is the seam.
//!   Applying a response does real I/O, so it can finish before the ACK goes
//!   out. Apply-then-ACK, never ACK-then-apply (S8). Keeping `proxy-config` out
//!   of this module keeps transport tests free of config.
//! - **`resources` is never read here.** Only `type_url`, `version_info` and
//!   `nonce` are used.
//!
//! [`AdsClient::run`] reconnects forever with jittered backoff, resetting
//! per-stream state before each stream (S8: versions persist across streams,
//! nonces do not). [`AdsClient::run_once`] drives exactly one stream and resets
//! nothing.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use proxy_api::envoy::config::core::v3::Node as NodeProto;
use proxy_api::envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use proxy_api::envoy::service::discovery::v3::{DiscoveryRequest, DiscoveryResponse};
use proxy_api::google::rpc::Status as RpcStatus;
use proxy_config::ir::NodeIdentity;
use tokio::sync::mpsc;
use tonic::transport::Channel;

use crate::backoff::{self, BackoffPolicy};
use crate::subscription::{Request, SubscriptionState, Verdict};

/// Decides the verdict for one `DiscoveryResponse`.
///
/// Rust note: a plain boxed `FnMut` rather than a custom trait -- there is
/// only one operation and no state a trait would let a caller name that a
/// closure's captures cannot already hold, so a trait would be ceremony
/// around a closure. `FnMut` (not `Fn`) because a real validator will want
/// to accumulate state across calls (e.g. an IR builder); `Send`
/// because it runs inside a `tokio::spawn`-able future.
pub type Validator = Box<dyn FnMut(&DiscoveryResponse) -> Verdict + Send>;

/// Decides the verdict for one `DiscoveryResponse`, and applies it.
///
/// Rust note: this is written as return-position `impl Trait` rather than a
/// bare `async fn`, so `+ Send` sits on the trait method. A non-`Send`
/// implementation then fails here, not at a distant `tokio::spawn`.
pub trait ResponseHandler: Send {
    fn handle(
        &mut self,
        resp: &DiscoveryResponse,
    ) -> impl std::future::Future<Output = Verdict> + Send;

    /// The resource names this handler wants subscribed for `type_url`. `None`
    /// means no opinion. `run_once` turns a change in this set into a follow-up
    /// request on the wire.
    ///
    /// Rust note: a defaulted trait method, so existing impls keep compiling.
    /// Only `ResourceApplier` overrides it.
    fn desired_names(&self, _type_url: &str) -> Option<BTreeSet<String>> {
        None
    }
}

/// Adapts a plain [`Validator`] closure to [`ResponseHandler`], for callers
/// with nothing to await, mostly tests.
///
/// Rust note: `std::future::ready` wraps a value in a future that is already
/// complete, meaning no awaiting happens.
pub struct FnHandler(pub Validator);

impl ResponseHandler for FnHandler {
    fn handle(&mut self, resp: &DiscoveryResponse) -> impl Future<Output = Verdict> + Send {
        std::future::ready((self.0)(resp))
    }
}

/// Errors from pumping ONE ADS stream. [`AdsClient::run`] treats each one as
/// "that stream ended", then reconnects. The process keeps serving last-good
/// config (`internal-docs/architecture.md` §12.2).
#[derive(Debug, thiserror::Error)]
pub enum AdsError {
    /// The stream itself failed (transport error, or the server closed it
    /// with a non-OK status).
    ///
    /// Rust note: boxed because `tonic::Status` is large, and the box keeps
    /// every `Result<_, AdsError>` small.
    #[error("ADS stream error: {0}")]
    Stream(Box<tonic::Status>),

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

impl From<tonic::Status> for AdsError {
    fn from(status: tonic::Status) -> Self {
        Self::Stream(Box::new(status))
    }
}

/// Wraps an `mpsc::Receiver<DiscoveryRequest>` as the `Stream` tonic wants for
/// the outbound half of the bidi stream.
///
/// Rust note: same shape as `testing/controlplane`'s private `OutboundStream`,
/// duplicated because neither crate depends on the other. `poll_next`
/// delegates to `Receiver::poll_recv`, which registers the waker.
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
///
/// `node` is `Some` only for the FIRST request sent on a stream; see
/// [`AdsClient::run_once`] for the rule and why it is per stream rather than
/// per request or per type.
fn to_proto(req: &Request, node: Option<&NodeIdentity>) -> DiscoveryRequest {
    DiscoveryRequest {
        node: node.map(|n| NodeProto {
            id: n.id.clone(),
            cluster: n.cluster.clone(),
            ..Default::default()
        }),
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

/// How [`AdsClient::run`] waits between streams. Randomness and sleeping are
/// injected, so the reconnect tests run in milliseconds and can assert the
/// exact delay requested.
pub struct Reconnect {
    pub policy: BackoffPolicy,
    /// Draws the jitter, in `[0.0, 1.0]`. Same shape as
    /// `proxy_http::retry::backoff_delay`'s.
    pub rng: Box<dyn FnMut() -> f64 + Send>,
    /// Waits for the delay the policy computed.
    pub sleep: Sleep,
}

/// The sleeping half of [`Reconnect`].
///
/// Rust note: a boxed `FnMut` returning a boxed future, because the closure
/// is stored in a struct and called from a loop holding `&mut self`.
pub type Sleep = Box<dyn FnMut(Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

impl Reconnect {
    /// The production wiring: Envoy's xDS mux curve, a real RNG, real sleeps.
    pub fn real() -> Self {
        Self {
            policy: BackoffPolicy::default(),
            rng: Box::new(rand::random::<f64>),
            sleep: Box::new(|delay| Box::pin(tokio::time::sleep(delay))),
        }
    }
}

/// One ADS client: the per-type subscription state this proxy holds, driven
/// over a single gRPC stream at a time by [`AdsClient::run_once`], and
/// re-established across streams by [`AdsClient::run`].
pub struct AdsClient {
    states: Vec<SubscriptionState>,
    /// Consecutive stream failures since the last response, i.e. the attempt
    /// number [`backoff::delay`] takes. It resets when a response arrives, not
    /// when a stream opens. Otherwise a server that accepts and then drops
    /// every connection would cause a reconnect storm (as in Envoy's `GrpcStream`).
    attempt: u32,
    /// The xDS `Node` identity this client announces. `None` sends no node, so
    /// a control plane that routes by `node.id` will not find a snapshot.
    node: Option<NodeIdentity>,
}

impl AdsClient {
    pub fn new(states: Vec<SubscriptionState>) -> Self {
        Self {
            states,
            attempt: 0,
            node: None,
        }
    }

    /// Announce this `Node` identity to the control plane.
    ///
    /// Rust note: a consuming builder method (`mut self` in, `Self` out) so a
    /// client can be written as
    /// `AdsClient::new(states).with_node(node)` -- the ordinary Rust shape for
    /// an optional construction-time knob, and it keeps `new` from growing a
    /// parameter every caller would have to pass `None` for.
    pub fn with_node(mut self, node: NodeIdentity) -> Self {
        self.node = Some(node);
        self
    }

    /// The current per-type state. Mostly for tests -- production callers
    /// drive everything through [`AdsClient::run`].
    pub fn states(&self) -> &[SubscriptionState] {
        &self.states
    }

    /// Consecutive failed streams since one last received a response. Zero
    /// while the control plane is healthy.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Reconnects forever: reset per-stream state, pump one stream, wait a
    /// jittered backoff, repeat. No stream error is fatal, because giving up
    /// would stop config updates while the last-good config keeps serving.
    ///
    /// The `Channel` is reused across streams. Tonic redials on each RPC.
    ///
    /// Rust note: `-> !` is how Rust says "this diverges". There is no `Ok` to handle.
    pub async fn run<H: ResponseHandler>(
        &mut self,
        client: &mut AggregatedDiscoveryServiceClient<Channel>,
        mut handler: H,
        mut reconnect: Reconnect,
    ) -> ! {
        loop {
            // S8: nonces die with their stream, so clear them before the next
            // `run_once` builds its requests. The acked version deliberately
            // survives -- "versions persist across streams for same server".
            for state in &mut self.states {
                state.reset_stream();
            }

            match self.run_once(client, &mut handler).await {
                Ok(()) => tracing::warn!("ADS stream closed by the control plane; reconnecting"),
                Err(err) => tracing::warn!(%err, "ADS stream ended; reconnecting"),
            }

            let delay = backoff::delay(&reconnect.policy, self.attempt, &mut reconnect.rng);
            // Saturating so a control plane that is down for a very long time
            // wraps to nothing -- `backoff::delay` already clamps the cap.
            self.attempt = self.attempt.saturating_add(1);
            tracing::debug!(?delay, attempt = self.attempt, "ADS reconnect backoff");
            (reconnect.sleep)(delay).await;
        }
    }

    /// Opens one `StreamAggregatedResources`, sends the initial request for
    /// each subscription that has something to request, then pumps responses.
    /// Returns `Ok(())` once the server ends the stream cleanly. Reconnecting
    /// and resetting per-stream state are left to [`AdsClient::run`].
    pub async fn run_once<H: ResponseHandler>(
        &mut self,
        client: &mut AggregatedDiscoveryServiceClient<Channel>,
        handler: &mut H,
    ) -> Result<(), AdsError> {
        // Rust note: bounded, so a client that never reads applies backpressure.
        // The bound must fit every initial request, which is queued before
        // anything drains the channel.
        let (tx, rx) = mpsc::channel::<DiscoveryRequest>(self.states.len().max(16));

        // S8: the node identity goes on the FIRST request of each stream and is
        // omitted after that. A reconnect opens a new stream, so it is sent again.
        let mut node_pending = self.node.clone();

        // These are queued BEFORE the stream opens, and the order is required.
        // `stream_aggregated_resources` resolves only once the server sends
        // response headers. grpc-go servers send headers only after receiving a
        // request. Awaiting the stream first would deadlock both sides. Queuing
        // into the buffered channel does not block, since the bound above fits
        // every initial request.
        for state in &self.states {
            if state.has_nothing_to_request() {
                // S8 / this crate's own doc: an empty name subscription
                // renders identically to a wildcard on the wire and would
                // ask for every resource of the type. Skip it outright
                // rather than send a request nobody meant.
                continue;
            }
            tx.send(to_proto(&state.initial_request(), node_pending.as_ref()))
                .await
                .map_err(|_| AdsError::OutboundClosed)?;
            node_pending = None;
        }

        let response = client
            .stream_aggregated_resources(OutboundStream(rx))
            .await?;
        let mut inbound = response.into_inner();

        loop {
            let Some(resp) = inbound.message().await? else {
                return Ok(());
            };

            // The control plane answered, so reset the backoff. See `attempt`.
            self.attempt = 0;

            let state = self
                .states
                .iter_mut()
                .find(|s| s.type_url() == resp.type_url.as_str())
                .ok_or_else(|| AdsError::UnknownTypeUrl(resp.type_url.clone()))?;

            let verdict = handler.handle(&resp).await;
            let next = state.on_response(&resp.version_info, &resp.nonce, verdict);
            tx.send(to_proto(&next, node_pending.as_ref()))
                .await
                .map_err(|_| AdsError::OutboundClosed)?;
            // Covers the case where every subscription had nothing to request
            // at stream open, so the first request on the wire is this ACK
            // rather than an initial request.
            node_pending = None;

            // This response may change what a name-based subscription (EDS)
            // wants. The ACK/NACK above goes out first, since it answers this
            // response's nonce. Only after
            // that does the pump ask every state what it wants now; a CDS
            // response naming a new EDS cluster is what makes
            // `ResourceApplier::desired_names` return a wider EDS set here,
            // which is the mechanism by which accepting a cluster subscribes
            // to its endpoints.
            for state in &mut self.states {
                let Some(names) = handler.desired_names(state.type_url()) else {
                    continue;
                };
                if state.set_names(names) {
                    tx.send(to_proto(&state.initial_request(), node_pending.as_ref()))
                        .await
                        .map_err(|_| AdsError::OutboundClosed)?;
                }
            }
        }
    }
}
