//! WP-20 increments 3a and 3b: the ADS gRPC request/response pump, and the
//! reconnect loop that keeps re-establishing it.
//!
//! This module owns exactly one thing: driving a single
//! `StreamAggregatedResources` bidi stream so that
//! [`crate::subscription::SubscriptionState`] sees every response and its
//! returned [`crate::subscription::Request`] reaches the wire. Everything
//! else is deliberately out of this increment's scope:
//!
//! - **Deciding a response's verdict, and applying it, is injected -- not
//!   implemented here.** [`ResponseHandler`] is the seam a caller supplies;
//!   [`FnHandler`] adapts a plain synchronous [`Validator`] closure to it for
//!   callers (mostly this crate's own tests) with nothing to await. Real
//!   validation and applying (WP-03/04 field-path errors against the IR, and
//!   `apply.rs`'s `ResourceApplier`) is increment 4's job; pulling
//!   `proxy-config` in HERE would make every transport test a config test,
//!   and this crate's whole point (per its own `Cargo.toml` comment) is
//!   staying free of that edge until then.
//! - **The response's `resources` field is never read by this module** --
//!   only `type_url`, `version_info` and `nonce`, which is all
//!   [`SubscriptionState::on_response`] needs. Whatever `handler.handle`
//!   returns is the only thing that ever looks at `resources`.
//!
//! Increment 3b added the layer above the pump: [`AdsClient::run`] reconnects
//! forever with a jittered backoff, calling
//! [`SubscriptionState::reset_stream`] before each new stream so S8's
//! "versions persist across streams, nonces do not" holds on the wire.
//! [`AdsClient::run_once`] still drives exactly ONE stream and still resets
//! nothing -- everything about reconnecting lives in `run`.
//!
//! Increment 4d-i made the handler seam async: [`ResponseHandler::handle`]
//! returns a future, so applying a response -- which does real I/O, e.g.
//! `crates/proxy/src/main.rs::reload`'s
//! `ClusterManager::update_from_snapshot` resolving DNS per cluster -- can
//! finish before the ACK for that response goes out. Apply-then-ACK, never
//! ACK-then-apply, per S8.

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
/// to accumulate state across calls (e.g. increment 4's IR builder); `Send`
/// because it runs inside a `tokio::spawn`-able future.
pub type Validator = Box<dyn FnMut(&DiscoveryResponse) -> Verdict + Send>;

/// Decides the verdict for one `DiscoveryResponse`, and applies it.
///
/// Rust note: written as return-position `impl Trait` in a trait (RPITIT,
/// stable since 1.75) rather than a bare `async fn` in the trait. A bare
/// `async fn handle(...)` here would still compile, but the trait could not
/// name a bound on the future it desugars to -- only a concrete `impl` could
/// choose to make its future `Send`, and the trait itself would have no way
/// to require it. `AdsClient::run` gets `tokio::spawn`ed by its callers,
/// which needs the whole future it returns -- and therefore every future it
/// awaits, including whatever `handle` returns -- to be `Send`. Spelling the
/// return type out lets `+ Send` sit on the trait method itself, so a
/// non-`Send` implementation fails to compile right here instead of at some
/// `tokio::spawn` call site several files away.
pub trait ResponseHandler: Send {
    fn handle(
        &mut self,
        resp: &DiscoveryResponse,
    ) -> impl std::future::Future<Output = Verdict> + Send;
}

/// Adapts a plain [`Validator`] closure to [`ResponseHandler`], so a caller
/// with nothing to await -- mostly this crate's own tests -- can still write
/// its intent as a one-line synchronous closure instead of a hand-written
/// handler type.
///
/// Rust note: `std::future::ready` is the whole body of the trait impl below
/// -- it wraps an already-computed value in a `Future` that resolves the
/// first time it is polled, which is exactly "no awaiting happened here".
pub struct FnHandler(pub Validator);

impl ResponseHandler for FnHandler {
    fn handle(&mut self, resp: &DiscoveryResponse) -> impl Future<Output = Verdict> + Send {
        std::future::ready((self.0)(resp))
    }
}

/// Errors from pumping ONE ADS stream. [`AdsClient::run_once`] never retries;
/// [`AdsClient::run`] treats every one of these as "that stream ended", logs
/// it, and reconnects after a backoff (PLAN.md Part 8.5: keep serving
/// last-good config, never shed state).
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

/// How [`AdsClient::run`] waits between streams. Both the randomness and the
/// sleeping are injected rather than reached for, which is the whole reason
/// the reconnect tests below take milliseconds instead of minutes: a test
/// supplies a constant draw and a sleep that records its argument and returns
/// immediately, then asserts the exact `Duration` the loop asked for.
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
/// Rust note: an `FnMut` returning a boxed future, rather than an `async fn`
/// in a trait -- the closure has to be stored in a struct and called from a
/// loop that already holds `&mut self`, and `Pin<Box<dyn Future>>` is the
/// ordinary way to name "some future I will not spell out". `'static` on the
/// future (not borrowing the closure) keeps the call site free to hold other
/// `&mut` borrows across the await.
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
    /// Consecutive stream failures since the last stream that received a
    /// response, i.e. the attempt number [`backoff::delay`] is asked about.
    ///
    /// Reset the instant a response arrives, NOT when a stream opens: a
    /// control plane that accepts the connection and then immediately drops
    /// it would otherwise pin the backoff at its floor forever and become a
    /// reconnect storm. This is Envoy's own placement (`GrpcStream`resets its
    /// backoff strategy in `onReceiveMessage`).
    attempt: u32,
    /// The xDS `Node` identity (S8) this client announces itself with, from
    /// bootstrap `dynamic_resources`. `None` means no node reaches the wire at
    /// all -- legal, but a control plane that routes by `node.id` (as
    /// go-control-plane's snapshot cache does) will not find a snapshot for
    /// this client.
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

    /// Reconnects forever: reset per-stream state, pump one stream, log why
    /// it ended, wait a jittered backoff, repeat. Never returns -- there is
    /// no stream-ending condition WP-20 treats as fatal, because giving up on
    /// xDS means never picking up config again while the process keeps
    /// serving the last-good one.
    ///
    /// The `client`'s `Channel` is reused across streams on purpose: tonic
    /// re-establishes the underlying connection per RPC, so a control plane
    /// that goes away and comes back needs no new `Channel` here -- the next
    /// `stream_aggregated_resources` call dials it again.
    ///
    /// Rust note: the `-> !` ("never") return type is how Rust spells "this
    /// diverges". Callers `tokio::spawn` it and drop the handle, or select
    /// against it; there is no `Ok` case to handle.
    pub async fn run<H: ResponseHandler>(
        &mut self,
        client: &mut AggregatedDiscoveryServiceClient<Channel>,
        mut handler: H,
        mut reconnect: Reconnect,
    ) -> ! {
        loop {
            // S8 rule 4, and the reason this is at the TOP of the loop rather
            // than after a failure: the nonce belongs to the stream that
            // issued it, so it must be gone BEFORE `run_once` builds the new
            // stream's initial requests. The acked version deliberately
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

    /// Opens `StreamAggregatedResources` on `client`, sends the initial
    /// request for every subscription for which
    /// [`SubscriptionState::has_nothing_to_request`] is false, then pumps:
    /// for each `DiscoveryResponse`, hands `(version_info, nonce, Verdict)`
    /// to the matching `SubscriptionState` and sends back the `Request` it
    /// returns. Returns `Ok(())` once the server ends the stream cleanly.
    ///
    /// Reconnecting is NOT this function's job, and neither is resetting
    /// per-stream state: [`AdsClient::run`] owns both.
    pub async fn run_once<H: ResponseHandler>(
        &mut self,
        client: &mut AggregatedDiscoveryServiceClient<Channel>,
        handler: &mut H,
    ) -> Result<(), AdsError> {
        // Rust note: bounded so a client that never reads applies
        // backpressure rather than growing memory unboundedly -- 16 matches
        // `testing/controlplane`'s own choice of bound for the same reason.
        let (tx, rx) = mpsc::channel::<DiscoveryRequest>(16);
        let response = client
            .stream_aggregated_resources(OutboundStream(rx))
            .await?;
        let mut inbound = response.into_inner();

        // S8 / Envoy's own `GrpcMuxImpl`: the node identity goes on the FIRST
        // request of a stream and is omitted from every request after it, so
        // this is per STREAM, not per request and not per resource type --
        // whichever type happens to be requested first carries it. A
        // reconnect opens a new stream and therefore sends it again, which is
        // what makes a control plane that lost its state able to identify us.
        let mut node_pending = self.node.clone();

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

        loop {
            let Some(resp) = inbound.message().await? else {
                return Ok(());
            };

            // The control plane is talking to us, so this stream counts as
            // established: the next failure starts its backoff from the floor
            // again. See the field's own note for why arrival, not connect,
            // is the right moment.
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
        }
    }
}
