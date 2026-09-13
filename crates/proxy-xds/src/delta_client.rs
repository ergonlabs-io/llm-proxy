//! Delta ADS gRPC transport.
//!
//! Delta responses carry independent resource versions and explicit removals.
//! [`DeltaAdsClient`] owns wire transport and delegates validation/application
//! to [`DeltaResponseHandler`] before updating subscription state and ACKing.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use proxy_api::envoy::config::core::v3::Node as NodeProto;
use proxy_api::envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use proxy_api::envoy::service::discovery::v3::{DeltaDiscoveryRequest, DeltaDiscoveryResponse};
use proxy_api::google::rpc::Status as RpcStatus;
use proxy_config::ir::NodeIdentity;
use tokio::sync::mpsc;
use tonic::transport::Channel;

use crate::backoff;
use crate::client::Reconnect;
use crate::delta_subscription::{DeltaRequest, DeltaSubscriptionState, ResourceVersion};
use crate::subscription::Verdict;

/// Validates and applies one delta response before its ACK reaches wire.
pub trait DeltaResponseHandler: Send {
    fn handle(&mut self, response: &DeltaDiscoveryResponse)
        -> impl Future<Output = Verdict> + Send;

    fn desired_names(&self, _type_url: &str) -> Option<BTreeSet<String>> {
        None
    }
}

pub type DeltaValidator = Box<dyn FnMut(&DeltaDiscoveryResponse) -> Verdict + Send>;

pub struct FnDeltaHandler(pub DeltaValidator);

impl DeltaResponseHandler for FnDeltaHandler {
    fn handle(
        &mut self,
        response: &DeltaDiscoveryResponse,
    ) -> impl Future<Output = Verdict> + Send {
        std::future::ready((self.0)(response))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeltaAdsError {
    #[error("delta ADS stream error: {0}")]
    Stream(#[from] tonic::Status),

    #[error(
        "delta ADS response for type_url `{0}`, which no subscribed DeltaSubscriptionState covers"
    )]
    UnknownTypeUrl(String),

    #[error("delta ADS outbound request channel closed while stream was still open")]
    OutboundClosed,
}

struct OutboundStream(mpsc::Receiver<DeltaDiscoveryRequest>);

impl futures::Stream for OutboundStream {
    type Item = DeltaDiscoveryRequest;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(context)
    }
}

fn to_proto(request: &DeltaRequest, node: Option<&NodeIdentity>) -> DeltaDiscoveryRequest {
    DeltaDiscoveryRequest {
        node: node.map(|identity| NodeProto {
            id: identity.id.clone(),
            cluster: identity.cluster.clone(),
            ..Default::default()
        }),
        type_url: request.type_url.clone(),
        resource_names_subscribe: request.resource_names_subscribe.clone(),
        resource_names_unsubscribe: request.resource_names_unsubscribe.clone(),
        initial_resource_versions: request
            .initial_resource_versions
            .clone()
            .into_iter()
            .collect(),
        response_nonce: request.response_nonce.clone().unwrap_or_default(),
        error_detail: request.error_detail.clone().map(|message| RpcStatus {
            code: 3,
            message,
            details: Vec::new(),
        }),
        ..Default::default()
    }
}

/// Multiplexed delta xDS client with per-type subscription state.
pub struct DeltaAdsClient {
    states: Vec<DeltaSubscriptionState>,
    attempt: u32,
    node: Option<NodeIdentity>,
}

impl DeltaAdsClient {
    pub fn new(states: Vec<DeltaSubscriptionState>) -> Self {
        Self {
            states,
            attempt: 0,
            node: None,
        }
    }

    pub fn with_node(mut self, node: NodeIdentity) -> Self {
        self.node = Some(node);
        self
    }

    pub fn states(&self) -> &[DeltaSubscriptionState] {
        &self.states
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    pub async fn run<H: DeltaResponseHandler>(
        &mut self,
        client: &mut AggregatedDiscoveryServiceClient<Channel>,
        mut handler: H,
        mut reconnect: Reconnect,
    ) -> ! {
        loop {
            for state in &mut self.states {
                state.reset_stream();
            }

            match self.run_once(client, &mut handler).await {
                Ok(()) => tracing::warn!("delta ADS stream closed by control plane; reconnecting"),
                Err(error) => tracing::warn!(%error, "delta ADS stream ended; reconnecting"),
            }

            let delay = backoff::delay(&reconnect.policy, self.attempt, &mut reconnect.rng);
            self.attempt = self.attempt.saturating_add(1);
            tracing::debug!(
                ?delay,
                attempt = self.attempt,
                "delta ADS reconnect backoff"
            );
            (reconnect.sleep)(delay).await;
        }
    }

    pub async fn run_once<H: DeltaResponseHandler>(
        &mut self,
        client: &mut AggregatedDiscoveryServiceClient<Channel>,
        handler: &mut H,
    ) -> Result<(), DeltaAdsError> {
        let (sender, receiver) = mpsc::channel::<DeltaDiscoveryRequest>(self.states.len().max(16));
        let mut node_pending = self.node.clone();

        // Queue initial requests before awaiting response headers. grpc-go
        // waits for first request before producing response headers.
        for state in &self.states {
            if state.has_nothing_to_request() {
                continue;
            }
            sender
                .send(to_proto(&state.initial_request(), node_pending.as_ref()))
                .await
                .map_err(|_| DeltaAdsError::OutboundClosed)?;
            node_pending = None;
        }

        let response = client
            .delta_aggregated_resources(OutboundStream(receiver))
            .await?;
        let mut inbound = response.into_inner();

        loop {
            let Some(response) = inbound.message().await? else {
                return Ok(());
            };
            self.attempt = 0;

            let state = self
                .states
                .iter_mut()
                .find(|state| state.type_url() == response.type_url.as_str())
                .ok_or_else(|| DeltaAdsError::UnknownTypeUrl(response.type_url.clone()))?;

            let verdict = handler.handle(&response).await;
            let versions = response.resources.iter().map(|resource| ResourceVersion {
                name: resource.name.clone(),
                version: resource.version.clone(),
            });
            let next = state.on_response(
                versions,
                response.removed_resources.iter().cloned(),
                &response.nonce,
                verdict,
            );
            sender
                .send(to_proto(&next, node_pending.as_ref()))
                .await
                .map_err(|_| DeltaAdsError::OutboundClosed)?;
            node_pending = None;

            for state in &mut self.states {
                let Some(names) = handler.desired_names(state.type_url()) else {
                    continue;
                };
                if let Some(request) = state.set_names(names) {
                    sender
                        .send(to_proto(&request, node_pending.as_ref()))
                        .await
                        .map_err(|_| DeltaAdsError::OutboundClosed)?;
                    node_pending = None;
                }
            }
        }
    }
}
