//! Minimal delta ADS wire harness used by WP-22 transport tests.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::{Stream, StreamExt};
use proxy_api::envoy::service::discovery::v3::aggregated_discovery_service_server::{
    AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
};
use proxy_api::envoy::service::discovery::v3::{
    DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

type ResponseStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[derive(Debug, Clone)]
pub struct RecordedDeltaRequest {
    pub type_url: String,
    pub response_nonce: String,
    pub error_detail: Option<String>,
    pub resource_names_subscribe: Vec<String>,
    pub resource_names_unsubscribe: Vec<String>,
    pub initial_resource_versions: std::collections::HashMap<String, String>,
    pub node: Option<(String, String)>,
}

impl From<DeltaDiscoveryRequest> for RecordedDeltaRequest {
    fn from(request: DeltaDiscoveryRequest) -> Self {
        Self {
            type_url: request.type_url,
            response_nonce: request.response_nonce,
            error_detail: request.error_detail.map(|status| status.message),
            resource_names_subscribe: request.resource_names_subscribe,
            resource_names_unsubscribe: request.resource_names_unsubscribe,
            initial_resource_versions: request.initial_resource_versions,
            node: request.node.map(|node| (node.id, node.cluster)),
        }
    }
}

#[derive(Clone)]
struct DeltaServer {
    response: DeltaDiscoveryResponse,
    requests: Arc<Mutex<Vec<RecordedDeltaRequest>>>,
}

#[tonic::async_trait]
impl AggregatedDiscoveryService for DeltaServer {
    type StreamAggregatedResourcesStream = ResponseStream<DiscoveryResponse>;
    type DeltaAggregatedResourcesStream = ResponseStream<DeltaDiscoveryResponse>;

    async fn stream_aggregated_resources(
        &self,
        _request: Request<tonic::Streaming<DiscoveryRequest>>,
    ) -> Result<Response<Self::StreamAggregatedResourcesStream>, Status> {
        Err(Status::unimplemented("delta harness only"))
    }

    async fn delta_aggregated_resources(
        &self,
        request: Request<tonic::Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
        let mut incoming = request.into_inner();
        let response = self.response.clone();
        let requests = Arc::clone(&self.requests);
        let (sender, receiver) = mpsc::channel(2);
        tokio::spawn(async move {
            let Some(Ok(initial)) = incoming.next().await else {
                return;
            };
            requests
                .lock()
                .expect("delta request log mutex poisoned")
                .push(initial.into());
            if sender.send(Ok(response)).await.is_err() {
                return;
            }
            if let Some(Ok(ack)) = incoming.next().await {
                requests
                    .lock()
                    .expect("delta request log mutex poisoned")
                    .push(ack.into());
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream(receiver))))
    }
}

struct ReceiverStream<T>(mpsc::Receiver<T>);

impl<T> Stream for ReceiverStream<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<T>> {
        self.0.poll_recv(context)
    }
}

struct TcpIncoming(TcpListener);

impl Stream for TcpIncoming {
    type Item = std::io::Result<TcpStream>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.poll_accept(context) {
            Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct DeltaHarness {
    pub addr: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedDeltaRequest>>>,
    shutdown: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl DeltaHarness {
    pub async fn spawn(response: DeltaDiscoveryResponse) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server = DeltaServer {
            response,
            requests: Arc::clone(&requests),
        };
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let join = tokio::spawn(async move {
            let result = tonic::transport::Server::builder()
                .add_service(AggregatedDiscoveryServiceServer::new(server))
                .serve_with_incoming_shutdown(TcpIncoming(listener), async {
                    let _ = shutdown_receiver.await;
                })
                .await;
            if let Err(error) = result {
                eprintln!("controlplane: delta server error: {error}");
            }
        });
        Ok(Self {
            addr,
            requests,
            shutdown: Some(shutdown_sender),
            join,
        })
    }

    pub fn requests(&self) -> Vec<RecordedDeltaRequest> {
        self.requests
            .lock()
            .expect("delta request log mutex poisoned")
            .clone()
    }

    pub async fn shutdown(mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        let _ = self.join.await;
    }
}
