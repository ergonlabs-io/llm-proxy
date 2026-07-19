//! `ScriptedAds`: a puppet SotW (state-of-the-world) ADS server. It plays
//! back a fixed [`Step`] script over `StreamAggregatedResources` and records
//! every request it receives — it has no idea what a Cluster or a Listener
//! is, and never diffs or warms anything. Delta xDS is out of scope for this
//! chunk.

use std::net::SocketAddr;
use std::pin::Pin;
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

use crate::log::RequestLog;
use crate::script::Step;

/// Boxed response stream shared by both ADS methods.
///
/// Rust note: `Pin<Box<dyn Stream<...> + Send>>` is the standard shape for
/// "a stream whose concrete type we don't want to name" (it's a hand-rolled
/// state machine below, `mpsc::Receiver` wrapped as a `Stream`). `Pin`
/// pins it in place because streams (like futures) may be self-referential
/// once polled; `Box` gives it a stable heap address; `dyn Stream + Send`
/// erases the concrete type behind a trait object.
type ResponseStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

/// The puppet ADS server. Cheap to clone (only an `Arc`-backed log and a
/// script `Vec` are cloned into each stream's driver task).
#[derive(Clone)]
pub struct ScriptedAds {
    script: Vec<Step>,
    log: RequestLog,
}

impl ScriptedAds {
    pub fn new(script: Vec<Step>) -> Self {
        Self {
            script,
            log: RequestLog::new(),
        }
    }

    /// The log every stream this server accepts appends its requests to.
    pub fn log(&self) -> RequestLog {
        self.log.clone()
    }
}

// Rust note: tonic marks server trait methods `async fn` via `#[async_trait]`
// in the generated trait, which desugars to a boxed future under the hood;
// we don't have to think about that, just write ordinary `async fn`s.
#[tonic::async_trait]
impl AggregatedDiscoveryService for ScriptedAds {
    type StreamAggregatedResourcesStream = ResponseStream<DiscoveryResponse>;
    type DeltaAggregatedResourcesStream = ResponseStream<DeltaDiscoveryResponse>;

    async fn stream_aggregated_resources(
        &self,
        request: Request<tonic::Streaming<DiscoveryRequest>>,
    ) -> Result<Response<Self::StreamAggregatedResourcesStream>, Status> {
        let mut incoming = request.into_inner();
        let log = self.log.clone();
        let script = self.script.clone();
        let (tx, rx) = mpsc::channel::<Result<DiscoveryResponse, Status>>(16);

        // Rust note: the driver runs in its own task so this method can
        // return immediately with the receiving half of the channel as the
        // response stream; tonic polls that stream to pull responses out as
        // the driver task pushes them in.
        tokio::spawn(async move {
            'steps: for step in script {
                let Step::Send {
                    type_url,
                    version_info,
                    nonce,
                    resources,
                } = step;

                // Wait for the client's next request for this step's
                // type_url, recording every request (including ones for
                // other in-flight types) as it arrives.
                loop {
                    match incoming.next().await {
                        Some(Ok(req)) => {
                            log.record(&req);
                            if req.type_url == type_url {
                                break;
                            }
                        }
                        _ => break 'steps,
                    }
                }

                let response = DiscoveryResponse {
                    version_info,
                    resources,
                    type_url,
                    nonce,
                    ..Default::default()
                };
                if tx.send(Ok(response)).await.is_err() {
                    break;
                }
            }

            // Script exhausted (or client disconnected mid-script): keep
            // recording anything the client still sends until it closes the
            // stream, so trailing ACK/NACKs of the last scripted response
            // are captured too.
            while let Some(Ok(req)) = incoming.next().await {
                log.record(&req);
            }
        });

        let out = ReceiverStream(rx);
        Ok(Response::new(Box::pin(out)))
    }

    async fn delta_aggregated_resources(
        &self,
        _request: Request<tonic::Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
        Err(Status::unimplemented(
            "ScriptedAds is a SotW-only puppet server; delta xDS is a later WP-28 chunk",
        ))
    }
}

/// Adapts a `tokio::sync::mpsc::Receiver` into a `futures::Stream`.
///
/// Rust note: the workspace doesn't depend on `tokio-stream` (which has this
/// exact wrapper built in), so this is the few lines it would otherwise save
/// us — `Receiver::poll_recv` already does the real work.
struct ReceiverStream<T>(mpsc::Receiver<T>);

impl<T> Stream for ReceiverStream<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.0.poll_recv(cx)
    }
}

/// Adapts a bound `TcpListener` into the `Stream` of accepted connections
/// `tonic::transport::Server::serve_with_incoming*` wants. We bind the
/// listener ourselves (rather than handing tonic a `SocketAddr` to bind)
/// so we can read back the OS-assigned ephemeral port before serving.
struct TcpIncoming(TcpListener);

impl Stream for TcpIncoming {
    type Item = std::io::Result<TcpStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.poll_accept(cx) {
            Poll::Ready(Ok((stream, _peer))) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A running `ScriptedAds` instance: its bound address, a handle onto its
/// request log, and a clean way to shut it down.
pub struct Harness {
    pub addr: SocketAddr,
    pub log: RequestLog,
    shutdown: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl Harness {
    /// Binds an ephemeral loopback port, starts serving the given script,
    /// and returns once the listener is ready to accept connections.
    pub async fn spawn(script: Vec<Step>) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let ads = ScriptedAds::new(script);
        let log = ads.log();

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let incoming = TcpIncoming(listener);

        let join = tokio::spawn(async move {
            let serve = tonic::transport::Server::builder()
                .add_service(AggregatedDiscoveryServiceServer::new(ads))
                .serve_with_incoming_shutdown(incoming, async {
                    // A dropped sender (Harness dropped without calling
                    // shutdown()) also ends serving, so this never hangs
                    // the task forever.
                    let _ = shutdown_rx.await;
                });
            if let Err(err) = serve.await {
                // Test harness: surface server errors on stderr rather than
                // panicking a detached task.
                eprintln!("controlplane: ScriptedAds server error: {err}");
            }
        });

        Ok(Self {
            addr,
            log,
            shutdown: Some(shutdown_tx),
            join,
        })
    }

    /// Signals the server to stop accepting/serving and waits for it to
    /// finish.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.join.await;
    }
}
