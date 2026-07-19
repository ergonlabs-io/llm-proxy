//! Self-test for `ScriptedAds` (WP-28): drives the harness with the real
//! generated ADS *client* stub over a real loopback socket, the same way a
//! WP-20 test driving llm-proxy's xDS client would, and asserts the
//! request log records what the wire exchange actually did.

use std::pin::Pin;
use std::task::{Context, Poll};

use controlplane::{Harness, RequestKind, Step};
use futures::Stream;
use proxy_api::envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use proxy_api::envoy::service::discovery::v3::DiscoveryRequest;
use proxy_api::google::rpc::Status as RpcStatus;
use tokio::sync::mpsc;

const CLUSTER_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";

/// Rust note: same `mpsc::Receiver`-as-`Stream` shape as
/// `controlplane::server`'s internal one, duplicated here because the real
/// one is a private implementation detail of the server, not part of the
/// harness's public API. It lets this test send requests interactively
/// (react to a response, then send the next request) instead of handing the
/// client a fixed `Vec` up front.
struct OutboundStream(mpsc::Receiver<DiscoveryRequest>);

impl Stream for OutboundStream {
    type Item = DiscoveryRequest;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<DiscoveryRequest>> {
        self.0.poll_recv(cx)
    }
}

#[tokio::test]
async fn records_initial_then_ack() {
    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![],
        },
        Step::Send {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: "v2".to_string(),
            nonce: "n2".to_string(),
            resources: vec![],
        },
    ])
    .await
    .expect("harness spawns");

    let mut client = AggregatedDiscoveryServiceClient::connect(format!("http://{}", harness.addr))
        .await
        .expect("client connects");

    let (req_tx, req_rx) = mpsc::channel(4);
    let response = client
        .stream_aggregated_resources(OutboundStream(req_rx))
        .await
        .expect("stream opens");
    let mut inbound = response.into_inner();

    // Initial request: no version_info, no response_nonce.
    req_tx
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            ..Default::default()
        })
        .await
        .expect("send initial request");

    let resp1 = inbound
        .message()
        .await
        .expect("stream healthy")
        .expect("first scripted response");
    assert_eq!(resp1.version_info, "v1");
    assert_eq!(resp1.nonce, "n1");

    // ACK: echo version_info + response_nonce, no error_detail.
    req_tx
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: resp1.version_info.clone(),
            response_nonce: resp1.nonce.clone(),
            ..Default::default()
        })
        .await
        .expect("send ack");

    let resp2 = inbound
        .message()
        .await
        .expect("stream healthy")
        .expect("second scripted response");
    assert_eq!(resp2.version_info, "v2");

    let log = harness.log.snapshot();
    assert_eq!(log.len(), 2, "expected initial request + ack recorded");
    assert_eq!(log[0].kind(), RequestKind::Initial);
    assert_eq!(log[0].version_info, "");
    assert_eq!(log[1].kind(), RequestKind::Ack);
    assert_eq!(log[1].version_info, "v1");
    assert_eq!(log[1].response_nonce, "n1");

    drop(req_tx);
    harness.shutdown().await;
}

#[tokio::test]
async fn records_nack() {
    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![],
        },
        Step::Send {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: "v1".to_string(),
            nonce: "n2".to_string(),
            resources: vec![],
        },
    ])
    .await
    .expect("harness spawns");

    let mut client = AggregatedDiscoveryServiceClient::connect(format!("http://{}", harness.addr))
        .await
        .expect("client connects");

    let (req_tx, req_rx) = mpsc::channel(4);
    let response = client
        .stream_aggregated_resources(OutboundStream(req_rx))
        .await
        .expect("stream opens");
    let mut inbound = response.into_inner();

    req_tx
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            ..Default::default()
        })
        .await
        .expect("send initial request");

    let resp1 = inbound
        .message()
        .await
        .expect("stream healthy")
        .expect("first scripted response");

    // NACK: previous version_info (rejected the new one), error_detail set.
    req_tx
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: String::new(),
            response_nonce: resp1.nonce.clone(),
            error_detail: Some(RpcStatus {
                code: 3,
                message: "bad cluster config".to_string(),
                details: vec![],
            }),
            ..Default::default()
        })
        .await
        .expect("send nack");

    let resp2 = inbound
        .message()
        .await
        .expect("stream healthy")
        .expect("second scripted response");
    assert_eq!(resp2.nonce, "n2");

    let log = harness.log.snapshot();
    assert_eq!(log.len(), 2, "expected initial request + nack recorded");
    assert_eq!(log[0].kind(), RequestKind::Initial);
    assert_eq!(log[1].kind(), RequestKind::Nack);
    assert_eq!(log[1].error_detail.as_deref(), Some("bad cluster config"));

    drop(req_tx);
    harness.shutdown().await;
}
