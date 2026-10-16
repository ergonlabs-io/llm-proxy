//! Self-test for `ScriptedAds`: drives the harness with the real
//! generated ADS *client* stub over a real loopback socket, the same way a
//! test driving llm-proxy's xDS client would, and asserts the
//! request log records what the wire exchange actually did.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use controlplane::{Harness, RequestKind, Step};
use futures::Stream;
use proxy_api::envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use proxy_api::envoy::service::discovery::v3::DiscoveryRequest;
use proxy_api::google::rpc::Status as RpcStatus;
use tokio::sync::mpsc;
use tokio::time::timeout;

const CLUSTER_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
const LISTENER_TYPE_URL: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";

/// Generous bound on any single wire round-trip in these tests (rule 14:
/// bound every request). Not a performance assertion -- just turns "the
/// harness hung" into a fast, named failure instead of a stall.
const STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// Rust note: the receiver stream enables interactive request/response steps;
/// the server's equivalent is private.
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

#[tokio::test]
async fn wait_for_ack_ignores_initial_requests_and_advances_on_the_exact_ack() {
    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![],
        },
        Step::WaitForAck {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: "v1".to_string(),
            response_nonce: "n1".to_string(),
        },
        Step::Push {
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
    let mut inbound = client
        .stream_aggregated_resources(OutboundStream(req_rx))
        .await
        .expect("stream opens")
        .into_inner();

    req_tx
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    let first = timeout(STEP_TIMEOUT, inbound.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    req_tx
        .send(DiscoveryRequest {
            type_url: LISTENER_TYPE_URL.to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), inbound.message())
            .await
            .is_err(),
        "an unrelated initial subscription must not release an ACK wait"
    );

    req_tx
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: first.version_info.clone(),
            response_nonce: "wrong-nonce".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), inbound.message())
            .await
            .is_err(),
        "an ACK for another response must not release this wait"
    );

    req_tx
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: first.version_info,
            response_nonce: first.nonce,
            ..Default::default()
        })
        .await
        .unwrap();
    let second = timeout(STEP_TIMEOUT, inbound.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(second.version_info, "v2");

    let log = harness.log.snapshot();
    assert_eq!(log.len(), 4);
    assert_eq!(log[0].kind(), RequestKind::Initial);
    assert_eq!(log[1].kind(), RequestKind::Initial);
    assert_eq!(log[2].kind(), RequestKind::Ack);
    assert_eq!(log[2].response_nonce, "wrong-nonce");
    assert_eq!(log[3].kind(), RequestKind::Ack);
    drop(req_tx);
    harness.shutdown().await;
}

#[tokio::test]
async fn wait_for_nack_does_not_accept_an_ack_for_the_same_nonce() {
    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![],
        },
        Step::WaitForNack {
            type_url: CLUSTER_TYPE_URL.to_string(),
            response_nonce: "n1".to_string(),
        },
        Step::Push {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: "recovery".to_string(),
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
    let mut inbound = client
        .stream_aggregated_resources(OutboundStream(req_rx))
        .await
        .expect("stream opens")
        .into_inner();

    req_tx
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    let first = timeout(STEP_TIMEOUT, inbound.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    req_tx
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: first.version_info.clone(),
            response_nonce: first.nonce.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), inbound.message())
            .await
            .is_err(),
        "an ACK must not release a NACK wait"
    );

    req_tx
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            response_nonce: first.nonce,
            error_detail: Some(RpcStatus {
                code: 3,
                message: "reject v1".to_string(),
                details: vec![],
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    let recovery = timeout(STEP_TIMEOUT, inbound.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(recovery.version_info, "recovery");

    let log = harness.log.snapshot();
    assert_eq!(log.len(), 3);
    assert_eq!(log[1].kind(), RequestKind::Ack);
    assert_eq!(log[2].kind(), RequestKind::Nack);
    drop(req_tx);
    harness.shutdown().await;
}

/// Reconnects on a second stream and resumes the script after `DropStream`.
/// Rust note: a multi-thread runtime lets both streams progress against the server
/// (AGENTS.md "Build And Test").
#[tokio::test(flavor = "multi_thread")]
async fn drop_stream_resumes_script_on_reconnect() {
    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![],
        },
        Step::DropStream,
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

    // Stream 1: send the initial request, get v1/n1 back, then observe the
    // server end the stream (DropStream) instead of a third response.
    let (req_tx_1, req_rx_1) = mpsc::channel(4);
    let response_1 = client
        .stream_aggregated_resources(OutboundStream(req_rx_1))
        .await
        .expect("stream 1 opens");
    let mut inbound_1 = response_1.into_inner();

    req_tx_1
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            ..Default::default()
        })
        .await
        .expect("send initial request on stream 1");

    let resp1 = timeout(STEP_TIMEOUT, inbound_1.message())
        .await
        .expect("stream 1 responds before timeout")
        .expect("stream 1 healthy")
        .expect("first scripted response");
    assert_eq!(resp1.version_info, "v1");
    assert_eq!(resp1.nonce, "n1");

    let end = timeout(STEP_TIMEOUT, inbound_1.message())
        .await
        .expect("stream 1 ends before timeout")
        .expect("stream 1 ends cleanly, not with an error");
    assert!(
        end.is_none(),
        "expected DropStream to end stream 1 with no further response"
    );
    drop(req_tx_1);

    // Stream 2 ("reconnect"): a client that reconnected after losing the
    // stream re-subscribes with its last-ACKed version_info but an empty
    // response_nonce (S8) -- there is no prior nonce on the new stream to
    // echo. The script must resume at the Send *after* DropStream, not
    // replay v1/n1.
    let (req_tx_2, req_rx_2) = mpsc::channel(4);
    let response_2 = client
        .stream_aggregated_resources(OutboundStream(req_rx_2))
        .await
        .expect("stream 2 opens");
    let mut inbound_2 = response_2.into_inner();

    req_tx_2
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: resp1.version_info.clone(),
            ..Default::default()
        })
        .await
        .expect("send re-subscribe request on stream 2");

    let resp2 = timeout(STEP_TIMEOUT, inbound_2.message())
        .await
        .expect("stream 2 responds before timeout")
        .expect("stream 2 healthy")
        .expect("second scripted response, not a replay of the first");
    assert_eq!(resp2.version_info, "v2");
    assert_eq!(resp2.nonce, "n2");

    let log = harness.log.snapshot();
    assert_eq!(
        log.len(),
        2,
        "one request per stream, and DropStream consumed no request"
    );
    assert_eq!(log[0].stream_id, 1);
    assert_eq!(log[0].kind(), RequestKind::Initial);
    assert_eq!(log[0].version_info, "");
    assert_eq!(
        log[1].stream_id, 2,
        "re-subscribe arrived on a NEW stream, not stream 1"
    );
    assert_eq!(
        log[1].kind(),
        RequestKind::Initial,
        "empty response_nonce classifies as Initial even with a carried-over version_info (S8)"
    );
    assert_eq!(log[1].version_info, "v1");

    drop(req_tx_2);
    harness.shutdown().await;
}

/// `Step::Wait` delays the next response without consuming a client
/// request. Proves the delay happens strictly before the second send, with
/// only a generous lower-bound timing check -- never a tight one, which
/// would be flaky (AGENTS.md "Build And Test").
#[tokio::test]
async fn wait_delays_next_send() {
    const WAIT: Duration = Duration::from_millis(300);
    // Deliberately loose: proves "a real delay happened", not "the delay
    // was exactly WAIT".
    const GENEROUS_LOWER_BOUND: Duration = Duration::from_millis(100);

    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![],
        },
        Step::Wait { duration: WAIT },
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

    req_tx
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            ..Default::default()
        })
        .await
        .expect("send initial request");

    let resp1 = timeout(STEP_TIMEOUT, inbound.message())
        .await
        .expect("first response before timeout")
        .expect("stream healthy")
        .expect("first scripted response");
    assert_eq!(resp1.version_info, "v1");

    req_tx
        .send(DiscoveryRequest {
            type_url: CLUSTER_TYPE_URL.to_string(),
            version_info: resp1.version_info.clone(),
            response_nonce: resp1.nonce.clone(),
            ..Default::default()
        })
        .await
        .expect("send ack");

    let before_wait = Instant::now();
    let resp2 = timeout(STEP_TIMEOUT, inbound.message())
        .await
        .expect("second response before timeout")
        .expect("stream healthy")
        .expect("second scripted response, sent only after the Wait step");
    let elapsed = before_wait.elapsed();

    assert_eq!(resp2.version_info, "v2");
    assert!(
        elapsed >= GENEROUS_LOWER_BOUND,
        "expected the Wait step to delay the second send by roughly {WAIT:?}, \
         but the second response arrived after only {elapsed:?}"
    );

    drop(req_tx);
    harness.shutdown().await;
}
