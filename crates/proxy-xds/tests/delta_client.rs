//! WP-22 delta ADS transport acceptance over real loopback gRPC.

use std::time::Duration;

use controlplane::DeltaHarness;
use proxy_api::envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use proxy_api::envoy::service::discovery::v3::{DeltaDiscoveryResponse, Resource};
use proxy_config::ir::NodeIdentity;
use proxy_xds::{
    BackoffPolicy, DeltaAdsClient, DeltaResponseHandler, DeltaSubscriptionState, FnDeltaHandler,
    Reconnect, Subscription, Verdict,
};

const CDS: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";

#[tokio::test(flavor = "multi_thread")]
async fn accepted_delta_response_is_acked_and_versions_reach_state() {
    let harness = DeltaHarness::spawn(DeltaDiscoveryResponse {
        type_url: CDS.to_string(),
        nonce: "nonce-1".to_string(),
        resources: vec![Resource {
            name: "cluster-a".to_string(),
            version: "resource-v7".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    })
    .await
    .expect("delta harness spawns");
    let mut grpc = AggregatedDiscoveryServiceClient::connect(format!("http://{}", harness.addr))
        .await
        .expect("client connects");
    let mut client = DeltaAdsClient::new(vec![DeltaSubscriptionState::new(
        CDS,
        Subscription::Wildcard,
    )])
    .with_node(NodeIdentity {
        id: "proxy-1".to_string(),
        cluster: "edge".to_string(),
    });
    let mut handler = FnDeltaHandler(Box::new(|_| Verdict::Accept));

    tokio::time::timeout(
        Duration::from_secs(5),
        client.run_once(&mut grpc, &mut handler),
    )
    .await
    .expect("delta stream completes")
    .expect("delta pump succeeds");

    let requests = harness.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0]
            .node
            .as_ref()
            .map(|(id, cluster)| (id.as_str(), cluster.as_str())),
        Some(("proxy-1", "edge"))
    );
    assert!(requests[0].response_nonce.is_empty());
    assert_eq!(requests[1].node, None);
    assert_eq!(requests[1].response_nonce, "nonce-1");
    assert!(requests[1].error_detail.is_none());
    assert_eq!(
        client.states()[0].resource_versions().get("cluster-a"),
        Some(&"resource-v7".to_string())
    );

    harness.shutdown().await;
}

struct DelayedHandler {
    release: std::sync::Arc<tokio::sync::Notify>,
}

impl DeltaResponseHandler for DelayedHandler {
    fn handle(
        &mut self,
        _response: &DeltaDiscoveryResponse,
    ) -> impl std::future::Future<Output = Verdict> + Send {
        let release = std::sync::Arc::clone(&self.release);
        async move {
            release.notified().await;
            Verdict::Accept
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ack_waits_until_delta_response_application_finishes() {
    let harness = DeltaHarness::spawn(DeltaDiscoveryResponse {
        type_url: CDS.to_string(),
        nonce: "nonce-delayed".to_string(),
        ..Default::default()
    })
    .await
    .expect("delta harness spawns");
    let mut grpc = AggregatedDiscoveryServiceClient::connect(format!("http://{}", harness.addr))
        .await
        .expect("client connects");
    let mut client = DeltaAdsClient::new(vec![DeltaSubscriptionState::new(
        CDS,
        Subscription::Wildcard,
    )]);
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let handler_release = std::sync::Arc::clone(&release);
    let run = tokio::spawn(async move {
        client
            .run_once(
                &mut grpc,
                &mut DelayedHandler {
                    release: handler_release,
                },
            )
            .await
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while harness.requests().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        harness.requests().len(),
        1,
        "ACK reached wire before handler completed"
    );

    release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("delta stream completes")
        .expect("client task joins")
        .expect("delta pump succeeds");
    assert_eq!(harness.requests()[1].response_nonce, "nonce-delayed");
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reconnect_resends_acked_versions_without_old_nonce() {
    let harness = DeltaHarness::spawn_sequence([
        DeltaDiscoveryResponse {
            type_url: CDS.to_string(),
            nonce: "nonce-v1".to_string(),
            resources: vec![Resource {
                name: "cluster-a".to_string(),
                version: "resource-v1".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        },
        DeltaDiscoveryResponse {
            type_url: CDS.to_string(),
            nonce: "nonce-v2".to_string(),
            resources: vec![Resource {
                name: "cluster-a".to_string(),
                version: "resource-v2".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        },
    ])
    .await
    .expect("delta harness spawns");
    let mut grpc = AggregatedDiscoveryServiceClient::connect(format!("http://{}", harness.addr))
        .await
        .expect("client connects");
    let mut client = DeltaAdsClient::new(vec![DeltaSubscriptionState::new(
        CDS,
        Subscription::Wildcard,
    )]);
    let seen_second = std::sync::Arc::new(tokio::sync::Notify::new());
    let handler_seen_second = std::sync::Arc::clone(&seen_second);
    let handler = FnDeltaHandler(Box::new(move |response| {
        if response.nonce == "nonce-v2" {
            handler_seen_second.notify_one();
        }
        Verdict::Accept
    }));
    let reconnect = Reconnect {
        policy: BackoffPolicy::default(),
        rng: Box::new(|| 0.0),
        sleep: Box::new(|_| Box::pin(std::future::ready(()))),
    };
    let run = tokio::spawn(async move { client.run(&mut grpc, handler, reconnect).await });

    tokio::time::timeout(Duration::from_secs(5), seen_second.notified())
        .await
        .expect("client reconnects and receives second response");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while harness.requests().len() < 4 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    run.abort();
    let _ = run.await;

    let requests = harness.requests();
    assert!(
        requests.len() >= 4,
        "expected two requests and ACKs per stream"
    );
    assert_eq!(requests[0].initial_resource_versions, Default::default());
    assert_eq!(requests[1].response_nonce, "nonce-v1");
    assert_eq!(
        requests[2].initial_resource_versions["cluster-a"],
        "resource-v1"
    );
    assert!(requests[2].response_nonce.is_empty());
    assert_eq!(requests[3].response_nonce, "nonce-v2");
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn removed_resources_reach_handler_before_delta_ack() {
    const SDS: &str = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";
    let harness = DeltaHarness::spawn(DeltaDiscoveryResponse {
        type_url: SDS.to_string(),
        nonce: "nonce-remove".to_string(),
        removed_resources: vec!["edge-cert".to_string()],
        ..Default::default()
    })
    .await
    .expect("delta harness spawns");
    let mut grpc = AggregatedDiscoveryServiceClient::connect(format!("http://{}", harness.addr))
        .await
        .expect("client connects");
    let mut client = DeltaAdsClient::new(vec![DeltaSubscriptionState::new(
        SDS,
        Subscription::Wildcard,
    )]);
    let removed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let handler_removed = std::sync::Arc::clone(&removed);
    let mut handler = FnDeltaHandler(Box::new(move |response| {
        *handler_removed.lock().expect("removed mutex poisoned") =
            response.removed_resources.clone();
        Verdict::Accept
    }));

    client
        .run_once(&mut grpc, &mut handler)
        .await
        .expect("delta pump succeeds");
    assert_eq!(
        *removed.lock().expect("removed mutex poisoned"),
        vec!["edge-cert".to_string()]
    );
    let requests = harness.requests();
    assert_eq!(requests[1].response_nonce, "nonce-remove");
    assert!(requests[1].error_detail.is_none());
    harness.shutdown().await;
}
