//! WP-20 increment 3a acceptance: the ADS gRPC request/response pump, run
//! against `testing/controlplane`'s `ScriptedAds` over a real loopback
//! socket -- the same model `testing/controlplane/tests/ads_selftest.rs`
//! uses to drive the generated client stub directly.
//!
//! Every test here bounds every wire wait with `tokio::time::timeout` (rule
//! 14: a hang must fail loudly, not stall) and uses ephemeral ports only
//! (`Harness::spawn` binds `127.0.0.1:0`; rule 15).

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use controlplane::{Harness, RequestKind, RequestLog, Step};
use proxy_api::envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use proxy_api::envoy::service::discovery::v3::DiscoveryResponse;
use proxy_xds::{AdsClient, Subscription, SubscriptionState, Verdict};

const CDS: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
const RDS: &str = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";

/// Generous bound on the whole test, not a single round-trip: this suite
/// polls the harness's `RequestLog` rather than reading the client's own
/// response stream (the pump owns that), so there is no single `.await` to
/// wrap -- this is what turns "the pump never sent the request we expect" into
/// a named failure instead of a stall.
const WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Polls `log` until it has at least `want` recorded requests, or panics
/// after `WAIT_TIMEOUT`. Loose by design (rule on timing assertions): this
/// proves "the pump got there", not "the pump got there fast".
async fn wait_for_log_len(log: &RequestLog, want: usize) {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        if log.snapshot().len() >= want {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out after {WAIT_TIMEOUT:?} waiting for {want} recorded requests, saw {}",
                log.snapshot().len()
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// An accept-everything validator, for tests that don't care about NACKs.
fn always_accept() -> proxy_xds::Validator {
    Box::new(|_resp: &DiscoveryResponse| Verdict::Accept)
}

/// S8, and this increment's first acceptance bullet: "an accepted response
/// produces an ACK carrying that version and echoing the nonce."
#[tokio::test(flavor = "multi_thread")]
async fn accept_produces_an_ack_with_the_accepted_version_and_nonce() {
    let harness = Harness::spawn(vec![Step::Send {
        type_url: CDS.to_string(),
        version_info: "v1".to_string(),
        nonce: "n1".to_string(),
        resources: vec![],
    }])
    .await
    .expect("harness spawns");

    let mut client = AggregatedDiscoveryServiceClient::connect(format!("http://{}", harness.addr))
        .await
        .expect("client connects");

    let mut ads = AdsClient::new(vec![SubscriptionState::new(CDS, Subscription::Wildcard)]);
    let run = tokio::spawn(async move { ads.run_once(&mut client, always_accept()).await });

    wait_for_log_len(&harness.log, 2).await;

    let log = harness.log.snapshot();
    assert_eq!(log[0].kind(), RequestKind::Initial);
    assert_eq!(log[0].type_url, CDS);
    assert_eq!(
        log[1].kind(),
        RequestKind::Ack,
        "expected an ACK, got {:?}",
        log[1]
    );
    assert_eq!(
        log[1].version_info, "v1",
        "ACK must carry the accepted version"
    );
    assert_eq!(
        log[1].response_nonce, "n1",
        "ACK must echo the response's nonce"
    );
    assert!(log[1].error_detail.is_none());

    run.abort();
    harness.shutdown().await;
}

/// S8, and this increment's second acceptance bullet: "a rejected response
/// produces a NACK carrying the PREVIOUS acked version and the new nonce,
/// with `error_detail` set." Scripted as accept-then-reject so "previous" is
/// a real, non-empty version rather than the trivially-empty one before
/// anything has ever been accepted.
#[tokio::test(flavor = "multi_thread")]
async fn reject_produces_a_nack_with_the_previous_version_and_new_nonce() {
    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CDS.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![],
        },
        Step::Send {
            type_url: CDS.to_string(),
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

    let mut ads = AdsClient::new(vec![SubscriptionState::new(CDS, Subscription::Wildcard)]);
    // Accept the first response (v1), reject the second (v2) -- the
    // validator decides purely from the response's own version_info, no
    // external call counter needed.
    let validate: proxy_xds::Validator = Box::new(|resp: &DiscoveryResponse| {
        if resp.version_info == "v2" {
            Verdict::Reject("bad cluster config".to_string())
        } else {
            Verdict::Accept
        }
    });
    let run = tokio::spawn(async move { ads.run_once(&mut client, validate).await });

    // [0] initial, [1] ACK of v1, [2] NACK of v2.
    wait_for_log_len(&harness.log, 3).await;

    let log = harness.log.snapshot();
    assert_eq!(log[1].kind(), RequestKind::Ack);
    assert_eq!(log[1].version_info, "v1");

    assert_eq!(
        log[2].kind(),
        RequestKind::Nack,
        "expected a NACK, got {:?}",
        log[2]
    );
    assert_eq!(
        log[2].version_info, "v1",
        "NACK must carry the PREVIOUS accepted version, not the rejected v2"
    );
    assert_eq!(
        log[2].response_nonce, "n2",
        "NACK must echo the rejected response's nonce"
    );
    assert_eq!(log[2].error_detail.as_deref(), Some("bad cluster config"));

    run.abort();
    harness.shutdown().await;
}

/// This increment's third acceptance bullet: "a type whose subscription has
/// no names is never requested." RDS here is subscribed with an empty name
/// set (the ordinary state before any LDS/CDS response has named anything),
/// which `SubscriptionState::has_nothing_to_request` says renders
/// identically to a wildcard on the wire -- the pump must skip it rather
/// than ask for every RouteConfiguration that exists.
#[tokio::test(flavor = "multi_thread")]
async fn empty_name_subscription_is_never_requested() {
    let harness = Harness::spawn(vec![Step::Send {
        type_url: CDS.to_string(),
        version_info: "v1".to_string(),
        nonce: "n1".to_string(),
        resources: vec![],
    }])
    .await
    .expect("harness spawns");

    let mut client = AggregatedDiscoveryServiceClient::connect(format!("http://{}", harness.addr))
        .await
        .expect("client connects");

    let mut ads = AdsClient::new(vec![
        SubscriptionState::new(CDS, Subscription::Wildcard),
        SubscriptionState::new(RDS, Subscription::Names(BTreeSet::new())),
    ]);
    let run = tokio::spawn(async move { ads.run_once(&mut client, always_accept()).await });

    // [0] CDS initial, [1] CDS ACK -- and nothing else, ever, for RDS.
    wait_for_log_len(&harness.log, 2).await;

    let log = harness.log.snapshot();
    assert!(
        log.iter().all(|r| r.type_url == CDS),
        "RDS must never be requested while its subscription has no names: {log:?}"
    );

    run.abort();
    harness.shutdown().await;
}
