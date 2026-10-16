//! The five ADS acceptance scenarios -- {ACK, NACK-recover, reconnect-resync,
//! spurious-nonce, out-of-order-response} -- run against
//! `testing/controlplane`'s `ScriptedAds` harness over a real loopback
//! socket, the same model `tests/client.rs` and
//! `testing/controlplane/tests/ads_selftest.rs` use.
//!
//! # Where each of the five lives
//!
//! Three of the five already had socket-level coverage in `tests/client.rs`.
//! This file adds the cases that were missing, plus one recovery leg that was
//! covered only at the unit level.
//!
//! | Scenario              | Socket-level test                                                              | Unit-level test (`tests/subscription.rs`)                       |
//! |------------------------|--------------------------------------------------------------------------------|-------------------------------------------------------------------|
//! | ACK                   | `client::accept_produces_an_ack_with_the_accepted_version_and_nonce`           | `an_accept_acks_the_new_version_and_echoes_the_nonce`             |
//! | NACK-recover           | `client::reject_produces_a_nack_with_the_previous_version_and_new_nonce` (the NACK half) + [`a_nack_is_followed_by_a_normal_accept_of_the_next_good_response`] (the recovery half, added here -- the existing e2e test never sent a THIRD, accepted response, so "recover" was proven only in `subscription.rs`'s `the_client_recovers_from_a_nack_on_the_next_good_response`, never over a wire) | `the_client_recovers_from_a_nack_on_the_next_good_response`        |
//! | reconnect-resync       | `client::reconnect_resends_the_acked_version_with_no_nonce`                     | `a_reconnect_keeps_the_acked_version_and_drops_the_nonce`          |
//! | spurious-nonce         | [`an_unrequested_second_response_is_still_answered_with_its_own_nonce`] (added here -- nothing before this file drove it over a socket) | `the_nonce_advances_on_a_nack_as_well_as_an_ack` (only proves the nonce field advances, not that the client answers a second response at all) |
//! | out-of-order-response  | [`an_lds_response_before_cds_is_still_acked_independently_of_arrival_order`] (added here) | `types_keep_independent_version_and_nonce_state` (proves independent state, not ordering over a wire) |
//!
//! Rust note: every test runs on a `multi_thread` runtime and bounds its waits
//! with `tokio::time::timeout`, so a hang fails loudly (AGENTS.md "Build And
//! Test", Hangs). Sockets are ephemeral (AGENTS.md "Running The Product").

use std::time::{Duration, Instant};

use controlplane::{Harness, RequestKind, RequestLog, Step};
use proxy_api::envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use proxy_api::envoy::service::discovery::v3::DiscoveryResponse;
use proxy_xds::{AdsClient, FnHandler, Subscription, SubscriptionState, Verdict};

const CDS: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
const LDS: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";

/// Same bound and rationale as `tests/client.rs`'s own constant: generous on
/// the whole test, not a single round-trip.
const WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Identical to `tests/client.rs::wait_for_log_len` -- duplicated rather than
/// shared because integration test binaries in this crate don't share a
/// `tests/common` module (there isn't one; see that file's own copy).
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

// ---------------------------------------------------------------------------
// NACK-recover: the recovery leg, over the wire.
// ---------------------------------------------------------------------------

/// The `NACK-recover` acceptance scenario, the half `tests/client.rs`
/// left unproven over a socket: `reject_produces_a_nack_with_the_previous_version_and_new_nonce`
/// stops at the NACK itself. S8's rule composes with a plain accept ("apply
/// -> ACK(version, nonce)") once the bad response is behind it, and
/// `subscription.rs::the_client_recovers_from_a_nack_on_the_next_good_response`
/// pins that at the unit level -- this is the same claim with a real NACK
/// answer actually reaching the wire in between.
///
/// Script: accept v1, reject v2, accept v3. The client must ACK v1, NACK v2
/// (echoing v1, the last accepted version), then ACK v3 normally -- proving
/// the rejection left no residue that would stop a later good response from
/// being accepted.
#[tokio::test(flavor = "multi_thread")]
async fn a_nack_is_followed_by_a_normal_accept_of_the_next_good_response() {
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
        Step::Send {
            type_url: CDS.to_string(),
            version_info: "v3".to_string(),
            nonce: "n3".to_string(),
            resources: vec![],
        },
    ])
    .await
    .expect("harness spawns");

    let mut client = AggregatedDiscoveryServiceClient::connect(format!("http://{}", harness.addr))
        .await
        .expect("client connects");

    let validate: proxy_xds::Validator = Box::new(|resp: &DiscoveryResponse| {
        if resp.version_info == "v2" {
            Verdict::Reject("bad cluster config".to_string())
        } else {
            Verdict::Accept
        }
    });
    let mut handler = FnHandler(validate);

    let mut ads = AdsClient::new(vec![SubscriptionState::new(CDS, Subscription::Wildcard)]);
    let run = tokio::spawn(async move { ads.run_once(&mut client, &mut handler).await });

    // [0] initial, [1] ACK v1, [2] NACK v2, [3] ACK v3.
    wait_for_log_len(&harness.log, 4).await;
    let log = harness.log.snapshot();

    assert_eq!(log[1].kind(), RequestKind::Ack);
    assert_eq!(log[1].version_info, "v1");

    assert_eq!(log[2].kind(), RequestKind::Nack);
    assert_eq!(
        log[2].version_info, "v1",
        "the NACK must still echo the last accepted version"
    );
    assert_eq!(log[2].error_detail.as_deref(), Some("bad cluster config"));

    assert_eq!(
        log[3].kind(),
        RequestKind::Ack,
        "the response after a NACK must be accepted normally, got {:?}",
        log[3]
    );
    assert_eq!(
        log[3].version_info, "v3",
        "recovery must move the acked version on to the next good response"
    );
    assert_eq!(log[3].response_nonce, "n3");
    assert!(log[3].error_detail.is_none());

    run.abort();
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// spurious-nonce
// ---------------------------------------------------------------------------

/// S8: the client answers every response, even one carrying a nonce it did
/// not most recently send. Stale-nonce filtering is the server's job.
///
/// Two scripted sends back to back serve the second response as soon as the
/// first ACK lands. A client that filtered it would time out here. This test
/// does not cover a response arriving before the prior ACK, because the
/// harness cannot script that.
#[tokio::test(flavor = "multi_thread")]
async fn an_unrequested_second_response_is_still_answered_with_its_own_nonce() {
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
    let run = tokio::spawn(async move {
        ads.run_once(&mut client, &mut FnHandler(always_accept()))
            .await
    });

    // [0] initial, [1] ACK of n1, [2] ACK of n2 -- if the client dropped the
    // second response this never reaches 3 and the test fails on a named
    // timeout instead of hanging forever.
    wait_for_log_len(&harness.log, 3).await;
    let log = harness.log.snapshot();

    assert_eq!(log[1].kind(), RequestKind::Ack);
    assert_eq!(log[1].response_nonce, "n1");

    assert_eq!(
        log[2].kind(),
        RequestKind::Ack,
        "the client must still answer the second response, got {:?}",
        log[2]
    );
    assert_eq!(
        log[2].version_info, "v2",
        "the second response must be applied, not ignored as stale"
    );
    assert_eq!(
        log[2].response_nonce, "n2",
        "the request must echo the LATEST nonce the client has seen, not the older n1"
    );

    run.abort();
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// out-of-order-response
// ---------------------------------------------------------------------------

/// The `out-of-order-response` acceptance scenario. S8: "Ordering
/// expectation (server-side, but client must tolerate any order):
/// make-before-break CDS->EDS->LDS->RDS->removes; client must not
/// crash/drop on out-of-order."
///
/// The subscription order here is `[LDS, CDS]`, so the client's own initial
/// requests go out LDS-then-CDS, and the script answers them in that same
/// arrival order -- LDS before CDS, the reverse of the expected
/// CDS-before-LDS make-before-break sequence. Each type's ACK must carry
/// that type's own version and nonce, proving the two subscriptions kept
/// independent state and neither response disturbed or blocked the other,
/// over a real stream with both types in flight at once.
#[tokio::test(flavor = "multi_thread")]
async fn an_lds_response_before_cds_is_still_acked_independently_of_arrival_order() {
    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: LDS.to_string(),
            version_info: "lv1".to_string(),
            nonce: "ln1".to_string(),
            resources: vec![],
        },
        Step::Send {
            type_url: CDS.to_string(),
            version_info: "cv1".to_string(),
            nonce: "cn1".to_string(),
            resources: vec![],
        },
    ])
    .await
    .expect("harness spawns");

    let mut client = AggregatedDiscoveryServiceClient::connect(format!("http://{}", harness.addr))
        .await
        .expect("client connects");

    // LDS first in the vec so its initial request is the first thing on the
    // wire -- see the module doc above for why that ordering is what makes
    // the script's LDS-before-CDS `Send` order deadlock-free.
    let mut ads = AdsClient::new(vec![
        SubscriptionState::new(LDS, Subscription::Wildcard),
        SubscriptionState::new(CDS, Subscription::Wildcard),
    ]);
    let run = tokio::spawn(async move {
        ads.run_once(&mut client, &mut FnHandler(always_accept()))
            .await
    });

    // [0] LDS initial, [1] CDS initial, [2] LDS ACK, [3] CDS ACK.
    wait_for_log_len(&harness.log, 4).await;
    let log = harness.log.snapshot();

    assert_eq!(log[0].type_url, LDS);
    assert_eq!(log[0].kind(), RequestKind::Initial);
    assert_eq!(log[1].type_url, CDS);
    assert_eq!(log[1].kind(), RequestKind::Initial);

    assert_eq!(
        log[2].type_url, LDS,
        "the LDS response arrived first, so the client must answer it first: {log:?}"
    );
    assert_eq!(log[2].kind(), RequestKind::Ack);
    assert_eq!(log[2].version_info, "lv1");
    assert_eq!(log[2].response_nonce, "ln1");

    assert_eq!(
        log[3].type_url, CDS,
        "the CDS ACK must still follow, unblocked by the earlier LDS response: {log:?}"
    );
    assert_eq!(log[3].kind(), RequestKind::Ack);
    assert_eq!(
        log[3].version_info, "cv1",
        "CDS's own version must not have been disturbed by the LDS response in between"
    );
    assert_eq!(log[3].response_nonce, "cn1");

    run.abort();
    harness.shutdown().await;
}
