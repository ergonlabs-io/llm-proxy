//! WP-20 increment 3a/3b acceptance: the ADS gRPC request/response pump and
//! the reconnect loop above it, run
//! against `testing/controlplane`'s `ScriptedAds` over a real loopback
//! socket -- the same model `testing/controlplane/tests/ads_selftest.rs`
//! uses to drive the generated client stub directly.
//!
//! Every test here bounds every wire wait with `tokio::time::timeout` (rule
//! 14: a hang must fail loudly, not stall) and uses ephemeral ports only
//! (`Harness::spawn` binds `127.0.0.1:0`; rule 15).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use controlplane::{Harness, RequestKind, RequestLog, Step};
use proxy_api::envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use proxy_api::envoy::service::discovery::v3::DiscoveryResponse;
use proxy_config::ir::NodeIdentity;
use proxy_xds::{
    AdsClient, BackoffPolicy, FnHandler, Reconnect, ResponseHandler, Subscription,
    SubscriptionState, Verdict,
};

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
    let run = tokio::spawn(async move {
        ads.run_once(&mut client, &mut FnHandler(always_accept()))
            .await
    });

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
    let mut handler = FnHandler(validate);
    let run = tokio::spawn(async move { ads.run_once(&mut client, &mut handler).await });

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
    let run = tokio::spawn(async move {
        ads.run_once(&mut client, &mut FnHandler(always_accept()))
            .await
    });

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

// ---------------------------------------------------------------------------
// WP-20 increment 3b: reconnect, resync, and backoff.
// ---------------------------------------------------------------------------

/// A `Reconnect` whose sleep records what it was asked to wait for and then
/// returns immediately, and whose jitter draw is the constant `1.0` (the top
/// of the range) so every recorded delay is the policy's exact cap for that
/// attempt.
///
/// Returning immediately is what keeps these tests at milliseconds: the
/// assertion is "the loop asked for 500ms", which is the real claim -- that
/// it actually slept is `tokio::time::sleep`'s problem, not WP-20's.
fn recording_reconnect(policy: BackoffPolicy) -> (Reconnect, Arc<Mutex<Vec<Duration>>>) {
    let recorded: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorded);
    let reconnect = Reconnect {
        policy,
        rng: Box::new(|| 1.0),
        sleep: Box::new(move |delay| {
            sink.lock().expect("delay sink mutex poisoned").push(delay);
            Box::pin(std::future::ready(()))
        }),
    };
    (reconnect, recorded)
}

/// Polls `delays` until it holds at least `want` entries, or panics after
/// `WAIT_TIMEOUT`.
async fn wait_for_delays(delays: &Arc<Mutex<Vec<Duration>>>, want: usize) -> Vec<Duration> {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        let seen = delays.lock().expect("delay sink mutex poisoned").clone();
        if seen.len() >= want {
            return seen;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out after {WAIT_TIMEOUT:?} waiting for {want} backoff delays, saw {seen:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// WP-20's `reconnect-resync` acceptance scenario, and S8's reconnect rule:
///
/// > Reconnect: new stream, re-send all subscriptions with acked versions
/// > (versions persist across streams for same server).
///
/// The script serves v1, drops the stream, then serves v2. The claim is
/// about the FIRST request of the second stream: it must carry `v1` (the
/// version survived) and an EMPTY nonce (the nonce did not). Sending `n1`
/// there would echo a nonce the new stream never issued; sending an empty
/// version would ask the control plane to re-send config we already have.
#[tokio::test(flavor = "multi_thread")]
async fn reconnect_resends_the_acked_version_with_no_nonce() {
    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CDS.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![],
        },
        Step::DropStream,
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
    let (reconnect, _delays) = recording_reconnect(BackoffPolicy::default());
    let run = tokio::spawn(async move {
        ads.run(&mut client, FnHandler(always_accept()), reconnect)
            .await
    });

    // Three requests, not four: `ScriptedAds` reaches its `DropStream` step
    // the instant it has pushed v1 and returns without reading again, so the
    // client's ACK of v1 lands on a stream nobody is recording. That costs
    // nothing here -- the claim under test is what the SECOND stream opens
    // with, and stream 2 carrying `v1` is itself proof the client accepted
    // v1 and kept it across the reconnect.
    wait_for_log_len(&harness.log, 3).await;
    let log = harness.log.snapshot();

    assert_eq!(log[0].stream_id, 1);
    assert_eq!(
        log[0].version_info, "",
        "the first request ever carries no version"
    );

    assert_eq!(
        log[1].stream_id, 2,
        "the client must open a NEW stream after the drop: {log:?}"
    );
    assert_eq!(
        log[1].version_info, "v1",
        "the acked version must persist across the reconnect"
    );
    assert_eq!(
        log[1].response_nonce, "",
        "the nonce belongs to the dropped stream and must NOT be echoed on the new one"
    );
    assert_eq!(
        log[1].kind(),
        RequestKind::Initial,
        "a resync request carries no nonce, so it reads as Initial"
    );

    assert_eq!(log[2].stream_id, 2);
    assert_eq!(log[2].kind(), RequestKind::Ack);
    assert_eq!(log[2].version_info, "v2");
    assert_eq!(log[2].response_nonce, "n2");

    run.abort();
    harness.shutdown().await;
}

/// The first reconnect must wait, and it must wait the policy's floor rather
/// than nothing. A zero first delay is what turns a control plane restart
/// into a reconnect storm (PLAN.md Part 8.5: "never NACK-storm").
#[tokio::test(flavor = "multi_thread")]
async fn the_first_reconnect_waits_the_base_interval() {
    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CDS.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![],
        },
        Step::DropStream,
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
    let (reconnect, delays) = recording_reconnect(BackoffPolicy::default());
    let run = tokio::spawn(async move {
        ads.run(&mut client, FnHandler(always_accept()), reconnect)
            .await
    });

    let seen = wait_for_delays(&delays, 1).await;
    assert_eq!(
        seen[0],
        Duration::from_millis(500),
        "with a max jitter draw the first reconnect must wait the full base interval"
    );

    run.abort();
    harness.shutdown().await;
}

/// Consecutive streams that never deliver a response must back off further
/// each time -- and a stream that DOES deliver one resets the curve to its
/// floor. Envoy resets its xDS backoff on message receipt for exactly this
/// reason: a control plane that accepts and instantly drops would otherwise
/// be hammered at the floor forever.
///
/// Script: three bare drops (no response at all), then a response, then a
/// drop. With a constant max draw the delays must read
/// `[500ms, 1s, 2s, 500ms]` -- the doubling, then the reset.
#[tokio::test(flavor = "multi_thread")]
async fn backoff_grows_across_dead_streams_and_resets_after_a_response() {
    let harness = Harness::spawn(vec![
        Step::DropStream,
        Step::DropStream,
        Step::DropStream,
        Step::Send {
            type_url: CDS.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![],
        },
        Step::DropStream,
    ])
    .await
    .expect("harness spawns");

    let mut client = AggregatedDiscoveryServiceClient::connect(format!("http://{}", harness.addr))
        .await
        .expect("client connects");

    let mut ads = AdsClient::new(vec![SubscriptionState::new(CDS, Subscription::Wildcard)]);
    let (reconnect, delays) = recording_reconnect(BackoffPolicy::default());
    let run = tokio::spawn(async move {
        ads.run(&mut client, FnHandler(always_accept()), reconnect)
            .await
    });

    let seen = wait_for_delays(&delays, 4).await;
    assert_eq!(
        &seen[..4],
        &[
            Duration::from_millis(500),
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_millis(500),
        ],
        "expected the curve to double across dead streams then reset after the v1 response"
    );

    run.abort();
    harness.shutdown().await;
}

/// `run` must call [`SubscriptionState::reset_stream`] before each new
/// stream, and this test observes the state directly rather than the wire.
///
/// It has to, and the reason is worth recording: `initial_request()` hardcodes
/// `response_nonce: None`, so a `run` that forgot the reset would still put a
/// correct (nonce-free) resync request on the wire. The reset is therefore
/// **state hygiene, not the wire guarantee** -- `last_nonce()` is public, and
/// increment 4 reads it. A mutation removing the reset survives every
/// wire-level assertion in this file and fails only here.
///
/// Rust note: `tokio::time::timeout` around `run` (whose return type is `!`)
/// is what makes the client inspectable -- the timeout drops the future, which
/// ends the `&mut ads` borrow, and the states are readable afterwards. That is
/// why this test does not `tokio::spawn` the way its neighbours do.
#[tokio::test(flavor = "multi_thread")]
async fn run_clears_the_nonce_but_keeps_the_version_across_a_reconnect() {
    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CDS.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![],
        },
        // Give the client time to read v1 and record its nonce before the
        // stream goes away, so the assertion below is about the reset and
        // not about a response the client never saw.
        Step::Wait {
            duration: Duration::from_millis(150),
        },
        Step::DropStream,
        // Stream 2 sends nothing: whatever `last_nonce` reads afterwards was
        // put there by stream 1, or cleared by the reset.
        Step::Wait {
            duration: Duration::from_secs(30),
        },
    ])
    .await
    .expect("harness spawns");

    let mut client = AggregatedDiscoveryServiceClient::connect(format!("http://{}", harness.addr))
        .await
        .expect("client connects");

    let mut ads = AdsClient::new(vec![SubscriptionState::new(CDS, Subscription::Wildcard)]);
    let (reconnect, delays) = recording_reconnect(BackoffPolicy::default());

    let _ = tokio::time::timeout(
        Duration::from_millis(800),
        ads.run(&mut client, FnHandler(always_accept()), reconnect),
    )
    .await;

    assert!(
        !delays.lock().expect("delay sink mutex poisoned").is_empty(),
        "the stream must have been dropped and reconnected at least once"
    );

    let state = &ads.states()[0];
    assert_eq!(
        state.acked_version(),
        Some("v1"),
        "the acked version belongs to the server and survives the reconnect"
    );
    assert_eq!(
        state.last_nonce(),
        None,
        "the nonce belongs to the dropped stream and must be cleared by reset_stream"
    );

    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// WP-20 increment 4c: the Node identity on the wire.
// ---------------------------------------------------------------------------

fn test_node() -> NodeIdentity {
    NodeIdentity {
        id: "proxy-1".to_string(),
        cluster: "edge".to_string(),
    }
}

/// The xDS protocol, and Envoy's own `GrpcMuxImpl`: a client sends its node
/// identity on the FIRST request of a stream and omits it from every request
/// after. Increment 3a built the request and never set the field at all --
/// `to_proto` filled five fields and then `..Default::default()` -- so every
/// request went out anonymous, which a control plane keying on `node.id`
/// (go-control-plane's snapshot cache does) has no way to serve.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_request_of_a_stream_carries_the_node_and_later_ones_do_not() {
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

    let mut ads = AdsClient::new(vec![SubscriptionState::new(CDS, Subscription::Wildcard)])
        .with_node(test_node());
    let run = tokio::spawn(async move {
        ads.run_once(&mut client, &mut FnHandler(always_accept()))
            .await
    });

    wait_for_log_len(&harness.log, 2).await;
    let log = harness.log.snapshot();

    assert_eq!(
        log[0]
            .node
            .as_ref()
            .map(|(id, c)| (id.as_str(), c.as_str())),
        Some(("proxy-1", "edge")),
        "the first request of a stream must carry the node identity"
    );
    assert_eq!(
        log[1].node, None,
        "requests after the first on the same stream must omit the node"
    );

    run.abort();
    harness.shutdown().await;
}

/// A reconnect opens a new stream, so the node must be sent again -- that is
/// the whole point of the rule being per stream rather than per client. A
/// control plane that lost its state on the restart that dropped us has no
/// other way to learn who we are.
#[tokio::test(flavor = "multi_thread")]
async fn a_reconnect_sends_the_node_again_on_the_new_stream() {
    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CDS.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![],
        },
        Step::DropStream,
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

    let mut ads = AdsClient::new(vec![SubscriptionState::new(CDS, Subscription::Wildcard)])
        .with_node(test_node());
    let (reconnect, _delays) = recording_reconnect(BackoffPolicy::default());
    let run = tokio::spawn(async move {
        ads.run(&mut client, FnHandler(always_accept()), reconnect)
            .await
    });

    // [0] stream 1 initial, [1] stream 2 resync, [2] stream 2 ACK of v2 -- the
    // stream-1 ACK is not recorded, see the resync test above for why.
    wait_for_log_len(&harness.log, 3).await;
    let log = harness.log.snapshot();

    assert_eq!(log[0].stream_id, 1);
    assert!(log[0].node.is_some(), "stream 1's first request carries it");

    assert_eq!(log[1].stream_id, 2);
    assert_eq!(
        log[1]
            .node
            .as_ref()
            .map(|(id, c)| (id.as_str(), c.as_str())),
        Some(("proxy-1", "edge")),
        "the new stream's first request must carry the node again"
    );
    assert_eq!(
        log[2].node, None,
        "and only its first request, not the ACK after it"
    );

    run.abort();
    harness.shutdown().await;
}

/// A client with no node configured sends none -- legal on the wire, and the
/// behavior every test written before increment 4c depended on.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_with_no_node_configured_sends_none() {
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
    let run = tokio::spawn(async move {
        ads.run_once(&mut client, &mut FnHandler(always_accept()))
            .await
    });

    wait_for_log_len(&harness.log, 2).await;
    let log = harness.log.snapshot();
    assert!(
        log.iter().all(|r| r.node.is_none()),
        "no node configured means no node on any request: {log:?}"
    );

    run.abort();
    harness.shutdown().await;
}

// ---------------------------------------------------------------------------
// WP-20 increment 4d-i: the handler seam is async -- applying a response can
// await before its ACK goes out.
// ---------------------------------------------------------------------------

/// A [`ResponseHandler`] whose future does not resolve until a `oneshot`
/// fires, so a test can hold `run_once` right at the point where it has a
/// verdict but has not yet sent the request that carries it.
///
/// Rust note: `gate` is an `Option` so `handle` can `.take()` its receiver out
/// from behind `&mut self` -- a `oneshot::Receiver` is consumed by awaiting
/// it, so it cannot be stored back, and this handler is only ever asked to
/// handle one response in this test.
struct DelayedHandler {
    gate: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl ResponseHandler for DelayedHandler {
    fn handle(
        &mut self,
        _resp: &DiscoveryResponse,
    ) -> impl std::future::Future<Output = Verdict> + Send {
        let gate = self
            .gate
            .take()
            .expect("DelayedHandler is only asked to handle one response in this test");
        async move {
            let _ = gate.await;
            Verdict::Accept
        }
    }
}

/// The acceptance claim for this increment: with a handler whose future is
/// still pending, the ACK for the response it is handling must not have
/// reached the control plane yet. Once the gate is released, the ACK follows.
///
/// Both waits are bounded (rule 14): the first is expected to time out, and
/// asserting that via `Result::expect_err` on a short `tokio::time::timeout`
/// is what turns "the ACK went out early" into a named failure rather than a
/// pass that just got lucky on timing, and what keeps this test itself from
/// hanging if `run_once` never sends the ACK at all.
#[tokio::test(flavor = "multi_thread")]
async fn the_ack_does_not_reach_the_wire_until_the_handler_future_resolves() {
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

    let (release, gate) = tokio::sync::oneshot::channel();
    let mut handler = DelayedHandler { gate: Some(gate) };

    let mut ads = AdsClient::new(vec![SubscriptionState::new(CDS, Subscription::Wildcard)]);
    let run = tokio::spawn(async move { ads.run_once(&mut client, &mut handler).await });

    // Only the initial request can have gone out yet -- the handler is
    // awaiting the gate, so `run_once` must not have reached the ACK send.
    tokio::time::timeout(
        Duration::from_millis(300),
        wait_for_log_len(&harness.log, 2),
    )
    .await
    .expect_err("the ACK must not reach the wire while the handler's future is still pending");

    release.send(()).expect("DelayedHandler is still awaiting");

    // Releasing the gate lets the handler's future resolve, and the ACK
    // follows it onto the wire.
    tokio::time::timeout(WAIT_TIMEOUT, wait_for_log_len(&harness.log, 2))
        .await
        .expect("the ACK must reach the wire once the handler future resolves");

    let log = harness.log.snapshot();
    assert_eq!(
        log[1].kind(),
        RequestKind::Ack,
        "expected an ACK once the handler resolved, got {:?}",
        log[1]
    );

    run.abort();
    harness.shutdown().await;
}
