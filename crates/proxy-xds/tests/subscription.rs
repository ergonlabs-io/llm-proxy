//! Acceptance: the S8 subscription state machine.
//!
//! Every test here pins one sentence of `internal-docs/envoy-semantics.md` S8.
//! That is the point of splitting this out of the transport — these are the rules a
//! control plane will hold us to, and none of them needs a socket to check.

use std::collections::BTreeSet;

use proxy_xds::{Subscription, SubscriptionState, Verdict};

const CDS: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
const RDS: &str = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";

fn names(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn cds() -> SubscriptionState {
    SubscriptionState::new(CDS, Subscription::Wildcard)
}

// --------------------------------------------------------- the first request

/// S8: the first request of a stream carries no nonce. With nothing ever
/// accepted it also carries no version — the control plane reads that as
/// "send me everything".
#[test]
fn the_first_request_ever_has_no_version_and_no_nonce() {
    let req = cds().initial_request();
    assert_eq!(req.version_info, None);
    assert_eq!(req.response_nonce, None);
    assert!(
        req.resource_names.is_empty(),
        "wildcard renders as no names"
    );
    assert!(!req.is_nack());
}

// ------------------------------------------------------------------ the ACK

/// S8: "validate all resources -> all-or-nothing accept -> apply ->
/// ACK(version, nonce)".
#[test]
fn an_accept_acks_the_new_version_and_echoes_the_nonce() {
    let mut state = cds();
    let ack = state.on_response("v1", "n1", Verdict::Accept);

    assert_eq!(ack.version_info.as_deref(), Some("v1"));
    assert_eq!(ack.response_nonce.as_deref(), Some("n1"));
    assert!(!ack.is_nack());
    assert_eq!(state.acked_version(), Some("v1"));
}

// ----------------------------------------------------------------- the NACK

/// **The load-bearing rule of this module.** S8: "any failure -> NACK(prev
/// version, nonce, error_detail)". Echoing the REJECTED version would tell the
/// control plane we accepted a config we just discarded.
#[test]
fn a_nack_carries_the_previous_acked_version_not_the_rejected_one() {
    let mut state = cds();
    state.on_response("v1", "n1", Verdict::Accept);

    let nack = state.on_response("v2", "n2", Verdict::Reject("bad cluster".into()));

    assert_eq!(
        nack.version_info.as_deref(),
        Some("v1"),
        "a NACK must echo the last ACCEPTED version, never the rejected one"
    );
    assert_eq!(nack.response_nonce.as_deref(), Some("n2"));
    assert!(nack.is_nack());
}

/// The same rule with nothing ever accepted: the NACK carries no version at
/// all rather than the rejected one.
#[test]
fn a_nack_before_any_accept_carries_no_version() {
    let mut state = cds();
    let nack = state.on_response("v1", "n1", Verdict::Reject("bad".into()));
    assert_eq!(nack.version_info, None);
    assert!(nack.is_nack());
}

/// S8: "discard entire response". A rejected response changes no state beyond
/// the nonce — there is no partial application.
#[test]
fn a_nacked_response_does_not_change_the_acked_version() {
    let mut state = cds();
    state.on_response("v1", "n1", Verdict::Accept);
    state.on_response("v2", "n2", Verdict::Reject("bad".into()));

    assert_eq!(
        state.acked_version(),
        Some("v1"),
        "a discarded response must leave the accepted version untouched"
    );
}

/// The error text reaches the wire: S8 wants our dotted-path config errors
/// in `error_detail`, not a generic failure.
#[test]
fn a_nack_carries_the_validation_message_verbatim() {
    let mut state = cds();
    let detail = "static_resources.clusters[0].load_assignment: missing endpoint";
    let nack = state.on_response("v1", "n1", Verdict::Reject(detail.into()));
    assert_eq!(nack.error_detail.as_deref(), Some(detail));
}

// ----------------------------------------------------------- nonce handling

/// S8: "Requests must echo latest nonce". The nonce advances on a rejection
/// too — freezing it would make every later request look stale to the server.
#[test]
fn the_nonce_advances_on_a_nack_as_well_as_an_ack() {
    let mut state = cds();
    state.on_response("v1", "n1", Verdict::Accept);
    state.on_response("v2", "n2", Verdict::Reject("bad".into()));
    assert_eq!(state.last_nonce(), Some("n2"));

    // And a subsequent accept echoes the newest nonce, not a stale one.
    let ack = state.on_response("v3", "n3", Verdict::Accept);
    assert_eq!(ack.response_nonce.as_deref(), Some("n3"));
    assert_eq!(ack.version_info.as_deref(), Some("v3"));
}

/// Recovery after a rejection: the next good response is accepted normally,
/// and the version moves on from the one that was held through the NACK.
#[test]
fn the_client_recovers_from_a_nack_on_the_next_good_response() {
    let mut state = cds();
    state.on_response("v1", "n1", Verdict::Accept);
    state.on_response("v2", "n2", Verdict::Reject("bad".into()));
    assert_eq!(state.acked_version(), Some("v1"));

    let ack = state.on_response("v3", "n3", Verdict::Accept);
    assert!(!ack.is_nack());
    assert_eq!(state.acked_version(), Some("v3"));
}

// -------------------------------------------------------------- reconnect --

/// S8: "re-send all subscriptions with acked versions ... versions persist
/// across streams for same server". The nonce does not: it belongs to the
/// stream that issued it.
#[test]
fn a_reconnect_keeps_the_acked_version_and_drops_the_nonce() {
    let mut state = cds();
    state.on_response("v7", "n7", Verdict::Accept);

    state.reset_stream();

    assert_eq!(state.acked_version(), Some("v7"), "versions persist");
    assert_eq!(state.last_nonce(), None, "a nonce belongs to one stream");

    let resumed = state.initial_request();
    assert_eq!(resumed.version_info.as_deref(), Some("v7"));
    assert_eq!(resumed.response_nonce, None);
}

/// A reconnect that happens while the last response was REJECTED must resume
/// from the last accepted version, not the rejected one — the two rules
/// compose, and getting either wrong shows up only here.
#[test]
fn a_reconnect_after_a_nack_resumes_from_the_last_accepted_version() {
    let mut state = cds();
    state.on_response("v1", "n1", Verdict::Accept);
    state.on_response("v2", "n2", Verdict::Reject("bad".into()));

    state.reset_stream();

    let resumed = state.initial_request();
    assert_eq!(resumed.version_info.as_deref(), Some("v1"));
    assert_eq!(resumed.response_nonce, None);
    assert!(!resumed.is_nack(), "a resumed subscription is not a NACK");
}

// ---------------------------------------------------- subscription sets ----

/// RDS/EDS name sets are derived from accepted LDS/CDS resources, and render
/// in sorted order so a packet capture reads the same way twice.
#[test]
fn a_name_subscription_renders_its_names_sorted() {
    let state = SubscriptionState::new(RDS, Subscription::Names(names(&["b", "a", "c"])));
    assert_eq!(state.initial_request().resource_names, vec!["a", "b", "c"]);
}

/// The trap this guards: an EMPTY name list is indistinguishable from a
/// wildcard on the wire, so sending one asks for every resource of the type
/// rather than none.
#[test]
fn an_empty_name_subscription_is_flagged_as_having_nothing_to_request() {
    let empty = SubscriptionState::new(RDS, Subscription::Names(BTreeSet::new()));
    assert!(
        empty.has_nothing_to_request(),
        "an empty name set must be reported, since on the wire it reads as a wildcard"
    );

    let wildcard = cds();
    assert!(
        !wildcard.has_nothing_to_request(),
        "a wildcard genuinely wants everything and must not be skipped"
    );
}

/// Updating derived names reports whether anything changed, so a caller can
/// avoid re-requesting an unchanged set.
#[test]
fn set_names_reports_whether_the_set_changed() {
    let mut state = SubscriptionState::new(RDS, Subscription::Names(names(&["a"])));
    assert!(
        state.set_names(names(&["a", "b"])),
        "adding a name changed it"
    );
    assert!(
        !state.set_names(names(&["a", "b"])),
        "the same set is no change"
    );
    assert_eq!(state.initial_request().resource_names, vec!["a", "b"]);
}

/// A wildcard has no derived name set; reaching here is a caller bug.
#[test]
#[should_panic(expected = "wildcard subscription")]
fn set_names_on_a_wildcard_panics_rather_than_silently_narrowing() {
    cds().set_names(names(&["a"]));
}

// ------------------------------------------------- per-type independence ---

/// S8 keeps state per type. A NACK on one type must not disturb another —
/// the ordering expectation (CDS→EDS→LDS→RDS) means responses interleave.
#[test]
fn types_keep_independent_version_and_nonce_state() {
    let mut clusters = cds();
    let mut routes = SubscriptionState::new(RDS, Subscription::Names(names(&["r1"])));

    clusters.on_response("cv1", "cn1", Verdict::Accept);
    routes.on_response("rv1", "rn1", Verdict::Reject("bad route".into()));

    assert_eq!(clusters.acked_version(), Some("cv1"));
    assert_eq!(clusters.last_nonce(), Some("cn1"));
    assert_eq!(
        routes.acked_version(),
        None,
        "the route NACK accepted nothing"
    );
    assert_eq!(routes.last_nonce(), Some("rn1"));
}
