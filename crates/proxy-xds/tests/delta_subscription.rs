use std::collections::{BTreeMap, BTreeSet};

use proxy_xds::{DeltaSubscriptionState, ResourceVersion, Subscription, Verdict};

const CDS: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";

fn names(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn version(name: &str, version: &str) -> ResourceVersion {
    ResourceVersion {
        name: name.to_string(),
        version: version.to_string(),
    }
}

#[test]
fn accept_updates_each_resource_version_and_applies_removals() {
    let mut state = DeltaSubscriptionState::new(CDS, Subscription::Wildcard);
    let ack = state.on_response(
        [version("a", "1"), version("b", "2")],
        [],
        "n1",
        Verdict::Accept,
    );
    assert_eq!(ack.response_nonce.as_deref(), Some("n1"));
    assert!(!ack.is_nack());
    state.on_response(
        [version("a", "3")],
        ["b".to_string()],
        "n2",
        Verdict::Accept,
    );
    assert_eq!(
        state.resource_versions(),
        &BTreeMap::from([("a".to_string(), "3".to_string())])
    );
}

#[test]
fn nack_changes_only_nonce_and_keeps_all_resource_versions() {
    let mut state = DeltaSubscriptionState::new(CDS, Subscription::Wildcard);
    state.on_response([version("a", "1")], [], "n1", Verdict::Accept);
    let nack = state.on_response(
        [version("a", "2"), version("b", "1")],
        ["a".to_string()],
        "n2",
        Verdict::Reject("clusters[1]: invalid".to_string()),
    );
    assert!(nack.is_nack());
    assert_eq!(nack.response_nonce.as_deref(), Some("n2"));
    assert_eq!(nack.error_detail.as_deref(), Some("clusters[1]: invalid"));
    assert_eq!(
        state.resource_versions(),
        &BTreeMap::from([("a".to_string(), "1".to_string())])
    );
}

#[test]
fn reconnect_keeps_versions_but_clears_nonce() {
    let mut state = DeltaSubscriptionState::new(CDS, Subscription::Wildcard);
    state.on_response([version("a", "7")], [], "n7", Verdict::Accept);
    state.reset_stream();
    let initial = state.initial_request();
    assert_eq!(initial.response_nonce, None);
    assert_eq!(
        initial.initial_resource_versions,
        BTreeMap::from([("a".to_string(), "7".to_string())])
    );
}

#[test]
fn named_subscription_emits_sorted_differences_and_drops_unsubscribed_versions() {
    let mut state = DeltaSubscriptionState::new(CDS, Subscription::Names(names(&["a", "b"])));
    state.on_response(
        [version("a", "1"), version("b", "2")],
        [],
        "n1",
        Verdict::Accept,
    );
    let update = state.set_names(names(&["b", "c"])).unwrap();
    assert_eq!(update.resource_names_subscribe, vec!["c"]);
    assert_eq!(update.resource_names_unsubscribe, vec!["a"]);
    assert_eq!(update.response_nonce, None);

    state.reset_stream();
    let initial = state.initial_request();
    assert_eq!(initial.resource_names_subscribe, vec!["b", "c"]);
    assert_eq!(
        initial.initial_resource_versions,
        BTreeMap::from([("b".to_string(), "2".to_string())])
    );
}

#[test]
fn unchanged_named_subscription_emits_no_request() {
    let mut state = DeltaSubscriptionState::new(CDS, Subscription::Names(names(&["a"])));
    assert!(state.set_names(names(&["a"])).is_none());
}

#[test]
fn empty_named_subscription_is_skipped_instead_of_becoming_wildcard() {
    let state = DeltaSubscriptionState::new(CDS, Subscription::Names(BTreeSet::new()));
    assert!(state.has_nothing_to_request());
    assert!(!DeltaSubscriptionState::new(CDS, Subscription::Wildcard).has_nothing_to_request());
}
