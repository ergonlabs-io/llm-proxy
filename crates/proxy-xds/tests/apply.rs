//! WP-20 increment 4b-ii acceptance tests: driving [`ResourceApplier`] with
//! hand-built `DiscoveryResponse`s directly -- no socket, no `controlplane`
//! harness. This is the apply layer, not the transport; `client.rs`'s own
//! tests already cover pumping a real stream.
//!
//! Fixture idiom matches `crates/proxy-config/tests/dynamic_lower.rs`, the
//! sibling file that just landed: build the proto types directly and
//! `prost::Message::encode`e them into an `Any`, rather than going through
//! YAML -- there is no bootstrap file on this path, only resources the ADS
//! client already decoded off the wire.

use std::sync::{Arc, Mutex};

use prost::Message;
use proxy_api::envoy::config::cluster::v3 as cluster_v3;
use proxy_api::envoy::config::core::v3 as core_v3;
use proxy_api::envoy::config::endpoint::v3 as endpoint_v3;
use proxy_api::envoy::config::listener::v3 as listener_v3;
use proxy_api::envoy::extensions::filters::network::tcp_proxy::v3 as tcp_proxy_v3;
use proxy_api::envoy::service::discovery::v3::DiscoveryResponse;
use proxy_config::ir::ConfigSnapshot;
use proxy_config::lower_dynamic_cluster;
use proxy_xds::{Publish, ResourceApplier, Verdict};

const TCP_PROXY_TYPE: &str = "envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy";
const CLUSTER_TYPE: &str = "envoy.config.cluster.v3.Cluster";
const LISTENER_TYPE: &str = "envoy.config.listener.v3.Listener";
const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
const LDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";

/// Wrap an encoded proto message as a `google.protobuf.Any`, the same shape
/// an ADS `DiscoveryResponse.resources` entry carries on the wire.
fn any_of<T: Message>(msg: &T, type_name: &str) -> prost_types::Any {
    prost_types::Any {
        type_url: format!("type.googleapis.com/{type_name}"),
        value: msg.encode_to_vec(),
    }
}

/// A minimal, valid `STATIC` cluster with one endpoint at `port` -- just
/// enough for `convert_cluster` to accept it. `port` is a parameter (not
/// fixed, as `dynamic_lower.rs`'s own fixture has it) so two clusters of the
/// same NAME can still carry different bytes, which is what makes a
/// name-collision test distinguishable from a no-op.
fn minimal_cluster(name: &str, port: u32) -> cluster_v3::Cluster {
    cluster_v3::Cluster {
        name: name.to_string(),
        cluster_discovery_type: Some(cluster_v3::cluster::ClusterDiscoveryType::Type(
            cluster_v3::cluster::DiscoveryType::Static as i32,
        )),
        load_assignment: Some(endpoint_v3::ClusterLoadAssignment {
            cluster_name: name.to_string(),
            endpoints: vec![endpoint_v3::LocalityLbEndpoints {
                lb_endpoints: vec![endpoint_v3::LbEndpoint {
                    host_identifier: Some(endpoint_v3::lb_endpoint::HostIdentifier::Endpoint(
                        endpoint_v3::Endpoint {
                            address: Some(core_v3::Address {
                                address: Some(core_v3::address::Address::SocketAddress(
                                    core_v3::SocketAddress {
                                        address: "127.0.0.1".to_string(),
                                        port_specifier: Some(
                                            core_v3::socket_address::PortSpecifier::PortValue(port),
                                        ),
                                        ..Default::default()
                                    },
                                )),
                            }),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A minimal, valid listener: one address, one filter chain running
/// `tcp_proxy` at a named cluster -- just enough for `convert_listener` to
/// accept it.
fn minimal_listener(name: &str, cluster: &str, port: u32) -> listener_v3::Listener {
    listener_v3::Listener {
        name: name.to_string(),
        address: Some(core_v3::Address {
            address: Some(core_v3::address::Address::SocketAddress(
                core_v3::SocketAddress {
                    address: "127.0.0.1".to_string(),
                    port_specifier: Some(core_v3::socket_address::PortSpecifier::PortValue(port)),
                    ..Default::default()
                },
            )),
        }),
        filter_chains: vec![listener_v3::FilterChain {
            filters: vec![listener_v3::Filter {
                name: "envoy.filters.network.tcp_proxy".to_string(),
                config_type: Some(listener_v3::filter::ConfigType::TypedConfig(any_of(
                    &tcp_proxy_v3::TcpProxy {
                        stat_prefix: "tcp".to_string(),
                        cluster_specifier: Some(
                            tcp_proxy_v3::tcp_proxy::ClusterSpecifier::Cluster(cluster.to_string()),
                        ),
                        ..Default::default()
                    },
                    TCP_PROXY_TYPE,
                ))),
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn cds_response(version: &str, clusters: &[cluster_v3::Cluster]) -> DiscoveryResponse {
    DiscoveryResponse {
        version_info: version.to_string(),
        type_url: CDS_TYPE_URL.to_string(),
        nonce: format!("n-{version}"),
        resources: clusters.iter().map(|c| any_of(c, CLUSTER_TYPE)).collect(),
        ..Default::default()
    }
}

fn lds_response(version: &str, listeners: &[listener_v3::Listener]) -> DiscoveryResponse {
    DiscoveryResponse {
        version_info: version.to_string(),
        type_url: LDS_TYPE_URL.to_string(),
        nonce: format!("n-{version}"),
        resources: listeners.iter().map(|l| any_of(l, LISTENER_TYPE)).collect(),
        ..Default::default()
    }
}

/// An empty base snapshot: no static listeners or clusters, so every dynamic
/// name is free to use.
fn empty_base() -> Arc<ConfigSnapshot> {
    Arc::new(ConfigSnapshot::default())
}

/// A base snapshot carrying one static cluster named `name`. Built via
/// `lower_dynamic_cluster` -- the same idiom `dynamic_lower.rs` uses -- since
/// there is no bootstrap file on this path to load a static cluster from.
fn base_with_static_cluster(name: &str, port: u32) -> Arc<ConfigSnapshot> {
    let any = any_of(&minimal_cluster(name, port), CLUSTER_TYPE);
    let ir = lower_dynamic_cluster(&any, "static_resources.clusters[0]")
        .expect("fixture cluster must lower");
    let mut snapshot = ConfigSnapshot::default();
    snapshot.clusters.insert(name.to_string(), Arc::new(ir));
    Arc::new(snapshot)
}

/// A recording [`Publish`]: every call appends the published snapshot to a
/// shared `Vec` so a test can assert both what was published and how many
/// times.
fn recording_publisher() -> (Publish, Arc<Mutex<Vec<Arc<ConfigSnapshot>>>>) {
    let published: Arc<Mutex<Vec<Arc<ConfigSnapshot>>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&published);
    let publish: Publish = Box::new(move |snapshot| recorded.lock().unwrap().push(snapshot));
    (publish, published)
}

// ------------------------------------------------------------- acceptance --

#[test]
fn a_cds_response_with_one_valid_cluster_publishes_a_snapshot_with_the_version_bumped() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = cds_response("v1", &[minimal_cluster("payments-primary", 8080)]);
    let verdict = applier.on_response(&resp);

    assert_eq!(verdict, Verdict::Accept);
    assert_eq!(published.lock().unwrap().len(), 1);
    assert!(applier.current().clusters.contains_key("payments-primary"));
    assert_eq!(applier.current().version.0, 1);
}

#[test]
fn a_lds_response_with_one_valid_listener_publishes_a_snapshot_with_the_version_bumped() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = lds_response("v1", &[minimal_listener("ingress", "some-cluster", 10000)]);
    let verdict = applier.on_response(&resp);

    assert_eq!(verdict, Verdict::Accept);
    assert_eq!(published.lock().unwrap().len(), 1);
    assert!(applier.current().listeners.contains_key("ingress"));
    assert_eq!(applier.current().version.0, 1);
}

#[test]
fn a_second_cds_response_dropping_a_cluster_removes_it_full_state() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    applier.on_response(&cds_response("v1", &[minimal_cluster("a", 8080)]));
    let verdict = applier.on_response(&cds_response("v2", &[]));

    assert_eq!(verdict, Verdict::Accept);
    assert!(!applier.current().clusters.contains_key("a"));
    assert_eq!(published.lock().unwrap().len(), 2);
    assert_eq!(applier.current().version.0, 2);
}

// ------------------------------------------------ all-or-nothing (S8) --

/// THE MOST IMPORTANT ONE. One of two clusters in the response fails to
/// lower (a field outside `allowed_fields`'s allowlist), so the whole
/// response must be discarded: no `SotwSet::apply`, no snapshot, no publish
/// call, `current()` unchanged.
#[test]
fn a_cds_response_where_one_of_two_clusters_fails_to_lower_rejects_and_publishes_nothing() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let mut bad = minimal_cluster("bad", 8080);
    bad.close_connections_on_host_health_failure = true; // outside the allowlist
    let good = minimal_cluster("good", 8081);
    let resp = cds_response("v1", &[good, bad]);

    let verdict = applier.on_response(&resp);
    assert!(
        matches!(verdict, Verdict::Reject(_)),
        "expected Reject, got {verdict:?}"
    );
    assert!(
        published.lock().unwrap().is_empty(),
        "publish must never be called when any resource in the response fails to lower"
    );
    assert!(!applier.current().clusters.contains_key("good"));
    assert!(!applier.current().clusters.contains_key("bad"));
    assert_eq!(applier.current().version.0, 0);
}

/// Same claim as above, for listeners.
#[test]
fn an_lds_response_where_one_of_two_listeners_fails_to_lower_rejects_and_publishes_nothing() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let mut bad = minimal_listener("bad", "some-cluster", 10000);
    bad.stat_prefix = "should-be-refused".to_string(); // outside the allowlist
    let good = minimal_listener("good", "some-cluster", 10001);
    let resp = lds_response("v1", &[good, bad]);

    let verdict = applier.on_response(&resp);
    assert!(
        matches!(verdict, Verdict::Reject(_)),
        "expected Reject, got {verdict:?}"
    );
    assert!(published.lock().unwrap().is_empty());
    assert!(!applier.current().listeners.contains_key("good"));
    assert_eq!(applier.current().version.0, 0);
}

#[test]
fn a_cds_response_naming_the_same_cluster_twice_is_rejected() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = cds_response(
        "v1",
        &[minimal_cluster("dup", 8080), minimal_cluster("dup", 8081)],
    );
    let verdict = applier.on_response(&resp);

    assert!(matches!(verdict, Verdict::Reject(_)));
    assert!(published.lock().unwrap().is_empty());
    assert!(!applier.current().clusters.contains_key("dup"));
}

// ----------------------------------------------------------- no-op resend --

#[test]
fn resending_an_identical_cluster_set_publishes_nothing_and_does_not_bump_the_version() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = cds_response("v1", &[minimal_cluster("a", 8080)]);
    applier.on_response(&resp);
    assert_eq!(published.lock().unwrap().len(), 1);
    assert_eq!(applier.current().version.0, 1);

    let verdict = applier.on_response(&resp);
    assert_eq!(verdict, Verdict::Accept);
    assert_eq!(
        published.lock().unwrap().len(),
        1,
        "no new publish for a no-op response"
    );
    assert_eq!(
        applier.current().version.0,
        1,
        "version must not bump for a no-op response"
    );
}

/// The mirror of the no-op test above, and the one that pins `Entry`'s
/// hand-written `PartialEq`. Same cluster NAME, different bytes (a different
/// endpoint port) must publish a new snapshot carrying the new definition.
///
/// Without this, an `Entry::eq` that always answered `true` -- the exact
/// shape a careless edit to that hand-written impl produces -- would classify
/// every re-delivery as `unchanged`, and a control plane moving a cluster to
/// a new endpoint would be **silently ignored**. That is ground rule 1's
/// failure mode arriving over the wire instead of from a file, and every
/// other test in this file passes while it happens.
#[test]
fn a_cluster_whose_bytes_changed_under_the_same_name_is_republished() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    applier.on_response(&cds_response("v1", &[minimal_cluster("a", 8080)]));
    assert_eq!(published.lock().unwrap().len(), 1);
    assert_eq!(applier.current().version.0, 1);

    let verdict = applier.on_response(&cds_response("v2", &[minimal_cluster("a", 9090)]));
    assert_eq!(verdict, Verdict::Accept);
    assert_eq!(
        published.lock().unwrap().len(),
        2,
        "a changed cluster must publish a new snapshot, not be treated as unchanged"
    );
    assert_eq!(
        applier.current().version.0,
        2,
        "a changed cluster must bump the version"
    );

    // The published snapshot must carry the NEW definition, not the old one
    // left in place. `ClusterConfig` has no `PartialEq`, so compare the one
    // field this fixture varies.
    let cluster = applier
        .current()
        .clusters
        .get("a")
        .expect("cluster `a` present");
    let rendered = format!("{cluster:?}");
    assert!(
        rendered.contains("9090"),
        "published snapshot must carry the updated endpoint, got {rendered}"
    );
}

// ----------------------------------------------------- static name immunity --

#[test]
fn a_dynamic_name_colliding_with_a_static_one_is_refused_and_the_static_definition_survives() {
    let base = base_with_static_cluster("shared", 9000);
    let static_arc = Arc::clone(base.clusters.get("shared").unwrap());
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(Arc::clone(&base), publish);

    // "shared" collides with the static cluster (different bytes: a
    // different port, so an unguarded apply would show it as `updated`);
    // "new-cluster" is a genuinely new dynamic name in the same response, so
    // the response as a whole still changes something and actually publishes.
    let resp = cds_response(
        "v1",
        &[
            minimal_cluster("shared", 9999),
            minimal_cluster("new-cluster", 9001),
        ],
    );
    let verdict = applier.on_response(&resp);
    assert_eq!(verdict, Verdict::Accept);

    let snapshot = applier.current();
    assert!(
        Arc::ptr_eq(snapshot.clusters.get("shared").unwrap(), &static_arc),
        "the static cluster must survive untouched -- not replaced by the colliding dynamic one"
    );
    assert!(snapshot.clusters.contains_key("new-cluster"));
    assert_eq!(published.lock().unwrap().len(), 1);
}

// ------------------------------------------------------------- type routing --

#[test]
fn an_rds_response_is_rejected_naming_the_work_package_that_owns_it() {
    let (publish, _published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = DiscoveryResponse {
        type_url: "type.googleapis.com/envoy.config.route.v3.RouteConfiguration".to_string(),
        ..Default::default()
    };
    let verdict = applier.on_response(&resp);
    let Verdict::Reject(message) = verdict else {
        panic!("expected Reject");
    };
    assert!(
        message.contains("RDS") || message.contains("RouteConfiguration"),
        "message should name what was rejected, got: {message}"
    );
}

#[test]
fn a_completely_unknown_type_url_is_rejected_not_silently_ignored() {
    let (publish, _published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = DiscoveryResponse {
        type_url: "type.googleapis.com/definitely.not.a.real.Type".to_string(),
        ..Default::default()
    };
    let verdict = applier.on_response(&resp);
    let Verdict::Reject(message) = verdict else {
        panic!("expected Reject");
    };
    assert!(message.contains("definitely.not.a.real.Type"));
}

// -------------------------------------------------------- independent sets --

#[test]
fn a_cds_full_state_response_does_not_remove_a_previously_published_listener() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    applier.on_response(&lds_response(
        "v1",
        &[minimal_listener("ingress", "some-cluster", 10000)],
    ));
    assert!(applier.current().listeners.contains_key("ingress"));

    let verdict = applier.on_response(&cds_response("v1", &[minimal_cluster("a", 8080)]));
    assert_eq!(verdict, Verdict::Accept);
    assert!(
        applier.current().listeners.contains_key("ingress"),
        "a CDS full-state response must not remove listeners -- they are a different SotwSet"
    );
    assert!(applier.current().clusters.contains_key("a"));
    assert_eq!(published.lock().unwrap().len(), 2);
}

// ----------------------------------------------------------- into_validator --

#[test]
fn into_validator_produces_a_validator_returning_the_same_verdict_as_on_response() {
    let resp = cds_response("v1", &[minimal_cluster("a", 8080)]);

    let (publish_a, _recorded_a) = recording_publisher();
    let mut applier_direct = ResourceApplier::new(empty_base(), publish_a);
    let direct = applier_direct.on_response(&resp);

    let (publish_b, _recorded_b) = recording_publisher();
    let applier_for_validator = ResourceApplier::new(empty_base(), publish_b);
    let mut validator = applier_for_validator.into_validator();
    let via_validator = validator(&resp);

    assert_eq!(direct, via_validator);
}
