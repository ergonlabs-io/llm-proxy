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
use proxy_config::ir::{ConfigSnapshot, EndpointIR};
use proxy_config::lower_dynamic_cluster;
use proxy_xds::{Publish, PublishEndpoints, ResourceApplier, ResponseHandler, Verdict};

const TCP_PROXY_TYPE: &str = "envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy";
const CLUSTER_TYPE: &str = "envoy.config.cluster.v3.Cluster";
const LISTENER_TYPE: &str = "envoy.config.listener.v3.Listener";
const ENDPOINT_TYPE: &str = "envoy.config.endpoint.v3.ClusterLoadAssignment";
const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
const LDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";
const EDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";

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

/// A minimal `ClusterLoadAssignment` naming `cluster_name`, with one endpoint
/// per `(ip, port)` pair -- just enough for `lower_dynamic_endpoints` to
/// accept it.
fn minimal_assignment(
    cluster_name: &str,
    hosts: &[(&str, u32)],
) -> endpoint_v3::ClusterLoadAssignment {
    endpoint_v3::ClusterLoadAssignment {
        cluster_name: cluster_name.to_string(),
        endpoints: vec![endpoint_v3::LocalityLbEndpoints {
            lb_endpoints: hosts
                .iter()
                .map(|(ip, port)| endpoint_v3::LbEndpoint {
                    host_identifier: Some(endpoint_v3::lb_endpoint::HostIdentifier::Endpoint(
                        endpoint_v3::Endpoint {
                            address: Some(core_v3::Address {
                                address: Some(core_v3::address::Address::SocketAddress(
                                    core_v3::SocketAddress {
                                        address: ip.to_string(),
                                        port_specifier: Some(
                                            core_v3::socket_address::PortSpecifier::PortValue(
                                                *port,
                                            ),
                                        ),
                                        ..Default::default()
                                    },
                                )),
                            }),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn eds_response(
    version: &str,
    assignments: &[endpoint_v3::ClusterLoadAssignment],
) -> DiscoveryResponse {
    DiscoveryResponse {
        version_info: version.to_string(),
        type_url: EDS_TYPE_URL.to_string(),
        nonce: format!("n-{version}"),
        resources: assignments
            .iter()
            .map(|a| any_of(a, ENDPOINT_TYPE))
            .collect(),
        ..Default::default()
    }
}

/// An EDS cluster proto: `type: EDS`, `eds_cluster_config` over ADS. Same
/// idiom as `minimal_cluster`, just the other `DiscoveryType`.
fn eds_cluster(name: &str, service_name: &str) -> cluster_v3::Cluster {
    cluster_v3::Cluster {
        name: name.to_string(),
        cluster_discovery_type: Some(cluster_v3::cluster::ClusterDiscoveryType::Type(
            cluster_v3::cluster::DiscoveryType::Eds as i32,
        )),
        eds_cluster_config: Some(cluster_v3::cluster::EdsClusterConfig {
            eds_config: Some(core_v3::ConfigSource {
                config_source_specifier: Some(core_v3::config_source::ConfigSourceSpecifier::Ads(
                    core_v3::AggregatedConfigSource {},
                )),
                resource_api_version: core_v3::ApiVersion::V3 as i32,
                ..Default::default()
            }),
            service_name: service_name.to_string(),
        }),
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

/// A base snapshot carrying one static EDS cluster named `name`, subscribing
/// to EDS resource `service_name`.
fn base_with_static_eds_cluster(name: &str, service_name: &str) -> Arc<ConfigSnapshot> {
    let any = any_of(&eds_cluster(name, service_name), CLUSTER_TYPE);
    let ir = lower_dynamic_cluster(&any, "static_resources.clusters[0]")
        .expect("fixture EDS cluster must lower");
    let mut snapshot = ConfigSnapshot::default();
    snapshot.clusters.insert(name.to_string(), Arc::new(ir));
    Arc::new(snapshot)
}

/// What [`recording_endpoint_sink`] hands back: every successful sink call,
/// in order, as `(cluster_name, endpoints)`.
type RecordedEndpointCalls = Arc<Mutex<Vec<(String, Vec<EndpointIR>)>>>;

/// A recording [`PublishEndpoints`]: every successful call appends
/// `(cluster_name, endpoints)` to a shared `Vec`. `fail_names` lists cluster
/// names whose FIRST call must return `Err` -- used to drive the
/// sink-failure-then-retry scenario -- and is consumed (removed) on that
/// first failing call, so a second call for the same name succeeds and is
/// recorded normally.
fn recording_endpoint_sink(fail_names: &[&str]) -> (PublishEndpoints, RecordedEndpointCalls) {
    let recorded: RecordedEndpointCalls = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::clone(&recorded);
    let mut still_failing: std::collections::HashSet<String> =
        fail_names.iter().map(|s| s.to_string()).collect();
    let sink: PublishEndpoints = Box::new(move |name, endpoints| {
        if still_failing.remove(&name) {
            return Box::pin(std::future::ready(Err(format!(
                "sink deliberately failed for `{name}`"
            ))));
        }
        calls.lock().unwrap().push((name, endpoints));
        Box::pin(std::future::ready(Ok(())))
    });
    (sink, recorded)
}

/// A recording [`Publish`]: every call appends the published snapshot to a
/// shared `Vec` so a test can assert both what was published and how many
/// times.
fn recording_publisher() -> (Publish, Arc<Mutex<Vec<Arc<ConfigSnapshot>>>>) {
    let published: Arc<Mutex<Vec<Arc<ConfigSnapshot>>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&published);
    // Rust note: `Publish` now returns a boxed future (see its own doc in
    // `apply.rs`), so even a publisher with nothing to await must wrap its
    // work in one -- `std::future::ready` is the synchronous case's whole
    // body, same idiom as `client::FnHandler` uses for `Validator`.
    let publish: Publish = Box::new(move |snapshot| {
        recorded.lock().unwrap().push(snapshot);
        Box::pin(std::future::ready(()))
    });
    (publish, published)
}

// ------------------------------------------------------------- acceptance --

#[tokio::test]
async fn a_cds_response_with_one_valid_cluster_publishes_a_snapshot_with_the_version_bumped() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = cds_response("v1", &[minimal_cluster("payments-primary", 8080)]);
    let verdict = applier.on_response(&resp).await;

    assert_eq!(verdict, Verdict::Accept);
    assert_eq!(published.lock().unwrap().len(), 1);
    assert!(applier.current().clusters.contains_key("payments-primary"));
    assert_eq!(applier.current().version.0, 1);
}

#[tokio::test]
async fn a_lds_response_with_one_valid_listener_publishes_a_snapshot_with_the_version_bumped() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = lds_response("v1", &[minimal_listener("ingress", "some-cluster", 10000)]);
    let verdict = applier.on_response(&resp).await;

    assert_eq!(verdict, Verdict::Accept);
    assert_eq!(published.lock().unwrap().len(), 1);
    assert!(applier.current().listeners.contains_key("ingress"));
    assert_eq!(applier.current().version.0, 1);
}

#[tokio::test]
async fn a_second_cds_response_dropping_a_cluster_removes_it_full_state() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    applier
        .on_response(&cds_response("v1", &[minimal_cluster("a", 8080)]))
        .await;
    let verdict = applier.on_response(&cds_response("v2", &[])).await;

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
#[tokio::test]
async fn a_cds_response_where_one_of_two_clusters_fails_to_lower_rejects_and_publishes_nothing() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let mut bad = minimal_cluster("bad", 8080);
    bad.close_connections_on_host_health_failure = true; // outside the allowlist
    let good = minimal_cluster("good", 8081);
    let resp = cds_response("v1", &[good, bad]);

    let verdict = applier.on_response(&resp).await;
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
#[tokio::test]
async fn an_lds_response_where_one_of_two_listeners_fails_to_lower_rejects_and_publishes_nothing() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let mut bad = minimal_listener("bad", "some-cluster", 10000);
    bad.stat_prefix = "should-be-refused".to_string(); // outside the allowlist
    let good = minimal_listener("good", "some-cluster", 10001);
    let resp = lds_response("v1", &[good, bad]);

    let verdict = applier.on_response(&resp).await;
    assert!(
        matches!(verdict, Verdict::Reject(_)),
        "expected Reject, got {verdict:?}"
    );
    assert!(published.lock().unwrap().is_empty());
    assert!(!applier.current().listeners.contains_key("good"));
    assert_eq!(applier.current().version.0, 0);
}

#[tokio::test]
async fn a_cds_response_naming_the_same_cluster_twice_is_rejected() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = cds_response(
        "v1",
        &[minimal_cluster("dup", 8080), minimal_cluster("dup", 8081)],
    );
    let verdict = applier.on_response(&resp).await;

    assert!(matches!(verdict, Verdict::Reject(_)));
    assert!(published.lock().unwrap().is_empty());
    assert!(!applier.current().clusters.contains_key("dup"));
}

// ----------------------------------------------------------- no-op resend --

#[tokio::test]
async fn resending_an_identical_cluster_set_publishes_nothing_and_does_not_bump_the_version() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = cds_response("v1", &[minimal_cluster("a", 8080)]);
    applier.on_response(&resp).await;
    assert_eq!(published.lock().unwrap().len(), 1);
    assert_eq!(applier.current().version.0, 1);

    let verdict = applier.on_response(&resp).await;
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
#[tokio::test]
async fn a_cluster_whose_bytes_changed_under_the_same_name_is_republished() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    applier
        .on_response(&cds_response("v1", &[minimal_cluster("a", 8080)]))
        .await;
    assert_eq!(published.lock().unwrap().len(), 1);
    assert_eq!(applier.current().version.0, 1);

    let verdict = applier
        .on_response(&cds_response("v2", &[minimal_cluster("a", 9090)]))
        .await;
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

#[tokio::test]
async fn a_dynamic_name_colliding_with_a_static_one_is_refused_and_the_static_definition_survives()
{
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
    let verdict = applier.on_response(&resp).await;
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

#[tokio::test]
async fn an_rds_response_is_rejected_naming_the_work_package_that_owns_it() {
    let (publish, _published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = DiscoveryResponse {
        type_url: "type.googleapis.com/envoy.config.route.v3.RouteConfiguration".to_string(),
        ..Default::default()
    };
    let verdict = applier.on_response(&resp).await;
    let Verdict::Reject(message) = verdict else {
        panic!("expected Reject");
    };
    assert!(
        message.contains("RDS") || message.contains("RouteConfiguration"),
        "message should name what was rejected, got: {message}"
    );
}

#[tokio::test]
async fn a_completely_unknown_type_url_is_rejected_not_silently_ignored() {
    let (publish, _published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = DiscoveryResponse {
        type_url: "type.googleapis.com/definitely.not.a.real.Type".to_string(),
        ..Default::default()
    };
    let verdict = applier.on_response(&resp).await;
    let Verdict::Reject(message) = verdict else {
        panic!("expected Reject");
    };
    assert!(message.contains("definitely.not.a.real.Type"));
}

// -------------------------------------------------------- independent sets --

#[tokio::test]
async fn a_cds_full_state_response_does_not_remove_a_previously_published_listener() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    applier
        .on_response(&lds_response(
            "v1",
            &[minimal_listener("ingress", "some-cluster", 10000)],
        ))
        .await;
    assert!(applier.current().listeners.contains_key("ingress"));

    let verdict = applier
        .on_response(&cds_response("v1", &[minimal_cluster("a", 8080)]))
        .await;
    assert_eq!(verdict, Verdict::Accept);
    assert!(
        applier.current().listeners.contains_key("ingress"),
        "a CDS full-state response must not remove listeners -- they are a different SotwSet"
    );
    assert!(applier.current().clusters.contains_key("a"));
    assert_eq!(published.lock().unwrap().len(), 2);
}

// ------------------------------------------------------------ ResponseHandler --

/// WP-20 increment 4d-i: `ResourceApplier` no longer needs an `into_validator`
/// adapter to reach the ADS client -- it IS a [`ResponseHandler`] directly.
/// This is the replacement for the old `into_validator` test: the same claim
/// ("the seam gives back exactly what `on_response` would"), now through
/// `ResponseHandler::handle` instead of a consumed `Validator` closure.
#[tokio::test]
async fn resource_applier_is_a_response_handler_returning_the_same_verdict_as_on_response() {
    let resp = cds_response("v1", &[minimal_cluster("a", 8080)]);

    let (publish_a, _recorded_a) = recording_publisher();
    let mut applier_direct = ResourceApplier::new(empty_base(), publish_a);
    let direct = applier_direct.on_response(&resp).await;

    let (publish_b, _recorded_b) = recording_publisher();
    let mut applier_via_handler = ResourceApplier::new(empty_base(), publish_b);
    let via_handler = applier_via_handler.handle(&resp).await;

    assert_eq!(direct, via_handler);
}

// ---------------------------------------------------------------- EDS (2b-ii) --

/// A valid EDS response reaches the sink with the right
/// `(cluster_name, endpoints)`.
#[tokio::test]
async fn a_valid_eds_response_reaches_the_sink_with_the_right_name_and_endpoints() {
    let (publish, _published) = recording_publisher();
    let (sink, recorded) = recording_endpoint_sink(&[]);
    let mut applier = ResourceApplier::new(empty_base(), publish).with_endpoint_sink(sink);

    let resp = eds_response(
        "v1",
        &[minimal_assignment("my-cluster", &[("10.0.0.1", 9090)])],
    );
    let verdict = applier.on_response(&resp).await;

    assert_eq!(verdict, Verdict::Accept);
    let calls = recorded.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "my-cluster");
    assert_eq!(calls[0].1.len(), 1);
    assert_eq!(calls[0].1[0].host, "10.0.0.1");
    assert_eq!(calls[0].1[0].port, 9090);
}

/// A second, identical EDS response must not reach the sink again -- the
/// same `unchanged` suppression `Entry`'s `PartialEq` gives CDS/LDS.
#[tokio::test]
async fn a_second_identical_eds_response_does_not_reach_the_sink_again() {
    let (publish, _published) = recording_publisher();
    let (sink, recorded) = recording_endpoint_sink(&[]);
    let mut applier = ResourceApplier::new(empty_base(), publish).with_endpoint_sink(sink);

    let resp = eds_response(
        "v1",
        &[minimal_assignment("my-cluster", &[("10.0.0.1", 9090)])],
    );
    applier.on_response(&resp).await;
    assert_eq!(recorded.lock().unwrap().len(), 1);

    let verdict = applier.on_response(&resp).await;
    assert_eq!(verdict, Verdict::Accept);
    assert_eq!(
        recorded.lock().unwrap().len(),
        1,
        "an unchanged EDS resource must not reach the sink a second time"
    );
}

/// An EDS response with a resource that fails to lower is rejected without
/// any sink call -- the all-or-nothing rule, same as CDS/LDS.
#[tokio::test]
async fn an_eds_response_with_a_resource_that_fails_to_lower_is_rejected_without_a_sink_call() {
    let (publish, _published) = recording_publisher();
    let (sink, recorded) = recording_endpoint_sink(&[]);
    let mut applier = ResourceApplier::new(empty_base(), publish).with_endpoint_sink(sink);

    let good = minimal_assignment("good", &[("10.0.0.1", 9090)]);
    let mut bad = minimal_assignment("bad", &[("10.0.0.2", 9091)]);
    // Outside `lower_dynamic_endpoints`'s allowlist for `LbEndpoint`.
    bad.endpoints[0].lb_endpoints[0].health_status = 1;
    let resp = eds_response("v1", &[good, bad]);

    let verdict = applier.on_response(&resp).await;
    assert!(
        matches!(verdict, Verdict::Reject(_)),
        "expected Reject, got {verdict:?}"
    );
    assert!(
        recorded.lock().unwrap().is_empty(),
        "the sink must never be called when any resource in the response fails to lower"
    );
}

/// The store-consistency fix from `apply.rs`'s own doc on `on_eds_response`:
/// a sink that fails once and then succeeds, given the same resource bytes
/// twice, must reach the sink the SECOND time too. Without the fix
/// (`SotwSet::forget` on a failed name), `apply` already recorded the first
/// attempt, the second identical response would compare `unchanged`, and the
/// sink would never be called again -- a resource stuck permanently
/// uninstalled while the store reports it fine. This is the deliverable this
/// increment's brief names explicitly.
#[tokio::test]
async fn a_sink_that_fails_once_is_retried_on_the_next_identical_response() {
    let (publish, _published) = recording_publisher();
    let (sink, recorded) = recording_endpoint_sink(&["my-cluster"]);
    let mut applier = ResourceApplier::new(empty_base(), publish).with_endpoint_sink(sink);

    let resp = eds_response(
        "v1",
        &[minimal_assignment("my-cluster", &[("10.0.0.1", 9090)])],
    );

    let first = applier.on_response(&resp).await;
    assert!(
        matches!(first, Verdict::Reject(_)),
        "expected the first attempt to reject (sink fails), got {first:?}"
    );
    assert!(recorded.lock().unwrap().is_empty());

    // Same bytes again. If the store were left believing the first attempt
    // applied, this would come back `unchanged` and the sink would never be
    // asked again.
    let second = applier.on_response(&resp).await;
    assert_eq!(
        second,
        Verdict::Accept,
        "the retry must reach the sink, which now succeeds"
    );
    let calls = recorded.lock().unwrap();
    assert_eq!(calls.len(), 1, "the sink must be called on the retry");
    assert_eq!(calls[0].0, "my-cluster");
}

/// An EDS response arriving before `with_endpoint_sink` is ever called is
/// refused by name, not silently ignored, and names that this applier has no
/// sink wired rather than blaming an unimplemented increment.
#[tokio::test]
async fn an_eds_response_with_no_sink_wired_is_rejected_naming_the_reason() {
    let (publish, _published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = eds_response(
        "v1",
        &[minimal_assignment("my-cluster", &[("10.0.0.1", 9090)])],
    );
    let verdict = applier.on_response(&resp).await;
    let Verdict::Reject(message) = verdict else {
        panic!("expected Reject, got {verdict:?}");
    };
    assert!(
        message.contains("no endpoint sink"),
        "message should say why, got: {message}"
    );
}

/// `eds_resource_names` picks up a static EDS cluster's `service_name`.
#[tokio::test]
async fn eds_resource_names_picks_up_a_static_eds_clusters_service_name() {
    let base = base_with_static_eds_cluster("payments", "payments-eds");
    let (publish, _published) = recording_publisher();
    let applier = ResourceApplier::new(base, publish);

    let names = applier.eds_resource_names();
    assert_eq!(
        names,
        std::collections::BTreeSet::from(["payments-eds".to_string()])
    );
}
