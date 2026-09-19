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

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use prost::Message;
use proxy_api::envoy::config::cluster::v3 as cluster_v3;
use proxy_api::envoy::config::core::v3 as core_v3;
use proxy_api::envoy::config::endpoint::v3 as endpoint_v3;
use proxy_api::envoy::config::listener::v3 as listener_v3;
use proxy_api::envoy::config::route::v3 as route_v3;
use proxy_api::envoy::extensions::filters::http::router::v3 as router_v3;
use proxy_api::envoy::extensions::filters::network::http_connection_manager::v3 as hcm_v3;
use proxy_api::envoy::extensions::filters::network::tcp_proxy::v3 as tcp_proxy_v3;
use proxy_api::envoy::extensions::transport_sockets::tls::v3 as tls_v3;
use proxy_api::envoy::service::discovery::v3::{
    DeltaDiscoveryResponse, DiscoveryResponse, Resource as DeltaResource, ResourceError,
    ResourceName,
};
use proxy_api::google::rpc::Status as RpcStatus;
use proxy_config::ir::{AdsConfig, AdsProtocol, ConfigSnapshot, EndpointIR, NodeIdentity};
use proxy_config::lower_dynamic_cluster;
use proxy_xds::apply::SecretUpdate;
use proxy_xds::{
    InitializationEvent, InitializationSink, Publish, PublishEndpoints, PublishSecrets,
    ResourceApplier, ResponseHandler, Verdict,
};

const TCP_PROXY_TYPE: &str = "envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy";
const HCM_TYPE: &str =
    "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
const ROUTER_TYPE: &str = "envoy.extensions.filters.http.router.v3.Router";
const CLUSTER_TYPE: &str = "envoy.config.cluster.v3.Cluster";
const LISTENER_TYPE: &str = "envoy.config.listener.v3.Listener";
const ENDPOINT_TYPE: &str = "envoy.config.endpoint.v3.ClusterLoadAssignment";
const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
const LDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";
const RDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";
const EDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
const SDS_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";
const DOWNSTREAM_TLS_TYPE: &str = "envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext";

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

/// A minimal HCM listener whose route table is delivered separately by RDS.
/// This is deliberately a proto fixture, not a pre-built IR value: it proves
/// the LDS path lowers the real `HttpConnectionManager.rds` surface.
fn minimal_rds_listener(name: &str, route_name: &str, port: u32) -> listener_v3::Listener {
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
                name: "envoy.filters.network.http_connection_manager".to_string(),
                config_type: Some(listener_v3::filter::ConfigType::TypedConfig(any_of(
                    &hcm_v3::HttpConnectionManager {
                        stat_prefix: "ingress".to_string(),
                        route_specifier: Some(
                            hcm_v3::http_connection_manager::RouteSpecifier::Rds(hcm_v3::Rds {
                                config_source: Some(core_v3::ConfigSource {
                                    config_source_specifier: Some(
                                        core_v3::config_source::ConfigSourceSpecifier::Ads(
                                            core_v3::AggregatedConfigSource {},
                                        ),
                                    ),
                                    resource_api_version: core_v3::ApiVersion::V3 as i32,
                                    ..Default::default()
                                }),
                                route_config_name: route_name.to_string(),
                            }),
                        ),
                        http_filters: vec![hcm_v3::HttpFilter {
                            name: "envoy.filters.http.router".to_string(),
                            config_type: Some(hcm_v3::http_filter::ConfigType::TypedConfig(
                                any_of(&router_v3::Router::default(), ROUTER_TYPE),
                            )),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    HCM_TYPE,
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

fn rds_response(version: &str, routes: &[route_v3::RouteConfiguration]) -> DiscoveryResponse {
    DiscoveryResponse {
        version_info: version.to_string(),
        type_url: RDS_TYPE_URL.to_string(),
        nonce: format!("n-{version}"),
        resources: routes
            .iter()
            .map(|route| any_of(route, "envoy.config.route.v3.RouteConfiguration"))
            .collect(),
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

fn with_ads_requirements(
    mut base: Arc<ConfigSnapshot>,
    cds: bool,
    lds: bool,
) -> Arc<ConfigSnapshot> {
    let snapshot = Arc::get_mut(&mut base).expect("fixture base must have one owner");
    snapshot.ads = Some(AdsConfig {
        cluster: "ads-control-plane".to_string(),
        protocol: AdsProtocol::Sotw,
        lds,
        cds,
        initial_fetch_timeout: None,
        node: NodeIdentity::default(),
    });
    base
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

type RecordedInitializationEvents = Arc<Mutex<Vec<InitializationEvent>>>;

fn recording_initialization_sink() -> (InitializationSink, RecordedInitializationEvents) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&events);
    let sink: InitializationSink = Box::new(move |event| {
        recorded.lock().unwrap().push(event);
        Box::pin(std::future::ready(()))
    });
    (sink, events)
}

// ------------------------------------------------------------- acceptance --

#[tokio::test]
async fn accepted_event_reports_received_eds_and_rds_after_sink_and_publish_work() {
    let base = with_ads_requirements(
        base_with_static_eds_cluster("payments", "payments-eds"),
        true,
        true,
    );
    let (publish, _published) = recording_publisher();
    let (endpoint_sink, endpoint_calls) = recording_endpoint_sink(&[]);
    let (initialization_sink, events) = recording_initialization_sink();
    let mut applier = ResourceApplier::new(base, publish)
        .with_endpoint_sink(endpoint_sink)
        .with_initialization_sink(initialization_sink);

    assert_eq!(
        applier
            .on_response(&lds_response(
                "lds-1",
                &[minimal_rds_listener("ingress", "ingress-routes", 10000)],
            ))
            .await,
        Verdict::Accept
    );
    assert_eq!(
        applier
            .on_response(&rds_response(
                "rds-1",
                &[route_v3::RouteConfiguration {
                    name: "ingress-routes".to_string(),
                    ..Default::default()
                }],
            ))
            .await,
        Verdict::Accept
    );
    assert_eq!(
        applier
            .on_response(&eds_response(
                "eds-1",
                &[minimal_assignment("payments-eds", &[("10.0.0.1", 8080)])],
            ))
            .await,
        Verdict::Accept
    );

    assert_eq!(endpoint_calls.lock().unwrap().len(), 1);
    let events = events.lock().unwrap();
    let event = events.last().expect("accepted EDS emits an event");
    assert_eq!(event.accepted_type_url, EDS_TYPE_URL);
    assert!(event.cds_required);
    assert!(event.lds_required);
    assert_eq!(
        event.required_eds,
        BTreeSet::from(["payments-eds".to_string()])
    );
    assert_eq!(event.received_eds, event.required_eds);
    assert_eq!(
        event.required_rds,
        BTreeSet::from(["ingress-routes".to_string()])
    );
    assert_eq!(event.received_rds, event.required_rds);
}

#[tokio::test]
async fn accepted_cds_and_lds_events_expose_new_dynamic_requirements() {
    let base = with_ads_requirements(empty_base(), true, true);
    let (publish, _published) = recording_publisher();
    let (sink, events) = recording_initialization_sink();
    let mut applier = ResourceApplier::new(base, publish).with_initialization_sink(sink);

    assert_eq!(
        applier
            .on_response(&cds_response(
                "cds-1",
                &[eds_cluster("payments", "payments-eds")],
            ))
            .await,
        Verdict::Accept
    );
    assert_eq!(
        applier
            .on_response(&lds_response(
                "lds-1",
                &[minimal_rds_listener("ingress", "ingress-routes", 10000)],
            ))
            .await,
        Verdict::Accept
    );

    let events = events.lock().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].accepted_type_url, CDS_TYPE_URL);
    assert_eq!(
        events[0].required_eds,
        BTreeSet::from(["payments-eds".to_string()])
    );
    assert!(events[0].received_eds.is_empty());
    assert_eq!(events[1].accepted_type_url, LDS_TYPE_URL);
    assert_eq!(
        events[1].required_rds,
        BTreeSet::from(["ingress-routes".to_string()])
    );
    assert!(events[1].received_rds.is_empty());
}

#[tokio::test]
async fn rejected_response_emits_no_initialization_event() {
    let (publish, _published) = recording_publisher();
    let (sink, events) = recording_initialization_sink();
    let mut applier = ResourceApplier::new(empty_base(), publish).with_initialization_sink(sink);
    let duplicate = minimal_cluster("duplicate", 8000);

    assert!(matches!(
        applier
            .on_response(&cds_response("bad", &[duplicate.clone(), duplicate]))
            .await,
        Verdict::Reject(_)
    ));
    assert!(events.lock().unwrap().is_empty());
}

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
async fn an_rds_response_publishes_its_named_route_table() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = rds_response(
        "v1",
        &[route_v3::RouteConfiguration {
            name: "ingress-routes".to_string(),
            ..Default::default()
        }],
    );
    let verdict = applier.on_response(&resp).await;
    assert_eq!(verdict, Verdict::Accept);
    assert!(applier.current().routes.contains_key("ingress-routes"));
    assert_eq!(published.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn omitting_a_route_from_a_later_rds_response_keeps_its_last_good_table() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    applier
        .on_response(&rds_response(
            "rds-1",
            &[route_v3::RouteConfiguration {
                name: "ingress-routes".to_string(),
                ..Default::default()
            }],
        ))
        .await;
    let verdict = applier.on_response(&rds_response("rds-2", &[])).await;

    assert_eq!(verdict, Verdict::Accept);
    assert!(
        applier.current().routes.contains_key("ingress-routes"),
        "RDS is PerName, so omission cannot remove an unrelated route table"
    );
    assert_eq!(
        published.lock().unwrap().len(),
        1,
        "an omitted PerName resource is not a worker-visible change"
    );
}

#[tokio::test]
async fn an_lds_listener_waits_for_its_named_rds_route_before_it_is_published() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let verdict = applier
        .on_response(&lds_response(
            "lds-1",
            &[minimal_rds_listener("ingress", "ingress-routes", 10000)],
        ))
        .await;
    assert_eq!(verdict, Verdict::Accept);
    assert!(
        !applier.current().listeners.contains_key("ingress"),
        "a listener without its named RDS table must stay out of the worker snapshot"
    );
    assert!(applier.rds_resource_names().contains("ingress-routes"));
    assert!(
        published.lock().unwrap().is_empty(),
        "staging an unready listener must not wake workers or replace last-good state"
    );

    let verdict = applier
        .on_response(&rds_response(
            "rds-1",
            &[route_v3::RouteConfiguration {
                name: "ingress-routes".to_string(),
                ..Default::default()
            }],
        ))
        .await;
    assert_eq!(verdict, Verdict::Accept);
    assert!(applier.current().listeners.contains_key("ingress"));
    assert_eq!(published.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn an_unwarmed_same_name_lds_replacement_keeps_the_last_good_listener_active() {
    let (publish, _published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    applier
        .on_response(&rds_response(
            "rds-a",
            &[route_v3::RouteConfiguration {
                name: "route-a".to_string(),
                ..Default::default()
            }],
        ))
        .await;
    applier
        .on_response(&lds_response(
            "lds-a",
            &[minimal_rds_listener("ingress", "route-a", 10000)],
        ))
        .await;

    applier
        .on_response(&lds_response(
            "lds-b",
            &[minimal_rds_listener("ingress", "route-b", 10000)],
        ))
        .await;
    let listener = applier
        .current()
        .listeners
        .get("ingress")
        .expect("last good listener");
    let proxy_config::ir::NetworkFilterSpec::HttpConnectionManager(hcm) =
        &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM");
    };
    assert_eq!(hcm.rds_route_config_name.as_deref(), Some("route-a"));

    applier
        .on_response(&rds_response(
            "rds-b",
            &[route_v3::RouteConfiguration {
                name: "route-b".to_string(),
                ..Default::default()
            }],
        ))
        .await;
    let listener = applier
        .current()
        .listeners
        .get("ingress")
        .expect("promoted listener");
    let proxy_config::ir::NetworkFilterSpec::HttpConnectionManager(hcm) =
        &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM");
    };
    assert_eq!(hcm.rds_route_config_name.as_deref(), Some("route-b"));
}

#[tokio::test]
async fn an_unwarmed_renamed_lds_replacement_keeps_the_last_good_listener_set_active() {
    let (publish, _published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    applier
        .on_response(&rds_response(
            "rds-a",
            &[route_v3::RouteConfiguration {
                name: "route-a".to_string(),
                ..Default::default()
            }],
        ))
        .await;
    applier
        .on_response(&lds_response(
            "lds-a",
            &[minimal_rds_listener("ingress-a", "route-a", 10000)],
        ))
        .await;

    applier
        .on_response(&lds_response(
            "lds-b",
            &[minimal_rds_listener("ingress-b", "route-b", 10001)],
        ))
        .await;
    assert!(
        applier.current().listeners.contains_key("ingress-a"),
        "a renamed listener must stay active until its replacement is warmed"
    );
    assert!(
        !applier.current().listeners.contains_key("ingress-b"),
        "an unwarmed replacement must not reach workers"
    );

    applier
        .on_response(&rds_response(
            "rds-b",
            &[route_v3::RouteConfiguration {
                name: "route-b".to_string(),
                ..Default::default()
            }],
        ))
        .await;
    assert!(
        !applier.current().listeners.contains_key("ingress-a"),
        "the old listener must retire once the complete replacement generation is warm"
    );
    assert!(applier.current().listeners.contains_key("ingress-b"));
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
/// `(cluster_name, endpoints)` -- here the resource name and the cluster name
/// happen to match, which is the common case; the mismatched-name case (the
/// Part 1 regression) has its own test below.
#[tokio::test]
async fn a_valid_eds_response_reaches_the_sink_with_the_right_name_and_endpoints() {
    let base = base_with_static_eds_cluster("my-cluster", "my-cluster");
    let (publish, _published) = recording_publisher();
    let (sink, recorded) = recording_endpoint_sink(&[]);
    let mut applier = ResourceApplier::new(base, publish).with_endpoint_sink(sink);

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

/// THE PART 1 REGRESSION TEST. The EDS resource's own name
/// (`ClusterLoadAssignment.cluster_name`) differs from the `Cluster.name` that
/// subscribes to it via `eds_cluster_config.service_name` -- Envoy allows
/// this. The sink must be called with the CLUSTER's name, never the resource
/// name passed straight through. Against the code as it landed in increment
/// 2b-ii (which called the sink with the assignment's own `cluster_name`),
/// this fails: the sink is never called at all, because nothing in
/// `empty_base()` is named `eds-resource-name`, or -- had the bug instead
/// been "call the sink with the resource name regardless of any cluster" --
/// it would have called the sink under the wrong name.
#[tokio::test]
async fn an_eds_resource_whose_name_differs_from_the_cluster_name_reaches_the_sink_under_the_cluster_name(
) {
    let base = base_with_static_eds_cluster("real-cluster-name", "eds-resource-name");
    let (publish, _published) = recording_publisher();
    let (sink, recorded) = recording_endpoint_sink(&[]);
    let mut applier = ResourceApplier::new(base, publish).with_endpoint_sink(sink);

    let resp = eds_response(
        "v1",
        &[minimal_assignment(
            "eds-resource-name",
            &[("10.0.0.1", 9090)],
        )],
    );
    let verdict = applier.on_response(&resp).await;

    assert_eq!(verdict, Verdict::Accept);
    let calls = recorded.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].0, "real-cluster-name",
        "the sink must be called with the CLUSTER's name, not the EDS resource name"
    );
    assert_eq!(calls[0].1[0].host, "10.0.0.1");
}

/// Two clusters share one `service_name` -- Envoy allows this too. A single
/// resource must feed both.
#[tokio::test]
async fn two_clusters_sharing_one_eds_resource_are_both_fed_from_a_single_response() {
    let any_a = any_of(&eds_cluster("cluster-a", "shared-eds"), CLUSTER_TYPE);
    let any_b = any_of(&eds_cluster("cluster-b", "shared-eds"), CLUSTER_TYPE);
    let ir_a = lower_dynamic_cluster(&any_a, "static_resources.clusters[0]")
        .expect("fixture cluster must lower");
    let ir_b = lower_dynamic_cluster(&any_b, "static_resources.clusters[1]")
        .expect("fixture cluster must lower");
    let mut snapshot = ConfigSnapshot::default();
    snapshot
        .clusters
        .insert("cluster-a".to_string(), Arc::new(ir_a));
    snapshot
        .clusters
        .insert("cluster-b".to_string(), Arc::new(ir_b));
    let base = Arc::new(snapshot);

    let (publish, _published) = recording_publisher();
    let (sink, recorded) = recording_endpoint_sink(&[]);
    let mut applier = ResourceApplier::new(base, publish).with_endpoint_sink(sink);

    let resp = eds_response(
        "v1",
        &[minimal_assignment("shared-eds", &[("10.0.0.1", 9090)])],
    );
    let verdict = applier.on_response(&resp).await;

    assert_eq!(verdict, Verdict::Accept);
    let calls = recorded.lock().unwrap();
    assert_eq!(
        calls.len(),
        2,
        "both clusters sharing the resource must be fed"
    );
    let names: std::collections::BTreeSet<&str> =
        calls.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        std::collections::BTreeSet::from(["cluster-a", "cluster-b"])
    );
}

/// A resource matching no cluster is accepted, calls no sink, and does not
/// reject -- a control plane pushing a resource nobody subscribed to is its
/// own bug, not a reason to stall every OTHER resource in the response.
#[tokio::test]
async fn an_eds_resource_matching_no_cluster_is_accepted_and_calls_no_sink() {
    let (publish, _published) = recording_publisher();
    let (sink, recorded) = recording_endpoint_sink(&[]);
    let mut applier = ResourceApplier::new(empty_base(), publish).with_endpoint_sink(sink);

    let resp = eds_response(
        "v1",
        &[minimal_assignment(
            "nobody-subscribed",
            &[("10.0.0.1", 9090)],
        )],
    );
    let verdict = applier.on_response(&resp).await;

    assert_eq!(verdict, Verdict::Accept);
    assert!(recorded.lock().unwrap().is_empty());
}

/// A second, identical EDS response must not reach the sink again -- the
/// same `unchanged` suppression `Entry`'s `PartialEq` gives CDS/LDS.
#[tokio::test]
async fn a_second_identical_eds_response_does_not_reach_the_sink_again() {
    let base = base_with_static_eds_cluster("my-cluster", "my-cluster");
    let (publish, _published) = recording_publisher();
    let (sink, recorded) = recording_endpoint_sink(&[]);
    let mut applier = ResourceApplier::new(base, publish).with_endpoint_sink(sink);

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
    let base = base_with_static_eds_cluster("my-cluster", "my-cluster");
    let (publish, _published) = recording_publisher();
    let (sink, recorded) = recording_endpoint_sink(&["my-cluster"]);
    let mut applier = ResourceApplier::new(base, publish).with_endpoint_sink(sink);

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

// -------------------------------------------------------------------------
// WP-22 increment 2a: SDS names its subscription from the listeners it holds.

/// An `SdsSecretConfig` naming `secret` over ADS -- the only form lowering
/// accepts (a name-only entry would mean `static_resources.secrets`, which is
/// still a stub, so `convert_certificate_sds_configs` refuses it).
fn ads_sds_secret_config(secret: &str) -> tls_v3::SdsSecretConfig {
    tls_v3::SdsSecretConfig {
        name: secret.to_string(),
        sds_config: Some(core_v3::ConfigSource {
            resource_api_version: core_v3::ApiVersion::V3 as i32,
            config_source_specifier: Some(core_v3::config_source::ConfigSourceSpecifier::Ads(
                core_v3::AggregatedConfigSource {},
            )),
            ..Default::default()
        }),
    }
}

/// [`minimal_listener`] plus a downstream TLS transport socket whose serving
/// certificates come from SDS under `secrets`.
fn listener_with_sds_certs(
    name: &str,
    cluster: &str,
    port: u32,
    secrets: &[&str],
) -> listener_v3::Listener {
    let mut listener = minimal_listener(name, cluster, port);
    let ctx = tls_v3::DownstreamTlsContext {
        common_tls_context: Some(tls_v3::CommonTlsContext {
            tls_certificate_sds_secret_configs: secrets
                .iter()
                .map(|s| ads_sds_secret_config(s))
                .collect(),
            ..Default::default()
        }),
        ..Default::default()
    };
    listener.filter_chains[0].transport_socket = Some(core_v3::TransportSocket {
        name: "envoy.transport_sockets.tls".to_string(),
        config_type: Some(core_v3::transport_socket::ConfigType::TypedConfig(any_of(
            &ctx,
            DOWNSTREAM_TLS_TYPE,
        ))),
    });
    listener
}

/// The same TLS listener shape with a dynamic downstream client-auth trust
/// anchor. A server certificate is still required independently; the extra
/// SDS name must join the same subscription set.
fn listener_with_sds_validation_context(
    name: &str,
    cluster: &str,
    port: u32,
    cert_secret: &str,
    validation_secret: &str,
) -> listener_v3::Listener {
    let mut listener = listener_with_sds_certs(name, cluster, port, &[cert_secret]);
    let socket = listener.filter_chains[0]
        .transport_socket
        .as_mut()
        .expect("fixture installs a TLS transport socket");
    let Some(core_v3::transport_socket::ConfigType::TypedConfig(any)) = socket.config_type.as_mut()
    else {
        panic!("fixture TLS socket must have typed config");
    };
    let mut context = tls_v3::DownstreamTlsContext::decode(any.value.as_slice()).unwrap();
    context
        .common_tls_context
        .as_mut()
        .unwrap()
        .validation_context_type = Some(
        tls_v3::common_tls_context::ValidationContextType::ValidationContextSdsSecretConfig(
            ads_sds_secret_config(validation_secret),
        ),
    );
    any.value = context.encode_to_vec();
    listener
}

/// An applied LDS listener whose chain names SDS secrets makes those names the
/// SDS subscription: `desired_names` answers a real set, where before
/// increment 2a it answered `None` for SDS unconditionally.
#[tokio::test]
async fn sds_desired_names_come_from_the_applied_listeners() {
    let (publish, _published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    // Nothing applied yet: an empty set, not `None` -- an empty set is what
    // unsubscribes, and it is the honest answer once SDS is name-driven.
    assert_eq!(
        applier.desired_names(SDS_TYPE_URL),
        Some(std::collections::BTreeSet::new())
    );

    let resp = lds_response(
        "v1",
        &[
            listener_with_sds_certs("l1", "my-cluster", 8443, &["cert-rsa", "cert-ecdsa"]),
            // Same secret named twice across two listeners: deduplicated.
            listener_with_sds_certs("l2", "my-cluster", 8444, &["cert-rsa"]),
            listener_with_sds_validation_context(
                "l3",
                "my-cluster",
                8445,
                "cert-l3",
                "client-ca-l3",
            ),
        ],
    );
    assert!(matches!(applier.on_response(&resp).await, Verdict::Accept));

    assert_eq!(
        applier.sds_resource_names(),
        std::collections::BTreeSet::from([
            "cert-ecdsa".to_string(),
            "cert-rsa".to_string(),
            "cert-l3".to_string(),
            "client-ca-l3".to_string(),
        ])
    );
    assert_eq!(
        applier.desired_names(SDS_TYPE_URL),
        Some(applier.sds_resource_names())
    );
}

/// A listener with no SDS-named chain contributes nothing -- an inline-cert or
/// plaintext chain must not widen the subscription.
#[tokio::test]
async fn a_listener_without_sds_certs_names_no_secrets() {
    let (publish, _published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let resp = lds_response("v1", &[minimal_listener("l1", "my-cluster", 8080)]);
    assert!(matches!(applier.on_response(&resp).await, Verdict::Accept));

    assert!(applier.sds_resource_names().is_empty());
}

// -------------------------------------------------------------------------
// WP-22 increment 2c: a `validation_context` secret reaches the real sink
// shape rather than being ACKed and discarded.
//
// `crates/proxy-xds/src/apply.rs`'s own unit tests (increment 1) already
// prove `a_well_formed_validation_context_secret_lowers_and_reaches_the_sink`
// -- that is `on_sds_response`'s sink-agnostic plumbing, and a
// `CertificateValidationContext` DOES lower and reach whatever sink is
// wired. What increment 2b adds is the REAL sink `crates/proxy/src/main.rs`'s
// `start_ads` builds, which has nowhere to route a validation_context secret
// yet (`DynamicSecret::tls_certificate_ir` answers `None` for it) and so must
// turn that into an explicit rejection rather than an accept. This test
// exercises that rejection shape end to end through `ResourceApplier`, using
// the same sink logic `main.rs` wires (mirrored here since the sink itself is
// a closure private to `main`, not something this crate exports).

fn tls_cert_secret(name: &str, chain: &[u8], key: &[u8]) -> tls_v3::Secret {
    tls_v3::Secret {
        name: name.to_string(),
        r#type: Some(tls_v3::secret::Type::TlsCertificate(
            tls_v3::TlsCertificate {
                certificate_chain: Some(core_v3::DataSource {
                    specifier: Some(core_v3::data_source::Specifier::InlineBytes(chain.to_vec())),
                    ..Default::default()
                }),
                private_key: Some(core_v3::DataSource {
                    specifier: Some(core_v3::data_source::Specifier::InlineBytes(key.to_vec())),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )),
    }
}

fn validation_context_secret(name: &str, trusted_ca: &[u8]) -> tls_v3::Secret {
    tls_v3::Secret {
        name: name.to_string(),
        r#type: Some(tls_v3::secret::Type::ValidationContext(
            tls_v3::CertificateValidationContext {
                trusted_ca: Some(core_v3::DataSource {
                    specifier: Some(core_v3::data_source::Specifier::InlineBytes(
                        trusted_ca.to_vec(),
                    )),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )),
    }
}

const SECRET_TYPE: &str = "envoy.extensions.transport_sockets.tls.v3.Secret";

fn sds_response(version: &str, secrets: &[tls_v3::Secret]) -> DiscoveryResponse {
    DiscoveryResponse {
        version_info: version.to_string(),
        type_url: SDS_TYPE_URL.to_string(),
        nonce: format!("n-{version}"),
        resources: secrets.iter().map(|s| any_of(s, SECRET_TYPE)).collect(),
        ..Default::default()
    }
}

/// `main.rs`'s `start_ads` secret sink shape. The registry itself is covered
/// in `proxy-core`; this proves neither supported secret kind is discarded at
/// the transport/apply boundary.
fn main_rs_shaped_secret_sink() -> PublishSecrets {
    Box::new(move |update| {
        Box::pin(async move {
            match update {
                SecretUpdate::Upsert { name, secret } => match secret.tls_certificate_ir() {
                    Ok(Some(_ir)) => Ok(()),
                    Ok(None) => match secret.validation_context_ir() {
                        Ok(Some(_)) => Ok(()),
                        Ok(None) => {
                            Err(format!("secret `{name}` has no supported SDS TLS payload"))
                        }
                        Err(err) => Err(err.to_string()),
                    },
                    Err(err) => Err(err.to_string()),
                },
                SecretUpdate::Remove { .. } => Ok(()),
            }
        })
    })
}

#[tokio::test]
async fn a_validation_context_secret_is_accepted_by_the_increment_2c_sink() {
    let (publish, _published) = recording_publisher();
    let mut applier =
        ResourceApplier::new(empty_base(), publish).with_secret_sink(main_rs_shaped_secret_sink());

    let resp = sds_response("v1", &[validation_context_secret("ca-1", b"ca-bytes")]);
    let verdict = applier.on_response(&resp).await;

    assert!(matches!(verdict, Verdict::Accept), "got {verdict:?}");
}

/// The same sink accepts an ordinary TLS certificate secret -- the rejection
/// above is specific to `validation_context`, not a blanket SDS refusal.
#[tokio::test]
async fn a_tls_certificate_secret_is_accepted_by_the_same_increment_2c_sink() {
    let (publish, _published) = recording_publisher();
    let mut applier =
        ResourceApplier::new(empty_base(), publish).with_secret_sink(main_rs_shaped_secret_sink());

    let resp = sds_response("v1", &[tls_cert_secret("cert-1", b"chain", b"key")]);
    let verdict = applier.on_response(&resp).await;

    assert!(matches!(verdict, Verdict::Accept), "got {verdict:?}");
}

fn delta_cds_response(
    nonce: &str,
    clusters: &[(&str, cluster_v3::Cluster)],
    removed: &[&str],
) -> DeltaDiscoveryResponse {
    DeltaDiscoveryResponse {
        type_url: CDS_TYPE_URL.to_string(),
        nonce: nonce.to_string(),
        resources: clusters
            .iter()
            .map(|(version, cluster)| DeltaResource {
                name: cluster.name.clone(),
                version: (*version).to_string(),
                resource: Some(any_of(cluster, CLUSTER_TYPE)),
                ..Default::default()
            })
            .collect(),
        removed_resources: removed.iter().map(|name| (*name).to_string()).collect(),
        ..Default::default()
    }
}

fn delta_sds_response(
    nonce: &str,
    secrets: &[(&str, tls_v3::Secret)],
    removed: &[&str],
) -> DeltaDiscoveryResponse {
    DeltaDiscoveryResponse {
        type_url: SDS_TYPE_URL.to_string(),
        nonce: nonce.to_string(),
        resources: secrets
            .iter()
            .map(|(version, secret)| DeltaResource {
                name: secret.name.clone(),
                version: (*version).to_string(),
                resource: Some(any_of(secret, SECRET_TYPE)),
                ..Default::default()
            })
            .collect(),
        removed_resources: removed.iter().map(|name| (*name).to_string()).collect(),
        ..Default::default()
    }
}

fn delta_resource_error(name: &str, code: i32, message: &str) -> ResourceError {
    ResourceError {
        resource_name: Some(ResourceName {
            name: name.to_string(),
            ..Default::default()
        }),
        error_detail: Some(RpcStatus {
            code,
            message: message.to_string(),
            ..Default::default()
        }),
    }
}

#[tokio::test]
async fn accepted_delta_response_emits_initialization_event() {
    let base = with_ads_requirements(empty_base(), true, false);
    let (publish, _published) = recording_publisher();
    let (sink, events) = recording_initialization_sink();
    let mut applier = ResourceApplier::new(base, publish).with_initialization_sink(sink);
    let response = delta_cds_response(
        "n1",
        &[("v1", eds_cluster("payments", "payments-eds"))],
        &[],
    );

    assert_eq!(applier.on_delta_response(&response).await, Verdict::Accept);
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].accepted_type_url, CDS_TYPE_URL);
    assert!(events[0].cds_required);
    assert!(!events[0].lds_required);
    assert_eq!(
        events[0].required_eds,
        BTreeSet::from(["payments-eds".to_string()])
    );
}

#[tokio::test]
async fn delta_sds_removal_reaches_sink_and_sink_failure_rolls_back_store() {
    let (publish, _published) = recording_publisher();
    let events = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&events);
    let mut fail_first_removal = true;
    let sink: PublishSecrets = Box::new(move |update| {
        let result = match update {
            SecretUpdate::Upsert { name, .. } => {
                recorded.lock().unwrap().push(format!("upsert:{name}"));
                Ok(())
            }
            SecretUpdate::Remove { name } if fail_first_removal => {
                fail_first_removal = false;
                Err(format!("deliberately failed removal of `{name}`"))
            }
            SecretUpdate::Remove { name } => {
                recorded.lock().unwrap().push(format!("remove:{name}"));
                Ok(())
            }
        };
        Box::pin(std::future::ready(result))
    });
    let mut applier = ResourceApplier::new(empty_base(), publish).with_secret_sink(sink);
    let secret = tls_cert_secret("cert-1", b"chain", b"key");
    let update = delta_sds_response("n1", &[("v1", secret.clone())], &[]);

    assert_eq!(applier.on_delta_response(&update).await, Verdict::Accept);
    let failed_remove = delta_sds_response("n2", &[], &["cert-1"]);
    assert!(matches!(
        applier.on_delta_response(&failed_remove).await,
        Verdict::Reject(message) if message.contains("deliberately failed removal")
    ));

    // Failed removal restored the prior store entry. Identical bytes remain
    // unchanged and do not replay through the sink.
    assert_eq!(applier.on_delta_response(&update).await, Verdict::Accept);
    assert_eq!(&*events.lock().unwrap(), &["upsert:cert-1"]);

    assert_eq!(
        applier.on_delta_response(&failed_remove).await,
        Verdict::Accept
    );
    let unknown_remove = delta_sds_response("n3", &[], &["unknown"]);
    assert_eq!(
        applier.on_delta_response(&unknown_remove).await,
        Verdict::Accept
    );
    assert_eq!(
        &*events.lock().unwrap(),
        &["upsert:cert-1", "remove:cert-1", "remove:unknown"]
    );
}

#[tokio::test]
async fn delta_cds_updates_and_explicit_removals_publish_incrementally() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let first = delta_cds_response(
        "n1",
        &[
            ("a1", minimal_cluster("a", 8001)),
            ("b1", minimal_cluster("b", 8002)),
        ],
        &[],
    );
    assert_eq!(applier.on_delta_response(&first).await, Verdict::Accept);

    let second = delta_cds_response("n2", &[("a2", minimal_cluster("a", 9001))], &["b"]);
    assert_eq!(applier.on_delta_response(&second).await, Verdict::Accept);

    let snapshots = published.lock().unwrap();
    let latest = snapshots.last().expect("second delta response publishes");
    assert!(latest.clusters.contains_key("a"));
    assert!(!latest.clusters.contains_key("b"));
    assert_eq!(snapshots.len(), 2);
}

#[tokio::test]
async fn delta_not_found_resource_error_removes_existing_resource() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let first = delta_cds_response("n1", &[("v1", minimal_cluster("a", 8001))], &[]);
    assert_eq!(applier.on_delta_response(&first).await, Verdict::Accept);

    let removal = DeltaDiscoveryResponse {
        type_url: CDS_TYPE_URL.to_string(),
        nonce: "n2".to_string(),
        resource_errors: vec![delta_resource_error("a", 5, "cluster no longer exists")],
        ..Default::default()
    };
    assert_eq!(applier.on_delta_response(&removal).await, Verdict::Accept);
    assert!(!published
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clusters
        .contains_key("a"));
}

#[tokio::test]
async fn delta_non_not_found_resource_error_nacks_without_mutating_state() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);

    let first = delta_cds_response("n1", &[("v1", minimal_cluster("a", 8001))], &[]);
    assert_eq!(applier.on_delta_response(&first).await, Verdict::Accept);
    let before = published.lock().unwrap().len();

    let failure = DeltaDiscoveryResponse {
        type_url: CDS_TYPE_URL.to_string(),
        nonce: "n2".to_string(),
        resource_errors: vec![delta_resource_error("a", 7, "permission denied")],
        ..Default::default()
    };
    let verdict = applier.on_delta_response(&failure).await;
    assert!(matches!(verdict, Verdict::Reject(message)
        if message.contains("delta_response.resource_errors[0].error_detail.code")
            && message.contains("permission denied")));
    assert_eq!(published.lock().unwrap().len(), before);
}

#[tokio::test]
async fn delta_wrapper_name_mismatch_nacks_without_publishing() {
    let (publish, published) = recording_publisher();
    let mut applier = ResourceApplier::new(empty_base(), publish);
    let mut response = delta_cds_response("n1", &[("v1", minimal_cluster("inside", 8001))], &[]);
    response.resources[0].name = "outside".to_string();

    let verdict = applier.on_delta_response(&response).await;

    assert!(
        matches!(verdict, Verdict::Reject(ref message) if message.contains("does not match resource name `inside`")),
        "got {verdict:?}"
    );
    assert!(published.lock().unwrap().is_empty());
}
