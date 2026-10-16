//! Acceptance tests for lowering individual xDS `Any` resources into IR.
//! Dynamic resources must pass the same strict surface checks as file config.
//! Tests construct messages directly because this path receives protobufs, not YAML.

use prost::Message;
use proxy_api::envoy::config::cluster::v3 as cluster_v3;
use proxy_api::envoy::config::core::v3 as core_v3;
use proxy_api::envoy::config::endpoint::v3 as endpoint_v3;
use proxy_api::envoy::config::listener::v3 as listener_v3;
use proxy_api::envoy::extensions::filters::network::tcp_proxy::v3 as tcp_proxy_v3;
use proxy_config::{lower_dynamic_cluster, lower_dynamic_listener, ConfigError};

const TCP_PROXY_TYPE: &str = "envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy";
const CLUSTER_TYPE: &str = "envoy.config.cluster.v3.Cluster";
const LISTENER_TYPE: &str = "envoy.config.listener.v3.Listener";

/// Wrap an encoded proto message as a `google.protobuf.Any`, the same shape
/// an ADS `DiscoveryResponse.resources` entry carries on the wire.
fn any_of<T: Message>(msg: &T, type_name: &str) -> prost_types::Any {
    prost_types::Any {
        type_url: format!("type.googleapis.com/{type_name}"),
        value: msg.encode_to_vec(),
    }
}

/// A minimal, valid `STATIC` cluster with one endpoint -- just enough for
/// `convert_cluster` to accept it.
fn minimal_cluster(name: &str) -> cluster_v3::Cluster {
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
                                            core_v3::socket_address::PortSpecifier::PortValue(8080),
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
fn minimal_listener(name: &str, cluster: &str) -> listener_v3::Listener {
    listener_v3::Listener {
        name: name.to_string(),
        address: Some(core_v3::Address {
            address: Some(core_v3::address::Address::SocketAddress(
                core_v3::SocketAddress {
                    address: "127.0.0.1".to_string(),
                    port_specifier: Some(core_v3::socket_address::PortSpecifier::PortValue(10000)),
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

// ------------------------------------------------------------- acceptance --

#[test]
fn a_minimal_dynamic_cluster_lowers_to_cluster_config_with_the_expected_name() {
    let any = any_of(&minimal_cluster("payments-primary"), CLUSTER_TYPE);
    let cluster = lower_dynamic_cluster(&any, "cds.clusters[payments-primary]")
        .expect("a minimal valid Cluster must lower");
    assert_eq!(cluster.name, "payments-primary");
}

#[test]
fn a_minimal_dynamic_listener_lowers_to_listener_config_with_the_expected_name() {
    let any = any_of(
        &minimal_listener("ingress", "payments-primary"),
        LISTENER_TYPE,
    );
    let listener = lower_dynamic_listener(&any, "lds.listeners[ingress]")
        .expect("a minimal valid Listener must lower");
    assert_eq!(listener.name, "ingress");
}

/// LDS goes through the same `convert_listener` check as file config, so a
/// dynamic listener with an explicit 0 buffer limit is refused (NACKed).
#[test]
fn a_dynamic_listener_with_zero_buffer_limit_is_rejected() {
    let mut listener = minimal_listener("ingress", "payments-primary");
    listener.per_connection_buffer_limit_bytes = Some(0);
    let any = any_of(&listener, LISTENER_TYPE);
    let err = lower_dynamic_listener(&any, "lds.listeners[ingress]")
        .expect_err("0 buffer limit must be rejected");
    match err {
        ConfigError::InvalidValue { field_path, .. } => assert_eq!(
            field_path,
            "lds.listeners[ingress].per_connection_buffer_limit_bytes"
        ),
        other => panic!("expected InvalidValue, got: {other}"),
    }
}

// ---------------------------------------------------- strict mode over xDS --

/// An unsupported real `Cluster` field must be refused on xDS with the caller's
/// path, just as it is for file-loaded config.
#[test]
fn a_dynamic_cluster_setting_a_field_outside_the_allowlist_is_refused_with_the_callers_path_root() {
    let mut c = minimal_cluster("payments-primary");
    c.close_connections_on_host_health_failure = true;
    let any = any_of(&c, CLUSTER_TYPE);

    let err = lower_dynamic_cluster(&any, "cds.clusters[payments-primary]")
        .expect_err("a field outside the allowlist must be refused");
    let ConfigError::UnsupportedField { field_path, .. } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert_eq!(
        field_path,
        "cds.clusters[payments-primary].close_connections_on_host_health_failure"
    );
}

/// Same claim, for `Listener.stat_prefix` (listener.proto field 28) -- not on
/// `allowed_fields("envoy.config.listener.v3.Listener")`.
#[test]
fn a_dynamic_listener_setting_a_field_outside_the_allowlist_is_refused_with_the_callers_path_root()
{
    let mut l = minimal_listener("ingress", "payments-primary");
    l.stat_prefix = "should-be-refused".to_string();
    let any = any_of(&l, LISTENER_TYPE);

    let err = lower_dynamic_listener(&any, "lds.listeners[ingress]")
        .expect_err("a field outside the allowlist must be refused");
    let ConfigError::UnsupportedField { field_path, .. } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert_eq!(field_path, "lds.listeners[ingress].stat_prefix");
}

// ------------------------------------------------------------- type checks --

#[test]
fn a_listener_typed_any_passed_to_lower_dynamic_cluster_is_refused_naming_both_types() {
    let any = any_of(
        &minimal_listener("ingress", "payments-primary"),
        LISTENER_TYPE,
    );
    let err = lower_dynamic_cluster(&any, "cds.clusters[ingress]")
        .expect_err("a Listener Any must be refused by lower_dynamic_cluster");
    let rendered = format!("{err}");
    assert!(
        rendered.contains(CLUSTER_TYPE) && rendered.contains(LISTENER_TYPE),
        "message must name both the expected and actual type, got: {rendered}"
    );
}

#[test]
fn a_cluster_typed_any_passed_to_lower_dynamic_listener_is_refused_naming_both_types() {
    let any = any_of(&minimal_cluster("payments-primary"), CLUSTER_TYPE);
    let err = lower_dynamic_listener(&any, "lds.listeners[payments-primary]")
        .expect_err("a Cluster Any must be refused by lower_dynamic_listener");
    let rendered = format!("{err}");
    assert!(
        rendered.contains(LISTENER_TYPE) && rendered.contains(CLUSTER_TYPE),
        "message must name both the expected and actual type, got: {rendered}"
    );
}

#[test]
fn a_type_url_absent_from_the_descriptor_pool_is_an_unknown_type_url_error() {
    let any = prost_types::Any {
        type_url: "type.googleapis.com/definitely.not.a.real.Type".to_string(),
        value: vec![],
    };
    let err = lower_dynamic_cluster(&any, "cds.clusters[bogus]")
        .expect_err("a type absent from the descriptor pool must be refused");
    let ConfigError::UnknownTypeUrl {
        field_path,
        type_url,
    } = &err
    else {
        panic!("expected UnknownTypeUrl, got: {err}");
    };
    assert_eq!(field_path, "cds.clusters[bogus]");
    assert_eq!(type_url, "type.googleapis.com/definitely.not.a.real.Type");
}

#[test]
fn undecodable_bytes_under_a_correct_type_url_are_refused_rather_than_panicking() {
    let any = prost_types::Any {
        type_url: format!("type.googleapis.com/{CLUSTER_TYPE}"),
        // Not valid protobuf wire format under any schema: an invalid varint
        // tag byte with the continuation bit set and no terminator.
        value: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    };
    let err = lower_dynamic_cluster(&any, "cds.clusters[garbage]")
        .expect_err("undecodable bytes must be refused, not panic");
    assert!(
        format!("{err}").to_lowercase().contains("decode"),
        "error should say decoding failed, got: {err}"
    );
}

// --------------------------------------------------- path rooted at caller --

/// Errors from typed lowering retain the caller's path rather than a
/// hardcoded `static_resources` prefix.
#[test]
fn an_error_from_deep_inside_convert_cluster_is_rooted_at_the_callers_path() {
    let mut c = minimal_cluster("payments-primary");
    c.lb_policy = cluster_v3::cluster::LbPolicy::RingHash as i32;
    let any = any_of(&c, CLUSTER_TYPE);

    let err = lower_dynamic_cluster(&any, "cds.clusters[payments-primary]")
        .expect_err("RING_HASH must still be rejected over xDS");
    let ConfigError::UnsupportedField { field_path, reason } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert_eq!(field_path, "cds.clusters[payments-primary].lb_policy");
    assert!(
        reason.contains("RING_HASH"),
        "message must name the policy, got: {reason}"
    );
}
