//! WP-21 increment 2a acceptance tests: lowering ONE xDS-delivered
//! `ClusterLoadAssignment` (an EDS resource) into endpoint IR.
//!
//! This is the config half of EDS only -- nothing here subscribes to EDS or
//! feeds a cluster manager (that is increment 2b). Mirrors
//! `dynamic_lower.rs`'s fixture idiom: build the proto by hand, encode it
//! into an `Any` (the shape an ADS `DiscoveryResponse.resources` entry
//! carries on the wire), and lower it directly -- there is no bootstrap file
//! on this path.
//!
//! **The strict-mode test is the point of this file, not a nice-to-have.**
//! `lower_dynamic_endpoints` runs the same `check_supported_surface` pass
//! `build_snapshot` runs over a whole file-loaded bootstrap; a `Cluster`
//! LoadAssignment delivered over EDS gets none of ground rule #1's
//! protection unless this function puts it there too.

use prost::Message;
use proxy_api::envoy::config::core::v3 as core_v3;
use proxy_api::envoy::config::endpoint::v3 as endpoint_v3;
use proxy_config::ir::EndpointIR;
use proxy_config::{lower_dynamic_endpoints, ConfigError};

const ENDPOINTS_TYPE: &str = "envoy.config.endpoint.v3.ClusterLoadAssignment";
const LISTENER_TYPE: &str = "envoy.config.listener.v3.Listener";

/// Wrap an encoded proto message as a `google.protobuf.Any`, the same shape
/// an ADS `DiscoveryResponse.resources` entry carries on the wire.
fn any_of<T: Message>(msg: &T, type_name: &str) -> prost_types::Any {
    prost_types::Any {
        type_url: format!("type.googleapis.com/{type_name}"),
        value: msg.encode_to_vec(),
    }
}

/// One `LbEndpoint` at `host:port`, weight defaulted (Envoy default: 1).
fn lb_endpoint(host: &str, port: u32) -> endpoint_v3::LbEndpoint {
    endpoint_v3::LbEndpoint {
        host_identifier: Some(endpoint_v3::lb_endpoint::HostIdentifier::Endpoint(
            endpoint_v3::Endpoint {
                address: Some(core_v3::Address {
                    address: Some(core_v3::address::Address::SocketAddress(
                        core_v3::SocketAddress {
                            address: host.to_string(),
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
    }
}

/// A `ClusterLoadAssignment` for `cluster_name`, with one locality per
/// `endpoints` group given.
fn assignment(
    cluster_name: &str,
    localities: Vec<Vec<endpoint_v3::LbEndpoint>>,
) -> endpoint_v3::ClusterLoadAssignment {
    endpoint_v3::ClusterLoadAssignment {
        cluster_name: cluster_name.to_string(),
        endpoints: localities
            .into_iter()
            .map(|lb_endpoints| endpoint_v3::LocalityLbEndpoints {
                lb_endpoints,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

// ------------------------------------------------------------- acceptance --

#[test]
fn a_valid_assignment_with_two_endpoints_in_one_locality_lowers_with_the_expected_cluster_name_and_endpoints(
) {
    let la = assignment(
        "payments-primary",
        vec![vec![
            lb_endpoint("10.0.0.1", 8080),
            lb_endpoint("10.0.0.2", 8080),
        ]],
    );
    let any = any_of(&la, ENDPOINTS_TYPE);

    let (cluster_name, endpoints) =
        lower_dynamic_endpoints(&any, "eds.assignments[payments-primary]")
            .expect("a minimal valid ClusterLoadAssignment must lower");

    assert_eq!(cluster_name, "payments-primary");
    assert_eq!(endpoints.len(), 2);
    let hosts: Vec<&str> = endpoints.iter().map(|e| e.host.as_str()).collect();
    assert_eq!(hosts, vec!["10.0.0.1", "10.0.0.2"]);
    assert!(endpoints.iter().all(|e| e.port == 8080));
}

/// The locality loop is nested (`endpoints[i].lb_endpoints[j]`); a
/// single-locality test cannot catch a broken outer loop that only ever
/// visits the first locality. Two localities, one endpoint each, both must
/// come back.
#[test]
fn endpoints_across_two_localities_are_all_collected() {
    let la = assignment(
        "payments-primary",
        vec![
            vec![lb_endpoint("10.0.0.1", 8080)],
            vec![lb_endpoint("10.0.1.1", 8080)],
        ],
    );
    let any = any_of(&la, ENDPOINTS_TYPE);

    let (_, endpoints) = lower_dynamic_endpoints(&any, "eds.assignments[payments-primary]")
        .expect("two localities must both lower");

    assert_eq!(endpoints.len(), 2);
    let hosts: Vec<&str> = endpoints.iter().map(|e| e.host.as_str()).collect();
    assert_eq!(hosts, vec!["10.0.0.1", "10.0.1.1"]);
}

// ---------------------------------------------------- strict mode over xDS --

/// THE IMPORTANT ONE. `LocalityLbEndpoints.locality` (field 1) is a real
/// field `allowed_fields("envoy.config.endpoint.v3.LocalityLbEndpoints")` in
/// `lower.rs` does not list (only `lb_endpoints` and `priority` are) --
/// picked by reading that allowlist, not guessed. A `ClusterLoadAssignment`
/// delivered over EDS setting it must be refused exactly as a file-loaded
/// one would be, naming the exact dotted path rooted at the caller's `path`.
#[test]
fn an_assignment_setting_locality_a_field_outside_the_allowlist_is_refused_with_the_exact_path() {
    let mut la = assignment(
        "payments-primary",
        vec![vec![lb_endpoint("10.0.0.1", 8080)]],
    );
    la.endpoints[0].locality = Some(core_v3::Locality {
        region: "us-east-1".to_string(),
        ..Default::default()
    });
    let any = any_of(&la, ENDPOINTS_TYPE);

    let err = lower_dynamic_endpoints(&any, "eds.assignments[payments-primary]")
        .expect_err("a field outside the allowlist must be refused");
    let ConfigError::UnsupportedField { field_path, .. } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert_eq!(
        field_path,
        "eds.assignments[payments-primary].endpoints[0].locality"
    );
}

// ------------------------------------------------------------- type checks --

#[test]
fn a_listener_typed_any_passed_to_lower_dynamic_endpoints_is_refused_naming_both_types() {
    use proxy_api::envoy::config::listener::v3 as listener_v3;

    let listener = listener_v3::Listener {
        name: "ingress".to_string(),
        ..Default::default()
    };
    let any = any_of(&listener, LISTENER_TYPE);

    let err = lower_dynamic_endpoints(&any, "eds.assignments[ingress]")
        .expect_err("a Listener Any must be refused by lower_dynamic_endpoints");
    let rendered = format!("{err}");
    assert!(
        rendered.contains(ENDPOINTS_TYPE) && rendered.contains(LISTENER_TYPE),
        "message must name both the expected and actual type, got: {rendered}"
    );
}

#[test]
fn a_type_url_absent_from_the_descriptor_pool_is_an_unknown_type_url_error() {
    let any = prost_types::Any {
        type_url: "type.googleapis.com/definitely.not.a.real.Type".to_string(),
        value: vec![],
    };
    let err = lower_dynamic_endpoints(&any, "eds.assignments[bogus]")
        .expect_err("a type absent from the descriptor pool must be refused");
    let ConfigError::UnknownTypeUrl {
        field_path,
        type_url,
    } = &err
    else {
        panic!("expected UnknownTypeUrl, got: {err}");
    };
    assert_eq!(field_path, "eds.assignments[bogus]");
    assert_eq!(type_url, "type.googleapis.com/definitely.not.a.real.Type");
}

#[test]
fn undecodable_bytes_under_a_correct_type_url_are_refused_rather_than_panicking() {
    let any = prost_types::Any {
        type_url: format!("type.googleapis.com/{ENDPOINTS_TYPE}"),
        // Not valid protobuf wire format under any schema: an invalid varint
        // tag byte with the continuation bit set and no terminator.
        value: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    };
    let err = lower_dynamic_endpoints(&any, "eds.assignments[garbage]")
        .expect_err("undecodable bytes must be refused, not panic");
    assert!(
        format!("{err}").to_lowercase().contains("decode"),
        "error should say decoding failed, got: {err}"
    );
}

// ------------------------------------------------------------- empty case --

/// An assignment with no localities at all is a legitimate "this cluster has
/// no endpoints right now" answer (Envoy sends exactly this while a cluster
/// is draining, or before any host has registered) -- it must lower to an
/// empty `Vec`, not error. This is NOT the same shape as the aggregate/EDS
/// cross-check `convert_cluster` runs on a *bootstrap-declared* cluster's own
/// `load_assignment` (see `lower.rs`'s doc on that check): there is no
/// competing endpoint source here to have gone stale, this function IS the
/// EDS-delivered source.
#[test]
fn an_assignment_with_no_localities_lowers_to_an_empty_endpoint_list_rather_than_an_error() {
    let la = assignment("payments-primary", vec![]);
    let any = any_of(&la, ENDPOINTS_TYPE);

    let (cluster_name, endpoints) =
        lower_dynamic_endpoints(&any, "eds.assignments[payments-primary]")
            .expect("an empty assignment is valid, not an error");

    assert_eq!(cluster_name, "payments-primary");
    assert_eq!(endpoints, Vec::<EndpointIR>::new());
}

// --------------------------------------------------------- hostnames vs IPs --

/// Decided (see `lower_dynamic_endpoints`'s doc in `lower.rs`): an
/// EDS-delivered endpoint is NOT held to the STATIC-cluster "must be a
/// literal IP" rule, because the management server -- not this data plane --
/// is the one that decided how to address the host, and Envoy's own EDS wire
/// format does not forbid a hostname there. A hostname must lower cleanly,
/// not be refused the way `convert_endpoint` refuses one under
/// `DiscoveryType::Static`.
#[test]
fn an_eds_endpoint_with_a_hostname_instead_of_a_literal_ip_lowers_without_error() {
    let la = assignment(
        "payments-primary",
        vec![vec![lb_endpoint("payments.internal.example.com", 8080)]],
    );
    let any = any_of(&la, ENDPOINTS_TYPE);

    let (_, endpoints) = lower_dynamic_endpoints(&any, "eds.assignments[payments-primary]")
        .expect("a hostname must be accepted for an EDS-delivered endpoint");

    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].host, "payments.internal.example.com");
}
