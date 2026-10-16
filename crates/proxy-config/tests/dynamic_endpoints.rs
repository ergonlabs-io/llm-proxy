//! Acceptance tests: lowering ONE xDS-delivered
//! `ClusterLoadAssignment` (an EDS resource) into endpoint IR.
//!
//! Tests config lowering for EDS endpoint resources without subscribing or
//! updating a cluster manager. Direct `Any` construction matches the ADS input
//! path, and strict surface checks apply to delivered resources too.

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

/// Same as [`lb_endpoint`], with `metadata.filter_metadata[namespace]` set
/// to the given single string field. Used by the metadata tests below.
fn lb_endpoint_with_metadata(
    host: &str,
    port: u32,
    namespace: &str,
    field: &str,
    value: prost_types::Value,
) -> endpoint_v3::LbEndpoint {
    let mut lbe = lb_endpoint(host, port);
    let mut fields = std::collections::BTreeMap::new();
    fields.insert(field.to_string(), value);
    let mut filter_metadata = std::collections::HashMap::new();
    filter_metadata.insert(namespace.to_string(), prost_types::Struct { fields });
    lbe.metadata = Some(core_v3::Metadata {
        filter_metadata,
        ..Default::default()
    });
    lbe
}

fn string_value(s: &str) -> prost_types::Value {
    prost_types::Value {
        kind: Some(prost_types::value::Kind::StringValue(s.to_string())),
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

// ------------------------------------------------------------- empty case --

/// An empty assignment is valid while a cluster is draining or has no hosts;
/// it lowers to an empty vector.
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

/// EDS endpoints require literal IPs because `static_hosts` does no name
/// resolution; rejecting hostnames here keeps errors at config time.
#[test]
fn an_eds_endpoint_with_a_hostname_instead_of_a_literal_ip_is_refused() {
    let la = assignment(
        "payments-primary",
        vec![vec![lb_endpoint("payments.internal.example.com", 8080)]],
    );
    let any = any_of(&la, ENDPOINTS_TYPE);

    let err = lower_dynamic_endpoints(&any, "eds.assignments[payments-primary]")
        .expect_err("a hostname cannot be installed without resolution, so it must be refused");

    let ConfigError::InvalidValue { field_path, reason } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(
        field_path,
        "eds.assignments[payments-primary].endpoints[0].lb_endpoints[0]\
         .endpoint.address.socket_address.address"
    );
    assert!(
        reason.contains("without name resolution"),
        "the message must say why a hostname cannot be used, not just that it was refused: \
         {reason}"
    );
}

// ------------------------------------------------------------------ metadata --

/// The EDS half of endpoint-metadata lowering: an EDS-delivered `LbEndpoint.metadata` under the
/// `io.llmproxy.endpoint` namespace lowers into `EndpointIR::metadata` the
/// same way the static `load_assignment` path does (see
/// `endpoint_metadata.rs` for that half) -- this is the whole point for the
/// consumer who asked, since an operator-facing label attached only at
/// bootstrap-load time would never reach a host EDS adds later.
#[test]
fn an_eds_delivered_endpoints_metadata_lowers_into_endpoint_ir() {
    let la = assignment(
        "payments-primary",
        vec![vec![lb_endpoint_with_metadata(
            "10.0.0.1",
            8080,
            "io.llmproxy.endpoint",
            "region",
            string_value("us-east-1"),
        )]],
    );
    let any = any_of(&la, ENDPOINTS_TYPE);

    let (_, endpoints) = lower_dynamic_endpoints(&any, "eds.assignments[payments-primary]")
        .expect("io.llmproxy.endpoint metadata must lower");

    assert_eq!(endpoints.len(), 1);
    assert_eq!(
        endpoints[0].metadata.get("region").map(String::as_str),
        Some("us-east-1")
    );
}

/// `envoy.lb` on an EDS-delivered endpoint is refused exactly as it is on a
/// bootstrap-loaded one -- EDS gets no exemption from AGENTS.md invariant 1.
#[test]
fn an_eds_delivered_endpoints_envoy_lb_metadata_is_refused() {
    let la = assignment(
        "payments-primary",
        vec![vec![lb_endpoint_with_metadata(
            "10.0.0.1",
            8080,
            "envoy.lb",
            "canary",
            string_value("true"),
        )]],
    );
    let any = any_of(&la, ENDPOINTS_TYPE);

    let err = lower_dynamic_endpoints(&any, "eds.assignments[payments-primary]")
        .expect_err("envoy.lb must be refused over EDS too");
    let ConfigError::UnsupportedField { field_path, reason } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert_eq!(
        field_path,
        "eds.assignments[payments-primary].endpoints[0].lb_endpoints[0]\
         .metadata.filter_metadata[\"envoy.lb\"]"
    );
    assert!(
        reason.contains("subset routing"),
        "message must explain envoy.lb is a subset-routing selector, got: {reason}"
    );
}
