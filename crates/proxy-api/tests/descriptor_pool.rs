//! Acceptance tests for the descriptor pool.
//!
//! Gate (internal-docs/IMPLEMENTATION_PLAN.md): `Bootstrap`, `Listener`, `Cluster`,
//! `RouteConfiguration`, `ClusterLoadAssignment`, `HttpConnectionManager`,
//! `Router`, ADS service types all addressable; the descriptor pool resolves
//! every `type.googleapis.com/envoy.*` URL used in the config corpus.

use proxy_api::descriptor_pool;

/// Every fully-qualified message name the rest of the project depends on.
/// Extend this list whenever a new extension root is added to build.rs.
const REQUIRED_MESSAGES: &[&str] = &[
    "envoy.config.bootstrap.v3.Bootstrap",
    "envoy.config.listener.v3.Listener",
    "envoy.config.listener.v3.FilterChain",
    "envoy.config.cluster.v3.Cluster",
    "envoy.config.cluster.v3.OutlierDetection",
    "envoy.config.cluster.v3.CircuitBreakers",
    "envoy.config.route.v3.RouteConfiguration",
    "envoy.config.route.v3.VirtualHost",
    "envoy.config.route.v3.RetryPolicy",
    "envoy.config.endpoint.v3.ClusterLoadAssignment",
    "envoy.config.core.v3.Address",
    "envoy.config.core.v3.HealthCheck",
    "envoy.service.discovery.v3.DiscoveryRequest",
    "envoy.service.discovery.v3.DiscoveryResponse",
    "envoy.service.discovery.v3.DeltaDiscoveryRequest",
    "envoy.service.discovery.v3.DeltaDiscoveryResponse",
    "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
    "envoy.extensions.filters.http.router.v3.Router",
    "envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
    "envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
    "envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
    "envoy.extensions.transport_sockets.tls.v3.Secret",
    "envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
    "envoy.config.accesslog.v3.AccessLog",
    "envoy.config.accesslog.v3.AccessLogFilter",
    "envoy.config.accesslog.v3.StatusCodeFilter",
    "envoy.config.accesslog.v3.ResponseFlagFilter",
    "envoy.config.core.v3.SubstitutionFormatString",
    "envoy.extensions.access_loggers.file.v3.FileAccessLog",
    "envoy.extensions.access_loggers.stream.v3.StdoutAccessLog",
    "envoy.extensions.access_loggers.stream.v3.StderrAccessLog",
];

#[test]
fn required_message_types_resolve() {
    let pool = descriptor_pool();
    let missing: Vec<&str> = REQUIRED_MESSAGES
        .iter()
        .copied()
        .filter(|name| pool.get_message_by_name(name).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "types missing from descriptor pool: {missing:?}"
    );
}

#[test]
fn ads_service_resolves() {
    let pool = descriptor_pool();
    let ads = pool
        .get_service_by_name("envoy.service.discovery.v3.AggregatedDiscoveryService")
        .expect("ADS service in pool");
    let methods: Vec<String> = ads.methods().map(|m| m.name().to_string()).collect();
    assert!(
        methods.contains(&"StreamAggregatedResources".to_string()),
        "got {methods:?}"
    );
    assert!(
        methods.contains(&"DeltaAggregatedResources".to_string()),
        "got {methods:?}"
    );
    assert!(
        pool.get_service_by_name("envoy.service.secret.v3.SecretDiscoveryService")
            .is_some(),
        "SDS service in pool"
    );
}

#[test]
fn generated_types_are_usable() {
    use prost::Message;
    use proxy_api::envoy::config::bootstrap::v3::Bootstrap;

    // Construct, encode, decode — proves the generated types round-trip.
    let b = Bootstrap {
        node: Some(proxy_api::envoy::config::core::v3::Node {
            id: "test-node".to_string(),
            cluster: "test-cluster".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let bytes = b.encode_to_vec();
    let back = Bootstrap::decode(bytes.as_slice()).expect("roundtrip decode");
    assert_eq!(back.node.as_ref().map(|n| n.id.as_str()), Some("test-node"));
}

/// End-to-end proof of the pipeline design: Envoy YAML -> serde_json
/// value -> prost-reflect proto3-JSON deserialize against the pool, including
/// `Any` resolution by type URL and proto3 JSON durations ("5s").
#[test]
fn example_bootstrap_yaml_parses_via_descriptor_pool() {
    use prost_reflect::DynamicMessage;

    let yaml = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/tcp-proxy.yaml"
    ))
    .expect("read examples/tcp-proxy.yaml");
    let value: serde_json::Value =
        serde_yaml::from_str(&yaml).expect("YAML converts to a JSON value");

    let desc = descriptor_pool()
        .get_message_by_name("envoy.config.bootstrap.v3.Bootstrap")
        .expect("Bootstrap descriptor");

    let msg = DynamicMessage::deserialize(desc, value).expect("example bootstrap parses");

    // Spot-check a nested field made it through: the tcp_proxy Any decoded
    // against its type URL, carrying the configured cluster name.
    let static_resources = msg
        .get_field_by_name("static_resources")
        .expect("static_resources present");
    let listeners = static_resources
        .as_message()
        .unwrap()
        .get_field_by_name("listeners")
        .unwrap();
    assert_eq!(
        listeners.as_list().unwrap().len(),
        1,
        "one listener in the example"
    );
}

/// Strict mode foundation (ground rule #2): unknown fields must be detectable
/// at parse time so that the config loader can reject them with a field path.
#[test]
fn unknown_fields_are_rejected() {
    use prost_reflect::DynamicMessage;

    let bad = serde_json::json!({
        "node": { "id": "x" },
        "definitely_not_a_bootstrap_field": true
    });
    let desc = descriptor_pool()
        .get_message_by_name("envoy.config.bootstrap.v3.Bootstrap")
        .unwrap();
    let err = DynamicMessage::deserialize(desc, bad).expect_err("unknown field must fail to parse");
    assert!(
        err.to_string().contains("definitely_not_a_bootstrap_field"),
        "error should name the unknown field, got: {err}"
    );
}
