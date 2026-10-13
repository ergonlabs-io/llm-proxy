use prost::Message;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};
const EXAMPLE: &str = include_str!("../../../examples/ext-authz.yaml");

fn load(text: &str) -> Result<proxy_config::ConfigSnapshot, proxy_config::ConfigError> {
    build_snapshot(&parse_bootstrap(
        text.as_bytes(),
        ConfigFormat::Yaml,
        StrictMode::Strict,
    )?)
}

#[test]
fn ext_authz_minimal_typed_bootstrap_and_timeout_default() {
    let snapshot = load(&EXAMPLE.replace("                        timeout: 0.2s\n", "")).unwrap();
    let listener = &snapshot.listeners["authorized_http"];
    let proxy_config::ir::NetworkFilterSpec::HttpConnectionManager(hcm) =
        &listener.filter_chains[0].filters[0]
    else {
        panic!()
    };
    let filter = &hcm.http_filters[0];
    assert!(
        filter.config.is_none(),
        "protobuf must not escape typed lowering"
    );
    let cfg = filter.ext_authz.as_ref().unwrap();
    assert_eq!(cfg.timeout, std::time::Duration::from_millis(200));
    assert_eq!(cfg.endpoint.unwrap().port(), 9001);
    assert_eq!(cfg.status_on_error, 403);
    assert!(!cfg.failure_mode_allow);
}

#[test]
fn ext_authz_rejects_unsupported_fields_and_invalid_values_with_full_paths() {
    for (old, new, path) in [
        (
            "validate_mutations: true",
            "validate_mutations: true\n                      with_request_body: {}",
            "typed_config.with_request_body",
        ),
        (
            "cluster_name: authorization",
            "cluster_name: authorization, authority: custom",
            "grpc_service.envoy_grpc.authority",
        ),
        ("timeout: 0.2s", "timeout: 0s", "grpc_service.timeout"),
        ("timeout: 0.2s", "timeout: 31s", "grpc_service.timeout"),
        ("timeout: 0.2s", "timeout: 0.0001s", "grpc_service.timeout"),
        (
            "transport_api_version: V3",
            "transport_api_version: V2",
            "transport_api_version",
        ),
        (
            "validate_mutations: true",
            "validate_mutations: false",
            "validate_mutations",
        ),
        (
            "encode_raw_headers: true",
            "encode_raw_headers: false",
            "encode_raw_headers",
        ),
        (
            "enable_dynamic_metadata_ingestion: false",
            "enable_dynamic_metadata_ingestion: true",
            "enable_dynamic_metadata_ingestion",
        ),
    ] {
        let error = load(&EXAMPLE.replacen(old, new, 1))
            .unwrap_err()
            .to_string();
        assert!(error.contains(path), "expected {path}: {error}");
        assert!(error.contains("static_resources.listeners[0]"), "{error}");
    }
}

#[test]
fn ext_authz_unknown_nested_field_and_unresolved_cluster_fail_before_traffic() {
    let unknown = EXAMPLE.replace(
        "cluster_name: authorization }",
        "cluster_name: authorization, unknown_field: 1 }",
    );
    assert!(load(&unknown)
        .unwrap_err()
        .to_string()
        .contains("unknown_field"));
    let missing = EXAMPLE.replacen("cluster_name: authorization", "cluster_name: missing", 1);
    assert!(load(&missing)
        .unwrap_err()
        .to_string()
        .contains("grpc_service.envoy_grpc.cluster_name"));
    let wrong_protocol = EXAMPLE.replace("http2_protocol_options: {}", "http_protocol_options: {}");
    assert!(load(&wrong_protocol)
        .unwrap_err()
        .to_string()
        .contains("plaintext HTTP/2"));
}

#[test]
fn ext_authz_dynamic_lds_is_rejected_before_acknowledgement() {
    let loaded =
        parse_bootstrap(EXAMPLE.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict).unwrap();
    let listener = &loaded.bootstrap.static_resources.unwrap().listeners[0];
    let any = prost_types::Any {
        type_url: "type.googleapis.com/envoy.config.listener.v3.Listener".into(),
        value: listener.encode_to_vec(),
    };
    let error = proxy_config::lower_dynamic_listener(&any, "lds.listeners[authorized_http]")
        .unwrap_err()
        .to_string();
    assert!(error.contains("lds.listeners[authorized_http]"));
    assert!(error.contains("bootstrap-only"));
}

#[test]
fn ext_authz_context_hierarchy_bounds_and_wrapper_paths_are_validated_before_traffic() {
    let context = |name: &str, prefix: &str, count: usize| {
        let extensions = (0..count)
            .map(|i| (format!("{prefix}{i}"), serde_json::json!("value")))
            .collect::<serde_json::Map<_, _>>();
        serde_yaml::to_value(serde_json::json!({name: {"@type": proxy_config::authorization::PER_ROUTE_TYPE_URL, "check_settings": {"context_extensions": extensions}}})).unwrap()
    };
    let mut document: serde_yaml::Value =
        serde_yaml::from_str(&EXAMPLE.replace("envoy.filters.http.ext_authz", "external_auth"))
            .unwrap();
    let hcm = &mut document["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"];
    hcm["route_config"]["typed_per_filter_config"] = context("external_auth", "fleet", 40);
    hcm["route_config"]["virtual_hosts"][0]["typed_per_filter_config"] =
        context("external_auth", "host", 40);
    let error = load(&serde_yaml::to_string(&document).unwrap())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("typed_per_filter_config[external_auth].check_settings.context_extensions"),
        "{error}"
    );

    let hcm = &mut document["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"];
    hcm["route_config"]["virtual_hosts"][0]["typed_per_filter_config"] = serde_yaml::to_value(serde_json::json!({"external_auth": {"@type": "type.googleapis.com/envoy.config.route.v3.FilterConfig", "disabled": true}})).unwrap();
    hcm["route_config"]["virtual_hosts"][0]["routes"][0]["typed_per_filter_config"] =
        context("external_auth", "route", 40);
    load(&serde_yaml::to_string(&document).unwrap()).unwrap();

    let hcm = &mut document["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"];
    let inner = context("external_auth", "overflow", 65)["external_auth"].clone();
    hcm["route_config"]["virtual_hosts"][0]["routes"][0]["typed_per_filter_config"] = serde_yaml::to_value(serde_json::json!({"external_auth": {"@type": "type.googleapis.com/envoy.config.route.v3.FilterConfig", "config": inner}})).unwrap();
    let error = load(&serde_yaml::to_string(&document).unwrap())
        .unwrap_err()
        .to_string();
    assert!(error.contains("typed_per_filter_config[external_auth].config.typed_config.check_settings.context_extensions"), "{error}");
}

#[test]
fn ext_authz_after_another_http_filter_is_rejected_with_its_path() {
    let block_start = EXAMPLE
        .find("                  - name: envoy.filters.http.ext_authz")
        .unwrap();
    let block_end = EXAMPLE
        .find("                  - name: envoy.filters.http.router")
        .unwrap();
    let ext_authz_block = &EXAMPLE[block_start..block_end];
    let second = EXAMPLE.replacen(
        "                  - name: envoy.filters.http.router",
        &format!("{ext_authz_block}                  - name: envoy.filters.http.router"),
        1,
    );
    let error = load(&second).unwrap_err().to_string();
    assert!(error.contains("http_filters[1].typed_config"), "{error}");
    assert!(
        error.contains("ext_authz must be the first HTTP filter"),
        "{error}"
    );
}
