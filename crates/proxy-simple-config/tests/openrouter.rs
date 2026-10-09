use proxy_simple_config::{lower_to_loaded, parse_simple_config_with_env};

#[test]
fn openrouter_example_builds_cluster_owned_auth_and_path_rewrite() {
    let config = parse_simple_config_with_env(
        include_str!("../../../examples/llmproxy-openrouter.yaml"),
        &|name| (name == "OPENROUTER_API_KEY").then(|| "test-router-key".into()),
    )
    .unwrap();
    let loaded = lower_to_loaded(&config).unwrap();
    let snapshot = proxy_config::build_snapshot(&loaded).unwrap();
    let cluster = &snapshot.clusters["provider:openrouter"];
    let rewrite = cluster.request_path_rewrite.as_ref().unwrap();
    assert_eq!(rewrite.match_prefix, "/v1");
    assert_eq!(rewrite.replacement_prefix, "/api/v1");
    assert_eq!(rewrite.query, None);
    assert_eq!(
        config.providers["openrouter"]
            .effective_base_url("openrouter")
            .as_deref(),
        Some("https://openrouter.ai")
    );
}

#[test]
fn explicit_openrouter_type_works_with_custom_provider_name() {
    let config = parse_simple_config_with_env(
        "version: 0\nproviders:\n  gateway: { type: openrouter, api_key: test }\nroutes:\n  - { model: '*', provider: gateway }\n",
        &|_| None,
    ).unwrap();
    let loaded = lower_to_loaded(&config).unwrap();
    let snapshot = proxy_config::build_snapshot(&loaded).unwrap();
    assert_eq!(
        snapshot.clusters["provider:gateway"]
            .request_path_rewrite
            .as_ref()
            .unwrap()
            .replacement_prefix,
        "/api/v1"
    );
}

#[test]
fn openrouter_rejects_endpoint_path_in_base_url() {
    let config = parse_simple_config_with_env(
        "version: 0\nproviders:\n  openrouter: { base_url: 'https://openrouter.ai/api/v1' }\nroutes:\n  - { model: '*', provider: openrouter }\n",
        &|_| None,
    ).unwrap();
    let error = lower_to_loaded(&config).err().unwrap().to_string();
    assert!(error.contains("providers.openrouter.base_url"), "{error}");
}

#[test]
fn configured_catalog_lists_aliases_and_excludes_wildcards() {
    let config = parse_simple_config_with_env(
        "version: 0\nproviders:\n  openrouter: {}\nroutes: []\nmodels:\n  local-alias: { providers: [openrouter/upstream/model] }\n  vendor/model: { providers: [openrouter] }\n  '*': { providers: [openrouter] }\n",
        &|_| None,
    ).unwrap();
    let lowered = proxy_simple_config::lower(&config).unwrap();
    let routes = lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["route_config"]["virtual_hosts"][0]["routes"]
        .as_array()
        .unwrap();
    let catalog = routes
        .iter()
        .find(|route| route["name"] == "llmproxy_model_catalog")
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(
        catalog["direct_response"]["body"]["inline_string"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["local-alias", "vendor/model"]
    );
    let index = routes
        .iter()
        .position(|route| route["name"] == "llmproxy_model_catalog")
        .unwrap();
    assert!(routes[index + 1]["match"]["headers"].is_null());
}
