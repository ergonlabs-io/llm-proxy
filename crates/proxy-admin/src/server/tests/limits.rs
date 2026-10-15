use super::*;

fn register_token_limit_marker(
    factory_state: &Arc<SharedFactoryState>,
    scope: &str,
    stat_prefix: &str,
    type_url: &'static str,
) {
    factory_state
        .get_or_try_init(scope, stat_prefix, type_url, || {
            Ok(Arc::new(()) as Arc<dyn std::any::Any + Send + Sync>)
        })
        .expect("test token-limit marker registration");
}

#[tokio::test]
async fn put_tenant_limits_sets_and_clears_snapshot() {
    let (factory_state, handle) = factory_state_with_control_plane();
    register_token_limit_marker(
        &factory_state,
        TEST_CHAIN_SCOPE,
        TEST_CHAIN_STAT_PREFIX,
        proxy_filters::token_limit_filter::TYPE_URL,
    );
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    let (status, _, body) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/limits",
        Some(ADMIN_TOKEN),
        r#"{"schema_version":1,"limits":{"tokens_per_minute":0,"requests_per_minute":60}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let limits = handle.load().tenant_limits[&TenantId::new("tenant-a")];
    assert_eq!(limits.tokens_per_minute, Some(0));
    assert_eq!(limits.requests_per_minute, Some(60));
    assert_eq!(limits.concurrent_streams, None);

    let (status, _, body) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/limits",
        Some(ADMIN_TOKEN),
        r#"{"limits":null}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(handle.load().tenant_limits.is_empty());
}

#[tokio::test]
async fn put_key_limits_updates_listing_and_all_absent_clears() {
    let (factory_state, handle) = factory_state_with_control_plane();
    register_token_limit_marker(
        &factory_state,
        TEST_CHAIN_SCOPE,
        TEST_CHAIN_STAT_PREFIX,
        proxy_filters::token_limit_filter::TYPE_URL,
    );
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    mint_policy_test_key(addr).await;
    let (status, _, body) = request(
        addr,
        "PUT",
        "/keys/key-a/limits",
        Some(ADMIN_TOKEN),
        r#"{"limits":{"concurrent_streams":3}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        handle.load().key_limits[&KeyId::new("key-a")].concurrent_streams,
        Some(3)
    );
    let (status, _, body) = request(addr, "GET", "/keys", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listing: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        listing["keys"][0]["limits"],
        serde_json::json!({"concurrent_streams": 3})
    );

    let (status, _, body) = request(
        addr,
        "PUT",
        "/keys/key-a/limits",
        Some(ADMIN_TOKEN),
        r#"{"limits":{}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(handle.load().key_limits.is_empty());
}

#[tokio::test]
async fn put_limits_unknown_key_and_unknown_fields_do_not_write() {
    let (factory_state, handle) = factory_state_with_control_plane();
    register_token_limit_marker(
        &factory_state,
        TEST_CHAIN_SCOPE,
        TEST_CHAIN_STAT_PREFIX,
        proxy_filters::token_limit_filter::TYPE_URL,
    );
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    assert_eq!(
        request(
            addr,
            "PUT",
            "/keys/missing/limits",
            Some(ADMIN_TOKEN),
            r#"{"limits":{"requests_per_minute":1}}"#
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(
            addr,
            "PUT",
            "/tenants/tenant-a/limits",
            Some(ADMIN_TOKEN),
            r#"{"limits":{"unknown":1}}"#
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            addr,
            "PUT",
            "/tenants/tenant-a/limits",
            Some(ADMIN_TOKEN),
            r#"{"limits":null,"unknown":1}"#
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            addr,
            "PUT",
            "/tenants/tenant-a/limits",
            Some(ADMIN_TOKEN),
            r#"{}"#
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            addr,
            "PUT",
            "/tenants/tenant-a/limits",
            Some(ADMIN_TOKEN),
            r#"{"schema_version":2,"limits":null}"#
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert!(handle.load().key_limits.is_empty());
    assert!(handle.load().tenant_limits.is_empty());
}

#[tokio::test]
async fn put_limits_without_token_limit_is_409_and_stores_nothing() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    let (status, _, body) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/limits",
        Some(ADMIN_TOKEN),
        r#"{"limits":{"tokens_per_minute":1}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "not_enforced");
    assert!(error["detail"]
        .as_str()
        .unwrap()
        .contains("limits would not be enforced"));
    assert!(handle.load().tenant_limits.is_empty());
}

#[tokio::test]
async fn scoped_put_limits_uses_named_chain_and_legacy_type_url() {
    let factory_state = Arc::new(SharedFactoryState::default());
    let handle_a = register_control_plane(
        &factory_state,
        "listener 'a' filter_chains[0]",
        "chain-a",
        TEST_HMAC_SECRET,
    );
    let handle_b = register_control_plane(
        &factory_state,
        "listener 'b' filter_chains[0]",
        "chain-b",
        TEST_HMAC_SECRET,
    );
    register_token_limit_marker(
        &factory_state,
        "listener 'a' filter_chains[0]",
        "chain-a",
        proxy_filters::token_limit_filter::LEGACY_TYPE_URL,
    );
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    let (status, _, body) = request(
        addr,
        "PUT",
        "/chains/chain-a/tenants/tenant-a/limits",
        Some(ADMIN_TOKEN),
        r#"{"limits":{"requests_per_minute":7}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        handle_a.load().tenant_limits[&TenantId::new("tenant-a")].requests_per_minute,
        Some(7)
    );
    assert!(handle_b.load().tenant_limits.is_empty());
    let (status, _, body) = request(
        addr,
        "POST",
        "/chains/chain-a/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, _, body) = request(
        addr,
        "PUT",
        "/chains/chain-a/keys/key-a/limits",
        Some(ADMIN_TOKEN),
        r#"{"limits":{"concurrent_streams":2}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        handle_a.load().key_limits[&KeyId::new("key-a")].concurrent_streams,
        Some(2)
    );
    assert!(handle_b.load().key_limits.is_empty());
    let (status, _, body) = request(
        addr,
        "PUT",
        "/chains/chain-b/tenants/tenant-a/limits",
        Some(ADMIN_TOKEN),
        r#"{"limits":{"requests_per_minute":7}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(handle_b.load().tenant_limits.is_empty());
}
