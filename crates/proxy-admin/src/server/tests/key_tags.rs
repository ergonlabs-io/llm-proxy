//! Chargeback tags as key metadata: set at mint and by `PUT /keys/{id}/tags`,
//! read back by the key listing, the key spend read and the authenticator.

use super::*;

fn key_tags_of(
    handle: &Arc<arc_swap::ArcSwap<proxy_control::control::ControlPlaneSnapshot>>,
    plaintext: &str,
) -> proxy_observability::chargeback::ChargebackTags {
    match test_authenticator(Arc::clone(handle)).authenticate(&headers_with_bearer(plaintext)) {
        AuthOutcome::Authenticated(principal) => (*principal.key_tags).clone(),
        _ => panic!("key must authenticate"),
    }
}

#[tokio::test]
async fn tags_set_at_mint_reach_the_listing_and_the_authenticated_principal() {
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
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a","tags":{"team":"infra","project":"search"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let minted: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        minted["tags"],
        serde_json::json!({"project": "search", "team": "infra"})
    );
    let plaintext = minted["key"].as_str().unwrap().to_owned();

    let (status, _, body) = request(addr, "GET", "/keys", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listing: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        listing["keys"][0]["tags"],
        serde_json::json!({"project": "search", "team": "infra"})
    );

    let tags = key_tags_of(&handle, &plaintext);
    assert_eq!(tags.get("team").map(String::as_str), Some("infra"));
    assert_eq!(tags.get("project").map(String::as_str), Some("search"));
}

#[tokio::test]
async fn put_key_tags_replaces_and_empty_map_clears() {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    let (_, _, body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a","tags":{"team":"infra"}}"#,
    )
    .await;
    let plaintext = serde_json::from_str::<serde_json::Value>(&body).unwrap()["key"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, _, body) = request(
        addr,
        "PUT",
        "/keys/key-a/tags",
        Some(ADMIN_TOKEN),
        r#"{"schema_version":2,"tags":{"project":"ads"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let tags = key_tags_of(&handle, &plaintext);
    assert_eq!(tags.len(), 1, "a PUT replaces, it does not merge: {tags:?}");
    assert_eq!(tags.get("project").map(String::as_str), Some("ads"));

    let (status, _, body) = request(
        addr,
        "PUT",
        &format!("/chains/{TEST_CHAIN_STAT_PREFIX}/keys/key-a/tags"),
        Some(ADMIN_TOKEN),
        r#"{"tags":{}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(key_tags_of(&handle, &plaintext).is_empty());
}

#[tokio::test]
async fn key_tag_writes_are_refused_when_invalid_unknown_or_revoked() {
    let (factory_state, _handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    // Invalid at mint: nothing is minted.
    let (status, _, body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a","tags":{"team":"in fra"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("tags"), "{body}");
    let (_, _, listing) = request(addr, "GET", "/keys", Some(ADMIN_TOKEN), "").await;
    assert!(listing.contains("\"count\":0"), "{listing}");

    mint_policy_test_key(addr).await;
    for bad in [
        r#"{"tags":{"Team":"infra"}}"#,
        r#"{"tags":{"team":"a,b"}}"#,
        r#"{"tags":{"team":"infra"},"extra":1}"#,
        r#"{}"#,
    ] {
        let (status, _, body) =
            request(addr, "PUT", "/keys/key-a/tags", Some(ADMIN_TOKEN), bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }

    let (status, _, _) = request(
        addr,
        "PUT",
        "/keys/nope/tags",
        Some(ADMIN_TOKEN),
        r#"{"tags":{"team":"infra"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _, _) = request(addr, "DELETE", "/keys/key-a", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, body) = request(
        addr,
        "PUT",
        "/keys/key-a/tags",
        Some(ADMIN_TOKEN),
        r#"{"tags":{"team":"infra"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // The write needs the admin bearer like every other key write.
    let (status, _, _) = request(addr, "PUT", "/keys/key-a/tags", None, r#"{"tags":{}}"#).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn key_spend_read_names_the_key_tags() {
    let (factory_state, _handle, _accumulator) =
        factory_state_with_control_plane_and_spend(Period::Monthly);
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    let (status, _, body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a","tags":{"team":"infra"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, _, body) = request(addr, "GET", "/keys/key-a/spend", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let spend: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(spend["tags"], serde_json::json!({"team": "infra"}));
}
