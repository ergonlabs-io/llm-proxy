//! Credential sources on budget writes and reads: a tenant budget's
//! `credential_source` scope (ADR-0007 decision 8) and a key budget's
//! `include_byok_in_limit` (amendment 1), and every budget rendering reports
//! them.

use proxy_credentials::CredentialSource;

use super::*;

/// A `credential_source` value that is neither `"platform"` nor `"tenant"`.
/// No 400 response may echo it back.
const REJECTED_SCOPE: &str = "scope-SENTINEL-7b2e";

/// The stored scope of `tenant`'s budget, read from the published snapshot.
fn stored_tenant_scope(
    handle: &Arc<arc_swap::ArcSwap<proxy_control::control::ControlPlaneSnapshot>>,
    tenant: &str,
) -> Option<(MicroUsd, CredentialSource)> {
    handle
        .load()
        .policies
        .get(tenant)
        .and_then(|p| p.budget)
        .map(|b| (b.max_micros, b.credential_source))
}

/// `key_id`'s stored budget and its `include_byok_in_limit`, read from the
/// published snapshot.
fn stored_key_budget(
    handle: &Arc<arc_swap::ArcSwap<proxy_control::control::ControlPlaneSnapshot>>,
    key_id: &str,
) -> Option<(MicroUsd, bool)> {
    handle
        .load()
        .key_budgets
        .get(&KeyId::new(key_id))
        .map(|b| (b.max_micros, b.include_byok_in_limit))
}

#[tokio::test]
async fn tenant_budget_scope_is_stored_and_reported_on_the_spend_read() {
    let (factory_state, handle, _accumulator) =
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
        "PUT",
        "/tenants/tenant-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":{"max_usd":"10.00","period":"monthly","credential_source":"tenant"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        stored_tenant_scope(&handle, "tenant-a"),
        Some((MicroUsd::from_micros(10_000_000), CredentialSource::Tenant)),
    );

    let (status, _, body) = request(
        addr,
        "GET",
        "/tenants/tenant-a/spend",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["credential_source"], "tenant", "{value}");
}

/// Absent `credential_source` is `platform`, and clearing the budget makes the
/// spend read report `null` like its other budget fields.
#[tokio::test]
async fn tenant_budget_without_credential_source_is_platform_and_clear_reports_null() {
    let (factory_state, handle, _accumulator) =
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
        "PUT",
        "/tenants/tenant-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":{"max_usd":"10.00","period":"monthly"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        stored_tenant_scope(&handle, "tenant-a"),
        Some((
            MicroUsd::from_micros(10_000_000),
            CredentialSource::Platform
        )),
    );
    let (status, _, body) = request(
        addr,
        "GET",
        "/tenants/tenant-a/spend",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(value["credential_source"], "platform", "{value}");

    let (status, _, body) = request(
        addr,
        "PUT",
        "/tenants/tenant-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":null}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, _, body) = request(
        addr,
        "GET",
        "/tenants/tenant-a/spend",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert!(
        value["credential_source"].is_null(),
        "an unlimited tenant has no budget scope to report: {value}"
    );
}

/// A bad `credential_source` is a 400 that names the field and nothing else,
/// and the previously stored budget survives untouched.
#[tokio::test]
async fn tenant_budget_with_an_unknown_credential_source_is_400_and_stores_nothing() {
    let (factory_state, handle, _spend) = factory_state_with_control_plane_and_spend(Period::Daily);
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
        "/tenants/tenant-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":{"max_usd":"5.00","period":"daily"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let rejected = [
        format!(
            r#"{{"budget":{{"max_usd":"9.00","period":"daily","credential_source":"{REJECTED_SCOPE}"}}}}"#
        ),
        r#"{"budget":{"max_usd":"9.00","period":"daily","credential_source":"Tenant"}}"#
            .to_string(),
        r#"{"budget":{"max_usd":"9.00","period":"daily","credential_source":""}}"#.to_string(),
        // The key-budget field is refused on a tenant budget, not ignored.
        r#"{"budget":{"max_usd":"9.00","period":"daily","include_byok_in_limit":true}}"#
            .to_string(),
    ];
    for body_text in &rejected {
        let (status, _, body) = request(
            addr,
            "PUT",
            "/tenants/tenant-a/budget",
            Some(ADMIN_TOKEN),
            body_text,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body.contains("credential_source"),
            "the 400 must name the field: {body}"
        );
        assert!(
            !body.contains(REJECTED_SCOPE),
            "the 400 must not echo the rejected value: {body}"
        );
        assert_eq!(
            stored_tenant_scope(&handle, "tenant-a"),
            Some((MicroUsd::from_micros(5_000_000), CredentialSource::Platform)),
            "a rejected write must not change the stored budget"
        );
    }
}

/// Starts an admin server with tenant `tenant-a` and its key `key-a`.
async fn server_with_key_a() -> (
    AdminServer,
    SocketAddr,
    Arc<arc_swap::ArcSwap<proxy_control::control::ControlPlaneSnapshot>>,
) {
    let (factory_state, handle, _accumulator) =
        factory_state_with_control_plane_and_spend(Period::Monthly);
    let (server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    let (status, _, body) = request(
        addr,
        "POST",
        "/tenants",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, _, body) = request(
        addr,
        "POST",
        "/keys",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"tenant-a","key_id":"key-a"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (server, addr, handle)
}

/// `include_byok_in_limit` is stored and reported on the listing and the
/// spend read; absent means `false` (ADR-0007 amendment 1).
#[tokio::test]
async fn key_budget_include_byok_in_limit_is_stored_and_reported_and_defaults_to_false() {
    let (_server, addr, handle) = server_with_key_a().await;

    for (body_text, expected) in [
        (
            r#"{"budget":{"max_usd":"3.00","period":"daily","include_byok_in_limit":true}}"#,
            true,
        ),
        (r#"{"budget":{"max_usd":"3.00","period":"daily"}}"#, false),
    ] {
        let (status, _, body) = request(
            addr,
            "PUT",
            "/keys/key-a/budget",
            Some(ADMIN_TOKEN),
            body_text,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert_eq!(
            stored_key_budget(&handle, "key-a"),
            Some((MicroUsd::from_micros(3_000_000), expected)),
            "{body_text}"
        );

        let (status, _, body) = request(addr, "GET", "/keys", Some(ADMIN_TOKEN), "").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(
            value["keys"][0]["budget"]["include_byok_in_limit"], expected,
            "{value}"
        );

        let (status, _, body) =
            request(addr, "GET", "/keys/key-a/spend", Some(ADMIN_TOKEN), "").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(value["include_byok_in_limit"], expected, "{value}");
    }
}

/// A key budget has no `credential_source` scope any more: naming one is a
/// 400 that points at `include_byok_in_limit`, never a silent reading, and
/// it stores nothing.
#[tokio::test]
async fn key_budget_with_a_credential_source_is_400_and_stores_nothing() {
    let (_server, addr, handle) = server_with_key_a().await;

    let (status, _, body) = request(
        addr,
        "PUT",
        "/keys/key-a/budget",
        Some(ADMIN_TOKEN),
        r#"{"budget":{"max_usd":"3.00","period":"daily"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    for scope in ["tenant", "platform", REJECTED_SCOPE] {
        let (status, _, body) = request(
            addr,
            "PUT",
            "/keys/key-a/budget",
            Some(ADMIN_TOKEN),
            &format!(
                r#"{{"budget":{{"max_usd":"9.00","period":"daily","credential_source":"{scope}"}}}}"#
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("include_byok_in_limit"), "{body}");
        assert!(
            !body.contains(REJECTED_SCOPE),
            "the 400 must not echo the rejected value: {body}"
        );
        assert_eq!(
            stored_key_budget(&handle, "key-a"),
            Some((MicroUsd::from_micros(3_000_000), false)),
            "a rejected write must not change the stored key budget"
        );
    }
}
