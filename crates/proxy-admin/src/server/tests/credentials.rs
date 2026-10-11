//! Tenant provider credential routes (`/tenants/{id}/provider_credentials`),
//! driven over a real admin socket like the rest of `server/tests.rs`.

use super::*;

/// A plaintext tenant key no response body, error message or listing may ever
/// contain.
const TENANT_KEY_SENTINEL: &str = "sk-tenant-SENTINEL-4d1e9a7c";

/// The provider name the fixture cluster's tenant-credential slot accepts.
const CRED_PROVIDER: &str = "openrouter";

const CRED_PATH: &str = "/tenants/acme/provider_credentials/openrouter";

/// `snapshot_with_secret()` with the single cluster carrying a tenant
/// credential slot for [`CRED_PROVIDER`], so `PUT` passes the
/// "provider is enabled" check.
fn snapshot_with_credential_slot() -> Arc<ConfigSnapshot> {
    let mut snapshot = snapshot_with_secret();
    let clusters = &mut Arc::get_mut(&mut snapshot)
        .expect("fresh snapshot is uniquely owned")
        .clusters;
    let cluster = Arc::get_mut(clusters.get_mut("upstream").expect("fixture cluster"))
        .expect("fresh cluster is uniquely owned");
    cluster.provider_runtime = Some(proxy_config::ir::ProviderRuntimeConfig {
        credential: None,
        path_template: None,
        model_rewrites: Vec::new(),
        tenant_credential: Some(proxy_config::ir::TenantCredentialSlot {
            provider: CRED_PROVIDER.to_string(),
            header: "authorization".to_string(),
            value_prefix: "Bearer ".to_string(),
            verify_path: None,
        }),
    });
    snapshot
}

/// Registers a `ControlPlane` that has (`with_kek`) or lacks key-encryption
/// keys, under the standard test chain.
fn factory_state_with_credential_plane(with_kek: bool) -> Arc<SharedFactoryState> {
    use proxy_filters::control::CredentialKeys;
    use proxy_filters::tenant_credential_crypto::{CredentialKek, KeyRing};

    let keys = with_kek.then(|| {
        let kek = CredentialKek::from_bytes("k1", *b"0123456789abcdef0123456789abcdef").unwrap();
        CredentialKeys::new(KeyRing::new(kek, Vec::new()).unwrap(), TEST_HMAC_SECRET)
    });
    let control_plane = ControlPlane::new_with_credential_keys(
        Box::new(InMemoryControlPlaneStore::default()),
        HmacSecret::new(TEST_HMAC_SECRET),
        KeySet::new(),
        keys,
    )
    .expect("an empty store must not fail ControlPlane::new");
    let factory_state = Arc::new(SharedFactoryState::default());
    factory_state
        .get_or_try_init(
            TEST_CHAIN_SCOPE,
            TEST_CHAIN_STAT_PREFIX,
            auth_filter::TYPE_URL,
            || Ok(Arc::new(control_plane) as Arc<dyn std::any::Any + Send + Sync>),
        )
        .expect("inserting the test ControlPlane singleton must not fail");
    factory_state
}

/// Admin server with a credential-capable control plane and tenant `acme`.
async fn start_credentials(with_kek: bool) -> (AdminServer, SocketAddr) {
    let (server, addr) = start_full(
        snapshot_with_credential_slot(),
        None,
        factory_state_with_credential_plane(with_kek),
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    let (status, ..) = request(
        addr,
        "POST",
        "/tenants",
        Some(ADMIN_TOKEN),
        r#"{"tenant":"acme"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    (server, addr)
}

fn credential_body(key: &str) -> String {
    serde_json::json!({ "schema_version": 1, "api_key": key }).to_string()
}

#[tokio::test]
async fn put_then_get_returns_metadata_and_no_response_contains_the_plaintext() {
    let (_server, addr) = start_credentials(true).await;

    let (status, headers, body) = request(
        addr,
        "PUT",
        CRED_PATH,
        Some(ADMIN_TOKEN),
        &credential_body(TENANT_KEY_SENTINEL),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers["content-type"], "application/json");
    assert!(!body.contains(TENANT_KEY_SENTINEL), "PUT leaked: {body}");
    let put: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(put["tenant"], "acme");
    assert_eq!(put["provider"], CRED_PROVIDER);
    assert_eq!(
        put["last4"],
        &TENANT_KEY_SENTINEL[TENANT_KEY_SENTINEL.len() - 4..]
    );
    assert!(
        put["verified_at"].is_null(),
        "the save-time probe is deferred, so a stored key is unverified"
    );

    let (status, _h, body) = request(
        addr,
        "GET",
        "/tenants/acme/provider_credentials",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains(TENANT_KEY_SENTINEL), "GET leaked: {body}");
    let list: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(list["schema_version"], 1);
    assert_eq!(list["tenant"], "acme");
    let credentials = list["credentials"].as_array().unwrap();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0]["provider"], CRED_PROVIDER);
    assert_eq!(credentials[0]["last4"], put["last4"]);
    assert_eq!(credentials[0]["fingerprint"], put["fingerprint"]);

    // The config dump is unauthenticated: it must not carry the key either.
    let (_, dump) = get(addr, "/config_dump").await;
    assert!(!dump.contains(TENANT_KEY_SENTINEL));
}

#[tokio::test]
async fn put_rejects_invalid_bodies_with_400_and_never_echoes_them() {
    let (_server, addr) = start_credentials(true).await;
    let long_key = "k".repeat(4097);
    let cases: Vec<(&str, String)> = vec![
        (
            "malformed json",
            format!("{{\"schema_version\":1,\"api_key\":\"{TENANT_KEY_SENTINEL}"),
        ),
        (
            "unknown field",
            format!(
                "{{\"schema_version\":1,\"api_key\":\"{TENANT_KEY_SENTINEL}\",\"{TENANT_KEY_SENTINEL}\":1}}"
            ),
        ),
        (
            "wrong schema version",
            serde_json::json!({"schema_version": 2, "api_key": TENANT_KEY_SENTINEL}).to_string(),
        ),
        (
            "missing schema version",
            serde_json::json!({"api_key": TENANT_KEY_SENTINEL}).to_string(),
        ),
        ("missing api_key", r#"{"schema_version":1}"#.to_string()),
        (
            "api_key of the wrong type",
            r#"{"schema_version":1,"api_key":7}"#.to_string(),
        ),
        ("empty key", credential_body("")),
        ("whitespace-only key", credential_body("  \t ")),
        ("over 4096 bytes", credential_body(&long_key)),
        (
            "LF in key",
            credential_body(&format!("{TENANT_KEY_SENTINEL}\nx-evil: 1")),
        ),
        (
            "CR in key",
            credential_body(&format!("{TENANT_KEY_SENTINEL}\rx")),
        ),
        (
            "NUL in key",
            credential_body(&format!("{TENANT_KEY_SENTINEL}\u{0}")),
        ),
        (
            "non-ASCII in key",
            credential_body(&format!("{TENANT_KEY_SENTINEL}\u{e9}")),
        ),
    ];
    for (name, body) in cases {
        let (status, _h, response) =
            request(addr, "PUT", CRED_PATH, Some(ADMIN_TOKEN), &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {response}");
        assert!(
            !response.contains(TENANT_KEY_SENTINEL),
            "{name}: error response echoed the key: {response}"
        );
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["error"]["type"], "invalid_request", "{name}");
    }
    // Nothing was stored by any rejected request.
    let (_s, _h, body) = request(
        addr,
        "GET",
        "/tenants/acme/provider_credentials",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    let list: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(list["credentials"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn unknown_tenant_is_404_for_put_get_and_delete() {
    let (_server, addr) = start_credentials(true).await;
    for (method, path, body) in [
        (
            "PUT",
            "/tenants/ghost/provider_credentials/openrouter",
            credential_body(TENANT_KEY_SENTINEL),
        ),
        ("GET", "/tenants/ghost/provider_credentials", String::new()),
        (
            "DELETE",
            "/tenants/ghost/provider_credentials/openrouter",
            String::new(),
        ),
    ] {
        let (status, _h, response) = request(addr, method, path, Some(ADMIN_TOKEN), &body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {response}");
        assert!(!response.contains(TENANT_KEY_SENTINEL));
    }
}

#[tokio::test]
async fn put_for_a_provider_no_cluster_accepts_is_422_provider_not_enabled() {
    let (_server, addr) = start_credentials(true).await;
    let (status, _h, body) = request(
        addr,
        "PUT",
        "/tenants/acme/provider_credentials/not-a-provider",
        Some(ADMIN_TOKEN),
        &credential_body(TENANT_KEY_SENTINEL),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(!body.contains(TENANT_KEY_SENTINEL));
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["error"]["type"], "provider_not_enabled");
}

#[tokio::test]
async fn put_without_key_encryption_keys_is_503_tenant_credentials_not_configured() {
    let (_server, addr) = start_credentials(false).await;
    let (status, _h, body) = request(
        addr,
        "PUT",
        CRED_PATH,
        Some(ADMIN_TOKEN),
        &credential_body(TENANT_KEY_SENTINEL),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(!body.contains(TENANT_KEY_SENTINEL));
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["error"]["type"], "tenant_credentials_not_configured");
}

#[tokio::test]
async fn credential_routes_are_gated_like_the_other_tenant_writes() {
    let (_server, addr) = start_credentials(true).await;
    for (method, path) in [
        ("PUT", CRED_PATH),
        ("GET", "/tenants/acme/provider_credentials"),
        ("DELETE", CRED_PATH),
    ] {
        let body = credential_body(TENANT_KEY_SENTINEL);
        let (status, headers, response) = request(addr, method, path, None, &body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert!(headers.contains_key("www-authenticate"));
        assert!(!response.contains(TENANT_KEY_SENTINEL));
        let (status, ..) = request(addr, method, path, Some("wrong-token"), &body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
    }

    // With no admin token configured at all, unset never means open.
    let (_open, open_addr) = start_full(
        snapshot_with_credential_slot(),
        None,
        factory_state_with_credential_plane(true),
        None,
    )
    .await;
    for (method, path) in [
        ("PUT", CRED_PATH),
        ("GET", "/tenants/acme/provider_credentials"),
        ("DELETE", CRED_PATH),
    ] {
        let (status, ..) = request(
            open_addr,
            method,
            path,
            Some(ADMIN_TOKEN),
            &credential_body(TENANT_KEY_SENTINEL),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
    }
}

#[tokio::test]
async fn chain_scoped_credential_routes_work_and_unknown_chain_is_404() {
    let (_server, addr) = start_credentials(true).await;
    let base = format!("/chains/{TEST_CHAIN_STAT_PREFIX}/tenants/acme/provider_credentials");

    let (status, _h, body) = request(
        addr,
        "PUT",
        &format!("{base}/openrouter"),
        Some(ADMIN_TOKEN),
        &credential_body(TENANT_KEY_SENTINEL),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.contains(TENANT_KEY_SENTINEL));

    let (status, _h, body) = request(addr, "GET", &base, Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::OK);
    let list: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(list["credentials"].as_array().unwrap().len(), 1);

    let (status, ..) = request(
        addr,
        "DELETE",
        &format!("{base}/openrouter"),
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, ..) = request(
        addr,
        "GET",
        "/chains/nope/tenants/acme/provider_credentials",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_credential_is_204_then_404_and_removes_it_from_the_listing() {
    let (_server, addr) = start_credentials(true).await;
    let (status, ..) = request(
        addr,
        "PUT",
        CRED_PATH,
        Some(ADMIN_TOKEN),
        &credential_body(TENANT_KEY_SENTINEL),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _h, body) = request(addr, "DELETE", CRED_PATH, Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty());
    let (status, ..) = request(addr, "DELETE", CRED_PATH, Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (_s, _h, body) = request(
        addr,
        "GET",
        "/tenants/acme/provider_credentials",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    let list: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(list["credentials"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn credential_route_with_a_wrong_verb_is_405() {
    let (_server, addr) = start_credentials(true).await;
    let (status, ..) = request(addr, "POST", CRED_PATH, Some(ADMIN_TOKEN), "{}").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (status, ..) = request(
        addr,
        "PUT",
        "/tenants/acme/provider_credentials",
        Some(ADMIN_TOKEN),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}
