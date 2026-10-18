//! `PUT /tenants/{id}/objects/{object_id}`: assigning a provider object no
//! tenant owns to its tenant, so `llmproxy.object_ownership` admits it.

use super::*;

/// Registers what `ObjectOwnershipFilterFactory::create` registers: the
/// chain's owners, over the control plane's own store.
fn register_object_ownership(factory_state: &Arc<SharedFactoryState>) {
    let control_plane = factory_state
        .get_across_scopes(proxy_filters::auth_filter::TYPE_URL)
        .expect("one scope")
        .expect("a control plane")
        .downcast::<ControlPlane>()
        .expect("a ControlPlane");
    factory_state
        .get_or_try_init(
            TEST_CHAIN_SCOPE,
            TEST_CHAIN_STAT_PREFIX,
            proxy_filters::object_ownership_filter::TYPE_URL,
            || {
                Ok(Arc::new(proxy_filters::object_ownership::ObjectOwners::new(
                    control_plane.store(),
                )) as Arc<dyn std::any::Any + Send + Sync>)
            },
        )
        .expect("inserting the owners must not fail");
}

async fn server(ownership: bool) -> (AdminServer, SocketAddr, Arc<ControlPlane>) {
    let (factory_state, _) = factory_state_with_control_plane();
    if ownership {
        register_object_ownership(&factory_state);
    }
    let control_plane = factory_state
        .get_across_scopes(proxy_filters::auth_filter::TYPE_URL)
        .unwrap()
        .unwrap()
        .downcast::<ControlPlane>()
        .unwrap();
    let (server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    (server, addr, control_plane)
}

async fn create_tenant(addr: SocketAddr, tenant: &str) {
    let (status, _, body) = request(
        addr,
        "POST",
        "/tenants",
        Some(ADMIN_TOKEN),
        &format!(r#"{{"tenant":"{tenant}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

async fn assign(addr: SocketAddr, tenant: &str, object: &str) -> (StatusCode, String) {
    let (status, _, body) = request(
        addr,
        "PUT",
        &format!("/tenants/{tenant}/objects/{object}"),
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    (status, body)
}

/// An unowned object is assigned, assigning it again to the same tenant is
/// a no-op, and another tenant can never take it over.
#[tokio::test]
async fn an_unowned_object_is_assigned_once_and_never_reassigned() {
    let (_server, addr, control_plane) = server(true).await;
    create_tenant(addr, "tenant-a").await;
    create_tenant(addr, "tenant-b").await;

    let (status, body) = assign(addr, "tenant-a", "file-legacy").await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        control_plane.store().object_owner("file-legacy").unwrap(),
        Some(TenantId::new("tenant-a"))
    );
    let (status, body) = assign(addr, "tenant-a", "file-legacy").await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let read = |tenant: &'static str, object: &'static str| async move {
        let (status, _, body) = request(
            addr,
            "GET",
            &format!("/tenants/{tenant}/objects/{object}"),
            Some(ADMIN_TOKEN),
            "",
        )
        .await;
        (status, body)
    };
    let (status, body) = read("tenant-a", "file-legacy").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Another tenant's object and an unknown one read the same.
    let (other, other_body) = read("tenant-b", "file-legacy").await;
    let (unknown, unknown_body) = read("tenant-b", "file-unknown").await;
    assert_eq!(other, StatusCode::NOT_FOUND, "{other_body}");
    assert_eq!(unknown, StatusCode::NOT_FOUND, "{unknown_body}");
    assert_eq!(other_body, unknown_body);

    let (status, body) = assign(addr, "tenant-b", "file-legacy").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("object_owned"), "{body}");
    assert_eq!(
        control_plane.store().object_owner("file-legacy").unwrap(),
        Some(TenantId::new("tenant-a")),
        "the first owner is kept"
    );
}

/// Each refusal assigns nothing: an unknown tenant, a chain without the
/// filter, and a caller without the admin token.
#[tokio::test]
async fn refused_assignments_record_no_owner() {
    let (_server, addr, control_plane) = server(true).await;
    let (status, body) = assign(addr, "nobody", "file-1").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, _, body) = request(addr, "PUT", "/tenants/nobody/objects/file-1", None, "").await;
    assert!(status.is_client_error(), "{status}: {body}");
    assert_eq!(control_plane.store().object_owner("file-1").unwrap(), None);

    let (_server, addr, control_plane) = server(false).await;
    create_tenant(addr, "tenant-a").await;
    let (status, body) = assign(addr, "tenant-a", "file-1").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("not_enforced"), "{body}");
    assert_eq!(control_plane.store().object_owner("file-1").unwrap(), None);
}
