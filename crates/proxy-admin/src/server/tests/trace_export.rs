//! `PUT`/`GET /tenants/{id}/trace_export`: a tenant's consent to trace
//! export (ADR-0008 decision 2).

use super::*;

async fn server() -> (
    AdminServer,
    SocketAddr,
    Arc<arc_swap::ArcSwap<proxy_filters::control::ControlPlaneSnapshot>>,
) {
    let (factory_state, handle) = factory_state_with_control_plane();
    let (server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    (server, addr, handle)
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

/// An opt-in reaches the snapshot the auth filter pins requests from, the
/// read reports it, and an opt-out removes it; another tenant is untouched.
#[tokio::test]
async fn an_opt_in_reaches_the_snapshot_and_an_opt_out_removes_it() {
    let (_server, addr, handle) = server().await;
    create_tenant(addr, "tenant-a").await;
    create_tenant(addr, "tenant-b").await;
    let put = |enabled: bool| {
        let body = format!(r#"{{"schema_version":1,"enabled":{enabled}}}"#);
        async move {
            request(
                addr,
                "PUT",
                "/tenants/tenant-a/trace_export",
                Some(ADMIN_TOKEN),
                &body,
            )
            .await
        }
    };
    let get = |tenant: &'static str| async move {
        let (status, _, body) = request(
            addr,
            "GET",
            &format!("/tenants/{tenant}/trace_export"),
            Some(ADMIN_TOKEN),
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["enabled"].clone()
    };

    assert_eq!(get("tenant-a").await, serde_json::json!(false));
    let (status, _, body) = put(true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(handle
        .load()
        .trace_export
        .contains(&TenantId::new("tenant-a")));
    assert_eq!(get("tenant-a").await, serde_json::json!(true));
    assert_eq!(get("tenant-b").await, serde_json::json!(false));

    let (status, _, body) = put(false).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(handle.load().trace_export.is_empty());
}

/// Each refusal leaves nothing opted in: an unknown tenant, a body that is
/// not exactly the documented shape, an id too long to name a segment
/// directory once encoded, and a caller without the admin token.
#[tokio::test]
async fn refused_writes_record_no_consent() {
    let (_server, addr, handle) = server().await;
    create_tenant(addr, "tenant-a").await;
    // 65 bytes; `~` percent-encodes to three, so `tenant=` plus 195 is over
    // the 200-byte bound, while 64 of them would fit.
    let long = "~".repeat(65);
    create_tenant(addr, &long).await;
    let enable = r#"{"schema_version":1,"enabled":true}"#;
    for (path, token, body, want) in [
        (
            "/tenants/nobody/trace_export",
            Some(ADMIN_TOKEN),
            enable,
            StatusCode::NOT_FOUND,
        ),
        (
            "/tenants/tenant-a/trace_export",
            Some(ADMIN_TOKEN),
            r#"{"enabled":true}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            "/tenants/tenant-a/trace_export",
            Some(ADMIN_TOKEN),
            r#"{"schema_version":2,"enabled":true}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            "/tenants/tenant-a/trace_export",
            Some(ADMIN_TOKEN),
            r#"{"schema_version":1,"enabled":true,"directions":["request"]}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            "/tenants/tenant-a/trace_export",
            None,
            enable,
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let (status, _, response) = request(addr, "PUT", path, token, body).await;
        assert_eq!(status, want, "{path} {body}: {response}");
    }
    let (status, _, response) = request(
        addr,
        "PUT",
        &format!("/tenants/{long}/trace_export"),
        Some(ADMIN_TOKEN),
        enable,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(response.contains("tenant_id_too_long"), "{response}");
    assert!(handle.load().trace_export.is_empty());
}
