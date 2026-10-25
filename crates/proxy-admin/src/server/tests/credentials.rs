//! Tenant provider credential routes (`/tenants/{id}/provider_credentials`),
//! driven over a real admin socket like the rest of `server/tests.rs`.

use super::*;
use proxy_http::credential_probe::{
    CredentialProbeOutcome, CredentialProbeRequest, TenantCredentialProbe,
};

/// A plaintext tenant key no response body, error message or listing may ever
/// contain.
const TENANT_KEY_SENTINEL: &str = "sk-tenant-SENTINEL-4d1e9a7c";

/// The provider name the fixture cluster's tenant-credential slot accepts.
const CRED_PROVIDER: &str = "openrouter";

const CRED_PATH: &str = "/tenants/acme/provider_credentials/openrouter";

/// One provider cluster named `name`, carrying a tenant credential slot for
/// [`CRED_PROVIDER`] with the given `verify_path`. Built field by field because
/// `ClusterConfig` is not `Clone`; it mirrors the fixture in `tests.rs`.
fn provider_cluster(name: &str, verify_path: Option<&str>) -> ClusterConfig {
    ClusterConfig {
        eds: None,
        name: name.to_string(),
        discovery: DiscoveryType::Static,
        lb_policy: LbPolicy::RoundRobin,
        connect_timeout: Duration::from_secs(5),
        endpoints: vec![EndpointIR {
            metadata: Default::default(),
            host: "10.0.0.5".to_string(),
            port: 8080,
            weight: 1,
            priority: 0,
        }],
        kind: ClusterKind::Endpoints,
        transport_socket: None,
        per_connection_buffer_limit_bytes: 1024 * 1024,
        circuit_breakers: Default::default(),
        upstream_protocol: UpstreamProtocol::Http1,
        request_headers_to_add: Vec::new(),
        usage_dialect: None,
        unanswered_usage: proxy_config::ir::UnansweredUsage::default(),
        request_path_rewrite: None,
        provider_runtime: Some(proxy_config::ir::ProviderRuntimeConfig {
            credential: None,
            path_template: None,
            model_rewrites: Vec::new(),
            request_field_policy: Default::default(),
            tenant_credential: Some(proxy_config::ir::TenantCredentialSlot {
                provider: CRED_PROVIDER.to_string(),
                header: "authorization".to_string(),
                value_prefix: "Bearer ".to_string(),
                verify_path: verify_path.map(str::to_string),
            }),
        }),
        health_check: None,
        outlier_detection: None,
    }
}

/// `snapshot_with_secret()` with one provider cluster per `(name, verify_path)`
/// entry, so `PUT` passes the "provider is enabled" check and the probe has a
/// slot cluster to choose from.
fn snapshot_with_slot_clusters(clusters: &[(&str, Option<&str>)]) -> Arc<ConfigSnapshot> {
    let mut snapshot = snapshot_with_secret();
    Arc::get_mut(&mut snapshot)
        .expect("fresh snapshot is uniquely owned")
        .clusters = clusters
        .iter()
        .map(|(name, verify_path)| {
            (
                name.to_string(),
                Arc::new(provider_cluster(name, *verify_path)),
            )
        })
        .collect();
    snapshot
}

/// A single `upstream` cluster carrying a tenant credential slot for
/// [`CRED_PROVIDER`], with the given `verify_path` (`None` means no probe can
/// verify a key for this provider).
fn snapshot_with_credential_slot(verify_path: Option<&str>) -> Arc<ConfigSnapshot> {
    snapshot_with_slot_clusters(&[("upstream", verify_path)])
}

/// The request a probe saw, reduced to what the tests assert on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SeenProbe {
    cluster: String,
    path: String,
    header: String,
    secret: String,
}

/// A [`TenantCredentialProbe`] that answers every call with one scripted
/// outcome and records what it was asked to dial. Never touches the network.
struct FakeProbe {
    outcome: CredentialProbeOutcome,
    seen: Mutex<Vec<SeenProbe>>,
}

impl FakeProbe {
    fn new(outcome: CredentialProbeOutcome) -> Arc<Self> {
        Arc::new(Self {
            outcome,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<SeenProbe> {
        self.seen.lock().unwrap().clone()
    }
}

impl TenantCredentialProbe for FakeProbe {
    // Rust note: `BoxFuture` is a type alias for a boxed, pinned trait object.
    // The fake spells it out because this test crate does not depend on
    // `futures`; `Box::pin(std::future::ready(..))` is the boxed form of an
    // already-finished future.
    fn probe(
        &self,
        request: CredentialProbeRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CredentialProbeOutcome> + Send>> {
        self.seen.lock().unwrap().push(SeenProbe {
            cluster: request.cluster,
            path: request.slot.verify_path.clone().unwrap_or_default(),
            header: request.slot.header.clone(),
            secret: request.secret.expose().to_string(),
        });
        Box::pin(std::future::ready(self.outcome.clone()))
    }
}

/// Registers a `ControlPlane` that has (`with_kek`) or lacks key-encryption
/// keys, under the standard test chain.
fn factory_state_with_credential_plane(with_kek: bool) -> Arc<SharedFactoryState> {
    use proxy_control::control::CredentialKeys;
    use proxy_control::tenant_credential_crypto::{CredentialKek, KeyRing};

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

/// Admin server with a credential-capable control plane, tenant `acme`, and
/// `probe` as the save-time probe (`None` means the probe is not wired).
async fn start_probed(
    snapshot: Arc<ConfigSnapshot>,
    with_kek: bool,
    probe: Option<Arc<dyn TenantCredentialProbe>>,
) -> (AdminServer, SocketAddr) {
    // Built directly rather than through `start_full`, which always passes
    // `credential_probe: None`.
    let config = SnapshotHandles::new().register(snapshot);
    let server = serve(
        "127.0.0.1:0".parse().unwrap(),
        AdminRuntime {
            config,
            registry: None,
            started_at: Instant::now(),
            factory_state: factory_state_with_credential_plane(with_kek),
            admin_token: Some(ADMIN_TOKEN.to_string()),
            readiness: None,
            cluster_state: None,
            ui: None,
            lifecycle: None,
            credential_probe: probe,
            ledger: None,
            trace_gate: None,
        },
    )
    .await
    .expect("admin server bind");
    let addr = server.local_addr();
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

/// Admin server with a credential-capable control plane and tenant `acme`, a
/// `verify_path`-less slot, and no probe.
async fn start_credentials(with_kek: bool) -> (AdminServer, SocketAddr) {
    start_probed(snapshot_with_credential_slot(None), with_kek, None).await
}

fn credential_body(key: &str) -> String {
    serde_json::json!({ "schema_version": 1, "api_key": key }).to_string()
}

/// A PUT body with `"verify": false`, for tests that are about storage rather
/// than the save-time probe.
fn unverified_body(key: &str) -> String {
    serde_json::json!({ "schema_version": 1, "api_key": key, "verify": false }).to_string()
}

/// The `error` object of a JSON error response.
fn error_object(body: &str) -> serde_json::Value {
    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    value["error"].clone()
}

/// The listing of `acme`'s stored credentials, as JSON.
async fn list_credentials(addr: SocketAddr) -> Vec<serde_json::Value> {
    let (status, _h, body) = request(
        addr,
        "GET",
        "/tenants/acme/provider_credentials",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let list: serde_json::Value = serde_json::from_str(&body).unwrap();
    list["credentials"].as_array().unwrap().clone()
}

#[tokio::test]
async fn put_then_get_returns_metadata_and_no_response_contains_the_plaintext() {
    let (_server, addr) = start_credentials(true).await;

    let (status, headers, body) = request(
        addr,
        "PUT",
        CRED_PATH,
        Some(ADMIN_TOKEN),
        &unverified_body(TENANT_KEY_SENTINEL),
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
        "verify:false stores a key unverified"
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
        (
            "verify of the wrong type",
            format!("{{\"schema_version\":1,\"api_key\":\"{TENANT_KEY_SENTINEL}\",\"verify\":\"yes\"}}"),
        ),
        (
            "verify as null",
            format!("{{\"schema_version\":1,\"api_key\":\"{TENANT_KEY_SENTINEL}\",\"verify\":null}}"),
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
        &unverified_body(TENANT_KEY_SENTINEL),
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
        snapshot_with_credential_slot(None),
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
        &unverified_body(TENANT_KEY_SENTINEL),
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
        &unverified_body(TENANT_KEY_SENTINEL),
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

/// The `verify_path` the default fixture's slot carries.
const VERIFY_PATH: &str = "/v1/models";

/// A plain `PUT` with the default `verify` (true).
async fn put_default(addr: SocketAddr) -> (StatusCode, String) {
    let (status, _h, body) = request(
        addr,
        "PUT",
        CRED_PATH,
        Some(ADMIN_TOKEN),
        &credential_body(TENANT_KEY_SENTINEL),
    )
    .await;
    (status, body)
}

fn probe_seen(cluster: &str, path: &str) -> SeenProbe {
    SeenProbe {
        cluster: cluster.to_string(),
        path: path.to_string(),
        header: "authorization".to_string(),
        secret: TENANT_KEY_SENTINEL.to_string(),
    }
}

#[tokio::test]
async fn verified_put_stores_with_verified_at_after_a_2xx_probe() {
    let probe = FakeProbe::new(CredentialProbeOutcome::Status(StatusCode::OK));
    let (_server, addr) = start_probed(
        snapshot_with_credential_slot(Some(VERIFY_PATH)),
        true,
        Some(probe.clone()),
    )
    .await;

    let (status, body) = put_default(addr).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.contains(TENANT_KEY_SENTINEL), "PUT leaked: {body}");
    let put: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(put["verified_at"].is_string(), "{body}");

    // The probe dialled the slot's cluster, at its path, with the candidate key.
    assert_eq!(
        probe.calls(),
        vec![probe_seen("upstream", VERIFY_PATH)],
        "the probe must see the slot cluster, its verify_path, and the key"
    );

    let listed = list_credentials(addr).await;
    assert_eq!(listed.len(), 1);
    assert!(listed[0]["verified_at"].is_string());
}

#[tokio::test]
async fn provider_401_or_403_is_422_credential_rejected_and_nothing_is_stored() {
    for upstream in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
        let probe = FakeProbe::new(CredentialProbeOutcome::Status(upstream));
        let (_server, addr) = start_probed(
            snapshot_with_credential_slot(Some(VERIFY_PATH)),
            true,
            Some(probe.clone()),
        )
        .await;

        let (status, body) = put_default(addr).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{upstream}: {body}"
        );
        assert!(!body.contains(TENANT_KEY_SENTINEL), "{upstream}: {body}");
        let error = error_object(&body);
        assert_eq!(error["type"], "credential_rejected", "{upstream}");
        assert_eq!(error["upstream_status"], upstream.as_u16(), "{upstream}");
        assert_eq!(probe.calls().len(), 1, "{upstream}");
        assert!(
            list_credentials(addr).await.is_empty(),
            "{upstream}: a rejected key was stored"
        );
    }
}

#[tokio::test]
async fn other_provider_status_is_502_with_upstream_status_and_nothing_is_stored() {
    for upstream in [
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::TOO_MANY_REQUESTS,
    ] {
        let probe = FakeProbe::new(CredentialProbeOutcome::Status(upstream));
        let (_server, addr) = start_probed(
            snapshot_with_credential_slot(Some(VERIFY_PATH)),
            true,
            Some(probe.clone()),
        )
        .await;

        let (status, body) = put_default(addr).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{upstream}: {body}");
        assert!(!body.contains(TENANT_KEY_SENTINEL), "{upstream}: {body}");
        let error = error_object(&body);
        assert_eq!(
            error["type"], "credential_verification_unavailable",
            "{upstream}"
        );
        assert_eq!(error["upstream_status"], upstream.as_u16(), "{upstream}");
        assert!(
            list_credentials(addr).await.is_empty(),
            "{upstream}: an unverified key was stored"
        );
    }
}

#[tokio::test]
async fn timed_out_and_unreachable_probes_are_502_without_upstream_status() {
    let outcomes = [
        CredentialProbeOutcome::TimedOut,
        CredentialProbeOutcome::Unreachable("connect refused".to_string()),
    ];
    for outcome in outcomes {
        let name = format!("{outcome:?}");
        let probe = FakeProbe::new(outcome);
        let (_server, addr) = start_probed(
            snapshot_with_credential_slot(Some(VERIFY_PATH)),
            true,
            Some(probe.clone()),
        )
        .await;

        let (status, body) = put_default(addr).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{name}: {body}");
        assert!(!body.contains(TENANT_KEY_SENTINEL), "{name}: {body}");
        // The Unreachable reason goes to the log, never into the reply.
        assert!(!body.contains("connect refused"), "{name}: {body}");
        let error = error_object(&body);
        assert_eq!(
            error["type"], "credential_verification_unavailable",
            "{name}"
        );
        assert!(
            error.get("upstream_status").is_none(),
            "{name}: no provider status was received, so none may be reported: {body}"
        );
        assert!(list_credentials(addr).await.is_empty(), "{name}: stored");
    }
}

/// Without key-encryption keys the key could not be stored, so it must not be
/// sent to the provider: 503 before the probe.
#[tokio::test]
async fn no_key_encryption_keys_is_503_before_the_probe() {
    let probe = FakeProbe::new(CredentialProbeOutcome::Status(StatusCode::OK));
    let (_server, addr) = start_probed(
        snapshot_with_credential_slot(Some(VERIFY_PATH)),
        false,
        Some(probe.clone()),
    )
    .await;

    let (status, body) = put_default(addr).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(
        error_object(&body)["type"],
        "tenant_credentials_not_configured"
    );
    assert!(
        probe.calls().is_empty(),
        "the candidate key reached the provider"
    );
}

#[tokio::test]
async fn verify_false_stores_unverified_and_never_calls_the_probe() {
    // A probe that would reject the key: if it were consulted, the PUT would
    // be a 422, so a 200 here shows it was skipped.
    let probe = FakeProbe::new(CredentialProbeOutcome::Status(StatusCode::UNAUTHORIZED));
    let (_server, addr) = start_probed(
        snapshot_with_credential_slot(Some(VERIFY_PATH)),
        true,
        Some(probe.clone()),
    )
    .await;

    let (status, _h, body) = request(
        addr,
        "PUT",
        CRED_PATH,
        Some(ADMIN_TOKEN),
        &unverified_body(TENANT_KEY_SENTINEL),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.contains(TENANT_KEY_SENTINEL), "{body}");
    let put: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(put["verified_at"].is_null(), "{body}");
    assert!(probe.calls().is_empty(), "verify:false must not probe");
    let listed = list_credentials(addr).await;
    assert_eq!(listed.len(), 1);
    assert!(listed[0]["verified_at"].is_null());
}

#[tokio::test]
async fn no_slot_with_a_verify_path_is_422_not_configured_and_nothing_is_stored() {
    let probe = FakeProbe::new(CredentialProbeOutcome::Status(StatusCode::OK));
    let (_server, addr) = start_probed(
        snapshot_with_credential_slot(None),
        true,
        Some(probe.clone()),
    )
    .await;

    let (status, body) = put_default(addr).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(!body.contains(TENANT_KEY_SENTINEL), "{body}");
    let error = error_object(&body);
    assert_eq!(error["type"], "credential_verification_not_configured");
    assert!(error.get("upstream_status").is_none(), "{body}");
    assert!(probe.calls().is_empty());
    assert!(list_credentials(addr).await.is_empty());
}

#[tokio::test]
async fn unwired_probe_is_422_not_configured_even_when_a_slot_has_a_verify_path() {
    let (_server, addr) =
        start_probed(snapshot_with_credential_slot(Some(VERIFY_PATH)), true, None).await;

    let (status, body) = put_default(addr).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(!body.contains(TENANT_KEY_SENTINEL), "{body}");
    assert_eq!(
        error_object(&body)["type"],
        "credential_verification_not_configured"
    );
    assert!(
        list_credentials(addr).await.is_empty(),
        "unverified key stored"
    );

    // The same server still stores a key the caller marks unverified.
    let (status, _h, body) = request(
        addr,
        "PUT",
        CRED_PATH,
        Some(ADMIN_TOKEN),
        &unverified_body(TENANT_KEY_SENTINEL),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(list_credentials(addr).await.len(), 1);
}

#[tokio::test]
async fn replacing_a_verified_key_with_verify_false_clears_verified_at() {
    let probe = FakeProbe::new(CredentialProbeOutcome::Status(StatusCode::OK));
    let (_server, addr) = start_probed(
        snapshot_with_credential_slot(Some(VERIFY_PATH)),
        true,
        Some(probe.clone()),
    )
    .await;

    let (status, body) = put_default(addr).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(list_credentials(addr).await[0]["verified_at"].is_string());

    let (status, _h, body) = request(
        addr,
        "PUT",
        CRED_PATH,
        Some(ADMIN_TOKEN),
        &unverified_body(TENANT_KEY_SENTINEL),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let put: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(put["verified_at"].is_null(), "{body}");
    assert_eq!(probe.calls().len(), 1, "only the verified PUT probes");
    assert!(list_credentials(addr).await[0]["verified_at"].is_null());
}

#[tokio::test]
async fn validation_errors_keep_their_codes_and_never_reach_the_probe() {
    let probe = FakeProbe::new(CredentialProbeOutcome::Status(StatusCode::OK));
    let (_server, addr) = start_probed(
        snapshot_with_credential_slot(Some(VERIFY_PATH)),
        true,
        Some(probe.clone()),
    )
    .await;
    let cases: Vec<(&str, &str, String, StatusCode, &str)> = vec![
        (
            "empty key",
            CRED_PATH,
            credential_body(""),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "whitespace-only key",
            CRED_PATH,
            credential_body(" \t "),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "verify of the wrong type",
            CRED_PATH,
            format!(
                "{{\"schema_version\":1,\"api_key\":\"{TENANT_KEY_SENTINEL}\",\"verify\":\"yes\"}}"
            ),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "unknown provider",
            "/tenants/acme/provider_credentials/not-a-provider",
            credential_body(TENANT_KEY_SENTINEL),
            StatusCode::UNPROCESSABLE_ENTITY,
            "provider_not_enabled",
        ),
        (
            "unknown tenant",
            "/tenants/ghost/provider_credentials/openrouter",
            credential_body(TENANT_KEY_SENTINEL),
            StatusCode::NOT_FOUND,
            "tenant_not_found",
        ),
    ];
    for (name, path, body, expected, error_type) in cases {
        let (status, _h, response) = request(addr, "PUT", path, Some(ADMIN_TOKEN), &body).await;
        assert_eq!(status, expected, "{name}: {response}");
        assert!(
            !response.contains(TENANT_KEY_SENTINEL),
            "{name}: {response}"
        );
        assert_eq!(error_object(&response)["type"], error_type, "{name}");
    }
    assert!(
        probe.calls().is_empty(),
        "a validation error reached the probe"
    );
    assert!(list_credentials(addr).await.is_empty());
}

#[tokio::test]
async fn probe_goes_to_the_first_slot_cluster_by_name_that_has_a_verify_path() {
    // `alpha` sorts first but carries no verify_path, so it is skipped;
    // `beta` is the first by name that can be probed.
    let snapshot =
        snapshot_with_slot_clusters(&[("zeta", Some("/z")), ("beta", Some("/b")), ("alpha", None)]);
    let probe = FakeProbe::new(CredentialProbeOutcome::Status(StatusCode::OK));
    let (_server, addr) = start_probed(snapshot, true, Some(probe.clone())).await;

    let (status, body) = put_default(addr).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(probe.calls(), vec![probe_seen("beta", "/b")]);
}
