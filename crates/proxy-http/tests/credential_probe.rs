//! `ClusterCredentialProbe` against live local upstreams (ADR-0007 decision 10).
//!
//! Each upstream is a real listener on an ephemeral port that records the raw
//! request it received. Test (a) follows AGENTS.md invariant 6's negative
//! assertion: the tenant key must be present and the operator key absent from
//! the whole received request, with the two on different header names.
//!
//! Every await is bounded by `tokio::time::timeout`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::StatusCode;
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::resolver::FakeResolver;
use proxy_config::ir::{
    ClusterConfig, ClusterKind, ClusterName, DiscoveryType, EndpointIR, HeaderAppendAction,
    HeaderMutation, LbPolicy, ProviderRuntimeConfig, TenantCredentialSlot,
};
use proxy_http::credential_probe::{
    ClusterCredentialProbe, CredentialProbeOutcome, CredentialProbeRequest, TenantCredentialProbe,
    CREDENTIAL_PROBE_TIMEOUT,
};
use proxy_http::tenant_credentials::TenantSecret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

const BOUND: Duration = Duration::from_secs(10);
const OPERATOR_KEY: &str = "operator-key-SENTINEL";
const TENANT_KEY: &str = "tenant-key-SENTINEL";
const VERIFY_PATH: &str = "/api/v1/key";

type Seen = Arc<Mutex<Vec<String>>>;

/// An upstream that records each request head and answers `status`, or, when
/// `status` is `None`, accepts and never answers.
/// Recorded by a never-answering upstream when the probe closes the connection.
const CLOSED: &str = "<closed>";

async fn spawn_upstream(status: Option<u16>) -> (SocketAddr, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let record = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let record = record.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
                record
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).to_ascii_lowercase());
                match status {
                    Some(status) => {
                        let reply = format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(reply.as_bytes()).await;
                    }
                    // Never answer; record when the probe closes the
                    // connection, so a test can check nothing is left open.
                    None => {
                        let closed =
                            tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
                                .await;
                        if matches!(closed, Ok(Ok(0)) | Ok(Err(_))) {
                            record.lock().unwrap().push(CLOSED.to_owned());
                        }
                    }
                }
            });
        }
    });
    (addr, seen)
}

fn slot() -> TenantCredentialSlot {
    TenantCredentialSlot {
        provider: "openrouter".to_owned(),
        header: "authorization".to_owned(),
        value_prefix: "Bearer ".to_owned(),
        verify_path: Some(VERIFY_PATH.to_owned()),
    }
}

fn mutation(key: &str, value: &str) -> HeaderMutation {
    HeaderMutation {
        key: key.to_owned(),
        value: value.to_owned(),
        action: HeaderAppendAction::OverwriteIfExistsOrAdd,
    }
}

/// A static cluster whose operator key sits on `x-api-key`, a different
/// header from the slot's `authorization`, plus a non-credential header.
fn cluster(name: &str, addr: SocketAddr) -> ClusterConfig {
    ClusterConfig {
        eds: None,
        name: name.to_owned(),
        discovery: DiscoveryType::Static,
        lb_policy: LbPolicy::RoundRobin,
        connect_timeout: Duration::from_secs(5),
        endpoints: vec![EndpointIR {
            metadata: Default::default(),
            host: addr.ip().to_string(),
            port: addr.port(),
            weight: 1,
            priority: 0,
        }],
        kind: ClusterKind::Endpoints,
        transport_socket: None,
        per_connection_buffer_limit_bytes: 1 << 20,
        circuit_breakers: proxy_config::ir::CircuitBreakers::default(),
        upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
        request_headers_to_add: vec![
            mutation("x-api-key", OPERATOR_KEY),
            mutation("x-static-header", "kept-value"),
        ],
        // The cluster's path rewrite must not apply to the probe.
        request_path_rewrite: None,
        provider_runtime: Some(ProviderRuntimeConfig {
            credential: None,
            path_template: None,
            model_rewrites: Vec::new(),
            tenant_credential: Some(slot()),
        }),
        usage_dialect: None,
        health_check: None,
        outlier_detection: None,
    }
}

async fn probe_for(config: ClusterConfig, limit: Duration) -> ClusterCredentialProbe {
    let manager = ClusterManager::with_default_transport(Arc::new(FakeResolver::new()));
    let mut snapshot: HashMap<ClusterName, Arc<ClusterConfig>> = HashMap::new();
    snapshot.insert(config.name.clone(), Arc::new(config));
    manager.update_from_snapshot(&snapshot).await;
    ClusterCredentialProbe::with_timeout(Arc::new(manager), limit)
}

fn request(cluster: &str) -> CredentialProbeRequest {
    CredentialProbeRequest {
        cluster: cluster.to_owned(),
        slot: slot(),
        secret: TenantSecret::new(TENANT_KEY.to_owned()),
    }
}

async fn run(probe: &ClusterCredentialProbe, cluster: &str) -> CredentialProbeOutcome {
    timeout(BOUND, probe.probe(request(cluster)))
        .await
        .expect("probe must finish within the test bound")
}

#[tokio::test(flavor = "multi_thread")]
async fn ok_response_reports_status_and_sends_only_the_tenant_credential() {
    let (addr, seen) = spawn_upstream(Some(200)).await;
    let probe = probe_for(cluster("openrouter", addr), CREDENTIAL_PROBE_TIMEOUT).await;

    assert_eq!(
        run(&probe, "openrouter").await,
        CredentialProbeOutcome::Status(StatusCode::OK)
    );

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "one probe is one request");
    let text = &seen[0];
    assert!(
        text.starts_with(&format!("get {VERIFY_PATH} http/1.1\r\n")),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "authorization: bearer {}",
            TENANT_KEY.to_lowercase()
        )),
        "{text}"
    );
    assert!(text.contains("x-static-header: kept-value"), "{text}");
    assert!(
        text.contains(&format!("host: {addr}")),
        "host falls back to the selected host: {text}"
    );
    // Negative assertion: the operator key is on a different header than the
    // slot, and must be nowhere in the request.
    assert!(!text.contains(&OPERATOR_KEY.to_lowercase()), "{text}");
    assert!(!text.contains("x-api-key"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthorized_response_is_reported_as_401() {
    let (addr, _seen) = spawn_upstream(Some(401)).await;
    let probe = probe_for(cluster("openrouter", addr), CREDENTIAL_PROBE_TIMEOUT).await;
    assert_eq!(
        run(&probe, "openrouter").await,
        CredentialProbeOutcome::Status(StatusCode::UNAUTHORIZED)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unavailable_response_is_reported_as_503() {
    let (addr, _seen) = spawn_upstream(Some(503)).await;
    let probe = probe_for(cluster("openrouter", addr), CREDENTIAL_PROBE_TIMEOUT).await;
    assert_eq!(
        run(&probe, "openrouter").await,
        CredentialProbeOutcome::Status(StatusCode::SERVICE_UNAVAILABLE)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn closed_port_is_unreachable_without_leaking_the_key() {
    // Bind, learn the address, drop: reliably refused on loopback.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let probe = probe_for(cluster("openrouter", addr), CREDENTIAL_PROBE_TIMEOUT).await;

    match run(&probe, "openrouter").await {
        CredentialProbeOutcome::Unreachable(reason) => {
            assert!(!reason.contains(TENANT_KEY), "{reason}");
            assert!(!reason.contains(OPERATOR_KEY), "{reason}");
        }
        other => panic!("expected Unreachable, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_that_never_answers_times_out() {
    let (addr, seen) = spawn_upstream(None).await;
    let probe = probe_for(cluster("openrouter", addr), Duration::from_millis(300)).await;

    assert_eq!(
        run(&probe, "openrouter").await,
        CredentialProbeOutcome::TimedOut
    );
    assert!(
        seen.lock()
            .unwrap()
            .first()
            .is_some_and(|r| r.contains(VERIFY_PATH)),
        "the request did reach it"
    );
    // The timed-out probe must close its connection (and so free its
    // circuit-breaker slot) rather than leave the driver running.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !seen.lock().unwrap().iter().any(|r| r == CLOSED) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the probe left its connection open after timing out"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_cluster_is_unreachable() {
    let (addr, _seen) = spawn_upstream(Some(200)).await;
    let probe = probe_for(cluster("openrouter", addr), CREDENTIAL_PROBE_TIMEOUT).await;

    assert_eq!(
        run(&probe, "missing").await,
        CredentialProbeOutcome::Unreachable("cluster `missing` not found".to_owned())
    );
}

#[test]
fn request_debug_does_not_contain_the_secret() {
    assert!(!format!("{:?}", request("openrouter")).contains(TENANT_KEY));
}
