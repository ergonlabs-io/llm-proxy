//! The cluster-owned OAuth2 JWT-bearer credential (ADR-0005, amendment
//! 2026-10-17), driven through `ClusterManager::update_from_snapshot` against a
//! local mock token endpoint. No real provider and no real key: the RSA key is
//! generated for the test run.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use proxy_cluster::manager::ClusterManager;
use proxy_cluster::resolver::TokioResolver;
use proxy_config::ir::{
    CircuitBreakers, ClusterConfig, ClusterKind, DiscoveryType, EndpointIR, LbPolicy,
    OAuth2JwtBearer, ProviderCredential, ProviderRuntimeConfig, RsaSigningKey, UpstreamProtocol,
};

const PROVIDER: &str = "provider:vertex";
const TOKEN_CLUSTER: &str = "oauth2-token:vertex";
const TOKEN_URL: &str = "http://token.test/oauth2/token";
/// Bounds every wait on the background refresher.
const WAIT: Duration = Duration::from_secs(10);

/// A PKCS#8 PEM RSA key, generated once per build directory and reused, since
/// RSA key generation takes seconds in a debug build. Never committed.
fn test_key_pem() -> String {
    use rsa::pkcs8::EncodePrivateKey;
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("oauth2-test-key.pem");
    if let Ok(pem) = std::fs::read_to_string(&path) {
        if RsaSigningKey::from_pkcs8_pem(&pem).is_ok() {
            return pem;
        }
    }
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("generate RSA key");
    let pem = key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("encode key")
        .to_string();
    // Write then rename, so a concurrent test never reads half a key.
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&tmp, &pem).expect("write key");
    std::fs::rename(&tmp, &path).expect("publish key");
    pem
}

/// One scripted reply: `(status, body)`. The last one repeats.
type Reply = (u16, String);

fn token(access_token: &str, expires_in: u64) -> Reply {
    (
        200,
        serde_json::json!({
            "access_token": access_token,
            "expires_in": expires_in,
            "token_type": "Bearer",
        })
        .to_string(),
    )
}

/// One recorded token request: path, headers, form body.
type Recorded = (String, Vec<(String, String)>, String);

/// A token endpoint that answers from a script and records each request's
/// path, headers and form body.
struct MockTokenEndpoint {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Recorded>>>,
    task: tokio::task::JoinHandle<()>,
}

impl MockTokenEndpoint {
    async fn spawn(script: Vec<Reply>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(script);
        let seen = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let (seen, script) = (Arc::clone(&seen), Arc::clone(&script));
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let (seen, script) = (Arc::clone(&seen), Arc::clone(&script));
                            async move {
                                let path = req.uri().path().to_string();
                                let headers = req
                                    .headers()
                                    .iter()
                                    .map(|(n, v)| {
                                        (n.to_string(), v.to_str().unwrap_or_default().to_string())
                                    })
                                    .collect();
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                let body = String::from_utf8_lossy(&body).to_string();
                                let index = {
                                    let mut seen = seen.lock().unwrap();
                                    seen.push((path, headers, body));
                                    seen.len() - 1
                                };
                                let (status, reply) = &script[index.min(script.len() - 1)];
                                Ok::<_, std::convert::Infallible>(
                                    hyper::Response::builder()
                                        .status(*status)
                                        .header("content-type", "application/json")
                                        .body(Full::new(Bytes::from(reply.clone())))
                                        .unwrap(),
                                )
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            addr,
            requests,
            task,
        }
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Drop for MockTokenEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn cluster(
    name: &str,
    addr: SocketAddr,
    provider_runtime: Option<ProviderRuntimeConfig>,
) -> ClusterConfig {
    ClusterConfig {
        eds: None,
        name: name.to_string(),
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
        circuit_breakers: CircuitBreakers::default(),
        upstream_protocol: UpstreamProtocol::Http1,
        request_headers_to_add: Vec::new(),
        request_path_rewrite: None,
        provider_runtime,
        usage_dialect: None,
        health_check: None,
        outlier_detection: None,
    }
}

fn oauth2(pem: &str, refresh_before: Duration) -> OAuth2JwtBearer {
    OAuth2JwtBearer {
        token_cluster: TOKEN_CLUSTER.to_string(),
        token_url: TOKEN_URL.to_string(),
        issuer: "svc@example.test".to_string(),
        subject: Some("user@example.test".to_string()),
        key_id: Some("key-1".to_string()),
        private_key: RsaSigningKey::from_pkcs8_pem(pem).expect("test key"),
        scopes: vec!["scope.a".to_string(), "scope.b".to_string()],
        audience: "https://audience.test".to_string(),
        assertion_lifetime: Duration::from_secs(600),
        refresh_before,
        request_timeout: Duration::from_secs(5),
    }
}

/// Installs the provider cluster and its token cluster the way a config load
/// does, and returns the manager.
async fn install(endpoint: &MockTokenEndpoint, config: OAuth2JwtBearer) -> ClusterManager {
    let manager = ClusterManager::with_default_transport(Arc::new(TokioResolver));
    // The provider's own endpoint is never dialled here; any address will do.
    let unused: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let runtime = ProviderRuntimeConfig {
        credential: Some(ProviderCredential::OAuth2JwtBearer(config)),
        path_template: None,
        model_rewrites: Vec::new(),
        request_field_policy: Default::default(),
        tenant_credential: None,
    };
    let clusters: HashMap<_, _> = [
        (
            PROVIDER.to_string(),
            Arc::new(cluster(PROVIDER, unused, Some(runtime))),
        ),
        (
            TOKEN_CLUSTER.to_string(),
            Arc::new(cluster(TOKEN_CLUSTER, endpoint.addr, None)),
        ),
    ]
    .into_iter()
    .collect();
    let rejected = manager.update_from_snapshot(&clusters).await;
    assert!(rejected.is_empty(), "clusters rejected: {rejected:?}");
    manager
}

fn bearer(manager: &ClusterManager) -> Option<String> {
    let entry = manager.cluster(PROVIDER).expect("provider cluster");
    let minted = entry.minted_credential().expect("minted credential");
    minted
        .bearer(Instant::now())
        .map(|value| value.to_str().unwrap().to_string())
}

async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The first token is minted inside the install, before the cluster set is
/// published, and the assertion is a valid RS256 JWT carrying the configured
/// claims. The mock verifies nothing itself; the test checks the signature
/// against the key's public half, so a wrong algorithm, signing input or key
/// fails here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_token_is_minted_with_a_signed_assertion_before_install_returns() {
    let pem = test_key_pem();
    let endpoint = MockTokenEndpoint::spawn(vec![token("minted-1", 3600)]).await;
    let manager = install(&endpoint, oauth2(&pem, Duration::from_secs(300))).await;

    assert_eq!(bearer(&manager).as_deref(), Some("Bearer minted-1"));

    let requests = endpoint.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "one mint");
    let (path, headers, form) = &requests[0];
    assert_eq!(path, "/oauth2/token");
    let header = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(header("host"), Some("token.test"));
    assert_eq!(
        header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    let assertion = form
        .strip_prefix("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=")
        .expect("RFC 7523 form body");

    let (signing_input, signature) = assertion.rsplit_once('.').expect("three JWT parts");
    let key_der = RsaSigningKey::from_pkcs8_pem(&pem).unwrap();
    let key = ring::signature::RsaKeyPair::from_pkcs8(key_der.pkcs8_der()).unwrap();
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        key.public().as_ref(),
    )
    .verify(
        signing_input.as_bytes(),
        &URL_SAFE_NO_PAD.decode(signature).unwrap(),
    )
    .expect("assertion signature verifies with the configured key");

    let (header_b64, claims_b64) = signing_input.split_once('.').unwrap();
    let jwt_header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims_b64).unwrap()).unwrap();
    assert_eq!(jwt_header["alg"], "RS256");
    assert_eq!(jwt_header["kid"], "key-1");
    assert_eq!(claims["iss"], "svc@example.test");
    assert_eq!(claims["sub"], "user@example.test");
    assert_eq!(claims["aud"], "https://audience.test");
    assert_eq!(claims["scope"], "scope.a scope.b");
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        600
    );
}

/// The refresher mints the next token `refresh_before` the current one
/// expires, while the current one is still valid, and publishes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_token_is_refreshed_before_it_expires() {
    let pem = test_key_pem();
    // A 60 s token refreshed 59 s early: the second mint is due after ~1 s,
    // with nearly a minute before the first token would expire.
    let endpoint =
        MockTokenEndpoint::spawn(vec![token("minted-1", 60), token("minted-2", 60)]).await;
    let minted_at = Instant::now();
    let manager = install(&endpoint, oauth2(&pem, Duration::from_secs(59))).await;
    assert_eq!(bearer(&manager).as_deref(), Some("Bearer minted-1"));

    wait_until("the refreshed token", || {
        bearer(&manager).as_deref() == Some("Bearer minted-2")
    })
    .await;
    assert!(
        minted_at.elapsed() < Duration::from_secs(60),
        "the refresh must land while the first token is still valid"
    );
}

/// A refresh that fails keeps serving the token that is still valid.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_refresh_keeps_the_still_valid_token() {
    let pem = test_key_pem();
    let endpoint = MockTokenEndpoint::spawn(vec![
        token("minted-1", 60),
        (503, r#"{"error":"temporarily_unavailable"}"#.to_string()),
    ])
    .await;
    let manager = install(&endpoint, oauth2(&pem, Duration::from_secs(59))).await;

    wait_until("a failed refresh", || endpoint.request_count() >= 2).await;
    assert_eq!(
        bearer(&manager).as_deref(),
        Some("Bearer minted-1"),
        "a failed refresh must not drop a token that has not expired"
    );
}

/// Once the last token expires and no refresh succeeded, the cell yields
/// nothing: the request path fails closed rather than sending an expired or
/// absent credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_expiry_with_no_successful_refresh_no_token_is_served() {
    let pem = test_key_pem();
    let endpoint = MockTokenEndpoint::spawn(vec![
        token("minted-1", 2),
        (500, r#"{"error":"server_error"}"#.to_string()),
    ])
    .await;
    let manager = install(&endpoint, oauth2(&pem, Duration::from_secs(1))).await;
    assert_eq!(bearer(&manager).as_deref(), Some("Bearer minted-1"));

    wait_until("the token to expire", || bearer(&manager).is_none()).await;
    assert!(
        endpoint.request_count() >= 2,
        "the refresher must have tried, and failed, to replace the token"
    );
}
