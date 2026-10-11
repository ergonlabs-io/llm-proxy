use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use proxy_http::{
    filter::RequestHeaders,
    handler::{local_boxed, DownstreamInfo, HttpRequestParts},
};
use proxy_xds::authorization::test_service::{Mode, TestService};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::LocalSet,
};

struct Upstream {
    address: std::net::SocketAddr,
    calls: Arc<AtomicUsize>,
    heads: Arc<std::sync::Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Upstream {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let heads = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = heads.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                let mut received = Vec::new();
                loop {
                    let mut byte = [0];
                    if socket.read_exact(&mut byte).await.is_err() {
                        break;
                    }
                    received.push(byte[0]);
                    if received.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    if received.len() > 64 * 1024 {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&received).to_ascii_lowercase();
                recorded.lock().unwrap().push(head.clone());
                assert!(
                    head.contains("x-authorized: yes")
                        || head.contains("x-envoy-auth-failure-mode-allowed: true"),
                    "authorization did not finish before dialing: {head}"
                );
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            }
        });
        Self {
            address,
            calls,
            heads,
            task,
        }
    }
}

async fn handler(
    service: &TestService,
    upstream: &Upstream,
    fail_open: bool,
) -> Rc<dyn StreamHandler> {
    handler_with(service, upstream, fail_open, None, "0.5s").await
}

async fn handler_with(
    service: &TestService,
    upstream: &Upstream,
    fail_open: bool,
    buffer_limit: Option<u32>,
    rpc_timeout: &str,
) -> Rc<dyn StreamHandler> {
    let text = include_str!("../../../examples/ext-authz.yaml").replace("port_value: 9001", &format!("port_value: {}", service.address.port()))
        .replace("port_value: 9002", &format!("port_value: {}", upstream.address.port()))
        .replace("timeout: 0.2s", &format!("timeout: {rpc_timeout}"))
        .replacen(
            "      filter_chains:",
            &format!(
                "{}      filter_chains:",
                buffer_limit.map_or(String::new(), |limit| format!(
                    "      per_connection_buffer_limit_bytes: {limit}\n"
                ))
            ),
            1,
        )
        .replace("validate_mutations: true", &format!("validate_mutations: true\n                      failure_mode_allow: {fail_open}\n                      failure_mode_allow_header_add: true"));
    let loaded = proxy_config::parse_bootstrap(
        text.as_bytes(),
        proxy_config::ConfigFormat::Yaml,
        proxy_config::StrictMode::Strict,
    )
    .unwrap();
    let snapshot = proxy_config::build_snapshot(&loaded).unwrap();
    let manager = Arc::new(ClusterManager::with_default_transport(Arc::new(
        proxy_cluster::resolver::TokioResolver,
    )));
    manager.update_from_snapshot(&snapshot.clusters).await;
    let control = proxy_observability::stats::StatsControl::new(1);
    let router = tests::router_stats_for(&control, &snapshot);
    let token = tests::token_stats_for(&control, &snapshot);
    let latency = tests::latency_stats_for(&control);
    let shared = Arc::new(SharedFactoryState::default());
    let runtime = HcmRuntime {
        snapshot_version: snapshot.version,
        routes: &snapshot.routes,
        cluster_manager: &manager,
        router_stats: &router,
        token_stats: &token,
        latency_stats: &latency,
        tracing_handles: None,
        metadata: None,
        factory_state: &shared,
    };
    build_listener_hcm(&snapshot.listeners["authorized_http"], &runtime)
        .unwrap()
        .chain_handlers[0]
        .as_ref()
        .unwrap()
        .clone()
}

fn request(body: proxy_http::handler::StreamBody) -> HttpRequestParts {
    HttpRequestParts {
        head: RequestHeaders {
            method: http::Method::POST,
            uri: "/v1?q=1".parse().unwrap(),
            headers: http::HeaderMap::new(),
        },
        body,
        downstream: DownstreamInfo::loopback(),
        on_upgrade: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ext_authz_denies_stalled_upload_before_reading_body() {
    LocalSet::new()
        .run_until(async {
            let service = TestService::spawn(Mode::Deny).await;
            let upstream = Upstream::spawn().await;
            let handler = handler(&service, &upstream, false).await;
            let stalled = http_body_util::StreamBody::new(futures::stream::pending::<
                Result<hyper::body::Frame<Bytes>, proxy_http::handler::BodyError>,
            >());
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                handler.handle(request(local_boxed(stalled))),
            )
            .await
            .unwrap();
            assert_eq!(response.head.status, http::StatusCode::UNAUTHORIZED);
            assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ext_authz_pending_cancellation_never_dials_upstream() {
    LocalSet::new()
        .run_until(async {
            let service = TestService::spawn(Mode::Stall).await;
            let upstream = Upstream::spawn().await;
            let handler = handler_with(&service, &upstream, false, None, "20s").await;
            let task = tokio::task::spawn_local(async move {
                handler
                    .handle(request(local_boxed(
                        Full::new(Bytes::new()).map_err(|never| match never {}),
                    )))
                    .await
            });
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                service.entered.notified(),
            )
            .await
            .unwrap();
            assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
            assert_eq!(service.cancelled.load(Ordering::SeqCst), 0);
            task.abort();
            let _ = task.await;
            // The RPC deadline is 20 s, so only dropping the pending check can
            // make the authz service see the call cancelled within this wait.
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                while service.cancelled.load(Ordering::SeqCst) == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("aborting the request must cancel the authorization RPC");
            service.release.notify_one();
            tokio::task::yield_now().await;
            assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
        })
        .await;
}

fn empty_body() -> proxy_http::handler::StreamBody {
    local_boxed(Full::new(Bytes::new()).map_err(|never| match never {}))
}

#[tokio::test(flavor = "multi_thread")]
async fn ext_authz_oversized_request_is_denied_even_when_fail_open() {
    for fail_open in [false, true] {
        LocalSet::new()
            .run_until(async {
                // An allow-everything service: the only thing that can stop this
                // request is the local size limit.
                let service = TestService::spawn(Mode::Allow).await;
                let upstream = Upstream::spawn().await;
                let handler = handler(&service, &upstream, fail_open).await;
                let mut parts = request(empty_body());
                for i in 0..10 {
                    parts.head.headers.insert(
                        http::HeaderName::from_bytes(format!("x-pad-{i}").as_bytes()).unwrap(),
                        http::HeaderValue::from_str(&"a".repeat(7 * 1024)).unwrap(),
                    );
                }
                let response =
                    tokio::time::timeout(std::time::Duration::from_secs(3), handler.handle(parts))
                        .await
                        .unwrap();
                assert_eq!(
                    response.head.status,
                    http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "fail_open={fail_open}"
                );
                assert!(!response
                    .head
                    .headers
                    .contains_key("x-envoy-auth-failure-mode-allowed"));
                assert_eq!(service.calls.load(Ordering::SeqCst), 0);
                assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
            })
            .await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ext_authz_body_above_default_limit_passes_when_listener_limit_is_larger() {
    // (configured limit, expected 413)
    for (limit, rejected) in [(None, true), (Some(4 * 1024 * 1024), false)] {
        LocalSet::new()
            .run_until(async {
                let service = TestService::spawn(Mode::Allow).await;
                let upstream = Upstream::spawn().await;
                let handler = handler_with(&service, &upstream, false, limit, "0.5s").await;
                let body = Bytes::from(vec![b'x'; 1536 * 1024]);
                let response = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    handler.handle(request(local_boxed(
                        Full::new(body).map_err(|never| match never {}),
                    ))),
                )
                .await
                .unwrap();
                assert_eq!(
                    response.head.status == http::StatusCode::PAYLOAD_TOO_LARGE,
                    rejected,
                    "limit={limit:?} status={}",
                    response.head.status
                );
                assert_eq!(
                    upstream.calls.load(Ordering::SeqCst),
                    usize::from(!rejected)
                );
            })
            .await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ext_authz_authority_mutation_updates_the_upstream_host_header() {
    LocalSet::new()
        .run_until(async {
            let service = TestService::spawn(Mode::MutateAuthority).await;
            let upstream = Upstream::spawn().await;
            let handler = handler(&service, &upstream, false).await;
            let mut parts = request(empty_body());
            parts
                .head
                .headers
                .insert(http::header::HOST, "original.example".parse().unwrap());
            tokio::time::timeout(std::time::Duration::from_secs(3), handler.handle(parts))
                .await
                .unwrap();
            let heads = upstream.heads.lock().unwrap();
            assert_eq!(heads.len(), 1);
            assert!(heads[0].contains("host: b.example"), "{}", heads[0]);
            assert!(!heads[0].contains("original.example"), "{}", heads[0]);
        })
        .await;
}
