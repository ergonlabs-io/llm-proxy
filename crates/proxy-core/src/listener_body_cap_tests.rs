//! Owner-boundary proof that the listener's `per_connection_buffer_limit_bytes`
//! caps every HTTP request body before any HTTP filter runs (AGENTS.md
//! "Architecture Invariants" 1; `internal-docs/envoy-divergences.md`). The
//! requests travel over real sockets through `serve_http1`, so what hyper does
//! with the unread remainder after the 413 is part of what is asserted.
use super::*;
use proxy_http::{
    filter::{
        DecoderCallbacks, FactoryContext, FilterHeadersStatus, FilterInstanceFactory, HttpFilter,
        HttpFilterFactory, RequestHeaders,
    },
    handler::DownstreamInfo,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::LocalSet,
};

const LIMIT: usize = 1024;
const WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Stand-in for `llmproxy.auth`: a decode filter that only records that it ran.
struct Recorder(Arc<AtomicUsize>);
impl HttpFilter for Recorder {
    fn decode_headers(
        &mut self,
        _cb: &mut dyn DecoderCallbacks,
        _headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        self.0.fetch_add(1, Ordering::SeqCst);
        FilterHeadersStatus::Continue
    }
}
struct RecorderInstances(Arc<AtomicUsize>);
impl FilterInstanceFactory for RecorderInstances {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(Recorder(self.0.clone()))
    }
}
/// `ConfiguredHttpFilter` wants a registered factory; `create` is never called
/// because the test supplies the instance factory directly.
struct RecorderFactory;
impl HttpFilterFactory for RecorderFactory {
    fn type_url(&self) -> &'static str {
        "type.llmproxy.dev/test.Recorder"
    }
    fn create(
        &self,
        _config: &prost_reflect::DynamicMessage,
        _ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, proxy_config::ConfigError> {
        unreachable!("the test supplies the instance factory directly")
    }
}

/// Counts dials and drains the request (head plus `Content-Length` body).
struct Upstream {
    address: std::net::SocketAddr,
    calls: Arc<AtomicUsize>,
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
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                let mut received = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read until the head and the whole declared body have arrived.
                while let Ok(n) = socket.read(&mut chunk).await {
                    if n == 0 {
                        break;
                    }
                    received.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&received).to_ascii_lowercase();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let declared = text
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if received.len() >= end + 4 + declared {
                            break;
                        }
                    }
                }
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
            task,
        }
    }
}

/// Serve one HCM listener (no ext_authz, `LIMIT` byte buffer limit, a
/// recording decode filter ahead of the router) on an ephemeral port.
async fn serve(upstream: &Upstream, ran: Arc<AtomicUsize>) -> std::net::SocketAddr {
    let text = format!(
        r#"
static_resources:
  listeners:
    - name: capped_http
      address:
        socket_address: {{ address: 127.0.0.1, port_value: 0 }}
      per_connection_buffer_limit_bytes: {LIMIT}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: capped_http
                route_config:
                  name: application_routes
                  virtual_hosts:
                    - name: application
                      domains: ['*']
                      routes:
                        - match: {{ prefix: / }}
                          route: {{ cluster: application }}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      '@type': type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: application
      type: STATIC
      connect_timeout: 1s
      load_assignment:
        cluster_name: application
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: {} }}
"#,
        upstream.address.port()
    );
    let loaded = proxy_config::parse_bootstrap(
        text.as_bytes(),
        proxy_config::ConfigFormat::Yaml,
        proxy_config::StrictMode::Strict,
    )
    .unwrap();
    let snapshot = proxy_config::build_snapshot(&loaded).unwrap();
    let listener_ir = &snapshot.listeners["capped_http"];
    assert_eq!(
        listener_ir.per_connection_buffer_limit_bytes as usize,
        LIMIT
    );
    let Some(NetworkFilterSpec::HttpConnectionManager(hcm)) =
        listener_ir.filter_chains[0].filters.last()
    else {
        panic!("expected an HTTP connection manager");
    };

    let manager = Arc::new(ClusterManager::with_default_transport(Arc::new(
        proxy_cluster::resolver::TokioResolver,
    )));
    manager.update_from_snapshot(&snapshot.clusters).await;
    let control = proxy_observability::stats::StatsControl::new(1);
    let router_stats = tests::router_stats_for(&control, &snapshot);
    let router_factory = RouterFilterFactory::new(manager, router_stats)
        .with_config_context("capped_http".to_string(), snapshot.version.0);
    let handler: Rc<dyn StreamHandler> = Rc::new(
        FilterChainHandler::new_with_filters_and_access_logs(
            vec![ConfiguredHttpFilter {
                name: "test.recorder".to_string(),
                instance_factory: Arc::new(RecorderInstances(ran)),
                factory: Arc::new(RecorderFactory),
            }],
            Arc::new(router_factory),
            hcm.route_table.clone(),
            false,
            false,
            0,
            &[],
        )
        .unwrap()
        .with_buffer_limit(listener_ir.per_connection_buffer_limit_bytes as usize),
    );

    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::task::spawn_local(async move {
        while let Ok((stream, _)) = socket.accept().await {
            let handler = handler.clone();
            tokio::task::spawn_local(async move {
                let _ = serve_http1(
                    stream,
                    handler,
                    Http1Options {
                        keep_alive: true,
                        header_read_timeout: None,
                    },
                    std::future::pending::<()>(),
                    DownstreamInfo::loopback(),
                )
                .await;
            });
        }
    });
    address
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_body_gets_413_before_any_filter_and_closes_the_connection() {
    LocalSet::new()
        .run_until(async {
            let upstream = Upstream::spawn().await;
            let ran = Arc::new(AtomicUsize::new(0));
            let address = serve(&upstream, ran.clone()).await;
            let mut client = TcpStream::connect(address).await.unwrap();
            // Chunked, so the server cannot reject on a declared length: it has
            // to cap the stream itself. Send LIMIT + 1 bytes and never finish.
            let chunk_head = format!(
                "POST /v1 HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                LIMIT + 1
            );
            client.write_all(chunk_head.as_bytes()).await.unwrap();
            client.write_all(&vec![b'x'; LIMIT + 1]).await.unwrap();

            // `read_to_end` only returns on EOF: the 413 arrived and the server
            // then closed the connection instead of keeping it alive with the
            // unread remainder still on it.
            let mut response = Vec::new();
            let read = tokio::time::timeout(WAIT, client.read_to_end(&mut response))
                .await
                .expect("server must answer 413 without waiting for the body to end");
            let text = String::from_utf8_lossy(&response);
            assert!(read.is_ok(), "{read:?} {text}");
            assert!(text.starts_with("HTTP/1.1 413"), "{text}");
            assert_eq!(ran.load(Ordering::SeqCst), 0, "a decode filter ran");
            assert_eq!(upstream.calls.load(Ordering::SeqCst), 0, "upstream dialled");
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn body_exactly_at_the_limit_reaches_the_upstream() {
    LocalSet::new()
        .run_until(async {
            let upstream = Upstream::spawn().await;
            let ran = Arc::new(AtomicUsize::new(0));
            let address = serve(&upstream, ran.clone()).await;
            let mut client = TcpStream::connect(address).await.unwrap();
            let head = format!("POST /v1 HTTP/1.1\r\nHost: t\r\nContent-Length: {LIMIT}\r\n\r\n");
            client.write_all(head.as_bytes()).await.unwrap();
            client.write_all(&vec![b'x'; LIMIT]).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(WAIT, async {
                let mut buf = [0u8; 1024];
                while !String::from_utf8_lossy(&response).ends_with("ok") {
                    let n = client.read(&mut buf).await.unwrap();
                    assert_ne!(n, 0, "closed before a full response");
                    response.extend_from_slice(&buf[..n]);
                }
            })
            .await
            .unwrap();
            let text = String::from_utf8_lossy(&response);
            assert!(text.starts_with("HTTP/1.1 200"), "{text}");
            assert_eq!(ran.load(Ordering::SeqCst), 1);
            assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
        })
        .await;
}
