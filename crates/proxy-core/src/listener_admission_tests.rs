//! Owner-boundary proof of downstream admission limits: the global connection cap, `ignore_global_conn_limit`, and
//! HCM `request_headers_timeout` and `request_timeout`. Runs through the real bootstrap, IR, `initial_bind`, and
//! `run_listener_manager` path, with real accept loops and sockets. Assertions are on outcomes inside the bounded
//! `WAIT`, never on a wall-clock window (AGENTS.md "Build And Test").
use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::LocalSet,
};

const WAIT: Duration = Duration::from_secs(10);

/// Reserve-then-release an ephemeral port number, the same technique the
/// sibling listener tests use (the proxy binds with `SO_REUSEPORT`, so a
/// reservation socket that stays open would receive a share of the
/// connections).
fn reserve_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Upstream that counts dials. It drains the request head, then answers `XY`;
/// with a nonzero `gap` it sends `X`, waits, then sends `Y`, so the response
/// outlasts a short request deadline.
struct Upstream {
    port: u16,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Upstream {
    async fn spawn(gap: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = calls.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nX",
                        )
                        .await;
                    tokio::time::sleep(gap).await;
                    let _ = socket.write_all(b"Y").await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { port, calls, task }
    }

    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// One listener spec for [`snapshot`].
struct ListenerSpec {
    name: &'static str,
    port: u16,
    ignore_global_conn_limit: bool,
    /// YAML lines spliced into the HCM `typed_config`.
    hcm_extra: String,
}

impl ListenerSpec {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            port: reserve_port(),
            ignore_global_conn_limit: false,
            hcm_extra: String::new(),
        }
    }
}

fn snapshot(
    listeners: &[&ListenerSpec],
    upstream_port: u16,
    max_connections: Option<i64>,
) -> Arc<ConfigSnapshot> {
    let overload = match max_connections {
        Some(max) => format!(
            r#"
overload_manager:
  resource_monitors:
    - name: envoy.resource_monitors.global_downstream_max_connections
      typed_config:
        '@type': type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig
        max_active_downstream_connections: {max}
"#
        ),
        None => String::new(),
    };
    let listeners: String = listeners
        .iter()
        .map(|l| {
            format!(
                r#"
    - name: {name}
      ignore_global_conn_limit: {ignore}
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: {name}
{extra}
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
"#,
                name = l.name,
                ignore = l.ignore_global_conn_limit,
                port = l.port,
                extra = l.hcm_extra,
            )
        })
        .collect();
    let text = format!(
        r#"{overload}
static_resources:
  listeners:{listeners}
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
                    socket_address: {{ address: 127.0.0.1, port_value: {upstream_port} }}
"#
    );
    let loaded = proxy_config::parse_bootstrap(
        text.as_bytes(),
        proxy_config::ConfigFormat::Yaml,
        proxy_config::StrictMode::Strict,
    )
    .unwrap();
    Arc::new(proxy_config::build_snapshot(&loaded).unwrap())
}

struct Harness {
    config: Arc<WorkerConfigHandle>,
    // Kept alive: the manager treats a dropped config sender as the end of
    // the control runtime and stops listening.
    _config_tx: watch::Sender<SnapshotVersion>,
    limiter: crate::admission::ConnectionLimiter,
    control: proxy_observability::stats::StatsControl,
    shutdown_tx: watch::Sender<bool>,
    manager: tokio::task::JoinHandle<()>,
}

async fn start(initial: Arc<ConfigSnapshot>) -> Harness {
    let config = Arc::new(WorkerConfigHandle::new(initial.clone()));
    let (config_tx, config_rx) = watch::channel(initial.version);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (_drain_tx, drain_rx) = watch::channel(DrainState::NotDraining);
    let registry = ConnectionRegistry::new();
    let cluster_manager = Arc::new(ClusterManager::with_default_transport(Arc::new(
        proxy_cluster::resolver::TokioResolver,
    )));
    cluster_manager
        .update_from_snapshot(&initial.clusters)
        .await;
    for name in initial.clusters.keys() {
        cluster_manager.force_initialize(name);
    }
    let control = proxy_observability::stats::StatsControl::new(1);
    let downstream_handles = Arc::new(proxy_http::stat_handles::DownstreamStatHandles::build(
        &control,
        initial.listeners.keys().map(String::as_str),
    ));
    let limiter = crate::admission::ConnectionLimiter::default();
    let stats = StatsRecorders {
        router: tests::router_stats_for(&control, &initial),
        downstream: Arc::new(DownstreamStats::new(
            control.registry(),
            downstream_handles,
            proxy_observability::stats::WorkerId(0),
        )),
        token: tests::token_stats_for(&control, &initial),
        latency: tests::latency_stats_for(&control),
        tracing: None,
        metadata: None,
        connection_limiter: limiter.clone(),
    };
    let factory_state = Arc::new(SharedFactoryState::default());
    let secret_registry = Arc::new(SdsSecretRegistry::new());
    let bound = initial_bind(
        &initial,
        &config,
        &registry,
        &shutdown_rx,
        &drain_rx,
        &cluster_manager,
        &stats,
        &factory_state,
        &secret_registry,
    )
    .expect("initial_bind");
    let manager = tokio::task::spawn_local(run_listener_manager(
        bound,
        config.clone(),
        config_rx,
        shutdown_rx,
        drain_rx,
        Arc::new(LifecycleState::new()),
        registry,
        cluster_manager,
        stats,
        factory_state,
        secret_registry,
    ));
    Harness {
        config,
        _config_tx: config_tx,
        limiter,
        control,
        shutdown_tx,
        manager,
    }
}

impl Harness {
    fn stats(&self) -> String {
        proxy_observability::stats::envoy_render::render(&self.control.registry())
    }

    /// Waits (bounded) until `n` counted connections are live, i.e. the
    /// accept loop has taken or released slots accordingly.
    async fn wait_live(&self, n: u64) {
        tokio::time::timeout(WAIT, async {
            while self.limiter.live() != n {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "live connections never reached {n}: {}",
                self.limiter.live()
            )
        });
    }

    async fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        self.manager.await.expect("listener manager task panicked");
    }
}

/// Sends one `Connection: close` GET and returns everything read until EOF.
async fn get(target: SocketAddr) -> String {
    let mut client = TcpStream::connect(target).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    read_to_end(&mut client).await
}

async fn read_to_end(client: &mut TcpStream) -> String {
    let mut response = Vec::new();
    tokio::time::timeout(WAIT, client.read_to_end(&mut response))
        .await
        .expect("connection must end within the bound")
        .ok();
    String::from_utf8_lossy(&response).into_owned()
}

/// True when the proxy closed `client` without sending anything (EOF or
/// reset), which is what an over-limit accept looks like from outside.
async fn closed_by_proxy(client: &mut TcpStream) -> bool {
    let mut buf = [0u8; 16];
    match tokio::time::timeout(WAIT, client.read(&mut buf))
        .await
        .expect("proxy must close the connection within the bound")
    {
        Ok(0) | Err(_) => true,
        Ok(_) => false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn connection_cap_closes_the_overflow_and_frees_the_slot_when_a_connection_ends() {
    LocalSet::new()
        .run_until(async {
            let upstream = Upstream::spawn(Duration::ZERO).await;
            let a = ListenerSpec::new("a");
            let h = start(snapshot(&[&a], upstream.port, Some(2))).await;

            let c1 = TcpStream::connect(addr(a.port)).await.unwrap();
            let _c2 = TcpStream::connect(addr(a.port)).await.unwrap();
            h.wait_live(2).await;

            let mut c3 = TcpStream::connect(addr(a.port)).await.unwrap();
            assert!(closed_by_proxy(&mut c3).await, "third connection served");
            let stats = h.stats();
            assert!(
                stats.contains("listener.a.downstream_global_cx_overflow: 1"),
                "{stats}"
            );
            // The rejected socket is not a counted connection.
            assert!(
                stats.contains("listener.a.downstream_cx_total: 2"),
                "{stats}"
            );
            assert_eq!(upstream.calls(), 0);

            // Ending a held connection frees its slot, driven through the
            // real connection task rather than by inspecting the counter.
            drop(c1);
            h.wait_live(1).await;
            let response = get(addr(a.port)).await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(
                h.stats()
                    .contains("listener.a.downstream_global_cx_overflow: 1"),
                "no further overflow"
            );
            h.stop().await;
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn listener_that_ignores_the_global_limit_bypasses_a_full_cap() {
    LocalSet::new()
        .run_until(async {
            let upstream = Upstream::spawn(Duration::ZERO).await;
            let capped = ListenerSpec::new("capped");
            let mut exempt = ListenerSpec::new("exempt");
            exempt.ignore_global_conn_limit = true;
            let h = start(snapshot(&[&capped, &exempt], upstream.port, Some(1))).await;

            let _held = TcpStream::connect(addr(capped.port)).await.unwrap();
            h.wait_live(1).await;
            let mut over = TcpStream::connect(addr(capped.port)).await.unwrap();
            assert!(closed_by_proxy(&mut over).await, "capped listener served");

            // Held exempt connections neither get refused nor use the cap.
            let mut held_exempt = Vec::new();
            for _ in 0..3 {
                held_exempt.push(TcpStream::connect(addr(exempt.port)).await.unwrap());
            }
            let response = get(addr(exempt.port)).await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert_eq!(h.limiter.live(), 1, "exempt connections are not counted");
            let stats = h.stats();
            assert!(
                stats.contains("listener.capped.downstream_global_cx_overflow: 1"),
                "{stats}"
            );
            assert!(
                stats.contains("listener.exempt.downstream_global_cx_overflow: 0"),
                "{stats}"
            );
            h.stop().await;
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reloaded_limit_applies_to_the_next_accept() {
    LocalSet::new()
        .run_until(async {
            let upstream = Upstream::spawn(Duration::ZERO).await;
            let a = ListenerSpec::new("a");
            let h = start(snapshot(&[&a], upstream.port, Some(3))).await;

            let _c1 = TcpStream::connect(addr(a.port)).await.unwrap();
            let _c2 = TcpStream::connect(addr(a.port)).await.unwrap();
            h.wait_live(2).await;

            // Lower the cap to the current count: the next accept is refused.
            h.config
                .store(snapshot_same_listeners(&a, upstream.port, Some(2)));
            let mut refused = TcpStream::connect(addr(a.port)).await.unwrap();
            assert!(closed_by_proxy(&mut refused).await);

            // Raise it again, then unset it: the next accepts are served.
            h.config
                .store(snapshot_same_listeners(&a, upstream.port, Some(5)));
            let response = get(addr(a.port)).await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            h.config
                .store(snapshot_same_listeners(&a, upstream.port, None));
            let response = get(addr(a.port)).await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            h.stop().await;
        })
        .await;
}

/// A new snapshot for the same listener (same port, same snapshot version, so
/// the accept loop keeps its compiled chains) differing only in the cap.
fn snapshot_same_listeners(
    spec: &ListenerSpec,
    upstream_port: u16,
    max_connections: Option<i64>,
) -> Arc<ConfigSnapshot> {
    snapshot(&[spec], upstream_port, max_connections)
}

#[tokio::test(flavor = "multi_thread")]
async fn request_headers_timeout_closes_a_stalled_http1_connection_but_not_a_long_response() {
    LocalSet::new()
        .run_until(async {
            // The response outlasts the 200ms header deadline by design.
            let upstream = Upstream::spawn(Duration::from_millis(1200)).await;
            let mut a = ListenerSpec::new("a");
            a.hcm_extra = "                request_headers_timeout: 0.2s".to_string();
            let h = start(snapshot(&[&a], upstream.port, None)).await;

            // A client that sends a partial request line and stalls.
            let mut stalled = TcpStream::connect(addr(a.port)).await.unwrap();
            stalled.write_all(b"GET / HT").await.unwrap();
            let bytes = read_to_end(&mut stalled).await;
            // hyper closes without a 408 (internal-docs/envoy-divergences.md).
            assert_eq!(bytes, "");
            assert_eq!(upstream.calls(), 0);

            // The deadline covers the request head only: a complete request
            // whose response streams for longer is not cut.
            let response = get(addr(a.port)).await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(
                response.contains('X') && response.contains('Y'),
                "{response}"
            );
            h.stop().await;
        })
        .await;
}

fn log_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "llm-proxy-admission-{tag}-{}-{}.log",
        std::process::id(),
        reserve_port()
    ))
}

fn access_log_yaml(path: &std::path::Path) -> String {
    format!(
        r#"                access_log:
                  - name: envoy.access_loggers.file
                    typed_config:
                      '@type': type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                      path: {}
                      log_format:
                        text_format: "%RESPONSE_CODE% %RESPONSE_CODE_DETAILS%\n"
"#,
        path.display()
    )
}

async fn logged(path: &std::path::Path) -> String {
    tokio::time::timeout(WAIT, async {
        loop {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            if !text.trim().is_empty() {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("access-log line never written")
}

#[tokio::test(flavor = "multi_thread")]
async fn request_timeout_answers_408_on_a_stalled_body_and_closes_the_connection() {
    LocalSet::new()
        .run_until(async {
            let upstream = Upstream::spawn(Duration::ZERO).await;
            let path = log_path("stall");
            let mut a = ListenerSpec::new("a");
            a.hcm_extra = format!(
                "                request_timeout: 0.2s\n{}",
                access_log_yaml(&path)
            );
            let h = start(snapshot(&[&a], upstream.port, None)).await;

            let mut client = TcpStream::connect(addr(a.port)).await.unwrap();
            // Declares 100 body bytes, sends 10, then stalls with the
            // connection open.
            client
                .write_all(b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 100\r\n\r\n0123456789")
                .await
                .unwrap();
            // `read_to_end` returning means the 408 arrived and the proxy then
            // closed the connection rather than reusing it with unread bytes.
            let response = read_to_end(&mut client).await;
            assert!(response.starts_with("HTTP/1.1 408"), "{response}");
            assert_eq!(upstream.calls(), 0, "a partial request reached upstream");

            let line = logged(&path).await;
            assert_eq!(line.trim(), "408 request_overall_timeout", "{line}");
            let _ = std::fs::remove_file(&path);
            h.stop().await;
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn request_timeout_does_not_cut_a_response_that_streams_past_the_deadline() {
    LocalSet::new()
        .run_until(async {
            // The request completes at once; the response takes 1.2s against
            // a 300ms request deadline. This is the LLM streaming case.
            let upstream = Upstream::spawn(Duration::from_millis(1200)).await;
            let mut a = ListenerSpec::new("a");
            a.hcm_extra = "                request_timeout: 0.3s".to_string();
            let h = start(snapshot(&[&a], upstream.port, None)).await;

            let mut client = TcpStream::connect(addr(a.port)).await.unwrap();
            client
                .write_all(
                    b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
                )
                .await
                .unwrap();
            let response = read_to_end(&mut client).await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(response.contains('X') && response.contains('Y'), "{response}");
            assert_eq!(upstream.calls(), 1);
            h.stop().await;
        })
        .await;
}
