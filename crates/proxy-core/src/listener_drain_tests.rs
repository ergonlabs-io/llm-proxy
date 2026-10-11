//! Owner-boundary proof of what a worker does when a drain starts: the real
//! `initial_bind` + `run_listener_manager` + accept loops + HTTP/1 codec over
//! real sockets (`internal-docs/architecture.md` section 8, "Drain"). Every
//! wait is bounded by `WAIT`; nothing asserts a wall-clock window.
use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore},
    task::LocalSet,
};

const WAIT: Duration = Duration::from_secs(10);

/// Upstream that reads one request head per connection, reports it on
/// `arrived`, then answers once `gate` hands out a permit.
struct Upstream {
    address: SocketAddr,
    gate: Arc<Semaphore>,
    arrived: mpsc::UnboundedReceiver<()>,
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
        let gate = Arc::new(Semaphore::new(0));
        let (arrived_tx, arrived) = mpsc::unbounded_channel();
        let gate_for_task = gate.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let gate = gate_for_task.clone();
                let arrived_tx = arrived_tx.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let _ = arrived_tx.send(());
                    gate.acquire().await.unwrap().forget();
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self {
            address,
            gate,
            arrived,
            task,
        }
    }
}

fn reserve_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Upstream that answers its first request with `101 Switching Protocols`,
/// then echoes tunnel bytes until the peer closes.
async fn spawn_upgrade_echo_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match socket.read(&mut byte).await {
                Ok(1) => head.push(byte[0]),
                _ => return,
            }
        }
        let switched = socket
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            )
            .await;
        if switched.is_err() {
            return;
        }
        let mut buf = [0u8; 4096];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if socket.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    address
}

/// One HTTP listener per entry in `ports`, all routing `/` to an upstream.
fn snapshot_for(ports: &[u16], upstream_port: u16, version: u64) -> Arc<ConfigSnapshot> {
    snapshot_with_hcm_extra(ports, upstream_port, version, "")
}

/// [`snapshot_for`] with WebSocket upgrades enabled on every listener.
fn websocket_snapshot_for(ports: &[u16], upstream_port: u16, version: u64) -> Arc<ConfigSnapshot> {
    snapshot_with_hcm_extra(
        ports,
        upstream_port,
        version,
        "upgrade_configs: [{ upgrade_type: websocket }]",
    )
}

/// `hcm_extra` is one YAML line spliced into each HCM's `typed_config`.
fn snapshot_with_hcm_extra(
    ports: &[u16],
    upstream_port: u16,
    version: u64,
    hcm_extra: &str,
) -> Arc<ConfigSnapshot> {
    let listeners: String = ports
        .iter()
        .enumerate()
        .map(|(i, port)| {
            format!(
                r#"
    - name: drain_http_{i}
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: drain_http_{i}
                {hcm_extra}
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
"#
            )
        })
        .collect();
    let text = format!(
        r#"
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
    let mut snapshot = proxy_config::build_snapshot(&loaded).unwrap();
    snapshot.version = SnapshotVersion(version);
    Arc::new(snapshot)
}

struct Worker {
    config: Arc<WorkerConfigHandle>,
    config_tx: watch::Sender<SnapshotVersion>,
    shutdown_tx: watch::Sender<bool>,
    drain_tx: watch::Sender<DrainState>,
    drain_rx: watch::Receiver<DrainState>,
    registry: ConnectionRegistry,
    manager: tokio::task::JoinHandle<()>,
}

async fn start_worker(initial: Arc<ConfigSnapshot>) -> Worker {
    let config = Arc::new(WorkerConfigHandle::new(initial.clone()));
    let (config_tx, config_rx) = watch::channel(initial.version);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (drain_tx, drain_rx) = watch::channel(DrainState::NotDraining);
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
        // Listeners added by a later snapshot have no handle; the drain
        // tests that publish one never reach an accept.
        initial.listeners.keys().map(String::as_str),
    ));
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
        drain_rx.clone(),
        Arc::new(LifecycleState::new()),
        registry.clone(),
        cluster_manager,
        stats,
        factory_state,
        secret_registry,
    ));
    Worker {
        config,
        config_tx,
        shutdown_tx,
        drain_tx,
        drain_rx,
        registry,
        manager,
    }
}

impl Worker {
    fn start_drain(&self) {
        let started = std::time::Instant::now();
        self.drain_tx
            .send(DrainState::Draining {
                started,
                // Far away on purpose: tests must finish because the drain
                // logic works, not because the deadline passed.
                until: started + Duration::from_secs(3600),
            })
            .unwrap();
    }

    async fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        self.manager.await.expect("listener manager task panicked");
    }
}

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Reads until the buffer contains a full response ending in the 2-byte body.
async fn read_response(client: &mut TcpStream) -> String {
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
    .expect("response must arrive");
    String::from_utf8(response).unwrap()
}

/// Connection attempts are refused only once the accept loop's listener is
/// dropped; the abort is asynchronous, so poll until the refusal is observed
/// (bounded by `WAIT`).
async fn assert_connect_refused(target: SocketAddr) {
    tokio::time::timeout(WAIT, async {
        loop {
            match TcpStream::connect(target).await {
                Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => return,
                _ => tokio::task::yield_now().await,
            }
        }
    })
    .await
    .expect("listener must stop accepting after drain start");
}

#[tokio::test(flavor = "multi_thread")]
async fn drain_start_closes_the_listening_socket() {
    LocalSet::new()
        .run_until(async {
            let upstream = Upstream::spawn().await;
            let port = reserve_port();
            let worker = start_worker(snapshot_for(&[port], upstream.address.port(), 1)).await;
            TcpStream::connect(addr(port))
                .await
                .expect("accepting before the drain");

            worker.start_drain();
            assert_connect_refused(addr(port)).await;
            worker.stop().await;
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_snapshot_published_after_drain_start_binds_nothing() {
    LocalSet::new()
        .run_until(async {
            let upstream = Upstream::spawn().await;
            let (first, second) = (reserve_port(), reserve_port());
            let worker = start_worker(snapshot_for(&[first], upstream.address.port(), 1)).await;

            worker.start_drain();
            assert_connect_refused(addr(first)).await;

            let next = snapshot_for(&[first, second], upstream.address.port(), 2);
            worker.config.store(next.clone());
            let _ = worker.config_tx.send(next.version);
            // The manager has already left its loop, so the ping is never
            // read. Yield so a manager that DID react would have run its
            // (synchronous) reconcile before the connect below.
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            assert_connect_refused(addr(second)).await;
            assert_connect_refused(addr(first)).await;
            worker.stop().await;
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_idle_keep_alive_connection_is_closed_at_drain_start() {
    LocalSet::new()
        .run_until(async {
            let upstream = Upstream::spawn().await;
            upstream.gate.add_permits(1);
            let port = reserve_port();
            let worker = start_worker(snapshot_for(&[port], upstream.address.port(), 1)).await;

            let mut client = TcpStream::connect(addr(port)).await.unwrap();
            client
                .write_all(b"GET /v1 HTTP/1.1\r\nHost: t\r\n\r\n")
                .await
                .unwrap();
            let first = read_response(&mut client).await;
            assert!(first.starts_with("HTTP/1.1 200"), "{first}");
            assert!(
                !first.to_ascii_lowercase().contains("connection: close"),
                "keep-alive must be on before the drain: {first}"
            );
            assert_eq!(worker.registry.live(), 1, "the idle connection is live");

            worker.start_drain();
            let mut rest = Vec::new();
            let read = tokio::time::timeout(WAIT, client.read_to_end(&mut rest))
                .await
                .expect("the server must close an idle connection at drain start");
            assert!(read.is_ok(), "{read:?}");
            assert!(rest.is_empty(), "no bytes expected, got {rest:?}");
            worker.stop().await;
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_in_flight_request_finishes_with_connection_close_then_the_connection_ends() {
    LocalSet::new()
        .run_until(async {
            let mut upstream = Upstream::spawn().await;
            let port = reserve_port();
            let worker = start_worker(snapshot_for(&[port], upstream.address.port(), 1)).await;

            let mut client = TcpStream::connect(addr(port)).await.unwrap();
            client
                .write_all(b"GET /v1 HTTP/1.1\r\nHost: t\r\n\r\n")
                .await
                .unwrap();
            tokio::time::timeout(WAIT, upstream.arrived.recv())
                .await
                .expect("request must reach the upstream")
                .unwrap();

            worker.start_drain();
            assert_connect_refused(addr(port)).await;
            // The request is mid-flight and must not have been cut.
            upstream.gate.add_permits(1);
            let response = read_response(&mut client).await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(
                response.to_ascii_lowercase().contains("connection: close"),
                "an HTTP/1 response during a drain must announce the close: {response}"
            );
            let mut rest = Vec::new();
            tokio::time::timeout(WAIT, client.read_to_end(&mut rest))
                .await
                .expect("connection must end after the in-flight response")
                .unwrap();
            worker.stop().await;
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn drain_worker_reports_done_when_only_an_idle_connection_remains() {
    LocalSet::new()
        .run_until(async {
            let upstream = Upstream::spawn().await;
            upstream.gate.add_permits(1);
            let port = reserve_port();
            let worker = start_worker(snapshot_for(&[port], upstream.address.port(), 1)).await;
            let (done_tx, mut done_rx) = mpsc::unbounded_channel();
            tokio::task::spawn_local(crate::drain::drain_worker(
                crate::runtime::WorkerId(0),
                worker.drain_rx.clone(),
                done_tx,
                worker.registry.clone(),
            ));

            let mut client = TcpStream::connect(addr(port)).await.unwrap();
            client
                .write_all(b"GET /v1 HTTP/1.1\r\nHost: t\r\n\r\n")
                .await
                .unwrap();
            read_response(&mut client).await;
            assert_eq!(worker.registry.live(), 1);

            // The deadline is an hour away, so only the registry emptying can
            // make the worker report.
            worker.start_drain();
            let done = tokio::time::timeout(WAIT, done_rx.recv())
                .await
                .expect("an idle keep-alive connection must not hold the drain open");
            assert_eq!(done, Some(crate::runtime::WorkerId(0)));
            drop(client);
            worker.stop().await;
        })
        .await;
}

/// Writes `payload` into an established tunnel and reads the echo back.
async fn echo(client: &mut TcpStream, payload: &[u8]) {
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(WAIT, client.read_exact(&mut echoed))
        .await
        .expect("tunnel echo must arrive")
        .expect("tunnel must still be open");
    assert_eq!(echoed, payload);
}

/// envoy-semantics.md S10.5: an upgraded stream counts as active for drain.
/// Hyper resolves an upgraded connection as soon as it hands the raw IO to
/// the tunnel task, so the drain start that gracefully shuts down HTTP
/// connections must neither cut the tunnel nor let `drain_worker` report
/// done while it still carries bytes.
#[tokio::test(flavor = "multi_thread")]
async fn an_upgraded_tunnel_survives_drain_start_and_holds_drain_open_until_it_closes() {
    LocalSet::new()
        .run_until(async {
            let upstream = spawn_upgrade_echo_upstream().await;
            let port = reserve_port();
            let worker = start_worker(websocket_snapshot_for(&[port], upstream.port(), 1)).await;
            let (done_tx, mut done_rx) = mpsc::unbounded_channel();
            tokio::task::spawn_local(crate::drain::drain_worker(
                crate::runtime::WorkerId(0),
                worker.drain_rx.clone(),
                done_tx,
                worker.registry.clone(),
            ));

            let mut client = TcpStream::connect(addr(port)).await.unwrap();
            client
                .write_all(
                    b"GET /ws HTTP/1.1\r\nHost: t\r\n\
                      Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                )
                .await
                .unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                tokio::time::timeout(WAIT, client.read_exact(&mut byte))
                    .await
                    .expect("101 head must arrive")
                    .expect("read 101 head");
                head.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&head);
            assert!(head.starts_with("HTTP/1.1 101"), "{head}");
            echo(&mut client, b"before").await;

            // The deadline is an hour away, so only the registry emptying can
            // make the worker report.
            worker.start_drain();
            // The refusal proves this worker has observed the drain start.
            assert_connect_refused(addr(port)).await;
            echo(&mut client, b"during").await;
            assert!(
                matches!(done_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
                "drain_worker reported done while an upgraded tunnel was live"
            );
            assert_eq!(worker.registry.live(), 1, "the tunnel's connection is live");

            drop(client);
            let done = tokio::time::timeout(WAIT, done_rx.recv())
                .await
                .expect("drain_worker must report once the tunnel closes");
            assert_eq!(done, Some(crate::runtime::WorkerId(0)));
            worker.stop().await;
        })
        .await;
}
