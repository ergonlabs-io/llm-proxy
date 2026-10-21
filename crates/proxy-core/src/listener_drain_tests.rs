//! Owner-boundary proof of what a worker does when a drain starts: the real `initial_bind`, `run_listener_manager`,
//! accept loops, and HTTP/1 codec over real sockets (`internal-docs/architecture.md` section 8, "Drain"). Every wait is
//! bounded by `WAIT`.
use super::*;
use crate::drain::DrainStrategy;
use crate::test_ports::free_port;
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
        ledger: None,
        traces: None,
        connection_limiter: crate::admission::ConnectionLimiter::default(),
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
        // Far away on purpose: tests must finish because the drain logic
        // works, not because the deadline passed.
        self.start_drain_with(DrainStrategy::Immediate, Duration::from_secs(3600));
    }

    fn start_drain_with(&self, strategy: DrainStrategy, window: Duration) {
        let started = std::time::Instant::now();
        self.drain_tx
            .send(DrainState::Draining {
                started,
                until: started + window,
                strategy,
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
            let port = free_port();
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
            let (first, second) = (free_port(), free_port());
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
            let port = free_port();
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
            let port = free_port();
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
            let port = free_port();
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

/// How many idle keep-alive connections the drain-strategy tests hold open.
const IDLE_CONNECTIONS: usize = 20;

/// Opens `n` keep-alive connections that have each finished one request, and watches each one: the returned channel
/// gets one message per connection the server closes.
async fn idle_keep_alive_connections(
    port: u16,
    upstream: &Upstream,
    worker: &Worker,
    n: usize,
) -> mpsc::UnboundedReceiver<()> {
    upstream.gate.add_permits(n);
    let (closed_tx, closed) = mpsc::unbounded_channel();
    for _ in 0..n {
        let mut client = TcpStream::connect(addr(port)).await.unwrap();
        client
            .write_all(b"GET /v1 HTTP/1.1\r\nHost: t\r\n\r\n")
            .await
            .unwrap();
        let response = read_response(&mut client).await;
        assert!(
            !response.to_ascii_lowercase().contains("connection: close"),
            "keep-alive must be on before the drain: {response}"
        );
        let closed_tx = closed_tx.clone();
        tokio::task::spawn_local(async move {
            let mut rest = Vec::new();
            let _ = client.read_to_end(&mut rest).await;
            let _ = closed_tx.send(());
        });
    }
    assert_eq!(worker.registry.live(), n, "every connection is live");
    closed
}

/// Waits (bounded by `within`) until `total` connections have closed in all, counting from `closed_so_far`.
async fn await_closed(
    closed: &mut mpsc::UnboundedReceiver<()>,
    mut closed_so_far: usize,
    total: usize,
    within: Duration,
) {
    tokio::time::timeout(within, async {
        while closed_so_far < total {
            closed.recv().await.unwrap();
            closed_so_far += 1;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("only {closed_so_far} of {total} connections closed"));
}

/// Connections whose close has already been reported, without waiting.
fn closed_now(closed: &mut mpsc::UnboundedReceiver<()>) -> usize {
    std::iter::from_fn(|| closed.try_recv().ok()).count()
}

#[tokio::test(flavor = "multi_thread")]
async fn immediate_drain_closes_every_idle_keep_alive_connection_at_drain_start() {
    LocalSet::new()
        .run_until(async {
            let upstream = Upstream::spawn().await;
            let port = free_port();
            let worker = start_worker(snapshot_for(&[port], upstream.address.port(), 1)).await;
            let mut closed =
                idle_keep_alive_connections(port, &upstream, &worker, IDLE_CONNECTIONS).await;

            // A gradual schedule over this hour would space the closes 45s apart, so all of them inside `WAIT`
            // proves no connection waited for a slot.
            worker.start_drain_with(DrainStrategy::Immediate, Duration::from_secs(3600));
            await_closed(&mut closed, 0, IDLE_CONNECTIONS, WAIT).await;
            worker.stop().await;
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn gradual_drain_spreads_idle_keep_alive_closes_over_the_window() {
    LocalSet::new()
        .run_until(async {
            let upstream = Upstream::spawn().await;
            let port = free_port();
            let worker = start_worker(snapshot_for(&[port], upstream.address.port(), 1)).await;
            let mut closed =
                idle_keep_alive_connections(port, &upstream, &worker, IDLE_CONNECTIONS).await;

            // The first quarter (5s) holds the schedule: one close at once, then one every 250ms.
            let window = Duration::from_secs(20);
            worker.start_drain_with(DrainStrategy::Gradual, window);
            await_closed(&mut closed, 0, 1, WAIT).await;
            let at_start = 1 + closed_now(&mut closed);
            assert!(
                at_start < IDLE_CONNECTIONS,
                "gradual must not close every connection at drain start ({at_start} closed)"
            );
            // This harness has no deadline cut, so every close below came from the schedule.
            await_closed(&mut closed, at_start, IDLE_CONNECTIONS, window).await;
            assert_eq!(worker.registry.live(), 0);
            worker.stop().await;
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reload_during_a_gradual_drain_closes_kept_alive_connections_at_once() {
    LocalSet::new()
        .run_until(async {
            let upstream = Upstream::spawn().await;
            let port = free_port();
            let worker = start_worker(snapshot_for(&[port], upstream.address.port(), 1)).await;
            let mut closed =
                idle_keep_alive_connections(port, &upstream, &worker, IDLE_CONNECTIONS).await;

            // Over an hour the slots are 45s apart: only the first closes on schedule within this test.
            worker.start_drain_with(DrainStrategy::Gradual, Duration::from_secs(3600));
            await_closed(&mut closed, 0, 1, WAIT).await;
            let before_reload = 1 + closed_now(&mut closed);
            assert!(before_reload < IDLE_CONNECTIONS, "{before_reload} closed");

            // A reload (a rotated provider credential) must not wait for the schedule.
            worker
                .config
                .store(snapshot_for(&[port], upstream.address.port(), 2));
            await_closed(&mut closed, before_reload, IDLE_CONNECTIONS, WAIT).await;
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

/// A client-to-server text frame: masked, as RFC 6455 section 5.3 requires.
fn masked_text_frame(payload: &[u8]) -> Vec<u8> {
    masked_frame(0x1, payload)
}

/// A client Close frame with code 1001.
fn masked_close_frame() -> Vec<u8> {
    masked_frame(0x8, &1001u16.to_be_bytes())
}

fn masked_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mask = [0x11, 0x22, 0x33, 0x44];
    let mut frame = vec![0x80 | opcode, 0x80 | payload.len() as u8];
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    frame
}

/// envoy-semantics.md S10.5: an upgraded stream counts as active for drain.
/// Hyper resolves an upgraded connection as soon as it hands the raw IO to
/// the tunnel task, so the drain start that gracefully shuts down HTTP
/// connections must neither cut the tunnel nor let `drain_worker` report
/// done while it still carries bytes. A WebSocket tunnel is told to go away
/// with a Close frame (code 1001).
#[tokio::test(flavor = "multi_thread")]
async fn an_upgraded_websocket_gets_close_1001_on_drain_and_holds_drain_open_until_it_closes() {
    LocalSet::new()
        .run_until(async {
            let upstream = spawn_upgrade_echo_upstream().await;
            let port = free_port();
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
            // Well-formed client frames (masked, RFC 6455 section 5.3); the
            // upstream echoes them back as they are.
            echo(&mut client, &masked_text_frame(b"before")).await;

            // The deadline is an hour away, so only the registry emptying can
            // make the worker report.
            worker.start_drain();
            // The refusal proves this worker has observed the drain start.
            assert_connect_refused(addr(port)).await;
            // S10.5 (llm-proxy extension): drain tells the client to go away
            // with a Close frame, code 1001, instead of a reset at the deadline.
            let close = proxy_http::websocket::close_frame(
                proxy_http::websocket::CLOSE_GOING_AWAY,
                "server draining",
            );
            let mut got = vec![0u8; close.len()];
            tokio::time::timeout(WAIT, client.read_exact(&mut got))
                .await
                .expect("the Close frame must arrive once drain starts")
                .expect("read the Close frame");
            assert_eq!(got, close);
            assert_eq!(&got[2..4], &1001u16.to_be_bytes());
            // The client's Close reply still reaches the upstream: the tunnel
            // stays open until a peer closes it.
            client.write_all(&masked_close_frame()).await.unwrap();
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

/// Upstream that streams a chunked SSE response: one event, then the rest once
/// `gate` hands out a permit. `arrived` fires after the first event is written.
async fn spawn_streaming_upstream() -> (SocketAddr, Arc<Semaphore>, mpsc::UnboundedReceiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let gate = Arc::new(Semaphore::new(0));
    let (arrived_tx, arrived) = mpsc::unbounded_channel();
    let gate_for_task = gate.clone();
    tokio::spawn(async move {
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
                let first = b"data: one\n\n";
                let _ = socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                             Transfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                            first.len()
                        )
                        .as_bytes(),
                    )
                    .await;
                let _ = socket.write_all(first).await;
                let _ = socket.write_all(b"\r\n").await;
                let _ = arrived_tx.send(());
                gate.acquire().await.unwrap().forget();
                let last = b"data: [DONE]\n\n";
                let _ = socket
                    .write_all(format!("{:x}\r\n", last.len()).as_bytes())
                    .await;
                let _ = socket.write_all(last).await;
                let _ = socket.write_all(b"\r\n0\r\n\r\n").await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (address, gate, arrived)
}

/// A drain that starts while a response body is mid-stream must let the stream
/// finish: the connection stays registered (so `drain_worker` keeps waiting)
/// and the client receives the final event.
async fn a_streaming_response_survives_drain_start(request: &'static [u8]) {
    LocalSet::new()
        .run_until(async {
            let (upstream, gate, mut arrived) = spawn_streaming_upstream().await;
            let port = free_port();
            let worker = start_worker(snapshot_for(&[port], upstream.port(), 1)).await;

            let mut client = TcpStream::connect(addr(port)).await.unwrap();
            client.write_all(request).await.unwrap();
            tokio::time::timeout(WAIT, arrived.recv())
                .await
                .expect("first event must leave the upstream")
                .unwrap();
            // Read until the first event reaches the client: the body is mid-stream.
            let mut received = Vec::new();
            let mut buf = [0u8; 4096];
            tokio::time::timeout(WAIT, async {
                while !String::from_utf8_lossy(&received).contains("data: one") {
                    let n = client.read(&mut buf).await.unwrap();
                    assert_ne!(n, 0, "closed before the first event");
                    received.extend_from_slice(&buf[..n]);
                }
            })
            .await
            .expect("first event must reach the client");

            worker.start_drain();
            assert_connect_refused(addr(port)).await;
            // Held past the point where a drain-start cut would have landed.
            tokio::time::sleep(Duration::from_millis(1500)).await;
            assert_eq!(
                worker.registry.live(),
                1,
                "the streaming connection must stay registered"
            );

            gate.add_permits(1);
            tokio::time::timeout(WAIT, client.read_to_end(&mut received))
                .await
                .expect("connection must end after the stream")
                .unwrap();
            let text = String::from_utf8_lossy(&received);
            assert!(text.contains("data: [DONE]"), "stream was cut: {text}");
            worker.stop().await;
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_keep_alive_stream_survives_drain_start() {
    a_streaming_response_survives_drain_start(
        b"POST /v1 HTTP/1.1\r\nHost: t\r\nContent-Length: 2\r\n\r\n{}",
    )
    .await;
}

/// nginx `proxy_pass` without upstream keepalive sends `Connection: close`.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_close_stream_survives_drain_start() {
    a_streaming_response_survives_drain_start(
        b"POST /v1 HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}",
    )
    .await;
}

/// nginx `proxy_pass` defaults to HTTP/1.0 upstream.
#[tokio::test(flavor = "multi_thread")]
async fn an_http10_stream_survives_drain_start() {
    a_streaming_response_survives_drain_start(
        b"POST /v1 HTTP/1.0\r\nHost: t\r\nContent-Length: 2\r\n\r\n{}",
    )
    .await;
}
