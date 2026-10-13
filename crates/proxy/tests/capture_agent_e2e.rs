#![cfg(unix)]
use proxy_capture_agent::{config::Config, Agent};
use proxy_capture_spool::MetadataSpool;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

#[test]
fn declarative_validate_is_offline_and_rejects_disabled_namespace_cli_collision() {
    let temp = tempfile::tempdir().unwrap();
    let bootstrap = temp.path().join("proxy.yaml");
    let capture = serde_json::json!({"version":1,"metadata":{"enabled":true},"policy":{"version":"offline"},
        "endpoint":{"unix_socket_path":"/nonexistent/agent.sock","expected_agent_uid":1,"expected_node_id":"node","producer_id":"proxy"},
        "emergency_control":{"unix_socket_path":"/nonexistent/control.sock","operator_uid":1}});
    std::fs::write(
        &bootstrap,
        format!("node:\n  metadata:\n    io.llmproxy.capture: {capture}\n"),
    )
    .unwrap();
    let output = Command::new(BIN)
        .arg("-c")
        .arg(&bootstrap)
        .args(["--mode", "validate", "--concurrency", "1"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::write(
        &bootstrap,
        "node:\n  metadata:\n    io.llmproxy.capture: {version: 1, metadata: {enabled: false}}\n",
    )
    .unwrap();
    let destination = temp.path().join("records.jsonl");
    let output = Command::new(BIN)
        .arg("-c")
        .arg(&bootstrap)
        .args(["--mode", "validate", "--request-records-file"])
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("node.metadata[\"io.llmproxy.capture\"]")
    );
    assert!(!destination.exists());
}

fn control(path: &std::path::Path, command: serde_json::Value) -> serde_json::Value {
    let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let bytes = serde_json::to_vec(&command).unwrap();
    assert!(bytes.len() <= 1024);
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let size = u32::from_be_bytes(prefix) as usize;
    assert!((1..=1024).contains(&size));
    let mut response = vec![0; size];
    stream.read_exact(&mut response).unwrap();
    serde_json::from_slice(&response).unwrap()
}

fn keepalive_get(stream: &mut TcpStream, path: &str) {
    write!(stream, "GET {path} HTTP/1.1\r\nHost: test.local\r\n\r\n").unwrap();
    // Read exactly one response; never consume bytes from a later response.
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        assert!(response.len() < 16384, "oversized response headers");
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        response.push(byte[0]);
    }
    let headers = String::from_utf8(response).unwrap();
    assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
    assert!(
        headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("content-length: 0")),
        "{headers}"
    );
    assert!(
        !headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("connection: close")),
        "{headers}"
    );
}

fn declarative_bootstrap(
    listener: u16,
    admin: u16,
    upstream: u16,
    capture: &serde_json::Value,
) -> String {
    format!(
        r#"
node:
  id: test-proxy
  cluster: test
  metadata:
    "io.llmproxy.capture": {capture}
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin} }}
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress
                route_config:
                  name: local
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route: {{ cluster: backend }}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: backend
      type: STATIC
      connect_timeout: 1s
      load_assignment:
        cluster_name: backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: {upstream} }}
"#
    )
}

#[test]
fn declarative_capture_reload_and_emergency_gate_on_existing_keepalive() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("agent.sock");
    let control_socket = temp.path().join("control.sock");
    let key = temp.path().join("key");
    std::fs::write(&key, [9; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let uid = runtime.block_on(async {
        tokio::net::UnixStream::pair()
            .unwrap()
            .0
            .peer_cred()
            .unwrap()
            .uid()
    });
    let agent_config = serde_json::json!({
        "version":1,"mode":"metadata_spool_only","socket_path":socket,"node_id":"test-node",
        "producers":[{"producer_id":"test-proxy","uid":uid,"tenants":["default"]}],
        "spool":{"directory":temp.path().join("spool"),"max_record_bytes":524288,
            "max_disk_bytes":4194304,"cache_bytes":4194304},
        "active_key_id":"key","keys":[{"key_id":"key","key_file":key}]
    });
    let agent = collector(serde_json::from_value(agent_config.clone()).unwrap());
    let upstream = mock();
    let listener = port();
    let admin = port();
    let bootstrap = temp.path().join("proxy.yaml");
    let log = temp.path().join("proxy.log");
    let mut capture = serde_json::json!({
        "version":1,"metadata":{"enabled":true,"max_attempts":8},"policy":{"version":"first"},
        "endpoint":{"unix_socket_path":socket,"expected_agent_uid":uid,
            "expected_node_id":"test-node","producer_id":"test-proxy"},
        "emergency_control":{"unix_socket_path":control_socket,"operator_uid":uid}
    });
    std::fs::write(
        &bootstrap,
        declarative_bootstrap(listener, admin, upstream.address.port(), &capture),
    )
    .unwrap();
    let mut proxy = Proxy(
        Command::new(BIN)
            .arg("-c")
            .arg(&bootstrap)
            .args(["--concurrency", "1", "--drain-time-s", "0"])
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap(),
    );
    wait(|| {
        assert!(
            proxy.0.try_wait().unwrap().is_none(),
            "proxy exited before binding"
        );
        control_socket.exists()
            && TcpStream::connect(("127.0.0.1", listener)).is_ok()
            && TcpStream::connect(("127.0.0.1", admin)).is_ok()
    });
    let mut downstream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], listener)),
        Duration::from_secs(2),
    )
    .unwrap();
    downstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    downstream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    keepalive_get(&mut downstream, "/first");
    wait(|| get(admin, "/stats/prometheus").contains("envoy_llmproxy_metadata_durable 1\n"));

    capture["policy"]["version"] = "second".into();
    std::fs::write(
        &bootstrap,
        declarative_bootstrap(listener, admin, upstream.address.port(), &capture),
    )
    .unwrap();
    assert!(Command::new("kill")
        .args(["-HUP", &proxy.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    wait(|| {
        std::fs::read_to_string(&log)
            .unwrap()
            .matches("SIGHUP: config reload succeeded")
            .count()
            == 1
    });
    keepalive_get(&mut downstream, "/second");
    wait(|| get(admin, "/stats/prometheus").contains("envoy_llmproxy_metadata_durable 2\n"));

    let status = control(&control_socket, serde_json::json!({"command":"Status"}));
    assert_eq!(status["disabled"], false);
    let generation = status["generation"].as_u64().unwrap();
    let disabled = control(
        &control_socket,
        serde_json::json!({"command":"Disable","expected_generation":generation}),
    );
    assert_eq!(disabled["disabled"], true);
    let disabled_generation = disabled["generation"].as_u64().unwrap();
    assert!(disabled_generation > generation);
    let stale = control(
        &control_socket,
        serde_json::json!({"command":"Enable","expected_generation":generation}),
    );
    assert!(stale["error"].is_string(), "{stale}");
    keepalive_get(&mut downstream, "/disabled");

    capture["policy"]["version"] = "third".into();
    std::fs::write(
        &bootstrap,
        declarative_bootstrap(listener, admin, upstream.address.port(), &capture),
    )
    .unwrap();
    assert!(Command::new("kill")
        .args(["-HUP", &proxy.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    wait(|| {
        std::fs::read_to_string(&log)
            .unwrap()
            .matches("SIGHUP: config reload succeeded")
            .count()
            == 2
    });
    let status = control(&control_socket, serde_json::json!({"command":"Status"}));
    assert_eq!(status["disabled"], true);
    assert_eq!(status["generation"], disabled_generation);
    keepalive_get(&mut downstream, "/disabled-after-reload");
    assert!(get(admin, "/stats/prometheus").contains("envoy_llmproxy_metadata_durable 2\n"));
    let enabled = control(
        &control_socket,
        serde_json::json!({"command":"Enable","expected_generation":disabled_generation}),
    );
    assert_eq!(enabled["disabled"], false);
    assert!(enabled["generation"].as_u64().unwrap() > disabled_generation);
    keepalive_get(&mut downstream, "/third");
    wait(|| get(admin, "/stats/prometheus").contains("envoy_llmproxy_metadata_durable 3\n"));
    drop(downstream);
    assert!(Command::new("kill")
        .args(["-TERM", &proxy.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    wait(|| proxy.0.try_wait().unwrap().is_some());
    drop(agent);
    let agent_config: Config = serde_json::from_value(agent_config).unwrap();
    let (active, recovery) = agent_config.load_keys().unwrap();
    let spool = MetadataSpool::open(agent_config.spool_config(), active, recovery).unwrap();
    let records = spool.replay(0, 64, 1048576).unwrap();
    assert_eq!(
        records.len(),
        3,
        "disabled requests must never reach the spool"
    );
    let records: Vec<proxy_observability::records::RequestRecord> = records
        .iter()
        .map(|record| serde_json::from_slice(&record.payload).unwrap())
        .collect();
    for (record, version) in records.iter().zip(["first", "second", "third"]) {
        let pinned = record.capture_policy_version.as_deref().unwrap();
        assert!(pinned.starts_with(&format!("{version}:")));
        assert_eq!(pinned.rsplit(':').next().unwrap().len(), 64);
        assert_eq!(record.status, Some(200));
        assert_eq!(record.tenant_id, "default");
        assert_eq!(record.selected_cluster.as_deref(), Some("backend"));
        assert_eq!(record.physical_attempt_count, 1);
    }
}

/// Upstream that answers only after `release` is set, so a request can span
/// SIGTERM. `arrived` counts requests that reached it.
fn gated_mock(release: Arc<AtomicBool>, arrived: Arc<std::sync::atomic::AtomicUsize>) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let halted = stop.clone();
    let thread = std::thread::spawn(move || {
        while !halted.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let _ = stream.read(&mut [0; 4096]);
                    arrived.fetch_add(1, Ordering::SeqCst);
                    while !release.load(Ordering::SeqCst) && !halted.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => break,
            }
        }
    });
    Mock {
        address,
        stop,
        thread: Some(thread),
    }
}

/// A request that spans SIGTERM completes during the drain and its record is
/// still delivered to the agent before the process exits: capture delivery is
/// flushed only after the workers have drained.
#[test]
fn a_request_spanning_sigterm_is_captured() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("agent.sock");
    let control_socket = temp.path().join("control.sock");
    let key = temp.path().join("key");
    std::fs::write(&key, [9; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let uid = runtime.block_on(async {
        tokio::net::UnixStream::pair()
            .unwrap()
            .0
            .peer_cred()
            .unwrap()
            .uid()
    });
    let agent_config = serde_json::json!({
        "version":1,"mode":"metadata_spool_only","socket_path":socket,"node_id":"test-node",
        "producers":[{"producer_id":"test-proxy","uid":uid,"tenants":["default"]}],
        "spool":{"directory":temp.path().join("spool"),"max_record_bytes":524288,
            "max_disk_bytes":4194304,"cache_bytes":4194304},
        "active_key_id":"key","keys":[{"key_id":"key","key_file":key}]
    });
    let agent = collector(serde_json::from_value(agent_config.clone()).unwrap());
    let release = Arc::new(AtomicBool::new(false));
    let arrived = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let upstream = gated_mock(release.clone(), arrived.clone());
    let (listener, admin) = (port(), port());
    let capture = serde_json::json!({
        "version":1,"metadata":{"enabled":true,"max_attempts":8},"policy":{"version":"drain"},
        "endpoint":{"unix_socket_path":socket,"expected_agent_uid":uid,
            "expected_node_id":"test-node","producer_id":"test-proxy"},
        "emergency_control":{"unix_socket_path":control_socket,"operator_uid":uid}
    });
    let bootstrap = temp.path().join("proxy.yaml");
    std::fs::write(
        &bootstrap,
        declarative_bootstrap(listener, admin, upstream.address.port(), &capture),
    )
    .unwrap();
    let mut proxy = Proxy(
        Command::new(BIN)
            .arg("-c")
            .arg(&bootstrap)
            .args(["--concurrency", "1", "--drain-time-s", "600"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait(|| {
        assert!(proxy.0.try_wait().unwrap().is_none(), "proxy exited early");
        control_socket.exists()
            && TcpStream::connect(("127.0.0.1", listener)).is_ok()
            && TcpStream::connect(("127.0.0.1", admin)).is_ok()
    });

    let mut client = TcpStream::connect(("127.0.0.1", listener)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        client,
        "GET /spanning HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    wait(|| arrived.load(Ordering::SeqCst) == 1);

    assert!(Command::new("kill")
        .args(["-TERM", &proxy.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    wait(|| get(admin, "/ready").contains("DRAINING"));
    release.store(true, Ordering::SeqCst);
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    wait(|| proxy.0.try_wait().unwrap().is_some());
    assert!(proxy.0.try_wait().unwrap().unwrap().success());

    drop(agent);
    let agent_config: Config = serde_json::from_value(agent_config).unwrap();
    let (active, recovery) = agent_config.load_keys().unwrap();
    let spool = MetadataSpool::open(agent_config.spool_config(), active, recovery).unwrap();
    let records = spool.replay(0, 64, 1048576).unwrap();
    assert_eq!(records.len(), 1, "the drained request must be captured");
    let record: proxy_observability::records::RequestRecord =
        serde_json::from_slice(&records[0].payload).unwrap();
    assert_eq!(record.status, Some(200));
}

struct Proxy(Child);
impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Mock {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
fn mock() -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let halted = stop.clone();
    let thread = std::thread::spawn(move || {
        while !halted.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // On macOS an accepted socket inherits the listener's
                    // O_NONBLOCK. Left set, a request that has not arrived yet
                    // reads as WouldBlock, the mock answers and closes with
                    // the request unread, and the kernel resets the
                    // connection under the proxy (UC, 502).
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    // Read the whole head (requests here carry no body) so
                    // dropping `stream` never closes it with request bytes
                    // unread.
                    let mut head = Vec::new();
                    let mut chunk = [0; 4096];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => break,
            }
        }
    });
    Mock {
        address,
        stop,
        thread: Some(thread),
    }
}
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn get(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}
fn wait(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !condition() {
        assert!(Instant::now() < deadline, "integration deadline exceeded");
        std::thread::sleep(Duration::from_millis(20));
    }
}
struct Collector {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Collector {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
fn collector(config: Config) -> Collector {
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let (ready, started) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let agent = Agent::start(config).unwrap();
            ready.send(()).unwrap();
            agent
                .run(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
    });
    started.recv_timeout(Duration::from_secs(10)).unwrap();
    Collector {
        stop: Some(stop),
        thread: Some(thread),
    }
}

#[test]
fn metadata_agent_outage_preserves_forwarding_and_recovery_commits_actual_records() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("agent.sock");
    let key = temp.path().join("key");
    std::fs::write(&key, [9; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let uid = runtime.block_on(async {
        tokio::net::UnixStream::pair()
            .unwrap()
            .0
            .peer_cred()
            .unwrap()
            .uid()
    });
    let config = serde_json::json!({"version":1,"mode":"metadata_spool_only","socket_path":socket,"node_id":"test-node",
        "producers":[{"producer_id":"test-proxy","uid":uid,"tenants":["default"]}],
        "spool":{"directory":temp.path().join("spool"),"max_record_bytes":524288,"max_disk_bytes":4194304,"cache_bytes":4194304},
        "active_key_id":"key","keys":[{"key_id":"key","key_file":key}]});
    let upstream = mock();
    let listener = port();
    let admin = port();
    let bootstrap = temp.path().join("proxy.yaml");
    std::fs::write(&bootstrap, format!(r#"
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin} }}
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress
                route_config:
                  name: local
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route: {{ cluster: backend }}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: backend
      type: STATIC
      connect_timeout: 1s
      load_assignment:
        cluster_name: backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: {upstream} }}
"#, upstream=upstream.address.port())).unwrap();
    let mut proxy = Proxy(
        Command::new(BIN)
            .arg("-c")
            .arg(&bootstrap)
            .args([
                "--concurrency",
                "1",
                "--drain-time-s",
                "0",
                "--request-records-agent",
            ])
            .arg(&socket)
            .args([
                "--request-records-agent-uid",
                &uid.to_string(),
                "--request-records-agent-node",
                "test-node",
                "--request-records-producer",
                "test-proxy",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait(|| {
        assert!(
            proxy.0.try_wait().unwrap().is_none(),
            "proxy exited before binding"
        );
        TcpStream::connect(("127.0.0.1", admin)).is_ok()
            && TcpStream::connect(("127.0.0.1", listener)).is_ok()
    });
    assert!(get(listener, "/during-outage").starts_with("HTTP/1.1 200"));
    wait(|| get(admin, "/stats/prometheus").contains("envoy_llmproxy_metadata_write_failures 1"));
    assert!(get(admin, "/ready").starts_with("HTTP/1.1 200"));
    let agent = collector(serde_json::from_value(config.clone()).unwrap());
    assert!(get(listener, "/after-recovery").starts_with("HTTP/1.1 200"));
    wait(|| get(admin, "/stats/prometheus").contains("envoy_llmproxy_metadata_durable 1"));
    let scrape = get(admin, "/stats/prometheus");
    assert!(scrape.contains("envoy_llmproxy_metadata_written 1"));
    assert!(scrape.contains("envoy_llmproxy_metadata_queue_depth 0"));
    assert!(scrape.contains("envoy_llmproxy_metadata_admission{outcome=\"closed\"} 0"));
    let _ = Command::new("kill")
        .args(["-TERM", &proxy.0.id().to_string()])
        .status();
    wait(|| proxy.0.try_wait().unwrap().is_some());
    drop(agent);
    let config: Config = serde_json::from_value(config).unwrap();
    let (active, recovery) = config.load_keys().unwrap();
    let spool = MetadataSpool::open(config.spool_config(), active, recovery).unwrap();
    let records = spool.replay(0, 64, 1048576).unwrap();
    assert_eq!(records.len(), 1);
    let record: proxy_observability::records::RequestRecord =
        serde_json::from_slice(&records[0].payload).unwrap();
    assert_eq!(record.status, Some(200));
    assert_eq!(record.tenant_id, "default");
    assert_eq!(record.selected_cluster.as_deref(), Some("backend"));
    assert_eq!(record.physical_attempt_count, 1);
    assert!(record.user_id.is_none());
    assert!(record.usage.is_none());
}

#[test]
fn metadata_agent_cli_rejects_dual_modes_and_missing_authentication() {
    for args in [
        vec!["--request-records-agent", "/private/tmp/agent.sock"],
        vec![
            "--request-records-file",
            "/private/tmp/records",
            "--request-records-agent",
            "/private/tmp/agent.sock",
            "--request-records-agent-uid",
            "0",
            "--request-records-agent-node",
            "node",
            "--request-records-producer",
            "proxy",
        ],
        vec!["--request-records-agent-uid", "0"],
    ] {
        assert!(!Command::new(BIN)
            .args(args)
            .output()
            .unwrap()
            .status
            .success());
    }
}

/// GET with extra request headers; returns `(status line, body)`. Bounded by
/// the same 2 s socket timeouts as `get`.
fn get_with(port: u16, path: &str, headers: &[(&str, &str)]) -> (String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let extra: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: test.local\r\n{extra}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((&response, ""));
    (
        head.lines().next().unwrap_or("").to_string(),
        body.to_string(),
    )
}

/// Real agent (in-process, as in the outage test), real proxy binary with an
/// admin token, and a mock upstream. Field order is drop order: the proxy
/// dies first, then the agent, upstream and temp directory, on every path.
struct InspectRig {
    proxy: Proxy,
    _agent: Collector,
    _upstream: Mock,
    _temp: tempfile::TempDir,
    listener: u16,
    admin: u16,
}

const ADMIN_TOKEN: &str = "inspect-e2e-token";

fn inspect_rig(inspect: bool) -> InspectRig {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("agent.sock");
    let key = temp.path().join("key");
    std::fs::write(&key, [9; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let uid = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::net::UnixStream::pair()
                .unwrap()
                .0
                .peer_cred()
                .unwrap()
                .uid()
        });
    let config = serde_json::json!({"version":1,"mode":"metadata_spool_only","socket_path":socket,"node_id":"test-node",
        "producers":[{"producer_id":"test-proxy","uid":uid,"tenants":["default"],"inspect":inspect}],
        "spool":{"directory":temp.path().join("spool"),"max_record_bytes":524288,"max_disk_bytes":4194304,"cache_bytes":4194304},
        "active_key_id":"key","keys":[{"key_id":"key","key_file":key}]});
    let agent = collector(serde_json::from_value(config).unwrap());
    let upstream = mock();
    let listener = port();
    let admin = port();
    let bootstrap = temp.path().join("proxy.yaml");
    std::fs::write(
        &bootstrap,
        declarative_bootstrap_without_capture(listener, admin, upstream.address.port()),
    )
    .unwrap();
    let mut proxy = Proxy(
        Command::new(BIN)
            .arg("-c")
            .arg(&bootstrap)
            .args([
                "--concurrency",
                "1",
                "--drain-time-s",
                "0",
                "--request-records-agent",
            ])
            .arg(&socket)
            .args([
                "--request-records-agent-uid",
                &uid.to_string(),
                "--request-records-agent-node",
                "test-node",
                "--request-records-producer",
                "test-proxy",
                // The first poll waits one period; keep it short for tests.
                "--capture-spool-poll-interval-ms",
                "100",
            ])
            .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait(|| {
        assert!(
            proxy.0.try_wait().unwrap().is_none(),
            "proxy exited before binding"
        );
        TcpStream::connect(("127.0.0.1", admin)).is_ok()
            && TcpStream::connect(("127.0.0.1", listener)).is_ok()
    });
    InspectRig {
        proxy,
        _agent: agent,
        _upstream: upstream,
        _temp: temp,
        listener,
        admin,
    }
}

/// The plain bootstrap of the outage test, shared here: no node metadata, the
/// agent is named on the command line.
fn declarative_bootstrap_without_capture(listener: u16, admin: u16, upstream: u16) -> String {
    declarative_bootstrap(listener, admin, upstream, &serde_json::json!({})).replace(
        "node:\n  id: test-proxy\n  cluster: test\n  metadata:\n    \"io.llmproxy.capture\": {}\n",
        "",
    )
}

#[test]
fn spool_inspection_pages_records_and_gates_them_behind_the_admin_token() {
    let rig = inspect_rig(true);
    let ids = ["inspect-req-1", "inspect-req-2", "inspect-req-3"];
    for id in ids {
        let (status, _) = get_with(rig.listener, "/x", &[("x-request-id", id)]);
        assert!(status.contains(" 200"), "{status}");
    }
    let bearer = format!("Bearer {ADMIN_TOKEN}");
    let auth = [("authorization", bearer.as_str())];

    // Poll until the agent reports all three durable; the ungated stats read.
    let mut stats = serde_json::Value::Null;
    wait(|| {
        let (status, body) = get_with(rig.admin, "/capture/spool/stats", &[]);
        if !status.contains(" 200") {
            return false;
        }
        stats = serde_json::from_str(&body).unwrap();
        stats["durable_total"].as_u64().unwrap_or(0) >= 3
            && stats["retained_records"].as_u64().unwrap_or(0) >= 3
    });
    assert!(stats["retained_records"].as_u64().unwrap() >= 3, "{stats}");
    assert!(stats["durable_total"].as_u64().unwrap() >= 3, "{stats}");

    // Page through with limit=2: 2 records, then the remainder.
    let page = |after: u64| -> serde_json::Value {
        let (status, body) = get_with(
            rig.admin,
            &format!("/capture/spool/records?after={after}&limit=2"),
            &auth,
        );
        assert!(status.contains(" 200"), "{status} {body}");
        serde_json::from_str(&body).unwrap()
    };
    let first = page(0);
    let first_records = first["records"].as_array().unwrap();
    assert_eq!(first_records.len(), 2, "{first}");
    let cursor = first["next_after_sequence"].as_u64().unwrap();
    let second = page(cursor);
    let second_records = second["records"].as_array().unwrap();
    assert_eq!(second_records.len(), 1, "{second}");
    let third = page(second["next_after_sequence"].as_u64().unwrap());
    assert!(third["records"].as_array().unwrap().is_empty(), "{third}");

    let all: Vec<&serde_json::Value> = first_records.iter().chain(second_records).collect();
    let sequences: Vec<u64> = all
        .iter()
        .map(|r| r["sequence"].as_u64().unwrap())
        .collect();
    assert!(
        sequences.windows(2).all(|w| w[0] < w[1]),
        "sequences must strictly increase without duplicates: {sequences:?}"
    );
    // The proxy mints its own request ids (a client x-request-id is not
    // adopted), so identity is checked by shape and uniqueness plus the
    // fields of the requests actually sent.
    let mut seen: Vec<&str> = all
        .iter()
        .map(|r| r["record"]["request_id"].as_str().unwrap())
        .collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), ids.len(), "one distinct record per request");
    assert!(seen
        .iter()
        .all(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())));
    assert!(all.iter().all(|r| r["record"]["method"] == "GET"
        && r["record"]["status"] == 200
        && r["record"]["selected_cluster"] == "backend"));
    assert!(all.iter().all(|r| r["record"]["tenant_id"] == "default"));

    // No token: refused, and the body carries no record field values.
    let (status, body) = get_with(rig.admin, "/capture/spool/records?limit=2", &[]);
    assert!(status.contains(" 401"), "{status}");
    for id in ids {
        assert!(!body.contains(id), "refusal leaked a record value: {body}");
    }
    for record in &all {
        let id = record["record"]["request_id"].as_str().unwrap();
        assert!(!body.contains(id), "refusal leaked a record value: {body}");
    }
    assert!(
        !body.contains("tenant_id") && !body.contains("sequence"),
        "{body}"
    );
    let (status, _) = get_with(
        rig.admin,
        "/capture/spool/records?limit=2",
        &[("authorization", "Bearer wrong")],
    );
    assert!(status.contains(" 401"), "{status}");

    wait(|| {
        let scrape = get(rig.admin, "/stats/prometheus");
        scrape.contains("envoy_llmproxy_capture_agent_reachable 1")
            && scrape.contains("envoy_llmproxy_capture_spool_stats_available 1")
    });
    drop(rig.proxy);
}

#[test]
fn spool_inspection_without_an_inspect_grant_is_forbidden() {
    let rig = inspect_rig(false);
    let bearer = format!("Bearer {ADMIN_TOKEN}");
    let (status, body) = get_with(
        rig.admin,
        "/capture/spool/records?limit=2",
        &[("authorization", bearer.as_str())],
    );
    assert!(status.contains(" 403"), "{status} {body}");
    let (status, _) = get_with(rig.admin, "/capture/spool/stats", &[]);
    assert!(status.contains(" 403"), "{status}");
    // The agent answered (with a refusal), so it is reachable; only the stats
    // are unavailable. Reachable 0 here would warn about an outage that is
    // really a missing `"inspect": true`.
    wait(|| {
        let scrape = get(rig.admin, "/stats/prometheus");
        scrape.contains("envoy_llmproxy_capture_agent_reachable 1")
            && scrape.contains("envoy_llmproxy_capture_spool_stats_available 0")
    });
}
