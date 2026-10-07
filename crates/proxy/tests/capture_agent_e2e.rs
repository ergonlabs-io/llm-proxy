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
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let _ = stream.read(&mut [0; 4096]);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
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
        "spool":{"directory":temp.path().join("spool"),"max_record_bytes":524288,"max_segment_bytes":1048576,"max_disk_bytes":4194304,"max_segments":8,"max_segment_age_seconds":60},
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
