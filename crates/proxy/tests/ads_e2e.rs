//! Acceptance: boot the real `llm-proxy` binary against a scripted control
//! plane (`testing/controlplane`'s `Harness`) and prove the ADS pipeline works
//! end to end in the shipped process. A control-plane-delivered cluster
//! reaches `/config_dump` and routes real traffic. The proxy also boots and
//! serves its static config when the control plane is unreachable.
//!
//! These tests do not catch the two ordering bugs. Mutating the ACK to run
//! before the snapshot is applied, or publishing before the clusters are
//! installed, leaves all three green. Observing the ACK costs a round trip,
//! so the racing apply nearly always wins. Publish order is now enforced by
//! the type system: `install_clusters` returns a `ClustersInstalled` receipt
//! that `publish_to_workers` consumes. ACK-before-apply is pinned one layer
//! down by `proxy-xds`'s
//! `the_ack_does_not_reach_the_wire_until_the_handler_future_resolves`, which
//! proves the seam works but not that `main.rs` uses it.

mod common;

use common::free_port;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use controlplane::{DeltaHarness, Harness, RequestKind, Step};
use prost::Message;
use proxy_api::envoy::config::cluster::v3 as cluster_v3;
use proxy_api::envoy::config::core::v3 as core_v3;
use proxy_api::envoy::config::endpoint::v3 as endpoint_v3;
use proxy_api::envoy::config::listener::v3 as listener_v3;
use proxy_api::envoy::config::route::v3 as route_v3;
use proxy_api::envoy::extensions::filters::http::router::v3 as router_v3;
use proxy_api::envoy::extensions::filters::network::http_connection_manager::v3 as hcm_v3;
use proxy_api::envoy::extensions::transport_sockets::tls::v3 as tls_v3;
use proxy_api::envoy::service::discovery::v3::{DeltaDiscoveryResponse, Resource};
use rcgen::{CertificateParams, DnType, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio_rustls::TlsConnector;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

/// Full `type_url` a CDS `DiscoveryResponse` carries -- matches
/// `crates/proxy-xds/src/apply.rs`'s own private constant of the same value.
const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
/// Bare type name `Any::type_url` is built from -- matches
/// `crates/proxy-xds/tests/apply.rs`'s own `CLUSTER_TYPE`.
const CLUSTER_TYPE: &str = "envoy.config.cluster.v3.Cluster";
/// Bare type name a dynamically delivered listener carries in `Any`.
const LISTENER_TYPE: &str = "envoy.config.listener.v3.Listener";
/// Bare type name of an HCM's typed configuration.
const HCM_TYPE: &str =
    "envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
/// Bare type name of the terminal router filter configuration.
const ROUTER_TYPE: &str = "envoy.extensions.filters.http.router.v3.Router";
/// Full `type_url` an EDS `DiscoveryResponse` carries -- matches
/// `crates/proxy-xds/src/apply.rs`'s own private `EDS_TYPE_URL`.
const EDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
/// Bare type name `Any::type_url` is built from, for a `ClusterLoadAssignment`
/// -- matches `crates/proxy-xds/tests/apply.rs`'s own `ENDPOINT_TYPE`.
const ENDPOINT_TYPE: &str = "envoy.config.endpoint.v3.ClusterLoadAssignment";
/// Full `type_url` an SDS `DiscoveryRequest` subscribes to -- matches
/// `crates/proxy-xds/src/apply.rs`'s own private `SDS_TYPE_URL`.
const SDS_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";
/// Full `type_url` an RDS `DiscoveryRequest` subscribes to -- matches
/// `crates/proxy-xds/src/apply.rs`'s own private `RDS_TYPE_URL`.
const RDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";
/// Full `type_url` an LDS `DiscoveryResponse` carries.
const LDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";

/// How long to wait for the freshly spawned `llm-proxy` to become
/// connectable -- a liveness backstop, not a speed assertion (matches every
/// sibling `tests/*.rs` file's `STARTUP_TIMEOUT`).
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait for the scripted control plane's CDS response to be
/// ACKed. Generous: a loopback gRPC round trip plus `apply_snapshot` is
/// normally sub-millisecond; this only turns a genuine hang into a named
/// failure (rule 14) rather than bounding anything tight.
const ACK_TIMEOUT: Duration = Duration::from_secs(10);

// --------------------------------------------------------------- helpers --

/// A reserved-then-immediately-dropped port: nothing is listening on it, so
/// a connect attempt fails fast -- what test C's ADS cluster needs to point
/// at an unreachable control plane. Same technique as
/// `tests/otlp_trace_e2e.rs`'s own `dead_addr`.
fn dead_addr() -> SocketAddr {
    format!("127.0.0.1:{}", free_port()).parse().unwrap()
}

fn wait_for_connectable(addr: (&str, u16), timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn spawn_line_reader(
    mut reader: BufReader<impl std::io::Read + Send + 'static>,
) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line.clone()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

fn drain_available_lines(rx: &mpsc::Receiver<String>) -> Vec<String> {
    let mut lines = Vec::new();
    while let Ok(line) = rx.try_recv() {
        lines.push(line);
    }
    lines
}

/// Kills and reaps a child process on drop -- see `tests/stats_e2e.rs`'s
/// identical type for why (AGENTS.md "Running The Product": a hand-run process that
/// outlives its test is a leak, not just a red test).
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_proxy(config_path: &std::path::Path) -> (ChildGuard, mpsc::Receiver<String>) {
    let mut child = Command::new(BIN)
        .args(["-c", config_path.to_str().unwrap(), "--concurrency", "1"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn llm-proxy");
    let stderr = child.stderr.take().expect("child stderr not piped");
    let rx = spawn_line_reader(BufReader::new(stderr));
    (ChildGuard(child), rx)
}

fn terminate(child: &mut ChildGuard) {
    let pid = child.0.id().to_string();
    let _ = Command::new("kill").arg("-TERM").arg(&pid).status();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(_)) = child.0.try_wait() {
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.0.kill();
            let _ = child.0.wait();
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Sends a plain `GET <path> HTTP/1.1` with `Connection: close` and returns
/// the full response (status line + headers + body) read up to EOF -- same
/// shape as every sibling `tests/*.rs` file's own `get`.
fn get(addr: SocketAddr, path: &str, host: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set_read_timeout");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read response to EOF");
    String::from_utf8_lossy(&response).to_string()
}

/// A mock upstream: accepts connections in a loop, forever, answering each
/// with a quick `200 OK` -- what a CDS-introduced cluster forwards to in
/// test B, and what the static `backend` cluster forwards to in test C.
/// Same shape as `tests/stats_e2e.rs`'s own `spawn_mock_upstream`.
fn spawn_mock_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            });
        }
    });
    addr
}

/// Wrap an encoded proto message as a `google.protobuf.Any`, the same shape
/// a `DiscoveryResponse.resources` entry carries on the wire -- identical to
/// `crates/proxy-xds/tests/apply.rs`'s own `any_of`.
fn any_of<T: Message>(msg: &T, type_name: &str) -> prost_types::Any {
    prost_types::Any {
        type_url: format!("type.googleapis.com/{type_name}"),
        value: msg.encode_to_vec(),
    }
}

/// A minimal, valid `STATIC` cluster with one endpoint at `127.0.0.1:port`
/// -- just enough for `proxy_config::lower_dynamic_cluster` to accept it.
/// Identical fixture to `crates/proxy-xds/tests/apply.rs`'s own
/// `minimal_cluster` (duplicated per this file's own module doc: no shared
/// test-fixture crate exists for this shape).
fn minimal_cluster(name: &str, port: u32) -> cluster_v3::Cluster {
    cluster_v3::Cluster {
        name: name.to_string(),
        cluster_discovery_type: Some(cluster_v3::cluster::ClusterDiscoveryType::Type(
            cluster_v3::cluster::DiscoveryType::Static as i32,
        )),
        load_assignment: Some(endpoint_v3::ClusterLoadAssignment {
            cluster_name: name.to_string(),
            endpoints: vec![endpoint_v3::LocalityLbEndpoints {
                lb_endpoints: vec![endpoint_v3::LbEndpoint {
                    host_identifier: Some(endpoint_v3::lb_endpoint::HostIdentifier::Endpoint(
                        endpoint_v3::Endpoint {
                            address: Some(core_v3::Address {
                                address: Some(core_v3::address::Address::SocketAddress(
                                    core_v3::SocketAddress {
                                        address: "127.0.0.1".to_string(),
                                        port_specifier: Some(
                                            core_v3::socket_address::PortSpecifier::PortValue(port),
                                        ),
                                        ..Default::default()
                                    },
                                )),
                            }),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A minimal `ClusterLoadAssignment` naming `cluster_name`, with one endpoint
/// at `host:port` -- just enough for `proxy_config::lower_dynamic_endpoints`
/// to accept it. Identical fixture shape to `crates/proxy-xds/tests/apply.rs`'s
/// own `minimal_assignment` (duplicated per this file's own module doc).
fn minimal_assignment(
    cluster_name: &str,
    host: &str,
    port: u32,
) -> endpoint_v3::ClusterLoadAssignment {
    endpoint_v3::ClusterLoadAssignment {
        cluster_name: cluster_name.to_string(),
        endpoints: vec![endpoint_v3::LocalityLbEndpoints {
            lb_endpoints: vec![endpoint_v3::LbEndpoint {
                host_identifier: Some(endpoint_v3::lb_endpoint::HostIdentifier::Endpoint(
                    endpoint_v3::Endpoint {
                        address: Some(core_v3::Address {
                            address: Some(core_v3::address::Address::SocketAddress(
                                core_v3::SocketAddress {
                                    address: host.to_string(),
                                    port_specifier: Some(
                                        core_v3::socket_address::PortSpecifier::PortValue(port),
                                    ),
                                    ..Default::default()
                                },
                            )),
                        }),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// Polls `harness.log` (bounded by `ACK_TIMEOUT`) until it has recorded at
/// least 2 requests -- the CDS subscription's `Initial` request plus one
/// more. This only detects *arrival*; it is deliberately NOT the property
/// under test (see this file's module doc on why the load-bearing check
/// that follows every call site of this function is a single, unretried
/// read instead of another poll).
async fn wait_for_second_request(harness: &Harness, stderr: &mpsc::Receiver<String>) {
    let deadline = Instant::now() + ACK_TIMEOUT;
    loop {
        if harness.log.snapshot().len() >= 2 {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out after {ACK_TIMEOUT:?} waiting for the CDS ACK to be recorded; \
                 stderr so far: {:?}",
                drain_available_lines(stderr)
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ------------------------------------------------------------------ test A --

/// The name of the cluster test A's scripted CDS response introduces.
const TEST_A_NEW_CLUSTER: &str = "ads_added_cluster";

/// No listeners at all -- test A only needs `admin` (to read `/config_dump`)
/// and `dynamic_resources` naming the harness as the ADS cluster.
fn bootstrap_no_listeners(admin_port: u16, ads_addr: SocketAddr, api_type: &str) -> String {
    format!(
        r#"
node:
  id: proxy-1
  cluster: proxy-fleet

admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin_port} }}

dynamic_resources:
  ads_config:
    api_type: {api_type}
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: {{ cluster_name: xds_cluster }}
  cds_config: {{ ads: {{}}, resource_api_version: V3 }}

static_resources:
  listeners: []
  clusters:
    - name: xds_cluster
      type: STATIC
      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {ads_ip}, port_value: {ads_port} }}
"#,
        ads_ip = ads_addr.ip(),
        ads_port = ads_addr.port(),
    )
}

/// Closes gap 2 (the `Publish` closure's `.await`) as observed through gap
/// 1's OTHER half: `apply_snapshot`'s step 5, `ConfigPublisher::publish`, is
/// what `/config_dump` reads through (`start_admin`'s doc names the same
/// `SnapshotHandles` registry). Quoting `start_ads`'s doc directly:
/// **"NO TEST IN THIS CRATE CATCHES THE LOSS OF THIS `.await`"** (the
/// `reply_rx.await` that gates the ACK on the control loop having actually
/// applied the response) -- this is that test, against the real binary.
///
/// If `main.rs` sent the ACK before `apply_snapshot` returned (i.e. before
/// `ConfigPublisher::publish` ran), this test would observe the ACK on the
/// wire while `/config_dump` still showed the boot snapshot with no
/// `ads_added_cluster` -- and the single, unretried read below would catch
/// exactly that.
#[tokio::test(flavor = "multi_thread")]
async fn a_cds_delivered_cluster_reaches_config_dump_in_the_running_binary() {
    let harness = Harness::spawn(vec![Step::Send {
        type_url: CDS_TYPE_URL.to_string(),
        version_info: "v1".to_string(),
        nonce: "n1".to_string(),
        resources: vec![any_of(
            &minimal_cluster(TEST_A_NEW_CLUSTER, 19999),
            CLUSTER_TYPE,
        )],
    }])
    .await
    .expect("harness spawns");

    let admin_port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-ads-e2e-a-{}-{admin_port}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &config_path,
        bootstrap_no_listeners(admin_port, harness.addr, "GRPC"),
    )
    .expect("write config");

    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let admin_ready = wait_for_connectable(("127.0.0.1", admin_port), STARTUP_TIMEOUT);
    assert!(
        admin_ready,
        "admin at 127.0.0.1:{admin_port} did not become connectable in time; stderr so far: {:?}",
        drain_available_lines(&stderr_rx)
    );

    // Bounded poll for ARRIVAL of the ACK -- retries here are fine, they
    // only detect "has it shown up yet", never the property under test.
    wait_for_second_request(&harness, &stderr_rx).await;
    let log = harness.log.snapshot();
    assert_eq!(
        log[1].kind(),
        RequestKind::Ack,
        "expected the second recorded request to be an ACK of the scripted CDS response, \
         got {:?}",
        log[1]
    );

    // The load-bearing read: exactly ONE GET, no retry loop. A retry loop
    // here would let a `main.rs` that ACKs before publishing catch up and
    // pass anyway -- see this file's module doc.
    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    let dump = get(admin_addr, "/config_dump", "admin.local");
    assert!(
        dump.contains(TEST_A_NEW_CLUSTER),
        "expected /config_dump to already show the ADS-introduced cluster \"{TEST_A_NEW_CLUSTER}\" \
         the instant its ACK was observed on the wire (proving `apply_snapshot` published before \
         `main.rs` let the ACK go out) -- got:\n{dump}"
    );

    terminate(&mut child);
    let _ = std::fs::remove_file(&config_path);
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn delta_cds_transport_reaches_config_dump_in_running_binary() {
    let cluster = minimal_cluster("delta_added_cluster", 19998);
    let harness = DeltaHarness::spawn(DeltaDiscoveryResponse {
        type_url: CDS_TYPE_URL.to_string(),
        nonce: "delta-n1".to_string(),
        resources: vec![Resource {
            name: cluster.name.clone(),
            version: "resource-v1".to_string(),
            resource: Some(any_of(&cluster, CLUSTER_TYPE)),
            ..Default::default()
        }],
        ..Default::default()
    })
    .await
    .expect("delta harness spawns");
    let admin_port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-delta-ads-e2e-{}-{admin_port}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &config_path,
        bootstrap_no_listeners(admin_port, harness.addr, "DELTA_GRPC"),
    )
    .expect("write config");
    let (mut child, stderr_rx) = spawn_proxy(&config_path);
    assert!(
        wait_for_connectable(("127.0.0.1", admin_port), STARTUP_TIMEOUT),
        "admin did not become connectable; stderr: {:?}",
        drain_available_lines(&stderr_rx)
    );

    let deadline = Instant::now() + ACK_TIMEOUT;
    while harness.requests().len() < 2 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let requests = harness.requests();
    assert!(requests.len() >= 2, "delta request and ACK must reach wire");
    assert_eq!(requests[1].response_nonce, "delta-n1");
    assert!(requests[1].error_detail.is_none());

    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    let dump = get(admin_addr, "/config_dump", "admin.local");
    assert!(dump.contains("delta_added_cluster"), "got:\n{dump}");

    terminate(&mut child);
    let _ = std::fs::remove_file(&config_path);
    harness.shutdown().await;
}

// ------------------------------------------------------------------ test B --

/// The name of the cluster test B's static listener routes to, before it
/// exists anywhere -- only CDS ever defines it.
const TEST_B_DYNAMIC_CLUSTER: &str = "dynamic_backend";

/// One static, already-bound listener whose route already names
/// `dynamic_backend` -- a cluster this bootstrap never defines statically.
/// `dynamic_resources` subscribes to CDS only (no LDS): the listener itself
/// never changes across this test.
fn bootstrap_static_listener_dynamic_cluster(listener_port: u16, ads_addr: SocketAddr) -> String {
    format!(
        r#"
node:
  id: proxy-1
  cluster: proxy-fleet

dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: {{ cluster_name: xds_cluster }}
  cds_config: {{ ads: {{}}, resource_api_version: V3 }}

static_resources:
  listeners:
    - name: ingress_http
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: {dynamic_cluster}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: xds_cluster
      type: STATIC
      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {ads_ip}, port_value: {ads_port} }}
"#,
        dynamic_cluster = TEST_B_DYNAMIC_CLUSTER,
        ads_ip = ads_addr.ip(),
        ads_port = ads_addr.port(),
    )
}

/// Closes gap 1 (`apply_snapshot`'s step-4/step-5 ordering) as observed
/// through real traffic rather than `/config_dump`. Quoting the doc
/// directly: step 4 (`ClusterManager::update_from_snapshot`) "must not run
/// until step 4 has already taught the cluster manager about every cluster
/// the new snapshot's routes can reach -- otherwise a worker could start
/// routing to a cluster the manager doesn't know about yet," and step 5
/// (`ConfigPublisher::publish`) "is what makes the snapshot visible to
/// workers." This test's claim is the composed, externally observable
/// promise those two sentences make together (see this file's module doc for
/// why the raw microsecond race is not reachable via HTTP behavior here):
/// once the CDS response naming
/// `dynamic_backend` is ACKed, a real request routed to it succeeds, with
/// no retry, and traffic never regresses from success back to failure
/// afterward.
///
/// **It is NOT regression coverage for either main.rs gap** -- that was the
/// hope when this test was written, and it was measured false: with
/// `start_ads`'s `reply_rx.await` deleted, and separately with `publish`
/// moved above `update_from_snapshot`, this test still passes. The
/// "unknown cluster 503" it was expected to catch does not materialise,
/// because observing the ACK takes far longer than the window the bug
/// opens. See this file's module doc.
#[tokio::test(flavor = "multi_thread")]
async fn a_cds_delivered_cluster_is_routable_by_real_traffic() {
    let upstream_addr = spawn_mock_upstream();
    let harness = Harness::spawn(vec![Step::Send {
        type_url: CDS_TYPE_URL.to_string(),
        version_info: "v1".to_string(),
        nonce: "n1".to_string(),
        resources: vec![any_of(
            &minimal_cluster(TEST_B_DYNAMIC_CLUSTER, upstream_addr.port() as u32),
            CLUSTER_TYPE,
        )],
    }])
    .await
    .expect("harness spawns");

    let listener_port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-ads-e2e-b-{}-{listener_port}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &config_path,
        bootstrap_static_listener_dynamic_cluster(listener_port, harness.addr),
    )
    .expect("write config");

    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "listener at 127.0.0.1:{listener_port} did not become connectable in time; \
         stderr so far: {:?}",
        drain_available_lines(&stderr_rx)
    );
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();

    // "Drive real requests at the proxy while the update lands": a
    // background thread (a plain OS thread, not sharing this test's tokio
    // runtime -- so it can never block the harness's own async server task)
    // hammers the listener throughout, purely to prove this holds under
    // genuinely concurrent traffic. It is NOT the load-bearing assertion --
    // see below.
    let stop = Arc::new(AtomicBool::new(false));
    let outcomes: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let bg_stop = stop.clone();
    let bg_outcomes = outcomes.clone();
    let background = std::thread::spawn(move || {
        while !bg_stop.load(Ordering::Relaxed) {
            let response = get(listener_addr, "/", "test.local");
            bg_outcomes
                .lock()
                .expect("outcomes mutex poisoned")
                .push(response.starts_with("HTTP/1.1 200"));
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    // Bounded poll for ARRIVAL of the ACK (retries fine here, same reasoning
    // as test A).
    wait_for_second_request(&harness, &stderr_rx).await;
    let log = harness.log.snapshot();
    assert_eq!(
        log[1].kind(),
        RequestKind::Ack,
        "expected the second recorded request to be an ACK of the scripted CDS response, \
         got {:?}",
        log[1]
    );

    // The load-bearing read: exactly ONE fresh request, no retry loop --
    // see this file's module doc for why a retry here would defeat the
    // point.
    let response = get(listener_addr, "/", "test.local");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected \"{TEST_B_DYNAMIC_CLUSTER}\" to already be routable the instant its CDS ACK \
         was observed on the wire -- got:\n{response}"
    );

    stop.store(true, Ordering::Relaxed);
    background
        .join()
        .expect("background traffic thread panicked");
    let outcomes = outcomes.lock().expect("outcomes mutex poisoned").clone();
    // Monotonic sanity over the concurrently-driven traffic: once the
    // cluster starts succeeding it must never flap back to failing --
    // catches a narrower, still-real regression the single post-ACK check
    // above could theoretically miss on an unlucky schedule.
    if let Some(first_success) = outcomes.iter().position(|&ok| ok) {
        assert!(
            outcomes[first_success..].iter().all(|&ok| ok),
            "background traffic flapped from success back to failure after \
             \"{TEST_B_DYNAMIC_CLUSTER}\" first became routable: {outcomes:?}"
        );
    }

    terminate(&mut child);
    let _ = std::fs::remove_file(&config_path);
    harness.shutdown().await;
}

/// A cluster that lowers cleanly but whose upstream TLS cannot be built (its
/// `trusted_ca` holds no certificate), so only `ClusterManager` rejects it.
fn cluster_with_unbuildable_tls(name: &str, port: u32) -> cluster_v3::Cluster {
    let tls = tls_v3::UpstreamTlsContext {
        common_tls_context: Some(tls_v3::CommonTlsContext {
            validation_context_type: Some(
                tls_v3::common_tls_context::ValidationContextType::ValidationContext(
                    tls_v3::CertificateValidationContext {
                        trusted_ca: Some(core_v3::DataSource {
                            specifier: Some(core_v3::data_source::Specifier::InlineString(
                                "not a certificate".to_string(),
                            )),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ),
            ),
            ..Default::default()
        }),
        ..Default::default()
    };
    cluster_v3::Cluster {
        transport_socket: Some(core_v3::TransportSocket {
            name: "envoy.transport_sockets.tls".to_string(),
            config_type: Some(core_v3::transport_socket::ConfigType::TypedConfig(any_of(
                &tls,
                "envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
            ))),
        }),
        ..minimal_cluster(name, port)
    }
}

/// S8: a CDS response with one cluster the cluster manager cannot
/// build is NACKed with that cluster's dotted path, and the whole response is
/// discarded. The same response also repoints `dynamic_backend` at a dead
/// port; serving 200 from the original upstream afterwards is the negative
/// half (a partial apply would 503), and no ACK of the bad nonce may ever be
/// sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_cds_cluster_that_fails_to_build_is_nacked_and_last_good_keeps_serving() {
    let upstream_addr = spawn_mock_upstream();
    let dead = dead_addr();
    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CDS_TYPE_URL.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![any_of(
                &minimal_cluster(TEST_B_DYNAMIC_CLUSTER, upstream_addr.port() as u32),
                CLUSTER_TYPE,
            )],
        },
        Step::WaitForAck {
            type_url: CDS_TYPE_URL.to_string(),
            version_info: "v1".to_string(),
            response_nonce: "n1".to_string(),
        },
        Step::Push {
            type_url: CDS_TYPE_URL.to_string(),
            version_info: "v2".to_string(),
            nonce: "n2".to_string(),
            resources: vec![
                any_of(
                    &minimal_cluster(TEST_B_DYNAMIC_CLUSTER, dead.port() as u32),
                    CLUSTER_TYPE,
                ),
                any_of(
                    &cluster_with_unbuildable_tls("broken_tls", upstream_addr.port() as u32),
                    CLUSTER_TYPE,
                ),
            ],
        },
        Step::WaitForNack {
            type_url: CDS_TYPE_URL.to_string(),
            response_nonce: "n2".to_string(),
        },
    ])
    .await
    .expect("harness spawns");

    let listener_port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-ads-e2e-nack-{}-{listener_port}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &config_path,
        bootstrap_static_listener_dynamic_cluster(listener_port, harness.addr),
    )
    .expect("write config");
    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let deadline = Instant::now() + ACK_TIMEOUT;
    let nack = loop {
        let log = harness.log.snapshot();
        if let Some(nack) = log
            .iter()
            .find(|r| r.kind() == RequestKind::Nack && r.response_nonce == "n2")
        {
            break nack.clone();
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for a NACK of n2; ADS requests so far: {log:?}; stderr: {:?}",
            drain_available_lines(&stderr_rx)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let detail = nack.error_detail.expect("a NACK carries error_detail");
    assert!(
        detail.contains("cds.clusters[broken_tls].transport_socket"),
        "NACK must name the cluster by dotted path, got: {detail}"
    );
    assert_eq!(
        nack.version_info, "v1",
        "a SotW NACK echoes the last accepted version"
    );
    assert!(
        !harness
            .log
            .snapshot()
            .iter()
            .any(|r| r.kind() == RequestKind::Ack && r.response_nonce == "n2"),
        "the rejected response must never be ACKed"
    );

    assert!(
        wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT),
        "listener at 127.0.0.1:{listener_port} never became connectable"
    );
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let response = get(listener_addr, "/", "test.local");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the last-good `{TEST_B_DYNAMIC_CLUSTER}` must keep serving; got:\n{response}"
    );

    terminate(&mut child);
    let _ = std::fs::remove_file(&config_path);
    harness.shutdown().await;
}

/// A mock upstream answering every request with `204 No Content`, so a test
/// can tell which upstream served it.
fn spawn_no_content_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
            });
        }
    });
    addr
}

/// Review C4: with `dynamic_resources` configured, SIGHUP is refused loudly
/// and changes nothing. The file is edited before the signal to route to a
/// static cluster on a 204 upstream; the old reload applied that static-only
/// snapshot, which dropped the CDS-delivered cluster and served the file's
/// route. The proxy must keep serving 200 from the CDS cluster.
#[tokio::test(flavor = "multi_thread")]
async fn sighup_is_refused_when_dynamic_resources_are_configured() {
    let upstream_addr = spawn_mock_upstream();
    let file_upstream = spawn_no_content_upstream();
    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CDS_TYPE_URL.to_string(),
            version_info: "v1".to_string(),
            nonce: "n1".to_string(),
            resources: vec![any_of(
                &minimal_cluster(TEST_B_DYNAMIC_CLUSTER, upstream_addr.port() as u32),
                CLUSTER_TYPE,
            )],
        },
        Step::WaitForAck {
            type_url: CDS_TYPE_URL.to_string(),
            version_info: "v1".to_string(),
            response_nonce: "n1".to_string(),
        },
    ])
    .await
    .expect("harness spawns");

    let listener_port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-ads-e2e-sighup-{}-{listener_port}.yaml",
        std::process::id()
    ));
    let boot = bootstrap_static_listener_dynamic_cluster(listener_port, harness.addr);
    std::fs::write(&config_path, &boot).expect("write config");
    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    wait_for_ack(&harness, &stderr_rx, CDS_TYPE_URL, "v1", "n1").await;
    assert!(
        wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT),
        "listener at 127.0.0.1:{listener_port} never became connectable"
    );
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let before = get(listener_addr, "/", "test.local");
    assert!(
        before.starts_with("HTTP/1.1 200"),
        "before SIGHUP: {before}"
    );

    let edited = boot.replace(
        &format!("cluster: {TEST_B_DYNAMIC_CLUSTER}"),
        "cluster: file_backend",
    ) + &format!(
        r#"    - name: file_backend
      type: STATIC
      load_assignment:
        cluster_name: file_backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: {} }}
"#,
        file_upstream.port()
    );
    std::fs::write(&config_path, edited).expect("rewrite config");
    let status = Command::new("kill")
        .args(["-HUP", &child.0.id().to_string()])
        .status()
        .expect("failed to send SIGHUP");
    assert!(status.success(), "kill -HUP failed");

    let deadline = Instant::now() + ACK_TIMEOUT;
    let mut seen = Vec::new();
    // Either outcome of the signal logs a line once handled (`SIGHUP: config
    // reload ...` or `SIGHUP ignored`); wait for it, then judge by traffic
    // first and by the log second.
    while !seen
        .iter()
        .any(|l: &String| l.contains("SIGHUP:") || l.contains("SIGHUP ignored"))
    {
        assert!(
            Instant::now() < deadline,
            "the SIGHUP was never handled; stderr: {seen:?}"
        );
        if let Ok(line) = stderr_rx.recv_timeout(Duration::from_millis(50)) {
            seen.push(line);
        }
    }

    let after = get(listener_addr, "/", "test.local");
    assert!(
        after.starts_with("HTTP/1.1 200"),
        "after a refused SIGHUP the CDS cluster must keep serving, got:\n{after}"
    );
    assert!(
        seen.iter().any(|l| l.contains("SIGHUP ignored")),
        "the refusal must be logged: {seen:?}"
    );

    terminate(&mut child);
    let _ = std::fs::remove_file(&config_path);
    harness.shutdown().await;
}

// ------------------------------------------------------------------ test C --

/// One static listener/cluster (a real, reachable mock upstream) plus
/// `dynamic_resources` pointing its ADS cluster at `dead_addr` -- a port
/// nothing is listening on.
fn bootstrap_unreachable_ads(
    listener_port: u16,
    dead_addr: SocketAddr,
    upstream: SocketAddr,
) -> String {
    format!(
        r#"
node:
  id: proxy-1
  cluster: proxy-fleet

dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: {{ cluster_name: xds_cluster }}
  cds_config: {{ ads: {{}}, resource_api_version: V3 }}

static_resources:
  listeners:
    - name: ingress_http
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: backend
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: xds_cluster
      type: STATIC
      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {dead_ip}, port_value: {dead_port} }}
    - name: backend
      type: STATIC
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {upstream_ip}, port_value: {upstream_port} }}
"#,
        dead_ip = dead_addr.ip(),
        dead_port = dead_addr.port(),
        upstream_ip = upstream.ip(),
        upstream_port = upstream.port(),
    )
}

/// architecture.md §12.2 rule 5's requirement, and the single most important
/// behavioral property of the ADS wiring:
/// an unreachable control plane at boot must not stop the proxy from
/// binding its listeners and serving its static config. `start_ads`'s doc
/// says the ADS `Channel` is built `connect_lazy` for exactly this reason,
/// and `AdsClient::run` reconnects forever in the background -- this proves
/// that promise holds through the real binary, not just through
/// `start_ads`'s doc comment.
#[test]
fn the_proxy_still_serves_static_config_when_its_ads_control_plane_is_unreachable() {
    let upstream_addr = spawn_mock_upstream();
    let listener_port = free_port();
    let unreachable = dead_addr();

    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-ads-e2e-c-{}-{listener_port}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &config_path,
        bootstrap_unreachable_ads(listener_port, unreachable, upstream_addr),
    )
    .expect("write config");

    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "the proxy's static listener must still bind even though its ADS control plane \
         ({unreachable}) is unreachable; stderr so far: {:?}",
        drain_available_lines(&stderr_rx)
    );

    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let response = get(listener_addr, "/", "test.local");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected the static config to keep serving real traffic with no reachable control \
         plane, got:\n{response}"
    );

    terminate(&mut child);
    let _ = std::fs::remove_file(&config_path);
}

// ------------------------------------------------------------------ test D --

/// The name of the cluster test D's bootstrap declares as `type: EDS`.
const TEST_D_EDS_CLUSTER: &str = "eds_backend";

/// One static, already-bound listener whose route already names an EDS
/// cluster -- its membership arrives only over an ADS-delivered
/// `ClusterLoadAssignment`, never `load_assignment` (`proxy-config`'s own
/// EDS-cluster check forbids setting both). `dynamic_resources` still needs
/// `cds_config` set: `convert_dynamic_resources` (not this test's to change)
/// only accepts `ads_config` when at least one of
/// `lds_config`/`cds_config` also subscribes over it -- EDS has no bootstrap
/// flag of its own, it rides on a `Cluster`'s own `eds_cluster_config`. The
/// harness script below never answers the resulting CDS subscription; it
/// just sits open, harmlessly, alongside the EDS one this test actually
/// exercises.
fn bootstrap_static_listener_eds_cluster(listener_port: u16, ads_addr: SocketAddr) -> String {
    format!(
        r#"
node:
  id: proxy-1
  cluster: proxy-fleet

dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: {{ cluster_name: xds_cluster }}
  cds_config: {{ ads: {{}}, resource_api_version: V3 }}

static_resources:
  listeners:
    - name: ingress_http
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: {eds_cluster}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: xds_cluster
      type: STATIC
      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {ads_ip}, port_value: {ads_port} }}
    - name: {eds_cluster}
      type: EDS
      eds_cluster_config:
        eds_config:
          ads: {{}}
          resource_api_version: V3
"#,
        eds_cluster = TEST_D_EDS_CLUSTER,
        ads_ip = ads_addr.ip(),
        ads_port = ads_addr.port(),
    )
}

/// Acceptance test: an ADS-delivered
/// `ClusterLoadAssignment` reaches `ClusterManager::accept_eds_update` in the
/// real binary, and the statically-declared EDS cluster it feeds becomes
/// routable by real traffic -- the same "observe through a real request, one
/// unretried read" shape tests A/B use, chosen over `/clusters` because that
/// endpoint reads `ConfigSnapshot` (`config_dump`'s own source), and an EDS
/// update deliberately never touches `ConfigSnapshot` at all (see
/// `apply.rs`'s own doc on `on_eds_response`) -- only a live request actually
/// exercises the path the ADS wiring adds.
///
/// Unlike test A/B, there is no CDS response to wait behind: `start_ads`'s
/// EDS-name seeding means the EDS subscription's initial request already names
/// `eds_backend` the moment the stream opens (read straight out of the boot
/// snapshot's `eds_cluster_config.service_name`, not derived from any prior
/// response) -- so this polls for the first ACK of ANY type_url, rather than
/// asserting on a fixed log index the way tests A/B do, because the CDS and
/// EDS initial requests can arrive in either order.
#[tokio::test(flavor = "multi_thread")]
async fn an_eds_delivered_endpoint_set_makes_a_statically_declared_cluster_routable() {
    let upstream_addr = spawn_mock_upstream();
    let harness = Harness::spawn(vec![Step::Send {
        type_url: EDS_TYPE_URL.to_string(),
        version_info: "v1".to_string(),
        nonce: "n1".to_string(),
        resources: vec![any_of(
            &minimal_assignment(TEST_D_EDS_CLUSTER, "127.0.0.1", upstream_addr.port() as u32),
            ENDPOINT_TYPE,
        )],
    }])
    .await
    .expect("harness spawns");

    let listener_port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-ads-e2e-d-{}-{listener_port}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &config_path,
        bootstrap_static_listener_eds_cluster(listener_port, harness.addr),
    )
    .expect("write config");

    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "listener at 127.0.0.1:{listener_port} did not become connectable in time; \
         stderr so far: {:?}",
        drain_available_lines(&stderr_rx)
    );
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();

    // Bounded poll for ARRIVAL of the EDS ACK (retries fine here, same
    // reasoning as tests A/B's own `wait_for_second_request`): any recorded
    // request classifying as an ACK, since the CDS and EDS initial requests
    // race for which lands first in the log.
    let deadline = Instant::now() + ACK_TIMEOUT;
    loop {
        if harness
            .log
            .snapshot()
            .iter()
            .any(|r| r.kind() == RequestKind::Ack)
        {
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out after {ACK_TIMEOUT:?} waiting for the EDS ACK to be recorded; \
                 stderr so far: {:?}",
                drain_available_lines(&stderr_rx)
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The load-bearing read: exactly ONE fresh request, no retry loop -- a
    // retry loop here would let a `main.rs` that ACKs before
    // `ClusterManager::accept_eds_update` has actually returned catch up and
    // pass anyway, the same reasoning as tests A/B's own single unretried
    // read.
    let response = get(listener_addr, "/", "test.local");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected \"{TEST_D_EDS_CLUSTER}\"'s host set to already be populated the instant its \
         EDS ACK was observed on the wire -- got:\n{response}"
    );

    terminate(&mut child);
    let _ = std::fs::remove_file(&config_path);
    harness.shutdown().await;
}

// ------------------------------------------------------------------ test E --

/// The certificate name the static listener in test E requests over ADS.
const TEST_E_SDS_SECRET: &str = "ingress-cert";

/// A static TLS listener which cannot serve a handshake until SDS delivers
/// `TEST_E_SDS_SECRET`. The test intentionally needs no scripted response:
/// the load-bearing claim is the initial request emitted by the real binary,
/// before a control plane has sent anything that could update subscriptions.
fn bootstrap_sds_only_listener(
    listener_port: u16,
    ads_addr: SocketAddr,
    backend_addr: SocketAddr,
) -> String {
    format!(
        r#"
node:
  id: proxy-1
  cluster: proxy-fleet

dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: {{ cluster_name: xds_cluster }}
  cds_config: {{ ads: {{}}, resource_api_version: V3 }}

static_resources:
  listeners:
    - name: ingress_tls
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: ingress_tls
                cluster: sds_backend
          transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificate_sds_secret_configs:
                  - name: {secret}
                    sds_config: {{ ads: {{}}, resource_api_version: V3 }}

  clusters:
    - name: xds_cluster
      type: STATIC
      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {ads_ip}, port_value: {ads_port} }}
    - name: sds_backend
      type: STATIC
      load_assignment:
        cluster_name: sds_backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {backend_ip}, port_value: {backend_port} }}
"#,
        secret = TEST_E_SDS_SECRET,
        ads_ip = ads_addr.ip(),
        ads_port = ads_addr.port(),
        backend_ip = backend_addr.ip(),
        backend_port = backend_addr.port(),
    )
}

/// A TLS-certificate SDS resource with inline PEM, the only secret shape
/// The SDS path accepts at this boundary. The returned DER is also installed in the
/// test client's trust store, so its successful handshake proves the proxy
/// installed this exact delivered certificate rather than merely accepting an
/// arbitrary TLS connection.
fn minted_sds_certificate() -> (tls_v3::Secret, rustls::pki_types::CertificateDer<'static>) {
    let key = KeyPair::generate().expect("generate SDS leaf key");
    let mut params = CertificateParams::new(vec!["sds.test".to_string()]).expect("leaf params");
    params
        .distinguished_name
        .push(DnType::CommonName, "sds.test");
    let certificate = params.self_signed(&key).expect("self-sign SDS leaf");
    let certificate_pem = certificate.pem();
    let certificate_der = certificate.der().clone();

    (
        tls_v3::Secret {
            name: TEST_E_SDS_SECRET.to_string(),
            r#type: Some(tls_v3::secret::Type::TlsCertificate(
                tls_v3::TlsCertificate {
                    certificate_chain: Some(core_v3::DataSource {
                        specifier: Some(core_v3::data_source::Specifier::InlineBytes(
                            certificate_pem.into_bytes(),
                        )),
                        ..Default::default()
                    }),
                    private_key: Some(core_v3::DataSource {
                        specifier: Some(core_v3::data_source::Specifier::InlineBytes(
                            key.serialize_pem().into_bytes(),
                        )),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )),
        },
        certificate_der,
    )
}

/// The delivered-secret path is only useful if `start_ads` initially
/// subscribes to an SDS-only listener's named certificate. `ResourceApplier`
/// unit tests already prove it can derive this name after an LDS update, but
/// the static boot snapshot has no update to trigger that path; this is the
/// binary boundary that used to omit SDS from its subscription list entirely.
#[tokio::test(flavor = "multi_thread")]
async fn an_sds_only_listener_subscribes_to_its_certificate_at_boot() {
    let harness = Harness::spawn(vec![]).await.expect("harness spawns");
    let listener_port = free_port();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-ads-e2e-e-{}-{listener_port}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &config_path,
        bootstrap_sds_only_listener(listener_port, harness.addr, harness.addr),
    )
    .expect("write config");

    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "SDS-only listener at 127.0.0.1:{listener_port} did not bind in time; stderr so far: {:?}",
        drain_available_lines(&stderr_rx)
    );

    // Poll only for arrival. The exact request fields below are the
    // load-bearing assertion: this must be a by-name SDS subscription, not
    // a wildcard request or an unrelated ADS request that happened to arrive
    // first alongside CDS/LDS/EDS.
    let deadline = Instant::now() + ACK_TIMEOUT;
    let request = loop {
        if let Some(request) = harness
            .log
            .snapshot()
            .into_iter()
            .find(|request| request.type_url == SDS_TYPE_URL)
        {
            break request;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out after {ACK_TIMEOUT:?} waiting for the SDS subscription for \\
                 `{TEST_E_SDS_SECRET}`; ADS requests so far: {:?}; stderr so far: {:?}",
                harness.log.snapshot(),
                drain_available_lines(&stderr_rx)
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(request.kind(), RequestKind::Initial, "got {request:?}");
    assert_eq!(
        request.resource_names,
        vec![TEST_E_SDS_SECRET],
        "got {request:?}"
    );

    terminate(&mut child);
    let _ = std::fs::remove_file(&config_path);
    harness.shutdown().await;
}

/// The crate-level tests prove subscriptions, secret decoding, and the
/// registry separately. This proves the real binary connects those seams:
/// its SDS-only listener requests the named secret, the scripted control
/// plane delivers it, and a client trusting only that secret completes TLS
/// and receives a proxied HTTP response.
#[tokio::test(flavor = "multi_thread")]
async fn an_sds_delivered_certificate_serves_a_tls_request_in_the_running_binary() {
    let (secret, certificate_der) = minted_sds_certificate();
    let harness = Harness::spawn(vec![Step::Send {
        type_url: SDS_TYPE_URL.to_string(),
        version_info: "sds-v1".to_string(),
        nonce: "sds-n1".to_string(),
        resources: vec![any_of(
            &secret,
            "envoy.extensions.transport_sockets.tls.v3.Secret",
        )],
    }])
    .await
    .expect("harness spawns");
    let upstream_addr = spawn_mock_upstream();
    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-ads-e2e-sds-delivery-{}-{listener_port}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &config_path,
        bootstrap_sds_only_listener(listener_port, harness.addr, upstream_addr),
    )
    .expect("write config");

    let (mut child, stderr_rx) = spawn_proxy(&config_path);
    assert!(
        wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT),
        "SDS-only listener at {listener_addr} did not bind in time; stderr so far: {:?}",
        drain_available_lines(&stderr_rx)
    );

    // Wait for the SDS ACK, not merely the initial subscription: the ACK is
    // emitted only after the delivery sink has updated the live TLS factory.
    let deadline = Instant::now() + ACK_TIMEOUT;
    loop {
        if harness.log.snapshot().iter().any(|request| {
            request.type_url == SDS_TYPE_URL
                && request.kind() == RequestKind::Ack
                && request.version_info == "sds-v1"
                && request.response_nonce == "sds-n1"
        }) {
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out after {ACK_TIMEOUT:?} waiting for the SDS delivery ACK; ADS requests so far: {:?}; stderr so far: {:?}",
                harness.log.snapshot(),
                drain_available_lines(&stderr_rx)
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(certificate_der)
        .expect("add delivered leaf as trust root");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name: rustls::pki_types::ServerName<'static> = "sds.test"
        .try_into()
        .expect("test name is a valid DNS name");
    let tcp = tokio::time::timeout(
        Duration::from_secs(5),
        TokioTcpStream::connect(listener_addr),
    )
    .await
    .expect("TCP connection must not hang")
    .expect("connect TLS listener");
    let mut tls = tokio::time::timeout(
        Duration::from_secs(5),
        TlsConnector::from(Arc::new(client_config)).connect(server_name, tcp),
    )
    .await
    .expect("TLS handshake must not hang")
    .expect("SDS-delivered certificate must complete TLS handshake");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: sds.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("write TLS request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut response))
        .await
        .expect("TLS response must not hang")
        .expect("read proxied TLS response");
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "expected the TLS request to reach the static upstream, got: {}",
        String::from_utf8_lossy(&response)
    );

    terminate(&mut child);
    let _ = std::fs::remove_file(&config_path);
    harness.shutdown().await;
}

// ------------------------------------------------------------------ test F --

/// Static RDS listener's requested route configuration name.
const TEST_F_RDS_ROUTE: &str = "ingress-routes";
const TEST_F_RDS_BACKEND: &str = "rds_backend";

/// A static listener whose HCM has no inline routes: it must not bind until
/// ADS supplies `TEST_F_RDS_ROUTE`.
fn bootstrap_static_rds_listener(
    listener_port: u16,
    ads_addr: SocketAddr,
    backend_addr: SocketAddr,
) -> String {
    format!(
        r#"
node:
  id: proxy-1
  cluster: proxy-fleet

dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: {{ cluster_name: xds_cluster }}
  cds_config: {{ ads: {{}}, resource_api_version: V3 }}

static_resources:
  listeners:
    - name: ingress_http
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                rds:
                  config_source: {{ ads: {{}}, resource_api_version: V3 }}
                  route_config_name: {route_name}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: xds_cluster
      type: STATIC
      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {ads_ip}, port_value: {ads_port} }}
    - name: {backend_name}
      type: STATIC
      load_assignment:
        cluster_name: {backend_name}
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {backend_ip}, port_value: {backend_port} }}
"#,
        route_name = TEST_F_RDS_ROUTE,
        backend_name = TEST_F_RDS_BACKEND,
        ads_ip = ads_addr.ip(),
        ads_port = ads_addr.port(),
        backend_ip = backend_addr.ip(),
        backend_port = backend_addr.port(),
    )
}

fn rds_route_to_backend() -> route_v3::RouteConfiguration {
    route_v3::RouteConfiguration {
        name: TEST_F_RDS_ROUTE.to_string(),
        virtual_hosts: vec![route_v3::VirtualHost {
            name: "backend".to_string(),
            domains: vec!["*".to_string()],
            routes: vec![route_v3::Route {
                r#match: Some(route_v3::RouteMatch {
                    path_specifier: Some(route_v3::route_match::PathSpecifier::Prefix(
                        "/".to_string(),
                    )),
                    ..Default::default()
                }),
                action: Some(route_v3::route::Action::Route(route_v3::RouteAction {
                    cluster_specifier: Some(route_v3::route_action::ClusterSpecifier::Cluster(
                        TEST_F_RDS_BACKEND.to_string(),
                    )),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// RDS has two boot-time contracts: `start_ads` must issue its named
/// subscription from a static HCM, and a listener missing that table must
/// wait rather than fail startup or serve the empty placeholder. Delivery of
/// one valid table must then bind it and route real traffic through that table.
#[tokio::test(flavor = "multi_thread")]
async fn an_rds_delivered_route_binds_and_serves_a_static_listener() {
    let harness = Harness::spawn(vec![Step::Send {
        type_url: RDS_TYPE_URL.to_string(),
        version_info: "rds-v1".to_string(),
        nonce: "rds-n1".to_string(),
        resources: vec![any_of(
            &rds_route_to_backend(),
            "envoy.config.route.v3.RouteConfiguration",
        )],
    }])
    .await
    .expect("harness spawns");
    let upstream_addr = spawn_mock_upstream();
    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-ads-e2e-rds-{}-{listener_port}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &config_path,
        bootstrap_static_rds_listener(listener_port, harness.addr, upstream_addr),
    )
    .expect("write config");

    let (mut child, stderr_rx) = spawn_proxy(&config_path);
    let deadline = Instant::now() + ACK_TIMEOUT;
    loop {
        if harness.log.snapshot().iter().any(|request| {
            request.type_url == RDS_TYPE_URL
                && request.kind() == RequestKind::Ack
                && request.version_info == "rds-v1"
                && request.response_nonce == "rds-n1"
        }) {
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out after {ACK_TIMEOUT:?} waiting for the RDS delivery ACK; ADS requests so far: {:?}; stderr so far: {:?}",
                harness.log.snapshot(),
                drain_available_lines(&stderr_rx)
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let initial_rds = harness
        .log
        .snapshot()
        .into_iter()
        .find(|request| request.type_url == RDS_TYPE_URL && request.kind() == RequestKind::Initial)
        .expect("static RDS listener must send an initial named subscription");
    assert_eq!(initial_rds.resource_names, vec![TEST_F_RDS_ROUTE]);
    assert!(
        wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT),
        "RDS-warmed listener at {listener_addr} did not bind in time; stderr so far: {:?}",
        drain_available_lines(&stderr_rx)
    );
    let response = get(listener_addr, "/", "rds.test");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "RDS-delivered route must reach the static backend, got:\n{response}"
    );

    terminate(&mut child);
    let _ = std::fs::remove_file(&config_path);
    harness.shutdown().await;
}

// -------------------------------------------------- initial fetch timeout --

/// One static EDS cluster whose control-plane connection stays open but never
/// delivers endpoints. The configured timeout belongs to `cds_config`'s
/// `ConfigSource`: the bootstrap lowering carries that ADS-wide deadline
/// into the readiness probe.
fn bootstrap_never_warmed_eds_cluster(
    listener_port: u16,
    admin_port: u16,
    ads_addr: SocketAddr,
) -> String {
    format!(
        r#"
node:
  id: proxy-1
  cluster: proxy-fleet

admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin_port} }}

dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: {{ cluster_name: xds_cluster }}
  cds_config:
    ads: {{}}
    resource_api_version: V3
    initial_fetch_timeout: 0.200s

static_resources:
  listeners:
    - name: ingress_http
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: {eds_cluster}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: xds_cluster
      type: STATIC
      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {ads_ip}, port_value: {ads_port} }}
    - name: {eds_cluster}
      type: EDS
      eds_cluster_config:
        eds_config:
          ads: {{}}
          resource_api_version: V3
"#,
        eds_cluster = TEST_D_EDS_CLUSTER,
        ads_ip = ads_addr.ip(),
        ads_port = ads_addr.port(),
    )
}

/// A timeout unblocks readiness only. It must not force an EDS cluster that
/// never received endpoints into the initialized state, or let its route send
/// traffic to an empty host set.
#[tokio::test(flavor = "multi_thread")]
async fn initial_fetch_timeout_marks_ready_live_without_warming_an_eds_cluster() {
    let harness = Harness::spawn(vec![]).await.expect("harness spawns");
    let listener_port = free_port();
    let admin_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-ads-e2e-initial-fetch-timeout-{}-{admin_port}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &config_path,
        bootstrap_never_warmed_eds_cluster(listener_port, admin_port, harness.addr),
    )
    .expect("write config");

    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    // Observation order is forced by the boot sequence: the admin server is
    // started BEFORE the gated worker pool, while the listener can only bind
    // once the startup gate releases -- and with a never-fed EDS cluster the
    // gate releases exactly when the warming deadline expires. Waiting for
    // the listener first (as this test once did) blocks until AFTER the
    // deadline, making the INITIALIZING phase structurally unobservable and
    // the first assertion a guaranteed failure. Poll admin, which is up
    // while the deadline is still in force.
    assert!(
        wait_for_connectable(("127.0.0.1", admin_port), STARTUP_TIMEOUT),
        "admin at {admin_addr} did not bind in time; stderr so far: {:?}",
        drain_available_lines(&stderr_rx)
    );

    let before_timeout = get(admin_addr, "/ready", "admin.local");
    assert!(
        before_timeout.starts_with("HTTP/1.1 503"),
        "a never-fed EDS cluster must keep /ready INITIALIZING before its configured timeout, got:\n{before_timeout}"
    );
    assert!(
        before_timeout.ends_with("INITIALIZING"),
        "expected Envoy-compatible initializing body before timeout, got:\n{before_timeout}"
    );

    // The gate's 200ms deadline expiring is what lets the listener bind, so
    // this wait doubles as "wait past the timeout" -- no fixed sleep needed.
    assert!(
        wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT),
        "listener at {listener_addr} did not bind after the warming deadline; stderr so far: {:?}",
        drain_available_lines(&stderr_rx)
    );

    let after_timeout = get(admin_addr, "/ready", "admin.local");
    assert!(
        after_timeout.starts_with("HTTP/1.1 200"),
        "initial_fetch_timeout must release readiness after 200ms, got:\n{after_timeout}"
    );
    assert!(
        after_timeout.ends_with("LIVE"),
        "expected Envoy-compatible live body after timeout, got:\n{after_timeout}"
    );

    let response = get(listener_addr, "/", "warming.test");
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "timeout must not make the never-fed EDS route serve traffic, got:\n{response}"
    );
    assert!(
        response.contains("cluster not warmed"),
        "timeout must not call force_initialize; the request path must remain not warmed, got:\n{response}"
    );

    terminate(&mut child);
    let _ = std::fs::remove_file(&config_path);
    harness.shutdown().await;
}

// --------------------------------------- dynamic listener make-before-break --

/// A bootstrap with no data-plane resources of its own. CDS and LDS deliver
/// the complete serving generation; only the ADS transport cluster is static.
fn bootstrap_dynamic_listeners(ads_addr: SocketAddr) -> String {
    format!(
        r#"
node:
  id: proxy-1
  cluster: proxy-fleet

dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
      - envoy_grpc: {{ cluster_name: xds_cluster }}
  cds_config: {{ ads: {{}}, resource_api_version: V3 }}
  lds_config: {{ ads: {{}}, resource_api_version: V3 }}

static_resources:
  listeners: []
  clusters:
    - name: xds_cluster
      type: STATIC
      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {ads_ip}, port_value: {ads_port} }}
"#,
        ads_ip = ads_addr.ip(),
        ads_port = ads_addr.port(),
    )
}

/// One ADS-delivered HCM listener whose route remains unavailable until RDS
/// supplies `route_name`. This is intentionally an HCM rather than a
/// `tcp_proxy`: listener warming is a dependency on RDS, so a TCP listener
/// would bind immediately and could not exercise the make-before-break path.
fn dynamic_rds_listener(name: &str, route_name: &str, port: u32) -> listener_v3::Listener {
    listener_v3::Listener {
        name: name.to_string(),
        address: Some(core_v3::Address {
            address: Some(core_v3::address::Address::SocketAddress(
                core_v3::SocketAddress {
                    address: "127.0.0.1".to_string(),
                    port_specifier: Some(core_v3::socket_address::PortSpecifier::PortValue(port)),
                    ..Default::default()
                },
            )),
        }),
        filter_chains: vec![listener_v3::FilterChain {
            filters: vec![listener_v3::Filter {
                name: "envoy.filters.network.http_connection_manager".to_string(),
                config_type: Some(listener_v3::filter::ConfigType::TypedConfig(any_of(
                    &hcm_v3::HttpConnectionManager {
                        stat_prefix: name.to_string(),
                        route_specifier: Some(
                            hcm_v3::http_connection_manager::RouteSpecifier::Rds(hcm_v3::Rds {
                                config_source: Some(core_v3::ConfigSource {
                                    config_source_specifier: Some(
                                        core_v3::config_source::ConfigSourceSpecifier::Ads(
                                            core_v3::AggregatedConfigSource {},
                                        ),
                                    ),
                                    resource_api_version: core_v3::ApiVersion::V3 as i32,
                                    ..Default::default()
                                }),
                                route_config_name: route_name.to_string(),
                            }),
                        ),
                        http_filters: vec![hcm_v3::HttpFilter {
                            name: "envoy.filters.http.router".to_string(),
                            config_type: Some(hcm_v3::http_filter::ConfigType::TypedConfig(
                                any_of(&router_v3::Router::default(), ROUTER_TYPE),
                            )),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    HCM_TYPE,
                ))),
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn route_to_cluster(name: &str, cluster: &str) -> route_v3::RouteConfiguration {
    route_v3::RouteConfiguration {
        name: name.to_string(),
        virtual_hosts: vec![route_v3::VirtualHost {
            name: "backend".to_string(),
            domains: vec!["*".to_string()],
            routes: vec![route_v3::Route {
                r#match: Some(route_v3::RouteMatch {
                    path_specifier: Some(route_v3::route_match::PathSpecifier::Prefix(
                        "/".to_string(),
                    )),
                    ..Default::default()
                }),
                action: Some(route_v3::route::Action::Route(route_v3::RouteAction {
                    cluster_specifier: Some(route_v3::route_action::ClusterSpecifier::Cluster(
                        cluster.to_string(),
                    )),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

async fn wait_for_ack(
    harness: &Harness,
    stderr: &mpsc::Receiver<String>,
    type_url: &str,
    version: &str,
    nonce: &str,
) {
    let deadline = Instant::now() + ACK_TIMEOUT;
    loop {
        if harness.log.snapshot().iter().any(|request| {
            request.type_url == type_url
                && request.kind() == RequestKind::Ack
                && request.version_info == version
                && request.response_nonce == nonce
        }) {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out after {ACK_TIMEOUT:?} waiting for {type_url} {version}/{nonce} ACK; \
                 ADS requests so far: {:?}; stderr so far: {:?}",
                harness.log.snapshot(),
                drain_available_lines(stderr)
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The make-before-break negative path. A replacement generation gets a
/// new cluster and listener name, but its listener waits on a not-yet-delivered
/// RDS table. The old generation must keep serving when the control plane
/// disappears in that window; dropping it because the listener name changed
/// turns a control-plane delay into a data-plane outage.
#[tokio::test(flavor = "multi_thread")]
async fn a_control_plane_loss_mid_listener_warm_keeps_the_last_good_generation_serving() {
    const CLUSTER_A: &str = "backend-a";
    const CLUSTER_B: &str = "backend-b";
    const LISTENER_A: &str = "ingress-a";
    const LISTENER_B: &str = "ingress-b";
    const ROUTE_A: &str = "route-a";
    const ROUTE_B: &str = "route-b";

    let upstream_a = spawn_mock_upstream();
    let upstream_b = spawn_mock_upstream();
    let listener_a_port = free_port();
    let listener_b_port = free_port();
    let listener_a: SocketAddr = format!("127.0.0.1:{listener_a_port}").parse().unwrap();

    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CDS_TYPE_URL.to_string(),
            version_info: "cds-v1".to_string(),
            nonce: "cds-n1".to_string(),
            resources: vec![any_of(
                &minimal_cluster(CLUSTER_A, upstream_a.port() as u32),
                CLUSTER_TYPE,
            )],
        },
        Step::Send {
            type_url: LDS_TYPE_URL.to_string(),
            version_info: "lds-v1".to_string(),
            nonce: "lds-n1".to_string(),
            resources: vec![any_of(
                &dynamic_rds_listener(LISTENER_A, ROUTE_A, listener_a_port as u32),
                LISTENER_TYPE,
            )],
        },
        Step::Send {
            type_url: RDS_TYPE_URL.to_string(),
            version_info: "rds-v1".to_string(),
            nonce: "rds-n1".to_string(),
            resources: vec![any_of(
                &route_to_cluster(ROUTE_A, CLUSTER_A),
                "envoy.config.route.v3.RouteConfiguration",
            )],
        },
        Step::WaitForRequest {
            type_url: RDS_TYPE_URL.to_string(),
        },
        Step::Wait {
            duration: Duration::from_millis(100),
        },
        Step::Push {
            // Adds B before the later LDS response retires A, per S8.4.
            type_url: CDS_TYPE_URL.to_string(),
            version_info: "cds-v2".to_string(),
            nonce: "cds-n2".to_string(),
            resources: vec![
                any_of(
                    &minimal_cluster(CLUSTER_A, upstream_a.port() as u32),
                    CLUSTER_TYPE,
                ),
                any_of(
                    &minimal_cluster(CLUSTER_B, upstream_b.port() as u32),
                    CLUSTER_TYPE,
                ),
            ],
        },
        Step::Wait {
            duration: Duration::from_millis(50),
        },
        Step::Push {
            type_url: LDS_TYPE_URL.to_string(),
            version_info: "lds-v2".to_string(),
            nonce: "lds-n2".to_string(),
            resources: vec![any_of(
                &dynamic_rds_listener(LISTENER_B, ROUTE_B, listener_b_port as u32),
                LISTENER_TYPE,
            )],
        },
        Step::WaitForRequest {
            type_url: LDS_TYPE_URL.to_string(),
        },
        // No route-b response: this is the precise mid-warm interruption.
        Step::Wait {
            duration: Duration::from_millis(250),
        },
        Step::DropStream,
    ])
    .await
    .expect("harness spawns");

    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-ads-e2e-make-before-break-{}-{listener_a_port}.yaml",
        std::process::id()
    ));
    std::fs::write(&config_path, bootstrap_dynamic_listeners(harness.addr)).expect("write config");
    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    wait_for_ack(&harness, &stderr_rx, RDS_TYPE_URL, "rds-v1", "rds-n1").await;
    assert!(
        wait_for_connectable(("127.0.0.1", listener_a_port), STARTUP_TIMEOUT),
        "first dynamic listener at {listener_a} did not warm; stderr so far: {:?}",
        drain_available_lines(&stderr_rx)
    );
    let before = get(listener_a, "/", "generation-a.test");
    assert!(
        before.starts_with("HTTP/1.1 200"),
        "first dynamic generation must serve before replacement begins, got:\n{before}"
    );

    wait_for_ack(&harness, &stderr_rx, LDS_TYPE_URL, "lds-v2", "lds-n2").await;
    // The second listener has no route table, so it must not bind; its absence
    // is what makes this a genuine warming window rather than a slow swap.
    assert!(
        !wait_for_connectable(("127.0.0.1", listener_b_port), Duration::from_millis(100)),
        "unwarmed replacement listener must not bind before its RDS table arrives"
    );

    // Simulate the control plane disappearing while the replacement is
    // staged. `DropStream` closes the active ADS RPC; wait for the client's
    // reconnect rather than mistaking the already-open old stream for proof.
    let deadline = Instant::now() + ACK_TIMEOUT;
    loop {
        if harness
            .log
            .snapshot()
            .iter()
            .any(|request| request.stream_id > 1)
        {
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out after {ACK_TIMEOUT:?} waiting for ADS reconnect after control-plane \
                 loss; requests so far: {:?}; stderr so far: {:?}",
                harness.log.snapshot(),
                drain_available_lines(&stderr_rx)
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let after = get(listener_a, "/", "generation-a.test");
    assert!(
        after.starts_with("HTTP/1.1 200"),
        "control-plane loss during replacement warm-up must keep generation A serving, got:\n{after}"
    );

    terminate(&mut child);
    let _ = std::fs::remove_file(&config_path);
    harness.shutdown().await;
}

/// `proxy_filters::auth_filter::TYPE_URL`; this crate does not depend on
/// `proxy-filters`, so the value is spelled out.
const AUTH_TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.Authentication";
const AUTH_SECRET: &str = "ads-e2e-auth-secret";
const AUTH_ROTATED_SECRET: &str = "ads-e2e-auth-rotated-secret";
const AUTH_KEY_1: &str = "llmp_ads-e2e-auth-key-1";
const AUTH_KEY_2: &str = "llmp_ads-e2e-auth-key-2";

/// An `llmproxy.auth` typed_config that admits `keys`, each digested under
/// `secret`. The filter has no generated Rust type, so the message is built
/// from the embedded descriptor pool, as the config loader decodes it.
fn auth_filter_config(secret: &str, keys: &[&str]) -> prost_types::Any {
    let hmac = proxy_control::auth::HmacSecret::new(secret.as_bytes());
    let virtual_keys: Vec<serde_json::Value> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            serde_json::json!({
                "keyId": format!("key-{i}"),
                "tenant": "tenant-a",
                "digestHex": proxy_control::auth::digest_hex(&hmac, key),
            })
        })
        .collect();
    let json = serde_json::json!({
        "hmacSecret": { "inlineString": secret },
        "virtualKeys": virtual_keys,
        "inMemory": {},
    });
    let descriptor = proxy_api::descriptor_pool()
        .get_message_by_name("llmproxy.filters.v0.Authentication")
        .expect("the descriptor pool carries llmproxy.filters.v0.Authentication");
    let message = prost_reflect::DynamicMessage::deserialize(descriptor, json)
        .expect("the auth typed_config matches its descriptor");
    prost_types::Any {
        type_url: AUTH_TYPE_URL.to_string(),
        value: message.encode_to_vec(),
    }
}

/// An ADS-delivered HCM listener with an inline route to `cluster` behind an
/// `llmproxy.auth` filter configured by `auth`.
fn dynamic_auth_listener(
    name: &str,
    port: u32,
    cluster: &str,
    auth: prost_types::Any,
) -> listener_v3::Listener {
    listener_v3::Listener {
        name: name.to_string(),
        address: Some(core_v3::Address {
            address: Some(core_v3::address::Address::SocketAddress(
                core_v3::SocketAddress {
                    address: "127.0.0.1".to_string(),
                    port_specifier: Some(core_v3::socket_address::PortSpecifier::PortValue(port)),
                    ..Default::default()
                },
            )),
        }),
        filter_chains: vec![listener_v3::FilterChain {
            filters: vec![listener_v3::Filter {
                name: "envoy.filters.network.http_connection_manager".to_string(),
                config_type: Some(listener_v3::filter::ConfigType::TypedConfig(any_of(
                    &hcm_v3::HttpConnectionManager {
                        stat_prefix: name.to_string(),
                        route_specifier: Some(
                            hcm_v3::http_connection_manager::RouteSpecifier::RouteConfig(
                                route_to_cluster("local", cluster),
                            ),
                        ),
                        http_filters: vec![
                            hcm_v3::HttpFilter {
                                name: "llmproxy.auth".to_string(),
                                config_type: Some(hcm_v3::http_filter::ConfigType::TypedConfig(
                                    auth,
                                )),
                                ..Default::default()
                            },
                            hcm_v3::HttpFilter {
                                name: "envoy.filters.http.router".to_string(),
                                config_type: Some(hcm_v3::http_filter::ConfigType::TypedConfig(
                                    any_of(&router_v3::Router::default(), ROUTER_TYPE),
                                )),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    },
                    HCM_TYPE,
                ))),
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// `GET /` carrying `Authorization: Bearer <key>`; returns the full response.
fn get_with_bearer(addr: SocketAddr, key: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set_read_timeout");
    stream
        .write_all(
            format!(
                "GET / HTTP/1.1\r\nHost: auth.test\r\nAuthorization: Bearer {key}\r\n\
                 Connection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read response to EOF");
    String::from_utf8_lossy(&response).to_string()
}

/// The xDS half of the startup-fixed auth control plane: an LDS update that
/// changes a running `llmproxy.auth` chain's `hmac_secret` is NACKed by name
/// before publish, never ACKed, and the last-good listener keeps verifying
/// with the secret its keys were minted under. Applying it would split the
/// mint and verify secrets and refuse every key with 401. The negative half:
/// a key digested only under the rejected secret must stay refused.
#[tokio::test(flavor = "multi_thread")]
async fn an_lds_update_that_changes_a_running_auth_secret_is_nacked_and_last_good_keeps_authenticating(
) {
    const CLUSTER: &str = "backend";
    const LISTENER: &str = "auth-ingress";

    let upstream = spawn_mock_upstream();
    let listener_port = free_port();
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();

    let harness = Harness::spawn(vec![
        Step::Send {
            type_url: CDS_TYPE_URL.to_string(),
            version_info: "cds-v1".to_string(),
            nonce: "cds-n1".to_string(),
            resources: vec![any_of(
                &minimal_cluster(CLUSTER, upstream.port() as u32),
                CLUSTER_TYPE,
            )],
        },
        Step::Send {
            type_url: LDS_TYPE_URL.to_string(),
            version_info: "lds-v1".to_string(),
            nonce: "lds-n1".to_string(),
            resources: vec![any_of(
                &dynamic_auth_listener(
                    LISTENER,
                    listener_port as u32,
                    CLUSTER,
                    auth_filter_config(AUTH_SECRET, &[AUTH_KEY_1]),
                ),
                LISTENER_TYPE,
            )],
        },
        Step::WaitForAck {
            type_url: LDS_TYPE_URL.to_string(),
            version_info: "lds-v1".to_string(),
            response_nonce: "lds-n1".to_string(),
        },
        Step::Push {
            // The operator rotates the secret and re-digests every key under
            // it, as a rotation would require.
            type_url: LDS_TYPE_URL.to_string(),
            version_info: "lds-v2".to_string(),
            nonce: "lds-n2".to_string(),
            resources: vec![any_of(
                &dynamic_auth_listener(
                    LISTENER,
                    listener_port as u32,
                    CLUSTER,
                    auth_filter_config(AUTH_ROTATED_SECRET, &[AUTH_KEY_1, AUTH_KEY_2]),
                ),
                LISTENER_TYPE,
            )],
        },
        Step::WaitForNack {
            type_url: LDS_TYPE_URL.to_string(),
            response_nonce: "lds-n2".to_string(),
        },
    ])
    .await
    .expect("harness spawns");

    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-ads-e2e-auth-nack-{}-{listener_port}.yaml",
        std::process::id()
    ));
    std::fs::write(&config_path, bootstrap_dynamic_listeners(harness.addr)).expect("write config");
    let (mut child, stderr_rx) = spawn_proxy(&config_path);

    let deadline = Instant::now() + ACK_TIMEOUT;
    let nack = loop {
        let log = harness.log.snapshot();
        if let Some(nack) = log.iter().find(|r| {
            r.type_url == LDS_TYPE_URL
                && r.kind() == RequestKind::Nack
                && r.response_nonce == "lds-n2"
        }) {
            break nack.clone();
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for a NACK of lds-n2; ADS requests so far: {log:?}; stderr: {:?}",
            drain_available_lines(&stderr_rx)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let detail = nack.error_detail.expect("a NACK carries error_detail");
    assert!(
        detail.contains("typed_config.hmac_secret"),
        "the NACK must name the startup-fixed field, got: {detail}"
    );
    assert!(
        !detail.contains(AUTH_SECRET) && !detail.contains(AUTH_ROTATED_SECRET),
        "the NACK must not render a secret: {detail}"
    );
    assert_eq!(
        nack.version_info, "lds-v1",
        "a SotW NACK echoes the last accepted version"
    );
    assert!(
        !harness
            .log
            .snapshot()
            .iter()
            .any(|r| r.kind() == RequestKind::Ack && r.response_nonce == "lds-n2"),
        "the rejected response must never be ACKed"
    );

    assert!(
        wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT),
        "listener at {listener_addr} never became connectable; stderr: {:?}",
        drain_available_lines(&stderr_rx)
    );
    let kept = get_with_bearer(listener_addr, AUTH_KEY_1);
    assert!(
        kept.starts_with("HTTP/1.1 200"),
        "the key minted under the running secret must keep authenticating; got:\n{kept}"
    );
    let rejected = get_with_bearer(listener_addr, AUTH_KEY_2);
    assert!(
        rejected.starts_with("HTTP/1.1 401"),
        "a key digested only under the NACKed secret must stay refused; got:\n{rejected}"
    );

    terminate(&mut child);
    let _ = std::fs::remove_file(&config_path);
    harness.shutdown().await;
}
