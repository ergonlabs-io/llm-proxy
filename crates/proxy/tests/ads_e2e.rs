//! WP-20 increment 5 acceptance: boot the REAL `llm-proxy` binary against a
//! scripted control plane (`testing/controlplane`'s `Harness`) and prove the
//! ADS pipeline works end to end in the shipped process.
//!
//! # These tests do NOT catch the two ordering bugs, and that was measured
//!
//! This file was written to close the two gaps `crates/proxy/src/main.rs`
//! records in its own comments: publish-before-cluster-install, and
//! ACK-before-apply. **It does not close either.** Both mutations were run
//! against these three tests on 2026-09-06 and all three stayed green:
//!
//! - deleting `start_ads`'s `reply_rx.await` (ACK before the snapshot is
//!   applied): 3/3 pass.
//! - moving `publish` above `update_from_snapshot` in `apply_snapshot`:
//!   3/3 pass.
//!
//! The reasoning that said otherwise -- that an ACK observed in the harness
//! log implies `apply_snapshot` has already returned, so a single unretried
//! check afterwards must see the result -- is wrong in the direction that
//! matters. Observing the ACK costs a network round trip plus a polling
//! interval, orders of magnitude longer than the window either bug opens, so
//! the racing apply always wins and the check passes either way. A test that
//! passes whether or not the bug is present is not coverage.
//!
//! **The publish ordering is now enforced by the type system instead** --
//! `install_clusters` returns a `ClustersInstalled` receipt that
//! `publish_to_workers` consumes, so the wrong order does not compile. See
//! `apply_snapshot`'s doc. ACK-before-apply remains pinned only one layer
//! down, by `proxy-xds`'s
//! `the_ack_does_not_reach_the_wire_until_the_handler_future_resolves`,
//! which proves the seam works but not that `main.rs` uses it. That gap is
//! still open and is recorded at the call site.
//!
//! # What these tests DO prove, which is worth having
//!
//! They are the first and only coverage of the ADS pipeline inside the real
//! binary: a control-plane-delivered cluster reaches `/config_dump`, it is
//! actually routable by real traffic, and the proxy boots and serves its
//! static config when the control plane is unreachable. All three were
//! untested before this file, and the last is the single most important
//! behavioral property of the wiring increment.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use controlplane::{Harness, RequestKind, Step};
use prost::Message;
use proxy_api::envoy::config::cluster::v3 as cluster_v3;
use proxy_api::envoy::config::core::v3 as core_v3;
use proxy_api::envoy::config::endpoint::v3 as endpoint_v3;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

/// Full `type_url` a CDS `DiscoveryResponse` carries -- matches
/// `crates/proxy-xds/src/apply.rs`'s own private constant of the same value.
const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
/// Bare type name `Any::type_url` is built from -- matches
/// `crates/proxy-xds/tests/apply.rs`'s own `CLUSTER_TYPE`.
const CLUSTER_TYPE: &str = "envoy.config.cluster.v3.Cluster";
/// Full `type_url` an EDS `DiscoveryResponse` carries -- matches
/// `crates/proxy-xds/src/apply.rs`'s own private `EDS_TYPE_URL`.
const EDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
/// Bare type name `Any::type_url` is built from, for a `ClusterLoadAssignment`
/// -- matches `crates/proxy-xds/tests/apply.rs`'s own `ENDPOINT_TYPE`.
const ENDPOINT_TYPE: &str = "envoy.config.endpoint.v3.ClusterLoadAssignment";
/// Full `type_url` an SDS `DiscoveryRequest` subscribes to -- matches
/// `crates/proxy-xds/src/apply.rs`'s own private `SDS_TYPE_URL`.
const SDS_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";

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

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
}

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
/// identical type for why (CLAUDE.md rule 15: a hand-run process that
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
fn bootstrap_no_listeners(admin_port: u16, ads_addr: SocketAddr) -> String {
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
        bootstrap_no_listeners(admin_port, harness.addr),
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

/// PLAN.md 8.5's own requirement, and currently the single most important
/// behavioral property of the ADS wiring increment with no test of its own:
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
/// `cds_config` set: `convert_dynamic_resources` (WP-21 increment 1, not this
/// increment's to change) only accepts `ads_config` when at least one of
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

/// WP-21 increment 2b-iii's own acceptance test: an ADS-delivered
/// `ClusterLoadAssignment` reaches `ClusterManager::accept_eds_update` in the
/// real binary, and the statically-declared EDS cluster it feeds becomes
/// routable by real traffic -- the same "observe through a real request, one
/// unretried read" shape tests A/B use, chosen over `/clusters` because that
/// endpoint reads `ConfigSnapshot` (`config_dump`'s own source), and an EDS
/// update deliberately never touches `ConfigSnapshot` at all (see
/// `apply.rs`'s own doc on `on_eds_response`) -- only a live request actually
/// exercises the path this increment wires.
///
/// Unlike test A/B, there is no CDS response to wait behind: `start_ads`'s
/// Part 2 seeding means the EDS subscription's initial request already names
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
fn bootstrap_sds_only_listener(listener_port: u16, ads_addr: SocketAddr) -> String {
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
                cluster: xds_cluster
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
"#,
        secret = TEST_E_SDS_SECRET,
        ads_ip = ads_addr.ip(),
        ads_port = ads_addr.port(),
    )
}

/// WP-22's delivered-secret path is only useful if `start_ads` initially
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
        bootstrap_sds_only_listener(listener_port, harness.addr),
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
