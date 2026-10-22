//! The real `llm-proxy` binary reaching a TLS-terminating control plane
//! (`testing/controlplane`'s `Harness::spawn_tls`) over the ADS cluster's
//! `UpstreamTlsContext` (architecture.md section 11).
//!
//! Each test checks the wire. The harness either records discovery requests
//! (TLS worked) or counts a refused handshake, so a proxy that never dialled
//! cannot pass the negative case.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

mod common;

use common::free_port;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use controlplane::{Harness, RequestKind, Step};
use prost::Message;
use proxy_api::envoy::config::cluster::v3 as cluster_v3;
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
/// A liveness backstop for a gRPC round trip on loopback, not a speed bound.
const WAIT: Duration = Duration::from_secs(15);

// ------------------------------------------------------------ certificates --

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

fn new_ca() -> Ca {
    let mut params = CertificateParams::new(Vec::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().expect("CA key");
    let cert = params.self_signed(&key).expect("self-sign CA");
    Ca { cert, key }
}

/// A leaf for `localhost` signed by `ca`; returns (cert, key).
fn leaf(ca: &Ca) -> (Certificate, KeyPair) {
    let params = CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    let key = KeyPair::generate().expect("leaf key");
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("sign leaf");
    (cert, key)
}

/// The control plane's TLS config: a `localhost` certificate from `ca`,
/// ALPN `h2`, and, when `client_ca` is set, a required client certificate
/// chaining to it.
fn server_config(ca: &Ca, client_ca: Option<&Ca>) -> Arc<rustls::ServerConfig> {
    let (cert, key) = leaf(ca);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocol versions");
    let builder = match client_ca {
        None => builder.with_no_client_auth(),
        Some(client_ca) => {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(CertificateDer::from(client_ca.cert.der().to_vec()))
                .expect("client CA root");
            let verifier =
                rustls::server::WebPkiClientVerifier::builder_with_provider(roots.into(), provider)
                    .build()
                    .expect("client verifier");
            builder.with_client_cert_verifier(verifier)
        }
    };
    let mut config = builder
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("server cert");
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

// ------------------------------------------------------------------ process --

/// Files a test writes, removed on drop.
struct TempFiles(Vec<PathBuf>);

impl TempFiles {
    fn write(&mut self, name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "llm-proxy-ads-tls-{}-{}-{name}",
            std::process::id(),
            free_port()
        ));
        std::fs::write(&path, contents).expect("write temp file");
        self.0.push(path.clone());
        path
    }
}

impl Drop for TempFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Kills and reaps the child on drop, so a failing assert leaks no process
/// (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    stderr: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Proxy {
    fn spawn(config: &Path) -> Self {
        let mut child = Command::new(BIN)
            .args(["-c", config.to_str().unwrap(), "--concurrency", "1"])
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn llm-proxy");
        let stderr = child.stderr.take().expect("stderr piped");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stderr: rx,
            seen: Vec::new(),
        }
    }

    /// Waits (bounded) for a stderr line containing every needle.
    fn wait_for_line(&mut self, needles: &[&str]) -> String {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(line) = self
                .seen
                .iter()
                .find(|line| needles.iter().all(|n| line.contains(n)))
            {
                return line.clone();
            }
            let left = deadline.saturating_duration_since(Instant::now());
            match self.stderr.recv_timeout(left) {
                Ok(line) => self.seen.push(line),
                Err(_) => panic!(
                    "no stderr line containing {needles:?} within {WAIT:?}; stderr:\n{}",
                    self.seen.join("\n")
                ),
            }
        }
    }

    fn stderr_so_far(&mut self) -> String {
        while let Ok(line) = self.stderr.try_recv() {
            self.seen.push(line);
        }
        self.seen.join("\n")
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------- bootstrap --

/// A CDS-over-ADS bootstrap with no listeners whose `xds_cluster` dials
/// `address:port`, with `transport_socket` (already indented YAML, or empty)
/// and `node_metadata` (already indented YAML, or empty).
fn bootstrap(address: &str, port: u16, transport_socket: &str, node_metadata: &str) -> String {
    format!(
        r#"node:
  id: proxy-1
  cluster: proxy-fleet
{node_metadata}
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
{transport_socket}      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {address}, port_value: {port} }}
"#
    )
}

/// An `UpstreamTlsContext` with SNI `localhost`, an optional trusted CA file,
/// and an optional client certificate (chain, key) for mTLS.
fn upstream_tls(trusted_ca: Option<&Path>, client_cert: Option<(&Path, &Path)>) -> String {
    let mut common = String::new();
    if let Some((chain, key)) = client_cert {
        common.push_str(&format!(
            "            tls_certificates:\n              - certificate_chain: {{ filename: {} }}\n                private_key: {{ filename: {} }}\n",
            chain.display(),
            key.display()
        ));
    }
    if let Some(ca) = trusted_ca {
        common.push_str(&format!(
            "            validation_context:\n              trusted_ca: {{ filename: {} }}\n",
            ca.display()
        ));
    }
    let common = if common.is_empty() {
        String::new()
    } else {
        format!("          common_tls_context:\n{common}")
    };
    format!(
        r#"      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: localhost
{common}"#
    )
}

/// The one-step script: answer the CDS subscription with a cluster.
fn cds_script() -> Vec<Step> {
    let cluster = cluster_v3::Cluster {
        name: "ads_tls_cluster".to_string(),
        cluster_discovery_type: Some(cluster_v3::cluster::ClusterDiscoveryType::Type(
            cluster_v3::cluster::DiscoveryType::Static as i32,
        )),
        ..Default::default()
    };
    vec![Step::Send {
        type_url: CDS_TYPE_URL.to_string(),
        version_info: "v1".to_string(),
        nonce: "n1".to_string(),
        resources: vec![prost_types::Any {
            type_url: "type.googleapis.com/envoy.config.cluster.v3.Cluster".to_string(),
            value: cluster.encode_to_vec(),
        }],
    }]
}

/// Waits (bounded) until the harness has recorded the ACK of `n1`, which
/// only a client that completed TLS and gRPC can send.
async fn wait_for_ack(harness: &Harness, proxy: &mut Proxy) {
    let deadline = Instant::now() + WAIT;
    loop {
        if harness
            .log
            .snapshot()
            .iter()
            .any(|r| r.kind() == RequestKind::Ack)
        {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "no ACK over TLS within {WAIT:?}; harness refused {} handshakes; stderr:\n{}",
                harness.tls_handshake_failures(),
                proxy.stderr_so_far()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// -------------------------------------------------------------------- tests --

/// mTLS: the control plane requires a client certificate and the proxy
/// verifies the control plane against `trusted_ca`; the CDS exchange
/// completes, so both directions of the handshake worked.
#[tokio::test(flavor = "multi_thread")]
async fn ads_over_mtls_completes_a_cds_exchange_in_the_running_binary() {
    let server_ca = new_ca();
    let client_ca = new_ca();
    let harness = Harness::spawn_tls(cds_script(), server_config(&server_ca, Some(&client_ca)))
        .await
        .expect("TLS harness");
    let (client_cert, client_key) = leaf(&client_ca);
    let mut files = TempFiles(Vec::new());
    let ca_path = files.write("ca.pem", &server_ca.cert.pem());
    let chain_path = files.write("client.pem", &client_cert.pem());
    let key_path = files.write("client.key", &client_key.serialize_pem());
    let tls = upstream_tls(Some(&ca_path), Some((&chain_path, &key_path)));
    let config = files.write(
        "bootstrap.yaml",
        &bootstrap("127.0.0.1", harness.addr.port(), &tls, ""),
    );

    let mut proxy = Proxy::spawn(&config);
    proxy.wait_for_line(&["ADS channel uses TLS", "xds_cluster"]);
    wait_for_ack(&harness, &mut proxy).await;
    assert_eq!(harness.tls_handshake_failures(), 0);
    drop(proxy);
    harness.shutdown().await;
}

/// The negative: the control plane's certificate chains to a CA the proxy
/// does not trust. The proxy dials (the harness counts a refused handshake),
/// never opens a stream, and logs the TLS cause at `warn`.
#[tokio::test(flavor = "multi_thread")]
async fn an_untrusted_control_plane_certificate_never_streams_and_logs_why() {
    let server_ca = new_ca();
    let other_ca = new_ca();
    let harness = Harness::spawn_tls(cds_script(), server_config(&server_ca, None))
        .await
        .expect("TLS harness");
    let mut files = TempFiles(Vec::new());
    let ca_path = files.write("other-ca.pem", &other_ca.cert.pem());
    let config = files.write(
        "bootstrap.yaml",
        &bootstrap(
            "127.0.0.1",
            harness.addr.port(),
            &upstream_tls(Some(&ca_path), None),
            "",
        ),
    );

    let mut proxy = Proxy::spawn(&config);
    let line = proxy.wait_for_line(&["ADS TLS handshake with the control plane failed"]);
    assert!(
        line.contains("WARN")
            && line.contains("xds_cluster")
            && line.contains("invalid peer certificate"),
        "the failure must be a warning naming the cluster and the TLS cause: {line}"
    );
    // The proxy logs its side of the failure before the harness reads the
    // proxy's alert, so the count is polled, bounded.
    let deadline = Instant::now() + WAIT;
    while harness.tls_handshake_failures() == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        harness.tls_handshake_failures() >= 1,
        "the harness must have seen the proxy's handshake fail; proxy line: {line}"
    );
    assert!(
        harness.log.snapshot().is_empty(),
        "no discovery request may cross an untrusted channel: {:?}",
        harness.log.snapshot()
    );
    drop(proxy);
    harness.shutdown().await;
}

/// Envoy parity: TLS with no `validation_context` accepts any server
/// certificate. The channel still works, and the proxy says at `warn` that
/// the control plane is not verified.
#[tokio::test(flavor = "multi_thread")]
async fn tls_without_a_validation_context_works_and_warns_that_the_server_is_unverified() {
    let harness = Harness::spawn_tls(cds_script(), server_config(&new_ca(), None))
        .await
        .expect("TLS harness");
    let mut files = TempFiles(Vec::new());
    let config = files.write(
        "bootstrap.yaml",
        &bootstrap(
            "127.0.0.1",
            harness.addr.port(),
            &upstream_tls(None, None),
            "",
        ),
    );

    let mut proxy = Proxy::spawn(&config);
    let line = proxy.wait_for_line(&["certificate is NOT verified"]);
    assert!(line.contains("WARN"), "{line}");
    wait_for_ack(&harness, &mut proxy).await;
    drop(proxy);
    harness.shutdown().await;
}

/// The fail-open path (AGENTS.md "Fail-open controls"): an operator who opts
/// into plaintext to a non-loopback control plane gets a `warn` naming the
/// target. 192.0.2.1 is TEST-NET-1, so nothing answers; only the startup
/// line is under test.
#[tokio::test(flavor = "multi_thread")]
async fn allowed_plaintext_to_a_remote_control_plane_warns_loudly() {
    let mut files = TempFiles(Vec::new());
    let config = files.write(
        "bootstrap.yaml",
        &bootstrap(
            "192.0.2.1",
            18000,
            "",
            "  metadata:\n    io.llmproxy.ads: { allow_plaintext: true }",
        ),
    );

    let mut proxy = Proxy::spawn(&config);
    let line = proxy.wait_for_line(&["PLAINTEXT to a non-loopback control plane"]);
    assert!(
        line.contains("WARN") && line.contains("192.0.2.1:18000"),
        "the warning must name the target: {line}"
    );
}
