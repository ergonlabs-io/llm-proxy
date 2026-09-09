//! Acceptance test for upstream TLS (the "P0 blocker" milestone): a real
//! HTTP request is routed, end to end through the real config path (YAML ->
//! `parse_bootstrap`/`build_snapshot` -> IR -> `ClusterManager` ->
//! `crate::tls::transport_socket_builder()`), to a real TLS HTTP/1.1
//! upstream over loopback. Mirrors
//! `crate::listener::tests::router_forwards_a_real_request_to_a_real_upstream_over_http1`
//! (plaintext counterpart) for the listener/router harness, and
//! `tests/tls.rs`'s `rcgen` cert-minting helpers for the TLS side.
//!
//! The negative cases matter more than the happy path here: every upstream
//! TLS defect in this project's history has been on the verification path,
//! not the handshake-succeeds path.

use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use proxy_cluster::manager::ClusterManager;
use proxy_config::ir::{
    CaSource, ClusterConfig, ClusterKind, DataSourceIR, DownstreamTlsSpec, TlsCertificateIR,
    TlsParametersIR, TlsVersion, UpstreamTlsSpec, ValidationContextIR,
};
use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, ConfigSnapshot, StrictMode};
use proxy_core::drain::ConnectionRegistry;
use proxy_core::listener::{initial_bind, run_listener_manager};
use proxy_core::runtime::run_local;
use proxy_core::runtime::SnapshotHandles;
use proxy_core::tls::{DownstreamTlsFactory, SdsSecretRegistry};
use proxy_http::codec::{serve_http1, Http1Options};
use proxy_http::filter::SharedFactoryState;
use proxy_http::handler::stub::FixedResponseHandler;
use proxy_http::handler::{DownstreamInfo, StreamHandler};
use proxy_http::stat_handles::{
    DownstreamStatHandles, DownstreamStats, GenAiTokenStats, RouterStats, StatHandles,
    TokenUsageStatHandles,
};
use proxy_observability::stats::{StatsControl, WorkerId};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::watch;

// ------------------------------------------------------------ cert minting --
// Same shapes as `tests/tls.rs` -- kept local since each file under `tests/`
// is its own compiled crate and can't share private helpers with a sibling.

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn mint_ca(name: &str) -> Ca {
    let key = KeyPair::generate().expect("ecdsa keygen");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, name);
    let cert = params.self_signed(&key).expect("self-sign CA");
    Ca { cert, key }
}

fn mint_leaf(ca: &Ca, sans: &[&str], key: &KeyPair) -> rcgen::Certificate {
    let names: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(names).expect("leaf params");
    params.distinguished_name.push(DnType::CommonName, sans[0]);
    params.signed_by(key, &ca.cert, &ca.key).expect("sign leaf")
}

fn tls_cert_ir(cert: &rcgen::Certificate, key: &KeyPair) -> TlsCertificateIR {
    TlsCertificateIR {
        cert_chain: DataSourceIR::Inline(cert.pem()),
        private_key: DataSourceIR::Inline(key.serialize_pem()),
    }
}

fn default_params() -> TlsParametersIR {
    TlsParametersIR {
        min_version: TlsVersion::V1_2,
        max_version: TlsVersion::V1_3,
        cipher_suites: vec![],
        ecdh_curves: vec![],
    }
}

// --------------------------------------------------------- upstream fixture --

/// Reserve an ephemeral port, then free it -- same technique as
/// `listener.rs`'s test `free_port`, needed here so the bootstrap YAML can
/// name the listener's port ahead of binding it.
async fn free_port() -> u16 {
    let l = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// A real TLS HTTP/1.1 upstream on loopback: accept, TLS-terminate with
/// `cert`/`key` (via the same `DownstreamTlsFactory` the downstream listener
/// side uses -- there's no reason to hand-roll a second rustls setup here),
/// then serve one fixed 200 response per connection.
async fn spawn_tls_http_upstream(
    cert: &rcgen::Certificate,
    key: &KeyPair,
    body: &'static [u8],
) -> SocketAddr {
    let spec = DownstreamTlsSpec {
        certificate_sds_names: Vec::new(),
        certificates: vec![tls_cert_ir(cert, key)],
        params: default_params(),
        alpn_protocols: vec![],
        validation: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    };
    // Rust note: `Arc` so every accepted connection's spawned task can hold
    // its own clone -- the factory (and the `ServerConfig` inside it) is
    // immutable and cheap to share this way.
    let downstream = Arc::new(DownstreamTlsFactory::build(&spec, "test-tls-upstream").unwrap());

    let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::task::spawn_local(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let downstream = Arc::clone(&downstream);
            tokio::task::spawn_local(async move {
                let Ok(tls_stream) = downstream.wrap(stream).await else {
                    return;
                };
                let handler: Rc<dyn StreamHandler> = Rc::new(FixedResponseHandler {
                    status: http::StatusCode::OK,
                    headers: http::HeaderMap::new(),
                    body: bytes::Bytes::from_static(body),
                });
                let _ = serve_http1(
                    tls_stream,
                    handler,
                    Http1Options { keep_alive: false },
                    std::future::pending(),
                    DownstreamInfo::loopback(),
                )
                .await;
            });
        }
    });
    addr
}

// --------------------------------------------------------------- bootstrap --

/// A one-listener, one-cluster bootstrap: the listener forwards every
/// request to cluster `up`, a STATIC cluster at `127.0.0.1:<upstream_port>`
/// whose `transport_socket` is an `UpstreamTlsContext` carrying `sni` and a
/// `trusted_ca` bundle -- the real config path from YAML down to
/// `UpstreamTlsSpec`, not hand-built IR.
fn bootstrap_yaml(
    listener_port: u16,
    upstream_port: u16,
    sni: &str,
    ca_pem: &str,
    san_matcher: Option<&str>,
) -> String {
    // Rust note: escaping the PEM's newlines into a double-quoted YAML flow
    // scalar (`"...\n...\n"`) sidesteps block-scalar indentation rules --
    // much simpler than getting a `|`-block's indent to line up inside a
    // `format!` template.
    let ca_pem_escaped = ca_pem.replace('\n', "\\n");
    // `san_matcher` is a caller-supplied, already-indented
    // `match_typed_subject_alt_names:` YAML block (or empty) so tests that
    // don't need one don't have to duplicate the whole template.
    let san_matcher_yaml = san_matcher.unwrap_or("");
    format!(
        r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes: [{{ match: {{ prefix: "/" }}, route: {{ cluster: up }} }}]
  clusters:
    - name: up
      type: STATIC
      load_assignment:
        cluster_name: up
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: {upstream_port} }}
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: {sni}
          common_tls_context:
            validation_context:
              trusted_ca:
                inline_string: "{ca_pem_escaped}"
{san_matcher_yaml}"#
    )
}

fn snapshot_from(yaml: &str) -> Arc<ConfigSnapshot> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
        .expect("bootstrap must parse");
    Arc::new(build_snapshot(&loaded).expect("bootstrap must lower to IR"))
}

// -------------------------------------------------------------- listener harness --

struct Harness {
    /// Held purely to keep the config-update channel open. `run_listener_manager`
    /// selects on `config_rx.changed()`, which resolves with `Err` as soon as the
    /// last sender drops -- it reads that as "control plane is gone" and returns,
    /// dropping every bound listening socket with it. Letting this sender fall out
    /// of scope at the end of `spawn_listener` therefore tears the proxy down
    /// before the test can connect to it (symptom: `ConnectionRefused`).
    _config_tx: watch::Sender<proxy_config::ir::SnapshotVersion>,
    shutdown_tx: watch::Sender<bool>,
    manager: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        self.manager.await.expect("listener manager task panicked");
    }
}

/// Boots the real listener manager against `snapshot`, with a `ClusterManager`
/// wired to the real `transport_socket_builder()` -- the same call
/// `crates/proxy`'s `serve()` makes, not a test-only stand-in.
async fn spawn_listener(snapshot: Arc<ConfigSnapshot>) -> Harness {
    // Same registration path production code uses -- see
    // `runtime::SnapshotHandles` for why a bare `WorkerConfigHandle::new` is
    // no longer reachable from outside `proxy-core`.
    let config = SnapshotHandles::new().register(snapshot.clone());
    let (config_tx, config_rx) = watch::channel(snapshot.version);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let registry = ConnectionRegistry::new();

    let cluster_manager = Arc::new(ClusterManager::new(
        Arc::new(proxy_cluster::resolver::TokioResolver),
        proxy_core::tls::transport_socket_builder(),
    ));
    let rejected = cluster_manager
        .update_from_snapshot(&snapshot.clusters)
        .await;
    assert!(
        rejected.is_empty(),
        "test cluster(s) must build cleanly, got: {rejected:?}"
    );
    for name in snapshot.clusters.keys() {
        cluster_manager.force_initialize(name);
    }

    // WP-23 increment 6a: `crates/proxy/src/main.rs` builds this once, at
    // boot, from the real config snapshot's cluster names -- mirrored here
    // rather than skipped, since `initial_bind` now requires it to build
    // `RouterFilterFactory`.
    let stats_control = StatsControl::new(1);
    let stat_handles = Arc::new(StatHandles::build(
        &stats_control,
        snapshot.clusters.keys().map(String::as_str),
    ));
    let router_stats = Arc::new(RouterStats::new(
        stats_control.registry(),
        stat_handles,
        WorkerId(0),
    ));

    // WP-23 increment 6b: `DownstreamStats`/`GenAiTokenStats` counterparts to
    // `router_stats` above -- `initial_bind` now requires both too, mirroring
    // `crates/proxy/src/main.rs`'s `worker_main`.
    let downstream_handles = Arc::new(DownstreamStatHandles::build(
        &stats_control,
        snapshot.listeners.keys().map(String::as_str),
    ));
    let downstream_stats = Arc::new(DownstreamStats::new(
        stats_control.registry(),
        downstream_handles,
        WorkerId(0),
    ));
    let token_usage_handles = Arc::new(TokenUsageStatHandles::build(
        &stats_control,
        snapshot.clusters.keys().map(String::as_str),
    ));
    let token_stats = Arc::new(GenAiTokenStats::new(
        stats_control.registry(),
        token_usage_handles,
        WorkerId(0),
    ));

    let stats = proxy_core::listener::StatsRecorders {
        router: router_stats,
        downstream: downstream_stats,
        token: token_stats,
        tracing: None,
    };

    let factory_state = Arc::new(SharedFactoryState::default());
    let secret_registry = Arc::new(SdsSecretRegistry::new());

    let bound = initial_bind(
        &snapshot,
        &config,
        &registry,
        &shutdown_rx,
        &cluster_manager,
        &stats,
        &factory_state,
        &secret_registry,
    )
    .expect("initial_bind should succeed in tests");

    let manager = tokio::task::spawn_local(run_listener_manager(
        bound,
        config,
        config_rx,
        shutdown_rx,
        registry,
        cluster_manager,
        stats,
        factory_state,
        secret_registry,
    ));

    Harness {
        _config_tx: config_tx,
        shutdown_tx,
        manager,
    }
}

/// Send a plain `GET / HTTP/1.1` over a real socket to `addr` and return the
/// full response bytes as a UTF-8 string.
async fn get_response(addr: SocketAddr) -> String {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect to proxy should succeed");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("read should not time out")
        .expect("read should succeed");

    String::from_utf8(response).expect("response should be valid utf8")
}

// ----------------------------------------------------------------- tests ---

/// The acceptance test: bytes cross a genuine TLS connection from the proxy
/// to the upstream, driven purely through YAML config -- `sni: upstream.test`
/// and a `trusted_ca` matching the upstream's minted CA.
///
/// Mutation-tested (see task notes): reverting `transport_socket_builder` to
/// always return `RawTransportSocket` makes the TLS-only upstream refuse the
/// plaintext preface and this test fails.
#[test]
fn router_forwards_a_real_request_to_a_real_tls_upstream_over_http1() {
    run_local(async {
        let ca = mint_ca("test CA");
        let upstream_key = KeyPair::generate().unwrap();
        let upstream_cert = mint_leaf(&ca, &["upstream.test"], &upstream_key);
        let upstream_body: &'static [u8] = b"hello from tls upstream";
        let upstream_addr =
            spawn_tls_http_upstream(&upstream_cert, &upstream_key, upstream_body).await;

        let listener_port = free_port().await;
        let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
        let snapshot = snapshot_from(&bootstrap_yaml(
            listener_port,
            upstream_addr.port(),
            "upstream.test",
            &ca.cert.pem(),
            None,
        ));
        let harness = spawn_listener(snapshot).await;

        tokio::time::sleep(Duration::from_millis(50)).await;

        let response = get_response(listener_addr).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected a 200 status line, got: {response:?}"
        );
        assert!(
            response.contains("hello from tls upstream"),
            "expected the real TLS upstream's body in the response, got: {response:?}"
        );

        harness.shutdown().await;
    });
}

/// Verification actually verifies: the cluster's `trusted_ca` is a
/// *different* CA than the one that signed the upstream's certificate.
/// Silently succeeding here (accepting an untrusted cert) would be a
/// security defect, not a test-writing choice to shrug at.
#[test]
fn upstream_tls_verification_rejects_the_wrong_ca() {
    run_local(async {
        let real_ca = mint_ca("real CA");
        let other_ca = mint_ca("other CA");
        let upstream_key = KeyPair::generate().unwrap();
        // Upstream's cert is signed by `other_ca`...
        let upstream_cert = mint_leaf(&other_ca, &["upstream.test"], &upstream_key);
        let upstream_addr =
            spawn_tls_http_upstream(&upstream_cert, &upstream_key, b"should never be seen").await;

        let listener_port = free_port().await;
        let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
        // ...but the cluster only trusts `real_ca`.
        let snapshot = snapshot_from(&bootstrap_yaml(
            listener_port,
            upstream_addr.port(),
            "upstream.test",
            &real_ca.cert.pem(),
            None,
        ));
        let harness = spawn_listener(snapshot).await;

        tokio::time::sleep(Duration::from_millis(50)).await;

        let response = get_response(listener_addr).await;
        assert!(
            response.starts_with("HTTP/1.1 503"),
            "wrong CA must be rejected (503), got: {response:?}"
        );
        assert!(
            response
                .to_ascii_lowercase()
                .contains("upstream connect failure"),
            "expected the router's connect-failure local reply, got: {response:?}"
        );

        harness.shutdown().await;
    });
}

/// A `validation_context` with only `trusted_ca` set validates chain trust
/// alone -- Envoy does NOT perform RFC 6125 hostname verification from
/// `trusted_ca` (or `system_root_certs`) by itself. Here the cluster's `sni`
/// is `wrong.test` while the upstream's certificate is only valid for
/// `upstream.test`, and the handshake still succeeds. This is genuine Envoy
/// parity, not a bug in this proxy -- but it is a real footgun: `trusted_ca`
/// alone is chain-of-trust-only, not identity checking. The real defense is
/// `match_typed_subject_alt_names`, exercised by
/// `upstream_tls_san_matcher_rejects_a_mismatched_certificate` below.
#[test]
fn upstream_tls_trusted_ca_alone_does_not_verify_the_hostname() {
    run_local(async {
        let ca = mint_ca("test CA");
        let upstream_key = KeyPair::generate().unwrap();
        let upstream_cert = mint_leaf(&ca, &["upstream.test"], &upstream_key);
        let upstream_body: &'static [u8] = b"hello from tls upstream";
        let upstream_addr =
            spawn_tls_http_upstream(&upstream_cert, &upstream_key, upstream_body).await;

        let listener_port = free_port().await;
        let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
        let snapshot = snapshot_from(&bootstrap_yaml(
            listener_port,
            upstream_addr.port(),
            "wrong.test",
            &ca.cert.pem(),
            None,
        ));
        let harness = spawn_listener(snapshot).await;

        tokio::time::sleep(Duration::from_millis(50)).await;

        let response = get_response(listener_addr).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "trusted_ca alone must not check the hostname/SNI (Envoy parity); \
             expected a 200 status line, got: {response:?}"
        );
        assert!(
            response.contains("hello from tls upstream"),
            "expected the real TLS upstream's body in the response, got: {response:?}"
        );

        harness.shutdown().await;
    });
}

/// The real defense against the footgun above: `match_typed_subject_alt_names`
/// performs the actual identity check. A DNS/exact matcher for `wrong.test`
/// rejects a certificate whose only SAN is `upstream.test` (503); the same
/// setup with a matcher for `upstream.test` (the positive control) succeeds,
/// proving the 503 comes from the matcher itself and not something incidental
/// like a malformed bootstrap.
#[test]
fn upstream_tls_san_matcher_rejects_a_mismatched_certificate() {
    run_local(async {
        let ca = mint_ca("test CA");
        let upstream_key = KeyPair::generate().unwrap();
        let upstream_cert = mint_leaf(&ca, &["upstream.test"], &upstream_key);
        let upstream_addr =
            spawn_tls_http_upstream(&upstream_cert, &upstream_key, b"should never be seen").await;

        let listener_port = free_port().await;
        let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
        let mismatched_matcher = "              match_typed_subject_alt_names:\n                - san_type: DNS\n                  matcher: { exact: wrong.test }\n";
        let snapshot = snapshot_from(&bootstrap_yaml(
            listener_port,
            upstream_addr.port(),
            "upstream.test",
            &ca.cert.pem(),
            Some(mismatched_matcher),
        ));
        let harness = spawn_listener(snapshot).await;

        tokio::time::sleep(Duration::from_millis(50)).await;

        let response = get_response(listener_addr).await;
        assert!(
            response.starts_with("HTTP/1.1 503"),
            "a SAN matcher for `wrong.test` must reject a cert whose SAN is `upstream.test`, got: {response:?}"
        );
        assert!(
            response
                .to_ascii_lowercase()
                .contains("upstream connect failure"),
            "expected the router's connect-failure local reply, got: {response:?}"
        );

        harness.shutdown().await;
    });

    // Positive control: the same setup, but the matcher matches the real SAN.
    run_local(async {
        let ca = mint_ca("test CA");
        let upstream_key = KeyPair::generate().unwrap();
        let upstream_cert = mint_leaf(&ca, &["upstream.test"], &upstream_key);
        let upstream_body: &'static [u8] = b"hello from tls upstream";
        let upstream_addr =
            spawn_tls_http_upstream(&upstream_cert, &upstream_key, upstream_body).await;

        let listener_port = free_port().await;
        let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
        let matching_matcher = "              match_typed_subject_alt_names:\n                - san_type: DNS\n                  matcher: { exact: upstream.test }\n";
        let snapshot = snapshot_from(&bootstrap_yaml(
            listener_port,
            upstream_addr.port(),
            "upstream.test",
            &ca.cert.pem(),
            Some(matching_matcher),
        ));
        let harness = spawn_listener(snapshot).await;

        tokio::time::sleep(Duration::from_millis(50)).await;

        let response = get_response(listener_addr).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "a SAN matcher matching the real SAN must succeed, got: {response:?}"
        );
        assert!(
            response.contains("hello from tls upstream"),
            "expected the real TLS upstream's body in the response, got: {response:?}"
        );

        harness.shutdown().await;
    });
}

/// Strict-mode guard: a `ClusterManager` built with
/// `proxy_cluster::transport::reject_tls_builder()` (the default for anyone
/// who hasn't installed the real TLS builder) must reject a cluster that
/// configures a `transport_socket`, not silently serve it in plaintext.
/// No sockets needed -- this is about `update_from_snapshot`'s return value.
#[tokio::test]
async fn strict_mode_cluster_manager_rejects_a_tls_cluster_without_a_transport_socket_builder() {
    let manager = Arc::new(ClusterManager::new(
        Arc::new(proxy_cluster::resolver::TokioResolver),
        proxy_cluster::transport::reject_tls_builder(),
    ));

    let cluster = ClusterConfig {
        // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
        eds: None,
        name: "secure".to_string(),
        discovery: proxy_config::ir::DiscoveryType::Static,
        lb_policy: proxy_config::ir::LbPolicy::RoundRobin,
        connect_timeout: Duration::from_secs(5),
        endpoints: vec![proxy_config::ir::EndpointIR {
            metadata: Default::default(),
            host: "127.0.0.1".to_string(),
            port: 1,
            weight: 1,
            priority: 0,
        }],
        kind: ClusterKind::Endpoints,
        transport_socket: Some(UpstreamTlsSpec {
            sni: Some("upstream.test".to_string()),
            params: default_params(),
            alpn_protocols: vec![],
            client_certificate: None,
            validation: Some(ValidationContextIR {
                ca: CaSource::TrustedCa(DataSourceIR::Inline("ca-bundle".to_string())),
                san_matchers: vec![],
                allow_expired_certificate: false,
            }),
        }),
        per_connection_buffer_limit_bytes: 1 << 20,
        circuit_breakers: Default::default(),
        upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
        request_headers_to_add: Vec::new(),
        usage_dialect: None,
        health_check: None,
        outlier_detection: None,
    };
    let mut snapshot = std::collections::HashMap::new();
    snapshot.insert("secure".to_string(), Arc::new(cluster));

    let rejected = manager.update_from_snapshot(&snapshot).await;
    assert_eq!(
        rejected.len(),
        1,
        "a transport_socket-configured cluster must be rejected, not silently downgraded"
    );
    assert_eq!(rejected[0].0, "secure");
    assert!(
        manager.cluster("secure").is_none(),
        "a rejected cluster must not become servable"
    );
}
