//! Self-signed TLS support for the mock LLM upstreams (`openai`/`anthropic`),
//! used by the hermetic TLS end-to-end test (the MVP north-star): a
//! throwaway CA + leaf certificate minted at runtime with `rcgen`, served
//! over HTTP/1.1 via `tokio-rustls`, so the proxy's real upstream-TLS path
//! (SNI + certificate verification, `crates/proxy-core/src/tls`) gets
//! exercised end to end with no network and no pre-baked fixtures.
//!
//! Cert-minting mirrors `crates/proxy-core/tests/upstream_tls.rs`'s
//! `mint_ca`/`mint_leaf` helpers -- kept local here (rather than shared)
//! since that file lives in a different crate and, being itself a `tests/`
//! integration test, has nothing to export.

use std::io::Cursor;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use super::ResponseBody;

/// A freshly minted CA + leaf certificate pair for one DNS name -- the PEM
/// material a test needs both to configure the mock server (internal
/// `cert_pem`/`key_pem`) and to point the dialect's `ca_file` at
/// (`ca_pem`).
pub struct MockTls {
    pub ca_pem: String,
    pub dns_name: String,
    cert_pem: String,
    key_pem: String,
}

impl MockTls {
    /// Mint a self-signed CA and a leaf certificate whose only SAN is
    /// `dns_name`. Deliberately never `localhost`: the whole point of this
    /// helper is exercising a real SNI/SAN hostname check, not the loopback
    /// name every resolver already special-cases.
    pub fn new(dns_name: &str) -> Self {
        let ca_key = KeyPair::generate().expect("ecdsa keygen");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "diffrig mock CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");

        let leaf_key = KeyPair::generate().expect("ecdsa keygen");
        let mut leaf_params =
            CertificateParams::new(vec![dns_name.to_string()]).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, dns_name);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("sign leaf");

        Self {
            ca_pem: ca_cert.pem(),
            dns_name: dns_name.to_string(),
            cert_pem: leaf_cert.pem(),
            key_pem: leaf_key.serialize_pem(),
        }
    }
}

/// Build a `TlsAcceptor` serving `tls`'s leaf certificate, no client auth.
///
/// Rust note: `ring` (not `aws-lc-rs`), matching every other TLS user in this
/// workspace (see the root `Cargo.toml`'s note on the same choice) --
/// `builder_with_provider` is used explicitly so this doesn't depend on a
/// process-wide default crypto provider ever having been installed (nothing
/// else in this crate installs one).
fn build_acceptor(tls: &MockTls) -> TlsAcceptor {
    let certs: Vec<_> = rustls_pemfile::certs(&mut Cursor::new(tls.cert_pem.as_bytes()))
        .collect::<Result<_, _>>()
        .expect("mock leaf cert PEM parses");
    let key = rustls_pemfile::private_key(&mut Cursor::new(tls.key_pem.as_bytes()))
        .expect("mock leaf key PEM parses")
        .expect("mock leaf key PEM contains a private key");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring's default protocol versions are always valid")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("mock cert/key pair builds a valid ServerConfig");
    TlsAcceptor::from(Arc::new(config))
}

/// Handle to a TLS-terminating mock upstream bound on loopback.
///
/// Rust note: bound on *both* `127.0.0.1` and `::1` at the same port --
/// `LOGICAL_DNS` clusters keep only the first address a hostname resolves to
/// (see `proxy_cluster::discovery::logical_dns_hosts`), and the OS resolver
/// for a `*.localhost` name (this module's whole hermetic-DNS trick; see the
/// TLS E2E test) may hand back the IPv6 loopback address first. Binding both
/// loopback families to the same port means whichever one the proxy dials,
/// this server is listening on it. Hosts with no IPv6 loopback configured
/// simply won't offer a `::1` DNS record either (the resolver filters
/// unconfigured address families by default), so a failed `::1` bind there
/// is self-consistent rather than a silent gap.
pub(crate) struct TlsServerHandle {
    pub(crate) port: u16,
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl TlsServerHandle {
    pub(crate) async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

/// Spawn a TLS-terminating HTTP/1.1 server on loopback (both address
/// families, see [`TlsServerHandle`]), calling `handler` for every request on
/// every accepted connection -- the TLS-capable twin of `super::serve`.
pub(crate) async fn serve_tls<F, Fut>(handler: F, tls: &MockTls) -> anyhow::Result<TlsServerHandle>
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<Response<ResponseBody>, std::convert::Infallible>>
        + Send
        + 'static,
{
    let acceptor = build_acceptor(tls);

    let v4 = TcpListener::bind("127.0.0.1:0").await?;
    let port = v4.local_addr()?.port();
    let v6 = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port))
        .await
        .ok();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = vec![tokio::spawn(accept_loop(
        v4,
        acceptor.clone(),
        handler.clone(),
        shutdown_rx.clone(),
    ))];
    if let Some(v6) = v6 {
        tasks.push(tokio::spawn(accept_loop(
            v6,
            acceptor,
            handler,
            shutdown_rx,
        )));
    }

    Ok(TlsServerHandle {
        port,
        shutdown_tx,
        tasks,
    })
}

/// A TLS front bound on loopback that decrypts and forwards, byte for byte,
/// to an already-running plaintext server.
///
/// Why a byte pump rather than an HTTP reverse proxy: the point is to put a
/// real TLS handshake in front of a server **we did not write** (Ollama)
/// without becoming a second implementation of HTTP in the path. Parsing and
/// re-emitting requests here would mean the thing under test talks to *our*
/// framing again, which is exactly the property this tier exists to avoid.
/// A `copy_bidirectional` cannot reframe anything.
pub struct TlsPassthrough {
    pub port: u16,
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl TlsPassthrough {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

/// Spawn a TLS terminator on loopback (both address families, see
/// [`TlsServerHandle`] for why) that forwards plaintext to `target`.
pub async fn spawn_tls_passthrough(
    tls: &MockTls,
    target: SocketAddr,
) -> anyhow::Result<TlsPassthrough> {
    let acceptor = build_acceptor(tls);

    let v4 = TcpListener::bind("127.0.0.1:0").await?;
    let port = v4.local_addr()?.port();
    let v6 = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port))
        .await
        .ok();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = vec![tokio::spawn(passthrough_accept_loop(
        v4,
        acceptor.clone(),
        target,
        shutdown_rx.clone(),
    ))];
    if let Some(v6) = v6 {
        tasks.push(tokio::spawn(passthrough_accept_loop(
            v6,
            acceptor,
            target,
            shutdown_rx,
        )));
    }

    Ok(TlsPassthrough {
        port,
        shutdown_tx,
        tasks,
    })
}

async fn passthrough_accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    target: SocketAddr,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls_stream) = acceptor.accept(stream).await else { return };
                    let Ok(mut upstream) = tokio::net::TcpStream::connect(target).await else {
                        return;
                    };
                    // Rust note: pumps both directions until either side
                    // closes. Errors are deliberately ignored -- a client
                    // hanging up mid-stream is normal here, and the test
                    // asserts on what the PROXY observed, not on this shim.
                    let _ = tokio::io::copy_bidirectional(&mut tls_stream, &mut upstream).await;
                });
            }
        }
    }
}

async fn accept_loop<F, Fut>(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    handler: F,
    mut shutdown_rx: watch::Receiver<bool>,
) where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<Response<ResponseBody>, std::convert::Infallible>>
        + Send
        + 'static,
{
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let acceptor = acceptor.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let Ok(tls_stream) = acceptor.accept(stream).await else { return };
                    let io = TokioIo::new(tls_stream);
                    let service = service_fn(handler);
                    let _ = http1::Builder::new().serve_connection(io, service).await;
                });
            }
        }
    }
}
