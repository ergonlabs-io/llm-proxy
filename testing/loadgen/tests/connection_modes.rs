use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject as _;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use loadgen::dialect::Endpoint;
use loadgen::driver::{self, DownstreamMode, RunConfig, TransportConfig};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const SSE: &str = "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n";

fn config(target: String, mode: DownstreamMode, pool: usize) -> Arc<RunConfig> {
    Arc::new(RunConfig {
        targets: driver::parse_targets(&[target]).expect("target"),
        endpoint: Endpoint::Chat,
        model: "test".into(),
        prompt: "hi".into(),
        max_tokens: 4,
        api_key: None,
        stream: true,
        timeout: Duration::from_secs(2),
        transport: TransportConfig {
            mode,
            h1_pool_size: pool,
            ca_file: None,
        },
    })
}

async fn response(_: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from_static(SSE.as_bytes()))))
}

#[tokio::test]
async fn h1_pool_is_bounded_and_reuses_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            count.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service_fn(response))
                    .await;
            });
        }
    });

    let summary = driver::run_closed_loop(
        config(format!("http://{addr}"), DownstreamMode::H1Pool, 2),
        8,
        Duration::from_millis(300),
        Duration::ZERO,
    )
    .await;
    assert_eq!(summary.error_rate, 0.0, "{summary:?}");
    assert!(summary.success > 2);
    assert!(summary.transport.connections_opened <= 2, "{summary:?}");
    assert!(summary.transport.connections_reused > 0);
    assert_eq!(
        summary.transport.connections_opened as usize,
        accepted.load(Ordering::Relaxed)
    );
}

#[tokio::test]
async fn h1_pool_preserves_timeout_accounting() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = service_fn(|request| async move {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    response(request).await
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service)
                    .await;
            });
        }
    });

    let mut cfg = config(format!("http://{addr}"), DownstreamMode::H1Pool, 2);
    Arc::get_mut(&mut cfg).expect("unique").timeout = Duration::from_millis(20);
    let summary = driver::run_closed_loop(cfg, 4, Duration::from_millis(100), Duration::ZERO).await;

    assert_eq!(summary.success, 0, "{summary:?}");
    assert!(summary.timeouts > 0, "{summary:?}");
    assert_eq!(summary.transport_errors, 0, "{summary:?}");
    assert_eq!(summary.timeouts, summary.streams_counted, "{summary:?}");
}

/// A TLS acceptor for `localhost` offering `alpn`, and the PEM of the CA
/// that signed it.
fn tls_acceptor(alpn: &[u8]) -> (TlsAcceptor, String) {
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "loadgen test CA");
    let ca = ca_params.self_signed(&ca_key).expect("ca cert");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = CertificateParams::new(vec!["localhost".into()])
        .expect("leaf params")
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("leaf cert");
    let certs = rustls::pki_types::CertificateDer::pem_slice_iter(leaf.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("cert");
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(leaf_key.serialize_pem().as_bytes())
        .expect("key");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");
    server.alpn_protocols = vec![alpn.to_vec()];
    (TlsAcceptor::from(Arc::new(server)), ca.pem())
}

#[tokio::test]
async fn h2_tls_alpn_multiplexes_simultaneous_streams() {
    let (acceptor, ca_pem) = tls_acceptor(b"h2");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            count.fetch_add(1, Ordering::Relaxed);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(tls),
                        service_fn(|req| async move {
                            tokio::time::sleep(Duration::from_millis(30)).await;
                            response(req).await
                        }),
                    )
                    .await;
            });
        }
    });
    let ca_path = std::env::temp_dir().join(format!("loadgen-ca-{}.pem", std::process::id()));
    std::fs::write(&ca_path, &ca_pem).expect("write CA");
    let mut cfg = config(
        format!("https://localhost:{}", addr.port()),
        DownstreamMode::H2,
        1,
    );
    Arc::get_mut(&mut cfg).expect("unique").transport.ca_file = Some(ca_path.clone());
    let summary = driver::run_closed_loop(cfg, 8, Duration::from_millis(300), Duration::ZERO).await;
    let _ = std::fs::remove_file(ca_path);
    assert_eq!(summary.error_rate, 0.0, "{summary:?}");
    assert!(summary.success >= 8);
    assert_eq!(summary.transport.connections_opened, 1, "{summary:?}");
    assert_eq!(accepted.load(Ordering::Relaxed), 1);
    assert!(summary.transport.streams_per_connection >= 8.0);
}

#[tokio::test]
async fn h1_pool_speaks_http1_over_tls_and_reuses_connections() {
    let (acceptor, ca_pem) = tls_acceptor(b"http/1.1");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            count.fetch_add(1, Ordering::Relaxed);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service_fn(response))
                    .await;
            });
        }
    });
    let ca_path = std::env::temp_dir().join(format!("loadgen-h1-ca-{}.pem", std::process::id()));
    std::fs::write(&ca_path, &ca_pem).expect("write CA");
    let mut cfg = config(
        format!("https://localhost:{}", addr.port()),
        DownstreamMode::H1Pool,
        2,
    );
    Arc::get_mut(&mut cfg).expect("unique").transport.ca_file = Some(ca_path.clone());
    let summary = driver::run_closed_loop(cfg, 8, Duration::from_millis(300), Duration::ZERO).await;
    let _ = std::fs::remove_file(ca_path);
    assert_eq!(summary.error_rate, 0.0, "{summary:?}");
    assert!(summary.success > 2, "{summary:?}");
    assert!(summary.transport.connections_opened <= 2, "{summary:?}");
    assert!(summary.transport.connections_reused > 0, "{summary:?}");
    assert_eq!(
        summary.transport.connections_opened as usize,
        accepted.load(Ordering::Relaxed),
        "every opened connection completed a TLS accept"
    );
}
