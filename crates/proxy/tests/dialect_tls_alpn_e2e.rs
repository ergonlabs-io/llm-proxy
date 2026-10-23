//! The `--config` dialect's TLS listener end to end: the real binary must
//! negotiate h2 through ALPN and serve the request over h2, and must still
//! serve an HTTP/1.1-only client. Before the listener offered ALPN, an
//! h2-only client could not connect at all.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

mod common;

use common::free_port;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The proxy child, killed on drop; its scratch directory is removed.
struct Proxy {
    child: Child,
    dir: PathBuf,
    port: u16,
    ca: CertificateDer<'static>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start_proxy() -> Proxy {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-dialect-tls-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = CertificateParams::new(vec!["localhost".to_string()])
        .expect("leaf params")
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("sign leaf");
    std::fs::write(dir.join("tls.crt"), leaf.pem()).expect("write cert");
    std::fs::write(dir.join("tls.key"), leaf_key.serialize_pem()).expect("write key");

    let port = free_port();
    // The provider points at a closed port: the test needs a response over
    // the negotiated protocol, not a successful upstream call.
    let config = format!(
        "version: 0\n\
         listen:\n  address: 127.0.0.1:{port}\n  tls: {{ cert_file: {crt}, key_file: {key} }}\n\
         providers:\n  local:\n    type: openai\n    base_url: http://127.0.0.1:{dead}\n\
         routes:\n  - model: \"*\"\n    provider: local\n",
        crt = dir.join("tls.crt").display(),
        key = dir.join("tls.key").display(),
        dead = free_port(),
    );
    let config_path = dir.join("llmproxy.yaml");
    std::fs::write(&config_path, config).expect("write config");
    let log = std::fs::File::create(dir.join("proxy.log")).expect("log file");
    let child = Command::new(BIN)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::from(log.try_clone().expect("log clone")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn llm-proxy");
    Proxy {
        child,
        dir,
        port,
        ca: CertificateDer::from(ca.der().to_vec()),
    }
}

fn log_of(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("proxy.log")).unwrap_or_default()
}

/// Completes a TLS handshake offering `alpn`, retrying until the listener is
/// up; returns the stream and the protocol the server selected.
async fn connect(
    proxy: &Proxy,
    alpn: &[&[u8]],
) -> (tokio_rustls::client::TlsStream<TcpStream>, Option<Vec<u8>>) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(proxy.ca.clone()).expect("CA root");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let connector = TlsConnector::from(Arc::new(config));
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Ok(tcp) = TcpStream::connect(("127.0.0.1", proxy.port)).await {
            let name = ServerName::try_from("localhost").expect("server name");
            if let Ok(Ok(tls)) =
                tokio::time::timeout(IO_TIMEOUT, connector.connect(name, tcp)).await
            {
                let selected = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                return (tls, selected);
            }
        }
        assert!(
            Instant::now() < deadline,
            "no TLS handshake with the proxy within {STARTUP_TIMEOUT:?}; log:\n{}",
            log_of(&proxy.dir)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

const BODY: &str = r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;

#[tokio::test(flavor = "multi_thread")]
async fn tls_listener_negotiates_h2_and_serves_the_request_over_it() {
    let proxy = start_proxy();
    let (tls, selected) = connect(&proxy, &[b"h2"]).await;
    assert_eq!(
        selected.as_deref(),
        Some(&b"h2"[..]),
        "an h2-only client must get h2; log:\n{}",
        log_of(&proxy.dir)
    );
    let (mut client, conn) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(conn);
    let request = http::Request::post("https://localhost/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("request");
    let (response, mut send) = client.send_request(request, false).expect("send headers");
    send.send_data(bytes::Bytes::from_static(BODY.as_bytes()), true)
        .expect("send body");
    let response = tokio::time::timeout(IO_TIMEOUT, response)
        .await
        .expect("response within the IO timeout")
        .expect("an h2 response, not a connection error");
    // The provider's port is closed, so the proxy answers itself; any HTTP
    // status proves the h2 codec served the stream.
    assert!(
        response.status().is_server_error(),
        "expected the proxy's own 5xx for a closed upstream, got {}",
        response.status()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_listener_still_serves_an_http1_only_client() {
    let proxy = start_proxy();
    let (mut tls, selected) = connect(&proxy, &[b"http/1.1"]).await;
    assert_eq!(selected.as_deref(), Some(&b"http/1.1"[..]));
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{BODY}",
        BODY.len()
    );
    tls.write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut head = vec![0u8; 12];
    tokio::time::timeout(IO_TIMEOUT, tls.read_exact(&mut head))
        .await
        .expect("response within the IO timeout")
        .expect("read status line");
    let line = String::from_utf8_lossy(&head);
    assert!(
        line.starts_with("HTTP/1.1 5"),
        "expected an HTTP/1.1 5xx, got {line:?}"
    );
}
