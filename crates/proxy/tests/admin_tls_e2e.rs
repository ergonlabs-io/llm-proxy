//! The `--config` dialect's `admin.tls` end to end: the real binary serves
//! the admin API over TLS and nothing in the clear on that port, re-reads the
//! certificate on `SIGHUP` like `listen.tls`, and warns once when a token-gated
//! admin API is bound to a non-loopback address without TLS.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

mod common;

use common::free_port;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const ADMIN_TOKEN: &str = "admin-tls-e2e-token";
/// The start-up warning for a plaintext, token-gated, non-loopback admin.
const EXPOSED_WARNING: &str = "is not a loopback address and the admin API has no TLS";

/// The proxy child, killed on drop; its scratch directory is removed.
struct Proxy {
    child: Child,
    dir: PathBuf,
    admin_port: u16,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Proxy {
    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("proxy.log")).unwrap_or_default()
    }

    fn sighup(&self) {
        let status = Command::new("kill")
            .args(["-HUP", &self.child.id().to_string()])
            .status()
            .expect("run kill -HUP");
        assert!(status.success(), "kill -HUP failed");
    }

    async fn wait_for_log(&self, needle: &str, count: usize) {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        while self.log().matches(needle).count() < count {
            assert!(
                Instant::now() < deadline,
                "log never showed {count} x {needle:?}; log:\n{}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-admin-tls-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// Writes a leaf for `localhost`, signed by a fresh CA, to `dir/admin.crt`
/// and `dir/admin.key`; returns the CA certificate a client must trust.
fn write_cert(dir: &Path) -> CertificateDer<'static> {
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = CertificateParams::new(vec!["localhost".to_string()])
        .expect("leaf params")
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("sign leaf");
    // Written then renamed, as the TLS docs tell operators to rotate.
    for (name, pem) in [
        ("admin.crt", leaf.pem()),
        ("admin.key", leaf_key.serialize_pem()),
    ] {
        let tmp = dir.join(format!("{name}.tmp"));
        std::fs::write(&tmp, pem).expect("write PEM");
        std::fs::rename(&tmp, dir.join(name)).expect("rename PEM");
    }
    CertificateDer::from(ca.der().to_vec())
}

/// Starts the proxy with `admin` as the dialect's `admin` value, rendered
/// with `{port}`, `{crt}` and `{key}` substituted.
fn start_proxy(dir: PathBuf, admin: &str) -> Proxy {
    let admin_port = free_port();
    let admin = admin
        .replace("{port}", &admin_port.to_string())
        .replace("{crt}", &dir.join("admin.crt").display().to_string())
        .replace("{key}", &dir.join("admin.key").display().to_string());
    // The provider points at a closed port: these tests only talk to admin.
    let config = format!(
        "version: 1\n\
         listen: 127.0.0.1:{listen}\n\
         admin: {admin}\n\
         providers:\n  local:\n    type: openai\n    base_url: http://127.0.0.1:{dead}\n\
         routes:\n  - model: \"*\"\n    provider: local\n",
        listen = free_port(),
        dead = free_port(),
    );
    let config_path = dir.join("llmproxy.yaml");
    std::fs::write(&config_path, config).expect("write config");
    let log = std::fs::File::create(dir.join("proxy.log")).expect("log file");
    let child = Command::new(BIN)
        .arg("--config")
        .arg(&config_path)
        .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
        .stdout(Stdio::from(log.try_clone().expect("log clone")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn llm-proxy");
    Proxy {
        child,
        dir,
        admin_port,
    }
}

const READY: &[u8] = b"GET /ready HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n";

/// Sends `GET /ready` over a stream and reads the whole response.
async fn ready_over<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
) -> std::io::Result<String> {
    stream.write_all(READY).await?;
    let mut response = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .map_err(|_| std::io::Error::other("no response within the IO timeout"))??;
    Ok(String::from_utf8_lossy(&response).into_owned())
}

/// One TLS `GET /ready` trusting only `ca`.
async fn ready_over_tls(port: u16, ca: &CertificateDer<'static>) -> std::io::Result<String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).expect("CA root");
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    let name = ServerName::try_from("localhost").expect("server name");
    let tls = tokio::time::timeout(
        IO_TIMEOUT,
        TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await
    .map_err(|_| std::io::Error::other("no TLS handshake within the IO timeout"))??;
    ready_over(tls).await
}

/// Retries `attempt` until it answers `200 LIVE` or the start-up deadline.
async fn until_live<F, Fut>(proxy: &Proxy, mut attempt: F) -> String
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<String>>,
{
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        match attempt().await {
            Ok(response) if response.starts_with("HTTP/1.1 200") => return response,
            other => assert!(
                Instant::now() < deadline,
                "admin never answered 200 (last: {other:?}); log:\n{}",
                proxy.log()
            ),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

const TLS_ADMIN: &str =
    "{ address: \"127.0.0.1:{port}\", tls: { cert_file: \"{crt}\", key_file: \"{key}\" } }";

#[tokio::test(flavor = "multi_thread")]
async fn admin_tls_serves_https_and_answers_no_plaintext_request_on_that_port() {
    let dir = scratch_dir();
    let ca = write_cert(&dir);
    let proxy = start_proxy(dir, TLS_ADMIN);
    let port = proxy.admin_port;
    let response = until_live(&proxy, || ready_over_tls(port, &ca)).await;
    assert!(
        response.ends_with("LIVE"),
        "unexpected /ready body: {response:?}"
    );

    // The port is up (the TLS request above just answered), so a plaintext
    // request reaches the same listener and must get no HTTP answer.
    let plain = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to the admin port");
    match ready_over(plain).await {
        Ok(response) => assert!(
            !response.contains("HTTP/1.1") && !response.contains("LIVE"),
            "a plaintext request on the TLS admin port got an HTTP answer: {response:?}"
        ),
        // A reset is also a refusal.
        Err(err) => assert_ne!(
            err.to_string(),
            "no response within the IO timeout",
            "the admin port held a plaintext request open instead of refusing it"
        ),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sighup_reload_serves_the_renewed_admin_certificate() {
    let dir = scratch_dir();
    let old_ca = write_cert(&dir);
    let proxy = start_proxy(dir, TLS_ADMIN);
    let port = proxy.admin_port;
    until_live(&proxy, || ready_over_tls(port, &old_ca)).await;

    let new_ca = write_cert(&proxy.dir);
    proxy.sighup();
    proxy
        .wait_for_log("SIGHUP: config reload succeeded", 1)
        .await;
    until_live(&proxy, || ready_over_tls(port, &new_ca)).await;
    assert!(
        ready_over_tls(port, &old_ca).await.is_err(),
        "after the reload the admin port still serves the certificate the old CA signed"
    );
}

/// The warning fires at start, names `admin.address`, and a reload of the
/// same config does not repeat it.
#[tokio::test(flavor = "multi_thread")]
async fn a_plaintext_admin_on_a_non_loopback_address_warns_once() {
    let proxy = start_proxy(scratch_dir(), "\"0.0.0.0:{port}\"");
    let port = proxy.admin_port;
    until_live(&proxy, || async move {
        ready_over(TcpStream::connect(("127.0.0.1", port)).await?).await
    })
    .await;
    proxy.sighup();
    proxy
        .wait_for_log("SIGHUP: config reload succeeded", 1)
        .await;
    // The admin server picks up a reloaded snapshot at its next accept.
    until_live(&proxy, || async move {
        ready_over(TcpStream::connect(("127.0.0.1", port)).await?).await
    })
    .await;
    let log = proxy.log();
    let warnings: Vec<&str> = log
        .lines()
        .filter(|l| l.contains(EXPOSED_WARNING))
        .collect();
    assert_eq!(
        warnings.len(),
        1,
        "expected exactly one exposure warning; log:\n{log}"
    );
    assert!(
        warnings[0].contains("admin.address") && warnings[0].contains(&format!("0.0.0.0:{port}")),
        "the warning must name admin.address and its value: {}",
        warnings[0]
    );
}

/// The two binds the warning must stay quiet for: loopback without TLS, and
/// a non-loopback address with TLS.
#[tokio::test(flavor = "multi_thread")]
async fn a_loopback_or_tls_admin_does_not_warn() {
    let loopback = start_proxy(scratch_dir(), "\"127.0.0.1:{port}\"");
    let port = loopback.admin_port;
    until_live(&loopback, || async move {
        ready_over(TcpStream::connect(("127.0.0.1", port)).await?).await
    })
    .await;

    let dir = scratch_dir();
    let ca = write_cert(&dir);
    let tls = start_proxy(dir, &TLS_ADMIN.replace("127.0.0.1", "0.0.0.0"));
    let tls_port = tls.admin_port;
    until_live(&tls, || ready_over_tls(tls_port, &ca)).await;

    for (proxy, what) in [(&loopback, "loopback"), (&tls, "non-loopback with TLS")] {
        let log = proxy.log();
        assert!(
            !log.contains(EXPOSED_WARNING),
            "a {what} admin warned about exposure; log:\n{log}"
        );
        // The same startup path the warning sits on did run.
        assert!(
            log.contains("admin server listening"),
            "the {what} admin never started; log:\n{log}"
        );
    }
}
