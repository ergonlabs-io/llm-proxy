//! A tenant's own provider key, stored through the admin API, replaces the
//! operator credential on upstream requests, survives a restart, and goes away
//! on DELETE (ADR-0007).
//!
//! Drives the real `llm-proxy` binary with an Envoy-mode bootstrap (`-c`), one
//! cluster that carries an operator credential and a `tenant_credential` slot
//! in `io.llmproxy.provider_auth` metadata, a recording mock upstream, a
//! persistent redb auth store, and a 0600 key-encryption-key file. Assertions
//! are on the `Authorization` header the upstream actually received, and on the
//! bytes of the redb file.
//!
//! Rust note: same harness shape as `tests/auth_store_e2e.rs` (std threads, no
//! async runtime, ephemeral ports, a guard that kills the proxy on drop). Every
//! wait is bounded, so a hung child fails the test instead of stalling it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const ADMIN_TOKEN: &str = "tenant-credentials-e2e-admin-token";
const HMAC_SECRET: &str = "tenant-credentials-e2e-hmac-secret";
const TENANT: &str = "tenant-t";
const OPERATOR_AUTH: &str = "Bearer operator-key";
const TENANT_SENTINEL: &str = "sk-tenant-SENTINEL";
const KEK: [u8; 32] = *b"e2e-kek-0123456789abcdef-padding";

#[test]
fn a_stored_tenant_key_replaces_the_operator_key_and_survives_a_restart() {
    let dir = scratch_dir();
    let kek_path = dir.join("credential-kek");
    std::fs::write(&kek_path, KEK).expect("write kek");
    std::fs::set_permissions(&kek_path, std::fs::Permissions::from_mode(0o600)).expect("chmod kek");
    let db = dir.join("control.redb");
    let upstream = RecordingUpstream::spawn();

    let virtual_key = {
        let proxy = Proxy::start(&dir, &upstream, &db, &kek_path);
        proxy.admin_ok(
            "POST",
            "/tenants",
            &format!(r#"{{"tenant":"{TENANT}"}}"#),
            201,
        );
        let minted = proxy.admin_ok(
            "POST",
            "/keys",
            &format!(r#"{{"tenant":"{TENANT}","key_id":"t-key-1"}}"#),
            201,
        );
        let virtual_key = minted["key"].as_str().expect("plaintext key").to_string();

        // Platform mode: the operator credential is what the provider sees.
        assert_eq!(upstream.send(&proxy, &virtual_key), OPERATOR_AUTH);

        // Store the tenant's own key; the next request must carry it instead.
        let stored = proxy.admin_ok(
            "PUT",
            &format!("/tenants/{TENANT}/provider_credentials/openrouter"),
            &format!(r#"{{"schema_version":1,"api_key":"{TENANT_SENTINEL}"}}"#),
            200,
        );
        assert!(!stored.to_string().contains(TENANT_SENTINEL));
        assert_eq!(
            upstream.send(&proxy, &virtual_key),
            format!("Bearer {TENANT_SENTINEL}")
        );
        virtual_key
    };

    // At rest the key is sealed: the plaintext is nowhere in the redb file.
    let on_disk = std::fs::read(&db).expect("read redb file");
    assert!(
        !contains(&on_disk, TENANT_SENTINEL.as_bytes()),
        "tenant key is present in plaintext in the redb file"
    );

    // Same store, same KEK, new process: still the tenant key.
    let restarted = Proxy::start(&dir, &upstream, &db, &kek_path);
    assert_eq!(
        upstream.send(&restarted, &virtual_key),
        format!("Bearer {TENANT_SENTINEL}"),
        "tenant key lost or operator key used after a restart"
    );

    // DELETE returns the tenant to platform mode.
    restarted.admin_ok(
        "DELETE",
        &format!("/tenants/{TENANT}/provider_credentials/openrouter"),
        "",
        204,
    );
    assert_eq!(upstream.send(&restarted, &virtual_key), OPERATOR_AUTH);

    // The operator key was seen before the PUT and after the DELETE only.
    let seen = upstream.authorizations();
    let expected_tenant = format!("Bearer {TENANT_SENTINEL}");
    assert_eq!(
        seen,
        vec![
            OPERATOR_AUTH.to_string(),
            expected_tenant.clone(),
            expected_tenant,
            OPERATOR_AUTH.to_string(),
        ]
    );
    drop(restarted);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ helpers --

fn bootstrap(listen: u16, admin: u16, upstream: u16, db: &Path, kek: &Path) -> String {
    format!(
        r#"
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin} }}
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listen} }}
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
                          route: {{ cluster: backend, timeout: 0s }}
                http_filters:
                  - name: llmproxy.auth
                    typed_config:
                      "@type": type.llmproxy.dev/llmproxy.filters.v0.Authentication
                      hmac_secret: {{ inline_string: "{HMAC_SECRET}" }}
                      persistent:
                        path: "{db}"
                      tenant_credentials:
                        encryption_key_file: "{kek}"
                        encryption_key_id: kek-e2e
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: backend
      type: STATIC
      connect_timeout: 2s
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - {{ key: authorization, value: "{OPERATOR_AUTH}" }}
            tenant_credential: {{ provider: openrouter, header: authorization, prefix: "Bearer " }}
      load_assignment:
        cluster_name: backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: {upstream} }}
"#,
        db = db.display(),
        kek = kek.display(),
    )
}

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "llm-proxy-tenant-credentials-e2e-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// A running proxy, killed and reaped on drop so a failed assertion cannot
/// leave a listener behind (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    listen: SocketAddr,
    admin: SocketAddr,
}

impl Proxy {
    fn start(dir: &Path, upstream: &RecordingUpstream, db: &Path, kek: &Path) -> Proxy {
        let (listen, admin) = (free_port(), free_port());
        let path = dir.join("bootstrap.yaml");
        std::fs::write(
            &path,
            bootstrap(listen, admin, upstream.addr.port(), db, kek),
        )
        .expect("write bootstrap");
        let child = Command::new(BIN)
            .args([
                "-c",
                path.to_str().expect("utf-8 path"),
                "--concurrency",
                "1",
            ])
            .env("LLMPROXY_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn llm-proxy");
        let proxy = Proxy {
            child,
            listen: SocketAddr::from(([127, 0, 0, 1], listen)),
            admin: SocketAddr::from(([127, 0, 0, 1], admin)),
        };
        assert!(
            wait_for_connectable(proxy.admin, STARTUP_TIMEOUT),
            "admin listener did not come up"
        );
        assert!(
            wait_for_connectable(proxy.listen, STARTUP_TIMEOUT),
            "data listener did not come up"
        );
        proxy
    }

    /// One admin call, retried while the control plane is still registering
    /// (503 right after boot), expecting `want`. Returns the JSON body, or
    /// `null` for an empty one.
    fn admin_ok(&self, method: &str, path: &str, body: &str, want: u16) -> serde_json::Value {
        let deadline = std::time::Instant::now() + STARTUP_TIMEOUT;
        loop {
            let response = http(
                self.admin,
                method,
                path,
                &[("Authorization", &format!("Bearer {ADMIN_TOKEN}"))],
                body,
            );
            if !response.starts_with("HTTP/1.1 503") || std::time::Instant::now() >= deadline {
                assert!(
                    response.starts_with(&format!("HTTP/1.1 {want}")),
                    "{method} {path} expected {want}:\n{response}"
                );
                return serde_json::from_str(response_body(&response))
                    .unwrap_or(serde_json::Value::Null);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A mock provider that answers `200` and records each request's
/// `Authorization` header.
struct RecordingUpstream {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
}

impl RecordingUpstream {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
        let addr = listener.local_addr().expect("local addr");
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let recorder = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let recorder = Arc::clone(&recorder);
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                    let mut raw = Vec::new();
                    let mut buf = [0u8; 4096];
                    let head_end = loop {
                        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i;
                        }
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => raw.extend_from_slice(&buf[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
                    let content_length: usize = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(str::to_string)
                        })
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    let mut have = raw.len() - (head_end + 4);
                    while have < content_length {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => have += n,
                        }
                    }
                    let authorization = head
                        .lines()
                        .find_map(|l| {
                            let (name, value) = l.split_once(':')?;
                            name.eq_ignore_ascii_case("authorization")
                                .then(|| value.trim().to_string())
                        })
                        .unwrap_or_default();
                    recorder.lock().unwrap().push(authorization);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                          Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                    );
                });
            }
        });
        RecordingUpstream { addr, seen }
    }

    fn authorizations(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    /// Sends one request through `proxy` with `virtual_key`, asserts a 200, and
    /// returns the `Authorization` value the upstream received for it.
    fn send(&self, proxy: &Proxy, virtual_key: &str) -> String {
        let before = self.authorizations().len();
        let response = http(
            proxy.listen,
            "POST",
            "/v1/chat/completions",
            &[("Authorization", &format!("Bearer {virtual_key}"))],
            r#"{"model":"m","messages":[]}"#,
        );
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "proxied request failed:\n{response}"
        );
        let seen = self.authorizations();
        assert_eq!(
            seen.len(),
            before + 1,
            "expected exactly one upstream request"
        );
        seen[before].clone()
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn response_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
}

fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set_read_timeout");
    let extra: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: proxy.local\r\n{extra}\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .expect("write request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

fn wait_for_connectable(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
}
