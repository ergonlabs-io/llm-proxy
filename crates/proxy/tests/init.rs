#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

mod common;

use common::free_port;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

fn unique_dir(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "llm-proxy-init-{label}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

#[test]
fn init_creates_a_valid_install_without_overwriting_it() {
    let dir = unique_dir("valid");
    let first = Command::new(BIN)
        .args(["init", dir.to_str().unwrap()])
        .output()
        .expect("run init");
    assert!(
        first.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(dir.join("llmproxy.yaml").is_file());
    assert!(dir.join("auth-secret").is_file());
    assert!(std::fs::read_to_string(dir.join("llmproxy.yaml"))
        .unwrap()
        .contains("output: ./llmproxy-access.log"));
    assert!(String::from_utf8_lossy(&first.stdout).contains("tenant: default"));

    let validate = Command::new(BIN)
        .current_dir(&dir)
        .args(["--config", "llmproxy.yaml", "--mode", "validate"])
        .output()
        .expect("validate generated config");
    assert!(
        validate.status.success(),
        "generated config invalid: {}",
        String::from_utf8_lossy(&validate.stderr)
    );

    let config_before = std::fs::read(dir.join("llmproxy.yaml")).unwrap();
    let second = Command::new(BIN)
        .args(["init", dir.to_str().unwrap()])
        .output()
        .expect("run init twice");
    assert!(!second.status.success());
    assert_eq!(
        config_before,
        std::fs::read(dir.join("llmproxy.yaml")).unwrap()
    );

    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn init_makes_the_authentication_secret_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = unique_dir("permissions");
    let status = Command::new(BIN)
        .args(["init", dir.to_str().unwrap()])
        .status()
        .expect("run init");
    assert!(status.success());
    let mode = std::fs::metadata(dir.join("auth-secret"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    std::fs::remove_dir_all(dir).unwrap();
}

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

struct Serving(Child);

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Sends one HTTP/1.1 request with `Connection: close` and returns the whole
/// response, bounded by [`IO_TIMEOUT`].
fn http(addr: SocketAddr, head: &str, body: &str) -> String {
    let mut stream = TcpStream::connect_timeout(&addr, IO_TIMEOUT).expect("connect");
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    write!(
        stream,
        "{head}\r\nhost: {addr}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut out = String::new();
    let _ = stream.read_to_string(&mut out);
    out
}

/// An OpenAI-compatible provider that answers every request with one chat
/// completion and counts what it served.
fn mock_provider() -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock provider");
    let addr = listener.local_addr().unwrap();
    let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = std::sync::Arc::clone(&served);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let count = std::sync::Arc::clone(&count);
            std::thread::spawn(move || {
                // The accepted socket may inherit non-blocking mode on macOS.
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let mut buf = Vec::new();
                let mut chunk = [0_u8; 4096];
                while let Ok(n) = stream.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf);
                    if let Some(end) = text.find("\r\n\r\n") {
                        let length = text[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let body = r#"{"id":"c1","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}"#;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    (addr, served)
}

/// The key `init` prints must work against the config `init` writes, with no
/// admin call first. The default tenant has no stored model policy, so this
/// holds only because the starter allows tenants without one.
#[test]
fn the_key_init_prints_is_served_by_the_starter_config() {
    let dir = unique_dir("serve");
    let init = Command::new(BIN)
        .args(["init", dir.to_str().unwrap()])
        .output()
        .expect("run init");
    assert!(init.status.success());
    let stdout = String::from_utf8_lossy(&init.stdout);
    let key = stdout
        .split_whitespace()
        .find(|word| word.starts_with("llmp_"))
        .expect("init prints a key")
        .to_string();

    let (provider, served) = mock_provider();
    let listen = free_port();
    let admin = free_port();
    let path = dir.join("llmproxy.yaml");
    let config = std::fs::read_to_string(&path)
        .unwrap()
        .replace(
            "listen: 0.0.0.0:53421",
            &format!("listen: 127.0.0.1:{listen}"),
        )
        .replace(
            "admin: 127.0.0.1:53422",
            &format!("admin: 127.0.0.1:{admin}"),
        )
        .replace(
            "base_url: http://127.0.0.1:11434",
            &format!("base_url: http://{provider}"),
        );
    std::fs::write(&path, config).unwrap();

    let _serving = Serving(
        Command::new(BIN)
            .current_dir(&dir)
            .args(["--config", "llmproxy.yaml", "--concurrency", "1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn llm-proxy"),
    );
    let admin_addr: SocketAddr = format!("127.0.0.1:{admin}").parse().unwrap();
    let listen_addr: SocketAddr = format!("127.0.0.1:{listen}").parse().unwrap();
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if TcpStream::connect_timeout(&admin_addr, Duration::from_millis(200)).is_ok()
            && http(admin_addr, "GET /ready HTTP/1.1", "").starts_with("HTTP/1.1 200")
            && TcpStream::connect_timeout(&listen_addr, Duration::from_millis(200)).is_ok()
        {
            break;
        }
        assert!(Instant::now() < deadline, "llm-proxy did not become ready");
        std::thread::sleep(Duration::from_millis(100));
    }

    let response = http(
        listen_addr,
        &format!(
            "POST /v1/chat/completions HTTP/1.1\r\nauthorization: Bearer {key}\r\ncontent-type: application/json"
        ),
        r#"{"model":"llama3.1:8b","messages":[{"role":"user","content":"hi"}]}"#,
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 1);

    drop(_serving);
    std::fs::remove_dir_all(dir).unwrap();
}
