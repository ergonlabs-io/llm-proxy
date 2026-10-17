//! The billing ledger (ADR-0009) in the real binary: a dialect `ledger`
//! block opens the writer at boot, served requests reach the encrypted spool,
//! shutdown commits what is queued, a restart opens a later epoch, and the
//! things that must stop the proxy do. Admission and the writer themselves
//! are tested in `proxy-core` and `proxy-observability`.

use proxy_observability::ledger::testing::{committed_entries, TempLedgerDir};
use proxy_observability::ledger::{LedgerConfig, OnUnavailable};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const NODE: &str = "ledger-e2e-node";

#[test]
fn served_requests_are_committed_and_a_restart_opens_a_later_epoch() {
    let dir = TempLedgerDir::new();
    let ledger = dir.config(1024, OnUnavailable::Reject);
    let upstream = mock_upstream();
    let config = config_text(&ledger, upstream, "");

    let mut proxy = Proxy::start(dir.root.path(), &config, Some(NODE));
    for _ in 0..2 {
        assert!(proxy.chat().starts_with("HTTP/1.1 200"));
    }
    proxy.terminate();
    let first = committed_entries(&ledger, NODE);
    assert_eq!(
        first.iter().map(|e| e.seq).collect::<Vec<_>>(),
        [0, 1],
        "shutdown commits every entry handed over"
    );
    assert!(first.iter().all(|e| e.instance_id == NODE));

    let mut proxy = Proxy::start(dir.root.path(), &config, Some(NODE));
    assert!(proxy.chat().starts_with("HTTP/1.1 200"));
    proxy.terminate();
    let all = committed_entries(&ledger, NODE);
    assert_eq!(all.len(), 3);
    assert_eq!(all[2].seq, 0);
    assert!(all[2].epoch > all[0].epoch, "{all:?}");
}

/// The instance id is the node id; without one the proxy refuses to start
/// rather than writing under a per-boot identity.
#[test]
fn a_ledger_without_a_node_id_stops_startup() {
    let dir = TempLedgerDir::new();
    let ledger = dir.config(1024, OnUnavailable::Reject);
    let config = config_text(&ledger, mock_upstream(), "");
    let stderr = Proxy::fails(dir.root.path(), &config, None);
    assert!(
        stderr.contains("node.metadata[\"io.llmproxy.ledger\"]")
            && stderr.contains("requires a configured node id"),
        "{stderr}"
    );
}

/// A key file the proxy cannot use stops startup with the field's path.
#[test]
fn a_missing_key_file_stops_startup_naming_the_field() {
    let dir = TempLedgerDir::new();
    let ledger = dir.config(1024, OnUnavailable::Reject);
    std::fs::remove_file(&ledger.encryption_key.file).unwrap();
    let config = config_text(&ledger, mock_upstream(), "");
    let stderr = Proxy::fails(dir.root.path(), &config, Some(NODE));
    assert!(
        stderr.contains("node.metadata[\"io.llmproxy.ledger\"].encryption_key_file"),
        "{stderr}"
    );
}

/// The writer is opened once at boot, so a reload that changes the ledger is
/// refused whole, loudly, and the proxy keeps serving with the old ledger.
#[test]
fn a_reload_that_changes_the_ledger_is_refused() {
    let dir = TempLedgerDir::new();
    let ledger = dir.config(1024, OnUnavailable::Reject);
    let upstream = mock_upstream();
    let config = config_text(&ledger, upstream, "");
    let mut proxy = Proxy::start(dir.root.path(), &config, Some(NODE));
    let changed = config.replace("on_unavailable: reject", "on_unavailable: admit");
    assert_ne!(changed, config);
    std::fs::write(dir.root.path().join("llmproxy.yaml"), changed).unwrap();
    proxy.sighup();
    proxy.wait_for_log("cannot change on reload");
    assert!(proxy.chat().starts_with("HTTP/1.1 200"));
    proxy.terminate();
    assert_eq!(committed_entries(&ledger, NODE).len(), 1);
}

// ------------------------------------------------------------------ helpers --

fn config_text(ledger: &LedgerConfig, upstream: SocketAddr, extra: &str) -> String {
    format!(
        r#"version: 0
listen: 127.0.0.1:{listen}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
routes:
  - {{ model: "*", provider: openai }}
ledger:
  directory: {directory}
  encryption_key_file: {key}
  encryption_key_id: {key_id}
  max_disk_bytes: {disk}
  group_commit_interval: 10ms
  on_unavailable: reject
{extra}"#,
        listen = free_port(),
        directory = ledger.directory.display(),
        key = ledger.encryption_key.file.display(),
        key_id = ledger.encryption_key.id,
        disk = ledger.max_disk_bytes,
    )
}

/// A running proxy, killed and reaped on drop so a failed assertion cannot
/// leave a listener behind (AGENTS.md "Running The Product").
struct Proxy {
    child: Child,
    listen: SocketAddr,
    stderr: std::path::PathBuf,
}

impl Proxy {
    fn spawn(dir: &Path, config: &str, node: Option<&str>) -> (Child, std::path::PathBuf) {
        let path = dir.join("llmproxy.yaml");
        std::fs::write(&path, config).unwrap();
        let stderr = dir.join(format!("stderr-{}.log", free_port()));
        let mut command = Command::new(BIN);
        command
            .args(["--config", path.to_str().unwrap(), "--concurrency", "1"])
            .args(["--drain-time-s", "1"])
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&stderr).unwrap());
        if let Some(node) = node {
            command.args(["--service-node", node]);
        }
        (command.spawn().expect("spawn llm-proxy"), stderr)
    }

    fn start(dir: &Path, config: &str, node: Option<&str>) -> Proxy {
        let listen: u16 = config
            .split("listen: 127.0.0.1:")
            .nth(1)
            .and_then(|r| r.lines().next())
            .and_then(|p| p.trim().parse().ok())
            .unwrap();
        let (child, stderr) = Self::spawn(dir, config, node);
        let proxy = Proxy {
            child,
            listen: SocketAddr::from(([127, 0, 0, 1], listen)),
            stderr,
        };
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        while TcpStream::connect(proxy.listen).is_err() {
            assert!(
                Instant::now() < deadline,
                "proxy did not start:\n{}",
                proxy.log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        proxy
    }

    /// Runs a proxy that must exit non-zero on its own; returns its stderr.
    fn fails(dir: &Path, config: &str, node: Option<&str>) -> String {
        let (mut child, stderr) = Self::spawn(dir, config, node);
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the proxy kept running");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(!status.success());
        std::fs::read_to_string(stderr).unwrap()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    fn wait_for_log(&self, needle: &str) {
        let deadline = Instant::now() + IO_TIMEOUT;
        while !self.log().contains(needle) {
            assert!(
                Instant::now() < deadline,
                "no `{needle}` in:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .args([name, &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn sighup(&self) {
        self.signal("-HUP");
    }

    /// SIGTERM and wait for a clean exit, so the writer's shutdown ran.
    fn terminate(&mut self) {
        self.signal("-TERM");
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "exit {status}:\n{}", self.log());
                return;
            }
            assert!(Instant::now() < deadline, "did not exit:\n{}", self.log());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn chat(&self) -> String {
        let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
        let mut stream = TcpStream::connect(self.listen).unwrap();
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream
            .write_all(
                format!(
                    "POST /v1/chat/completions HTTP/1.1\r\nHost: proxy.local\r\n\
                     Content-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .unwrap();
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        String::from_utf8_lossy(&response).into_owned()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An OpenAI-shaped upstream on a std thread that answers every request.
fn mock_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
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
                let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
                let length: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut have = raw.len() - (head_end + 4);
                while have < length {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => have += n,
                    }
                }
                let body = r#"{"id":"x","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":6,"completion_tokens":4,"total_tokens":10}}"#;
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            });
        }
    });
    addr
}
