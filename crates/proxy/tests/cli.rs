//! Integration tests for the `llm-proxy` binary's CLI surface (WP-06 chunk C):
//! `--mode validate` exit codes and the SIGTERM drain-then-exit sequence.
//!
//! Rust note: `env!("CARGO_BIN_EXE_llm-proxy")` is filled in by cargo at build
//! time for integration tests (anything under `tests/`) -- it expands to the
//! absolute path of the `llm-proxy` binary this crate produces, so we don't
//! have to guess `target/debug/...` ourselves.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

fn repo_root() -> std::path::PathBuf {
    // `tests/` runs with CARGO_MANIFEST_DIR = crates/proxy.
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn validate_exits_zero_for_a_good_config() {
    let config = repo_root().join("examples/tcp-proxy.yaml");
    let status = Command::new(BIN)
        .args(["-c", config.to_str().unwrap(), "--mode", "validate"])
        .status()
        .expect("failed to run llm-proxy");
    assert!(status.success(), "expected exit 0, got {status:?}");
}

#[test]
fn validate_exits_nonzero_for_a_bad_config() {
    let dir = std::env::temp_dir();
    let bad_path = dir.join(format!("llm-proxy-bad-config-{}.yaml", std::process::id()));
    std::fs::write(&bad_path, "not: valid: yaml: [").expect("failed to write temp config");

    let status = Command::new(BIN)
        .args(["-c", bad_path.to_str().unwrap(), "--mode", "validate"])
        .status()
        .expect("failed to run llm-proxy");

    let _ = std::fs::remove_file(&bad_path);
    assert!(!status.success(), "expected a nonzero exit, got {status:?}");
}

/// Waits (with a timeout) for a line matching `needle` to appear on `reader`,
/// returning `true` if found.
///
/// Rust note: `BufReader::read_line` blocks, so we drive it from a helper
/// thread and hand lines back over an `mpsc` channel; `recv_timeout` on the
/// receiving end gives us the actual timeout without any blind `sleep`.
fn wait_for_line(
    mut reader: BufReader<impl std::io::Read + Send + 'static>,
    needle: &str,
    timeout: Duration,
) -> bool {
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

    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match rx.recv_timeout(remaining) {
            Ok(line) if line.contains(needle) => return true,
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
}

#[test]
fn sigterm_drains_then_exits_cleanly() {
    let config = repo_root().join("examples/tcp-proxy.yaml");
    let mut child = Command::new(BIN)
        .args([
            "-c",
            config.to_str().unwrap(),
            "--concurrency",
            "2",
            "--drain-time-s",
            "1",
        ])
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn llm-proxy");

    let stderr = child.stderr.take().expect("child stderr not piped");
    let found = wait_for_line(
        BufReader::new(stderr),
        "llm-proxy started",
        Duration::from_secs(5),
    );
    assert!(found, "startup line did not appear on stderr in time");

    // `Child::kill` sends SIGKILL, not SIGTERM -- shell out to `kill -TERM`
    // to exercise the actual signal our graceful-shutdown path listens for.
    let pid = child.id().to_string();
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(&pid)
        .status()
        .expect("failed to send SIGTERM");
    assert!(status.success(), "kill -TERM failed");

    let exit = child
        .wait_timeout_or_kill(Duration::from_secs(5))
        .expect("llm-proxy did not exit after SIGTERM within timeout");
    assert!(
        exit.success(),
        "expected exit 0 after SIGTERM, got {exit:?}"
    );
}

/// Small helper: `std::process::Child` has no built-in "wait with timeout",
/// so poll `try_wait` instead of pulling in an extra crate for one test.
trait WaitTimeoutOrKill {
    fn wait_timeout_or_kill(&mut self, timeout: Duration) -> Option<std::process::ExitStatus>;
}

impl WaitTimeoutOrKill for std::process::Child {
    fn wait_timeout_or_kill(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Ok(Some(status)) = self.try_wait() {
                return Some(status);
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.kill();
                let _ = self.wait();
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
