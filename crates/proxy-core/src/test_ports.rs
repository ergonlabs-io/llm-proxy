//! Test-only port picker, shared by the in-crate listener tests and, via
//! `#[path]`, by `tests/upstream_tls.rs`.

/// A loopback port that is free now, for a test to name before a listener
/// binds it.
///
/// The port comes from 20000-32767, below the kernel's ephemeral range
/// (Linux 32768-60999, macOS 49152-65535). A port from bind-to-0 is in that
/// range, so between the probe and the listener's bind any outgoing connection
/// (the test's own, or the proxy's to a mock upstream) can take it as its
/// source port, and the bind fails with "Address already in use". Ports
/// below the range are never handed out that way. The start point varies by
/// process and call so parallel test binaries spread out; a port another
/// process holds fails the probe and the next one is tried.
///
/// The probe alone leaves a window: it closes its socket, and until the
/// listener binds, another test process can probe the same port, name it in
/// its own config, and lose the bind. So each port is first claimed with a
/// lock on a per-port file (see [`claim`]), held until this process exits.
/// Every test process on the machine goes through the same lock directory,
/// so no two of them hand out the same port while either is alive.
///
/// The single copy: `crates/proxy-core/tests/upstream_tls.rs`,
/// `crates/proxy/tests/common/mod.rs` and `testing/diffrig/src/harness.rs`
/// include this file with `#[path]`.
pub fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU32, Ordering};
    const LOW: u32 = 20_000;
    const SPAN: u32 = 32_768 - LOW;
    static CALLS: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let call = CALLS.fetch_add(1, Ordering::Relaxed);
    let start = std::process::id()
        .wrapping_mul(7919)
        .wrapping_add(nanos)
        .wrapping_add(call.wrapping_mul(104_729));
    for step in 0..SPAN {
        let port = (LOW + (start.wrapping_add(step) % SPAN)) as u16;
        if claim(port) && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free loopback port in {LOW}-32767");
}

/// Claim `port` for this process: take a non-blocking exclusive lock on
/// `<temp dir>/llm-proxy-test-ports/<port>` and keep the file open until the
/// process exits, when the OS drops the lock. A lock another process holds,
/// or this one already holds through an earlier claim, refuses the claim.
///
/// A lock directory that cannot be used claims every port, which falls back
/// to the probe alone rather than failing the test over a temp-dir problem.
fn claim(port: u16) -> bool {
    use std::fs::{File, OpenOptions};
    use std::sync::{Mutex, PoisonError};
    static HELD: Mutex<Vec<File>> = Mutex::new(Vec::new());

    let dir = std::env::temp_dir().join("llm-proxy-test-ports");
    if std::fs::create_dir_all(&dir).is_err() {
        return true;
    }
    let Ok(file) = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join(port.to_string()))
    else {
        return true;
    };
    if file.try_lock().is_err() {
        return false;
    }
    HELD.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(file);
    true
}
