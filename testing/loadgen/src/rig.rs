//! Honesty guard: before driving any load, work out how much concurrency
//! *this box* can plausibly support, so a run that hits the rig's own
//! ceiling (fd limit, ephemeral port exhaustion) is self-evident instead of
//! being misread as the proxy's ceiling.
//!
//! The environment this was designed against (see the crate's task brief):
//! 8 cores / 16 GB, ephemeral range 49152-65535 (16,384 ports), `somaxconn`
//! 128. With connect-per-stream, a single-box run (loadgen -> proxy -> mock)
//! burns two ephemeral ports per logical stream, so port space -- not fds or
//! CPU -- caps out first, around ~8k concurrent streams.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct RigInfo {
    /// Open-file-descriptor soft limit for this process, if it could be read.
    pub fd_soft_limit: Option<u64>,
    /// The OS's ephemeral (client-side auto-assigned) port range, if it
    /// could be read; falls back to the IANA-recommended range this crate
    /// was built against when the platform-specific lookup isn't available.
    pub ephemeral_port_range: (u16, u16),
    pub ephemeral_port_range_is_measured: bool,
    /// Rough ceiling on concurrent streams *this rig* can sustain, ignoring
    /// the proxy/target entirely: min(fd budget, port budget / 2). Two
    /// ephemeral ports are consumed per logical stream on a single-box run
    /// (loadgen->proxy, proxy->mock), so the port budget is halved.
    pub estimated_max_concurrency: u64,
}

const FALLBACK_EPHEMERAL_RANGE: (u16, u16) = (49152, 65535);
/// Leave headroom for stdio, the listening/admin sockets, and whatever else
/// the process already has open -- an estimate, not a hard guarantee.
const FD_RESERVE: u64 = 64;

pub fn detect() -> RigInfo {
    let fd_soft_limit = fd_soft_limit();
    let (ephemeral_port_range, ephemeral_port_range_is_measured) = ephemeral_port_range()
        .map(|r| (r, true))
        .unwrap_or((FALLBACK_EPHEMERAL_RANGE, false));

    let port_budget = (ephemeral_port_range.1 as u64 - ephemeral_port_range.0 as u64).div_ceil(2);
    let fd_budget = fd_soft_limit.map(|limit| limit.saturating_sub(FD_RESERVE) / 2);
    let estimated_max_concurrency = match fd_budget {
        Some(fd_budget) => port_budget.min(fd_budget),
        None => port_budget,
    };

    RigInfo {
        fd_soft_limit,
        ephemeral_port_range,
        ephemeral_port_range_is_measured,
        estimated_max_concurrency,
    }
}

/// Log a one-line summary to stderr so it's visible without parsing the JSON
/// output -- this is meant to be read by a human before they trust a number.
pub fn log_summary(info: &RigInfo) {
    eprintln!(
        "rig: fd_soft_limit={} ephemeral_ports={}-{}{} -> estimated max concurrency this rig \
         can sustain (independent of the target under test): ~{}",
        info.fd_soft_limit
            .map(|l| l.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        info.ephemeral_port_range.0,
        info.ephemeral_port_range.1,
        if info.ephemeral_port_range_is_measured {
            ""
        } else {
            " (assumed, could not read OS range)"
        },
        info.estimated_max_concurrency,
    );
}

fn fd_soft_limit() -> Option<u64> {
    // Rust note: `rlimit` wraps the OS's `getrlimit`/`setrlimit` behind a
    // safe API (its own crate carries the `unsafe` FFI call, not us -- our
    // workspace only denies `unsafe` in *our* code) so this stays free of
    // any `unsafe` block.
    rlimit::Resource::NOFILE.get_soft().ok()
}

/// Best-effort OS lookup of the ephemeral port range. Linux exposes it as
/// two whitespace-separated numbers in a procfs file; macOS exposes it via
/// two `sysctl` keys. Both are read without any dependency beyond `std`,
/// falling back to `None` (and the IANA default) anywhere else, or if the
/// lookup fails for any reason -- this is a best-effort log line, not load
/// bearing for the run itself.
fn ephemeral_port_range() -> Option<(u16, u16)> {
    #[cfg(target_os = "linux")]
    {
        let contents = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok()?;
        let mut parts = contents.split_whitespace();
        let low: u16 = parts.next()?.parse().ok()?;
        let high: u16 = parts.next()?.parse().ok()?;
        return Some((low, high));
    }
    #[cfg(target_os = "macos")]
    {
        let low = sysctl_u16("net.inet.ip.portrange.first")?;
        let high = sysctl_u16("net.inet.ip.portrange.last")?;
        return Some((low, high));
    }
    #[allow(unreachable_code)]
    None
}

#[cfg(target_os = "macos")]
fn sysctl_u16(name: &str) -> Option<u16> {
    let output = std::process::Command::new("sysctl")
        .arg("-n")
        .arg(name)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_a_nonzero_estimate() {
        let info = detect();
        assert!(info.estimated_max_concurrency > 0);
        assert!(info.ephemeral_port_range.1 > info.ephemeral_port_range.0);
    }
}
