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
    /// The kernel's listen backlog ceiling (`somaxconn`), if it could be
    /// read. Bounds burst *connection setup* rate, not steady-state
    /// concurrency, but a sweep that fails immediately at low concurrency
    /// with connection-refused errors should have this in view.
    pub somaxconn: Option<u64>,
    /// Streams the ephemeral port range alone could sustain: two ephemeral
    /// ports are consumed per logical stream on a single-box run
    /// (loadgen->proxy, proxy->mock with no upstream connection reuse), so
    /// this is `range / 2`.
    pub port_budget: u64,
    /// Streams the fd soft limit alone could sustain, if the limit could be
    /// read (`None` otherwise -- never a fabricated budget).
    pub fd_budget: Option<u64>,
    /// Rough ceiling on concurrent streams *this rig* can sustain, ignoring
    /// the proxy/target entirely: `min(fd_budget, port_budget)`.
    pub estimated_max_concurrency: u64,
}

/// Which harness ceiling a sweep landed on, if any -- see [`harness_bound`].
#[derive(Debug, Clone, Serialize)]
pub struct HarnessBound {
    pub limit_name: &'static str,
    pub limit_value: u64,
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
    let somaxconn = somaxconn();

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
        somaxconn,
        port_budget,
        fd_budget,
        estimated_max_concurrency,
    }
}

/// Log a one-line summary to stderr so it's visible without parsing the JSON
/// output -- this is meant to be read by a human before they trust a number.
pub fn log_summary(info: &RigInfo) {
    eprintln!(
        "rig: fd_soft_limit={} ephemeral_ports={}-{}{} somaxconn={} -> estimated max \
         concurrency this rig can sustain (independent of the target under test): ~{}",
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
        info.somaxconn
            .map(|l| l.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        info.estimated_max_concurrency,
    );
}

/// Print the full self-check report (`loadgen --self-check`): every limit
/// this crate could detect, plus the theoretical max concurrency they
/// imply, so a user can sanity-check the box before a long sweep.
pub fn print_self_check(info: &RigInfo) {
    println!("=== loadgen rig self-check ===");
    println!("fd_soft_limit          = {}", fmt_opt(info.fd_soft_limit));
    println!(
        "ephemeral_port_range    = {}-{}{}",
        info.ephemeral_port_range.0,
        info.ephemeral_port_range.1,
        if info.ephemeral_port_range_is_measured {
            " (measured)"
        } else {
            " (assumed IANA default -- could not read the OS range)"
        }
    );
    println!("somaxconn               = {}", fmt_opt(info.somaxconn));
    println!(
        "port_budget (streams)   = {}  (connect-per-stream burns ~2 ports/stream)",
        info.port_budget
    );
    println!("fd_budget (streams)     = {}", fmt_opt(info.fd_budget));
    println!(
        "estimated_max_concurrency = {}  <- the ceiling THIS RIG imposes, independent of the \
         proxy under test; a sweep that terminates at or near this number is HARNESS-BOUND, \
         not a proxy capacity result",
        info.estimated_max_concurrency
    );
}

fn fmt_opt(v: Option<u64>) -> String {
    v.map(|v| v.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// If a sweep's furthest-reached concurrency landed at or within
/// `slack_percent` of a harness ceiling, name which ceiling -- so a report
/// never presents a harness limit as a proxy capacity result (see the
/// module doc). Checks whichever of the port/fd budgets is *tighter*
/// first, since that's the one that would actually have been hit.
pub fn harness_bound(reached: usize, rig: &RigInfo, slack_percent: u64) -> Option<HarnessBound> {
    let reached = reached as u64;
    let near =
        |limit: u64| limit > 0 && reached.saturating_mul(100) >= limit * (100 - slack_percent);

    let fd_budget = rig.fd_budget.unwrap_or(u64::MAX);
    if rig.port_budget <= fd_budget {
        if near(rig.port_budget) {
            return Some(HarnessBound {
                limit_name: "ephemeral port range (connect-per-stream, ~2 ports/stream)",
                limit_value: rig.port_budget,
            });
        }
    } else if let Some(fd_budget) = rig.fd_budget {
        if near(fd_budget) {
            return Some(HarnessBound {
                limit_name: "open-file-descriptor soft limit",
                limit_value: fd_budget,
            });
        }
    }
    None
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
    sysctl_value(name)
}

#[cfg(target_os = "macos")]
fn sysctl_u64(name: &str) -> Option<u64> {
    sysctl_value(name)
}

#[cfg(target_os = "macos")]
fn sysctl_value<T: std::str::FromStr>(name: &str) -> Option<T> {
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

/// Best-effort lookup of the kernel's listen backlog ceiling (`somaxconn`).
/// Linux exposes it as a plain integer in a procfs file; macOS via a
/// `sysctl` key. `None` (never a fabricated number) if the lookup fails or
/// the platform isn't supported.
fn somaxconn() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_to_string("/proc/sys/net/core/somaxconn")
            .ok()
            .and_then(|s| s.trim().parse().ok());
    }
    #[cfg(target_os = "macos")]
    {
        return sysctl_u64("kern.ipc.somaxconn");
    }
    #[allow(unreachable_code)]
    None
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

    fn info_with_budgets(port_budget: u64, fd_budget: Option<u64>) -> RigInfo {
        RigInfo {
            fd_soft_limit: fd_budget.map(|b| b * 2 + FD_RESERVE),
            ephemeral_port_range: FALLBACK_EPHEMERAL_RANGE,
            ephemeral_port_range_is_measured: false,
            somaxconn: None,
            port_budget,
            fd_budget,
            estimated_max_concurrency: fd_budget.unwrap_or(port_budget).min(port_budget),
        }
    }

    #[test]
    fn harness_bound_names_the_tighter_of_port_and_fd_budget() {
        let info = info_with_budgets(100, Some(1_000));
        // Reached 95/100 of the (tighter) port budget -> port-bound.
        let bound = harness_bound(95, &info, 10).expect("should be harness-bound");
        assert!(bound.limit_name.contains("ephemeral port"));
        assert_eq!(bound.limit_value, 100);

        let info = info_with_budgets(1_000, Some(100));
        // Reached 95/100 of the (tighter) fd budget -> fd-bound.
        let bound = harness_bound(95, &info, 10).expect("should be harness-bound");
        assert!(bound.limit_name.contains("file-descriptor"));
        assert_eq!(bound.limit_value, 100);
    }

    #[test]
    fn harness_bound_is_none_when_reached_is_well_under_every_budget() {
        let info = info_with_budgets(10_000, Some(10_000));
        assert!(harness_bound(50, &info, 10).is_none());
    }
}
