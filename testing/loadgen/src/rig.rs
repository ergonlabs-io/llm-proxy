//! Honesty guard: before driving any load, work out how much concurrency
//! *this box* can plausibly support, so a run that hits the rig's own
//! ceiling (fd limit, ephemeral port exhaustion) is self-evident instead of
//! being misread as the proxy's ceiling.
//!
//! The environment this was designed against (see the crate's task brief):
//! 8 cores / 16 GB, ephemeral range 49152-65535 (16,384 ports), `somaxconn`
//! 128. With connect-per-stream on both hops, a single-box run (loadgen ->
//! proxy -> mock) burns two ephemeral ports per logical stream, so port
//! space -- not fds or CPU -- caps out first, around ~8k concurrent streams.
//! Against a pooled (HTTP/2) upstream the proxy->mock hop is nearly free of
//! new ports, so the honest divisor there is 1, not 2 -- see
//! `RigInfo::sockets_per_stream`.
//!
//! Both budgets below describe *this process* (loadgen) alone. `fd_budget`
//! in particular must not be halved to "account for the proxy": the proxy is
//! a separate process with its own independent `RLIMIT_NOFILE` that this
//! crate cannot read from here and does not try to -- it is instead
//! *observed*, directly, by `sampler.rs` sampling the `--sweep-pid` process's
//! own open-fd count (`peak_fds` in `SamplerSummary`) during a sweep. Baking
//! a guess about the proxy's fd pressure into loadgen's own budget would
//! just be a second, worse guess sitting next to a real measurement.
//!
//! **Concurrency is not the only axis a rig can run out of.**
//! `estimated_max_concurrency` above bounds how many streams can be held
//! open *at once*; it says nothing about how fast new connections can be
//! opened and torn down. Those only coincide when responses are slow enough
//! that few connects happen per second. loadgen is deliberately
//! connect-per-stream (see `driver.rs`'s module doc, no connection reuse),
//! so against a fast upstream the CHURN rate -- connects/sec -- can exhaust
//! the ephemeral port range long before concurrency does: a closed socket's
//! port sits in `TIME_WAIT` for a while before the OS will reuse it, so the
//! sustainable churn rate is bounded by `port range / TIME_WAIT`, not by
//! concurrency at all. This was found the hard way: an upstream answering in
//! 0.1ms drove ~5,800 connects/sec at concurrency ONE, against a box that
//! sustains ~546/sec (16,383 ephemeral ports over a 30s `TIME_WAIT`, macOS
//! `net.inet.tcp.msl=15000`ms) -- a 10.6x overload that the
//! concurrency-only guard could not see, because concurrency never got
//! above 1. `connect_rate_budget` below is the missing axis.

use std::time::Duration;

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
    /// How many ephemeral ports one logical stream is assumed to burn,
    /// end to end. `2` is connect-per-stream on both hops (loadgen->proxy,
    /// proxy->upstream) -- the correct assumption for an HTTP/1.1 upstream
    /// with no connection reuse, and the default so every existing
    /// invocation keeps its current behavior. `1` is the honest number once
    /// the upstream hop is pooled: `crates/proxy-http/src/upstream_pool.rs`
    /// keeps one connection per (cluster, address, protocol) and multiplexes
    /// every concurrent stream over it for an HTTP/2 upstream, so that hop
    /// costs approximately zero new ports per stream and only the
    /// loadgen->proxy hop remains. Set via `--rig-sockets-per-stream`.
    pub sockets_per_stream: u64,
    /// Streams the ephemeral port range alone could sustain:
    /// `range / sockets_per_stream`.
    pub port_budget: u64,
    /// Streams the fd soft limit alone could sustain, if the limit could be
    /// read (`None` otherwise -- never a fabricated budget). This is
    /// loadgen's OWN fd budget (one fd per in-flight stream, its client
    /// socket to the proxy) -- not an estimate of the proxy's, which is a
    /// different process's rlimit; see the module doc.
    pub fd_budget: Option<u64>,
    /// Rough ceiling on concurrent streams *this rig* can sustain, ignoring
    /// the proxy/target entirely: `min(fd_budget, port_budget)`.
    pub estimated_max_concurrency: u64,
    /// How long a closed socket holds its local port in `TIME_WAIT` before
    /// the OS allows reuse. Read from the OS where possible
    /// (`net.inet.tcp.msl` on macOS -- which is HALF of `TIME_WAIT`, hence
    /// the 2x in `time_wait_duration` -- or `/proc/sys/net/ipv4/tcp_fin_timeout`
    /// as a rough Linux analogue; see that function's doc for why it's only
    /// a rough one) and falling back to a documented constant otherwise --
    /// see `time_wait_is_measured`, following the same pattern as
    /// `ephemeral_port_range_is_measured` above.
    pub time_wait: Duration,
    pub time_wait_is_measured: bool,
    /// Sustainable steady-state CONNECT rate (connects/sec) this rig's
    /// ephemeral port range can support: `port range width / time_wait`.
    /// This is the CHURN axis, distinct from `estimated_max_concurrency` --
    /// see the module doc for why they only coincide when responses are
    /// slow, and for the 10.6x overload this axis exists to catch.
    pub connect_rate_budget: f64,
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
/// Connect-per-stream on both hops -- the default so every existing
/// invocation of `--rig-sockets-per-stream` keeps its current behavior
/// exactly. See `RigInfo::sockets_per_stream`.
pub const DEFAULT_SOCKETS_PER_STREAM: u64 = 2;
/// Used when the OS's `TIME_WAIT` duration can't be read (see
/// `time_wait_duration`) -- 60s is the classic BSD/Linux default
/// (`2*MSL` with the historical 30s MSL) and Linux hardcodes exactly this
/// value with no runtime knob to read it back from, so it's the least
/// surprising fallback across platforms. Never presented as measured --
/// see `RigInfo::time_wait_is_measured`.
const FALLBACK_TIME_WAIT: Duration = Duration::from_secs(60);

/// `sockets_per_stream` is the caller's assumption about how many ephemeral
/// ports one logical stream burns end to end -- see `RigInfo::sockets_per_stream`
/// for what `1` vs `2` mean. Callers that don't care (tests, anything not
/// touching `port_budget`) can pass the crate's own default,
/// [`DEFAULT_SOCKETS_PER_STREAM`].
pub fn detect(sockets_per_stream: u64) -> RigInfo {
    let fd_soft_limit = fd_soft_limit();
    let (ephemeral_port_range, ephemeral_port_range_is_measured) = ephemeral_port_range()
        .map(|r| (r, true))
        .unwrap_or((FALLBACK_EPHEMERAL_RANGE, false));
    let somaxconn = somaxconn();
    let (time_wait, time_wait_is_measured) = time_wait_duration()
        .map(|d| (d, true))
        .unwrap_or((FALLBACK_TIME_WAIT, false));

    let port_range = ephemeral_port_range.1 as u64 - ephemeral_port_range.0 as u64;
    let port_budget = port_range.div_ceil(sockets_per_stream.max(1));
    // Rust note: no `/ 2` here -- `fd_soft_limit` is *this process's* rlimit
    // (loadgen holds exactly one fd per in-flight stream: its socket to the
    // proxy), so it isn't shared with anything else that needs dividing out.
    // See the module doc for why the proxy's own fd pressure belongs to
    // `sampler.rs`'s `peak_fds`, not a guess here.
    let fd_budget = fd_soft_limit.map(|limit| limit.saturating_sub(FD_RESERVE));
    let estimated_max_concurrency = match fd_budget {
        Some(fd_budget) => port_budget.min(fd_budget),
        None => port_budget,
    };
    // Rust note: the CHURN budget deliberately uses the raw port-range width,
    // not `port_budget` (which already divides by `sockets_per_stream`) --
    // see the module doc. It describes the box's own ephemeral-port supply,
    // a single shared OS resource, and the caller compares it against an
    // OBSERVED connects/sec that's already counted the same way (one
    // completed stream ~= one connect from loadgen's side; see
    // `harness_bound` and `report::build_capacity_report`).
    let connect_rate_budget = port_range as f64 / time_wait.as_secs_f64();

    RigInfo {
        fd_soft_limit,
        ephemeral_port_range,
        ephemeral_port_range_is_measured,
        somaxconn,
        sockets_per_stream,
        port_budget,
        fd_budget,
        estimated_max_concurrency,
        time_wait,
        time_wait_is_measured,
        connect_rate_budget,
    }
}

/// Log a one-line summary to stderr so it's visible without parsing the JSON
/// output -- this is meant to be read by a human before they trust a number.
pub fn log_summary(info: &RigInfo) {
    eprintln!(
        "rig: fd_soft_limit={} ephemeral_ports={}-{}{} somaxconn={} sockets_per_stream={} \
         (assumed ephemeral ports burned per logical stream; 2=connect-per-stream both hops, \
         1=pooled HTTP/2 upstream) -> estimated max concurrency this rig can sustain \
         (independent of the target under test): ~{}",
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
        info.sockets_per_stream,
        info.estimated_max_concurrency,
    );
    eprintln!(
        "rig: time_wait={:.1}s{} -> sustainable ephemeral-port CHURN rate (connects/sec, a \
         DIFFERENT axis from concurrency -- see rig.rs module doc): ~{:.0}/s",
        info.time_wait.as_secs_f64(),
        if info.time_wait_is_measured {
            ""
        } else {
            " (assumed, could not read OS TIME_WAIT)"
        },
        info.connect_rate_budget,
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
        "sockets_per_stream      = {}  (assumed ephemeral ports burned per logical stream: \
         2=connect-per-stream on both hops [HTTP/1.1 upstream, today's default], \
         1=proxy->upstream hop pools [HTTP/2 upstream reaching the connection cache] -- \
         set via --rig-sockets-per-stream)",
        info.sockets_per_stream
    );
    println!(
        "port_budget (streams)   = {}  (ephemeral range / sockets_per_stream)",
        info.port_budget
    );
    println!(
        "fd_budget (streams)     = {}  (this process's own fd limit -- the proxy's fd \
         pressure is a different process's rlimit; it is measured, not guessed, via \
         --sweep-pid sampling, see sampler.rs)",
        fmt_opt(info.fd_budget)
    );
    println!(
        "estimated_max_concurrency = {}  <- the ceiling THIS RIG imposes, independent of the \
         proxy under test; a sweep that terminates at or near this number is HARNESS-BOUND, \
         not a proxy capacity result",
        info.estimated_max_concurrency
    );
    println!(
        "time_wait               = {:.1}s{}  (how long a closed socket holds its port before \
         reuse; macOS reads 2x net.inet.tcp.msl, Linux reads tcp_fin_timeout as a rough \
         analogue, see rig.rs module doc)",
        info.time_wait.as_secs_f64(),
        if info.time_wait_is_measured {
            " (measured)"
        } else {
            " (assumed -- could not read the OS TIME_WAIT)"
        }
    );
    println!(
        "connect_rate_budget     = ~{:.0}/s  (sustainable CONNECT rate = ephemeral range width \
         / time_wait -- a DIFFERENT axis from estimated_max_concurrency above: loadgen is \
         connect-per-stream with no reuse, so a fast upstream can exhaust this budget through \
         port CHURN at concurrency as low as 1, well before concurrency itself is the \
         constraint)",
        info.connect_rate_budget
    );
}

fn fmt_opt(v: Option<u64>) -> String {
    v.map(|v| v.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// If a sweep's furthest-reached concurrency landed at or within
/// `slack_percent` of a harness ceiling, name which ceiling -- so a report
/// never presents a harness limit as a proxy capacity result (see the
/// module doc).
///
/// `peak_connect_rate` is the highest observed connects/sec across the
/// sweep's levels (see `report::build_capacity_report`, which derives it
/// from completed streams over elapsed time -- loadgen is
/// connect-per-stream, so that's a direct connect-rate measurement, not an
/// estimate). The CHURN check runs first and independently of `reached`:
/// the whole point of this axis (see the module doc's 10.6x incident) is
/// that a run can be badly churn-bound while `reached` still looks tiny --
/// checking concurrency first would misreport it as under-loaded or, worse,
/// silently let the concurrency checks below miss it entirely. Only once
/// churn is clear do the port/fd concurrency budgets get checked, tighter
/// one first, since that's the one that would actually have been hit.
pub fn harness_bound(
    reached: usize,
    peak_connect_rate: f64,
    rig: &RigInfo,
    slack_percent: u64,
) -> Option<HarnessBound> {
    if rig.connect_rate_budget > 0.0
        && peak_connect_rate * 100.0
            >= rig.connect_rate_budget * (100 - slack_percent.min(100)) as f64
    {
        return Some(HarnessBound {
            limit_name: "ephemeral port churn rate (connects/sec, TIME_WAIT-bound -- a \
                         different axis from concurrency, see rig.rs module doc)",
            // Rust note: `round()` before the `as u64` cast -- straight
            // truncation would always report a value at or below the true
            // budget, understating it by up to 1/sec for no reason.
            limit_value: rig.connect_rate_budget.round() as u64,
        });
    }

    let reached = reached as u64;
    let near =
        |limit: u64| limit > 0 && reached.saturating_mul(100) >= limit * (100 - slack_percent);

    let fd_budget = rig.fd_budget.unwrap_or(u64::MAX);
    if rig.port_budget <= fd_budget {
        if near(rig.port_budget) {
            // Rust note: `limit_name` is `&'static str`, so the label picks
            // between two pre-written strings by `sockets_per_stream` rather
            // than formatting the number in -- cheaper than a `String` and
            // there are only the two assumptions this crate models.
            let limit_name = if rig.sockets_per_stream <= 1 {
                "ephemeral port range (pooled upstream hop, ~1 port/stream)"
            } else {
                "ephemeral port range (connect-per-stream, ~2 ports/stream)"
            };
            return Some(HarnessBound {
                limit_name,
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

/// Best-effort OS lookup of how long a closed socket holds its local port in
/// `TIME_WAIT`. `None` (never a fabricated duration) if the lookup fails or
/// the platform isn't supported -- see `FALLBACK_TIME_WAIT`.
///
/// Neither platform exposes `TIME_WAIT` itself as a runtime-readable value,
/// so both readings here are indirect:
/// - **macOS**: `net.inet.tcp.msl` is the Maximum Segment Lifetime in
///   milliseconds, and the BSD network stack defines `TIME_WAIT` as exactly
///   `2*MSL` -- so this doubles the sysctl value. This one is exact, not an
///   approximation.
/// - **Linux**: the kernel hardcodes `TIME_WAIT` at 60s (`2*MSL` with the
///   historical 30s MSL) and does not expose a knob for it at all.
///   `/proc/sys/net/ipv4/tcp_fin_timeout` is a DIFFERENT timer (how long a
///   locally-initiated close waits in `FIN_WAIT_2` for the peer's FIN) that
///   happens to be readable and roughly the same order of magnitude, so it's
///   used here as a documented rough analogue rather than leaving Linux with
///   no OS signal at all -- callers should not treat it as exact.
fn time_wait_duration() -> Option<Duration> {
    #[cfg(target_os = "linux")]
    {
        let secs: u64 = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_fin_timeout")
            .ok()?
            .trim()
            .parse()
            .ok()?;
        return Some(Duration::from_secs(secs));
    }
    #[cfg(target_os = "macos")]
    {
        let msl_ms = sysctl_u64("net.inet.tcp.msl")?;
        return Some(Duration::from_millis(msl_ms.saturating_mul(2)));
    }
    #[allow(unreachable_code)]
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_a_nonzero_estimate() {
        let info = detect(DEFAULT_SOCKETS_PER_STREAM);
        assert!(info.estimated_max_concurrency > 0);
        assert!(info.ephemeral_port_range.1 > info.ephemeral_port_range.0);
    }

    #[test]
    fn detect_computes_a_nonzero_connect_rate_budget_from_the_port_range_and_time_wait() {
        let info = detect(DEFAULT_SOCKETS_PER_STREAM);
        assert!(info.time_wait > Duration::ZERO);
        assert!(info.connect_rate_budget > 0.0);
        let port_range =
            (info.ephemeral_port_range.1 as u64 - info.ephemeral_port_range.0 as u64) as f64;
        let expected = port_range / info.time_wait.as_secs_f64();
        assert!(
            (info.connect_rate_budget - expected).abs() < 1e-6,
            "expected connect_rate_budget {} to equal port_range/time_wait {}",
            info.connect_rate_budget,
            expected
        );
    }

    #[test]
    fn fd_budget_no_longer_halves_the_soft_limit() {
        // Defect 1: `fd_budget` used to be `(limit - reserve) / 2`, modelling
        // a second process's descriptors that this crate can't read. It must
        // now be exactly `limit - reserve` -- loadgen holds one fd per
        // in-flight stream, nothing to divide out.
        let info = detect(DEFAULT_SOCKETS_PER_STREAM);
        if let (Some(soft_limit), Some(fd_budget)) = (info.fd_soft_limit, info.fd_budget) {
            assert_eq!(fd_budget, soft_limit.saturating_sub(FD_RESERVE));
        }
    }

    #[test]
    fn port_budget_halves_with_two_sockets_per_stream_and_matches_the_range_with_one() {
        // Defect 2: the divisor must come from `sockets_per_stream`, not a
        // hardcoded `2`.
        let info_pooled = detect(1);
        let info_unpooled = detect(2);
        let range = (info_pooled.ephemeral_port_range.1 as u64
            - info_pooled.ephemeral_port_range.0 as u64)
            .div_ceil(1);
        assert_eq!(info_pooled.port_budget, range);
        assert_eq!(info_unpooled.port_budget, range.div_ceil(2));
        assert_eq!(info_pooled.sockets_per_stream, 1);
        assert_eq!(info_unpooled.sockets_per_stream, 2);
    }

    fn info_with_budgets(port_budget: u64, fd_budget: Option<u64>) -> RigInfo {
        RigInfo {
            fd_soft_limit: fd_budget.map(|b| b + FD_RESERVE),
            ephemeral_port_range: FALLBACK_EPHEMERAL_RANGE,
            ephemeral_port_range_is_measured: false,
            somaxconn: None,
            sockets_per_stream: DEFAULT_SOCKETS_PER_STREAM,
            port_budget,
            fd_budget,
            estimated_max_concurrency: fd_budget.unwrap_or(port_budget).min(port_budget),
            time_wait: FALLBACK_TIME_WAIT,
            time_wait_is_measured: false,
            // 0.0 means "no churn budget configured" -- `harness_bound`'s
            // churn check is a no-op, so these concurrency-only tests below
            // aren't affected by the new axis.
            connect_rate_budget: 0.0,
        }
    }

    #[test]
    fn harness_bound_names_the_tighter_of_port_and_fd_budget() {
        let info = info_with_budgets(100, Some(1_000));
        // Reached 95/100 of the (tighter) port budget -> port-bound.
        let bound = harness_bound(95, 0.0, &info, 10).expect("should be harness-bound");
        assert!(bound.limit_name.contains("ephemeral port"));
        assert_eq!(bound.limit_value, 100);

        let info = info_with_budgets(1_000, Some(100));
        // Reached 95/100 of the (tighter) fd budget -> fd-bound.
        let bound = harness_bound(95, 0.0, &info, 10).expect("should be harness-bound");
        assert!(bound.limit_name.contains("file-descriptor"));
        assert_eq!(bound.limit_value, 100);
    }

    /// Defect 2: the churn-rate axis. A run that never reaches meaningful
    /// CONCURRENCY (`reached` stays tiny) but drives an observed connect
    /// rate past what the ephemeral-port/TIME_WAIT budget can sustain must
    /// be reported as churn-bound, naming the churn limit -- not silently
    /// passed through the concurrency-only checks, and not mislabeled as a
    /// concurrency bound. Numbers match the real incident recorded in the
    /// module doc: 16,383 ports / 30s TIME_WAIT =~ 546/s budget, observed
    /// ~5,800/s at concurrency 1.
    #[test]
    fn harness_bound_names_the_churn_rate_limit_even_when_concurrency_reached_is_tiny() {
        let mut info = info_with_budgets(8_000, Some(500_000));
        info.time_wait = Duration::from_secs(30);
        info.connect_rate_budget = 16_383.0 / 30.0; // ~546.1/s

        let bound = harness_bound(1, 5_800.0, &info, 10).expect("should be churn-bound");
        assert!(
            bound.limit_name.contains("churn"),
            "expected the churn-rate limit to be named, got {:?}",
            bound.limit_name
        );
        assert_eq!(bound.limit_value, 546);
    }

    #[test]
    fn harness_bound_is_not_churn_bound_when_observed_rate_is_well_under_the_budget() {
        let mut info = info_with_budgets(8_000, Some(500_000));
        info.time_wait = Duration::from_secs(30);
        info.connect_rate_budget = 16_383.0 / 30.0; // ~546.1/s

        // Observed rate well clear of the budget, and concurrency well
        // clear of its own budgets too -> no bound at all.
        assert!(harness_bound(1, 50.0, &info, 10).is_none());
    }

    #[test]
    fn harness_bound_prefers_churn_over_concurrency_when_both_are_in_view() {
        // Concurrency `reached` is ALSO near its own port budget here, so
        // this proves churn is checked (and reported) ahead of it, not that
        // concurrency merely stayed clear.
        let mut info = info_with_budgets(100, Some(1_000));
        info.connect_rate_budget = 546.0;
        let bound = harness_bound(95, 600.0, &info, 10).expect("should be harness-bound");
        assert!(bound.limit_name.contains("churn"));
    }

    #[test]
    fn harness_bound_is_none_when_reached_is_well_under_every_budget() {
        let info = info_with_budgets(10_000, Some(10_000));
        assert!(harness_bound(50, 0.0, &info, 10).is_none());
    }
}
