//! Process resource sampler: samples RSS, cumulative CPU
//! time (converted to %-of-one-core), and open-fd count for a given PID at
//! a fixed interval, so a sweep can attribute capacity to a memory/CPU
//! budget instead of just a request count.
//!
//! Platform note: there is no portable way to read *another* process's
//! resource usage from safe Rust without pulling in a large external crate,
//! so both platforms below shell out to (macOS) `ps`/`lsof` or read (Linux)
//! `/proc/<pid>/...` directly -- neither needs `unsafe`, matching the
//! workspace's `unsafe`-denial rule. If a platform's sampling route is
//! unavailable, [`sample_once`] returns an `Err`; it never fabricates a
//! zero, which is the whole point of measuring this at all (see the crate's
//! task brief).

use std::time::{Duration, Instant};

use anyhow::Context;
use serde::Serialize;
use tokio::sync::oneshot;
use tokio::time::MissedTickBehavior;

/// One point-in-time reading of a process's resource usage.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ProcessSample {
    /// Milliseconds since sampling started (not a wall-clock timestamp --
    /// easier to reason about and to fabricate in tests).
    pub elapsed_ms: u64,
    pub rss_bytes: u64,
    /// Cumulative CPU time the process has consumed *since it started*, as
    /// of this sample -- not a per-interval figure. [`SampleSeries::summarize`]
    /// differences consecutive samples to turn this into %-of-a-core.
    pub cpu_time: Duration,
    pub fd_count: u64,
}

/// The raw platform-specific reading before it is stamped with `elapsed_ms`.
struct RawSample {
    rss_bytes: u64,
    cpu_time: Duration,
    fd_count: u64,
}

/// The full time series for one sampled run.
#[derive(Debug, Clone, Serialize)]
pub struct SampleSeries {
    pub samples: Vec<ProcessSample>,
}

/// Derived stats from a [`SampleSeries`]. CPU fields are `None` rather than
/// `0.0` when there weren't at least two samples to difference -- a lone
/// sample can't tell you a rate, and reporting `0%` in that case would look
/// like a real (idle) measurement instead of "we don't know".
#[derive(Debug, Clone, Serialize)]
pub struct SamplerSummary {
    pub sample_count: usize,
    pub peak_rss_bytes: u64,
    pub mean_cpu_percent: Option<f64>,
    pub peak_cpu_percent: Option<f64>,
    pub peak_fds: u64,
}

impl SampleSeries {
    /// Summarize the series. Errors if the series is empty -- an empty
    /// series (sampler stopped before its first tick, or every sample
    /// failed) must not silently collapse into a summary of zeros.
    pub fn summarize(&self) -> anyhow::Result<SamplerSummary> {
        if self.samples.is_empty() {
            anyhow::bail!("no process samples were collected -- cannot summarize");
        }
        let peak_rss_bytes = self.samples.iter().map(|s| s.rss_bytes).max().unwrap();
        let peak_fds = self.samples.iter().map(|s| s.fd_count).max().unwrap();

        // Rust note: `windows(2)` hands back overlapping pairs
        // `[s0,s1],[s1,s2],...` -- exactly the consecutive-sample deltas we
        // need to turn cumulative CPU time into a %-of-one-core rate.
        let mut cpu_percents = Vec::new();
        for pair in self.samples.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            let wall_ms = b.elapsed_ms.saturating_sub(a.elapsed_ms);
            if wall_ms == 0 {
                continue;
            }
            let cpu_delta = b.cpu_time.saturating_sub(a.cpu_time);
            let pct = cpu_delta.as_secs_f64() / (wall_ms as f64 / 1000.0) * 100.0;
            cpu_percents.push(pct);
        }
        let (mean_cpu_percent, peak_cpu_percent) = if cpu_percents.is_empty() {
            (None, None)
        } else {
            let mean = cpu_percents.iter().sum::<f64>() / cpu_percents.len() as f64;
            let peak = cpu_percents.iter().cloned().fold(f64::MIN, f64::max);
            (Some(mean), Some(peak))
        };

        Ok(SamplerSummary {
            sample_count: self.samples.len(),
            peak_rss_bytes,
            mean_cpu_percent,
            peak_cpu_percent,
            peak_fds,
        })
    }
}

/// A running sampler task, stoppable from the outside.
pub struct SamplerHandle {
    stop_tx: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<anyhow::Result<SampleSeries>>,
}

impl SamplerHandle {
    /// Signal the background sampling task to stop and wait for it, giving
    /// back everything it collected (or the error that made it give up).
    pub async fn stop(mut self) -> anyhow::Result<SampleSeries> {
        // Rust note: `.take()` leaves `None` behind so `stop` can't be
        // called twice and try to send on an already-consumed channel; the
        // `Option` here is the "run at most once" guard, not an Option over
        // whether we ever had a sender.
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        self.join.await.context("sampler task panicked")?
    }
}

/// Spawn a background task that samples `pid`'s RSS/CPU/fd usage every
/// `interval` until [`SamplerHandle::stop`] is called (or the process
/// disappears, in which case the task ends early with an `Err`).
pub fn spawn(pid: u32, interval: Duration) -> SamplerHandle {
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let join = tokio::spawn(async move {
        let start = Instant::now();
        let mut samples = Vec::new();
        let mut ticker = tokio::time::interval(interval);
        // Rust note: `Delay` (rather than the default `Burst`) means a
        // slow/blocked sample doesn't cause the ticker to fire a storm of
        // catch-up ticks once it's unblocked -- we'd rather sample less
        // often than pretend we sampled on schedule.
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let raw = sample_once(pid)?;
                    samples.push(ProcessSample {
                        elapsed_ms: start.elapsed().as_millis() as u64,
                        rss_bytes: raw.rss_bytes,
                        cpu_time: raw.cpu_time,
                        fd_count: raw.fd_count,
                    });
                }
                _ = &mut stop_rx => break,
            }
        }
        Ok(SampleSeries { samples })
    });
    SamplerHandle {
        stop_tx: Some(stop_tx),
        join,
    }
}

// ---------------------------------------------------------------------
// macOS: shell out to `ps` (RSS + cumulative CPU time) and `lsof` (fd
// count). Neither needs root and both are present on every macOS install.
// ---------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn sample_once(pid: u32) -> anyhow::Result<RawSample> {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=,time=", "-p", &pid.to_string()])
        .output()
        .context("spawning `ps` to sample the proxy process")?;
    if !output.status.success() {
        anyhow::bail!(
            "`ps -p {pid}` exited with {} -- the process may have exited",
            output.status
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("`ps -p {pid}` produced no output"))?;
    let mut fields = line.split_whitespace();
    let rss_kb: u64 = fields
        .next()
        .ok_or_else(|| anyhow::anyhow!("`ps` output missing rss field: {line:?}"))?
        .parse()
        .context("parsing ps rss field")?;
    let time_field = fields
        .next()
        .ok_or_else(|| anyhow::anyhow!("`ps` output missing time field: {line:?}"))?;
    let cpu_time = parse_ps_time(time_field)?;
    let fd_count = macos_fd_count(pid)?;

    Ok(RawSample {
        rss_bytes: rss_kb * 1024,
        cpu_time,
        fd_count,
    })
}

#[cfg(target_os = "macos")]
fn macos_fd_count(pid: u32) -> anyhow::Result<u64> {
    let output = std::process::Command::new("lsof")
        .args(["-p", &pid.to_string()])
        .output()
        .context("spawning `lsof` to count open file descriptors")?;
    // Rust note: unlike `ps`, `lsof` can exit nonzero on some macOS
    // versions purely because the target has zero listed fds (a warning,
    // not a hard failure) -- so we read stdout regardless of exit status
    // and only fail if there's truly nothing there to parse.
    let text = String::from_utf8_lossy(&output.stdout);
    if text.trim().is_empty() {
        anyhow::bail!("`lsof -p {pid}` produced no output -- the process may have exited");
    }
    // First line is the header row (COMMAND PID USER FD TYPE ...).
    Ok(text.lines().count().saturating_sub(1) as u64)
}

/// Parse a `ps time=` field: `[[dd-]hh:]mm:ss[.ss]`.
#[cfg(target_os = "macos")]
fn parse_ps_time(s: &str) -> anyhow::Result<Duration> {
    let (days, rest) = match s.split_once('-') {
        Some((d, r)) => (d.parse::<f64>().context("parsing ps time days field")?, r),
        None => (0.0, s),
    };
    let parts: Vec<&str> = rest.split(':').collect();
    let (hours, minutes, seconds) = match parts.as_slice() {
        [h, m, s] => (
            h.parse::<f64>().context("parsing ps time hours field")?,
            m.parse::<f64>().context("parsing ps time minutes field")?,
            s.parse::<f64>().context("parsing ps time seconds field")?,
        ),
        [m, s] => (
            0.0,
            m.parse::<f64>().context("parsing ps time minutes field")?,
            s.parse::<f64>().context("parsing ps time seconds field")?,
        ),
        _ => anyhow::bail!("unrecognized `ps` time format: {s:?}"),
    };
    let total_secs = days * 86_400.0 + hours * 3_600.0 + minutes * 60.0 + seconds;
    Ok(Duration::from_secs_f64(total_secs))
}

// ---------------------------------------------------------------------
// Linux: read /proc/<pid>/status (RSS), /proc/<pid>/stat (CPU ticks), and
// /proc/<pid>/fd (fd count) directly -- no subprocess needed.
// ---------------------------------------------------------------------

/// Assumed kernel clock-ticks-per-second, used to convert `utime`/`stime`
/// (reported in ticks) into wall-clock CPU time. The exact value needs
/// `sysconf(_SC_CLK_TCK)`, a libc FFI call this workspace's `unsafe`-deny
/// rule keeps out of this crate; 100 is the value on effectively every
/// mainstream Linux distribution (x86_64 and arm64 alike), so this is a
/// documented approximation, not a silent one -- see the module doc.
#[cfg(target_os = "linux")]
const LINUX_CLK_TCK: u64 = 100;

#[cfg(target_os = "linux")]
fn sample_once(pid: u32) -> anyhow::Result<RawSample> {
    Ok(RawSample {
        rss_bytes: linux_rss_bytes(pid)?,
        cpu_time: linux_cpu_time(pid)?,
        fd_count: linux_fd_count(pid)?,
    })
}

#[cfg(target_os = "linux")]
fn linux_rss_bytes(pid: u32) -> anyhow::Result<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("reading /proc/{pid}/status (process may have exited)"))?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .ok_or_else(|| anyhow::anyhow!("VmRSS line has no value: {line:?}"))?
                .parse()
                .context("parsing VmRSS value")?;
            return Ok(kb * 1024);
        }
    }
    anyhow::bail!(
        "/proc/{pid}/status has no VmRSS line -- the process may have no resident memory yet"
    )
}

#[cfg(target_os = "linux")]
fn linux_cpu_time(pid: u32) -> anyhow::Result<Duration> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .with_context(|| format!("reading /proc/{pid}/stat (process may have exited)"))?;
    // Rust note: field 2 (`comm`, the process name) is parenthesized and may
    // itself contain spaces or parens, so anchor on the *last* ')' rather
    // than splitting on whitespace from the start -- see proc(5).
    let after_comm = stat
        .rsplit_once(')')
        .map(|(_, rest)| rest)
        .ok_or_else(|| anyhow::anyhow!("/proc/{pid}/stat missing ')' after comm field"))?;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // After the comm field, field 3 (state) is fields[0]; utime is field 14
    // -> fields[11], stime is field 15 -> fields[12] (proc(5)).
    let utime: u64 = fields
        .get(11)
        .ok_or_else(|| anyhow::anyhow!("/proc/{pid}/stat too short for utime"))?
        .parse()
        .context("parsing utime")?;
    let stime: u64 = fields
        .get(12)
        .ok_or_else(|| anyhow::anyhow!("/proc/{pid}/stat too short for stime"))?
        .parse()
        .context("parsing stime")?;
    let ticks = utime + stime;
    Ok(Duration::from_secs_f64(ticks as f64 / LINUX_CLK_TCK as f64))
}

#[cfg(target_os = "linux")]
fn linux_fd_count(pid: u32) -> anyhow::Result<u64> {
    let entries = std::fs::read_dir(format!("/proc/{pid}/fd")).with_context(|| {
        format!("reading /proc/{pid}/fd (process may have exited or fd table unreadable)")
    })?;
    Ok(entries.count() as u64)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn sample_once(_pid: u32) -> anyhow::Result<RawSample> {
    anyhow::bail!(
        "process sampling (RSS/CPU/fd count) is only implemented for macOS and Linux; \
         refusing to report a fabricated zero on this platform"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(elapsed_ms: u64, rss_bytes: u64, cpu_ms: u64, fd_count: u64) -> ProcessSample {
        ProcessSample {
            elapsed_ms,
            rss_bytes,
            cpu_time: Duration::from_millis(cpu_ms),
            fd_count,
        }
    }

    #[test]
    fn summarize_errors_on_empty_series() {
        let series = SampleSeries { samples: vec![] };
        assert!(series.summarize().is_err());
    }

    #[test]
    fn summarize_reports_no_cpu_rate_from_a_single_sample() {
        let series = SampleSeries {
            samples: vec![sample(0, 1_000_000, 50, 10)],
        };
        let summary = series.summarize().expect("summarize");
        assert_eq!(summary.peak_rss_bytes, 1_000_000);
        assert_eq!(summary.peak_fds, 10);
        assert!(
            summary.mean_cpu_percent.is_none() && summary.peak_cpu_percent.is_none(),
            "a lone sample can't yield a rate -- must be None, not a fabricated 0.0"
        );
    }

    #[test]
    fn summarize_computes_cpu_percent_from_consecutive_deltas() {
        // 500ms of CPU consumed over 1000ms of wall time at each step -> 50%.
        let series = SampleSeries {
            samples: vec![
                sample(0, 1_000_000, 0, 5),
                sample(1_000, 2_000_000, 500, 8),
                sample(2_000, 1_500_000, 1_000, 6),
            ],
        };
        let summary = series.summarize().expect("summarize");
        assert_eq!(summary.peak_rss_bytes, 2_000_000);
        assert_eq!(summary.peak_fds, 8);
        assert!((summary.mean_cpu_percent.unwrap() - 50.0).abs() < 1e-6);
        assert!((summary.peak_cpu_percent.unwrap() - 50.0).abs() < 1e-6);
    }

    #[cfg(target_os = "macos")]
    mod macos_time_parsing {
        use super::*;

        #[test]
        fn parses_minutes_seconds() {
            let d = parse_ps_time("1:02.50").expect("parse");
            assert!((d.as_secs_f64() - 62.5).abs() < 1e-6);
        }

        #[test]
        fn parses_hours_minutes_seconds() {
            let d = parse_ps_time("2:01:02.50").expect("parse");
            assert!((d.as_secs_f64() - (2.0 * 3600.0 + 62.5)).abs() < 1e-6);
        }

        #[test]
        fn parses_days_prefix() {
            let d = parse_ps_time("1-00:00:01.00").expect("parse");
            assert!((d.as_secs_f64() - 86_401.0).abs() < 1e-6);
        }

        #[test]
        fn rejects_garbage() {
            assert!(parse_ps_time("not-a-time").is_err());
        }
    }
}
