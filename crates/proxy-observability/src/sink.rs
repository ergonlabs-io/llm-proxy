//! WP-24 (chunk 2): the access-log *writer* half — turning a rendered
//! [`crate::access_log::render`] line into bytes on stdout/stderr/disk.
//!
//! [`AccessLogSink`] is defined **here**, not in `proxy-config`'s IR, and the
//! IR re-exports it (`proxy_config::ir::AccessLogSink`). The dependency edge
//! only runs one way — `proxy-config` depends on this crate for
//! [`crate::access_log::FormatString`] and [`crate::ResponseFlag`] — so
//! defining the enum on this side is what lets both crates name one type
//! instead of two same-shaped twins that could silently drift apart.
//!
//! Wiring this into the router/filter manager and SIGUSR1-driven `reopen()`
//! are both out of scope here; this module only has to make "write a line
//! to the configured destination, and support logrotate-style reopen" true.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Where a rendered access-log line is written. Re-exported by the config IR
/// as `proxy_config::ir::AccessLogSink` — see the module doc for why it is
/// defined on this side of the dependency edge.
///
/// `File` carries a path only; opening, buffering, and logrotate-style
/// reopen are [`FileSink`]'s job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessLogSink {
    Stdout,
    Stderr,
    File { path: String },
}

/// A destination for rendered access-log lines.
///
/// Rust note: this is a trait object (`Arc<dyn AccessLogWriter>`) rather than
/// an enum because the set of sinks is open-ended in spirit (stdout, stderr,
/// file today; a network sink is a plausible future variant) and callers
/// only ever need "write a line somewhere" — they don't match on which sink
/// they got.
///
/// `write_line` deliberately does **not** return a `Result`: a broken log
/// destination (disk full, permission revoked out from under us, a deleted
/// stdout pipe) must never fail — or even slow down — the request whose line
/// we're trying to log. Errors are swallowed here, but a write that starts
/// failing tends to keep failing on every subsequent request, so an
/// unfiltered `tracing::warn!` per call would just trade "silent data loss"
/// for "log-flood self-DoS." We rate-limit the warning instead: the first
/// failure (and at most one every few seconds after) is surfaced: enough to
/// notice, not enough to make things worse.
pub trait AccessLogWriter: Send + Sync {
    /// Write one already-rendered line verbatim (no newline is added or
    /// assumed; Envoy format strings typically end with `\n` themselves).
    fn write_line(&self, line: &str);
    /// Flush any buffered bytes to the underlying destination.
    fn flush(&self);
    /// Close and reopen the same destination (logrotate: the file at this
    /// path may have been renamed out from under us since we opened it; this
    /// re-opens the *path*, creating a fresh file there).
    fn reopen(&self) -> io::Result<()>;
}

/// Warns at most once per [`RATE_LIMIT_SECS`] seconds, no matter how many
/// callers race to report a failure at once.
///
/// Rust note: `AtomicU64` (not `Mutex<Instant>`) so `should_warn` never
/// blocks — it's called from the hot write path of a sink that failed, and
/// we don't want a failing log destination to also become a lock contention
/// point.
struct RateLimiter {
    last_warn_unix_secs: AtomicU64,
}

const RATE_LIMIT_SECS: u64 = 5;

impl RateLimiter {
    fn new() -> Self {
        Self {
            // 0 = "never warned yet", so the very first failure always
            // surfaces immediately.
            last_warn_unix_secs: AtomicU64::new(0),
        }
    }

    fn should_warn(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let last = self.last_warn_unix_secs.load(Ordering::Relaxed);
        if now.saturating_sub(last) < RATE_LIMIT_SECS {
            return false;
        }
        // Rust note: compare_exchange, not a plain store — if two threads
        // both decide "should warn" at once, only one wins the race and
        // actually logs; the loser sees a fresh `last` and backs off. Either
        // outcome is fine (we only promise *a* bound on warn frequency, not
        // exactly one warn per window), `Ok`/`Err` just picks who logs here.
        self.last_warn_unix_secs
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    fn warn(&self, context: &str, err: &io::Error) {
        if self.should_warn() {
            tracing::warn!(
                error = %err,
                "access-log write failed ({context}); further failures in the next {RATE_LIMIT_SECS}s are suppressed"
            );
        }
    }
}

// ------------------------------------------------------------- stdout/stderr --

/// Writes one line at a time to the process's stdout, flushing after every
/// write so lines interleave cleanly with any other stdout writer (e.g.
/// `tracing`'s own console output).
pub struct StdoutSink {
    limiter: RateLimiter,
}

impl StdoutSink {
    pub fn new() -> Self {
        Self {
            limiter: RateLimiter::new(),
        }
    }
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AccessLogWriter for StdoutSink {
    fn write_line(&self, line: &str) {
        // Rust note: `io::stdout().lock()` takes the same process-wide lock
        // `println!` uses, so access-log lines never get torn apart by a
        // concurrent write from elsewhere.
        let mut out = io::stdout().lock();
        if let Err(e) = out.write_all(line.as_bytes()) {
            self.limiter.warn("stdout", &e);
            return;
        }
        if let Err(e) = out.flush() {
            self.limiter.warn("stdout flush", &e);
        }
    }

    fn flush(&self) {
        let _ = io::stdout().lock().flush();
    }

    fn reopen(&self) -> io::Result<()> {
        // Nothing to do: stdout isn't a path we opened, there's nothing to
        // rotate.
        Ok(())
    }
}

/// Stderr counterpart of [`StdoutSink`].
pub struct StderrSink {
    limiter: RateLimiter,
}

impl StderrSink {
    pub fn new() -> Self {
        Self {
            limiter: RateLimiter::new(),
        }
    }
}

impl Default for StderrSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AccessLogWriter for StderrSink {
    fn write_line(&self, line: &str) {
        let mut out = io::stderr().lock();
        if let Err(e) = out.write_all(line.as_bytes()) {
            self.limiter.warn("stderr", &e);
            return;
        }
        if let Err(e) = out.flush() {
            self.limiter.warn("stderr flush", &e);
        }
    }

    fn flush(&self) {
        let _ = io::stderr().lock().flush();
    }

    fn reopen(&self) -> io::Result<()> {
        Ok(())
    }
}

// ------------------------------------------------------------------ file --

/// Writes to a file, opened in append mode, buffered.
///
/// Rust note: `Mutex<BufWriter<File>>`, not `RefCell<BufWriter<File>>` —
/// `RefCell` gives interior mutability but isn't `Sync`, so it can't cross
/// threads; sinks are shared (`Arc<dyn AccessLogWriter>`) across every
/// worker thread handling a request, so the lock has to actually be a lock.
pub struct FileSink {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
    limiter: RateLimiter,
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

impl FileSink {
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let file = open_append(&path)?;
        Ok(Self {
            path,
            writer: Mutex::new(BufWriter::new(file)),
            limiter: RateLimiter::new(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AccessLogWriter for FileSink {
    fn write_line(&self, line: &str) {
        // Rust note: `.lock().unwrap()` — a poisoned mutex here would mean a
        // previous writer panicked mid-write, which never happens (this
        // method never panics); `.unwrap()` documents "this can't fail" the
        // same way it does throughout the codebase's Mutex usage.
        let mut w = self.writer.lock().unwrap();
        if let Err(e) = w.write_all(line.as_bytes()) {
            self.limiter.warn("file write", &e);
        }
    }

    fn flush(&self) {
        let mut w = self.writer.lock().unwrap();
        if let Err(e) = w.flush() {
            self.limiter.warn("file flush", &e);
        }
    }

    fn reopen(&self) -> io::Result<()> {
        let file = open_append(&self.path)?;
        let mut w = self.writer.lock().unwrap();
        // Flush whatever's still buffered against the *old* file handle
        // before we drop it — best effort, matches `write_line`'s "never
        // fail the caller" contract by simply not propagating this error.
        let _ = w.flush();
        *w = BufWriter::new(file);
        Ok(())
    }
}

// -------------------------------------------------------------- build_sink --

/// Build a single, non-shared writer for `sink`. Ground rule #1: every
/// [`AccessLogSink`] variant is matched explicitly, so adding a variant
/// without updating this function is a compile error, not a silent
/// stdout-fallback.
pub fn build_sink(sink: &AccessLogSink) -> io::Result<Arc<dyn AccessLogWriter>> {
    Ok(match sink {
        AccessLogSink::Stdout => Arc::new(StdoutSink::new()),
        AccessLogSink::Stderr => Arc::new(StderrSink::new()),
        AccessLogSink::File { path } => Arc::new(FileSink::new(path)?),
    })
}

// ------------------------------------------------------------- registry --

/// Canonicalize `path` into a stable dedup key without requiring the file to
/// already exist (`Path::canonicalize` would fail on a not-yet-created log
/// file, which is the common case).
///
/// Rust note: this resolves "relative vs. absolute", not symlinks — two
/// different symlinks to the same inode are treated as different sinks. Good
/// enough for the config-authoring pattern this dedups (the same
/// `access_log.path` string reused across multiple listeners/filters), not a
/// general filesystem-identity check.
fn canonical_key(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

/// De-duplicates sinks by destination so that two access-log configs naming
/// the same file share one [`FileSink`] (one `BufWriter`, one `Mutex`)
/// instead of interleaving partial lines through two independent buffers.
///
/// Rust note: `Mutex<HashMap<...>>` guards the *registry* (inserting a new
/// entry); each `FileSink` inside has its own `Mutex` guarding writes. Two
/// different locks for two different concerns — registration is rare
/// (config-load time), writes are per-request.
pub struct SinkRegistry {
    files: Mutex<HashMap<PathBuf, Arc<FileSink>>>,
}

impl SinkRegistry {
    pub fn new() -> Self {
        Self {
            files: Mutex::new(HashMap::new()),
        }
    }

    /// Build (or reuse) the writer for `sink`. Stdout/stderr are cheap and
    /// not deduplicated — only file destinations need shared buffering.
    pub fn build(&self, sink: &AccessLogSink) -> io::Result<Arc<dyn AccessLogWriter>> {
        match sink {
            AccessLogSink::Stdout => Ok(Arc::new(StdoutSink::new())),
            AccessLogSink::Stderr => Ok(Arc::new(StderrSink::new())),
            AccessLogSink::File { path } => {
                let key = canonical_key(Path::new(path));
                let mut files = self.files.lock().unwrap();
                if let Some(existing) = files.get(&key) {
                    return Ok(existing.clone() as Arc<dyn AccessLogWriter>);
                }
                let sink = Arc::new(FileSink::new(path)?);
                files.insert(key, sink.clone());
                Ok(sink as Arc<dyn AccessLogWriter>)
            }
        }
    }
}

impl Default for SinkRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_log::{parse_format, render, LogContext};
    use crate::flags::ResponseFlag;
    use std::io::Read as _;

    /// A unique path under the OS temp dir, cleaned up by the caller.
    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "proxy-observability-test-{}-{}-{}",
            std::process::id(),
            name,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p
    }

    fn read_to_string(path: &Path) -> String {
        let mut s = String::new();
        File::open(path).unwrap().read_to_string(&mut s).unwrap();
        s
    }

    #[test]
    fn file_sink_writes_line_to_disk() {
        let path = temp_path("write");
        let sink = FileSink::new(&path).unwrap();
        sink.write_line("hello access log\n");
        sink.flush();

        assert_eq!(read_to_string(&path), "hello access log\n");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn reopen_after_rotate_targets_a_fresh_file() {
        let path = temp_path("rotate");
        let renamed = temp_path("rotate-renamed");

        let sink = FileSink::new(&path).unwrap();
        sink.write_line("before rotate\n");
        sink.flush();

        // logrotate-style: move the file out from under the open handle.
        std::fs::rename(&path, &renamed).unwrap();

        sink.reopen().unwrap();
        sink.write_line("after rotate\n");
        sink.flush();

        // A fresh file exists at the original path with only the new line.
        assert_eq!(read_to_string(&path), "after rotate\n");
        // The renamed file is untouched — it stopped growing at rotate time.
        assert_eq!(read_to_string(&renamed), "before rotate\n");

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&renamed).unwrap();
    }

    #[test]
    fn registry_dedups_same_path_shares_arc() {
        let path = temp_path("dedup");
        let registry = SinkRegistry::new();

        let a = registry
            .build(&AccessLogSink::File {
                path: path.to_string_lossy().into_owned(),
            })
            .unwrap();
        let b = registry
            .build(&AccessLogSink::File {
                path: path.to_string_lossy().into_owned(),
            })
            .unwrap();
        assert!(Arc::ptr_eq(&a, &b), "same path must share one FileSink");

        let other_path = temp_path("dedup-other");
        let c = registry
            .build(&AccessLogSink::File {
                path: other_path.to_string_lossy().into_owned(),
            })
            .unwrap();
        assert!(
            !Arc::ptr_eq(&a, &c),
            "different paths must not share a FileSink"
        );

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&other_path).unwrap();
    }

    #[test]
    fn build_sink_covers_every_variant() {
        assert!(build_sink(&AccessLogSink::Stdout).is_ok());
        assert!(build_sink(&AccessLogSink::Stderr).is_ok());

        let path = temp_path("build-sink-file");
        let sink = build_sink(&AccessLogSink::File {
            path: path.to_string_lossy().into_owned(),
        })
        .unwrap();
        sink.write_line("x\n");
        sink.flush();
        assert_eq!(read_to_string(&path), "x\n");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rendered_line_roundtrips_through_sink_unchanged() {
        let fmt = parse_format("%PROTOCOL% %RESPONSE_CODE%\n").unwrap();
        let empty = http::HeaderMap::new();
        let flags: [ResponseFlag; 0] = [];
        let ctx = LogContext {
            start_time: SystemTime::UNIX_EPOCH,
            request_headers: &empty,
            response_headers: &empty,
            response_trailers: &empty,
            protocol: Some("HTTP/1.1"),
            response_code: Some(200),
            response_flags: &flags,
            duration: None,
            bytes_received: 0,
            bytes_sent: 0,
            upstream_host: None,
            upstream_cluster: None,
            downstream_remote_address: None,
            llm_tokens: None,
            llm_ttft: None,
            request_method: None,
            request_path: None,
            request_authority: None,
            request_scheme: None,
        };
        let line = render(&fmt, &ctx);
        assert_eq!(line, "HTTP/1.1 200\n");

        let path = temp_path("roundtrip");
        let sink = FileSink::new(&path).unwrap();
        sink.write_line(&line);
        sink.flush();
        assert_eq!(read_to_string(&path), line);
        std::fs::remove_file(&path).unwrap();
    }
}
