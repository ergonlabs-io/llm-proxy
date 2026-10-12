//! The access-log *writer* half — turning a rendered
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

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

// ------------------------------------------------------------ queued sink --

/// Upper bound on bytes waiting in one [`QueuedSink`]. Bytes, not lines,
/// because line size varies by an order of magnitude between a text format
/// and a JSON format with many fields. 8 MiB is roughly 40k typical lines:
/// several seconds of buffering at thousands of requests per second, enough
/// to ride out a logrotate hiccup or a short collector stall, small enough
/// that a destination that never recovers costs a bounded, known amount of
/// memory per destination rather than growing with traffic.
const QUEUE_MAX_BYTES: usize = 8 * 1024 * 1024;

/// How long the blocking control calls (`flush`, `reopen`) wait for the
/// writer thread. Bounded so a destination stuck in a kernel write cannot
/// hang shutdown or a SIGUSR1 handler forever.
const CONTROL_WAIT: Duration = Duration::from_secs(5);

/// One unit of work for the writer thread. Lines and control messages share
/// one FIFO so a `flush`/`reopen` is ordered after every line queued before
/// it.
enum Item {
    Line(String),
    Flush(mpsc::Sender<()>),
    Reopen(mpsc::Sender<io::Result<()>>),
}

#[derive(Default)]
struct QueueState {
    items: VecDeque<Item>,
    /// Bytes held by `Item::Line`s only; control items are tiny and must
    /// never be refused, or shutdown could not flush a full queue.
    line_bytes: usize,
    /// Set when the owning [`QueuedSink`] is dropped: the writer drains what
    /// is left and exits.
    closed: bool,
    /// Set by the writer under the lock just before it exits, so a late
    /// control request fails fast instead of waiting for an ack that never
    /// comes.
    exited: bool,
}

struct QueueShared {
    state: Mutex<QueueState>,
    wake: Condvar,
    dropped: AtomicU64,
    limiter: RateLimiter,
    label: String,
    max_bytes: usize,
}

/// Lines dropped by every [`QueuedSink`] in the process since start.
static DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Every live writer thread's shared state, so shutdown can flush them all
/// without holding the sinks themselves (workers drop their handlers, and
/// with them the sinks, before the main thread gets to flush).
static LIVE_QUEUES: Mutex<Vec<Weak<QueueShared>>> = Mutex::new(Vec::new());

/// Total lines dropped because a queue was full, across all destinations.
pub fn dropped_lines_total() -> u64 {
    DROPPED_TOTAL.load(Ordering::Relaxed)
}

/// Where drops are also counted as a stat, set by
/// [`register_dropped_lines_counter`].
static DROP_STAT: std::sync::RwLock<Option<(Arc<crate::stats::Registry>, crate::stats::Handle)>> =
    std::sync::RwLock::new(None);

/// Count every future dropped line in `llmproxy_access_log_dropped_lines`.
/// Call once at boot, after the stats control exists. Registering again
/// (tests, a second `run_serve` in one process) replaces the destination.
/// Lines dropped before registration are not back-filled; sinks open at
/// config load and a queue cannot overflow before traffic starts.
///
/// The drop path takes this read lock, which is fine: it only runs once a
/// queue is already overflowing, never on the healthy path.
pub fn register_dropped_lines_counter(control: &crate::stats::StatsControl) {
    let handle = control.resolve(&crate::stats::instruments::ACCESS_LOG_DROPPED_LINES, &[]);
    // Rust note: a poisoned lock only means another thread panicked while
    // holding it; the data (an `Option` we overwrite whole) is still valid.
    *DROP_STAT.write().unwrap_or_else(|e| e.into_inner()) = Some((control.registry(), handle));
}

fn record_drop_stat() {
    if let Some((registry, handle)) = DROP_STAT.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        // Shard 0 for every writer thread: counters are atomic, and this is a
        // process-level signal, not worker traffic (same convention as
        // `MetadataDeliveryStats`).
        registry.incr(crate::stats::WorkerId(0), *handle, 1);
    }
}

/// Flush every live [`QueuedSink`], waiting at most `timeout` overall.
/// Returns `false` if some writer did not catch up in time (the lines stay
/// queued; the caller is exiting anyway). Shutdown/control paths only.
pub fn flush_all_queued(timeout: Duration) -> bool {
    let live: Vec<Arc<QueueShared>> = {
        let mut guard = LIVE_QUEUES.lock().unwrap();
        guard.retain(|w| w.strong_count() > 0);
        guard.iter().filter_map(Weak::upgrade).collect()
    };
    // Enqueue every barrier first so slow destinations drain in parallel.
    let acks: Vec<mpsc::Receiver<()>> = live
        .iter()
        .filter_map(|q| {
            let (tx, rx) = mpsc::channel();
            q.submit_control(Item::Flush(tx)).then_some(rx)
        })
        .collect();
    let deadline = Instant::now() + timeout;
    let mut all = true;
    for rx in acks {
        let left = deadline.saturating_duration_since(Instant::now());
        // A disconnected sender means the writer exited after draining.
        if matches!(rx.recv_timeout(left), Err(mpsc::RecvTimeoutError::Timeout)) {
            all = false;
        }
    }
    all
}

impl QueueShared {
    /// Queue a control item. `false` if the writer thread has already gone.
    fn submit_control(&self, item: Item) -> bool {
        let mut st = self.state.lock().unwrap();
        if st.exited {
            return false;
        }
        st.items.push_back(item);
        drop(st);
        self.wake.notify_one();
        true
    }
}

/// Makes any [`AccessLogWriter`] non-blocking for the caller.
///
/// `write_line` copies the line into a bounded queue and returns; a
/// dedicated OS thread (`access-log-writer`) drains it in batches, writes
/// each line to the inner sink, and flushes once per batch. A stalled stdout
/// pipe or slow disk therefore stalls only that thread, never a request
/// worker (and never the other workers, which previously serialized on the
/// sink's lock).
///
/// Drop policy (fail-open, loud): when the queue is full the NEW line is
/// dropped and counted. Dropping the newest keeps the queue contents in
/// order and costs nothing on the healthy path. Each drop bumps
/// [`QueuedSink::dropped`] and the process-wide [`dropped_lines_total`]; a
/// `tracing::warn!` names the destination and the running count, at most once
/// per [`RATE_LIMIT_SECS`]. The limiter is only consulted after the queue has
/// already refused a line, so the healthy path never touches it.
///
/// Semantics of the trait methods:
/// - `flush()` BLOCKS (up to 5s) until the writer has written and flushed
///   everything queued before the call. Call it from shutdown/control paths
///   only, never per request.
/// - `reopen()` is a control message ordered after earlier lines, so it
///   cannot race in-flight writes; it returns the inner result.
/// - Dropping the sink lets the writer drain the remainder and exit but does
///   not wait; use [`flush_all_queued`] before process exit.
pub struct QueuedSink {
    shared: Arc<QueueShared>,
}

impl QueuedSink {
    /// Wrap `inner`, labelling warnings with `label` (e.g. `"stdout"`).
    pub fn new(label: impl Into<String>, inner: Arc<dyn AccessLogWriter>) -> Self {
        Self::with_capacity(label, inner, QUEUE_MAX_BYTES)
    }

    /// As [`QueuedSink::new`] with an explicit byte bound (tests).
    pub fn with_capacity(
        label: impl Into<String>,
        inner: Arc<dyn AccessLogWriter>,
        max_bytes: usize,
    ) -> Self {
        let shared = Arc::new(QueueShared {
            state: Mutex::new(QueueState::default()),
            wake: Condvar::new(),
            dropped: AtomicU64::new(0),
            limiter: RateLimiter::new(),
            label: label.into(),
            max_bytes,
        });
        let worker = shared.clone();
        // Rust note: `move` hands the thread its own `Arc` clones; the
        // thread keeps the queue alive after the `QueuedSink` handle drops,
        // which is what lets it drain the remainder.
        std::thread::Builder::new()
            .name("access-log-writer".to_string())
            .spawn(move || writer_loop(&worker, inner.as_ref()))
            .expect("spawn access-log-writer thread");
        {
            let mut live = LIVE_QUEUES.lock().unwrap();
            live.retain(|w| w.strong_count() > 0);
            live.push(Arc::downgrade(&shared));
        }
        Self { shared }
    }

    /// Lines dropped by this sink because its queue was full.
    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

fn writer_loop(shared: &QueueShared, inner: &dyn AccessLogWriter) {
    loop {
        // Take the whole backlog in one lock acquisition so producers are
        // never blocked behind inner-sink I/O.
        let batch = {
            let mut st = shared.state.lock().unwrap();
            while st.items.is_empty() && !st.closed {
                st = shared.wake.wait(st).unwrap();
            }
            if st.items.is_empty() {
                st.exited = true;
                return;
            }
            st.line_bytes = 0;
            std::mem::take(&mut st.items)
        };
        let mut dirty = false;
        for item in batch {
            match item {
                Item::Line(line) => {
                    inner.write_line(&line);
                    dirty = true;
                }
                Item::Flush(ack) => {
                    inner.flush();
                    dirty = false;
                    let _ = ack.send(());
                }
                Item::Reopen(ack) => {
                    let _ = ack.send(inner.reopen());
                }
            }
        }
        if dirty {
            inner.flush();
        }
    }
}

impl AccessLogWriter for QueuedSink {
    fn write_line(&self, line: &str) {
        let mut st = self.shared.state.lock().unwrap();
        if st.line_bytes + line.len() > self.shared.max_bytes {
            drop(st);
            let n = self.shared.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
            record_drop_stat();
            if self.shared.limiter.should_warn() {
                tracing::warn!(
                    destination = %self.shared.label,
                    dropped_total = n,
                    "access-log queue full: dropping log lines because the destination is not \
                     keeping up (requests are unaffected; lines are lost); further drops in the \
                     next {RATE_LIMIT_SECS}s are suppressed"
                );
            }
            return;
        }
        st.line_bytes += line.len();
        st.items.push_back(Item::Line(line.to_string()));
        drop(st);
        self.shared.wake.notify_one();
    }

    fn flush(&self) {
        let (tx, rx) = mpsc::channel();
        if self.shared.submit_control(Item::Flush(tx)) {
            let _ = rx.recv_timeout(CONTROL_WAIT);
        }
    }

    fn reopen(&self) -> io::Result<()> {
        let (tx, rx) = mpsc::channel();
        if !self.shared.submit_control(Item::Reopen(tx)) {
            return Err(io::Error::other("access-log writer thread has exited"));
        }
        rx.recv_timeout(CONTROL_WAIT).unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "access-log writer did not service reopen in time",
            ))
        })
    }
}

impl Drop for QueuedSink {
    fn drop(&mut self) {
        self.shared.state.lock().unwrap().closed = true;
        self.shared.wake.notify_one();
    }
}

/// One shared queued sink per process for stdout and for stderr: they are
/// process-wide resources, so a second writer thread would only add
/// interleaving. `None` for file sinks.
fn shared_stdio(sink: &AccessLogSink) -> Option<Arc<dyn AccessLogWriter>> {
    static STDOUT: OnceLock<Arc<QueuedSink>> = OnceLock::new();
    static STDERR: OnceLock<Arc<QueuedSink>> = OnceLock::new();
    match sink {
        AccessLogSink::Stdout => Some(
            STDOUT
                .get_or_init(|| Arc::new(QueuedSink::new("stdout", Arc::new(StdoutSink::new()))))
                .clone(),
        ),
        AccessLogSink::Stderr => Some(
            STDERR
                .get_or_init(|| Arc::new(QueuedSink::new("stderr", Arc::new(StderrSink::new()))))
                .clone(),
        ),
        AccessLogSink::File { .. } => None,
    }
}

// -------------------------------------------------------------- build_sink --

/// Build a single writer for `sink`, queued so callers never block on I/O
/// (stdout/stderr share one process-wide queue). AGENTS.md invariant 1: every
/// [`AccessLogSink`] variant is matched explicitly, so adding a variant
/// without updating this function is a compile error, not a silent
/// stdout-fallback.
pub fn build_sink(sink: &AccessLogSink) -> io::Result<Arc<dyn AccessLogWriter>> {
    Ok(match sink {
        AccessLogSink::Stdout | AccessLogSink::Stderr => {
            shared_stdio(sink).expect("stdio variants always have a shared sink")
        }
        AccessLogSink::File { path } => Arc::new(QueuedSink::new(
            path.clone(),
            Arc::new(FileSink::new(path)?),
        )),
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
    files: Mutex<HashMap<PathBuf, Arc<QueuedSink>>>,
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
            AccessLogSink::Stdout | AccessLogSink::Stderr => {
                Ok(shared_stdio(sink).expect("stdio variants always have a shared sink"))
            }
            AccessLogSink::File { path } => {
                let key = canonical_key(Path::new(path));
                let mut files = self.files.lock().unwrap();
                if let Some(existing) = files.get(&key) {
                    return Ok(existing.clone());
                }
                let sink = Arc::new(QueuedSink::new(
                    path.clone(),
                    Arc::new(FileSink::new(path)?),
                ));
                files.insert(key, sink.clone());
                Ok(sink)
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

    /// Inner sink that parks in `write_line` until the test sends on `gate`,
    /// recording what it wrote.
    struct GatedSink {
        gate: Mutex<mpsc::Receiver<()>>,
        lines: Arc<Mutex<Vec<String>>>,
    }

    impl AccessLogWriter for GatedSink {
        fn write_line(&self, line: &str) {
            let _ = self.gate.lock().unwrap().recv();
            self.lines.lock().unwrap().push(line.to_string());
        }
        fn flush(&self) {}
        fn reopen(&self) -> io::Result<()> {
            Ok(())
        }
    }

    fn gated(max_bytes: usize) -> (QueuedSink, mpsc::Sender<()>, Arc<Mutex<Vec<String>>>) {
        let (open, gate) = mpsc::channel();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let inner = Arc::new(GatedSink {
            gate: Mutex::new(gate),
            lines: lines.clone(),
        });
        (
            QueuedSink::with_capacity("gated", inner, max_bytes),
            open,
            lines,
        )
    }

    #[test]
    fn drops_are_counted_in_the_registered_stat_and_rendered() {
        let control = crate::stats::StatsControl::new(1);
        // Resolved before registering so the series exists (explicit zero)
        // for an idle process.
        register_dropped_lines_counter(&control);
        let handle = control.resolve(&crate::stats::instruments::ACCESS_LOG_DROPPED_LINES, &[]);
        assert_eq!(control.registry().value(handle), 0);

        let (sink, open, _lines) = gated(8);
        sink.write_line("a\n");
        loop {
            if sink.shared.state.lock().unwrap().items.is_empty() {
                break;
            }
            std::thread::yield_now();
        }
        for i in 0..10 {
            sink.write_line(&format!("{i}\n"));
        }
        assert_eq!(sink.dropped(), 6);
        // `>=`: other tests in the same process may also overflow a sink.
        assert!(control.registry().value(handle) >= 6);
        let rendered = crate::stats::prometheus_render::render(&control.registry());
        assert!(
            rendered.contains("llmproxy_access_log_dropped_lines"),
            "{rendered}"
        );
        for _ in 0..5 {
            open.send(()).unwrap();
        }
        sink.flush();
    }

    #[test]
    fn queued_sink_never_blocks_and_drops_exactly_the_overflow() {
        // Room for exactly four two-byte lines.
        let (sink, open, lines) = gated(8);
        let before = dropped_lines_total();
        // Park the writer inside the inner sink on line "a": once the queue
        // has been taken (items empty) the writer holds "a" and blocks on the
        // gate. flush() can't be used here, it would queue behind the write.
        sink.write_line("a\n");
        loop {
            if sink.shared.state.lock().unwrap().items.is_empty() {
                break;
            }
            std::thread::yield_now();
        }
        // The inner sink is blocked, yet every write_line returns at once:
        // 4 fit, the other 6 overflow.
        for i in 0..10 {
            sink.write_line(&format!("{i}\n"));
        }
        assert_eq!(sink.dropped(), 6);
        // Global counter is shared with parallel tests, so only a lower bound.
        assert!(dropped_lines_total() - before >= 6);
        for _ in 0..5 {
            open.send(()).unwrap();
        }
        sink.flush();
        assert_eq!(
            *lines.lock().unwrap(),
            vec!["a\n", "0\n", "1\n", "2\n", "3\n"],
            "non-dropped lines arrive in order, newest lines are the ones dropped"
        );
    }

    #[test]
    fn queued_sink_flush_waits_for_every_queued_line() {
        let path = temp_path("queued-flush");
        let sink = QueuedSink::new("file", Arc::new(FileSink::new(&path).unwrap()));
        for i in 0..1000 {
            sink.write_line(&format!("line {i}\n"));
        }
        sink.flush();
        let text = read_to_string(&path);
        assert_eq!(text.lines().count(), 1000);
        assert!(text.starts_with("line 0\n"));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn flush_all_queued_drains_a_sink_that_was_already_dropped() {
        // Shutdown case: workers drop their handlers (and sinks) before the
        // main thread flushes. Lines queued before the drop must still land.
        let path = temp_path("queued-dropped");
        let sink = QueuedSink::new("file", Arc::new(FileSink::new(&path).unwrap()));
        for i in 0..100 {
            sink.write_line(&format!("{i}\n"));
        }
        drop(sink);
        assert!(flush_all_queued(Duration::from_secs(5)));
        // If the writer finished its last batch before our barrier was
        // queued there is nothing to wait for; otherwise the barrier ordered
        // us after the lines. Either way the file is complete now, except in
        // the narrow window where the thread is mid-final-batch, so poll
        // instead of asserting on the first read.
        let mut n = 0;
        for _ in 0..200 {
            n = read_to_string(&path).lines().count();
            if n == 100 {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(n, 100);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn queued_sink_reopen_is_ordered_after_earlier_lines() {
        let path = temp_path("queued-rotate");
        let renamed = temp_path("queued-rotate-renamed");
        let sink = QueuedSink::new("file", Arc::new(FileSink::new(&path).unwrap()));

        sink.write_line("before rotate\n");
        sink.flush();
        std::fs::rename(&path, &renamed).unwrap();
        // Queued before reopen, so it must land via the OLD file handle.
        sink.write_line("queued before reopen\n");
        sink.reopen().unwrap();
        sink.write_line("after rotate\n");
        sink.flush();

        assert_eq!(read_to_string(&path), "after rotate\n");
        assert_eq!(
            read_to_string(&renamed),
            "before rotate\nqueued before reopen\n"
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&renamed).unwrap();
    }

    #[test]
    fn queued_sink_reopen_returns_the_inner_error() {
        struct FailingReopen;
        impl AccessLogWriter for FailingReopen {
            fn write_line(&self, _: &str) {}
            fn flush(&self) {}
            fn reopen(&self) -> io::Result<()> {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "nope"))
            }
        }
        let sink = QueuedSink::new("failing", Arc::new(FailingReopen));
        assert_eq!(
            sink.reopen().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
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
            response_code_details: None,
            llm_tokens: None,
            llm_ttft: None,
            llm_max_stall: None,
            llm_response_chunks: 0,
            llm_list_cost_nanodollars: None,
            llm_key_id: None,
            llm_tenant: None,
            llm_credential_source: None,
            llm_user_id: None,
            llm_requested_model: None,
            llm_selected_model: None,
            llm_rate_card_version: None,

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
