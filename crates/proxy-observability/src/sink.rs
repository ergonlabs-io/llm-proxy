//! The access-log writer. It turns a rendered [`crate::access_log::render`]
//! line into bytes on stdout, stderr or a file.
//!
//! [`AccessLogSink`] lives here and the IR re-exports it. `proxy-config`
//! depends on this crate, not the reverse, so defining the enum here keeps one
//! type instead of two that could drift apart.

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
/// Rust note: a trait object (`Arc<dyn AccessLogWriter>`), since callers only
/// need "write a line somewhere" and never match on the sink kind.
///
/// `write_line` returns no `Result`. A broken destination must never fail or
/// slow the request being logged. Errors are counted, and the warning is
/// rate-limited so a persistent failure cannot flood the log.
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

/// Warns at most once per [`RATE_LIMIT_SECS`], however many callers race.
///
/// Rust note: an `AtomicU64`, not a `Mutex`, so a failing destination does not
/// also become a lock contention point.
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
        // Rust note: `compare_exchange` lets only one racing thread win the
        // warn for this window.
        self.last_warn_unix_secs
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Counts the failure unconditionally (the counter is the record of loss),
    /// then warns at most once per window.
    fn warn(&self, context: &str, err: &io::Error) {
        WRITE_FAILURES_TOTAL.fetch_add(1, Ordering::Relaxed);
        record_write_failure_stat();
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
            writer: Mutex::new(BufWriter::with_capacity(WAKE_BYTES, file)),
            limiter: RateLimiter::new(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AccessLogWriter for FileSink {
    fn write_line(&self, line: &str) {
        // Rust note: `.lock().expect("lock poisoned: a holder panicked")` — a poisoned mutex here would mean a
        // previous writer panicked mid-write, which never happens (this
        // method never panics); `.unwrap()` documents "this can't fail" the
        // same way it does throughout the codebase's Mutex usage.
        let mut w = self
            .writer
            .lock()
            .expect("lock poisoned: a holder panicked");
        if let Err(e) = w.write_all(line.as_bytes()) {
            self.limiter.warn("file write", &e);
        }
    }

    fn flush(&self) {
        let mut w = self
            .writer
            .lock()
            .expect("lock poisoned: a holder panicked");
        if let Err(e) = w.flush() {
            self.limiter.warn("file flush", &e);
        }
    }

    fn reopen(&self) -> io::Result<()> {
        let file = open_append(&self.path)?;
        let mut w = self
            .writer
            .lock()
            .expect("lock poisoned: a holder panicked");
        // Flush whatever's still buffered against the *old* file handle
        // before we drop it — best effort, matches `write_line`'s "never
        // fail the caller" contract by simply not propagating this error.
        let _ = w.flush();
        *w = BufWriter::with_capacity(WAKE_BYTES, file);
        Ok(())
    }
}

// ------------------------------------------------------------ queued sink --

/// Upper bound on bytes waiting in one [`QueuedSink`]. It is measured in bytes
/// because line sizes vary widely between formats. 8 MiB rides out a short
/// stall, and a dead destination costs a bounded amount of memory.
const QUEUE_MAX_BYTES: usize = 8 * 1024 * 1024;

/// How long the blocking control calls (`flush`, `reopen`) wait for the
/// writer thread. Bounded so a destination stuck in a kernel write cannot
/// hang shutdown or a SIGUSR1 handler forever.
const CONTROL_WAIT: Duration = Duration::from_secs(5);

/// The writer thread drains and flushes at least this often. Between ticks a
/// producer wakes it only once [`WAKE_BYTES`] are waiting, so a request does
/// not pay a futex wake, and the writer a `write(2)` and flush, per line.
/// Envoy batches file access logs the same way (`file_flush_interval_msec`
/// and a minimum flush size). Explicit `flush()`, `reopen()` and shutdown
/// still act at once.
const FLUSH_INTERVAL: Duration = Duration::from_millis(100);

/// Queued line bytes at which a producer wakes the writer before the next
/// [`FLUSH_INTERVAL`] tick, so a burst cannot fill the queue between ticks.
const WAKE_BYTES: usize = 64 * 1024;

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
    /// A `Flush` or `Reopen` is queued, so the writer must not sleep out its
    /// tick before serving it.
    has_control: bool,
    /// The writer is waiting on an empty queue with no timeout, so the next
    /// line must wake it.
    parked: bool,
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

/// Write or flush errors from every destination in the process since start.
static WRITE_FAILURES_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Total access-log write/flush failures, across all destinations.
pub fn write_failures_total() -> u64 {
    WRITE_FAILURES_TOTAL.load(Ordering::Relaxed)
}

/// Total lines dropped because a queue was full, across all destinations.
pub fn dropped_lines_total() -> u64 {
    DROPPED_TOTAL.load(Ordering::Relaxed)
}

/// Where drops are also counted as a stat, set by
/// [`register_dropped_lines_counter`].
static DROP_STAT: std::sync::RwLock<Option<(Arc<crate::stats::Registry>, crate::stats::Handle)>> =
    std::sync::RwLock::new(None);

/// Where write failures are counted as a stat, set by
/// [`register_dropped_lines_counter`] alongside [`DROP_STAT`].
static WRITE_FAILURE_STAT: std::sync::RwLock<
    Option<(Arc<crate::stats::Registry>, crate::stats::Handle)>,
> = std::sync::RwLock::new(None);

/// Count future dropped lines in `llmproxy_access_log_dropped_lines`. Call once
/// at boot. Registering again replaces the destination. The drop path takes this
/// read lock, but only once a queue is already overflowing.
pub fn register_dropped_lines_counter(control: &crate::stats::StatsControl) {
    let handle = control.resolve(&crate::stats::instruments::ACCESS_LOG_DROPPED_LINES, &[]);
    // Rust note: a poisoned lock only means another thread panicked while
    // holding it; the data (an `Option` we overwrite whole) is still valid.
    *DROP_STAT.write().unwrap_or_else(|e| e.into_inner()) = Some((control.registry(), handle));
    // Same boot hook also exposes `llmproxy_access_log_write_failures`, so an
    // idle process renders an explicit zero for both loss signals.
    let failures = control.resolve(&crate::stats::instruments::ACCESS_LOG_WRITE_FAILURES, &[]);
    *WRITE_FAILURE_STAT
        .write()
        .unwrap_or_else(|e| e.into_inner()) = Some((control.registry(), failures));
}

fn record_write_failure_stat() {
    if let Some((registry, handle)) = WRITE_FAILURE_STAT
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
    {
        registry.incr(crate::stats::WorkerId(0), *handle, 1);
    }
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
        let mut guard = LIVE_QUEUES
            .lock()
            .expect("lock poisoned: a holder panicked");
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

/// Reopen the destination of every live [`QueuedSink`]: SIGUSR1 after
/// logrotate renamed the files. Each reopen is queued behind the lines before
/// it, so those still reach the old file. Waits at most `timeout` overall.
/// Returns how many destinations reopened, and the label and error of each
/// that failed or did not answer in time. stdout and stderr reopen as a no-op.
/// Control paths only.
pub fn reopen_all_queued(timeout: Duration) -> (usize, Vec<(String, io::Error)>) {
    let live: Vec<Arc<QueueShared>> = {
        let mut guard = LIVE_QUEUES
            .lock()
            .expect("lock poisoned: a holder panicked");
        guard.retain(|w| w.strong_count() > 0);
        guard.iter().filter_map(Weak::upgrade).collect()
    };
    reopen_queues(&live, timeout)
}

/// [`reopen_all_queued`] over a given set of queues. Enqueues every reopen
/// first, so slow destinations reopen in parallel.
fn reopen_queues(
    live: &[Arc<QueueShared>],
    timeout: Duration,
) -> (usize, Vec<(String, io::Error)>) {
    let acks: Vec<(&str, mpsc::Receiver<io::Result<()>>)> = live
        .iter()
        .filter_map(|q| {
            let (tx, rx) = mpsc::channel();
            q.submit_control(Item::Reopen(tx))
                .then_some((q.label.as_str(), rx))
        })
        .collect();
    let deadline = Instant::now() + timeout;
    let mut reopened = 0;
    let mut failed = Vec::new();
    for (label, rx) in acks {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(Ok(())) => reopened += 1,
            Ok(Err(err)) => failed.push((label.to_string(), err)),
            Err(mpsc::RecvTimeoutError::Timeout) => failed.push((
                label.to_string(),
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "access-log writer did not service reopen in time",
                ),
            )),
            // The writer exited after draining: its sink is gone, so there
            // is nothing left to reopen.
            Err(mpsc::RecvTimeoutError::Disconnected) => {}
        }
    }
    (reopened, failed)
}

impl QueueShared {
    /// Queue a control item. `false` if the writer thread has already gone.
    fn submit_control(&self, item: Item) -> bool {
        let mut st = self.state.lock().expect("lock poisoned: a holder panicked");
        if st.exited {
            return false;
        }
        st.items.push_back(item);
        st.has_control = true;
        drop(st);
        self.wake.notify_one();
        true
    }
}

/// Makes any [`AccessLogWriter`] non-blocking for the caller.
///
/// `write_line` copies the line into a bounded queue. A dedicated thread drains
/// it every [`FLUSH_INTERVAL`], or sooner once [`WAKE_BYTES`] are waiting, so
/// a stalled pipe or slow disk never blocks a request worker and a healthy
/// destination costs a request no syscall.
///
/// Drop policy is fail-open and loud. When the queue is full the NEW line is
/// dropped and counted, and a rate-limited warning names the destination. The
/// limiter runs only after a refusal, so the healthy path never touches it.
///
/// - `flush()` blocks (up to 5s). Use it only on shutdown or control paths.
/// - `reopen()` is queued after earlier lines, so it cannot race them.
/// - Dropping the sink does not wait. Call [`flush_all_queued`] before exit.
pub struct QueuedSink {
    shared: Arc<QueueShared>,
}

impl QueuedSink {
    /// Wrap `inner`, labelling warnings with `label` (e.g. `"stdout"`).
    ///
    /// Errors if the writer thread cannot be spawned (resource exhaustion);
    /// callers surface it as a config error rather than panicking.
    pub fn new(label: impl Into<String>, inner: Arc<dyn AccessLogWriter>) -> io::Result<Self> {
        Self::with_capacity(label, inner, QUEUE_MAX_BYTES)
    }

    /// As [`QueuedSink::new`] with an explicit byte bound (tests).
    pub fn with_capacity(
        label: impl Into<String>,
        inner: Arc<dyn AccessLogWriter>,
        max_bytes: usize,
    ) -> io::Result<Self> {
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
            .spawn(move || writer_loop(&worker, inner.as_ref()))?;
        {
            let mut live = LIVE_QUEUES
                .lock()
                .expect("lock poisoned: a holder panicked");
            live.retain(|w| w.strong_count() > 0);
            live.push(Arc::downgrade(&shared));
        }
        Ok(Self { shared })
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
            let mut st = shared
                .state
                .lock()
                .expect("lock poisoned: a holder panicked");
            while !st.closed && !st.has_control && st.line_bytes < WAKE_BYTES {
                if st.items.is_empty() {
                    // Idle: the next line wakes us (see `parked`).
                    st.parked = true;
                    st = shared
                        .wake
                        .wait(st)
                        .expect("lock poisoned: a holder panicked");
                    st.parked = false;
                } else {
                    // Lines are waiting: let more join them for one tick.
                    // Producers do not wake us per line, so this is where
                    // the batching happens. A control item, the byte
                    // threshold or shutdown cuts the tick short.
                    st = shared
                        .wake
                        .wait_timeout(st, FLUSH_INTERVAL)
                        .expect("lock poisoned: a holder panicked")
                        .0;
                    break;
                }
            }
            // Only shutdown leaves the loop above with nothing queued.
            if st.items.is_empty() {
                st.exited = true;
                return;
            }
            st.line_bytes = 0;
            st.has_control = false;
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
        let mut st = self
            .shared
            .state
            .lock()
            .expect("lock poisoned: a holder panicked");
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
        let before = st.line_bytes;
        st.line_bytes += line.len();
        st.items.push_back(Item::Line(line.to_string()));
        // Wake the writer for the first line after idle and once per
        // crossing of the threshold, not per line: otherwise its own tick
        // picks the line up.
        let wake = st.parked || (before < WAKE_BYTES && st.line_bytes >= WAKE_BYTES);
        drop(st);
        if wake {
            self.shared.wake.notify_one();
        }
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
        self.shared
            .state
            .lock()
            .expect("lock poisoned: a holder panicked")
            .closed = true;
        self.shared.wake.notify_one();
    }
}

/// One shared queued sink per process for stdout and for stderr: they are
/// process-wide resources, so a second writer thread would only add
/// interleaving. `None` for file sinks.
fn shared_stdio(sink: &AccessLogSink) -> io::Result<Option<Arc<dyn AccessLogWriter>>> {
    static STDOUT: OnceLock<Arc<QueuedSink>> = OnceLock::new();
    static STDERR: OnceLock<Arc<QueuedSink>> = OnceLock::new();
    // Rust note: `OnceLock::get_or_init` cannot take a fallible closure, so
    // build first and let `get_or_init` keep whichever value won a race; the
    // loser's `QueuedSink` drops and its writer thread exits.
    fn shared(
        cell: &'static OnceLock<Arc<QueuedSink>>,
        label: &str,
        inner: impl FnOnce() -> Arc<dyn AccessLogWriter>,
    ) -> io::Result<Arc<dyn AccessLogWriter>> {
        if let Some(existing) = cell.get() {
            return Ok(existing.clone());
        }
        let built = Arc::new(QueuedSink::new(label, inner())?);
        Ok(cell.get_or_init(|| built).clone())
    }
    Ok(match sink {
        AccessLogSink::Stdout => Some(shared(&STDOUT, "stdout", || Arc::new(StdoutSink::new()))?),
        AccessLogSink::Stderr => Some(shared(&STDERR, "stderr", || Arc::new(StderrSink::new()))?),
        AccessLogSink::File { .. } => None,
    })
}

// -------------------------------------------------------------- build_sink --

/// Build a queued writer for `sink`. Every [`AccessLogSink`] variant is matched
/// explicitly, so a new variant is a compile error here, not a silent
/// stdout fallback (AGENTS.md invariant 1).
pub fn build_sink(sink: &AccessLogSink) -> io::Result<Arc<dyn AccessLogWriter>> {
    Ok(match sink {
        AccessLogSink::Stdout | AccessLogSink::Stderr => {
            shared_stdio(sink)?.expect("stdio variants always have a shared sink")
        }
        AccessLogSink::File { path } => shared_file(path)?,
    })
}

// ------------------------------------------------------------- registry --

/// Canonicalize `path` into a dedup key without requiring the file to exist.
///
/// Rust note: this resolves relative vs. absolute paths, not symlinks. That is
/// enough for the same `access_log.path` string reused across listeners.
fn canonical_key(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

type FileSinkMap = HashMap<PathBuf, Weak<QueuedSink>>;

/// Process-wide file sinks by canonical path. `Weak`, so a path's sink (and
/// its writer thread) goes away when the last access logger using it drops;
/// dead entries are pruned on insert, bounding the map by live paths.
fn file_sinks() -> &'static Mutex<FileSinkMap> {
    static FILE_SINKS: OnceLock<Mutex<FileSinkMap>> = OnceLock::new();
    FILE_SINKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The one [`QueuedSink`] for `path` in this process, created on first use.
/// Sharing keeps the queue bound per path, and avoids interleaved partial
/// lines from separate buffers. The file opens outside the lock. If another
/// thread won the race, the extra sink is dropped.
fn shared_file(path: &str) -> io::Result<Arc<QueuedSink>> {
    let key = canonical_key(Path::new(path));
    if let Some(live) = file_sinks()
        .lock()
        .expect("lock poisoned: a holder panicked")
        .get(&key)
        .and_then(Weak::upgrade)
    {
        return Ok(live);
    }
    let fresh = Arc::new(QueuedSink::new(
        path.to_string(),
        Arc::new(FileSink::new(path)?),
    )?);
    let mut map = file_sinks()
        .lock()
        .expect("lock poisoned: a holder panicked");
    if let Some(live) = map.get(&key).and_then(Weak::upgrade) {
        return Ok(live);
    }
    map.retain(|_, w| w.strong_count() > 0);
    map.insert(key, Arc::downgrade(&fresh));
    Ok(fresh)
}

/// Entry point for building writers from access-log config. Configs that name
/// the same file share one [`QueuedSink`]. The registry is stateless, and the
/// dedup map is process-wide.
pub struct SinkRegistry {
    _private: (),
}

impl SinkRegistry {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Build (or reuse) the writer for `sink`. Stdout/stderr share one
    /// process-wide queue each; files share one per canonical path.
    pub fn build(&self, sink: &AccessLogSink) -> io::Result<Arc<dyn AccessLogWriter>> {
        build_sink(sink)
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
    fn file_write_and_flush_failures_are_counted_and_rendered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ro.log");
        std::fs::write(&path, "").unwrap();
        let control = crate::stats::StatsControl::new(1);
        register_dropped_lines_counter(&control);
        let handle = control.resolve(&crate::stats::instruments::ACCESS_LOG_WRITE_FAILURES, &[]);
        // A read-only handle fails every write on every platform (EBADF), unlike
        // /dev/full which macOS lacks. Built in-module: no production seam.
        let sink = FileSink {
            path: path.clone(),
            writer: Mutex::new(BufWriter::new(File::open(&path).unwrap())),
            limiter: RateLimiter::new(),
        };
        let before = write_failures_total();
        sink.write_line("buffered, so the error surfaces on flush\n");
        sink.flush();
        // `>=`: process-wide counters, other tests may also fail writes.
        assert!(write_failures_total() - before >= 1);
        assert!(control.registry().value(handle) >= 1);
        let rendered = crate::stats::prometheus_render::render(&control.registry());
        assert!(
            rendered.contains("llmproxy_access_log_write_failures"),
            "{rendered}"
        );
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
            QueuedSink::with_capacity("gated", inner, max_bytes).unwrap(),
            open,
            lines,
        )
    }

    /// Inner sink that records lines and counts flushes.
    #[derive(Default)]
    struct CountingSink {
        lines: Mutex<Vec<String>>,
        flushes: AtomicU64,
    }

    impl AccessLogWriter for CountingSink {
        fn write_line(&self, line: &str) {
            self.lines.lock().unwrap().push(line.to_string());
        }
        fn flush(&self) {
            self.flushes.fetch_add(1, Ordering::Relaxed);
        }
        fn reopen(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Polls until `inner` has `n` lines, without calling `flush()`: the
    /// writer's own wake-up and tick must deliver them.
    fn await_lines(inner: &CountingSink, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while inner.lines.lock().unwrap().len() < n {
            assert!(
                Instant::now() < deadline,
                "lines never reached the inner sink"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn an_idle_writer_delivers_a_single_line_without_flush() {
        let inner = Arc::new(CountingSink::default());
        let sink = QueuedSink::new("counting", inner.clone()).unwrap();
        // Twice, so the second line meets a writer that has gone idle again.
        sink.write_line("one\n");
        await_lines(&inner, 1);
        sink.write_line("two\n");
        await_lines(&inner, 2);
        assert_eq!(*inner.lines.lock().unwrap(), ["one\n", "two\n"]);
    }

    #[test]
    fn queued_lines_share_a_flush_rather_than_paying_one_each() {
        let inner = Arc::new(CountingSink::default());
        let sink = QueuedSink::new("counting", inner.clone()).unwrap();
        for i in 0..100 {
            sink.write_line(&format!("line {i}\n"));
        }
        await_lines(&inner, 100);
        // One flush per line would need every write to land after the
        // writer's previous batch, a 100 ms stall each time.
        let flushes = inner.flushes.load(Ordering::Relaxed);
        assert!(flushes < 100, "{flushes} flushes for 100 lines");
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
        let sink = QueuedSink::new("file", Arc::new(FileSink::new(&path).unwrap())).unwrap();
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
        let sink = QueuedSink::new("file", Arc::new(FileSink::new(&path).unwrap())).unwrap();
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
        let sink = QueuedSink::new("file", Arc::new(FileSink::new(&path).unwrap())).unwrap();

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
    fn reopen_all_moves_a_file_sink_to_a_fresh_file() {
        let path = temp_path("reopen-all");
        let renamed = temp_path("reopen-all-renamed");
        let sink = QueuedSink::new("reopen-all", Arc::new(FileSink::new(&path).unwrap())).unwrap();
        sink.write_line("before rotate\n");
        sink.flush();
        std::fs::rename(&path, &renamed).unwrap();
        sink.write_line("queued before reopen\n");

        // Only this test's queue: `cargo test` shares `LIVE_QUEUES` across
        // tests, and a reopen queued on another test's gated sink would
        // stall that test.
        let (reopened, failed) =
            reopen_queues(std::slice::from_ref(&sink.shared), Duration::from_secs(5));
        assert!(failed.is_empty(), "{failed:?}");
        assert_eq!(reopened, 1);
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
    fn reopen_all_names_the_destination_that_failed() {
        struct FailingReopen;
        impl AccessLogWriter for FailingReopen {
            fn write_line(&self, _: &str) {}
            fn flush(&self) {}
            fn reopen(&self) -> io::Result<()> {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "nope"))
            }
        }
        let failing = QueuedSink::new("failing", Arc::new(FailingReopen)).unwrap();
        let path = temp_path("reopen-all-ok");
        let healthy = QueuedSink::new("healthy", Arc::new(FileSink::new(&path).unwrap())).unwrap();
        let (reopened, failed) = reopen_queues(
            &[failing.shared.clone(), healthy.shared.clone()],
            Duration::from_secs(5),
        );
        assert_eq!(reopened, 1, "one failure does not stop the others");
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert_eq!(failed[0].0, "failing");
        assert_eq!(failed[0].1.kind(), io::ErrorKind::PermissionDenied);
        std::fs::remove_file(&path).unwrap();
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
        let sink = QueuedSink::new("failing", Arc::new(FailingReopen)).unwrap();
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

    fn file_sink_cfg(path: &Path) -> AccessLogSink {
        AccessLogSink::File {
            path: path.to_string_lossy().into_owned(),
        }
    }

    /// Whether `path` has a live entry in the process-wide map.
    fn is_live(path: &Path) -> bool {
        file_sinks()
            .lock()
            .unwrap()
            .get(&canonical_key(path))
            .is_some_and(|w| w.strong_count() > 0)
    }

    #[test]
    fn independent_registries_share_one_sink_per_path() {
        let path = temp_path("shared-across-registries");
        let other = temp_path("shared-across-registries-other");
        // Two registries stand in for two workers / chains / generations.
        let a = SinkRegistry::new().build(&file_sink_cfg(&path)).unwrap();
        let b = SinkRegistry::new().build(&file_sink_cfg(&path)).unwrap();
        let c = SinkRegistry::new().build(&file_sink_cfg(&other)).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "same path must share one writer");
        assert!(!Arc::ptr_eq(&a, &c), "different paths must not share");

        for i in 0..50 {
            a.write_line(&format!("a{i}\n"));
            b.write_line(&format!("b{i}\n"));
        }
        a.flush();
        let text = std::fs::read_to_string(&path).unwrap();
        let expected: String = (0..50).map(|i| format!("a{i}\nb{i}\n")).collect();
        assert_eq!(text, expected, "one queue keeps submission order intact");

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&other).unwrap();
    }

    #[test]
    fn relative_and_absolute_spellings_share() {
        let rel = PathBuf::from(format!(
            "relabs-{}-{}.log",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let abs = std::env::current_dir().unwrap().join(&rel);
        let a = SinkRegistry::new().build(&file_sink_cfg(&rel)).unwrap();
        let b = SinkRegistry::new().build(&file_sink_cfg(&abs)).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "relative and absolute must share");
        drop((a, b));
        std::fs::remove_file(&abs).unwrap();
    }

    #[test]
    fn dead_entry_is_replaced_and_pruned() {
        let path = temp_path("dead-entry");
        let other = temp_path("dead-entry-other");
        let first = SinkRegistry::new().build(&file_sink_cfg(&path)).unwrap();
        assert!(is_live(&path));
        drop(first);
        assert!(!is_live(&path), "last holder dropped, entry is dead");

        // Building another path prunes the dead entry; building the same
        // path again yields a fresh, working sink.
        let o = SinkRegistry::new().build(&file_sink_cfg(&other)).unwrap();
        assert!(
            !file_sinks()
                .lock()
                .unwrap()
                .contains_key(&canonical_key(&path)),
            "dead entry pruned on insert"
        );
        let again = SinkRegistry::new().build(&file_sink_cfg(&path)).unwrap();
        again.write_line("fresh\n");
        again.flush();
        assert!(std::fs::read_to_string(&path).unwrap().contains("fresh\n"));

        drop((o, again));
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&other).unwrap();
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
            llm_resolved_model: None,
            llm_guardrail: None,
            llm_selected_model: None,
            llm_served_model: None,
            llm_upstream_id: None,
            llm_upstream_usage: None,
            llm_usage_completeness: None,
            llm_cost_kind: None,
            llm_rate_card_version: None,
            llm_media: Default::default(),

            request_method: None,
            request_path: None,
            request_authority: None,
            request_scheme: None,
            time_points: Default::default(),
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
