//! Worker runtime pool and control-to-worker config propagation (ADR-0003).
//!
//! Workers are share-nothing, `!Send` `current_thread` tokio runtimes, each on a dedicated OS thread driving a
//! `LocalSet`. Config crosses threads only as an immutable `Arc<ConfigSnapshot>`, published into each worker's
//! [`WorkerConfigHandle`] and followed by a `watch` ping. Every other snapshot consumer (the admin server) enrolls
//! its handle in the same [`SnapshotHandles`] registry, so [`ConfigPublisher::publish`] cannot leave it behind.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use proxy_config::ir::SnapshotVersion;
use proxy_config::ConfigSnapshot;
use tokio::runtime::Builder;
use tokio::sync::{mpsc, watch};
use tokio::task::LocalSet;

use crate::drain::{DrainCoordinator, DrainOutcome, DrainState};
use crate::WorkerConfigHandle;

/// Identifies a worker thread/runtime.
///
/// Rust note: a newtype around `usize` so a worker index can't be mixed up
/// with, say, a listener index at a call site -- the compiler catches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkerId(pub usize);

/// How many workers to run and whether to pin each to a dedicated CPU core.
#[derive(Debug, Clone, Copy)]
pub struct WorkerPoolConfig {
    pub concurrency: usize,
    pub pin_cores: bool,
}

impl Default for WorkerPoolConfig {
    fn default() -> Self {
        Self {
            concurrency: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            pin_cores: true,
        }
    }
}

/// Everything a worker's driving future needs, handed to `worker_main` once
/// per worker.
pub struct WorkerContext {
    pub id: WorkerId,
    /// This worker's slice of config: `load()`/`load_full()` returns the
    /// latest snapshot published by the control runtime.
    pub config: Arc<WorkerConfigHandle>,
    /// Fires whenever the control runtime calls `ConfigPublisher::publish`. The new snapshot is already visible via
    /// `config` by the time this resolves.
    pub config_ping: watch::Receiver<SnapshotVersion>,
    /// Flips to `true` when `ConfigPublisher::shutdown` is called.
    pub shutdown: watch::Receiver<bool>,
    /// Fires when the control runtime calls `ConfigPublisher::start_drain`. Worker mains hand it to
    /// [`crate::drain::drain_worker`].
    pub drain: watch::Receiver<DrainState>,
    /// The worker reports here (via `drain_worker`) once its connection
    /// registry has emptied or its drain deadline has passed.
    pub drain_done: mpsc::UnboundedSender<WorkerId>,
    /// The one process-wide downstream connection counter, a clone of the
    /// same handle every sibling worker gets.
    pub connection_limiter: crate::admission::ConnectionLimiter,
}

/// Every live [`WorkerConfigHandle`] that must observe a republished snapshot: one per worker, plus the admin
/// server's when it runs. [`ConfigPublisher::publish`] walks this registry. `WorkerConfigHandle::new` is
/// `pub(crate)`, so [`SnapshotHandles::register`] is the only way outside `proxy-core` to get a handle, and it
/// always enrolls the handle it returns. A new consumer is therefore registered by construction. (Unit tests in
/// this crate may still call `WorkerConfigHandle::new` directly.)
///
/// Rust note: `Mutex<Vec<_>>`, because registration comes from two call sites on the control runtime
/// (`WorkerPool::spawn` and `start_admin`) that share one `Arc`. Registration happens only at startup, and
/// `store_all` runs only on a SIGHUP publish, never on the per-connection hot path.
#[derive(Default)]
pub struct SnapshotHandles {
    handles: Mutex<Vec<Arc<WorkerConfigHandle>>>,
}

impl SnapshotHandles {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a [`WorkerConfigHandle`] seeded with `initial`, enrolls it in this registry, and returns it.
    /// Constructing one directly and skipping registration is the bug this prevents: the compiler refuses the
    /// shortcut.
    pub fn register(&self, initial: Arc<ConfigSnapshot>) -> Arc<WorkerConfigHandle> {
        let handle = Arc::new(WorkerConfigHandle::new(initial));
        self.handles
            .lock()
            .expect("snapshot handle registry poisoned")
            .push(handle.clone());
        handle
    }

    /// Stores `snapshot` into every registered handle. [`ConfigPublisher::publish`] calls this, and the store comes
    /// before the ping. It is `pub` so a test can drive a registry directly.
    pub fn store_all(&self, snapshot: &Arc<ConfigSnapshot>) {
        for handle in self
            .handles
            .lock()
            .expect("snapshot handle registry poisoned")
            .iter()
        {
            handle.store(snapshot.clone());
        }
    }
}

/// Owns nothing after `spawn` returns. It exists to give `spawn` a home (`WorkerPool::spawn(...)`). The handles a
/// caller needs live on [`ConfigPublisher`].
pub struct WorkerPool;

impl WorkerPool {
    /// Spawns `config.concurrency` worker threads, each running a `current_thread` tokio runtime and `LocalSet`, and
    /// returns the [`ConfigPublisher`] the control runtime uses to talk to them.
    ///
    /// `worker_main` runs once per worker, on that worker's own OS thread, to build the future that drives its
    /// `LocalSet`. The future cannot move threads after the fact, since it may be `!Send`.
    ///
    /// `snapshot_handles` is the registry every worker's handle is enrolled into. Pass the same one any other
    /// snapshot consumer (the admin server) already uses, so `publish` keeps all of them current.
    ///
    /// Rust note: the bound is deliberately asymmetric. `worker_main` must be `Send + Clone + 'static` to move into
    /// each `std::thread::spawn`. The future it returns need not be `Send`: per ADR-0003 it is built and polled on
    /// the thread it was created on, and may hold `Rc` or `RefCell` across an `.await`.
    pub fn spawn<F, W>(
        config: WorkerPoolConfig,
        initial_snapshot: Arc<ConfigSnapshot>,
        snapshot_handles: Arc<SnapshotHandles>,
        worker_main: W,
    ) -> ConfigPublisher
    where
        F: Future<Output = ()> + 'static,
        W: Fn(WorkerContext) -> F + Send + Clone + 'static,
    {
        // Best-effort core discovery: `pin_cores` is a hint, never a hard
        // requirement (S-spec parity: Envoy also falls back to unpinned).
        let core_ids = if config.pin_cores {
            core_affinity::get_core_ids()
        } else {
            None
        };

        let mut threads = Vec::with_capacity(config.concurrency);
        let mut config_txs = Vec::with_capacity(config.concurrency);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        // Rust note: `DrainCoordinator::new` returns one `watch::Receiver` that every worker clones, plus the
        // coordinator, which owns the `mpsc` sender workers report drain completion through.
        let (drain_coordinator, drain_rx) = DrainCoordinator::new(config.concurrency);
        let drain_done_tx = drain_coordinator.done_sender();

        let available_cores = core_ids.as_ref().map_or(0, Vec::len);
        if config.pin_cores && available_cores < config.concurrency {
            tracing::warn!(
                workers = config.concurrency,
                cores = available_cores,
                "fewer CPU cores to pin to than workers (pin_cores requested); the rest run unpinned"
            );
        }
        let pin_failure_reported = Arc::new(AtomicBool::new(false));

        let connection_limiter = crate::admission::ConnectionLimiter::default();
        for i in 0..config.concurrency {
            let id = WorkerId(i);
            let connection_limiter = connection_limiter.clone();
            // `register` builds this worker's handle and enrolls it in `snapshot_handles`, so the enrollment cannot be
            // forgotten.
            let handle_for_thread = snapshot_handles.register(initial_snapshot.clone());
            let (config_tx, config_rx) = watch::channel(initial_snapshot.version);
            let shutdown_rx = shutdown_rx.clone();
            let drain_rx = drain_rx.clone();
            let drain_done_tx = drain_done_tx.clone();
            let worker_main = worker_main.clone();

            let core_id = core_ids.as_ref().and_then(|ids| ids.get(i).copied());
            let pin_failure_reported = pin_failure_reported.clone();

            let thread = std::thread::Builder::new()
                .name(format!("worker-{i}"))
                .spawn(move || {
                    if let Some(core_id) = core_id {
                        // One warning per process, not per worker: the cause (macOS on Apple
                        // silicon refuses affinity, a cgroup cpuset) is the same for every worker.
                        if !core_affinity::set_for_current(core_id)
                            && !pin_failure_reported.swap(true, Ordering::Relaxed)
                        {
                            tracing::warn!(
                                "failed to pin workers to cores (unsupported on this platform), continuing unpinned"
                            );
                        }
                    }

                    let ctx = WorkerContext {
                        id,
                        config: handle_for_thread,
                        config_ping: config_rx,
                        shutdown: shutdown_rx,
                        drain: drain_rx,
                        drain_done: drain_done_tx,
                        connection_limiter,
                    };

                    // Rust note: `new_current_thread` plus `LocalSet` is the `!Send` half of ADR-0003. Everything
                    // spawned with `tokio::task::spawn_local` stays on this OS thread, so data-plane code can use
                    // `Rc` and `RefCell` instead of `Arc` and `Mutex`.
                    let rt = Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("failed to build worker runtime");
                    let local = LocalSet::new();
                    local.block_on(&rt, worker_main(ctx));
                })
                .expect("failed to spawn worker thread");

            threads.push(thread);
            config_txs.push(config_tx);
        }

        ConfigPublisher {
            handles: snapshot_handles,
            config_txs,
            shutdown_tx,
            threads,
            drain: drain_coordinator,
        }
    }
}

/// Control-plane handle to a running [`WorkerPool`]: publishes config
/// snapshots, signals shutdown, and joins the worker threads.
pub struct ConfigPublisher {
    /// Every consumer `publish` must keep current. Shared as a registry, not a `Vec` built here: the admin server's
    /// handle is registered by `start_admin` before `WorkerPool::spawn` builds this publisher.
    handles: Arc<SnapshotHandles>,
    config_txs: Vec<watch::Sender<SnapshotVersion>>,
    shutdown_tx: watch::Sender<bool>,
    threads: Vec<JoinHandle<()>>,
    /// Drain coordination lives here too, so publish, shutdown, and drain all sit on one control-side type.
    drain: DrainCoordinator,
}

impl ConfigPublisher {
    /// Publishes a new snapshot to every handle registered in this publisher's [`SnapshotHandles`], workers and
    /// others alike.
    ///
    /// Ordering matters: this stores into every handle before sending the `watch` ping. A worker woken by the ping
    /// then always sees the new snapshot on `config.load()`. A non-worker consumer has no ping to race and sees the
    /// new snapshot on its next `load()`.
    pub fn publish(&self, snapshot: Arc<ConfigSnapshot>) {
        self.handles.store_all(&snapshot);
        for tx in &self.config_txs {
            // Rust note: `send` errors only if every receiver is gone, meaning the worker thread has exited. That is not
            // ours to report, so the error is ignored rather than unwrapped.
            let _ = tx.send(snapshot.version);
        }
    }

    /// Signal every worker to shut down. Does not wait for them; call
    /// [`ConfigPublisher::join`] for that.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Begins a drain: broadcasts the new [`DrainState`] to every worker. Workers react through
    /// [`crate::drain::drain_worker`].
    pub fn start_drain(
        &self,
        duration: std::time::Duration,
        strategy: crate::drain::DrainStrategy,
    ) -> std::time::Instant {
        self.drain.start_drain(duration, strategy)
    }

    /// Wait until every worker has reported drain completion, or `deadline`
    /// passes -- whichever comes first.
    pub async fn wait_drained(&mut self, deadline: std::time::Instant) -> DrainOutcome {
        self.drain.wait_drained(deadline).await
    }

    /// Block until every worker thread has exited.
    pub fn join(self) {
        for thread in self.threads {
            // A worker panic is a bug to surface, not swallow. `join`'s `Err` is a `Box<dyn Any>` we cannot act on
            // here beyond logging.
            if let Err(err) = thread.join() {
                tracing::error!(?err, "worker thread panicked");
            }
        }
    }

    /// Like [`ConfigPublisher::join`], but waits on a blocking-pool thread, so the async shutdown path on the control
    /// runtime never parks one of its own threads while workers finish.
    pub async fn join_async(self) {
        if let Err(err) = tokio::task::spawn_blocking(move || self.join()).await {
            tracing::error!(?err, "worker join task failed");
        }
    }
}

/// Test helper for exercising `!Send` types outside a full `WorkerPool`
/// (ADR-0003 consequences: tests over data-plane types need a `LocalSet`).
pub fn run_local<F: Future>(f: F) -> F::Output {
    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build test runtime");
    let local = LocalSet::new();
    local.block_on(&rt, f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    fn snapshot(version: u64) -> Arc<ConfigSnapshot> {
        Arc::new(ConfigSnapshot {
            version: SnapshotVersion(version),
            ..Default::default()
        })
    }

    fn handles() -> Arc<SnapshotHandles> {
        Arc::new(SnapshotHandles::new())
    }

    #[test]
    fn join_async_does_not_block_the_calling_runtime() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
        let publisher = WorkerPool::spawn(
            WorkerPoolConfig {
                concurrency: 1,
                pin_cores: false,
            },
            snapshot(0),
            handles(),
            move |_ctx: WorkerContext| {
                let rx = release_rx.lock().unwrap().take();
                async move {
                    // The worker thread stays busy until the test releases
                    // it, so `join` has something to wait for.
                    if let Some(rx) = rx {
                        let _ = rx.recv();
                    }
                }
            },
        );
        publisher.shutdown();

        // A current-thread runtime has one thread. A blocking join inside it would wait for a release only this thread
        // can send, so the test would hang.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let joined = tokio::spawn(publisher.join_async());
            tokio::task::yield_now().await;
            release_tx.send(()).unwrap();
            joined.await.expect("join task panicked");
        });
    }

    #[test]
    fn publish_updates_every_worker_snapshot() {
        let initial = snapshot(0);
        let (result_tx, result_rx) = mpsc::channel::<(WorkerId, u64)>();

        let publisher = WorkerPool::spawn(
            WorkerPoolConfig {
                concurrency: 3,
                pin_cores: false,
            },
            initial,
            handles(),
            move |mut ctx: WorkerContext| {
                let result_tx = result_tx.clone();
                async move {
                    // Wait for the ping, then report the snapshot seen after it, proving publish's store-then-ping
                    // ordering.
                    let _ = ctx.config_ping.changed().await;
                    let seen = ctx.config.load().version.0;
                    let _ = result_tx.send((ctx.id, seen));
                }
            },
        );

        publisher.publish(snapshot(7));

        let mut seen = vec![];
        for _ in 0..3 {
            seen.push(
                result_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("worker did not report snapshot in time"),
            );
        }
        assert_eq!(seen.len(), 3);
        for (_, version) in seen {
            assert_eq!(version, 7);
        }

        publisher.shutdown();
        publisher.join();
    }

    #[test]
    fn workers_run_on_distinct_named_threads() {
        let (result_tx, result_rx) = mpsc::channel::<String>();

        let publisher = WorkerPool::spawn(
            WorkerPoolConfig {
                concurrency: 2,
                pin_cores: false,
            },
            snapshot(0),
            handles(),
            move |_ctx: WorkerContext| {
                let result_tx = result_tx.clone();
                async move {
                    let name = std::thread::current()
                        .name()
                        .unwrap_or_default()
                        .to_string();
                    let _ = result_tx.send(name);
                }
            },
        );

        let mut names: Vec<String> = (0..2)
            .map(|_| {
                result_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("worker did not report its thread name in time")
            })
            .collect();
        names.sort();
        assert_eq!(names, vec!["worker-0".to_string(), "worker-1".to_string()]);

        publisher.shutdown();
        publisher.join();
    }

    #[test]
    fn worker_main_future_can_hold_non_send_state_across_await() {
        // An `Rc` (which is `!Send`) lives across an `.await` inside the future `worker_main` returns. This fails to
        // compile if `WorkerPool::spawn` requires `F: Send`.
        let done = Arc::new(AtomicUsize::new(0));
        let done_for_worker = done.clone();

        let publisher = WorkerPool::spawn(
            WorkerPoolConfig {
                concurrency: 1,
                pin_cores: false,
            },
            snapshot(0),
            handles(),
            move |ctx: WorkerContext| {
                let done = done_for_worker.clone();
                async move {
                    let rc = Rc::new(42usize);
                    let mut ping = ctx.config_ping.clone();
                    let _ = ping.changed().await;
                    done.store(*rc, Ordering::SeqCst);
                }
            },
        );

        publisher.publish(snapshot(1));

        for _ in 0..200 {
            if done.load(Ordering::SeqCst) == 42 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(done.load(Ordering::SeqCst), 42);

        publisher.shutdown();
        publisher.join();
    }

    #[test]
    fn shutdown_and_join_terminate_cleanly() {
        let publisher = WorkerPool::spawn(
            WorkerPoolConfig {
                concurrency: 2,
                pin_cores: false,
            },
            snapshot(0),
            handles(),
            |mut ctx: WorkerContext| async move {
                let _ = ctx.shutdown.changed().await;
            },
        );

        publisher.shutdown();
        // If shutdown didn't wake the workers, this hangs and the test
        // times out -- that's the assertion.
        publisher.join();
    }

    #[test]
    fn run_local_drives_a_non_send_future() {
        let value = run_local(async {
            let rc = Rc::new(5usize);
            tokio::task::yield_now().await;
            *rc
        });
        assert_eq!(value, 5);
    }

    /// A handle registered into the SAME [`SnapshotHandles`] but not created by `WorkerPool::spawn` (the admin
    /// server's shape) must still see a `publish()`. Before the registry existed, `publish` walked a private `Vec`
    /// built inside `spawn`, so an externally registered handle was never touched.
    #[test]
    fn publish_updates_a_handle_registered_outside_spawn() {
        let registry = handles();
        // Stands in for `start_admin`'s handle, registered BEFORE `WorkerPool::spawn`, as `main.rs` does.
        let external_handle = registry.register(snapshot(0));

        let publisher = WorkerPool::spawn(
            WorkerPoolConfig {
                concurrency: 1,
                pin_cores: false,
            },
            snapshot(0),
            registry,
            |mut ctx: WorkerContext| async move {
                let _ = ctx.shutdown.changed().await;
            },
        );

        publisher.publish(snapshot(9));
        assert_eq!(
            external_handle.load().version.0,
            9,
            "a handle registered outside WorkerPool::spawn must still be updated by publish()"
        );

        publisher.shutdown();
        publisher.join();
    }
}
