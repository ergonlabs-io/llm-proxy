//! Worker runtime pool and control -> worker config propagation (WP-06,
//! ADR-0003).
//!
//! Workers are share-nothing, `!Send` `current_thread` tokio runtimes, each
//! on a dedicated OS thread driving a `LocalSet` (optionally core-pinned).
//! Config crosses threads only as an immutable `Arc<ConfigSnapshot>`,
//! published into each worker's [`WorkerConfigHandle`] and followed by a
//! `watch` ping that wakes the worker to reload.

use std::future::Future;
use std::sync::Arc;
use std::thread::JoinHandle;

use proxy_config::ir::SnapshotVersion;
use proxy_config::ConfigSnapshot;
use tokio::runtime::Builder;
use tokio::sync::{mpsc, watch};
use tokio::task::LocalSet;

use crate::drain::{DrainCoordinator, DrainOutcome, DrainState, DrainStrategy};
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
    /// Fires whenever the control runtime calls `ConfigPublisher::publish`.
    /// The new snapshot is already visible via `config` by the time this
    /// resolves (see [`ConfigPublisher::publish`] for the ordering).
    pub config_ping: watch::Receiver<SnapshotVersion>,
    /// Flips to `true` when `ConfigPublisher::shutdown` is called.
    pub shutdown: watch::Receiver<bool>,
    /// Fires when the control runtime calls `ConfigPublisher::start_drain`
    /// (WP-06 chunk B). Worker mains hand this to
    /// [`crate::drain::drain_worker`].
    pub drain: watch::Receiver<DrainState>,
    /// The worker reports here (via `drain_worker`) once its connection
    /// registry has emptied or its drain deadline has passed.
    pub drain_done: mpsc::UnboundedSender<WorkerId>,
}

/// Owns nothing after `spawn` returns; it only exists to give `spawn` a
/// natural home (`WorkerPool::spawn(...)`). The real handles a caller needs
/// -- to publish config, to shut down, to join -- live on [`ConfigPublisher`].
pub struct WorkerPool;

impl WorkerPool {
    /// Spawn `config.concurrency` worker threads, each running a
    /// `current_thread` tokio runtime + `LocalSet`, and return the
    /// [`ConfigPublisher`] the control runtime uses to talk to them.
    ///
    /// `worker_main` is called once per worker, *on that worker's own OS
    /// thread*, to build the future which then drives the worker's
    /// `LocalSet`. It has to run there: the `!Send` future it returns could
    /// not be moved onto the worker thread after the fact.
    ///
    /// Rust note: the bound is deliberately asymmetric. `worker_main` (the
    /// closure *factory*) must be `Send + Clone + 'static` so a copy of it
    /// can move into each new `std::thread::spawn`. But the future `F` it
    /// returns is *not* required to be `Send` -- per ADR-0003 it is built
    /// and polled entirely on the worker thread it was created on (via
    /// `LocalSet::block_on`) and may hold `Rc`/`RefCell`/other `!Send`
    /// worker-local state across an `.await`.
    pub fn spawn<F, W>(
        config: WorkerPoolConfig,
        initial_snapshot: Arc<ConfigSnapshot>,
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
        let mut handles = Vec::with_capacity(config.concurrency);
        let mut config_txs = Vec::with_capacity(config.concurrency);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        // Rust note: `DrainCoordinator::new` hands back one `watch::Receiver`
        // that every worker clones (watch receivers are `Clone`) plus the
        // coordinator itself, which owns the `mpsc` sender side worker
        // clones report drain completion through.
        let (drain_coordinator, drain_rx) = DrainCoordinator::new(config.concurrency);
        let drain_done_tx = drain_coordinator.done_sender();

        for i in 0..config.concurrency {
            let id = WorkerId(i);
            let handle = Arc::new(WorkerConfigHandle::new(initial_snapshot.clone()));
            let (config_tx, config_rx) = watch::channel(initial_snapshot.version);
            let shutdown_rx = shutdown_rx.clone();
            let drain_rx = drain_rx.clone();
            let drain_done_tx = drain_done_tx.clone();
            let worker_main = worker_main.clone();
            let handle_for_thread = handle.clone();

            let core_id = core_ids.as_ref().and_then(|ids| ids.get(i).copied());
            if config.pin_cores && core_id.is_none() {
                tracing::warn!(
                    worker = i,
                    "no CPU core available to pin to (pin_cores requested); running unpinned"
                );
            }

            let thread = std::thread::Builder::new()
                .name(format!("worker-{i}"))
                .spawn(move || {
                    if let Some(core_id) = core_id {
                        if !core_affinity::set_for_current(core_id) {
                            tracing::warn!(
                                worker = i,
                                "failed to pin worker to core, continuing unpinned"
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
                    };

                    // Rust note: `new_current_thread` + `LocalSet` is the
                    // `!Send` half of ADR-0003. Everything spawned with
                    // `tokio::task::spawn_local` inside this `LocalSet` is
                    // pinned to this OS thread for its whole lifetime, so
                    // data-plane code can reach for `Rc`/`RefCell` instead of
                    // `Arc`/`Mutex` on the hot path.
                    let rt = Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("failed to build worker runtime");
                    let local = LocalSet::new();
                    local.block_on(&rt, worker_main(ctx));
                })
                .expect("failed to spawn worker thread");

            threads.push(thread);
            handles.push(handle);
            config_txs.push(config_tx);
        }

        ConfigPublisher {
            handles,
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
    handles: Vec<Arc<WorkerConfigHandle>>,
    config_txs: Vec<watch::Sender<SnapshotVersion>>,
    shutdown_tx: watch::Sender<bool>,
    threads: Vec<JoinHandle<()>>,
    /// Drain coordination (WP-06 chunk B): kept here, not as a separate
    /// handle callers juggle alongside this one, so "publish config",
    /// "shut down", and "drain" all live on the one control-side type.
    drain: DrainCoordinator,
}

impl ConfigPublisher {
    /// Publish a new snapshot to every worker.
    ///
    /// Ordering matters: this stores into every worker's
    /// [`WorkerConfigHandle`] *before* sending the `watch` ping. That way a
    /// worker woken by the ping is guaranteed to observe the new snapshot the
    /// moment it calls `config.load()` -- it can never race ahead of the
    /// store and see a stale one.
    pub fn publish(&self, snapshot: Arc<ConfigSnapshot>) {
        for handle in &self.handles {
            handle.store(snapshot.clone());
        }
        for tx in &self.config_txs {
            // Rust note: `send` only errors if every receiver was dropped
            // (i.e. the worker thread is gone); that's not our problem to
            // report here, so we ignore it rather than unwrap.
            let _ = tx.send(snapshot.version);
        }
    }

    /// Signal every worker to shut down. Does not wait for them; call
    /// [`ConfigPublisher::join`] for that.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Begin a drain: broadcast the new [`DrainState`] to every worker.
    /// Workers see this via `WorkerContext::drain` and react through
    /// [`crate::drain::drain_worker`].
    pub fn start_drain(&self, duration: std::time::Duration, strategy: DrainStrategy) {
        self.drain.start_drain(duration, strategy);
    }

    /// Wait until every worker has reported drain completion, or `deadline`
    /// passes -- whichever comes first.
    pub async fn wait_drained(&mut self, deadline: std::time::Instant) -> DrainOutcome {
        self.drain.wait_drained(deadline).await
    }

    /// Block until every worker thread has exited.
    pub fn join(self) {
        for thread in self.threads {
            // A worker thread panicking is a bug we want surfaced, not
            // swallowed -- but `join`'s `Err` is a `Box<dyn Any>`, not
            // something we can usefully act on here beyond logging.
            if let Err(err) = thread.join() {
                tracing::error!(?err, "worker thread panicked");
            }
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
            move |mut ctx: WorkerContext| {
                let result_tx = result_tx.clone();
                async move {
                    // Wait for the ping, then report what the snapshot looks
                    // like *after* seeing it -- proving publish()'s
                    // store-then-ping ordering.
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
        // Proves the !Send seam compiles: an `Rc` (which is !Send and
        // !Sync) lives across an `.await` inside the future returned by
        // `worker_main`. This would fail to compile if `WorkerPool::spawn`
        // required `F: Send`.
        let done = Arc::new(AtomicUsize::new(0));
        let done_for_worker = done.clone();

        let publisher = WorkerPool::spawn(
            WorkerPoolConfig {
                concurrency: 1,
                pin_cores: false,
            },
            snapshot(0),
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
}
