//! Drain state machine, per-worker connection registry, and control/worker
//! coordination for graceful shutdown.
//!
//! Drain semantics follow Envoy v1.38 (`--drain-time-s`, `--drain-strategy`):
//! during a drain window connections are progressively encouraged to close on
//! request completion (`Connection: close` on HTTP/1, `GOAWAY` on HTTP/2).
//! Those protocol nudges live in the HTTP codecs; this module only
//! builds the seam they consult (`DrainState::drain_close_probability`) plus
//! the registry and coordination machinery around it.

use std::cell::Cell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch, Notify};

use crate::runtime::WorkerId;

/// Envoy's default `--drain-time-s`.
///
/// See Envoy v1.38 docs: the drain sequence lasts this long before
/// connections still open are forcibly closed.
pub const DEFAULT_DRAIN_TIME: Duration = Duration::from_secs(600);

/// How aggressively requests are encouraged to drain over the drain window.
///
/// Rust note: `#[default]` on a variant (stable since Rust 1.62) lets us
/// derive `Default` while still picking a specific variant -- here, the
/// Envoy-parity choice that gradual is the default strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DrainStrategy {
    /// The probability that a response is closed ramps linearly from 0% at
    /// the start of the drain window to 100% at the deadline. Matches
    /// Envoy's `--drain-strategy=gradual` (the default).
    #[default]
    Gradual,
    /// All requests are encouraged to drain as soon as the drain sequence
    /// begins. Matches Envoy's `--drain-strategy=immediate`.
    Immediate,
}

/// Drain state broadcast from the control runtime to every worker.
///
/// `Send + Sync` (in fact `Copy`): it crosses control -> worker over a
/// `tokio::sync::watch` channel per ADR-0003 ("cross-worker interaction is
/// explicit message passing").
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum DrainState {
    #[default]
    NotDraining,
    Draining {
        started: Instant,
        until: Instant,
        strategy: DrainStrategy,
    },
}

impl DrainState {
    /// The probability that an in-flight response should be closed (rather
    /// than kept alive) at `now`. This is the seam HTTP codecs
    /// will consult per-response.
    ///
    /// Deliberately a pure function of `now` -- no RNG here -- so tests (and
    /// callers, who supply their own randomness if they want jitter) get
    /// deterministic behavior.
    pub fn drain_close_probability(&self, now: Instant) -> f64 {
        match *self {
            DrainState::NotDraining => 0.0,
            DrainState::Draining {
                started,
                until,
                strategy,
            } => match strategy {
                DrainStrategy::Immediate => 1.0,
                DrainStrategy::Gradual => {
                    if now <= started {
                        0.0
                    } else if now >= until {
                        1.0
                    } else {
                        let total = (until - started).as_secs_f64();
                        let elapsed = (now - started).as_secs_f64();
                        if total <= 0.0 {
                            1.0
                        } else {
                            (elapsed / total).clamp(0.0, 1.0)
                        }
                    }
                }
            },
        }
    }
}

/// Worker-local registry of live connections, consulted by
/// [`drain_worker`]'s `wait_empty` race against the drain deadline.
///
/// Rust note: deliberately `!Send` (built on `Rc`/`Cell`, not `Arc`/atomics)
/// per ADR-0003 -- each worker owns exactly one of these, never shared
/// across threads, so there is no need to pay for atomics or locking.
#[derive(Clone)]
pub struct ConnectionRegistry {
    inner: Rc<RegistryInner>,
}

struct RegistryInner {
    live: Cell<usize>,
    // Rust note: `Notify` gives us "wake anyone awaiting `notified()`"
    // without a full channel; we re-check the `live` count after each wake
    // since `Notify` doesn't carry a payload.
    empty: Notify,
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionRegistry {
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RegistryInner {
                live: Cell::new(0),
                empty: Notify::new(),
            }),
        }
    }

    /// Register a new live connection. The returned guard decrements the
    /// count when dropped (i.e. when the connection ends).
    pub fn register(&self) -> ConnectionGuard {
        self.inner.live.set(self.inner.live.get() + 1);
        ConnectionGuard {
            inner: self.inner.clone(),
        }
    }

    pub fn live(&self) -> usize {
        self.inner.live.get()
    }

    /// Resolves as soon as the live count reaches 0 -- immediately if it's
    /// already 0.
    pub async fn wait_empty(&self) {
        loop {
            if self.inner.live.get() == 0 {
                return;
            }
            // Rust note: `notify_waiters` (used in ConnectionGuard::drop)
            // wakes only tasks *already* awaiting `notified()` -- it stores
            // nothing for later. That would be a missed-wakeup race in
            // multi-threaded code (drop could fire between our count check
            // and this await). It is safe here only because this registry is
            // `!Send` on a current-thread runtime: there is no await point
            // between the check above and the first poll of `notified()`
            // (which registers us), so no other task can run -- and thus no
            // guard can drop -- in that gap.
            self.inner.empty.notified().await;
        }
    }
}

/// RAII handle for a single registered connection. Rust note: this is the
/// idiomatic "resource acquired, released on `Drop`" pattern -- nothing needs
/// to remember to call an explicit `unregister()`; scope does it.
pub struct ConnectionGuard {
    inner: Rc<RegistryInner>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let remaining = self.inner.live.get() - 1;
        self.inner.live.set(remaining);
        if remaining == 0 {
            self.inner.empty.notify_waiters();
        }
    }
}

/// Result of [`DrainCoordinator::wait_drained`]: did every worker report
/// drain_done before the deadline, or did the deadline win?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    Completed,
    DeadlineExpired { workers_pending: usize },
}

/// Control-side drain coordination: broadcasts [`DrainState`] to every
/// worker and tracks which workers have reported back that they've drained
/// (registry empty, or they gave up at the deadline).
///
/// Owned by [`crate::runtime::ConfigPublisher`], which is the public surface
/// callers use (`publisher.start_drain(..)` / `publisher.wait_drained(..)`);
/// this type just keeps that coordination logic in one cohesive place
/// instead of spreading `watch`/`mpsc` bookkeeping across `runtime.rs`.
pub struct DrainCoordinator {
    drain_tx: watch::Sender<DrainState>,
    done_tx: mpsc::UnboundedSender<WorkerId>,
    done_rx: mpsc::UnboundedReceiver<WorkerId>,
    worker_count: usize,
}

impl DrainCoordinator {
    /// Build a coordinator for `worker_count` workers. The returned
    /// `watch::Receiver` should be cloned once per worker into their
    /// [`crate::runtime::WorkerContext::drain`]; the returned
    /// `mpsc::UnboundedSender` is cloned once per worker into their
    /// `drain_done` field.
    pub fn new(worker_count: usize) -> (Self, watch::Receiver<DrainState>) {
        let (drain_tx, drain_rx) = watch::channel(DrainState::NotDraining);
        let (done_tx, done_rx) = mpsc::unbounded_channel();
        (
            Self {
                drain_tx,
                done_tx,
                done_rx,
                worker_count,
            },
            drain_rx,
        )
    }

    /// The sender half workers use to report drain completion; clone one per
    /// worker into [`crate::runtime::WorkerContext::drain_done`].
    pub fn done_sender(&self) -> mpsc::UnboundedSender<WorkerId> {
        self.done_tx.clone()
    }

    /// Broadcast a new draining state to every worker, starting now and
    /// lasting `duration`.
    pub fn start_drain(&self, duration: Duration, strategy: DrainStrategy) {
        let started = Instant::now();
        let until = started + duration;
        let _ = self.drain_tx.send(DrainState::Draining {
            started,
            until,
            strategy,
        });
    }

    /// Wait until every worker has reported drain_done, or `deadline`
    /// passes -- whichever comes first.
    pub async fn wait_drained(&mut self, deadline: Instant) -> DrainOutcome {
        let mut reported: HashMap<WorkerId, ()> = HashMap::with_capacity(self.worker_count);

        loop {
            if reported.len() >= self.worker_count {
                return DrainOutcome::Completed;
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return DrainOutcome::DeadlineExpired {
                    workers_pending: self.worker_count - reported.len(),
                };
            }

            tokio::select! {
                recv = self.done_rx.recv() => {
                    match recv {
                        Some(id) => {
                            reported.insert(id, ());
                        }
                        None => {
                            // All senders dropped (every worker gone) --
                            // treat as everyone having reported.
                            return DrainOutcome::Completed;
                        }
                    }
                }
                _ = tokio::time::sleep(remaining) => {
                    return DrainOutcome::DeadlineExpired {
                        workers_pending: self.worker_count - reported.len(),
                    };
                }
            }
        }
    }
}

/// Worker-side drain routine: waits for a drain signal, then races the
/// registry hitting empty against the drain deadline, then reports back to
/// the control runtime via `drain_done`. Worker mains compose this with
/// `tokio::task::spawn_local`.
pub async fn drain_worker(
    id: WorkerId,
    mut drain: watch::Receiver<DrainState>,
    drain_done: mpsc::UnboundedSender<WorkerId>,
    registry: ConnectionRegistry,
) {
    // Wait for the control runtime to actually start a drain; `NotDraining`
    // is the initial value so the first `changed()` (or an already-draining
    // value observed via `borrow()`) is what we're after.
    let until = loop {
        let state = *drain.borrow();
        if let DrainState::Draining { until, .. } = state {
            break until;
        }
        if drain.changed().await.is_err() {
            // Control runtime dropped the sender -- nothing left to drain
            // for.
            return;
        }
    };

    tokio::select! {
        _ = registry.wait_empty() => {}
        _ = tokio::time::sleep_until(until.into()) => {}
    }

    let _ = drain_done.send(id);
}

/// Control-side convenience: sequences a full graceful shutdown --
/// `start_drain` -> `wait_drained` -> `shutdown` -> `join`.
///
/// SIGTERM/CLI wiring that calls this lives in the binary; this function is
/// triggered programmatically.
pub async fn graceful_shutdown(
    mut publisher: crate::runtime::ConfigPublisher,
    drain_time: Duration,
    strategy: DrainStrategy,
) -> DrainOutcome {
    publisher.start_drain(drain_time, strategy);
    let deadline = Instant::now() + drain_time;
    let outcome = publisher.wait_drained(deadline).await;
    publisher.shutdown();
    publisher.join();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{run_local, SnapshotHandles, WorkerContext, WorkerPool, WorkerPoolConfig};
    use proxy_config::ir::SnapshotVersion;
    use proxy_config::ConfigSnapshot;
    use std::sync::Arc;

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
    fn drain_close_probability_not_draining_is_zero() {
        let state = DrainState::NotDraining;
        assert_eq!(state.drain_close_probability(Instant::now()), 0.0);
    }

    #[test]
    fn drain_close_probability_immediate_is_always_one() {
        let started = Instant::now();
        let state = DrainState::Draining {
            started,
            until: started + Duration::from_secs(10),
            strategy: DrainStrategy::Immediate,
        };
        assert_eq!(state.drain_close_probability(started), 1.0);
        assert_eq!(
            state.drain_close_probability(started + Duration::from_secs(1)),
            1.0
        );
        assert_eq!(
            state.drain_close_probability(started + Duration::from_secs(100)),
            1.0
        );
    }

    #[test]
    fn drain_close_probability_gradual_ramps_linearly() {
        let started = Instant::now();
        let until = started + Duration::from_secs(10);
        let state = DrainState::Draining {
            started,
            until,
            strategy: DrainStrategy::Gradual,
        };

        assert_eq!(state.drain_close_probability(started), 0.0);
        let mid = state.drain_close_probability(started + Duration::from_secs(5));
        assert!((mid - 0.5).abs() < 1e-9, "expected ~0.5, got {mid}");
        assert_eq!(state.drain_close_probability(until), 1.0);
        assert_eq!(
            state.drain_close_probability(until + Duration::from_secs(1)),
            1.0
        );

        // Monotonic.
        let p1 = state.drain_close_probability(started + Duration::from_secs(2));
        let p2 = state.drain_close_probability(started + Duration::from_secs(6));
        assert!(p1 < p2);
    }

    #[test]
    fn registry_wait_empty_resolves_immediately_when_empty() {
        run_local(async {
            let registry = ConnectionRegistry::new();
            assert_eq!(registry.live(), 0);
            registry.wait_empty().await;
        });
    }

    #[test]
    fn registry_wait_empty_blocks_until_guard_dropped() {
        run_local(async {
            let registry = ConnectionRegistry::new();
            let guard = registry.register();
            assert_eq!(registry.live(), 1);

            let registry_clone = registry.clone();
            let waiter = tokio::task::spawn_local(async move {
                registry_clone.wait_empty().await;
            });

            // Give the waiter a chance to register interest before we drop.
            tokio::task::yield_now().await;
            drop(guard);

            waiter.await.expect("waiter task panicked");
            assert_eq!(registry.live(), 0);
        });
    }

    #[test]
    fn registry_handles_multiple_guards() {
        run_local(async {
            let registry = ConnectionRegistry::new();
            let g1 = registry.register();
            let g2 = registry.register();
            assert_eq!(registry.live(), 2);

            let registry_clone = registry.clone();
            let waiter = tokio::task::spawn_local(async move {
                registry_clone.wait_empty().await;
            });

            tokio::task::yield_now().await;
            drop(g1);
            tokio::task::yield_now().await;
            assert_eq!(registry.live(), 1);
            drop(g2);

            waiter.await.expect("waiter task panicked");
            assert_eq!(registry.live(), 0);
        });
    }

    #[test]
    fn wait_drained_completes_when_workers_release_guards() {
        let mut publisher = WorkerPool::spawn(
            WorkerPoolConfig {
                concurrency: 2,
                pin_cores: false,
            },
            snapshot(0),
            handles(),
            move |ctx: WorkerContext| async move {
                let registry = ConnectionRegistry::new();
                let guard = registry.register();

                // Drop the guard shortly after the worker starts so the
                // registry empties out well within the drain window.
                let registry_for_drop = registry.clone();
                tokio::task::spawn_local(async move {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    drop(guard);
                    let _ = registry_for_drop.live();
                });

                drain_worker(ctx.id, ctx.drain, ctx.drain_done, registry).await;
            },
        );

        run_local(async {
            publisher.start_drain(Duration::from_millis(500), DrainStrategy::Gradual);
            let deadline = Instant::now() + Duration::from_secs(5);
            let outcome = publisher.wait_drained(deadline).await;
            assert_eq!(outcome, DrainOutcome::Completed);
        });

        publisher.shutdown();
        publisher.join();
    }

    #[test]
    fn wait_drained_expires_when_a_worker_never_empties() {
        let mut publisher = WorkerPool::spawn(
            WorkerPoolConfig {
                concurrency: 2,
                pin_cores: false,
            },
            snapshot(0),
            handles(),
            move |ctx: WorkerContext| async move {
                let registry = ConnectionRegistry::new();
                if ctx.id.0 == 0 {
                    // Worker 0 holds a guard for the whole test -- its
                    // registry never empties, so `drain_worker` only
                    // returns (and reports) once its own deadline
                    // (`sleep_until(until)`) fires.
                    let _guard = registry.register();
                    drain_worker(ctx.id, ctx.drain, ctx.drain_done, registry).await;
                } else {
                    // Worker 1 has nothing registered, so its `wait_empty`
                    // resolves immediately once the drain starts and it
                    // reports done well before the coordinator's own
                    // deadline below.
                    drain_worker(ctx.id, ctx.drain, ctx.drain_done, registry).await;
                }
            },
        );

        run_local(async {
            // Give workers a drain window comfortably longer than the
            // coordinator-side deadline below, so the coordinator gives up
            // first (with worker 0 still pending) and we exercise
            // `DeadlineExpired` deterministically.
            publisher.start_drain(Duration::from_secs(5), DrainStrategy::Gradual);
            let deadline = Instant::now() + Duration::from_millis(50);
            let outcome = publisher.wait_drained(deadline).await;
            assert_eq!(
                outcome,
                DrainOutcome::DeadlineExpired { workers_pending: 1 }
            );
        });

        publisher.shutdown();
        publisher.join();
    }

    #[test]
    fn graceful_shutdown_sequences_drain_then_shutdown() {
        let publisher = WorkerPool::spawn(
            WorkerPoolConfig {
                concurrency: 1,
                pin_cores: false,
            },
            snapshot(0),
            handles(),
            move |ctx: WorkerContext| async move {
                let registry = ConnectionRegistry::new();
                drain_worker(ctx.id, ctx.drain, ctx.drain_done, registry).await;
                // After drain_worker returns, wait for the shutdown
                // signal too, mirroring how a real worker main composes
                // both seams.
                let mut shutdown = ctx.shutdown;
                let _ = shutdown.changed().await;
            },
        );

        run_local(async {
            let outcome = graceful_shutdown(
                publisher,
                Duration::from_millis(20),
                DrainStrategy::Immediate,
            )
            .await;
            assert_eq!(outcome, DrainOutcome::Completed);
        });
    }
}
