//! Drain state machine, per-worker connection registry, and control and worker coordination for graceful shutdown.
//!
//! Drain follows Envoy v1.38's `--drain-time-s` and `--drain-strategy`. The listener manager closes the listening
//! sockets at drain start. Each HTTP connection then shuts down gracefully (an idle keep-alive closes, an in-flight
//! request finishes, then `Connection: close` or `GOAWAY`), at a moment the strategy picks: at once under
//! [`DrainStrategy::Immediate`], spread over the window under [`DrainStrategy::Gradual`]
//! ([`connection_drain_delay`], [`drain_close`]). Those reactions live in `listener.rs`. This module holds the state
//! they watch, the schedule, and the per-worker registry.

use std::cell::Cell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::time::{Duration, Instant};

use proxy_http::handler::{HttpRequestParts, HttpResponseParts, StreamHandler};
use tokio::sync::{mpsc, watch, Notify};

use crate::runtime::WorkerId;

/// Envoy's default `--drain-time-s`. Connections still open after this long are force-closed.
pub const DEFAULT_DRAIN_TIME: Duration = Duration::from_secs(600);

/// Drain state broadcast from the control runtime to every worker. It is `Copy`, and it crosses over a `watch`
/// channel, per ADR-0003 ("cross-worker interaction is explicit message passing").
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

/// Envoy's `--drain-strategy`: when, inside the drain window, each HTTP connection is told to close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DrainStrategy {
    /// Every connection is told to close at drain start. Envoy's default.
    #[default]
    Immediate,
    /// Closes spread over the window, so clients behind a balancer do not all reconnect at once: each connection
    /// starts its close at its own point in the first quarter ([`connection_drain_delay`]), or earlier when a request
    /// draws a close ([`drain_close`]).
    Gradual,
}

/// How long after drain start one connection starts its graceful close. Envoy's `DrainManagerImpl::
/// startDrainSequence` runs the on-drain callbacks spaced evenly over the first quarter of the window: callback `slot`
/// of `slots` waits `slot / 4 / slots` of it, so the first fires at once and every connection keeps at least three
/// quarters of the window to finish. A slot at or past `slots` (a connection that registered after drain start) waits
/// the full quarter. Zero unless the drain is gradual.
pub fn connection_drain_delay(state: DrainState, slot: usize, slots: usize) -> Duration {
    let DrainState::Draining {
        started,
        until,
        strategy: DrainStrategy::Gradual,
    } = state
    else {
        return Duration::ZERO;
    };
    let slots = slots.max(1);
    let window = until.saturating_duration_since(started);
    window.mul_f64(slot.min(slots) as f64 / 4.0 / slots as f64)
}

/// Envoy's `DrainManagerImpl::drainClose`: whether a request handled at `now` should close its connection. Never
/// outside a drain, always under `immediate`; under `gradual` with a probability that rises linearly from 0 at drain
/// start to 1 at the deadline. `draw` is uniform in `[0, 1)`; it is a parameter so the schedule is testable.
pub fn drain_close(state: DrainState, now: Instant, draw: f64) -> bool {
    match state {
        DrainState::NotDraining => false,
        DrainState::Draining {
            strategy: DrainStrategy::Immediate,
            ..
        } => true,
        DrainState::Draining {
            started,
            until,
            strategy: DrainStrategy::Gradual,
        } => {
            let window = until.saturating_duration_since(started);
            if now >= until || window.is_zero() {
                return true;
            }
            let elapsed = now.saturating_duration_since(started);
            draw < elapsed.as_secs_f64() / window.as_secs_f64()
        }
    }
}

/// Resolves when a drain tells this HTTP connection to start its graceful close: at drain start under `immediate`;
/// under `gradual` at its slot's [`connection_drain_delay`], or earlier once `close_now` fires (a request on the
/// connection drew a close, see [`DrainCloseHandler`]). Never resolves outside a drain, like [`drain_started`].
pub async fn connection_drain_close(
    drain: &mut watch::Receiver<DrainState>,
    registry: &ConnectionRegistry,
    close_now: &Notify,
) {
    drain_started(drain).await;
    let state = *drain.borrow();
    let DrainState::Draining {
        started,
        strategy: DrainStrategy::Gradual,
        ..
    } = state
    else {
        return;
    };
    let (slot, slots) = registry.take_drain_slot();
    let at = started + connection_drain_delay(state, slot, slots);
    tokio::select! {
        _ = tokio::time::sleep_until(at.into()) => {}
        _ = close_now.notified() => {}
    }
}

/// Applies [`drain_close`] to each request one HTTP connection handles, then hands the request on. A close it draws
/// fires the connection's `close_now`, which starts the connection's graceful close while the request is in flight,
/// so the request's response is the connection's last (`Connection: close` on HTTP/1, GOAWAY on HTTP/2).
///
/// Envoy draws when it encodes the response headers; this draws when the request reaches the handler, the last point
/// that is still before the response head on both codecs (`internal-docs/envoy-divergences.md`, "Drain strategy").
pub struct DrainCloseHandler {
    inner: Rc<dyn StreamHandler>,
    drain: watch::Receiver<DrainState>,
    close_now: Rc<Notify>,
}

impl DrainCloseHandler {
    pub fn new(
        inner: Rc<dyn StreamHandler>,
        drain: watch::Receiver<DrainState>,
        close_now: Rc<Notify>,
    ) -> Self {
        Self {
            inner,
            drain,
            close_now,
        }
    }
}

impl StreamHandler for DrainCloseHandler {
    fn handle<'a>(
        &'a self,
        req: HttpRequestParts,
    ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>> {
        let state = *self.drain.borrow();
        if state != DrainState::NotDraining && drain_close(state, Instant::now(), rand::random()) {
            // Rust note: `notify_one` stores a permit when nobody waits yet, so a close drawn before the
            // connection's drain future first polls `notified()` is not lost.
            self.close_now.notify_one();
        }
        self.inner.handle(req)
    }
}

/// Resolves once `drain` reports [`DrainState::Draining`], immediately if it already does. It never resolves if the
/// sender was dropped without draining, so a torn-down publisher cannot look like a drain.
pub async fn drain_started(drain: &mut watch::Receiver<DrainState>) {
    loop {
        if matches!(*drain.borrow_and_update(), DrainState::Draining { .. }) {
            return;
        }
        if drain.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Worker-local registry of live connections, consulted by [`drain_worker`]'s `wait_empty` race against the drain
/// deadline.
///
/// Rust note: `!Send` (built on `Rc` and `Cell`, not `Arc` and atomics). Each worker owns exactly one, so no atomics
/// or locks are needed (ADR-0003).
#[derive(Clone)]
pub struct ConnectionRegistry {
    inner: Rc<RegistryInner>,
}

struct RegistryInner {
    live: Cell<usize>,
    // Rust note: `Notify` wakes anyone awaiting `notified()` without a payload, so the `live` count is re-checked after
    // each wake.
    empty: Notify,
    /// The gradual drain's close order: `(next slot, slots)`, set when the first connection takes a slot.
    drain_slots: Cell<Option<(usize, usize)>>,
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
                drain_slots: Cell::new(None),
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

    /// This connection's place in the gradual drain's close order, as `(slot, slots)` for
    /// [`connection_drain_delay`]. `slots` is the live count when the first connection asks, which is at drain start;
    /// it also counts TCP proxy connections, which take no slot, so HTTP closes then end before the quarter.
    pub fn take_drain_slot(&self) -> (usize, usize) {
        let (slot, slots) = self.inner.drain_slots.get().unwrap_or((0, self.live()));
        self.inner.drain_slots.set(Some((slot + 1, slots)));
        (slot, slots)
    }

    /// Resolves as soon as the live count reaches 0 -- immediately if it's
    /// already 0.
    pub async fn wait_empty(&self) {
        loop {
            if self.inner.live.get() == 0 {
                return;
            }
            // Rust note: `notify_waiters` wakes only tasks already awaiting `notified()` and stores nothing for later. That
            // would be a missed-wakeup race under multi-threading. It is safe here because the registry is `!Send` on a
            // current-thread runtime: no await point separates the count check from the first poll of `notified()`, so no
            // guard can drop in that gap.
            self.inner.empty.notified().await;
        }
    }
}

/// RAII handle for one registered connection. The connection is unregistered on `Drop`, so nothing needs an explicit
/// `unregister()` call.
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

/// Control-side drain coordination: broadcasts [`DrainState`] to every worker and tracks which have reported back
/// (registry empty, or the deadline passed).
///
/// Owned by [`crate::runtime::ConfigPublisher`], which is the public surface (`start_drain`, `wait_drained`).
pub struct DrainCoordinator {
    drain_tx: watch::Sender<DrainState>,
    done_tx: mpsc::UnboundedSender<WorkerId>,
    done_rx: mpsc::UnboundedReceiver<WorkerId>,
    worker_count: usize,
}

impl DrainCoordinator {
    /// Builds a coordinator for `worker_count` workers. Clone the returned `watch::Receiver` once per worker into
    /// [`crate::runtime::WorkerContext::drain`], and clone the `mpsc` sender into each worker's `drain_done`.
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

    /// Broadcasts a draining state to every worker, lasting `duration`, with `strategy`. Returns the deadline (`started + duration`),
    /// so the caller waits on the same instant the workers use.
    pub fn start_drain(&self, duration: Duration, strategy: DrainStrategy) -> Instant {
        let started = Instant::now();
        let until = started + duration;
        let _ = self.drain_tx.send(DrainState::Draining {
            started,
            until,
            strategy,
        });
        until
    }

    /// Wait until every worker has reported drain_done, or `deadline`
    /// passes -- whichever comes first.
    pub async fn wait_drained(&mut self, deadline: Instant) -> DrainOutcome {
        let mut reported: HashMap<WorkerId, ()> = HashMap::with_capacity(self.worker_count);

        loop {
            // Consume reports already buffered BEFORE judging the deadline. After an admin drain the workers finish early,
            // and a report that arrives after the deadline must still count as drained.
            while let Ok(id) = self.done_rx.try_recv() {
                reported.insert(id, ());
            }
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

/// Worker-side drain routine: waits for a drain signal, races the registry emptying against the drain deadline, then
/// reports to the control runtime via `drain_done`. Worker mains compose it with `tokio::task::spawn_local`.
pub async fn drain_worker(
    id: WorkerId,
    mut drain: watch::Receiver<DrainState>,
    drain_done: mpsc::UnboundedSender<WorkerId>,
    registry: ConnectionRegistry,
) {
    // Wait for a drain to start. `NotDraining` is the initial value, so the first `changed()`, or an already-draining
    // value seen via `borrow()`, is what we want.
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

    fn draining(strategy: DrainStrategy, window: Duration) -> (DrainState, Instant) {
        let started = Instant::now();
        let state = DrainState::Draining {
            started,
            until: started + window,
            strategy,
        };
        (state, started)
    }

    #[test]
    fn gradual_spaces_connection_closes_evenly_over_the_first_quarter() {
        let window = Duration::from_secs(40);
        let (gradual, _) = draining(DrainStrategy::Gradual, window);
        // (slot, slots, delay): Envoy's `slot / 4 / slots` of the window. A slot past the end waits the full quarter.
        for (slot, slots, secs) in [
            (0, 4, 0.0),
            (1, 4, 2.5),
            (3, 4, 7.5),
            (4, 4, 10.0),
            (9, 4, 10.0),
            (0, 0, 0.0),
        ] {
            assert_eq!(
                connection_drain_delay(gradual, slot, slots),
                Duration::from_secs_f64(secs),
                "slot {slot} of {slots}"
            );
        }
        let (immediate, _) = draining(DrainStrategy::Immediate, window);
        assert_eq!(connection_drain_delay(immediate, 3, 4), Duration::ZERO);
        assert_eq!(
            connection_drain_delay(DrainState::NotDraining, 3, 4),
            Duration::ZERO
        );
    }

    #[test]
    fn drain_close_probability_rises_linearly_over_the_window() {
        let window = Duration::from_secs(100);
        let (gradual, started) = draining(DrainStrategy::Gradual, window);
        // (seconds since drain start, draw, closes)
        for (at, draw, closes) in [
            (0.0, 0.0, false),
            (50.0, 0.49, true),
            (50.0, 0.51, false),
            (99.0, 0.98, true),
            (100.0, 0.999, true),
            (500.0, 0.999, true),
        ] {
            let now = started + Duration::from_secs_f64(at);
            assert_eq!(
                drain_close(gradual, now, draw),
                closes,
                "at {at}s, draw {draw}"
            );
        }
        let (immediate, started) = draining(DrainStrategy::Immediate, window);
        assert!(drain_close(immediate, started, 0.999));
        assert!(!drain_close(DrainState::NotDraining, started, 0.0));
        let (zero, started) = draining(DrainStrategy::Gradual, Duration::ZERO);
        assert!(drain_close(zero, started, 0.999), "a zero window closes");
    }

    #[test]
    fn drain_close_handler_signals_a_drawn_close_and_still_serves_the_request() {
        use http_body_util::BodyExt;
        use proxy_http::filter::RequestHeaders;
        use proxy_http::handler::{local_boxed, stub::FixedResponseHandler, DownstreamInfo};

        fn request() -> HttpRequestParts {
            HttpRequestParts {
                head: RequestHeaders {
                    method: http::Method::GET,
                    uri: "/".parse().unwrap(),
                    headers: http::HeaderMap::new(),
                },
                body: local_boxed(
                    http_body_util::Empty::<bytes::Bytes>::new().map_err(|never| match never {}),
                ),
                downstream: DownstreamInfo::loopback(),
                on_upgrade: None,
            }
        }

        run_local(async {
            let inner: Rc<dyn StreamHandler> = Rc::new(FixedResponseHandler {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: bytes::Bytes::from_static(b"ok"),
            });
            let (drain_tx, drain_rx) = watch::channel(DrainState::NotDraining);
            let close_now = Rc::new(Notify::new());
            let handler = DrainCloseHandler::new(inner, drain_rx, close_now.clone());
            let signalled = || async {
                tokio::time::timeout(Duration::from_millis(50), close_now.notified())
                    .await
                    .is_ok()
            };

            let response = handler.handle(request()).await;
            assert_eq!(response.head.status, http::StatusCode::OK);
            assert!(!signalled().await, "no drain, no close");

            // Past the deadline the gradual draw always closes.
            let started = Instant::now() - Duration::from_secs(10);
            drain_tx
                .send(DrainState::Draining {
                    started,
                    until: started + Duration::from_secs(1),
                    strategy: DrainStrategy::Gradual,
                })
                .unwrap();
            let response = handler.handle(request()).await;
            assert_eq!(response.head.status, http::StatusCode::OK);
            assert!(signalled().await, "a drawn close must reach the connection");
        });
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
            publisher.start_drain(Duration::from_millis(500), DrainStrategy::Immediate);
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
                    // Worker 0 holds a guard for the whole test, so its registry never empties. `drain_worker` returns
                    // only when its own deadline fires.
                    let _guard = registry.register();
                    drain_worker(ctx.id, ctx.drain, ctx.drain_done, registry).await;
                } else {
                    // Worker 1 has nothing registered, so `wait_empty` resolves at once and it reports before the
                    // coordinator's deadline.
                    drain_worker(ctx.id, ctx.drain, ctx.drain_done, registry).await;
                }
            },
        );

        run_local(async {
            // Give workers a drain window longer than the coordinator's deadline below. The coordinator gives up first,
            // with worker 0 still pending, so `DeadlineExpired` is exercised deterministically.
            publisher.start_drain(Duration::from_secs(5), DrainStrategy::Immediate);
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
    fn wait_drained_counts_reports_buffered_before_a_deadline_that_already_passed() {
        run_local(async {
            let (mut coordinator, _rx) = DrainCoordinator::new(2);
            let done = coordinator.done_sender();
            let past = Instant::now();
            // Both workers drained early (an admin drain); the deadline is
            // read only afterwards, as when a signal arrives much later.
            done.send(WorkerId(0)).unwrap();
            done.send(WorkerId(1)).unwrap();

            let outcome = coordinator.wait_drained(past).await;
            assert!(
                matches!(outcome, DrainOutcome::Completed),
                "everyone had reported: {outcome:?}"
            );
        });
    }

    #[test]
    fn drain_started_resolves_when_already_draining_and_stays_pending_otherwise() {
        run_local(async {
            let (coordinator, mut rx) = DrainCoordinator::new(1);
            // Not draining: must not resolve.
            let pending =
                tokio::time::timeout(Duration::from_millis(50), drain_started(&mut rx)).await;
            assert!(pending.is_err(), "NotDraining must not look like a drain");

            coordinator.start_drain(Duration::from_secs(60), DrainStrategy::Immediate);
            tokio::time::timeout(Duration::from_secs(5), drain_started(&mut rx))
                .await
                .expect("a drain that started before the call must still resolve it");
        });
    }
}
