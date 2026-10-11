//! Process lifecycle state shared by the admin server, the signal loop, and
//! the readiness probe.
//!
//! One place answers "should this process be out of rotation?" so that
//! `/healthcheck/fail`, `POST /drain_listeners`, and SIGTERM cannot disagree
//! about what `/ready` reports. Drain is one-way (listeners are closed and
//! cannot be reopened); a health-check failure is reversible.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

// Rust note: every flag below is an independent boolean read and written on
// its own, with no other memory that must be observed in a matching order, so
// `Relaxed` is enough. The one cross-task handoff (waking the signal loop)
// goes through `Notify`, which does its own synchronization.
#[derive(Debug, Default)]
pub struct LifecycleState {
    health_check_failed: AtomicBool,
    draining: AtomicBool,
    listener_bound: AtomicBool,
    drain_requested: Notify,
}

impl LifecycleState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes `/ready` answer DRAINING until [`Self::restore_health_check`].
    pub fn fail_health_check(&self) {
        self.health_check_failed.store(true, Ordering::Relaxed);
    }

    /// Clears the health-check failure. Never undoes a drain.
    pub fn restore_health_check(&self) {
        self.health_check_failed.store(false, Ordering::Relaxed);
    }

    /// Marks the process draining (one-way) and wakes the signal loop.
    /// Returns true only for the call that started the drain.
    pub fn request_drain(&self) -> bool {
        let first = !self.draining.swap(true, Ordering::Relaxed);
        if first {
            // `notify_one` stores a permit when nobody is waiting yet, so a
            // request that lands before the signal loop awaits is not lost.
            self.drain_requested.notify_one();
        }
        first
    }

    /// Resolves once a drain has been requested through
    /// [`Self::request_drain`]. The binary's signal loop awaits this next to
    /// its OS signals.
    pub async fn drain_requested(&self) {
        self.drain_requested.notified().await;
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Records that a worker has bound at least one listener. Monotonic.
    pub fn mark_listener_bound(&self) {
        self.listener_bound.store(true, Ordering::Relaxed);
    }

    /// True once any worker has bound at least one listener.
    pub fn listener_bound(&self) -> bool {
        self.listener_bound.load(Ordering::Relaxed)
    }

    /// True when `/ready` must answer DRAINING: health check failed or
    /// draining.
    pub fn out_of_rotation(&self) -> bool {
        self.health_check_failed.load(Ordering::Relaxed) || self.is_draining()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn request_drain_returns_true_only_for_the_first_call() {
        let state = LifecycleState::new();
        assert!(state.request_drain());
        assert!(!state.request_drain());
        assert!(state.is_draining());
    }

    #[test]
    fn restore_health_check_does_not_clear_a_drain() {
        let state = LifecycleState::new();
        state.fail_health_check();
        state.request_drain();
        state.restore_health_check();
        assert!(
            state.out_of_rotation(),
            "drain must outlive /healthcheck/ok"
        );
    }

    #[tokio::test]
    async fn a_drain_requested_before_anyone_waits_still_wakes_a_later_waiter() {
        let state = LifecycleState::new();
        state.request_drain();
        tokio::time::timeout(Duration::from_secs(5), state.drain_requested())
            .await
            .expect("stored permit must wake the late waiter");
    }
}
