//! Process-wide downstream connection admission.
//!
//! Envoy's `global_downstream_max_connections` caps open downstream connections across every worker and listener
//! (`internal-docs/envoy-semantics.md` S4; departures are in `envoy-divergences.md`). Workers are single-threaded
//! `LocalSet`s (ADR-0003), but the cap is global, so this counter must be `Send + Sync`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Shared counter of live downstream connections. Cloning shares the count. The limit is not stored here: each accept
/// reads it from the current snapshot, so a reload applies to the next accept.
#[derive(Clone, Default)]
pub struct ConnectionLimiter {
    inner: Arc<LimiterInner>,
}

#[derive(Default)]
struct LimiterInner {
    live: AtomicU64,
    /// Latched by the first non-exempt accept that finds no limit
    /// configured, so the warning is logged once per process.
    warned_unlimited: AtomicBool,
}

/// RAII claim on one connection slot. Dropping it releases the slot, however the connection task ends.
pub struct ConnectionSlot {
    // `None` for exempt listeners (`ignore_global_conn_limit`), which are
    // neither checked against nor counted toward the limit.
    counted: Option<Arc<LimiterInner>>,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        if let Some(inner) = &self.counted {
            inner.live.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl ConnectionLimiter {
    /// Tries to admit one connection. `limit` is `ConfigSnapshot::max_downstream_connections` (`None` is unlimited).
    /// `exempt` is the listener's `ignore_global_conn_limit`. Returns `None` when the connection must close. The check
    /// and the increment are one compare-and-swap loop, so two workers cannot both take the last slot.
    pub fn try_acquire(&self, limit: Option<u64>, exempt: bool) -> Option<ConnectionSlot> {
        if exempt {
            return Some(ConnectionSlot { counted: None });
        }
        let live = &self.inner.live;
        let mut current = live.load(Ordering::Acquire);
        loop {
            if limit.is_some_and(|max| current >= max) {
                return None;
            }
            match live.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        if limit.is_none() && !self.inner.warned_unlimited.swap(true, Ordering::Relaxed) {
            // Fail-open path (AGENTS.md "Fail-open controls"): availability
            // wins when no limit is configured, so say so loudly, once.
            tracing::warn!(
                "there is no configured limit to the number of allowed active downstream \
                 connections; configure max_active_downstream_connections on the \
                 envoy.resource_monitors.global_downstream_max_connections overload resource monitor"
            );
        }
        Some(ConnectionSlot {
            counted: Some(self.inner.clone()),
        })
    }

    /// Live counted connections (exempt listeners excluded).
    pub fn live(&self) -> u64 {
        self.inner.live.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_is_enforced_and_slots_release_on_drop() {
        let limiter = ConnectionLimiter::default();
        let a = limiter.try_acquire(Some(2), false).expect("first");
        let _b = limiter.try_acquire(Some(2), false).expect("second");
        assert!(limiter.try_acquire(Some(2), false).is_none(), "over limit");
        drop(a);
        assert_eq!(limiter.live(), 1);
        assert!(limiter.try_acquire(Some(2), false).is_some(), "slot freed");
    }

    #[test]
    fn lowered_limit_applies_to_the_next_acquire() {
        let limiter = ConnectionLimiter::default();
        let _held: Vec<_> = (0..3)
            .map(|_| limiter.try_acquire(Some(10), false).unwrap())
            .collect();
        assert!(limiter.try_acquire(Some(3), false).is_none());
        assert!(limiter.try_acquire(Some(4), false).is_some());
    }

    #[test]
    fn exempt_connections_bypass_and_are_not_counted() {
        let limiter = ConnectionLimiter::default();
        let _held = limiter.try_acquire(Some(1), false).unwrap();
        let exempt = limiter.try_acquire(Some(1), true);
        assert!(exempt.is_some(), "exempt listener bypasses a full limit");
        assert_eq!(limiter.live(), 1, "exempt connection is not counted");
        drop(exempt);
        assert_eq!(limiter.live(), 1);
    }

    /// A `tracing` writer that appends to a shared buffer.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn unlimited_warning_is_logged_once_and_only_where_the_control_applies() {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let limiter = ConnectionLimiter::default();
            // An exempt listener is not subject to the control: silent.
            let _exempt = limiter.try_acquire(None, true);
            assert!(captured.0.lock().unwrap().is_empty());
            // A configured limit is not the fail-open path: silent.
            let _limited = limiter.try_acquire(Some(10), false);
            assert!(captured.0.lock().unwrap().is_empty());
            // No limit on a listener the control applies to: one warning,
            // however many accepts follow.
            let _slots: Vec<_> = (0..5).map(|_| limiter.try_acquire(None, false)).collect();
            // A second limiter (a different process) would warn again; the
            // same one never does.
            let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
            assert_eq!(text.matches("no configured limit").count(), 1, "{text}");
            assert!(text.contains("WARN"), "{text}");
        });
    }

    #[test]
    fn concurrent_acquires_never_exceed_the_limit() {
        let limiter = ConnectionLimiter::default();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let limiter = limiter.clone();
                std::thread::spawn(move || {
                    (0..100)
                        .filter_map(|_| limiter.try_acquire(Some(5), false))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        // Hold every admitted slot until all threads finish, so nothing is
        // released mid-run and the total must equal the limit exactly.
        let held: Vec<Vec<ConnectionSlot>> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(held.iter().map(Vec::len).sum::<usize>(), 5);
        drop(held);
        assert_eq!(limiter.live(), 0, "every slot released");
    }
}
