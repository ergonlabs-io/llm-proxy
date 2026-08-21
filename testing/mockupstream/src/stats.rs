//! Served-request counters, and the optional periodic stderr printer
//! (`--stats-interval-secs`).
//!
//! Rust note: plain `AtomicU64`s with `Ordering::Relaxed`, never a `Mutex`.
//! Nothing here needs cross-field consistency -- a reader may observe one
//! counter having advanced past a request while a sibling counter hasn't
//! caught up yet, and that's fine for eyeball stats printed once a second.
//! What it must never do is make a request path contend a lock: under a
//! capacity sweep with thousands of concurrent connections, a contended
//! mutex would become the thing under test rather than the proxy in front
//! of this mock. See the crate doc's "no `Mutex` on the request path" rule.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Default)]
pub struct Stats {
    pub requests_total: AtomicU64,
    pub requests_streaming: AtomicU64,
    pub requests_non_streaming: AtomicU64,
    /// Requests that never reached a dialect handler: unknown path/method
    /// (404) or an oversized body (413).
    pub requests_rejected: AtomicU64,
}

impl Stats {
    pub fn record_request(&self, streaming: bool) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        let counter = if streaming {
            &self.requests_streaming
        } else {
            &self.requests_non_streaming
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rejected(&self) {
        self.requests_rejected.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot_line(&self) -> String {
        format!(
            "mock-upstream stats: total={} streaming={} non_streaming={} rejected={}",
            self.requests_total.load(Ordering::Relaxed),
            self.requests_streaming.load(Ordering::Relaxed),
            self.requests_non_streaming.load(Ordering::Relaxed),
            self.requests_rejected.load(Ordering::Relaxed),
        )
    }
}

/// Spawn the periodic stderr printer. A no-op (spawns nothing) when
/// `interval` is zero -- matches `--stats-interval-secs`'s "0 = off"
/// default.
pub fn spawn_printer(stats: Arc<Stats>, interval: Duration) {
    if interval.is_zero() {
        return;
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately; skip it so the first real print
        // is a full interval after startup, not at t=0 with nothing served
        // yet.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            eprintln!("{}", stats.snapshot_line());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_request_splits_streaming_and_non_streaming() {
        let stats = Stats::default();
        stats.record_request(true);
        stats.record_request(false);
        stats.record_request(true);
        assert_eq!(stats.requests_total.load(Ordering::Relaxed), 3);
        assert_eq!(stats.requests_streaming.load(Ordering::Relaxed), 2);
        assert_eq!(stats.requests_non_streaming.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn record_rejected_is_independent_of_total() {
        let stats = Stats::default();
        stats.record_rejected();
        stats.record_rejected();
        assert_eq!(stats.requests_rejected.load(Ordering::Relaxed), 2);
        assert_eq!(stats.requests_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn snapshot_line_reports_current_counts() {
        let stats = Stats::default();
        stats.record_request(true);
        stats.record_rejected();
        let line = stats.snapshot_line();
        assert!(line.contains("total=1"));
        assert!(line.contains("streaming=1"));
        assert!(line.contains("non_streaming=0"));
        assert!(line.contains("rejected=1"));
    }
}
