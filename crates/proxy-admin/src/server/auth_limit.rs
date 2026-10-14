//! Rate limit on failed admin bearer tokens, per peer IP (review M9).
//!
//! The admin token gates key minting, revocation, tenant policy and tenant
//! provider credentials. Without a limit a peer can try tokens as fast as it
//! can open connections. After [`MAX_FAILURES`] wrong or missing tokens
//! within [`WINDOW`], that peer's admin requests are refused with 429 until
//! the window ends, even with the right token, so a guess cannot be confirmed
//! from inside a burst. A correct token before the limit clears the peer's
//! count, so an operator who mistypes once is not left counting toward it.
//!
//! The table is bounded ([`MAX_PEERS`]): expired windows are dropped first,
//! and a peer that still does not fit shares one overflow window with every
//! other such peer. Spreading guesses over many addresses therefore buys a
//! shared budget, not a fresh one per address.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Failed tokens a peer may present within one [`WINDOW`].
pub(crate) const MAX_FAILURES: u32 = 10;
/// How long a peer's failures count, from its first failure.
pub(crate) const WINDOW: Duration = Duration::from_secs(60);
/// Most peers tracked individually; see the module doc for the overflow.
const MAX_PEERS: usize = 4096;

/// One peer's failures in its current window.
struct Window {
    started: Instant,
    failures: u32,
    /// Whether the switch to refusing this peer has been logged, so the log
    /// records it once per window rather than once per refused request.
    announced: bool,
}

/// What [`AuthFailureLimiter::check`] decided.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Compare the token.
    Allow,
    /// Refuse without comparing. `first` is true for the first refusal of
    /// this window, the one to log.
    Limited { retry_after: Duration, first: bool },
}

/// Shared by every connection of one admin server. A `std` mutex: the
/// critical section is a map lookup, never held across an await.
#[derive(Default)]
pub(crate) struct AuthFailureLimiter {
    /// `None` is the overflow window.
    windows: Mutex<HashMap<Option<IpAddr>, Window>>,
}

impl AuthFailureLimiter {
    /// Whether `peer` may present a token now.
    pub(crate) fn check(&self, peer: IpAddr, now: Instant) -> Verdict {
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        let key = Self::key(&windows, peer);
        let Some(window) = windows.get_mut(&key) else {
            return Verdict::Allow;
        };
        let elapsed = now.saturating_duration_since(window.started);
        if elapsed >= WINDOW {
            windows.remove(&key);
            return Verdict::Allow;
        }
        if window.failures < MAX_FAILURES {
            return Verdict::Allow;
        }
        let first = !window.announced;
        window.announced = true;
        Verdict::Limited {
            retry_after: WINDOW - elapsed,
            first,
        }
    }

    /// Counts a wrong or missing token from `peer`.
    pub(crate) fn record_failure(&self, peer: IpAddr, now: Instant) {
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        if !windows.contains_key(&Some(peer)) && windows.len() >= MAX_PEERS {
            windows.retain(|_, window| now.saturating_duration_since(window.started) < WINDOW);
        }
        let key = Self::key(&windows, peer);
        let window = windows.entry(key).or_insert(Window {
            started: now,
            failures: 0,
            announced: false,
        });
        if now.saturating_duration_since(window.started) >= WINDOW {
            *window = Window {
                started: now,
                failures: 0,
                announced: false,
            };
        }
        window.failures = window.failures.saturating_add(1);
    }

    /// A correct token from `peer`: its count starts over.
    pub(crate) fn record_success(&self, peer: IpAddr) {
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        windows.remove(&Some(peer));
    }

    /// `peer`'s own window, or the overflow window when the table is full
    /// and `peer` has none.
    fn key(windows: &HashMap<Option<IpAddr>, Window>, peer: IpAddr) -> Option<IpAddr> {
        if windows.contains_key(&Some(peer)) || windows.len() < MAX_PEERS {
            Some(peer)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    /// The window ends and the peer may try again; a correct token clears
    /// the count before the limit. The over-the-limit refusal itself is
    /// driven over a real socket in `server/tests.rs`.
    #[test]
    fn the_limit_lifts_when_the_window_ends_and_a_success_clears_the_count() {
        let limiter = AuthFailureLimiter::default();
        let start = Instant::now();
        for _ in 0..MAX_FAILURES {
            limiter.record_failure(ip(1), start);
        }
        assert!(matches!(
            limiter.check(ip(1), start + Duration::from_secs(1)),
            Verdict::Limited { first: true, .. }
        ));
        assert!(matches!(
            limiter.check(ip(1), start + Duration::from_secs(2)),
            Verdict::Limited { first: false, .. }
        ));
        assert_eq!(limiter.check(ip(2), start), Verdict::Allow, "per peer");
        assert_eq!(limiter.check(ip(1), start + WINDOW), Verdict::Allow);

        for _ in 0..MAX_FAILURES - 1 {
            limiter.record_failure(ip(3), start);
        }
        limiter.record_success(ip(3));
        limiter.record_failure(ip(3), start);
        assert_eq!(limiter.check(ip(3), start), Verdict::Allow);
    }

    /// Past [`MAX_PEERS`] live windows, new peers share the overflow window,
    /// so many addresses do not each get a fresh budget.
    #[test]
    fn peers_past_the_table_bound_share_one_window() {
        let limiter = AuthFailureLimiter::default();
        let now = Instant::now();
        for n in 0..MAX_PEERS {
            let peer = IpAddr::from((n as u32 + 1).to_be_bytes());
            limiter.record_failure(peer, now);
        }
        for n in 0..MAX_FAILURES {
            limiter.record_failure(IpAddr::from([192, 168, 1, n as u8]), now);
        }
        assert!(matches!(
            limiter.check(IpAddr::from([192, 168, 2, 1]), now),
            Verdict::Limited { .. }
        ));
    }
}
