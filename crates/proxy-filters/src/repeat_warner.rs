//! Repeat suppression for fail-open and fail-safe warnings, shared by
//! `llmproxy.token_limit` and `llmproxy.spend_limit` (AGENTS.md "Fail-open
//! controls": suppress repeats, or the log becomes the incident).
//!
//! [`RepeatWarner::check`] says whether a line for a key is due. Each filter
//! renders its own lines; this module only decides when.
//!
//! # Once per key, but not once ever
//!
//! A condition can hold for the whole life of a process (a usage-filter
//! dialect misconfigured at boot and never fixed), and an operator who starts
//! reading logs an hour in must still see it. So a key repeats, at most once
//! per [`REPEAT_INTERVAL`], rather than going silent after its first line.
//!
//! # Bounded by expiry, then by a cap
//!
//! Keys come from tenants, keys and credentials, so they keep arriving for the
//! life of the process. An entry older than [`REPEAT_INTERVAL`] behaves exactly
//! like no entry (the key is due either way), so when the map is full the
//! warner first drops expired entries, which changes no line. If the cap's
//! worth of keys all warned within the last interval, a new key is not
//! tracked: [`Due::Overflow`] tells the caller to write one line that names no
//! key, itself repeated at most once per interval. The sweep runs only when the
//! map is full and the oldest entry could have expired, so a burst past the cap
//! does not rescan the map on every call.
//!
//! # Why a `Mutex<HashMap<..>>`
//!
//! Callers touch the warner only on the rare path (the condition being warned
//! about), never on a healthy request, so the lock is never contended by
//! healthy traffic.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How long a key's line is suppressed before it may be written again. Not
/// configurable: an operability aid, not a tunable knob, and a fixed value
/// keeps "at most once a minute" in the log text true.
pub(crate) const REPEAT_INTERVAL: Duration = Duration::from_secs(60);

/// What the caller should write for one occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a due line that is never written makes the warner suppress nothing but output"]
pub(crate) enum Due {
    /// Write this key's own line.
    Key,
    /// The map is full of keys that warned within the interval: write the one
    /// line that stands for every untracked key.
    Overflow,
    /// Suppressed: this key (or the overflow line) warned within the interval.
    Suppressed,
}

/// Per-key repeat suppression with a bounded key set. See the module doc.
pub(crate) struct RepeatWarner<K> {
    state: Mutex<State<K>>,
    max_keys: usize,
}

struct State<K> {
    last_warned: HashMap<K, Instant>,
    /// No entry can expire before this instant, so a sweep before it would
    /// free nothing. `None` until the first sweep.
    next_sweep: Option<Instant>,
    /// When the overflow line last fired.
    overflow_warned_at: Option<Instant>,
}

fn is_due(last: Option<Instant>, now: Instant) -> bool {
    last.is_none_or(|last| now.saturating_duration_since(last) >= REPEAT_INTERVAL)
}

impl<K: Hash + Eq + Clone> State<K> {
    /// Drops entries older than [`REPEAT_INTERVAL`], if any could have
    /// expired by `now`.
    fn sweep_expired(&mut self, now: Instant) {
        if self.next_sweep.is_some_and(|at| now < at) {
            return;
        }
        self.last_warned
            .retain(|_, last| now.saturating_duration_since(*last) < REPEAT_INTERVAL);
        self.next_sweep = self
            .last_warned
            .values()
            .min()
            .map(|oldest| *oldest + REPEAT_INTERVAL);
    }
}

impl<K: Hash + Eq + Clone> RepeatWarner<K> {
    /// A warner that tracks at most `max_keys` keys at once.
    pub(crate) fn new(max_keys: usize) -> Self {
        RepeatWarner {
            state: Mutex::new(State {
                last_warned: HashMap::new(),
                next_sweep: None,
                overflow_warned_at: None,
            }),
            max_keys,
        }
    }

    /// Whether a line for `key` is due at `now`, recording it when it is.
    pub(crate) fn check(&self, key: &K, now: Instant) -> Due {
        // Rust note: `unwrap_or_else(PoisonError::into_inner)` recovers the
        // guard from a poisoned `Mutex` rather than panicking. A panic while
        // holding this lock elsewhere would otherwise turn "we could not warn
        // about a gap" into "every request now panics", a worse outage than
        // the one the warning exists to make visible.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let last = state.last_warned.get(key).copied();
        if !is_due(last, now) {
            return Due::Suppressed;
        }
        if last.is_none() && state.last_warned.len() >= self.max_keys {
            state.sweep_expired(now);
        }
        if last.is_none() && state.last_warned.len() >= self.max_keys {
            if !is_due(state.overflow_warned_at, now) {
                return Due::Suppressed;
            }
            state.overflow_warned_at = Some(now);
            return Due::Overflow;
        }
        state.last_warned.insert(key.clone(), now);
        Due::Key
    }

    /// How many keys are tracked now.
    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last_warned
            .len()
    }

    /// Whether `key` is tracked now.
    #[cfg(test)]
    pub(crate) fn is_tracked(&self, key: &K) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last_warned
            .contains_key(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_repeats_once_per_interval() {
        let warner = RepeatWarner::new(4);
        let start = Instant::now();
        assert_eq!(warner.check(&"a", start), Due::Key);
        assert_eq!(
            warner.check(&"a", start + Duration::from_secs(1)),
            Due::Suppressed
        );
        assert_eq!(warner.check(&"a", start + REPEAT_INTERVAL), Due::Key);
    }

    #[test]
    fn past_the_cap_one_overflow_line_stands_for_new_keys() {
        let warner = RepeatWarner::new(2);
        let start = Instant::now();
        assert_eq!(warner.check(&1, start), Due::Key);
        assert_eq!(warner.check(&2, start), Due::Key);
        assert_eq!(warner.check(&3, start), Due::Overflow);
        assert_eq!(warner.check(&4, start), Due::Suppressed);
        assert_eq!(warner.tracked(), 2, "an overflow key must not be tracked");
        // Every tracked key has expired: a new key is tracked again.
        assert_eq!(warner.check(&5, start + REPEAT_INTERVAL), Due::Key);
        assert!(warner.is_tracked(&5));
        assert_eq!(warner.tracked(), 1, "expired keys were dropped");
    }
}
