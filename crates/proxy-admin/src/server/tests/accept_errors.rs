//! A persistent admin accept failure (EMFILE) warns once per interval, and the
//! next warning counts the failures it suppressed.

use std::time::{Duration, Instant};

use crate::server::{AcceptWarnings, ACCEPT_ERROR_BACKOFF, ACCEPT_WARN_INTERVAL};

#[test]
fn accept_failures_warn_once_per_interval_and_count_the_suppressed() {
    let mut warnings = AcceptWarnings::default();
    let start = Instant::now();
    assert_eq!(
        warnings.should_warn(start),
        Some(0),
        "the first failure warns"
    );
    // One interval of failures at the backoff pace.
    let per_interval = (ACCEPT_WARN_INTERVAL.as_millis() / ACCEPT_ERROR_BACKOFF.as_millis()) as u64;
    for step in 1..per_interval {
        let now = start + ACCEPT_ERROR_BACKOFF * step as u32;
        assert_eq!(
            warnings.should_warn(now),
            None,
            "failure {step} is suppressed"
        );
    }
    assert_eq!(
        warnings.should_warn(start + ACCEPT_WARN_INTERVAL),
        Some(per_interval - 1),
        "the next warning reports what was suppressed"
    );
    assert_eq!(
        warnings.should_warn(start + ACCEPT_WARN_INTERVAL + Duration::from_millis(1)),
        None
    );
}
