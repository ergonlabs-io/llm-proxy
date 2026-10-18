//! The `llmproxy_counter_reconciliation_age_seconds` gauge: how long each
//! counter seam has gone without reconciling with the store (ADR-0006 §5,
//! amendment F).
//!
//! Every seam fails open while its store is unreachable, so this gauge is how
//! an operator sees the degraded state before the warning bound trips. Each
//! seam's control-side thread publishes it once per tick, so nothing on the
//! request path touches it.
//!
//! Labels are bounded: `scope` is the chain's operator-chosen `stat_prefix`
//! and `seam` is one of three fixed names. No tenant or key id is a label.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use proxy_observability::stats::{instruments, Handle, Registry, WorkerId};

/// Chains past this many series share one overflow series per seam.
const MAX_SCOPES: usize = 256;

/// Which counter seam a gauge reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seam {
    /// Tier-3 token and request windows ([`crate::window_counter::WindowAccumulator`]).
    RateWindow,
    /// Tier-4 concurrent-stream leases ([`crate::window_counter::LeaseGauge`]).
    StreamLease,
    /// Tier-3 spend totals ([`crate::spend::SpendAccumulator`]).
    Spend,
}

impl Seam {
    pub fn as_str(self) -> &'static str {
        match self {
            Seam::RateWindow => "rate_window",
            Seam::StreamLease => "stream_lease",
            Seam::Spend => "spend",
        }
    }
}

/// One `(scope, seam)` series.
pub struct ReconciliationAgeGauge {
    registry: Arc<Registry>,
    handle: Handle,
    /// The whole seconds last published; the registry only takes deltas.
    last: AtomicU64,
}

impl ReconciliationAgeGauge {
    pub fn new(registry: Arc<Registry>, scope: &str, seam: Seam) -> Self {
        let handle = registry.resolve_capped(
            &instruments::COUNTER_RECONCILIATION_AGE_SECONDS,
            &[("scope", scope), ("seam", seam.as_str())],
            MAX_SCOPES,
            &[("scope", "overflow"), ("seam", seam.as_str())],
        );
        ReconciliationAgeGauge {
            registry,
            handle,
            last: AtomicU64::new(0),
        }
    }

    /// Set the series to `age`, in whole seconds.
    pub fn publish(&self, age: Duration) {
        let age = age.as_secs();
        let last = self.last.swap(age, Ordering::AcqRel);
        // Rust note: the wrapping difference, applied back as an i64, sets
        // an absolute value through the registry's delta-only `add` (the
        // same trick `ControlPlane::publish_snapshot_age` uses).
        self.registry
            .add(WorkerId(0), self.handle, age.wrapping_sub(last) as i64);
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;

    /// The value `registry` renders on `/stats/prometheus` for one series,
    /// or `None` when the series is not exported.
    pub fn rendered_age(registry: &Registry, scope: &str, seam: Seam) -> Option<u64> {
        let series = format!(
            "envoy_llmproxy_counter_reconciliation_age_seconds{{scope=\"{scope}\",seam=\"{}\"}}",
            seam.as_str()
        );
        proxy_observability::stats::prometheus_render::render(registry)
            .lines()
            .find(|line| line.starts_with(&series))
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|value| value.parse().ok())
    }

    /// Wait, up to a deadline only a broken run reaches, until the series
    /// reads at least `at_least` seconds; returns whether it did. For tests
    /// of a control-side thread, which publishes on its own schedule.
    pub fn wait_for_age(registry: &Registry, scope: &str, seam: Seam, at_least: u64) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if rendered_age(registry, scope, seam).is_some_and(|age| age >= at_least) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::rendered_age;
    use super::*;

    #[test]
    fn a_gauge_renders_the_last_published_age_under_its_scope_and_seam() {
        let registry = proxy_observability::stats::StatsControl::new(1).registry();
        let windows =
            ReconciliationAgeGauge::new(Arc::clone(&registry), "ingress", Seam::RateWindow);
        let leases =
            ReconciliationAgeGauge::new(Arc::clone(&registry), "ingress", Seam::StreamLease);

        windows.publish(Duration::from_millis(90_900));
        leases.publish(Duration::from_secs(4));
        assert_eq!(
            rendered_age(&registry, "ingress", Seam::RateWindow),
            Some(90)
        );
        assert_eq!(
            rendered_age(&registry, "ingress", Seam::StreamLease),
            Some(4)
        );

        windows.publish(Duration::ZERO);
        assert_eq!(
            rendered_age(&registry, "ingress", Seam::RateWindow),
            Some(0),
            "a later, smaller age replaces the value rather than adding to it"
        );
    }
}
