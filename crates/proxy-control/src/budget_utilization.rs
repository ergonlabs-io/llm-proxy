//! The `llmproxy_spend_budget_utilization` gauge: how much of each tenant
//! and scoped spend ceiling the current period has used, in whole percent.
//!
//! The spend flusher publishes it once per tick from the accumulator's
//! buckets, so nothing on the request path touches it. Labels are the chain,
//! the tenant and the budget name; a key budget has no series, because a key
//! is a user and a user id never becomes a label (AGENTS.md "Policy Domains").
//! Tenants are not bounded by config, so series past [`MAX_SERIES`] fold into
//! one overflow series.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use proxy_observability::stats::{instruments, Handle, Registry, WorkerId};

use crate::auth::TenantId;

/// Budgets past this many series share one overflow series per chain.
const MAX_SERIES: usize = 4096;

const OVERFLOW: &str = "-cardinality-overflow-";

/// The published series of one accumulator.
pub(crate) struct BudgetUtilizationGauges {
    registry: Arc<Registry>,
    scope: String,
    /// Subject -> its series and the value last published there. Touched only
    /// by the flusher thread; the mutex makes the type `Sync`.
    series: Mutex<HashMap<TenantId, (Handle, i64)>>,
}

/// What one series reads this tick: the bucket's subject, its label values
/// and its utilization.
pub(crate) struct Reading {
    pub subject: TenantId,
    pub tenant: String,
    pub budget: String,
    pub percent: i64,
}

impl BudgetUtilizationGauges {
    pub(crate) fn new(registry: Arc<Registry>, scope: &str) -> Self {
        BudgetUtilizationGauges {
            registry,
            scope: scope.to_owned(),
            series: Mutex::new(HashMap::new()),
        }
    }

    /// Sets every series in `readings`, and sets to 0 every series published
    /// before that has no reading now (its period ended with no new charge,
    /// or the budget was removed), so a stale level never lingers.
    pub(crate) fn publish(&self, readings: Vec<Reading>) {
        let mut series = self.series.lock().unwrap_or_else(PoisonError::into_inner);
        let mut seen = std::collections::HashSet::with_capacity(readings.len());
        for reading in readings {
            let entry = series.entry(reading.subject.clone()).or_insert_with(|| {
                let handle = self.registry.resolve_capped(
                    &instruments::SPEND_BUDGET_UTILIZATION,
                    &[
                        ("scope", self.scope.as_str()),
                        ("tenant", reading.tenant.as_str()),
                        ("budget", reading.budget.as_str()),
                    ],
                    MAX_SERIES,
                    &[
                        ("scope", self.scope.as_str()),
                        ("tenant", OVERFLOW),
                        ("budget", OVERFLOW),
                    ],
                );
                (handle, 0)
            });
            Self::set(&self.registry, entry, reading.percent);
            seen.insert(reading.subject);
        }
        for (subject, entry) in series.iter_mut() {
            if !seen.contains(subject) {
                Self::set(&self.registry, entry, 0);
            }
        }
    }

    /// Sets an absolute value through the registry's delta-only `add`.
    fn set(registry: &Registry, (handle, last): &mut (Handle, i64), value: i64) {
        let delta = value.saturating_sub(*last);
        if delta != 0 {
            registry.add(WorkerId(0), *handle, delta);
            *last = value;
        }
    }
}
