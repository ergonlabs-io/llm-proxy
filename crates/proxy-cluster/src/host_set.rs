//! The per-cluster host-set snapshot (WP-16 §1).
//!
//! `HostSet` is the immutable membership view the cluster manager publishes.
//! It's built on the control runtime by [`crate::discovery`] and shared with
//! workers as `Arc<HostSet>` -- the same "control computes, workers swap"
//! model `ConfigSnapshot` uses (ADR-0003): discovery/DNS refresh recompute a
//! whole new snapshot, and readers only ever `load` the latest one, never
//! mutate in place.
//!
//! Envoy itself publishes incremental host-set *deltas* to workers rather
//! than whole-set swaps. WP-16 v1 always rebuilds the snapshot wholesale (see
//! [`crate::manager::ClusterManager::refresh_cluster`]) but still exposes the
//! added/removed/unchanged classification via [`diff_host_sets`], both for
//! observability and so tests can assert on it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use crate::{HealthFlags, Host};

/// Immutable per-cluster membership snapshot, indexed by numeric priority
/// (0 = primary, matching [`crate::RoutingPriority`]/S5/S7 failover order).
#[derive(Debug, Default)]
pub struct HostSet {
    /// Rust note: a `BTreeMap` keeps priorities in ascending order for free,
    /// which is the order failover walks them in -- no separate sort needed.
    by_priority: BTreeMap<u32, Vec<Arc<Host>>>,
}

impl HostSet {
    /// Build a snapshot from a flat host list, bucketing by `Host::priority`.
    pub fn from_hosts(hosts: Vec<Arc<Host>>) -> Self {
        let mut by_priority: BTreeMap<u32, Vec<Arc<Host>>> = BTreeMap::new();
        for host in hosts {
            by_priority.entry(host.priority).or_default().push(host);
        }
        Self { by_priority }
    }

    /// The member hosts of one priority level; empty slice if the priority
    /// has no members (or doesn't exist).
    pub fn hosts_for_priority(&self, priority: u32) -> &[Arc<Host>] {
        self.by_priority
            .get(&priority)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Priorities present in this snapshot, ascending -- failover order
    /// (S5/S7). Used by [`crate::load_balancer`]'s priority-spillover pass.
    ///
    /// Rust note: `BTreeMap::keys()` already yields ascending order, so this
    /// is just naming that guarantee for callers rather than doing any work.
    pub fn priorities(&self) -> impl Iterator<Item = u32> + '_ {
        self.by_priority.keys().copied()
    }

    /// All hosts across every priority with no health flag set (see
    /// [`crate::HealthFlags::is_healthy`]).
    pub fn all_healthy_hosts(&self) -> Vec<Arc<Host>> {
        self.by_priority
            .values()
            .flatten()
            .filter(|h| h.is_healthy())
            .cloned()
            .collect()
    }

    /// All hosts across every priority, regardless of health.
    pub fn all_hosts(&self) -> Vec<Arc<Host>> {
        self.by_priority.values().flatten().cloned().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.by_priority.values().all(Vec::is_empty)
    }
}

/// Address-level classification from comparing two host sets.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostSetDiff {
    pub added: Vec<SocketAddr>,
    pub removed: Vec<SocketAddr>,
    pub unchanged: Vec<SocketAddr>,
}

/// Diff two host sets by address. Each list is sorted for deterministic
/// comparison in tests/logs.
///
/// v1 tracks membership only: a host whose weight/priority changed but whose
/// address didn't is reported as `unchanged` (attribute churn is out of
/// scope here).
pub fn diff_host_sets(old: &HostSet, new: &HostSet) -> HostSetDiff {
    let old_addrs: HashSet<SocketAddr> = old.all_hosts().iter().map(|h| h.address).collect();
    let new_addrs: HashSet<SocketAddr> = new.all_hosts().iter().map(|h| h.address).collect();

    let mut diff = HostSetDiff::default();
    for &addr in &new_addrs {
        if old_addrs.contains(&addr) {
            diff.unchanged.push(addr);
        } else {
            diff.added.push(addr);
        }
    }
    for &addr in &old_addrs {
        if !new_addrs.contains(&addr) {
            diff.removed.push(addr);
        }
    }
    diff.added.sort();
    diff.removed.sort();
    diff.unchanged.sort();
    diff
}

/// Carry `health_flags` over from `old` to `new` for every address `diff`
/// calls `unchanged` (WP-18 runtime wiring).
///
/// `discovery::resolve` builds every `Host` fresh, with `HealthFlags::default()`
/// -- it has no notion of "this address was already known", so a plain
/// `managed.host_set.store(new)` on every DNS/EDS refresh would silently
/// mark a host healthy again on a timer, erasing the active health checker's
/// (and outlier detector's) entire output with nothing logged. Only
/// `unchanged` addresses are touched: `added` addresses are genuinely new
/// (nothing to carry from), and `removed` addresses don't exist in `new` to
/// carry anything onto.
///
/// Rust note: rebuilds the `Vec<Arc<Host>>` and re-buckets via
/// `HostSet::from_hosts` rather than mutating in place -- `Host` has no
/// interior mutability for `health_flags` (see `health_check`'s own
/// `apply_health_transition`, which rebuilds for the same reason), so a new
/// `Arc<Host>` is the only way to change it.
pub fn carry_over_health_flags(old: &HostSet, new: HostSet, diff: &HostSetDiff) -> HostSet {
    if diff.unchanged.is_empty() {
        return new;
    }
    let old_flags: HashMap<SocketAddr, HealthFlags> = old
        .all_hosts()
        .iter()
        .map(|h| (h.address, h.health_flags))
        .collect();
    let hosts: Vec<Arc<Host>> = new
        .all_hosts()
        .into_iter()
        .map(|h| match old_flags.get(&h.address) {
            Some(flags) if *flags != h.health_flags => Arc::new(Host {
                address: h.address,
                hostname: h.hostname.clone(),
                metadata: h.metadata.clone(),
                weight: h.weight,
                priority: h.priority,
                health_flags: *flags,
                active_requests: AtomicU64::new(h.active_request_count()),
            }),
            _ => h,
        })
        .collect();
    HostSet::from_hosts(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn host(ip: [u8; 4], port: u16, priority: u32) -> Arc<Host> {
        Arc::new(Host {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port),
            hostname: None,
            metadata: BTreeMap::new(),
            weight: 1,
            priority,
            health_flags: crate::HealthFlags::default(),
            active_requests: std::sync::atomic::AtomicU64::new(0),
        })
    }

    #[test]
    fn diff_classifies_added_removed_unchanged() {
        let old = HostSet::from_hosts(vec![host([10, 0, 0, 1], 80, 0), host([10, 0, 0, 2], 80, 0)]);
        let new = HostSet::from_hosts(vec![host([10, 0, 0, 2], 80, 0), host([10, 0, 0, 3], 80, 0)]);
        let diff = diff_host_sets(&old, &new);
        assert_eq!(
            diff.added,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 80)]
        );
        assert_eq!(
            diff.removed,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80)]
        );
        assert_eq!(
            diff.unchanged,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80)]
        );
    }

    #[test]
    fn hosts_for_priority_buckets_correctly() {
        let set = HostSet::from_hosts(vec![host([10, 0, 0, 1], 80, 0), host([10, 0, 0, 2], 80, 1)]);
        assert_eq!(set.hosts_for_priority(0).len(), 1);
        assert_eq!(set.hosts_for_priority(1).len(), 1);
        assert!(set.hosts_for_priority(2).is_empty());
    }
}
