//! Load balancing (S7): `ROUND_ROBIN` (smooth weighted), `LEAST_REQUEST` (power of two choices), `RANDOM`, plus
//! the priority-spillover and healthy-panic-threshold behavior every policy shares.
//!
//! `RING_HASH` and `MAGLEV` are not implemented. Both need bit-exact parity with Envoy's hash function and endpoint
//! key format to avoid silently breaking session affinity across a mixed fleet, and there is no differential
//! harness yet to prove that parity (see [`build`]). AGENTS.md invariant 1 forbids silently substituting another
//! policy, so the config is rejected instead.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use proxy_config::ir::LbPolicy;

use crate::host_set::HostSet;
use crate::{Host, LoadBalancerContext};

/// Envoy's overprovisioning factor (S7), as a percent multiplier (140 == 1.4x) so the priority math stays integer.
/// See [`HostPicker::choose_priority`] for the worked example.
const OVERPROVISIONING_FACTOR_PERCENT: u64 = 140;

/// Envoy's healthy-panic threshold (S7). If the healthy fraction within the selected priority is strictly below
/// this percentage, selection widens to every host at that priority. Exactly 50% healthy does not panic: Envoy's
/// check is `<`, not `<=`.
const PANIC_THRESHOLD_PERCENT: u64 = 50;

/// A configured `lb_policy` unsupported by this build. Cluster construction
/// must fail loudly on this rather than silently falling back to
/// round-robin (AGENTS.md invariant 1).
#[derive(Debug, thiserror::Error)]
pub enum LbError {
    #[error(
        "lb_policy {0:?} is not implemented: it requires bit-exact parity with Envoy's hash \
         function (ketama/xxhash64 for RING_HASH, the paper's permutation algorithm for \
         MAGLEV) to avoid silently breaking session affinity across a mixed fleet, and we \
         don't have the differential test harness for that yet; refusing to substitute another policy silently"
    )]
    UnsupportedPolicy(LbPolicy),
}

/// One policy's choice among an already-narrowed candidate list (the priority and panic-threshold pool, see
/// [`HostPicker::pick`]). Implementors do not handle `ctx.host_override`, which [`HostPicker::pick`] resolves once.
/// `ctx.hash` is unused here; it matters only for `RING_HASH`/`MAGLEV`, which are not implemented (see [`build`]).
pub trait LoadBalancer: Send + Sync {
    fn pick(&self, hosts: &[Arc<Host>], ctx: &LoadBalancerContext) -> Option<Arc<Host>>;
}

/// Build the [`LoadBalancer`] for a configured `lb_policy`, or an [`LbError`]
/// naming the policy for the two we deliberately don't implement yet.
pub fn build(policy: LbPolicy) -> Result<Box<dyn LoadBalancer>, LbError> {
    match policy {
        LbPolicy::RoundRobin => Ok(Box::new(RoundRobinLb::new())),
        LbPolicy::Random => Ok(Box::new(RandomLb::new())),
        LbPolicy::LeastRequest => Ok(Box::new(LeastRequestLb::new())),
        LbPolicy::RingHash | LbPolicy::Maglev => Err(LbError::UnsupportedPolicy(policy)),
        // `CLUSTER_PROVIDED` is not `RING_HASH`/`MAGLEV`'s "not implemented yet". It means there is no host-picking
        // `LoadBalancer` by design: an aggregate has members, not hosts (see `LbPolicy::ClusterProvided`). Defensive
        // only: `ManagedCluster::from_config`'s aggregate arm never calls `build`.
        LbPolicy::ClusterProvided => Err(LbError::UnsupportedPolicy(policy)),
    }
}

// --------------------------------------------------------------- ROUND_ROBIN --

/// One host's smooth-weighted-round-robin scheduling state, used only when
/// the candidate hosts' weights actually differ (see [`RoundRobinLb::pick`]).
struct SwrrEntry {
    address: SocketAddr,
    weight: i64,
    current: i64,
}

/// `ROUND_ROBIN` (S7): a plain rotating cursor when every candidate has the same weight. Otherwise smooth weighted
/// round robin, so a 5:1 weight comes out interleaved (`A A A B A A`) rather than batched (`A A A A A B`). Envoy
/// uses an EDF scheduler; this nginx-style SWRR gives the same spread with plain integers.
pub struct RoundRobinLb {
    cursor: AtomicUsize,
    // Rust note: SWRR is stateful, since each pick rewrites every entry's `current` weight. `pick` takes `&self`
    // because one `Arc<dyn LoadBalancer>` is shared across workers, so the `Mutex` is the interior-mutability seam.
    // TODO: a per-pick lock is a known contention point under load. A per-worker instance would remove it, but that
    // is a larger structural change.
    swrr: Mutex<Vec<SwrrEntry>>,
}

impl RoundRobinLb {
    pub fn new() -> Self {
        Self {
            cursor: AtomicUsize::new(0),
            swrr: Mutex::new(Vec::new()),
        }
    }

    /// Smooth weighted round robin (nginx's algorithm): add each candidate's weight to its `current`, pick the
    /// highest `current`, then subtract the total weight from that one.
    ///
    /// Rust note: over any `total_weight` consecutive picks, every host is chosen exactly `weight` times. The
    /// chosen host's `current` drops below zero, so it cannot win again until other picks accumulate enough weight.
    /// Weights 5 and 1 (total 6) give `A A A B A A`, repeating: `B` never waits through five `A`s.
    fn smooth_weighted_pick(&self, hosts: &[Arc<Host>]) -> Option<Arc<Host>> {
        let mut state = self.swrr.lock().expect("lock poisoned: a holder panicked");
        // Reconcile with the current candidate set. Tracked hosts keep their `current` (the memory across picks), new
        // hosts start at 0, and departed hosts are dropped.
        let mut next: Vec<SwrrEntry> = Vec::with_capacity(hosts.len());
        for h in hosts {
            let current = state
                .iter()
                .find(|e| e.address == h.address)
                .map(|e| e.current)
                .unwrap_or(0);
            next.push(SwrrEntry {
                address: h.address,
                weight: i64::from(h.weight),
                current,
            });
        }
        let total_weight: i64 = next.iter().map(|e| e.weight).sum();
        if total_weight <= 0 {
            return None;
        }
        for e in next.iter_mut() {
            e.current += e.weight;
        }
        // Rust note: `max_by_key` returns the *last* maximal element on
        // ties, which just needs to be a consistent tiebreak (it is).
        let best_idx = next
            .iter()
            .enumerate()
            .max_by_key(|(_, e)| e.current)
            .map(|(i, _)| i)?;
        next[best_idx].current -= total_weight;
        let picked = next[best_idx].address;
        *state = next;
        hosts.iter().find(|h| h.address == picked).cloned()
    }
}

impl Default for RoundRobinLb {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer for RoundRobinLb {
    fn pick(&self, hosts: &[Arc<Host>], _ctx: &LoadBalancerContext) -> Option<Arc<Host>> {
        if hosts.is_empty() {
            return None;
        }
        let all_equal_weight = hosts.iter().all(|h| h.weight == hosts[0].weight);
        if all_equal_weight {
            let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % hosts.len();
            return Some(Arc::clone(&hosts[idx]));
        }
        self.smooth_weighted_pick(hosts)
    }
}

// ------------------------------------------------------------------- RANDOM --

/// `RANDOM` (S7): uniform pick over the candidate set.
pub struct RandomLb {
    // Rust note: same interior-mutability story as `RoundRobinLb::swrr` --
    // drawing a random number needs `&mut`, `pick` only has `&self`.
    rng: Mutex<StdRng>,
}

impl RandomLb {
    pub fn new() -> Self {
        Self::with_seed(rand::random())
    }

    /// Test/reproducibility seam: a fixed seed makes `RANDOM`'s statistical
    /// tests deterministic instead of flaky.
    pub fn with_seed(seed: u64) -> Self {
        Self {
            rng: Mutex::new(StdRng::seed_from_u64(seed)),
        }
    }
}

impl Default for RandomLb {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer for RandomLb {
    fn pick(&self, hosts: &[Arc<Host>], _ctx: &LoadBalancerContext) -> Option<Arc<Host>> {
        if hosts.is_empty() {
            return None;
        }
        let mut rng = self.rng.lock().expect("lock poisoned: a holder panicked");
        let idx = rng.gen_range(0..hosts.len());
        Some(Arc::clone(&hosts[idx]))
    }
}

// --------------------------------------------------------------- LEAST_REQUEST --

/// Envoy's default `choice_count` for power-of-two-choices (S7).
const DEFAULT_CHOICE_COUNT: usize = 2;

/// `LEAST_REQUEST` (S7): pick `choice_count` candidates uniformly at random and take the one with fewer active
/// requests. With `choice_count` 2 (Envoy's default) this is power of two choices. The router holds a
/// `Host::begin_request` guard per attempt, so `Host::active_requests` is the live in-flight count. With all hosts
/// idle this is uniform random.
pub struct LeastRequestLb {
    choice_count: usize,
    rng: Mutex<StdRng>,
}

impl LeastRequestLb {
    pub fn new() -> Self {
        Self::with_seed(DEFAULT_CHOICE_COUNT, rand::random())
    }

    pub fn with_seed(choice_count: usize, seed: u64) -> Self {
        Self {
            choice_count: choice_count.max(1),
            rng: Mutex::new(StdRng::seed_from_u64(seed)),
        }
    }
}

impl Default for LeastRequestLb {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer for LeastRequestLb {
    fn pick(&self, hosts: &[Arc<Host>], _ctx: &LoadBalancerContext) -> Option<Arc<Host>> {
        if hosts.is_empty() {
            return None;
        }
        if hosts.len() == 1 {
            return Some(Arc::clone(&hosts[0]));
        }
        let mut rng = self.rng.lock().expect("lock poisoned: a holder panicked");
        let k = self.choice_count.min(hosts.len());
        // Rust note: partial Fisher-Yates shuffles only the first `k` slots, since P2C needs `k` distinct candidates.
        // Sampling without replacement matters: sampling with replacement could draw the same host twice and never
        // compare it against anything. That made this fail non-deterministically in early testing with 2 hosts.
        let mut indices: Vec<usize> = (0..hosts.len()).collect();
        for i in 0..k {
            let j = rng.gen_range(i..indices.len());
            indices.swap(i, j);
        }
        let mut best_idx = indices[0];
        let mut best_load = hosts[best_idx].active_request_count();
        for &idx in &indices[1..k] {
            let load = hosts[idx].active_request_count();
            // Strict `<`: the first candidate drawn wins a tie, which is deterministic.
            if load < best_load {
                best_load = load;
                best_idx = idx;
            }
        }
        Some(Arc::clone(&hosts[best_idx]))
    }
}

// ------------------------------------------------- priority + panic threshold --

/// Combines a policy's [`LoadBalancer`] with the priority-spillover and healthy-panic-threshold behavior that every
/// policy shares (S7). It is the single path for `ClusterEntry::select_host`, so that behavior cannot drift between
/// policies.
pub struct HostPicker {
    policy: Box<dyn LoadBalancer>,
    // Rust note: the priority a request lands on is a weighted random draw (see `choose_priority`), which needs the
    // same `&self`-but-mutates seam as the policies.
    priority_rng: Mutex<StdRng>,
}

impl HostPicker {
    pub fn new(policy: Box<dyn LoadBalancer>) -> Self {
        Self::with_seed(policy, rand::random())
    }

    pub fn with_seed(policy: Box<dyn LoadBalancer>, seed: u64) -> Self {
        Self {
            policy,
            priority_rng: Mutex::new(StdRng::seed_from_u64(seed)),
        }
    }

    /// Full S7 host pick: the `host_override` short-circuit, then priority spillover, then healthy-panic widening,
    /// then the policy's choice among the resulting pool. With Envoy's `previous_hosts` predicate, a rejected pick is
    /// re-run up to `host_selection_retry_max_attempts` times. The final pick is used even if it repeats, as Envoy
    /// specifies when no unused host is found.
    pub fn pick(&self, host_set: &HostSet, ctx: &LoadBalancerContext) -> Option<Arc<Host>> {
        // The override is a hint. Honor it only when the address is in the set; otherwise select normally.
        if let Some(addr) = ctx.host_override {
            if let Some(host) = host_set.all_hosts().iter().find(|h| h.address == addr) {
                if !ctx.avoid_previous_hosts || !ctx.attempted_hosts.contains(&addr) {
                    return Some(Arc::clone(host));
                }
            }
        }

        let priority = self.choose_priority(host_set)?;
        let members = host_set.hosts_for_priority(priority);
        if members.is_empty() {
            return None;
        }

        let healthy_count = members.iter().filter(|h| h.is_healthy()).count() as u64;
        let total_count = members.len() as u64;
        // Panic check: `< 50`, not `<= 50` -- exactly 50% healthy stays on
        // the healthy-only path.
        let panicking = healthy_count * 100 < total_count * PANIC_THRESHOLD_PERCENT;

        let candidates: Vec<Arc<Host>> = if panicking {
            // TODO (stats): count this as `lb_healthy_panic`.
            members.to_vec()
        } else {
            members.iter().filter(|h| h.is_healthy()).cloned().collect()
        };
        if candidates.is_empty() {
            return None;
        }
        let max_retries = if ctx.avoid_previous_hosts {
            ctx.host_selection_retry_max_attempts
        } else {
            0
        };
        for selection_attempt in 0..=max_retries {
            let picked = self.policy.pick(&candidates, ctx)?;
            if !ctx.avoid_previous_hosts
                || !ctx.attempted_hosts.contains(&picked.address)
                || selection_attempt == max_retries
            {
                return Some(picked);
            }
        }
        unreachable!("the inclusive selection loop always returns")
    }

    /// Picks the priority for this request, per S7's overprovisioning-factor spillover.
    ///
    /// Envoy's formula (overprovisioning factor 1.4 == 140%): walk priorities ascending. Each gets
    /// `min(100, healthy_ratio * 140, remaining_load)` percent, except the last priority present, which absorbs
    /// whatever load is left. Percentages are integers 0..=100 that sum to 100.
    ///
    /// Example: P0 50% healthy, P1 fully healthy. P0 gets `min(100, 50 * 140 / 100) = 70`, and the remaining 30
    /// goes to P1 (the last priority) regardless of its ratio. A fully healthy P0 gets 100, so nothing spills. A
    /// fully unhealthy P0 gets 0, so P1 absorbs all 100.
    fn choose_priority(&self, host_set: &HostSet) -> Option<u32> {
        let priorities: Vec<u32> = host_set.priorities().collect();
        if priorities.is_empty() {
            return None;
        }
        let last = *priorities.last().expect("checked non-empty above");

        let mut loads: Vec<(u32, u64)> = Vec::with_capacity(priorities.len());
        let mut remaining: u64 = 100;
        for &priority in &priorities {
            let load = if priority == last {
                remaining
            } else {
                let members = host_set.hosts_for_priority(priority);
                let total = members.len() as u64;
                let healthy = members.iter().filter(|h| h.is_healthy()).count() as u64;
                let ratio_percent = (healthy * 100).checked_div(total).unwrap_or(0);
                let available =
                    std::cmp::min(100, ratio_percent * OVERPROVISIONING_FACTOR_PERCENT / 100);
                std::cmp::min(available, remaining)
            };
            loads.push((priority, load));
            remaining = remaining.saturating_sub(load);
        }

        let mut rng = self
            .priority_rng
            .lock()
            .expect("lock poisoned: a holder panicked");
        let draw = rng.gen_range(0..100u64);
        let mut acc = 0u64;
        for (priority, load) in &loads {
            acc += load;
            if draw < acc {
                return Some(*priority);
            }
        }
        // Integer math should always sum to exactly 100. If it does not, fall back to the last priority rather than
        // return `None` for a non-empty host set.
        Some(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HealthFlags, HealthStatus};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)), 80)
    }

    // Rust note: these tests predate `HealthFlags`. Rather than touch every call site, `host()` maps the old
    // `HealthStatus` onto `failed_active_hc`. `Unhealthy` here means failing active HC, which is what the S7 panic
    // and spillover tests exercise, not outlier ejection.
    fn host(last: u8, weight: u32, priority: u32, health: HealthStatus) -> Arc<Host> {
        Arc::new(Host {
            address: addr(last),
            hostname: None,
            metadata: Default::default(),
            weight,
            priority,
            health_flags: HealthFlags {
                failed_active_hc: health == HealthStatus::Unhealthy,
                failed_outlier_check: false,
            },
            active_requests: Default::default(),
        })
    }

    fn healthy_host(last: u8, weight: u32) -> Arc<Host> {
        host(last, weight, 0, HealthStatus::Healthy)
    }

    // --------------------------------------------------------- build() ---

    #[test]
    fn ring_hash_is_rejected_at_build_time() {
        let err = match build(LbPolicy::RingHash) {
            Err(err) => err,
            Ok(_) => panic!("RingHash should be rejected at build time"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("RingHash"),
            "error should name the policy: {msg}"
        );
    }

    #[test]
    fn maglev_is_rejected_at_build_time() {
        let err = match build(LbPolicy::Maglev) {
            Err(err) => err,
            Ok(_) => panic!("Maglev should be rejected at build time"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("Maglev"),
            "error should name the policy: {msg}"
        );
    }

    #[test]
    fn round_robin_random_and_least_request_all_build() {
        assert!(build(LbPolicy::RoundRobin).is_ok());
        assert!(build(LbPolicy::Random).is_ok());
        assert!(build(LbPolicy::LeastRequest).is_ok());
    }

    // --------------------------------------------------------- ROUND_ROBIN --

    #[test]
    fn round_robin_cycles_equal_weight_hosts() {
        let lb = RoundRobinLb::new();
        let hosts = vec![healthy_host(1, 1), healthy_host(2, 1), healthy_host(3, 1)];
        let ctx = LoadBalancerContext::default();
        let picks: Vec<_> = (0..6)
            .map(|_| lb.pick(&hosts, &ctx).unwrap().address)
            .collect();
        assert_eq!(
            picks,
            vec![addr(1), addr(2), addr(3), addr(1), addr(2), addr(3)]
        );
    }

    #[test]
    fn weighted_round_robin_is_smooth_not_batched() {
        // Weights 5:1. A naive "emit weight copies in a row" scheme is periodic with period 6 and always puts the
        // light host last: A,A,A,A,A,B. A run of five A's must appear somewhere, since there is one gap per period.
        // What matters is where the interruption falls. Smooth weighting visits host 2 well before the naive scheme does.
        let lb = RoundRobinLb::new();
        let hosts = vec![healthy_host(1, 5), healthy_host(2, 1)];
        let ctx = LoadBalancerContext::default();
        let picks: Vec<u8> = (0..12)
            .map(|_| {
                let picked = lb.pick(&hosts, &ctx).unwrap();
                if picked.address == addr(1) {
                    1
                } else {
                    2
                }
            })
            .collect();

        // Exact counts: 10 of host 1, 2 of host 2 over 12 picks (5:1 ratio).
        assert_eq!(picks.iter().filter(|&&h| h == 1).count(), 10);
        assert_eq!(picks.iter().filter(|&&h| h == 2).count(), 2);

        // The naive scheme's whole 12-pick sequence, verbatim: two periods
        // of AAAAAB back to back.
        let naive: Vec<u8> = vec![1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 2];
        assert_ne!(
            picks, naive,
            "smooth weighting should not match the naive batched sequence"
        );

        // The naive scheme's first interruption is at index 5 (0-based). Smooth weighting interleaves the light host
        // well before that.
        let first_light = picks.iter().position(|&h| h == 2).unwrap();
        assert!(
            first_light < 5,
            "expected host 2 to be interleaved before the naive scheme's \
             first interruption (index 5), got it at index {first_light} in {picks:?}"
        );
    }

    #[test]
    fn weighted_round_robin_distribution_within_one_percent_over_100k_picks() {
        let lb = RoundRobinLb::new();
        let hosts = vec![healthy_host(1, 1), healthy_host(2, 2), healthy_host(3, 7)];
        let ctx = LoadBalancerContext::default();
        let mut counts: HashMap<SocketAddr, u64> = HashMap::new();
        const N: u64 = 100_000;
        for _ in 0..N {
            let picked = lb.pick(&hosts, &ctx).unwrap();
            *counts.entry(picked.address).or_default() += 1;
        }
        let expect = [
            (addr(1), 1.0 / 10.0),
            (addr(2), 2.0 / 10.0),
            (addr(3), 7.0 / 10.0),
        ];
        for (a, ratio) in expect {
            let got = counts[&a] as f64 / N as f64;
            assert!(
                (got - ratio).abs() < 0.01,
                "addr {a}: expected ~{ratio}, got {got}"
            );
        }
    }

    #[test]
    fn round_robin_empty_hosts_returns_none() {
        let lb = RoundRobinLb::new();
        let ctx = LoadBalancerContext::default();
        assert!(lb.pick(&[], &ctx).is_none());
    }

    #[test]
    fn round_robin_single_host_always_picked() {
        let lb = RoundRobinLb::new();
        let hosts = vec![healthy_host(1, 1)];
        let ctx = LoadBalancerContext::default();
        for _ in 0..5 {
            assert_eq!(lb.pick(&hosts, &ctx).unwrap().address, addr(1));
        }
    }

    // ------------------------------------------------------------- RANDOM --

    #[test]
    fn random_distribution_within_one_percent_over_100k_picks() {
        let lb = RandomLb::with_seed(42);
        let hosts = vec![healthy_host(1, 1), healthy_host(2, 1), healthy_host(3, 1)];
        let ctx = LoadBalancerContext::default();
        let mut counts: HashMap<SocketAddr, u64> = HashMap::new();
        const N: u64 = 100_000;
        for _ in 0..N {
            let picked = lb.pick(&hosts, &ctx).unwrap();
            *counts.entry(picked.address).or_default() += 1;
        }
        for a in [addr(1), addr(2), addr(3)] {
            let got = counts[&a] as f64 / N as f64;
            assert!((got - 1.0 / 3.0).abs() < 0.01, "addr {a}: got {got}");
        }
    }

    #[test]
    fn random_empty_hosts_returns_none() {
        let lb = RandomLb::with_seed(1);
        let ctx = LoadBalancerContext::default();
        assert!(lb.pick(&[], &ctx).is_none());
    }

    // ------------------------------------------------------- LEAST_REQUEST --

    #[test]
    fn least_request_prefers_lower_active_count() {
        let lb = LeastRequestLb::with_seed(2, 7);
        let low = healthy_host(1, 1);
        let high = healthy_host(2, 1);
        high.set_active_requests_for_test(50);
        let hosts = vec![Arc::clone(&low), Arc::clone(&high)];
        let ctx = LoadBalancerContext::default();
        for _ in 0..20 {
            assert_eq!(lb.pick(&hosts, &ctx).unwrap().address, addr(1));
        }
    }

    #[test]
    fn least_request_ties_do_not_panic() {
        let lb = LeastRequestLb::with_seed(2, 3);
        let hosts = vec![healthy_host(1, 1), healthy_host(2, 1)];
        let ctx = LoadBalancerContext::default();
        for _ in 0..20 {
            lb.pick(&hosts, &ctx).unwrap();
        }
    }

    #[test]
    fn least_request_single_host() {
        let lb = LeastRequestLb::new();
        let hosts = vec![healthy_host(1, 1)];
        let ctx = LoadBalancerContext::default();
        assert_eq!(lb.pick(&hosts, &ctx).unwrap().address, addr(1));
    }

    #[test]
    fn least_request_empty_hosts_returns_none() {
        let lb = LeastRequestLb::new();
        let ctx = LoadBalancerContext::default();
        assert!(lb.pick(&[], &ctx).is_none());
    }

    // ------------------------------------------------------- HostPicker ---

    fn host_set_from(hosts: Vec<Arc<Host>>) -> HostSet {
        HostSet::from_hosts(hosts)
    }

    #[test]
    fn host_override_honored_when_present() {
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let set = host_set_from(vec![healthy_host(1, 1), healthy_host(2, 1)]);
        let ctx = LoadBalancerContext {
            hash: None,
            host_override: Some(addr(2)),
            attempted_clusters: Vec::new(),
            ..LoadBalancerContext::default()
        };
        for _ in 0..5 {
            assert_eq!(picker.pick(&set, &ctx).unwrap().address, addr(2));
        }
    }

    #[test]
    fn host_override_ignored_when_absent() {
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let set = host_set_from(vec![healthy_host(1, 1), healthy_host(2, 1)]);
        let ctx = LoadBalancerContext {
            hash: None,
            host_override: Some(addr(99)),
            attempted_clusters: Vec::new(),
            ..LoadBalancerContext::default()
        };
        let picked = picker.pick(&set, &ctx).unwrap();
        assert!(picked.address == addr(1) || picked.address == addr(2));
    }

    #[test]
    fn empty_host_set_returns_none() {
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let set = host_set_from(vec![]);
        let ctx = LoadBalancerContext::default();
        assert!(picker.pick(&set, &ctx).is_none());
    }

    #[test]
    fn single_host_always_picked() {
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let set = host_set_from(vec![healthy_host(1, 1)]);
        let ctx = LoadBalancerContext::default();
        assert_eq!(picker.pick(&set, &ctx).unwrap().address, addr(1));
    }

    #[test]
    fn previous_hosts_predicate_reselects_a_new_host() {
        // Round robin starts at host 1.  A retry that has already dispatched
        // it must re-run host selection and land on host 2 instead.
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let set = host_set_from(vec![healthy_host(1, 1), healthy_host(2, 1)]);
        let ctx = LoadBalancerContext {
            attempted_hosts: vec![addr(1)],
            avoid_previous_hosts: true,
            host_selection_retry_max_attempts: 1,
            ..LoadBalancerContext::default()
        };
        assert_eq!(picker.pick(&set, &ctx).unwrap().address, addr(2));
    }

    #[test]
    fn previous_hosts_predicate_reuses_last_pick_when_all_hosts_were_tried() {
        // Envoy does not turn a retriable request into UH just because the predicate finds no new host. After its
        // configured re-picks it uses the final selection, which may be a previous host.
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let set = host_set_from(vec![healthy_host(1, 1)]);
        let ctx = LoadBalancerContext {
            attempted_hosts: vec![addr(1)],
            avoid_previous_hosts: true,
            host_selection_retry_max_attempts: 3,
            ..LoadBalancerContext::default()
        };
        assert_eq!(picker.pick(&set, &ctx).unwrap().address, addr(1));
    }

    #[test]
    fn all_unhealthy_everywhere_still_returns_a_host_via_panic() {
        // A single fully unhealthy priority still gets 100% of the load, since it is the last priority. The panic
        // threshold widens selection to the unhealthy hosts.
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let set = host_set_from(vec![
            host(1, 1, 0, HealthStatus::Unhealthy),
            host(2, 1, 0, HealthStatus::Unhealthy),
        ]);
        let ctx = LoadBalancerContext::default();
        let picked = picker.pick(&set, &ctx).unwrap();
        assert!(picked.address == addr(1) || picked.address == addr(2));
    }

    // ------------------------------------------------- panic threshold ---

    #[test]
    fn panic_threshold_one_of_four_healthy_selects_across_all() {
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let set = host_set_from(vec![
            host(1, 1, 0, HealthStatus::Healthy),
            host(2, 1, 0, HealthStatus::Unhealthy),
            host(3, 1, 0, HealthStatus::Unhealthy),
            host(4, 1, 0, HealthStatus::Unhealthy),
        ]);
        let ctx = LoadBalancerContext::default();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.insert(picker.pick(&set, &ctx).unwrap().address);
        }
        // 1 healthy of 4 = 25% < 50% panic threshold -> all 4 selectable.
        assert_eq!(seen.len(), 4, "panic mode should make all hosts selectable");
    }

    #[test]
    fn panic_threshold_three_of_four_healthy_stays_healthy_only() {
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let set = host_set_from(vec![
            host(1, 1, 0, HealthStatus::Healthy),
            host(2, 1, 0, HealthStatus::Healthy),
            host(3, 1, 0, HealthStatus::Healthy),
            host(4, 1, 0, HealthStatus::Unhealthy),
        ]);
        let ctx = LoadBalancerContext::default();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.insert(picker.pick(&set, &ctx).unwrap().address);
        }
        // 3 of 4 = 75% >= 50% panic threshold -> stays healthy-only.
        assert_eq!(seen.len(), 3);
        assert!(!seen.contains(&addr(4)));
    }

    #[test]
    fn panic_threshold_boundary_exactly_50_percent_does_not_panic() {
        // Exactly 50% healthy: Envoy's check is `< threshold`, so 50% ==
        // threshold does NOT panic -- only the healthy hosts are selectable.
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let set = host_set_from(vec![
            host(1, 1, 0, HealthStatus::Healthy),
            host(2, 1, 0, HealthStatus::Healthy),
            host(3, 1, 0, HealthStatus::Unhealthy),
            host(4, 1, 0, HealthStatus::Unhealthy),
        ]);
        let ctx = LoadBalancerContext::default();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.insert(picker.pick(&set, &ctx).unwrap().address);
        }
        assert_eq!(seen.len(), 2);
        assert!(!seen.contains(&addr(3)) && !seen.contains(&addr(4)));
    }

    // --------------------------------------------------- priority spillover --

    #[test]
    fn all_healthy_priority_zero_gets_all_traffic() {
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let set = host_set_from(vec![
            host(1, 1, 0, HealthStatus::Healthy),
            host(2, 1, 0, HealthStatus::Healthy),
            host(3, 1, 1, HealthStatus::Healthy),
        ]);
        let ctx = LoadBalancerContext::default();
        for _ in 0..200 {
            let picked = picker.pick(&set, &ctx).unwrap();
            assert_ne!(picked.address, addr(3), "no traffic should spill to P1");
        }
    }

    #[test]
    fn half_healthy_priority_zero_spills_thirty_percent_to_priority_one() {
        // P0: 1 of 2 healthy = 50%, so min(100, 50*140/100) = 70% to P0. The remaining 30% goes to P1, the last
        // priority (see `choose_priority`'s doc).
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let set = host_set_from(vec![
            host(1, 1, 0, HealthStatus::Healthy),
            host(2, 1, 0, HealthStatus::Unhealthy),
            host(3, 1, 1, HealthStatus::Healthy),
        ]);
        let ctx = LoadBalancerContext::default();
        const N: u64 = 100_000;
        let mut p0 = 0u64;
        let mut p1 = 0u64;
        for _ in 0..N {
            let picked = picker.pick(&set, &ctx).unwrap();
            if picked.address == addr(3) {
                p1 += 1;
            } else {
                p0 += 1;
            }
        }
        let p0_ratio = p0 as f64 / N as f64;
        let p1_ratio = p1 as f64 / N as f64;
        assert!((p0_ratio - 0.70).abs() < 0.01, "P0 ratio {p0_ratio}");
        assert!((p1_ratio - 0.30).abs() < 0.01, "P1 ratio {p1_ratio}");
    }

    #[test]
    fn fully_unhealthy_priority_zero_sends_everything_to_priority_one() {
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let set = host_set_from(vec![
            host(1, 1, 0, HealthStatus::Unhealthy),
            host(2, 1, 0, HealthStatus::Unhealthy),
            host(3, 1, 1, HealthStatus::Healthy),
        ]);
        let ctx = LoadBalancerContext::default();
        for _ in 0..200 {
            let picked = picker.pick(&set, &ctx).unwrap();
            assert_eq!(picked.address, addr(3));
        }
    }
}
