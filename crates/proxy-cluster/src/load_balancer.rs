//! Load balancing (WP-17, S7): `ROUND_ROBIN` (smooth weighted),
//! `LEAST_REQUEST` (power-of-two-choices), `RANDOM`, plus the
//! priority-spillover / healthy-panic-threshold behavior every policy shares.
//!
//! `RING_HASH`/`MAGLEV` are **not** implemented here -- both need bit-exact
//! parity with Envoy's hash function and endpoint-key format to avoid
//! silently breaking session affinity across a mixed fleet, and we don't yet
//! have the differential harness to prove that parity (see [`build`]). That
//! is a deliberate scope cut, not an oversight -- ground rule #1 forbids
//! silently substituting a different policy, so we reject the config
//! instead.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use proxy_config::ir::LbPolicy;

use crate::host_set::HostSet;
use crate::{Host, LoadBalancerContext};

/// Envoy's overprovisioning factor (S7), expressed as a percent multiplier
/// (140 == 1.4x) so priority-load math stays integer. See
/// [`priority_loads`] for the worked example.
const OVERPROVISIONING_FACTOR_PERCENT: u64 = 140;

/// Envoy's healthy-panic threshold (S7): if the healthy fraction *within the
/// selected priority* is strictly below this percentage, load balancing
/// widens to every host at that priority (healthy and unhealthy) instead of
/// just the healthy ones. Exactly 50% healthy does **not** panic -- Envoy's
/// check is `healthy_percent < panic_threshold`, not `<=`.
const PANIC_THRESHOLD_PERCENT: u64 = 50;

/// A configured `lb_policy` unsupported by this build. Cluster construction
/// must fail loudly on this rather than silently falling back to
/// round-robin (ground rule #1).
#[derive(Debug, thiserror::Error)]
pub enum LbError {
    #[error(
        "lb_policy {0:?} is not implemented: it requires bit-exact parity with Envoy's hash \
         function (ketama/xxhash64 for RING_HASH, the paper's permutation algorithm for \
         MAGLEV) to avoid silently breaking session affinity across a mixed fleet, and we \
         don't have the differential test harness for that yet (see IMPLEMENTATION_PLAN.md \
         WP-17 follow-up); refusing to substitute another policy silently"
    )]
    UnsupportedPolicy(LbPolicy),
}

/// One policy's choice among an already-narrowed candidate list (the
/// priority + panic-threshold pool, see [`HostPicker::pick`]). Implementors
/// do not need to handle `ctx.host_override` themselves -- that's resolved
/// once, in [`HostPicker::pick`], so it can't drift between policies.
/// `ctx.hash` is likewise unused here; it only matters for `RING_HASH`/
/// `MAGLEV`, which aren't implemented (see [`build`]).
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
        // `CLUSTER_PROVIDED` gets its own arm rather than joining the one
        // above: RING_HASH/MAGLEV mean "not implemented yet"; this means
        // "there is no host-picking `LoadBalancer` to build here, by
        // design" -- an aggregate cluster (the only user of this policy,
        // see `LbPolicy::ClusterProvided`'s doc) has no hosts of its own,
        // only members. This arm is defensive: `ManagedCluster::from_config`'s
        // aggregate branch (`proxy-cluster/src/manager.rs:140-166`) never
        // calls `build` at all, so reaching this in practice would mean a
        // bug elsewhere, not a missing feature here.
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

/// `ROUND_ROBIN` (S7): a plain rotating cursor when every candidate has the
/// same weight (the common case, and indistinguishable from anything
/// fancier), otherwise smooth weighted round robin so weight 5-vs-1 comes
/// out interleaved (`A A A B A A`) instead of batched (`A A A A A B`) --
/// Envoy uses an EDF scheduler for this; the nginx-style SWRR algorithm
/// below produces the same "spread the low-weight host out" property with
/// plain integers instead of floating-point deadlines.
pub struct RoundRobinLb {
    cursor: AtomicUsize,
    // Rust note: SWRR is a stateful scheduler -- each pick both reads and
    // rewrites every entry's `current` weight so it "remembers" where it
    // left off -- but `LoadBalancer::pick` takes `&self` because one
    // `Arc<dyn LoadBalancer>` is shared across worker threads. `Mutex` is
    // the interior-mutability seam that lets a `&self` method still mutate.
    // TODO(WP-17 perf): a per-pick lock here is a known contention point
    // under load; a per-worker LB instance (no cross-thread sharing) would
    // remove it, but that's a bigger structural change than this WP.
    swrr: Mutex<Vec<SwrrEntry>>,
}

impl RoundRobinLb {
    pub fn new() -> Self {
        Self {
            cursor: AtomicUsize::new(0),
            swrr: Mutex::new(Vec::new()),
        }
    }

    /// Smooth weighted round robin (nginx's algorithm): bump every
    /// candidate's `current` by its own weight, pick whichever now has the
    /// highest `current`, then discount that one by the total weight.
    ///
    /// Rust note: the loop invariant is what makes this "smooth" -- over any
    /// `total_weight` consecutive picks, every host is chosen exactly
    /// `weight` times, and because a host's `current` resets below zero
    /// right after it's picked, it can't win again until enough other picks
    /// have accumulated weight past it. Worked example, weights 5 and 1
    /// (total 6): the sequence this produces is `A A A B A A` (repeating) --
    /// B never has to wait through five A's in a row.
    fn smooth_weighted_pick(&self, hosts: &[Arc<Host>]) -> Option<Arc<Host>> {
        let mut state = self.swrr.lock().unwrap();
        // Reconcile against the current candidate set: hosts that were
        // already tracked keep their `current` (that's the "memory" across
        // picks); anything new starts at 0; anything that disappeared is
        // simply dropped.
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
        let mut rng = self.rng.lock().unwrap();
        let idx = rng.gen_range(0..hosts.len());
        Some(Arc::clone(&hosts[idx]))
    }
}

// --------------------------------------------------------------- LEAST_REQUEST --

/// Envoy's default `choice_count` for power-of-two-choices (S7).
const DEFAULT_CHOICE_COUNT: usize = 2;

/// `LEAST_REQUEST` (S7): pick `choice_count` candidates uniformly at random
/// and take whichever has fewer active requests ("power of two choices" when
/// `choice_count` is 2, Envoy's default). Until WP-15's connection pool and
/// the WP-13 router start incrementing/decrementing `Host::active_requests`,
/// every host reads 0 and this degrades to uniform random -- which is the
/// correct behavior for "no signal yet", not a bug.
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
        let mut rng = self.rng.lock().unwrap();
        let k = self.choice_count.min(hosts.len());
        // Rust note: partial Fisher-Yates -- shuffle only the first `k`
        // slots of an index array instead of the whole thing, since P2C
        // only needs `k` *distinct* candidates, not a full random ordering.
        // Sampling without replacement matters here: sampling *with*
        // replacement could draw the same host twice and never actually
        // compare it against anything, which defeats the "power of two
        // choices" property (and made this fail non-deterministically with
        // only 2 hosts in early testing).
        let mut indices: Vec<usize> = (0..hosts.len()).collect();
        for i in 0..k {
            let j = rng.gen_range(i..indices.len());
            indices.swap(i, j);
        }
        let mut best_idx = indices[0];
        let mut best_load = hosts[best_idx].active_request_count();
        for &idx in &indices[1..k] {
            let load = hosts[idx].active_request_count();
            // Strict `<` (not `<=`): the first candidate drawn wins a tie --
            // deterministic, and there's nothing here that could panic on a
            // tie either way.
            if load < best_load {
                best_load = load;
                best_idx = idx;
            }
        }
        Some(Arc::clone(&hosts[best_idx]))
    }
}

// ------------------------------------------------- priority + panic threshold --

/// Combines a policy-specific [`LoadBalancer`] with the priority-spillover /
/// healthy-panic-threshold behavior that's identical across every policy
/// (S7). This is the single path a non-aggregate cluster's
/// `ClusterEntry::select_host` (and, per-member, an aggregate's) calls into,
/// so that shared behavior can't drift between policies.
pub struct HostPicker {
    policy: Box<dyn LoadBalancer>,
    // Rust note: which priority a given request lands on is itself a
    // weighted random draw (see `choose_priority`), so this needs the same
    // `&self`-but-mutates seam as the policies above.
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

    /// Full S7 host pick: `ctx.host_override` short-circuit, then priority
    /// spillover, then the healthy-panic-threshold widening, then the
    /// configured policy's choice among the resulting pool.
    pub fn pick(&self, host_set: &HostSet, ctx: &LoadBalancerContext) -> Option<Arc<Host>> {
        // WP-36 endpoint-picker hook: honor an explicit override when it's
        // actually present in the set; otherwise fall through to normal
        // selection rather than erroring (the override is a *hint*).
        if let Some(addr) = ctx.host_override {
            if let Some(host) = host_set.all_hosts().iter().find(|h| h.address == addr) {
                return Some(Arc::clone(host));
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
            // TODO(WP-23 stats): count this as `lb_healthy_panic`.
            members.to_vec()
        } else {
            members.iter().filter(|h| h.is_healthy()).cloned().collect()
        };
        if candidates.is_empty() {
            return None;
        }
        self.policy.pick(&candidates, ctx)
    }

    /// Picks which priority level this request routes to, per S7's
    /// overprovisioning-factor spillover.
    ///
    /// Formula (Envoy's, ⚠️ overprovisioning factor 1.4 == 140%): walk
    /// priorities ascending; each gets `min(100, healthy_ratio * 140,
    /// remaining_load)` percent, except the *last* priority present, which
    /// always absorbs whatever load is left over (there's nowhere else for
    /// it to go). Percentages are integers 0..=100 that sum to exactly 100.
    ///
    /// Worked example, P0 50% healthy, P1 fully healthy: P0 gets
    /// `min(100, 50 * 140 / 100) = 70`; the remaining 30 goes to P1 (the
    /// last priority) regardless of P1's own ratio. All-healthy P0 (alone or
    /// with other priorities) gets `min(100, 100*140/100) = 100`, so nothing
    /// spills. P0 fully unhealthy gets `min(100, 0) = 0`, so P1 (as the last
    /// priority) absorbs all 100.
    fn choose_priority(&self, host_set: &HostSet) -> Option<u32> {
        let priorities: Vec<u32> = host_set.priorities().collect();
        if priorities.is_empty() {
            return None;
        }
        let last = *priorities.last().unwrap();

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

        let mut rng = self.priority_rng.lock().unwrap();
        let draw = rng.gen_range(0..100u64);
        let mut acc = 0u64;
        for (priority, load) in &loads {
            acc += load;
            if draw < acc {
                return Some(*priority);
            }
        }
        // Rounding safety net: integer math should always sum to exactly
        // 100, but if it somehow doesn't, fall back to the last priority
        // rather than returning `None` for a non-empty host set.
        Some(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HealthFlags, HealthStatus};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicU64;

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)), 80)
    }

    // Rust note: these tests predate `HealthFlags` (WP-19) and were written
    // against the old two-state `HealthStatus` enum; rather than touch every
    // one of the dozens of call sites below, `host()` keeps the old
    // `HealthStatus` parameter and maps it onto the new `failed_active_hc`
    // bit -- `Unhealthy` here means "failing active HC", which is exactly
    // what these tests are exercising (S7 panic threshold / spillover), not
    // outlier ejection.
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
            active_requests: AtomicU64::new(0),
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
        // Weights 5:1 -- a naive "emit weight copies in a row, in host-list
        // order" scheme is periodic with period 6 and *always* puts the
        // light host at the very end of each period: A,A,A,A,A,B repeated.
        // Note the ratio itself (5:1) forces a run of 5 A's to appear
        // *somewhere* in any periodic schedule (there's only one gap per
        // period to place) -- so the meaningful distinguishing property
        // isn't "no run of 5 ever", it's *where* the interruption falls.
        // Smooth (nginx-style SWRR, standing in for Envoy's EDF) does not
        // front-load all of host 1's picks before ever visiting host 2: the
        // first interruption happens well before the naive scheme's would.
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

        // The distinguishing assertion: the naive scheme's first
        // interruption is at index 5 (0-based) -- the light host never
        // appears before all 5 copies of the heavy host have run. Smooth
        // weighting interleaves it in well before that.
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
    fn all_unhealthy_everywhere_still_returns_a_host_via_panic() {
        // A single priority, fully unhealthy: still gets 100% of the load
        // (it's the only/last priority), and the panic threshold widens
        // selection to the unhealthy hosts since there are no healthy ones.
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
        // P0: 1 of 2 healthy = 50% -> min(100, 50*140/100) = 70% to P0.
        // Remaining 30% goes to P1 (the last priority), per the worked
        // example in `choose_priority`'s doc comment.
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
