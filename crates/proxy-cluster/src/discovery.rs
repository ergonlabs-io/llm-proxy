//! Discovery: turns a [`ClusterConfig`]'s configured endpoints into a
//! [`HostSet`], and paces the re-resolution of the DNS ones.
//!
//! `STATIC` needs no I/O -- its endpoints are already literal IPs (enforced
//! at config lowering, see `proxy-config/src/lower.rs`). `STRICT_DNS` and
//! `LOGICAL_DNS` resolve through a [`HostResolver`] and are the only variants
//! that re-resolve on a timer: [`RefreshSchedule`] decides how long to wait
//! after each lookup, and `ClusterManager` runs the timer (see
//! `manager.rs`'s `run_dns_refresh`). `EDS` clusters have no self-driven
//! discovery here at all; their membership is fed in externally, handled at
//! the [`crate::manager::ClusterManager`] level (see
//! `ClusterManager::accept_eds_update`).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use proxy_config::ir::{ClusterConfig, DiscoveryType, DnsRefresh, EndpointIR};

use crate::host_set::HostSet;
use crate::resolver::HostResolver;
use crate::{HealthFlags, Host};

/// Envoy's default `initial_fetch_timeout`: how long cluster warming
/// waits for a cluster's first resolution/EDS response before proceeding
/// with an empty host set. The caller (`proxy/src/main.rs`) applies it; the
/// manual "mark initialized anyway" escape hatch is
/// [`crate::manager::ClusterManager::force_initialize`].
pub const DEFAULT_INITIAL_FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// Resolve `config`'s endpoints into a host set. `previous` is the host set
/// currently published for this cluster (empty on the first resolution); only
/// `LOGICAL_DNS` reads it, to keep a host's address steady across refreshes.
pub async fn resolve(
    config: &ClusterConfig,
    resolver: &dyn HostResolver,
    previous: &HostSet,
) -> io::Result<HostSet> {
    let hosts = match config.discovery {
        DiscoveryType::Static => static_hosts(&config.endpoints)?,
        DiscoveryType::StrictDns(_) => strict_dns_hosts(&config.endpoints, resolver).await?,
        DiscoveryType::LogicalDns(_) => {
            logical_dns_hosts(&config.endpoints, resolver, previous).await?
        }
        // An EDS cluster owns no endpoints to resolve -- its membership
        // arrives through
        // [`crate::manager::ClusterManager::accept_eds_update`]. Empty, not
        // an error: a cluster whose EDS response has not landed yet is the
        // ordinary startup state, and warming is what stops traffic
        // reaching it meanwhile.
        //
        // **Callers must not reach here for an EDS cluster in the steady
        // state**, and `ManagedCluster::resolve_and_publish` has an explicit
        // arm to make sure they do not: resolving to empty on a DNS-cadence
        // refresh would WIPE the host set EDS had already delivered. This arm
        // is the defensive floor for a caller that gets that wrong, not the
        // intended path.
        DiscoveryType::Eds => Vec::new(),
    };
    Ok(HostSet::from_hosts(hosts))
}

/// Literal-IP endpoints -> hosts, no I/O. Also used by
/// [`crate::manager::ClusterManager::accept_eds_update`], since externally
/// supplied EDS endpoints are just more `EndpointIR`s.
pub(crate) fn static_hosts(endpoints: &[EndpointIR]) -> io::Result<Vec<Arc<Host>>> {
    endpoints
        .iter()
        .map(|e| {
            let ip: IpAddr = e.host.parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("endpoint host `{}` is not a literal IP address", e.host),
                )
            })?;
            Ok(Arc::new(Host {
                address: SocketAddr::new(ip, e.port),
                hostname: None,
                metadata: e.metadata.clone(),
                weight: e.weight,
                priority: e.priority,
                health_flags: HealthFlags::default(),
                active_requests: AtomicU64::new(0),
            }))
        })
        .collect()
}

/// `STRICT_DNS`: membership is the full current record set for every
/// configured endpoint's hostname.
async fn strict_dns_hosts(
    endpoints: &[EndpointIR],
    resolver: &dyn HostResolver,
) -> io::Result<Vec<Arc<Host>>> {
    let mut hosts = Vec::new();
    for e in endpoints {
        let ips = resolver.resolve(&e.host).await?;
        hosts.extend(ips.into_iter().map(|ip| {
            Arc::new(Host {
                address: SocketAddr::new(ip, e.port),
                hostname: Some(e.host.clone()),
                metadata: e.metadata.clone(),
                weight: e.weight,
                priority: e.priority,
                health_flags: HealthFlags::default(),
                active_requests: AtomicU64::new(0),
            })
        }));
    }
    Ok(hosts)
}

/// `LOGICAL_DNS`: one logical host per configured endpoint, holding one
/// address from the latest resolution.
///
/// The address stays where it is while the answer still contains it, and
/// moves to the answer's first address only when it is gone. Round-robin DNS
/// reorders its answers on every query, so always taking the first address
/// would swap the host every refresh -- and every swap makes the next
/// requests dial a new address and pay a new TCP and TLS handshake for no
/// reason. Envoy gets the same stability differently: its one logical host
/// keeps its pooled connections when the address behind it changes; this
/// proxy's hosts are immutable snapshots, so stability comes from not
/// changing the address unless it has to (see
/// `internal-docs/envoy-divergences.md`).
async fn logical_dns_hosts(
    endpoints: &[EndpointIR],
    resolver: &dyn HostResolver,
    previous: &HostSet,
) -> io::Result<Vec<Arc<Host>>> {
    let mut hosts = Vec::new();
    for e in endpoints {
        let ips = resolver.resolve(&e.host).await?;
        let chosen = current_address(previous, e)
            .filter(|current| ips.contains(current))
            .or_else(|| ips.first().copied());
        if let Some(ip) = chosen {
            hosts.push(Arc::new(Host {
                address: SocketAddr::new(ip, e.port),
                hostname: Some(e.host.clone()),
                metadata: e.metadata.clone(),
                weight: e.weight,
                priority: e.priority,
                health_flags: HealthFlags::default(),
                active_requests: AtomicU64::new(0),
            }));
        }
    }
    Ok(hosts)
}

/// The address `previous` already holds for `endpoint`'s logical host. A
/// logical host is identified by what it was resolved from -- hostname, port
/// and priority -- because the address is the part that changes.
fn current_address(previous: &HostSet, endpoint: &EndpointIR) -> Option<IpAddr> {
    previous
        .hosts_for_priority(endpoint.priority)
        .iter()
        .find(|host| {
            host.hostname.as_deref() == Some(endpoint.host.as_str())
                && host.address.port() == endpoint.port
        })
        .map(|host| host.address.ip())
}

// ------------------------------------------------------- refresh pacing --

/// The wait before the next lookup after one that succeeded: the refresh rate
/// plus a share of the jitter bound. Envoy's `dns_jitter` is the exclusive
/// upper bound of a uniform random delay added to every refresh.
///
/// `unit` is the random draw, in `[0, 1)`. It is an argument rather than drawn
/// here so the arithmetic is exactly testable.
fn success_wait(refresh: &DnsRefresh, unit: f64) -> Duration {
    refresh
        .refresh_rate
        .saturating_add(refresh.jitter.mul_f64(unit))
}

/// The wait before retrying after `consecutive_failures` failed lookups in a
/// row (1 = the first failure): exponential from `failure_base_interval`,
/// doubling per failure and capped at `failure_max_interval`, with jitter.
///
/// The jitter keeps the wait uniform in `(step / 2, step]`, so a fleet of
/// replicas that lost DNS together does not retry in lockstep, a retry never
/// comes sooner than half of the exponential step (a down resolver is not
/// hammered), and the wait never exceeds the configured maximum. When the
/// base and maximum are equal -- Envoy's default, where failures retry at the
/// refresh rate -- the interval is fixed and gets no jitter.
///
/// `unit` is the random draw, in `[0, 1)`; see [`success_wait`].
fn failure_wait(refresh: &DnsRefresh, consecutive_failures: u32, unit: f64) -> Duration {
    let base = refresh.failure_base_interval;
    let max = refresh.failure_max_interval;
    // base * 2^(failures - 1), found by doubling until the cap: unlike a
    // `1 << n` shift this cannot overflow however long the outage lasts, and
    // it stops after a handful of steps instead of walking the whole streak.
    let mut step = base;
    for _ in 1..consecutive_failures {
        if step >= max {
            break;
        }
        step = step.saturating_mul(2);
    }
    let step = step.min(max);
    if base == max {
        return step;
    }
    step.mul_f64(1.0 - 0.5 * unit)
}

/// Whether the `consecutive_failures`-th failure of a streak is logged at
/// `warn`: the first, then every power of two (2nd, 4th, 8th, ...). An outage
/// is loud when it starts and stays visible while it lasts, without a line
/// per retry; the failures in between log at `debug`.
pub(crate) fn should_warn(consecutive_failures: u32) -> bool {
    consecutive_failures.is_power_of_two()
}

/// Paces one DNS cluster's lookups: how long to wait after each result, and
/// how many lookups in a row have failed.
#[derive(Debug)]
pub(crate) struct RefreshSchedule {
    refresh: DnsRefresh,
    /// Failed lookups in a row; 0 while lookups succeed.
    consecutive_failures: u32,
}

impl RefreshSchedule {
    /// `refresh` must come from lowering, which guarantees every interval is
    /// above 1ms: a zero interval here would make the refresh timer spin.
    pub(crate) fn new(refresh: DnsRefresh) -> Self {
        Self {
            refresh,
            consecutive_failures: 0,
        }
    }

    /// A lookup succeeded. Returns how many failures in a row it ended (0 when
    /// the previous lookup succeeded too) and how long to wait for the next.
    pub(crate) fn lookup_succeeded(&mut self) -> (u32, Duration) {
        let ended = std::mem::take(&mut self.consecutive_failures);
        (ended, success_wait(&self.refresh, rand::random()))
    }

    /// A lookup failed. Returns the length of the failure streak, this
    /// failure included, and how long to wait before retrying.
    pub(crate) fn lookup_failed(&mut self) -> (u32, Duration) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        (
            self.consecutive_failures,
            failure_wait(&self.refresh, self.consecutive_failures, rand::random()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::FakeResolver;
    use proxy_config::ir::{ClusterKind, LbPolicy};
    use std::time::Duration as StdDuration;

    fn cluster(discovery: DiscoveryType, endpoints: Vec<EndpointIR>) -> ClusterConfig {
        ClusterConfig {
            // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
            eds: None,
            name: "test".to_string(),
            discovery,
            lb_policy: LbPolicy::RoundRobin,
            connect_timeout: StdDuration::from_secs(5),
            endpoints,
            kind: ClusterKind::Endpoints,
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1 << 20,
            circuit_breakers: Default::default(),
            upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
            request_headers_to_add: Vec::new(),
            request_path_rewrite: None,
            provider_runtime: None,
            usage_dialect: None,
            health_check: None,
            outlier_detection: None,
        }
    }

    fn endpoint(host: &str, port: u16) -> EndpointIR {
        EndpointIR {
            metadata: Default::default(),
            host: host.to_string(),
            port,
            weight: 1,
            priority: 0,
        }
    }

    #[tokio::test]
    async fn static_discovery_uses_literal_endpoints() {
        let config = cluster(
            DiscoveryType::Static,
            vec![endpoint("10.0.0.1", 80), endpoint("10.0.0.2", 80)],
        );
        let resolver = FakeResolver::new();
        let set = resolve(&config, &resolver, &HostSet::default())
            .await
            .unwrap();
        let mut addrs: Vec<_> = set
            .all_hosts()
            .iter()
            .map(|h| h.address.to_string())
            .collect();
        addrs.sort();
        assert_eq!(addrs, vec!["10.0.0.1:80", "10.0.0.2:80"]);
    }

    #[tokio::test]
    async fn strict_dns_yields_all_records() {
        let config = cluster(
            DiscoveryType::StrictDns(DnsRefresh::ENVOY_DEFAULT),
            vec![endpoint("svc.internal", 80)],
        );
        let resolver = FakeResolver::new();
        resolver.set(
            "svc.internal",
            vec![
                IpAddr::from([10, 0, 0, 1]),
                IpAddr::from([10, 0, 0, 2]),
                IpAddr::from([10, 0, 0, 3]),
            ],
        );
        let set = resolve(&config, &resolver, &HostSet::default())
            .await
            .unwrap();
        assert_eq!(set.all_hosts().len(), 3);
    }

    #[tokio::test]
    async fn logical_dns_keeps_a_single_host() {
        let config = cluster(
            DiscoveryType::LogicalDns(DnsRefresh::ENVOY_DEFAULT),
            vec![endpoint("svc.internal", 80)],
        );
        let resolver = FakeResolver::new();
        resolver.set(
            "svc.internal",
            vec![IpAddr::from([10, 0, 0, 1]), IpAddr::from([10, 0, 0, 2])],
        );
        let set = resolve(&config, &resolver, &HostSet::default())
            .await
            .unwrap();
        assert_eq!(set.all_hosts().len(), 1);
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    /// The addresses `set` holds, sorted, as strings.
    fn addresses(set: &HostSet) -> Vec<String> {
        let mut addrs: Vec<_> = set
            .all_hosts()
            .iter()
            .map(|h| h.address.to_string())
            .collect();
        addrs.sort();
        addrs
    }

    fn logical(endpoints: Vec<EndpointIR>) -> ClusterConfig {
        cluster(
            DiscoveryType::LogicalDns(DnsRefresh::ENVOY_DEFAULT),
            endpoints,
        )
    }

    /// Round-robin DNS answers the same record set in a different order on
    /// every query. The logical host must not follow the first entry around.
    #[tokio::test]
    async fn logical_dns_keeps_its_address_while_the_answer_still_contains_it() {
        let config = logical(vec![endpoint("svc.internal", 80)]);
        let resolver = FakeResolver::new();
        resolver.set("svc.internal", vec![ip(1), ip(2)]);
        let first = resolve(&config, &resolver, &HostSet::default())
            .await
            .unwrap();
        assert_eq!(addresses(&first), vec!["10.0.0.1:80"]);

        // Reordered, then reordered again with a new record: still .1.
        for answer in [vec![ip(2), ip(1)], vec![ip(3), ip(2), ip(1)]] {
            resolver.set("svc.internal", answer);
            let next = resolve(&config, &resolver, &first).await.unwrap();
            assert_eq!(addresses(&next), vec!["10.0.0.1:80"]);
        }
    }

    #[tokio::test]
    async fn logical_dns_moves_to_the_first_address_when_its_own_is_gone() {
        let config = logical(vec![endpoint("svc.internal", 80)]);
        let resolver = FakeResolver::new();
        resolver.set("svc.internal", vec![ip(1), ip(2)]);
        let first = resolve(&config, &resolver, &HostSet::default())
            .await
            .unwrap();

        resolver.set("svc.internal", vec![ip(3), ip(2)]);
        let next = resolve(&config, &resolver, &first).await.unwrap();
        assert_eq!(addresses(&next), vec!["10.0.0.3:80"]);
    }

    /// A logical host is identified by hostname, port and priority; another
    /// endpoint's address in `previous` must not be adopted.
    #[tokio::test]
    async fn logical_dns_stickiness_is_per_endpoint() {
        let config = logical(vec![endpoint("a.internal", 80), endpoint("b.internal", 80)]);
        let resolver = FakeResolver::new();
        resolver.set("a.internal", vec![ip(1), ip(2)]);
        resolver.set("b.internal", vec![ip(3), ip(4)]);
        let first = resolve(&config, &resolver, &HostSet::default())
            .await
            .unwrap();
        assert_eq!(addresses(&first), vec!["10.0.0.1:80", "10.0.0.3:80"]);

        // `a` rotates; `b`'s old address (.3) now also appears in `a`'s
        // answer, which must not drag `a` there.
        resolver.set("a.internal", vec![ip(3), ip(2), ip(1)]);
        resolver.set("b.internal", vec![ip(4), ip(3)]);
        let next = resolve(&config, &resolver, &first).await.unwrap();
        let by_host: Vec<_> = next
            .all_hosts()
            .iter()
            .map(|h| (h.hostname.clone().unwrap(), h.address.to_string()))
            .collect();
        assert_eq!(
            by_host,
            vec![
                ("a.internal".to_string(), "10.0.0.1:80".to_string()),
                ("b.internal".to_string(), "10.0.0.3:80".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn strict_dns_ignores_the_previous_set() {
        let config = cluster(
            DiscoveryType::StrictDns(DnsRefresh::ENVOY_DEFAULT),
            vec![endpoint("svc.internal", 80)],
        );
        let resolver = FakeResolver::new();
        resolver.set("svc.internal", vec![ip(1), ip(2)]);
        let first = resolve(&config, &resolver, &HostSet::default())
            .await
            .unwrap();
        resolver.set("svc.internal", vec![ip(2), ip(3)]);
        let next = resolve(&config, &resolver, &first).await.unwrap();
        assert_eq!(addresses(&next), vec!["10.0.0.2:80", "10.0.0.3:80"]);
    }

    // ------------------------------------------------------ refresh pacing --

    const S: StdDuration = StdDuration::from_secs(1);

    fn refresh(rate: u64, jitter: u64, failure_base_ms: u64, failure_max_ms: u64) -> DnsRefresh {
        DnsRefresh {
            refresh_rate: StdDuration::from_secs(rate),
            jitter: StdDuration::from_secs(jitter),
            failure_base_interval: StdDuration::from_millis(failure_base_ms),
            failure_max_interval: StdDuration::from_millis(failure_max_ms),
        }
    }

    #[test]
    fn success_wait_adds_a_share_of_the_jitter_bound() {
        let r = refresh(5, 4, 5000, 5000);
        assert_eq!(success_wait(&r, 0.0), 5 * S);
        assert_eq!(success_wait(&r, 0.5), 7 * S);
        // The bound is exclusive: a draw just under 1 stays under it.
        assert!(success_wait(&r, 0.999_999) < 9 * S);
        assert!(success_wait(&r, 0.999_999) > 8 * S);
    }

    #[test]
    fn success_wait_without_jitter_is_exactly_the_refresh_rate() {
        let r = refresh(5, 0, 5000, 5000);
        for unit in [0.0, 0.3, 0.999] {
            assert_eq!(success_wait(&r, unit), 5 * S);
        }
    }

    /// Streaks 1..=6 against base 1s: the exponential step doubles until it
    /// reaches the max and stays there, and the jittered wait lies in
    /// (step/2, step]. Two maxima: 8s, a power-of-two multiple of the base, and
    /// 5s, where plain doubling would overshoot (1, 2, 4, 8) and the cap has to
    /// pull the step back down.
    #[test]
    fn failure_wait_doubles_from_the_base_and_stops_at_the_max() {
        for (max_ms, steps) in [(8000, [1, 2, 4, 8, 8, 8]), (5000, [1, 2, 4, 5, 5, 5])] {
            let r = refresh(5, 0, 1000, max_ms);
            for (i, step) in steps.into_iter().enumerate() {
                let streak = i as u32 + 1;
                let step = step * S;
                // unit 0 is the top of the range: the whole step.
                assert_eq!(
                    failure_wait(&r, streak, 0.0),
                    step,
                    "max {max_ms}ms, streak {streak}"
                );
                let low = failure_wait(&r, streak, 0.999_999);
                assert!(
                    low > step / 2,
                    "max {max_ms}ms, streak {streak}: {low:?} not above half of {step:?}"
                );
                assert!(low <= step, "max {max_ms}ms, streak {streak}");
            }
        }
    }

    /// Envoy's default: no `dns_failure_refresh_rate`, so failures retry at
    /// the refresh rate -- a fixed interval, no growth and no jitter.
    #[test]
    fn failure_wait_is_fixed_when_base_and_max_are_equal() {
        let r = refresh(5, 0, 5000, 5000);
        for streak in [1, 2, 10, 1000] {
            for unit in [0.0, 0.4, 0.999] {
                assert_eq!(failure_wait(&r, streak, unit), 5 * S);
            }
        }
    }

    #[test]
    fn failure_wait_survives_an_enormous_streak() {
        let r = refresh(5, 0, 1, 3_600_000);
        let wait = failure_wait(&r, u32::MAX, 0.5);
        assert!(wait <= StdDuration::from_secs(3600));
        assert!(wait > StdDuration::from_secs(1800));
    }

    #[test]
    fn only_the_first_and_each_power_of_two_failure_warns() {
        let warned: Vec<u32> = (1..=40).filter(|n| should_warn(*n)).collect();
        assert_eq!(warned, vec![1, 2, 4, 8, 16, 32]);
    }

    #[test]
    fn schedule_counts_the_streak_and_reports_it_when_it_ends() {
        let mut schedule = RefreshSchedule::new(refresh(5, 0, 5000, 5000));
        assert_eq!(schedule.lookup_failed(), (1, 5 * S));
        assert_eq!(schedule.lookup_failed(), (2, 5 * S));
        assert_eq!(schedule.lookup_succeeded(), (2, 5 * S));
        // The streak is over: a success after a success ended nothing.
        assert_eq!(schedule.lookup_succeeded(), (0, 5 * S));
        assert_eq!(schedule.lookup_failed(), (1, 5 * S));
    }
}
