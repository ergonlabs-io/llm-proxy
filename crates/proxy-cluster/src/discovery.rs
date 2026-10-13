//! Discovery: turns a [`ClusterConfig`]'s configured endpoints into a
//! [`HostSet`].
//!
//! `STATIC` needs no I/O -- its endpoints are already literal IPs (enforced
//! at config lowering, see `proxy-config/src/lower.rs`). `STRICT_DNS` and
//! `LOGICAL_DNS` resolve through a [`HostResolver`] and are the only variants
//! that need re-resolution on a timer. `EDS` clusters have no self-driven
//! discovery here at all; their membership is fed in externally, handled at
//! the [`crate::manager::ClusterManager`] level (see
//! `ClusterManager::accept_eds_update`).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use proxy_config::ir::{ClusterConfig, DiscoveryType, EndpointIR};

use crate::host_set::HostSet;
use crate::resolver::HostResolver;
use crate::{HealthFlags, Host};

/// Envoy's default `dns_refresh_rate` for `STRICT_DNS`/`LOGICAL_DNS`
/// clusters. TODO: wire `ClusterConfig.dns_refresh_rate` once the IR
/// carries it. Nothing in the workspace uses this constant yet.
pub const DEFAULT_DNS_REFRESH_RATE: Duration = Duration::from_secs(5);

/// Envoy's default `initial_fetch_timeout`: how long cluster warming
/// waits for a cluster's first resolution/EDS response before proceeding
/// with an empty host set. The caller (`proxy/src/main.rs`) applies it; the
/// manual "mark initialized anyway" escape hatch is
/// [`crate::manager::ClusterManager::force_initialize`].
pub const DEFAULT_INITIAL_FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// Resolve `config`'s endpoints into a host set.
pub async fn resolve(config: &ClusterConfig, resolver: &dyn HostResolver) -> io::Result<HostSet> {
    let hosts = match config.discovery {
        DiscoveryType::Static => static_hosts(&config.endpoints)?,
        DiscoveryType::StrictDns(_) => strict_dns_hosts(&config.endpoints, resolver).await?,
        DiscoveryType::LogicalDns(_) => logical_dns_hosts(&config.endpoints, resolver).await?,
        // An EDS cluster owns no endpoints to resolve -- its membership
        // arrives through
        // [`crate::manager::ClusterManager::accept_eds_update`]. Empty, not
        // an error: a cluster whose EDS response has not landed yet is the
        // ordinary startup state, and warming is what stops traffic
        // reaching it meanwhile.
        //
        // **Callers must not reach here for an EDS cluster in the steady
        // state**, and `ClusterManager::refresh_cluster` has an explicit arm
        // to make sure they do not: resolving to empty on a DNS-cadence
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

/// `LOGICAL_DNS`: one logical host per configured endpoint, keeping only the
/// first address from the latest resolution (Envoy semantics -- connect-time
/// re-resolution belongs to the connection pool, not here).
async fn logical_dns_hosts(
    endpoints: &[EndpointIR],
    resolver: &dyn HostResolver,
) -> io::Result<Vec<Arc<Host>>> {
    let mut hosts = Vec::new();
    for e in endpoints {
        let ips = resolver.resolve(&e.host).await?;
        if let Some(ip) = ips.into_iter().next() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::FakeResolver;
    use proxy_config::ir::{ClusterKind, DnsRefresh, LbPolicy};
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
        let set = resolve(&config, &resolver).await.unwrap();
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
        let set = resolve(&config, &resolver).await.unwrap();
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
        let set = resolve(&config, &resolver).await.unwrap();
        assert_eq!(set.all_hosts().len(), 1);
    }
}
