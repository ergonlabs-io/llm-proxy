//! Internal representation (IR) of the proxy configuration — WP-05.
//!
//! The IR is the single most load-bearing API surface in the project: every lane
//! codes against these types. It is built once per config update on the control
//! runtime, is immutable, and is shared with workers as `Arc<ConfigSnapshot>`.
//!
//! All matcher pre-computation (S1 domain sort orders, compiled regexes, weighted
//! cluster cumulative arrays) happens at IR-build time, never on the hot path.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

pub type ListenerName = String;
pub type ClusterName = String;
pub type RouteConfigName = String;
pub type SecretName = String;

/// Monotonic snapshot version, surfaced in `/config_dump` and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct SnapshotVersion(pub u64);

/// The immutable root of all runtime configuration.
#[derive(Debug, Default)]
pub struct ConfigSnapshot {
    pub listeners: HashMap<ListenerName, Arc<ListenerConfig>>,
    pub clusters: HashMap<ClusterName, Arc<ClusterConfig>>,
    pub routes: HashMap<RouteConfigName, Arc<RouteTable>>,
    pub secrets: HashMap<SecretName, Arc<TlsSecret>>,
    pub version: SnapshotVersion,
}

/// IR for `envoy.config.listener.v3.Listener`. TODO(WP-05): full field set —
/// every proto field maps here or errors (exhaustive-match checklist).
#[derive(Debug)]
pub struct ListenerConfig {
    pub name: ListenerName,
    pub address: SocketAddr,
    pub filter_chains: Vec<FilterChainSpec>,
    pub default_filter_chain: Option<FilterChainSpec>,
    /// Default 1 MiB (verify against pinned docs, see S-table).
    pub per_connection_buffer_limit_bytes: u32,
}

/// One `filter_chains` entry: match criteria + transport socket + network filters.
/// Matching algorithm is the fixed 8-step narrowing specified in WP-07.
#[derive(Debug)]
pub struct FilterChainSpec {
    // TODO(WP-05/WP-07): match criteria (dst port/IP CIDR, SNI, ALPN, source...),
    // transport socket config, ordered network filter configs.
}

/// IR for `envoy.config.cluster.v3.Cluster`.
#[derive(Debug)]
pub struct ClusterConfig {
    pub name: ClusterName,
    // TODO(WP-05/WP-16): discovery type, LB policy (S7), connect_timeout,
    // circuit breakers (S5), outlier detection (S6), health checks,
    // upstream TLS context, protocol options.
}

/// Pre-compiled route table for one `RouteConfiguration` (S1 semantics).
#[derive(Debug)]
pub struct RouteTable {
    pub name: RouteConfigName,
    // TODO(WP-05/WP-12): virtual hosts with pre-sorted domain match structures
    // (exact map, suffix wildcards longest-first, prefix wildcards longest-first,
    // optional catch-all), each with its ordered route list (first match wins).
}

/// One matched route: the resolved action + policies for a request (S1). Returned
/// by the WP-12 matching engine and cached per-stream (S2.8 route cache).
#[derive(Debug)]
pub struct RouteEntry {
    // TODO(WP-05/WP-12): action (cluster / weighted / redirect / direct response),
    // timeouts (S4), retry policy (S3), header mutations, per-filter config map.
}

/// A validated TLS certificate/validation-context secret (static or SDS-delivered).
#[derive(Debug)]
pub struct TlsSecret {
    pub name: SecretName,
    // TODO(WP-08/WP-22): cert chain, private key, validation context.
}
