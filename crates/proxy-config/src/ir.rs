//! Internal representation (IR) of the proxy configuration — WP-05.
//!
//! The IR is the single most load-bearing API surface in the project: every
//! lane codes against these types. It is built once per config update on the
//! control runtime (see [`crate::lower`]), is immutable, and is shared with
//! workers as `Arc<ConfigSnapshot>`.
//!
//! All matcher pre-computation happens at IR-build time, never on the hot
//! path: S1 domain lookup structures (exact map + wildcard lists sorted
//! longest-first), compiled regexes, weighted-cluster cumulative weight arrays.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

// Rust note: `FormatString` and `ResponseFlag` are re-exported from
// `proxy-observability` rather than redefined here — WP-24's format engine
// (parser + renderer) lives there (see that crate's `access_log` module),
// and the IR only needs to *hold* the already-parsed result, not know how to
// build or render it (ground rule #2's spirit: keep the parsing/rendering
// logic in the crate that owns it).
use proxy_observability::access_log::FormatString;
use proxy_observability::ResponseFlag;

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
    /// RDS-delivered route tables (WP-21). Route tables inlined in an HCM live
    /// on the [`HttpConnectionManagerConfig`] itself, not here.
    pub routes: HashMap<RouteConfigName, Arc<RouteTable>>,
    pub secrets: HashMap<SecretName, Arc<TlsSecret>>,
    /// Admin endpoint bind address (WP-25), when configured.
    pub admin: Option<SocketAddr>,
    pub version: SnapshotVersion,
}

// ---------------------------------------------------------------- listeners --

/// IR for `envoy.config.listener.v3.Listener` (supported surface; unsupported
/// proto fields are rejected at conversion with their full path).
#[derive(Debug)]
pub struct ListenerConfig {
    pub name: ListenerName,
    pub address: SocketAddr,
    pub filter_chains: Vec<FilterChainSpec>,
    pub default_filter_chain: Option<FilterChainSpec>,
    /// Ordered listener (pre-connection) filters that run against the raw
    /// socket before filter-chain matching — currently only `tls_inspector`.
    /// May be auto-injected: see [`ListenerFilterSpec`].
    pub listener_filters: Vec<ListenerFilterSpec>,
    /// Envoy default: 1 MiB.
    pub per_connection_buffer_limit_bytes: u32,
    /// `None` = platform default backlog.
    pub tcp_backlog_size: Option<u32>,
    /// Envoy default: true.
    pub bind_to_port: bool,
}

/// A listener filter (`envoy.config.listener.v3.ListenerFilter`), resolved
/// from its `typed_config` type URL. These run on the accepted connection
/// *before* filter-chain matching, populating the properties the matcher
/// keys on (SNI, ALPN, transport protocol).
///
/// Auto-injection: like Envoy, the lowering inserts a default `TlsInspector`
/// when a filter chain matches on `server_names`, `application_protocols`, or
/// `transport_protocol: tls` but no `tls_inspector` was configured — omitting
/// it would silently make those criteria never match TLS traffic, a worse
/// divergence than the injection. Recorded in `docs/envoy-divergences.md`.
#[derive(Debug)]
pub enum ListenerFilterSpec {
    TlsInspector(TlsInspectorConfig),
}

/// IR for `envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector`
/// (supported subset). Peeks the ClientHello for SNI + ALPN without consuming
/// the bytes, so the real TLS handshake still sees them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsInspectorConfig {
    /// Upper bound on bytes buffered while waiting for a full ClientHello
    /// before giving up. Envoy default: 64 KiB (`max_client_hello_size`,
    /// which Envoy caps at 16 KiB — the TLS record maximum — but the field
    /// default is 16384). A ClientHello exceeding this is treated as a parse
    /// failure.
    pub max_client_hello_size: u32,
}

impl Default for TlsInspectorConfig {
    fn default() -> Self {
        // Envoy's `max_client_hello_size` default and hard cap are both
        // 16384 (one TLS record); a ClientHello can't exceed that on the wire.
        Self {
            max_client_hello_size: 16384,
        }
    }
}

/// One `filter_chains` entry: match criteria + transport socket + the network
/// filters. Full 8-step matching lands with WP-07; the criteria live here.
#[derive(Debug)]
pub struct FilterChainSpec {
    pub name: Option<String>,
    pub match_criteria: FilterChainMatch,
    /// Downstream TLS termination, when configured.
    pub transport_socket: Option<DownstreamTlsSpec>,
    /// Ordered network filters; the last one is terminal.
    pub filters: Vec<NetworkFilterSpec>,
}

/// `envoy.config.core.v3.CidrRange`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrRange {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl CidrRange {
    /// True if `ip` is inside this range. Address families never match each
    /// other (an IPv4 range does not contain a v4-mapped IPv6 address, and
    /// vice versa — Envoy keeps the families distinct).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let prefix = self.prefix_len.min(32);
                // Rust note: a 0-bit mask can't be built with `<< 32` (that's a
                // shift-by-width, which panics/UB) so it's special-cased.
                let mask: u32 = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let prefix = self.prefix_len.min(128);
                let mask: u128 = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                (u128::from(net) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }
}

/// `FilterChainMatch.ConnectionSourceType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SourceType {
    #[default]
    Any,
    SameIpOrLoopback,
    External,
}

/// Full 9-criteria `FilterChainMatch` (WP-07). Field order mirrors Envoy's
/// matching precedence.
#[derive(Debug, Default, PartialEq)]
pub struct FilterChainMatch {
    pub destination_port: Option<u32>,
    pub prefix_ranges: Vec<CidrRange>,
    /// SNI: exact names or `*.`-prefixed suffix wildcards.
    pub server_names: Vec<String>,
    /// e.g. "raw_buffer" or "tls"; `None` = any.
    pub transport_protocol: Option<String>,
    /// ALPN protocol list; empty = any.
    pub application_protocols: Vec<String>,
    pub direct_source_prefix_ranges: Vec<CidrRange>,
    pub source_type: SourceType,
    pub source_prefix_ranges: Vec<CidrRange>,
    pub source_ports: Vec<u32>,
}

/// A network (L4) filter, resolved from its `typed_config` type URL.
#[derive(Debug)]
pub enum NetworkFilterSpec {
    TcpProxy(TcpProxyConfig),
    HttpConnectionManager(HttpConnectionManagerConfig),
}

/// IR for `envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy`.
#[derive(Debug)]
pub struct TcpProxyConfig {
    pub stat_prefix: String,
    pub cluster: ClusterName,
    /// Envoy default: 1h. `None` = disabled (explicit 0).
    pub idle_timeout: Option<Duration>,
    /// Upstream connect attempts before giving up. Envoy default 1 (no
    /// retry); proto floor is 1.
    pub max_connect_attempts: u32,
}

/// IR for the HTTP connection manager (supported subset).
#[derive(Debug)]
pub struct HttpConnectionManagerConfig {
    pub stat_prefix: String,
    /// The inlined route table (RDS arrives with WP-21).
    pub route_table: Arc<RouteTable>,
    /// Ordered HTTP filters; the last must be the router.
    pub http_filters: Vec<HttpFilterSpec>,
    /// S9: generate an `x-request-id` when the request lacks one. Envoy
    /// default true (the proto field is a `BoolValue`; absent => true).
    pub generate_request_id: bool,
    /// S9/HCM `use_remote_address`: when true, append the immediate downstream
    /// peer to `x-forwarded-for` and set `x-forwarded-proto` from our
    /// transport (edge behavior). Envoy default: false.
    pub use_remote_address: bool,
    /// S9/HCM `xff_num_trusted_hops`: trusted proxy hops when resolving the
    /// real client from an inbound XFF (only meaningful with
    /// use_remote_address=false). Envoy default: 0.
    pub xff_num_trusted_hops: u32,
    /// WP-24 chunk 1: parsed access-log sinks, in configured order. Chunk 2
    /// wires the actual per-request render + write; this crate only builds
    /// the IR.
    pub access_logs: Vec<AccessLogIR>,
}

// -------------------------------------------------------------- access log --

/// IR for one `envoy.config.accesslog.v3.AccessLog` entry: where a rendered
/// line goes, how it's formatted, and (optionally) whether it's emitted at
/// all for a given request.
#[derive(Debug, Clone)]
pub struct AccessLogIR {
    pub sink: AccessLogSink,
    pub format: AccessLogFormat,
    pub filter: Option<AccessLogFilterIR>,
}

/// Where a rendered access-log line is written.
///
/// This is `proxy_observability`'s type, re-exported so the IR reads as one
/// surface — the same arrangement already used for [`FormatString`] and
/// [`ResponseFlag`] above. It deliberately lives in `proxy-observability`
/// rather than here because that crate owns the runtime sink that opens and
/// writes the destination, and `proxy-config` depends on it (never the
/// reverse). Defining a same-shaped twin here instead would mean a new sink
/// variant could be added on one side and silently not exist on the other,
/// which is exactly the class of drift ground rule #1 exists to prevent.
pub use proxy_observability::sink::AccessLogSink;

/// A logger's `log_format`, pre-parsed at config time (never re-parsed per
/// request). Mirrors `envoy.config.core.v3.SubstitutionFormatString`'s
/// `text_format`/`json_format` oneof.
#[derive(Debug, Clone)]
pub enum AccessLogFormat {
    Text(FormatString),
    /// Ordered `(key, value-format)` pairs — `Struct` field order isn't
    /// significant in JSON, but keeping the configured order makes output
    /// deterministic and diff-friendly.
    Json(Vec<(String, FormatString)>),
}

/// Envoy's real default access-log line (no `log_format` configured), from
/// the Envoy access-log documentation's "Default format string" section
/// (`SubstitutionFormatUtils::DEFAULT_FORMAT` in Envoy's source,
/// `source/common/formatter/substitution_formatter.cc`):
///
/// ```text
/// [%START_TIME%] "%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%"
/// %RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION%
/// %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% "%REQ(X-FORWARDED-FOR)%"
/// "%REQ(USER-AGENT)%" "%REQ(X-REQUEST-ID)%" "%REQ(:AUTHORITY)%" "%UPSTREAM_HOST%"
/// ```
pub const DEFAULT_ACCESS_LOG_FORMAT: &str = concat!(
    "[%START_TIME%] \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" ",
    "%RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% ",
    "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%REQ(X-FORWARDED-FOR)%\" ",
    "\"%REQ(USER-AGENT)%\" \"%REQ(X-REQUEST-ID)%\" \"%REQ(:AUTHORITY)%\" \"%UPSTREAM_HOST%\"\n",
);

/// S9-style gate on whether a request's line is emitted at all. Envoy's
/// `AccessLogFilter` has a much larger oneof (duration, runtime sampling,
/// header match, and/and, gRPC status, metadata, ...); only the two
/// operators reachable with what the proxy records today are implemented —
/// anything else is a strict-mode config error naming its dotted path
/// (ground rule #1), not a silent no-op filter.
#[derive(Debug, Clone)]
pub enum AccessLogFilterIR {
    StatusCode {
        op: ComparisonOp,
        value: u32,
    },
    /// Log only if the response carries at least one of these flags. An
    /// empty list matches Envoy's "unspecified = any flag passes" behavior.
    ResponseFlag(Vec<ResponseFlag>),
}

/// `envoy.config.accesslog.v3.ComparisonFilter.Op`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonOp {
    Eq,
    Ge,
    Le,
    Ne,
}

/// One entry of Envoy's `typed_per_filter_config` map: a per-route override
/// for a single HTTP filter, left undecoded for the same reason
/// [`HttpFilterSpec::config`] is (ground rule #2 -- the `proxy-http` registry
/// owns per-filter parsing, not the IR).
#[derive(Debug)]
pub struct PerFilterConfig {
    /// Type URL of the *inner* config (after any `FilterConfig` unwrapping).
    pub type_url: String,
    /// `None` when `disabled` is set (Envoy allows a bare disable with no config).
    pub config: Option<prost_reflect::DynamicMessage>,
    /// `envoy.config.route.v3.FilterConfig.is_optional`: tolerate a filter
    /// name that isn't in the chain, instead of rejecting the config.
    pub is_optional: bool,
    /// `envoy.config.route.v3.FilterConfig.disabled`: disable this filter for
    /// this route.
    pub disabled: bool,
}

/// An HTTP filter, resolved from its `typed_config` type URL.
///
/// Rust note: `config` is left as a [`prost_reflect::DynamicMessage`] (a
/// reflectively-typed proto value, not a generated Rust struct) rather than
/// decoded into a filter-specific IR type here — `proxy-config` doesn't know
/// what any given filter's config shape means; that's `HttpFilterFactory`'s
/// job (`proxy-http`), which is why `create` takes a `&DynamicMessage`
/// directly (ground rule #2: the registry, not the IR, owns per-filter
/// parsing).
#[derive(Debug)]
pub struct HttpFilterSpec {
    /// Envoy filter name, e.g. `envoy.filters.http.router`.
    pub name: String,
    /// `typed_config` type URL, the registry key.
    pub type_url: String,
    /// The filter's own decoded `typed_config`; `None` for filters with no
    /// config.
    pub config: Option<prost_reflect::DynamicMessage>,
    /// True for `envoy.filters.http.router` — the terminal filter.
    pub is_router: bool,
}

// ----------------------------------------------------------------- clusters --

/// IR for `envoy.config.cluster.v3.Cluster` (supported surface).
#[derive(Debug)]
pub struct ClusterConfig {
    pub name: ClusterName,
    pub discovery: DiscoveryType,
    pub lb_policy: LbPolicy,
    /// Envoy default: 5s.
    pub connect_timeout: Duration,
    pub endpoints: Vec<EndpointIR>,
    /// Whether this cluster owns its own hosts ([`ClusterKind::Endpoints`],
    /// the common case) or is an [`envoy.clusters.aggregate`][agg] that
    /// serves its members' hosts instead ([`ClusterKind::Aggregate`],
    /// WP-35 provider fallback).
    ///
    /// [agg]: https://www.envoyproxy.io/docs/envoy/latest/configuration/upstream/cluster_manager/cluster_runtime#aggregate-cluster
    ///
    /// This is a separate field rather than a `DiscoveryType::Aggregate`
    /// variant because `discovery` answers a narrower question -- "how do I
    /// turn *this cluster's own* endpoints into hosts" -- and an aggregate
    /// has no endpoints at all to turn into anything. Folding "aggregate" in
    /// as a `DiscoveryType` variant would force every `match` that's really
    /// only about STATIC/STRICT_DNS/LOGICAL_DNS resolution mechanics
    /// (`discovery.rs`'s resolver dispatch, `lower.rs`'s STATIC-endpoint-
    /// must-be-an-IP check) to grow an arm for a case that can structurally
    /// never reach it -- exactly the kind of unreachable-but-required-to-
    /// handle match arm a separate field avoids.
    pub kind: ClusterKind,
    /// Upstream TLS, when configured.
    pub transport_socket: Option<UpstreamTlsSpec>,
    /// Envoy default: 1 MiB.
    pub per_connection_buffer_limit_bytes: u32,
    /// S5 circuit-breaker budgets, per routing priority. Always present:
    /// Envoy applies the default thresholds when the config omits them.
    pub circuit_breakers: CircuitBreakers,
    /// Which HTTP protocol the proxy speaks to this cluster's upstreams.
    /// Envoy's default when unconfigured is HTTP/1.1.
    pub upstream_protocol: UpstreamProtocol,
    /// Request header mutations applied because *this cluster* was the one an
    /// attempt actually dialed — applied to the per-attempt head inside the
    /// router's retry loop, never once up front.
    ///
    /// **This is where provider credentials belong, and the reason is WP-35.**
    /// The dialect originally injected the API key, `anthropic-version`, and
    /// `extra_headers` through [`RouteEntry::request_headers_to_add`], which is
    /// resolved once when the route matches. That is correct only while a
    /// request can reach exactly one provider. The moment provider fallback
    /// exists, a route-level credential means the *primary's* API key is sent
    /// to the *fallback's* endpoint — a real key disclosure to a third party,
    /// and the `request_headers_to_add` P0 inverted (not "credentials never
    /// arrive" but "credentials arrive at the wrong place"). A credential has
    /// to follow the connection, not the routing decision.
    ///
    /// **No Envoy proto field maps here, deliberately.** Envoy's own mechanism
    /// for cluster-dependent header mutation is
    /// `WeightedCluster.ClusterWeight.request_headers_to_add`, which is a
    /// *split* construct; `envoy.clusters.aggregate` — the failover construct —
    /// has no equivalent, because aggregate clusters were designed for
    /// homogeneous failover (same service, different zones) where every member
    /// shares one identity. LLM providers are the heterogeneous case. So this
    /// field stays empty under Envoy-mode config (no Envoy config expresses
    /// per-provider auth, so none is rejected for lacking it) and is populated
    /// only by the `llmproxy` dialect. Ground rule #1 governs config → IR, not
    /// IR → Envoy proto, so an IR concept with no proto source violates
    /// nothing — the IR is a semantic model, not a proto mirror (compare
    /// [`UpstreamProtocol`], which flattens `typed_extension_protocol_options`).
    ///
    /// Ordering note: these apply strictly *after*
    /// `access_logging::snapshot_request` has already run (the snapshot is
    /// taken after the decode chain, before the router terminal), so moving
    /// credentials here keeps them out of the access log — the same guarantee
    /// route-level injection had, and for the same reason.
    pub request_headers_to_add: Vec<HeaderMutation>,
}

/// Which HTTP protocol version the proxy speaks to a cluster's upstreams.
///
/// Envoy configures this through the cluster's `typed_extension_protocol_options`
/// map keyed by `envoy.extensions.upstreams.http.v3.HttpProtocolOptions`; the IR
/// flattens that surface to the single dimension the data plane acts on. Envoy's
/// default when the option is absent is HTTP/1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpstreamProtocol {
    /// HTTP/1.1 (Envoy default).
    #[default]
    Http1,
    /// HTTP/2 — prior-knowledge cleartext (h2c) in the current data plane;
    /// ALPN-negotiated h2 over upstream TLS is a follow-up.
    Http2,
}

/// S5 circuit breakers for a cluster: one [`CircuitBreakerThresholds`] bucket
/// per routing priority (`DEFAULT` / `HIGH`). Envoy's proto carries a repeated
/// `thresholds` list tagged by priority; the IR flattens it to the two buckets
/// and fills missing ones with the Envoy defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitBreakers {
    /// Budgets for priority 0 (`RoutingPriority::Default`).
    pub default: CircuitBreakerThresholds,
    /// Budgets for priority 1 (`RoutingPriority::High`).
    pub high: CircuitBreakerThresholds,
}

/// One priority's S5 budgets. Each field caps a live gauge; exceeding it makes
/// the cluster shed load (503 + `UO` + `x-envoy-overloaded`) rather than pile
/// work onto a struggling upstream. Envoy defaults are baked into
/// [`CircuitBreakerThresholds::ENVOY_DEFAULT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitBreakerThresholds {
    /// Max open upstream connections (Envoy default 1024).
    pub max_connections: u32,
    /// Max requests queued waiting for a connection (Envoy default 1024).
    pub max_pending_requests: u32,
    /// Max concurrent active requests (Envoy default 1024).
    pub max_requests: u32,
    /// Max concurrent retries in flight (Envoy default 3).
    pub max_retries: u32,
}

impl CircuitBreakerThresholds {
    /// Envoy's documented per-priority defaults (S5), applied when a priority
    /// has no `thresholds` entry or a field is left at the proto zero-value's
    /// "unset" meaning (Envoy treats an absent `UInt32Value` as the default,
    /// not as 0 — lowering is responsible for that distinction).
    pub const ENVOY_DEFAULT: Self = Self {
        max_connections: 1024,
        max_pending_requests: 1024,
        max_requests: 1024,
        max_retries: 3,
    };
}

impl Default for CircuitBreakerThresholds {
    fn default() -> Self {
        Self::ENVOY_DEFAULT
    }
}

impl Default for CircuitBreakers {
    fn default() -> Self {
        Self {
            default: CircuitBreakerThresholds::ENVOY_DEFAULT,
            high: CircuitBreakerThresholds::ENVOY_DEFAULT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryType {
    /// Endpoints are literal IPs.
    Static,
    /// DNS-resolve every returned address (WP-16).
    StrictDns,
    /// DNS-resolve, use one address at a time (WP-16).
    LogicalDns,
}

/// Where a cluster's hosts come from -- see [`ClusterConfig::kind`]'s doc for
/// why this is a field on `ClusterConfig` rather than a `DiscoveryType`
/// variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterKind {
    /// Hosts come from this cluster's own `endpoints` + `discovery`. Every
    /// cluster before WP-35 increment 2a, and still the overwhelming common
    /// case.
    Endpoints,
    /// `envoy.clusters.aggregate`: this cluster has no hosts of its own.
    /// Host selection walks `members`, in the order listed, and serves the
    /// first member that yields a host -- see
    /// `proxy_cluster::manager::ClusterHandle::select_aggregate_member` for
    /// the exact algorithm (including how it deliberately diverges from
    /// Envoy's own cross-member combined priority set).
    ///
    /// This exists for WP-35 provider fallback: one route target (the
    /// aggregate) whose members are different LLM providers, each with its
    /// own TLS and credentials (`ClusterConfig::request_headers_to_add`) --
    /// a retried attempt that falls over to the next member must carry that
    /// member's identity, never the aggregate's or a previous member's.
    ///
    /// `endpoints`, `discovery`, `transport_socket`, and `upstream_protocol`
    /// are all unused on a `ClusterConfig` whose `kind` is `Aggregate` -- the
    /// member that actually serves the request supplies all four. Ground
    /// rule #1 ("every field maps to IR or errors") does not apply to these
    /// four staying unread here: they simply don't apply to an aggregate,
    /// the same way `endpoints` doesn't apply to an EDS cluster.
    Aggregate {
        /// Member cluster names, in the order failover tries them.
        members: Vec<ClusterName>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbPolicy {
    RoundRobin,
    LeastRequest,
    RingHash,
    Random,
    Maglev,
}

/// An upstream endpoint. `host` is an IP for STATIC clusters and may be a DNS
/// name for the DNS discovery types — resolution is the cluster manager's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointIR {
    pub host: String,
    pub port: u16,
    /// LB weight; Envoy default 1.
    pub weight: u32,
    /// Failover priority; 0 = primary (S5/S7).
    pub priority: u32,
}

// -------------------------------------------------------------------- routes --

/// Pre-compiled route table for one `RouteConfiguration` (S1 semantics).
#[derive(Debug)]
pub struct RouteTable {
    pub name: RouteConfigName,
    pub virtual_hosts: Vec<Arc<VirtualHostIR>>,
    index: DomainIndex,
    /// `RouteConfiguration.typed_per_filter_config`.
    pub typed_per_filter_config: BTreeMap<String, PerFilterConfig>,
}

/// S1 domain-precedence lookup structure, built once at conversion time.
/// Precedence: exact -> suffix wildcard (longest) -> prefix wildcard (longest)
/// -> catch-all `*`. Domain matching is case-insensitive.
#[derive(Debug, Default)]
struct DomainIndex {
    exact: HashMap<String, usize>,
    /// (`suffix` of a `*suffix` domain, vhost index), sorted longest-first.
    suffix_wildcards: Vec<(String, usize)>,
    /// (`prefix` of a `prefix*` domain, vhost index), sorted longest-first.
    prefix_wildcards: Vec<(String, usize)>,
    catch_all: Option<usize>,
}

impl RouteTable {
    /// Build a table, pre-computing the S1 domain index. Duplicate domains
    /// across virtual hosts are a config error (as in Envoy).
    pub fn new(
        name: RouteConfigName,
        mut virtual_hosts: Vec<VirtualHostIR>,
        typed_per_filter_config: BTreeMap<String, PerFilterConfig>,
    ) -> Result<Self, DuplicateDomain> {
        let mut index = DomainIndex::default();
        let mut seen: HashMap<String, ()> = HashMap::new();
        for (i, vhost) in virtual_hosts.iter().enumerate() {
            for domain in &vhost.domains {
                let d = domain.to_ascii_lowercase();
                if seen.insert(d.clone(), ()).is_some() {
                    return Err(DuplicateDomain(d));
                }
                if d == "*" {
                    index.catch_all = Some(i);
                } else if let Some(suffix) = d.strip_prefix('*') {
                    index.suffix_wildcards.push((suffix.to_string(), i));
                } else if let Some(prefix) = d.strip_suffix('*') {
                    index.prefix_wildcards.push((prefix.to_string(), i));
                } else {
                    index.exact.insert(d, i);
                }
            }
        }
        // Rust note: `sort_by_key` with `Reverse` gives descending order and is
        // stable — equal lengths keep config order, matching Envoy.
        use std::cmp::Reverse;
        index
            .suffix_wildcards
            .sort_by_key(|(s, _)| Reverse(s.len()));
        index
            .prefix_wildcards
            .sort_by_key(|(p, _)| Reverse(p.len()));

        // Rust note: assign a dense `route_index` across the whole table
        // before wrapping the virtual hosts in `Arc` and sharing them.
        // `Arc::get_mut` only succeeds while the `Arc`'s strong count is 1,
        // which it still is here -- `convert_route` set each `RouteEntry`'s
        // `Arc` up as a unique owner, and `virtual_hosts` arrived by value,
        // so nothing else has cloned any of these `Arc`s yet.
        let mut next_index = 0usize;
        for vhost in virtual_hosts.iter_mut() {
            for route in vhost.routes.iter_mut() {
                let entry =
                    Arc::get_mut(route).expect("route Arc is still uniquely owned in new()");
                entry.route_index = next_index;
                next_index += 1;
            }
        }

        Ok(Self {
            name,
            virtual_hosts: virtual_hosts.into_iter().map(Arc::new).collect(),
            index,
            typed_per_filter_config,
        })
    }

    /// Number of routes in this table; every `RouteEntry::route_index` is
    /// `< route_count()`. Sized for the `proxy-http` side table.
    pub fn route_count(&self) -> usize {
        self.virtual_hosts.iter().map(|v| v.routes.len()).sum()
    }

    /// S1 virtual-host selection for a request `:authority`/`Host`.
    pub fn find_virtual_host(&self, host: &str) -> Option<&Arc<VirtualHostIR>> {
        let host = host.to_ascii_lowercase();
        let idx = self
            .index
            .exact
            .get(&host)
            .copied()
            .or_else(|| {
                self.index
                    .suffix_wildcards
                    .iter()
                    .find(|(s, _)| host.len() > s.len() && host.ends_with(s.as_str()))
                    .map(|&(_, i)| i)
            })
            .or_else(|| {
                self.index
                    .prefix_wildcards
                    .iter()
                    .find(|(p, _)| host.len() > p.len() && host.starts_with(p.as_str()))
                    .map(|&(_, i)| i)
            })
            .or(self.index.catch_all)?;
        self.virtual_hosts.get(idx)
    }
}

/// Error from [`RouteTable::new`]: the offending (lowercased) domain.
#[derive(Debug)]
pub struct DuplicateDomain(pub String);

#[derive(Debug)]
pub struct VirtualHostIR {
    pub name: String,
    /// Original domain strings, as configured (for `/config_dump`).
    pub domains: Vec<String>,
    /// Ordered routes; first match wins (S1) — evaluated by WP-12.
    ///
    /// Rust note: `Arc<RouteEntry>`, not a bare `RouteEntry` — the S2.8 route
    /// cache (`DecoderCallbacks::route`, in `proxy-http`'s frozen filter API)
    /// hands callers an `Arc<RouteEntry>` clone rather than a borrow tied to
    /// the request's lifetime, so there has to be an `Arc` here to clone from.
    pub routes: Vec<Arc<RouteEntry>>,
    /// `VirtualHost.typed_per_filter_config`.
    pub typed_per_filter_config: BTreeMap<String, PerFilterConfig>,
}

/// One route: pre-compiled matcher + resolved action.
#[derive(Debug)]
pub struct RouteEntry {
    pub name: Option<String>,
    pub matcher: RouteMatcher,
    pub action: RouteActionIR,
    /// Request header mutations applied on match.
    pub request_headers_to_add: Vec<HeaderMutation>,
    /// `Route.typed_per_filter_config`.
    pub typed_per_filter_config: BTreeMap<String, PerFilterConfig>,
    /// Dense index, unique within the owning [`RouteTable`], assigned by
    /// `RouteTable::new`. Lets `proxy-http` keep a side table of parsed
    /// per-route filter configs (which are `proxy-http` types and so cannot
    /// live in the IR) indexed by route, without hashing pointers.
    pub route_index: usize,
}

#[derive(Debug)]
pub struct RouteMatcher {
    pub path: PathMatch,
    /// Envoy default: true.
    pub case_sensitive: bool,
    pub headers: Vec<HeaderMatch>,
}

#[derive(Debug)]
pub enum PathMatch {
    Prefix(String),
    Exact(String),
    /// Compiled at conversion time; full-string match like Envoy's safe_regex.
    Regex(regex::Regex),
}

impl PathMatch {
    /// Path matching semantics (S1); `case_sensitive` is ignored for regexes,
    /// as in Envoy.
    pub fn matches(&self, path: &str, case_sensitive: bool) -> bool {
        match self {
            Self::Prefix(p) if case_sensitive => path.starts_with(p.as_str()),
            Self::Prefix(p) => starts_with_ignore_case(path, p),
            Self::Exact(e) if case_sensitive => path == e,
            Self::Exact(e) => path.eq_ignore_ascii_case(e),
            Self::Regex(re) => re.is_match(path),
        }
    }
}

fn starts_with_ignore_case(haystack: &str, prefix: &str) -> bool {
    haystack.len() >= prefix.len()
        && haystack.is_char_boundary(prefix.len())
        && haystack[..prefix.len()].eq_ignore_ascii_case(prefix)
}

#[derive(Debug)]
pub struct HeaderMatch {
    pub name: String,
    pub kind: HeaderMatchKind,
}

#[derive(Debug)]
pub enum HeaderMatchKind {
    Exact {
        value: String,
        ignore_case: bool,
    },
    Prefix {
        value: String,
        ignore_case: bool,
    },
    Suffix {
        value: String,
        ignore_case: bool,
    },
    Regex(regex::Regex),
    /// `present_match`: header exists (true) / is absent (false).
    Present(bool),
}

#[derive(Debug)]
pub enum RouteActionIR {
    Forward(ForwardAction),
    Redirect(RedirectIR),
    DirectResponse {
        status: u16,
        body: Option<DataSourceIR>,
    },
}

#[derive(Debug)]
pub struct ForwardAction {
    pub target: ForwardTarget,
    /// Total upstream timeout. Envoy default 15s; explicit `0s` disables
    /// (`None`) — the right setting for LLM streaming routes (S4).
    pub timeout: Option<Duration>,
    /// Idle timeout override; `None` inherits the HCM stream idle timeout.
    pub idle_timeout: Option<Duration>,
    pub retry_policy: Option<RetryPolicyIR>,
    pub host_rewrite_literal: Option<String>,
    pub prefix_rewrite: Option<String>,
}

#[derive(Debug)]
pub enum ForwardTarget {
    Cluster(ClusterName),
    /// Cluster name read from a request header (set by e.g. the WP-35 model
    /// router).
    ClusterHeader(String),
    Weighted(WeightedClusters),
}

/// Weighted cluster split with the cumulative-weight array pre-computed for
/// O(log n) selection on the hot path.
#[derive(Debug)]
pub struct WeightedClusters {
    /// (cluster, cumulative weight): e.g. weights 20/30/50 store 20/50/100.
    pub cumulative: Vec<(ClusterName, u64)>,
    pub total_weight: u64,
}

impl WeightedClusters {
    /// Pick a cluster for a uniform draw in `[0, total_weight)`.
    pub fn pick(&self, draw: u64) -> &ClusterName {
        // Rust note: `partition_point` is a binary search returning the first
        // index whose cumulative weight exceeds the draw.
        let i = self.cumulative.partition_point(|&(_, cum)| cum <= draw);
        &self.cumulative[i.min(self.cumulative.len() - 1)].0
    }
}

/// S3 retry policy. Defaults follow Envoy: `num_retries` 1, fully-jittered
/// exponential backoff (base 25ms, cap 250ms) — timing lives in WP-14.
#[derive(Debug, Default)]
pub struct RetryPolicyIR {
    pub retry_on: RetryOn,
    pub num_retries: u32,
    pub per_try_timeout: Option<Duration>,
    pub retriable_status_codes: Vec<u16>,
    /// S3.3 fully-jittered exponential backoff parameters.
    pub retry_back_off: RetryBackOff,
    /// S3.1: how many times a retry may re-run host selection to avoid a
    /// previously-tried host before giving up and reusing one. Envoy default 1.
    pub host_selection_retry_max_attempts: u32,
}

/// S3.3 backoff: attempt *n* (1-based) waits a delay drawn uniformly from
/// `[0, min((2^n - 1) * base_interval, max_interval)]` — "fully jittered"
/// exponential backoff. The progression with Envoy's defaults is 0–25ms,
/// 0–75ms, 0–175ms, ... capped at `max_interval`.
///
/// Drawing from `[0, cap]` rather than waiting exactly `cap` is the whole
/// point: it de-synchronizes clients that all failed at the same instant, so
/// a struggling upstream doesn't get a retry thundering herd on a fixed beat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryBackOff {
    /// Envoy default 25ms.
    pub base_interval: Duration,
    /// Envoy default: 10 × `base_interval`.
    pub max_interval: Duration,
}

impl RetryBackOff {
    /// Envoy's defaults, applied when `retry_back_off` is absent.
    pub const ENVOY_DEFAULT: Self = Self {
        base_interval: Duration::from_millis(25),
        max_interval: Duration::from_millis(250),
    };
}

impl Default for RetryBackOff {
    fn default() -> Self {
        Self::ENVOY_DEFAULT
    }
}

/// Parsed `retry_on` policy set. Unrecognized tokens are ignored, as in Envoy.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RetryOn {
    pub five_xx: bool,
    pub gateway_error: bool,
    pub reset: bool,
    pub reset_before_request: bool,
    pub connect_failure: bool,
    pub refused_stream: bool,
    /// S3: retriable-4xx means 409 only.
    pub retriable_4xx: bool,
    pub retriable_status_codes: bool,
    pub envoy_ratelimited: bool,
}

impl RetryOn {
    pub fn parse(spec: &str) -> Self {
        let mut on = Self::default();
        for token in spec.split(',').map(str::trim) {
            match token {
                "5xx" => on.five_xx = true,
                "gateway-error" => on.gateway_error = true,
                "reset" => on.reset = true,
                "reset-before-request" => on.reset_before_request = true,
                "connect-failure" => on.connect_failure = true,
                "refused-stream" => on.refused_stream = true,
                "retriable-4xx" => on.retriable_4xx = true,
                "retriable-status-codes" => on.retriable_status_codes = true,
                "envoy-ratelimited" => on.envoy_ratelimited = true,
                // Unknown tokens: ignored for Envoy parity (it logs and skips).
                _ => {}
            }
        }
        on
    }
}

#[derive(Debug)]
pub struct RedirectIR {
    pub host_redirect: Option<String>,
    pub path_redirect: Option<String>,
    pub https_redirect: bool,
    /// Envoy default: 301.
    pub response_code: u16,
}

/// A request/response header mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderMutation {
    pub key: String,
    pub value: String,
    pub action: HeaderAppendAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderAppendAction {
    AppendIfExistsOrAdd,
    AddIfAbsent,
    OverwriteIfExistsOrAdd,
    OverwriteIfExists,
}

// ----------------------------------------------------------------- tls/misc --

/// Downstream TLS termination config for a filter chain (WP-08).
///
/// Field-presence semantics follow Envoy v1.38's `DownstreamTlsContext`:
/// anything the lowering can't honor errors at config load with its dotted
/// path — this struct only holds what the rustls transport socket actually
/// implements.
#[derive(Debug)]
pub struct DownstreamTlsSpec {
    /// At least one; multiple entries = one cert per key type (RSA + ECDSA),
    /// selected per-handshake like Envoy/BoringSSL.
    pub certificates: Vec<TlsCertificateIR>,
    pub params: TlsParametersIR,
    /// Offered via ALPN in server order; empty = no ALPN extension.
    pub alpn_protocols: Vec<String>,
    /// Client-certificate (mTLS) verification. `None` = no client certs
    /// requested at all.
    pub validation: Option<ValidationContextIR>,
    /// Envoy: reject connections without a valid client certificate.
    /// Lowering enforces that this requires `validation` to be present.
    pub require_client_certificate: bool,
    /// Envoy default `false`: the server issues stateless session tickets
    /// encrypted with an internally generated key (verified against the
    /// v1.38 proto comment on `disable_stateless_session_resumption`).
    pub disable_stateless_session_resumption: bool,
}

/// Upstream TLS origination config for a cluster (WP-08).
#[derive(Debug)]
pub struct UpstreamTlsSpec {
    pub sni: Option<String>,
    pub params: TlsParametersIR,
    pub alpn_protocols: Vec<String>,
    /// Client certificate presented to the upstream (mTLS); at most one.
    pub client_certificate: Option<TlsCertificateIR>,
    /// Server-certificate verification. Envoy parity: `None` means the
    /// upstream cert is NOT verified (Envoy's documented — and dangerous —
    /// default when no validation context is configured).
    pub validation: Option<ValidationContextIR>,
}

/// One `TlsCertificate` (supported subset: chain + key from file/inline).
#[derive(Debug)]
pub struct TlsCertificateIR {
    pub cert_chain: DataSourceIR,
    pub private_key: DataSourceIR,
}

/// `TlsParameters` subset. Defaults are direction-dependent in Envoy
/// (`TLS_AUTO`): min TLSv1.2 both ways; max TLSv1.3 downstream but TLSv1.2
/// upstream — the lowering resolves `TLS_AUTO` per direction so consumers
/// never see "auto".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsParametersIR {
    pub min_version: TlsVersion,
    pub max_version: TlsVersion,
    /// Empty = rustls defaults. Only TLS 1.2 suites are configurable
    /// (TLS 1.3 suites are fixed — same as Envoy/BoringSSL); names are
    /// translated and validated at lowering, so this is already
    /// rustls-supported by construction.
    pub cipher_suites: Vec<TlsCipherSuite>,
    /// Empty = rustls defaults (X25519, P-256, P-384).
    pub ecdh_curves: Vec<TlsEcdhCurve>,
}

/// TLS protocol versions we can actually speak (rustls has no 1.0/1.1;
/// configs asking for them error at load, listing the unsupported version).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    V1_2,
    V1_3,
}

/// TLS 1.2 cipher suites supported by both Envoy's default set and rustls.
/// Rust note: an enum (not a String) so "unsupported suite" is impossible
/// to represent post-lowering — the name translation errored already.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCipherSuite {
    EcdheEcdsaAes128GcmSha256,
    EcdheRsaAes128GcmSha256,
    EcdheEcdsaAes256GcmSha384,
    EcdheRsaAes256GcmSha384,
    EcdheEcdsaChacha20Poly1305,
    EcdheRsaChacha20Poly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsEcdhCurve {
    X25519,
    P256,
    P384,
}

/// `CertificateValidationContext` subset.
#[derive(Debug)]
pub struct ValidationContextIR {
    pub ca: CaSource,
    /// `match_typed_subject_alt_names`: cert accepted if ANY matcher matches
    /// ANY SAN of its type (Envoy semantics). Empty = chain trust only.
    pub san_matchers: Vec<SanMatcherIR>,
    pub allow_expired_certificate: bool,
}

/// Where trust anchors come from.
#[derive(Debug)]
pub enum CaSource {
    /// `trusted_ca` PEM bundle.
    TrustedCa(DataSourceIR),
    /// `system_root_certs` — the platform trust store.
    SystemRoots,
}

/// `SubjectAltNameMatcher` (supported SAN types only; EMAIL/OTHER_NAME are
/// rejected at lowering).
#[derive(Debug)]
pub struct SanMatcherIR {
    pub san_type: SanType,
    pub matcher: StringMatcherIR,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanType {
    Dns,
    Uri,
    IpAddress,
}

/// `envoy.type.matcher.v3.StringMatcher` (supported subset), mirroring
/// [`HeaderMatchKind`]'s shape: `ignore_case` per variant (Envoy has no
/// `ignore_case` for regexes). Regexes are compiled at conversion time,
/// same as [`PathMatch::Regex`].
#[derive(Debug)]
pub enum StringMatcherIR {
    Exact {
        value: String,
        ignore_case: bool,
    },
    Prefix {
        value: String,
        ignore_case: bool,
    },
    Suffix {
        value: String,
        ignore_case: bool,
    },
    Contains {
        value: String,
        ignore_case: bool,
    },
    /// Full-string match, like Envoy's safe_regex.
    SafeRegex(regex::Regex),
}

impl StringMatcherIR {
    /// Envoy `StringMatcher` semantics. `ignore_case` is ASCII-only, like
    /// Envoy's (which lowercases with `absl::AsciiStrToLower`).
    pub fn matches(&self, input: &str) -> bool {
        match self {
            Self::Exact { value, ignore_case } if *ignore_case => input.eq_ignore_ascii_case(value),
            Self::Exact { value, .. } => input == value,
            Self::Prefix { value, ignore_case } if *ignore_case => {
                starts_with_ignore_case(input, value)
            }
            Self::Prefix { value, .. } => input.starts_with(value.as_str()),
            Self::Suffix { value, ignore_case } if *ignore_case => {
                ends_with_ignore_case(input, value)
            }
            Self::Suffix { value, .. } => input.ends_with(value.as_str()),
            Self::Contains { value, ignore_case } if *ignore_case => {
                // Rust note: no case-insensitive `contains` in std; lowercase
                // both sides. Allocates, but this only runs during TLS
                // handshake SAN checks, not per-request.
                input
                    .to_ascii_lowercase()
                    .contains(&value.to_ascii_lowercase())
            }
            Self::Contains { value, .. } => input.contains(value.as_str()),
            Self::SafeRegex(re) => re.is_match(input),
        }
    }
}

fn ends_with_ignore_case(haystack: &str, suffix: &str) -> bool {
    haystack.len() >= suffix.len()
        && haystack.is_char_boundary(haystack.len() - suffix.len())
        && haystack[haystack.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// `envoy.config.core.v3.DataSource` (supported subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataSourceIR {
    File(PathBuf),
    Inline(String),
}

/// A validated TLS certificate/validation-context secret (static or
/// SDS-delivered). Populated by WP-08/WP-22.
#[derive(Debug)]
pub struct TlsSecret {
    pub name: SecretName,
}
