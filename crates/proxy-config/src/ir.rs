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

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

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
}

/// An HTTP filter, resolved from its `typed_config` type URL.
#[derive(Debug, PartialEq, Eq)]
pub enum HttpFilterSpec {
    /// `envoy.filters.http.router` — the terminal filter (WP-13).
    Router,
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
    /// Upstream TLS, when configured.
    pub transport_socket: Option<UpstreamTlsSpec>,
    /// Envoy default: 1 MiB.
    pub per_connection_buffer_limit_bytes: u32,
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
        virtual_hosts: Vec<VirtualHostIR>,
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
        Ok(Self {
            name,
            virtual_hosts: virtual_hosts.into_iter().map(Arc::new).collect(),
            index,
        })
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
    pub routes: Vec<RouteEntry>,
}

/// One route: pre-compiled matcher + resolved action.
#[derive(Debug)]
pub struct RouteEntry {
    pub name: Option<String>,
    pub matcher: RouteMatcher,
    pub action: RouteActionIR,
    /// Request header mutations applied on match.
    pub request_headers_to_add: Vec<HeaderMutation>,
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
