//! Internal representation (IR) of the proxy configuration.
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
// `proxy-observability` rather than redefined here — the format engine
// (parser + renderer) lives there (see that crate's `access_log` module),
// and the IR only needs to *hold* the already-parsed result, not know how to
// build or render it (AGENTS.md invariant 2's spirit: keep the parsing/rendering
// logic in the crate that owns it).
use proxy_observability::access_log::FormatString;
#[cfg(unix)]
pub use proxy_observability::capture_policy::EndUserCaptureConfig;
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
    /// RDS-delivered route tables. Route tables inlined in an HCM live
    /// on the [`HttpConnectionManagerConfig`] itself, not here.
    pub routes: HashMap<RouteConfigName, Arc<RouteTable>>,
    pub secrets: HashMap<SecretName, Arc<TlsSecret>>,
    /// Admin endpoint bind address, when configured.
    pub admin: Option<SocketAddr>,
    /// OTLP trace export, when configured. `None` (the
    /// default) means tracing is off entirely -- no exporter runs, and no
    /// span is ever created, regardless of an inbound `traceparent`.
    ///
    /// This lives at the snapshot root rather than per-HCM even though the
    /// Envoy field it would otherwise mirror
    /// (`HttpConnectionManager.tracing.provider`) is per-HCM: Envoy mode does
    /// not implement that field yet (see `convert_hcm` in `lower.rs` for
    /// why -- the tracer extension proto isn't compiled into the descriptor
    /// pool), so nothing there produces a value to place per-HCM in the first
    /// place, and one exporter per process is what every present caller
    /// (dialect and, later, the runtime) actually wants. See
    /// [`TracingConfig`]'s doc for the config shape and the sampling
    /// contract.
    pub tracing: Option<TracingConfig>,
    /// OTLP metric export, when configured. `None` -- the default, and the
    /// behavior of every config written before this field existed -- means no
    /// metric export task runs at all. It says nothing about whether metrics
    /// are *collected*: the stats registry is populated unconditionally and
    /// `/stats/prometheus` renders it with no OTLP configuration of any kind,
    /// which is design doc §5.3's "Prometheus scrape remains available without
    /// OTLP or tracing" and is why this field is independent of
    /// [`Self::tracing`] rather than a mode of it.
    pub metrics: Option<MetricsExportConfig>,
    /// Independently bounded, metadata-only local-agent capture.
    #[cfg(unix)]
    pub end_user_capture: Option<EndUserCaptureConfig>,
    /// Presence is retained so an explicitly disabled namespace still conflicts
    /// with legacy capture CLI controls rather than silently choosing a mode.
    pub end_user_capture_configured: bool,
    /// ADS transport configuration, from bootstrap `dynamic_resources`.
    /// `None` -- the default, and every release through v0.2.0 -- means fully
    /// static configuration and no control-plane connection is ever attempted.
    ///
    /// This sits at the snapshot root rather than in a per-resource map (like
    /// [`Self::listeners`]) because it is bootstrap-level: it describes where
    /// resources come FROM, not a resource.
    pub ads: Option<AdsConfig>,
    pub version: SnapshotVersion,
}

impl ConfigSnapshot {
    /// Build the snapshot that succeeds this one when xDS delivers a new set
    /// of dynamic resources: everything that is not a
    /// listener, cluster, or RDS route is carried forward from `self`
    /// unchanged, and those resource maps become `self`'s static entries plus
    /// the dynamic ones.
    ///
    /// **This lives here, rather than in `proxy-xds` where its only caller
    /// is, for one specific reason** -- and it is the reason
    /// `crates/proxy-config/tests/ir_readership.rs` exists. That test proves
    /// every IR field has a real runtime reader, by scanning the runtime
    /// crates for the field's name; its module doc names the failure mode it
    /// was written to prevent, "a `/config_dump` that grows to render the
    /// whole IR would defeat it one field at a time, quietly, with no test
    /// ever failing". A snapshot-assembly function written as a struct literal
    /// in a runtime crate is exactly that shape: it names every field of
    /// `ConfigSnapshot`, so every one of them reads as consumed forever after,
    /// whether or not anything actually acts on it. Keeping the assembly in
    /// `proxy-config` keeps the instrument sharp.
    ///
    /// `version` is the caller's, not derived here: it counts snapshots
    /// actually published, and a response that changes nothing publishes
    /// nothing (see `proxy_xds::apply`), so this type cannot know it.
    ///
    /// # Panics (debug builds)
    ///
    /// Static resources are immune to xDS -- Envoy's own rule, and
    /// `proxy_xds::store` enforces it by refusing a dynamic name that
    /// collides with a static one. A collision reaching here means that
    /// refusal broke, so it is a `debug_assert!` rather than a silent
    /// overwrite of the static definition.
    pub fn with_dynamic_resources(
        &self,
        dynamic_listeners: HashMap<ListenerName, Arc<ListenerConfig>>,
        dynamic_clusters: HashMap<ClusterName, Arc<ClusterConfig>>,
        dynamic_routes: HashMap<RouteConfigName, Arc<RouteTable>>,
        version: SnapshotVersion,
    ) -> ConfigSnapshot {
        let mut listeners = self.listeners.clone();
        for (name, cfg) in dynamic_listeners {
            debug_assert!(
                !self.listeners.contains_key(&name),
                "dynamic listener `{name}` collides with a static one; static names are immune \
                 to xDS and should have been refused before reaching here"
            );
            listeners.insert(name, cfg);
        }

        let mut clusters = self.clusters.clone();
        for (name, cfg) in dynamic_clusters {
            debug_assert!(
                !self.clusters.contains_key(&name),
                "dynamic cluster `{name}` collides with a static one; static names are immune \
                 to xDS and should have been refused before reaching here"
            );
            clusters.insert(name, cfg);
        }

        let mut routes = self.routes.clone();
        for (name, table) in dynamic_routes {
            debug_assert!(
                !self.routes.contains_key(&name),
                "dynamic route `{name}` collides with a static route; static names are immune \
                 to xDS and should have been refused before reaching here"
            );
            routes.insert(name, table);
        }

        ConfigSnapshot {
            listeners,
            clusters,
            routes,
            secrets: self.secrets.clone(),
            admin: self.admin,
            tracing: self.tracing.clone(),
            // Carried forward for the same reason `tracing` is: metric export
            // is bootstrap-scoped (a collector endpoint), not an xDS resource,
            // so a listener/cluster/route delivery has nothing to say about it.
            metrics: self.metrics.clone(),
            #[cfg(unix)]
            end_user_capture: self.end_user_capture.clone(),
            end_user_capture_configured: self.end_user_capture_configured,
            ads: self.ads.clone(),
            version,
        }
    }
}

// -------------------------------------------------------------------- ads --

/// How to reach the ADS control plane, lowered from bootstrap
/// `dynamic_resources`. Config surface only: nothing in this snapshot
/// dials anything, and the client that will is `proxy-xds`.
///
/// v1 is deliberately narrow -- `api_type: GRPC|DELTA_GRPC`,
/// `transport_api_version: V3`, and exactly one `envoy_grpc` service naming a
/// statically-defined cluster when any source uses ADS. LDS and CDS may also
/// use filesystem sources independently.
/// Every other member of `ApiConfigSource` is refused at load with its full
/// dotted path rather than silently ignored (AGENTS.md invariant 1); see
/// `lower::convert_dynamic_resources`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdsConfig {
    /// The statically-defined cluster carrying ADS streams, when any source
    /// uses ADS. Filesystem-only configurations leave this unset.
    pub cluster: Option<ClusterName>,
    /// ADS wire protocol selected by `ApiConfigSource.api_type`.
    pub protocol: AdsProtocol,
    /// Whether listeners arrive over the ADS channel (bootstrap `lds_config`
    /// with its `ads` field set).
    pub lds: bool,
    /// Whether clusters arrive over the ADS channel (bootstrap `cds_config`
    /// with its `ads` field set).
    pub cds: bool,
    /// S8 `initial_fetch_timeout`. Carried so the config surface is complete;
    /// resource warming is what consumes it.
    pub initial_fetch_timeout: Option<Duration>,
    /// The xDS `Node` identity echoed on every `DiscoveryRequest` (S8).
    pub node: NodeIdentity,
    /// Per-resource transport selection. Envoy permits LDS and CDS to use
    /// different sources, including one ADS source and one filesystem file.
    pub lds_source: Option<DiscoverySource>,
    pub cds_source: Option<DiscoverySource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverySource {
    Ads,
    Filesystem(std::path::PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdsProtocol {
    Sotw,
    Delta,
}

/// The bootstrap `node` fields the xDS protocol itself needs. Distinct from
/// `node.metadata`, which this crate already reads for an unrelated purpose
/// (see `lower::convert_tracing_metadata`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeIdentity {
    pub id: String,
    pub cluster: String,
}

// ---------------------------------------------------------------- tracing --

/// OTLP trace-export configuration -- config surface
/// only. Nothing in the data plane consumes this yet; a later increment
/// wires an actual exporter and starts minting/propagating spans. See
/// `crates/proxy-config/tests/ir_readership.rs` for the allowlist entries
/// that must be deleted when that lands.
///
/// # The sampling contract
///
/// `sample_ratio` governs head sampling **only for a request that starts a
/// new trace** (no inbound `traceparent`, or one that arrives unsampled).
/// An inbound `traceparent` whose sampled flag is already set MUST always be
/// honored regardless of `sample_ratio` -- this proxy is a participant in
/// someone else's trace at that point, not the one deciding whether the
/// trace exists, and dropping a span the caller already committed to
/// recording breaks the trace they're assembling. The runtime that consumes
/// this field is required to satisfy that contract; it cannot be checked at
/// config-lowering time, so it is recorded here as the interface's promise.
#[derive(Debug, Clone, PartialEq)]
pub struct TracingConfig {
    /// The OTLP/gRPC collector endpoint, e.g. `"http://localhost:4317"`.
    /// Validated non-empty at lowering; no default -- there is no sensible
    /// destination to guess.
    pub otlp_endpoint: String,
    /// OTLP resource attribute `service.name`. Default: `"llm-proxy"`.
    pub service_name: String,
    /// Head-sampling ratio for a newly minted ROOT span, `0.0..=1.0`.
    /// Default: `1.0` (sample everything). See this type's doc for what this
    /// does and does not govern.
    pub sample_ratio: f64,
    /// Per-export deadline, applied as a `tokio::time::timeout` around each
    /// trace-batch export RPC. Default: 5s.
    ///
    /// The metric exporter has a deadline of its own, and leaving traces
    /// without one would repeat, exactly, the hazard the split exists to
    /// prevent -- a collector that accepts a connection and then goes silent
    /// parks the trace exporter's `.await` forever, buffering every later
    /// batch and filling the bounded sink behind it. So neither signal can be stalled
    /// indefinitely by the other's collector or its own. Bounded at lowering
    /// to `100ms..=60s` (the ceiling is
    /// `proxy_observability::otlp::TRACE_EXPORT_DEADLINE_MAX`, a multiple of
    /// the fixed 5s batch interval, so one timeout costs at most a bounded
    /// number of batch cycles rather than an unbounded number of RPCs).
    pub export_deadline: Duration,
}

/// OTLP metric-export configuration -- the second, independent half of
/// operational export (`docs/telemetry-design.md` §5.3: "Configure OTLP metric
/// export independently of trace sampling/export. Disabling traces must not
/// disable metrics").
///
/// **This is a separate field from [`ConfigSnapshot::tracing`] rather than a
/// flag on it, and that separation is the point of the type.** Until this
/// existed, [`ConfigSnapshot::tracing`] was the only OTLP configuration in the
/// IR and the metric exporter rode along inside the trace exporter's task: a
/// config with no `tracing` block exported no metrics over OTLP at all, even
/// though the stats registry those metrics are read from is populated
/// unconditionally and Prometheus scrape (`/stats/prometheus`) works with no
/// OTLP configuration whatsoever. Two config surfaces means an operator can
/// export metrics with tracing fully off, and turning tracing off can no longer
/// silently stop metrics.
///
/// Both halves may name the same collector, and `crates/proxy/src/main.rs`
/// spawns their exporter tasks independently, so a slow or failing *trace*
/// export cannot indefinitely delay metric snapshots (design doc §5.3:
/// "Separate metric and span scheduling/deadlines"). The registry is
/// cumulative and never cleared, so a metric snapshot that fails to export is
/// superseded by the next one rather than losing an interval's worth of data
/// the way a dropped trace batch does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsExportConfig {
    /// The OTLP/gRPC collector endpoint, e.g. `"http://localhost:4317"`.
    /// Validated non-empty at lowering; no default. May differ from
    /// [`TracingConfig::otlp_endpoint`] -- pointing metrics and traces at
    /// different collectors is a normal deployment, not a mistake.
    pub otlp_endpoint: String,
    /// OTLP resource attribute `service.name`. Default: `"llm-proxy"`.
    pub service_name: String,
    /// How often to snapshot and export the registry. Default: 15s.
    ///
    /// The registry read is cheap (a summed pass over already-resolved
    /// handles) and each export is a cumulative full snapshot, so a shorter
    /// interval costs bandwidth rather than correctness. Bounded at lowering to
    /// `1s..=1h` -- see `convert_metrics_metadata` in `lower.rs`.
    pub export_interval: Duration,
    /// Per-export deadline, applied as a `tokio::time::timeout` around each
    /// export RPC. Default: 10s.
    ///
    /// This is what makes a hung collector *bounded* rather than merely
    /// best-effort: tonic's `connect_lazy` channel reconnects on its own, but a
    /// connection that establishes and then stops responding would otherwise
    /// hold the export task's `.await` open indefinitely, and with it every
    /// later tick. Validated at lowering to be strictly less than
    /// [`Self::export_interval`], so a deadline expiry can never cause ticks to
    /// pile up behind each other.
    pub export_deadline: Duration,
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
/// divergence than the injection. Recorded in `internal-docs/envoy-divergences.md`.
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
/// filters. The criteria live here.
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

/// Full 9-criteria `FilterChainMatch`. Field order mirrors Envoy's
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

/// Which HTTP codec the connection manager assumes for a downstream
/// connection, before any bytes have been read from it. Envoy's
/// `HttpConnectionManager.codec_type`; `HTTP3` isn't representable here — this
/// proxy has no QUIC/UDP listener, so lowering rejects it with its dotted
/// path rather than adding a variant nothing can ever produce (AGENTS.md invariant
/// 1 still applies to values with no implementation, not just unknown
/// fields).
///
/// The dispatch that actually reads this lives in `proxy-core`'s listener
/// (`terminal_filter`/`serve_connection`): `Auto` on a TLS connection defers
/// to negotiated ALPN; `Auto` on a plaintext
/// connection peeks the client connection preface (RFC 9113 §3.4) to tell h2
/// prior-knowledge apart from h1; `Http1`/`Http2` skip detection entirely and
/// assume the operator is right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CodecType {
    /// Envoy default: ALPN over TLS, protocol-sniffed over plaintext.
    #[default]
    Auto,
    /// Always HTTP/1.1, even if the client speaks the h2 preface.
    Http1,
    /// Always HTTP/2, prior-knowledge cleartext allowed (Envoy does not
    /// require TLS/ALPN for h2 — see the proto's own `CodecType.HTTP2` doc).
    Http2,
}

/// IR for the HTTP connection manager (supported subset).
#[derive(Debug)]
pub struct HttpConnectionManagerConfig {
    pub stat_prefix: String,
    /// The inlined route table. When [`Self::rds_route_config_name`] is set,
    /// this is an empty placeholder and workers resolve the named table from
    /// [`ConfigSnapshot::routes`] before accepting traffic.
    pub route_table: Arc<RouteTable>,
    /// RDS name when this HCM's route specifier is `rds`. Keeping the name
    /// beside the HCM rather than replacing `route_table` with an enum keeps
    /// the hot-path filter manager concrete: a listener is published only
    /// after this name resolves to a real table.
    pub rds_route_config_name: Option<RouteConfigName>,
    /// Ordered HTTP filters; the last must be the router.
    pub http_filters: Vec<HttpFilterSpec>,
    /// Which codec serves a downstream connection on this HCM. Envoy
    /// default `AUTO`; see [`CodecType`]'s doc for the dispatch this drives.
    pub codec_type: CodecType,
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
    /// Parsed access-log sinks, in configured order. The per-request render
    /// + write happens in the data plane; this crate only builds the IR.
    pub access_logs: Vec<AccessLogIR>,
    /// S10: the upgrade types this HCM will proxy (`Upgrade:
    /// <type>` requests are tunnelled upstream). Empty = upgrades disabled
    /// (the Envoy default — no `upgrade_configs` means no upgrades). Each
    /// entry names a type and whether it is enabled by default; a route may
    /// override `enabled` per type (S10.1, wired later). Per-upgrade filter
    /// chains (`UpgradeConfig.filters`) are rejected at lowering as
    /// unimplemented — the current tunnel is transparent (S10.2 deferred).
    pub upgrade_configs: Vec<UpgradeConfig>,
}

impl ListenerConfig {
    /// Every ADS RDS resource this listener needs before it can accept traffic.
    /// This walks both ordinary and default chains because either can carry an
    /// HTTP connection manager.
    pub fn rds_route_config_names(&self) -> impl Iterator<Item = &RouteConfigName> {
        self.filter_chains
            .iter()
            .chain(self.default_filter_chain.iter())
            .flat_map(|chain| chain.filters.iter())
            .filter_map(|filter| match filter {
                NetworkFilterSpec::HttpConnectionManager(hcm) => hcm.rds_route_config_name.as_ref(),
                NetworkFilterSpec::TcpProxy(_) => None,
            })
    }

    /// An inline-route listener is ready immediately; an RDS listener is
    /// ready only after every named table appears in this snapshot.
    pub fn routes_are_warmed(&self, routes: &HashMap<RouteConfigName, Arc<RouteTable>>) -> bool {
        self.rds_route_config_names()
            .all(|name| routes.contains_key(name))
    }
}

/// S10: one entry of an HCM's `upgrade_configs`. `upgrade_type` is
/// stored lowercased because Envoy matches it case-insensitively against the
/// request's `Upgrade` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeConfig {
    pub upgrade_type: String,
    /// Envoy default true (the proto field is a `BoolValue`; absent => true).
    pub enabled: bool,
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
/// which is exactly the class of drift AGENTS.md invariant 1 exists to prevent.
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
/// (AGENTS.md invariant 1), not a silent no-op filter.
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
/// [`HttpFilterSpec::config`] is (AGENTS.md invariant 2 -- the `proxy-http` registry
/// owns per-filter parsing, not the IR).
#[derive(Debug)]
pub struct PerFilterConfig {
    pub ext_authz: Option<crate::authorization::ExtAuthzPerRoute>,
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
/// directly (AGENTS.md invariant 2: the registry, not the IR, owns per-filter
/// parsing).
#[derive(Debug)]
pub struct HttpFilterSpec {
    pub ext_authz: Option<crate::authorization::ExtAuthzConfig>,
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

/// Provider-owned rewrite for an upstream request path.
///
/// Route rewrites run before this transform. `match_prefix` is replaced by
/// `replacement_prefix`, while any unmatched path suffix is preserved. An
/// optional query replaces request query parameters. Keeping this on cluster
/// IR makes provider-specific URL details follow selected aggregate member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPathRewrite {
    pub match_prefix: String,
    pub replacement_prefix: String,
    pub query: Option<String>,
}

/// IR for `envoy.config.cluster.v3.Cluster` (supported surface).
///
/// `PartialEq` is a derive over every field, not a
/// hand-written comparison — `ClusterManager::update_from_snapshot` uses it
/// to decide whether an incoming cluster's config actually changed, and a
/// hand-written `eq` that skipped a field would silently treat a real change
/// to that field as "unchanged" and carry forward a `ManagedCluster` that
/// should have been rebuilt. Deriving means a field added later is compared
/// automatically instead of by whoever remembers to update a hand-written impl.
#[derive(Debug, PartialEq)]
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
    /// provider fallback).
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
    /// **This is where provider credentials belong, and the reason is provider fallback.**
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
    /// only by the `llmproxy` dialect. AGENTS.md invariant 1 governs config → IR, not
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
    /// Provider-owned path/query rewrite applied after route transforms and
    /// before credentials. This follows actual cluster selected on failover.
    pub request_path_rewrite: Option<RequestPathRewrite>,
    /// Provider-specific authentication and model URL templating. Both are
    /// cluster-owned so fallback cannot send primary-provider material to a
    /// different upstream.
    pub provider_runtime: Option<ProviderRuntimeConfig>,
    /// Which wire dialect this cluster's upstream speaks, for the usage
    /// filter's token accounting -- a known instance of AGENTS.md invariant 6,
    /// alongside credentials (`request_headers_to_add`) and
    /// `host_rewrite_literal`. The dialect is a property of the *provider
    /// actually dialled*, not of the route that picked an aggregate; the
    /// route still carries its own `typed_per_filter_config` copy today,
    /// but a value that varies per provider
    /// and lives on the route follows the routing decision instead of the
    /// connection, and reaches the wrong provider on failover -- exactly the
    /// credentials and `Host` bugs, just for token accounting instead of
    /// secrecy or connection identity. The usage filter does not read this
    /// field yet; until then it rides
    /// along unused, same as `request_headers_to_add` did before the router
    /// grew retries.
    ///
    /// `None` on an ordinary Envoy-mode cluster (no proto field maps here,
    /// same reasoning as `request_headers_to_add`'s doc above); `Some` only
    /// when the `llmproxy` dialect populates
    /// `Cluster.metadata.filter_metadata["io.llmproxy.usage"]`. Always `None`
    /// on an aggregate -- `metadata` itself is a hard load error there (see
    /// `convert_cluster`), so the member that actually serves a request is
    /// the one that must carry it.
    pub usage_dialect: Option<UsageDialect>,
    /// S6 active health checking; `None` when the config configures
    /// none, which is Envoy's own default (no probing, every host healthy).
    /// Singular though the proto field is repeated — see [`HealthCheckIR`].
    pub health_check: Option<HealthCheckIR>,
    /// S6 passive outlier detection; `None` when the config configures
    /// none, which is Envoy's own default (no passive ejection at all — every
    /// host stays eligible regardless of the error rate it's returning).
    /// Shape-only: nothing in `proxy-cluster` builds an
    /// [`crate::ir::OutlierDetectionIR`]-backed detector from this field yet
    /// (see `crates/proxy-config/tests/ir_readership.rs`'s allowlist entry).
    pub outlier_detection: Option<OutlierDetectionIR>,
    /// `Cluster.eds_cluster_config`, present exactly when `discovery` is
    /// [`DiscoveryType::Eds`] (`lower.rs::convert_cluster` sets the two
    /// together, never one without the other). `None` for every other
    /// discovery type, including `Aggregate` -- an aggregate has no
    /// discovery mechanism of its own (see `kind`'s doc).
    ///
    /// Lowering only validates this shape; nothing here
    /// subscribes to EDS or applies an endpoint update, so `endpoints`
    /// stays empty on an EDS cluster the same way it does on an aggregate --
    /// see `crates/proxy-config/tests/ir_readership.rs`'s allowlist entry for
    /// who reads it.
    pub eds: Option<EdsClusterConfig>,
}

/// IR for `envoy.config.cluster.v3.Cluster.EdsClusterConfig` (supported
/// surface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdsClusterConfig {
    /// The resource name to subscribe to. Envoy defaults this to the
    /// cluster's own name when `service_name` is unset -- `lower.rs`
    /// resolves that default at lowering time, so this is always the
    /// resource name to request, never the proto's raw (possibly empty)
    /// field.
    pub service_name: String,
}

// ---------------------------------------------------------- health checks --

/// IR for `envoy.config.core.v3.HealthCheck` (supported surface).
///
/// Envoy's `Cluster.health_checks` is *repeated*, and a host must pass every
/// configured check. Only one check per cluster is implemented, so lowering
/// rejects a config carrying more than one rather than silently running the
/// first (AGENTS.md invariant 1).
///
/// Envoy marks `timeout`, `interval`, `unhealthy_threshold` and
/// `healthy_threshold` required in its own PGV rules, so none of the four has
/// a default to fall back on here.
#[derive(Debug, Clone, PartialEq)]
pub struct HealthCheckIR {
    /// Spacing between probes of one host.
    pub interval: Duration,
    /// Bound on a single probe (connect + check); exceeding it is a failure.
    pub timeout: Duration,
    /// Uniform random jitter added to `interval` on each scheduling decision,
    /// so a cluster's hosts don't fall into lockstep. Envoy default: 0.
    pub interval_jitter: Duration,
    /// Consecutive failures required to flip a host healthy → unhealthy.
    pub unhealthy_threshold: u32,
    /// Consecutive successes required to flip a host unhealthy → healthy.
    pub healthy_threshold: u32,
    /// Carried for surface completeness only — the engine does not act on it
    /// yet, and says why at
    /// `proxy_cluster::health_check::DEFAULT_NO_TRAFFIC_INTERVAL`.
    pub no_traffic_interval: Duration,
    /// What the probe actually sends and accepts.
    pub kind: HealthCheckKindIR,
}

/// Which health checker a [`HealthCheckIR`] runs — Envoy's `health_checker`
/// oneof, narrowed to the two modes the engine implements. `grpc_health_check`
/// and `custom_health_check` are rejected at lowering: a stub that always
/// reported healthy would be worse than refusing the config.
#[derive(Debug, Clone, PartialEq)]
pub enum HealthCheckKindIR {
    /// `HttpHealthCheck`: a `GET path` with `Connection: close` and an
    /// optional `Host` override. An empty `expected_statuses` means 200 only,
    /// which is Envoy's own zero-value-means-default convention for the field.
    Http {
        path: String,
        expected_statuses: Vec<u16>,
        host: Option<String>,
    },
    /// `TcpHealthCheck`: connect, optionally write `send`, then optionally
    /// read `expect.len()` bytes and require an exact match. Both empty means
    /// a bare TCP connect is the whole check.
    Tcp { send: Vec<u8>, expect: Vec<u8> },
}

// ------------------------------------------------------- outlier detection --

/// IR for `envoy.config.cluster.v3.OutlierDetection` (supported surface).
/// Mirrors `proxy_cluster::outlier::OutlierDetectionConfig` field for
/// field; see that type's doc for the full S6 semantics (edge-triggered
/// counters, the gateway-failure/5xx interaction, enforcement-percent dice
/// roll). Every field here is commented with its S6 default, duplicated from
/// that type rather than shared with it: `proxy-config` cannot depend on
/// `proxy-cluster` (the dependency runs the other way — the data plane
/// consumes the IR, not the reverse), so [`OutlierDetectionIR::ENVOY_DEFAULT`]
/// and `OutlierDetectionConfig::default()` are two independent sources of
/// truth for the same numbers. `crates/proxy-cluster/src/outlier.rs` carries
/// a test asserting they agree field for field — see that test before
/// changing either side.
///
/// Two deliberate differences from `OutlierDetectionConfig`:
/// - `split_external_local_origin_errors` is **not** carried here at all.
///   Only `false` (Envoy's own default) is implemented anywhere in this
///   project — see `OutlierDetectionConfig::split_external_local_origin_errors`'s
///   doc — so lowering rejects `true` outright with its dotted path rather
///   than accepting a field the IR would then silently ignore (AGENTS.md invariant
///   1's exact shape: accepted-but-inert is still a P0).
/// - `uneject_on_healthy_active_hc` maps a real Envoy field,
///   `successful_active_health_check_uneject_host` (field 23, a `BoolValue`
///   defaulting to true) — `OutlierDetectionConfig`'s own doc comment used to
///   claim Envoy does not expose this as configurable; that was wrong, and is
///   fixed there as part of this same change.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OutlierDetectionIR {
    /// How often the success-rate and failure-percentage detectors re-run
    /// over the whole host set. S6 default: 10s.
    pub interval: Duration,
    /// First ejection's duration; later ejections grow by this amount per
    /// consecutive ejection. S6 default: 30s.
    pub base_ejection_time: Duration,
    /// Ceiling on ejection duration regardless of growth. Envoy documents
    /// this as `max(300s, base_ejection_time)` when unset — lowering clamps
    /// an explicit value below `base_ejection_time` up to it too, since a
    /// cap tighter than the base would silently mean "every ejection lasts
    /// `base_ejection_time`, not the configured max" (see `convert_outlier_detection`).
    pub max_ejection_time: Duration,
    /// Percent of a cluster's hosts that may be simultaneously ejected. S6
    /// default: 10. 0–100.
    pub max_ejection_percent: u8,
    /// If true, at least one host may always be ejected even if
    /// `max_ejection_percent` would otherwise round down to zero for a small
    /// cluster. S6 default: false — there is deliberately no "at least one"
    /// exemption.
    pub always_eject_one_host: bool,

    /// Consecutive 5xx (or folded local-origin failure) responses required
    /// to trip this detector. S6 default: 5.
    pub consecutive_5xx: u32,
    /// Percent chance a tripped consecutive-5xx detection is actually
    /// enforced (ejects the host) rather than merely logged/counted. S6
    /// default: 100. 0–100.
    pub enforcing_consecutive_5xx: u8,
    /// Consecutive gateway-failure (502/503/504) responses required to trip
    /// this detector. S6 default: 5.
    pub consecutive_gateway_failure: u32,
    /// Percent chance a tripped consecutive-gateway-failure detection is
    /// enforced. S6 default: **0** — tracked but never enforced out of the
    /// box; this is one of the two defaults most implementations get wrong
    /// (see `enforcing_failure_percentage` below for the other). 0–100.
    pub enforcing_consecutive_gateway_failure: u8,

    /// Minimum number of hosts (with at least `success_rate_request_volume`
    /// requests in the interval) required before the success-rate detector
    /// runs at all. S6 default: 5.
    pub success_rate_min_hosts: u32,
    /// Minimum requests a host must have seen in the interval to be eligible
    /// for success-rate detection. S6 default: 100.
    pub success_rate_request_volume: u32,
    /// Ejection threshold in thousandths of a standard deviation below the
    /// mean success rate (1900 == 1.9 sigma). S6 default: 1900.
    pub success_rate_stdev_factor: u32,
    /// Percent chance a tripped success-rate detection is enforced. S6
    /// default: 100. 0–100.
    pub enforcing_success_rate: u8,

    /// Failure-percentage threshold above which a host is a candidate for
    /// ejection. S6 default: 85. 0–100.
    pub failure_percentage_threshold: u8,
    /// Percent chance a tripped failure-percentage detection is enforced. S6
    /// default: **0** — see `enforcing_consecutive_gateway_failure` above,
    /// the other default most implementations get wrong. 0–100.
    pub enforcing_failure_percentage: u8,
    /// Minimum number of eligible hosts required before the
    /// failure-percentage detector runs. S6 default: 5.
    pub failure_percentage_min_hosts: u32,
    /// Minimum requests a host must have seen in the interval to be eligible
    /// for failure-percentage detection. S6 default: 50.
    pub failure_percentage_request_volume: u32,

    /// Whether a host un-ejects the moment it passes an active health check, independent of its outlier ejection timer. S6 default: true
    /// — maps `successful_active_health_check_uneject_host`
    /// (`envoy.config.cluster.v3.OutlierDetection`, field 23).
    pub uneject_on_healthy_active_hc: bool,
}

impl OutlierDetectionIR {
    /// Envoy's documented S6 defaults, applied field-by-field when the config
    /// omits `outlier_detection` entirely (`ClusterConfig::outlier_detection`
    /// stays `None` in that case — this constant is for the *present-but-
    /// empty-block* case, where every field must still take its real
    /// default rather than the Rust zero value; a zero `max_ejection_percent`
    /// or `enforcing_consecutive_5xx`, for instance, would silently disable
    /// ejection outright).
    pub const ENVOY_DEFAULT: Self = Self {
        interval: Duration::from_secs(10),
        base_ejection_time: Duration::from_secs(30),
        max_ejection_time: Duration::from_secs(300),
        max_ejection_percent: 10,
        always_eject_one_host: false,
        consecutive_5xx: 5,
        enforcing_consecutive_5xx: 100,
        consecutive_gateway_failure: 5,
        enforcing_consecutive_gateway_failure: 0,
        success_rate_min_hosts: 5,
        success_rate_request_volume: 100,
        success_rate_stdev_factor: 1900,
        enforcing_success_rate: 100,
        failure_percentage_threshold: 85,
        enforcing_failure_percentage: 0,
        failure_percentage_min_hosts: 5,
        failure_percentage_request_volume: 50,
        uneject_on_healthy_active_hc: true,
    };
}

impl Default for OutlierDetectionIR {
    fn default() -> Self {
        Self::ENVOY_DEFAULT
    }
}

/// The wire dialect a provider cluster speaks, for the usage filter's request
/// and response parsing. Kept as its own IR type rather than reusing
/// `proxy_filters::usage::Dialect`: `proxy-config` cannot depend on
/// `proxy-filters` (that edge is dev-only in the other direction, and adding
/// a real one would cycle), so the two dialects are deliberately separate
/// types that happen to agree on their variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageDialect {
    /// OpenAI's request/response and SSE shapes (also openai-compatible
    /// upstreams: vLLM, Ollama, TGI).
    OpenAi,
    /// Anthropic's Messages API request/response and SSE shapes.
    Anthropic,
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
#[derive(Debug, Clone, Copy, PartialEq)]
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
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CircuitBreakerThresholds {
    /// Max open upstream connections (Envoy default 1024).
    pub max_connections: u32,
    /// Max requests queued waiting for a connection (Envoy default 1024).
    pub max_pending_requests: u32,
    /// Max concurrent active requests (Envoy default 1024).
    pub max_requests: u32,
    /// Max concurrent retries in flight (Envoy default 3).
    pub max_retries: u32,
    /// When present, replaces `max_retries` with Envoy's concurrency-relative
    /// retry budget. Its percentage is deliberately a `f64`: Envoy's
    /// `Percent` accepts fractional values, so narrowing it to an integer
    /// would silently alter an operator's limit.
    pub retry_budget: Option<RetryBudget>,
}

/// Envoy's `CircuitBreakers.Thresholds.RetryBudget`, lowered exactly rather
/// than approximated by the fixed `max_retries` breaker.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetryBudget {
    /// Percentage of active + pending requests allowed to be active retries.
    /// Validated finite and in `[0, 100]` while lowering.
    pub budget_percent: f64,
    /// Floor for small clusters. Envoy default 3.
    pub min_retry_concurrency: u32,
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
        retry_budget: None,
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
    /// DNS-resolve every returned address.
    StrictDns,
    /// DNS-resolve, use one address at a time.
    LogicalDns,
    /// Endpoints arrive over EDS rather than from the cluster's own
    /// `endpoints` list -- `ClusterConfig::endpoints` is always empty for a
    /// cluster with this discovery type (`lower.rs::convert_cluster` rejects
    /// a non-empty `load_assignment` alongside `type: EDS`). The EDS
    /// subscription is what delivers a host set for these; lowering only
    /// makes the config surface loadable.
    Eds,
}

/// Where a cluster's hosts come from -- see [`ClusterConfig::kind`]'s doc for
/// why this is a field on `ClusterConfig` rather than a `DiscoveryType`
/// variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterKind {
    /// Hosts come from this cluster's own `endpoints` + `discovery`. The
    /// overwhelming common case.
    Endpoints,
    /// `envoy.clusters.aggregate`: this cluster has no hosts of its own.
    /// Host selection walks `members`, in the order listed, and serves the
    /// first member that yields a host -- see
    /// `proxy_cluster::manager::ClusterHandle::select_aggregate_member` for
    /// the exact algorithm (including how it deliberately diverges from
    /// Envoy's own cross-member combined priority set).
    ///
    /// This exists for provider fallback: one route target (the
    /// aggregate) whose members are different LLM providers, each with its
    /// own TLS and credentials (`ClusterConfig::request_headers_to_add`) --
    /// a retried attempt that falls over to the next member must carry that
    /// member's identity, never the aggregate's or a previous member's.
    ///
    /// `endpoints`, `discovery`, `transport_socket`, and `upstream_protocol`
    /// are all unused on a `ClusterConfig` whose `kind` is `Aggregate` -- the
    /// member that actually serves the request supplies all four. AGENTS.md
    /// invariant 1 ("every field maps to IR or errors") does not apply to these
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
    /// Envoy's `CLUSTER_PROVIDED`: the cluster implementation picks its own
    /// host rather than delegating to one of the policies above. Envoy
    /// *requires* this on an `envoy.clusters.aggregate` cluster
    /// ([`ClusterKind::Aggregate`]) -- an aggregate has no hosts of its own
    /// to run a policy over, so lowering rejects any other `lb_policy` there
    /// (`lower.rs::convert_cluster`), and the converse: this policy on a
    /// cluster that *does* own hosts (`ClusterKind::Endpoints`) is rejected
    /// too, since we implement no cluster-provided host-picking of our own.
    /// `proxy_cluster::load_balancer::build` has its own defensive arm for
    /// this variant -- see its comment for why that arm is expected to be
    /// unreachable in practice.
    ClusterProvided,
}

/// An upstream endpoint. `host` must be a literal IP for STATIC clusters (see
/// `lower.rs::convert_endpoint`) and for EDS-delivered endpoints
/// (`discovery::static_hosts` installs those without resolving them); it may be a DNS name for the DNS discovery types, where resolution
/// is the cluster manager's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointIR {
    pub host: String,
    pub port: u16,
    /// LB weight; Envoy default 1.
    pub weight: u32,
    /// Failover priority; 0 = primary (S5/S7).
    pub priority: u32,
    /// Operator-facing labels for this endpoint, lowered from
    /// `LbEndpoint.metadata.filter_metadata["io.llmproxy.endpoint"]` -- the
    /// same `filter_metadata` smuggling channel `ClusterConfig`'s
    /// `request_headers_to_add` and `usage_dialect` already use, under an
    /// endpoint-scoped namespace of its own.
    ///
    /// **Advisory: nothing routes on this, and that is deliberate.** Envoy's
    /// own convention for endpoint metadata that affects host selection is
    /// the `envoy.lb` namespace, read by LB subset routing -- which this
    /// proxy does not implement. Lowering therefore REFUSES `envoy.lb` (and
    /// every other namespace) by dotted path rather than accepting it into
    /// this map: quietly taking a subset-routing selector and then not
    /// routing on it is AGENTS.md invariant 1's exact shape, and it would silently
    /// send traffic to endpoints the operator meant to exclude.
    ///
    /// `BTreeMap` rather than `HashMap` so `/config_dump` and test assertions
    /// see a deterministic order.
    pub metadata: BTreeMap<String, String>,
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
    /// Ordered routes; first match wins (S1).
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
    /// A route-level assertion that every configured HTTP filter flushes
    /// response bytes through.  It is validated against the real filter
    /// factories while the listener chain is built.
    pub streaming_strict: bool,
    /// `Route.typed_per_filter_config`.
    pub typed_per_filter_config: BTreeMap<String, PerFilterConfig>,
    /// Dense index, unique within the owning [`RouteTable`], assigned by
    /// `RouteTable::new`. Lets `proxy-http` keep a side table of parsed
    /// per-route filter configs (which are `proxy-http` types and so cannot
    /// live in the IR) indexed by route, without hashing pointers.
    pub route_index: usize,
    /// `VirtualHost.include_request_attempt_count` (Envoy default false),
    /// denormalized from the owning vhost at lowering: when true the router
    /// sets `x-envoy-attempt-count` on the upstream request to this attempt's
    /// 1-based number. Vhost-level in Envoy, copied onto every route here
    /// because the router only holds an `Arc<RouteEntry>` (S2.8 cache), never
    /// the vhost.
    pub include_request_attempt_count: bool,
    /// `VirtualHost.include_attempt_count_in_response` (Envoy default false):
    /// when true the router sets `x-envoy-attempt-count` on the response to
    /// the TOTAL attempts made. Same denormalization as above.
    pub include_attempt_count_in_response: bool,
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
    /// Cluster name read from a request header (set by e.g. the model
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
/// exponential backoff (base 25ms, cap 250ms) — timing lives in the router.
#[derive(Debug, Default)]
pub struct RetryPolicyIR {
    pub retry_on: RetryOn,
    pub num_retries: u32,
    pub per_try_timeout: Option<Duration>,
    /// S3 hedging: when a safe request has not produced response headers by
    /// `per_try_timeout`, leave that attempt running and issue one replay.
    /// The router returns whichever response head arrives first.  This is
    /// deliberately attached to the retry policy because a hedge spends the
    /// same attempt budget and has no meaning without one.
    pub hedge_on_per_try_timeout: bool,
    pub retriable_status_codes: Vec<u16>,
    /// S3.3 fully-jittered exponential backoff parameters.
    pub retry_back_off: RetryBackOff,
    /// S3.1: how many times a retry may re-run host selection to avoid a
    /// previously-tried host before giving up and reusing one. Envoy default 1.
    pub host_selection_retry_max_attempts: u32,
    /// Whether the supported Envoy `previous_hosts` retry predicate is
    /// configured.  The router records every dispatched host on the request
    /// context; the load balancer re-picks when this predicate rejects one.
    pub avoid_previous_hosts: bool,
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

/// Downstream TLS termination config for a filter chain.
///
/// Field-presence semantics follow Envoy v1.38's `DownstreamTlsContext`:
/// anything the lowering can't honor errors at config load with its dotted
/// path — this struct only holds what the rustls transport socket actually
/// implements.
#[derive(Debug)]
pub struct DownstreamTlsSpec {
    /// Inline certificates. Multiple entries = one cert per key type (RSA +
    /// ECDSA), selected per-handshake like Envoy/BoringSSL.
    ///
    /// Empty ONLY when [`Self::certificate_sds_names`] is non-empty -- the
    /// two are mutually exclusive and exactly one of them is set. Lowering
    /// enforces both halves of that invariant; nothing else constructs this
    /// struct.
    pub certificates: Vec<TlsCertificateIR>,
    /// `CommonTlsContext.tls_certificate_sds_secret_configs` names, in
    /// declaration order. Non-empty means the serving
    /// certificates arrive over SDS and the listener binds with an EMPTY
    /// cert set: it accepts TCP and fails every TLS handshake until the
    /// control plane delivers, rather than serving in the clear.
    ///
    /// **Divergence from Envoy, deliberate.** Envoy documents
    /// `tls_certificate_sds_secret_configs` as *ignored* when
    /// `tls_certificates` is also set. Silently ignoring a set field is
    /// exactly what AGENTS.md invariant 1 forbids, so lowering rejects the mixed
    /// case with its dotted path instead of applying Envoy's precedence.
    /// Recorded in `internal-docs/envoy-divergences.md`.
    ///
    /// Each name here must carry an ADS `sds_config`; an `SdsSecretConfig`
    /// with no `sds_config` means "look this up in
    /// `static_resources.secrets`", which is [`ConfigSnapshot::secrets`] --
    /// still a stub ([`TlsSecret`] carries only a name), so lowering refuses
    /// it by path rather than resolving to nothing.
    pub certificate_sds_names: Vec<SecretName>,
    pub params: TlsParametersIR,
    /// Offered via ALPN in server order; empty = no ALPN extension.
    pub alpn_protocols: Vec<String>,
    /// Client-certificate (mTLS) verification. `None` = no client certs
    /// requested at all.
    pub validation: Option<ValidationContextIR>,
    /// `CommonTlsContext.validation_context_sds_secret_config` name, when
    /// the downstream client-auth trust anchor arrives over ADS/SDS. While
    /// this is set and no secret has reached the serving factory, it remains
    /// fail-closed: no client is authenticated against an absent CA bundle.
    ///
    /// This is deliberately a separate field from [`Self::validation`]. The
    /// protobuf members are a oneof, so lowering permits exactly one of the
    /// static and SDS forms; `combined_validation_context` remains refused
    /// until its static-plus-dynamic merge semantics are implemented.
    pub validation_sds_name: Option<SecretName>,
    /// Envoy: reject connections without a valid client certificate.
    /// Lowering enforces that this requires `validation` to be present.
    pub require_client_certificate: bool,
    /// Envoy default `false`: the server issues stateless session tickets
    /// encrypted with an internally generated key (verified against the
    /// v1.38 proto comment on `disable_stateless_session_resumption`).
    pub disable_stateless_session_resumption: bool,
}

/// Upstream TLS origination config for a cluster.
#[derive(Debug, PartialEq)]
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
#[derive(Debug, PartialEq)]
pub struct TlsCertificateIR {
    pub cert_chain: DataSourceIR,
    pub private_key: DataSourceIR,
}

/// One SDS-delivered TLS secret after xDS has decoded its protobuf envelope.
///
/// This is configuration IR rather than xDS-client state: the discovery
/// transport decodes it, while the TLS serving layer consumes it. Keeping the
/// payload here prevents either layer from depending on the other.
#[derive(Debug, Clone)]
pub struct DynamicSecret {
    /// `Secret.name` -- what an `SdsSecretConfig.name` subscribes to.
    pub name: SecretName,
    pub kind: SecretKind,
}

/// Which supported `Secret.type` oneof case a [`DynamicSecret`] holds.
#[derive(Debug, Clone)]
pub enum SecretKind {
    TlsCertificate {
        certificate_chain: Vec<u8>,
        private_key: Vec<u8>,
    },
    ValidationContext {
        trusted_ca: Vec<u8>,
    },
}

impl DynamicSecret {
    /// Convert a certificate secret into the TLS IR the serving registry
    /// consumes. A validation-context secret has no certificate material and
    /// therefore returns `None`; its trust-anchor delivery goes
    /// through a distinct update path.
    ///
    /// SDS carries certificate bytes inline. They must be UTF-8 PEM so the
    /// existing `DataSourceIR::Inline` TLS loader can consume them; invalid
    /// UTF-8 is rejected rather than lossy-converted.
    pub fn tls_certificate_ir(&self) -> Result<Option<TlsCertificateIR>, crate::ConfigError> {
        let (certificate_chain, private_key) = match &self.kind {
            SecretKind::TlsCertificate {
                certificate_chain,
                private_key,
            } => (certificate_chain, private_key),
            SecretKind::ValidationContext { .. } => return Ok(None),
        };
        let cert_chain = sds_utf8_pem(
            certificate_chain,
            &self.name,
            "tls_certificate.certificate_chain",
        )?;
        let private_key = sds_utf8_pem(private_key, &self.name, "tls_certificate.private_key")?;
        Ok(Some(TlsCertificateIR {
            cert_chain: DataSourceIR::Inline(cert_chain),
            private_key: DataSourceIR::Inline(private_key),
        }))
    }

    /// Convert a validation-context secret into the TLS IR consumed by the
    /// downstream trust-anchor reload seam. SDS currently supports only an
    /// inline `trusted_ca`; the decoder rejects every other validation field,
    /// so the resulting context has no hidden defaults to merge.
    pub fn validation_context_ir(&self) -> Result<Option<ValidationContextIR>, crate::ConfigError> {
        let trusted_ca = match &self.kind {
            SecretKind::TlsCertificate { .. } => return Ok(None),
            SecretKind::ValidationContext { trusted_ca } => trusted_ca,
        };
        let trusted_ca = sds_utf8_pem(trusted_ca, &self.name, "validation_context.trusted_ca")?;
        Ok(Some(ValidationContextIR {
            ca: CaSource::TrustedCa(DataSourceIR::Inline(trusted_ca)),
            san_matchers: Vec::new(),
            allow_expired_certificate: false,
        }))
    }
}

fn sds_utf8_pem(
    bytes: &[u8],
    secret_name: &str,
    field: &str,
) -> Result<String, crate::ConfigError> {
    String::from_utf8(bytes.to_vec()).map_err(|err| crate::ConfigError::InvalidValue {
        field_path: format!("sds.secrets[{secret_name}].{field}"),
        reason: format!("not valid UTF-8 PEM text: {err}"),
    })
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
#[derive(Debug, PartialEq)]
pub struct ValidationContextIR {
    pub ca: CaSource,
    /// `match_typed_subject_alt_names`: cert accepted if ANY matcher matches
    /// ANY SAN of its type (Envoy semantics). Empty = chain trust only.
    pub san_matchers: Vec<SanMatcherIR>,
    pub allow_expired_certificate: bool,
}

/// Where trust anchors come from.
#[derive(Debug, PartialEq)]
pub enum CaSource {
    /// `trusted_ca` PEM bundle.
    TrustedCa(DataSourceIR),
    /// `system_root_certs` — the platform trust store.
    SystemRoots,
}

/// `SubjectAltNameMatcher` (supported SAN types only; EMAIL/OTHER_NAME are
/// rejected at lowering).
#[derive(Debug, PartialEq)]
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

/// Hand-written, not derived — `regex::Regex` itself has no `PartialEq`
/// (`ValidationContextIR`'s `san_matchers` need this,
/// pulled in through `ClusterConfig::transport_socket`). This does not skip
/// any field the way `apply.rs`'s `Entry<T>` comparison does: `compile_regex`
/// (`lower.rs`) is a pure function of the pattern string (`^(?:{pattern})$`,
/// no other input), so two `Regex`es built from equal `as_str()` output are
/// guaranteed to match identically — comparing the pattern string compares
/// the regex's whole behavior, not a subset of it.
impl PartialEq for StringMatcherIR {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Exact {
                    value: v1,
                    ignore_case: i1,
                },
                Self::Exact {
                    value: v2,
                    ignore_case: i2,
                },
            ) => v1 == v2 && i1 == i2,
            (
                Self::Prefix {
                    value: v1,
                    ignore_case: i1,
                },
                Self::Prefix {
                    value: v2,
                    ignore_case: i2,
                },
            ) => v1 == v2 && i1 == i2,
            (
                Self::Suffix {
                    value: v1,
                    ignore_case: i1,
                },
                Self::Suffix {
                    value: v2,
                    ignore_case: i2,
                },
            ) => v1 == v2 && i1 == i2,
            (
                Self::Contains {
                    value: v1,
                    ignore_case: i1,
                },
                Self::Contains {
                    value: v2,
                    ignore_case: i2,
                },
            ) => v1 == v2 && i1 == i2,
            (Self::SafeRegex(r1), Self::SafeRegex(r2)) => r1.as_str() == r2.as_str(),
            // Cross-variant (and, if a variant is ever added, unmatched-new-variant)
            // pairs fall here. That is conservative in the caller's favor for
            // `update_from_snapshot`'s carry-forward check: it can only ever make
            // two `StringMatcherIR`s that are secretly equal compare as "changed"
            // (costing a spurious `ManagedCluster` rebuild), never the reverse
            // (treating a real difference as unchanged and wrongly carrying a
            // stale cluster forward).
            _ => false,
        }
    }
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

/// Provider credential material and request shaping that must follow the
/// cluster selected for an upstream attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderCredential {
    /// OAuth2 bearer token published by control-side credential work. The
    /// request worker never mints or refreshes this value.
    VertexOAuth2 { access_token: String },
    /// AWS Signature Version 4 credentials. Signing happens after body and
    /// route transforms, on the final per-attempt request.
    BedrockSigV4 {
        region: String,
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    },
}

/// One provider-owned logical-to-upstream model mapping. Kept on the cluster
/// because it affects the endpoint actually selected during fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderModelRewrite {
    pub pattern: String,
    pub upstream_model: String,
}

/// Provider URL path template and its model map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderPathTemplate {
    Vertex {
        project: String,
        location: String,
        publisher: String,
        models: Vec<ProviderModelRewrite>,
    },
    Bedrock {
        models: Vec<ProviderModelRewrite>,
    },
}

/// Runtime-only provider behavior carried by a cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRuntimeConfig {
    pub credential: Option<ProviderCredential>,
    pub path_template: Option<ProviderPathTemplate>,
    /// Provider-owned aliases to apply to the JSON request body after this
    /// cluster has been selected. This cannot live on the route: an aggregate
    /// fallback must send the selected member's upstream model, not the
    /// primary member's model.
    pub model_rewrites: Vec<ProviderModelRewrite>,
}

/// A validated TLS certificate/validation-context secret (static or
/// SDS-delivered).
#[derive(Debug)]
pub struct TlsSecret {
    pub name: SecretName,
}
