//! Redacted JSON views of a [`ConfigSnapshot`] for `/config_dump` and
//! `/clusters`.
//!
//! See the crate-level "Redaction policy" doc for the rule these types
//! enforce. In short: every struct here is a hand-picked allowlist of IR
//! fields, never a `#[derive(Serialize)]` on the IR types themselves --
//! that would re-expose everything on the day a new IR field is added,
//! silently.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use proxy_config::ir::{
    ClusterConfig, ConfigSnapshot, DiscoveryType, ForwardTarget, HeaderMatch, HeaderMatchKind,
    HttpConnectionManagerConfig, LbPolicy, ListenerConfig, NetworkFilterSpec, PathMatch,
    RouteActionIR, RouteEntry, RouteTable, UpstreamProtocol,
};
use proxy_filters::body_rewrite_filter::MODEL_HEADER_NAME;
use serde::Serialize;

/// String rendered in place of every credential-shaped value this module
/// redacts. A single constant so a grep for the literal finds every call
/// site.
const REDACTED: &str = "[redacted]";

#[derive(Debug, Serialize)]
pub struct ConfigDump {
    pub version: u64,
    /// Admin bind address, when configured -- not a secret, and useful for
    /// confirming which admin instance answered.
    pub admin: Option<String>,
    pub listeners: Vec<ListenerDump>,
    pub clusters: Vec<ClusterDump>,
    /// RDS-delivered route tables (WP-21); tables inlined in an HTTP
    /// connection manager are nested under that listener's filter chain
    /// instead (`ConfigSnapshot.routes` doc, `ir.rs`).
    pub routes: Vec<RouteTableDump>,
    /// Secret **names** only -- never key material (`TlsSecret` today only
    /// carries a name, but this stays an explicit allowlist rather than a
    /// derive so that stays true if the type grows fields later).
    pub secrets: Vec<String>,
}

impl ConfigDump {
    pub fn from_snapshot(snapshot: &ConfigSnapshot) -> Self {
        let mut listeners: Vec<ListenerDump> = snapshot
            .listeners
            .values()
            .map(|l| ListenerDump::from_ir(l))
            .collect();
        listeners.sort_by(|a, b| a.name.cmp(&b.name));

        let mut clusters: Vec<ClusterDump> = snapshot
            .clusters
            .values()
            .map(|c| ClusterDump::from_ir(c))
            .collect();
        clusters.sort_by(|a, b| a.name.cmp(&b.name));

        let mut routes: Vec<RouteTableDump> = snapshot
            .routes
            .values()
            .map(|r| RouteTableDump::from_ir(r))
            .collect();
        routes.sort_by(|a, b| a.name.cmp(&b.name));

        let mut secrets: Vec<String> = snapshot.secrets.keys().cloned().collect();
        secrets.sort();

        Self {
            version: snapshot.version.0,
            admin: snapshot.admin.map(|a| a.to_string()),
            listeners,
            clusters,
            routes,
            secrets,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ListenerDump {
    pub name: String,
    pub address: String,
    pub bind_to_port: bool,
    pub filter_chains: Vec<FilterChainDump>,
}

impl ListenerDump {
    fn from_ir(l: &ListenerConfig) -> Self {
        Self {
            name: l.name.clone(),
            address: l.address.to_string(),
            bind_to_port: l.bind_to_port,
            filter_chains: l
                .filter_chains
                .iter()
                .chain(l.default_filter_chain.iter())
                .map(FilterChainDump::from_ir)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FilterChainDump {
    pub name: Option<String>,
    /// Whether downstream TLS is terminated on this chain. Never the
    /// certificate/key material itself -- see module doc.
    pub tls: bool,
    pub filters: Vec<NetworkFilterDump>,
}

impl FilterChainDump {
    fn from_ir(fc: &proxy_config::ir::FilterChainSpec) -> Self {
        Self {
            name: fc.name.clone(),
            tls: fc.transport_socket.is_some(),
            filters: fc.filters.iter().map(NetworkFilterDump::from_ir).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum NetworkFilterDump {
    TcpProxy {
        stat_prefix: String,
        cluster: String,
    },
    HttpConnectionManager {
        stat_prefix: String,
        generate_request_id: bool,
        use_remote_address: bool,
        xff_num_trusted_hops: u32,
        /// Filter names/type URLs only. `HttpFilterSpec.config` is an
        /// opaque `DynamicMessage` this crate has not vetted per filter, so
        /// it is never rendered -- default-deny, per module doc.
        http_filters: Vec<HttpFilterDump>,
        route_table: RouteTableDump,
    },
}

impl NetworkFilterDump {
    fn from_ir(f: &NetworkFilterSpec) -> Self {
        match f {
            NetworkFilterSpec::TcpProxy(t) => Self::TcpProxy {
                stat_prefix: t.stat_prefix.clone(),
                cluster: t.cluster.clone(),
            },
            NetworkFilterSpec::HttpConnectionManager(h) => Self::from_hcm(h),
        }
    }

    fn from_hcm(h: &HttpConnectionManagerConfig) -> Self {
        Self::HttpConnectionManager {
            stat_prefix: h.stat_prefix.clone(),
            generate_request_id: h.generate_request_id,
            use_remote_address: h.use_remote_address,
            xff_num_trusted_hops: h.xff_num_trusted_hops,
            http_filters: h
                .http_filters
                .iter()
                .map(|f| HttpFilterDump {
                    name: f.name.clone(),
                    type_url: f.type_url.clone(),
                    is_router: f.is_router,
                })
                .collect(),
            route_table: RouteTableDump::from_ir(&h.route_table),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HttpFilterDump {
    pub name: String,
    pub type_url: String,
    pub is_router: bool,
}

#[derive(Debug, Serialize)]
pub struct RouteTableDump {
    pub name: String,
    pub virtual_hosts: Vec<VirtualHostDump>,
}

impl RouteTableDump {
    fn from_ir(t: &RouteTable) -> Self {
        Self {
            name: t.name.clone(),
            virtual_hosts: t
                .virtual_hosts
                .iter()
                .map(|vh| VirtualHostDump::from_ir(vh))
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct VirtualHostDump {
    pub name: String,
    pub domains: Vec<String>,
    pub routes: Vec<RouteDump>,
}

impl VirtualHostDump {
    fn from_ir(vh: &proxy_config::ir::VirtualHostIR) -> Self {
        Self {
            name: vh.name.clone(),
            domains: vh.domains.clone(),
            routes: vh.routes.iter().map(RouteDump::from_ir).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RouteDump {
    pub name: Option<String>,
    pub path: PathMatchDump,
    pub case_sensitive: bool,
    pub action: RouteActionDump,
    /// Header **names** the router adds/appends on match -- this is exactly
    /// how provider API keys reach the upstream (see WP-34/WP-50 history).
    /// Every value renders as `"[redacted]"` unconditionally, regardless of
    /// header name: this list is credential-shaped by construction, not by
    /// name-matching, so there is no name pattern to keep in sync.
    pub request_headers_to_add: Vec<HeaderMutationDump>,
}

impl RouteDump {
    fn from_ir(r: &Arc<RouteEntry>) -> Self {
        Self {
            name: r.name.clone(),
            path: PathMatchDump::from_ir(&r.matcher.path),
            case_sensitive: r.matcher.case_sensitive,
            action: RouteActionDump::from_ir(&r.action),
            request_headers_to_add: r
                .request_headers_to_add
                .iter()
                .map(|m| HeaderMutationDump {
                    key: m.key.clone(),
                    value: REDACTED,
                    action: format!("{:?}", m.action),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HeaderMutationDump {
    pub key: String,
    pub value: &'static str,
    pub action: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", content = "value")]
pub enum PathMatchDump {
    Prefix(String),
    Exact(String),
    /// The regex source as configured -- operator-authored routing syntax,
    /// not a secret.
    Regex(String),
}

impl PathMatchDump {
    fn from_ir(p: &PathMatch) -> Self {
        match p {
            PathMatch::Prefix(s) => Self::Prefix(s.clone()),
            PathMatch::Exact(s) => Self::Exact(s.clone()),
            PathMatch::Regex(re) => Self::Regex(re.as_str().to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum RouteActionDump {
    Forward {
        target: ForwardTargetDump,
        timeout_ms: Option<u128>,
        idle_timeout_ms: Option<u128>,
        host_rewrite_literal: Option<String>,
        prefix_rewrite: Option<String>,
    },
    Redirect {
        host_redirect: Option<String>,
        path_redirect: Option<String>,
        https_redirect: bool,
        response_code: u16,
    },
    DirectResponse {
        status: u16,
        /// Presence only. Not rendering the body is the conservative
        /// default-deny call: this crate has not vetted `DataSourceIR` as
        /// safe-to-show (a `File` variant is a path, but nothing stops a
        /// future direct-response body from carrying something sensitive).
        has_body: bool,
    },
}

impl RouteActionDump {
    fn from_ir(a: &RouteActionIR) -> Self {
        match a {
            RouteActionIR::Forward(f) => Self::Forward {
                target: ForwardTargetDump::from_ir(&f.target),
                timeout_ms: f.timeout.map(|d| d.as_millis()),
                idle_timeout_ms: f.idle_timeout.map(|d| d.as_millis()),
                host_rewrite_literal: f.host_rewrite_literal.clone(),
                prefix_rewrite: f.prefix_rewrite.clone(),
            },
            RouteActionIR::Redirect(r) => Self::Redirect {
                host_redirect: r.host_redirect.clone(),
                path_redirect: r.path_redirect.clone(),
                https_redirect: r.https_redirect,
                response_code: r.response_code,
            },
            RouteActionIR::DirectResponse { status, body } => Self::DirectResponse {
                status: *status,
                has_body: body.is_some(),
            },
        }
    }
}

// Rust note: adjacently tagged (`tag`+`content`), not internally tagged
// (`tag` alone) -- internal tagging needs each variant's payload to
// serialize as a map, which a bare `String`/`Vec` can't; this is the same
// shape `PathMatchDump` above uses for the same reason.
#[derive(Debug, Serialize)]
#[serde(tag = "type", content = "value")]
pub enum ForwardTargetDump {
    Cluster(String),
    /// Header name the router reads the cluster from at request time (WP-35
    /// model router) -- not the runtime value of that header.
    ClusterHeader(String),
    /// (cluster, cumulative weight) pairs, as precomputed on the IR.
    Weighted(Vec<(String, u64)>),
}

impl ForwardTargetDump {
    fn from_ir(t: &ForwardTarget) -> Self {
        match t {
            ForwardTarget::Cluster(c) => Self::Cluster(c.clone()),
            ForwardTarget::ClusterHeader(h) => Self::ClusterHeader(h.clone()),
            ForwardTarget::Weighted(w) => Self::Weighted(w.cumulative.clone()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ClusterDump {
    pub name: String,
    pub discovery: &'static str,
    pub lb_policy: &'static str,
    pub connect_timeout_ms: u128,
    pub upstream_protocol: &'static str,
    /// Whether upstream TLS origination is configured. Never certificate or
    /// key material -- see module doc.
    pub tls: bool,
    pub endpoints: Vec<EndpointDump>,
    /// Present only on `/clusters` when its live-state provider is wired.
    /// `/config_dump` remains a configuration dump and intentionally omits
    /// this runtime-only value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialized: Option<bool>,
    pub circuit_breakers: CircuitBreakersDump,
}

impl ClusterDump {
    pub(crate) fn from_ir(c: &ClusterConfig) -> Self {
        Self {
            name: c.name.clone(),
            discovery: discovery_type_str(c.discovery),
            lb_policy: lb_policy_str(c.lb_policy),
            connect_timeout_ms: c.connect_timeout.as_millis(),
            upstream_protocol: upstream_protocol_str(c.upstream_protocol),
            tls: c.transport_socket.is_some(),
            endpoints: c
                .endpoints
                .iter()
                .map(|e| EndpointDump {
                    host: e.host.clone(),
                    port: e.port,
                    weight: e.weight,
                    priority: e.priority,
                    hostname: None,
                    health_flags: None,
                    metadata: None,
                })
                .collect(),
            initialized: None,
            circuit_breakers: CircuitBreakersDump {
                default: ThresholdsDump::from_ir(&c.circuit_breakers.default),
                high: ThresholdsDump::from_ir(&c.circuit_breakers.high),
            },
        }
    }

    /// Build the `/clusters` view from safe configuration fields plus the
    /// manager's live host-set snapshot. If the manager cannot prove that it
    /// owns the same configuration (a reload is between manager install and
    /// config publication), `live` is `None`: report no endpoints rather
    /// than leaking a future configuration's members into this snapshot.
    pub(crate) fn from_ir_and_live(c: &ClusterConfig, live: Option<&LiveCluster>) -> Self {
        let mut dump = Self::from_ir(c);
        dump.endpoints = live
            .map(|cluster| {
                cluster
                    .endpoints
                    .iter()
                    .map(EndpointDump::from_live)
                    .collect()
            })
            .unwrap_or_default();
        dump.initialized = Some(live.is_some_and(|cluster| cluster.initialized));
        dump
    }
}

#[derive(Debug, Serialize)]
pub struct EndpointDump {
    pub host: String,
    pub port: u16,
    pub weight: u32,
    pub priority: u32,
    /// DNS name used to resolve this live address, if any. The `host` field
    /// remains the concrete address traffic currently dials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Envoy-compatible health-flag rendering (`""` means healthy).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_flags: Option<String>,
    /// Explicit endpoint labels only; opaque config/filter blobs never reach
    /// this allowlisted view.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
}

impl EndpointDump {
    fn from_live(endpoint: &LiveEndpoint) -> Self {
        Self {
            host: endpoint.host.clone(),
            port: endpoint.port,
            weight: endpoint.weight,
            priority: endpoint.priority,
            hostname: endpoint.hostname.clone(),
            health_flags: Some(endpoint.health_flags.clone()),
            metadata: Some(endpoint.metadata.clone()),
        }
    }
}

/// Runtime host-set input to `/clusters`. It intentionally uses only plain
/// owned values: `proxy-admin` remains independent of the data-plane cluster
/// crate and, in particular, generated proto types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveCluster {
    pub name: String,
    pub initialized: bool,
    pub endpoints: Vec<LiveEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveEndpoint {
    pub host: String,
    pub port: u16,
    pub hostname: Option<String>,
    pub weight: u32,
    pub priority: u32,
    pub health_flags: String,
    pub metadata: BTreeMap<String, String>,
}

/// Render every configured cluster against the corresponding live host set.
/// Names absent from `live` deliberately render an empty endpoint list: that
/// means the provider could not prove it describes this config snapshot, and
/// showing configured/stale endpoints would be less honest than empty.
pub(crate) fn clusters_from_snapshot_and_live(
    snapshot: &ConfigSnapshot,
    live: &[LiveCluster],
) -> Vec<ClusterDump> {
    let live_by_name: HashMap<&str, &LiveCluster> = live
        .iter()
        .map(|cluster| (cluster.name.as_str(), cluster))
        .collect();
    let mut clusters: Vec<ClusterDump> = snapshot
        .clusters
        .values()
        .map(|cluster| {
            ClusterDump::from_ir_and_live(cluster, live_by_name.get(cluster.name.as_str()).copied())
        })
        .collect();
    clusters.sort_by(|a, b| a.name.cmp(&b.name));
    clusters
}

#[derive(Debug, Serialize)]
pub struct CircuitBreakersDump {
    pub default: ThresholdsDump,
    pub high: ThresholdsDump,
}

#[derive(Debug, Serialize)]
pub struct ThresholdsDump {
    pub max_connections: u32,
    pub max_pending_requests: u32,
    pub max_requests: u32,
    pub max_retries: u32,
}

impl ThresholdsDump {
    fn from_ir(t: &proxy_config::ir::CircuitBreakerThresholds) -> Self {
        Self {
            max_connections: t.max_connections,
            max_pending_requests: t.max_pending_requests,
            max_requests: t.max_requests,
            max_retries: t.max_retries,
        }
    }
}

fn discovery_type_str(d: DiscoveryType) -> &'static str {
    match d {
        DiscoveryType::Static => "STATIC",
        DiscoveryType::StrictDns => "STRICT_DNS",
        DiscoveryType::LogicalDns => "LOGICAL_DNS",
        // Matches the proto enum name, as every arm here does -- a
        // `/config_dump` reader is comparing against Envoy's own output.
        DiscoveryType::Eds => "EDS",
    }
}

fn lb_policy_str(p: LbPolicy) -> &'static str {
    match p {
        LbPolicy::RoundRobin => "ROUND_ROBIN",
        LbPolicy::LeastRequest => "LEAST_REQUEST",
        LbPolicy::RingHash => "RING_HASH",
        LbPolicy::Random => "RANDOM",
        LbPolicy::Maglev => "MAGLEV",
        // `/config_dump` must round-trip what the config actually said;
        // mapping this to "ROUND_ROBIN" would misreport an aggregate
        // cluster's lb_policy in the one surface people use to check what
        // the proxy loaded.
        LbPolicy::ClusterProvided => "CLUSTER_PROVIDED",
    }
}

fn upstream_protocol_str(p: UpstreamProtocol) -> &'static str {
    match p {
        UpstreamProtocol::Http1 => "HTTP1",
        UpstreamProtocol::Http2 => "HTTP2",
    }
}

// ------------------------------------------------------------------ models --

/// The body `GET /models` answers with: the model patterns this snapshot
/// routes on. See [`models_from_snapshot`] for what is and is not in here.
#[derive(Debug, Serialize)]
pub struct ModelInventory {
    /// The request header every entry below is matched on -- the one
    /// dimension model routing is expressed on (see [`models_from_snapshot`]).
    pub header: &'static str,
    pub models: Vec<ModelDump>,
}

/// One model pattern, as `GET /models` renders it. Same allowlist rule as
/// every other type in this module: hand-picked fields, never a
/// `#[derive(Serialize)]` on an IR type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ModelDump {
    /// The pattern as an operator would write it -- an exact name, or a glob
    /// reconstructed from the route's prefix/suffix matcher (see
    /// [`Self::from_header_match`]).
    pub model: String,
    /// How the route matches that pattern: `exact`, `prefix`, `suffix`,
    /// `regex`, `present`, or `absent`.
    ///
    /// Rust note: `r#match` is a RAW IDENTIFIER -- `match` is a Rust keyword
    /// so it cannot be a plain field name, but `serde` still serializes the
    /// field as plain `match`, which is the wire name a reader expects.
    pub r#match: &'static str,
    /// The route's configured `name`, when it has one -- provenance, so the
    /// entry can be found again in `/config_dump`.
    pub route: Option<String>,
    /// The route table holding the route: an HCM-inlined table's name, or an
    /// RDS-delivered table's (`ConfigSnapshot::routes` doc).
    pub route_table: String,
}

impl ModelDump {
    /// Renders one `x-llmproxy-model` header matcher as a model pattern.
    ///
    /// Prefix/suffix matchers are shown back as GLOBS (`gpt-4` -> `gpt-4*`,
    /// `gpt-4o` suffix -> `*gpt-4o`) because that is exactly the string an
    /// operator wrote and Envoy's prefix matcher means precisely that set of
    /// models -- showing the bare prefix would read like a truncated name.
    /// A regex cannot be reconstructed as a glob without guessing, so its
    /// source is shown verbatim and labelled `regex` rather than flattened
    /// into something that might not mean the same thing.
    fn from_header_match(
        header: &HeaderMatch,
        route_name: &Option<String>,
        route_table: &str,
    ) -> Self {
        let (model, kind) = match &header.kind {
            HeaderMatchKind::Exact { value, .. } => (value.clone(), "exact"),
            HeaderMatchKind::Prefix { value, .. } => (format!("{value}*"), "prefix"),
            HeaderMatchKind::Suffix { value, .. } => (format!("*{value}"), "suffix"),
            HeaderMatchKind::Regex(re) => (re.as_str().to_string(), "regex"),
            // A presence matcher keys on the header EXISTING, not on any
            // particular model. `*` is the honest rendering (it spans every
            // model, or every model-less request); the kind is what tells the
            // two directions apart.
            HeaderMatchKind::Present(true) => ("*".to_string(), "present"),
            HeaderMatchKind::Present(false) => ("*".to_string(), "absent"),
        };
        Self {
            model,
            r#match: kind,
            route: route_name.clone(),
            route_table: route_table.to_string(),
        }
    }
}

/// Builds `GET /models`'s body: every route in the snapshot that matches on
/// [`MODEL_HEADER_NAME`].
///
/// That header IS the model dimension in this proxy:
/// `proxy_filters::body_rewrite_filter` publishes the request's `model` onto
/// it (removing any client-supplied value first), and `proxy_simple_config`
/// lowers every `routes[].model` pattern and every `models.<name>` catalogue
/// entry into a matcher on it.
///
/// **Routes that do not match on that header are deliberately absent.** A
/// plain `/v1/chat/completions` prefix route serves every model and names
/// none; inventing an entry for it would report a model the config never
/// mentioned. This endpoint reports what routing actually keys on, not what
/// a reader might wish it keyed on -- the same honesty rule as `/stats`
/// answering 404 rather than a fake empty `200` when unwired.
///
/// Both route sources are walked: RDS-delivered tables
/// (`ConfigSnapshot::routes`) and the tables inlined in an HCM (the
/// simple-config lowering inlines; see `ConfigSnapshot::routes`'s doc).
/// Identical entries from two tables are de-duplicated, and the result is
/// sorted, so the response is stable across calls for the same config.
pub fn models_from_snapshot(snapshot: &ConfigSnapshot) -> ModelInventory {
    let mut models: Vec<ModelDump> = Vec::new();
    for table in snapshot.routes.values() {
        collect_models(table, &mut models);
    }
    for listener in snapshot.listeners.values() {
        for chain in listener
            .filter_chains
            .iter()
            .chain(listener.default_filter_chain.iter())
        {
            for filter in &chain.filters {
                if let NetworkFilterSpec::HttpConnectionManager(hcm) = filter {
                    collect_models(&hcm.route_table, &mut models);
                }
            }
        }
    }
    models.sort();
    models.dedup();
    ModelInventory {
        header: MODEL_HEADER_NAME,
        models,
    }
}

/// One route table's contribution to [`models_from_snapshot`].
fn collect_models(table: &RouteTable, out: &mut Vec<ModelDump>) {
    for vhost in &table.virtual_hosts {
        for route in &vhost.routes {
            for header in &route.matcher.headers {
                if header.name.eq_ignore_ascii_case(MODEL_HEADER_NAME) {
                    out.push(ModelDump::from_header_match(
                        header,
                        &route.name,
                        table.name.as_str(),
                    ));
                }
            }
        }
    }
}
